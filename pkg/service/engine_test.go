package service

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func targetFor(address string) model.Target {
	addrPort := netip.MustParseAddrPort(address)
	return model.Target{Address: addrPort.Addr(), Port: addrPort.Port(), Transport: model.TCP}
}

func newInspector(t *testing.T, options Options) *Inspector {
	t.Helper()
	i, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestHTTPProbeUsesHEADHostAndDoesNotFollowRedirects(t *testing.T) {
	var redirectCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirectCalls.Add(1) }))
	defer destination.Close()
	requests := make(chan *http.Request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(context.Background())
		w.Header().Set("Server", "test-http/2.4")
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	target := targetFor(server.Listener.Addr().String())
	target.Hostname = "original.test"
	i := newInspector(t, Options{Timeout: 3 * time.Second, MaxBytes: 1024, Active: true, ServerName: "virtual.test"})
	var gates atomic.Int32
	service, info := i.Identify(context.Background(), target, func(context.Context) error { gates.Add(1); return nil })
	if service == nil || service.Name != "http" || service.Product != "test-http" || service.Version != "2.4" || info.Status != "identified" || info.Connections != 3 || gates.Load() != 3 {
		t.Fatalf("service=%+v info=%+v gates=%d", service, info, gates.Load())
	}
	select {
	case request := <-requests:
		if request.Method != "HEAD" || request.Host != net.JoinHostPort("virtual.test", strconv.Itoa(int(target.Port))) || request.URL.Path != "/" {
			t.Fatalf("unexpected request: %+v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("no HEAD request")
	}
	if redirectCalls.Load() != 0 {
		t.Fatal("probe followed a redirect")
	}
}

func TestBannerIdentificationAndReadLimits(t *testing.T) {
	for _, tc := range []struct {
		name             string
		data             []byte
		protocol, status string
		limit            bool
	}{
		{"SSH", []byte("SSH-2.0-OpenSSH_9.7p1\r\n"), "ssh", "identified", false},
		{"unknown", []byte("220 SMTP ready\r\n"), "", "unrecognized", false},
		{"binary", []byte{255, 254, 0, 10}, "", "unrecognized", false},
		{"limit", []byte(strings.Repeat("X", 1024)), "", "unrecognized", true},
		{"partial HTTP", []byte("HTTP/1.1 200 OK\r\nServer: " + strings.Repeat("X", 1024)), "", "unrecognized", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			i := newInspector(t, Options{Timeout: time.Second, MaxBytes: 256, Active: true, Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
				client, server := net.Pipe()
				go func() { defer close(done); defer server.Close(); _, _ = server.Write(tc.data) }()
				return client, nil
			})})
			service, info := i.Identify(context.Background(), targetFor("127.0.0.1:2222"), nil)
			if info.Status != tc.status || info.Connections != 1 || info.ReadLimitReached != tc.limit {
				t.Fatalf("unexpected inspection: %+v", info)
			}
			if tc.protocol != "" {
				if service == nil || service.Name != tc.protocol {
					t.Fatalf("service=%+v", service)
				}
			} else if service != nil {
				t.Fatalf("unrecognized banner guessed as %+v", service)
			}
			if len(info.Evidence) != 0 {
				value := []byte(info.Evidence[0].Value)
				if info.Evidence[0].Kind == "banner_base64" {
					var err error
					value, err = base64.StdEncoding.DecodeString(string(value))
					if err != nil {
						t.Fatal(err)
					}
				}
				if len(value) > 256 {
					t.Fatal("evidence exceeds read limit")
				}
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("banner connection leaked")
			}
		})
	}
}

func TestPassiveModeSendsNoPayload(t *testing.T) {
	read := make(chan []byte, 1)
	i := newInspector(t, Options{Timeout: 100 * time.Millisecond, MaxBytes: 256, Active: false, Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { defer server.Close(); data, _ := io.ReadAll(server); read <- data }()
		return client, nil
	})})
	service, info := i.Identify(context.Background(), targetFor("127.0.0.1:443"), nil)
	if service != nil || info.Connections != 1 || info.Status != "timeout" {
		t.Fatalf("passive result: %+v %+v", service, info)
	}
	select {
	case data := <-read:
		if len(data) != 0 {
			t.Fatalf("passive mode sent %q", data)
		}
	case <-time.After(time.Second):
		t.Fatal("passive socket leaked")
	}
}

func TestInspectionCancellationAndGateDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	closed := make(chan struct{})
	i := newInspector(t, Options{Timeout: time.Second, MaxBytes: 256, Active: true, Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		close(started)
		go func() { defer close(closed); defer server.Close(); _, _ = io.Copy(io.Discard, server) }()
		return client, nil
	})})
	done := make(chan model.Identification, 1)
	go func() { _, info := i.Identify(ctx, targetFor("127.0.0.1:80"), nil); done <- info }()
	<-started
	cancel()
	select {
	case info := <-done:
		if info.Status != "canceled" {
			t.Fatalf("lost cancellation: %+v", info)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation blocked")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("canceled socket leaked")
	}
	i = newInspector(t, Options{Timeout: 20 * time.Millisecond, MaxBytes: 256, Active: true, Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
		t.Error("dial bypassed connection gate")
		return nil, errors.New("unexpected dial")
	})})
	_, info := i.Identify(context.Background(), targetFor("127.0.0.1:80"), func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	if info.Status != "timeout" || info.Connections != 0 {
		t.Fatalf("gate wait did not use inspection deadline: %+v", info)
	}
}
