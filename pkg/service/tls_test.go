package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testCertificate(t *testing.T, expired bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1234), Subject: pkix.Name{CommonName: "example.test", Organization: []string{"Netgo test fixture"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"example.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if expired {
		template.NotBefore, template.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSCertificateSNIAndHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name, hostname, override, sni string
		matches, expired              bool
	}{
		{"override", "original.test", "EXAMPLE.test.", "example.test", true, false},
		{"mismatch", "wrong.test", "", "wrong.test", false, false},
		{"expired", "example.test", "", "example.test", true, true},
		{"IP reference", "", "", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sni := make(chan string, 4)
			host := make(chan string, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host <- r.Host
				w.Header().Set("Server", "tls-test/1.0")
				w.Header().Set("X-Amz-Cf-Id", "fixture-id")
				w.Header().Set("X-Amz-Cf-Pop", "fixture-pop")
				w.WriteHeader(http.StatusNoContent)
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{testCertificate(t, tc.expired)}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni <- hello.ServerName; return nil, nil }}
			server.StartTLS()
			defer server.Close()
			target := targetFor(server.Listener.Addr().String())
			target.Hostname = tc.hostname
			i := newInspector(t, Options{Timeout: 3 * time.Second, MaxBytes: 1024, Active: true, ServerName: tc.override})
			service, info := i.Identify(context.Background(), target, nil)
			if service == nil || service.Name != "https" || service.Product != "tls-test" || service.TLS == nil || info.Status != "identified" || info.Connections != 2 {
				t.Fatalf("service=%+v info=%+v", service, info)
			}
			observed := service.TLS
			if service.Web == nil || len(service.Web.Edge) != 1 || service.Web.Edge[0].Provider != "cloudfront" || service.Web.WAF.Status != "unknown" {
				t.Fatalf("HTTPS lost web observations: %+v", service.Web)
			}
			if observed.CertificateVerification != "not_performed" || observed.HostnameMatches != tc.matches || observed.SNISent != (tc.sni != "") || observed.ServerName != tc.sni || observed.Version == "" || observed.CipherSuite == "" {
				t.Fatalf("incorrect TLS observation: %+v", observed)
			}
			if observed.Certificate == nil || observed.Certificate.TimeValid == tc.expired || len(observed.Certificate.SHA256) != 64 || observed.Certificate.Serial != "1234" || len(observed.Certificate.DNSNames) != 1 {
				t.Fatalf("incorrect certificate: %+v", observed.Certificate)
			}
			if !tc.matches && observed.HostnameError == "" {
				t.Fatal("certificate mismatch was not explained")
			}
			select {
			case sent := <-sni:
				if sent != tc.sni {
					t.Fatalf("SNI=%q, want %q", sent, tc.sni)
				}
			case <-time.After(time.Second):
				t.Fatal("TLS ClientHello not observed")
			}
			reference := tc.sni
			if reference == "" {
				reference = target.Address.String()
			}
			if actual := <-host; actual != net.JoinHostPort(reference, strconv.Itoa(int(target.Port))) {
				t.Fatalf("HTTP Host=%q", actual)
			}
		})
	}
}

func TestTLSIdentitySurvivesHTTPTimeout(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{testCertificate(t, false)}}
	server.StartTLS()
	defer server.Close()
	i := newInspector(t, Options{Timeout: 600 * time.Millisecond, MaxBytes: 256, Active: true})
	service, info := i.Identify(context.Background(), targetFor(server.Listener.Addr().String()), nil)
	if service == nil || service.Name != "tls" || service.TLS == nil || info.Status != "identified" || info.Error == "" {
		t.Fatalf("TLS evidence lost on HTTP failure: service=%+v info=%+v", service, info)
	}
}

func TestTLSWireReadBound(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = server.Write(make([]byte, 16)) }()
	conn := &boundedConn{Conn: client, remaining: 8}
	data := make([]byte, 16)
	if n, err := conn.Read(data); err != nil || n != 8 {
		t.Fatalf("wire bound not applied: n=%d err=%v", n, err)
	}
	if n, err := conn.Read(data); n != 0 || err == nil {
		t.Fatalf("wire limit not enforced: n=%d err=%v", n, err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wire fixture leaked")
	}
}

func TestHTTP2HeadersUseExistingTLSConnection(t *testing.T) {
	var requests atomic.Int32
	request := make(chan *http.Request, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		request <- r
		w.Header().Set("Server", "cloudflare/1.0")
		w.Header().Set("Cf-Ray", "fixture")
		w.Header().Set("X-Amzn-Waf-Action", "challenge")
		w.Header().Set("Location", "https://redirect.invalid/")
		w.WriteHeader(http.StatusAccepted)
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	i := newInspector(t, Options{Timeout: 3 * time.Second, MaxBytes: 1024, Active: true, ServerName: "example.test"})
	var acquired, released atomic.Int32
	gate := func(context.Context) (func(), error) {
		acquired.Add(1)
		return func() { released.Add(1) }, nil
	}
	service, info := i.Identify(context.Background(), targetFor(server.Listener.Addr().String()), gate)
	if service == nil || service.Name != "https" || service.TLS.ALPN != "h2" || info.Status != "identified" || info.Error != "" || info.Connections != 2 || requests.Load() != 1 || acquired.Load() != 2 || released.Load() != 2 {
		t.Fatalf("HTTP/2 evidence incorrect: %+v, %+v requests=%d", service, info, requests.Load())
	}
	r := <-request
	if r.ProtoMajor != 2 || r.Method != http.MethodHead || r.URL.Path != "/" || !strings.HasPrefix(r.Host, "example.test:") || r.UserAgent() != "netgo" {
		t.Fatalf("unexpected HTTP/2 request: %+v", r)
	}
	if service.Product != "cloudflare" || service.Version != "1.0" || service.Web == nil || len(service.Web.Edge) != 1 || service.Web.WAF.Status != "signal_observed" || len(service.Web.WAF.Detections) != 1 || service.Web.WAF.Detections[0].Provider != "aws-waf" {
		t.Fatalf("HTTP/2 headers were not fingerprinted: %+v", service)
	}
	if service.Evidence[len(service.Evidence)-1].Kind != "alpn" {
		t.Fatal("HTTP/2 ALPN evidence was lost")
	}
}

func TestHTTP2HeaderLimitAndTimeoutPreserveTLS(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(strconv.FormatBool(oversized), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if oversized {
					w.Header().Set("Server", strings.Repeat("x", 2048))
					w.WriteHeader(http.StatusOK)
				} else {
					<-r.Context().Done()
				}
			}))
			server.EnableHTTP2 = true
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			i := newInspector(t, Options{Timeout: 900 * time.Millisecond, MaxBytes: 256, Active: true})
			started := time.Now()
			service, info := i.Identify(context.Background(), targetFor(server.Listener.Addr().String()), nil)
			if service == nil || service.Name != "https" || service.TLS.ALPN != "h2" || service.Web != nil || info.Error == "" || info.Connections != 2 {
				t.Fatalf("bounded failure lost evidence: service=%+v info=%+v", service, info)
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("HTTP/2 exceeded inspection deadline")
			}
		})
	}
}

func TestHTTP2DecodedHeaderLimit(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", strings.Repeat("x", 300))
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	i := newInspector(t, Options{Timeout: 3 * time.Second, MaxBytes: 256, Active: true})
	service, info := i.Identify(context.Background(), targetFor(server.Listener.Addr().String()), nil)
	if service == nil || service.Web != nil || service.Product != "" || !info.ReadLimitReached || info.Error != errHTTP2HeaderLimit.Error() {
		t.Fatalf("decoded headers exceeded evidence limit: service=%+v info=%+v", service, info)
	}
}

func TestHTTP2DoesNotFollowRedirects(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusFound)
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	i := newInspector(t, Options{Timeout: 3 * time.Second, MaxBytes: 1024, Active: true})
	service, info := i.Identify(context.Background(), targetFor(server.Listener.Addr().String()), nil)
	if service == nil || service.Web == nil || info.Error != "" || requests.Load() != 1 || service.Evidence[0].Value != "HTTP/2.0 302 Found" {
		t.Fatalf("redirect followed or headers lost: service=%+v info=%+v requests=%d", service, info, requests.Load())
	}
}

func TestHTTP2CancellationReleasesConnectionLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	var active atomic.Int32
	gate := func(context.Context) (func(), error) {
		active.Add(1)
		return func() { active.Add(-1) }, nil
	}
	i := newInspector(t, Options{Timeout: 3 * time.Second, MaxBytes: 1024, Active: true})
	started := time.Now()
	service, info := i.Identify(ctx, targetFor(server.Listener.Addr().String()), gate)
	if service == nil || service.TLS.ALPN != "h2" || info.Status != "canceled" || info.Connections != 2 || active.Load() != 0 || time.Since(started) > 2*time.Second {
		t.Fatalf("cancellation leaked or lost TLS evidence: service=%+v info=%+v active=%d", service, info, active.Load())
	}
}

// A refusing peer keeps its connection open so transport-level stream replays
// are observable. No HPACK decoding is needed to count request HEADERS frames.
func TestHTTP2DoesNotRetryRefusedStream(t *testing.T) {
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{testCertificate(t, false)}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var requests atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		preface := make([]byte, 24)
		if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
			return
		}
		if _, err := conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}); err != nil {
			return
		} // SETTINGS
		for {
			var header [9]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				return
			}
			size := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
			if size > 65536 {
				return
			}
			if _, err := io.CopyN(io.Discard, conn, int64(size)); err != nil {
				return
			}
			if header[3] == 4 && header[4]&1 == 0 {
				if _, err := conn.Write([]byte{0, 0, 0, 4, 1, 0, 0, 0, 0}); err != nil {
					return
				}
			}
			if header[3] == 1 {
				requests.Add(1)
				frame := []byte{0, 0, 4, 3, 0, header[5], header[6], header[7], header[8], 0, 0, 0, 0}
				binary.BigEndian.PutUint32(frame[9:], 7) // REFUSED_STREAM
				if _, err := conn.Write(frame); err != nil {
					return
				}
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	i := newInspector(t, Options{Timeout: 3 * time.Second, MaxBytes: 1024, Active: true})
	_, err = i.http2Probe(ctx, conn.(*tls.Conn), targetFor(listener.Addr().String()))
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refused-stream fixture leaked")
	}
	if err == nil || requests.Load() != 1 {
		t.Fatalf("request replayed: err=%v requests=%d", err, requests.Load())
	}
}
