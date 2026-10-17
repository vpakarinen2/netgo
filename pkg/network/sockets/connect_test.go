package sockets

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

type dialFunc func(context.Context, string, string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func tcpTarget(address string) model.Target {
	addrPort := netip.MustParseAddrPort(address)
	return model.Target{Address: addrPort.Addr(), Port: addrPort.Port(), Transport: model.TCP}
}

func TestConnectOpenAndClosesWithoutPayload(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "tcp6" {
				address = "[::1]:0"
			}
			listener, err := net.Listen(network, address)
			if err != nil && network == "tcp6" {
				t.Skipf("IPv6 loopback unavailable: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				var data [1]byte
				_, err = conn.Read(data[:])
				done <- err
			}()
			result, err := (&Connect{Timeout: time.Second}).Probe(context.Background(), tcpTarget(listener.Addr().String()))
			if err != nil || result.State != model.Open || result.Reason != "connected" {
				t.Fatalf("result=%+v, error=%v", result, err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("socket did not close without payload: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("accepted connection remained open")
			}
		})
	}
}

func TestConnectRefusedOnLoopback(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := tcpTarget(listener.Addr().String())
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := (&Connect{Timeout: 5 * time.Second}).Probe(context.Background(), target)
	if err != nil || result.State != model.Closed || result.Reason != "connection_refused" {
		t.Fatalf("result=%+v, error=%v", result, err)
	}
}

func TestConnectTimeoutAndCancellation(t *testing.T) {
	prober := &Connect{Timeout: 10 * time.Millisecond, Dialer: dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})}
	result, err := prober.Probe(context.Background(), tcpTarget("127.0.0.1:80"))
	if err != nil || result.State != model.Unknown || result.Reason != "timeout" {
		t.Fatalf("timeout misclassified: %+v, %v", result, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prober.Probe(ctx, tcpTarget("127.0.0.1:80")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation must be an error: %v", err)
	}
}

func TestConnectErrorEvidence(t *testing.T) {
	for _, tc := range []struct {
		err    error
		state  model.PortState
		reason string
	}{
		{refusedCode, model.Closed, "connection_refused"},
		{netUnreachCode, model.Unknown, "network_unreachable"},
		{hostUnreachCode, model.Unknown, "host_unreachable"},
		{resetCode, model.Unknown, "connection_reset"},
	} {
		prober := &Connect{Timeout: time.Second, Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", tc.err)}
		})}
		result, err := prober.Probe(context.Background(), tcpTarget("127.0.0.1:80"))
		if err != nil || result.State != tc.state || result.Reason != tc.reason {
			t.Fatalf("%v: result=%+v, error=%v", tc.err, result, err)
		}
	}
	localErr := errors.New("out of sockets")
	prober := &Connect{Timeout: time.Second, Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, localErr })}
	if result, err := prober.Probe(context.Background(), tcpTarget("127.0.0.1:80")); !errors.Is(err, localErr) || result.State != "" {
		t.Fatalf("local failure became network evidence: %+v, %v", result, err)
	}
}

type trackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedConn) Close() error { c.closed.Store(true); return c.Conn.Close() }

func TestConnectClosesConnectionReturnedWithError(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	tracked := &trackedConn{Conn: client}
	prober := &Connect{Timeout: time.Second, Dialer: dialFunc(func(context.Context, string, string) (net.Conn, error) { return tracked, refusedCode })}
	_, _ = prober.Probe(context.Background(), tcpTarget("127.0.0.1:80"))
	if !tracked.closed.Load() {
		t.Fatal("connection leaked")
	}
}
