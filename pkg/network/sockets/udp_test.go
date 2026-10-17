package sockets

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func udpFixture(t *testing.T, network string, respond func([]byte) [][]byte) model.Target {
	t.Helper()
	ip := net.ParseIP("127.0.0.1")
	if network == "udp6" {
		ip = net.ParseIP("::1")
	}
	listener, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil && network == "udp6" {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		for {
			n, peer, err := listener.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			for _, response := range respond(append([]byte(nil), buffer[:n]...)) {
				_, _ = listener.WriteToUDP(response, peer)
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP fixture leaked")
		}
	})
	address := listener.LocalAddr().(*net.UDPAddr).AddrPort()
	return model.Target{Address: address.Addr(), Port: address.Port(), Transport: model.UDP}
}

func udpProber(kind string) *UDP { return &UDP{Timeout: time.Second, Kind: kind, MaxBytes: 4096} }

func dnsReply(t *testing.T, request []byte) []byte {
	t.Helper()
	var query dns.Msg
	if err := query.Unpack(request); err != nil {
		t.Error(err)
		return nil
	}
	if query.RecursionDesired || len(query.Question) != 1 || query.Question[0].Name != "." || query.Question[0].Qtype != dns.TypeNS {
		t.Error("unexpected DNS request")
	}
	response := new(dns.Msg)
	response.SetRcode(&query, dns.RcodeRefused)
	data, err := response.Pack()
	if err != nil {
		t.Error(err)
	}
	return data
}

func ntpReply(request []byte) []byte {
	response := make([]byte, 48)
	response[0], response[1] = 4<<3|4, 2
	if len(request) >= 48 {
		copy(response[24:32], request[40:48])
		copy(response[40:48], request[40:48])
	}
	return response
}

func TestUDPProtocolRepliesAndCorrelation(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, kind := range []string{"dns", "ntp"} {
			t.Run(network+"/"+kind, func(t *testing.T) {
				target := udpFixture(t, network, func(request []byte) [][]byte {
					var response []byte
					if kind == "dns" {
						response = dnsReply(t, request)
					} else {
						response = ntpReply(request)
					}
					wrong := append([]byte(nil), response...)
					if kind == "dns" {
						wrong[0] ^= 1
					} else {
						wrong[24] ^= 1
					}
					return [][]byte{wrong, {1, 2, 3}, response}
				})
				result, err := udpProber(kind).Probe(context.Background(), target)
				if err != nil || result.State != model.Open || result.Reason != "udp_response" || result.Service == nil || result.Service.Name != kind || result.UDP.IgnoredResponses != 2 || result.UDP.ResponseBytes == 0 {
					t.Fatalf("result=%+v UDP=%+v err=%v", result, result.UDP, err)
				}
				if result.Method != model.UDPProbe || result.Target.Transport != model.UDP {
					t.Fatal("UDP method/transport lost")
				}
			})
		}
	}
}

func TestUDPGenericEmptyDatagramsAndPeerFiltering(t *testing.T) {
	for _, reply := range [][]byte{{}, []byte("reply")} {
		target := udpFixture(t, "udp4", func(request []byte) [][]byte {
			if len(request) != 0 {
				t.Error("generic probe must be empty")
			}
			return [][]byte{reply}
		})
		result, err := udpProber("empty").Probe(context.Background(), target)
		if err != nil || result.State != model.Open || result.UDP.ResponseBytes != len(reply) || result.Service != nil {
			t.Fatalf("empty/generic response lost: %+v %v", result, err)
		}
	}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 1)
		_, peer, err := listener.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			return
		}
		defer other.Close()
		_, _ = other.WriteToUDP([]byte("wrong-source-port"), peer)
	}()
	address := listener.LocalAddr().(*net.UDPAddr).AddrPort()
	prober := udpProber("empty")
	prober.Timeout = 80 * time.Millisecond
	result, err := prober.Probe(context.Background(), model.Target{Address: address.Addr(), Port: address.Port(), Transport: model.UDP})
	if err != nil || result.State != model.OpenFiltered || result.Reason != "timeout" {
		t.Fatalf("unrelated endpoint was accepted: %+v %v", result, err)
	}
	<-done
}

func TestUDPSilenceMalformedAndOversizedResponses(t *testing.T) {
	for _, kind := range []string{"empty", "dns", "ntp"} {
		target := udpFixture(t, "udp4", func([]byte) [][]byte {
			if kind == "empty" {
				return nil
			}
			return [][]byte{{1, 2, 3}}
		})
		prober := udpProber(kind)
		prober.Timeout = 40 * time.Millisecond
		result, err := prober.Probe(context.Background(), target)
		if err != nil || result.State != model.OpenFiltered || result.Reason != "timeout" || result.Service != nil {
			t.Fatalf("silence/malformed must remain ambiguous: %+v %v", result, err)
		}
	}
	target := udpFixture(t, "udp4", func(request []byte) [][]byte { return [][]byte{make([]byte, 1024), ntpReply(request)} })
	prober := udpProber("ntp")
	prober.MaxBytes = 48
	result, err := prober.Probe(context.Background(), target)
	if err != nil || result.State != model.Open || result.UDP.OversizedResponses != 1 || result.UDP.IgnoredResponses != 1 {
		t.Fatalf("oversized datagram handling failed: %+v UDP=%+v err=%v", result, result.UDP, err)
	}
	target = udpFixture(t, "udp4", func([]byte) [][]byte {
		replies := make([][]byte, maxIgnoredUDPReplies)
		for i := range replies {
			replies[i] = []byte{0}
		}
		return replies
	})
	result, err = udpProber("dns").Probe(context.Background(), target)
	if err != nil || result.State != model.Unknown || result.Reason != "response_limit" || result.UDP.IgnoredResponses != maxIgnoredUDPReplies {
		t.Fatalf("reply processing was not bounded: %+v UDP=%+v err=%v", result, result.UDP, err)
	}
}

func TestUDPPortUnreachableOnLoopback(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = listener.Close()
	result, err := udpProber("empty").Probe(context.Background(), model.Target{Address: address.Addr(), Port: address.Port(), Transport: model.UDP})
	if err != nil || result.State != model.Closed || result.Reason != "port_unreachable" {
		t.Fatalf("OS port-unreachable report was not recognized: %+v %v", result, err)
	}
}

type datagramConn struct {
	read   func([]byte) (int, error)
	write  func([]byte) (int, error)
	closed atomic.Bool
}

func (c *datagramConn) Read(p []byte) (int, error) { return c.read(p) }
func (c *datagramConn) Write(p []byte) (int, error) {
	if c.write != nil {
		return c.write(p)
	}
	return len(p), nil
}
func (c *datagramConn) Close() error                     { c.closed.Store(true); return nil }
func (c *datagramConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *datagramConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *datagramConn) SetDeadline(time.Time) error      { return nil }
func (c *datagramConn) SetReadDeadline(time.Time) error  { return nil }
func (c *datagramConn) SetWriteDeadline(time.Time) error { return nil }

func TestUDPErrorsAndCancellationCloseSockets(t *testing.T) {
	localErr := errors.New("socket resources exhausted")
	for _, tc := range []struct {
		err    error
		state  model.PortState
		reason string
		fatal  bool
	}{
		{refusedCode, model.Closed, "port_unreachable", false},
		{netUnreachCode, model.Unknown, "network_unreachable", false},
		{hostUnreachCode, model.Unknown, "host_unreachable", false},
		{localErr, "", "", true},
	} {
		conn := &datagramConn{read: func([]byte) (int, error) { return 0, &net.OpError{Op: "read", Net: "udp", Err: tc.err} }}
		prober := udpProber("empty")
		prober.Dialer = dialFunc(func(context.Context, string, string) (net.Conn, error) { return conn, nil })
		result, err := prober.Probe(context.Background(), model.Target{Address: netip.MustParseAddr("127.0.0.1"), Port: 53, Transport: model.UDP})
		if tc.fatal {
			if !errors.Is(err, localErr) || result.State != "" {
				t.Fatalf("local error became network evidence: %+v %v", result, err)
			}
		} else if err != nil || result.State != tc.state || result.Reason != tc.reason {
			t.Fatalf("classification failed: %+v %v", result, err)
		}
		if !conn.closed.Load() {
			t.Fatal("socket leaked")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var conn *datagramConn
	prober := udpProber("empty")
	prober.Dialer = dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn = &datagramConn{read: func([]byte) (int, error) { close(started); <-ctx.Done(); return 0, ctx.Err() }}
		return conn, nil
	})
	done := make(chan error, 1)
	go func() {
		_, err := prober.Probe(ctx, model.Target{Address: netip.MustParseAddr("127.0.0.1"), Port: 53, Transport: model.UDP})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !conn.closed.Load() {
			t.Fatalf("cancellation failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP cancellation blocked")
	}
}

func TestUDPSetupAndSendDeadlinesAreNotSilence(t *testing.T) {
	for _, duringSend := range []bool{false, true} {
		prober := udpProber("empty")
		prober.Timeout = 10 * time.Millisecond
		prober.Dialer = dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			if !duringSend {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return &datagramConn{write: func([]byte) (int, error) { <-ctx.Done(); return 0, net.ErrClosed }, read: func([]byte) (int, error) { t.Error("read without a successful send"); return 0, net.ErrClosed }}, nil
		})
		result, err := prober.Probe(context.Background(), model.Target{Address: netip.MustParseAddr("127.0.0.1"), Port: 53, Transport: model.UDP})
		if !errors.Is(err, context.DeadlineExceeded) || result.State != "" {
			t.Fatalf("local deadline became UDP silence: %+v %v", result, err)
		}
	}
}
