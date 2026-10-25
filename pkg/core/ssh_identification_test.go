package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/service"
)

type sshFixtureDialer func(context.Context, string, string) (net.Conn, error)

func (f sshFixtureDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestConcurrentSSHBannersStayWithTheirTargetsAcrossScans(t *testing.T) {
	fixtures := []struct{ software, product, version string }{
		{"JKAR9HrxeD-", "JKAR9HrxeD-", ""},
		{"libssh0.8.0", "libssh0.8.0", ""},
		{"paramiko", "paramiko", ""},
		{"dropbear2022.82", "dropbear2022.82", ""},
		{"OpenSSH_9.7p1", "OpenSSH", "9.7p1"},
		{"dropbear_2022.82", "dropbear", "2022.82"},
	}
	fixtureFor := func(address netip.AddrPort) int {
		return (int(address.Addr().As4()[3]) + int(address.Port())) % len(fixtures)
	}
	bannerFor := func(address netip.AddrPort) string {
		return fmt.Sprintf("SSH-2.0-%s fixture-%s\r\n", fixtures[fixtureFor(address)].software, address)
	}
	var peers sync.WaitGroup
	defer peers.Wait()
	inspector, err := service.New(service.Options{
		Timeout: 3 * time.Second, MaxBytes: 1024, Active: true,
		Dialer: sshFixtureDialer(func(_ context.Context, _, address string) (net.Conn, error) {
			endpoint, err := netip.ParseAddrPort(address)
			if err != nil {
				return nil, err
			}
			client, peer := net.Pipe()
			peers.Add(1)
			go func() {
				defer peers.Done()
				defer peer.Close()
				_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
				banner := bannerFor(endpoint)
				// Fragment the greeting while other target inspections run, to
				// exercise socket buffers, parsing, and result association.
				if _, err := io.WriteString(peer, banner[:8]); err != nil {
					return
				}
				time.Sleep(time.Duration(endpoint.Port()%3) * time.Millisecond)
				_, _ = io.WriteString(peer, banner[8:])
			}()
			return client, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	options := testOptions()
	options.Concurrency, options.ServiceConcurrency, options.Identifier = 32, 16, inspector
	plan := testPlan(t, "127.0.0.0/26")
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
		return openResult(target), nil
	})
	for scan := 0; scan < 3; scan++ {
		writer := &recordingWriter{}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		summary, err := Run(ctx, plan, []uint16{22, 2222, 2200, 2022}, options, prober, writer)
		cancel()
		if err != nil || summary.Completed != 256 || len(writer.results) != 256 {
			t.Fatalf("scan %d: summary=%+v err=%v", scan, summary, err)
		}
		seen := make(map[model.Target]bool)
		for _, result := range writer.results {
			endpoint := netip.AddrPortFrom(result.Target.Address, result.Target.Port)
			want := fixtures[fixtureFor(endpoint)]
			got := result.Service
			if seen[result.Target] || got == nil || result.Identification == nil || result.Identification.Status != "identified" || result.Identification.Connections != 1 {
				t.Fatalf("scan %d: duplicate or unidentified target: %+v", scan, result)
			}
			seen[result.Target] = true
			if got.Name != "ssh" || got.Product != want.product || got.Version != want.version || len(got.Evidence) != 1 || got.Evidence[0].Kind != "banner" || got.Evidence[0].Value != bannerFor(endpoint) {
				t.Fatalf("scan %d target %s: expected %s/%s and its own raw banner, got %+v", scan, endpoint, want.product, want.version, got)
			}
		}
	}
}
