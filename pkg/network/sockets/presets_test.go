package sockets

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/core"
	"github.com/vpakarinen2/netgo/pkg/network/targets"
	"github.com/vpakarinen2/netgo/pkg/output"
)

// Every dial stays in memory. Only the attempt deadline changes between runs:
// 80 succeeds immediately, 22 refuses, 443 responds after 100ms, others stay silent.
type presetFixture struct{}

func (presetFixture) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	port := netip.MustParseAddrPort(address).Port()
	if port == 22 {
		return nil, &net.OpError{Op: "dial", Net: network, Err: refusedCode}
	}
	if port != 80 {
		if port != 443 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	client, peer := net.Pipe()
	_ = peer.Close()
	return client, nil
}

func TestPresetsUnderControlledLatency(t *testing.T) {
	for _, count := range []int{10, 100, 1000} {
		for _, timeout := range []time.Duration{20 * time.Millisecond, 250 * time.Millisecond} {
			t.Run(fmt.Sprintf("%d/%s", count, timeout), func(t *testing.T) {
				ports, err := targets.TopPorts(count)
				if err != nil {
					t.Fatal(err)
				}
				plan, err := targets.NewPlan(context.Background(), []string{"127.0.0.1"}, targets.Options{MaxHosts: 1, DNSConcurrency: 1, DNSTimeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				prober := &Connect{Timeout: timeout, Dialer: presetFixture{}}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				summary, err := core.Run(ctx, plan, ports, core.Options{Concurrency: 128, Rate: 1000000, MaxProbes: 1000, Diagnostics: true}, prober, output.NewJSON(io.Discard))
				wantOpen := uint64(1)
				if timeout > 100*time.Millisecond {
					wantOpen = 2
				}
				if err != nil || summary.Total != uint64(count) || summary.Open != wantOpen || summary.Closed != 1 || summary.Unknown != uint64(count)-wantOpen-1 || summary.Attempts != uint64(count) {
					t.Fatalf("summary=%+v err=%v", summary, err)
				}
				if summary.Diagnostics.Reasons["timeout"] != summary.Unknown {
					t.Fatal("timeout diagnostics disagree")
				}
			})
		}
	}
}
