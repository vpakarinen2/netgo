package core

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network"
)

func TestTCPHostSlotsSharedWithInspection(t *testing.T) {
	options := testOptions()
	options.Concurrency, options.ServiceConcurrency, options.HostConcurrency = 8, 8, 2
	options.Diagnostics = true
	var active, peak atomic.Int32
	work := func(ctx context.Context) {
		n := active.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		select {
		case <-time.After(2 * time.Millisecond):
		case <-ctx.Done():
		}
		active.Add(-1)
	}
	options.Identifier = identifyFunc(func(ctx context.Context, target model.Target, gate network.ConnectionGate) (*model.Service, model.Identification) {
		for range 2 {
			release, err := gate(ctx)
			if err != nil {
				return nil, model.Identification{Status: "canceled"}
			}
			work(ctx)
			release()
		}
		return &model.Service{Name: "ssh"}, model.Identification{Status: "identified", Connections: 2}
	})
	prober := probeFunc(func(ctx context.Context, target model.Target) (model.Result, error) {
		work(ctx)
		return openResult(target), nil
	})
	ports := make([]uint16, 32)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	summary, err := Run(ctx, testPlan(t, "127.0.0.1"), ports, options, prober, &recordingWriter{})
	if err != nil || peak.Load() > 2 || active.Load() != 0 {
		t.Fatalf("peak=%d active=%d err=%v", peak.Load(), active.Load(), err)
	}
	d := summary.Diagnostics
	if d == nil || d.ActiveConnections != 0 || d.PeakConnections > 2 || d.PortAttempts != 32 || d.ServiceStatuses["identified"] != 32 {
		t.Fatalf("bad diagnostics: %+v", d)
	}
}

func TestTCPHostRateIncludesRetries(t *testing.T) {
	options := testOptions()
	options.HostRate, options.Retries, options.Diagnostics = 20, 1, true
	var mu sync.Mutex
	var starts []time.Time
	calls := make(map[uint16]int)
	prober := probeFunc(func(ctx context.Context, target model.Target) (model.Result, error) {
		mu.Lock()
		defer mu.Unlock()
		starts = append(starts, time.Now())
		calls[target.Port]++
		result := openResult(target)
		if calls[target.Port] == 1 {
			result.State, result.Reason = model.Unknown, "timeout"
		}
		return result, nil
	})
	summary, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{22, 80, 443}, options, prober, &recordingWriter{})
	if err != nil || summary.Open != 3 || summary.Attempts != 6 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	for i := 1; i < len(starts); i++ {
		if starts[i].Sub(starts[i-1]) < 35*time.Millisecond {
			t.Fatal("TCP retry bypassed host pacing")
		}
	}
	d := summary.Diagnostics
	if d.Reasons["timeout"] != 3 || d.Reasons["connected"] != 3 || len(d.Hosts) != 1 || d.Hosts[0].Timeouts != 3 || d.GateWait <= 0 {
		t.Fatalf("bad diagnostics: %+v", d)
	}
}

func TestHostSlotCancellationDoesNotLeak(t *testing.T) {
	b := newConnectionBudget(1000000, 0)
	b.hostConcurrency = 1
	address := netip.MustParseAddr("127.0.0.1")
	release, err := b.acquire(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := b.acquire(ctx, address); err == nil {
		t.Fatal("capacity wait ignored cancellation")
	}
	release()
	release() // Releases are idempotent.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	release2, err := b.acquire(ctx2, address)
	if err != nil {
		t.Fatal(err)
	}
	release2()
}

func TestDiagnosticsBoundedAndOptional(t *testing.T) {
	d := newDiagnostics(true, nil)
	for i := 0; i < 1000; i++ {
		d.probe(fmt.Sprintf("host-%04d", i), model.Result{Reason: fmt.Sprintf("reason-%d", i)}, nil, time.Millisecond)
	}
	s := d.snapshot()
	if len(s.Hosts) != diagnosticHostLimit || len(s.Reasons) > 16 || s.UnattributedAttempts != 744 || s.PortAttempts != 1000 {
		t.Fatalf("unbounded diagnostic state: %+v", s)
	}
	if newDiagnostics(false, nil).snapshot() != nil {
		t.Fatal("disabled stats allocated output")
	}
}
