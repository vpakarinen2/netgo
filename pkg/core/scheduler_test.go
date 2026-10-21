package core

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func TestSlowHostDoesNotOccupyWaitingWorkers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	options := testOptions()
	options.Concurrency, options.HostConcurrency, options.Diagnostics = 2, 1, true
	ports := make([]uint16, 20)
	for index := range ports {
		ports[index] = uint16(index + 1)
	}
	blocked := netip.MustParseAddr("127.0.0.0")
	unblock := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	counts := map[netip.Addr]int{}
	progressed := false
	prober := probeFunc(func(ctx context.Context, target model.Target) (model.Result, error) {
		if target.Address == blocked {
			select {
			case <-unblock:
			case <-ctx.Done():
				return model.Result{}, ctx.Err()
			}
		} else {
			mu.Lock()
			counts[target.Address]++
			if counts[target.Address] == len(ports) {
				progressed = true
				once.Do(func() { close(unblock) })
			}
			mu.Unlock()
		}
		return openResult(target), nil
	})
	summary, err := Run(ctx, testPlan(t, "127.0.0.0/30"), ports, options, prober, &recordingWriter{})
	if err != nil || !progressed || summary.Completed != 80 || summary.Diagnostics.ActiveConnections != 0 || summary.Diagnostics.PeakConnections > 2 {
		t.Fatalf("other hosts did not finish while first host blocked: progressed=%v summary=%+v err=%v", progressed, summary, err)
	}
}

func TestSchedulerRefillsBoundedHostWindowAndRetries(t *testing.T) {
	options := testOptions()
	options.Concurrency, options.Retries = 4, 1
	var mu sync.Mutex
	seen := map[model.Target]int{}
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
		mu.Lock()
		defer mu.Unlock()
		seen[target]++
		result := openResult(target)
		if seen[target] == 1 {
			result.State, result.Reason = model.Unknown, "timeout"
		}
		return result, nil
	})
	writer := &recordingWriter{}
	summary, err := Run(context.Background(), testPlan(t, "2001:db8::/118"), []uint16{80, 443}, options, prober, writer)
	if err != nil || summary.Completed != 2048 || summary.Attempts != 4096 || summary.Open != 2048 || len(writer.results) != 2048 || len(seen) != 2048 {
		t.Fatalf("refill lost targets/retries: summary=%+v err=%v", summary, err)
	}
	for _, result := range writer.results {
		if result.Attempts != 2 || seen[result.Target] != 2 {
			t.Fatalf("duplicate or lost attempt: %+v", result)
		}
	}
}
