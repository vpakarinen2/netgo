package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network"
)

func TestUDPTransportRetriesAndSummaryStates(t *testing.T) {
	options := testOptions()
	options.Transport, options.HostRate, options.Retries = model.UDP, 1000, 1
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
		if target.Transport != model.UDP {
			t.Error("dispatcher created a TCP target")
		}
		result := model.Result{Target: target, Method: model.UDPProbe}
		switch target.Port {
		case 1:
			result.State, result.Reason = model.Open, "udp_response"
		case 2:
			result.State, result.Reason = model.Closed, "port_unreachable"
		case 3:
			result.State, result.Reason = model.OpenFiltered, "timeout"
		case 4:
			result.State, result.Reason = model.Unknown, "network_unreachable"
		case 5:
			result.State, result.Reason = model.Filtered, "fixture_admin_prohibited"
		}
		return result, nil
	})
	writer := &recordingWriter{}
	summary, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{1, 2, 3, 4, 5}, options, prober, writer)
	if err != nil || summary.Status != "completed" || summary.Attempts != 6 || summary.Completed != 5 || summary.Open != 1 || summary.Closed != 1 || summary.OpenFiltered != 1 || summary.Filtered != 1 || summary.Unknown != 1 {
		t.Fatalf("UDP counters/retries failed: %+v err=%v", summary, err)
	}
	for _, result := range writer.results {
		if result.Target.Port == 3 && result.Attempts != 2 {
			t.Fatal("UDP silence was not retried")
		}
	}
}

func TestUDPGlobalAndHostPacingIncludeRetries(t *testing.T) {
	for _, hostLimited := range []bool{true, false} {
		options := testOptions()
		options.Transport, options.Retries = model.UDP, 1
		options.Rate, options.HostRate = 20, 1000
		if hostLimited {
			options.Rate, options.HostRate = 1000, 20
		}
		var mu sync.Mutex
		var times []time.Time
		prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
			mu.Lock()
			times = append(times, time.Now())
			mu.Unlock()
			return model.Result{Target: target, Method: model.UDPProbe, State: model.OpenFiltered, Reason: "timeout"}, nil
		})
		writer := &recordingWriter{}
		started := time.Now()
		summary, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{53, 123}, options, prober, writer)
		if err != nil || summary.Attempts != 4 || time.Since(started) < 135*time.Millisecond {
			t.Fatalf("pacing bypassed (host-limited=%v): %+v err=%v", hostLimited, summary, err)
		}
		for i := 1; i < len(times); i++ {
			if gap := times[i].Sub(times[i-1]); gap < 35*time.Millisecond {
				t.Fatalf("attempts bunched past rate budget: %s", gap)
			}
		}
	}
}

func TestUDPHostPacingCancellationAndTCPInspectionGuard(t *testing.T) {
	options := testOptions()
	options.Transport, options.HostRate, options.Retries = model.UDP, 1, 1
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
		return model.Result{Target: target, Method: model.UDPProbe, State: model.OpenFiltered, Reason: "timeout"}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	writer := &recordingWriter{}
	summary, err := Run(ctx, testPlan(t, "127.0.0.1"), []uint16{53}, options, prober, writer)
	if !errors.Is(err, context.DeadlineExceeded) || summary.Attempts != 1 || summary.Status != "canceled" || !writer.closed {
		t.Fatalf("host-rate cancellation failed: %+v %v", summary, err)
	}
	options.Identifier = identifyFunc(func(context.Context, model.Target, network.ConnectionGate) (*model.Service, model.Identification) {
		t.Error("TCP identification ran on UDP")
		return nil, model.Identification{}
	})
	writer = &recordingWriter{}
	if _, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{53}, options, prober, writer); err == nil || !writer.closed {
		t.Fatal("UDP accepted TCP inspection or leaked writer")
	}
}
