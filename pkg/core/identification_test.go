package core

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network"
)

type identifyFunc func(context.Context, model.Target, network.ConnectionGate) (*model.Service, model.Identification)

func (f identifyFunc) Identify(ctx context.Context, target model.Target, gate network.ConnectionGate) (*model.Service, model.Identification) {
	return f(ctx, target, gate)
}

func TestIdentificationConcurrencyAndFailuresPreservePortEvidence(t *testing.T) {
	options := testOptions()
	options.ServiceConcurrency = 2
	var active, peak, calls atomic.Int32
	options.Identifier = identifyFunc(func(ctx context.Context, target model.Target, gate network.ConnectionGate) (*model.Service, model.Identification) {
		calls.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for previous := peak.Load(); current > previous && !peak.CompareAndSwap(previous, current); previous = peak.Load() {
		}
		release, err := gate(ctx)
		if err != nil {
			return nil, model.Identification{Status: "canceled", Error: err.Error()}
		}
		defer release()
		select {
		case <-time.After(5 * time.Millisecond):
		case <-ctx.Done():
			return nil, model.Identification{Status: "canceled"}
		}
		if target.Port == 80 {
			return nil, model.Identification{Status: "failed", Error: "inspection fixture failure"}
		}
		return &model.Service{Name: "ssh"}, model.Identification{Status: "identified", Connections: 1}
	})
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
		result := openResult(target)
		result.Duration = 123 * time.Millisecond
		if target.Port == 22 {
			result.State, result.Reason = model.Closed, "connection_refused"
		}
		return result, nil
	})
	writer := &recordingWriter{}
	summary, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{22, 80, 443, 8080, 1234}, options, prober, writer)
	if err != nil || summary.Status != "completed" || summary.Open != 4 || summary.Closed != 1 || calls.Load() != 4 || peak.Load() > 2 || active.Load() != 0 {
		t.Fatalf("summary=%+v calls=%d peak=%d active=%d err=%v", summary, calls.Load(), peak.Load(), active.Load(), err)
	}
	for _, result := range writer.results {
		if result.Duration != 123*time.Millisecond || result.Attempts != 1 {
			t.Fatalf("port evidence changed: %+v", result)
		}
		if result.Target.Port == 22 && result.Identification != nil {
			t.Fatal("closed port was inspected")
		}
		if result.Target.Port == 80 && (result.State != model.Open || result.Identification == nil || result.Identification.Status != "failed") {
			t.Fatal("inspection failure erased open evidence")
		}
		if result.Target.Port == 443 && (result.Service == nil || result.Service.Name != "ssh") {
			t.Fatal("service stage was canceled when port workers finished")
		}
	}
}

func TestServiceStageDoesNotOccupyPortWorkers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	options := testOptions()
	options.Concurrency, options.ServiceConcurrency = 1, 1
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	options.Identifier = identifyFunc(func(ctx context.Context, _ model.Target, _ network.ConnectionGate) (*model.Service, model.Identification) {
		once.Do(func() { close(started) })
		select {
		case <-release:
			return &model.Service{Name: "ssh"}, model.Identification{Status: "identified"}
		case <-ctx.Done():
			return nil, model.Identification{Status: "canceled"}
		}
	})
	probes := make(chan uint16, 4)
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
		probes <- target.Port
		return openResult(target), nil
	})
	writer := &recordingWriter{}
	done := make(chan error, 1)
	plan := testPlan(t, "127.0.0.1")
	go func() { _, err := Run(ctx, plan, []uint16{1, 2, 3, 4}, options, prober, writer); done <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("inspection never started")
	}
	for probe := 0; probe < 2; probe++ {
		select {
		case <-probes:
		case <-ctx.Done():
			t.Fatal("inspection occupied the only port worker")
		}
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("pipeline did not finish")
	}
}

func TestInspectionConnectionsShareRateBudget(t *testing.T) {
	options := testOptions()
	options.Rate, options.ServiceConcurrency = 20, 1
	options.Identifier = identifyFunc(func(ctx context.Context, _ model.Target, gate network.ConnectionGate) (*model.Service, model.Identification) {
		for range 2 {
			release, err := gate(ctx)
			if err != nil {
				return nil, model.Identification{Status: "failed", Error: err.Error()}
			}
			release()
		}
		return &model.Service{Name: "tls"}, model.Identification{Status: "identified", Connections: 2}
	})
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) { return openResult(target), nil })
	writer := &recordingWriter{}
	started := time.Now()
	summary, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{443}, options, prober, writer)
	if err != nil || time.Since(started) < 90*time.Millisecond || summary.Attempts != 1 || writer.results[0].Identification.Connections != 2 {
		t.Fatalf("shared rate budget/counters failed: %+v %v", summary, err)
	}
}

func TestCancellationAndOutputFailureWithIdentification(t *testing.T) {
	for _, writeFailure := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		options := testOptions()
		options.ServiceConcurrency = 1
		started := make(chan struct{}, 1)
		var completed atomic.Int32
		options.Identifier = identifyFunc(func(ctx context.Context, _ model.Target, _ network.ConnectionGate) (*model.Service, model.Identification) {
			if writeFailure {
				return &model.Service{Name: "ssh"}, model.Identification{Status: "identified"}
			}
			started <- struct{}{}
			<-ctx.Done()
			return nil, model.Identification{Status: "canceled"}
		})
		prober := probeFunc(func(ctx context.Context, target model.Target) (model.Result, error) {
			if err := ctx.Err(); err != nil {
				return model.Result{}, err
			}
			completed.Add(1)
			return openResult(target), nil
		})
		writer := &recordingWriter{}
		if writeFailure {
			writer.resultErr = io.ErrClosedPipe
		}
		done := make(chan error, 1)
		plan := testPlan(t, "127.0.0.0/24")
		go func() { _, err := Run(ctx, plan, []uint16{80}, options, prober, writer); done <- err }()
		if !writeFailure {
			select {
			case <-started:
			case <-time.After(time.Second):
				cancel()
				t.Fatal("inspection never started")
			}
			cancel()
		}
		select {
		case err := <-done:
			if writeFailure {
				if !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("lost output failure: %v", err)
				}
			} else if !errors.Is(err, context.Canceled) || int32(len(writer.results)) != completed.Load() {
				t.Fatalf("open results lost: produced=%d written=%d err=%v", completed.Load(), len(writer.results), err)
			}
			if !writer.closed {
				t.Fatal("writer leaked")
			}
		case <-time.After(time.Second):
			cancel()
			t.Fatal("service pipeline did not stop")
		}
		cancel()
	}
}
