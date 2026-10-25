package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network"
)

type scriptFunc func(context.Context, model.Result, time.Time) []model.ScriptRun

func (f scriptFunc) Run(ctx context.Context, result model.Result, evaluation time.Time) []model.ScriptRun {
	return f(ctx, result, evaluation)
}

func TestScriptEvaluationTimeFollowsInspection(t *testing.T) {
	options := testOptions()
	options.ServiceConcurrency, options.ScriptConcurrency = 1, 1
	var inspectedAt time.Time
	options.Identifier = identifyFunc(func(_ context.Context, _ model.Target, _ network.ConnectionGate) (*model.Service, model.Identification) {
		time.Sleep(5 * time.Millisecond)
		inspectedAt = time.Now().UTC()
		return &model.Service{Name: "tls"}, model.Identification{Status: "identified"}
	})
	var called bool
	options.Scripts = scriptFunc(func(_ context.Context, _ model.Result, evaluation time.Time) []model.ScriptRun {
		called = true
		if evaluation.Before(inspectedAt) || evaluation.After(time.Now().UTC()) || evaluation.Location() != time.UTC {
			t.Errorf("evaluation time %s must be UTC at check execution, after inspection %s", evaluation, inspectedAt)
		}
		return []model.ScriptRun{{ID: "fixture", Status: "completed"}}
	})
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
		return openResult(target), nil
	})
	if _, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{443}, options, prober, &recordingWriter{}); err != nil || !called {
		t.Fatalf("check did not complete: called=%t err=%v", called, err)
	}
}

func TestScriptFailuresPreservePortsAndFinishOtherWork(t *testing.T) {
	options := testOptions()
	options.ServiceConcurrency, options.ScriptConcurrency, options.OpenOnly = 2, 2, true
	options.Identifier = identifyFunc(func(_ context.Context, _ model.Target, _ network.ConnectionGate) (*model.Service, model.Identification) {
		return &model.Service{Name: "ssh", Product: "fixture"}, model.Identification{Status: "identified"}
	})
	var active, peak, calls atomic.Int32
	options.Scripts = scriptFunc(func(ctx context.Context, result model.Result, evaluation time.Time) []model.ScriptRun {
		calls.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); current > old && !peak.CompareAndSwap(old, current); old = peak.Load() {
		}
		if evaluation.IsZero() || result.Service == nil || result.Service.Product != "fixture" {
			t.Error("missing inspection evidence")
		}
		time.Sleep(2 * time.Millisecond)
		run := model.ScriptRun{ID: "fixture", Status: "completed"}
		if result.Target.Port == 80 {
			run.Status, run.Error = "error", "fixture failure"
		}
		return []model.ScriptRun{run}
	})
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
		result := openResult(target)
		result.Duration = 123 * time.Millisecond
		if target.Port == 443 {
			result.State, result.Reason = model.Closed, "connection_refused"
		}
		return result, nil
	})
	writer := &recordingWriter{}
	summary, err := Run(context.Background(), testPlan(t, "127.0.0.0/30"), []uint16{22, 80, 443}, options, prober, writer)
	if err == nil || summary.Status != "failed" || summary.Completed != 12 || summary.Reported != 8 || summary.Open != 8 || summary.Closed != 4 || calls.Load() != 8 || active.Load() != 0 || peak.Load() > 2 {
		t.Fatalf("summary=%+v calls=%d peak=%d err=%v", summary, calls.Load(), peak.Load(), err)
	}
	if summary.Scripts == nil || summary.Scripts.Errors != 4 || summary.Scripts.Completed != 4 || summary.Scripts.Invocations != 8 {
		t.Fatalf("wrong script counts: %+v", summary.Scripts)
	}
	for _, result := range writer.results {
		if result.State != model.Open || result.Reason != "connected" || result.Duration != 123*time.Millisecond || result.Service.Product != "fixture" || len(result.Scripts) != 1 {
			t.Fatalf("script changed port evidence: %+v", result)
		}
	}
}

func TestScriptCancellationDrainsOriginalPortResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options := testOptions()
	options.ServiceConcurrency, options.ScriptConcurrency = 1, 1
	options.Identifier = identifyFunc(func(_ context.Context, _ model.Target, _ network.ConnectionGate) (*model.Service, model.Identification) {
		return &model.Service{Name: "ssh"}, model.Identification{Status: "identified"}
	})
	started := make(chan struct{}, 1)
	options.Scripts = scriptFunc(func(ctx context.Context, _ model.Result, _ time.Time) []model.ScriptRun {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return []model.ScriptRun{{ID: "fixture", Status: "canceled", Error: ctx.Err().Error()}}
	})
	var probes atomic.Int32
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
		probes.Add(1)
		return openResult(target), nil
	})
	writer := &recordingWriter{}
	done := make(chan error, 1)
	plan := testPlan(t, "127.0.0.1")
	go func() { _, err := Run(ctx, plan, []uint16{22, 80, 443}, options, prober, writer); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scripts did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || int(probes.Load()) != len(writer.results) || !writer.closed {
			t.Fatalf("lost results: probes=%d written=%d err=%v", probes.Load(), len(writer.results), err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("script cancellation leaked workers")
	}
}
