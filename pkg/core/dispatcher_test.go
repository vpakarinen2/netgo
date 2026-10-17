package core

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network/targets"
)

type probeFunc func(context.Context, model.Target) (model.Result, error)

func (f probeFunc) Probe(ctx context.Context, target model.Target) (model.Result, error) {
	return f(ctx, target)
}

type recordingWriter struct {
	results    []model.Result
	summary    model.Summary
	closed     bool
	resultErr  error
	summaryErr error
	closeErr   error
	onResult   func()
}

func (w *recordingWriter) WriteResult(ctx context.Context, result model.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.resultErr != nil {
		return w.resultErr
	}
	w.results = append(w.results, result)
	if w.onResult != nil {
		w.onResult()
	}
	return nil
}

func (w *recordingWriter) WriteSummary(ctx context.Context, summary model.Summary) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.summary = summary
	return w.summaryErr
}

func (w *recordingWriter) Close() error { w.closed = true; return w.closeErr }

func testPlan(t *testing.T, input string) *targets.Plan {
	t.Helper()
	plan, err := targets.NewPlan(context.Background(), []string{input}, targets.Options{MaxHosts: 65536, DNSConcurrency: 1, DNSTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testOptions() Options {
	return Options{Concurrency: 3, Rate: 1000000, MaxProbes: 1000000}
}

func openResult(target model.Target) model.Result {
	return model.Result{Target: target, Method: model.TCPConnect, State: model.Open, Reason: "connected", ObservedAt: time.Now().UTC()}
}

func TestConcurrencyAndSummary(t *testing.T) {
	var active, peak atomic.Int32
	prober := probeFunc(func(ctx context.Context, target model.Target) (model.Result, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for previous := peak.Load(); current > previous && !peak.CompareAndSwap(previous, current); previous = peak.Load() {
		}
		select {
		case <-time.After(5 * time.Millisecond):
			return openResult(target), nil
		case <-ctx.Done():
			return model.Result{}, ctx.Err()
		}
	})
	writer := &recordingWriter{}
	summary, err := Run(context.Background(), testPlan(t, "127.0.0.0/30"), []uint16{22, 80, 443}, testOptions(), prober, writer)
	if err != nil {
		t.Fatal(err)
	}
	if peak.Load() > 3 || active.Load() != 0 || summary.Total != 12 || summary.Completed != 12 || summary.Open != 12 || summary.Attempts != 12 || summary.Status != "completed" || !writer.closed || len(writer.results) != 12 {
		t.Fatalf("peak=%d active=%d results=%d closed=%v summary=%+v", peak.Load(), active.Load(), len(writer.results), writer.closed, summary)
	}
	seen := map[model.Target]bool{}
	for _, result := range writer.results {
		if seen[result.Target] || result.Attempts != 1 {
			t.Fatalf("duplicate or incorrect result: %+v", result)
		}
		seen[result.Target] = true
	}
}

func TestRetriesConsumeRateBudget(t *testing.T) {
	options := testOptions()
	options.Rate, options.Retries = 20, 2
	var calls atomic.Int32
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
		result := openResult(target)
		if calls.Add(1) < 3 {
			result.State, result.Reason = model.Unknown, "timeout"
		}
		return result, nil
	})
	writer := &recordingWriter{}
	started := time.Now()
	summary, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{80}, options, prober, writer)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 90*time.Millisecond {
		t.Fatalf("retries bypassed the rate budget: %s", elapsed)
	}
	if calls.Load() != 3 || summary.Attempts != 3 || summary.Completed != 1 || summary.Open != 1 || len(writer.results) != 1 || writer.results[0].Attempts != 3 {
		t.Fatalf("retry result or counters incorrect: %+v, %+v", writer.results, summary)
	}
}

func TestOnlyTimeoutsAreRetried(t *testing.T) {
	for _, tc := range []struct {
		state    model.PortState
		reason   string
		attempts uint64
	}{
		{model.Open, "connected", 1},
		{model.Closed, "connection_refused", 1},
		{model.Unknown, "host_unreachable", 1},
		{model.Unknown, "timeout", 3},
	} {
		options := testOptions()
		options.Retries = 2
		writer := &recordingWriter{}
		prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
			result := openResult(target)
			result.State, result.Reason = tc.state, tc.reason
			return result, nil
		})
		summary, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{80}, options, prober, writer)
		if err != nil || summary.Attempts != tc.attempts || summary.Completed != 1 {
			t.Fatalf("%s: summary=%+v error=%v", tc.reason, summary, err)
		}
	}
}

func TestCancellationStopsBlockedProducerAndWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active atomic.Int32
	started := make(chan struct{}, 3)
	prober := probeFunc(func(ctx context.Context, _ model.Target) (model.Result, error) {
		active.Add(1)
		defer active.Add(-1)
		started <- struct{}{}
		<-ctx.Done()
		return model.Result{}, ctx.Err()
	})
	writer := &recordingWriter{}
	plan := testPlan(t, "2001:db8::/112")
	type outcome struct {
		summary model.Summary
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		summary, err := Run(ctx, plan, []uint16{80}, testOptions(), prober, writer)
		done <- outcome{summary, err}
	}()
	for i := 0; i < 3; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("workers did not start")
		}
	}
	cancel()
	select {
	case result := <-done:
		if !errors.Is(result.err, context.Canceled) || result.summary.Status != "canceled" || active.Load() != 0 || !writer.closed || writer.summary.Status != "canceled" {
			t.Fatalf("cancellation cleanup failed: summary=%+v active=%d closed=%v error=%v", result.summary, active.Load(), writer.closed, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not terminate blocked producers and workers")
	}
}

func TestCancellationDrainsCompletedResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var completed atomic.Int32
	prober := probeFunc(func(ctx context.Context, target model.Target) (model.Result, error) {
		if err := ctx.Err(); err != nil {
			return model.Result{}, err
		}
		completed.Add(1)
		return openResult(target), nil
	})
	writer := &recordingWriter{onResult: cancel}
	summary, err := Run(ctx, testPlan(t, "127.0.0.0/24"), []uint16{80}, testOptions(), prober, writer)
	if !errors.Is(err, context.Canceled) || int32(len(writer.results)) != completed.Load() || summary.Completed != uint64(completed.Load()) || writer.summary.Status != "canceled" {
		t.Fatalf("completed results lost: produced=%d written=%d summary=%+v err=%v", completed.Load(), len(writer.results), summary, err)
	}
}

func TestProbeAndOutputFailures(t *testing.T) {
	localFailure := errors.New("socket resource exhausted")
	for _, tc := range []struct {
		name      string
		probeErr  error
		resultErr error
		closeErr  error
		want      error
	}{
		{"local probe failure", localFailure, nil, nil, localFailure},
		{"result write failure", nil, io.ErrClosedPipe, nil, io.ErrClosedPipe},
		{"close failure", nil, nil, io.ErrClosedPipe, io.ErrClosedPipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer := &recordingWriter{resultErr: tc.resultErr, closeErr: tc.closeErr}
			prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) {
				return openResult(target), tc.probeErr
			})
			_, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{80}, testOptions(), prober, writer)
			if !errors.Is(err, tc.want) || !writer.closed {
				t.Fatalf("failure lost or writer not closed: %v, %v", err, writer.closed)
			}
			if tc.probeErr != nil && (len(writer.results) != 0 || writer.summary.Status != "failed") {
				t.Fatal("local failure became a port result or success summary")
			}
		})
	}
	writer := &recordingWriter{summaryErr: io.ErrClosedPipe}
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) { return openResult(target), nil })
	if _, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{80}, testOptions(), prober, writer); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("summary failure lost: %v", err)
	}
}

func TestRateWaitDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	options := testOptions()
	options.Rate = 1
	writer := &recordingWriter{}
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) { return openResult(target), nil })
	_, err := Run(ctx, testPlan(t, "127.0.0.1"), []uint16{80, 81}, options, prober, writer)
	if !errors.Is(err, context.DeadlineExceeded) || writer.summary.Status != "canceled" {
		t.Fatalf("rate wait did not honor context deadline: %v, %+v", err, writer.summary)
	}
}

func TestPreflightAndProgressFailuresDoNotProbe(t *testing.T) {
	prober := probeFunc(func(context.Context, model.Target) (model.Result, error) {
		t.Error("probe started despite preflight failure")
		return model.Result{}, nil
	})
	options := testOptions()
	options.MaxProbes = 1
	writer := &recordingWriter{}
	if _, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{80, 81}, options, prober, writer); err == nil || !writer.closed {
		t.Fatal("pair limit not enforced or writer leaked")
	}
	options = testOptions()
	options.Progress = func(model.Progress) error { return io.ErrClosedPipe }
	writer = &recordingWriter{}
	if _, err := Run(context.Background(), testPlan(t, "127.0.0.1"), []uint16{80}, options, prober, writer); !errors.Is(err, io.ErrClosedPipe) || !writer.closed {
		t.Fatal("progress failure not propagated or writer leaked")
	}
}
