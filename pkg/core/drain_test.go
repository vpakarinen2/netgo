package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

type blockingWriter struct {
	started chan struct{}
	closed  bool
}

func (w *blockingWriter) WriteResult(ctx context.Context, _ model.Result) error {
	close(w.started)
	<-ctx.Done()
	return ctx.Err()
}

func (w *blockingWriter) WriteSummary(context.Context, model.Summary) error { return nil }
func (w *blockingWriter) Close() error                                      { w.closed = true; return nil }

func TestCancellationBoundsAlreadyBlockedCooperativeSink(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &blockingWriter{started: make(chan struct{})}
	prober := probeFunc(func(_ context.Context, target model.Target) (model.Result, error) { return openResult(target), nil })
	plan := testPlan(t, "127.0.0.1")
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, plan, []uint16{80}, testOptions(), prober, writer)
		done <- err
	}()
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("sink did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !writer.closed {
			t.Fatalf("blocked sink not canceled and closed: %v, %v", err, writer.closed)
		}
	case <-time.After(drainTimeout + time.Second):
		t.Fatal("blocked cooperative sink exceeded drain deadline")
	}
}

func TestProbeFailureCancelsAlreadyBlockedSink(t *testing.T) {
	writer := &blockingWriter{started: make(chan struct{})}
	localFailure := errors.New("socket limit exceeded")
	prober := probeFunc(func(ctx context.Context, target model.Target) (model.Result, error) {
		if target.Port == 80 {
			return openResult(target), nil
		}
		select {
		case <-writer.started:
			return model.Result{}, localFailure
		case <-ctx.Done():
			return model.Result{}, ctx.Err()
		}
	})
	plan := testPlan(t, "127.0.0.1")
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), plan, []uint16{80, 81}, testOptions(), prober, writer)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, localFailure) || !writer.closed {
			t.Fatalf("original failure lost or sink not closed: %v", err)
		}
	case <-time.After(drainTimeout + time.Second):
		t.Fatal("local failure did not stop blocked output")
	}
}
