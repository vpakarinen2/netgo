package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network"
	"github.com/vpakarinen2/netgo/pkg/network/targets"
	"github.com/vpakarinen2/netgo/pkg/output"
)

const drainTimeout = 2 * time.Second

type Options struct {
	Concurrency        int
	Rate               int
	Retries            int
	MaxProbes          uint64
	Progress           func(model.Progress) error
	Identifier         Identifier
	ServiceConcurrency int
	Transport          model.Transport
	HostRate           int
	HostConcurrency    int
	Diagnostics        bool
	Settings           json.RawMessage
}

// Run owns the writer and closes it on every return. Results already completed
// are drained after cancellation, for up to drainTimeout with cooperative sinks.
// An I/O failure cancels producers/workers and the remaining queue is discarded.
func Run(ctx context.Context, plan *targets.Plan, ports []uint16, options Options, prober network.Prober, writer output.Writer) (summary model.Summary, runErr error) {
	if writer == nil {
		return summary, fmt.Errorf("result writer is required")
	}
	defer func() { runErr = errors.Join(runErr, writer.Close()) }()
	if options.Transport == "" {
		options.Transport = model.TCP
	}
	if options.Diagnostics && len(options.Settings) > 0 && !json.Valid(options.Settings) {
		return summary, fmt.Errorf("invalid diagnostic settings JSON")
	}
	if options.Transport != model.TCP && options.Transport != model.UDP || options.HostRate < 0 || options.HostRate > 1000000 || options.HostConcurrency < 0 || options.HostConcurrency > 65535 {
		return summary, fmt.Errorf("invalid transport or per-host rate")
	}
	if options.Transport == model.UDP && options.Identifier != nil {
		return summary, fmt.Errorf("TCP service inspection cannot be used for UDP")
	}
	if plan == nil || prober == nil || options.Concurrency < 1 || options.Concurrency > 65535 || options.Rate < 1 || options.Rate > 1000000 || options.Retries < 0 || options.Retries > 10 || options.MaxProbes > 100000000 {
		return summary, fmt.Errorf("invalid dispatcher options")
	}
	if options.Identifier != nil && (options.ServiceConcurrency < 1 || options.ServiceConcurrency > 256) {
		return summary, fmt.Errorf("service concurrency must be between 1 and 256")
	}
	seen := make(map[uint16]bool, len(ports))
	for _, port := range ports {
		if port == 0 || seen[port] {
			return summary, fmt.Errorf("dispatcher ports must be nonzero and unique")
		}
		seen[port] = true
	}
	total, err := plan.ProbeCount(len(ports), options.MaxProbes)
	if err != nil {
		return summary, err
	}
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	started := time.Now()
	stats := &state{summary: model.Summary{Hosts: plan.HostCount(), Ports: len(ports), Total: total, StartedAt: started.UTC()}}
	if options.Progress != nil {
		if err := options.Progress(stats.progress()); err != nil {
			return summary, fmt.Errorf("write progress: %w", err)
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	group, workCtx := errgroup.WithContext(runCtx)
	var failOnce sync.Once
	var firstErr error
	fail := func(err error) error {
		if err != nil {
			failOnce.Do(func() {
				firstErr = err
				cancel()
			})
		}
		return err
	}
	workers := min(options.Concurrency, int(total))
	jobs := make(chan model.Target, workers)
	results := make(chan model.Result, workers)
	budget := newConnectionBudget(options.Rate, options.HostRate)
	budget.hostConcurrency = options.HostConcurrency
	diagnostics := newDiagnostics(options.Diagnostics, options.Settings)
	acquire := func(ctx context.Context, target model.Target) (func(), error) {
		started := time.Now()
		release, err := budget.acquire(ctx, target.Address)
		if err != nil {
			diagnostics.waited(time.Since(started))
			return nil, err
		}
		finished := diagnostics.acquired(time.Since(started))
		return func() { finished(); release() }, nil
	}
	probeResults := results
	var inspections sync.WaitGroup
	if options.Identifier != nil {
		probeResults = make(chan model.Result, workers)
		for worker := 0; worker < min(options.ServiceConcurrency, int(total)); worker++ {
			inspections.Add(1)
			go func() {
				defer inspections.Done()
				for result := range probeResults {
					if result.State == model.Open {
						var info model.Identification
						if runCtx.Err() != nil {
							info.Status, info.Error = "canceled", runCtx.Err().Error()
						} else {
							result.Service, info = options.Identifier.Identify(runCtx, result.Target, func(ctx context.Context) (func(), error) { return acquire(ctx, result.Target) })
						}
						result.Identification = &info
						diagnostics.inspection(info)
					}
					results <- result
				}
			}()
		}
	}
	group.Go(func() error {
		defer close(jobs)
		return fail(plan.ForEach(workCtx, func(host targets.Host) error {
			for _, port := range ports {
				target := model.Target{Address: host.Address, Hostname: host.Hostname, Port: port, Transport: options.Transport}
				select {
				case jobs <- target:
				case <-workCtx.Done():
					return workCtx.Err()
				}
			}
			return nil
		}))
	})
	for worker := 0; worker < workers; worker++ {
		group.Go(func() (workerErr error) {
			defer func() { fail(workerErr) }()
			for {
				select {
				case <-workCtx.Done():
					return workCtx.Err()
				case target, ok := <-jobs:
					if !ok {
						return nil
					}
					var result model.Result
					for attempt := 1; attempt <= options.Retries+1; attempt++ {
						release, err := acquire(workCtx, target)
						if err != nil {
							return err
						}
						stats.attempts.Add(1)
						probeStarted := time.Now()
						result, err = prober.Probe(workCtx, target)
						release()
						diagnostics.probe(target.Address.String(), result, err, time.Since(probeStarted))
						if err != nil {
							return fmt.Errorf("probe %s:%d: %w", target.Address, target.Port, err)
						}
						result.Attempts = attempt
						if result.Reason != "timeout" || result.State != model.Unknown && result.State != model.OpenFiltered {
							break
						}
					}
					// The coordinator keeps draining until every worker exits, even
					// after a write error. Preserve finished results on cancellation.
					probeResults <- result
				}
			}
		})
	}
	done := make(chan error, 1)
	go func() {
		err := group.Wait()
		if err != nil {
			cancel()
		}
		if options.Identifier != nil {
			close(probeResults)
			inspections.Wait()
		}
		close(results)
		done <- err
	}()
	writeCtx, stopWrites := context.WithCancel(context.WithoutCancel(ctx))
	defer stopWrites()
	outputDone := make(chan struct{})
	defer close(outputDone)
	// This watcher can cancel a cooperative sink already blocked in a write.
	// Setting a deadline only in the coordinator loop would be too late.
	go func() {
		select {
		case <-runCtx.Done():
			timer := time.NewTimer(drainTimeout)
			defer timer.Stop()
			select {
			case <-timer.C:
				stopWrites()
			case <-outputDone:
			}
		case <-outputDone:
		}
	}()
	canceled := runCtx.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var writeErr error
	for results != nil {
		select {
		case <-canceled:
			canceled = nil
			ticker.Stop()
		case <-ticker.C:
			if writeErr == nil && options.Progress != nil {
				if err := options.Progress(stats.progress()); err != nil {
					writeErr = fmt.Errorf("write progress: %w", err)
					cancel()
				}
			}
		case result, ok := <-results:
			if !ok {
				results = nil
				continue
			}
			if writeErr != nil {
				continue
			}
			if err := writer.WriteResult(writeCtx, result); err != nil {
				writeErr = fmt.Errorf("write result: %w", err)
				cancel()
				continue
			}
			stats.record(result)
		}
	}
	groupErr := <-done
	if firstErr != nil {
		groupErr = firstErr
	}
	switch {
	case writeErr != nil:
		runErr = errors.Join(writeErr, groupErr)
	case groupErr != nil:
		runErr = groupErr
	case ctx.Err() != nil:
		runErr = ctx.Err()
	}
	stats.summary.Status = "completed"
	if ctx.Err() != nil {
		stats.summary.Status = "canceled"
	} else if runErr != nil {
		stats.summary.Status = "failed"
	}
	stats.summary.Attempts = stats.attempts.Load()
	stats.summary.Diagnostics = diagnostics.snapshot()
	stats.summary.FinishedAt = time.Now().UTC()
	stats.summary.Duration = time.Since(started)
	if runErr != nil {
		stats.summary.Error = runErr.Error()
	}
	summary = stats.summary
	if writeErr == nil {
		if err := writer.WriteSummary(writeCtx, summary); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("write summary: %w", err))
		}
	}
	return summary, runErr
}
