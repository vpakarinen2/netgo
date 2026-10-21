package core

import (
	"context"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network/targets"
)

// Only this many hosts have scheduling state, regardless of CIDR size.
const maxScheduledHosts = 256

type probeJob struct {
	target  model.Target
	host    *scheduledHost
	attempt int
	waiting time.Time
	release func()
	retry   bool
}

type scheduledHost struct {
	host     targets.Host
	nextPort int
	active   int
	waiting  time.Time
	retries  []probeJob
}

// scheduleProbes rotates over a bounded host window, skipping exhausted rate
// and connection budgets. Workers receive one already-admitted attempt at a
// time; retries return to the scheduler rather than tying up waiting workers.
func scheduleProbes(ctx context.Context, hosts <-chan targets.Host, ports []uint16, transport model.Transport, window int, budget *connectionBudget, diagnostics *diagnostics, ready <-chan chan probeJob, finished <-chan probeJob, stopped chan<- struct{}) error {
	defer close(stopped)
	var active []*scheduledHost
	addHost := func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case host, ok := <-hosts:
			if ok {
				active = append(active, &scheduledHost{host: host})
			}
			return nil
		}
	}
	for len(active) < window {
		previous := len(active)
		if err := addHost(); err != nil {
			return err
		}
		if len(active) == previous {
			break
		}
	}
	var idle []chan probeJob
	cursor := 0
	for len(active) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		changed := budget.changes() // Snapshot before checking eligibility.
		var delay time.Duration
		dispatched := false
		if len(idle) > 0 {
			for offset := 0; offset < len(active); offset++ {
				index := (cursor + offset) % len(active)
				host := active[index]
				var job probeJob
				if len(host.retries) > 0 {
					job = host.retries[0]
				} else if host.nextPort < len(ports) {
					if host.waiting.IsZero() {
						host.waiting = time.Now()
					}
					job = probeJob{host: host, target: model.Target{Address: host.host.Address, Hostname: host.host.Hostname, Port: ports[host.nextPort], Transport: transport}, attempt: 1, waiting: host.waiting}
				} else {
					continue
				}
				release, wait := budget.tryAcquire(job.target.Address)
				if release == nil {
					if wait > 0 && (delay == 0 || wait < delay) {
						delay = wait
					}
					continue
				}
				finishedLease := diagnostics.acquired(time.Since(job.waiting))
				job.release = func() { finishedLease(); release() }
				worker := idle[len(idle)-1]
				select {
				case worker <- job:
				case <-ctx.Done():
					job.release()
					return ctx.Err()
				}
				idle = idle[:len(idle)-1]
				if len(host.retries) > 0 {
					host.retries = host.retries[1:]
				} else {
					host.nextPort++
					host.waiting = time.Time{}
				}
				host.active++
				cursor = (index + 1) % len(active)
				dispatched = true
				break
			}
		}
		if dispatched {
			continue
		}
		var timer *time.Timer
		var tick <-chan time.Time
		if delay > 0 {
			timer = time.NewTimer(delay)
			tick = timer.C
		}
		select {
		case <-ctx.Done():
		case <-changed:
		case <-tick:
		case worker := <-ready:
			idle = append(idle, worker)
		case job := <-finished:
			host := job.host
			host.active--
			if job.retry {
				job.attempt++
				job.retry, job.release, job.waiting = false, nil, time.Now()
				host.retries = append(host.retries, job)
			}
			if host.active == 0 && host.nextPort == len(ports) && len(host.retries) == 0 {
				for index, candidate := range active {
					if candidate == host {
						active = append(active[:index], active[index+1:]...)
						if index < cursor {
							cursor--
						}
						break
					}
				}
				if err := addHost(); err != nil {
					if timer != nil {
						timer.Stop()
					}
					return err
				}
				if len(active) > 0 {
					cursor %= len(active)
				}
			}
		}
		if timer != nil {
			timer.Stop()
		}
	}
	return ctx.Err()
}
