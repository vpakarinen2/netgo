package core

import (
	"context"
	"hash/maphash"
	"math"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const hostRateBuckets = 1024

// connectionBudget uses a fixed-size hashed host table. Collisions share a
// conservative budget instead of evicting active hosts or growing with CIDRs.
// Tokens are consumed together at dispatch time, not reserved before another
// limiter's wait, so delayed workers cannot bunch sends beyond either budget.
type connectionBudget struct {
	global          *rate.Limiter
	hostRate        int
	hostConcurrency int
	seed            maphash.Seed
	mu              sync.Mutex
	hosts           [hostRateBuckets]*rate.Limiter
	active          [hostRateBuckets]int
	changed         chan struct{}
}

// acquire bounds both probes and inspection sockets. Buckets are fixed-size;
// collisions conservatively share capacity. No lock is held while waiting.
func (b *connectionBudget) acquire(ctx context.Context, address netip.Addr) (func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		changed := b.changes()
		release, delay := b.tryAcquire(address)
		if release != nil {
			return release, nil
		}
		var tick <-chan time.Time
		var timer *time.Timer
		if delay > 0 {
			timer = time.NewTimer(delay)
			tick = timer.C
		}
		select {
		case <-ctx.Done():
		case <-changed:
		case <-tick:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func newConnectionBudget(globalRate, hostRate int) *connectionBudget {
	return &connectionBudget{global: rate.NewLimiter(rate.Limit(globalRate), 1), hostRate: hostRate, seed: maphash.MakeSeed(), changed: make(chan struct{})}
}

func (b *connectionBudget) changes() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.changed
}

// tryAcquire consumes capacity and both tokens together, or consumes nothing.
// A zero delay with no lease means a connection release must wake the caller.
func (b *connectionBudget) tryAcquire(address netip.Addr) (func(), time.Duration) {
	data := address.Unmap().As16()
	index := maphash.Bytes(b.seed, data[:]) % hostRateBuckets
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.hostConcurrency > 0 && b.active[index] >= b.hostConcurrency {
		return nil, 0
	}
	now := time.Now()
	delay := tokenDelay(b.global, now)
	if b.hostRate > 0 {
		host := b.hosts[index]
		if host == nil {
			host = rate.NewLimiter(rate.Limit(b.hostRate), 1)
			b.hosts[index] = host
		}
		delay = max(delay, tokenDelay(host, now))
	}
	if delay > 0 {
		return nil, delay
	}
	b.global.AllowN(now, 1)
	if b.hostRate > 0 {
		b.hosts[index].AllowN(now, 1)
	}
	b.active[index]++
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.active[index]--
			close(b.changed)
			b.changed = make(chan struct{})
		})
	}, 0
}

func tokenDelay(limiter *rate.Limiter, now time.Time) time.Duration {
	missing := 1 - limiter.TokensAt(now)
	if missing <= 0 {
		return 0
	}
	return time.Duration(math.Ceil(missing / float64(limiter.Limit()) * float64(time.Second)))
}
