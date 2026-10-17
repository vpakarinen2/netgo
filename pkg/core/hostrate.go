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
	global   *rate.Limiter
	hostRate int
	seed     maphash.Seed
	mu       sync.Mutex
	hosts    [hostRateBuckets]*rate.Limiter
}

func newConnectionBudget(globalRate, hostRate int) *connectionBudget {
	return &connectionBudget{global: rate.NewLimiter(rate.Limit(globalRate), 1), hostRate: hostRate, seed: maphash.MakeSeed()}
}

func (b *connectionBudget) wait(ctx context.Context, address netip.Addr) error {
	if b.hostRate == 0 {
		return waitToken(ctx, b.global)
	}
	data := address.Unmap().As16()
	index := maphash.Bytes(b.seed, data[:]) % hostRateBuckets
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		b.mu.Lock()
		host := b.hosts[index]
		if host == nil {
			host = rate.NewLimiter(rate.Limit(b.hostRate), 1)
			b.hosts[index] = host
		}
		now := time.Now()
		delay := max(tokenDelay(b.global, now), tokenDelay(host, now))
		if delay <= 0 {
			b.global.AllowN(now, 1)
			host.AllowN(now, 1)
			b.mu.Unlock()
			return ctx.Err()
		}
		b.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func tokenDelay(limiter *rate.Limiter, now time.Time) time.Duration {
	missing := 1 - limiter.TokensAt(now)
	if missing <= 0 {
		return 0
	}
	return time.Duration(math.Ceil(missing / float64(limiter.Limit()) * float64(time.Second)))
}
