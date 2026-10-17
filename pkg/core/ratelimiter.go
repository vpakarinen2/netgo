package core

import (
	"context"
	"time"

	"golang.org/x/time/rate"
)

// waitToken uses reservations so cancellation consistently returns the context
// error, including when the next token would be past a context deadline.
func waitToken(ctx context.Context, limiter *rate.Limiter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	reservation := limiter.Reserve()
	delay := reservation.Delay()
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		reservation.Cancel()
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}
