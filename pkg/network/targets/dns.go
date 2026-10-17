package targets

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	MaxInputs     = 4096
	MaxDNSAnswers = 256
	MaxPlanRanges = 65536
)

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// ValidHostname validates an ASCII DNS hostname, allowing a final dot.
func ValidHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// resolveAll is a per-plan deduplication cache. Each unique name is looked up
// once, with a bounded worker pool and a separate deadline for each lookup.
func resolveAll(ctx context.Context, names []string, resolver Resolver, concurrency int, timeout time.Duration) ([][]netip.Addr, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	answers := make([][]netip.Addr, len(names))
	var answerCount atomic.Int64
	group, workCtx := errgroup.WithContext(ctx)
	jobs := make(chan int)
	group.Go(func() error {
		defer close(jobs)
		for i := range names {
			select {
			case jobs <- i:
			case <-workCtx.Done():
				return workCtx.Err()
			}
		}
		return nil
	})
	for worker := 0; worker < min(concurrency, len(names)); worker++ {
		group.Go(func() error {
			for {
				select {
				case <-workCtx.Done():
					return workCtx.Err()
				case i, ok := <-jobs:
					if !ok {
						return nil
					}
					lookupCtx, cancel := context.WithTimeout(workCtx, timeout)
					addresses, err := resolver.LookupNetIP(lookupCtx, "ip", names[i])
					cancel()
					if err != nil {
						return fmt.Errorf("resolve %q: %w", names[i], err)
					}
					if len(addresses) == 0 || len(addresses) > MaxDNSAnswers {
						return fmt.Errorf("resolve %q: expected 1-%d addresses, got %d", names[i], MaxDNSAnswers, len(addresses))
					}
					if answerCount.Add(int64(len(addresses))) > MaxPlanRanges {
						return fmt.Errorf("DNS answers exceed %d address records", MaxPlanRanges)
					}
					answers[i] = addresses
				}
			}
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return answers, ctx.Err()
}
