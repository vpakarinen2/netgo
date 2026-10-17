package targets

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, name string) ([]netip.Addr, error) {
	return f(ctx, network, name)
}

func planOptions() Options {
	return Options{MaxHosts: 65536, DNSConcurrency: 2, DNSTimeout: time.Second}
}

func TestPlanUnionAndHostnameMetadata(t *testing.T) {
	options := planOptions()
	var lookups atomic.Int32
	options.Resolver = resolverFunc(func(_ context.Context, network, name string) ([]netip.Addr, error) {
		lookups.Add(1)
		if network != "ip" || name != "example.test" {
			t.Errorf("unexpected lookup: %s %s", network, name)
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("::ffff:192.0.2.2")}, nil
	})
	plan, err := NewPlan(context.Background(), []string{"192.0.2.1/30", "192.0.2.2/31", "::ffff:192.0.2.2", "Example.Test", "example.test", "2001:db8::/127"}, options)
	if err != nil {
		t.Fatal(err)
	}
	if plan.HostCount() != 6 || lookups.Load() != 1 {
		t.Fatalf("count=%d, lookups=%d", plan.HostCount(), lookups.Load())
	}
	var hosts []Host
	if err := plan.ForEach(context.Background(), func(host Host) error { hosts = append(hosts, host); return nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::", "2001:db8::1"}
	for i, host := range hosts {
		if host.Address.String() != want[i] {
			t.Fatalf("host %d: got %s, want %s", i, host.Address, want[i])
		}
		if host.Address.String() == "192.0.2.2" && host.Hostname != "example.test" {
			t.Fatal("hostname was lost when deduplicating CIDR and DNS targets")
		}
	}
	if _, err := plan.ProbeCount(3, 17); err == nil {
		t.Fatal("host/port product exceeded its limit")
	}
	if got, err := plan.ProbeCount(3, 18); err != nil || got != 18 {
		t.Fatalf("count=%d, error=%v", got, err)
	}
}

func TestPlanAddressBoundaries(t *testing.T) {
	for _, tc := range []struct {
		inputs []string
		count  uint64
	}{
		{[]string{"255.255.255.255/32"}, 1},
		{[]string{"255.255.255.254/31", "255.255.255.255"}, 2},
		{[]string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"}, 1},
		{[]string{"2001:db8::ffff:ffff:ffff:ffff", "2001:db8:0:1::"}, 2},
		{[]string{"::ffff:192.0.2.0/126", "192.0.2.0/30"}, 4},
		{[]string{"2001:db8::/126", "2001:db8::2/127", "2001:db8::4/126"}, 8},
	} {
		plan, err := NewPlan(context.Background(), tc.inputs, planOptions())
		if err != nil {
			t.Fatal(err)
		}
		var count uint64
		if err := plan.ForEach(context.Background(), func(Host) error { count++; return nil }); err != nil {
			t.Fatal(err)
		}
		if count != tc.count || plan.HostCount() != count {
			t.Fatalf("%v: got %d/%d, want %d", tc.inputs, count, plan.HostCount(), tc.count)
		}
	}
}

func TestPlanRejectsBeforeDNS(t *testing.T) {
	for _, input := range []string{"::/0", "0.0.0.0/0", "192.0.2.1/99", "http://localhost", "localhost:80", "999.999.999.999", "192.0.2.01", "fe80::1%eth0", "bad..test", "-bad.test", "", strings.Repeat("a", 64) + ".test"} {
		t.Run(input, func(t *testing.T) {
			options := planOptions()
			options.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				t.Error("resolver called before all target syntax and CIDR bounds were checked")
				return nil, errors.New("unexpected lookup")
			})
			if _, err := NewPlan(context.Background(), []string{"example.test", input}, options); err == nil {
				t.Fatalf("accepted %q", input)
			}
		})
	}
}

func TestPlanLimitUsesUniqueAddresses(t *testing.T) {
	options := planOptions()
	options.MaxHosts = 4
	if plan, err := NewPlan(context.Background(), []string{"192.0.2.0/30", "192.0.2.1", "192.0.2.2/31"}, options); err != nil || plan.HostCount() != 4 {
		t.Fatalf("overlap should fit: plan=%v, error=%v", plan, err)
	}
	if _, err := NewPlan(context.Background(), []string{"192.0.2.0/30", "192.0.2.4"}, options); err == nil {
		t.Fatal("disjoint additional host exceeded limit")
	}
}

func TestLargePlanIsLazyAndCancellable(t *testing.T) {
	plan, err := NewPlan(context.Background(), []string{"2001:db8::/112"}, planOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.spans) != 1 || plan.HostCount() != 65536 {
		t.Fatal("subnet was not represented by a single interval")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	err = plan.ForEach(ctx, func(Host) error {
		calls++
		if calls == 2 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || calls != 2 {
		t.Fatalf("iteration did not stop: calls=%d, error=%v", calls, err)
	}
}

func TestDNSConcurrencyAndFailure(t *testing.T) {
	options := planOptions()
	var active, peak, calls atomic.Int32
	options.Resolver = resolverFunc(func(ctx context.Context, _, name string) ([]netip.Addr, error) {
		calls.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for previous := peak.Load(); current > previous && !peak.CompareAndSwap(previous, current); previous = peak.Load() {
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
	})
	inputs := []string{"a.test", "b.test", "c.test", "d.test", "a.test"}
	plan, err := NewPlan(context.Background(), inputs, options)
	if err != nil || plan.HostCount() != 1 || calls.Load() != 4 || peak.Load() > 2 || active.Load() != 0 {
		t.Fatalf("DNS pool failure: plan=%v, calls=%d peak=%d active=%d err=%v", plan, calls.Load(), peak.Load(), active.Load(), err)
	}
	options.DNSTimeout = 10 * time.Millisecond
	options.Resolver = resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() })
	if _, err := NewPlan(context.Background(), inputs, options); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DNS deadline lost: %v", err)
	}
	for _, answer := range [][]netip.Addr{nil, make([]netip.Addr, MaxDNSAnswers+1), {{}}} {
		options.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return answer, nil })
		if _, err := NewPlan(context.Background(), []string{"a.test"}, options); err == nil {
			t.Fatal("invalid DNS answer was accepted")
		}
	}
}

func FuzzSpanUnion(f *testing.F) {
	f.Add(uint8(1), uint8(7), uint8(4), uint8(12))
	f.Add(uint8(255), uint8(255), uint8(0), uint8(0))
	f.Fuzz(func(t *testing.T, a, b, c, d uint8) {
		a, b = min(a, b), max(a, b)
		c, d = min(c, d), max(c, d)
		addr := func(last uint8) netip.Addr { return netip.AddrFrom4([4]byte{192, 0, 2, last}) }
		merged, count, err := mergeSpans([]span{{addr(a), addr(b)}, {addr(c), addr(d)}}, 256)
		if err != nil {
			t.Fatal(err)
		}
		want := uint64(0)
		for i := 0; i < 256; i++ {
			if i >= int(a) && i <= int(b) || i >= int(c) && i <= int(d) {
				want++
			}
		}
		if count != want || len(merged) > 2 {
			t.Fatal(fmt.Sprintf("union count=%d, want=%d", count, want))
		}
	})
}
