package targets

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type Host struct {
	Address  netip.Addr
	Hostname string
}

type Options struct {
	MaxHosts       uint64
	DNSConcurrency int
	DNSTimeout     time.Duration
	Resolver       Resolver
}

// Plan stores merged address intervals, never a materialized subnet. DNS
// metadata is bounded by MaxPlanRanges. A plan is immutable after construction.
type Plan struct {
	spans     []span
	hostnames map[netip.Addr]string
	count     uint64
}

func NewPlan(ctx context.Context, inputs []string, options Options) (*Plan, error) {
	if options.MaxHosts < 1 || options.MaxHosts > 1000000 || options.DNSConcurrency < 1 || options.DNSConcurrency > 256 || options.DNSTimeout <= 0 || options.DNSTimeout > time.Minute {
		return nil, fmt.Errorf("invalid target planning options")
	}
	if len(inputs) == 0 || len(inputs) > MaxInputs {
		return nil, fmt.Errorf("expected 1-%d target arguments", MaxInputs)
	}
	var spans []span
	var names []string
	seenNames := make(map[string]bool)
	// Parse every input before starting DNS, including checking CIDR sizes.
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if addr, err := netip.ParseAddr(input); err == nil {
			if addr.Zone() != "" {
				return nil, fmt.Errorf("scoped IPv6 targets are not supported: %q", input)
			}
			addr = addr.Unmap()
			spans = append(spans, span{addr, addr})
		} else if prefix, err := netip.ParsePrefix(input); err == nil {
			s, err := prefixSpan(prefix, options.MaxHosts)
			if err != nil {
				return nil, err
			}
			spans = append(spans, s)
		} else {
			if !ValidHostname(input) || looksLikeIPv4(input) {
				return nil, fmt.Errorf("invalid target %q: expected an IP address, CIDR, or ASCII hostname", input)
			}
			name := strings.ToLower(input)
			if !seenNames[name] {
				names = append(names, name)
				seenNames[name] = true
			}
		}
	}
	// Fail excessive literal ranges before issuing even DNS queries.
	if _, _, err := mergeSpans(append([]span(nil), spans...), options.MaxHosts); err != nil {
		return nil, err
	}
	answers, err := resolveAll(ctx, names, options.Resolver, options.DNSConcurrency, options.DNSTimeout)
	if err != nil {
		return nil, err
	}
	hostnames := make(map[netip.Addr]string)
	for i, addresses := range answers {
		if len(spans)+len(addresses) > MaxPlanRanges {
			return nil, fmt.Errorf("target plan exceeds %d address records", MaxPlanRanges)
		}
		for _, addr := range addresses {
			if !addr.IsValid() || addr.Zone() != "" {
				return nil, fmt.Errorf("resolve %q: invalid or scoped address", names[i])
			}
			addr = addr.Unmap()
			spans = append(spans, span{addr, addr})
			if _, exists := hostnames[addr]; !exists {
				hostnames[addr] = strings.TrimSuffix(names[i], ".")
			}
		}
	}
	merged, count, err := mergeSpans(spans, options.MaxHosts)
	if err != nil {
		return nil, err
	}
	return &Plan{spans: merged, hostnames: hostnames, count: count}, nil
}

func looksLikeIPv4(input string) bool {
	if !strings.Contains(input, ".") {
		return false
	}
	for _, c := range input {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (p *Plan) HostCount() uint64 { return p.count }

// ProbeCount checks the host/port product before dispatch, without overflow.
func (p *Plan) ProbeCount(ports int, limit uint64) (uint64, error) {
	if ports < 1 || limit == 0 || p.count > limit/uint64(ports) {
		return 0, fmt.Errorf("scan exceeds the %d host/port pair limit", limit)
	}
	return p.count * uint64(ports), nil
}

// ForEach lazily yields each unique address in ascending numeric order.
func (p *Plan) ForEach(ctx context.Context, yield func(Host) error) error {
	for _, s := range p.spans {
		for addr := s.first; ; addr = addr.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := yield(Host{Address: addr, Hostname: p.hostnames[addr]}); err != nil {
				return err
			}
			if addr == s.last {
				break
			}
		}
	}
	return ctx.Err()
}
