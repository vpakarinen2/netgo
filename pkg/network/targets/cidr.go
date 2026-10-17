package targets

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"sort"
)

type span struct{ first, last netip.Addr }

// prefixSpan computes endpoints without enumerating addresses. IPv4 network
// and broadcast addresses are included, including /31 and /32 prefixes.
func prefixSpan(prefix netip.Prefix, limit uint64) (span, error) {
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return span{}, fmt.Errorf("mapped IPv4 prefix must have at least 96 prefix bits")
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits >= 64 || uint64(1)<<hostBits > limit {
		return span{}, fmt.Errorf("CIDR %s exceeds the %d host limit", prefix, limit)
	}
	first := prefix.Masked().Addr()
	last := first.As16()
	for bit := 0; bit < hostBits; bit++ {
		last[15-bit/8] |= 1 << (bit % 8)
	}
	end := netip.AddrFrom16(last)
	if first.Is4() {
		end = end.Unmap()
	}
	return span{first, end}, nil
}

// spanSize saturates at limit+1, even for a range covering all of IPv6.
func spanSize(s span, limit uint64) uint64 {
	a, b := s.first.As16(), s.last.As16()
	low, borrow := bits.Sub64(binary.BigEndian.Uint64(b[8:]), binary.BigEndian.Uint64(a[8:]), 0)
	high, _ := bits.Sub64(binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(a[:8]), borrow)
	if high != 0 || low >= limit {
		return limit + 1
	}
	return low + 1
}

func mergeSpans(spans []span, limit uint64) ([]span, uint64, error) {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].first == spans[j].first {
			return spans[i].last.Compare(spans[j].last) < 0
		}
		return spans[i].first.Compare(spans[j].first) < 0
	})
	merged := spans[:0]
	for _, next := range spans {
		if len(merged) == 0 {
			merged = append(merged, next)
			continue
		}
		previous := &merged[len(merged)-1]
		adjacent := previous.last.Next()
		if previous.first.Is4() == next.first.Is4() && (next.first.Compare(previous.last) <= 0 || next.first == adjacent) {
			if next.last.Compare(previous.last) > 0 {
				previous.last = next.last
			}
		} else {
			merged = append(merged, next)
		}
	}
	var count uint64
	for _, s := range merged {
		size := spanSize(s, limit)
		if size > limit-count {
			return nil, 0, fmt.Errorf("targets exceed the %d unique host limit", limit)
		}
		count += size
	}
	return merged, count, nil
}
