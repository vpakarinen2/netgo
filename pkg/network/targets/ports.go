// Package targets validates and expands scanner target specifications.
package targets

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePorts parses comma-separated ports and inclusive ranges. The result is
// sorted and deduplicated, and never contains port zero.
func ParsePorts(spec string) ([]uint16, error) {
	var seen [65536]bool
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("empty port or range")
		}
		parts := strings.Split(item, "-")
		if len(parts) > 2 {
			return nil, fmt.Errorf("invalid port range %q", item)
		}
		first, err := parsePort(parts[0])
		if err != nil {
			return nil, err
		}
		last := first
		if len(parts) == 2 {
			last, err = parsePort(parts[1])
			if err != nil {
				return nil, err
			}
			if last < first {
				return nil, fmt.Errorf("descending port range %q", item)
			}
		}
		for port := first; port <= last; port++ {
			seen[port] = true
		}
	}
	ports := make([]uint16, 0)
	for port := 1; port < len(seen); port++ {
		if seen[port] {
			ports = append(ports, uint16(port))
		}
	}
	return ports, nil
}

func parsePort(value string) (int, error) {
	value = strings.TrimSpace(value)
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("invalid port %q: expected an integer from 1 to 65535", value)
		}
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q: expected an integer from 1 to 65535", value)
	}
	return port, nil
}
