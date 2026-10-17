package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vpakarinen2/netgo/pkg/network/targets"
)

// Port selectors compete as a unit across flags > environment > YAML > defaults.
// A same-layer ambiguity is rejected rather than silently merging scan scopes.
func (c *Config) selectPorts(portsPriority, topPriority int) error {
	if portsPriority > topPriority {
		c.Scan.TopPorts = 0
	}
	if c.Scan.TopPorts == 0 {
		return nil
	}
	if portsPriority == topPriority && portsPriority > 0 {
		return fmt.Errorf("scan.ports (--ports) and scan.top_ports (--top-ports) are alternatives; set only one at the same configuration level")
	}
	ports, err := targets.TopPorts(c.Scan.TopPorts)
	if err != nil {
		return fmt.Errorf("scan.top_ports: %w", err)
	}
	values := make([]string, len(ports))
	for i, port := range ports {
		values[i] = strconv.Itoa(int(port))
	}
	// Keep --check-config and the dispatcher aligned on the exact selected ports.
	c.Scan.Ports = strings.Join(values, ",")
	return nil
}
