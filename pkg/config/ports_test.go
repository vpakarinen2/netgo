package config

import (
	"strings"
	"testing"

	"github.com/vpakarinen2/netgo/pkg/network/targets"
)

func TestPortSelectorPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, envPorts, envTop string
		args                         []string
		count, top                   int
		wantError                    string
	}{
		{name: "default", count: 3},
		{name: "file preset", yaml: "scan:\n  top_ports: 100\n", count: 100, top: 100},
		{name: "env preset over file ports", yaml: "scan:\n  ports: '8080'\n", envTop: "10", count: 10, top: 10},
		{name: "flag preset over env ports", envPorts: "8080", args: []string{"--top-ports", "1000"}, count: 1000, top: 1000},
		{name: "env ports over file preset", yaml: "scan:\n  top_ports: 100\n", envPorts: "8443", count: 1},
		{name: "flag ports over env preset", envTop: "100", args: []string{"--ports", "22,80,443"}, count: 3},
		{name: "flag ports override malformed env selector", envTop: "ten", args: []string{"--ports", "80"}, count: 1},
		{name: "flag disables preset", envTop: "100", args: []string{"--top-ports", "0"}, count: 3},
		{name: "both flags disabled", args: []string{"--ports", "8443", "--top-ports", "0"}, count: 1},
		{name: "both flags", args: []string{"--ports", "80", "--top-ports", "10"}, wantError: "alternatives"},
		{name: "both env", envPorts: "80", envTop: "10", wantError: "alternatives"},
		{name: "both file", yaml: "scan:\n  ports: '80'\n  top_ports: 10\n", wantError: "alternatives"},
		{name: "higher flag resolves file conflict", yaml: "scan:\n  ports: '80'\n  top_ports: 10\n", args: []string{"--top-ports", "100"}, count: 100, top: 100},
		{name: "invalid count", args: []string{"--top-ports", "50"}, wantError: "10, 100, or 1000"},
		{name: "negative count", envTop: "-1", wantError: "scan.top_ports"},
		{name: "non integer", envTop: "ten", wantError: "integer"},
		{name: "fraction", envTop: "10.5", wantError: "integer"},
		{name: "UDP", args: []string{"--transport", "udp", "--top-ports", "10"}, wantError: "TCP only"},
		{name: "UDP explicit ports override TCP preset", envTop: "100", args: []string{"--transport", "udp", "--ports", "53,123"}, count: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv(t)
			path := ""
			if tc.yaml != "" {
				path = writeConfig(t, tc.yaml)
			}
			if tc.envPorts != "" {
				t.Setenv("NETGO_SCAN_PORTS", tc.envPorts)
			}
			if tc.envTop != "" {
				t.Setenv("NETGO_SCAN_TOP_PORTS", tc.envTop)
			}
			flags := testFlags()
			if err := flags.Parse(tc.args); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path, flags)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("got %v, want %s", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			ports, err := targets.ParsePorts(cfg.Scan.Ports)
			if err != nil || len(ports) != tc.count || cfg.Scan.TopPorts != tc.top {
				t.Fatalf("unexpected selection: count=%d top=%d err=%v", len(ports), cfg.Scan.TopPorts, err)
			}
		})
	}
}
