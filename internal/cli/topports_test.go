package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/vpakarinen2/netgo/pkg/network/targets"
	"github.com/vpakarinen2/netgo/pkg/output"
)

func TestTopPortsCheckConfig(t *testing.T) {
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"--check-config", "--top-ports", "1000"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	// Durations have a separate JSON representation; decode only scan selectors.
	var actual struct {
		Scan struct {
			Ports    string `json:"ports"`
			TopPorts int    `json:"top_ports"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(out.Bytes(), &actual); err != nil {
		t.Fatal(err)
	}
	ports, err := targets.ParsePorts(actual.Scan.Ports)
	if err != nil || len(ports) != 1000 || actual.Scan.TopPorts != 1000 {
		t.Fatalf("unexpected config: %s", out.String())
	}
}

func TestTopPortsHonorsProbeLimit(t *testing.T) {
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"127.0.0.1", "--top-ports", "1000", "--max-probes", "999"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "host/port pair limit") || out.Len() != 0 {
		t.Fatalf("err=%v output=%s", err, out.String())
	}
}

func TestTopPortsScanLoopback(t *testing.T) {
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"127.0.0.1", "--top-ports", "10", "--timeout", "100ms", "--rate", "1000", "--format", "ndjson", "--quiet"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	want, _ := targets.TopPorts(10)
	seen := make(map[uint16]bool)
	decoder := json.NewDecoder(&out)
	var summarySeen bool
	for {
		var event output.Event
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if event.Result != nil {
			seen[event.Result.Target.Port] = true
		}
		if event.Summary != nil {
			summarySeen = true
			if event.Summary.Total != 10 || event.Summary.Completed != 10 {
				t.Fatalf("unexpected summary: %+v", event.Summary)
			}
		}
	}
	if !summarySeen || len(seen) != 10 {
		t.Fatalf("summary=%v ports=%v", summarySeen, seen)
	}
	for _, port := range want {
		if !seen[port] {
			t.Fatalf("missing port %d", port)
		}
	}
}
