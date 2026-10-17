package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vpakarinen2/netgo/pkg/output"
)

func TestScanLocalTCPToNDJSONAndFile(t *testing.T) {
	openListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer openListener.Close()
	closedListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closedListener.Addr().(*net.TCPAddr).Port
	if err := closedListener.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "scan.ndjson")
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"127.0.0.1", "127.0.0.1/32", "--ports", fmt.Sprintf("%d,%d", openListener.Addr().(*net.TCPAddr).Port, closedPort), "--timeout", "5s", "--rate", "1000", "--format", "ndjson", "--output", path})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	emitted := append([]byte(nil), stdout.Bytes()...)
	decoder := json.NewDecoder(bytes.NewReader(emitted))
	states := make(map[string]int)
	results := 0
	for {
		var event output.Event
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if event.SchemaVersion != 1 {
			t.Fatal("missing schema version")
		}
		switch event.Type {
		case "result":
			if event.Result == nil || event.Result.Attempts != 1 {
				t.Fatalf("invalid result: %+v", event)
			}
			results++
			states[string(event.Result.State)]++
		case "summary":
			if event.Summary == nil || event.Summary.Status != "completed" || event.Summary.Total != 2 || event.Summary.Completed != 2 || event.Summary.Open != 1 || event.Summary.Closed != 1 {
				t.Fatalf("invalid summary: %+v", event.Summary)
			}
		default:
			t.Fatalf("unexpected event type: %s", event.Type)
		}
	}
	if results != 2 || states["open"] != 1 || states["closed"] != 1 || !strings.Contains(stderr.String(), "0/2 completed") {
		t.Fatalf("results=%d states=%v diagnostics=%q", results, states, stderr.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, emitted) || strings.Count(string(data), "\n") != 3 {
		t.Fatalf("file does not contain two results and one summary: %s", data)
	}
}

func TestConsoleScanQuiet(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"127.0.0.1", "-p", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port), "--quiet"})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Scan completed: 1/1 completed, 1 open") || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestPreflightBeforeOutputCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "must-not-exist.ndjson")
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"127.0.0.1", "-p", "1-3", "--max-probes", "2", "--output", path})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "host/port pair limit") {
		t.Fatalf("pair limit was not enforced: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) || stdout.Len() != 0 {
		t.Fatal("output was created before preflight finished")
	}
}

func TestScanFailsOnBrokenOutput(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"127.0.0.1", "-p", fmt.Sprint(listener.Addr().(*net.TCPAddr).Port), "--format", "ndjson", "--quiet"})
	cmd.SetOut(brokenWriter{})
	if err := cmd.Execute(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output failure did not fail the scan: %v", err)
	}
}

func TestServiceIdentificationCLIIsOptInAndStreamsMetadata(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "HEAD" || !strings.HasPrefix(r.Host, "virtual.test:") {
			t.Errorf("unexpected service request: %s %s", r.Method, r.Host)
		}
		w.Header().Set("Server", "cli-fixture/1.2.3")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	port := fmt.Sprint(server.Listener.Addr().(*net.TCPAddr).Port)
	for _, enabled := range []bool{false, true} {
		cmd := NewCommand("test")
		args := []string{"127.0.0.1", "-p", port, "--format", "ndjson", "--quiet"}
		if enabled {
			args = append(args, "--service", "--sni", "virtual.test")
		}
		cmd.SetArgs(args)
		var out bytes.Buffer
		cmd.SetOut(&out)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(&out)
		var result, summary output.Event
		if err := decoder.Decode(&result); err != nil {
			t.Fatal(err)
		}
		if err := decoder.Decode(&summary); err != nil {
			t.Fatal(err)
		}
		if result.Result == nil || result.Result.State != "open" || summary.Summary == nil || summary.Summary.Open != 1 || summary.Summary.Status != "completed" {
			t.Fatalf("invalid scan results: %+v %+v", result, summary)
		}
		if enabled {
			if result.Result.Service == nil || result.Result.Service.Name != "http" || result.Result.Service.Product != "cli-fixture" || result.Result.Identification.Status != "identified" {
				t.Fatalf("missing service metadata: %+v", result.Result)
			}
		} else if result.Result.Service != nil || result.Result.Identification != nil || requests.Load() != 0 {
			t.Fatal("default scan sent service probes")
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("unexpected number of HTTP requests: %d", requests.Load())
	}
}
