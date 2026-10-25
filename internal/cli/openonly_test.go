package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpakarinen2/netgo/pkg/output"
)

func TestOpenOnlyServiceOutputAndFile(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("SSH-2.0-fixture\r\n"))
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()
	openPort := listener.Addr().(*net.TCPAddr).Port
	for _, format := range []string{"console", "text", "ndjson"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "results.txt")
			cmd := NewCommand("test")
			cmd.SetArgs([]string{"127.0.0.1", "-p", fmt.Sprintf("%d,%d", openPort, closedPort), "--open-only", "--stats", "--service", "--service-active=false", "--format", format, "--quiet", "--output", path})
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(data, stdout.Bytes()) {
				t.Fatalf("file mismatch: %v", err)
			}
			if stderr.Len() != 0 {
				t.Fatalf("quiet output: %s", stderr.String())
			}
			if format != "ndjson" {
				if strings.Contains(stdout.String(), fmt.Sprintf("%d/tcp", closedPort)) || !strings.Contains(stdout.String(), "ssh") || !strings.Contains(stdout.String(), "1 result rows shown") {
					t.Fatalf("unexpected console: %s", stdout.String())
				}
				return
			}
			lines := bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n"))
			if len(lines) != 2 {
				t.Fatalf("expected one result and one summary: %s", stdout.String())
			}
			var result, summary output.Event
			if err := json.Unmarshal(lines[0], &result); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(lines[1], &summary); err != nil {
				t.Fatal(err)
			}
			if result.Result == nil || result.Result.State != "open" || result.Result.Service == nil || result.Result.Service.Name != "ssh" {
				t.Fatalf("service lost: %+v", result)
			}
			s := summary.Summary
			if s == nil || !s.OpenOnly || s.Reported != 1 || s.Completed != 2 || s.Closed != 1 || s.Diagnostics == nil || s.Diagnostics.PortAttempts != 2 {
				t.Fatalf("counts changed: %+v", s)
			}
		})
	}
}
