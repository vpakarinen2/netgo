package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/vpakarinen2/netgo/pkg/output"
)

func TestTop1000FindsKnownLocalListenerWithStats(t *testing.T) {
	var listener net.Listener
	var err error
	for _, port := range []int{8080, 8443, 8888, 5900, 9999, 8000, 8008} {
		listener, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("cannot start local preset fixture: %v", err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"127.0.0.1", "--top-ports", "1000", "--timeout", "1s", "--rate", "1000", "--tcp-host-rate", "1000", "--tcp-host-concurrency", "8", "--concurrency", "16", "--stats", "--format", "ndjson", "--quiet"})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&stdout)
	var found, summarySeen bool
	for decoder.More() {
		var event output.Event
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.Result != nil && event.Result.Target.Port == port {
			found = event.Result.State == "open"
		}
		if event.Summary != nil {
			summarySeen = true
			s := event.Summary
			d := s.Diagnostics
			if s.Total != 1000 || s.Completed != 1000 || d == nil || d.PortAttempts != 1000 || d.ActiveConnections != 0 || d.PeakConnections > 8 || len(d.Hosts) != 1 || len(d.Settings) == 0 {
				t.Fatalf("bad final summary: %+v diagnostics=%+v", s, d)
			}
		}
	}
	if !found || !summarySeen || stderr.Len() != 0 {
		t.Fatalf("listener found=%v summary=%v stderr=%q", found, summarySeen, stderr.String())
	}
}
