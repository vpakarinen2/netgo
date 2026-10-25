package output

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func sampleResult() model.Result {
	return model.Result{
		Target: model.Target{Address: netip.MustParseAddr("2001:db8::1"), Port: 443, Transport: model.TCP, Hostname: "example.test"},
		Method: model.TCPConnect, State: model.Open, Reason: "connected", Attempts: 1, ObservedAt: time.Now().UTC(), Duration: time.Millisecond,
	}
}

func TestNDJSONStreamingSchema(t *testing.T) {
	var out bytes.Buffer
	writer := NewJSON(&out)
	if err := writer.WriteResult(context.Background(), sampleResult()); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteSummary(context.Background(), model.Summary{Status: "completed", Total: 1, Completed: 1}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected exactly two NDJSON lines: %q", out.String())
	}
	for i, line := range lines {
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if event.SchemaVersion != 1 || (i == 0 && (event.Type != "result" || event.Result == nil || event.Summary != nil)) || (i == 1 && (event.Type != "summary" || event.Summary == nil || event.Result != nil)) {
			t.Fatalf("invalid event envelope: %+v", event)
		}
	}
}

func TestRouterMirrorsAndPreservesExistingFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.ndjson")
	var stdout bytes.Buffer
	writer, err := New("ndjson", &stdout, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteResult(context.Background(), sampleResult()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("repeated close failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, stdout.Bytes()) {
		t.Fatalf("mirrored output differs: %v", err)
	}
	if _, err := New("ndjson", io.Discard, path); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing file was not preserved: %v", err)
	}
	unchanged, _ := os.ReadFile(path)
	if !bytes.Equal(data, unchanged) {
		t.Fatal("existing file changed")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestOutputErrorsAndCancellation(t *testing.T) {
	for _, format := range []string{"console", "text", "ndjson"} {
		writer, err := New(format, failWriter{}, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WriteResult(context.Background(), sampleResult()); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("%s lost write error: %v", format, err)
		}
		if err := writer.WriteSummary(context.Background(), model.Summary{}); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("%s lost summary write error: %v", format, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := writer.WriteResult(ctx, sampleResult()); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s ignored cancellation: %v", format, err)
		}
		if err := writer.WriteSummary(ctx, model.Summary{}); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s ignored summary cancellation: %v", format, err)
		}
	}
}

func TestConsoleSanitizesControlCharacters(t *testing.T) {
	var out bytes.Buffer
	result := sampleResult()
	result.Target.Hostname = "bad\x1b[31m\nhost"
	result.Service = &model.Service{Name: "http", Product: "bad\x1b[31m\nserver", Version: "1\t2"}
	writer := NewConsole(&out)
	if err := writer.WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b") || strings.Count(out.String(), "\n") != 2 {
		t.Fatalf("terminal control characters escaped into output: %q", out.String())
	}
}
