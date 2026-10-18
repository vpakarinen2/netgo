package output

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func TestInteractiveProgressKeepsResultsClean(t *testing.T) {
	var stdout, stderr bytes.Buffer
	width := 50
	p := NewProgress(NewJSON(&stdout), &stderr, true, func() int { return width })
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := p.Report(model.Progress{Completed: uint64(i), Total: 1000}); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Contains(stderr.String(), "\n") {
		t.Fatal("interactive progress added log lines")
	}
	for _, line := range strings.Split(stderr.String(), "\r") {
		if len(line) > 49 {
			t.Fatal("progress wraps terminal")
		}
	}
	if err := p.WriteResult(ctx, sampleResult()); err != nil {
		t.Fatal(err)
	}
	width = 20
	if err := p.Report(model.Progress{Completed: 1, Total: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := p.WriteSummary(ctx, model.Summary{Status: "completed"}); err != nil {
		t.Fatal(err)
	}
	if p.visible != 0 || p.hasProgress {
		t.Fatal("summary left progress active")
	}
	if strings.ContainsAny(stdout.String(), "\r\x1b") || strings.Count(stdout.String(), "\n") != 2 {
		t.Fatalf("polluted results: %q", stdout.String())
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRedirectedProgressAndErrors(t *testing.T) {
	var results, logs bytes.Buffer
	p := NewProgress(NewJSON(&results), &logs, false, nil)
	if err := p.Report(model.Progress{Total: 10}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(logs.String(), "\n") || strings.ContainsAny(logs.String(), "\r\x1b") {
		t.Fatal("redirected progress not plain text")
	}
	p = NewProgress(NewJSON(io.Discard), failWriter{}, true, func() int { return 80 })
	if err := p.Report(model.Progress{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("lost progress error: %v", err)
	}
}

func TestStatsAreOptionalInJSONAndConsole(t *testing.T) {
	for _, format := range []string{"console", "ndjson"} {
		var out bytes.Buffer
		writer, err := New(format, &out, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WriteSummary(context.Background(), model.Summary{Status: "completed"}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "diagnostics") || strings.Contains(out.String(), "Diagnostics") {
			t.Fatal("statistics printed without opt-in")
		}
		out.Reset()
		s := model.Summary{Diagnostics: &model.Diagnostics{PortAttempts: 2, Reasons: map[string]uint64{"timeout": 1}, Hosts: []model.HostDiagnostics{{Address: "127.0.0.1", Attempts: 2, Timeouts: 1}}}}
		if err := writer.WriteSummary(context.Background(), s); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "timeout") {
			t.Fatal("missing stats output")
		}
	}
}
