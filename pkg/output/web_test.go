package output

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func TestWebConsoleAndNDJSON(t *testing.T) {
	result := sampleResult()
	result.Service = &model.Service{Name: "http", Web: &model.WebInfo{Edge: []model.WebDetection{{Provider: "cloudflare", Confidence: "medium", Kind: "cdn", Evidence: []model.Evidence{{Kind: "http_header", Value: "server=cloudflare"}}}}, WAF: model.WAFObservation{Status: "unknown"}}}
	var console, ndjson bytes.Buffer
	if err := NewConsole(&console).WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(console.String(), "cloudflare [medium]") || !strings.Contains(console.String(), "unknown") || strings.Contains(console.String(), "Web:") || strings.Count(console.String(), "\n") != 2 {
		t.Fatalf("unexpected console: %s", console.String())
	}
	if err := NewJSON(&ndjson).WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if strings.Count(ndjson.String(), "\n") != 1 {
		t.Fatal("NDJSON event gained extra lines")
	}
	var event Event
	if err := json.Unmarshal(ndjson.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Result.Service.Web.Edge[0].Evidence[0].Value != "server=cloudflare" {
		t.Fatal("lost evidence")
	}
	console.Reset()
	result.Service.Web.Edge[0].Provider = "bad\x1b\nprovider"
	if err := NewConsole(&console).WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(console.String(), "\x1b") || strings.Count(console.String(), "\n") != 2 {
		t.Fatal("terminal controls escaped web details")
	}
}

func TestWebColumnsStayAlignedAcrossMixedResults(t *testing.T) {
	var out bytes.Buffer
	writer := NewConsole(&out)
	result := sampleResult()
	result.Service = &model.Service{Name: "https"}
	if err := writer.WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	result.Service = &model.Service{Name: "http", Product: "nginx", Version: "1.26", Web: &model.WebInfo{Edge: []model.WebDetection{{Provider: "cloudflare", Confidence: "high"}}, WAF: model.WAFObservation{Status: "unknown"}}}
	if err := writer.WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("unexpected row count: %q", out.String())
	}
	for _, column := range []string{"EDGE", "WAF", "IDENTIFICATION"} {
		start := strings.Index(lines[0], column)
		if start < 0 {
			t.Fatalf("missing column %s", column)
		}
		for _, row := range lines[1:] {
			if len(row) <= start || row[start] == ' ' {
				t.Fatalf("misaligned %s: %q", column, row)
			}
		}
	}
	if !strings.Contains(lines[2], "nginx/1.26") {
		t.Fatal("product version was lost")
	}
}
