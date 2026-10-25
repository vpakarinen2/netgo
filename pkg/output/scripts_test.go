package output

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func TestScriptConsoleAndJSONRetainEvidence(t *testing.T) {
	result := sampleResult()
	result.Scripts = []model.ScriptRun{{ID: "fixture", Status: "completed", Findings: []model.ScriptFinding{{ID: "finding", Message: "untrusted\x1b[31m\ntext", EvidenceFields: []string{"/target/address"}}}}}
	result.Scripts[0].Details = []model.ScriptDetail{{Label: "Subject\x1b\n", Value: "untrusted\x1b\nvalue", EvidenceFields: []string{"/target/address"}}}
	var console, ndjson bytes.Buffer
	writer := NewConsoleWithWidth(&console, func() int { return 80 })
	if err := writer.WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if strings.Count(console.String(), "\n") != 2 || !strings.Contains(console.String(), "CHECKS") || !strings.Contains(console.String(), "1 findings") || strings.Contains(console.String(), "\x1b") {
		t.Fatalf("bad console: %q", console.String())
	}
	if err := NewJSON(&ndjson).WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(ndjson.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.SchemaVersion != 1 || event.Result.Scripts[0].Findings[0].Message != result.Scripts[0].Findings[0].Message || event.Result.Scripts[0].Details[0].Value != result.Scripts[0].Details[0].Value {
		t.Fatal("JSON evidence changed")
	}
	var text bytes.Buffer
	if err := NewText(&text).WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(text.String(), "\x1b\r") || !strings.Contains(text.String(), "Subject??: untrusted??value") {
		t.Fatalf("unsafe informational detail output: %q", text.String())
	}
	console.Reset()
	if err := writer.WriteSummary(context.Background(), model.Summary{Status: "completed", Diagnostics: &model.Diagnostics{}, Scripts: &model.ScriptSummary{Invocations: 1, Findings: 1, Completed: 1}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(console.String(), "Diagnostics:") || !strings.Contains(console.String(), "Scripts: 1 invocations, 1 findings") {
		t.Fatalf("summary omitted script stats: %s", console.String())
	}
}
