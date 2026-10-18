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
	if !strings.Contains(console.String(), "edge=cloudflare [medium]; WAF=unknown") || strings.Count(console.String(), "\n") != 3 {
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
	if strings.Contains(console.String(), "\x1b") || strings.Count(console.String(), "\n") != 3 {
		t.Fatal("terminal controls escaped web details")
	}
}
