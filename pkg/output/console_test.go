package output

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func TestConsoleResponsiveRowsAndResize(t *testing.T) {
	var out bytes.Buffer
	columns := 200
	writer := NewConsoleWithWidth(&out, func() int { return columns })
	result := sampleResult()
	result.Service = &model.Service{Name: "https", Product: "测试服务器", Version: "1.0", Web: &model.WebInfo{Edge: []model.WebDetection{{Provider: "cloudflare", Confidence: "high"}}, WAF: model.WAFObservation{Status: "unknown"}}}
	for _, address := range []string{"127.0.0.1", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"} {
		result.Target.Address = netip.MustParseAddr(address)
		for _, size := range []int{200, 160, 120, 80, 50, 30, 10, 1, 120} {
			columns = size
			out.Reset()
			if err := writer.WriteResult(context.Background(), result); err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
				if textWidth(line) > max(1, columns-1) {
					t.Fatalf("width %d overflowed: %q", size, line)
				}
			}
			if size >= 50 && !strings.Contains(out.String(), "443/tcp") {
				t.Fatalf("endpoint lost: %q", out.String())
			}
		}
	}
}

func TestConsoleCompactColumnsAndFullRedirectedOutput(t *testing.T) {
	var compact, full bytes.Buffer
	result := sampleResult()
	result.Identification = &model.Identification{Status: "identified"}
	if err := NewConsoleWithWidth(&compact, func() int { return 80 }).WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if err := NewConsole(&full).WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(compact.String(), "EDGE") || !strings.Contains(compact.String(), "WAF") || strings.Contains(compact.String(), "IDENTIFICATION") {
		t.Fatalf("compact priorities incorrect: %q", compact.String())
	}
	if !strings.Contains(full.String(), "IDENTIFICATION") || !strings.Contains(full.String(), "HOSTNAME") {
		t.Fatal("redirected output lost columns")
	}
	if got := fitText("测试e\u0301abcdef", 7); got != "测试..." || textWidth(got) != 7 {
		t.Fatalf("wide character truncation: %q", got)
	}
}

func TestConsoleCompactBasicScanKeepsReason(t *testing.T) {
	var out bytes.Buffer
	result := sampleResult()
	result.State, result.Reason = model.Unknown, "timeout"
	if err := NewConsoleWithWidth(&out, func() int { return 80 }).WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "REASON") || !strings.Contains(out.String(), "timeout") || strings.Contains(out.String(), "SERVICE") {
		t.Fatalf("basic scan displaced reason with unused service fields: %q", out.String())
	}
}
