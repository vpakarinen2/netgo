package output

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func TestTextShowsTLSAndFullScriptFindings(t *testing.T) {
	result := sampleResult()
	message := "Certificate expires at 2026-11-19T06:47:46Z (within 30 days)"
	result.Service = &model.Service{Name: "https", Product: "fixture", Version: "1.2", TLS: &model.TLSInfo{
		Version: "TLS 1.3", ALPN: "h2", ReferenceName: "example.test", HostnameMatches: true, CertificateVerification: "not_performed",
		Certificate: &model.Certificate{Subject: "CN=example.test", Issuer: "CN=Test CA", NotAfter: time.Date(2026, 11, 19, 6, 47, 46, 0, time.UTC)},
	}}
	result.Scripts = []model.ScriptRun{
		{ID: "tls-expiry", Version: "0.1.0", Status: "completed", Duration: 15 * time.Millisecond, Findings: []model.ScriptFinding{{Severity: "low", Kind: "observation", Message: message, EvidenceFields: []string{"/service/tls/certificate/not_after"}}}},
		{ID: "other", Status: "completed"},
		{ID: "missing", Status: "inconclusive", Reason: "certificate missing"},
		{ID: "bad", Status: "error", Error: "invalid response"},
		{ID: "irrelevant", Status: "skipped", Reason: "service_not_matched"},
		{ID: "slow", Status: "timeout", Error: "deadline exceeded"},
	}
	var out bytes.Buffer
	writer := NewText(&out)
	ctx := context.Background()
	if err := writer.WriteResult(ctx, result); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteResult(ctx, sampleResult()); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteSummary(ctx, model.Summary{Status: "failed", Total: 2, Completed: 2, Error: "script failure", Scripts: &model.ScriptSummary{Invocations: 5, Findings: 1, Errors: 1, Timeouts: 1}}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[2001:db8::1]:443/tcp (example.test)\n  State: open (connected)",
		"Service: https", "Product: fixture/1.2", "TLS: TLS 1.3", "ALPN: h2",
		"tls-expiry v0.1.0 — completed (15ms)", "[low] observation: " + message,
		"Evidence fields: /service/tls/certificate/not_after", "No findings.", "certificate missing",
		"invalid response", "service_not_matched", "deadline exceeded", "\n\n[2001:db8::1]:443/tcp",
		"\n\nScan failed:", "Scripts: 5 invocations, 1 findings", "Error: script failure",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in text output:\n%s", want, out.String())
		}
	}
}

func TestTextScriptsDoNotTriggerCertificateDump(t *testing.T) {
	result := sampleResult()
	result.Service = &model.Service{Name: "https", TLS: &model.TLSInfo{
		Version: "TLS 1.3", ALPN: "h2", ReferenceName: "certificate-name.test",
		HostnameError: "certificate name mismatch", CertificateVerification: "not_performed",
		Certificate: &model.Certificate{
			Subject: "CN=certificate-subject.test", Issuer: "CN=Certificate issuer",
			SHA256: "certificate-fingerprint", DNSNames: []string{"certificate-san.test"},
			NotAfter: time.Date(2026, 11, 19, 6, 47, 46, 0, time.UTC),
		},
	}}
	for _, tc := range []struct {
		name string
		runs []model.ScriptRun
	}{
		{name: "no script"},
		{name: "unrelated script", runs: []model.ScriptRun{{ID: "unrelated", Status: "completed"}}},
		{name: "skipped TLS script", runs: []model.ScriptRun{{ID: "tls-hostname", Status: "skipped"}}},
		{name: "hostname matches without findings", runs: []model.ScriptRun{{ID: "tls-hostname", Status: "completed"}}},
		{name: "expiry outside threshold without findings", runs: []model.ScriptRun{{ID: "tls-expiry", Status: "completed"}}},
		{name: "custom TLS finding", runs: []model.ScriptRun{{ID: "custom", Status: "completed", Findings: []model.ScriptFinding{{Kind: "observation", Severity: "low", Message: "Custom TLS observation", EvidenceFields: []string{"/service/tls/hostname_matches"}}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result.Scripts = tc.runs
			var out bytes.Buffer
			if err := NewText(&out).WriteResult(context.Background(), result); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "TLS: TLS 1.3") || !strings.Contains(out.String(), "ALPN: h2") {
				t.Fatalf("basic TLS identification missing: %s", out.String())
			}
			for _, field := range []string{"Certificate subject:", "Certificate issuer:", "Certificate hostname:", "Expires:", "Valid from:", "Certificate trust:", "certificate-fingerprint", "certificate-san.test"} {
				if strings.Contains(out.String(), field) {
					t.Fatalf("script selection triggered certificate dump (%q): %s", field, out.String())
				}
			}
			if len(tc.runs) > 0 && tc.runs[0].Status == "completed" && len(tc.runs[0].Findings) == 0 && !strings.Contains(out.String(), "No findings.") {
				t.Fatalf("no-findings status missing: %s", out.String())
			}
		})
	}
	// Custom checks provide their own observations, without special plugin IDs.
	result.Scripts = []model.ScriptRun{{ID: "my-certificate-check", Status: "completed", Findings: []model.ScriptFinding{{
		Kind: "observation", Severity: "low", Message: "Certificate expires at 2026-11-19T06:47:46Z",
		EvidenceFields: []string{"/service/tls/certificate/not_after"},
	}}}}
	var out bytes.Buffer
	if err := NewText(&out).WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "[low] observation: Certificate expires at 2026-11-19T06:47:46Z") {
		t.Fatalf("certificate script finding missing: %s", out.String())
	}
}

func TestTextSanitizesUntrustedDetails(t *testing.T) {
	malicious := "untrusted\x1b[31m\r\n\u202evalue"
	result := sampleResult()
	result.Target.Address = result.Target.Address.WithZone(malicious)
	result.Target.Hostname = malicious
	result.Service = &model.Service{
		Name: malicious, Product: malicious,
		TLS: &model.TLSInfo{ReferenceName: malicious, HostnameError: malicious, CertificateVerification: malicious, Certificate: &model.Certificate{Subject: malicious, Issuer: malicious, Serial: malicious, SHA256: malicious, DNSNames: []string{malicious}}},
		Web: &model.WebInfo{Edge: []model.WebDetection{{Provider: malicious, Confidence: malicious, Evidence: []model.Evidence{{Kind: malicious, Value: malicious}}}}, WAF: model.WAFObservation{Status: malicious}, Warnings: []string{malicious}},
	}
	result.Identification = &model.Identification{Status: malicious, Error: malicious, Evidence: []model.Evidence{{Value: malicious}}}
	result.Scripts = []model.ScriptRun{{ID: malicious, Version: malicious, Status: malicious, Reason: malicious, Error: malicious, Findings: []model.ScriptFinding{{Kind: malicious, Severity: malicious, Message: malicious, EvidenceFields: []string{malicious}}}}}
	result.Scripts = append(result.Scripts, model.ScriptRun{ID: "tls-hostname", Status: "completed"})
	var out bytes.Buffer
	writer := NewText(&out)
	if err := writer.WriteResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteSummary(context.Background(), model.Summary{Status: malicious, Error: malicious}); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\x1b\r\u202e") || strings.Contains(out.String(), malicious) {
		t.Fatalf("terminal controls reached output: %q", out.String())
	}
	if result.Scripts[0].Findings[0].Message != malicious || result.Service.TLS.Certificate.DNSNames[0] != malicious {
		t.Fatal("display formatting changed source evidence")
	}
}
