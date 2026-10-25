package plugins

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/internal/testplugins"
	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/output"
	"github.com/vpakarinen2/netgo/pkg/plugins/sdk"
)

func TestCertificateScriptReportsAllCollectedNamesWithoutFindings(t *testing.T) {
	module := testplugins.Build(t, "./examples/plugins/tls-certificate")
	engine, err := Load(context.Background(), []string{testBundle(t, module, "valid")}, nil, Limits{Timeout: time.Second, MemoryMiB: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close(context.Background())
	request := testRequest()
	cert := &model.Certificate{
		Subject: strings.Repeat("S", 512), Issuer: strings.Repeat("I", 512), Serial: "1234", SHA256: strings.Repeat("a", 64),
		NotBefore: request.EvaluationTime.Add(-time.Hour), NotAfter: request.EvaluationTime.Add(90 * 24 * time.Hour), TimeValid: true, NamesOmitted: 7,
	}
	for index := 0; index < 32; index++ {
		cert.DNSNames = append(cert.DNSNames, fmt.Sprintf("%02d.%s.test", index, strings.Repeat("a", 245)))
		cert.IPAddresses = append(cert.IPAddresses, fmt.Sprintf("2001:db8::%x", index+1))
	}
	request.Result.Service = &model.Service{Name: "https", TLS: &model.TLSInfo{
		Certificate: cert, ReferenceName: "fixture.test", HostnameMatches: false, HostnameError: strings.Repeat("H", 512), CertificateVerification: "not_performed",
	}}
	run, err := engine.Test(context.Background(), request)
	if err != nil || run.Status != "completed" || len(run.Findings) != 0 || len(run.Details) != 76 {
		t.Fatalf("certificate report failed: %+v, %v", run, err)
	}
	dnsNames, ipAddresses := 0, 0
	for _, detail := range run.Details {
		if detail.Label == "DNS name" {
			dnsNames++
		}
		if detail.Label == "IP address" {
			ipAddresses++
		}
	}
	if dnsNames != 32 || ipAddresses != 32 {
		t.Fatalf("report omitted retained names: DNS=%d IP=%d", dnsNames, ipAddresses)
	}
	request.Result.Scripts = []model.ScriptRun{run}
	var text bytes.Buffer
	if err := output.NewText(&text).WriteResult(context.Background(), request.Result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Subject: " + cert.Subject, "Issuer: " + cert.Issuer, "SHA-256 fingerprint: " + cert.SHA256, "Hostname matches: false", "Certificate trust: not checked", "Additional names omitted: 7", cert.DNSNames[31], cert.IPAddresses[31]} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Contains(text.String(), "No findings.") {
		t.Fatal("informational report incorrectly displayed as empty")
	}
	request.Result.Scripts = nil
	request.Result.Service = nil
	run, err = engine.Test(context.Background(), request)
	if err != nil || run.Status != "inconclusive" || run.Reason != "certificate_not_collected" || len(run.Details) != 0 {
		t.Fatalf("missing certificate not handled: %+v %v", run, err)
	}
}

func TestInformationalDetailsRequireBoundedScalarEvidence(t *testing.T) {
	valid := model.ScriptDetail{Label: "Port", Value: "22", EvidenceFields: []string{"/target/port"}}
	for _, tc := range []struct {
		name    string
		details []model.ScriptDetail
		bad     bool
	}{
		{"valid", []model.ScriptDetail{valid}, false},
		{"count", make([]model.ScriptDetail, sdk.MaxDetails+1), true},
		{"label", []model.ScriptDetail{{Label: strings.Repeat("L", 65), Value: "22", EvidenceFields: valid.EvidenceFields}}, true},
		{"value", []model.ScriptDetail{{Label: "Port", Value: strings.Repeat("v", 513), EvidenceFields: valid.EvidenceFields}}, true},
		{"empty", []model.ScriptDetail{{Label: "Port", EvidenceFields: valid.EvidenceFields}}, true},
		{"missing evidence", []model.ScriptDetail{{Label: "Port", Value: "22"}}, true},
		{"invented evidence", []model.ScriptDetail{{Label: "Port", Value: "22", EvidenceFields: []string{"/missing"}}}, true},
		{"object evidence", []model.ScriptDetail{{Label: "Target", Value: "value", EvidenceFields: []string{"/target"}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResponse(sdk.Response{APIVersion: sdk.APIVersion, Outcome: "completed", Details: tc.details}, testRequest())
			if (err != nil) != tc.bad {
				t.Fatalf("validation error=%v, want error=%t", err, tc.bad)
			}
		})
	}
}
