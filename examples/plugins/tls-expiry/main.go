package main

import (
	"fmt"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/plugins/sdk"
)

func main() { sdk.Main(check) }

func check(request sdk.Request) (sdk.Response, error) {
	response := sdk.Response{Outcome: "inconclusive", Reason: "certificate_not_collected"}
	service := request.Result.Service
	if service == nil || service.TLS == nil || service.TLS.Certificate == nil {
		return response, nil
	}
	days, err := request.Int("days")
	if err != nil || days < 1 || days > 365 {
		return sdk.Response{}, fmt.Errorf("days must be between 1 and 365")
	}
	response.Outcome, response.Reason = "completed", ""
	expiry := service.TLS.Certificate.NotAfter
	if expiry.IsZero() {
		return sdk.Response{Outcome: "inconclusive", Reason: "certificate_expiry_missing"}, nil
	}
	if !expiry.After(request.EvaluationTime.Add(time.Duration(days) * 24 * time.Hour)) {
		message := fmt.Sprintf("Certificate expires at %s (within %d days)", expiry.UTC().Format(time.RFC3339), days)
		if !expiry.After(request.EvaluationTime) {
			message = "Certificate expired at " + expiry.UTC().Format(time.RFC3339)
		}
		response.Findings = []model.ScriptFinding{{ID: "certificate-expiry", Kind: "observation", Severity: "low", Message: message, EvidenceFields: []string{"/service/tls/certificate/not_after"}}}
	}
	return response, nil
}
