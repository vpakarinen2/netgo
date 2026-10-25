package main

import (
	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/plugins/sdk"
)

func main() {
	sdk.Main(func(request sdk.Request) (sdk.Response, error) {
		service := request.Result.Service
		if service == nil || service.TLS == nil || service.TLS.Certificate == nil {
			return sdk.Response{Outcome: "inconclusive", Reason: "certificate_not_collected"}, nil
		}
		response := sdk.Response{Outcome: "completed"}
		if !service.TLS.HostnameMatches {
			response.Findings = []model.ScriptFinding{{ID: "certificate-hostname-mismatch", Kind: "observation", Severity: "low", Message: "Certificate does not match the scan's reference hostname or IP; chain trust was not verified", EvidenceFields: []string{"/service/tls/hostname_matches", "/service/tls/reference_name"}}}
		}
		return response, nil
	})
}
