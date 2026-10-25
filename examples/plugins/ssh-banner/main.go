package main

import (
	"fmt"
	"strings"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/plugins/sdk"
)

func main() {
	sdk.Main(func(request sdk.Request) (sdk.Response, error) {
		service := request.Result.Service
		if service == nil || service.Name != "ssh" || service.Product == "" {
			return sdk.Response{Outcome: "inconclusive", Reason: "ssh_product_not_collected"}, nil
		}
		pattern, err := request.String("contains")
		if err != nil || pattern == "" {
			return sdk.Response{}, fmt.Errorf("contains must be a nonempty string")
		}
		response := sdk.Response{Outcome: "completed"}
		if strings.Contains(strings.ToLower(service.Product), strings.ToLower(pattern)) {
			response.Findings = []model.ScriptFinding{{ID: "ssh-product-match", Kind: "match", Severity: "info", Message: "SSH greeting reports a product matching the configured text; this does not authenticate the implementation", EvidenceFields: []string{"/service/product"}}}
		}
		return response, nil
	})
}
