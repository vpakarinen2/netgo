package service

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/vpakarinen2/netgo/pkg/model"
)

// observeWeb uses only an already-parsed, size-bounded HTTP response. IDs,
// cookies, and arbitrary header values are never copied into this metadata.
// Signatures are independently implemented from the provider references in
// docs/edge-waf.md. Confidence measures signature strength, not authentication.
func observeWeb(response *http.Response) *model.WebInfo {
	info := &model.WebInfo{WAF: model.WAFObservation{Status: "unknown"}}
	h := response.Header
	servers := make(map[string]bool)
	for _, value := range h.Values("Server") {
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		product, _, _ := strings.Cut(strings.ToLower(fields[0]), "/")
		servers[product] = true
	}
	if len(servers) > 1 {
		info.Warnings = append(info.Warnings, "conflicting_server_headers")
	}
	for _, candidate := range []struct {
		provider, kind string
		evidence       []model.Evidence
		explicit       bool
	}{
		{"cloudflare", "cdn", cloudflareEvidence(h, servers), servers["cloudflare"]},
		{"cloudfront", "cdn", cloudfrontEvidence(h, servers), servers["cloudfront"]},
		{"varnish", "cache", varnishEvidence(h, servers), servers["varnish"]},
	} {
		if len(candidate.evidence) == 0 {
			continue
		}
		confidence := "low"
		if candidate.explicit {
			confidence = "medium"
		}
		if len(candidate.evidence) >= 2 {
			confidence = "high"
		}
		if len(servers) > 1 {
			confidence = "low"
		}
		info.Edge = append(info.Edge, model.WebDetection{Provider: candidate.provider, Kind: candidate.kind, Confidence: confidence, Evidence: candidate.evidence})
	}
	if exactValue(h, "Cf-Mitigated", "challenge") {
		info.Challenges = append(info.Challenges, model.WebDetection{Provider: "cloudflare", Kind: "challenge", Confidence: "medium", Evidence: []model.Evidence{headerEvidence("cf-mitigated", "challenge")}})
	}
	// AWS documents both the header action and status code. Repeated/contradictory
	// values are ambiguous even when one of them happens to match the signature.
	if values := h.Values("X-Amzn-Waf-Action"); len(values) > 0 {
		action := ""
		if len(values) == 1 {
			action = strings.ToLower(strings.TrimSpace(values[0]))
		}
		valid := (action == "challenge" && response.StatusCode == http.StatusAccepted) || (action == "captcha" && response.StatusCode == http.StatusMethodNotAllowed)
		if valid {
			info.WAF.Status = "signal_observed"
			info.WAF.Detections = []model.WebDetection{{Provider: "aws-waf", Kind: "waf", Confidence: "high", Evidence: []model.Evidence{headerEvidence("x-amzn-waf-action", action), {Kind: "http_status", Value: strconv.Itoa(response.StatusCode)}}}}
		} else {
			info.Warnings = append(info.Warnings, "unmatched_aws_waf_action")
		}
	}
	return info
}

func headerEvidence(name, value string) model.Evidence {
	return model.Evidence{Kind: "http_header", Value: name + "=" + value}
}

func present(h http.Header, name string) bool {
	for _, value := range h.Values(name) {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func exactValue(h http.Header, name, value string) bool {
	values := h.Values(name)
	return len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), value)
}

func cloudflareEvidence(h http.Header, servers map[string]bool) []model.Evidence {
	var evidence []model.Evidence
	if servers["cloudflare"] {
		evidence = append(evidence, headerEvidence("server", "cloudflare"))
	}
	if present(h, "Cf-Ray") {
		evidence = append(evidence, headerEvidence("cf-ray", "present"))
	}
	if exactValue(h, "Cf-Mitigated", "challenge") {
		evidence = append(evidence, headerEvidence("cf-mitigated", "challenge"))
	}
	return evidence
}

func cloudfrontEvidence(h http.Header, servers map[string]bool) []model.Evidence {
	var evidence []model.Evidence
	if servers["cloudfront"] {
		evidence = append(evidence, headerEvidence("server", "cloudfront"))
	}
	if present(h, "X-Amz-Cf-Id") {
		evidence = append(evidence, headerEvidence("x-amz-cf-id", "present"))
	}
	if present(h, "X-Amz-Cf-Pop") {
		evidence = append(evidence, headerEvidence("x-amz-cf-pop", "present"))
	}
	for _, value := range h.Values("X-Cache") {
		fields := strings.Fields(strings.ToLower(value))
		if len(fields) == 3 && fields[1] == "from" && fields[2] == "cloudfront" {
			switch fields[0] {
			case "hit", "miss", "refreshhit", "error":
				evidence = append(evidence, headerEvidence("x-cache", strings.Join(fields, " ")))
				return evidence
			}
		}
	}
	return evidence
}

func varnishEvidence(h http.Header, servers map[string]bool) []model.Evidence {
	var evidence []model.Evidence
	if servers["varnish"] {
		evidence = append(evidence, headerEvidence("server", "varnish"))
	}
	for _, value := range h.Values("Via") {
		matched := false
		for _, hop := range strings.Split(value, ",") {
			fields := strings.Fields(strings.ToLower(hop))
			if len(fields) < 2 {
				continue
			}
			version := strings.TrimPrefix(fields[0], "http/")
			httpVersion := version == "1.0" || version == "1.1" || version == "2" || version == "2.0" || version == "3" || version == "3.0"
			if httpVersion && fields[1] == "varnish" {
				matched = true
				break
			}
		}
		if matched {
			evidence = append(evidence, headerEvidence("via", "varnish"))
			break
		}
	}
	for _, value := range h.Values("X-Varnish") {
		fields := strings.Fields(value)
		if len(fields) < 1 || len(fields) > 2 {
			continue
		}
		valid := true
		for _, field := range fields {
			for _, r := range field {
				if r < '0' || r > '9' {
					valid = false
				}
			}
		}
		if valid {
			evidence = append(evidence, headerEvidence("x-varnish", "present"))
			break
		}
	}
	return evidence
}
