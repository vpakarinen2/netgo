package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/plugins/sdk"
)

func main() { sdk.Main(check) }

func check(request sdk.Request) (sdk.Response, error) {
	service := request.Result.Service
	if service == nil || service.TLS == nil || service.TLS.Certificate == nil {
		return sdk.Response{Outcome: "inconclusive", Reason: "certificate_not_collected"}, nil
	}
	tls, cert := service.TLS, service.TLS.Certificate
	response := sdk.Response{Outcome: "completed"}
	add := func(label, value, field string) {
		if value == "" {
			value = "(empty)"
		}
		response.Details = append(response.Details, model.ScriptDetail{Label: label, Value: value, EvidenceFields: []string{"/service/tls/" + field}})
	}
	add("Subject", cert.Subject, "certificate/subject")
	add("Issuer", cert.Issuer, "certificate/issuer")
	add("Serial number", cert.Serial, "certificate/serial")
	add("SHA-256 fingerprint", cert.SHA256, "certificate/sha256")
	add("Valid from", cert.NotBefore.UTC().Format(time.RFC3339), "certificate/not_before")
	add("Expires", cert.NotAfter.UTC().Format(time.RFC3339), "certificate/not_after")
	add("Dates valid at inspection", strconv.FormatBool(cert.TimeValid), "certificate/time_valid")
	add("Reference name", tls.ReferenceName, "reference_name")
	add("Hostname matches", strconv.FormatBool(tls.HostnameMatches), "hostname_matches")
	if tls.HostnameError != "" {
		add("Hostname error", tls.HostnameError, "hostname_error")
	}
	trust := tls.CertificateVerification
	if trust == "not_performed" {
		trust = "not checked"
	}
	add("Certificate trust", trust, "certificate_verification")
	for index, name := range cert.DNSNames {
		add("DNS name", name, fmt.Sprintf("certificate/dns_names/%d", index))
	}
	for index, address := range cert.IPAddresses {
		add("IP address", address, fmt.Sprintf("certificate/ip_addresses/%d", index))
	}
	if cert.NamesOmitted > 0 {
		add("Additional names omitted", strconv.Itoa(cert.NamesOmitted), "certificate/names_omitted")
	}
	return response, nil
}
