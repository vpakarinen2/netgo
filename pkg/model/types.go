// Package model defines shared scanner data independent of scheduling and I/O.
package model

import (
	"fmt"
	"net/netip"
	"time"
)

type Transport string

const (
	TCP Transport = "tcp"
	UDP Transport = "udp"
)

type Method string

const (
	TCPConnect Method = "tcp-connect"
	TCPSYN     Method = "tcp-syn"
	UDPProbe   Method = "udp"
)

type PortState string

const (
	Open         PortState = "open"
	Closed       PortState = "closed"
	Filtered     PortState = "filtered"
	OpenFiltered PortState = "open|filtered"
	Unknown      PortState = "unknown"
)

// Target retains the source hostname for later HTTP Host and TLS SNI handling.
type Target struct {
	Address   netip.Addr `json:"address"`
	Hostname  string     `json:"hostname,omitempty"`
	Port      uint16     `json:"port"`
	Transport Transport  `json:"transport"`
}

func (t Target) Validate() error {
	if !t.Address.IsValid() {
		return fmt.Errorf("target address is invalid")
	}
	if t.Port == 0 {
		return fmt.Errorf("target port must be between 1 and 65535")
	}
	if t.Transport != TCP && t.Transport != UDP {
		return fmt.Errorf("unsupported transport %q", t.Transport)
	}
	return nil
}

type Evidence struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type Service struct {
	Name     string     `json:"name"`
	Product  string     `json:"product,omitempty"`
	Version  string     `json:"version,omitempty"`
	Evidence []Evidence `json:"evidence,omitempty"`
	TLS      *TLSInfo   `json:"tls,omitempty"`
}

// Identification describes a best-effort inspection without changing port
// evidence. Connections counts additional dials, including failed dials.
type Identification struct {
	Status           string        `json:"status"`
	Duration         time.Duration `json:"duration_ns"`
	Connections      int           `json:"connections"`
	Error            string        `json:"error,omitempty"`
	Evidence         []Evidence    `json:"evidence,omitempty"`
	ReadLimitReached bool          `json:"read_limit_reached,omitempty"`
}

type TLSInfo struct {
	Version                 string       `json:"version"`
	CipherSuite             string       `json:"cipher_suite"`
	ALPN                    string       `json:"alpn,omitempty"`
	ServerName              string       `json:"server_name,omitempty"`
	SNISent                 bool         `json:"sni_sent"`
	ReferenceName           string       `json:"reference_name"`
	HostnameMatches         bool         `json:"hostname_matches"`
	HostnameError           string       `json:"hostname_error,omitempty"`
	CertificateVerification string       `json:"certificate_verification"`
	Certificate             *Certificate `json:"certificate,omitempty"`
}

type Certificate struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	Serial       string    `json:"serial"`
	SHA256       string    `json:"sha256"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	TimeValid    bool      `json:"time_valid"`
	DNSNames     []string  `json:"dns_names,omitempty"`
	IPAddresses  []string  `json:"ip_addresses,omitempty"`
	NamesOmitted int       `json:"names_omitted,omitempty"`
}

// Result represents network evidence. Local failures are returned separately
// by the prober and must never be converted into a closed or filtered state.
type Result struct {
	Target         Target          `json:"target"`
	Method         Method          `json:"method"`
	State          PortState       `json:"state"`
	Reason         string          `json:"reason"`
	ObservedAt     time.Time       `json:"observed_at"`
	Duration       time.Duration   `json:"duration_ns"`
	Attempts       int             `json:"attempts"`
	Service        *Service        `json:"service,omitempty"`
	Identification *Identification `json:"identification,omitempty"`
	UDP            *UDPInfo        `json:"udp,omitempty"`
}

type UDPInfo struct {
	Probe              string `json:"probe"`
	ResponseBytes      int    `json:"response_bytes"`
	IgnoredResponses   int    `json:"ignored_responses"`
	OversizedResponses int    `json:"oversized_responses"`
}

// Summary counts final results written successfully, rather than every retry.
// Attempts includes all started probes, including canceled or failed attempts.
type Summary struct {
	Status       string        `json:"status"`
	Hosts        uint64        `json:"hosts"`
	Ports        int           `json:"ports"`
	Total        uint64        `json:"total"`
	Completed    uint64        `json:"completed"`
	Attempts     uint64        `json:"attempts"`
	Open         uint64        `json:"open"`
	Closed       uint64        `json:"closed"`
	OpenFiltered uint64        `json:"open_filtered"`
	Filtered     uint64        `json:"filtered"`
	Unknown      uint64        `json:"unknown"`
	StartedAt    time.Time     `json:"started_at"`
	FinishedAt   time.Time     `json:"finished_at"`
	Duration     time.Duration `json:"duration_ns"`
	Error        string        `json:"error,omitempty"`
}

type Progress struct {
	Completed    uint64
	Total        uint64
	Attempts     uint64
	Open         uint64
	Closed       uint64
	OpenFiltered uint64
	Filtered     uint64
	Unknown      uint64
}
