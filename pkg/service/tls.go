package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network"
)

const maxTLSWireBytes = 256 * 1024

// boundedConn caps TLS wire input, including certificate/handshake messages.
type boundedConn struct {
	net.Conn
	remaining int
}

func (c *boundedConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, fmt.Errorf("TLS input exceeds %d bytes", maxTLSWireBytes)
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= n
	return n, err
}

func (i *Inspector) inspectTLS(ctx context.Context, target model.Target, gate network.ConnectionGate, info *model.Identification) (*model.Service, error) {
	conn, release, err := i.dial(ctx, target, gate, info)
	if err != nil {
		return nil, err
	}
	defer release()
	serverName := i.options.ServerName
	if serverName == "" {
		serverName = target.Hostname
	}
	// Inspection intentionally accepts untrusted certificates so evidence can be
	// collected. Hostname/time checks are separate; chain trust is not asserted.
	secured := tls.Client(&boundedConn{Conn: conn, remaining: maxTLSWireBytes}, &tls.Config{
		InsecureSkipVerify: true, // certificate_verification is explicitly not_performed
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err := secured.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := secured.ConnectionState()
	reference := serverName
	if reference == "" {
		reference = target.Address.String()
	}
	tlsInfo := &model.TLSInfo{Version: tls.VersionName(state.Version), CipherSuite: tls.CipherSuiteName(state.CipherSuite), ALPN: state.NegotiatedProtocol, ServerName: serverName, SNISent: serverName != "", ReferenceName: reference, CertificateVerification: "not_performed"}
	if len(state.PeerCertificates) != 0 {
		cert := state.PeerCertificates[0]
		now := time.Now()
		digest := sha256.Sum256(cert.Raw)
		summary := &model.Certificate{Subject: clipped(cert.Subject.String(), 512), Issuer: clipped(cert.Issuer.String(), 512), Serial: clipped(cert.SerialNumber.String(), 128), SHA256: hex.EncodeToString(digest[:]), NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(), TimeValid: !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)}
		for _, name := range cert.DNSNames[:min(len(cert.DNSNames), 32)] {
			summary.DNSNames = append(summary.DNSNames, clipped(name, 253))
		}
		for _, address := range cert.IPAddresses[:min(len(cert.IPAddresses), 32)] {
			summary.IPAddresses = append(summary.IPAddresses, address.String())
		}
		summary.NamesOmitted = max(0, len(cert.DNSNames)-32) + max(0, len(cert.IPAddresses)-32)
		tlsInfo.Certificate = summary
		if err := cert.VerifyHostname(reference); err != nil {
			tlsInfo.HostnameError = clipped(err.Error(), 512)
		} else {
			tlsInfo.HostnameMatches = true
		}
	}
	service := &model.Service{Name: "tls", TLS: tlsInfo}
	if state.NegotiatedProtocol == "h2" {
		// ALPN is protocol evidence. Do not send HTTP/1 bytes on a connection
		// that negotiated HTTP/2; no application request is made in this case.
		service.Name = "https"
		service.Evidence = []model.Evidence{{Kind: "alpn", Value: "h2"}}
		return service, nil
	}
	data, err := i.httpProbe(secured, target)
	info.ReadLimitReached = info.ReadLimitReached || len(data) == i.options.MaxBytes
	if httpService := i.fingerprinter.Match(data); httpService != nil && httpService.Name == "http" {
		httpService.Name, httpService.TLS = "https", tlsInfo
		return httpService, nil
	}
	if err != nil && err != io.EOF {
		return service, err
	}
	return service, nil
}
