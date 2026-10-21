package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network"
)

const maxTLSWireBytes = 256 * 1024

var errHTTP2HeaderLimit = errors.New("HTTP/2 response headers exceed service byte limit")

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
		service.Name = "https"
		service.Evidence = []model.Evidence{{Kind: "alpn", Value: "h2"}}
		response, err := i.http2Probe(ctx, secured, target)
		if err != nil {
			// Keep the negotiated protocol and certificate even if headers fail.
			info.ReadLimitReached = info.ReadLimitReached || errors.Is(err, errHTTP2HeaderLimit) || strings.Contains(err.Error(), "response header list larger than advertised limit")
			return service, err
		}
		httpService := matchHTTPResponse(response)
		httpService.Name, httpService.TLS = "https", tlsInfo
		httpService.Evidence = append(httpService.Evidence, service.Evidence...)
		return httpService, nil
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

// http2Probe lends the existing TLS socket to a private standard-library
// transport. It cannot open another socket, follow redirects, or read a body.
func (i *Inspector) http2Probe(ctx context.Context, conn *tls.Conn, target model.Target) (*http.Response, error) {
	var borrowed atomic.Bool
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	transport := &http.Transport{
		Protocols:              protocols,
		DisableCompression:     true,
		DisableKeepAlives:      true, // Never replay a refused stream on this socket.
		MaxResponseHeaderBytes: int64(i.options.MaxBytes),
		HTTP2:                  &http.HTTP2Config{MaxReadFrameSize: 16 * 1024, MaxReceiveBufferPerConnection: 64 * 1024, MaxReceiveBufferPerStream: 64 * 1024},
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			if borrowed.Swap(true) {
				return nil, fmt.Errorf("HTTP/2 inspection cannot reconnect")
			}
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+i.httpAuthority(target)+"/", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "netgo")
	response, err := transport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	_ = response.Body.Close()
	// The transport allows HTTP/2 accounting overhead in its byte limit.
	// Apply the configured limit to decoded fields before retaining evidence.
	size := 32 + len(":status") + 3
	for key, values := range response.Header {
		for _, value := range values {
			size += 32 + len(key) + len(value)
		}
	}
	if size > i.options.MaxBytes {
		return nil, errHTTP2HeaderLimit
	}
	return response, nil
}
