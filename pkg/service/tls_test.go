package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func testCertificate(t *testing.T, expired bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1234), Subject: pkix.Name{CommonName: "example.test", Organization: []string{"Netgo test fixture"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"example.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if expired {
		template.NotBefore, template.NotAfter = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSCertificateSNIAndHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name, hostname, override, sni string
		matches, expired              bool
	}{
		{"override", "original.test", "EXAMPLE.test.", "example.test", true, false},
		{"mismatch", "wrong.test", "", "wrong.test", false, false},
		{"expired", "example.test", "", "example.test", true, true},
		{"IP reference", "", "", "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sni := make(chan string, 4)
			host := make(chan string, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host <- r.Host
				w.Header().Set("Server", "tls-test/1.0")
				w.Header().Set("X-Amz-Cf-Id", "fixture-id")
				w.Header().Set("X-Amz-Cf-Pop", "fixture-pop")
				w.WriteHeader(http.StatusNoContent)
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{testCertificate(t, tc.expired)}, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni <- hello.ServerName; return nil, nil }}
			server.StartTLS()
			defer server.Close()
			target := targetFor(server.Listener.Addr().String())
			target.Hostname = tc.hostname
			i := newInspector(t, Options{Timeout: 3 * time.Second, MaxBytes: 1024, Active: true, ServerName: tc.override})
			service, info := i.Identify(context.Background(), target, nil)
			if service == nil || service.Name != "https" || service.Product != "tls-test" || service.TLS == nil || info.Status != "identified" || info.Connections != 2 {
				t.Fatalf("service=%+v info=%+v", service, info)
			}
			observed := service.TLS
			if service.Web == nil || len(service.Web.Edge) != 1 || service.Web.Edge[0].Provider != "cloudfront" || service.Web.WAF.Status != "unknown" {
				t.Fatalf("HTTPS lost web observations: %+v", service.Web)
			}
			if observed.CertificateVerification != "not_performed" || observed.HostnameMatches != tc.matches || observed.SNISent != (tc.sni != "") || observed.ServerName != tc.sni || observed.Version == "" || observed.CipherSuite == "" {
				t.Fatalf("incorrect TLS observation: %+v", observed)
			}
			if observed.Certificate == nil || observed.Certificate.TimeValid == tc.expired || len(observed.Certificate.SHA256) != 64 || observed.Certificate.Serial != "1234" || len(observed.Certificate.DNSNames) != 1 {
				t.Fatalf("incorrect certificate: %+v", observed.Certificate)
			}
			if !tc.matches && observed.HostnameError == "" {
				t.Fatal("certificate mismatch was not explained")
			}
			select {
			case sent := <-sni:
				if sent != tc.sni {
					t.Fatalf("SNI=%q, want %q", sent, tc.sni)
				}
			case <-time.After(time.Second):
				t.Fatal("TLS ClientHello not observed")
			}
			reference := tc.sni
			if reference == "" {
				reference = target.Address.String()
			}
			if actual := <-host; actual != net.JoinHostPort(reference, strconv.Itoa(int(target.Port))) {
				t.Fatalf("HTTP Host=%q", actual)
			}
		})
	}
}

func TestTLSIdentitySurvivesHTTPTimeout(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{testCertificate(t, false)}}
	server.StartTLS()
	defer server.Close()
	i := newInspector(t, Options{Timeout: 600 * time.Millisecond, MaxBytes: 256, Active: true})
	service, info := i.Identify(context.Background(), targetFor(server.Listener.Addr().String()), nil)
	if service == nil || service.Name != "tls" || service.TLS == nil || info.Status != "identified" || info.Error == "" {
		t.Fatalf("TLS evidence lost on HTTP failure: service=%+v info=%+v", service, info)
	}
}

func TestTLSWireReadBound(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = server.Write(make([]byte, 16)) }()
	conn := &boundedConn{Conn: client, remaining: 8}
	data := make([]byte, 16)
	if n, err := conn.Read(data); err != nil || n != 8 {
		t.Fatalf("wire bound not applied: n=%d err=%v", n, err)
	}
	if n, err := conn.Read(data); n != 0 || err == nil {
		t.Fatalf("wire limit not enforced: n=%d err=%v", n, err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("wire fixture leaked")
	}
}

func TestHTTP2ALPNIdentificationSendsNoHTTP1Request(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	i := newInspector(t, Options{Timeout: 3 * time.Second, MaxBytes: 1024, Active: true})
	service, info := i.Identify(context.Background(), targetFor(server.Listener.Addr().String()), nil)
	if service == nil || service.Name != "https" || service.TLS.ALPN != "h2" || info.Status != "identified" || info.Connections != 2 || requests.Load() != 0 {
		t.Fatalf("HTTP/2 evidence incorrect: %+v, %+v requests=%d", service, info, requests.Load())
	}
	if len(service.Evidence) != 1 || service.Evidence[0].Kind != "alpn" {
		t.Fatal("HTTP/2 identification lacked ALPN evidence")
	}
}
