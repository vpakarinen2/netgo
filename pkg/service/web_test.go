package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func TestWebSignaturesAndFalsePositives(t *testing.T) {
	f, err := NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, headers        string
		status               int
		edges                string
		confidence           string
		waf                  bool
		challenges, warnings int
	}{
		{name: "cloudflare server", headers: "Server: cloudflare\r\n", edges: "cloudflare", confidence: "medium"},
		{name: "cloudflare combined", headers: "server: CLOUDFLARE\r\ncF-rAy: private-id\r\n", edges: "cloudflare", confidence: "high"},
		{name: "cloudflare weak", headers: "Cf-Ray: private-id\r\n", edges: "cloudflare", confidence: "low"},
		{name: "cloudflare empty", headers: "Cf-Ray: \r\n"},
		{name: "challenge not WAF", headers: "Cf-Mitigated: challenge\r\n", edges: "cloudflare", confidence: "low", challenges: 1},
		{name: "duplicate challenge", headers: "Cf-Mitigated: challenge\r\nCf-Mitigated: challenge\r\n"},
		{name: "cloudfront server", headers: "Server: CloudFront\r\n", edges: "cloudfront", confidence: "medium"},
		{name: "cloudfront combined", headers: "X-Amz-Cf-Id: private-id\r\nX-Amz-Cf-Pop: private-pop\r\n", edges: "cloudfront", confidence: "high"},
		{name: "cloudfront cache", headers: "X-Cache: Hit from cloudfront\r\n", edges: "cloudfront", confidence: "low"},
		{name: "varnish server", headers: "Server: Varnish/7.5\r\n", edges: "varnish", confidence: "medium"},
		{name: "varnish combined", headers: "Via: 1.1 varnish\r\nX-Varnish: 123 456\r\n", edges: "varnish", confidence: "high"},
		{name: "varnish invalid id", headers: "X-Varnish: abc\r\n"},
		{name: "varnish invalid protocol", headers: "Via: invalid varnish\r\n"},
		{name: "varnish too many ids", headers: "X-Varnish: 123 456 789\r\n"},
		{name: "generic error", status: 403},
		{name: "generic rate limit", status: 429, headers: "Retry-After: 30\r\n"},
		{name: "generic cache", headers: "X-Cache: HIT\r\nAge: 30\r\n"},
		{name: "substring false positive", headers: "Server: notcloudflare\r\nVia: 1.1 notvarnish\r\nX-Cache: hit from cloudfront.example\r\n"},
		{name: "server comment", headers: "Server: nginx (cloudflare)\r\n"},
		{name: "conflicting servers", headers: "Server: cloudflare\r\nServer: CloudFront\r\n", edges: "cloudflare,cloudfront", confidence: "low", warnings: 1},
		{name: "layered providers", headers: "X-Cache: Hit from cloudfront\r\nVia: 1.1 varnish\r\n", edges: "cloudfront,varnish", confidence: "low"},
		{name: "AWS challenge", status: 202, headers: "X-Amzn-Waf-Action: challenge\r\n", waf: true},
		{name: "AWS captcha", status: 405, headers: "X-Amzn-Waf-Action: captcha\r\n", waf: true},
		{name: "AWS wrong status", status: 403, headers: "X-Amzn-Waf-Action: challenge\r\n", warnings: 1},
		{name: "AWS unknown action", status: 202, headers: "X-Amzn-Waf-Action: block\r\n", warnings: 1},
		{name: "AWS duplicate", status: 202, headers: "X-Amzn-Waf-Action: challenge\r\nX-Amzn-Waf-Action: captcha\r\n", warnings: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := tc.status
			if status == 0 {
				status = 200
			}
			data := fmt.Sprintf("HTTP/1.1 %d %s\r\n%sSet-Cookie: session=secret-cookie\r\n\r\nServer: cloudflare\nX-Amzn-Waf-Action: challenge", status, http.StatusText(status), tc.headers)
			service := f.Match([]byte(data))
			if service == nil || service.Web == nil {
				t.Fatal("HTTP observation missing")
			}
			web := service.Web
			var providers []string
			for _, edge := range web.Edge {
				providers = append(providers, edge.Provider)
				if edge.Confidence != tc.confidence {
					t.Fatalf("bad confidence: %+v", edge)
				}
			}
			if strings.Join(providers, ",") != tc.edges || len(web.Challenges) != tc.challenges || len(web.Warnings) != tc.warnings {
				t.Fatalf("unexpected observation: %+v", web)
			}
			if tc.waf {
				if web.WAF.Status != "signal_observed" || len(web.WAF.Detections) != 1 || web.WAF.Detections[0].Provider != "aws-waf" {
					t.Fatalf("missing WAF evidence: %+v", web.WAF)
				}
			} else if web.WAF.Status != "unknown" || len(web.WAF.Detections) != 0 {
				t.Fatalf("false WAF detection: %+v", web.WAF)
			}
			encoded, err := json.Marshal(web)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"private-id", "private-pop", "secret-cookie"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("retained secret: %s", encoded)
				}
			}
		})
	}
}

func TestWebIdentificationReusesExistingHTTPProbe(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "HEAD" {
			t.Errorf("extra request method %s", r.Method)
		}
		w.Header().Set("X-Amz-Cf-Id", "private-id")
		w.Header().Set("X-Amz-Cf-Pop", "private-pop")
		w.Header().Set("X-Amzn-Waf-Action", "challenge")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	i := newInspector(t, Options{Timeout: 3 * time.Second, MaxBytes: 8192, Active: true})
	service, info := i.Identify(context.Background(), targetFor(server.Listener.Addr().String()), nil)
	if service == nil || service.Web == nil || service.Web.WAF.Status != "signal_observed" || len(service.Web.Edge) != 1 || requests.Load() != 1 || info.Connections != 3 {
		t.Fatalf("service=%+v info=%+v requests=%d", service, info, requests.Load())
	}
}

func TestWebIsOmittedWithoutHTTPHeaders(t *testing.T) {
	f, _ := NewFingerprinter()
	if service := f.Match([]byte("SSH-2.0-OpenSSH_9.7\r\n")); service == nil || service.Web != nil {
		t.Fatal("SSH gained HTTP metadata")
	}
	if service := f.Match([]byte("HTTP/1.1 200 OK\r\nServer: cloudflare")); service != nil {
		t.Fatal("incomplete headers identified")
	}
}

func FuzzWebFingerprint(f *testing.F) {
	engine, err := NewFingerprinter()
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{"Server: cloudflare\r\nCf-Ray: id", "X-Amzn-Waf-Action: challenge", "X-Cache: Hit from cloudfront", "Via: 1.1 varnish\r\nX-Varnish: 123 456", "", "\xff"} {
		f.Add(seed, uint16(202))
	}
	f.Fuzz(func(t *testing.T, headers string, status uint16) {
		if len(headers) > MaxBytes {
			headers = headers[:MaxBytes]
		}
		data := fmt.Sprintf("HTTP/1.1 %d Test\r\n%s\r\n\r\n", 100+int(status)%500, headers)
		service := engine.Match([]byte(data))
		if service == nil || service.Web == nil {
			return
		}
		web := service.Web
		if len(web.Edge) > 3 || len(web.WAF.Detections) > 1 || len(web.Challenges) > 1 || len(web.Warnings) > 2 {
			t.Fatal("unbounded web metadata")
		}
		if web.WAF.Status != "unknown" && web.WAF.Status != "signal_observed" {
			t.Fatal("invalid WAF state")
		}
		groups := [][]model.WebDetection{web.Edge, web.WAF.Detections, web.Challenges}
		for _, group := range groups {
			for _, d := range group {
				if len(d.Evidence) > 4 || d.Confidence != "low" && d.Confidence != "medium" && d.Confidence != "high" {
					t.Fatalf("invalid detection: %+v", d)
				}
			}
		}
		encoded, err := json.Marshal(web)
		if err != nil || len(encoded) > 4096 {
			t.Fatalf("web output size=%d err=%v", len(encoded), err)
		}
	})
}
