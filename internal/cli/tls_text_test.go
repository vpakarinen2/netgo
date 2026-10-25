package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/internal/testplugins"
)

func TestTextTLSHostnameReportsCheckWithoutCertificateDump(t *testing.T) {
	module := testplugins.Build(t, "./examples/plugins/tls-hostname")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "check.wasm"), module, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(module)
	manifest := filepath.Join(dir, "plugin.yaml")
	data := fmt.Sprintf("api_version: netgo.script/v1\nid: tls-hostname\nversion: 0.1.0\ndescription: Check certificate hostname\nauthor: tests\nlicense: Apache-2.0\nmodule: check.wasm\nsha256: %x\npermissions: [scan.read]\nmatch:\n  transport: tcp\n  states: [open]\n  services: [https, tls]\n", digest)
	if err := os.WriteFile(manifest, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	installTestScript(t, manifest, "tls-hostname")
	certificateModule := testplugins.Build(t, "./examples/plugins/tls-certificate")
	if err := os.WriteFile(filepath.Join(dir, "certificate.wasm"), certificateModule, 0600); err != nil {
		t.Fatal(err)
	}
	certificateManifest := filepath.Join(dir, "certificate.yaml")
	certificateData := fmt.Sprintf("api_version: netgo.script/v1\nid: tls-certificate\nversion: 0.1.0\ndescription: Report certificate information\nauthor: tests\nlicense: Apache-2.0\nmodule: certificate.wasm\nsha256: %x\npermissions: [scan.read]\nmatch:\n  transport: tcp\n  states: [open]\n  services: [https, tls]\n", sha256.Sum256(certificateModule))
	if err := os.WriteFile(certificateManifest, []byte(certificateData), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	if err := server.Certificate().VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("test requires a matching certificate: %v", err)
	}
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		useScript   bool
		sni         string
		certificate bool
	}{
		{name: "no script"},
		{name: "matching certificate", useScript: true},
		{name: "hostname mismatch", useScript: true, sni: "mismatch.test"},
		{name: "dedicated certificate report", certificate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"127.0.0.1", "-p", port, "--service", "--format", "text", "--quiet"}
			if tc.useScript {
				args = append(args, "--script", "tls-hostname")
			}
			if tc.certificate {
				args = append(args, "--script", certificateManifest)
			}
			if tc.sni != "" {
				args = append(args, "--sni", tc.sni)
			}
			var out bytes.Buffer
			cmd := NewCommand("test")
			cmd.SetOut(&out)
			cmd.SetArgs(args)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := cmd.ExecuteContext(ctx); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "TLS: TLS") {
				t.Fatalf("TLS identification missing: %s", out.String())
			}
			if tc.certificate {
				for _, field := range []string{"tls-certificate v0.1.0 — completed", "Subject:", "Issuer:", "SHA-256 fingerprint:", "Expires:", "Hostname matches: true", "Certificate trust: not checked"} {
					if !strings.Contains(out.String(), field) {
						t.Fatalf("certificate report field %q missing: %s", field, out.String())
					}
				}
				if strings.Contains(out.String(), "No findings.") || !strings.Contains(out.String(), "Scripts: 1 invocations, 0 findings") {
					t.Fatalf("certificate details confused with findings: %s", out.String())
				}
				return
			}
			for _, field := range []string{"Certificate hostname:", "Certificate issuer:", "Certificate subject:", "Expires:", "Certificate trust:"} {
				if strings.Contains(out.String(), field) {
					t.Fatalf("unexpected certificate dump (%q): %s", field, out.String())
				}
			}
			if tc.useScript {
				finding := "No findings."
				if tc.sni != "" {
					finding = "[low] observation: Certificate does not match"
				}
				if !strings.Contains(out.String(), "tls-hostname v0.1.0 — completed") || !strings.Contains(out.String(), finding) {
					t.Fatalf("script result missing: %s", out.String())
				}
			}
		})
	}
}
