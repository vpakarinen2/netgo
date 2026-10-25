package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/internal/testplugins"
	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/output"
)

func cliScriptBundle(t *testing.T) string {
	t.Helper()
	module := testplugins.Build(t, "./examples/plugins/ssh-banner")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh.wasm"), module, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(module)
	manifest := fmt.Sprintf("api_version: netgo.script/v1\nid: ssh-banner\nversion: 0.1.0\ndescription: Match SSH greetings\nauthor: tests\nlicense: Apache-2.0\nmodule: ssh.wasm\nsha256: %x\npermissions: [scan.read]\nmatch:\n  transport: tcp\n  states: [open]\n  services: [ssh]\nparameters:\n  contains:\n    type: string\n    default: OpenSSH\n", digest)
	path := filepath.Join(dir, "plugin.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScriptCommandsAndPreflight(t *testing.T) {
	manifest := cliScriptBundle(t)
	installTestScript(t, manifest, "ssh-banner")
	fixture := filepath.Join("..", "..", "examples", "plugins", "fixtures", "ssh.json")
	for _, args := range [][]string{{"scripts", "validate", manifest}, {"scripts", "test", manifest, "--input", fixture}, {"scripts", "validate", "ssh-banner"}, {"scripts", "test", "ssh-banner", "--input", fixture, "--script-param", "ssh-banner.contains=OpenSSH"}} {
		var out bytes.Buffer
		cmd := NewCommand("test")
		cmd.SetArgs(args)
		cmd.SetOut(&out)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		var value map[string]any
		if err := json.Unmarshal(out.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		if value["id"] != "ssh-banner" {
			t.Fatalf("wrong output: %s", out.String())
		}
		if args[1] == "test" && value["status"] != "completed" {
			t.Fatalf("fixture failed: %s", out.String())
		}
	}
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"invalid/target", "--service", "--script", filepath.Join(t.TempDir(), "missing.yaml")})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "initialize scripts") {
		t.Fatalf("plugin preflight did not run before target planning: %v", err)
	}
	cmd = NewCommand("test")
	cmd.SetArgs([]string{"127.0.0.1", "--script", manifest})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "scripts require TCP and --service") {
		t.Fatalf("script without service accepted: %v", err)
	}
	cmd = NewCommand("test")
	cmd.SetArgs([]string{"invalid/target", "--service", "--script", "no-such-script"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("name lookup did not run before target planning: %v", err)
	}
	installTestScript(t, manifest, "wrong-name")
	cmd = NewCommand("test")
	cmd.SetArgs([]string{"scripts", "validate", "wrong-name"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "resolved to plugin ID") {
		t.Fatalf("plugin name/ID mismatch accepted: %v", err)
	}
}

func TestLiveScanRunsWasmWithoutChangingPortEvidence(t *testing.T) {
	manifest := cliScriptBundle(t)
	installTestScript(t, manifest, "ssh-banner")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(conn, "SSH-2.0-OpenSSH_9.7p1\r\n")
			_ = conn.Close()
		}
	}()
	defer func() { listener.Close(); <-done }()
	port := listener.Addr().(*net.TCPAddr).Port
	var out bytes.Buffer
	cmd := NewCommand("test")
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"127.0.0.1", "-p", strconv.Itoa(port), "--service", "--script", "ssh-banner", "--format", "ndjson", "--quiet"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&out)
	var result, summary output.Event
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&summary); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != 1 || result.Result == nil || result.Result.State != model.Open || result.Result.Reason != "connected" || result.Result.Service.Product != "OpenSSH" || len(result.Result.Scripts) != 1 || result.Result.Scripts[0].Status != "completed" || len(result.Result.Scripts[0].Findings) != 1 {
		t.Fatalf("bad result: %+v", result.Result)
	}
	if summary.Summary == nil || summary.Summary.Status != "completed" || summary.Summary.Scripts == nil || summary.Summary.Scripts.Findings != 1 {
		t.Fatalf("bad summary: %+v", summary.Summary)
	}
	out.Reset()
	cmd = NewCommand("test")
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"127.0.0.1", "-p", strconv.Itoa(port), "--service", "--script", "ssh-banner", "--format", "text", "--quiet"})
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"State: open (connected)", "Product: OpenSSH/9.7p1", "ssh-banner v0.1.0", "[info] match:", "Evidence fields:", "Scan completed:", "Scripts: 1 invocations, 1 findings"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in live text output:\n%s", want, out.String())
		}
	}
}
