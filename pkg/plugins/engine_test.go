package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vpakarinen2/netgo/internal/testplugins"
	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/plugins/sdk"
)

func testBundle(t *testing.T, module []byte, mode string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "guest.wasm"), module, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(module)
	manifest := fmt.Sprintf("api_version: netgo.script/v1\nid: fixture\nversion: 0.1.0\ndescription: Test command\nauthor: tests\nlicense: Apache-2.0\nmodule: guest.wasm\nsha256: %x\npermissions: [scan.read]\nmatch:\n  transport: tcp\n  states: [open]\nparameters:\n  mode:\n    type: string\n    default: %s\n", digest, mode)
	path := filepath.Join(dir, "plugin.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testRequest() sdk.Request {
	return sdk.Request{APIVersion: sdk.APIVersion, EvaluationTime: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC), Result: model.Result{Target: model.Target{Address: netip.MustParseAddr("127.0.0.1"), Port: 22, Transport: model.TCP}, State: model.Open, Method: model.TCPConnect}}
}

func TestRuntimeBoundsAndProtocol(t *testing.T) {
	module := testplugins.Build(t, "./pkg/plugins/testdata/guest")
	t.Setenv("NETGO_PLUGIN_SECRET", "must-not-be-inherited")
	for _, tc := range []struct{ mode, status string }{{"valid", "completed"}, {"deny", "completed"}, {"loop", "timeout"}, {"memory", "error"}, {"stdout", "error"}, {"stderr", "error"}, {"trap", "error"}, {"exit", "error"}, {"invalid", "error"}, {"duplicate", "error"}, {"unknown", "error"}, {"trailing", "error"}, {"utf8", "error"}, {"missing", "error"}} {
		t.Run(tc.mode, func(t *testing.T) {
			engine, err := Load(context.Background(), []string{testBundle(t, module, tc.mode)}, nil, Limits{Timeout: 200 * time.Millisecond, MemoryMiB: 64})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close(context.Background())
			started := time.Now()
			run, err := engine.Test(context.Background(), testRequest())
			if err != nil || run.Status != tc.status || len(run.Stderr) > MaxStderr || time.Since(started) > 2*time.Second {
				t.Fatalf("run=%+v err=%v", run, err)
			}
			if tc.status != "completed" && (run.Error == "" || len(run.Findings) > 0) {
				t.Fatalf("invalid failure: %+v", run)
			}
		})
	}
}

func TestFreshInstancesKeepTargetsAndCancellation(t *testing.T) {
	module := testplugins.Build(t, "./pkg/plugins/testdata/guest")
	path := testBundle(t, module, "valid")
	engine, err := Load(context.Background(), []string{path}, nil, Limits{Timeout: time.Second, MemoryMiB: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close(context.Background())
	var group sync.WaitGroup
	for port := 1; port <= 12; port++ {
		group.Add(1)
		go func(port int) {
			defer group.Done()
			request := testRequest()
			request.Result.Target.Port = uint16(port)
			run, err := engine.Test(context.Background(), request)
			want := fmt.Sprintf("127.0.0.1:%d instance=1", port)
			if err != nil || run.Status != "completed" || len(run.Findings) != 1 || run.Findings[0].Message != want {
				t.Errorf("run=%+v err=%v expected %s", run, err, want)
			}
		}(port)
	}
	group.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	run, err := engine.Test(ctx, testRequest())
	if err != nil || run.Status != "canceled" {
		t.Fatalf("cancellation not propagated: %+v %v", run, err)
	}
	if err := engine.CheckCount(MaxRuns + 1); err == nil {
		t.Fatal("unbounded planned executions")
	}
}

func TestManifestValidationAndOverrides(t *testing.T) {
	module := testplugins.Build(t, "./pkg/plugins/testdata/guest")
	for _, tc := range []struct{ old, new string }{{"scan.read", "network.tcp"}, {"netgo.script/v1", "netgo.script/v2"}, {"guest.wasm", "../guest.wasm"}, {"description: Test command", "description: Test command\nunknown: field"}, {"id: fixture", "id: fixture\nid: other"}} {
		path := testBundle(t, module, "valid")
		data, _ := os.ReadFile(path)
		if err := os.WriteFile(path, []byte(strings.Replace(string(data), tc.old, tc.new, 1)), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadManifest(path); err == nil {
			t.Errorf("accepted invalid manifest %s", tc.new)
		}
	}
	path := testBundle(t, module, "valid")
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "guest.wasm"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadManifest(path); err == nil {
		t.Fatal("checksum change accepted")
	}
	path = testBundle(t, module, "valid")
	if _, err := Load(context.Background(), []string{path, path}, nil, Limits{Timeout: time.Second, MemoryMiB: 64}); err == nil {
		t.Fatal("duplicate plugin accepted")
	}
	for _, values := range [][]string{{"other.mode=valid"}, {"fixture.unknown=x"}, {"fixture.mode=valid", "fixture.mode=deny"}} {
		if _, err := Load(context.Background(), []string{path}, values, Limits{Timeout: time.Second, MemoryMiB: 64}); err == nil {
			t.Errorf("accepted invalid overrides %v", values)
		}
	}
	engine, err := Load(context.Background(), []string{path}, []string{"fixture.mode=deny"}, Limits{Timeout: time.Second, MemoryMiB: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close(context.Background())
	request := testRequest()
	request.Parameters = map[string]json.RawMessage{"mode": json.RawMessage(`"invalid"`)}
	run, err := engine.Test(context.Background(), request)
	if err != nil || run.Status != "completed" {
		t.Fatalf("explicit override did not win: %+v %v", run, err)
	}
}

func TestCommandImportsAndBundleSymlinks(t *testing.T) {
	module := testplugins.Build(t, "./pkg/plugins/testdata/guest")
	for _, mutation := range []struct{ old, new string }{{"wasi_snapshot_preview1", "wasi_snapshot_previewX"}, {"_start", "_other"}} {
		changed := bytes.ReplaceAll(module, []byte(mutation.old), []byte(mutation.new))
		path := testBundle(t, changed, "valid")
		if _, err := Load(context.Background(), []string{path}, nil, Limits{Timeout: time.Second, MemoryMiB: 64}); err == nil {
			t.Fatalf("accepted unsupported module %s", mutation.new)
		}
	}
	t.Run("symlink escape", func(t *testing.T) {
		path := testBundle(t, module, "valid")
		outside := filepath.Join(t.TempDir(), "outside.wasm")
		if err := os.WriteFile(outside, module, 0600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(filepath.Dir(path), "linked.wasm")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		data, _ := os.ReadFile(path)
		if err := os.WriteFile(path, []byte(strings.Replace(string(data), "module: guest.wasm", "module: linked.wasm", 1)), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadManifest(path); err == nil {
			t.Fatal("module symlink escaped bundle")
		}
	})
}
