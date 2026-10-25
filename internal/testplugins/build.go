// Package testplugins builds source-controlled WASI fixtures with standard Go.
package testplugins

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var mu sync.Mutex
var cache = map[string][]byte{}

func Build(t *testing.T, path string) []byte {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	if data, ok := cache[path]; ok {
		return data
	}
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(filepath.Dir(source)))
	output := filepath.Join(t.TempDir(), "guest.wasm")
	command := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-ldflags=-s -w", "-o", output, path)
	command.Dir = root
	for _, value := range os.Environ() {
		key := strings.SplitN(value, "=", 2)[0]
		if key != "GOOS" && key != "GOARCH" && key != "CGO_ENABLED" {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if data, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build WASI fixture: %v\n%s", err, data)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	cache[path] = data
	return data
}
