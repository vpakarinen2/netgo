package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScriptNameLookupPriorityAndExplicitPaths(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	for _, dir := range []string{first, second} {
		bundle := filepath.Join(dir, "my.check")
		if err := os.MkdirAll(bundle, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundle, "plugin.yaml"), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	explicit := filepath.Join(t.TempDir(), "custom plugin.yaml")
	selections := []string{"my.check", explicit, "plugin.yaml", "./custom"}
	paths, err := resolveScriptSelections(selections, []string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if paths[0] != filepath.Join(first, "my.check", "plugin.yaml") {
		t.Fatalf("lookup ignored search priority: %v", paths)
	}
	for index := 1; index < len(paths); index++ {
		if paths[index] != selections[index] {
			t.Fatalf("explicit path changed: %q", paths[index])
		}
	}
	if _, err := resolveScriptSelections([]string{"missing"}, []string{first}); err == nil || !strings.Contains(err.Error(), "not found") || !strings.Contains(err.Error(), "build-plugins") {
		t.Fatalf("missing-script error is not actionable: %v", err)
	}
	// A broken higher-priority install must not silently select another bundle.
	if err := os.MkdirAll(filepath.Join(first, "broken", "plugin.yaml"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveScriptSelections([]string{"broken"}, []string{first, second}); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("invalid manifest path accepted: %v", err)
	}
}

func installTestScript(t *testing.T, manifest, name string) {
	t.Helper()
	config := t.TempDir()
	t.Setenv("APPDATA", config)
	t.Setenv("XDG_CONFIG_HOME", config)
	if runtime.GOOS == "darwin" {
		t.Setenv("HOME", config)
		config = filepath.Join(config, "Library", "Application Support")
	}
	dir := filepath.Join(config, "netgo", "scripts", name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(manifest))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(manifest), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
