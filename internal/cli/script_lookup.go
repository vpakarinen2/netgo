package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vpakarinen2/netgo/pkg/plugins"
)

var scriptName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

func isScriptName(selection string) bool {
	ext := filepath.Ext(selection)
	return scriptName.MatchString(selection) && ext != ".yaml" && ext != ".yml"
}

// Installed bundles take precedence over development examples. Resolve the
// executable itself so launchers/symlinks do not change its adjacent bundle root.
func scriptSearchDirs() []string {
	var dirs []string
	var executableDir string
	if executable, err := os.Executable(); err == nil {
		if canonical, err := filepath.EvalSymlinks(executable); err == nil {
			executable = canonical
		}
		executableDir = filepath.Dir(executable)
		dirs = append(dirs, filepath.Join(executableDir, "scripts"))
	}
	if config, err := os.UserConfigDir(); err == nil {
		dirs = append(dirs, filepath.Join(config, "netgo", "scripts"))
	}
	if executableDir != "" {
		dirs = append(dirs, filepath.Join(executableDir, "..", "examples", "plugins"))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(cwd, "examples", "plugins"))
	}
	return dirs
}

func resolveScriptSelections(selections, dirs []string) ([]string, error) {
	paths := make([]string, 0, len(selections))
	for _, selection := range selections {
		if !isScriptName(selection) {
			paths = append(paths, selection)
			continue
		}
		found := ""
		for _, dir := range dirs {
			path := filepath.Join(dir, selection, "plugin.yaml")
			info, err := os.Stat(path)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("look up script %q: %w", selection, err)
			}
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("script %q manifest %q must be a regular file", selection, path)
			}
			found = path
			break
		}
		if found == "" {
			return nil, fmt.Errorf("script %q not found; install its bundle as scripts/%s/plugin.yaml beside the executable, build examples with 'go run ./tools/build-plugins', or supply a manifest path (searched: %s)", selection, selection, strings.Join(dirs, ", "))
		}
		paths = append(paths, found)
	}
	return paths, nil
}

func loadSelectedScripts(ctx context.Context, selections, parameters []string, limits plugins.Limits) (*plugins.Engine, error) {
	paths, err := resolveScriptSelections(selections, scriptSearchDirs())
	if err != nil {
		return nil, err
	}
	engine, err := plugins.Load(ctx, paths, parameters, limits)
	if err != nil {
		return nil, err
	}
	for index, manifest := range engine.Manifests() {
		if isScriptName(selections[index]) && manifest.ID != selections[index] {
			_ = engine.Close(context.Background())
			return nil, fmt.Errorf("script name %q resolved to plugin ID %q; use the matching name or an explicit manifest path", selections[index], manifest.ID)
		}
	}
	return engine, nil
}
