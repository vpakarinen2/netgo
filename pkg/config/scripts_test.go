package config

import (
	"strings"
	"testing"
	"time"
)

func TestScriptConfigPriorityAndValidation(t *testing.T) {
	cleanEnv(t)
	path := writeConfig(t, "service:\n  enabled: true\nscripts:\n  paths: [file.yaml]\n  timeout: 1s\n  memory_mib: 32\n")
	flags := testFlags()
	cfg, err := Load(path, flags)
	if err != nil || len(cfg.Scripts.Paths) != 1 || cfg.Scripts.Paths[0] != "file.yaml" || cfg.Scripts.Timeout != time.Second {
		t.Fatalf("cfg=%+v err=%v", cfg.Scripts, err)
	}
	t.Setenv("NETGO_SCRIPTS_PATHS", `["env.yaml"]`)
	t.Setenv("NETGO_SCRIPTS_TIMEOUT", "2s")
	cfg, err = Load(path, flags)
	if err != nil || cfg.Scripts.Paths[0] != "env.yaml" || cfg.Scripts.Timeout != 2*time.Second {
		t.Fatalf("environment priority lost: %+v %v", cfg.Scripts, err)
	}
	if err := flags.Parse([]string{"--script", "first.yaml", "--script", "second.yaml", "--script-timeout", "3s", "--script-param", "first.text=contains,commas"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path, flags)
	if err != nil || len(cfg.Scripts.Paths) != 2 || cfg.Scripts.Paths[0] != "first.yaml" || cfg.Scripts.Timeout != 3*time.Second || cfg.Scripts.Parameters[0] != "first.text=contains,commas" {
		t.Fatalf("flag priority or parameter preservation lost: %+v %v", cfg.Scripts, err)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Service.Enabled = false }, func(c *Config) { c.Scripts.MemoryMiB = 1024 }, func(c *Config) { c.Scripts.Concurrency = 16; c.Scripts.MemoryMiB = 64 }, func(c *Config) { c.Scripts.Timeout = 6 * time.Second }} {
		broken := cfg
		mutate(&broken)
		if err := broken.Validate(); err == nil {
			t.Fatal("invalid script configuration accepted")
		}
	}
	t.Setenv("NETGO_SCRIPTS_PATHS", "not-an-array")
	if _, err := Load(path, testFlags()); err == nil || !strings.Contains(err.Error(), "scripts.paths") {
		t.Fatalf("malformed array accepted: %v", err)
	}
}
