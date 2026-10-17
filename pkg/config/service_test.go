package config

import (
	"testing"
	"time"
)

func TestServicePrecedenceAndDefaults(t *testing.T) {
	cleanEnv(t)
	defaults := Defaults()
	if defaults.Service.Enabled || !defaults.Service.Active || defaults.Service.Timeout != 3*time.Second {
		t.Fatalf("unexpected defaults: %+v", defaults.Service)
	}
	path := writeConfig(t, "service:\n  enabled: true\n  active: false\n  concurrency: 3\n  timeout: 2s\n  max_bytes: 512\n  server_name: example.test\n")
	flags := testFlags()
	cfg, err := Load(path, flags)
	if err != nil || !cfg.Service.Enabled || cfg.Service.Active || cfg.Service.Concurrency != 3 || cfg.Service.MaxBytes != 512 || cfg.Service.ServerName != "example.test" {
		t.Fatalf("file: %+v, %v", cfg.Service, err)
	}
	t.Setenv("NETGO_SERVICE_ENABLED", "false")
	t.Setenv("NETGO_SERVICE_TIMEOUT", "4s")
	t.Setenv("NETGO_SERVICE_SERVER_NAME", "virtual.test")
	cfg, err = Load(path, flags)
	if err != nil || cfg.Service.Enabled || cfg.Service.Timeout != 4*time.Second || cfg.Service.ServerName != "virtual.test" {
		t.Fatalf("environment: %+v, %v", cfg.Service, err)
	}
	if err := flags.Parse([]string{"--service", "--service-active", "--service-timeout", "3s", "--sni", "override.test"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path, flags)
	if err != nil || !cfg.Service.Enabled || !cfg.Service.Active || cfg.Service.Timeout != 3*time.Second || cfg.Service.ServerName != "override.test" {
		t.Fatalf("flags: %+v, %v", cfg.Service, err)
	}
}
