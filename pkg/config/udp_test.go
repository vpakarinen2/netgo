package config

import "testing"

func TestUDPConfigPrecedence(t *testing.T) {
	cleanEnv(t)
	path := writeConfig(t, "scan:\n  transport: udp\n  ports: '53,123'\nudp:\n  probe: dns\n  host_rate: 12\n  max_bytes: 1024\n")
	flags := testFlags()
	cfg, err := Load(path, flags)
	if err != nil || cfg.Scan.Transport != "udp" || cfg.Scan.Ports != "53,123" || cfg.UDP.Probe != "dns" || cfg.UDP.HostRate != 12 || cfg.UDP.MaxBytes != 1024 {
		t.Fatalf("file overrides failed: %+v, %v", cfg, err)
	}
	t.Setenv("NETGO_SCAN_TRANSPORT", "tcp")
	t.Setenv("NETGO_UDP_PROBE", "ntp")
	cfg, err = Load(path, flags)
	if err != nil || cfg.Scan.Transport != "tcp" || cfg.UDP.Probe != "ntp" {
		t.Fatalf("environment overrides failed: %+v %v", cfg, err)
	}
	if err := flags.Parse([]string{"--transport", "udp", "--udp-probe", "empty", "--udp-host-rate", "20"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path, flags)
	if err != nil || cfg.Scan.Transport != "udp" || cfg.UDP.Probe != "empty" || cfg.UDP.HostRate != 20 {
		t.Fatalf("flag overrides failed: %+v %v", cfg, err)
	}
}
