package config

import (
	"strings"
	"testing"
)

func TestHardeningSettingsPrecedence(t *testing.T) {
	cleanEnv(t)
	path := writeConfig(t, "tcp:\n  host_rate: 20\n  host_concurrency: 16\noutput:\n  stats: true\n")
	cfg, err := Load(path, testFlags())
	if err != nil || cfg.TCP.HostRate != 20 || cfg.TCP.HostConcurrency != 16 || !cfg.Output.Stats {
		t.Fatalf("file: %+v %v", cfg, err)
	}
	t.Setenv("NETGO_TCP_HOST_RATE", "30")
	t.Setenv("NETGO_TCP_HOST_CONCURRENCY", "8")
	t.Setenv("NETGO_OUTPUT_STATS", "false")
	cfg, err = Load(path, testFlags())
	if err != nil || cfg.TCP.HostRate != 30 || cfg.TCP.HostConcurrency != 8 || cfg.Output.Stats {
		t.Fatalf("env: %+v %v", cfg, err)
	}
	f := testFlags()
	if err := f.Parse([]string{"--tcp-host-rate", "0", "--tcp-host-concurrency", "0", "--stats"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path, f)
	if err != nil || cfg.TCP.HostRate != 0 || cfg.TCP.HostConcurrency != 0 || !cfg.Output.Stats {
		t.Fatalf("flags: %+v %v", cfg, err)
	}
}

func TestInvalidHardeningSettings(t *testing.T) {
	for _, tc := range []struct{ key, value, want string }{
		{"TCP_HOST_RATE", "-1", "tcp.host_rate"}, {"TCP_HOST_RATE", "1000001", "tcp.host_rate"}, {"TCP_HOST_RATE", "1.5", "integer"},
		{"TCP_HOST_CONCURRENCY", "-1", "tcp.host_concurrency"}, {"TCP_HOST_CONCURRENCY", "65536", "tcp.host_concurrency"}, {"TCP_HOST_CONCURRENCY", "", "integer"},
		{"OUTPUT_STATS", "maybe", "boolean"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			cleanEnv(t)
			t.Setenv("NETGO_"+tc.key, tc.value)
			_, err := Load("", nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
