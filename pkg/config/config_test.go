package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func cleanEnv(t *testing.T) {
	t.Helper()
	for _, binding := range bindings {
		key := "NETGO_" + strings.ToUpper(strings.ReplaceAll(binding.key, ".", "_"))
		previous, existed := os.LookupEnv(key)
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if existed {
				_ = os.Setenv(key, previous)
			} else {
				_ = os.Unsetenv(key)
			}
		})
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testFlags() *pflag.FlagSet {
	d := Defaults()
	f := pflag.NewFlagSet("test", pflag.ContinueOnError)
	f.Int("tcp-host-rate", d.TCP.HostRate, "")
	f.Int("tcp-host-concurrency", d.TCP.HostConcurrency, "")
	f.Bool("stats", d.Output.Stats, "")
	f.String("transport", d.Scan.Transport, "")
	f.String("udp-probe", d.UDP.Probe, "")
	f.Int("udp-host-rate", d.UDP.HostRate, "")
	f.Int("udp-max-bytes", d.UDP.MaxBytes, "")
	f.String("ports", d.Scan.Ports, "")
	f.Int("top-ports", d.Scan.TopPorts, "")
	f.Int("concurrency", d.Scan.Concurrency, "")
	f.Int("rate", d.Scan.Rate, "")
	f.Duration("timeout", d.Scan.Timeout, "")
	f.Int("retries", d.Scan.Retries, "")
	f.Int("max-hosts", d.Scan.MaxHosts, "")
	f.Int("max-probes", d.Scan.MaxProbes, "")
	f.Int("dns-concurrency", d.DNS.Concurrency, "")
	f.Duration("dns-timeout", d.DNS.Timeout, "")
	f.Bool("service", d.Service.Enabled, "")
	f.Bool("service-active", d.Service.Active, "")
	f.Int("service-concurrency", d.Service.Concurrency, "")
	f.Duration("service-timeout", d.Service.Timeout, "")
	f.Int("service-max-bytes", d.Service.MaxBytes, "")
	f.String("sni", d.Service.ServerName, "")
	f.String("format", d.Output.Format, "")
	f.String("output", d.Output.File, "")
	f.Bool("quiet", d.Output.Quiet, "")
	return f
}

func TestPrecedence(t *testing.T) {
	cleanEnv(t)
	path := writeConfig(t, "scan:\n  rate: 50\n  concurrency: 16\n  timeout: 2s\noutput:\n  format: ndjson\n")
	f := testFlags()
	cfg, err := Load(path, f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.Rate != 50 || cfg.Scan.Concurrency != 16 || cfg.Scan.Timeout != 2*time.Second || cfg.Output.Format != "ndjson" || cfg.Scan.Ports != "22,80,443" {
		t.Fatalf("file values or embedded fallbacks lost: %+v", cfg)
	}
	t.Setenv("NETGO_SCAN_RATE", "75")
	t.Setenv("NETGO_SCAN_TIMEOUT", "3s")
	t.Setenv("NETGO_OUTPUT_FORMAT", "console")
	cfg, err = Load(path, f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.Rate != 75 || cfg.Scan.Timeout != 3*time.Second || cfg.Output.Format != "console" {
		t.Fatalf("environment did not override file: %+v", cfg)
	}
	if err := f.Parse([]string{"--rate", "200", "--timeout", "1s", "--format", "ndjson"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path, f)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scan.Rate != 200 || cfg.Scan.Timeout != time.Second || cfg.Output.Format != "ndjson" {
		t.Fatalf("explicit flags equal to defaults must still override environment: %+v", cfg)
	}
}

func TestInvalidConfig(t *testing.T) {
	cleanEnv(t)
	for _, tc := range []struct{ name, yaml, want string }{
		{"unknown nested key", "scan:\n  concurency: 5\n", "concurency"},
		{"unknown top key", "scanner:\n  rate: 2\n", "scanner"},
		{"syntax", "scan: [", "read config"},
		{"ports type", "scan:\n  ports: [22, 80]\n", "config"},
		{"ports syntax", "scan:\n  ports: '80-22'\n", "scan.ports"},
		{"concurrency", "scan:\n  concurrency: 0\n", "scan.concurrency"},
		{"rate", "scan:\n  rate: -1\n", "scan.rate"},
		{"fraction", "scan:\n  retries: 1.5\n", "scan.retries"},
		{"boolean integer", "scan:\n  retries: true\n", "scan.retries"},
		{"retry garbage", "scan:\n  retries: bad\n", "config"},
		{"retry limit", "scan:\n  retries: 11\n", "scan.retries"},
		{"timeout", "scan:\n  timeout: -1s\n", "scan.timeout"},
		{"numeric timeout", "scan:\n  timeout: 10\n", "scan.timeout"},
		{"format", "output:\n  format: json\n", "output.format"},
		{"hosts", "scan:\n  max_hosts: 1000001\n", "scan.max_hosts"},
		{"probes", "scan:\n  max_probes: 0\n", "scan.max_probes"},
		{"DNS concurrency", "dns:\n  concurrency: 257\n", "dns.concurrency"},
		{"DNS timeout", "dns:\n  timeout: 0s\n", "dns.timeout"},
		{"quiet", "output:\n  quiet: garbage\n", "config"},
		{"service concurrency", "service:\n  concurrency: 0\n", "service.concurrency"},
		{"service timeout", "service:\n  timeout: 61s\n", "service.timeout"},
		{"service byte limit", "service:\n  max_bytes: 65537\n", "service.max_bytes"},
		{"service byte minimum", "service:\n  max_bytes: 255\n", "service.max_bytes"},
		{"SNI injection", "service:\n  server_name: 'bad/name'\n", "service.server_name"},
		{"SNI IP", "service:\n  server_name: '127.0.0.1.'\n", "service.server_name"},
		{"SNI double dot", "service:\n  server_name: 'example.test..'\n", "service.server_name"},
		{"transport", "scan:\n  transport: sctp\n", "scan.transport"},
		{"UDP probe", "udp:\n  probe: snmp\n", "udp.probe"},
		{"UDP host rate", "udp:\n  host_rate: 0\n", "udp.host_rate"},
		{"UDP byte cap", "udp:\n  max_bytes: 65536\n", "udp.max_bytes"},
		{"UDP byte minimum", "udp:\n  max_bytes: 47\n", "udp.max_bytes"},
		{"UDP TCP inspection", "scan:\n  transport: udp\nservice:\n  enabled: true\n", "for TCP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.yaml), nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestInvalidEnvironment(t *testing.T) {
	cleanEnv(t)
	for _, tc := range []struct{ key, value string }{
		{"NETGO_SCAN_RETRIES", "garbage"},
		{"NETGO_SCAN_RETRIES", ""},
		{"NETGO_SCAN_RATE", "1.5"},
		{"NETGO_SCAN_TIMEOUT", "bad"},
		{"NETGO_SCAN_PORTS", ""},
		{"NETGO_OUTPUT_FORMAT", ""},
		{"NETGO_SCAN_MAX_HOSTS", "0"},
		{"NETGO_DNS_TIMEOUT", "bad"},
		{"NETGO_OUTPUT_QUIET", "bad"},
		{"NETGO_SERVICE_ENABLED", "bad"},
		{"NETGO_SERVICE_ACTIVE", "bad"},
		{"NETGO_SERVICE_TIMEOUT", "bad"},
		{"NETGO_SERVICE_MAX_BYTES", "1.5"},
		{"NETGO_SCAN_TRANSPORT", ""},
		{"NETGO_UDP_HOST_RATE", "bad"},
		{"NETGO_UDP_MAX_BYTES", "1.5"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if _, err := Load("", nil); err == nil {
				t.Fatal("expected invalid environment to fail")
			}
		})
	}
}

func TestMissingConfig(t *testing.T) {
	cleanEnv(t)
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), nil); err == nil {
		t.Fatal("explicit missing config must fail")
	}
}

func TestDefaultsIgnoreEnvironment(t *testing.T) {
	t.Setenv("NETGO_SCAN_RATE", "bad")
	if Defaults().Scan.Rate != 200 {
		t.Fatal("defaults depend on environment")
	}
}

func TestConfigJSON(t *testing.T) {
	data, err := json.Marshal(Defaults())
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Scan struct {
			Timeout string `json:"timeout"`
			Rate    int    `json:"rate"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Scan.Timeout != "1s" || decoded.Scan.Rate != 200 {
		t.Fatalf("incorrect effective configuration JSON: %s", data)
	}
}
