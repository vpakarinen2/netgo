// Package config loads and validates scanner configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/vpakarinen2/netgo/configs"
	"github.com/vpakarinen2/netgo/pkg/network/targets"
	"github.com/vpakarinen2/netgo/pkg/service"
)

// Config contains only settings implemented by the CLI. Target inputs are
// positional arguments and are deliberately not read from the environment.
type Config struct {
	Scan    Scan    `mapstructure:"scan" json:"scan"`
	DNS     DNS     `mapstructure:"dns" json:"dns"`
	Service Service `mapstructure:"service" json:"service"`
	Output  Output  `mapstructure:"output" json:"output"`
	UDP     UDP     `mapstructure:"udp" json:"udp"`
	TCP     TCP     `mapstructure:"tcp" json:"tcp"`
}

type TCP struct {
	HostRate        int `mapstructure:"host_rate" json:"host_rate"`
	HostConcurrency int `mapstructure:"host_concurrency" json:"host_concurrency"`
}

type Scan struct {
	Transport   string        `mapstructure:"transport" json:"transport"`
	Ports       string        `mapstructure:"ports" json:"ports"`
	TopPorts    int           `mapstructure:"top_ports" json:"top_ports"`
	Concurrency int           `mapstructure:"concurrency" json:"concurrency"`
	Rate        int           `mapstructure:"rate" json:"rate"`
	Timeout     time.Duration `mapstructure:"timeout" json:"-"`
	Retries     int           `mapstructure:"retries" json:"retries"`
	MaxHosts    int           `mapstructure:"max_hosts" json:"max_hosts"`
	MaxProbes   int           `mapstructure:"max_probes" json:"max_probes"`
}

type UDP struct {
	Probe    string `mapstructure:"probe" json:"probe"`
	HostRate int    `mapstructure:"host_rate" json:"host_rate"`
	MaxBytes int    `mapstructure:"max_bytes" json:"max_bytes"`
}

type DNS struct {
	Concurrency int           `mapstructure:"concurrency" json:"concurrency"`
	Timeout     time.Duration `mapstructure:"timeout" json:"-"`
}

type Output struct {
	OpenOnly bool   `mapstructure:"open_only" json:"open_only"`
	Stats    bool   `mapstructure:"stats" json:"stats"`
	Format   string `mapstructure:"format" json:"format"`
	File     string `mapstructure:"file" json:"file"`
	Quiet    bool   `mapstructure:"quiet" json:"quiet"`
}

type Service struct {
	Enabled     bool          `mapstructure:"enabled" json:"enabled"`
	Active      bool          `mapstructure:"active" json:"active"`
	Concurrency int           `mapstructure:"concurrency" json:"concurrency"`
	Timeout     time.Duration `mapstructure:"timeout" json:"-"`
	MaxBytes    int           `mapstructure:"max_bytes" json:"max_bytes"`
	ServerName  string        `mapstructure:"server_name" json:"server_name"`
}

var bindings = []struct{ key, flag string }{
	{"output.open_only", "open-only"},
	{"tcp.host_rate", "tcp-host-rate"},
	{"tcp.host_concurrency", "tcp-host-concurrency"},
	{"output.stats", "stats"},
	{"scan.transport", "transport"},
	{"udp.probe", "udp-probe"},
	{"udp.host_rate", "udp-host-rate"},
	{"udp.max_bytes", "udp-max-bytes"},
	{"scan.ports", "ports"},
	{"scan.top_ports", "top-ports"},
	{"scan.concurrency", "concurrency"},
	{"scan.rate", "rate"},
	{"scan.timeout", "timeout"},
	{"scan.retries", "retries"},
	{"scan.max_hosts", "max-hosts"},
	{"scan.max_probes", "max-probes"},
	{"dns.concurrency", "dns-concurrency"},
	{"dns.timeout", "dns-timeout"},
	{"service.enabled", "service"},
	{"service.active", "service-active"},
	{"service.concurrency", "service-concurrency"},
	{"service.timeout", "service-timeout"},
	{"service.max_bytes", "service-max-bytes"},
	{"service.server_name", "sni"},
	{"output.format", "format"},
	{"output.file", "output"},
	{"output.quiet", "quiet"},
}

// Load applies flags > NETGO_* environment variables > explicit YAML > embedded
// defaults. It never searches the current directory or home directory for files.
// A nil flag set is supported for library callers.
func Load(path string, flags *pflag.FlagSet) (Config, error) {
	return load(path, flags, true)
}

// Defaults returns the embedded settings, independent of environment variables.
// A malformed embedded configuration is a programming error.
func Defaults() Config {
	cfg, err := load("", nil, false)
	if err != nil {
		panic(fmt.Sprintf("invalid embedded configuration: %v", err))
	}
	return cfg
}

func load(path string, flags *pflag.FlagSet, environment bool) (Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(configs.Defaults)); err != nil {
		return Config{}, fmt.Errorf("read embedded defaults: %w", err)
	}
	portsPriority, topPriority := 0, 0
	if path != "" {
		file := viper.New()
		file.SetConfigFile(path)
		file.SetConfigType("yaml")
		if err := file.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("read config %q: %w", path, err)
		}
		// Check the file before applying overrides so misspelled keys cannot be
		// hidden by flags or environment values.
		var shape Config
		if err := file.UnmarshalExact(&shape); err != nil {
			return Config{}, fmt.Errorf("decode config %q: %w", path, err)
		}
		if file.IsSet("scan.ports") {
			portsPriority = 1
		}
		if file.IsSet("scan.top_ports") {
			topPriority = 1
		}
		if err := v.MergeConfigMap(file.AllSettings()); err != nil {
			return Config{}, fmt.Errorf("merge config: %w", err)
		}
	}
	if environment {
		if _, ok := os.LookupEnv("NETGO_SCAN_PORTS"); ok {
			portsPriority = 2
		}
		if _, ok := os.LookupEnv("NETGO_SCAN_TOP_PORTS"); ok {
			topPriority = 2
		}
		v.SetEnvPrefix("NETGO")
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		v.AutomaticEnv()
		v.AllowEmptyEnv(true)
	}
	for _, binding := range bindings {
		if flags != nil {
			flag := flags.Lookup(binding.flag)
			if flag == nil {
				return Config{}, fmt.Errorf("missing flag binding --%s", binding.flag)
			}
			if err := v.BindPFlag(binding.key, flag); err != nil {
				return Config{}, fmt.Errorf("bind --%s: %w", binding.flag, err)
			}
		}
	}
	var cfg Config
	var err error
	if cfg.Output.OpenOnly, err = boolValue(v, "output.open_only"); err != nil {
		return Config{}, err
	}
	if cfg.TCP.HostRate, err = intValue(v, "tcp.host_rate"); err != nil {
		return Config{}, err
	}
	if cfg.TCP.HostConcurrency, err = intValue(v, "tcp.host_concurrency"); err != nil {
		return Config{}, err
	}
	if cfg.Output.Stats, err = boolValue(v, "output.stats"); err != nil {
		return Config{}, err
	}
	if flags != nil {
		if flags.Changed("ports") {
			portsPriority = 3
		}
		if flags.Changed("top-ports") {
			topPriority = 3
		}
	}
	if cfg.Scan.Transport, err = stringValue(v, "scan.transport"); err != nil {
		return Config{}, err
	}
	if cfg.UDP.Probe, err = stringValue(v, "udp.probe"); err != nil {
		return Config{}, err
	}
	if cfg.UDP.HostRate, err = intValue(v, "udp.host_rate"); err != nil {
		return Config{}, err
	}
	if cfg.UDP.MaxBytes, err = intValue(v, "udp.max_bytes"); err != nil {
		return Config{}, err
	}
	if cfg.Scan.Ports, err = stringValue(v, "scan.ports"); err != nil {
		return Config{}, err
	}
	if topPriority >= portsPriority {
		if cfg.Scan.TopPorts, err = intValue(v, "scan.top_ports"); err != nil {
			return Config{}, err
		}
	}
	if cfg.Scan.Concurrency, err = intValue(v, "scan.concurrency"); err != nil {
		return Config{}, err
	}
	if cfg.Scan.Rate, err = intValue(v, "scan.rate"); err != nil {
		return Config{}, err
	}
	if cfg.Scan.Retries, err = intValue(v, "scan.retries"); err != nil {
		return Config{}, err
	}
	if cfg.Scan.MaxHosts, err = intValue(v, "scan.max_hosts"); err != nil {
		return Config{}, err
	}
	if cfg.Scan.MaxProbes, err = intValue(v, "scan.max_probes"); err != nil {
		return Config{}, err
	}
	if cfg.DNS.Concurrency, err = intValue(v, "dns.concurrency"); err != nil {
		return Config{}, err
	}
	timeout, err := stringValue(v, "scan.timeout")
	if err != nil {
		return Config{}, err
	}
	if cfg.Scan.Timeout, err = time.ParseDuration(timeout); err != nil {
		return Config{}, fmt.Errorf("scan.timeout: %w", err)
	}
	if cfg.Output.Format, err = stringValue(v, "output.format"); err != nil {
		return Config{}, err
	}
	dnsTimeout, err := stringValue(v, "dns.timeout")
	if err != nil {
		return Config{}, err
	}
	if cfg.DNS.Timeout, err = time.ParseDuration(dnsTimeout); err != nil {
		return Config{}, fmt.Errorf("dns.timeout: %w", err)
	}
	if cfg.Output.File, err = stringValue(v, "output.file"); err != nil {
		return Config{}, err
	}
	if cfg.Output.Quiet, err = boolValue(v, "output.quiet"); err != nil {
		return Config{}, err
	}
	if cfg.Service.Enabled, err = boolValue(v, "service.enabled"); err != nil {
		return Config{}, err
	}
	if cfg.Service.Active, err = boolValue(v, "service.active"); err != nil {
		return Config{}, err
	}
	if cfg.Service.Concurrency, err = intValue(v, "service.concurrency"); err != nil {
		return Config{}, err
	}
	if cfg.Service.MaxBytes, err = intValue(v, "service.max_bytes"); err != nil {
		return Config{}, err
	}
	if cfg.Service.ServerName, err = stringValue(v, "service.server_name"); err != nil {
		return Config{}, err
	}
	serviceTimeout, err := stringValue(v, "service.timeout")
	if err != nil {
		return Config{}, err
	}
	if cfg.Service.Timeout, err = time.ParseDuration(serviceTimeout); err != nil {
		return Config{}, fmt.Errorf("service.timeout: %w", err)
	}
	if err := cfg.selectPorts(portsPriority, topPriority); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the effective configuration before any network work begins.
func (c Config) Validate() error {
	var problems []error
	if c.TCP.HostRate < 0 || c.TCP.HostRate > 1000000 {
		problems = append(problems, errors.New("tcp.host_rate must be between 0 and 1000000 (0 disables)"))
	}
	if c.TCP.HostConcurrency < 0 || c.TCP.HostConcurrency > 65535 {
		problems = append(problems, errors.New("tcp.host_concurrency must be between 0 and 65535 (0 disables)"))
	}
	if c.Scan.TopPorts != 0 {
		if _, err := targets.TopPorts(c.Scan.TopPorts); err != nil {
			problems = append(problems, fmt.Errorf("scan.top_ports: %w", err))
		}
		if c.Scan.Transport != "tcp" {
			problems = append(problems, errors.New("scan.top_ports supports TCP only; use --ports for UDP"))
		}
	}
	if c.Scan.Transport != "tcp" && c.Scan.Transport != "udp" {
		problems = append(problems, errors.New("scan.transport must be tcp or udp"))
	}
	if c.UDP.Probe != "auto" && c.UDP.Probe != "empty" && c.UDP.Probe != "dns" && c.UDP.Probe != "ntp" {
		problems = append(problems, errors.New("udp.probe must be auto, empty, dns, or ntp"))
	}
	if c.UDP.HostRate < 1 || c.UDP.HostRate > 1000000 {
		problems = append(problems, errors.New("udp.host_rate must be between 1 and 1000000 attempts per second"))
	}
	if c.UDP.MaxBytes < 48 || c.UDP.MaxBytes > 65535 {
		problems = append(problems, errors.New("udp.max_bytes must be between 48 and 65535"))
	}
	if c.Scan.Transport == "udp" && c.Service.Enabled {
		problems = append(problems, errors.New("--service is for TCP; UDP protocol identification is built into its probes"))
	}
	if _, err := targets.ParsePorts(c.Scan.Ports); err != nil {
		problems = append(problems, fmt.Errorf("scan.ports: %w", err))
	}
	if c.Scan.Concurrency < 1 || c.Scan.Concurrency > 65535 {
		problems = append(problems, errors.New("scan.concurrency must be between 1 and 65535"))
	}
	if c.Scan.Rate < 1 || c.Scan.Rate > 1000000 {
		problems = append(problems, errors.New("scan.rate must be between 1 and 1000000 attempts per second"))
	}
	if c.Scan.Timeout <= 0 || c.Scan.Timeout > time.Minute {
		problems = append(problems, errors.New("scan.timeout must be greater than zero and at most 1m"))
	}
	if c.Scan.Retries < 0 || c.Scan.Retries > 10 {
		problems = append(problems, errors.New("scan.retries must be between 0 and 10"))
	}
	if c.Scan.MaxHosts < 1 || c.Scan.MaxHosts > 1000000 {
		problems = append(problems, errors.New("scan.max_hosts must be between 1 and 1000000"))
	}
	if c.Scan.MaxProbes < 1 || c.Scan.MaxProbes > 100000000 {
		problems = append(problems, errors.New("scan.max_probes must be between 1 and 100000000"))
	}
	if c.DNS.Concurrency < 1 || c.DNS.Concurrency > 256 {
		problems = append(problems, errors.New("dns.concurrency must be between 1 and 256"))
	}
	if c.DNS.Timeout <= 0 || c.DNS.Timeout > time.Minute {
		problems = append(problems, errors.New("dns.timeout must be greater than zero and at most 1m"))
	}
	if strings.IndexByte(c.Output.File, 0) >= 0 {
		problems = append(problems, errors.New("output.file contains a null byte"))
	}
	if c.Output.Format != "console" && c.Output.Format != "ndjson" {
		problems = append(problems, errors.New("output.format must be console or ndjson"))
	}
	if c.Service.Concurrency < 1 || c.Service.Concurrency > 256 {
		problems = append(problems, errors.New("service.concurrency must be between 1 and 256"))
	}
	if c.Service.Timeout <= 0 || c.Service.Timeout > time.Minute {
		problems = append(problems, errors.New("service.timeout must be greater than zero and at most 1m"))
	}
	if c.Service.MaxBytes < 256 || c.Service.MaxBytes > service.MaxBytes {
		problems = append(problems, errors.New("service.max_bytes must be between 256 and 65536"))
	}
	if c.Service.ServerName != "" && !service.ValidServerName(c.Service.ServerName) {
		problems = append(problems, errors.New("service.server_name must be an ASCII DNS hostname"))
	}
	return errors.Join(problems...)
}

func boolValue(v *viper.Viper, key string) (bool, error) {
	value, err := strconv.ParseBool(fmt.Sprint(v.Get(key)))
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return value, nil
}

func stringValue(v *viper.Viper, key string) (string, error) {
	value, ok := v.Get(key).(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return value, nil
}

func intValue(v *viper.Viper, key string) (int, error) {
	// Viper's integer getters silently coerce malformed input to zero or truncate
	// fractional values. Parse explicitly, including for retries where zero is valid.
	value, err := strconv.Atoi(fmt.Sprint(v.Get(key)))
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	return value, nil
}
