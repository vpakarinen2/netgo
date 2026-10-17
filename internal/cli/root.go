// Package cli constructs the command independently of process globals.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vpakarinen2/netgo/pkg/config"
)

// NewCommand creates an isolated CLI command suitable for embedding and tests.
func NewCommand(version string) *cobra.Command {
	var path string
	var check bool
	cmd := &cobra.Command{
		Use:           "scan [targets...]",
		Short:         "A modern TCP connect scanner and UDP prober",
		Long:          "Netgo is a TCP connect scanner and UDP prober for IP addresses, CIDRs, and\nhostnames. Work is bounded and rate-limited. Results stream to stdout;\nprogress and diagnostics go to stderr.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Example:       "  scan 127.0.0.1 -p 22,80,443\n  scan localhost -p 22,443 --service --format ndjson\n  scan 127.0.0.1 --transport udp -p 53,123 --format ndjson\n  scan 192.0.2.0/28 --rate 100 --format ndjson\n  scan --config configs/default.yaml --check-config",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			cfg, err := config.Load(path, cmd.Flags())
			if err != nil {
				return fmt.Errorf("invalid configuration: %w", err)
			}
			if check {
				if len(args) != 0 {
					return errors.New("--check-config does not accept target arguments")
				}
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(cfg); err != nil {
					return fmt.Errorf("write configuration: %w", err)
				}
				return nil
			}
			if len(args) == 0 {
				return cmd.Help()
			}
			return runScan(cmd.Context(), cfg, args, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	// Read help defaults from the same embedded source as runtime configuration.
	// Do not consult the environment until command execution.
	defaults := config.Defaults()
	flags := cmd.Flags()
	flags.StringVar(&path, "config", "", "Explicit YAML configuration file")
	flags.BoolVar(&check, "check-config", false, "Validate settings and print effective JSON without network activity")
	flags.String("transport", defaults.Scan.Transport, "Scan transport: tcp or udp")
	flags.String("udp-probe", defaults.UDP.Probe, "UDP payload: auto (DNS on 53, NTP on 123), empty, dns, or ntp")
	flags.Int("udp-host-rate", defaults.UDP.HostRate, "Maximum UDP attempts per host per second (1-1000000)")
	flags.Int("udp-max-bytes", defaults.UDP.MaxBytes, "Maximum accepted UDP response size (48-65535 bytes)")
	flags.StringP("ports", "p", defaults.Scan.Ports, "Ports and inclusive ranges, e.g. 22,80,8000-8010")
	flags.Int("top-ports", defaults.Scan.TopPorts, "TCP common-port preset: 10, 100, or 1000 (0 disables; alternative to --ports)")
	flags.Int("concurrency", defaults.Scan.Concurrency, "Maximum in-flight probes (1-65535)")
	flags.Int("rate", defaults.Scan.Rate, "Maximum probe starts per second, including TCP identification (1-1000000)")
	flags.Duration("timeout", defaults.Scan.Timeout, "Per-attempt timeout, greater than zero and at most 1m")
	flags.Int("retries", defaults.Scan.Retries, "Additional attempts after the first (0-10)")
	flags.Int("max-hosts", defaults.Scan.MaxHosts, "Maximum unique hosts in the target plan (1-1000000)")
	flags.Int("max-probes", defaults.Scan.MaxProbes, "Maximum unique host/port pairs (1-100000000)")
	flags.Int("dns-concurrency", defaults.DNS.Concurrency, "Maximum concurrent DNS lookups (1-256)")
	flags.Duration("dns-timeout", defaults.DNS.Timeout, "Per-hostname DNS timeout, greater than zero and at most 1m")
	flags.Bool("service", defaults.Service.Enabled, "Identify services on open TCP ports (additional connections/probes)")
	flags.Bool("service-active", defaults.Service.Active, "Allow TLS handshakes and HTTP HEAD probes when --service is enabled")
	flags.Int("service-concurrency", defaults.Service.Concurrency, "Maximum concurrent service inspections (1-256)")
	flags.Duration("service-timeout", defaults.Service.Timeout, "Total per-port inspection budget, including rate waits (at most 1m)")
	flags.Int("service-max-bytes", defaults.Service.MaxBytes, "Maximum banner/HTTP response bytes per connection (256-65536)")
	flags.String("sni", defaults.Service.ServerName, "Override TLS SNI, certificate reference name, and HTTP Host with a DNS hostname")
	flags.String("format", defaults.Output.Format, "Scan result format: console or ndjson")
	flags.StringP("output", "o", defaults.Output.File, "Also write results to a new file (existing files are preserved)")
	flags.BoolP("quiet", "q", defaults.Output.Quiet, "Suppress progress on stderr")
	return cmd
}
