package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

func printDiagnostics(writer io.Writer, stats *model.Diagnostics) error {
	average := time.Duration(0)
	if stats.OpenLatencySamples > 0 {
		average = stats.OpenLatencyTotal / time.Duration(stats.OpenLatencySamples)
	}
	var settings struct {
		Scan struct {
			Transport         string
			Rate, Concurrency int
			Timeout           string
		}
		TCP struct {
			HostRate        int `json:"host_rate"`
			HostConcurrency int `json:"host_concurrency"`
		}
	}
	if err := json.Unmarshal(stats.Settings, &settings); err == nil {
		if _, err := fmt.Fprintf(writer, "Settings: %s, rate %d/s, concurrency %d, timeout %s, TCP host rate %d/s, TCP host slots %d\n", settings.Scan.Transport, settings.Scan.Rate, settings.Scan.Concurrency, settings.Scan.Timeout, settings.TCP.HostRate, settings.TCP.HostConcurrency); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "Diagnostics: %d port attempts, %d probe errors, peak %d connection slots; gate wait %s, probe time %s (cumulative), mean open TCP attempt %s (%d samples)\n", stats.PortAttempts, stats.ProbeErrors, stats.PeakConnections, stats.GateWait.Round(time.Millisecond), stats.ProbeTime.Round(time.Millisecond), average.Round(time.Microsecond), stats.OpenLatencySamples); err != nil {
		return err
	}
	for _, group := range []struct {
		name   string
		counts map[string]uint64
	}{{"Attempt reasons", stats.Reasons}, {"Service inspections", stats.ServiceStatuses}} {
		keys := make([]string, 0, len(group.counts))
		for key := range group.counts {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			continue
		}
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", safeText(key), group.counts[key]))
		}
		if _, err := fmt.Fprintf(writer, "%s: %s\n", group.name, strings.Join(parts, ", ")); err != nil {
			return err
		}
	}
	for _, host := range stats.Hosts {
		if _, err := fmt.Fprintf(writer, "Host %s: %d attempts, %d timeouts, %d probe errors\n", safeText(host.Address), host.Attempts, host.Timeouts, host.Errors); err != nil {
			return err
		}
	}
	if stats.UnattributedAttempts > 0 {
		_, err := fmt.Fprintf(writer, "Host detail limit reached: %d further attempts counted only in totals\n", stats.UnattributedAttempts)
		return err
	}
	return nil
}
