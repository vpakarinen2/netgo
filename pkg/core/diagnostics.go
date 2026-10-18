package core

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/vpakarinen2/netgo/pkg/model"
)

const diagnosticHostLimit = 256

type diagnostics struct {
	mu    sync.Mutex
	data  model.Diagnostics
	hosts map[string]*model.HostDiagnostics
}

func newDiagnostics(enabled bool, settings json.RawMessage) *diagnostics {
	if !enabled {
		return nil
	}
	return &diagnostics{data: model.Diagnostics{Settings: append(json.RawMessage(nil), settings...), Reasons: make(map[string]uint64), ServiceStatuses: make(map[string]uint64)}, hosts: make(map[string]*model.HostDiagnostics)}
}

func (d *diagnostics) acquired(wait time.Duration) func() {
	if d == nil {
		return func() {}
	}
	d.mu.Lock()
	d.data.GateWait += wait
	d.data.ActiveConnections++
	d.data.PeakConnections = max(d.data.PeakConnections, d.data.ActiveConnections)
	d.mu.Unlock()
	return func() { d.mu.Lock(); d.data.ActiveConnections--; d.mu.Unlock() }
}

func (d *diagnostics) waited(wait time.Duration) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.data.GateWait += wait
	d.mu.Unlock()
}

func (d *diagnostics) probe(address string, result model.Result, err error, elapsed time.Duration) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data.PortAttempts++
	d.data.ProbeTime += elapsed
	if err != nil {
		d.data.ProbeErrors++
	}
	if result.State == model.Open && result.Target.Transport == model.TCP {
		d.data.OpenLatencySamples++
		d.data.OpenLatencyTotal += result.Duration
	}
	reason := result.Reason
	if err != nil {
		reason = "probe_error"
	}
	if reason == "" {
		reason = "unspecified"
	}
	if _, exists := d.data.Reasons[reason]; !exists && len(d.data.Reasons) >= 15 {
		reason = "other"
	}
	d.data.Reasons[reason]++
	host := d.hosts[address]
	if host == nil {
		if len(d.hosts) >= diagnosticHostLimit {
			d.data.UnattributedAttempts++
			return
		}
		host = &model.HostDiagnostics{Address: address}
		d.hosts[address] = host
	}
	host.Attempts++
	if result.Reason == "timeout" {
		host.Timeouts++
	}
	if err != nil {
		host.Errors++
	}
}

func (d *diagnostics) inspection(info model.Identification) {
	if d == nil {
		return
	}
	status := info.Status
	if status != "identified" && status != "unrecognized" && status != "timeout" && status != "failed" && status != "canceled" {
		status = "other"
	}
	d.mu.Lock()
	d.data.ServiceStatuses[status]++
	d.mu.Unlock()
}

func (d *diagnostics) snapshot() *model.Diagnostics {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	data := d.data
	data.Hosts = make([]model.HostDiagnostics, 0, len(d.hosts))
	for _, host := range d.hosts {
		data.Hosts = append(data.Hosts, *host)
	}
	sort.Slice(data.Hosts, func(i, j int) bool { return data.Hosts[i].Address < data.Hosts[j].Address })
	return &data
}
