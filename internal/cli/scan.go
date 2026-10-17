package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/vpakarinen2/netgo/pkg/config"
	"github.com/vpakarinen2/netgo/pkg/core"
	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network"
	"github.com/vpakarinen2/netgo/pkg/network/sockets"
	"github.com/vpakarinen2/netgo/pkg/network/targets"
	"github.com/vpakarinen2/netgo/pkg/output"
	"github.com/vpakarinen2/netgo/pkg/service"
)

func runScan(ctx context.Context, cfg config.Config, inputs []string, stdout, stderr io.Writer) error {
	ports, err := targets.ParsePorts(cfg.Scan.Ports)
	if err != nil {
		return err
	}
	plan, err := targets.NewPlan(ctx, inputs, targets.Options{
		MaxHosts: uint64(cfg.Scan.MaxHosts), DNSConcurrency: cfg.DNS.Concurrency, DNSTimeout: cfg.DNS.Timeout,
	})
	if err != nil {
		return fmt.Errorf("plan targets: %w", err)
	}
	if _, err := plan.ProbeCount(len(ports), uint64(cfg.Scan.MaxProbes)); err != nil {
		return err
	}
	options := core.Options{Concurrency: cfg.Scan.Concurrency, Rate: cfg.Scan.Rate, Retries: cfg.Scan.Retries, MaxProbes: uint64(cfg.Scan.MaxProbes), Transport: model.Transport(cfg.Scan.Transport)}
	var prober network.Prober = &sockets.Connect{Timeout: cfg.Scan.Timeout}
	if cfg.Scan.Transport == "udp" {
		prober = &sockets.UDP{Timeout: cfg.Scan.Timeout, Kind: cfg.UDP.Probe, MaxBytes: cfg.UDP.MaxBytes}
		options.HostRate = cfg.UDP.HostRate
	}
	if cfg.Service.Enabled {
		identifier, err := service.New(service.Options{Timeout: cfg.Service.Timeout, MaxBytes: cfg.Service.MaxBytes, Active: cfg.Service.Active, ServerName: cfg.Service.ServerName})
		if err != nil {
			return fmt.Errorf("initialize identification: %w", err)
		}
		options.Identifier, options.ServiceConcurrency = identifier, cfg.Service.Concurrency
	}
	writer, err := output.New(cfg.Output.Format, stdout, cfg.Output.File)
	if err != nil {
		return err
	}
	if !cfg.Output.Quiet {
		options.Progress = func(progress model.Progress) error { return output.PrintProgress(stderr, progress) }
	}
	_, err = core.Run(ctx, plan, ports, options, prober, writer)
	return err
}
