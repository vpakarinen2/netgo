package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/vpakarinen2/netgo/pkg/config"
	"github.com/vpakarinen2/netgo/pkg/core"
	"github.com/vpakarinen2/netgo/pkg/model"
	"github.com/vpakarinen2/netgo/pkg/network"
	"github.com/vpakarinen2/netgo/pkg/network/sockets"
	"github.com/vpakarinen2/netgo/pkg/network/targets"
	"github.com/vpakarinen2/netgo/pkg/output"
	"github.com/vpakarinen2/netgo/pkg/plugins"
	"github.com/vpakarinen2/netgo/pkg/service"
)

func runScan(ctx context.Context, cfg config.Config, inputs []string, stdout, stderr io.Writer) (runErr error) {
	ports, err := targets.ParsePorts(cfg.Scan.Ports)
	if err != nil {
		return err
	}
	var engine *plugins.Engine
	if len(cfg.Scripts.Paths) > 0 {
		engine, err = loadSelectedScripts(ctx, cfg.Scripts.Paths, cfg.Scripts.Parameters, plugins.Limits{Timeout: cfg.Scripts.Timeout, MemoryMiB: cfg.Scripts.MemoryMiB})
		if err != nil {
			return fmt.Errorf("initialize scripts: %w", err)
		}
		defer func() { runErr = errors.Join(runErr, engine.Close(context.Background())) }()
	}
	plan, err := targets.NewPlan(ctx, inputs, targets.Options{
		MaxHosts: uint64(cfg.Scan.MaxHosts), DNSConcurrency: cfg.DNS.Concurrency, DNSTimeout: cfg.DNS.Timeout,
	})
	if err != nil {
		return fmt.Errorf("plan targets: %w", err)
	}
	total, err := plan.ProbeCount(len(ports), uint64(cfg.Scan.MaxProbes))
	if err != nil {
		return err
	}
	if engine != nil {
		if err := engine.CheckCount(total); err != nil {
			return err
		}
	}
	options := core.Options{Concurrency: cfg.Scan.Concurrency, Rate: cfg.Scan.Rate, Retries: cfg.Scan.Retries, MaxProbes: uint64(cfg.Scan.MaxProbes), Transport: model.Transport(cfg.Scan.Transport)}
	if engine != nil {
		options.Scripts, options.ScriptConcurrency = engine, cfg.Scripts.Concurrency
	}
	if cfg.Scan.Transport == "tcp" {
		options.HostRate, options.HostConcurrency = cfg.TCP.HostRate, cfg.TCP.HostConcurrency
	}
	options.Diagnostics = cfg.Output.Stats
	options.OpenOnly = cfg.Output.OpenOnly
	if options.Diagnostics {
		options.Settings, err = json.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("encode diagnostic settings: %w", err)
		}
	}
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
		outFile, outOK := stdout.(*os.File)
		errFile, errOK := stderr.(*os.File)
		interactive := cfg.Output.Format != "ndjson" && outOK && errOK && term.IsTerminal(int(outFile.Fd())) && term.IsTerminal(int(errFile.Fd()))
		width := func() int {
			if errOK {
				if columns, _, err := term.GetSize(int(errFile.Fd())); err == nil {
					return columns
				}
			}
			return 80
		}
		progress := output.NewProgress(writer, stderr, interactive, width)
		writer, options.Progress = progress, progress.Report
	}
	_, err = core.Run(ctx, plan, ports, options, prober, writer)
	return err
}
