package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/vpakarinen2/netgo/pkg/plugins"
	"github.com/vpakarinen2/netgo/pkg/plugins/sdk"
)

func newScriptsCommand() *cobra.Command {
	command := &cobra.Command{Use: "scripts", Short: "Validate local Wasm plugins or run them on a JSON fixture"}
	for _, mode := range []string{"validate", "test"} {
		mode := mode
		var input string
		var parameters []string
		limits := plugins.Limits{Timeout: 2 * time.Second, MemoryMiB: 64}
		child := &cobra.Command{Use: mode + " <name|manifest.yaml>", Short: map[string]string{"validate": "Validate manifest, checksum, imports, and WASI command", "test": "Run a plugin on a netgo.script/v1 JSON fixture without network access"}[mode], Args: cobra.ExactArgs(1)}
		child.Flags().DurationVar(&limits.Timeout, "script-timeout", limits.Timeout, "Per-invocation deadline (at most 5s)")
		child.Flags().IntVar(&limits.MemoryMiB, "script-memory", limits.MemoryMiB, "Wasm linear memory per invocation in MiB")
		child.Flags().StringArrayVar(&parameters, "script-param", nil, "Typed ID.name=value parameter override (repeatable)")
		if mode == "test" {
			child.Flags().StringVar(&input, "input", "", "JSON request fixture file")
			_ = child.MarkFlagRequired("input")
		}
		child.RunE = func(cmd *cobra.Command, args []string) error {
			engine, err := loadSelectedScripts(cmd.Context(), args, parameters, limits)
			if err != nil {
				return err
			}
			defer engine.Close(cmd.Context())
			encoder := json.NewEncoder(cmd.OutOrStdout())
			if mode == "validate" {
				return encoder.Encode(engine.Manifests()[0])
			}
			data, err := plugins.ReadBounded(input, sdk.MaxInput)
			if err != nil {
				return err
			}
			request, err := sdk.ReadRequest(bytes.NewReader(data))
			if err != nil {
				return err
			}
			run, err := engine.Test(cmd.Context(), request)
			if err != nil {
				return err
			}
			if err := encoder.Encode(run); err != nil {
				return err
			}
			if run.Status == "error" || run.Status == "timeout" || run.Status == "canceled" {
				if cmd.Context().Err() != nil {
					return cmd.Context().Err()
				}
				return fmt.Errorf("script %s %s; see the JSON response for details", run.ID, run.Status)
			}
			return nil
		}
		command.AddCommand(child)
	}
	return command
}
