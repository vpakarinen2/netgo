package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/vpakarinen2/netgo/internal/cli"
)

// version can be set at build time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd := cli.NewCommand(version)
	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			return 130
		}
		return 1
	}
	return 0
}
