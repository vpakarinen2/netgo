package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
		err  bool
	}{
		{"help", []string{"--help"}, "TCP connect scanner", false},
		{"no args", nil, "Usage:", false},
		{"version", []string{"--version"}, "v0.test", false},
		{"check", []string{"--check-config", "--rate", "75"}, `"rate": 75`, false},
		{"text format", []string{"--check-config", "--format", "text"}, `"format": "text"`, false},
		{"bad flag", []string{"--unknown"}, "unknown flag", true},
		{"bad config", []string{"--check-config", "--concurrency", "0"}, "scan.concurrency", true},
		{"bad ports", []string{"--check-config", "--ports", "0"}, "scan.ports", true},
		{"missing file", []string{"--check-config", "--config", "does-not-exist.yaml"}, "read config", true},
		{"check with target", []string{"--check-config", "127.0.0.1"}, "does not accept target", true},
		{"invalid target", []string{"http://localhost"}, "invalid target", true},
		{"excessive CIDR", []string{"::/0"}, "host limit", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewCommand("v0.test")
			var out, diagnostics bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&diagnostics)
			cmd.SetArgs(tc.args)
			err := cmd.ExecuteContext(context.Background())
			if (err != nil) != tc.err {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.err {
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got error %q, want %q", err, tc.want)
				}
				if out.Len() != 0 {
					t.Fatalf("failed command polluted stdout: %s", out.String())
				}
			} else if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("got output %q, want %q", out.String(), tc.want)
			}
			if diagnostics.Len() != 0 {
				t.Fatalf("command printed diagnostics instead of returning them: %s", diagnostics.String())
			}
		})
	}
}

func TestCheckConfigIsJSON(t *testing.T) {
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"--check-config"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	decoder := json.NewDecoder(&out)
	if err := decoder.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&cfg); !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected trailing output: %v", err)
	}
}

func TestCanceledCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"--check-config"})
	if err := cmd.ExecuteContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestOutputFailure(t *testing.T) {
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"--check-config"})
	cmd.SetOut(brokenWriter{})
	if err := cmd.Execute(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output failure lost: %v", err)
	}
}

func TestHelpDoesNotReadEnvironment(t *testing.T) {
	t.Setenv("NETGO_SCAN_RATE", "bad")
	cmd := NewCommand("test")
	cmd.SetArgs([]string{"--help"})
	cmd.SetOut(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}
