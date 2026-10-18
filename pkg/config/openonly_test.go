package config

import "testing"

func TestOpenOnlyPrecedence(t *testing.T) {
	cleanEnv(t)
	if Defaults().Output.OpenOnly {
		t.Fatal("filter enabled by default")
	}
	path := writeConfig(t, "output:\n  open_only: true\n")
	cfg, err := Load(path, testFlags())
	if err != nil || !cfg.Output.OpenOnly {
		t.Fatalf("file: %+v %v", cfg, err)
	}
	t.Setenv("NETGO_OUTPUT_OPEN_ONLY", "false")
	cfg, err = Load(path, testFlags())
	if err != nil || cfg.Output.OpenOnly {
		t.Fatalf("env: %+v %v", cfg, err)
	}
	f := testFlags()
	if err := f.Parse([]string{"--open-only"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path, f)
	if err != nil || !cfg.Output.OpenOnly {
		t.Fatalf("flag: %+v %v", cfg, err)
	}
	t.Setenv("NETGO_OUTPUT_OPEN_ONLY", "maybe")
	if _, err := Load("", nil); err == nil {
		t.Fatal("invalid boolean accepted")
	}
}
