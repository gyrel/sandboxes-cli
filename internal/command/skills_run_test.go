package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestPrepareSkillsModes(t *testing.T) {
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	for _, mode := range []string{"", "off"} {
		got, err := prepareSkills(mode)
		if err != nil || got != nil {
			t.Fatalf("mode %q: got %+v, %v", mode, got, err)
		}
	}
	got, err := prepareSkills("readonly")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(config, "rheic", "skills")
	if got == nil || got.Mode != sdk.SkillsReadOnly || got.StorePath != want {
		t.Fatalf("got %+v, want store %q", got, want)
	}
	if info, err := os.Lstat(want); err != nil || !info.IsDir() {
		t.Fatalf("store not created: %v %v", info, err)
	}
	if _, err := prepareSkills("readwrite"); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("readwrite: %v", err)
	}
	if _, err := prepareSkills("sometimes"); err == nil || !strings.Contains(err.Error(), "off, readonly or readwrite") {
		t.Fatalf("invalid: %v", err)
	}
}

func TestParseRunSkillsFlag(t *testing.T) {
	for _, args := range [][]string{
		{"--skills", "readonly", "codex"},
		{"--skills=readonly", "codex"},
	} {
		opts, positionals, err := parseRunArgs(nil, args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if opts.skills != "readonly" || len(positionals) != 1 || positionals[0] != "codex" {
			t.Fatalf("%v: opts=%+v positionals=%v", args, opts, positionals)
		}
	}
}
