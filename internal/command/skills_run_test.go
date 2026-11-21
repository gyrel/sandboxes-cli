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
	if _, err := prepareSkills(""); err == nil || !strings.Contains(err.Error(), "not resolved") {
		t.Fatalf("unresolved mode must fail closed: %v", err)
	}
	if got, err := prepareSkills("off"); err != nil || got != nil {
		t.Fatalf("mode off: got %+v, %v", got, err)
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

func TestResolveSkillsMode(t *testing.T) {
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)

	// Explicit flag always wins.
	if got, err := (&Runner{}).resolveSkillsMode("off"); err != nil || got != "off" {
		t.Fatalf("explicit off: %q, %v", got, err)
	}
	// Omitted flag with no settings file uses the catalog default (readonly),
	// matching the sbx run --help contract.
	t.Setenv("RHEIC_SETTINGS_FILE", filepath.Join(config, "absent.toml"))
	got, err := (&Runner{}).resolveSkillsMode("")
	if err != nil || got != "readonly" {
		t.Fatalf("default mode: %q, %v", got, err)
	}
	// An explicit skills.defaultMode setting is honored.
	settingsPath := filepath.Join(config, "settings.toml")
	if err := os.WriteFile(settingsPath, []byte("skills.defaultMode = \"off\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RHEIC_SETTINGS_FILE", settingsPath)
	if got, err := (&Runner{}).resolveSkillsMode(""); err != nil || got != "off" {
		t.Fatalf("configured mode: %q, %v", got, err)
	}
	// A malformed settings file fails closed rather than guessing a mount mode.
	if err := os.WriteFile(settingsPath, []byte("this is not a setting\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Runner{}).resolveSkillsMode(""); err == nil {
		t.Fatal("malformed settings must fail closed")
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
