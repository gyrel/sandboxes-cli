package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeCustomRegistry(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agents.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadWithCustomMergesPreviewAgent(t *testing.T) {
	path := writeCustomRegistry(t, `agents:
  - name: hermes
    image: rheic/hermes-sandbox:local
    command: ["hermes"]
    status: preview
    notes: local custom image
`)
	t.Setenv("RHEIC_AGENTS_FILE", path)
	registry, err := LoadWithCustom()
	if err != nil {
		t.Fatal(err)
	}
	spec, ok := registry.Lookup("hermes")
	if !ok || spec.Command[0] != "hermes" || spec.Image != "rheic/hermes-sandbox:local" {
		t.Fatalf("hermes spec = %+v ok=%t", spec, ok)
	}
	if _, ok := registry.Lookup("codex"); !ok {
		t.Fatal("built-in codex disappeared")
	}
}

func TestLoadWithCustomRejectsShadowing(t *testing.T) {
	path := writeCustomRegistry(t, `agents:
  - name: codex
    image: example/codex:latest
    command: ["codex"]
    status: preview
`)
	t.Setenv("RHEIC_AGENTS_FILE", path)
	if _, err := LoadWithCustom(); err == nil || !strings.Contains(err.Error(), "shadows") {
		t.Fatalf("shadowing error = %v", err)
	}
}

func TestLoadWithCustomRejectsUndigestedAvailable(t *testing.T) {
	path := writeCustomRegistry(t, `agents:
  - name: hermes
    image: rheic/hermes-sandbox:local
    command: ["hermes"]
    status: available
`)
	t.Setenv("RHEIC_AGENTS_FILE", path)
	if _, err := LoadWithCustom(); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("undigested available error = %v", err)
	}
}

func TestLoadWithCustomRejectsInvalidName(t *testing.T) {
	path := writeCustomRegistry(t, `agents:
  - name: "../hermes"
    image: rheic/hermes-sandbox:local
    command: ["hermes"]
    status: preview
`)
	t.Setenv("RHEIC_AGENTS_FILE", path)
	if _, err := LoadWithCustom(); err == nil {
		t.Fatal("invalid custom name was accepted")
	}
}

func TestLoadWithCustomMissingFileKeepsBuiltins(t *testing.T) {
	t.Setenv("RHEIC_AGENTS_FILE", filepath.Join(t.TempDir(), "absent.yaml"))
	registry, err := LoadWithCustom()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Lookup("codex"); !ok {
		t.Fatal("built-in codex missing")
	}
}

func TestLoadWithCustomRejectsWritableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not authoritative on Windows")
	}
	path := writeCustomRegistry(t, "agents: []\n")
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RHEIC_AGENTS_FILE", path)
	if _, err := LoadWithCustom(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("writable registry error = %v", err)
	}
}
