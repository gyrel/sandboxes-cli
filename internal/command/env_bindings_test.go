package command

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

func TestPruneBindingsFileVariants(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    []string // substrings that must survive
		gone    []string // substrings that must disappear
		changed bool
	}{
		{
			name:    "top level environment key",
			body:    "env-remove:\n  api: value-1\nkeep:\n  other: value-2\n",
			want:    []string{"keep:", "other: value-2"},
			gone:    []string{"env-remove"},
			changed: true,
		},
		{
			name:    "bindings map entry",
			body:    "bindings:\n  env-remove:\n    token: t\n  other-env:\n    token: u\n",
			want:    []string{"other-env", "token: u"},
			gone:    []string{"env-remove"},
			changed: true,
		},
		{
			name:    "entries keyed by environment field",
			body:    "credentials:\n  first:\n    environment: env-remove\n  second:\n    environment: other-env\n",
			want:    []string{"second", "other-env"},
			gone:    []string{"first"},
			changed: true,
		},
		{
			name:    "string list",
			body:    "environments:\n  - env-remove\n  - keep-me\n",
			want:    []string{"keep-me"},
			gone:    []string{"env-remove"},
			changed: true,
		},
		{
			name:    "no match leaves file untouched",
			body:    "bindings:\n  other-env:\n    token: t\n",
			want:    []string{"other-env", "token: t"},
			changed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials.yaml")
			if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := pruneBindingsFile(path, "env-remove"); err != nil {
				t.Fatalf("prune: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got := string(data)
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Fatalf("survivor %q missing after prune: %q", want, got)
				}
			}
			for _, gone := range tt.gone {
				if strings.Contains(got, gone) {
					t.Fatalf("pruned content %q still present: %q", gone, got)
				}
			}
			if !tt.changed && got != tt.body {
				t.Fatalf("unchanged file was rewritten: %q", got)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("temp files left behind: %v", entries)
			}
		})
	}
}

func TestPruneBindingsFileRefusesCorruptedAndSymlink(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(corrupt, []byte("bindings: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pruneBindingsFile(corrupt, "env-remove"); err == nil {
		t.Fatal("corrupted file was accepted")
	}
	before, err := os.ReadFile(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != "bindings: [unclosed\n" {
		t.Fatal("corrupted file was modified before parse failure")
	}

	outside := filepath.Join(dir, "victim.yaml")
	if err := os.WriteFile(outside, []byte("victim: keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "credentials-link.yaml")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := pruneBindingsFile(link, "victim"); err == nil {
		t.Fatal("symlinked store was accepted")
	}
	victim, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(victim) != "victim: keep\n" {
		t.Fatal("symlink target was rewritten")
	}
}

func TestCredentialsCandidatesAreGyrelOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	for _, candidate := range credentialsBindingsCandidates() {
		if strings.Contains(candidate, string(filepath.Separator)+"sbx") || strings.Contains(candidate, ".sbx") {
			t.Fatalf("candidate reaches docker sbx state: %q", candidate)
		}
	}
}

func TestEnvironmentRemovePrunesBindingsAndSparesSbx(t *testing.T) {
	workspace := t.TempDir()
	path := filepath.Join(workspace, "sbxenv.yaml")
	if err := os.WriteFile(path, []byte("schemaVersion: \"1\"\nname: env-remove\nagent: shell\nworkspace: .\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("USERPROFILE", home)                       // os.UserHomeDir on Windows
	gyrelDir := filepath.Join(home, ".config", "rheic") // legacy-compat dir name
	sbxDir := filepath.Join(home, ".config", "sbx")
	for _, dir := range []string{gyrelDir, sbxDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		body := "bindings:\n  env-remove:\n    token: gone\n  other-env:\n    token: keep\n"
		if err := os.WriteFile(filepath.Join(dir, "credentials.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sandboxes := &runSandbox{items: []sdk.Sandbox{{
		ID: "sb-env-remove", Name: "env-remove", Agent: "shell", State: sdk.StateRunning,
		Workspace: workspace, Workspaces: []sdk.Workspace{{Path: workspace}},
	}}}
	var stdout, stderr bytes.Buffer
	runner := NewRunner(&stdout, &stderr)
	runner.In = strings.NewReader("")
	runner.NewClient = func(string) (sdk.Client, error) {
		return runClient{sandboxes: sandboxes, sessions: &fakeSessions{}}, nil
	}
	if code := runner.Run(context.Background(), []string{"env", "rm", "--force", "--prune-bindings", path}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	gyrel, err := os.ReadFile(filepath.Join(gyrelDir, "credentials.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(gyrel), "env-remove") || !strings.Contains(string(gyrel), "other-env") {
		t.Fatalf("gyrel bindings after prune: %q", gyrel)
	}
	sbx, err := os.ReadFile(filepath.Join(sbxDir, "credentials.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sbx), "env-remove") {
		t.Fatalf("docker sbx store was modified: %q", sbx)
	}
	if !strings.Contains(stdout.String(), "Removed environment sandbox") {
		t.Fatalf("missing removal line: %q", stdout.String())
	}
}
