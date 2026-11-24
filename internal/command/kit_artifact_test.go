package command

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const kitArtifactGoodSpec = "apiVersion: rheic.dev/v1alpha1\nkind: Kit\nmetadata:\n  name: good-kit\nspec:\n  agent: shell\n"

const kitArtifactArgsSpec = "# syntax=docker/sandbox-kit:3\nschemaVersion: \"3\"\nkind: mixin\nargs:\n  region:\n    required: true\n    enum: [eu, us]\n"

func writeKitArtifact(t *testing.T, root string, files map[string]string) string {
	t.Helper()
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// kitFixtures returns a good v2 kit, a v3 kit with a required argument and a
// parent directory holding both, so each test works in its own tree.
func kitFixtures(t *testing.T) (string, string) {
	t.Helper()
	parent := t.TempDir()
	good := writeKitArtifact(t, filepath.Join(parent, "good-kit"), map[string]string{
		"spec.yaml":   kitArtifactGoodSpec,
		"files/a.txt": "a",
	})
	argkit := writeKitArtifact(t, filepath.Join(parent, "argkit"), map[string]string{
		"spec.yaml": kitArtifactArgsSpec,
	})
	return good, argkit
}

func runKitArtifact(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	runner := &Runner{Out: &stdout, Err: &stderr}
	code := runner.Run(context.Background(), append([]string{"kit"}, args...))
	return code, stdout.String(), stderr.String()
}

func TestKitValidateGrammarAndOutcomes(t *testing.T) {
	good, argkit := kitFixtures(t)
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	if err := os.WriteFile(argsFile, []byte("region=us\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{name: "no reference", args: []string{"validate"}, code: 2, stderr: "usage: rsbx kit validate"},
		{name: "two references", args: []string{"validate", good, argkit}, code: 2, stderr: "usage: rsbx kit validate"},
		{name: "invalid format", args: []string{"validate", good, "--format", "xml", "--offline"}, code: 2, stderr: `invalid format "xml"`},
		{name: "json with explicit format", args: []string{"validate", good, "--json", "--format", "yaml", "--offline"}, code: 2, stderr: "--json cannot be combined with an explicit --format"},
		{name: "unknown flag", args: []string{"validate", good, "--bogus"}, code: 1, stderr: "error: unknown flag: --bogus\n  try: rsbx kit validate --help"},
		{name: "malformed kit-arg", args: []string{"validate", good, "--kit-arg", "region", "--offline"}, code: 1, stderr: "kit argument must use name=value"},
		{name: "missing args file", args: []string{"validate", good, "--kit-args-file", "/nonexistent/args.txt", "--offline"}, code: 1, stderr: "read kit arguments file"},
		{name: "git https reference", args: []string{"validate", "https://example.com/org/kit.git", "--offline"}, code: 1, stderr: "error: kit validate git references are not implemented yet\n"},
		{name: "git scp reference without offline", args: []string{"validate", "git@example.com:org/kit.git"}, code: 1, stderr: "error: kit validate git references are not implemented yet\n"},
		{name: "policy check fails closed", args: []string{"validate", good}, code: 1, stderr: "error: policy could not be checked: "},
		{name: "policy hint", args: []string{"validate", good}, code: 1, stderr: "\n  try: rsbx kit validate --offline "},
		{name: "offline table", args: []string{"validate", good, "--offline"}, code: 0, stdout: "Validated kit good-kit (offline: daemon kit policy not checked)\n"},
		{name: "flag before reference", args: []string{"validate", "--offline", good}, code: 0, stdout: "Validated kit good-kit"},
		{name: "offline json", args: []string{"validate", good, "--offline", "--json"}, code: 0, stdout: `"policyChecked": false`},
		{name: "offline yaml", args: []string{"validate", good, "--offline", "--format", "yaml"}, code: 0, stdout: "policyChecked: false"},
		{name: "required missing", args: []string{"validate", argkit, "--offline"}, code: 1, stderr: `error: spec.yaml: required kit argument "region" is not set`},
		{name: "required supplied", args: []string{"validate", argkit, "--offline", "--kit-arg", "region=eu"}, code: 0, stdout: "Validated kit argkit"},
		{name: "required from file", args: []string{"validate", argkit, "--offline", "--kit-args-file", argsFile}, code: 0, stdout: "Validated kit argkit"},
		{name: "qualified argument", args: []string{"validate", argkit, "--offline", "--kit-arg", "argkit.region=us"}, code: 0, stdout: "Validated kit argkit"},
		{name: "argument outside enum", args: []string{"validate", argkit, "--offline", "--kit-arg", "region=xx"}, code: 1, stderr: `kit argument "region" is not one of its allowed values`},
		{name: "undeclared argument", args: []string{"validate", good, "--offline", "--kit-arg", "extra=1"}, code: 1, stderr: `kit argument "extra" is not declared by this kit`},
		{name: "missing path", args: []string{"validate", filepath.Join(t.TempDir(), "absent"), "--offline"}, code: 1, stderr: "inspect kit reference"},
		{name: "help", args: []string{"validate", "--help"}, code: 0, stdout: "EXPERIMENTAL: this command may change or be removed in future releases."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runKitArtifact(t, tt.args...)
			if code != tt.code {
				t.Fatalf("code=%d want %d stdout=%q stderr=%q", code, tt.code, stdout, stderr)
			}
			if !strings.Contains(stdout, tt.stdout) || !strings.Contains(stderr, tt.stderr) {
				t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

func TestKitValidateViolationsUseRelativePaths(t *testing.T) {
	_, argkit := kitFixtures(t)
	code, _, stderr := runKitArtifact(t, "validate", argkit, "--offline")
	if code != 1 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "error: ") && strings.Contains(line, argkit) {
			t.Fatalf("violation leaks host path: %q", line)
		}
	}
	if !strings.Contains(stderr, "error: spec.yaml: required kit argument") {
		t.Fatalf("stderr=%q", stderr)
	}
}

func TestKitValidateAcceptsZipArchive(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "good-kit.zip")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create("spec.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(kitArtifactGoodSpec)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runKitArtifact(t, "validate", archive, "--offline")
	if code != 0 || !strings.Contains(stdout, "Validated kit good-kit") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKitPackGrammarAndOutcomes(t *testing.T) {
	good, argkit := kitFixtures(t)
	dir := t.TempDir()
	tests := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{name: "no directory", args: []string{"pack"}, code: 2, stderr: "usage: rsbx kit pack"},
		{name: "two directories", args: []string{"pack", good, argkit}, code: 2, stderr: "usage: rsbx kit pack"},
		{name: "output without zip suffix", args: []string{"pack", good, "-o", filepath.Join(dir, "out.tar")}, code: 2, stderr: "kit pack output must end in .zip"},
		{name: "unknown flag", args: []string{"pack", good, "--force"}, code: 1, stderr: "error: unknown flag: --force"},
		{name: "required argument blocks pack", args: []string{"pack", argkit, "-o", filepath.Join(dir, "argkit.zip")}, code: 1, stderr: `required kit argument "region" is not set`},
		{name: "short output flag", args: []string{"pack", good, "-o", filepath.Join(dir, "short.zip")}, code: 0, stdout: "Packed kit good-kit to " + filepath.Join(dir, "short.zip")},
		{name: "long output flag", args: []string{"pack", good, "--output", filepath.Join(dir, "long.zip")}, code: 0, stdout: "Packed kit good-kit to "},
		{name: "output exists", args: []string{"pack", good, "-o", filepath.Join(dir, "short.zip")}, code: 1, stderr: "already exists"},
		{name: "help", args: []string{"pack", "--help"}, code: 0, stdout: "EXPERIMENTAL: this command may change or be removed in future releases."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runKitArtifact(t, tt.args...)
			if code != tt.code || !strings.Contains(stdout, tt.stdout) || !strings.Contains(stderr, tt.stderr) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestKitPackDefaultOutputAndRoundTrip(t *testing.T) {
	good, _ := kitFixtures(t)
	work := t.TempDir()
	t.Chdir(work)
	code, stdout, stderr := runKitArtifact(t, "pack", good)
	if code != 0 || stdout != "Packed kit good-kit to good-kit.zip\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runKitArtifact(t, "validate", filepath.Join(work, "good-kit.zip"), "--offline")
	if code != 0 || !strings.Contains(stdout, "Validated kit good-kit") {
		t.Fatalf("round trip code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKitPackRefusesSymlinks(t *testing.T) {
	good, _ := kitFixtures(t)
	if err := os.Symlink(filepath.Join(good, "spec.yaml"), filepath.Join(good, "files", "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	output := filepath.Join(t.TempDir(), "linked.zip")
	code, _, stderr := runKitArtifact(t, "pack", good, "-o", output)
	if code != 1 || !strings.Contains(stderr, "error: files/link: symbolic links are not allowed in kit artifacts") {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Lstat(output); err == nil {
		t.Fatal("refused pack wrote an archive")
	}
}

func TestKitHelpListsArtifactVerbs(t *testing.T) {
	code, stdout, _ := runKitArtifact(t, "--help")
	if code != 0 || !strings.Contains(stdout, "pack") || !strings.Contains(stdout, "validate") {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
}
