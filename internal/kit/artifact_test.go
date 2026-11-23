package kit

import (
	"archive/zip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const goodSpec = "apiVersion: rheic.dev/v1alpha1\nkind: Kit\nmetadata:\n  name: good-kit\nspec:\n  agent: shell\n"

const argsSpec = `# syntax=docker/sandbox-kit:3
schemaVersion: "3"
kind: mixin
args:
  region:
    required: true
    enum: [eu, us]
  tag:
    default: latest
    pattern: '^[a-z]+$'
`

type zipFixture struct {
	name string
	body string
	mode fs.FileMode
}

func writeTree(t *testing.T, root string, files map[string]string) {
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
}

func newKitDir(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTree(t, root, files)
	return root
}

func writeZipFixture(t *testing.T, path string, files []zipFixture) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	for _, item := range files {
		header := &zip.FileHeader{Name: item.name, Method: zip.Deflate}
		if item.mode != 0 {
			header.SetMode(item.mode)
		}
		writer, err := archive.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(item.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func violationMessages(violations []Violation) []string {
	out := make([]string, 0, len(violations))
	for _, violation := range violations {
		out = append(out, violation.String())
	}
	return out
}

func requireViolation(t *testing.T, violations []Violation, want string) {
	t.Helper()
	for _, violation := range violations {
		if strings.Contains(violation.String(), want) {
			return
		}
	}
	t.Fatalf("no violation containing %q in %q", want, violationMessages(violations))
}

func TestValidateDirectoryAcceptsGoodKit(t *testing.T) {
	root := newKitDir(t, "good-kit", map[string]string{
		"spec.yaml":        goodSpec,
		"files/a.txt":      "a",
		"files/sub/b.txt":  "b",
		"files/sub/z.yaml": "z",
	})
	result, err := Validate(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Violations) != 0 {
		t.Fatalf("violations=%q", violationMessages(result.Violations))
	}
	if result.Name != "good-kit" || result.Kind != "Kit" {
		t.Fatalf("name=%q kind=%q", result.Name, result.Kind)
	}
	names := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		names = append(names, entry.Name)
	}
	want := []string{"files", "files/a.txt", "files/sub", "files/sub/b.txt", "files/sub/z.yaml", "spec.yaml"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("entries=%v want %v", names, want)
	}
}

func TestValidateDirectoryReportsRelativePaths(t *testing.T) {
	root := newKitDir(t, "bad-kit", map[string]string{
		"spec.yaml": "apiVersion: rheic.dev/v1alpha1\nkind: Kit\nmetadata:\n  name: \"\"\nspec:\n  agent: shell\n",
	})
	result, err := Validate(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireViolation(t, result.Violations, "spec.yaml: kit metadata.name is required")
	for _, violation := range result.Violations {
		if strings.Contains(violation.String(), root) || strings.Contains(violation.String(), t.TempDir()) {
			t.Fatalf("violation leaks host path: %q", violation.String())
		}
	}
}

func TestValidateDirectoryRejectsStructuralProblems(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{name: "missing spec", files: map[string]string{"README": "x"}, want: "kit requires <name>.yaml, spec.yaml or spec.yml"},
		{name: "unknown field", files: map[string]string{"spec.yaml": goodSpec + "extra: 1\n"}, want: "spec.yaml: parse kit"},
		{name: "oversized file", files: map[string]string{"spec.yaml": goodSpec, "files/big.bin": strings.Repeat("x", maxArtifactFileBytes+1)}, want: "files/big.bin: file exceeds 1 MiB"},
		{name: "backslash name", files: map[string]string{"spec.yaml": goodSpec, `files/a\b`: "x"}, want: "file name contains a backslash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "backslash name" && runtime.GOOS == "windows" {
				t.Skip("NTFS cannot store backslashes in names; the same check is covered on every platform by TestValidateZipRejectsUnsafeEntryNames")
			}
			root := newKitDir(t, "kit", tt.files)
			result, err := Validate(root, nil)
			if err != nil {
				t.Fatal(err)
			}
			requireViolation(t, result.Violations, tt.want)
		})
	}
}

func TestValidateDirectoryRefusesSymlinks(t *testing.T) {
	root := newKitDir(t, "kit", map[string]string{"spec.yaml": goodSpec, "files/real.txt": "x"})
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "files", "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	result, err := Validate(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireViolation(t, result.Violations, "files/link: symbolic links are not allowed")
	for _, entry := range result.Entries {
		if entry.Name == "files/link" {
			t.Fatal("symlink was listed as an entry")
		}
	}
}

func TestValidateDirectoryRefusesSymlinkedSpec(t *testing.T) {
	root := newKitDir(t, "kit", map[string]string{"real.yaml": goodSpec})
	if err := os.Symlink("real.yaml", filepath.Join(root, "spec.yaml")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	result, err := Validate(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireViolation(t, result.Violations, "spec.yaml: symbolic links are not allowed")
	requireViolation(t, result.Violations, "kit requires")
}

func TestValidateDirectoryEntryBound(t *testing.T) {
	files := map[string]string{"spec.yaml": goodSpec}
	for i := 0; i < maxArtifactEntries; i++ {
		files[fmt.Sprintf("files/f%04d", i)] = "x"
	}
	root := newKitDir(t, "kit", files)
	result, err := Validate(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireViolation(t, result.Violations, fmt.Sprintf("kit has more than %d entries", maxArtifactEntries))
}

func TestValidateRejectsUnsupportedReferences(t *testing.T) {
	file := filepath.Join(t.TempDir(), "kit.yaml")
	if err := os.WriteFile(file, []byte(goodSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(file, nil); err == nil || !strings.Contains(err.Error(), "must be a local directory or .zip file") {
		t.Fatalf("plain file err=%v", err)
	}
	if _, err := Validate(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("missing reference was accepted")
	}
}

// TestValidateZipRejectsUnsafeEntryNames runs the name grammar on raw ZIP
// entry strings, which every platform can construct even where the local
// filesystem forbids such names (backslashes and colons on Windows).
func TestValidateZipRejectsUnsafeEntryNames(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "unsafe-kit.zip")
	writeZipFixture(t, archive, []zipFixture{
		{name: "spec.yaml", body: goodSpec},
		{name: `files/a\b`, body: "x"},
		{name: "/absolute", body: "x"},
		{name: "../escape", body: "x"},
		{name: "C:drive", body: "x"},
		{name: "./redundant", body: "x"},
	})
	result, err := Validate(archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{`files/a\b`, "/absolute", "../escape", "C:drive", "./redundant"} {
		found := false
		for _, violation := range result.Violations {
			if violation.Path == name && strings.Contains(violation.Message, "archive entry name is unsafe") {
				found = true
			}
		}
		if !found {
			t.Fatalf("unsafe entry %q not rejected: %v", name, violationMessages(result.Violations))
		}
	}
	for _, entry := range result.Entries {
		if entry.Name != "spec.yaml" {
			t.Fatalf("unsafe entry reached the listing: %q", entry.Name)
		}
	}
}

func TestIsGitReference(t *testing.T) {
	t.Chdir(t.TempDir())
	// The SCP-style reference is only a local path when that exact name
	// exists; NTFS forbids colons in names, so the "existing path wins"
	// fixture is built only where representable.
	localSCP := `git@example.com:kit`
	if runtime.GOOS != "windows" {
		writeTree(t, ".", map[string]string{localSCP + "/spec.yaml": goodSpec})
	}
	tests := []struct {
		reference string
		want      bool
	}{
		{"https://github.com/org/kit.git", true},
		{"http://example.com/kit", true},
		{"ssh://git@example.com/kit.git", true},
		{"git://example.com/kit", true},
		{"git@example.com:org/kit.git", true},
		{"./my-kit", false},
		{"ghcr.io/org/kit:1.0", false},
		{"file:///tmp/kit", false},
		{localSCP, false},
	}
	for _, tt := range tests {
		if tt.reference == localSCP && runtime.GOOS == "windows" {
			continue // name not representable; covered on Unix hosts
		}
		if got := IsGitReference(tt.reference); got != tt.want {
			t.Fatalf("IsGitReference(%q)=%v want %v", tt.reference, got, tt.want)
		}
	}
}

func TestValidateV3ArgumentsRequiredAndDeclared(t *testing.T) {
	root := newKitDir(t, "argkit", map[string]string{"spec.yaml": argsSpec})
	tests := []struct {
		name     string
		args     map[string]string
		wantBad  []string
		wantFine bool
	}{
		{name: "missing required", args: nil, wantBad: []string{`required kit argument "region" is not set`}},
		{name: "supplied", args: map[string]string{"region": "eu"}, wantFine: true},
		{name: "default applies to tag", args: map[string]string{"region": "us", "tag": "stable"}, wantFine: true},
		{name: "outside enum", args: map[string]string{"region": "xx"}, wantBad: []string{`kit argument "region" is not one of its allowed values`}},
		{name: "outside pattern", args: map[string]string{"region": "eu", "tag": "Bad1"}, wantBad: []string{`kit argument "tag" does not match its pattern`}},
		{name: "undeclared", args: map[string]string{"region": "eu", "extra": "1"}, wantBad: []string{`kit argument "extra" is not declared by this kit`}},
		{name: "qualified for this kit", args: map[string]string{"argkit.region": "eu"}, wantFine: true},
		{name: "qualified for other kit", args: map[string]string{"other.region": "eu"}, wantBad: []string{`required kit argument "region" is not set`, `kit argument "other.region" is for kit "other", not this kit`}},
		{name: "qualified overrides unqualified", args: map[string]string{"region": "xx", "argkit.region": "us"}, wantFine: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Validate(root, tt.args)
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantFine {
				if len(result.Violations) != 0 {
					t.Fatalf("violations=%q", violationMessages(result.Violations))
				}
				return
			}
			for _, want := range tt.wantBad {
				requireViolation(t, result.Violations, want)
			}
		})
	}
}

func TestValidateV2KitDeclaresNoArguments(t *testing.T) {
	root := newKitDir(t, "good-kit", map[string]string{"spec.yaml": goodSpec})
	result, err := Validate(root, map[string]string{"region": "eu"})
	if err != nil {
		t.Fatal(err)
	}
	requireViolation(t, result.Violations, `kit argument "region" is not declared by this kit`)
}

func TestValidateZipAcceptsGoodKit(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "good-kit.zip")
	writeZipFixture(t, archive, []zipFixture{
		{name: "spec.yaml", body: goodSpec},
		{name: "files/", body: ""},
		{name: "files/a.txt", body: "a"},
	})
	result, err := Validate(archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Violations) != 0 || result.Name != "good-kit" {
		t.Fatalf("name=%q violations=%q", result.Name, violationMessages(result.Violations))
	}
}

func TestValidateZipRefusesTraversalAndUnsafeNames(t *testing.T) {
	tests := []struct {
		name  string
		entry string
	}{
		{name: "parent traversal", entry: "../evil.txt"},
		{name: "nested traversal", entry: "files/../../evil.txt"},
		{name: "absolute", entry: "/etc/evil.txt"},
		{name: "windows separator", entry: `files\..\evil.txt`},
		{name: "drive letter", entry: "C:/evil.txt"},
		{name: "double slash", entry: "files//a.txt"},
		{name: "dot segment", entry: "files/./a.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			archive := filepath.Join(dir, "kit.zip")
			writeZipFixture(t, archive, []zipFixture{{name: "spec.yaml", body: goodSpec}, {name: tt.entry, body: "x"}})
			result, err := Validate(archive, nil)
			if err != nil {
				t.Fatal(err)
			}
			requireViolation(t, result.Violations, "archive entry name is unsafe")
			if _, err := os.Stat(filepath.Join(dir, "evil.txt")); err == nil {
				t.Fatal("validation wrote outside the archive directory")
			}
		})
	}
}

func TestValidateZipRefusesDuplicatesSymlinksAndSpecialFiles(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "kit.zip")
	writeZipFixture(t, archive, []zipFixture{
		{name: "spec.yaml", body: goodSpec},
		{name: "files/a.txt", body: "a"},
		{name: "files/a.txt", body: "b"},
		{name: "files/link", body: "/etc/passwd", mode: fs.ModeSymlink | 0o777},
		{name: "files/pipe", mode: fs.ModeNamedPipe | 0o644},
	})
	result, err := Validate(archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireViolation(t, result.Violations, "files/a.txt: archive entry is duplicated")
	requireViolation(t, result.Violations, "files/link: symbolic links are not allowed")
	requireViolation(t, result.Violations, "files/pipe: only regular files and directories")
}

func TestValidateZipRequiresRootSpec(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "kit.zip")
	writeZipFixture(t, archive, []zipFixture{{name: "files/spec.yaml", body: goodSpec}})
	result, err := Validate(archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireViolation(t, result.Violations, "kit requires <name>.yaml, spec.yaml or spec.yml")
}

func TestValidateZipEntryBounds(t *testing.T) {
	t.Run("entry count", func(t *testing.T) {
		archive := filepath.Join(t.TempDir(), "kit.zip")
		fixtures := []zipFixture{{name: "spec.yaml", body: goodSpec}}
		for i := 0; i < maxArtifactEntries; i++ {
			fixtures = append(fixtures, zipFixture{name: fmt.Sprintf("files/f%04d", i), body: "x"})
		}
		writeZipFixture(t, archive, fixtures)
		result, err := Validate(archive, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireViolation(t, result.Violations, fmt.Sprintf("kit has more than %d entries", maxArtifactEntries))
	})
	t.Run("declared file size", func(t *testing.T) {
		archive := filepath.Join(t.TempDir(), "kit.zip")
		writeZipFixture(t, archive, []zipFixture{
			{name: "spec.yaml", body: goodSpec},
			{name: "files/big.bin", body: strings.Repeat("\x00", maxArtifactFileBytes+1)},
		})
		result, err := Validate(archive, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireViolation(t, result.Violations, "files/big.bin: file exceeds 1 MiB")
	})
}

func TestValidateZipArguments(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "argkit.zip")
	writeZipFixture(t, archive, []zipFixture{{name: "spec.yaml", body: argsSpec}})
	result, err := Validate(archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireViolation(t, result.Violations, `required kit argument "region" is not set`)
	result, err = Validate(archive, map[string]string{"region": "us"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Violations) != 0 || result.Name != "argkit" {
		t.Fatalf("name=%q violations=%q", result.Name, violationMessages(result.Violations))
	}
}
