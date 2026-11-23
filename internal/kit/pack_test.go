package kit

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPackIsDeterministicAndRoundTrips(t *testing.T) {
	root := newKitDir(t, "good-kit", map[string]string{
		"spec.yaml":       goodSpec,
		"files/z.txt":     "z",
		"files/a/b.txt":   "b",
		"files/a.txt":     "a",
		"files/run.sh":    "#!/bin/sh\n",
		"files/empty.txt": "",
	})
	if err := os.Chmod(filepath.Join(root, "files", "run.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	first := filepath.Join(dir, "first.zip")
	second := filepath.Join(dir, "second.zip")
	if _, err := Pack(root, first); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(root, second); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two packs of the same tree differ")
	}
	reader, err := zip.OpenReader(first)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	names := make([]string, 0, len(reader.File))
	for _, file := range reader.File {
		names = append(names, file.Name)
		if !file.Modified.Equal(packTime) {
			t.Fatalf("%s modified=%v", file.Name, file.Modified)
		}
		if file.Name == "files/run.sh" && file.Mode().Perm() != 0o755 {
			t.Fatalf("run.sh mode=%v", file.Mode())
		}
	}
	want := []string{"files/a.txt", "files/a/b.txt", "files/empty.txt", "files/run.sh", "files/z.txt", "spec.yaml"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("entries=%v want %v", names, want)
	}
	result, err := Validate(first, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Violations) != 0 || result.Name != "good-kit" {
		t.Fatalf("round trip name=%q violations=%q", result.Name, violationMessages(result.Violations))
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".kit-pack-*")); len(matches) != 0 {
		t.Fatalf("temporary files left behind: %v", matches)
	}
}

func TestPackRefusalsWriteNothing(t *testing.T) {
	spec := map[string]string{"spec.yaml": goodSpec}
	tests := []struct {
		name    string
		files   map[string]string
		link    bool
		wantMsg string
	}{
		{name: "extra root file", files: map[string]string{"spec.yaml": goodSpec, "README.md": "x"}, wantMsg: "README.md: not packaged"},
		{name: "spec.yml only", files: map[string]string{"spec.yml": goodSpec}, wantMsg: "spec.yaml: kit pack requires spec.yaml"},
		{name: "symlink", files: spec, link: true, wantMsg: "files/link: symbolic links are not allowed"},
		{name: "files is a file", files: map[string]string{"spec.yaml": goodSpec, "files": "x"}, wantMsg: "files: not packaged"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := newKitDir(t, "good-kit", tt.files)
			if tt.link {
				if err := os.MkdirAll(filepath.Join(root, "files"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "spec.yaml"), filepath.Join(root, "files", "link")); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			output := filepath.Join(t.TempDir(), "out.zip")
			_, err := Pack(root, output)
			var violations *ViolationError
			if !errors.As(err, &violations) {
				t.Fatalf("err=%v", err)
			}
			requireViolation(t, violations.Violations, tt.wantMsg)
			if _, statErr := os.Lstat(output); statErr == nil {
				t.Fatal("refused pack still wrote an archive")
			}
		})
	}
}

func TestPackRequiresArgumentsToBeSupplied(t *testing.T) {
	root := newKitDir(t, "argkit", map[string]string{"spec.yaml": argsSpec})
	_, err := Pack(root, filepath.Join(t.TempDir(), "argkit.zip"))
	var violations *ViolationError
	if !errors.As(err, &violations) {
		t.Fatalf("err=%v", err)
	}
	requireViolation(t, violations.Violations, `required kit argument "region" is not set`)
}

func TestPackOutputRules(t *testing.T) {
	root := newKitDir(t, "good-kit", map[string]string{"spec.yaml": goodSpec})
	dir := t.TempDir()
	if _, err := Pack(root, filepath.Join(dir, "out.tar")); err == nil || !strings.Contains(err.Error(), "must end in .zip") {
		t.Fatalf("non-zip output err=%v", err)
	}
	existing := filepath.Join(dir, "existing.zip")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(root, existing); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output err=%v", err)
	}
	if data, _ := os.ReadFile(existing); string(data) != "keep" {
		t.Fatal("existing output was overwritten")
	}
	if _, err := Pack(filepath.Join(root, "spec.yaml"), filepath.Join(dir, "x.zip")); err == nil || !strings.Contains(err.Error(), "expects a directory") {
		t.Fatalf("file input err=%v", err)
	}
	nested := filepath.Join(dir, "dist", "nested", "good-kit.zip")
	if _, err := Pack(root, nested); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(nested); err != nil {
		t.Fatal(err)
	}
}

func TestPackDefaultOutputUsesKitName(t *testing.T) {
	root := newKitDir(t, "dir-name", map[string]string{"spec.yaml": goodSpec})
	work := t.TempDir()
	t.Chdir(work)
	packed, err := Pack(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if packed.Output != "good-kit.zip" || packed.Name != "good-kit" || packed.Files != 1 {
		t.Fatalf("packed=%+v", packed)
	}
	if _, err := os.Stat(filepath.Join(work, "good-kit.zip")); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultPackOutputRejectsUnsafeNames(t *testing.T) {
	for _, name := range []string{"", ".", "..", "a/b", `a\b`} {
		if _, err := defaultPackOutput(name); err == nil {
			t.Fatalf("name %q accepted", name)
		}
	}
}

func TestPackRejectsChangedSource(t *testing.T) {
	root := newKitDir(t, "good-kit", map[string]string{"spec.yaml": goodSpec, "files/a.txt": "a"})
	result, err := Validate(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	var member Entry
	for _, entry := range result.Entries {
		if entry.Name == "files/a.txt" {
			member = entry
		}
	}
	replacement := member.path + ".new"
	if err := os.WriteFile(replacement, []byte("swapped"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, member.path); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(member.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	if err := verifyUnchanged(source, member); err == nil {
		t.Fatal("replaced file passed identity check")
	}
}
