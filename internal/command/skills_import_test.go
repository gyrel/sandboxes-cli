//go:build !windows

package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSkillsImportValidAndIdempotent(t *testing.T) {
	home := setSkillsTestHome(t)
	source := writeTestSkill(t, t.TempDir(), "alpha", "Test skill", map[string]string{
		"notes.txt":      "fixture",
		"scripts/run.sh": "#!/bin/sh\nexit 0\n",
	})
	code, output := importTestSkill(t, source)
	if code != 0 || !strings.Contains(output, `Imported skill "alpha"`) {
		t.Fatalf("import exit=%d output=%q", code, output)
	}
	stored := filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha")
	if data, err := os.ReadFile(filepath.Join(stored, "notes.txt")); err != nil || string(data) != "fixture" {
		t.Fatalf("stored notes=%q err=%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".sandboxes")); !os.IsNotExist(err) {
		t.Fatalf("import touched Docker state: %v", err)
	}
	registry := readTestRegistry(t)
	if len(registry.Skills) != 1 {
		t.Fatalf("registry=%+v", registry)
	}
	entry := registry.Skills[0]
	if entry.Name != "alpha" || entry.Source != source || !strings.HasPrefix(entry.Digest, "sha256:") {
		t.Fatalf("entry=%+v", entry)
	}
	code, output = importTestSkill(t, source)
	if code != 0 || !strings.Contains(output, "already imported") {
		t.Fatalf("repeat import exit=%d output=%q", code, output)
	}
	again := readTestRegistry(t)
	if len(again.Skills) != 1 || again.Skills[0].ImportedAt != entry.ImportedAt || again.Skills[0].Digest != entry.Digest {
		t.Fatalf("idempotent import changed registry: %+v", again)
	}
}

func TestSkillsImportRequiresForceForChangedContent(t *testing.T) {
	home := setSkillsTestHome(t)
	source := writeTestSkill(t, t.TempDir(), "alpha", "Test skill", map[string]string{"notes.txt": "original"})
	if code, output := importTestSkill(t, source); code != 0 {
		t.Fatalf("initial import exit=%d output=%q", code, output)
	}
	original := readTestRegistry(t).Skills[0]
	if err := os.WriteFile(filepath.Join(source, "notes.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, output := importTestSkill(t, source)
	if code != 1 || !strings.Contains(output, "--force") {
		t.Fatalf("duplicate exit=%d output=%q", code, output)
	}
	stored := filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha", "notes.txt")
	if data, err := os.ReadFile(stored); err != nil || string(data) != "original" {
		t.Fatalf("store changed without force: %q %v", data, err)
	}
	if unchanged := readTestRegistry(t).Skills[0]; unchanged.Digest != original.Digest {
		t.Fatalf("registry changed without force: %+v", unchanged)
	}
	code, output = importTestSkill(t, source, "--force")
	if code != 0 || !strings.Contains(output, `Replaced skill "alpha"`) {
		t.Fatalf("forced import exit=%d output=%q", code, output)
	}
	if data, err := os.ReadFile(stored); err != nil || string(data) != "changed" {
		t.Fatalf("store not replaced: %q %v", data, err)
	}
	replaced := readTestRegistry(t).Skills[0]
	if replaced.Digest == original.Digest {
		t.Fatal("registry digest did not change")
	}
}

func TestSkillsImportUnsafePaths(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T) string
		want  string
	}{
		{
			name: "source symlink",
			build: func(t *testing.T) string {
				t.Helper()
				realSource := writeTestSkill(t, t.TempDir(), "alpha", "Test skill", nil)
				link := filepath.Join(t.TempDir(), "alpha-link")
				if err := os.Symlink(realSource, link); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				return link
			},
			want: "symbolic link",
		},
		{
			name: "nested symlink",
			build: func(t *testing.T) string {
				t.Helper()
				source := writeTestSkill(t, t.TempDir(), "alpha", "Test skill", nil)
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, []byte("synthetic"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(source, "linked")); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				return source
			},
			want: "symbolic link",
		},
		{
			name: "regular file source",
			build: func(t *testing.T) string {
				t.Helper()
				path := filepath.Join(t.TempDir(), "alpha")
				if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
				return path
			},
			want: "must be a directory",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setSkillsTestHome(t)
			path := test.build(t)
			code, output := importTestSkill(t, path)
			if code != 1 || !strings.Contains(output, test.want) {
				t.Fatalf("exit=%d output=%q", code, output)
			}
		})
	}
}

func TestSkillsImportRejectsBadManifest(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "missing manifest", want: "SKILL.md is required"},
		{name: "no frontmatter", content: "# alpha\n", want: "must start with YAML frontmatter"},
		{name: "unterminated frontmatter", content: "---\nname: alpha\n", want: "not terminated"},
		{name: "missing name", content: "---\ndescription: Test skill\n---\n", want: "name is invalid"},
		{name: "missing description", content: "---\nname: alpha\n---\n", want: "description is required"},
		{name: "name mismatch", content: "---\nname: beta\ndescription: Test skill\n---\n", want: "must match source directory"},
		{name: "invalid name", content: "---\nname: bad name\ndescription: Test skill\n---\n", want: "name is invalid"},
		{name: "multiline description", content: "---\nname: alpha\ndescription: \"first\\nsecond\"\n---\n", want: "single line"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setSkillsTestHome(t)
			source := filepath.Join(t.TempDir(), "alpha")
			if err := os.MkdirAll(source, 0o700); err != nil {
				t.Fatal(err)
			}
			if test.content != "" {
				if err := os.WriteFile(filepath.Join(source, "SKILL.md"), []byte(test.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			code, output := importTestSkill(t, source)
			if code != 1 || !strings.Contains(output, test.want) {
				t.Fatalf("exit=%d output=%q", code, output)
			}
		})
	}
}

func TestSkillsImportNeverOverwritesForeignDirectory(t *testing.T) {
	home := setSkillsTestHome(t)
	foreign := filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(foreign, "marker")
	if err := os.WriteFile(marker, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeTestSkill(t, t.TempDir(), "alpha", "Test skill", nil)
	for _, extra := range [][]string{nil, {"--force"}} {
		code, output := importTestSkill(t, source, extra...)
		if code != 1 || !strings.Contains(output, "not imported by Rheic") {
			t.Fatalf("extra=%v exit=%d output=%q", extra, code, output)
		}
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "foreign" {
		t.Fatalf("foreign directory changed: %q %v", data, err)
	}
}

func TestSkillsImportRejectsOversizedFile(t *testing.T) {
	setSkillsTestHome(t)
	source := writeTestSkill(t, t.TempDir(), "alpha", "Test skill", nil)
	large := make([]byte, maxSkillFileBytes+1)
	if err := os.WriteFile(filepath.Join(source, "large.bin"), large, 0o600); err != nil {
		t.Fatal(err)
	}
	code, output := importTestSkill(t, source)
	if code != 1 || !strings.Contains(output, "per-file limit") {
		t.Fatalf("exit=%d output=%q", code, output)
	}
}
