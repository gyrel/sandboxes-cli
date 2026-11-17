package command

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setSkillsTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	return home
}

func skillsTestConfig(home string) string {
	return filepath.Join(home, ".config", "rheic")
}

func runSkillsTest(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var output bytes.Buffer
	runner := &Runner{Out: &output, Err: &output, In: strings.NewReader("")}
	code := runner.Run(context.Background(), append([]string{"skills"}, args...))
	return code, output.String()
}

func writeTestSkill(t *testing.T, parent, name, description string, files map[string]string) string {
	t.Helper()
	directory := filepath.Join(parent, name)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := "---\nname: " + name + "\ndescription: " + description + "\n---\n\n# " + name + "\n"
	if err := os.WriteFile(filepath.Join(directory, "SKILL.md"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	for relative, content := range files {
		path := filepath.Join(directory, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func importTestSkill(t *testing.T, path string, extra ...string) (int, string) {
	t.Helper()
	args := append([]string{"import"}, extra...)
	args = append(args, path)
	return runSkillsTest(t, args...)
}

func readTestRegistry(t *testing.T) skillsRegistry {
	t.Helper()
	paths, err := resolveSkillsPaths()
	if err != nil {
		t.Fatal(err)
	}
	root, err := openSkillsRoot(paths, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	registry, err := readSkillsRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestSkillsListOutputs(t *testing.T) {
	tests := []struct {
		name      string
		withSkill bool
		args      []string
		want      []string
		validate  func(t *testing.T, output string, home string)
	}{
		{
			name: "empty table",
			args: []string{"ls"},
			want: []string{"No skills imported"},
		},
		{
			name: "empty json",
			args: []string{"ls", "--json"},
			validate: func(t *testing.T, output string, home string) {
				t.Helper()
				var report skillsListOutput
				if err := json.Unmarshal([]byte(output), &report); err != nil {
					t.Fatalf("json: %v output=%q", err, output)
				}
				if len(report.Skills) != 0 {
					t.Fatalf("skills=%v", report.Skills)
				}
				if report.Store != filepath.Join(skillsTestConfig(home), skillsDirectoryName) {
					t.Fatalf("store=%q", report.Store)
				}
			},
		},
		{
			name:      "non-empty table",
			withSkill: true,
			args:      []string{"list"},
			want:      []string{"SKILL", "SOURCE", "IMPORTED", "alpha"},
		},
		{
			name:      "non-empty json",
			withSkill: true,
			args:      []string{"ls", "--format", "json"},
			validate: func(t *testing.T, output string, _ string) {
				t.Helper()
				var report skillsListOutput
				if err := json.Unmarshal([]byte(output), &report); err != nil {
					t.Fatalf("json: %v output=%q", err, output)
				}
				if len(report.Skills) != 1 || report.Skills[0].Name != "alpha" {
					t.Fatalf("skills=%+v", report.Skills)
				}
				if report.Skills[0].Source == "" || report.Skills[0].ImportedAt == "" {
					t.Fatalf("incomplete record: %+v", report.Skills[0])
				}
			},
		},
		{
			name:      "non-empty yaml",
			withSkill: true,
			args:      []string{"ls", "--format", "yaml"},
			want:      []string{"store:", "skills:", "name: alpha"},
		},
		{
			name:      "non-empty quiet",
			withSkill: true,
			args:      []string{"ls", "--quiet"},
			want:      []string{"alpha"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := setSkillsTestHome(t)
			if test.withSkill {
				source := writeTestSkill(t, t.TempDir(), "alpha", "Test skill", map[string]string{"notes.txt": "fixture"})
				if code, output := importTestSkill(t, source); code != 0 {
					t.Fatalf("import exit=%d output=%q", code, output)
				}
			}
			code, output := runSkillsTest(t, test.args...)
			if code != 0 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			for _, want := range test.want {
				if !strings.Contains(output, want) {
					t.Errorf("missing %q in %q", want, output)
				}
			}
			if test.validate != nil {
				test.validate(t, output, home)
			}
			if !test.withSkill {
				if _, err := os.Stat(skillsTestConfig(home)); !os.IsNotExist(err) {
					t.Fatalf("listing created config state: %v", err)
				}
			}
		})
	}
}

func TestSkillsListRejectsInvalidFlags(t *testing.T) {
	setSkillsTestHome(t)
	for _, args := range [][]string{
		{"ls", "--quiet", "--json"},
		{"ls", "--quiet", "--format", "yaml"},
		{"ls", "--format", "xml"},
		{"ls", "extra"},
	} {
		if code, output := runSkillsTest(t, args...); code == 0 {
			t.Errorf("%v exit=%d output=%q", args, code, output)
		}
	}
}

func TestSkillsHelpAndDispatch(t *testing.T) {
	setSkillsTestHome(t)
	for _, args := range [][]string{{"--help"}, {"ls", "--help"}, {"import", "--help"}, {"rm", "--help"}} {
		code, output := runSkillsTest(t, args...)
		if code != 0 || !strings.Contains(strings.ToLower(output), "usage:") {
			t.Fatalf("%v exit=%d output=%q", args, code, output)
		}
	}
	if code, output := runSkillsTest(t, "unknown"); code != 2 || !strings.Contains(output, "unknown subcommand") {
		t.Fatalf("unknown exit=%d output=%q", code, output)
	}
	var rootOutput bytes.Buffer
	rootRunner := &Runner{Out: &rootOutput, Err: &rootOutput}
	if code := rootRunner.Run(context.Background(), []string{"--help"}); code != 0 {
		t.Fatalf("root help exit=%d output=%q", code, rootOutput.String())
	}
	if !strings.Contains(rootOutput.String(), "Experimental Commands:") || !strings.Contains(rootOutput.String(), "skills") {
		t.Fatalf("root help does not label skills experimental: %q", rootOutput.String())
	}
}
