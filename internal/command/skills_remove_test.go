package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSkillsRemoveCases(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, home string) string
		args       []string
		wantCode   int
		wantOutput string
		check      func(t *testing.T, home, skill string)
	}{
		{
			name: "existing",
			setup: func(t *testing.T, _ string) string {
				t.Helper()
				source := writeTestSkill(t, t.TempDir(), "alpha", "Test skill", map[string]string{"notes.txt": "fixture"})
				if code, output := importTestSkill(t, source); code != 0 {
					t.Fatalf("import exit=%d output=%q", code, output)
				}
				return "alpha"
			},
			args:       []string{"rm", "--force", "alpha"},
			wantOutput: `Removed skill "alpha"`,
			check: func(t *testing.T, home, skill string) {
				t.Helper()
				if _, err := os.Lstat(filepath.Join(skillsTestConfig(home), skillsDirectoryName, skill)); !os.IsNotExist(err) {
					t.Fatalf("skill remains: %v", err)
				}
				if registry := readTestRegistry(t); len(registry.Skills) != 0 {
					t.Fatalf("registry=%+v", registry)
				}
			},
		},
		{
			name: "missing",
			setup: func(t *testing.T, home string) string {
				t.Helper()
				source := writeTestSkill(t, t.TempDir(), "alpha", "Test skill", nil)
				if code, output := importTestSkill(t, source); code != 0 {
					t.Fatalf("import exit=%d output=%q", code, output)
				}
				if err := os.RemoveAll(filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha")); err != nil {
					t.Fatal(err)
				}
				return "alpha"
			},
			args:       []string{"remove", "--force", "alpha"},
			wantCode:   1,
			wantOutput: "not installed",
			check: func(t *testing.T, _ string, _ string) {
				t.Helper()
				if registry := readTestRegistry(t); len(registry.Skills) != 1 {
					t.Fatalf("missing record was silently pruned: %+v", registry)
				}
			},
		},
		{
			name: "foreign",
			setup: func(t *testing.T, home string) string {
				t.Helper()
				foreign := filepath.Join(skillsTestConfig(home), skillsDirectoryName, "foreign")
				if err := os.MkdirAll(foreign, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(foreign, "marker"), []byte("foreign"), 0o600); err != nil {
					t.Fatal(err)
				}
				return "foreign"
			},
			args:       []string{"rm", "--force", "foreign"},
			wantCode:   1,
			wantOutput: "not managed by Rheic",
			check: func(t *testing.T, home, skill string) {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(skillsTestConfig(home), skillsDirectoryName, skill, "marker"))
				if err != nil || string(data) != "foreign" {
					t.Fatalf("foreign skill changed: %q %v", data, err)
				}
			},
		},
		{
			name: "requires terminal without force",
			setup: func(t *testing.T, _ string) string {
				t.Helper()
				source := writeTestSkill(t, t.TempDir(), "alpha", "Test skill", nil)
				if code, output := importTestSkill(t, source); code != 0 {
					t.Fatalf("import exit=%d output=%q", code, output)
				}
				return "alpha"
			},
			args:       []string{"rm", "alpha"},
			wantCode:   1,
			wantOutput: "not a terminal",
			check: func(t *testing.T, home, skill string) {
				t.Helper()
				if _, err := os.Stat(filepath.Join(skillsTestConfig(home), skillsDirectoryName, skill)); err != nil {
					t.Fatalf("skill changed without confirmation: %v", err)
				}
			},
		},
		{
			name: "rejects traversal",
			setup: func(t *testing.T, _ string) string {
				t.Helper()
				return "../alpha"
			},
			args:       []string{"rm", "--force", "../alpha"},
			wantCode:   1,
			wantOutput: "invalid skill name",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := setSkillsTestHome(t)
			skill := test.setup(t, home)
			code, output := runSkillsTest(t, test.args...)
			if code != test.wantCode || !strings.Contains(output, test.wantOutput) {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			if test.check != nil {
				test.check(t, home, skill)
			}
		})
	}
}

func TestSkillsRemovePreservesOtherImports(t *testing.T) {
	home := setSkillsTestHome(t)
	for _, name := range []string{"alpha", "beta"} {
		source := writeTestSkill(t, t.TempDir(), name, "Test skill", map[string]string{"notes.txt": name})
		if code, output := importTestSkill(t, source); code != 0 {
			t.Fatalf("import %s exit=%d output=%q", name, code, output)
		}
	}
	if code, output := runSkillsTest(t, "rm", "--force", "alpha"); code != 0 {
		t.Fatalf("remove exit=%d output=%q", code, output)
	}
	beta := filepath.Join(skillsTestConfig(home), skillsDirectoryName, "beta", "notes.txt")
	if data, err := os.ReadFile(beta); err != nil || string(data) != "beta" {
		t.Fatalf("unselected skill changed: %q %v", data, err)
	}
	registry := readTestRegistry(t)
	if len(registry.Skills) != 1 || registry.Skills[0].Name != "beta" {
		t.Fatalf("registry=%+v", registry)
	}
}
