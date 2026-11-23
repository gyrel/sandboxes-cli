//go:build !windows

package command

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func requireSkillsGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required for repository fixtures")
	}
}

func runFixtureGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(safeGitEnvironment(),
		"GIT_AUTHOR_NAME=Rheic Test", "GIT_AUTHOR_EMAIL=test@example.invalid",
		"GIT_COMMITTER_NAME=Rheic Test", "GIT_COMMITTER_EMAIL=test@example.invalid")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func commitFixture(t *testing.T, repo, message string) {
	t.Helper()
	runFixtureGit(t, repo, "add", "-A")
	runFixtureGit(t, repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", message)
}

func fixtureHead(t *testing.T, repo string) string {
	t.Helper()
	return runFixtureGit(t, repo, "rev-parse", "HEAD")
}

// newSkillsRepoFixture builds a synthetic repository with two skills under
// skills/. No network is involved: the clone source is a local path.
func newSkillsRepoFixture(t *testing.T) string {
	t.Helper()
	requireSkillsGit(t)
	repo := t.TempDir()
	runFixtureGit(t, repo, "init", "-q", "-b", "main")
	writeTestSkill(t, filepath.Join(repo, "skills"), "alpha", "Alpha skill", map[string]string{"notes.txt": "one"})
	writeTestSkill(t, filepath.Join(repo, "skills"), "beta", "Beta skill", nil)
	commitFixture(t, repo, "initial")
	return repo
}

func setSkillsRepoFile(t *testing.T, repo, relative, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, relative), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func registryByName(t *testing.T) map[string]skillsRegistryEntry {
	t.Helper()
	entries := make(map[string]skillsRegistryEntry)
	for _, entry := range readTestRegistry(t).Skills {
		entries[entry.Name] = entry
	}
	return entries
}

func readStoredSkillFile(t *testing.T, home, name, relative string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(skillsTestConfig(home), skillsDirectoryName, name, relative))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestSkillsAddImportsRepositorySkills(t *testing.T) {
	home := setSkillsTestHome(t)
	repo := newSkillsRepoFixture(t)
	code, output := runSkillsTest(t, "add", repo)
	if code != 0 || !strings.Contains(output, `Imported skill "alpha" from `+filepath.Base(repo)) || !strings.Contains(output, `Imported skill "beta"`) {
		t.Fatalf("add exit=%d output=%q", code, output)
	}
	if got := readStoredSkillFile(t, home, "alpha", "notes.txt"); got != "one" {
		t.Fatalf("stored notes=%q", got)
	}
	entries := registryByName(t)
	alpha, ok := entries["alpha"]
	if !ok || len(entries) != 2 {
		t.Fatalf("registry=%+v", entries)
	}
	if alpha.Repository != repo || alpha.Source != repo || alpha.Branch != "main" || alpha.Commit != fixtureHead(t, repo) {
		t.Fatalf("provenance=%+v", alpha)
	}
	if strings.Contains(output, repo) {
		t.Fatalf("output echoed the repository path: %q", output)
	}
}

func TestSkillsAddSelectsNamedSkills(t *testing.T) {
	setSkillsTestHome(t)
	repo := newSkillsRepoFixture(t)
	if code, output := runSkillsTest(t, "add", "--skill", "alpha", repo); code != 0 {
		t.Fatalf("single skill exit=%d output=%q", code, output)
	}
	if entries := registryByName(t); len(entries) != 1 || entries["alpha"].Name == "" {
		t.Fatalf("single skill registry=%+v", entries)
	}
	if code, output := runSkillsTest(t, "add", "-s", "beta,alpha", repo); code != 0 {
		t.Fatalf("comma list exit=%d output=%q", code, output)
	}
	if entries := registryByName(t); len(entries) != 2 {
		t.Fatalf("comma list registry=%+v", entries)
	}
}

func TestSkillsAddRejectsMissingNamedSkillBeforeWriting(t *testing.T) {
	home := setSkillsTestHome(t)
	repo := newSkillsRepoFixture(t)
	code, output := runSkillsTest(t, "add", "--skill", "alpha", "--skill", "missing", repo)
	if code != 1 || !strings.Contains(output, `skill "missing" was not found`) {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	if _, err := os.Stat(filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha")); !os.IsNotExist(err) {
		t.Fatalf("store changed for a failed add: %v", err)
	}
}

func TestSkillsAddConflictAndForce(t *testing.T) {
	home := setSkillsTestHome(t)
	repo := newSkillsRepoFixture(t)
	if code, output := runSkillsTest(t, "add", repo); code != 0 {
		t.Fatalf("initial add exit=%d output=%q", code, output)
	}
	code, output := runSkillsTest(t, "add", repo)
	if code != 0 || !strings.Contains(output, "already imported") {
		t.Fatalf("identical re-add exit=%d output=%q", code, output)
	}
	setSkillsRepoFile(t, repo, "skills/alpha/notes.txt", "two")
	commitFixture(t, repo, "change alpha")
	code, output = runSkillsTest(t, "add", repo)
	if code != 1 || !strings.Contains(output, "--force") {
		t.Fatalf("conflict exit=%d output=%q", code, output)
	}
	if got := readStoredSkillFile(t, home, "alpha", "notes.txt"); got != "one" {
		t.Fatalf("store changed without --force: %q", got)
	}
	code, output = runSkillsTest(t, "add", "--force", repo)
	if code != 0 || !strings.Contains(output, `Replaced skill "alpha"`) {
		t.Fatalf("forced add exit=%d output=%q", code, output)
	}
	if got := readStoredSkillFile(t, home, "alpha", "notes.txt"); got != "two" {
		t.Fatalf("store not replaced: %q", got)
	}
}

func TestSkillsAddRefusesSymlinkedSkill(t *testing.T) {
	home := setSkillsTestHome(t)
	repo := newSkillsRepoFixture(t)
	if err := os.Symlink(filepath.Join("skills", "alpha"), filepath.Join(repo, "skills", "linked")); err != nil {
		t.Fatal(err)
	}
	commitFixture(t, repo, "add symlink")
	code, output := runSkillsTest(t, "add", repo)
	if code != 1 || !strings.Contains(output, "symbolic link") {
		t.Fatalf("symlink exit=%d output=%q", code, output)
	}
	if _, err := os.Stat(filepath.Join(skillsTestConfig(home), skillsDirectoryName)); !os.IsNotExist(err) {
		t.Fatalf("store written for refused repository: %v", err)
	}
}

func TestSkillsAddRefusesCredentialAndUnsafeSources(t *testing.T) {
	home := setSkillsTestHome(t)
	for _, source := range []string{
		"https://user:topsecret@example.invalid/acme/skills.git",
		"https://example.invalid/acme/skills?token=topsecret",
		"https://example.invalid/acme/skills#topsecret",
		"http://example.invalid/acme/skills",
		"ssh://git@example.invalid/acme/skills.git",
		"ext::sh -c touch",
		"--upload-pack=touch",
		"https://",
	} {
		code, output := runSkillsTest(t, "add", source)
		if code == 0 || strings.Contains(output, "topsecret") {
			t.Fatalf("add %q exit=%d output=%q", source, code, output)
		}
	}
	if _, err := os.Stat(filepath.Join(skillsTestConfig(home), skillsDirectoryName)); !os.IsNotExist(err) {
		t.Fatalf("refused sources wrote to the store: %v", err)
	}
}

func TestSkillsAddRedactsHostPaths(t *testing.T) {
	setSkillsTestHome(t)
	requireSkillsGit(t)
	missing := filepath.Join(t.TempDir(), "missing")
	notRepo := t.TempDir()
	for _, source := range []string{missing, "file://" + missing, notRepo} {
		code, output := runSkillsTest(t, "add", source)
		if code == 0 {
			t.Fatalf("add %q succeeded: %q", source, output)
		}
		if strings.Contains(output, filepath.Dir(missing)) || strings.Contains(output, notRepo) {
			t.Fatalf("add %q echoed a host path: %q", source, output)
		}
	}
}

func TestSkillsAddArgumentErrors(t *testing.T) {
	setSkillsTestHome(t)
	for _, test := range []struct {
		name string
		args []string
		want int
	}{
		{name: "no repository", args: []string{"add"}, want: 2},
		{name: "two repositories", args: []string{"add", "a/b", "c/d"}, want: 2},
		{name: "unknown flag", args: []string{"add", "--all", "a/b"}, want: 1},
		{name: "empty skill name", args: []string{"add", "--skill", "", "a/b"}, want: 1},
		{name: "invalid skill name", args: []string{"add", "--skill", "../x", "a/b"}, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if code, output := runSkillsTest(t, test.args...); code != test.want {
				t.Fatalf("exit=%d want %d output=%q", code, test.want, output)
			}
		})
	}
}

func TestSkillsAddHelpAndAliases(t *testing.T) {
	setSkillsTestHome(t)
	for _, args := range [][]string{{"add", "--help"}, {"a", "--help"}} {
		code, output := runSkillsTest(t, args...)
		if code != 0 || !strings.Contains(output, "rsbx skills add REPOSITORY [flags]") || !strings.Contains(output, "--skill") || !strings.Contains(output, "EXPERIMENTAL") {
			t.Fatalf("%v exit=%d output=%q", args, code, output)
		}
	}
	code, output := runSkillsTest(t, "--help")
	if code != 0 || !strings.Contains(output, "add, a") || !strings.Contains(output, "update, upgrade") {
		t.Fatalf("family help exit=%d output=%q", code, output)
	}
}

func TestSkillsUpdateRefreshesUpstreamChanges(t *testing.T) {
	home := setSkillsTestHome(t)
	repo := newSkillsRepoFixture(t)
	if code, output := runSkillsTest(t, "add", repo); code != 0 {
		t.Fatalf("add exit=%d output=%q", code, output)
	}
	before := registryByName(t)["alpha"]
	setSkillsRepoFile(t, repo, "skills/alpha/notes.txt", "two")
	commitFixture(t, repo, "change alpha")
	code, output := runSkillsTest(t, "update")
	if code != 0 || !strings.Contains(output, `Updated skill "alpha" from `) || !strings.Contains(output, `Skill "beta" is already up to date`) {
		t.Fatalf("update exit=%d output=%q", code, output)
	}
	if got := readStoredSkillFile(t, home, "alpha", "notes.txt"); got != "two" {
		t.Fatalf("stored notes=%q", got)
	}
	after := registryByName(t)["alpha"]
	if after.Commit != fixtureHead(t, repo) || after.Commit == before.Commit || after.Digest == before.Digest {
		t.Fatalf("registry not refreshed: before=%+v after=%+v", before, after)
	}
}

func TestSkillsUpdateUnchangedIsNoop(t *testing.T) {
	setSkillsTestHome(t)
	repo := newSkillsRepoFixture(t)
	if code, output := runSkillsTest(t, "add", repo); code != 0 {
		t.Fatalf("add exit=%d output=%q", code, output)
	}
	before := registryByName(t)
	code, output := runSkillsTest(t, "update", "alpha")
	if code != 0 || !strings.Contains(output, `Skill "alpha" is already up to date`) {
		t.Fatalf("update exit=%d output=%q", code, output)
	}
	after := registryByName(t)
	if after["alpha"] != before["alpha"] {
		t.Fatalf("no-op update changed the record: before=%+v after=%+v", before["alpha"], after["alpha"])
	}
}

func TestSkillsUpdateRejectsLocalImportsAndUnknownNames(t *testing.T) {
	home := setSkillsTestHome(t)
	local := writeTestSkill(t, t.TempDir(), "gamma", "Local skill", nil)
	if code, output := importTestSkill(t, local); code != 0 {
		t.Fatalf("import exit=%d output=%q", code, output)
	}
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "local import", args: []string{"update", "gamma"}, want: "must be added from a repository"},
		{name: "unknown name", args: []string{"update", "nope"}, want: "not managed by Rheic"},
		{name: "invalid name", args: []string{"update", "bad/name"}, want: "invalid skill name"},
	} {
		t.Run(test.name, func(t *testing.T) {
			code, output := runSkillsTest(t, test.args...)
			if code != 1 || !strings.Contains(output, test.want) {
				t.Fatalf("exit=%d output=%q", code, output)
			}
		})
	}
	if code, _ := runSkillsTest(t, "update", "--all"); code != 1 {
		t.Fatalf("--all exit=%d, want 1", code)
	}
	if data, err := os.ReadFile(filepath.Join(skillsTestConfig(home), skillsDirectoryName, "gamma", "SKILL.md")); err != nil || len(data) == 0 {
		t.Fatalf("local import changed: %v", err)
	}
}

func TestSkillsUpdateWithoutRepositoryEntries(t *testing.T) {
	setSkillsTestHome(t)
	code, output := runSkillsTest(t, "update")
	if code != 0 || !strings.Contains(output, "No skills added from a repository are installed") {
		t.Fatalf("exit=%d output=%q", code, output)
	}
}

func TestSkillsUpdateRefusesLocalEdits(t *testing.T) {
	home := setSkillsTestHome(t)
	repo := newSkillsRepoFixture(t)
	if code, output := runSkillsTest(t, "add", repo); code != 0 {
		t.Fatalf("add exit=%d output=%q", code, output)
	}
	edited := filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha", "notes.txt")
	if err := os.WriteFile(edited, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, output := runSkillsTest(t, "update", "alpha")
	if code != 1 || !strings.Contains(output, "local changes") {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	if got := readStoredSkillFile(t, home, "alpha", "notes.txt"); got != "tampered" {
		t.Fatalf("local edit overwritten: %q", got)
	}
}

func TestSkillsUpdateReportsSkillRemovedUpstream(t *testing.T) {
	setSkillsTestHome(t)
	repo := newSkillsRepoFixture(t)
	if code, output := runSkillsTest(t, "add", repo); code != 0 {
		t.Fatalf("add exit=%d output=%q", code, output)
	}
	runFixtureGit(t, repo, "rm", "-q", "-r", "skills/beta")
	commitFixture(t, repo, "remove beta")
	code, output := runSkillsTest(t, "update")
	if code != 1 || !strings.Contains(output, `Skill "alpha" is already up to date`) {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	if !strings.Contains(output, `skills update: skill "beta" is no longer in the repository`) {
		t.Fatalf("missing upstream removal report: %q", output)
	}
}

func TestSkillsAddConcurrentRepositoriesShareStore(t *testing.T) {
	setSkillsTestHome(t)
	first := newSkillsRepoFixture(t)
	second := t.TempDir()
	runFixtureGit(t, second, "init", "-q", "-b", "main")
	writeTestSkill(t, filepath.Join(second, "skills"), "gamma", "Gamma skill", nil)
	commitFixture(t, second, "initial")
	sources := []string{first, second}
	codes := make([]int, len(sources))
	outputs := make([]string, len(sources))
	var wg sync.WaitGroup
	for i, source := range sources {
		wg.Add(1)
		go func(i int, source string) {
			defer wg.Done()
			var output bytes.Buffer
			runner := &Runner{Out: &output, Err: &output, In: strings.NewReader("")}
			codes[i] = runner.Run(context.Background(), []string{"skills", "add", source})
			outputs[i] = output.String()
		}(i, source)
	}
	wg.Wait()
	for i := range sources {
		if codes[i] != 0 {
			t.Fatalf("concurrent add %d exit=%d output=%q", i, codes[i], outputs[i])
		}
	}
	if entries := registryByName(t); len(entries) != 3 || entries["gamma"].Name == "" {
		t.Fatalf("registry=%+v", entries)
	}
}
