//go:build !windows

package command

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSkillRepositoryTable(t *testing.T) {
	setSkillsTestHome(t)
	local := t.TempDir()
	for _, test := range []struct {
		name     string
		input    string
		location string
		wantErr  bool
	}{
		{name: "shorthand", input: "anthropics/skills", location: "https://github.com/anthropics/skills"},
		{name: "https url", input: "https://github.com/anthropics/skills", location: "https://github.com/anthropics/skills"},
		{name: "local directory", input: local, location: local},
		{name: "file url", input: "file://" + local, location: local},
		{name: "userinfo", input: "https://user:secret@example.invalid/acme/skills.git", wantErr: true},
		{name: "query token", input: "https://example.invalid/acme/skills?token=abc", wantErr: true},
		{name: "fragment", input: "https://example.invalid/acme/skills#abc", wantErr: true},
		{name: "plain http", input: "http://example.invalid/acme/skills", wantErr: true},
		{name: "ssh", input: "ssh://example.invalid/acme/skills", wantErr: true},
		{name: "ext helper", input: "ext::sh -c id", wantErr: true},
		{name: "option-like", input: "--upload-pack=id", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "missing absolute", input: filepath.Join(local, "missing"), wantErr: true},
		{name: "https without host", input: "https:///acme", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo, err := parseSkillRepository(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parse %q accepted: %+v", test.input, repo)
				}
				if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "abc") {
					t.Fatalf("error echoed input: %v", err)
				}
				return
			}
			if err != nil || repo.Location != test.location {
				t.Fatalf("parse %q = %+v, %v; want location %q", test.input, repo, err, test.location)
			}
			if err := validateRepositoryLocation(repo.Location); err != nil {
				t.Fatalf("parsed location fails registry validation: %v", err)
			}
		})
	}
}

func TestValidateRepositoryLocationRejectsCredentials(t *testing.T) {
	for _, location := range []string{"https://user:pw@example.invalid/x", "http://example.invalid/x", "relative/path", "https:///x"} {
		if err := validateRepositoryLocation(location); err == nil {
			t.Fatalf("location %q accepted", location)
		}
	}
}

func TestParseSkillNamesFlattens(t *testing.T) {
	names, err := parseSkillNames([]string{"alpha,beta", "alpha", " gamma "})
	if err != nil || strings.Join(names, " ") != "alpha beta gamma" {
		t.Fatalf("names=%v err=%v", names, err)
	}
	for _, values := range [][]string{{"a,,b"}, {"../x"}, {""}} {
		if _, err := parseSkillNames(values); err == nil {
			t.Fatalf("names %q accepted", values)
		}
	}
}

func TestRedactRepositoryTextRemovesHostPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	scratch := filepath.Join(t.TempDir(), "rsbx-skills-1")
	repo := skillRepository{Location: filepath.Join(t.TempDir(), "acme"), Display: "acme"}
	text := "fatal: '" + repo.Location + "' at " + scratch + "/checkout and " + home + "/x"
	got := redactRepositoryText(text, repo, scratch)
	for _, leaked := range []string{repo.Location, scratch, home} {
		if strings.Contains(got, leaked) {
			t.Fatalf("redaction leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "<checkout>") || !strings.Contains(got, "~/x") {
		t.Fatalf("redaction missing placeholders: %q", got)
	}
}

func TestDiscoverRepositorySkillsRules(t *testing.T) {
	ctx := context.Background()
	t.Run("nested and hidden", func(t *testing.T) {
		checkout := t.TempDir()
		writeTestSkill(t, filepath.Join(checkout, "group"), "alpha", "Alpha", nil)
		writeTestSkill(t, filepath.Join(checkout, ".hidden"), "beta", "Beta", nil)
		writeTestSkill(t, filepath.Join(checkout, "group", "alpha", "nested"), "inner", "Inner", nil)
		found, err := discoverRepositorySkills(ctx, checkout)
		if err != nil || len(found) != 1 || found[0].Name != "alpha" {
			t.Fatalf("found=%+v err=%v", found, err)
		}
	})
	t.Run("duplicate names", func(t *testing.T) {
		checkout := t.TempDir()
		writeTestSkill(t, filepath.Join(checkout, "one"), "alpha", "Alpha", nil)
		writeTestSkill(t, filepath.Join(checkout, "two"), "alpha", "Alpha", nil)
		if _, err := discoverRepositorySkills(ctx, checkout); err == nil || !strings.Contains(err.Error(), "more than once") {
			t.Fatalf("duplicate err=%v", err)
		}
	})
	t.Run("symlink named like a skill", func(t *testing.T) {
		checkout := t.TempDir()
		writeTestSkill(t, checkout, "alpha", "Alpha", nil)
		if err := os.Symlink("alpha", filepath.Join(checkout, "beta")); err != nil {
			t.Fatal(err)
		}
		if _, err := discoverRepositorySkills(ctx, checkout); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("symlink err=%v", err)
		}
	})
	t.Run("no skills", func(t *testing.T) {
		checkout := t.TempDir()
		if err := os.WriteFile(filepath.Join(checkout, "README.md"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := discoverRepositorySkills(ctx, checkout); err == nil {
			t.Fatal("empty repository accepted")
		}
	})
	t.Run("canceled", func(t *testing.T) {
		checkout := t.TempDir()
		writeTestSkill(t, checkout, "alpha", "Alpha", nil)
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := discoverRepositorySkills(canceled, checkout); err == nil {
			t.Fatal("canceled scan succeeded")
		}
	})
}

func TestSelectRepositorySkillsKeepsRequestedOrder(t *testing.T) {
	found := []repositorySkill{{Name: "alpha", Path: "/a"}, {Name: "beta", Path: "/b"}}
	selected, err := selectRepositorySkills(found, []string{"beta"})
	if err != nil || len(selected) != 1 || selected[0].Name != "beta" {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
	all, err := selectRepositorySkills(found, nil)
	if err != nil || len(all) != 2 {
		t.Fatalf("all=%+v err=%v", all, err)
	}
	if _, err := selectRepositorySkills(found, []string{"gamma"}); err == nil {
		t.Fatal("unknown skill selected")
	}
}

func TestValidateSkillsRegistryRepositoryRecords(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	commit := strings.Repeat("b", 40)
	const repo = "https://github.com/acme/skills"
	repository := skillsRegistryEntry{
		Name: "alpha", Source: repo, Digest: digest, ImportedAt: "2026-11-23T00:00:00Z",
		Repository: repo, Branch: "main", Commit: commit,
	}
	credentialed := repository
	credentialed.Repository, credentialed.Source = "https://u:p@github.com/acme/skills", "https://u:p@github.com/acme/skills"
	mismatched := repository
	mismatched.Source = "/elsewhere"
	badCommit := repository
	badCommit.Commit = "not-a-commit"
	noBranch := repository
	noBranch.Branch = ""
	localWithProvenance := skillsRegistryEntry{Name: "beta", Source: "/tmp/beta", Digest: digest, ImportedAt: "2026-11-23T00:00:00Z", Commit: commit}
	for _, test := range []struct {
		name    string
		entry   skillsRegistryEntry
		wantErr bool
	}{
		{name: "valid repository", entry: repository},
		{name: "credentials in repository", entry: credentialed, wantErr: true},
		{name: "source mismatch", entry: mismatched, wantErr: true},
		{name: "bad commit", entry: badCommit, wantErr: true},
		{name: "missing branch", entry: noBranch, wantErr: true},
		{name: "local with provenance", entry: localWithProvenance, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateSkillsRegistry(skillsRegistry{Version: skillsRegistryVer, Skills: []skillsRegistryEntry{test.entry}})
			if (err != nil) != test.wantErr {
				t.Fatalf("validate=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
}
