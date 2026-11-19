//go:build !windows

package command

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHostSkillsImportPriority(t *testing.T) {
	home := setSkillsTestHome(t)
	first := filepath.Join(home, ".agents", "skills")
	second := filepath.Join(home, ".claude", "skills")
	writeTestSkill(t, first, "alpha", "First copy", map[string]string{"data": "first"})
	writeTestSkill(t, second, "alpha", "Second copy", map[string]string{"data": "second"})
	writeTestSkill(t, second, "beta", "Other skill", nil)
	if code, output := runSkillsTest(t, "import"); code != 0 {
		t.Fatalf("import exit %d: %s", code, output)
	}
	data, err := os.ReadFile(filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha", "data"))
	if err != nil || string(data) != "first" {
		t.Fatalf("wrong priority: %q, %v", data, err)
	}
	if len(readTestRegistry(t).Skills) != 2 {
		t.Fatal("expected both unique skills")
	}
}

func TestHostSkillsImportRejectsExternalLink(t *testing.T) {
	home := setSkillsTestHome(t)
	source := filepath.Join(home, ".agents", "skills")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	target := writeTestSkill(t, t.TempDir(), "alpha", "External skill", nil)
	if err := os.Symlink(target, filepath.Join(source, "alpha")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	code, output := runSkillsTest(t, "import", "--force")
	if code == 0 || !strings.Contains(output, "requires explicit target review") {
		t.Fatalf("unexpected exit %d: %s", code, output)
	}
	if _, err := os.Stat(filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha")); !os.IsNotExist(err) {
		t.Fatalf("external content was imported: %v", err)
	}
}

func TestHostSkillsImportApprovesExactExternalLink(t *testing.T) {
	home := setSkillsTestHome(t)
	source := filepath.Join(home, ".agents", "skills")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	target := writeTestSkill(t, t.TempDir(), "alpha", "External skill", map[string]string{"fixture": "synthetic"})
	canonical, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(source, "alpha")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if code, _ := runSkillsTest(t, "import", "--force", "--allow-link", "alpha="+filepath.Dir(canonical)); code == 0 {
		t.Fatal("incorrect target approval was accepted")
	}
	if code, output := runSkillsTest(t, "import", "--allow-link", "alpha="+canonical); code != 0 {
		t.Fatalf("approved import failed: %s", output)
	}
	data, err := os.ReadFile(filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha", "fixture"))
	if err != nil || string(data) != "synthetic" {
		t.Fatalf("wrong imported content: %q, %v", data, err)
	}
}

func TestSkillLinkReviewRejectsReplacement(t *testing.T) {
	dir := t.TempDir()
	linkPath := filepath.Join(dir, "alpha")
	if err := os.Symlink("first", linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	before, err := root.Lstat("alpha")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(linkPath, filepath.Join(dir, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("first", linkPath); err != nil {
		t.Fatal(err)
	}
	if err := verifyApprovedSkillLink(root, dir, "alpha", "first", before); err == nil {
		t.Fatal("replaced link was accepted")
	}
}

func TestHostSkillsImportRejectsSourceDirectoryEscape(t *testing.T) {
	home := setSkillsTestHome(t)
	external := t.TempDir()
	writeTestSkill(t, external, "alpha", "External skill", nil)
	if err := os.MkdirAll(filepath.Join(home, ".agents"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(home, ".agents", "skills")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	code, _ := runSkillsTest(t, "import", "--force")
	if code == 0 {
		t.Fatal("expected source directory escape to be rejected")
	}
	if _, err := os.Stat(filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha")); !os.IsNotExist(err) {
		t.Fatalf("external content was imported: %v", err)
	}
}

func TestHostSkillsImportRejectsSourceSymlinkInsideHome(t *testing.T) {
	home := setSkillsTestHome(t)
	external := filepath.Join(home, "other")
	writeTestSkill(t, external, "alpha", "Other skill", nil)
	if err := os.MkdirAll(filepath.Join(home, ".agents"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(home, ".agents", "skills")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if code, _ := runSkillsTest(t, "import"); code == 0 {
		t.Fatal("source directory symlink was accepted")
	}
	if code, _ := runSkillsTest(t, "import", "--dry-run"); code == 0 {
		t.Fatal("preview followed source directory symlink")
	}
}

func TestSkillCopyRejectsReplacedFile(t *testing.T) {
	parent := t.TempDir()
	path := writeTestSkill(t, parent, "alpha", "Skill", map[string]string{"data": "first"})
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	entries, err := collectSkillEntries(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(path, "data"), filepath.Join(parent, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "data"), []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	stage, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stage.Close() }()
	if err := copySkillTree(root, entries, stage); err == nil {
		t.Fatal("replacement file was accepted")
	}
}

func TestSkillCopyRejectsChangedFileWithSameSize(t *testing.T) {
	dir := t.TempDir()
	path := writeTestSkill(t, dir, "alpha", "Skill", map[string]string{"data": "first"})
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	entries, err := collectSkillEntries(root)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, "data")
	if err := os.WriteFile(file, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(file, changed, changed); err != nil {
		t.Fatal(err)
	}
	stage, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stage.Close() }()
	if err := copySkillTree(root, entries, stage); err == nil {
		t.Fatal("modified source file was accepted")
	}
}

func TestSkillCopyVerificationRejectsChangedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("first"))
	if err := os.WriteFile(path, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifySkillSourceCopy(file, info, digest[:], 5); err == nil {
		t.Fatal("changed source content was accepted")
	}
}

func TestSkillWalkRejectsReplacedDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(dir, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	var state skillWalkState
	var entries []skillTreeEntry
	if err := walkSkillDirectory(root, "nested", info, 0, &state, &entries); err == nil {
		t.Fatal("replacement directory was accepted")
	}
}

func TestHostSkillsImportRejectsHardlink(t *testing.T) {
	home := setSkillsTestHome(t)
	skill := writeTestSkill(t, filepath.Join(home, ".agents", "skills"), "alpha", "Skill", nil)
	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(external, filepath.Join(skill, "linked")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if code, _ := runSkillsTest(t, "import", "--force"); code == 0 {
		t.Fatal("hard link was imported")
	}
	if _, err := os.Stat(filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha")); !os.IsNotExist(err) {
		t.Fatalf("hard-linked content was imported: %v", err)
	}
}
