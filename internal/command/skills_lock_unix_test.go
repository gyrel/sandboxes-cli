//go:build darwin || linux

package command

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestSkillsLockProcessHelper(t *testing.T) {
	if os.Getenv("RHEIC_SKILLS_LOCK_HELPER") != "hold" {
		return
	}
	root, err := os.OpenRoot(os.Getenv("RHEIC_SKILLS_LOCK_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	lock, err := acquireSkillsLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	_, _ = fmt.Fprintln(os.Stdout, "locked")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestSkillsLockBlocksAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSkillsLockProcessHelper$") // #nosec G204 -- same test executable, fixed test filter.
	cmd.Env = append(os.Environ(), "RHEIC_SKILLS_LOCK_HELPER=hold", "RHEIC_SKILLS_LOCK_ROOT="+dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("child did not lock: %q, %v, %s", line, err, stderr.String())
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	blocked, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	if lock, err := acquireSkillsLock(blocked, root); !errors.Is(err, context.DeadlineExceeded) {
		if lock != nil {
			_ = lock.Close()
		}
		t.Fatalf("expected blocked lock, got %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper failed: %v: %s", err, stderr.String())
	}
	lock, err := acquireSkillsLock(context.Background(), root)
	if err != nil {
		t.Fatalf("released lock not available: %v", err)
	}
	_ = lock.Close()
}

func TestSkillsImportProcessHelper(t *testing.T) {
	source := os.Getenv("RHEIC_SKILLS_IMPORT_SOURCE")
	if source == "" {
		return
	}
	code, output := runSkillsTest(t, "import", source)
	if code != 0 {
		t.Fatalf("import failed (%d): %s", code, output)
	}
}

func TestSkillsConcurrentImportsPreserveRegistry(t *testing.T) {
	home := setSkillsTestHome(t)
	fixtures := t.TempDir()
	alpha := writeTestSkill(t, fixtures, "alpha", "First skill", nil)
	beta := writeTestSkill(t, fixtures, "beta", "Second skill", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	commands := make([]*exec.Cmd, 0, 2)
	for _, source := range []string{alpha, beta} {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSkillsImportProcessHelper$") // #nosec G204 -- same test executable, fixed test filter.
		cmd.Env = append(os.Environ(), "RHEIC_SKILLS_IMPORT_SOURCE="+source)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, cmd)
	}
	for _, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	registry := readTestRegistry(t)
	if len(registry.Skills) != 2 {
		t.Fatalf("expected two registered skills, got %+v", registry.Skills)
	}
	for _, name := range []string{"alpha", "beta"} {
		if _, ok := registryEntry(registry, name); !ok {
			t.Fatalf("skill %q not registered", name)
		}
		if _, err := os.Stat(filepath.Join(skillsTestConfig(home), skillsDirectoryName, name, "SKILL.md")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSkillsMutationsFailClosedWhenLockBusy(t *testing.T) {
	home := setSkillsTestHome(t)
	fixtures := t.TempDir()
	alpha := writeTestSkill(t, fixtures, "alpha", "Existing skill", nil)
	beta := writeTestSkill(t, fixtures, "beta", "New skill", nil)
	if code, output := importTestSkill(t, alpha); code != 0 {
		t.Fatalf("setup import failed (%d): %s", code, output)
	}
	root, err := os.OpenRoot(skillsTestConfig(home))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	lock, err := acquireSkillsLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	for _, args := range [][]string{{"import", beta}, {"rm", "--force", "alpha"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		code := runner.Run(ctx, append([]string{"skills"}, args...))
		cancel()
		if code == 0 {
			t.Fatalf("busy mutation %v succeeded: %s", args, out.String())
		}
	}
	registry := readTestRegistry(t)
	if len(registry.Skills) != 1 || registry.Skills[0].Name != "alpha" {
		t.Fatalf("registry changed while locked: %+v", registry.Skills)
	}
	if _, err := os.Stat(filepath.Join(skillsTestConfig(home), skillsDirectoryName, "alpha", "SKILL.md")); err != nil {
		t.Fatalf("existing skill changed while locked: %v", err)
	}
	if _, err := os.Stat(filepath.Join(skillsTestConfig(home), skillsDirectoryName, "beta")); !os.IsNotExist(err) {
		t.Fatalf("new skill appeared while locked: %v", err)
	}
}

func TestSkillsLockReleasedWhenProcessDies(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSkillsLockProcessHelper$") // #nosec G204 -- same test executable, fixed test filter.
	cmd.Env = append(os.Environ(), "RHEIC_SKILLS_LOCK_HELPER=hold", "RHEIC_SKILLS_LOCK_ROOT="+dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("child did not lock: %q, %v", line, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("expected killed process to report failure")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	lock, err := acquireSkillsLock(ctx, root)
	if err != nil {
		t.Fatalf("lock was not released after process death: %v", err)
	}
	_ = lock.Close()
}
