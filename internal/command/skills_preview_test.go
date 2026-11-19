package command

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostSkillsPreview(t *testing.T) {
	home := t.TempDir()
	for _, dir := range []string{".agents/skills/alpha", ".claude/skills/alpha", ".claude/skills/beta", ".agents/skills/.hidden"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := writeHostSkillsPreview(context.Background(), &out, home); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Count(got, `Candidate "alpha"`) != 1 || !strings.Contains(got, `Candidate "alpha" from .agents/skills`) || !strings.Contains(got, `Candidate "beta"`) || strings.Contains(got, ".hidden") {
		t.Fatalf("unexpected preview: %s", got)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "rheic")); !os.IsNotExist(err) {
		t.Fatalf("preview created a store: %v", err)
	}
}

func TestHostSkillsPreviewReportsLinksWithoutReadingTargets(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, ".agents", "skills")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "missing-target"), filepath.Join(source, "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	var out bytes.Buffer
	if err := writeHostSkillsPreview(context.Background(), &out, home); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `Link "linked"`) || !strings.Contains(out.String(), "requires explicit review") {
		t.Fatalf("link was not reported: %s", out.String())
	}
}

func TestHostSkillsPreviewHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := writeHostSkillsPreview(ctx, &out, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("canceled preview produced output: %s", out.String())
	}
}

func TestHostSkillsPreviewBoundsEntries(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"one", "two"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if _, err := readRootSkillEntries(root, 1); err == nil {
		t.Fatal("expected an error when source entries exceed the limit")
	}
	if entries, err := readRootSkillEntries(root, 2); err != nil || len(entries) != 2 {
		t.Fatalf("expected two entries at the limit, got %d, %v", len(entries), err)
	}
}
