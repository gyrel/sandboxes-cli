//go:build darwin || linux

package command

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSkillSourceFIFORejectedWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe"), 0o600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	done := make(chan error, 1)
	go func() {
		var state skillWalkState
		var entries []skillTreeEntry
		done <- walkSkillDirectory(root, "pipe", nil, 0, &state, &entries)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as a directory")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("opening FIFO blocked")
	}
}

func TestSkillHashRejectsReplacedFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	entries, err := collectSkillEntries(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("collect: %v, entries=%d", err, len(entries))
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- hashSkillFile(root, entries[0], io.Discard) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("replacement FIFO was accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hash blocked on FIFO")
	}
}
