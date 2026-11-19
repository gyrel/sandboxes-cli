package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	dryRunName = "dry-run"
	dryRunFlag = "--" + dryRunName
)

// previewHostSkills discovers candidates only; it does not read or copy skill files.
func (r *Runner) previewHostSkills(ctx context.Context) int {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		r.error(errors.New("skills import: home directory is unavailable"))
		return 1
	}
	if err := writeHostSkillsPreview(ctx, r.Out, home); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func writeHostSkillsPreview(ctx context.Context, out io.Writer, home string) error {
	root, err := os.OpenRoot(home)
	if err != nil {
		return errors.New("skills import: cannot open home directory")
	}
	defer func() { _ = root.Close() }()
	seen := make(map[string]bool)
	total := 0
	for _, source := range hostSkillSources {
		if err := ctx.Err(); err != nil {
			return err
		}
		sourceRoot, err := openHostSkillSource(root, source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		entries, err := readRootSkillEntries(sourceRoot, 10000-total)
		_ = sourceRoot.Close()
		if err != nil {
			return err
		}
		total += len(entries)
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		if err := printSkillCandidates(out, source, entries, seen); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(out, "Preview only: candidates have not been validated.")
	return err
}

func printSkillCandidates(out io.Writer, source string, entries []os.DirEntry, seen map[string]bool) error {
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || seen[name] {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if _, err := fmt.Fprintf(out, "Link %q from %s requires explicit review before import\n", name, source); err != nil {
				return err
			}
			continue
		}
		if !entry.IsDir() {
			continue
		}
		seen[name] = true
		if _, err := fmt.Fprintf(out, "Candidate %q from %s\n", name, source); err != nil {
			return err
		}
	}
	return nil
}
