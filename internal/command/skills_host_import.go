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

var hostSkillSources = []string{
	".agents/skills", ".claude/skills", ".config/opencode/skills",
	".copilot/skills", ".cursor/skills", ".factory/skills",
}

// importHostSkills confines discovery to HOME. Explicit skill-directory links
// are rejected instead of silently copying an unapproved external target.
func (r *Runner) importHostSkills(ctx context.Context, force bool, allowedLinks []string) int {
	approved, err := parseApprovedSkillLinks(allowedLinks)
	if err != nil {
		r.error(err)
		return 1
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		r.error(errors.New("skills import: home directory is unavailable"))
		return 1
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		r.error(errors.New("skills import: cannot open home directory"))
		return 1
	}
	defer func() { _ = root.Close() }()
	seen := make(map[string]bool)
	total := 0
	for _, source := range hostSkillSources {
		if err := ctx.Err(); err != nil {
			r.error(err)
			return 1
		}
		sourceRoot, err := openHostSkillSource(root, source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			r.error(err)
			return 1
		}
		entries, err := readRootSkillEntries(sourceRoot, 10000-total)
		if err != nil {
			_ = sourceRoot.Close()
			r.error(err)
			return 1
		}
		total += len(entries)
		code := r.importHostEntries(ctx, sourceRoot, home, source, entries, seen, force, approved)
		_ = sourceRoot.Close()
		if code != 0 {
			return 1
		}
	}
	return 0
}

// openHostSkillSource anchors each component before inspecting the next one.
// A symlink is never accepted as a substitute for a configured source path.
func openHostSkillSource(home *os.Root, source string) (*os.Root, error) {
	current := home
	for _, part := range strings.Split(source, "/") {
		info, err := current.Lstat(part)
		if err != nil {
			if current != home {
				_ = current.Close()
			}
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			if current != home {
				_ = current.Close()
			}
			return nil, errors.New("skills import: source path must contain only real directories")
		}
		next, err := current.OpenRoot(part)
		if current != home {
			_ = current.Close()
		}
		if err != nil {
			return nil, errors.New("skills import: cannot safely open source path")
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) {
			_ = next.Close()
			return nil, errors.New("skills import: source path changed while opening")
		}
		current = next
	}
	return current, nil
}

func readRootSkillEntries(root *os.Root, remaining int) ([]os.DirEntry, error) {
	dir, err := openCopySource(root, ".")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("skills import: cannot safely open source directory")
	}
	info, err := dir.Stat()
	if err != nil || !info.IsDir() {
		_ = dir.Close()
		return nil, errors.New("skills import: source must be a directory")
	}
	entries, readErr := dir.ReadDir(remaining + 1)
	closeErr := dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, errors.New("skills import: cannot read source directory")
	}
	if closeErr != nil || len(entries) > remaining {
		return nil, errors.New("skills import: source directory exceeds limit or cannot be closed")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func (r *Runner) importHostSkill(ctx context.Context, sourceRoot *os.Root, home, source, name string, force bool) int {
	rel := filepath.Join(filepath.FromSlash(source), name)
	info, err := sourceRoot.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		r.error(errors.New("skills import: source changed or is not a real directory"))
		return 1
	}
	root, err := sourceRoot.OpenRoot(name)
	if err != nil {
		r.error(errors.New("skills import: cannot safely open skill directory"))
		return 1
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		r.error(errors.New("skills import: source changed while opening"))
		return 1
	}
	skill, err := finishSourceSkill(root, filepath.Join(home, rel), name)
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = skill.root.Close() }()
	return r.installSourceSkill(ctx, skill, force)
}

func (r *Runner) importHostEntries(ctx context.Context, root *os.Root, home, source string, entries []os.DirEntry, seen map[string]bool, force bool, approved map[string]string) int {
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || seen[name] {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, ok := approved[name]
			if !ok {
				r.error(fmt.Errorf("skills import: link %q requires explicit target review", name))
				return 1
			}
			seen[name] = true
			if r.importApprovedSkillLink(ctx, root, home, source, name, target, force) != 0 {
				return 1
			}
			continue
		}
		if !entry.IsDir() {
			continue
		}
		seen[name] = true
		if r.importHostSkill(ctx, root, home, source, name, force) != 0 {
			return 1
		}
	}
	return 0
}
