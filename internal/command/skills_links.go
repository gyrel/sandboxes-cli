package command

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Each approval names one skill and one canonical, absolute target directory.
func parseApprovedSkillLinks(values []string) (map[string]string, error) {
	approved := make(map[string]string, len(values))
	for _, value := range values {
		name, target, ok := strings.Cut(value, "=")
		if !ok || validateSkillName(name) != nil || !filepath.IsAbs(target) || filepath.Clean(target) != target {
			return nil, errors.New("skills import: --allow-link requires NAME=clean-absolute-target")
		}
		if _, exists := approved[name]; exists {
			return nil, errors.New("skills import: duplicate link approval")
		}
		approved[name] = target
	}
	return approved, nil
}

func (r *Runner) importApprovedSkillLink(ctx context.Context, sourceRoot *os.Root, home, source, name, target string, force bool) int {
	root, err := openApprovedSkillLink(sourceRoot, filepath.Join(home, filepath.FromSlash(source)), name, target)
	if err != nil {
		r.error(err)
		return 1
	}
	skill, err := finishSourceSkill(root, target, name)
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = skill.root.Close() }()
	return r.installSourceSkill(ctx, skill, force)
}

func openApprovedSkillLink(sourceRoot *os.Root, sourcePath, name, target string) (*os.Root, error) {
	before, err := sourceRoot.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink == 0 {
		return nil, errors.New("skills import: approved link changed")
	}
	link, err := sourceRoot.Readlink(name)
	if err != nil {
		return nil, errors.New("skills import: cannot read approved link")
	}
	candidate := link
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(sourcePath, candidate)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil || resolved != target {
		return nil, errors.New("skills import: link target does not match approved target")
	}
	expected, err := os.Stat(candidate)
	if err != nil || !expected.IsDir() {
		return nil, errors.New("skills import: approved link target is unavailable")
	}
	root, err := openApprovedTarget(target)
	if err != nil {
		return nil, err
	}
	opened, openErr := root.Stat(".")
	current, pathErr := os.Stat(candidate)
	if openErr != nil || pathErr != nil || !os.SameFile(expected, opened) || !os.SameFile(expected, current) {
		_ = root.Close()
		return nil, errors.New("skills import: approved target changed while opening")
	}
	if err := verifyApprovedSkillLink(sourceRoot, sourcePath, name, link, before); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

func openApprovedTarget(target string) (*os.Root, error) {
	volume := filepath.VolumeName(target)
	filesystem, err := os.OpenRoot(volume + string(filepath.Separator))
	if err != nil {
		return nil, errors.New("skills import: cannot open approved target root")
	}
	defer func() { _ = filesystem.Close() }()
	rel := strings.TrimPrefix(strings.TrimPrefix(target, volume), string(filepath.Separator))
	if rel == "" {
		return nil, errors.New("skills import: filesystem root cannot be approved")
	}
	root, err := openHostSkillSource(filesystem, filepath.ToSlash(rel))
	if err != nil {
		return nil, errors.New("skills import: approved target path changed or contains a link")
	}
	return root, nil
}

func verifyApprovedSkillLink(sourceRoot *os.Root, sourcePath, name, link string, before os.FileInfo) error {
	after, err := sourceRoot.Lstat(name)
	if err != nil || !os.SameFile(before, after) {
		return errors.New("skills import: approved link changed")
	}
	current, err := sourceRoot.Readlink(name)
	if err != nil || current != link {
		return errors.New("skills import: approved link changed")
	}
	rootInfo, rootErr := sourceRoot.Stat(".")
	pathInfo, pathErr := os.Stat(sourcePath)
	if rootErr != nil || pathErr != nil || !os.SameFile(rootInfo, pathInfo) {
		return fmt.Errorf("skills import: source directory changed while resolving %q", name)
	}
	return nil
}
