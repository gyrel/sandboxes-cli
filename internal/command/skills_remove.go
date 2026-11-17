package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const skillsRemoveUsage = `usage: rsbx skills rm [--force] NAME

Remove one skill that Rheic imported. Directories in the skills store that are
not recorded in Rheic's registry are never removed. Without --force, an
interactive terminal confirmation is required.
`

func (r *Runner) removeSkills(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("skills rm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	force := fs.Bool("force", false, "skip confirmation")
	fs.BoolVar(force, "f", false, "skip confirmation")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{forceFlag: false, "-f": false})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return r.showCommandHelp(skillsRemoveHelp())
		}
		return r.flagParseFailure("skills rm", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, skillsRemoveUsage)
		return 2
	}
	name := fs.Arg(0)
	if err := validateSkillName(name); err != nil {
		r.error(err)
		return 1
	}
	if err := ctx.Err(); err != nil {
		r.error(err)
		return 1
	}
	return r.removeManagedSkill(ctx, name, *force)
}

func (r *Runner) removeManagedSkill(ctx context.Context, name string, force bool) int {
	paths, err := resolveSkillsPaths()
	if err != nil {
		r.error(err)
		return 1
	}
	root, err := openSkillsRoot(paths, false)
	if errors.Is(err, errSkillsRootMissing) {
		_, _ = fmt.Fprintf(r.Err, "skills rm: skill %q is not managed by Rheic\n", sanitizeSkillErrorText(name))
		return 1
	}
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = root.Close() }()
	registry, err := readSkillsRegistry(root)
	if err != nil {
		r.error(err)
		return 1
	}
	if _, managed := registryEntry(registry, name); !managed {
		_, _ = fmt.Fprintf(r.Err, "skills rm: skill %q is not managed by Rheic; refusing to remove it\n", sanitizeSkillErrorText(name))
		return 1
	}
	store, err := openSkillsStore(root)
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = store.Close() }()
	if err := verifyManagedSkill(store, name); err != nil {
		r.error(err)
		return 1
	}
	confirmed, code := r.confirmSecretRemoval("skill "+sanitizeSkillErrorText(name), force)
	if !confirmed {
		return code
	}
	if err := stageAndRemoveSkill(ctx, root, store, registry, name); err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Removed skill %q\n", sanitizeSkillErrorText(name))
	return 0
}

func verifyManagedSkill(store *os.Root, name string) error {
	info, err := store.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("skills rm: skill %q is not installed", name)
	}
	if err != nil {
		return errors.New("skills rm: cannot inspect skill")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("skills rm: skill %q is not a real directory", name)
	}
	return nil
}

func stageAndRemoveSkill(ctx context.Context, root *os.Root, store *os.Root, registry skillsRegistry, name string) error {
	stageName, err := randomSkillHiddenName(".remove-")
	if err != nil {
		return err
	}
	if err := store.Mkdir(stageName, 0o700); err != nil {
		return errors.New("skills rm: cannot create removal staging directory")
	}
	if err := store.Rename(name, stageName+"/"+name); err != nil {
		_ = store.Remove(stageName)
		return errors.New("skills rm: cannot stage skill for removal")
	}
	if err := ctx.Err(); err != nil {
		return restoreRemovalStage(store, stageName, name, err)
	}
	if err := writeSkillsRegistry(root, registryWithoutEntry(registry, name)); err != nil {
		return restoreRemovalStage(store, stageName, name, fmt.Errorf("skills rm: registry update failed: %w", err))
	}
	if err := store.RemoveAll(stageName); err != nil {
		return fmt.Errorf("skills rm: skill was unregistered but staging cleanup failed; inspect %q", stageName)
	}
	return nil
}

func restoreRemovalStage(store *os.Root, stageName, name string, cause error) error {
	if err := store.Rename(stageName+"/"+name, name); err != nil {
		return fmt.Errorf("skills rm: removal canceled and recovery failed; inspect %q: %w", stageName, cause)
	}
	_ = store.Remove(stageName)
	return cause
}
