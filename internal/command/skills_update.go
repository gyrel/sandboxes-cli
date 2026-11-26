package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
)

type repositoryUpdateGroup struct {
	repo    skillRepository
	entries []skillsRegistryEntry
}

func (r *Runner) updateSkills(ctx context.Context, args []string) int {
	fs := r.newFlagSet("skills update")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(reorderFlagArgs(args, nil)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return r.showCommandHelp(skillsUpdateHelp())
		}
		return r.flagParseFailure("skills update", err)
	}
	groups, err := planRepositoryUpdates(fs.Args())
	if err != nil {
		r.error(err)
		return 1
	}
	if len(groups) == 0 {
		_, _ = fmt.Fprintln(r.Out, "No skills added from a repository are installed")
		return 0
	}
	failed := false
	for _, group := range groups {
		if err := ctx.Err(); err != nil {
			r.error(err)
			return 1
		}
		if r.updateRepositoryGroup(ctx, group) {
			failed = true
		}
	}
	if failed {
		return 1
	}
	return 0
}

func planRepositoryUpdates(names []string) ([]repositoryUpdateGroup, error) {
	registry, err := readOptionalSkillsRegistry()
	if err != nil {
		return nil, err
	}
	entries, err := selectUpdateEntries(registry, names)
	if err != nil {
		return nil, err
	}
	return groupRepositoryEntries(entries)
}

func readOptionalSkillsRegistry() (skillsRegistry, error) {
	paths, err := resolveSkillsPaths()
	if err != nil {
		return skillsRegistry{}, err
	}
	root, err := openSkillsRoot(paths, false)
	if errors.Is(err, errSkillsRootMissing) {
		return skillsRegistry{Version: skillsRegistryVer, Skills: []skillsRegistryEntry{}}, nil
	}
	if err != nil {
		return skillsRegistry{}, err
	}
	defer func() { _ = root.Close() }()
	return readSkillsRegistry(root)
}

// selectUpdateEntries accepts only skills recorded with a repository. With no
// names, every such skill is selected; a named skill that is missing or was
// imported locally stops the command before any network access.
func selectUpdateEntries(registry skillsRegistry, names []string) ([]skillsRegistryEntry, error) {
	if len(names) == 0 {
		entries := make([]skillsRegistryEntry, 0, len(registry.Skills))
		for _, entry := range registry.Skills {
			if entry.Repository != "" {
				entries = append(entries, entry)
			}
		}
		return entries, nil
	}
	entries := make([]skillsRegistryEntry, 0, len(names))
	for _, name := range names {
		if err := validateSkillName(name); err != nil {
			return nil, err
		}
		entry, managed := registryEntry(registry, name)
		if !managed {
			return nil, fmt.Errorf("skills update: skill %q is not managed by Gyrel", name)
		}
		if entry.Repository == "" {
			return nil, fmt.Errorf("skills update: skill %q was not added from a repository; skills installed with 'rsbx skills import' must be added from a repository before they can be updated", name)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// groupRepositoryEntries keeps one clone per repository, so skills from the
// same repository are refreshed from a single fetch.
func groupRepositoryEntries(entries []skillsRegistryEntry) ([]repositoryUpdateGroup, error) {
	groups := make([]repositoryUpdateGroup, 0)
	index := make(map[string]int)
	for _, entry := range entries {
		position, ok := index[entry.Repository]
		if !ok {
			repo, err := repositoryFromRecord(entry.Repository)
			if err != nil {
				return nil, err
			}
			position = len(groups)
			index[entry.Repository] = position
			groups = append(groups, repositoryUpdateGroup{repo: repo})
		}
		groups[position].entries = append(groups[position].entries, entry)
	}
	return groups, nil
}

// updateRepositoryGroup reports whether any skill in the group failed.
func (r *Runner) updateRepositoryGroup(ctx context.Context, group repositoryUpdateGroup) bool {
	checkout, err := cloneSkillRepository(ctx, group.repo)
	if err != nil {
		r.error(err)
		return true
	}
	defer checkout.Close()
	found, err := discoverRepositorySkills(ctx, checkout.Path)
	if err != nil {
		r.error(err)
		return true
	}
	paths := make(map[string]string, len(found))
	for _, skill := range found {
		paths[skill.Name] = skill.Path
	}
	failed := false
	for _, entry := range group.entries {
		if err := r.updateRepositorySkill(ctx, group.repo, checkout, paths, entry); err != nil {
			r.error(err)
			failed = true
		}
	}
	return failed
}

func (r *Runner) updateRepositorySkill(ctx context.Context, repo skillRepository, checkout *repositoryCheckout, paths map[string]string, entry skillsRegistryEntry) error {
	path, ok := paths[entry.Name]
	if !ok {
		return fmt.Errorf("skills update: skill %q is no longer in the repository", entry.Name)
	}
	source, err := loadSourceSkill(path)
	if err != nil {
		return err
	}
	defer func() { _ = source.root.Close() }()
	decision, err := commitSourceSkill(ctx, source, true, repositoryRegistryEntry(repo, checkout), entry.Digest)
	if err != nil {
		return err
	}
	if decision == skillImportNoop {
		_, _ = fmt.Fprintf(r.Out, "Skill %q is already up to date\n", sanitizeSkillErrorText(entry.Name))
		return nil
	}
	_, _ = fmt.Fprintf(r.Out, "Updated skill %q from %s\n", sanitizeSkillErrorText(entry.Name), sanitizeSkillErrorText(repo.Display))
	return nil
}
