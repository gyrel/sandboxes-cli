package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
)

const skillsAddUsage = "usage: rsbx skills add [--force] [--skill NAME]... REPOSITORY\n"

func (r *Runner) addSkills(ctx context.Context, args []string) int {
	fs := r.newFlagSet("skills add")
	fs.SetOutput(io.Discard)
	force := fs.Bool("force", false, "overwrite existing skills without prompting")
	fs.BoolVar(force, "f", false, "overwrite existing skills without prompting")
	var selected repeatedStringFlag
	fs.Var(&selected, "skill", "add only the named skill (repeatable or comma-separated)")
	fs.Var(&selected, "s", "add only the named skill (repeatable or comma-separated)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{forceFlag: false, "-f": false, "--skill": true, "-s": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return r.showCommandHelp(skillsAddHelp())
		}
		return r.flagParseFailure("skills add", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, skillsAddUsage)
		return 2
	}
	names, err := parseSkillNames(selected)
	if err != nil {
		r.error(err)
		return 1
	}
	repo, err := parseSkillRepository(fs.Arg(0))
	if err != nil {
		r.error(err)
		return 1
	}
	if err := ctx.Err(); err != nil {
		r.error(err)
		return 1
	}
	return r.addRepositorySkills(ctx, repo, names, *force)
}

// addRepositorySkills clones outside the store lock, validates every selected
// skill, and only then commits. A failure while committing can leave earlier
// skills from the same command installed; each commit is itself atomic.
func (r *Runner) addRepositorySkills(ctx context.Context, repo skillRepository, names []string, force bool) int {
	checkout, err := cloneSkillRepository(ctx, repo)
	if err != nil {
		r.error(err)
		return 1
	}
	defer checkout.Close()
	found, err := discoverRepositorySkills(ctx, checkout.Path)
	if err != nil {
		r.error(err)
		return 1
	}
	selected, err := selectRepositorySkills(found, names)
	if err != nil {
		r.error(err)
		return 1
	}
	sources, err := loadRepositorySkills(selected)
	if err != nil {
		r.error(err)
		return 1
	}
	defer closeSourceSkills(sources)
	entry := repositoryRegistryEntry(repo, checkout)
	for _, source := range sources {
		decision, err := commitSourceSkill(ctx, source, force, entry, "")
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = fmt.Fprintln(r.Out, skillImportLine(decision, source.name, repo.Display))
	}
	return 0
}
