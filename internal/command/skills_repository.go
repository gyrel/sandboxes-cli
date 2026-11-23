package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	repositoryFetchTimeout = 2 * time.Minute
	repositoryWaitDelay    = 5 * time.Second
	repositoryOutputLimit  = 16 << 10
	repositoryScanLimit    = 10000
	repositoryGitProtocols = "GIT_ALLOW_PROTOCOL=file:https"
	githubRepositoryPrefix = "https://github.com/"
)

var (
	errSkillRepositoryInvalid = errors.New("skills: repository must be an https URL, owner/repository or local directory")
	repositoryShorthand       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// skillRepository is a validated clone source. Location is recorded in the
// registry and given to Git; Display is the only form printed to the user.
type skillRepository struct {
	Location string
	Display  string
}

func parseSkillRepository(value string) (skillRepository, error) {
	if value == "" || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "\x00\r\n") {
		return skillRepository{}, errSkillRepositoryInvalid
	}
	if strings.Contains(value, "://") {
		return parseRepositoryURL(value)
	}
	if _, err := os.Stat(value); err == nil || filepath.IsAbs(value) {
		return localSkillRepository(value)
	}
	if repositoryShorthand.MatchString(value) {
		location := githubRepositoryPrefix + value
		return skillRepository{Location: location, Display: location}, nil
	}
	return skillRepository{}, errSkillRepositoryInvalid
}

// parseRepositoryURL admits https and file URLs only. Userinfo and query
// strings are refused because either could carry a credential into argv or the
// registry; other transports (ext::, ssh, git) can run commands or need keys.
func parseRepositoryURL(value string) (skillRepository, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return skillRepository{}, errSkillRepositoryInvalid
	}
	if parsed.User != nil {
		return skillRepository{}, errors.New("skills: repository URL must not contain credentials; configure a Git credential helper instead")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return skillRepository{}, errors.New("skills: repository URL must not contain a query or fragment")
	}
	switch parsed.Scheme {
	case schemeHTTPS:
		if parsed.Host == "" {
			return skillRepository{}, errSkillRepositoryInvalid
		}
		return skillRepository{Location: value, Display: value}, nil
	case "file":
		if (parsed.Host != "" && parsed.Host != "localhost") || !filepath.IsAbs(filepath.FromSlash(parsed.Path)) {
			return skillRepository{}, errSkillRepositoryInvalid
		}
		return localSkillRepository(filepath.FromSlash(parsed.Path))
	default:
		return skillRepository{}, errSkillRepositoryInvalid
	}
}

func localSkillRepository(value string) (skillRepository, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return skillRepository{}, errors.New("skills: repository directory is unavailable")
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return skillRepository{}, errors.New("skills: repository directory is unavailable")
	}
	if !info.IsDir() {
		return skillRepository{}, errors.New("skills: repository must be a directory")
	}
	return skillRepository{Location: absolute, Display: filepath.Base(absolute)}, nil
}

// repositoryFromRecord rebuilds the clone source from a registry entry. Records
// are validated on read, so this only derives the printable name.
func repositoryFromRecord(location string) (skillRepository, error) {
	if err := validateRepositoryLocation(location); err != nil {
		return skillRepository{}, fmt.Errorf("skills: registry repository is invalid: %w", err)
	}
	if filepath.IsAbs(location) {
		return skillRepository{Location: location, Display: filepath.Base(location)}, nil
	}
	return skillRepository{Location: location, Display: location}, nil
}

// repositoryCheckout is a shallow clone of the default branch. Dir is a fresh
// private temporary directory that Close removes; Path is the clone inside it.
type repositoryCheckout struct {
	Dir    string
	Path   string
	Branch string
	Commit string
}

func (c *repositoryCheckout) Close() {
	_ = os.RemoveAll(c.Dir)
}

func cloneSkillRepository(ctx context.Context, repo skillRepository) (*repositoryCheckout, error) {
	dir, err := os.MkdirTemp("", "rsbx-skills-")
	if err != nil {
		return nil, errors.New("skills: cannot create a temporary checkout directory")
	}
	checkout := &repositoryCheckout{Dir: dir, Path: filepath.Join(dir, "checkout")}
	if err := checkout.fetch(ctx, repo); err != nil {
		checkout.Close()
		return nil, err
	}
	return checkout, nil
}

func (c *repositoryCheckout) fetch(ctx context.Context, repo skillRepository) error {
	ctx, cancel := context.WithTimeout(ctx, repositoryFetchTimeout)
	defer cancel()
	args := []string{"clone", "--quiet", "--depth", "1", "--no-tags", "--single-branch", "--", repo.Location, c.Path}
	if _, err := runRepositoryGit(ctx, repo, c.Dir, args...); err != nil {
		return err
	}
	branch, err := runRepositoryGit(ctx, repo, c.Dir, "-C", c.Path, "symbolic-ref", "--quiet", "--short", "HEAD")
	if err != nil || !skillBranchPattern.MatchString(branch) {
		return fmt.Errorf("skills: repository %s has no default branch", repo.Display)
	}
	commit, err := runRepositoryGit(ctx, repo, c.Dir, "-C", c.Path, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || !skillCommitPattern.MatchString(commit) {
		return fmt.Errorf("skills: repository %s has no readable commit", repo.Display)
	}
	c.Branch = branch
	c.Commit = commit
	return nil
}

// runRepositoryGit runs the fixed git executable with structured arguments.
// Output is bounded, the context deadline stops the process, and failures are
// redacted so neither host paths nor a credential can reach the terminal.
func runRepositoryGit(ctx context.Context, repo skillRepository, scratch string, args ...string) (string, error) {
	var stdout, stderr boundedRepositoryOutput
	//nolint:gosec // fixed Git executable; arguments are structured argv values, never shell text.
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(safeGitEnvironment(), repositoryGitProtocols)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = repositoryWaitDelay
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", fmt.Errorf("skills: reading repository %s: %w", repo.Display, ctxErr)
		}
		return "", fmt.Errorf("skills: cannot read repository %s: %s", repo.Display, firstRepositoryLine(redactRepositoryText(stderr.String(), repo, scratch)))
	}
	return strings.TrimSpace(stdout.String()), nil
}

type boundedRepositoryOutput struct {
	buf bytes.Buffer
}

func (b *boundedRepositoryOutput) Write(p []byte) (int, error) {
	if remaining := repositoryOutputLimit - b.buf.Len(); remaining > 0 {
		b.buf.Write(p[:min(remaining, len(p))])
	}
	return len(p), nil
}

func (b *boundedRepositoryOutput) String() string {
	return b.buf.String()
}

func redactRepositoryText(text string, repo skillRepository, scratch string) string {
	pairs := make([]string, 0, 6)
	if scratch != "" {
		pairs = append(pairs, scratch, "<checkout>")
	}
	if repo.Location != repo.Display {
		pairs = append(pairs, repo.Location, repo.Display)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		pairs = append(pairs, home, "~")
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

func firstRepositoryLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return sanitizeSkillErrorText(truncateText(line, 240))
		}
	}
	return "git failed"
}

func truncateText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

// repositorySkill is a skill directory found in a checkout. Path is absolute
// and inside the checkout; Name is the directory name, which must match the
// manifest name when the skill is loaded.
type repositorySkill struct {
	Name string
	Path string
}

// discoverRepositorySkills returns every directory that holds a SKILL.md.
// Hidden entries are skipped, skill directories are not searched for nested
// skills, and symbolic links are never followed. A link whose name is a valid
// skill name is refused, because it could otherwise point outside the clone.
func discoverRepositorySkills(ctx context.Context, checkout string) ([]repositorySkill, error) {
	found := make([]repositorySkill, 0)
	seen := make(map[string]bool)
	visited := 0
	err := filepath.WalkDir(checkout, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("skills: cannot scan repository")
		}
		if path == checkout {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		visited++
		if visited > repositoryScanLimit {
			return errors.New("skills: repository exceeds the entry limit")
		}
		return visitRepositoryEntry(path, entry, seen, &found)
	})
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, errors.New("skills: repository contains no skills with a SKILL.md file")
	}
	return found, nil
}

func visitRepositoryEntry(path string, entry fs.DirEntry, seen map[string]bool, found *[]repositorySkill) error {
	name := entry.Name()
	if strings.HasPrefix(name, ".") {
		if entry.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
	if entry.Type()&fs.ModeSymlink != 0 {
		if validateSkillName(name) == nil {
			return fmt.Errorf("skills: skill %q is a symbolic link; symbolic links are not imported from repositories", name)
		}
		return nil
	}
	if !entry.IsDir() {
		return nil
	}
	if !hasSkillManifestEntry(path) {
		return nil
	}
	if seen[name] {
		return fmt.Errorf("skills: skill %q appears more than once in the repository", sanitizeSkillErrorText(name))
	}
	seen[name] = true
	*found = append(*found, repositorySkill{Name: name, Path: path})
	return filepath.SkipDir
}

func hasSkillManifestEntry(directory string) bool {
	_, err := os.Lstat(filepath.Join(directory, "SKILL.md"))
	return err == nil
}

// parseSkillNames flattens repeatable and comma-separated --skill values,
// keeping the first occurrence of each name.
func parseSkillNames(values []string) ([]string, error) {
	names := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			name := strings.TrimSpace(part)
			if err := validateSkillName(name); err != nil {
				return nil, err
			}
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names, nil
}

func selectRepositorySkills(found []repositorySkill, names []string) ([]repositorySkill, error) {
	if len(names) == 0 {
		return found, nil
	}
	byName := make(map[string]repositorySkill, len(found))
	for _, skill := range found {
		byName[skill.Name] = skill
	}
	selected := make([]repositorySkill, 0, len(names))
	for _, name := range names {
		skill, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("skills: skill %q was not found in the repository", name)
		}
		selected = append(selected, skill)
	}
	return selected, nil
}

// loadRepositorySkills validates every selected skill before any store write,
// so a bad skill stops the command before the store changes.
func loadRepositorySkills(selected []repositorySkill) ([]*sourceSkill, error) {
	sources := make([]*sourceSkill, 0, len(selected))
	for _, skill := range selected {
		source, err := loadSourceSkill(skill.Path)
		if err != nil {
			closeSourceSkills(sources)
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, nil
}

func closeSourceSkills(sources []*sourceSkill) {
	for _, source := range sources {
		_ = source.root.Close()
	}
}

func repositoryRegistryEntry(repo skillRepository, checkout *repositoryCheckout) skillsRegistryEntry {
	return skillsRegistryEntry{
		Source:     repo.Location,
		Repository: repo.Location,
		Branch:     checkout.Branch,
		Commit:     checkout.Commit,
	}
}
