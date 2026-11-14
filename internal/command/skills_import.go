package command

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

const skillsImportUsage = `usage: rsbx skills import [--force] PATH

Import a local skill directory into Rheic's host-side skills store. PATH must
be a real directory with a SKILL.md file. SKILL.md requires YAML frontmatter:

  ---
  name: my-skill
  description: One line describing the skill.
  ---

Symlinks, special files, oversized files and oversized trees are rejected.
Identical re-imports are no-ops. Use --force only to replace skill content that
Rheic already imported; unmanaged directories are never overwritten.
`

type sourceSkill struct {
	root     *os.Root
	entries  []skillTreeEntry
	manifest skillManifest
	path     string
	name     string
}

type skillManifest struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

func (r *Runner) importSkills(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("skills import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	force := fs.Bool("force", false, "replace skill content previously imported by Rheic")
	fs.BoolVar(force, "f", false, "replace skill content previously imported by Rheic")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{forceFlag: false, "-f": false})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(r.Out, skillsImportUsage)
			return 0
		}
		return r.flagParseFailure("skills import", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, skillsImportUsage)
		return 2
	}
	if err := ctx.Err(); err != nil {
		r.error(err)
		return 1
	}
	source, err := loadSourceSkill(fs.Arg(0))
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = source.root.Close() }()
	return r.installSourceSkill(ctx, source, *force)
}

func loadSourceSkill(path string) (*sourceSkill, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("skills import: source path is invalid")
	}
	absolute = filepath.Clean(absolute)
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, errors.New("skills import: source path is unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("skills import: source path must not be a symbolic link")
	}
	if !info.IsDir() {
		return nil, errors.New("skills import: source path must be a directory")
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, errors.New("skills import: cannot open source directory")
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, errors.New("skills import: source directory changed while opening")
	}
	manifest, err := readSkillManifest(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if filepath.Base(absolute) != manifest.Name {
		_ = root.Close()
		return nil, fmt.Errorf("skills import: manifest name %q must match source directory %q", sanitizeSkillErrorText(manifest.Name), sanitizeSkillErrorText(filepath.Base(absolute)))
	}
	entries, err := collectSkillEntries(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	return &sourceSkill{root: root, entries: entries, manifest: manifest, path: absolute, name: manifest.Name}, nil
}

func readSkillManifest(root *os.Root) (skillManifest, error) {
	info, err := root.Lstat("SKILL.md")
	if errors.Is(err, os.ErrNotExist) {
		return skillManifest{}, errors.New("skills import: SKILL.md is required")
	}
	if err != nil {
		return skillManifest{}, errors.New("skills import: cannot inspect SKILL.md")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return skillManifest{}, errors.New("skills import: SKILL.md must be a regular file")
	}
	if info.Size() > maxSkillManifestBytes {
		return skillManifest{}, errors.New("skills import: SKILL.md exceeds the size limit")
	}
	file, err := root.Open("SKILL.md")
	if err != nil {
		return skillManifest{}, errors.New("skills import: cannot open SKILL.md")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxSkillManifestBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return skillManifest{}, errors.New("skills import: cannot read SKILL.md")
	}
	if len(data) > maxSkillManifestBytes {
		return skillManifest{}, errors.New("skills import: SKILL.md exceeds the size limit")
	}
	return parseSkillManifest(data)
}

func parseSkillManifest(data []byte) (skillManifest, error) {
	frontmatter, err := skillFrontmatter(data)
	if err != nil {
		return skillManifest{}, err
	}
	var manifest skillManifest
	if err := yaml.Unmarshal(frontmatter, &manifest); err != nil {
		return skillManifest{}, errors.New("skills import: SKILL.md frontmatter is not valid YAML")
	}
	manifest.Name = strings.TrimSpace(manifest.Name)
	manifest.Description = strings.TrimSpace(manifest.Description)
	if err := validateSkillName(manifest.Name); err != nil {
		return skillManifest{}, fmt.Errorf("skills import: SKILL.md name is invalid: %w", err)
	}
	if manifest.Description == "" {
		return skillManifest{}, errors.New("skills import: SKILL.md description is required")
	}
	if len(manifest.Description) > maxSkillDescription {
		return skillManifest{}, errors.New("skills import: SKILL.md description is too long")
	}
	if strings.IndexFunc(manifest.Description, unicode.IsControl) >= 0 {
		return skillManifest{}, errors.New("skills import: SKILL.md description must be a single line")
	}
	return manifest, nil
}

func skillFrontmatter(data []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxSkillManifestBytes)
	if !scanner.Scan() || strings.TrimSpace(scanner.Text()) != "---" {
		return nil, errors.New("skills import: SKILL.md must start with YAML frontmatter")
	}
	var frontmatter strings.Builder
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "---" {
			if frontmatter.Len() == 0 {
				return nil, errors.New("skills import: SKILL.md frontmatter is empty")
			}
			return []byte(frontmatter.String()), nil
		}
		frontmatter.WriteString(scanner.Text())
		frontmatter.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("skills import: cannot read SKILL.md frontmatter")
	}
	return nil, errors.New("skills import: SKILL.md frontmatter is not terminated")
}

func (r *Runner) installSourceSkill(ctx context.Context, source *sourceSkill, force bool) int {
	state, err := openSkillImportState()
	if err != nil {
		r.error(err)
		return 1
	}
	defer state.Close()
	stageName, digest, err := stageSourceSkill(state.store, source)
	if err != nil {
		r.error(err)
		return 1
	}
	stageInstalled := false
	defer func() {
		if !stageInstalled {
			removeSkillStage(state.store, stageName)
		}
	}()
	if err := ctx.Err(); err != nil {
		r.error(err)
		return 1
	}
	decision, err := inspectSkillImportDecision(state.store, state.registry, source.name, digest, force)
	if err != nil {
		r.error(err)
		return 1
	}
	if decision == skillImportNoop {
		_, _ = fmt.Fprintf(r.Out, "Skill %q is already imported\n", sanitizeSkillErrorText(source.name))
		return 0
	}
	entry := skillsRegistryEntry{
		Name:       source.name,
		Source:     source.path,
		Digest:     digest,
		ImportedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := commitSkillImport(state.root, state.store, stageName, entry, decision == skillImportReplace); err != nil {
		r.error(err)
		return 1
	}
	stageInstalled = true
	action := "Imported"
	if decision == skillImportReplace {
		action = "Replaced"
	}
	_, _ = fmt.Fprintf(r.Out, "%s skill %q from %s\n", action, sanitizeSkillErrorText(source.name), sanitizeSkillErrorText(source.path))
	return 0
}

type skillImportState struct {
	root     *os.Root
	store    *os.Root
	registry skillsRegistry
}

func openSkillImportState() (*skillImportState, error) {
	paths, err := resolveSkillsPaths()
	if err != nil {
		return nil, err
	}
	root, err := openSkillsRoot(paths, true)
	if err != nil {
		return nil, err
	}
	if err := ensureSkillsStore(root); err != nil {
		_ = root.Close()
		return nil, err
	}
	store, err := openSkillsStore(root)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	registry, err := readSkillsRegistry(root)
	if err != nil {
		_ = store.Close()
		_ = root.Close()
		return nil, err
	}
	return &skillImportState{root: root, store: store, registry: registry}, nil
}

func (s *skillImportState) Close() {
	_ = s.store.Close()
	_ = s.root.Close()
}

type skillImportDecision int

const (
	skillImportInstall skillImportDecision = iota
	skillImportReplace
	skillImportNoop
)

func inspectSkillImportDecision(store *os.Root, registry skillsRegistry, name, digest string, force bool) (skillImportDecision, error) {
	info, err := store.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return skillImportInstall, nil
	}
	if err != nil {
		return 0, errors.New("skills import: cannot inspect existing skill")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("skills import: existing entry %q is not a real directory", name)
	}
	entry, managed := registryEntry(registry, name)
	if !managed {
		return 0, fmt.Errorf("skills import: %q already exists but was not imported by Rheic; refusing to overwrite it", name)
	}
	installed, err := installedSkillDigest(store, name)
	if err != nil {
		return 0, err
	}
	if installed == digest {
		return skillImportNoop, nil
	}
	if !force {
		return 0, fmt.Errorf("skills import: %q already exists with different content; use --force to replace it", name)
	}
	if entry.Digest == "" {
		return 0, errors.New("skills import: existing skill record is incomplete")
	}
	return skillImportReplace, nil
}

func stageSourceSkill(store *os.Root, source *sourceSkill) (string, string, error) {
	stageName, stage, err := createSkillStage(store)
	if err != nil {
		return "", "", err
	}
	if err := copySkillTree(source.root, source.entries, stage); err != nil {
		_ = stage.Close()
		removeSkillStage(store, stageName)
		return "", "", err
	}
	manifest, err := readSkillManifest(stage)
	if err != nil {
		_ = stage.Close()
		removeSkillStage(store, stageName)
		return "", "", err
	}
	if manifest.Name != source.name {
		_ = stage.Close()
		removeSkillStage(store, stageName)
		return "", "", errors.New("skills import: source changed while importing")
	}
	entries, err := collectSkillEntries(stage)
	if err != nil {
		_ = stage.Close()
		removeSkillStage(store, stageName)
		return "", "", err
	}
	digest, err := hashSkillEntries(stage, entries)
	closeErr := stage.Close()
	if err != nil || closeErr != nil {
		removeSkillStage(store, stageName)
		return "", "", errors.New("skills import: cannot verify staged skill")
	}
	return stageName, digest, nil
}

func commitSkillImport(root *os.Root, store *os.Root, stageName string, entry skillsRegistryEntry, replace bool) error {
	registry, err := readSkillsRegistry(root)
	if err != nil {
		return err
	}
	var backup string
	if replace {
		backup, err = randomSkillHiddenName(".backup-")
		if err != nil {
			return err
		}
		if err := store.Rename(entry.Name, backup); err != nil {
			return errors.New("skills import: cannot stage existing skill for replacement")
		}
	}
	if err := store.Rename(stageName, entry.Name); err != nil {
		restoreSkillBackup(store, entry.Name, backup)
		return errors.New("skills import: cannot install staged skill")
	}
	if err := writeSkillsRegistry(root, registryWithEntry(registry, entry)); err != nil {
		rollbackSkillImport(store, stageName, entry.Name, backup)
		return fmt.Errorf("skills import: registry update failed: %w", err)
	}
	if backup != "" {
		if err := store.RemoveAll(backup); err != nil {
			return fmt.Errorf("skills import: cannot remove replacement backup %q", backup)
		}
	}
	return nil
}

func rollbackSkillImport(store *os.Root, stageName, name, backup string) {
	_ = store.Rename(name, stageName)
	restoreSkillBackup(store, name, backup)
}

func restoreSkillBackup(store *os.Root, name, backup string) {
	if backup != "" {
		_ = store.Rename(backup, name)
	}
}
