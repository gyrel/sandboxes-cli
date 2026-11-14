package command

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	skillsDirectoryName = "skills"
	skillsRegistryName  = "skills.json"
	skillsRegistryVer   = 1

	maxSkillsRegistryBytes = 1 << 20
	maxSkillTreeEntries    = 1000
	maxSkillTreeDepth      = 16
	maxSkillTreeBytes      = 8 << 20
	maxSkillFileBytes      = 1 << 20
	maxSkillManifestBytes  = 256 << 10
	maxSkillNameLength     = 64
	maxSkillDescription    = 2048
)

var (
	errSkillsRootMissing = errors.New("skills: config directory does not exist")
	skillNamePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	skillDigestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type skillsPaths struct {
	base     string
	store    string
	registry string
}

type skillsRegistry struct {
	Version int                   `json:"version"`
	Skills  []skillsRegistryEntry `json:"skills"`
}

type skillsRegistryEntry struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	Digest     string `json:"digest"`
	ImportedAt string `json:"imported_at"`
}

func resolveSkillsPaths() (skillsPaths, error) {
	base, err := skillsBaseDirectory()
	if err != nil {
		return skillsPaths{}, err
	}
	return skillsPaths{
		base:     base,
		store:    filepath.Join(base, skillsDirectoryName),
		registry: filepath.Join(base, skillsRegistryName),
	}, nil
}

func skillsBaseDirectory() (string, error) {
	if configured := os.Getenv("XDG_CONFIG_HOME"); configured != "" {
		if !filepath.IsAbs(configured) {
			return "", errors.New("skills: XDG_CONFIG_HOME must be an absolute path")
		}
		return filepath.Join(configured, "rheic"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) {
		return "", errors.New("skills: home directory is unavailable")
	}
	return filepath.Join(home, ".config", "rheic"), nil
}

// openSkillsRoot anchors all store operations under the Rheic config
// directory. It rejects a symlinked root instead of following it.
func openSkillsRoot(paths skillsPaths, create bool) (*os.Root, error) {
	info, err := os.Lstat(paths.base)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return nil, errSkillsRootMissing
		}
		if err := os.MkdirAll(paths.base, 0o700); err != nil {
			return nil, fmt.Errorf("skills: create config directory: %w", err)
		}
		info, err = os.Lstat(paths.base)
	}
	if err != nil {
		return nil, fmt.Errorf("skills: inspect config directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("skills: config directory must be a real directory")
	}
	root, err := os.OpenRoot(paths.base)
	if err != nil {
		return nil, fmt.Errorf("skills: open config directory: %w", err)
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, errors.New("skills: config directory changed while opening")
	}
	return root, nil
}

func ensureSkillsStore(root *os.Root) error {
	info, err := root.Lstat(skillsDirectoryName)
	if errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(skillsDirectoryName, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("skills: create store: %w", err)
		}
		info, err = root.Lstat(skillsDirectoryName)
	}
	if err != nil {
		return fmt.Errorf("skills: inspect store: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("skills: store must be a real directory")
	}
	return nil
}

func openSkillsStore(root *os.Root) (*os.Root, error) {
	info, err := root.Lstat(skillsDirectoryName)
	if err != nil {
		return nil, fmt.Errorf("skills: inspect store: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("skills: store must be a real directory")
	}
	store, err := root.OpenRoot(skillsDirectoryName)
	if err != nil {
		return nil, fmt.Errorf("skills: open store: %w", err)
	}
	opened, err := store.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = store.Close()
		return nil, errors.New("skills: store changed while opening")
	}
	return store, nil
}

func readSkillsRegistry(root *os.Root) (skillsRegistry, error) {
	empty := skillsRegistry{Version: skillsRegistryVer, Skills: []skillsRegistryEntry{}}
	info, err := root.Lstat(skillsRegistryName)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return skillsRegistry{}, fmt.Errorf("skills: inspect registry: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return skillsRegistry{}, errors.New("skills: registry must be a regular file")
	}
	if info.Size() > maxSkillsRegistryBytes {
		return skillsRegistry{}, errors.New("skills: registry exceeds the safety limit")
	}
	file, err := root.Open(skillsRegistryName)
	if err != nil {
		return skillsRegistry{}, fmt.Errorf("skills: open registry: %w", err)
	}
	defer func() { _ = file.Close() }()
	var registry skillsRegistry
	decoder := json.NewDecoder(io.LimitReader(file, maxSkillsRegistryBytes+1))
	if err := decoder.Decode(&registry); err != nil {
		return skillsRegistry{}, fmt.Errorf("skills: parse registry: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return skillsRegistry{}, err
	}
	if registry.Version != skillsRegistryVer {
		return skillsRegistry{}, errors.New("skills: unsupported registry version")
	}
	if registry.Skills == nil {
		registry.Skills = []skillsRegistryEntry{}
	}
	if err := validateSkillsRegistry(registry); err != nil {
		return skillsRegistry{}, err
	}
	return registry, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("skills: registry contains trailing data")
		}
		return fmt.Errorf("skills: parse registry: %w", err)
	}
	return nil
}

func validateSkillsRegistry(registry skillsRegistry) error {
	seen := make(map[string]struct{}, len(registry.Skills))
	for _, entry := range registry.Skills {
		if err := validateSkillName(entry.Name); err != nil {
			return err
		}
		if _, exists := seen[entry.Name]; exists {
			return fmt.Errorf("skills: duplicate registry entry %q", entry.Name)
		}
		seen[entry.Name] = struct{}{}
		if !filepath.IsAbs(entry.Source) {
			return fmt.Errorf("skills: registry source for %q must be absolute", entry.Name)
		}
		if !skillDigestPattern.MatchString(entry.Digest) {
			return fmt.Errorf("skills: registry digest for %q is invalid", entry.Name)
		}
		if _, err := time.Parse(time.RFC3339, entry.ImportedAt); err != nil {
			return fmt.Errorf("skills: registry timestamp for %q is invalid", entry.Name)
		}
	}
	return nil
}

func writeSkillsRegistry(root *os.Root, registry skillsRegistry) error {
	registry.Version = skillsRegistryVer
	sort.Slice(registry.Skills, func(i, j int) bool { return registry.Skills[i].Name < registry.Skills[j].Name })
	if registry.Skills == nil {
		registry.Skills = []skillsRegistryEntry{}
	}
	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return fmt.Errorf("skills: encode registry: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxSkillsRegistryBytes {
		return errors.New("skills: registry exceeds the safety limit")
	}
	temp, err := randomSkillHiddenName(".registry-")
	if err != nil {
		return err
	}
	if err := writeRegistryTemp(root, temp, data); err != nil {
		_ = root.Remove(temp)
		return err
	}
	if err := root.Rename(temp, skillsRegistryName); err != nil {
		return replaceRegistryFallback(root, temp)
	}
	return nil
}

func writeRegistryTemp(root *os.Root, name string, data []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("skills: create registry staging file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("skills: write registry: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("skills: sync registry: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("skills: close registry: %w", err)
	}
	return nil
}

// replaceRegistryFallback handles filesystems where rename cannot replace an
// existing file (notably Windows). The caller still fails closed on errors.
func replaceRegistryFallback(root *os.Root, temp string) error {
	if err := root.Remove(skillsRegistryName); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = root.Remove(temp)
		return fmt.Errorf("skills: replace registry: %w", err)
	}
	if err := root.Rename(temp, skillsRegistryName); err != nil {
		_ = root.Remove(temp)
		return fmt.Errorf("skills: install registry: %w", err)
	}
	return nil
}

func registryEntry(registry skillsRegistry, name string) (skillsRegistryEntry, bool) {
	for _, entry := range registry.Skills {
		if entry.Name == name {
			return entry, true
		}
	}
	return skillsRegistryEntry{}, false
}

func registryWithEntry(registry skillsRegistry, entry skillsRegistryEntry) skillsRegistry {
	updated := skillsRegistry{Version: skillsRegistryVer, Skills: make([]skillsRegistryEntry, 0, len(registry.Skills)+1)}
	for _, existing := range registry.Skills {
		if existing.Name != entry.Name {
			updated.Skills = append(updated.Skills, existing)
		}
	}
	updated.Skills = append(updated.Skills, entry)
	sort.Slice(updated.Skills, func(i, j int) bool { return updated.Skills[i].Name < updated.Skills[j].Name })
	return updated
}

func registryWithoutEntry(registry skillsRegistry, name string) skillsRegistry {
	updated := skillsRegistry{Version: skillsRegistryVer, Skills: make([]skillsRegistryEntry, 0, len(registry.Skills))}
	for _, existing := range registry.Skills {
		if existing.Name != name {
			updated.Skills = append(updated.Skills, existing)
		}
	}
	return updated
}

func validateSkillName(name string) error {
	if name == "" {
		return errors.New("skills: skill name is required")
	}
	if len(name) > maxSkillNameLength {
		return fmt.Errorf("skills: skill name %q is too long", name)
	}
	if !skillNamePattern.MatchString(name) {
		return fmt.Errorf("skills: invalid skill name %q", name)
	}
	return nil
}

func randomSkillHiddenName(prefix string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("skills: generate staging name: %w", err)
	}
	return prefix + hex.EncodeToString(random[:]), nil
}

func sanitizeSkillErrorText(value string) string {
	return strings.Map(func(value rune) rune {
		if unsafeSkillRune(value) {
			return '?'
		}
		return value
	}, value)
}
