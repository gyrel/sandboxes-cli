package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxCustomAgentsFile = 1 << 20

var customAgentName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// CustomPath returns the host-owned custom agent registry path.
// RHEIC_AGENTS_FILE overrides the default; XDG_CONFIG_HOME is honored.
func CustomPath() string {
	if path := strings.TrimSpace(os.Getenv("RHEIC_AGENTS_FILE")); path != "" {
		return path
	}
	if dir := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); dir != "" {
		return filepath.Join(dir, "rheic", "agents.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "rheic", "agents.yaml")
}

// LoadWithCustom merges the built-in registry with host-configured custom
// agents. Custom agents cannot shadow built-in names.
func LoadWithCustom() (*Registry, error) {
	registry, err := Load()
	if err != nil {
		return nil, err
	}
	path := CustomPath()
	if path == "" {
		return registry, nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return registry, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect custom agent registry: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("custom agent registry must be a regular file: %s", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("custom agent registry must not be group- or world-writable: %s", path)
	}
	if info.Size() > maxCustomAgentsFile {
		return nil, fmt.Errorf("custom agent registry exceeds %d bytes", maxCustomAgentsFile)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- host-configured path
	if err != nil {
		return nil, fmt.Errorf("read custom agent registry: %w", err)
	}
	var doc struct {
		Agents []Spec `yaml:"agents"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse custom agent registry %s: %w", path, err)
	}
	for i := range doc.Agents {
		if err := registry.addCustom(doc.Agents[i]); err != nil {
			return nil, fmt.Errorf("custom agent registry %s: %w", path, err)
		}
	}
	return registry, nil
}

func (r *Registry) addCustom(spec Spec) error {
	spec.Name = strings.TrimSpace(spec.Name)
	if !customAgentName.MatchString(spec.Name) {
		return fmt.Errorf("invalid custom agent name %q", spec.Name)
	}
	if _, exists := r.byName[spec.Name]; exists {
		return fmt.Errorf("custom agent %q shadows an existing agent", spec.Name)
	}
	switch spec.Status {
	case StatusAvailable, StatusPreview:
		if err := validateCustomLaunchable(spec); err != nil {
			return err
		}
	case StatusUnsupported:
	default:
		return fmt.Errorf("custom agent %q has unknown status %q", spec.Name, spec.Status)
	}
	if len(spec.Notes) > 1024 || len(spec.Auth) > 1024 {
		return fmt.Errorf("custom agent %q notes/auth exceed 1024 bytes", spec.Name)
	}
	r.byName[spec.Name] = spec
	r.names = append(r.names, spec.Name)
	return nil
}

func validateCustomLaunchable(spec Spec) error {
	if len(spec.Command) == 0 || strings.TrimSpace(spec.Command[0]) == "" {
		return fmt.Errorf("custom agent %q has no command", spec.Name)
	}
	if strings.TrimSpace(spec.Image) == "" {
		return fmt.Errorf("custom agent %q has no image", spec.Name)
	}
	if strings.ContainsAny(spec.Image, " \t\r\n") {
		return fmt.Errorf("custom agent %q has an invalid image reference", spec.Name)
	}
	if spec.Status == StatusAvailable && !isDigestPinned(spec.Image) {
		return fmt.Errorf("custom agent %q must pin its image by sha256 digest when status is available", spec.Name)
	}
	for _, arg := range spec.Command {
		if strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("custom agent %q command contains NUL", spec.Name)
		}
	}
	return nil
}
