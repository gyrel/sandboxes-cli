package command

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/gyrel/sandboxes-cli/internal/envfile"
)

// credentialsBindingsCandidates returns the global credentials.yaml locations
// owned by Gyrel. Only existing files are edited; no new storage file is
// created. Docker sbx directories are deliberately excluded: pruning must not
// mutate another product's credential state (AGENTS repository-boundary rule).
func credentialsBindingsCandidates() []string {
	var candidates []string
	add := func(dir string) {
		if dir == "" {
			return
		}
		for _, name := range []string{"credentials.yaml", "credentials.yml"} {
			candidates = append(candidates, filepath.Join(dir, name))
		}
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		add(filepath.Join(dir, "rheic")) // legacy-compat dir name
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		add(filepath.Join(home, ".config", "rheic")) // legacy-compat dir name
		add(filepath.Join(home, ".rheic"))           // legacy-compat legacy dotdir
	}
	return candidates
}

func pruneEnvironmentBindings(plan envfile.Plan) error {
	name := plan.Name
	if name == "" {
		return errors.New("environment name is required to prune bindings")
	}
	var firstErr error
	for _, path := range credentialsBindingsCandidates() {
		info, err := os.Stat(path) // #nosec G304,G703 -- path is one of the fixed Gyrel config-dir candidates, never derived from user input beyond $HOME/$XDG_CONFIG_HOME
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("inspect credentials bindings %s: %w", path, err)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			if firstErr == nil {
				firstErr = fmt.Errorf("credentials bindings %s is not a regular file", path)
			}
			continue
		}
		if err := pruneBindingsFile(path, name); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func pruneBindingsFile(path, name string) error {
	// Reject symlinks before reading: rename would otherwise replace whatever
	// the link points to outside the config directory.
	info, err := os.Lstat(path) // #nosec G304,G703 -- fixed Gyrel candidate path; symlink targets are refused below
	if err != nil {
		return fmt.Errorf("inspect credentials bindings %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("credentials bindings %s is not a regular file", path)
	}
	data, err := os.ReadFile(path) // #nosec G304,G703 -- fixed Gyrel candidate store path after regular-file check
	if err != nil {
		return fmt.Errorf("read credentials bindings %s: %w", path, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse credentials bindings %s: %w", path, err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	changed := pruneBindingsDocument(doc, name)
	if !changed {
		return nil
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal credentials bindings %s: %w", path, err)
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".credentials-*") // #nosec G304,G703 -- directory of a validated fixed candidate path
	if err != nil {
		return fmt.Errorf("create credentials bindings temp file %s: %w", path, err)
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("chmod credentials bindings temp file %s: %w", path, err)
	}
	if _, err := temp.Write(out); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write credentials bindings %s: %w", path, err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync credentials bindings %s: %w", path, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close credentials bindings %s: %w", path, err)
	}
	if err := os.Rename(tempName, path); err != nil { // #nosec G304,G703 -- atomic replace of the validated regular candidate file
		return fmt.Errorf("replace credentials bindings %s: %w", path, err)
	}
	return nil
}

func pruneBindingsDocument(doc map[string]any, name string) bool {
	changed := false
	if _, ok := doc[name]; ok {
		delete(doc, name)
		changed = true
	}
	for _, key := range []string{"bindings", "credentials", "environments"} {
		value, ok := doc[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			if pruneBindingsMap(typed, name) {
				changed = true
			}
		case []any:
			filtered, didChange := pruneBindingsList(typed, name)
			if didChange {
				doc[key] = filtered
				changed = true
			}
		}
	}
	return changed
}

func pruneBindingsMap(entries map[string]any, name string) bool {
	changed := false
	if _, ok := entries[name]; ok {
		delete(entries, name)
		changed = true
	}
	for _, itemKey := range []string{helpNameName, "environment", "environmentName", helpNameSandbox, "sandboxName"} {
		for entryKey, entryValue := range entries {
			entryMap, ok := entryValue.(map[string]any)
			if !ok {
				continue
			}
			if scalarString(entryMap[itemKey]) == name {
				delete(entries, entryKey)
				changed = true
			}
		}
	}
	return changed
}

func pruneBindingsList(items []any, name string) ([]any, bool) {
	filtered := make([]any, 0, len(items))
	changed := false
	for _, item := range items {
		if shouldPruneBindingItem(item, name) {
			changed = true
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered, changed
}

func shouldPruneBindingItem(item any, name string) bool {
	if m, ok := item.(map[string]any); ok {
		for _, key := range []string{helpNameName, "environment", "environmentName", helpNameSandbox, "sandboxName"} {
			if scalarString(m[key]) == name {
				return true
			}
		}
		return false
	}
	if s, ok := item.(string); ok {
		return s == name
	}
	return false
}

func scalarString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return ""
	}
}
