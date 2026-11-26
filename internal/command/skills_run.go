package command

import (
	"errors"
	"fmt"
	"strings"

	sdk "github.com/gyrel/sandboxes-go-sdk"

	"github.com/gyrel/sandboxes-cli/internal/settings"
)

// skillsDefaultModeKey is the settings entry consulted when --skills is
// omitted, mirroring the sbx contract "Default: readonly, or the configured
// skills.defaultMode setting".
const skillsDefaultModeKey = "skills.defaultMode"

// resolveSkillsMode picks the effective skills mode for a create: an explicit
// --skills flag wins; an omitted flag falls back to the skills.defaultMode
// setting; an unset setting falls back to the catalog default (readonly). The
// fallback stays security-neutral: readonly links the Gyrel-owned store
// (~/.config/rheic/skills; legacy-compat dir retained so existing stores keep
// loading), which is empty until the user imports skills; it
// never exposes agent host directories, and readwrite keeps failing closed
// downstream. An unreadable or malformed settings file fails the create path
// instead of guessing a mount mode.
func (r *Runner) resolveSkillsMode(flagMode string) (string, error) {
	if flagMode != "" {
		return flagMode, nil
	}
	values, err := settings.Load(r.settingsPath())
	if err != nil {
		return "", fmt.Errorf("skills: read %s: %w", skillsDefaultModeKey, err)
	}
	if value := strings.TrimSpace(values.Extra[skillsDefaultModeKey]); value != "" {
		return value, nil
	}
	return catalogDefaultSkillsMode(), nil
}

// prepareSkillsOption resolves an (possibly empty) --skills flag against
// settings and builds the store request. It is the single entry point for
// run/create so the omitted-flag default lives in one place.
func (r *Runner) prepareSkillsOption(flagMode string) (*sdk.SkillsOptions, error) {
	mode, err := r.resolveSkillsMode(flagMode)
	if err != nil {
		return nil, err
	}
	return prepareSkills(mode)
}

// catalogDefaultSkillsMode reads the declared catalog default so the CLI and
// `rsbx settings ls` can never disagree.
func catalogDefaultSkillsMode() string {
	for _, entry := range settings.Catalog() {
		if entry.Key == skillsDefaultModeKey {
			return entry.Default
		}
	}
	return "off"
}

// prepareRunSkills turns the --skills mode into a store request. The store is
// created on demand with the same layout as `rsbx skills import`, so a default
// read-only request never depends on an explicitly pre-created directory.
// Callers must resolve an omitted flag through resolveSkillsMode first.
func prepareSkills(mode string) (*sdk.SkillsOptions, error) {
	switch mode {
	case "":
		return nil, errors.New("skills: mode not resolved (internal error)")
	case "off":
		return nil, nil //nolint:nilnil // No skills options means shared skills are disabled.
	case string(sdk.SkillsReadOnly):
		paths, err := resolveSkillsPaths()
		if err != nil {
			return nil, err
		}
		root, err := openSkillsRoot(paths, true)
		if err != nil {
			return nil, err
		}
		defer func() { _ = root.Close() }()
		if err := ensureSkillsStore(root); err != nil {
			return nil, err
		}
		return &sdk.SkillsOptions{Mode: sdk.SkillsReadOnly, StorePath: paths.store}, nil
	case string(sdk.SkillsReadWrite):
		return nil, errors.New("skills: readwrite mode is not supported yet")
	default:
		return nil, fmt.Errorf("skills: mode must be off, readonly or readwrite")
	}
}
