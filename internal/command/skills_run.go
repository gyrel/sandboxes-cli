package command

import (
	"errors"
	"fmt"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

// prepareRunSkills turns the --skills mode into a store request. The store is
// created on demand with the same layout as `rsbx skills import`, so a default
// read-only request never depends on an explicitly pre-created directory.
func prepareSkills(mode string) (*sdk.SkillsOptions, error) {
	switch mode {
	case "", "off":
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
