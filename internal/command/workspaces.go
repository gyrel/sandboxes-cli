package command

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func workspaceSpecReadOnly(value string) bool {
	return strings.HasSuffix(value, ":ro") || strings.HasSuffix(value, ":readonly")
}

func parseWorkspaceSpec(value string) (sdk.Workspace, error) {
	readOnly := workspaceSpecReadOnly(value)
	path := value
	if strings.HasSuffix(value, ":readonly") {
		path = strings.TrimSuffix(value, ":readonly")
	} else if strings.HasSuffix(value, ":ro") {
		path = strings.TrimSuffix(value, ":ro")
	}
	if path == "" || strings.ContainsRune(path, '\x00') {
		return sdk.Workspace{}, errors.New("workspace path is invalid")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return sdk.Workspace{}, err
	}
	// Direct workspace paths are user-trusted by contract (§8 workspace
	// direct); normalize explicitly so the stat target is unambiguously a
	// cleaned absolute path rather than a tainted passthrough.
	absolute = filepath.Clean(absolute)
	info, err := os.Stat(absolute)
	if err != nil {
		return sdk.Workspace{}, fmt.Errorf("workspace %s: %w", path, err)
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return sdk.Workspace{}, fmt.Errorf("workspace %s is not a directory or regular file", path)
		}
		if !readOnly {
			return sdk.Workspace{}, fmt.Errorf("workspace file %s must be read-only (:ro)", path)
		}
	}
	return sdk.Workspace{Path: absolute, ReadOnly: readOnly}, nil
}

func resolveWorkspaces(paths []string, defaultCurrent bool) ([]sdk.Workspace, error) {
	if len(paths) == 0 {
		if !defaultCurrent {
			return nil, nil
		}
		paths = []string{"."}
	}
	if len(paths) > 16 {
		return nil, errors.New("at most 16 workspaces are supported")
	}
	seen := make(map[string]struct{}, len(paths))
	workspaces := make([]sdk.Workspace, 0, len(paths))
	for _, path := range paths {
		workspace, err := parseWorkspaceSpec(path)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[workspace.Path]; exists {
			return nil, fmt.Errorf("duplicate workspace %s", workspace.Path)
		}
		seen[workspace.Path] = struct{}{}
		workspaces = append(workspaces, workspace)
	}
	return workspaces, nil
}

func workspacePaths(workspaces []sdk.Workspace) []string {
	out := make([]string, 0, len(workspaces))
	for i := range workspaces {
		out = append(out, workspaces[i].Path)
	}
	return out
}
