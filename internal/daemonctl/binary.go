package daemonctl

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DaemonBinaryEnv overrides daemon binary discovery.
const DaemonBinaryEnv = "SANDBOXES_DAEMON_BINARY"

// ResolveBinary finds sandboxesd in this order: the explicit override, the
// SANDBOXES_DAEMON_BINARY environment variable, PATH, then the CLI's directory.
func ResolveBinary(explicit string) (string, error) {
	for _, candidate := range []string{explicit, os.Getenv(DaemonBinaryEnv)} {
		if candidate == "" {
			continue
		}
		return checkBinary(candidate)
	}
	if found, err := exec.LookPath(daemonBinaryName()); err == nil {
		return checkBinary(found)
	}
	executable, err := os.Executable()
	if err == nil {
		sibling := filepath.Join(filepath.Dir(executable), daemonBinaryName())
		if resolved, checkErr := checkBinary(sibling); checkErr == nil {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("daemon binary %s not found; set %s or add it to PATH", daemonBinaryName(), DaemonBinaryEnv)
}

func checkBinary(candidate string) (string, error) {
	path := candidate
	if !strings.ContainsRune(path, filepath.Separator) {
		found, err := exec.LookPath(path)
		if err != nil {
			return "", fmt.Errorf("daemon binary %q not found: %w", candidate, err)
		}
		path = found
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(absolute) // #nosec G703 -- explicit operator-supplied daemon binary path is validated as a regular executable file.
	if err != nil {
		return "", fmt.Errorf("daemon binary %q: %w", candidate, err)
	}
	if !isExecutableBinary(info) {
		return "", errors.New("daemon binary must be a regular executable file")
	}
	return absolute, nil
}
