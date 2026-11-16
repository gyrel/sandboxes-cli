//go:build windows

package daemonctl

import (
	"os"
	"path/filepath"
	"strings"
)

func defaultStateDir() string {
	if dir := os.Getenv("SANDBOXES_STATE"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".sandboxes"
	}
	return filepath.Join(home, ".sandboxes")
}

func stateDirForSocket(socket string) (string, error) {
	if strings.HasPrefix(strings.ToLower(socket), `\\.\pipe\`) {
		return defaultStateDir(), nil
	}
	absolute, err := filepath.Abs(socket)
	if err != nil {
		return "", err
	}
	return filepath.Dir(filepath.Clean(absolute)), nil
}

func socketPathExists(socket string) bool {
	if strings.HasPrefix(strings.ToLower(socket), `\\.\pipe\`) {
		return false
	}
	_, err := os.Lstat(socket)
	return err == nil || !os.IsNotExist(err)
}

func removeStaleSocket(socket string) error {
	if strings.HasPrefix(strings.ToLower(socket), `\\.\pipe\`) {
		return nil
	}
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
