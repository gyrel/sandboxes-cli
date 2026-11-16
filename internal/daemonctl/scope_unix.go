//go:build !windows

package daemonctl

import (
	"os"
	"path/filepath"
)

func stateDirForSocket(socket string) (string, error) {
	absolute, err := filepath.Abs(socket)
	if err != nil {
		return "", err
	}
	return filepath.Dir(filepath.Clean(absolute)), nil
}

func socketPathExists(socket string) bool {
	_, err := os.Lstat(socket)
	return err == nil || !os.IsNotExist(err)
}
