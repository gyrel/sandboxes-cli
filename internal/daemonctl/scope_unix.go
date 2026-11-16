//go:build !windows

package daemonctl

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
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

func removeStaleSocket(socket string) error {
	info, err := os.Lstat(socket)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("refusing to remove a non-socket daemon endpoint")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("refusing to remove a daemon socket owned by another user")
	}
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
