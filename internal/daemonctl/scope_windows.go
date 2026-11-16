//go:build windows

package daemonctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
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
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		conn, err := winio.DialPipeContext(ctx, socket)
		if err == nil {
			_ = conn.Close()
			return true
		}
		return !errors.Is(err, windows.ERROR_FILE_NOT_FOUND)
	}
	_, err := os.Lstat(socket)
	return err == nil || !os.IsNotExist(err)
}
