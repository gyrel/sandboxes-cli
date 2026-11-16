//go:build linux

package daemonctl

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func processCommand(pid int) (string, []string, error) {
	if pid <= 0 {
		return "", nil, ErrProcessNotFound
	}
	executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil, ErrProcessNotFound
		}
		return "", nil, err
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)) // #nosec G304 -- fixed procfs path for a verified PID.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil, ErrProcessNotFound
		}
		return "", nil, err
	}
	args := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	if len(args) == 1 && args[0] == "" {
		args = nil
	}
	return executable, args, nil
}
