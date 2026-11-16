//go:build darwin

package daemonctl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func processCommand(pid int) (string, []string, error) {
	if pid <= 0 {
		return "", nil, ErrProcessNotFound
	}
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if errors.Is(err, unix.ESRCH) {
		return "", nil, ErrProcessNotFound
	}
	if err != nil {
		return "", nil, err
	}
	return parseProcArgs(raw)
}

func parseProcArgs(raw []byte) (string, []string, error) {
	if len(raw) < 4 {
		return "", nil, errors.New("kern.procargs2 returned a truncated record")
	}
	argc := int(binary.LittleEndian.Uint32(raw[:4]))
	rest := raw[4:]
	index := bytes.IndexByte(rest, 0)
	if index < 0 {
		return "", nil, errors.New("kern.procargs2 returned no executable path")
	}
	executable := string(rest[:index])
	rest = rest[index+1:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	args := make([]string, 0, argc)
	for len(rest) > 0 && len(args) < argc {
		index = bytes.IndexByte(rest, 0)
		if index < 0 {
			break
		}
		args = append(args, string(rest[:index]))
		rest = rest[index+1:]
	}
	if executable == "" {
		return "", nil, fmt.Errorf("%w: process executable path is empty", ErrIdentityUnverifiable)
	}
	return executable, args, nil
}
