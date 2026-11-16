//go:build linux

package daemonctl

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func socketPeerPID(socket string) (int, error) {
	conn, err := dialEndpoint(socket)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("%w: endpoint syscall connection: %w", ErrIdentityUnverifiable, err)
	}
	var (
		pid   int
		uid   uint32
		opErr error
	)
	if err := raw.Control(func(fd uintptr) {
		credentials, credErr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credErr != nil {
			opErr = credErr
			return
		}
		pid = int(credentials.Pid)
		uid = credentials.Uid
	}); err != nil {
		return 0, fmt.Errorf("%w: inspect endpoint peer: %w", ErrIdentityUnverifiable, err)
	}
	if opErr != nil {
		return 0, fmt.Errorf("%w: inspect endpoint peer: %w", ErrIdentityUnverifiable, opErr)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("%w: endpoint did not report a peer PID", ErrIdentityUnverifiable)
	}
	if int(uid) != os.Geteuid() {
		return 0, fmt.Errorf("%w: endpoint peer UID %d does not match the current user", ErrIdentityUnverifiable, uid)
	}
	return pid, nil
}
