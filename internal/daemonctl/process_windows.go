//go:build windows

package daemonctl

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// signalStop terminates the verified daemon process on Windows. Windows has no
// SIGTERM equivalent for a detached process, so termination is explicit and
// the daemon's crash-safe reconciliation runs on the next start.
func signalStop(process process) error {
	return process.Kill()
}

func configureDetached(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
}
