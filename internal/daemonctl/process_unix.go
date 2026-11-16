//go:build !windows

package daemonctl

import (
	"os/exec"
	"syscall"
)

func signalStop(process process) error {
	return process.Signal(syscall.SIGTERM)
}

func configureDetached(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
