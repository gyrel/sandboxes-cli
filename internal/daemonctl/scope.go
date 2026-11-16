package daemonctl

import (
	"errors"
	"path/filepath"
)

// ScopeForSocket derives the installation scope from the configured socket.
// The daemon writes its control files beside the socket, so a caller only
// needs --socket to identify the installation it intends to control.
func ScopeForSocket(socket string) (Scope, error) {
	if socket == "" {
		return Scope{}, errors.New("daemon socket path is empty")
	}
	stateDir, err := stateDirForSocket(socket)
	if err != nil {
		return Scope{}, err
	}
	return (Scope{StateDir: stateDir, Socket: socket}).Canonical()
}

// LogPath returns the daemon log file used by detached starts and status.
func LogPath(scope Scope) string {
	return filepath.Join(scope.StateDir, "daemon.log")
}
