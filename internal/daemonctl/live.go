package daemonctl

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// liveEndpointIdentity proves the identity of the process that owns the
// configured endpoint without relying on the CLI-written control record. The
// socket peer PID is authoritative, and its process-start identifier is
// captured so the supervisor can re-check it immediately before signaling.
//
// A readable control record for this scope is still treated as a constraint:
// if it names the live PID, the start identifier must match; if it names a
// different PID, that process must be gone before the live peer is accepted.
func (s *Supervisor) liveEndpointIdentity() (Record, error) {
	pid, err := s.endpointInspector().PeerPID(s.Scope.Socket)
	if err != nil {
		return Record{}, err
	}
	if pid <= 0 {
		return Record{}, fmt.Errorf("%w: endpoint reported an invalid PID %d", ErrIdentityUnverifiable, pid)
	}
	startID, err := s.Inspector.StartIdentity(pid)
	if err != nil {
		if errors.Is(err, ErrProcessNotFound) {
			return Record{}, fmt.Errorf("%w: endpoint peer PID %d", ErrProcessNotFound, pid)
		}
		return Record{}, fmt.Errorf("%w: endpoint peer PID %d: %w", ErrIdentityUnverifiable, pid, err)
	}
	recordBacked, err := s.checkLiveRecord(pid, startID)
	if err != nil {
		return Record{}, err
	}
	if !recordBacked {
		if err := s.verifyDaemonProcess(pid); err != nil {
			return Record{}, err
		}
	}
	return Record{
		StateDir:       s.Scope.StateDir,
		Socket:         s.Scope.Socket,
		PID:            pid,
		ProcessStartID: startID,
	}, nil
}

func (s *Supervisor) endpointInspector() EndpointInspector {
	if s.EndpointInspector != nil {
		return s.EndpointInspector
	}
	return SystemEndpointInspector{}
}

func (s *Supervisor) checkLiveRecord(pid int, startID string) (bool, error) {
	record, err := ReadRecord(s.Scope.StateDir)
	if errors.Is(err, ErrNoRecord) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrIdentityUnverifiable, err)
	}
	recordState, stateErr := canonicalPath(record.StateDir)
	recordSocket, socketErr := canonicalPath(record.Socket)
	if stateErr != nil || socketErr != nil {
		return false, fmt.Errorf("%w: control record paths are invalid", ErrIdentityUnverifiable)
	}
	if !samePath(recordState, s.Scope.StateDir) || !samePath(recordSocket, s.Scope.Socket) {
		// The record describes another installation; it cannot constrain the
		// live endpoint selected by this scope.
		return false, nil
	}
	if record.PID == pid {
		if record.ProcessStartID != startID {
			return false, fmt.Errorf("%w: PID %d was reused at the endpoint", ErrIdentityMismatch, pid)
		}
		return true, nil
	}
	if _, liveErr := s.Inspector.StartIdentity(record.PID); liveErr == nil {
		return false, fmt.Errorf("%w: control record names PID %d but the endpoint is owned by PID %d", ErrIdentityMismatch, record.PID, pid)
	} else if !errors.Is(liveErr, ErrProcessNotFound) {
		return false, fmt.Errorf("%w: recorded PID %d: %w", ErrIdentityUnverifiable, record.PID, liveErr)
	}
	// The recorded process is gone. The live socket peer is the only daemon
	// that can own this endpoint, so its identity is the one to stop.
	return false, nil
}

func (s *Supervisor) verifyDaemonProcess(pid int) error {
	inspector, ok := s.Inspector.(ProcessCommandInspector)
	if !ok {
		return fmt.Errorf("%w: no process command inspector is available for PID %d", ErrIdentityUnverifiable, pid)
	}
	executable, args, err := inspector.Command(pid)
	if err != nil {
		if errors.Is(err, ErrProcessNotFound) {
			return fmt.Errorf("%w: endpoint peer PID %d", ErrProcessNotFound, pid)
		}
		return fmt.Errorf("%w: endpoint peer PID %d: %w", ErrIdentityUnverifiable, pid, err)
	}
	if daemonInvocation(executable, args, s.Scope.Socket) {
		return nil
	}
	return fmt.Errorf("%w: endpoint PID %d (%s) is not a sandboxesd daemon for %s", ErrIdentityUnverifiable, pid, executable, s.Scope.Socket)
}

func daemonInvocation(executable string, args []string, socket string) bool {
	switch strings.ToLower(filepath.Base(executable)) {
	case "sandboxesd", "sandboxesd.exe":
		return true
	}
	for index, arg := range args {
		switch {
		case arg == "--socket" && index+1 < len(args):
			if sameEndpointPath(args[index+1], socket) {
				return true
			}
		case strings.HasPrefix(arg, "--socket="):
			if sameEndpointPath(strings.TrimPrefix(arg, "--socket="), socket) {
				return true
			}
		}
	}
	return false
}

func sameEndpointPath(left, right string) bool {
	leftPath, leftErr := canonicalPath(left)
	rightPath, rightErr := canonicalPath(right)
	if leftErr == nil && rightErr == nil && samePath(leftPath, rightPath) {
		return true
	}
	resolvedLeft, leftErr := filepath.EvalSymlinks(left)
	resolvedRight, rightErr := filepath.EvalSymlinks(right)
	return leftErr == nil && rightErr == nil && samePath(resolvedLeft, resolvedRight)
}

func (s *Supervisor) verifyStartIdentity(pid int, want string) error {
	current, err := s.Inspector.StartIdentity(pid)
	if err != nil {
		if errors.Is(err, ErrProcessNotFound) {
			return fmt.Errorf("%w: PID %d", ErrProcessNotFound, pid)
		}
		return fmt.Errorf("%w: PID %d: %w", ErrIdentityUnverifiable, pid, err)
	}
	if current != want {
		return fmt.Errorf("%w: PID %d was reused", ErrIdentityMismatch, pid)
	}
	return nil
}
