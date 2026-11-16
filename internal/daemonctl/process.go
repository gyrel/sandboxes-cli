package daemonctl

import "os"

// ProcessInspector proves that a PID still names the process recorded in the
// control file. Implementations must return ErrProcessNotFound when the PID no
// longer exists and any other error when identity cannot be proven.
type ProcessInspector interface {
	StartIdentity(pid int) (string, error)
}

// ProcessCommandInspector is an optional extension used to prove that a live
// endpoint peer is a sandboxesd process when no control record can prove it.
type ProcessCommandInspector interface {
	Command(pid int) (executable string, args []string, err error)
}

// SystemInspector reads process identity from the operating system.
type SystemInspector struct{}

// StartIdentity returns an opaque token that changes whenever a PID is reused.
func (SystemInspector) StartIdentity(pid int) (string, error) {
	return startIdentity(pid)
}

// Command returns the executable path and arguments of a live process.
func (SystemInspector) Command(pid int) (string, []string, error) {
	return processCommand(pid)
}

// CurrentProcessStartID returns the identity token of this process.
func CurrentProcessStartID() (string, error) {
	return startIdentity(os.Getpid())
}
