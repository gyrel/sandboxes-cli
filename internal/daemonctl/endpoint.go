package daemonctl

import "errors"

var (
	// ErrEndpointNotRunning means nothing is listening on the daemon endpoint.
	ErrEndpointNotRunning = errors.New("daemon endpoint is not listening")
)

// EndpointInspector discovers the process that owns a local daemon endpoint.
// Implementations must return ErrEndpointNotRunning when the endpoint has no
// listener, and ErrIdentityUnverifiable when ownership cannot be proven.
type EndpointInspector interface {
	PeerPID(socket string) (int, error)
}

// SystemEndpointInspector reads endpoint peer credentials from the operating
// system.
type SystemEndpointInspector struct{}

// PeerPID returns the PID of the process listening on a local daemon endpoint.
func (SystemEndpointInspector) PeerPID(socket string) (int, error) {
	return socketPeerPID(socket)
}
