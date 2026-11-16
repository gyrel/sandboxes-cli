//go:build !windows && !linux && !darwin

package daemonctl

import "fmt"

func socketPeerPID(string) (int, error) {
	return 0, fmt.Errorf("%w: endpoint peer discovery is not supported on this platform", ErrIdentityUnverifiable)
}
