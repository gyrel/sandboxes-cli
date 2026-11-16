//go:build windows

package daemonctl

import "fmt"

func socketPeerPID(string) (int, error) {
	return 0, fmt.Errorf("%w: endpoint peer discovery is not supported on Windows", ErrIdentityUnverifiable)
}
