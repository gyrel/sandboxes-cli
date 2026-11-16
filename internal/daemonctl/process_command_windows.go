//go:build windows

package daemonctl

import "fmt"

func processCommand(int) (string, []string, error) {
	return "", nil, fmt.Errorf("%w: process command lines are unavailable on Windows", ErrIdentityUnverifiable)
}
