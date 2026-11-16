//go:build !windows

package daemonctl

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

const endpointDialTimeout = 2 * time.Second

func dialEndpoint(socket string) (*net.UnixConn, error) {
	info, err := os.Lstat(socket)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrEndpointNotRunning
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("%w: %s is not a Unix socket", ErrIdentityUnverifiable, socket)
	}
	dialer := net.Dialer{Timeout: endpointDialTimeout}
	conn, err := dialer.Dial("unix", socket)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) ||
			errors.Is(err, syscall.ENOENT) ||
			errors.Is(err, syscall.ECONNRESET) {
			return nil, ErrEndpointNotRunning
		}
		return nil, err
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: endpoint connection is not a Unix socket", ErrIdentityUnverifiable)
	}
	return unixConn, nil
}
