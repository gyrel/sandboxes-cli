//go:build windows

package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const orgPolicyPipePrefix = `\\.\pipe\rheic-sandboxesd-`

// orgPolicyEndpoint mirrors the SDK's local pipe derivation so the direct
// org-policy client reaches the same access-controlled daemon pipe.
func orgPolicyEndpoint(address string) (string, orgPolicyEndpointFunc, error) {
	pipe, err := orgPolicyPipePath(address)
	if err != nil {
		return "", nil, err
	}
	return "passthrough:///local-daemon", func(ctx context.Context, _ string) (net.Conn, error) {
		return winio.DialPipeContext(ctx, pipe)
	}, nil
}

func orgPolicyPipePath(address string) (string, error) {
	if strings.HasPrefix(strings.ToLower(address), strings.ToLower(`\\.\pipe\`)) {
		return address, nil
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read current user SID: %w", err)
	}
	identity := user.User.Sid.String() + "\x00" + strings.ToLower(filepath.Clean(address))
	sum := sha256.Sum256([]byte(identity))
	return orgPolicyPipePrefix + hex.EncodeToString(sum[:16]), nil
}
