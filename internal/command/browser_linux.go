//go:build linux

package command

import (
	"errors"
	"os/exec"
	"strings"
)

// openBrowser opens a URL with the platform browser. The URL is the provider
// verification page printed by the daemon, never a guest or user argument.
func openBrowser(url string) error {
	if !strings.HasPrefix(url, "https://") {
		return errors.New("refusing to open a non-HTTPS browser URL")
	}
	//nolint:gosec // G204: the argument is a validated HTTPS provider URL.
	return exec.Command("xdg-open", url).Start()
}
