//go:build linux

package command

import "os/exec"

// openBrowser opens a URL with the platform browser.
func openBrowser(url string) error {
	return exec.Command("xdg-open", url).Start()
}
