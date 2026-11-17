//go:build windows

package command

import "os/exec"

// openBrowser opens a URL with the platform browser.
func openBrowser(url string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}
