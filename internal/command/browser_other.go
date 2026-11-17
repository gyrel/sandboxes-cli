//go:build !darwin && !linux && !windows

package command

import "errors"

// openBrowser reports that the platform has no browser launcher.
func openBrowser(string) error {
	return errors.New("opening a browser is not supported on this platform")
}
