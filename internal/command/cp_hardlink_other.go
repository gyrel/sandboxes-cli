//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package command

import (
	"errors"
	"os"
)

// hostSourceCopySupported is false wherever safe source opening is a
// fail-closed stub: host-to-guest cp must refuse before opening any exec
// session, so a refusal never leaves session state behind.
const hostSourceCopySupported = false

func rejectCopyHardlink(_ os.FileInfo) error {
	return errors.New("source hard link validation is unsupported on this platform")
}

func openCopySource(_ *os.Root, _ string) (*os.File, error) {
	return nil, errors.New("safe source opening is unsupported on this platform")
}

func openCopyPath(_ string) (*os.File, error) {
	return nil, errors.New("safe source opening is unsupported on this platform")
}
