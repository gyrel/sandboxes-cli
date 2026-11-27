//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package command

// cpHostSourceCopySupported mirrors the fail-closed stub in
// cp_hardlink_other.go: host-to-guest cp source opening is explicitly
// unsupported on this platform, so cp must refuse with a typed error after
// emitting the disclosure note.
const cpHostSourceCopySupported = false
