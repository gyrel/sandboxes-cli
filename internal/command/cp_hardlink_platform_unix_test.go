//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package command

// cpHostSourceCopySupported mirrors the build constraint of cp_hardlink_unix.go:
// host-to-guest cp source opening (with hardlink validation) is implemented on
// these platforms. Tests assert the disclosure note everywhere and the
// platform-specific exit contract (AGENTS.md section 5: enforced or explicitly
// unsupported).
const cpHostSourceCopySupported = true
