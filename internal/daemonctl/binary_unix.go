//go:build !windows

package daemonctl

import "os"

func daemonBinaryName() string {
	return "sandboxesd"
}

func isExecutableBinary(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}
