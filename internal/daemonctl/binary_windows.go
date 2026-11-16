//go:build windows

package daemonctl

import "os"

func daemonBinaryName() string {
	return "sandboxesd.exe"
}

func isExecutableBinary(info os.FileInfo) bool {
	return info.Mode().IsRegular()
}
