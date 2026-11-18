// Package version exposes the CLI build version.
package version

// Version is the current build version. Release builds inject the tag; keep
// this fallback at the version of the current release train.
var Version = "0.0.62"

// Commit is the source revision of the build, injected via -ldflags.
var Commit string
