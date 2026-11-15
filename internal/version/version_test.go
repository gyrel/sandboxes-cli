package version

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestVersionNotOlderThanLatestChangelogRelease keeps the development fallback
// from silently drifting behind the release train. Release builds inject the
// tag, but local builds report Version, so it must not lag the changelog.
func TestVersionNotOlderThanLatestChangelogRelease(t *testing.T) {
	path := filepath.Join("..", "..", "CHANGELOG.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read changelog: %v", err)
	}
	latest, ok := latestReleasedVersion(string(data))
	if !ok {
		t.Fatalf("no released version heading found in %s", path)
	}
	if compareVersions(Version, latest) < 0 {
		t.Fatalf("version.Version = %q is older than the latest changelog release v%s; bump internal/version/version.go", Version, latest)
	}
}

func latestReleasedVersion(changelog string) (string, bool) {
	for _, line := range strings.Split(changelog, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "## v")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		if isVersion(fields[0]) {
			return fields[0], true
		}
	}
	return "", false
}

func isVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

func compareVersions(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	for i := 0; i < len(leftParts) || i < len(rightParts); i++ {
		var leftValue, rightValue int
		if i < len(leftParts) {
			leftValue, _ = strconv.Atoi(leftParts[i])
		}
		if i < len(rightParts) {
			rightValue, _ = strconv.Atoi(rightParts[i])
		}
		switch {
		case leftValue < rightValue:
			return -1
		case leftValue > rightValue:
			return 1
		}
	}
	return 0
}
