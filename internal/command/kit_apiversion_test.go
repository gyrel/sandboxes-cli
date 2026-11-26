package command

import (
	"path/filepath"
	"strings"
	"testing"
)

const kitLegacySpec = "apiVersion: rheic.dev/v1alpha1\nkind: Kit\nmetadata:\n  name: legacy-kit\nspec:\n  agent: shell\n"

const kitLegacyWarning = "warning: apiVersion rheic.dev/v1alpha1 is deprecated; repack with gyrel.dev/v1alpha1"

func TestKitValidateLegacyAPIVersionWarns(t *testing.T) {
	legacy := writeKitArtifact(t, filepath.Join(t.TempDir(), "legacy-kit"), map[string]string{"spec.yaml": kitLegacySpec})
	good, _ := kitFixtures(t)

	code, stdout, stderr := runKitArtifact(t, "validate", legacy, "--offline")
	if code != 0 || !strings.Contains(stdout, "Validated kit legacy-kit") {
		t.Fatalf("legacy validate code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, kitLegacyWarning) {
		t.Fatalf("legacy validate stderr=%q", stderr)
	}

	code, _, stderr = runKitArtifact(t, "validate", good, "--offline")
	if code != 0 {
		t.Fatalf("current validate code=%d stderr=%q", code, stderr)
	}
	if strings.Contains(stderr, kitLegacyWarning) {
		t.Fatalf("current apiVersion warned: %q", stderr)
	}
}

func TestKitPackLegacyAPIVersionWarnsAndNormalizes(t *testing.T) {
	legacy := writeKitArtifact(t, filepath.Join(t.TempDir(), "legacy-kit"), map[string]string{"spec.yaml": kitLegacySpec})
	output := filepath.Join(t.TempDir(), "legacy.zip")
	code, stdout, stderr := runKitArtifact(t, "pack", legacy, "-o", output)
	if code != 0 || !strings.Contains(stdout, "Packed kit legacy-kit to") {
		t.Fatalf("legacy pack code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, kitLegacyWarning) {
		t.Fatalf("legacy pack stderr=%q", stderr)
	}
	// The packed archive is a new output: re-validating it must not warn again.
	code, _, stderr = runKitArtifact(t, "validate", output, "--offline")
	if code != 0 {
		t.Fatalf("packed validate code=%d stderr=%q", code, stderr)
	}
	if strings.Contains(stderr, kitLegacyWarning) {
		t.Fatalf("packed legacy kit warned again: %q", stderr)
	}
}

func TestKitListLegacyAPIVersionWarnsOnce(t *testing.T) {
	dir := t.TempDir()
	writeKitArtifact(t, dir, map[string]string{
		"a.yaml": kitLegacySpec,
		"b.yaml": kitLegacySpec,
	})
	code, _, stderr := runKitArtifact(t, "ls", dir)
	if code != 0 {
		t.Fatalf("kit ls code=%d stderr=%q", code, stderr)
	}
	if got := strings.Count(stderr, "apiVersion rheic.dev/v1alpha1 is deprecated"); got != 1 {
		t.Fatalf("warning count=%d want 1: %q", got, stderr)
	}
}
