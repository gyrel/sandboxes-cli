package kit

import (
	"archive/zip"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

const legacySpec = "apiVersion: rheic.dev/v1alpha1\nkind: Kit\nmetadata:\n  name: legacy-kit\nspec:\n  agent: shell\n"

func TestDecodeAcceptsLegacyAPIVersion(t *testing.T) {
	t.Cleanup(ResetDeprecations)
	ResetDeprecations()
	doc, err := Decode(strings.NewReader(legacySpec))
	if err != nil {
		t.Fatalf("legacy kit rejected: %v", err)
	}
	if doc.APIVersion != APIVersion {
		t.Fatalf("legacy apiVersion not normalized: got %q want %q", doc.APIVersion, APIVersion)
	}
	if got := ConsumeDeprecations(); got != LegacyAPIVersionWarning {
		t.Fatalf("deprecation warning = %q, want %q", got, LegacyAPIVersionWarning)
	}
	if got := ConsumeDeprecations(); got != "" {
		t.Fatalf("deprecation warning emitted twice: %q", got)
	}
}

func TestDecodeCurrentAPIVersionUnaffected(t *testing.T) {
	ResetDeprecations()
	doc, err := Decode(strings.NewReader(goodSpec))
	if err != nil {
		t.Fatal(err)
	}
	if doc.APIVersion != APIVersion {
		t.Fatalf("current apiVersion changed: %q", doc.APIVersion)
	}
	if got := ConsumeDeprecations(); got != "" {
		t.Fatalf("current apiVersion triggered a warning: %q", got)
	}
}

func TestValidateAcceptsLegacyAPIVersion(t *testing.T) {
	if err := (Kit{APIVersion: APIVersionLegacy, Kind: "Kit", Metadata: Metadata{Name: "legacy"}, Spec: Spec{Agent: "shell"}}).Validate(); err != nil {
		t.Fatalf("legacy apiVersion rejected by Validate: %v", err)
	}
}

func TestDecodeRejectsUnknownAPIVersion(t *testing.T) {
	ResetDeprecations()
	for _, apiVersion := range []string{"example.dev/v9", "v1", ""} {
		body := "apiVersion: " + apiVersion + "\nkind: Kit\nmetadata: {name: x}\nspec: {agent: shell}\n"
		if _, err := Decode(strings.NewReader(body)); err == nil {
			t.Fatalf("accepted unknown apiVersion %q", apiVersion)
		}
	}
	if got := ConsumeDeprecations(); got != "" {
		t.Fatalf("unknown apiVersion triggered a warning: %q", got)
	}
}

func TestPackNormalizesLegacyAPIVersion(t *testing.T) {
	root := newKitDir(t, "legacy-kit", map[string]string{"spec.yaml": legacySpec})
	output := filepath.Join(t.TempDir(), "legacy.zip")
	if _, err := Pack(root, output); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	var packedSpec []byte
	for _, file := range reader.File {
		if file.Name != kitSpecFile {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		packedSpec, err = io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if packedSpec == nil {
		t.Fatal("packed archive has no spec.yaml")
	}
	text := string(packedSpec)
	if strings.Contains(text, APIVersionLegacy) {
		t.Fatalf("packed spec still carries legacy apiVersion: %q", text)
	}
	if !strings.Contains(text, "apiVersion: "+APIVersion) {
		t.Fatalf("packed spec missing current apiVersion: %q", text)
	}
}
