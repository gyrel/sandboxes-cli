package kit

import (
	"reflect"
	"strings"
	"testing"
)

const argValuesKit = `schemaVersion: "3"
kind: mixin
args:
  region:
    env: KIT_REGION
    enum: [eu, us]
    required: true
  tier:
    env: KIT_TIER
    default: basic
    pattern: '^[a-z]+$'
  note:
    description: no delivery
`

func decodeArgValuesKit(t *testing.T, body string) Kit {
	t.Helper()
	doc, err := Decode(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestResolveArgumentValuesAppliesDefaultsAndQualifiedPrecedence(t *testing.T) {
	doc := decodeArgValuesKit(t, argValuesKit)
	values, violations := ResolveArgumentValues(doc, "argkit", "", map[string]string{"region": "eu", "argkit.region": "us"})
	if len(violations) != 0 {
		t.Fatalf("violations = %v", violations)
	}
	if want := map[string]string{"region": "us", "tier": "basic"}; !reflect.DeepEqual(values, want) {
		t.Fatalf("values = %v, want %v", values, want)
	}
}

func TestResolveArgumentValuesReportsViolations(t *testing.T) {
	doc := decodeArgValuesKit(t, argValuesKit)
	tests := []struct {
		name      string
		arguments map[string]string
		want      string
	}{
		{name: "missing required", arguments: map[string]string{}, want: `required kit argument "region" is not set`},
		{name: "enum", arguments: map[string]string{"region": "xx"}, want: `kit argument "region" is not one of its allowed values`},
		{name: "pattern", arguments: map[string]string{"region": "eu", "tier": "BAD"}, want: `kit argument "tier" does not match its pattern`},
		{name: "unknown key", arguments: map[string]string{"region": "eu", "extra": "1"}, want: `kit argument "extra" is not declared by this kit`},
		{name: "other kit", arguments: map[string]string{"region": "eu", "other.region": "us"}, want: `kit argument "other.region" is for kit "other", not this kit`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, violations := ResolveArgumentValues(doc, "argkit", "", tc.arguments)
			if len(violations) != 1 || violations[0].Message != tc.want {
				t.Fatalf("violations = %v, want one %q", violations, tc.want)
			}
		})
	}
}

func TestArgumentEnvironmentEmitsResolvedEnvOnly(t *testing.T) {
	doc := decodeArgValuesKit(t, argValuesKit)
	entries, err := ArgumentEnvironment(doc, map[string]string{"region": "eu", "tier": "basic"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"KIT_REGION=eu", "KIT_TIER=basic"}; !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries = %v, want %v", entries, want)
	}
	entries, err = ArgumentEnvironment(doc, map[string]string{})
	if err != nil || len(entries) != 0 {
		t.Fatalf("unresolved entries = %v err = %v", entries, err)
	}
}

func TestArgumentEnvironmentRefusesBuildAndUnsafeDeclarations(t *testing.T) {
	tests := map[string]struct {
		body string
		want string
	}{
		"buildArg": {
			body: "schemaVersion: \"3\"\nkind: mixin\nargs:\n  version: {buildArg: GH_VERSION}\n",
			want: `kit argument "version" is a build argument; building kits is not implemented`,
		},
		"buildSecret": {
			body: "schemaVersion: \"3\"\nkind: mixin\nargs:\n  token: {buildSecret: id}\n",
			want: `kit argument "token" is a build argument; building kits is not implemented`,
		},
		"duplicate env": {
			body: "schemaVersion: \"3\"\nkind: mixin\nargs:\n  a: {env: SAME, default: x}\n  b: {env: SAME, default: y}\n",
			want: `kit arguments "a" and "b" both set env SAME`,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			doc := decodeArgValuesKit(t, tc.body)
			values, violations := ResolveArgumentValues(doc, "argkit", "", map[string]string{})
			if len(violations) != 0 {
				t.Fatalf("violations = %v", violations)
			}
			if _, err := ArgumentEnvironment(doc, values); err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
