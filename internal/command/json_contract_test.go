package command

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

var (
	contractUUID        = regexp.MustCompile(`\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	contractPrefixedID  = regexp.MustCompile(`\b(?:sb|op)_[A-Za-z0-9]+\b`)
	contractTimestamp   = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b`)
	contractPortPattern = regexp.MustCompile(`("(?:host|host_port|guest|guest_port|sandbox_port)":\s*)[1-9][0-9]*`)
)

// normalizeContractJSON replaces only random identifiers, ports and
// timestamps. Key ordering and every other value stay byte-for-byte intact.
func normalizeContractJSON(input string) string {
	// Git may check the golden fixtures out with CRLF on Windows runners.
	input = strings.ReplaceAll(input, "\r\n", "\n")
	input = contractUUID.ReplaceAllString(input, "<ID>")
	input = contractPrefixedID.ReplaceAllString(input, "<ID>")
	input = contractTimestamp.ReplaceAllString(input, "<TIMESTAMP>")
	return contractPortPattern.ReplaceAllString(input, `${1}<PORT>`)
}

type jsonContractCase struct {
	name   string
	golden string
	run    func(t *testing.T) string
}

func jsonContractCases() []jsonContractCase {
	return []jsonContractCase{
		{name: "ls", golden: "ls.golden.json", run: func(t *testing.T) string {
			runner, out := lifecycleRunner(&lifecycleSandbox{items: contractListSandboxes(t)})
			if code := runner.Run(context.Background(), []string{"ls", "--json"}); code != 0 {
				t.Fatalf("ls exit=%d output=%q", code, out.String())
			}
			return out.String()
		}},
		{name: "rm", golden: "rm.golden.json", run: func(t *testing.T) string {
			sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
				ID: "sb-contract-rm", Name: "matrix-20261115-json", State: sdk.StateStopped,
			}}}
			runner, out := lifecycleRunner(sandbox)
			if code := runner.Run(context.Background(), []string{"rm", "--force", "--json", "matrix-20261115-json"}); code != 0 {
				t.Fatalf("rm exit=%d output=%q", code, out.String())
			}
			return out.String()
		}},
		{name: "stop", golden: "stop.golden.json", run: func(t *testing.T) string {
			sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
				ID: "sb-contract-stop", Name: "matrix-20261115-json", State: sdk.StateRunning,
			}}}
			runner, out := lifecycleRunner(sandbox)
			if code := runner.Run(context.Background(), []string{"stop", "--json", "matrix-20261115-json"}); code != 0 {
				t.Fatalf("stop exit=%d output=%q", code, out.String())
			}
			return out.String()
		}},
		{name: "prune-dry-run", golden: "prune-dry-run.golden.json", run: func(t *testing.T) string {
			runner, out := lifecycleRunner(&lifecycleSandbox{items: contractPruneSandboxes(t)})
			if code := runner.Run(context.Background(), []string{"prune", "--dry-run", "--json"}); code != 0 {
				t.Fatalf("prune --dry-run exit=%d output=%q", code, out.String())
			}
			return out.String()
		}},
		{name: "prune-remove", golden: "prune-remove.golden.json", run: func(t *testing.T) string {
			sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
				ID: "sb-contract-prune", Name: "matrix-20261115-1025", State: sdk.StateStopped,
				StoppedAt: mustContractTime(t, "2026-11-15T06:22:40Z"),
			}}}
			runner, out := lifecycleRunner(sandbox)
			if code := runner.Run(context.Background(), []string{"prune", "--force", "--json"}); code != 0 {
				t.Fatalf("prune --force exit=%d output=%q", code, out.String())
			}
			return out.String()
		}},
	}
}

func contractListSandboxes(t *testing.T) []sdk.Sandbox {
	t.Helper()
	return []sdk.Sandbox{
		{
			ID: "40e3fd21-352c-46a0-9a09-c062c73c54cf", Name: "matrix-20261115-1025", Agent: "codex",
			State: sdk.StateRunning, LastUsedAt: mustContractTime(t, "2026-11-15T06:21:26.307931Z"),
			Workspaces: []sdk.Workspace{{Path: "/private/tmp/rheic-sbx-matrix-20261115/repo"}},
			CreatedAt:  mustContractTime(t, "2026-11-15T06:21:23Z"),
		},
		{
			ID: "fd0c91c4-2eab-44c8-b4c9-e3c11a85935f", Name: "my-sandbox", Agent: "codex",
			State: sdk.StateStopped, LastUsedAt: mustContractTime(t, "2026-10-29T11:34:41.523278Z"),
			Workspaces: []sdk.Workspace{{Path: "/Users/vladimirzikman/Workspace/opensource/sandboxes"}},
			CreatedAt:  mustContractTime(t, "2026-10-28T18:46:01Z"),
		},
	}
}

func contractPruneSandboxes(t *testing.T) []sdk.Sandbox {
	t.Helper()
	return []sdk.Sandbox{
		{
			ID: "sb-contract-1", Name: "matrix-20261115-1025", Agent: "codex", State: sdk.StateStopped,
			StoppedAt:  mustContractTime(t, "2026-11-15T06:22:40Z"),
			Workspaces: []sdk.Workspace{{Path: "/private/tmp/rheic-sbx-matrix-20261115/repo"}},
		},
		{
			ID: "sb-contract-2", Name: "matrix-20261115-1035-prune", Agent: "codex", State: sdk.StateStopped,
			StoppedAt:  mustContractTime(t, "2026-11-15T06:25:08Z"),
			Workspaces: []sdk.Workspace{{Path: "/private/tmp/rheic-sbx-matrix-20261115/repo"}},
		},
		{
			ID: "sb-contract-3", Name: "my-sandbox", Agent: "codex", State: sdk.StateStopped,
			StoppedAt:  mustContractTime(t, "2026-10-29T11:35:11Z"),
			Workspaces: []sdk.Workspace{{Path: "/Users/vladimirzikman/Workspace/opensource/sandboxes"}},
		},
	}
}

func mustContractTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatalf("parse fixture time %q: %v", value, err)
	}
	return parsed
}

func readContractGolden(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "contract", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return string(data)
}

func TestJSONContractsMatchSBXFixtures(t *testing.T) {
	for _, tc := range jsonContractCases() {
		t.Run(tc.name, func(t *testing.T) {
			actual := normalizeContractJSON(tc.run(t))
			want := normalizeContractJSON(readContractGolden(t, tc.golden))
			if actual != want {
				t.Fatalf("JSON contract mismatch\n--- got ---\n%s\n--- want ---\n%s", actual, want)
			}
		})
	}
}

func TestJSONShapeHasNoExtraKeysComparedWithSBXFixture(t *testing.T) {
	for _, tc := range jsonContractCases() {
		t.Run(tc.name, func(t *testing.T) {
			var actual, fixture any
			if err := json.Unmarshal([]byte(tc.run(t)), &actual); err != nil {
				t.Fatalf("unmarshal actual: %v", err)
			}
			if err := json.Unmarshal([]byte(readContractGolden(t, tc.golden)), &fixture); err != nil {
				t.Fatalf("unmarshal golden: %v", err)
			}
			assertNoExtraJSONKeys(t, tc.name, actual, fixture)
		})
	}
}

func assertNoExtraJSONKeys(t *testing.T, path string, actual, fixture any) {
	t.Helper()
	switch expected := fixture.(type) {
	case map[string]any:
		got, ok := actual.(map[string]any)
		if !ok {
			t.Fatalf("%s: got %T, want object", path, actual)
		}
		for key, value := range got {
			expectedValue, exists := expected[key]
			if !exists {
				t.Fatalf("%s: extra key %q (fixture keys: %v)", path, key, sortedJSONKeys(expected))
			}
			assertNoExtraJSONKeys(t, path+"."+key, value, expectedValue)
		}
	case []any:
		got, ok := actual.([]any)
		if !ok {
			t.Fatalf("%s: got %T, want array", path, actual)
		}
		if len(expected) == 0 {
			return
		}
		for i := range got {
			fixtureIndex := i
			if fixtureIndex >= len(expected) {
				fixtureIndex = len(expected) - 1
			}
			assertNoExtraJSONKeys(t, fmt.Sprintf("%s[%d]", path, i), got[i], expected[fixtureIndex])
		}
	default:
		if reflect.TypeOf(actual) != reflect.TypeOf(fixture) {
			t.Fatalf("%s: got type %T, want %T", path, actual, fixture)
		}
	}
}

func sortedJSONKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func TestEmptyMutationJSONIsBareArray(t *testing.T) {
	for _, args := range [][]string{
		{"rm", "--all", "--force", "--json"},
		{"prune", "--force", "--json"},
	} {
		runner, out := lifecycleRunner(&lifecycleSandbox{})
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v exit=%d output=%q", args, code, out.String())
		}
		if strings.TrimSpace(out.String()) != "[]" {
			t.Fatalf("%v empty JSON=%q, want []", args, out.String())
		}
	}
}

func TestPruneDryRunReportsSkippedUnknownStop(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-unknown", Name: "unknown-stop", State: sdk.StateStopped},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "--dry-run", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var report pruneDryRunOutput
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	if len(report.WouldRemove) != 0 {
		t.Fatalf("would_remove=%v", report.WouldRemove)
	}
	if len(report.SkippedUnknownStop) != 1 || report.SkippedUnknownStop[0] != "unknown-stop" {
		t.Fatalf("skipped_unknown_stop=%v", report.SkippedUnknownStop)
	}
	if !strings.Contains(out.String(), `"would_remove": []`) {
		t.Fatalf("empty would_remove must be an array: %q", out.String())
	}
	if len(sandbox.deletes) != 0 {
		t.Fatalf("dry-run deleted %v", sandbox.deletes)
	}
}
