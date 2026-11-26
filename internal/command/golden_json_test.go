package command

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

var updateGoldenJSON = flag.Bool("update", false, "rewrite testdata golden JSON files")

// assertGoldenJSON compares the decoded JSON so whitespace and field order do
// not matter, while types, field names, omitted fields and array order do.
func assertGoldenJSON(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGoldenJSON {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) // #nosec G304 -- fixed testdata path.
	if err != nil {
		t.Fatalf("read golden %s: %v (run go test -run Golden -update)", name, err)
	}
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("golden %s: output is not JSON: %v\n%s", name, err, got)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("golden %s: fixture is not JSON: %v", name, err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("golden %s mismatch\nwant:\n%s\ngot:\n%s", name, want, got)
	}
}

func TestGoldenPolicyListJSON(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Allow: []sdk.NetworkRule{
			{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443},
			{Protocol: "tcp", Domain: "api.example.com", Port: 8443},
		},
		Deny: []sdk.NetworkRule{{Protocol: "udp", CIDR: "192.0.2.0/24", Port: 53}},
	}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
		return fakeClient{sandbox: sandbox}, nil
	}}
	if code := runner.Run(context.Background(), []string{"policy", "ls", "dev", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	assertGoldenJSON(t, "policy_ls.json", out.Bytes())
}

func TestGoldenPolicyCheckNetworkJSON(t *testing.T) {
	runner, out, _ := newPolicyCheckNetworkRunner(t, sdk.PolicyDecision{
		Allowed: true,
		RuleID:  "rul_internal",
		Reason:  "internal reason",
	})
	if code := runner.Run(context.Background(), []string{"policy", "check", "network", "--sandbox", "dev", "--json", "api.example.com"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	assertGoldenJSON(t, "policy_check_network.json", out.Bytes())
}

func TestGoldenSettingsListJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL validation is not implemented; Load remains fail closed")
	}
	path := filepath.Join(t.TempDir(), "settings.toml")
	t.Setenv("GYREL_SETTINGS_FILE", path)
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"settings", "ls", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	assertGoldenJSON(t, "settings_ls.json", out.Bytes())
}

func TestGoldenDiagnoseJSON(t *testing.T) {
	report := diagnoseReport{
		DaemonVersion: "v0.0.50",
		Sections: []diagnoseSection{
			{Title: "INSTALLATION", Checks: []diagnoseCheck{
				{Name: "CLI binary", Status: diagnosePass, Detail: "/usr/local/bin/rsbx"},
				{Name: "Binary version", Status: diagnosePass, Detail: "v0.0.50"},
			}},
			{Title: "CONNECTION", Checks: []diagnoseCheck{
				{Name: "Daemon", Status: diagnosePass, Detail: "healthy (v0.0.50)"},
				{Name: "Authentication", Status: diagnoseWarn, Detail: "not signed in; run rsbx login to enable registry and account features"},
				{Name: "ZFS offset sync", Status: diagnoseSkip, Detail: "state directory is not on ZFS"},
			}},
		},
	}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if err := runner.renderDiagnose(report, listFormatJSON); err != nil {
		t.Fatal(err)
	}
	assertGoldenJSON(t, "diagnose.json", out.Bytes())
}
