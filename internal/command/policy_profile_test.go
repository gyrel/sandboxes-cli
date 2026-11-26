package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

func TestCreatePolicyProfile(t *testing.T) {
	workspace := t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--policy-profile", "allow-all", "--name", "compat", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if sandbox.request.PolicyProfile != "allow-all" || len(sandbox.request.Allow) != 0 {
		t.Fatalf("request=%+v", sandbox.request)
	}
}

func TestRunPolicyProfile(t *testing.T) {
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--policy-profile", "balanced", "--name", "balanced", "shell", t.TempDir()}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.created.PolicyProfile != "balanced" || len(sandboxes.created.Allow) != 0 {
		t.Fatalf("request=%+v", sandboxes.created)
	}
}

func TestPolicyProfileLsFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "ls", args: []string{"ls"}},
		{name: "list alias", args: []string{"list"}},
		{name: "json", args: []string{"ls", "--json"}},
		{name: "yaml format", args: []string{"ls", "--format", "yaml"}},
		{name: "quiet", args: []string{"ls", "-q"}},
		{name: "quiet long", args: []string{"ls", "--quiet"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &policyUpdateClient{profile: "balanced"}
			var out, errOut bytes.Buffer
			runner := &Runner{Out: &out, Err: &errOut, NewClient: func(string) (sdk.Client, error) { return client, nil }}
			code := runner.Run(context.Background(), append([]string{"policy", "profile"}, tc.args...))
			if code != 1 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if out.Len() != 0 {
				t.Fatalf("fail-closed listing wrote stdout=%q", out.String())
			}
			if !strings.Contains(errOut.String(), "governance policy profiles are not available") ||
				!strings.Contains(errOut.String(), "try: rsbx policy profile ls --help") {
				t.Fatalf("stderr=%q", errOut.String())
			}
		})
	}
}

func TestPolicyProfileLsFlagValidation(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		contains string
	}{
		{name: "quiet json", args: []string{"ls", "-q", "--json"}, contains: "cannot be combined"},
		{name: "quiet format", args: []string{"ls", "--quiet", "--format", "table"}, contains: "cannot be combined"},
		{name: "json format", args: []string{"ls", "--json", "--format", "yaml"}, contains: "cannot be combined"},
		{name: "invalid format", args: []string{"ls", "--format", "xml"}, contains: "invalid format"},
		{name: "positional arg", args: []string{"ls", "extra"}, contains: "accepts 0 arg(s), received 1"},
		{name: "unknown flag", args: []string{"ls", "--bogus"}, contains: "unknown flag: --bogus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			runner := &Runner{Out: &out, Err: &errOut, NewClient: func(string) (sdk.Client, error) { return &policyUpdateClient{}, nil }}
			code := runner.Run(context.Background(), append([]string{"policy", "profile"}, tc.args...))
			if code != 1 || !strings.Contains(errOut.String(), tc.contains) {
				t.Fatalf("exit=%d stderr=%q want 1/%q", code, errOut.String(), tc.contains)
			}
		})
	}
}

func TestPolicyProfileHelp(t *testing.T) {
	cases := []struct {
		args []string
		want []string
	}{
		{args: []string{"profile", "--help"}, want: []string{"rsbx policy profile [ls]", "fails closed"}},
		{args: []string{"profile", "ls", "--help"}, want: []string{"rsbx policy profile ls [flags]", "Aliases", "--format", "--json", "-q, --quiet", "fails closed"}},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return &policyUpdateClient{}, nil }}
		if code := runner.Run(context.Background(), append([]string{"policy"}, tc.args...)); code != 0 {
			t.Fatalf("%v exit=%d output=%q", tc.args, code, out.String())
		}
		for _, want := range tc.want {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("%v help missing %q:\n%s", tc.args, want, out.String())
			}
		}
	}
}

func TestPolicyProfileBareShowsGlobalDefault(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return &policyUpdateClient{profile: "allow-all"}, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "profile"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if out.String() != "global: allow-all\nchoices: deny-all, balanced, allow-all\n" {
		t.Fatalf("output=%q", out.String())
	}
}
