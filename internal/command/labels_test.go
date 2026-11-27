package command

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

func TestLabelParseAssignments(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		want    map[string]string
		wantErr string
	}{
		{name: "single pair", values: []string{"team=platform"}, want: map[string]string{"team": "platform"}},
		{name: "multiple pairs", values: []string{"team=platform", "env=ci"}, want: map[string]string{"team": "platform", "env": "ci"}},
		{name: "empty value is allowed", values: []string{"team="}, want: map[string]string{"team": ""}},
		{name: "value keeps additional equals signs", values: []string{"query=a=b"}, want: map[string]string{"query": "a=b"}},
		{name: "duplicate keys keep the last value", values: []string{"env=ci", "env=prod"}, want: map[string]string{"env": "prod"}},
		{name: "no values", values: nil, want: nil},
		{name: "missing equals", values: []string{"env"}, wantErr: "SPEC_INVALID: label must use KEY=VALUE syntax"},
		{name: "empty key", values: []string{"=ci"}, wantErr: "SPEC_INVALID: label key must not be empty"},
		{name: "space in value", values: []string{"env=continuous integration"}, wantErr: "SPEC_INVALID: label value must not contain whitespace"},
		{name: "tab in value", values: []string{"env=ci\tprod"}, wantErr: "SPEC_INVALID: label value must not contain whitespace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLabelAssignments(tc.values)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("labels = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestLabelCreateAndRunReachSDK(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		sandbox := &recordingCreateSandbox{}
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
			return fakeClient{sandbox: sandbox}, nil
		}}
		if code := runner.Run(context.Background(), []string{"create", "--label=team=platform", "--label", "env=ci", "--label", "env=prod", "shell"}); code != 0 {
			t.Fatalf("exit=%d output=%q", code, out.String())
		}
		want := map[string]string{"team": "platform", "env": "prod"}
		if !reflect.DeepEqual(sandbox.request.Labels, want) {
			t.Fatalf("create labels = %#v, want %#v", sandbox.request.Labels, want)
		}
	})

	t.Run("run", func(t *testing.T) {
		workspace := t.TempDir()
		sandboxes := &runSandbox{}
		sessions := &fakeSessions{}
		runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
		if code := runner.Run(context.Background(), []string{"run", "--detach", "--name", "dev", "--label=team=platform", "--label", "env=dev", "--label", "env=ci", "shell", workspace}); code != 0 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
		}
		want := map[string]string{"team": "platform", "env": "ci"}
		if !reflect.DeepEqual(sandboxes.created.Labels, want) {
			t.Fatalf("run labels = %#v, want %#v", sandboxes.created.Labels, want)
		}
	})
}

func TestLabelBadShapeRefusedBeforeRPC(t *testing.T) {
	tests := [][]string{
		{"create", "--label", "env", "shell"},
		{"create", "--label", "=ci", "shell"},
		{"create", "--label", "env=continuous integration", "shell"},
		{"run", "--label", "env", "shell"},
		{"run", "--label", "=ci", "shell"},
		{"run", "--label", "env=continuous integration", "shell"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out bytes.Buffer
			clientCalls := 0
			runner := &Runner{
				Out: &out, Err: &out,
				NewClient: func(string) (sdk.Client, error) {
					clientCalls++
					return fakeClient{}, nil
				},
			}
			if code := runner.Run(context.Background(), args); code != 2 {
				t.Fatalf("%v: exit=%d output=%q", args, code, out.String())
			}
			if clientCalls != 0 {
				t.Fatalf("%v: NewClient called %d times before rejecting the label", args, clientCalls)
			}
			if !strings.Contains(out.String(), "SPEC_INVALID:") {
				t.Fatalf("%v: output %q does not contain SPEC_INVALID: prefix", args, out.String())
			}
		})
	}
}

func TestLabelAfterAgentSeparatorStaysAgentArgument(t *testing.T) {
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "dev", "shell", "--", "--label", "env=ci"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if len(sandboxes.created.Labels) != 0 {
		t.Fatalf("labels after -- were consumed by the CLI: %#v", sandboxes.created.Labels)
	}
	joined := strings.Join(sessions.req.Argv, "\x00")
	if !strings.Contains(joined, "--label\x00env=ci") {
		t.Fatalf("agent argv = %#v, want --label env=ci preserved", sessions.req.Argv)
	}
}

func TestLabelReuseKeepsExistingAndWarns(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, _, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--detach", "--name", "dev", "--label", "env=ci"}); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if sandboxes.createCalls != 0 {
		t.Fatalf("reused sandbox was recreated: %d create calls", sandboxes.createCalls)
	}
	if !strings.Contains(stderr.String(), "keeps its existing labels") {
		t.Fatalf("stderr = %q, want label reuse warning", stderr.String())
	}
}

func TestLabelMachineOutputJSONAndYAMLOnly(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-labeled", Name: "labeled", Agent: "shell", State: sdk.StateRunning,
		Labels: map[string]string{"team": "platform", "env": "ci"},
	}}}

	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"ls", "--format", "json"}); code != 0 {
		t.Fatalf("json exit=%d output=%q", code, out.String())
	}
	var items []sandboxOutput
	if err := json.Unmarshal(out.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	if len(items) != 1 || !reflect.DeepEqual(items[0].Labels, map[string]string{"team": "platform", "env": "ci"}) {
		t.Fatalf("json labels = %#v", items)
	}

	runner, out = lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"ls", "--format", "yaml"}); code != 0 {
		t.Fatalf("yaml exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "labels:") || !strings.Contains(out.String(), "team: platform") {
		t.Fatalf("yaml output lacks labels: %q", out.String())
	}

	runner, out = lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"ls"}); code != 0 {
		t.Fatalf("table exit=%d output=%q", code, out.String())
	}
	if strings.Contains(out.String(), "labels") || strings.Contains(out.String(), "platform") {
		t.Fatalf("table output disclosed labels: %q", out.String())
	}
}

func TestLabelMachineOutputOmitsUnsetLabels(t *testing.T) {
	runner, out := lifecycleRunner(&lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-plain", Name: "plain", State: sdk.StateStopped,
	}}})
	if code := runner.Run(context.Background(), []string{"ls", "--format", "json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Contains(out.String(), `"labels"`) {
		t.Fatalf("unset labels must be omitted: %q", out.String())
	}
}
