package command

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

func newFamilyPolicyCheckRunner(sandbox sdk.SandboxService) (*Runner, *bytes.Buffer, *bytes.Buffer, *policyCheckNetworkRecorder) {
	recorder := &policyCheckNetworkRecorder{decision: sdk.PolicyDecision{Allowed: true, RuleID: "rul_net", Reason: "allow rule"}}
	var stdout, stderr bytes.Buffer
	runner := &Runner{Out: &stdout, Err: &stderr, NewClient: func(string) (sdk.Client, error) {
		return policyCheckNetworkClient{fakeClient: fakeClient{sandbox: sandbox}, recorder: recorder}, nil
	}}
	return runner, &stdout, &stderr, recorder
}

func TestFamilyArgumentsPreserveFlagLikePolicyValues(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		sandbox     *lifecycleSandbox
		wantID      string
		wantAddress string
		wantDomain  string
		wantDebug   bool
	}{
		{
			name:       "sandbox value",
			args:       []string{"policy", "check", "network", "--sandbox", "--debug", "example"},
			sandbox:    &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-debug", Name: "--debug", State: sdk.StateRunning}}},
			wantID:     "sb-debug",
			wantDomain: "example",
		},
		{
			name:        "terminator keeps target",
			args:        []string{"policy", "check", "network", "--sandbox", "dev", "--", "192.0.2.1"},
			sandbox:     &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: sdk.StateRunning}}},
			wantID:      "sb-1",
			wantAddress: "192.0.2.1",
		},
		{
			name:       "debug after child command",
			args:       []string{"policy", "check", "network", "--sandbox", "dev", "--debug", "example"},
			sandbox:    &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: sdk.StateRunning}}},
			wantID:     "sb-1",
			wantDomain: "example",
			wantDebug:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, out, stderr, recorder := newFamilyPolicyCheckRunner(tt.sandbox)
			if code := runner.Run(context.Background(), tt.args); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			if len(recorder.calls) != 1 {
				t.Fatalf("calls=%+v", recorder.calls)
			}
			call := recorder.calls[0]
			if call.ID != tt.wantID || call.Address != tt.wantAddress || call.Domain != tt.wantDomain || call.Port != 443 {
				t.Fatalf("call=%+v want id=%q address=%q domain=%q port=443", call, tt.wantID, tt.wantAddress, tt.wantDomain)
			}
			if runner.Debug != tt.wantDebug {
				t.Fatalf("debug=%t want=%t stderr=%q", runner.Debug, tt.wantDebug, stderr.String())
			}
			if !tt.wantDebug && strings.Contains(stderr.String(), "level=DEBUG") {
				t.Fatalf("debug-like value enabled logging: %q", stderr.String())
			}
		})
	}
}

func TestFamilyArgumentsPreserveFlagLikeSecretValues(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantToken string
		wantDebug bool
	}{
		{
			name:      "token value",
			args:      []string{"secret", "set", "--token", "--debug", "github"},
			wantToken: "--debug",
		},
		{
			name:      "terminator after token value",
			args:      []string{"secret", "set", "--token", "--debug", "--", "github"},
			wantToken: "--debug",
		},
		{
			name:      "debug after child command",
			args:      []string{"secret", "set", "--token", "synthetic-token", "github", "--debug"},
			wantToken: "synthetic-token",
			wantDebug: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets := &fakeServiceSecrets{}
			var out, stderr bytes.Buffer
			runner := &Runner{Out: &out, Err: &stderr, In: strings.NewReader(""), NewClient: func(string) (sdk.Client, error) {
				return fakeClient{secrets: secrets}, nil
			}}
			if code := runner.Run(context.Background(), tt.args); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			if secrets.service != "github" || string(secrets.value) != tt.wantToken {
				t.Fatalf("stored service=%q value=%q want=%q", secrets.service, secrets.value, tt.wantToken)
			}
			if runner.Debug != tt.wantDebug {
				t.Fatalf("debug=%t want=%t stderr=%q", runner.Debug, tt.wantDebug, stderr.String())
			}
			if !tt.wantDebug && strings.Contains(stderr.String(), "level=DEBUG") {
				t.Fatalf("debug-like value enabled logging: %q", stderr.String())
			}
		})
	}
}

func TestPrepareFamilyArgsOnlyScansBeforeSubcommand(t *testing.T) {
	families := []string{
		policyCommand, secretCommand, envCommand, mcpCommand,
		settingsCommand, kitCommand, daemonCommand, templateCommand, skillsCommand,
	}
	for _, family := range families {
		t.Run(family, func(t *testing.T) {
			runner := &Runner{}
			args := []string{"--debug", "--socket", "synthetic.sock", "child", "--child-flag", "--debug", "value", "--", "--debug"}
			got, code, done := runner.prepareFamilyArgs(family, args)
			if done || code != 0 {
				t.Fatalf("done=%t code=%d", done, code)
			}
			want := []string{"child", "--child-flag", "--debug", "value", "--", "--debug"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("args=%q want=%q", got, want)
			}
			if !runner.Debug || runner.Socket != "synthetic.sock" {
				t.Fatalf("debug=%t socket=%q", runner.Debug, runner.Socket)
			}
		})
	}
}
