package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

// runtimeProbeSandbox models a daemon that persists Start before discovering
// whether a runtime can back it. The CLI probe must detect the unsupported
// runtime and restore the stopped state instead of reporting success.
type runtimeProbeSandbox struct {
	lifecycleSandbox
	state     string
	execErr   error
	execCalls int
}

func (s *runtimeProbeSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: s.state}}}, nil
}

func (s *runtimeProbeSandbox) Get(context.Context, string) (*sdk.Sandbox, error) {
	return &sdk.Sandbox{ID: "sb-1", Name: "dev", State: s.state}, nil
}

func (s *runtimeProbeSandbox) Start(_ context.Context, id string) (*sdk.Operation, error) {
	s.starts = append(s.starts, id)
	s.state = sdk.StateRunning
	return &sdk.Operation{ID: "op-start", Kind: "start", State: sdk.StateDone}, nil
}

func (s *runtimeProbeSandbox) Stop(_ context.Context, id string, _ sdk.StopOptions) (*sdk.Operation, error) {
	s.stops = append(s.stops, id)
	s.state = sdk.StateStopped
	return &sdk.Operation{ID: "op-stop", Kind: "stop", State: sdk.StateDone}, nil
}

type probeClient struct {
	fakeClient
	executor sdk.Executor
}

func (c probeClient) Executor() sdk.Executor { return c.executor }

type probeExecutor struct{ sandbox *runtimeProbeSandbox }

func (e probeExecutor) Exec(context.Context, sdk.ExecRequest) (int, error) {
	e.sandbox.execCalls++
	return 0, e.sandbox.execErr
}

func TestStartFailsClosedWithoutRuntimeAndRestoresState(t *testing.T) {
	tests := []struct {
		name      string
		execErr   error
		wantCode  int
		wantState string
		wantStops int
		wantOut   []string
		wantErr   []string
	}{
		{
			name:      "state-only daemon fails and restores stopped",
			execErr:   &sdk.Error{Code: "conflict", Message: "runtime does not support exec"},
			wantCode:  1,
			wantState: sdk.StateStopped,
			wantStops: 1,
			wantErr:   []string{"cannot start sandbox dev", "daemon has no runtime backend", "restored to stopped"},
		},
		{
			name:      "runtime-backed start succeeds",
			wantCode:  0,
			wantState: sdk.StateRunning,
			wantOut:   []string{"Started sandbox dev"},
		},
		{
			name:      "non-runtime probe errors do not fail a backed start",
			execErr:   errors.New("guest probe command failed"),
			wantCode:  0,
			wantState: sdk.StateRunning,
			wantOut:   []string{"Started sandbox dev"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sandbox := &runtimeProbeSandbox{state: sdk.StateStopped, execErr: tt.execErr}
			var stdout, stderr bytes.Buffer
			runner := &Runner{
				Out: &stdout, Err: &stderr, In: strings.NewReader(""),
				NewClient: func(string) (sdk.Client, error) {
					return probeClient{fakeClient: fakeClient{sandbox: sandbox}, executor: probeExecutor{sandbox: sandbox}}, nil
				},
			}
			if code := runner.Run(context.Background(), []string{"start", "dev"}); code != tt.wantCode {
				t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", code, tt.wantCode, stdout.String(), stderr.String())
			}
			if sandbox.state != tt.wantState {
				t.Fatalf("state=%q want=%q stdout=%q stderr=%q", sandbox.state, tt.wantState, stdout.String(), stderr.String())
			}
			if len(sandbox.stops) != tt.wantStops {
				t.Fatalf("stop calls=%v want=%d", sandbox.stops, tt.wantStops)
			}
			if sandbox.execCalls != 1 {
				t.Fatalf("exec probes=%d want=1", sandbox.execCalls)
			}
			assertOutputContains(t, stdout.String(), tt.wantOut)
			assertOutputContains(t, stderr.String(), tt.wantErr)
			if tt.wantCode != 0 && strings.Contains(stdout.String(), "Started sandbox") {
				t.Fatalf("failed start reported success: %q", stdout.String())
			}
		})
	}
}

func TestStartWithoutExecCapabilityKeepsWorking(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"start", "dev"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "Started sandbox dev") {
		t.Fatalf("missing success output: %q", out.String())
	}
}

func TestGetOutputFormats(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout []string
		wantStderr []string
		wantJSON   bool
		wantYAML   bool
		wantCall   bool
	}{
		{
			name:       "help long flag",
			args:       []string{"get", "--help"},
			wantStdout: []string{"usage: rsbx get", "Docker sbx has no", "get command", "--format table|json|yaml"},
		},
		{
			name:       "help short flag",
			args:       []string{"get", "-h"},
			wantStdout: []string{"usage: rsbx get", "Rheic extension"},
		},
		{
			name:       "help after positional",
			args:       []string{"get", "dev", "--help"},
			wantStdout: []string{"usage: rsbx get", "--json"},
		},
		{
			name:       "table block",
			args:       []string{"get", "dev"},
			wantStdout: []string{"id: sb-1", "name: dev", "state: stopped", "cpus:", "created:", "updated:"},
			wantCall:   true,
		},
		{
			name:       "json shorthand",
			args:       []string{"get", "dev", "--json"},
			wantJSON:   true,
			wantStdout: []string{`"name": "dev"`},
			wantCall:   true,
		},
		{
			name:       "json format before name",
			args:       []string{"get", "--format", "json", "dev"},
			wantJSON:   true,
			wantStdout: []string{`"status": "stopped"`},
			wantCall:   true,
		},
		{
			name:       "json format after name",
			args:       []string{"get", "dev", "--format=json"},
			wantJSON:   true,
			wantStdout: []string{`"id": "sb-1"`},
			wantCall:   true,
		},
		{
			name:       "yaml format",
			args:       []string{"get", "--format", "yaml", "dev"},
			wantYAML:   true,
			wantStdout: []string{"name: dev", "status: stopped"},
			wantCall:   true,
		},
		{
			name:       "unknown flag uses shared error path",
			args:       []string{"get", "dev", "--bogus"},
			wantCode:   1,
			wantStderr: []string{"error: unknown flag: --bogus", "try: rsbx get --help"},
		},
		{
			name:       "missing argument is usage error",
			args:       []string{"get"},
			wantCode:   2,
			wantStderr: []string{"usage: rsbx get", "SANDBOX"},
		},
		{
			name:       "extra argument is usage error",
			args:       []string{"get", "dev", "extra"},
			wantCode:   2,
			wantStderr: []string{"usage: rsbx get"},
		},
		{
			name:       "invalid format",
			args:       []string{"get", "--format", "xml", "dev"},
			wantCode:   2,
			wantStderr: []string{`invalid format "xml"; use table, json or yaml`},
		},
		{
			name:       "json and explicit format conflict",
			args:       []string{"get", "--json", "--format", "yaml", "dev"},
			wantCode:   2,
			wantStderr: []string{"--json cannot be combined with an explicit --format"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			var stdout, stderr bytes.Buffer
			runner := &Runner{
				Out: &stdout, Err: &stderr, In: strings.NewReader(""),
				NewClient: func(string) (sdk.Client, error) {
					called = true
					return fakeClient{}, nil
				},
			}
			if code := runner.Run(context.Background(), tt.args); code != tt.wantCode {
				t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", code, tt.wantCode, stdout.String(), stderr.String())
			}
			if called != tt.wantCall {
				t.Fatalf("client called=%t want=%t", called, tt.wantCall)
			}
			assertOutputContains(t, stdout.String(), tt.wantStdout)
			assertOutputContains(t, stderr.String(), tt.wantStderr)
			if tt.wantJSON {
				var out sandboxOutput
				if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
					t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
				}
				if out.Name != "dev" || out.ID != "sb-1" || out.Status != sdk.StateStopped {
					t.Fatalf("unexpected JSON: %#v", out)
				}
			}
			if tt.wantYAML && !strings.Contains(stdout.String(), "status: stopped") {
				t.Fatalf("unexpected YAML: %q", stdout.String())
			}
		})
	}
}

func TestGetTreatsTerminatorAsLiteralName(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-dash", Name: "--json", State: sdk.StateStopped}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"get", "--", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "id: sb-dash") {
		t.Fatalf("literal name was not resolved: %q", out.String())
	}
}
