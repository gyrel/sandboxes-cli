package command

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestRemoveAcceptsInterspersedFlags(t *testing.T) {
	items := []sdk.Sandbox{
		{ID: "sb-1", Name: "one", State: sdk.StateRunning},
		{ID: "sb-2", Name: "two", State: sdk.StateRunning},
		{ID: "sb-dash", Name: "--force", State: sdk.StateStopped},
	}
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantDelete []string
		wantOps    int
		wantOutput []string
	}{
		{
			name:       "flag before arguments",
			args:       []string{"rm", "--force", "one"},
			wantDelete: []string{"sb-1"},
		},
		{
			name:       "flag after arguments",
			args:       []string{"rm", "one", "--force"},
			wantDelete: []string{"sb-1"},
		},
		{
			name:       "value flag after arguments",
			args:       []string{"rm", "one", "--force", "--format", "json"},
			wantDelete: []string{"sb-1"},
			wantOps:    1,
		},
		{
			name:       "flag between arguments",
			args:       []string{"rm", "one", "--force", "--format", "json", "two"},
			wantDelete: []string{"sb-1", "sb-2"},
			wantOps:    2,
		},
		{
			name:       "terminator keeps flag-like name positional",
			args:       []string{"rm", "--force", "--", "--force"},
			wantDelete: []string{"sb-dash"},
		},
		{
			name:       "unknown flag before arguments still errors",
			args:       []string{"rm", "--bogus", "one"},
			wantCode:   1,
			wantOutput: []string{"error: unknown flag: --bogus", "try: rsbx rm --help"},
		},
		{
			name:       "unknown flag after arguments still errors",
			args:       []string{"rm", "one", "--bogus"},
			wantCode:   1,
			wantOutput: []string{"error: unknown flag: --bogus", "try: rsbx rm --help"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sandbox := &lifecycleSandbox{items: append([]sdk.Sandbox(nil), items...)}
			runner, out := lifecycleRunner(sandbox)
			if code := runner.Run(context.Background(), tt.args); code != tt.wantCode {
				t.Fatalf("exit=%d want=%d output=%q", code, tt.wantCode, out.String())
			}
			if got, want := strings.Join(sandbox.deletes, ","), strings.Join(tt.wantDelete, ","); got != want {
				t.Fatalf("deletes=%q want=%q output=%q", got, want, out.String())
			}
			assertOperationCount(t, out.String(), tt.wantOps)
			assertOutputContains(t, out.String(), tt.wantOutput)
		})
	}
}

func TestLifecycleAcceptsInterspersedFlags(t *testing.T) {
	items := []sdk.Sandbox{
		{ID: "sb-1", Name: "one"},
		{ID: "sb-2", Name: "two"},
		{ID: "sb-dash", Name: "--json"},
	}
	for _, command := range []string{startCommand, stopCommand} {
		t.Run(command, func(t *testing.T) {
			tests := []struct {
				name       string
				args       []string
				wantCode   int
				wantTarget []string
				wantOps    int
				wantOutput []string
			}{
				{
					name:       "flag before arguments",
					args:       []string{command, "--json", "one"},
					wantTarget: []string{"sb-1"},
					wantOps:    1,
				},
				{
					name:       "flag after arguments",
					args:       []string{command, "one", "--json"},
					wantTarget: []string{"sb-1"},
					wantOps:    1,
				},
				{
					name:       "value flag after arguments",
					args:       []string{command, "one", "--format", "json"},
					wantTarget: []string{"sb-1"},
					wantOps:    1,
				},
				{
					name:       "flag between arguments",
					args:       []string{command, "one", "--json", "two"},
					wantTarget: []string{"sb-1", "sb-2"},
					wantOps:    2,
				},
				{
					name:       "value flag between arguments",
					args:       []string{command, "one", "--format", "json", "two"},
					wantTarget: []string{"sb-1", "sb-2"},
					wantOps:    2,
				},
				{
					name:       "terminator keeps flag-like name positional",
					args:       []string{command, "--json", "--", "--json"},
					wantTarget: []string{"sb-dash"},
					wantOps:    1,
				},
				{
					name:       "unknown flag before arguments still errors",
					args:       []string{command, "--bogus", "one"},
					wantCode:   1,
					wantOutput: []string{"error: unknown flag: --bogus", "try: rsbx " + command + " --help"},
				},
				{
					name:       "unknown flag after arguments still errors",
					args:       []string{command, "one", "--bogus"},
					wantCode:   1,
					wantOutput: []string{"error: unknown flag: --bogus", "try: rsbx " + command + " --help"},
				},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					sandbox := &lifecycleSandbox{items: append([]sdk.Sandbox(nil), items...)}
					runner, out := lifecycleRunner(sandbox)
					if code := runner.Run(context.Background(), tt.args); code != tt.wantCode {
						t.Fatalf("exit=%d want=%d output=%q", code, tt.wantCode, out.String())
					}
					targets := sandbox.starts
					if command == stopCommand {
						targets = sandbox.stops
					}
					if got, want := strings.Join(targets, ","), strings.Join(tt.wantTarget, ","); got != want {
						t.Fatalf("targets=%q want=%q output=%q", got, want, out.String())
					}
					assertOperationCount(t, out.String(), tt.wantOps)
					assertOutputContains(t, out.String(), tt.wantOutput)
				})
			}
		})
	}
}

func TestListAcceptsInterspersedFlags(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantOutput []string
	}{
		{
			name:       "flag before arguments",
			args:       []string{"ls", "--json"},
			wantOutput: []string{`"name": "one"`},
		},
		{
			name:       "positional rejected with trailing flag",
			args:       []string{"ls", "stray", "--json"},
			wantCode:   2,
			wantOutput: []string{"usage: rsbx ls"},
		},
		{
			name:       "positional rejected with middle flag",
			args:       []string{"ls", "stray", "--json", "other"},
			wantCode:   2,
			wantOutput: []string{"usage: rsbx ls"},
		},
		{
			name:       "terminator keeps flag-like positional",
			args:       []string{"ls", "--", "--json"},
			wantCode:   2,
			wantOutput: []string{"usage: rsbx ls"},
		},
		{
			name:       "unknown flag before arguments still errors",
			args:       []string{"ls", "--bogus"},
			wantCode:   1,
			wantOutput: []string{"error: unknown flag: --bogus", "try: rsbx ls --help"},
		},
		{
			name:       "unknown flag after positional still errors",
			args:       []string{"ls", "stray", "--bogus"},
			wantCode:   1,
			wantOutput: []string{"error: unknown flag: --bogus", "try: rsbx ls --help"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, out := listRunner(twoSandbox{})
			if code := runner.Run(context.Background(), tt.args); code != tt.wantCode {
				t.Fatalf("exit=%d want=%d output=%q", code, tt.wantCode, out.String())
			}
			assertOutputContains(t, out.String(), tt.wantOutput)
		})
	}
}

func TestGetAcceptsInterspersedFlagsAndTerminator(t *testing.T) {
	items := []sdk.Sandbox{
		{ID: "sb-1", Name: "one"},
		{ID: "sb-dash", Name: "--help"},
	}
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantOutput []string
	}{
		{
			name:       "flag before arguments",
			args:       []string{"get", "--help"},
			wantOutput: []string{"usage: rsbx get SANDBOX"},
		},
		{
			name:       "flag after arguments",
			args:       []string{"get", "one", "--help"},
			wantOutput: []string{"usage: rsbx get SANDBOX"},
		},
		{
			name:       "flag between arguments",
			args:       []string{"get", "one", "--help", "two"},
			wantOutput: []string{"usage: rsbx get SANDBOX"},
		},
		{
			name:       "terminator keeps flag-like name positional",
			args:       []string{"get", "--", "--help"},
			wantOutput: []string{"id: sb-dash"},
		},
		{
			name:       "unknown flag before arguments still errors",
			args:       []string{"get", "--bogus", "one"},
			wantCode:   1,
			wantOutput: []string{"error: unknown flag: --bogus", "try: rsbx get --help"},
		},
		{
			name:       "unknown flag after arguments still errors",
			args:       []string{"get", "one", "--bogus"},
			wantCode:   1,
			wantOutput: []string{"error: unknown flag: --bogus", "try: rsbx get --help"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sandbox := &lifecycleSandbox{items: append([]sdk.Sandbox(nil), items...)}
			runner, out := lifecycleRunner(sandbox)
			if code := runner.Run(context.Background(), tt.args); code != tt.wantCode {
				t.Fatalf("exit=%d want=%d output=%q", code, tt.wantCode, out.String())
			}
			assertOutputContains(t, out.String(), tt.wantOutput)
		})
	}
}

func TestHelpTextShowsBothFlagPositions(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "rm",
			args: []string{"rm", "--help"},
			want: []string{"rsbx rm --force api", "rsbx rm api --force"},
		},
		{
			name: "start",
			args: []string{"start", "--help"},
			want: []string{"rsbx start --format json api", "rsbx start api --format json"},
		},
		{
			name: "stop",
			args: []string{"stop", "--help"},
			want: []string{"rsbx stop --format json api", "rsbx stop api --format json"},
		},
		{
			name: "ls",
			args: []string{"ls", "--help"},
			want: []string{"rsbx ls --json", "rsbx ls --limit 10 --format yaml"},
		},
		{
			name: "get",
			args: []string{"get", "--help"},
			want: []string{"rsbx get -- --literal-name"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, out := lifecycleRunner(&lifecycleSandbox{})
			if code := runner.Run(context.Background(), tt.args); code != 0 {
				t.Fatalf("exit=%d output=%q", code, out.String())
			}
			assertOutputContains(t, out.String(), tt.want)
		})
	}
}

func assertOperationCount(t *testing.T, output string, want int) {
	t.Helper()
	trimmed := strings.TrimSpace(output)
	if !strings.HasPrefix(trimmed, "[") {
		if want > 0 {
			t.Fatalf("operations=%d want=%d but output is not JSON: %q", 0, want, output)
		}
		return
	}
	var operations []operationOutput
	if err := json.Unmarshal([]byte(trimmed), &operations); err != nil {
		t.Fatalf("invalid operation JSON %q: %v", output, err)
	}
	if len(operations) != want {
		t.Fatalf("operations=%d want=%d output=%q", len(operations), want, output)
	}
}

func assertOutputContains(t *testing.T, output string, wants []string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(output, want) {
			t.Fatalf("output lacks %q: %q", want, output)
		}
	}
}
