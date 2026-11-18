package command

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
	"github.com/rheic/slogx"
)

type debugSandbox struct {
	fakeSandbox
	name string
}

func (s debugSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{ID: "sb-1", Name: s.name, State: sdk.StateRunning}}}, nil
}

type debugExecClient struct {
	fakeClient
	executor sdk.Executor
	name     string
}

func (c debugExecClient) Executor() sdk.Executor { return c.executor }

func (c debugExecClient) Sandboxes() sdk.SandboxService {
	return debugSandbox{name: c.name}
}

type failingExecutor struct {
	request sdk.ExecRequest
	err     error
}

func (e *failingExecutor) Exec(_ context.Context, req sdk.ExecRequest) (int, error) {
	e.request = req
	return 0, e.err
}

func debugOnly(stderr string) string {
	var out strings.Builder
	for _, line := range strings.Split(stderr, "\n") {
		if strings.Contains(line, "level=DEBUG") {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

func requireQuiet(t *testing.T, stderr *bytes.Buffer) {
	t.Helper()
	if stderr.Len() != 0 {
		t.Fatalf("stderr must be quiet without --debug: %q", stderr.String())
	}
}

func TestDebugLoggingIsQuietWithoutFlag(t *testing.T) {
	executor := &recordingExecutor{}
	runner, out, stderr := runTestRunner(t, debugExecClient{executor: executor, name: "sandbox-canary"}, "")
	args := []string{"exec", "--workdir", "/Users/canary/work", "--env", "TOKEN=secret-canary", "sandbox-canary", "cat", "/etc/passwd"}
	if code := runner.Run(context.Background(), args); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	requireQuiet(t, stderr)
	if runner.Debug {
		t.Fatal("debug was enabled without --debug")
	}
}

func TestDebugLogsUsefulExecEventsWithoutValues(t *testing.T) {
	executor := &recordingExecutor{}
	runner, out, stderr := runTestRunner(t, debugExecClient{executor: executor, name: "sandbox-canary"}, "")
	args := []string{
		"--debug", "exec", "--workdir", "/Users/alice/secret",
		"--env", "TOKEN=secret-canary", "--user", "alice",
		"sandbox-canary", "--", "cat", "/etc/passwd", "--token=canary-argument",
	}
	if code := runner.Run(context.Background(), args); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	wantArgv := []string{"cat", "/etc/passwd", "--token=canary-argument"}
	if !reflect.DeepEqual(executor.request.Argv, wantArgv) || executor.request.Workdir != "/Users/alice/secret" {
		t.Fatalf("unexpected request: %#v", executor.request)
	}
	for _, want := range []string{
		"msg=command.start command=exec",
		"msg=exec.prepare",
		"has_workdir=true",
		"user_set=true",
		"env_count=1",
		"msg=client.connect",
		"msg=exec.sandbox",
		"msg=exec.finish",
		"result=ok",
		"msg=command.finish command=exec",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr lacks %q: %q", want, stderr.String())
		}
	}
	for _, forbidden := range []string{
		"alice", "/Users", "secret-canary", "TOKEN", "sandbox-canary",
		"cat", "/etc/passwd", "canary-argument", "token=",
	} {
		if strings.Contains(debugOnly(stderr.String()), forbidden) {
			t.Fatalf("debug log leaked %q: %q", forbidden, stderr.String())
		}
	}
}

func TestDebugFlagAfterCommandKeepsOperands(t *testing.T) {
	t.Run("exec", func(t *testing.T) {
		executor := &recordingExecutor{}
		runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")
		if code := runner.Run(context.Background(), []string{"exec", "dev", "--debug", "true"}); code != 0 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
		}
		if !reflect.DeepEqual(executor.request.Argv, []string{"true"}) {
			t.Fatalf("argv=%q", executor.request.Argv)
		}
		if !runner.Debug || !strings.Contains(stderr.String(), "msg=exec.prepare") {
			t.Fatalf("debug=%t stderr=%q", runner.Debug, stderr.String())
		}
	})

	t.Run("run", func(t *testing.T) {
		workspace := t.TempDir()
		sessions := &fakeSessions{}
		runner, out, stderr := runTestRunner(t, runClient{sandboxes: &runSandbox{}, sessions: sessions}, "")
		args := []string{"run", "--name", "dev", "shell", workspace, "--debug"}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
		}
		if !sessions.opened {
			t.Fatal("run did not open a session")
		}
		if !runner.Debug || !strings.Contains(stderr.String(), "msg=run.prepare") {
			t.Fatalf("debug=%t stderr=%q", runner.Debug, stderr.String())
		}
	})
}

func TestDebugPreservesFlagValuesAndTerminator(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		assert func(*testing.T, *recordingExecutor, *Runner)
	}{
		{
			name: "debug as workdir value",
			args: []string{"exec", "--workdir", "--debug", "dev", "true"},
			assert: func(t *testing.T, executor *recordingExecutor, runner *Runner) {
				if executor.request.Workdir != "--debug" || runner.Debug {
					t.Fatalf("workdir=%q debug=%t", executor.request.Workdir, runner.Debug)
				}
			},
		},
		{
			name: "debug false as workdir value",
			args: []string{"exec", "--workdir", "--debug=false", "dev", "true"},
			assert: func(t *testing.T, executor *recordingExecutor, runner *Runner) {
				if executor.request.Workdir != "--debug=false" || runner.Debug {
					t.Fatalf("workdir=%q debug=%t", executor.request.Workdir, runner.Debug)
				}
			},
		},
		{
			name: "socket as workdir value",
			args: []string{"exec", "--workdir", "--socket", "dev", "true"},
			assert: func(t *testing.T, executor *recordingExecutor, runner *Runner) {
				if executor.request.Workdir != "--socket" || runner.Socket != "unused" {
					t.Fatalf("workdir=%q socket=%q", executor.request.Workdir, runner.Socket)
				}
			},
		},
		{
			name: "terminator keeps debug in argv",
			args: []string{"exec", "dev", "--", "echo", "--debug", "-D"},
			assert: func(t *testing.T, executor *recordingExecutor, runner *Runner) {
				if want := []string{"echo", "--debug", "-D"}; !reflect.DeepEqual(executor.request.Argv, want) {
					t.Fatalf("argv=%q want=%q", executor.request.Argv, want)
				}
				if runner.Debug {
					t.Fatal("debug after -- was consumed")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := &recordingExecutor{}
			runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")
			if code := runner.Run(context.Background(), tt.args); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			tt.assert(t, executor, runner)
			requireQuiet(t, stderr)
		})
	}

	t.Run("stop keeps debug-like target after terminator", func(t *testing.T) {
		sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-dash", Name: "--debug", State: sdk.StateRunning}}}
		runner, out := lifecycleRunner(sandbox)
		if code := runner.Run(context.Background(), []string{"stop", "--", "--debug"}); code != 0 {
			t.Fatalf("exit=%d output=%q", code, out.String())
		}
		if strings.Join(sandbox.stops, ",") != "sb-dash" || runner.Debug {
			t.Fatalf("stops=%v debug=%t", sandbox.stops, runner.Debug)
		}
		if strings.Contains(out.String(), "level=DEBUG") {
			t.Fatalf("debug log after --: %q", out.String())
		}
	})
}

func TestDebugSocketValueAfterCommandIsPreserved(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"stop", "dev", "--socket", "--debug"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if runner.Socket != "--debug" || runner.Debug {
		t.Fatalf("socket=%q debug=%t", runner.Socket, runner.Debug)
	}
	if strings.Join(sandbox.stops, ",") != "sb-1" {
		t.Fatalf("stops=%v output=%q", sandbox.stops, out.String())
	}
	if strings.Contains(out.String(), "level=DEBUG") {
		t.Fatalf("socket value enabled debug: %q", out.String())
	}
}

func TestDebugNeverLogsRawErrorsOrCanaries(t *testing.T) {
	const raw = "dial unix /Users/canary/private.sock: token=canary-secret sandbox=secret-sandbox argv=secret-argument"
	runner, out, stderr := runTestRunner(t, debugExecClient{
		executor: &failingExecutor{err: errors.New(raw)}, name: "secret-sandbox",
	}, "")
	args := []string{"exec", "--debug", "secret-sandbox", "secret-argument"}
	if code := runner.Run(context.Background(), args); code != 125 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "msg=exec.finish") || !strings.Contains(stderr.String(), "result=error") {
		t.Fatalf("stderr lacks error debug event: %q", stderr.String())
	}
	logged := debugOnly(stderr.String())
	for _, forbidden := range []string{
		"dial", "unix", "/Users", "canary", "token=", "canary-secret",
		"secret-sandbox", "secret-argument", raw,
	} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("debug log leaked %q: %q", forbidden, logged)
		}
	}
}

func TestDebugInvalidValueAfterCommandIsNotSwallowed(t *testing.T) {
	for _, args := range [][]string{
		{"exec", "--debug=maybe", "dev", "true"},
		{"ls", "--debug=maybe"},
	} {
		called := false
		runner, out, stderr := runTestRunner(t, recordingExecClient{executor: &recordingExecutor{}}, "")
		runner.NewClient = func(string) (sdk.Client, error) {
			called = true
			return recordingExecClient{executor: &recordingExecutor{}}, nil
		}
		if code := runner.Run(context.Background(), args); code != 1 {
			t.Fatalf("%v: exit=%d stdout=%q stderr=%q", args, code, out.String(), stderr.String())
		}
		if called {
			t.Fatalf("%v: invalid debug value dialed the daemon", args)
		}
		if runner.Debug {
			t.Fatalf("%v: invalid debug value enabled debug", args)
		}
		if !strings.Contains(stderr.String(), `invalid argument "maybe" for "-D, --debug" flag`) {
			t.Fatalf("%v: stderr=%q", args, stderr.String())
		}
	}
}

func TestDebugRunnerReuseDoesNotLeak(t *testing.T) {
	executor := &recordingExecutor{}
	runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")

	if code := runner.Run(context.Background(), []string{"exec", "--debug", "dev", "true"}); code != 0 {
		t.Fatalf("first run: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if !runner.Debug || !strings.Contains(stderr.String(), "msg=exec.prepare") {
		t.Fatalf("first run did not log: debug=%t stderr=%q", runner.Debug, stderr.String())
	}

	stderr.Reset()
	out.Reset()
	if code := runner.Run(context.Background(), []string{"exec", "dev", "true"}); code != 0 {
		t.Fatalf("second run: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if runner.Debug {
		t.Fatal("debug leaked into the second run")
	}
	requireQuiet(t, stderr)

	stderr.Reset()
	out.Reset()
	if code := runner.Run(context.Background(), []string{"--debug", "exec", "dev", "true"}); code != 0 {
		t.Fatalf("third run: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if !runner.Debug || !strings.Contains(stderr.String(), "msg=exec.prepare") {
		t.Fatalf("third run did not log: debug=%t stderr=%q", runner.Debug, stderr.String())
	}
}

func TestDebugUsesInjectedPerRunnerLogger(t *testing.T) {
	var logs bytes.Buffer
	executor := &recordingExecutor{}
	runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")
	runner.Logger = slogx.New(
		slogx.WithOutput(&logs),
		slogx.WithLevel(slog.LevelDebug),
		slogx.WithFormat(slogx.FormatText),
	)

	if code := runner.Run(context.Background(), []string{"exec", "--debug", "dev", "true"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if !strings.Contains(logs.String(), "msg=exec.prepare") {
		t.Fatalf("injected logger did not receive events: %q", logs.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("default logger also wrote to stderr: %q", stderr.String())
	}
}
