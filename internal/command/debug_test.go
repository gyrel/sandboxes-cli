package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"

	"github.com/gyrel/sandboxes-cli/internal/version"
)

func TestDebugFlagAcceptedBeforeAndAfterVersion(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "short before", args: []string{"-D", "version"}, want: true},
		{name: "long before", args: []string{"--debug", "version"}, want: true},
		{name: "short after", args: []string{"version", "-D"}, want: true},
		{name: "long after", args: []string{"version", "--debug"}, want: true},
		{name: "explicit true", args: []string{"version", "--debug=true"}, want: true},
		{name: "explicit one", args: []string{"version", "-D=1"}, want: true},
		{name: "explicit false", args: []string{"version", "--debug=false"}, want: false},
		{name: "explicit zero", args: []string{"-D=0", "version"}, want: false},
		{name: "last value wins", args: []string{"-D", "version", "--debug=false"}, want: false},
		{name: "later value wins", args: []string{"--debug=false", "version", "--debug"}, want: true},
		{name: "last value wins after format", args: []string{"version", "--format", "table", "--debug"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, out, _ := runTestRunner(t, versionFakeClient{info: sdk.VersionInfo{Version: "0.0.9"}}, "")
			if code := runner.Run(context.Background(), tt.args); code != 0 {
				t.Fatalf("exit=%d output=%q", code, out.String())
			}
			if runner.Debug != tt.want {
				t.Fatalf("debug=%t want=%t", runner.Debug, tt.want)
			}
			if tt.want != strings.Contains(out.String(), "Client Version:") {
				t.Fatalf("debug=%t output=%q", tt.want, out.String())
			}
		})
	}
}

func TestDebugVersionTextShowsClientAndServer(t *testing.T) {
	runner, out, _ := runTestRunner(t, versionFakeClient{info: sdk.VersionInfo{Version: "0.0.9", APIVersion: "0.0.5"}}, "")
	if code := runner.Run(context.Background(), []string{"-D", "version"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	for _, want := range []string{
		"  Client Version:  v" + version.Version,
		"  Server Version:  v0.0.9",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q: %q", want, out.String())
		}
	}
	if strings.Contains(out.String(), "rsbx version v") {
		t.Fatalf("debug output used the non-debug line: %q", out.String())
	}
}

func TestDebugVersionTextReportsUnavailableServer(t *testing.T) {
	runner, out, _ := runTestRunner(t, versionFakeClient{err: errors.New("daemon not running")}, "")
	if code := runner.Run(context.Background(), []string{"version", "--debug"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if want := "  Server Version:  Unavailable (daemon not running)"; !strings.Contains(out.String(), want) {
		t.Fatalf("output lacks %q: %q", want, out.String())
	}
}

func TestDebugFlagInvalidValueMatchesReferenceError(t *testing.T) {
	const invalid = `invalid argument "maybe" for "-D, --debug" flag: strconv.ParseBool: parsing "maybe": invalid syntax`
	tests := []struct {
		args []string
		hint string
	}{
		{args: []string{"version", "--debug=maybe"}, hint: "try: rsbx version --help"},
		{args: []string{"version", "-D=maybe"}, hint: "try: rsbx version --help"},
		{args: []string{"--debug=maybe", "version"}, hint: "try: rsbx --help"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			runner, _, stderr := runTestRunner(t, versionFakeClient{}, "")
			if code := runner.Run(context.Background(), tt.args); code != 1 {
				t.Fatalf("%v: exit=%d stderr=%q", tt.args, code, stderr.String())
			}
			for _, want := range []string{invalid, tt.hint} {
				if !strings.Contains(stderr.String(), want) {
					t.Fatalf("%v: stderr lacks %q: %q", tt.args, want, stderr.String())
				}
			}
			if runner.Debug {
				t.Fatal("invalid debug value enabled debug mode")
			}
		})
	}
}

func TestDebugPrefixAcceptedForAllCommands(t *testing.T) {
	for _, args := range [][]string{
		{"--debug", "completion", "bash"},
		{"-D", "completion", "bash"},
	} {
		var out, stderr bytes.Buffer
		runner := &Runner{Out: &out, Err: &stderr}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v: exit=%d stdout=%q stderr=%q", args, code, out.String(), stderr.String())
		}
		if !strings.Contains(out.String(), "# bash completion for rsbx") {
			t.Fatalf("%v: output=%q", args, out.String())
		}
		if !strings.Contains(stderr.String(), "msg=command.start command=completion") {
			t.Fatalf("%v: stderr lacks debug start event: %q", args, stderr.String())
		}
		if !runner.Debug {
			t.Fatalf("%v: debug flag was not recorded", args)
		}
	}
}

func TestDebugPrefixExecutesWithFakeSDK(t *testing.T) {
	executor := &recordingExecutor{}
	called := false
	runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")
	runner.NewClient = func(string) (sdk.Client, error) {
		called = true
		return recordingExecClient{executor: executor}, nil
	}
	if code := runner.Run(context.Background(), []string{"--debug", "exec", "dev", "true"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if !called {
		t.Fatal("debug did not dial the daemon")
	}
	if !reflect.DeepEqual(executor.request.Argv, []string{"true"}) || executor.request.SandboxID != "sb-1" {
		t.Fatalf("unexpected request: %#v", executor.request)
	}
	if !strings.Contains(stderr.String(), "msg=exec.prepare") || !strings.Contains(stderr.String(), "msg=exec.finish") {
		t.Fatalf("stderr lacks exec debug events: %q", stderr.String())
	}
}

func TestDebugFalsePrefixAllowsUnsupportedCommands(t *testing.T) {
	for _, args := range [][]string{
		{"--debug=false", "completion", "bash"},
		{"-D=0", "completion", "bash"},
	} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v: exit=%d output=%q", args, code, out.String())
		}
		if !strings.Contains(out.String(), "# bash completion for rsbx") {
			t.Fatalf("%v: output=%q", args, out.String())
		}
	}
}

func TestDebugAfterSubcommandIsGlobal(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		want []string
		on   bool
	}{
		{
			name: "exec after command with false",
			args: []string{"exec", "-t", "--debug=false", "--help"},
			code: 0,
			want: []string{"Usage:", "rsbx exec [flags] SANDBOX COMMAND"},
		},
		{
			name: "completion after shell",
			args: []string{"completion", "bash", "--debug"},
			code: 0,
			want: []string{"# bash completion for rsbx"},
			on:   true,
		},
		{
			name: "ls before help",
			args: []string{"ls", "--debug", "--help"},
			code: 0,
			want: []string{"Usage:", "rsbx ls [flags]"},
			on:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			runner := &Runner{Out: &out, Err: &stderr, In: strings.NewReader("")}
			if code := runner.Run(context.Background(), tt.args); code != tt.code {
				t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", code, tt.code, out.String(), stderr.String())
			}
			for _, want := range tt.want {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("stdout lacks %q: %q", want, out.String())
				}
			}
			if runner.Debug != tt.on {
				t.Fatalf("debug=%t want=%t", runner.Debug, tt.on)
			}
			if tt.on != strings.Contains(stderr.String(), "level=DEBUG") {
				t.Fatalf("debug=%t stderr=%q", tt.on, stderr.String())
			}
		})
	}
}

func TestDebugDoesNotConsumeExecFlagValues(t *testing.T) {
	executor := &recordingExecutor{}
	runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")
	args := []string{"exec", "--env", "--debug=false", "--help"}
	if code := runner.Run(context.Background(), args); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if !strings.Contains(out.String(), "rsbx exec [flags] SANDBOX COMMAND") {
		t.Fatalf("output=%q", out.String())
	}
	if runner.Debug {
		t.Fatal("debug flag used as an exec value was consumed")
	}
}

func TestDebugLikeExecFlagValueReachesFakeSDK(t *testing.T) {
	executor := &recordingExecutor{}
	runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")
	if code := runner.Run(context.Background(), []string{"exec", "--workdir", "--debug", "dev", "true"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if executor.request.Workdir != "--debug" {
		t.Fatalf("workdir=%q", executor.request.Workdir)
	}
	if !reflect.DeepEqual(executor.request.Argv, []string{"true"}) {
		t.Fatalf("argv=%q", executor.request.Argv)
	}
	if runner.Debug {
		t.Fatal("debug-like workdir value enabled debug mode")
	}
}

func TestDebugAfterTerminatorReachesExecAsCommandArgs(t *testing.T) {
	executor := &recordingExecutor{}
	runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")
	args := []string{"exec", "--workdir", "/tmp", "dev", "--", "echo", "--debug", "-D=0"}
	if code := runner.Run(context.Background(), args); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if executor.request.SandboxID != "sb-1" || executor.request.Workdir != "/tmp" {
		t.Fatalf("unexpected request: %#v", executor.request)
	}
	if want := []string{"echo", "--debug", "-D=0"}; !reflect.DeepEqual(executor.request.Argv, want) {
		t.Fatalf("argv=%q want=%q", executor.request.Argv, want)
	}
	if runner.Debug {
		t.Fatal("debug after the terminator was consumed")
	}
}

func TestDebugAfterTerminatorReachesRunAgentArgs(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	args := []string{"run", "--name", "dev", "shell", workspace, "--", "--debug", "-D=0"}
	if code := runner.Run(context.Background(), args); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if !sessions.opened {
		t.Fatal("run did not open a session")
	}
	if len(sessions.req.Argv) < 2 || !reflect.DeepEqual(sessions.req.Argv[len(sessions.req.Argv)-2:], []string{"--debug", "-D=0"}) {
		t.Fatalf("agent argv=%q", sessions.req.Argv)
	}
	if runner.Debug {
		t.Fatal("debug after the terminator was consumed")
	}
}

func TestDebugAfterTerminatorCanNameSandboxTarget(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-dash", Name: "--debug", State: sdk.StateRunning}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"stop", "--", "--debug"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if got := strings.Join(sandbox.stops, ","); got != "sb-dash" {
		t.Fatalf("stops=%q output=%q", got, out.String())
	}
	if runner.Debug {
		t.Fatal("debug after the terminator was consumed")
	}
}

func TestVersionTerminatorKeepsDebugAsPositional(t *testing.T) {
	called := false
	runner, _, stderr := runTestRunner(t, versionFakeClient{}, "")
	runner.NewClient = func(string) (sdk.Client, error) {
		called = true
		return versionFakeClient{}, nil
	}
	if code := runner.Run(context.Background(), []string{"version", "--", "--debug"}); code != 1 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if called {
		t.Fatal("version after -- dialed the daemon")
	}
	if runner.Debug {
		t.Fatal("debug after -- was consumed")
	}
	if !strings.Contains(stderr.String(), versionNoArgsMessage) {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestDebugVersionFlagValuesAreNotSwallowed(t *testing.T) {
	tests := [][]string{
		{"version", "--format", "--debug"},
		{"version", "--format=--debug"},
	}
	for _, args := range tests {
		runner, _, stderr := runTestRunner(t, versionFakeClient{}, "")
		if code := runner.Run(context.Background(), args); code != 1 {
			t.Fatalf("%v: exit=%d stderr=%q", args, code, stderr.String())
		}
		if runner.Debug {
			t.Fatalf("%v: debug flag used as a version format value was consumed", args)
		}
		if !strings.Contains(stderr.String(), `unknown format "--debug"`) {
			t.Fatalf("%v: stderr=%q", args, stderr.String())
		}
	}
}

func TestDebugAllowedForExplicitHelpCommand(t *testing.T) {
	for _, args := range [][]string{
		{"--debug", "help"},
		{"--debug", "help", "version"},
	} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v: exit=%d output=%q", args, code, out.String())
		}
		if !strings.Contains(out.String(), "Usage:") {
			t.Fatalf("%v: help output=%q", args, out.String())
		}
	}
}

func TestDebugPrefixDoesNotChangeHelpLikeOperands(t *testing.T) {
	workspace := t.TempDir()
	t.Run("help as exec flag value", func(t *testing.T) {
		executor := &recordingExecutor{}
		runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")
		args := []string{"--debug", "exec", "--workdir", "--help", "dev", "true"}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
		}
		if executor.request.Workdir != "--help" {
			t.Fatalf("workdir=%q", executor.request.Workdir)
		}
		if !reflect.DeepEqual(executor.request.Argv, []string{"true"}) {
			t.Fatalf("argv=%q", executor.request.Argv)
		}
		if strings.Contains(stderr.String(), "--help") {
			t.Fatalf("debug log leaked a flag value: %q", stderr.String())
		}
	})
	t.Run("help after exec positionals", func(t *testing.T) {
		executor := &recordingExecutor{}
		runner, out, _ := runTestRunner(t, recordingExecClient{executor: executor}, "")
		if code := runner.Run(context.Background(), []string{"--debug", "exec", "dev", "--help"}); code != 0 {
			t.Fatalf("exit=%d stdout=%q", code, out.String())
		}
		if !strings.Contains(out.String(), "rsbx exec [flags] SANDBOX COMMAND") {
			t.Fatalf("help output=%q", out.String())
		}
	})
	t.Run("help after run positionals", func(t *testing.T) {
		runner, out, _ := runTestRunner(t, runClient{sandboxes: &runSandbox{}, sessions: &fakeSessions{}}, "")
		args := []string{"--debug", "run", "--name", "dev", "shell", workspace, "--help"}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("exit=%d stdout=%q", code, out.String())
		}
		if !strings.Contains(out.String(), "rsbx run [flags] [AGENT] [PATH...]") {
			t.Fatalf("help output=%q", out.String())
		}
	})
}

func TestSocketValuesThatLookLikeDebugArePreserved(t *testing.T) {
	for _, args := range [][]string{
		{"--socket", "--debug", "version"},
		{"--socket=--debug", "version"},
	} {
		var got string
		runner, out, stderr := runTestRunner(t, versionFakeClient{}, "")
		runner.NewClient = func(address string) (sdk.Client, error) {
			got = address
			return versionFakeClient{info: sdk.VersionInfo{Version: "0.0.9"}}, nil
		}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v: exit=%d stdout=%q stderr=%q", args, code, out.String(), stderr.String())
		}
		if got != "--debug" || runner.Socket != "--debug" {
			t.Fatalf("%v: client address=%q socket=%q", args, got, runner.Socket)
		}
		if runner.Debug {
			t.Fatalf("%v: debug-like socket value enabled debug mode", args)
		}
		if strings.Contains(out.String(), "Client Version:") {
			t.Fatalf("%v: debug table printed: %q", args, out.String())
		}
	}
}

func TestRunnerReuseResetsDebugMode(t *testing.T) {
	client := versionFakeClient{
		runClient: runClient{sandboxes: &runSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: sdk.StateRunning}}}},
		info:      sdk.VersionInfo{Version: "0.0.9"},
	}
	runner, out, stderr := runTestRunner(t, client, "")

	if code := runner.Run(context.Background(), []string{"-D", "version"}); code != 0 {
		t.Fatalf("debug version: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if !runner.Debug || !strings.Contains(out.String(), "Client Version:") {
		t.Fatalf("first run did not enable debug: debug=%t output=%q", runner.Debug, out.String())
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"version"}); code != 0 {
		t.Fatalf("plain version: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if runner.Debug || strings.Contains(out.String(), "Client Version:") || !strings.Contains(out.String(), "rsbx version") {
		t.Fatalf("debug leaked into the second run: debug=%t output=%q", runner.Debug, out.String())
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"ls"}); code != 0 {
		t.Fatalf("ls after debug: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if runner.Debug || !strings.Contains(out.String(), "dev") {
		t.Fatalf("unrelated command inherited debug: debug=%t output=%q", runner.Debug, out.String())
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"--debug", "version"}); code != 0 {
		t.Fatalf("debug version again: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if !runner.Debug || !strings.Contains(out.String(), "Client Version:") {
		t.Fatalf("third debug run failed: debug=%t output=%q", runner.Debug, out.String())
	}
}

func TestRunnerReuseAfterDebugHelpDoesNotLeak(t *testing.T) {
	client := versionFakeClient{
		runClient: runClient{sandboxes: &runSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: sdk.StateRunning}}}},
		info:      sdk.VersionInfo{Version: "0.0.9"},
	}
	runner, out, stderr := runTestRunner(t, client, "")
	if code := runner.Run(context.Background(), []string{"--debug", "help", "version"}); code != 0 {
		t.Fatalf("help: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"version"}); code != 0 {
		t.Fatalf("version after help: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if runner.Debug || strings.Contains(out.String(), "Client Version:") {
		t.Fatalf("debug leaked from help: debug=%t output=%q", runner.Debug, out.String())
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"ls"}); code != 0 {
		t.Fatalf("ls after help: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
}

func TestRunnerReuseClearsDebugAfterParseError(t *testing.T) {
	client := versionFakeClient{
		runClient: runClient{sandboxes: &runSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: sdk.StateRunning}}}},
		info:      sdk.VersionInfo{Version: "0.0.9"},
	}
	runner, out, stderr := runTestRunner(t, client, "")
	if code := runner.Run(context.Background(), []string{"-D", "version"}); code != 0 {
		t.Fatalf("debug version: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}

	stderr.Reset()
	if code := runner.Run(context.Background(), []string{"version", "--socket"}); code != 2 {
		t.Fatalf("missing socket: exit=%d stderr=%q", code, stderr.String())
	}
	if runner.Debug {
		t.Fatal("failed run retained debug mode")
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"ls"}); code != 0 {
		t.Fatalf("ls after failed run: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
}

func TestVersionDebugStructuredFormatsAreNotRewritten(t *testing.T) {
	runner, out, stderr := runTestRunner(t, versionFakeClient{info: sdk.VersionInfo{Version: "0.0.9"}}, "")
	if code := runner.Run(context.Background(), []string{"version", "--debug", "--json"}); code != 0 {
		t.Fatalf("json: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if strings.Contains(out.String(), "Client Version:") || !json.Valid(out.Bytes()) {
		t.Fatalf("json output was rewritten: %q", out.String())
	}
	if !runner.Debug {
		t.Fatal("debug flag was not recorded for json output")
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"version", "--debug", "--format", "yaml"}); code != 0 {
		t.Fatalf("yaml: exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if strings.Contains(out.String(), "Client Version:") || !strings.Contains(out.String(), "client:") {
		t.Fatalf("yaml output was rewritten: %q", out.String())
	}
}

func TestVersionDebugTextDoesNotLeakDaemonErrorOrSocket(t *testing.T) {
	const raw = "dial unix /tmp/private-daemon.sock: connect: connection refused"
	runner, out, _ := runTestRunner(t, versionFakeClient{err: errors.New(raw)}, "")
	if code := runner.Run(context.Background(), []string{"version", "--debug"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	for _, forbidden := range []string{"dial", "/tmp/private-daemon.sock", "connection refused", raw} {
		if strings.Contains(out.String(), forbidden) {
			t.Fatalf("output leaked %q: %q", forbidden, out.String())
		}
	}
	for _, want := range []string{"Client Version:", "Server Version:  Unavailable", "daemon not running"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q: %q", want, out.String())
		}
	}
}

func TestVersionDebugTextUsesStableGenericUnavailableReason(t *testing.T) {
	runner, out, _ := runTestRunner(t, versionFakeClient{err: errors.New("unexpected daemon failure")}, "")
	if code := runner.Run(context.Background(), []string{"version", "--debug"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Contains(out.String(), "unexpected daemon failure") {
		t.Fatalf("output leaked the raw error: %q", out.String())
	}
	if want := "Server Version:  Unavailable (daemon unavailable)"; !strings.Contains(out.String(), want) {
		t.Fatalf("output lacks %q: %q", want, out.String())
	}
}

func TestDebugFlagListedInHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"version", "--help"}} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v exit=%d output=%q", args, code, out.String())
		}
		if !strings.Contains(out.String(), "-D, --debug") {
			t.Fatalf("%v help lacks debug flag: %q", args, out.String())
		}
		for _, want := range []string{"Enable debug logging", "structured events on stderr"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("%v help lacks %q: %q", args, want, out.String())
			}
		}
	}
}

func TestDebugFlagsAreInCompletionTrees(t *testing.T) {
	for _, want := range []string{"-D", "--debug"} {
		foundTop := false
		for _, word := range completionTopLevelWords() {
			if word == want {
				foundTop = true
				break
			}
		}
		if !foundTop {
			t.Errorf("top-level completion lacks %q", want)
		}
		foundVersion := false
		for _, flag := range completionTree[versionCommand] {
			if flag == want {
				foundVersion = true
				break
			}
		}
		if !foundVersion {
			t.Errorf("version completion lacks %q", want)
		}
	}
	if !strings.Contains(fishCompletionScript(), "-l debug -s D") {
		t.Error("fish completion lacks the top-level debug flag")
	}
}
