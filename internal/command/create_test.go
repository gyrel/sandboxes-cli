package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestCreateAcceptsAgentAndPositionalWorkspaces(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "shell", first, second + ":ro"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if sandbox.request.Agent != shellAgent || len(sandbox.request.Workspaces) != 2 ||
		!sandbox.request.Workspaces[1].ReadOnly || sandbox.request.Name == "" {
		t.Fatalf("request=%+v", sandbox.request)
	}
}

func TestCreateNameFlagWithAgent(t *testing.T) {
	workspace := t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--name", "dev", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if sandbox.request.Name != "dev" || sandbox.request.Agent != shellAgent {
		t.Fatalf("request=%+v", sandbox.request)
	}
}

func TestCreateRejectsUnsupportedAgentBeforeConnecting(t *testing.T) {
	called := false
	runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
		called = true
		return fakeClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"create", "cline", "."}); code != 2 || called {
		t.Fatalf("exit=%d client-called=%t", code, called)
	}
}

func TestCreateBakesEnv(t *testing.T) {
	workspace := t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--name", "env", "-e", "A=1", "--env", "B=2", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.request.Env) != 2 || sandbox.request.Env["A"] != "1" || sandbox.request.Env["B"] != "2" {
		t.Fatalf("env=%v", sandbox.request.Env)
	}
}

func TestCreateAcceptsFlagsAfterWorkspaces(t *testing.T) {
	workspace := t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "shell", workspace, "--name", "dev", "--image", "example.test/image:tag", "--cpus", "2"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if sandbox.request.Name != "dev" || sandbox.request.Agent != shellAgent || sandbox.request.Image != "example.test/image:tag" || sandbox.request.CPUs != 2 || len(sandbox.request.Workspaces) != 1 {
		t.Fatalf("request=%+v", sandbox.request)
	}
}

func TestAgentCreateRejectsReadOnlyPrimaryWorkspace(t *testing.T) {
	workspace := t.TempDir()
	for _, suffix := range []string{":ro", ":readonly"} {
		called := false
		var output bytes.Buffer
		runner := &Runner{Out: &output, Err: &output, NewClient: func(string) (sdk.Client, error) { called = true; return nil, nil }}
		if code := runner.Run(context.Background(), []string{"create", "shell", workspace + suffix}); code != 1 || called || !strings.Contains(output.String(), "primary workspace must be read/write") {
			t.Fatalf("%s: exit=%d connected=%t output=%q", suffix, code, called, output.String())
		}
	}
}

func TestAgentCreateAcceptsReadOnlyAdditionalWorkspace(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var output bytes.Buffer
	runner := &Runner{Out: &output, Err: &output, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "shell", first, second + ":readonly"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	if len(sandbox.request.Workspaces) != 2 || !sandbox.request.Workspaces[1].ReadOnly {
		t.Fatalf("workspaces=%+v", sandbox.request.Workspaces)
	}
}

func TestCreateRejectsLegacyNameGrammar(t *testing.T) {
	workspace := t.TempDir()
	called := false
	var output bytes.Buffer
	runner := &Runner{Out: &output, Err: &output, NewClient: func(string) (sdk.Client, error) {
		called = true
		return fakeClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"create", "local", workspace}); code != 2 || called {
		t.Fatalf("exit=%d connected=%t output=%q", code, called, output.String())
	}
	if !strings.Contains(output.String(), `unknown agent "local"`) {
		t.Fatalf("output=%q", output.String())
	}
}

func TestAgentRunRejectsReadOnlyPrimaryWorkspace(t *testing.T) {
	workspace := t.TempDir()
	for _, suffix := range []string{":ro", ":readonly"} {
		called := false
		var output bytes.Buffer
		runner := &Runner{Out: &output, Err: &output, NewClient: func(string) (sdk.Client, error) { called = true; return nil, nil }}
		if code := runner.Run(context.Background(), []string{"run", "shell", workspace + suffix, "--detach"}); code != 1 || called || !strings.Contains(output.String(), "primary workspace must be read/write") {
			t.Fatalf("%s: exit=%d connected=%t output=%q", suffix, code, called, output.String())
		}
	}
}

func TestCreateNoProgressAfterAgent(t *testing.T) {
	sandbox := &recordingCreateSandbox{}
	var output bytes.Buffer
	runner := &Runner{Out: &output, Err: &output, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "shell", "--no-progress"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	if sandbox.request.Agent != shellAgent {
		t.Fatalf("agent=%q", sandbox.request.Agent)
	}
}
