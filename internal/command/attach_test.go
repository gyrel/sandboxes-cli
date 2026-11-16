package command

import (
	"context"
	"reflect"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestLocalAttachStartsStoppedSandboxAndUsesAgent(t *testing.T) {
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", Agent: "shell", State: sdk.StateStopped}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"attach", "dev"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.startCalls != 1 || !sessions.opened || sessions.req.SandboxID != "sb-1" {
		t.Fatalf("starts=%d opened=%v request=%+v", sandboxes.startCalls, sessions.opened, sessions.req)
	}
	if !reflect.DeepEqual(sessions.req.Argv, agentCommandArgs("shell")) {
		t.Fatalf("argv=%q", sessions.req.Argv)
	}
}

func TestLocalAttachShellOverride(t *testing.T) {
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", Agent: "shell", State: sdk.StateRunning}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"attach", "dev", "--shell"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.startCalls != 0 || !sessions.opened || !reflect.DeepEqual(sessions.req.Argv, []string{shellPath}) {
		t.Fatalf("starts=%d opened=%v argv=%q", sandboxes.startCalls, sessions.opened, sessions.req.Argv)
	}
}
