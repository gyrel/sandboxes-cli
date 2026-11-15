package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func resetRunner(sandbox *lifecycleSandbox, stdin string) (*Runner, *bytes.Buffer) {
	runner, out := lifecycleRunner(sandbox)
	runner.In = strings.NewReader(stdin)
	return runner, out
}

func TestResetRequiresTerminalWithoutForce(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one", State: sdk.StateStopped}}}
	runner, out := resetRunner(sandbox, "y\n")
	if code := runner.Run(context.Background(), []string{"reset"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.deletes) != 0 {
		t.Fatalf("reset deleted without a terminal: %v", sandbox.deletes)
	}
	if !strings.Contains(out.String(), "use --force") {
		t.Fatalf("missing force guidance: %q", out.String())
	}
}

func TestResetEmptyLineCancels(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one", State: sdk.StateStopped}}}
	runner, out := resetRunner(sandbox, "\n")
	runner.confirmTerminal = func() bool { return true }
	if code := runner.Run(context.Background(), []string{"reset"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.deletes) != 0 {
		t.Fatalf("reset deleted on an empty answer: %v", sandbox.deletes)
	}
	if !strings.Contains(out.String(), "Reset canceled") {
		t.Fatalf("missing cancel message: %q", out.String())
	}
}

func TestResetConfirmationAcceptsYes(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one", State: sdk.StateStopped}}}
	runner, out := resetRunner(sandbox, "yes\n")
	runner.confirmTerminal = func() bool { return true }
	if code := runner.Run(context.Background(), []string{"reset"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.deletes, ",") != "sb-1" {
		t.Fatalf("deletes=%v output=%q", sandbox.deletes, out.String())
	}
}
