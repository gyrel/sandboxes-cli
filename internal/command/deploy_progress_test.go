package command

import (
	"bytes"
	"strings"
	"testing"
	"time"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func newTestProgress(width int) (*deployProgress, *bytes.Buffer) {
	var buf bytes.Buffer
	return newDeployProgress(&buf, true, true, width), &buf
}

func TestDeployProgressDisabledWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	p := newDeployProgress(&buf, false, false, 0)
	p.summary("x", "shell", "/tmp/x", false, "")
	p.begin("sandbox — creating…")
	p.next("sandbox — ready")
	p.begin("runtime — starting…")
	p.fail()
	p.line("sandbox x — reused")
	p.notice("Created sandbox x")
	p.sub("workspace /tmp/x")
	p.halt()
	if buf.Len() != 0 {
		t.Fatalf("disabled progress wrote %q", buf.String())
	}
}

func TestDeployProgressNilSafe(t *testing.T) {
	var p *deployProgress
	p.summary("x", "shell", "/tmp/x", false, "")
	p.begin("sandbox — creating…")
	p.next("sandbox — ready")
	p.fail()
	p.line("note")
	p.notice("Created sandbox x")
	p.sub("detail")
	p.halt()
}

func TestDeployProgressSbxStageGrammar(t *testing.T) {
	p, buf := newTestProgress(80)
	p.summary("rheic-demo", "shell", "/tmp/ws", false, "docker/sandbox-templates@sha256:b178ca62ec2e79af2a044e3ec321bdb72188690e1c15d573ea5524b397554d3d")
	p.begin("sandbox — creating…")
	p.next("sandbox — ready")
	p.notice("Created sandbox rheic-demo")
	p.notice("sandbox rheic-demo — running detached")
	p.sub("workspace /tmp/ws")
	visible := stripANSI(buf.String())
	lines := strings.Split(strings.TrimRight(visible, "\n"), "\n")
	if lines[0] != "  SANDBOX" {
		t.Fatalf("sbx starts with the two-space SANDBOX heading: %q", lines[0])
	}
	if lines[4] != "    Image:      docker/sandbox-templates@sha256:b178ca62ec2e" {
		t.Fatalf("image digest must be shortened like a tag reference: %q", lines[4])
	}
	if lines[5] != "" {
		t.Fatalf("summary block must end with a blank row: %q", lines[5])
	}
	// The spinner row has no trailing newline (it is redrawn in place), so the
	// committed stage appears after a \r inside the same split chunk.
	if !strings.Contains(visible, "\r    ✓ sandbox — ready\n") {
		t.Fatalf("stage commit must sit at the four-space indent: %q", visible)
	}
	if !strings.Contains(visible, "\n\n    ✓ Created sandbox rheic-demo\n") {
		t.Fatalf("notices must be blank-line separated (sbx layout): %q", visible)
	}
	if !strings.Contains(visible, "\n\n    ✓ sandbox rheic-demo — running detached\n") {
		t.Fatalf("detached notice must follow the sbx layout: %q", visible)
	}
	if !strings.Contains(visible, "\n        workspace /tmp/ws\n") {
		t.Fatalf("sub row must use the sbx 8-space indent: %q", visible)
	}
	// sbx uses 16-ANSI codes, not truecolor: magenta spinner, green checks,
	// bright-blue heading, gray labels.
	if !strings.Contains(buf.String(), "\x1b[35m") || !strings.Contains(buf.String(), "\x1b[32m") ||
		!strings.Contains(buf.String(), "\x1b[94m") || !strings.Contains(buf.String(), "\x1b[90m") {
		t.Fatalf("16-ANSI sbx palette expected: %q", buf.String())
	}
	if strings.Contains(buf.String(), "\x1b[38;2") {
		t.Fatalf("truecolor must not be used after the sbx alignment: %q", buf.String())
	}
}

func TestDeployProgressNoElapsedAfterSbxAlignment(t *testing.T) {
	p, buf := newTestProgress(80)
	p.begin("sandbox — creating…")
	time.Sleep(progressTick * 2)
	p.next("sandbox — ready")
	if strings.Contains(stripANSI(buf.String()), "0.1s") || strings.Contains(stripANSI(buf.String()), "0.2s") {
		t.Fatalf("sbx shows no elapsed durations: %q", buf.String())
	}
}

func TestDeployProgressNextKeepsLabelWhenDoneEmpty(t *testing.T) {
	p, buf := newTestProgress(80)
	p.begin("sandbox — removing…")
	p.next("")
	if !strings.Contains(stripANSI(buf.String()), "✓ sandbox — removing…") {
		t.Fatalf("empty done must reuse the active label: %q", buf.String())
	}
}

func TestDeployProgressFailMarker(t *testing.T) {
	p, buf := newTestProgress(80)
	p.begin("sandbox — creating…")
	p.fail()
	out := stripANSI(buf.String())
	if !strings.Contains(out, "✗ sandbox — creating…") {
		t.Fatalf("missing failure marker: %q", out)
	}
	if !strings.Contains(buf.String(), "\x1b[31m") {
		t.Fatalf("failure must use the red ANSI marker: %q", buf.String())
	}
	if strings.Contains(out, "✓") {
		t.Fatalf("failure rendered as success: %q", out)
	}
}

func TestDeployProgressLineNotice(t *testing.T) {
	p, buf := newTestProgress(80)
	p.summary("shell-demo", "shell", "/tmp/ws", false, "")
	p.line("sandbox shell-demo — reused")
	out := stripANSI(buf.String())
	if !strings.Contains(out, "\n    · sandbox shell-demo — reused") {
		t.Fatalf("missing indented notice: %q", out)
	}
}

func TestDeployProgressHaltClearsActiveLine(t *testing.T) {
	p, buf := newTestProgress(80)
	p.begin("sandbox — creating…")
	p.halt()
	if !strings.HasSuffix(buf.String(), ansiEraseLine+ansiShowCursor) {
		t.Fatalf("halt must clear the row and restore the cursor: %q", buf.String())
	}
	if strings.Contains(stripANSI(buf.String()), "✓") {
		t.Fatalf("halt must not settle the stage: %q", buf.String())
	}
	// A settled stage keeps its history line; halt after next restores the
	// cursor without an extra clear.
	p.begin("runtime — starting…")
	p.next("sandbox — ready")
	p.halt()
	if strings.HasSuffix(buf.String(), ansiEraseLine+ansiShowCursor) {
		t.Fatalf("halt after settled stage must not emit a clear: %q", buf.String())
	}
}

func TestDeployProgressCursorHiddenWhileSpinning(t *testing.T) {
	p, buf := newTestProgress(80)
	p.begin("sandbox — creating…")
	if !strings.Contains(buf.String(), ansiHideCursor) {
		t.Fatalf("spinner must hide the cursor like sbx: %q", buf.String())
	}
	p.halt()
	if !strings.HasSuffix(buf.String(), ansiShowCursor) {
		t.Fatalf("halt must restore the cursor: %q", buf.String())
	}
	// A second deployment run re-hides the cursor exactly once.
	p.begin("runtime — starting…")
	if strings.Count(buf.String(), ansiHideCursor) != 2 {
		t.Fatalf("cursor hides once per spinner activation: %q", buf.String())
	}
	p.halt()
}

func TestDeployProgressCommittedRowsRestoreCursor(t *testing.T) {
	// Every committing method must leave the terminal usable even when the
	// caller forgets halt(): the env-run and reuse paths rely on this.
	for _, tc := range []struct {
		name   string
		commit func(p *deployProgress)
	}{
		{"next", func(p *deployProgress) { p.next("sandbox — ready") }},
		{"fail", func(p *deployProgress) { p.fail() }},
		{"line", func(p *deployProgress) { p.line("sandbox x — reused") }},
		{"notice", func(p *deployProgress) { p.notice("sandbox x — running detached") }},
	} {
		p, buf := newTestProgress(80)
		p.begin("sandbox — creating…")
		tc.commit(p)
		if !strings.Contains(buf.String(), ansiShowCursor) {
			t.Fatalf("%s must restore the cursor: %q", tc.name, buf.String())
		}
	}
}

func TestDeployProgressColorsSuppressed(t *testing.T) {
	var buf bytes.Buffer
	p := newDeployProgress(&buf, true, false, 80)
	p.summary("shell-demo", "shell", "/tmp/ws", false, "")
	p.begin("sandbox — creating…")
	p.next("Created sandbox shell-demo")
	for _, seq := range []string{"\x1b[3", "\x1b[9", "\x1b[0m"} {
		if strings.Contains(buf.String(), seq) {
			t.Fatalf("color sequence %q must be absent when disabled: %q", seq, buf.String())
		}
	}
	if !strings.Contains(buf.String(), "    ✓ Created sandbox shell-demo") {
		t.Fatalf("markers must survive color suppression: %q", buf.String())
	}
}

func TestDeployProgressClipsToTerminalWidth(t *testing.T) {
	p, buf := newTestProgress(40)
	p.summary("x", "shell", strings.Repeat("/tmp/", 20), false, "docker/sandbox-templates@sha256:"+strings.Repeat("a", 64))
	p.begin("sandbox — creating " + strings.Repeat("b", 60) + "…")
	p.next("Created sandbox " + strings.Repeat("c", 60))
	p.notice("sandbox " + strings.Repeat("d", 60) + " — running detached")
	p.sub(strings.Repeat("e", 60))
	for _, line := range strings.Split(buf.String(), "\n") {
		for _, row := range strings.Split(stripANSI(line), "\r") {
			if len([]rune(row)) > 39 {
				t.Fatalf("row must stay one cell short of the 40-col terminal (%d): %q", len([]rune(row)), row)
			}
		}
	}
	if !strings.Contains(stripANSI(buf.String()), "…") {
		t.Fatalf("clipped text must end with an ellipsis: %q", buf.String())
	}
}

func TestDeployProgressSpinnerAdvances(t *testing.T) {
	p, buf := newTestProgress(80)
	p.begin("sandbox — creating…")
	// Wait past two tick intervals so at least one animated frame renders.
	time.Sleep(progressTick * 3)
	p.halt()
	out := buf.String()
	frames := 0
	for _, frame := range progressFrames {
		if strings.Contains(out, frame) {
			frames++
		}
	}
	if frames < 2 {
		t.Fatalf("expected multiple spinner frames, got %d in %q", frames, out)
	}
}

func TestDeployProgressStageChurnStopsGoroutines(t *testing.T) {
	p, _ := newTestProgress(80)
	for i := 0; i < 20; i++ {
		p.begin("sandbox — creating…")
		p.next("sandbox — ready")
	}
	p.halt()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopCh != nil || p.doneCh != nil {
		t.Fatal("spinner goroutine channels must be released")
	}
}

func TestRunParsesNoProgressFlag(t *testing.T) {
	cases := []struct {
		args []string
		want bool
		err  bool
	}{
		{args: []string{"--no-progress"}, want: true},
		{args: []string{"--no-progress=true"}, want: true},
		{args: []string{"--no-progress=false"}, want: false},
		{args: []string{"--no-progress", "opencode", "."}, want: true},
		{args: []string{"--no-progress=maybe"}, err: true},
	}
	for _, tc := range cases {
		opts, positionals, err := parseRunArgs(&Runner{}, tc.args)
		if tc.err {
			if err == nil {
				t.Fatalf("args %v: expected parse error", tc.args)
			}
			continue
		}
		if err != nil {
			t.Fatalf("args %v: unexpected error %v", tc.args, err)
		}
		if opts.noProgress != tc.want {
			t.Fatalf("args %v: noProgress=%v want %v", tc.args, opts.noProgress, tc.want)
		}
		if tc.want && len(positionals) > 0 && positionals[0] != "opencode" {
			t.Fatalf("args %v: unexpected positionals %v", tc.args, positionals)
		}
	}
}

func TestRunUsageAndHelpDocumentNoProgress(t *testing.T) {
	if !strings.Contains(runUsage, "--no-progress") {
		t.Fatal("runUsage must document --no-progress")
	}
	found := false
	for _, flag := range runHelp().Flags {
		if flag.Name == "no-progress" {
			found = true
		}
	}
	if !found {
		t.Fatal("run help must list the no-progress flag")
	}
}

// TestRunAttachedUnknownStateStartsBeforeAttach covers the sbx parity case: a
// sandbox that the daemon reconciled to unknown after a restart must be
// started before the agent session attaches, not refused.
func TestRunAttachedUnknownStateStartsBeforeAttach(t *testing.T) {
	sandboxes := &runSandbox{items: []sdk.Sandbox{{
		ID: "sb_unknown", Name: "unknown-demo", State: sdk.StateUnknown, Workspace: "/tmp/ws",
	}}}
	sessions := &fakeSessions{}
	runner := &Runner{Out: new(bytes.Buffer), Err: new(bytes.Buffer), In: strings.NewReader("")}
	// A buffered writer is not a terminal: the disabled indicator must leave
	// stderr and stdout byte-clean while the stages still run underneath.
	indicator := newDeployProgress(runner.Err, false, false, 0)
	code := runner.runAttached(
		t.Context(),
		&runClient{fakeClient: fakeClient{}, sandboxes: sandboxes, sessions: sessions},
		runOptions{name: "unknown-demo"},
		&sandboxes.items[0], false, shellAgent,
		[]sdk.Workspace{{Path: "/tmp/ws"}}, false,
		nil, runResources{},
		indicator,
	)
	if code != 0 {
		t.Fatalf("runAttached code = %d, want 0", code)
	}
	if sandboxes.startCalls != 1 {
		t.Fatalf("start calls = %d, want 1", sandboxes.startCalls)
	}
	if !sessions.opened {
		t.Fatal("the agent session must open after the unknown-state restart")
	}
	if sessions.req.TTY {
		t.Fatalf("non-terminal run attach must stay raw: %+v", sessions.req)
	}
	if buf := runner.Err.(*bytes.Buffer); buf.Len() != 0 {
		t.Fatalf("disabled indicator must write no stderr bytes, got %q", buf.String())
	}
	if buf := runner.Out.(*bytes.Buffer); strings.Contains(buf.String(), "\x1b") {
		t.Fatalf("stdout must never carry indicator ANSI: %q", buf.String())
	}
}

func stripANSI(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' && s[i] != 'K' && s[i] != 'l' && s[i] != 'h' {
				i++
			}
			i++
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}
