package command

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v3"
	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestCatalogEventName(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"rheic.sandbox.created", "sandbox.created"},
		{"rheic.operation.failed", "operation.failed"},
		{"sandbox", "sandbox"},
		{"operation", "operation"},
		{"", "event"},
	} {
		if got := catalogEventName(tt.in); got != tt.want {
			t.Errorf("catalogEventName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCatalogEventReason(t *testing.T) {
	if got := catalogEventReason(sdk.Event{Operation: &sdk.Operation{Error: "boom"}}); got != "boom" {
		t.Errorf("error reason = %q", got)
	}
	if got := catalogEventReason(sdk.Event{Operation: &sdk.Operation{State: "running"}}); got != "running" {
		t.Errorf("operation state = %q", got)
	}
	if got := catalogEventReason(sdk.Event{Sandbox: &sdk.Sandbox{State: "stopped"}}); got != "stopped" {
		t.Errorf("sandbox state = %q", got)
	}
	if got := catalogEventReason(sdk.Event{Operation: &sdk.Operation{Progress: &sdk.Progress{Phase: "pulling", Completed: 3, Total: 7}}}); got != "pulling 3/7" {
		t.Errorf("progress fallback = %q", got)
	}
	if got := catalogEventReason(sdk.Event{}); got != "" {
		t.Errorf("empty reason = %q", got)
	}
}

func TestEventRowMatchesAndFilter(t *testing.T) {
	rows := []eventRow{
		{Time: "rev 1", Event: "sandbox.created", Correlation: "op_abc", Reason: "running", Sandbox: "dev"},
		{Time: "rev 2", Event: "operation.failed", Correlation: "op_def", Reason: "boom", Sandbox: "prod"},
	}
	if !eventRowMatches(rows[0], "op_abc") {
		t.Fatal("correlation prefix not matched")
	}
	if eventRowMatches(rows[0], "op_def") {
		t.Fatal("wrong correlation prefix matched")
	}
	if !eventRowMatches(rows[1], "boom") {
		t.Fatal("reason substring not matched")
	}
	if !eventRowMatches(rows[0], "") {
		t.Fatal("empty filter must match every row")
	}
	if got := filterEventRows(rows, "op_"); len(got) != 2 {
		t.Fatalf("op_ filter matched %d rows, want 2", len(got))
	}
	if got := filterEventRows(rows, "dev"); len(got) != 1 || got[0].Sandbox != "dev" {
		t.Fatalf("dev filter = %+v", got)
	}
	if got := filterEventRows(rows, "nomatch"); len(got) != 0 {
		t.Fatalf("nomatch filter = %+v", got)
	}
}

func TestEventFilterKeyFlow(t *testing.T) {
	model := &dashboardModel{panel: dashboardPanelEvents}
	ctx := context.Background()

	dashboardKey(keyRune('f'), model, ctx, nil)
	if model.mode != modeEventFilter {
		t.Fatalf("f did not enter filter mode: %v", model.mode)
	}
	for _, r := range "op_" {
		dashboardKey(keyRune(r), model, ctx, nil)
	}
	if model.eventFilter != "op_" {
		t.Fatalf("filter = %q", model.eventFilter)
	}
	dashboardKey(tcell.NewEventKey(tcell.KeyBackspace, "", tcell.ModNone), model, ctx, nil)
	if model.eventFilter != "op" {
		t.Fatalf("filter after backspace = %q", model.eventFilter)
	}
	dashboardKey(tcell.NewEventKey(tcell.KeyEnter, "", tcell.ModNone), model, ctx, nil)
	if model.mode != modeList || model.eventFilter != "op" {
		t.Fatalf("enter kept mode=%v filter=%q", model.mode, model.eventFilter)
	}
	dashboardKey(keyRune('f'), model, ctx, nil)
	dashboardKey(tcell.NewEventKey(tcell.KeyEscape, "", tcell.ModNone), model, ctx, nil)
	if model.mode != modeList || model.eventFilter != "" {
		t.Fatalf("esc cleared mode=%v filter=%q", model.mode, model.eventFilter)
	}
}

func TestDiagnoseRefusalRules(t *testing.T) {
	output := strings.Join([]string{
		"bearer logs/daemon.tail.jsonl line 1 offset 10",
		"openai_key logs/daemon.tail.jsonl line 2 offset 20",
		"bearer logs/daemon.tail.jsonl line 3 offset 30",
		"unrecognized line",
		"logs/daemon.tail.jsonl line 4 offset 40",
	}, "\n")
	rules := diagnoseRefusalRules(output)
	want := []string{"bearer", "openai_key"}
	if len(rules) != len(want) {
		t.Fatalf("rules = %v, want %v", rules, want)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Fatalf("rules = %v, want %v", rules, want)
		}
	}
	if got := diagnoseRefusalRules(""); len(got) != 0 {
		t.Fatalf("empty output rules = %v", got)
	}
}

func TestDashboardDiagnoseBundleRefusalPrintsRulesOnly(t *testing.T) {
	socket := bundleFixtures(t,
		`{"ts":"2026-11-25T10:00:00Z","level":"info","msg":"auth header Bearer abcdefghijklmnop"}`,
		`{"ts":"2026-11-25T10:00:01Z","level":"info","msg":"using key sk-abcdefghijklmnopqrstuvwxyz"}`,
	)
	runner, _, _ := bundleRunner(socket, bundleClient(bundleApprovalService{}), nil)
	model := &dashboardModel{panel: dashboardPanelEvents, diagnoseBundle: runner.diagnoseRun}
	dashboardKey(keyRune('d'), model, context.Background(), nil)

	notice := model.notice
	for _, want := range []string{"diagnose refused", "bearer", "openai_key"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice lacks %q: %s", want, notice)
		}
	}
	for _, leak := range []string{"abcdefghijklmnop", "abcdefghijklmnopqrstuvwxyz"} {
		if strings.Contains(notice, leak) {
			t.Fatalf("canary bytes leaked into the notice: %s", notice)
		}
	}
}

func TestDashboardDiagnoseBundleSuccessShowsPathAndSHA(t *testing.T) {
	socket := bundleFixtures(t)
	runner, _, _ := bundleRunner(socket, bundleClient(bundleApprovalService{}), nil)
	model := &dashboardModel{panel: dashboardPanelEvents, diagnoseBundle: runner.diagnoseRun}
	dashboardKey(keyRune('d'), model, context.Background(), nil)

	notice := model.notice
	if !strings.HasPrefix(notice, "bundle ") || !strings.Contains(notice, " sha256:") {
		t.Fatalf("success notice = %q", notice)
	}
	rest := strings.TrimPrefix(notice, "bundle ")
	bundlePath := strings.SplitN(rest, " ", 2)[0]
	defer func() { _ = os.RemoveAll(filepath.Dir(bundlePath)) }()
	if _, err := os.Stat(bundlePath); err != nil {
		t.Fatalf("bundle not published at %q: %v", bundlePath, err)
	}
}

func TestPendingApprovalsCountShownAndErrorHidden(t *testing.T) {
	ctx := context.Background()

	model := &dashboardModel{}
	client := fakeClient{approvals: bundleApprovalService{items: []sdk.Approval{{}, {}, {}}}}
	model.refreshPendingApprovals(ctx, client)
	if model.pendingApprovals != 3 {
		t.Fatalf("pending = %d, want 3", model.pendingApprovals)
	}

	model = &dashboardModel{}
	client = fakeClient{approvals: bundleApprovalService{err: errors.New("unreachable")}}
	model.refreshPendingApprovals(ctx, client)
	if model.pendingApprovals != -1 {
		t.Fatalf("pending = %d, want -1 (hidden)", model.pendingApprovals)
	}
}
