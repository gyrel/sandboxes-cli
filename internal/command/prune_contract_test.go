package command

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

type machineCodeTestError struct{ code string }

func (e machineCodeTestError) Error() string       { return e.code + ": synthetic refusal" }
func (e machineCodeTestError) MachineCode() string { return e.code }

type pruneForeignSandbox struct {
	*lifecycleSandbox
	refuse map[string]string
}

func (s *pruneForeignSandbox) Get(ctx context.Context, id string) (*sdk.Sandbox, error) {
	if code, ok := s.refuse[id]; ok {
		return nil, machineCodeTestError{code: code}
	}
	return s.lifecycleSandbox.Get(ctx, id)
}

type pruneSequenceSandbox struct {
	*lifecycleSandbox
	lists     [][]sdk.Sandbox
	listCalls int
}

func (s *pruneSequenceSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	index := s.listCalls
	if index >= len(s.lists) {
		index = len(s.lists) - 1
	}
	s.listCalls++
	return &sdk.Page[sdk.Sandbox]{Items: s.lists[index]}, nil
}

func (s *pruneSequenceSandbox) Get(_ context.Context, id string) (*sdk.Sandbox, error) {
	index := s.listCalls - 1
	if index < 0 {
		index = 0
	}
	if index >= len(s.lists) {
		index = len(s.lists) - 1
	}
	for i := range s.lists[index] {
		if s.lists[index][i].ID == id || s.lists[index][i].Name == id {
			item := s.lists[index][i]
			return &item, nil
		}
	}
	return nil, sandboxNotFoundError{name: id}
}

func pruneStopped(id, name string) sdk.Sandbox {
	return sdk.Sandbox{ID: id, Name: name, State: sdk.StateStopped, StoppedAt: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)}
}

func TestPruneFilterMatrixRejectsBeforeAnyDelete(t *testing.T) {
	for _, tc := range []struct{ filter, code string }{
		{"", pruneCodeFilterReq},
		{"   ", pruneCodeFilterReq},
		{"bogus=1", pruneCodeFilterBad},
		{"status=", pruneCodeFilterBad},
		{"status", pruneCodeFilterBad},
		{"until=soon", pruneCodeFilterBad},
		{"label=env", pruneCodeFilterBad},
		{"name~tmp-", pruneCodeFilterBad},
	} {
		sandbox := &lifecycleSandbox{items: []sdk.Sandbox{pruneStopped("sb-1", "one")}}
		runner, out := lifecycleRunner(sandbox)
		if code := runner.Run(context.Background(), []string{"prune", "-f", "--filter", tc.filter}); code != 2 {
			t.Fatalf("filter %q exit=%d output=%q", tc.filter, code, out.String())
		}
		if len(sandbox.deletes) != 0 || len(sandbox.stops) != 0 {
			t.Fatalf("filter %q performed actions: deletes=%v stops=%v", tc.filter, sandbox.deletes, sandbox.stops)
		}
		if !strings.Contains(out.String(), tc.code) {
			t.Fatalf("filter %q missing %s: %q", tc.filter, tc.code, out.String())
		}
	}
}

func TestPruneFilterMatrixSelectsExpectedSubset(t *testing.T) {
	now := time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)
	items := []sdk.Sandbox{
		{ID: "old", Name: "tmp-old", State: sdk.StateStopped, StoppedAt: now.Add(-3 * time.Hour), Labels: map[string]string{"env": "ci", "team": "platform"}},
		{ID: "new", Name: "tmp-new", State: sdk.StateStopped, StoppedAt: now.Add(-time.Hour), Labels: map[string]string{"env": "dev"}},
		{ID: "run", Name: "web", State: sdk.StateRunning},
		{ID: "other", Name: "other", State: sdk.StateStopped, StoppedAt: now.Add(-2 * time.Hour)},
	}
	for _, tc := range []struct {
		filter string
		want   []string
	}{
		{"status=stopped", []string{"old", "new", "other"}},
		{"status=running", []string{"run"}},
		{"name=web", []string{"run"}},
		{"name~^tmp-", []string{"old", "new"}},
		{"until=2h", []string{"old"}},
		{"label=env=ci", []string{"old"}},
		{"label=team=platform", []string{"old"}},
		{"label=env=missing", nil},
	} {
		filter, err := parsePruneFilter(tc.filter, now)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.filter, err)
		}
		plan := buildPrunePlan(items, pruneOptions{filter: filter})
		got := make([]string, 0, len(plan))
		for i := range plan {
			got = append(got, plan[i].ID)
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("filter %q selected %v, want %v", tc.filter, got, tc.want)
		}
	}
}

func TestPruneDryRunAbortExitsTwoWithoutRemovedClaims(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{
		pruneStopped("sb-own", "owned"),
		pruneStopped("sb-foreign", "foreign"),
	}}
	sandbox := &pruneForeignSandbox{lifecycleSandbox: base, refuse: map[string]string{"sb-foreign": pruneCodeNotOwned}}
	runner, out := lifecycleRunner(base)
	runner.NewClient = func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }
	if code := runner.Run(context.Background(), []string{"prune", "--dry-run", "--json", "--filter", "name~^.*"}); code != 2 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Contains(out.String(), `"action": "removed"`) || !strings.Contains(out.String(), `"code": "NOT_OWNED"`) {
		t.Fatalf("abort output=%q", out.String())
	}
	if len(base.deletes) != 0 {
		t.Fatalf("dry-run abort deleted: %v", base.deletes)
	}
}

func TestPruneDryRunAndRealPlanIDsMatch(t *testing.T) {
	items := []sdk.Sandbox{pruneStopped("sb-1", "one"), pruneStopped("sb-2", "two")}
	drySandbox := &lifecycleSandbox{items: items}
	dryRunner, dryOut := lifecycleRunner(drySandbox)
	if code := dryRunner.Run(context.Background(), []string{"prune", "--dry-run"}); code != 0 {
		t.Fatalf("dry-run exit=%d output=%q", code, dryOut.String())
	}
	dryPlan := strings.TrimSpace(dryOut.String())
	if dryPlan != "sb-1\nsb-2" {
		t.Fatalf("dry plan=%q", dryPlan)
	}
	realSandbox := &lifecycleSandbox{items: items}
	realRunner, realOut := lifecycleRunner(realSandbox)
	if code := realRunner.Run(context.Background(), []string{"prune", "-f", "--filter", "status=stopped"}); code != 0 {
		t.Fatalf("real exit=%d output=%q", code, realOut.String())
	}
	ids := make([]string, 0, 2)
	for _, line := range strings.Split(strings.TrimSpace(realOut.String()), "\n") {
		if strings.HasPrefix(line, "summary:") {
			continue
		}
		ids = append(ids, strings.SplitN(line, "|", 2)[0])
	}
	if strings.Join(ids, ",") != "sb-1,sb-2" {
		t.Fatalf("real ids=%v output=%q", ids, realOut.String())
	}
}

func TestPruneStaleRecordSkipsAndExitsOne(t *testing.T) {
	first := pruneStopped("sb-1", "one")
	second := first
	second.UpdatedAt = time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)
	sandbox := &pruneSequenceSandbox{
		lifecycleSandbox: &lifecycleSandbox{},
		lists:            [][]sdk.Sandbox{{first}, {second}},
	}
	runner, out := lifecycleRunner(nil)
	runner.NewClient = func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }
	if code := runner.Run(context.Background(), []string{"prune", "-f", "--filter", "status=stopped"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.deletes) != 0 {
		t.Fatalf("stale item was deleted: %v", sandbox.deletes)
	}
	if !strings.Contains(out.String(), "sb-1|one|stale|STALE") ||
		!strings.Contains(out.String(), "summary: pruned=0 skipped=0 stale=1 unclassified=0 failure=0") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestPruneForeignRecordAbortsDefaultAndSkipsWithFlag(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{
		pruneStopped("sb-own", "owned"),
		pruneStopped("sb-foreign", "foreign"),
	}}
	sandbox := &pruneForeignSandbox{lifecycleSandbox: base, refuse: map[string]string{"sb-foreign": pruneCodeNotOwned}}

	runner, out := lifecycleRunner(base)
	runner.NewClient = func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }
	if code := runner.Run(context.Background(), []string{"prune", "-f", "--filter", "name~^.*"}); code != 2 {
		t.Fatalf("default exit=%d output=%q", code, out.String())
	}
	if len(base.deletes) != 0 {
		t.Fatalf("default run deleted: %v", base.deletes)
	}
	if !strings.Contains(out.String(), "sb-foreign|foreign|unclassified|NOT_OWNED") ||
		!strings.Contains(out.String(), "sb-own|owned|skipped|-") ||
		!strings.Contains(out.String(), "summary: pruned=0 skipped=1 stale=0 unclassified=1 failure=0") {
		t.Fatalf("output=%q", out.String())
	}

	allowBase := &lifecycleSandbox{items: []sdk.Sandbox{
		pruneStopped("sb-own", "owned"),
		pruneStopped("sb-foreign", "foreign"),
	}}
	allowSandbox := &pruneForeignSandbox{lifecycleSandbox: allowBase, refuse: map[string]string{"sb-foreign": pruneCodeNotOwned}}
	allowRunner, allowOut := lifecycleRunner(allowBase)
	allowRunner.NewClient = func(string) (sdk.Client, error) { return fakeClient{sandbox: allowSandbox}, nil }
	if code := allowRunner.Run(context.Background(), []string{"prune", "-f", "--allow-unknown-skip", "--filter", "name~^.*"}); code != 1 {
		t.Fatalf("allow exit=%d output=%q", code, allowOut.String())
	}
	if strings.Join(allowBase.deletes, ",") != "sb-own" {
		t.Fatalf("allow deletes=%v", allowBase.deletes)
	}
	if !strings.Contains(allowOut.String(), "sb-foreign|foreign|skipped|NOT_OWNED") ||
		!strings.Contains(allowOut.String(), "sb-own|owned|removed|-") {
		t.Fatalf("output=%q", allowOut.String())
	}
}

func TestPruneAllStopsRunningThenDeletes(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-run", Name: "running", State: sdk.StateRunning},
		pruneStopped("sb-stop", "stopped"),
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "-f", "--all"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.stops, ",") != "sb-run" || strings.Join(sandbox.deletes, ",") != "sb-run,sb-stop" {
		t.Fatalf("stops=%v deletes=%v", sandbox.stops, sandbox.deletes)
	}
	if !strings.Contains(out.String(), "sb-run|running|removed|-") ||
		!strings.Contains(out.String(), "summary: pruned=2 skipped=0 stale=0 unclassified=0 failure=0") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestPruneUnknownStopTimeSkipsAndExitsOne(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-unknown", Name: "unknown", State: sdk.StateStopped}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "-f", "--filter", "status=stopped"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.deletes) != 0 || !strings.Contains(out.String(), "sb-unknown|unknown|skipped|UNKNOWN_STATE") {
		t.Fatalf("deletes=%v output=%q", sandbox.deletes, out.String())
	}
}

func TestPruneLabelFilterMatchesAndSelects(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-ci", Name: "ci", State: sdk.StateStopped, StoppedAt: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC), Labels: map[string]string{"env": "ci"}},
		{ID: "sb-dev", Name: "dev", State: sdk.StateStopped, StoppedAt: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC), Labels: map[string]string{"env": "dev"}},
		pruneStopped("sb-plain", "plain"),
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "-f", "--filter", "label=env=ci"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.deletes, ",") != "sb-ci" {
		t.Fatalf("deletes=%v output=%q", sandbox.deletes, out.String())
	}
	if !strings.Contains(out.String(), "sb-ci|ci|removed|-") ||
		!strings.Contains(out.String(), "summary: pruned=1 skipped=0 stale=0 unclassified=0 failure=0") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestPruneLabelFilterParticipatesInDryRunPlan(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-ci", Name: "ci", State: sdk.StateStopped, StoppedAt: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC), Labels: map[string]string{"env": "ci"}},
		{ID: "sb-dev", Name: "dev", State: sdk.StateStopped, StoppedAt: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC), Labels: map[string]string{"env": "dev"}},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "--dry-run", "--json", "--filter", "label=env=dev"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var plan pruneDryRunEnvelope
	if err := json.Unmarshal(out.Bytes(), &plan); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	if len(plan.WouldRemove) != 1 || plan.WouldRemove[0].ID != "sb-dev" || plan.Summary.Planned != 1 {
		t.Fatalf("plan=%#v output=%q", plan, out.String())
	}
	if len(sandbox.deletes) != 0 {
		t.Fatalf("dry-run deleted %v", sandbox.deletes)
	}
}

func TestRmMultiTargetForeignRecordContinuesAndExitsOne(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{
		pruneStopped("sb-own", "owned"),
		pruneStopped("sb-foreign", "foreign"),
	}}
	sandbox := &pruneForeignSandbox{lifecycleSandbox: base, refuse: map[string]string{"sb-foreign": pruneCodeNotOwned}}
	runner, out := lifecycleRunner(base)
	runner.NewClient = func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }
	if code := runner.Run(context.Background(), []string{"rm", "-f", "owned", "foreign"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Join(base.deletes, ",") != "sb-own" {
		t.Fatalf("deletes=%v", base.deletes)
	}
	if !strings.Contains(out.String(), "sb-own|owned|removed|-") ||
		!strings.Contains(out.String(), "sb-foreign|foreign|refused|NOT_OWNED") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestRmSingleTargetOutputUnchanged(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{pruneStopped("sb-1", "one")}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "-f", "one"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if out.String() != "Removed sandbox one\n" {
		t.Fatalf("single-target output=%q", out.String())
	}
}

func TestMachineCodeOfFindsRegisteredToken(t *testing.T) {
	if got := machineCodeOf(errors.New("delete refused: PATH_ESCAPE: outside root")); got != pruneCodePathEscape {
		t.Fatalf("machineCodeOf=%q", got)
	}
	if got := machineCodeOf(errors.New("plain failure")); got != "" {
		t.Fatalf("machineCodeOf=%q", got)
	}
}
