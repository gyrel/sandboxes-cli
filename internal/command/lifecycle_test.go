package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

type lifecycleSandbox struct {
	fakeSandbox
	items     []sdk.Sandbox
	starts    []string
	stops     []string
	deletes   []string
	startErr  error
	deleteErr error
}

func (s *lifecycleSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: s.items}, nil
}
func (s *lifecycleSandbox) Start(_ context.Context, id string) (*sdk.Operation, error) {
	s.starts = append(s.starts, id)
	if s.startErr != nil {
		return nil, s.startErr
	}
	return &sdk.Operation{ID: "op-start", State: sdk.StateDone}, nil
}
func (s *lifecycleSandbox) Get(_ context.Context, id string) (*sdk.Sandbox, error) {
	for i := range s.items {
		if s.items[i].ID == id || s.items[i].Name == id {
			item := s.items[i]
			return &item, nil
		}
	}
	return nil, errors.New("not found")
}

func (s *lifecycleSandbox) Stop(_ context.Context, id string, _ sdk.StopOptions) (*sdk.Operation, error) {
	s.stops = append(s.stops, id)
	return &sdk.Operation{ID: "op-stop", State: sdk.StateDone}, nil
}
func (s *lifecycleSandbox) Delete(_ context.Context, id string, _ sdk.DeleteOptions) (*sdk.Operation, error) {
	s.deletes = append(s.deletes, id)
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	return &sdk.Operation{ID: "op-delete", State: sdk.StateDone}, nil
}

func lifecycleRunner(sandbox *lifecycleSandbox) (*Runner, *bytes.Buffer) {
	var out bytes.Buffer
	return &Runner{
		Out: &out, Err: &out, In: strings.NewReader(""),
		NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil },
	}, &out
}

func TestRemoveRequiresForceWithoutTerminal(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: sdk.StateStopped}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "dev"}); code != 1 || len(sandbox.deletes) != 0 {
		t.Fatalf("exit=%d deletes=%v output=%q", code, sandbox.deletes, out.String())
	}
	if !strings.Contains(out.String(), "use --force") {
		t.Fatalf("missing force guidance: %q", out.String())
	}
}

func TestRemoveRequiresStoppedSandboxesWithoutForce(t *testing.T) {
	tests := []struct {
		name        string
		items       []sdk.Sandbox
		args        []string
		confirmed   bool
		wantCode    int
		wantDeletes []string
		wantErrors  []string
		wantPrompts int
	}{
		{
			name:       "running without force",
			items:      []sdk.Sandbox{{ID: "sb-run", Name: "running", State: sdk.StateRunning}},
			args:       []string{"rm", "running"},
			wantCode:   1,
			wantErrors: []string{"sandbox running is running; stop it first or pass --force"},
		},
		{
			name:       "other active state without force",
			items:      []sdk.Sandbox{{ID: "sb-create", Name: "booting", State: sdk.StateCreating}},
			args:       []string{"rm", "booting"},
			wantCode:   1,
			wantErrors: []string{"sandbox booting is creating; wait until it is stopped or pass --force"},
		},
		{
			name:        "running with force",
			items:       []sdk.Sandbox{{ID: "sb-run", Name: "running", State: sdk.StateRunning}},
			args:        []string{"rm", "--force", "running"},
			wantCode:    0,
			wantDeletes: []string{"sb-run"},
		},
		{
			name: "mixed batch refuses the whole batch",
			items: []sdk.Sandbox{
				{ID: "sb-stop", Name: "stopped", State: sdk.StateStopped},
				{ID: "sb-run", Name: "running", State: sdk.StateRunning},
			},
			args:       []string{"rm", "stopped", "running"},
			wantCode:   1,
			wantErrors: []string{"sandbox running is running; stop it first or pass --force"},
		},
		{
			name: "multiple running sandboxes are all reported",
			items: []sdk.Sandbox{
				{ID: "sb-one", Name: "one", State: sdk.StateRunning},
				{ID: "sb-two", Name: "two", State: sdk.StateRunning},
			},
			args:     []string{"rm", "one", "two"},
			wantCode: 1,
			wantErrors: []string{
				"sandbox one is running; stop it first or pass --force",
				"sandbox two is running; stop it first or pass --force",
			},
		},
		{
			name:        "stopped without force deletes after confirmation",
			items:       []sdk.Sandbox{{ID: "sb-stop", Name: "stopped", State: sdk.StateStopped}},
			args:        []string{"rm", "stopped"},
			confirmed:   true,
			wantCode:    0,
			wantDeletes: []string{"sb-stop"},
			wantPrompts: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sandbox := &lifecycleSandbox{items: tt.items}
			runner, out := lifecycleRunner(sandbox)
			prompts := 0
			runner.removalPrompt = func(int) (bool, error) {
				prompts++
				return tt.confirmed, nil
			}
			if code := runner.Run(context.Background(), tt.args); code != tt.wantCode {
				t.Fatalf("exit=%d want=%d output=%q", code, tt.wantCode, out.String())
			}
			if got, want := strings.Join(sandbox.deletes, ","), strings.Join(tt.wantDeletes, ","); got != want {
				t.Fatalf("deletes=%q want=%q", got, want)
			}
			if prompts != tt.wantPrompts {
				t.Fatalf("prompts=%d want=%d", prompts, tt.wantPrompts)
			}
			for _, want := range tt.wantErrors {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("output lacks %q: %q", want, out.String())
				}
			}
		})
	}
}

func TestRemoveMultipleResolvesNamesAndForces(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-1", Name: "one", State: sdk.StateStopped},
		{ID: "sb-2", Name: "two", State: sdk.StateStopped},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "-f", "one", "two"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.deletes, ",") != "sb-1,sb-2" {
		t.Fatalf("deletes=%v", sandbox.deletes)
	}
}

func TestRemovePartialFailureReturnsOne(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one", State: sdk.StateStopped}}, deleteErr: errors.New("cannot remove")}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "--force", "one", "missing"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.deletes) != 1 || !strings.Contains(out.String(), "cannot remove") || !strings.Contains(out.String(), "missing") {
		t.Fatalf("unexpected partial failure: deletes=%v output=%q", sandbox.deletes, out.String())
	}
}

func TestStopMultipleSandboxes(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-1", Name: "one"}, {ID: "sb-2", Name: "two"},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"stop", "one", "two"}); code != 0 {
		t.Fatalf("stop exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.stops, ",") != "sb-1,sb-2" {
		t.Fatalf("stops=%v", sandbox.stops)
	}
}

func TestPruneDryRunListsOnlyStopped(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-run", Name: "running", State: sdk.StateRunning},
		{ID: "sb-stop", Name: "stopped", State: sdk.StateStopped, StoppedAt: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "--dry-run"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "stopped") || strings.Contains(out.String(), "running") || len(sandbox.deletes) != 0 {
		t.Fatalf("unexpected dry-run: deletes=%v output=%q", sandbox.deletes, out.String())
	}
}

func TestPruneRemovesOnlyStopped(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-run", Name: "running", State: sdk.StateRunning},
		{ID: "sb-stop", Name: "stopped", State: sdk.StateStopped, StoppedAt: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "-f"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.deletes, ",") != "sb-stop" {
		t.Fatalf("deletes=%v", sandbox.deletes)
	}
}

func TestPruneRequiresForceWithoutTerminal(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-stop", Name: "stopped", State: sdk.StateStopped, StoppedAt: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune"}); code != 1 || len(sandbox.deletes) != 0 {
		t.Fatalf("exit=%d deletes=%v output=%q", code, sandbox.deletes, out.String())
	}
	if !strings.Contains(out.String(), "use --force") {
		t.Fatalf("missing force guidance: %q", out.String())
	}
}

func TestRemoveAllRequiresForceWithoutTerminal(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one", State: sdk.StateStopped}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "--all"}); code != 1 || len(sandbox.deletes) != 0 {
		t.Fatalf("exit=%d deletes=%v output=%q", code, sandbox.deletes, out.String())
	}
}

func TestRemoveAllForceDeletesEverySandbox(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-1", Name: "one", State: sdk.StateStopped},
		{ID: "sb-2", Name: "two", State: sdk.StateStopped},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "--all", "--force"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.deletes, ",") != "sb-1,sb-2" {
		t.Fatalf("deletes=%v", sandbox.deletes)
	}
}

func TestRemoveAllRejectsTargets(t *testing.T) {
	sandbox := &lifecycleSandbox{}
	runner, _ := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "--all", "one"}); code != 2 {
		t.Fatalf("exit=%d", code)
	}
}

func TestStopJSONAndYAMLFormats(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one"}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"stop", "--json", "one"}); code != 0 {
		t.Fatalf("json exit=%d output=%q", code, out.String())
	}
	var records []mutationOutput
	if err := json.Unmarshal(out.Bytes(), &records); err != nil || len(records) != 1 ||
		records[0].Action != "stopped" || records[0].Resource != "sandbox" || records[0].Name != "one" {
		t.Fatalf("records=%#v err=%v", records, err)
	}
	runner, out = lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"stop", "--format", "yaml", "one"}); code != 0 {
		t.Fatalf("yaml exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "action: stopped") || !strings.Contains(out.String(), "name: one") {
		t.Fatalf("unexpected yaml: %q", out.String())
	}
}

func TestRemoveJSONFormat(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one", State: sdk.StateStopped}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "-f", "--json", "one"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var records []mutationOutput
	if err := json.Unmarshal(out.Bytes(), &records); err != nil || len(records) != 1 ||
		records[0].Action != "removed" || records[0].Resource != "sandbox" || records[0].Name != "one" {
		t.Fatalf("records=%#v err=%v", records, err)
	}
}

func TestPruneJSONFormats(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-stop", Name: "stopped", State: sdk.StateStopped, StoppedAt: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "--dry-run", "--json"}); code != 0 {
		t.Fatalf("dry-run exit=%d output=%q", code, out.String())
	}
	var candidates pruneDryRunOutput
	if err := json.Unmarshal(out.Bytes(), &candidates); err != nil || len(candidates.WouldRemove) != 1 ||
		candidates.WouldRemove[0].Name != "stopped" || len(candidates.SkippedUnknownStop) != 0 {
		t.Fatalf("candidates=%#v err=%v", candidates, err)
	}
	runner, out = lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "-f", "--json"}); code != 0 {
		t.Fatalf("force exit=%d output=%q", code, out.String())
	}
	var records []mutationOutput
	if err := json.Unmarshal(out.Bytes(), &records); err != nil || len(records) != 1 ||
		records[0].Action != "removed" || records[0].Name != "stopped" {
		t.Fatalf("records=%#v err=%v", records, err)
	}
}

func TestParsePruneFilter(t *testing.T) {
	now := time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		value string
		want  time.Time
		has   bool
		ok    bool
	}{
		{"", time.Time{}, false, true},
		{"until=2026-10-31T01:00:00Z", time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC), true, true},
		{"until=1761862800", time.Unix(1761862800, 0).UTC(), true, true},
		{"until=2h", now.Add(-2 * time.Hour), true, true},
		{"until=bad", time.Time{}, false, false},
		{"not-until=2h", time.Time{}, false, false},
		{"until=-1h", time.Time{}, false, false},
	} {
		got, has, err := parsePruneFilter(tc.value, now)
		if (err == nil) != tc.ok || has != tc.has || !got.Equal(tc.want) {
			t.Fatalf("parsePruneFilter(%q)=%v,%t,%v", tc.value, got, has, err)
		}
	}
}

func TestSelectPruneCandidatesHonorsUntilAndUnknownStopTime(t *testing.T) {
	now := time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)
	items := []sdk.Sandbox{
		{ID: "old", Name: "old", State: sdk.StateStopped, StoppedAt: now.Add(-3 * time.Hour)},
		{ID: "new", Name: "new", State: sdk.StateStopped, StoppedAt: now.Add(-time.Hour)},
		{ID: "unknown", Name: "unknown", State: sdk.StateStopped},
		{ID: "running", Name: "running", State: sdk.StateRunning, StoppedAt: now.Add(-4 * time.Hour)},
	}
	cutoff := now.Add(-2 * time.Hour)
	got, skipped := selectPruneCandidates(items, &cutoff)
	if len(got) != 1 || got[0].ID != "old" {
		t.Fatalf("filtered=%v", got)
	}
	if len(skipped) != 1 || skipped[0] != "unknown" {
		t.Fatalf("skipped=%v", skipped)
	}
	all, skippedAll := selectPruneCandidates(items, nil)
	if len(all) != 2 || len(skippedAll) != 1 || skippedAll[0] != "unknown" {
		t.Fatalf("unfiltered=%v skipped=%v", all, skippedAll)
	}
}

func TestResetRemovesAllSandboxesWithForce(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-1", Name: "one", State: sdk.StateRunning},
		{ID: "sb-2", Name: "two", State: sdk.StateStopped},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"reset", "--force"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.deletes) != 2 {
		t.Fatalf("deletes=%v", sandbox.deletes)
	}
	if !strings.Contains(out.String(), "Reset 2 sandbox") {
		t.Fatalf("output=%q", out.String())
	}
}
