package command

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

type cloneRemoteState int

const (
	cloneRemoteOwned cloneRemoteState = iota
	cloneRemoteUserEdited
	cloneRemoteForeignOwner
	cloneRemoteNoOwner
	cloneRemoteExtraConfig
	cloneRemoteBrokenWorkspace
)

func (s cloneRemoteState) preserved() bool {
	return s == cloneRemoteUserEdited || s == cloneRemoteForeignOwner ||
		s == cloneRemoteNoOwner || s == cloneRemoteExtraConfig
}

func TestPruneCleansCloneRemotes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		state       cloneRemoteState
		wantWarning bool
	}{
		{name: "owned remote is removed", state: cloneRemoteOwned},
		{name: "user edited remote is preserved", state: cloneRemoteUserEdited, wantWarning: true},
		{name: "foreign remote is preserved", state: cloneRemoteForeignOwner, wantWarning: true},
		{name: "remote without owner is preserved", state: cloneRemoteNoOwner, wantWarning: true},
		{name: "remote with extra user config is preserved", state: cloneRemoteExtraConfig, wantWarning: true},
		{name: "cleanup failure only warns", state: cloneRemoteBrokenWorkspace, wantWarning: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			workspace := newCloneCleanupWorkspace(t, tt.state != cloneRemoteBrokenWorkspace)
			sb := cloneCleanupSandbox("demo", "sb-demo", workspace)
			state := newFakeGitConfigState(cloneRemoteValues("sandbox-demo", sb.ID, tt.state))
			sandboxes := &lifecycleSandbox{items: []sdk.Sandbox{sb}}
			runner, out, errOut := cloneCleanupRunner(sandboxes, state)

			if code := runner.Run(context.Background(), []string{"prune", "--force"}); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if len(sandboxes.deletes) != 1 || sandboxes.deletes[0] != sb.ID {
				t.Fatalf("deletes=%v", sandboxes.deletes)
			}
			assertCloneRemoteState(t, state, "sandbox-demo", sb.ID, tt.state)
			assertCloneCleanupWarning(t, errOut.String(), tt.wantWarning)
		})
	}
}

func TestResetCleansCloneRemotesForMultipleSandboxes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		states       []cloneRemoteState
		wantWarnings int
	}{
		{
			name:   "all owned remotes are removed",
			states: []cloneRemoteState{cloneRemoteOwned, cloneRemoteOwned},
		},
		{
			name: "edited and foreign remotes are preserved",
			states: []cloneRemoteState{
				cloneRemoteOwned,
				cloneRemoteUserEdited,
				cloneRemoteForeignOwner,
			},
			wantWarnings: 2,
		},
		{
			name: "broken workspace does not fail the reset",
			states: []cloneRemoteState{
				cloneRemoteBrokenWorkspace,
				cloneRemoteOwned,
			},
			wantWarnings: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			items := make([]sdk.Sandbox, 0, len(tt.states))
			state := newFakeGitConfigState(nil)
			for i, remoteState := range tt.states {
				name := fmt.Sprintf("demo%d", i)
				workspace := newCloneCleanupWorkspace(t, remoteState != cloneRemoteBrokenWorkspace)
				sb := cloneCleanupSandbox(name, fmt.Sprintf("sb-%d", i), workspace)
				items = append(items, sb)
				for key, values := range cloneRemoteValues("sandbox-"+name, sb.ID, remoteState) {
					state.values[key] = slices.Clone(values)
				}
			}
			sandboxes := &lifecycleSandbox{items: items}
			runner, out, errOut := cloneCleanupRunner(sandboxes, state)

			if code := runner.Run(context.Background(), []string{"reset", "--force"}); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if len(sandboxes.deletes) != len(items) {
				t.Fatalf("deletes=%v, want %d", sandboxes.deletes, len(items))
			}
			for i, remoteState := range tt.states {
				assertCloneRemoteState(t, state, "sandbox-"+items[i].Name, items[i].ID, remoteState)
			}
			if got := strings.Count(errOut.String(), "warning: clone remote cleanup"); got != tt.wantWarnings {
				t.Fatalf("warnings=%d, want %d: %q", got, tt.wantWarnings, errOut.String())
			}
		})
	}
}

func TestBulkDeleteWithoutCloneMetadataDoesNotAccessGit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "prune", args: []string{"prune", "--force"}},
		{name: "reset", args: []string{"reset", "--force"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sandboxes := &lifecycleSandbox{items: []sdk.Sandbox{{
				ID: "sb-plain", Name: "plain", State: sdk.StateStopped,
				StoppedAt: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC),
				Workspace: filepath.Join(t.TempDir(), "missing"),
			}}}
			state := newFakeGitConfigState(nil)
			runner, out, errOut := cloneCleanupRunner(sandboxes, state)

			if code := runner.Run(context.Background(), tc.args); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if len(state.calls) != 0 {
				t.Fatalf("Git config was accessed without clone metadata: %v", state.calls)
			}
			if len(sandboxes.deletes) != 1 {
				t.Fatalf("deletes=%v", sandboxes.deletes)
			}
			if errOut.Len() != 0 {
				t.Fatalf("unexpected stderr: %q", errOut.String())
			}
		})
	}
}

func TestRemoveCloneSandboxWarnsAboutUnfetchedCommits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		clone       bool
		wantWarning bool
	}{
		{name: "clone sandbox warns before removal", clone: true, wantWarning: true},
		{name: "plain sandbox does not warn", clone: false},
	}
	wantParts := []string{
		"warning: sandbox demo is a private clone",
		"commits made inside it are lost when the sandbox is removed unless they are fetched first",
		"git fetch sandbox-demo",
		"refs/sandboxes/demo/*",
		"survive removal",
		"git branch LOCAL refs/sandboxes/demo/BRANCH",
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var sb sdk.Sandbox
			var state *fakeGitConfigState
			if tt.clone {
				workspace := newCloneCleanupWorkspace(t, true)
				sb = cloneCleanupSandbox("demo", "sb-demo", workspace)
				state = newFakeGitConfigState(cloneRemoteValues("sandbox-demo", sb.ID, cloneRemoteOwned))
			} else {
				sb = sdk.Sandbox{ID: "sb-demo", Name: "demo", State: sdk.StateStopped}
				state = newFakeGitConfigState(nil)
			}
			sandboxes := &lifecycleSandbox{items: []sdk.Sandbox{sb}}
			runner, out, errOut := cloneCleanupRunner(sandboxes, state)

			if code := runner.Run(context.Background(), []string{"rm", "--force", "demo"}); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if len(sandboxes.deletes) != 1 || sandboxes.deletes[0] != sb.ID {
				t.Fatalf("deletes=%v", sandboxes.deletes)
			}
			if strings.Contains(out.String(), "warning:") {
				t.Fatalf("clone warning was written to stdout: %q", out.String())
			}
			if !tt.wantWarning {
				if errOut.Len() != 0 {
					t.Fatalf("plain sandbox produced stderr: %q", errOut.String())
				}
				return
			}
			for _, part := range wantParts {
				if !strings.Contains(errOut.String(), part) {
					t.Fatalf("warning lacks %q: %q", part, errOut.String())
				}
			}
			assertCloneRemoteState(t, state, "sandbox-demo", sb.ID, cloneRemoteOwned)
		})
	}
}

func TestCloneRemovalWarningOnlyAppliesToOwnedClones(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		sb   *sdk.Sandbox
		want bool
	}{
		{name: "nil sandbox", sb: nil},
		{name: "no clone metadata", sb: &sdk.Sandbox{ID: "id", Name: "demo"}},
		{name: "mismatched remote name", sb: &sdk.Sandbox{ID: "id", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "sandbox-other"}}},
		{name: "remote without sandbox prefix", sb: &sdk.Sandbox{ID: "id", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "demo"}}},
		{name: "owned clone", sb: &sdk.Sandbox{ID: "id", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "sandbox-demo"}}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := cloneRemovalWarning(tt.sb)
			if (got != "") != tt.want {
				t.Fatalf("cloneRemovalWarning() = %q, want warning=%t", got, tt.want)
			}
			if tt.want && !strings.Contains(got, "refs/sandboxes/demo/*") {
				t.Fatalf("warning lacks the mirrored ref namespace: %q", got)
			}
		})
	}
}

func cloneCleanupSandbox(name, id, workspace string) sdk.Sandbox {
	return sdk.Sandbox{
		ID: id, Name: name, State: sdk.StateStopped,
		StoppedAt: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC),
		Workspace: workspace,
		Clone:     &sdk.CloneInfo{RemoteName: "sandbox-" + name, GuestWorkdir: "/workspace/" + name},
	}
}

func cloneCleanupRunner(sandboxes *lifecycleSandbox, state *fakeGitConfigState) (*Runner, *bytes.Buffer, *bytes.Buffer) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	return &Runner{
		Out: &out, Err: &errOut, In: strings.NewReader(""),
		NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandboxes}, nil },
		gitConfig: state.run,
	}, &out, &errOut
}

func newCloneCleanupWorkspace(t *testing.T, withGitDir bool) string {
	t.Helper()
	root := t.TempDir()
	if !withGitDir {
		return root
	}
	gitDir := filepath.Join(root, ".git")
	if err := os.Mkdir(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func cloneRemoteValues(remote, sandboxID string, state cloneRemoteState) map[string][]string {
	if state == cloneRemoteBrokenWorkspace {
		return nil
	}
	url := "git://127.0.0.1:4321/demo"
	name := strings.TrimPrefix(remote, "sandbox-")
	// legacy-compat "rheic-" git config keys (see cloneManagedByKey/cloneLastURLKey).
	values := map[string][]string{
		"remote." + remote + ".url":              {url},
		"remote." + remote + ".rheic-managed-by": {sandboxID},
		"remote." + remote + ".rheic-last-url":   {url},
		"remote." + remote + ".fetch": {
			"+refs/heads/*:refs/remotes/" + remote + "/*",
			"+refs/heads/*:refs/sandboxes/" + name + "/*",
		},
	}
	switch state {
	case cloneRemoteUserEdited:
		values["remote."+remote+".url"] = []string{"git://user-edit.invalid/demo"}
	case cloneRemoteForeignOwner:
		values["remote."+remote+".rheic-managed-by"] = []string{"other-sandbox-id"}
	case cloneRemoteNoOwner:
		delete(values, "remote."+remote+".rheic-managed-by")
	case cloneRemoteExtraConfig:
		values["remote."+remote+".pushurl"] = []string{"git://user-edit.invalid/demo"}
	}
	return values
}

func assertCloneRemoteState(t *testing.T, state *fakeGitConfigState, remote, sandboxID string, want cloneRemoteState) {
	t.Helper()
	prefix := "remote." + remote + "."
	if want == cloneRemoteOwned {
		for key := range state.values {
			if strings.HasPrefix(key, prefix) {
				t.Errorf("owned remote key %q was not removed", key)
			}
		}
		return
	}
	if !want.preserved() {
		return
	}
	for key, values := range cloneRemoteValues(remote, sandboxID, want) {
		if got := state.values[key]; !slices.Equal(got, values) {
			t.Errorf("preserved key %q = %v, want %v", key, got, values)
		}
	}
}

func assertCloneCleanupWarning(t *testing.T, stderr string, want bool) {
	t.Helper()
	got := strings.Contains(stderr, "warning: clone remote cleanup")
	if got != want {
		t.Fatalf("warning=%t, want %t: %q", got, want, stderr)
	}
	if want && !strings.Contains(stderr, "preserv") && !strings.Contains(stderr, "requires") {
		t.Fatalf("warning does not explain the failure: %q", stderr)
	}
}

type fakeGitExitError struct{ code int }

func (e fakeGitExitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func (e fakeGitExitError) ExitCode() int { return e.code }

type fakeGitConfigState struct {
	values map[string][]string
	calls  []string
}

func newFakeGitConfigState(values map[string][]string) *fakeGitConfigState {
	state := &fakeGitConfigState{values: make(map[string][]string, len(values))}
	for key, value := range values {
		state.values[key] = slices.Clone(value)
	}
	return state
}

func (s *fakeGitConfigState) run(_ context.Context, _ string, args ...string) (string, error) {
	s.calls = append(s.calls, strings.Join(args, " "))
	if len(args) < 2 {
		return "", fmt.Errorf("unexpected Git config invocation: %v", args)
	}
	switch args[0] {
	case "--get-all":
		values := s.values[args[1]]
		if len(values) == 0 {
			return "", fakeGitExitError{code: 1}
		}
		return strings.Join(values, "\n"), nil
	case "--get-regexp":
		pattern, err := regexp.Compile(args[1])
		if err != nil {
			return "", err
		}
		var lines []string
		for key, values := range s.values {
			if !pattern.MatchString(key) {
				continue
			}
			for _, value := range values {
				lines = append(lines, key+" "+value)
			}
		}
		if len(lines) == 0 {
			return "", fakeGitExitError{code: 1}
		}
		sort.Strings(lines)
		return strings.Join(lines, "\n"), nil
	case "--replace-all":
		if len(args) < 3 {
			return "", fmt.Errorf("replace-all requires a value: %v", args)
		}
		s.values[args[1]] = []string{args[2]}
		return "", nil
	case "--add":
		if len(args) < 3 {
			return "", fmt.Errorf("add requires a value: %v", args)
		}
		s.values[args[1]] = append(s.values[args[1]], args[2])
		return "", nil
	case "--unset-all":
		delete(s.values, args[1])
		return "", nil
	default:
		return "", fmt.Errorf("unexpected Git config invocation: %v", args)
	}
}

func TestPruneWarnsBeforeRemovingCloneSandbox(t *testing.T) {
	t.Parallel()
	workspace := newCloneCleanupWorkspace(t, true)
	sb := cloneCleanupSandbox("demo", "sb-demo", workspace)
	state := newFakeGitConfigState(cloneRemoteValues("sandbox-demo", sb.ID, cloneRemoteOwned))
	sandboxes := &lifecycleSandbox{items: []sdk.Sandbox{sb}}
	runner, out, errOut := cloneCleanupRunner(sandboxes, state)

	if code := runner.Run(context.Background(), []string{"prune", "--force"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if len(sandboxes.deletes) != 1 || sandboxes.deletes[0] != sb.ID {
		t.Fatalf("deletes=%v", sandboxes.deletes)
	}
	for _, part := range []string{
		"warning: sandbox demo is a private clone",
		"commits made inside it are lost",
		"git fetch sandbox-demo",
	} {
		if !strings.Contains(errOut.String(), part) {
			t.Fatalf("stderr=%q, want %q", errOut.String(), part)
		}
	}
}
