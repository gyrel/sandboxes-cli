package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

// testCloneToken is a fixed, well-formed sandbox token used by clone tests.
var testCloneToken = strings.Repeat("a", 64)

func cloneTestEndpointPath(repository string) string {
	return testCloneToken + "/" + repository
}

func cloneTestEndpointURL(port uint32, repository string) string {
	return fmt.Sprintf("git://127.0.0.1:%d/%s", port, cloneTestEndpointPath(repository))
}

func TestValidateCloneInfo(t *testing.T) {
	t.Parallel()
	sb := &sdk.Sandbox{
		ID: "id-1", Name: "demo",
		Clone: &sdk.CloneInfo{
			RemoteName: "sandbox-demo", GuestWorkdir: "/workspace/demo",
			GitEndpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 4321, Repository: cloneTestEndpointPath("demo")},
		},
	}
	workdir, url, err := validateCloneInfo(sb)
	if err != nil || workdir != "/workspace/demo" || url != cloneTestEndpointURL(4321, "demo") {
		t.Fatalf("validateCloneInfo() = %q, %q, %v", workdir, url, err)
	}
	badCases := []*sdk.Sandbox{
		{ID: "x", Name: "demo"},
		{ID: "x", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "origin", GuestWorkdir: "/workspace", GitEndpoint: sb.Clone.GitEndpoint}},
		{ID: "x", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "sandbox-demo", GuestWorkdir: "/workspace/../etc", GitEndpoint: sb.Clone.GitEndpoint}},
		{ID: "x", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "sandbox-demo", GuestWorkdir: "/workspace", GitEndpoint: &sdk.GitEndpoint{HostIP: "0.0.0.0", Port: 1, Repository: cloneTestEndpointPath("repo")}}},
		{ID: "x", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "sandbox-demo", GuestWorkdir: "/workspace", GitEndpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 0, Repository: cloneTestEndpointPath("repo")}}},
		{ID: "x", Name: "demo", Clone: &sdk.CloneInfo{RemoteName: "sandbox-demo", GuestWorkdir: "/workspace", GitEndpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: cloneTestEndpointPath("../repo")}}},
	}
	for i, bad := range badCases {
		if _, _, err := validateCloneInfo(bad); err == nil {
			t.Errorf("case %d unexpectedly validated", i)
		}
	}
}

func TestCloneEndpointURLShape(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		endpoint *sdk.GitEndpoint
		want     string
		wantErr  bool
	}{
		{
			name:     "token and repository path",
			endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 4321, Repository: cloneTestEndpointPath("demo")},
			want:     cloneTestEndpointURL(4321, "demo"),
		},
		{
			name:     "low port and punctuated repository",
			endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: cloneTestEndpointPath("my.repo_1")},
			want:     cloneTestEndpointURL(1, "my.repo_1"),
		},
		{
			name:     "highest port",
			endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 65535, Repository: cloneTestEndpointPath("r")},
			want:     cloneTestEndpointURL(65535, "r"),
		},
		{name: "missing endpoint", wantErr: true},
		{name: "non-loopback host", endpoint: &sdk.GitEndpoint{HostIP: "192.0.2.10", Port: 1, Repository: cloneTestEndpointPath("r")}, wantErr: true},
		{name: "zero port", endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 0, Repository: cloneTestEndpointPath("r")}, wantErr: true},
		{name: "port above range", endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 65536, Repository: cloneTestEndpointPath("r")}, wantErr: true},
		{name: "legacy tokenless repository", endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: "r"}, wantErr: true},
		{name: "short token", endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: testCloneToken[:63] + "/r"}, wantErr: true},
		{name: "uppercase token", endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: strings.ToUpper(testCloneToken) + "/r"}, wantErr: true},
		{name: "empty token", endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: "/r"}, wantErr: true},
		{name: "dot repository", endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: cloneTestEndpointPath(".")}, wantErr: true},
		{name: "traversal repository", endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: cloneTestEndpointPath("../r")}, wantErr: true},
		{name: "empty repository", endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: cloneTestEndpointPath("")}, wantErr: true},
		{name: "repository with slash", endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: cloneTestEndpointPath("a/b")}, wantErr: true},
		{name: "repository with newline", endpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: 1, Repository: cloneTestEndpointPath("r\nevil")}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := cloneEndpointURL(tt.endpoint)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("cloneEndpointURL(%#v) = %q, want error", tt.endpoint, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("cloneEndpointURL() = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, ".git") || strings.HasSuffix(got, "/") {
				t.Fatalf("clone URL does not match the sbx shape: %q", got)
			}
		})
	}
}

func TestReconcileCloneRemoteManagesSbxFetchRefspecs(t *testing.T) {
	t.Parallel()
	const (
		url            = "git://127.0.0.1:4321/demo"
		firstRefspec   = "+refs/heads/*:refs/remotes/sandbox-demo/*"
		secondRefspec  = "+refs/heads/*:refs/sandboxes/demo/*"
		managedFetch   = "remote.sandbox-demo.fetch"
		reconcileCalls = 2
	)
	tests := []struct {
		name     string
		fresh    bool
		existing []string
		want     []string
	}{
		{name: "new remote gets both refspecs", fresh: true, want: []string{firstRefspec, secondRefspec}},
		{name: "remote from an older release gains both refspecs", existing: nil, want: []string{firstRefspec, secondRefspec}},
		{name: "missing mirror refspec is repaired", existing: []string{firstRefspec}, want: []string{firstRefspec, secondRefspec}},
		{name: "missing remote-tracking refspec is repaired", existing: []string{secondRefspec}, want: []string{secondRefspec, firstRefspec}},
		{name: "complete remote is left unchanged", existing: []string{firstRefspec, secondRefspec}, want: []string{firstRefspec, secondRefspec}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := initCloneTestRepo(t)
			configPath := filepath.Join(root, ".git", "config")
			if !tt.fresh {
				seedCloneRemote(t, configPath, url, tt.existing)
			}
			ctx := context.Background()
			for attempt := 0; attempt < reconcileCalls; attempt++ {
				if err := reconcileCloneRemote(ctx, root, "sandbox-demo", "sandbox-id", url, runGitConfig); err != nil {
					t.Fatalf("reconcile attempt %d: %v", attempt, err)
				}
				if got := gitConfigValues(t, configPath, managedFetch); !slices.Equal(got, tt.want) {
					t.Fatalf("attempt %d refspecs = %#v, want %#v", attempt, got, tt.want)
				}
			}
		})
	}
}

func TestReconcileCloneRemoteRefreshIsByteIdempotent(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	ctx := context.Background()
	if err := reconcileCloneRemote(ctx, root, "sandbox-demo", "sandbox-id", "git://127.0.0.1:4321/demo", runGitConfig); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconcileCloneRemote(ctx, root, "sandbox-demo", "sandbox-id", "git://127.0.0.1:4321/demo", runGitConfig); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("idempotent refresh rewrote .git/config:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestReconcileCloneRemoteNeverRewritesForeignRemote(t *testing.T) {
	t.Parallel()
	const url = "git://127.0.0.1:4321/demo"
	// The "rheic-" git config keys below are legacy-compat: the pre-rename
	// on-disk keys are retained (see cloneManagedByKey/cloneLastURLKey) so
	// existing clones keep their management bookkeeping.
	tests := []struct {
		name     string
		settings map[string]string
		fetch    string
	}{
		{
			name: "foreign owner",
			settings: map[string]string{
				"url": url, "rheic-last-url": url, "rheic-managed-by": "other-sandbox-id",
			},
		},
		{
			name: "user edited URL",
			settings: map[string]string{
				"url": "git://user-edit.invalid/demo", "rheic-last-url": url, "rheic-managed-by": "sandbox-id",
			},
		},
		{
			name: "missing owner marker",
			settings: map[string]string{
				"url": url, "rheic-last-url": url,
			},
		},
		{
			name: "user added fetch refspec",
			settings: map[string]string{
				"url": url, "rheic-last-url": url, "rheic-managed-by": "sandbox-id",
			},
			fetch: "+refs/heads/*:refs/tags/private/*",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := initCloneTestRepo(t)
			configPath := filepath.Join(root, ".git", "config")
			for key, value := range tt.settings {
				if err := gitConfigSet(t, configPath, "--replace-all", "remote.sandbox-demo."+key, value); err != nil {
					t.Fatal(err)
				}
			}
			if tt.fetch != "" {
				if err := gitConfigSet(t, configPath, "--add", "remote.sandbox-demo.fetch", tt.fetch); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			err = reconcileCloneRemote(context.Background(), root, "sandbox-demo", "sandbox-id", url, runGitConfig)
			if err == nil || !strings.Contains(err.Error(), "preserving it") {
				t.Fatalf("reconcile error = %v, want preservation error", err)
			}
			after, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("foreign remote was rewritten:\nbefore:\n%s\nafter:\n%s", before, after)
			}
		})
	}
}

func seedCloneRemote(t *testing.T, configPath, url string, refspecs []string) {
	t.Helper()
	// legacy-compat "rheic-" git config keys (see cloneManagedByKey/cloneLastURLKey).
	for key, value := range map[string]string{
		"remote.sandbox-demo.url":              url,
		"remote.sandbox-demo.rheic-last-url":   url,
		"remote.sandbox-demo.rheic-managed-by": "sandbox-id",
	} {
		if err := gitConfigSet(t, configPath, "--replace-all", key, value); err != nil {
			t.Fatal(err)
		}
	}
	for _, refspec := range refspecs {
		if err := gitConfigSet(t, configPath, "--add", "remote.sandbox-demo.fetch", refspec); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReusedCloneRequiresMatchingSource(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	canonical, err := canonicalCloneSourcePath(root)
	if err != nil {
		t.Fatal(err)
	}
	sandbox := &sdk.Sandbox{
		ID: "id-1", Name: "demo", Workspace: canonical,
		Clone: &sdk.CloneInfo{RemoteName: "sandbox-demo", GuestWorkdir: "/workspace/demo"},
	}
	if err := checkReusedCloneSource(sandbox, canonical); err != nil {
		t.Fatalf("matching source rejected: %v", err)
	}
	if err := checkReusedCloneSource(sandbox, canonical+"-other"); err == nil {
		t.Fatal("mismatched source accepted")
	}
}

func TestCloneWorkspaceRejectsWorktreeGitFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: /tmp/elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cloneWorkspaceForMount(context.Background(), sdk.Workspace{Path: root}); err == nil || !strings.Contains(err.Error(), ".git directory") {
		t.Fatalf("expected .git file rejection, got %v", err)
	}
}

func TestSafeGitEnvironmentDropsInheritedGitOverrides(t *testing.T) {
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "remote.origin.url")
	t.Setenv("GIT_CONFIG_VALUE_0", "https://attacker.invalid/repo")
	t.Setenv("GIT_DIR", "/tmp/attacker.git")
	for _, item := range safeGitEnvironment() {
		key, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(strings.ToUpper(key), "GIT_") && key != "GIT_CONFIG_NOSYSTEM" && key != "GIT_CONFIG_GLOBAL" && key != "GIT_TERMINAL_PROMPT" {
			t.Errorf("unsafe inherited Git environment variable remains: %s", key)
		}
	}
}

func TestReconcileCloneRemoteOwnershipAndDuplicateProtection(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	cfg := filepath.Join(root, ".git", "config")
	ctx := context.Background()
	remote := "sandbox-demo"
	first := "git://127.0.0.1:1234/demo"
	second := "git://127.0.0.1:5678/demo"
	if err := reconcileCloneRemote(ctx, root, remote, "sandbox-id", first, runGitConfig); err != nil {
		t.Fatal(err)
	}
	if err := reconcileCloneRemote(ctx, root, remote, "sandbox-id", second, runGitConfig); err != nil {
		t.Fatal(err)
	}
	if err := gitConfigSet(t, cfg, "--add", "remote.sandbox-demo.url", "git://user-edit.invalid/demo.git"); err != nil {
		t.Fatal(err)
	}
	if err := reconcileCloneRemote(ctx, root, remote, "sandbox-id", first, runGitConfig); err == nil {
		t.Fatal("duplicate URL values were not reported as conflict")
	}
	values := gitConfigValues(t, cfg, "remote.sandbox-demo.url")
	if len(values) != 2 || values[0] != second || values[1] != "git://user-edit.invalid/demo.git" {
		t.Fatalf("duplicate/user URL values changed: %#v", values)
	}
}

func TestRemoveCloneRemotePreservesUserAddedOptions(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	cfg := filepath.Join(root, ".git", "config")
	ctx := context.Background()
	if err := reconcileCloneRemote(ctx, root, "sandbox-demo", "sandbox-id", "git://127.0.0.1:1234/demo", runGitConfig); err != nil {
		t.Fatal(err)
	}
	if got := gitConfigValues(t, cfg, "remote.sandbox-demo.fetch"); !slices.Equal(got, []string{
		"+refs/heads/*:refs/remotes/sandbox-demo/*",
		"+refs/heads/*:refs/sandboxes/demo/*",
	}) {
		t.Fatalf("managed fetch refspecs = %#v", got)
	}
	if err := gitConfigSet(t, cfg, "--add", "remote.sandbox-demo.pushurl", "git://user-edit.invalid/demo"); err != nil {
		t.Fatal(err)
	}
	if err := removeCloneRemote(ctx, root, "sandbox-demo", "sandbox-id", runGitConfig); err == nil {
		t.Fatal("removal should preserve and report a user-extended section")
	}
	if got := gitConfigValues(t, cfg, "remote.sandbox-demo.pushurl"); len(got) != 1 {
		t.Fatalf("user remote option was removed: %#v", got)
	}
	if got := gitConfigValues(t, cfg, "remote.sandbox-demo.url"); len(got) != 1 {
		t.Fatalf("owned remote URL should remain on conflict: %#v", got)
	}
}

func TestReconcileCloneRemoteSerializesConcurrentGitConfigWriter(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	ctx := context.Background()
	concurrentAttempted := false
	var concurrentErr error
	run := func(ctx context.Context, path string, args ...string) (string, error) {
		if !concurrentAttempted {
			concurrentAttempted = true
			commandArgs := []string{"config", "--file", configPath, "--replace-all", "remote.sandbox-demo.url", "git://user-edit.invalid/demo.git"}
			command := exec.CommandContext(ctx, "git", commandArgs...)
			output, err := command.CombinedOutput()
			if err != nil {
				concurrentErr = &testCommandError{err: err, output: string(output)}
			} else {
				concurrentErr = errors.New("concurrent Git config writer unexpectedly succeeded")
			}
		}
		return runGitConfig(ctx, path, args...)
	}
	if err := reconcileCloneRemote(ctx, root, "sandbox-demo", "sandbox-id", cloneTestEndpointURL(4321, "demo"), run); err != nil {
		t.Fatal(err)
	}
	if concurrentErr == nil {
		t.Fatal("concurrent Git config writer was not blocked by the config lock")
	}
	values := gitConfigValues(t, configPath, "remote.sandbox-demo.url")
	if len(values) != 1 || values[0] != cloneTestEndpointURL(4321, "demo") {
		t.Fatalf("unexpected remote after serialized update: %#v", values)
	}
}

func TestGitConfigLockRejectsReplacedLockPath(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	gitDir, err := os.Lstat(filepath.Join(root, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := configPath + ".lock"
	replacement := []byte("attacker lock replacement")
	err = withGitConfigLock(configPath, gitDir, func(string) error {
		if err := os.Remove(lockPath); err != nil {
			return err
		}
		return os.WriteFile(lockPath, replacement, 0o600)
	})
	if err == nil || !strings.Contains(err.Error(), "lock was replaced") {
		t.Fatalf("expected lock replacement conflict, got %v", err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("replacement lock was committed over the original Git config")
	}
	got, err := os.ReadFile(lockPath)
	if err != nil || !bytes.Equal(got, replacement) {
		t.Fatalf("foreign replacement lock was removed or changed: %q, %v", got, err)
	}
}

func TestGitConfigLockMutationFailureLeavesConfigUntouched(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	gitDir, err := os.Lstat(filepath.Join(root, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("synthetic mutation failure")
	err = withGitConfigLock(configPath, gitDir, func(string) error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected injected failure, got %v", err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed config mutation changed the original file")
	}
	if _, err := os.Lstat(configPath + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned config lock was not cleaned up: %v", err)
	}
}

func TestGitConfigLockRejectsReplacedGitDirectory(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	gitDir, err := os.Lstat(filepath.Join(root, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	err = withGitConfigLock(configPath, gitDir, func(string) error {
		oldPath := filepath.Join(root, ".git-original")
		if err := os.Rename(filepath.Join(root, ".git"), oldPath); err != nil {
			// Windows refuses to rename a directory that still has an open lock
			// file, so the replacement cannot be staged there; the lock itself
			// is still exercised by the other cases.
			t.Skipf("host cannot replace a locked Git directory: %v", err)
		}
		if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, ".git", "config"), []byte("replacement directory"), 0o600)
	})
	if err == nil || !strings.Contains(err.Error(), "directory changed") {
		t.Fatalf("expected Git directory replacement conflict, got %v", err)
	}
	after, err := os.ReadFile(filepath.Join(root, ".git", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("replaced Git directory unexpectedly contains the original config")
	}
}

func TestActivateCloneSandboxReachableEndpointWritesRemote(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	sb := cloneTestSandbox("demo", 4321)
	var calls int
	var address string
	runner := &Runner{cloneDial: func(_ context.Context, network, target string) (net.Conn, error) {
		calls++
		if network != "tcp" {
			t.Errorf("probe network = %q, want tcp", network)
		}
		address = target
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}}
	workdir, err := runner.activateCloneSandbox(context.Background(), sb, root)
	if err != nil {
		t.Fatalf("activateCloneSandbox() error = %v", err)
	}
	if workdir != "/workspace/demo" {
		t.Fatalf("workdir = %q", workdir)
	}
	if calls != 1 || address != "127.0.0.1:4321" {
		t.Fatalf("probe calls=%d address=%q", calls, address)
	}
	configPath := filepath.Join(root, ".git", "config")
	values := gitConfigValues(t, configPath, "remote.sandbox-demo.url")
	if len(values) != 1 || values[0] != cloneTestEndpointURL(4321, "demo") {
		t.Fatalf("managed remote = %#v", values)
	}
	refspecs := gitConfigValues(t, configPath, "remote.sandbox-demo.fetch")
	if !slices.Equal(refspecs, []string{
		"+refs/heads/*:refs/remotes/sandbox-demo/*",
		"+refs/heads/*:refs/sandboxes/demo/*",
	}) {
		t.Fatalf("managed fetch refspecs = %#v", refspecs)
	}
}

func TestActivateCloneSandboxUnreachableEndpointLeavesConfigUntouched(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	runner := &Runner{cloneDial: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("connection refused")
	}}
	_, err = runner.activateCloneSandbox(context.Background(), cloneTestSandbox("demo", 4321), root)
	want := "the clone endpoint for sandbox demo is not reachable; run 'rsbx stop demo' and 'rsbx run --name demo' to republish it"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if calls != cloneEndpointProbeAttempts {
		t.Fatalf("probe attempts = %d, want %d", calls, cloneEndpointProbeAttempts)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("unreachable endpoint changed .git/config")
	}
}

func TestActivateCloneSandboxUnreachableEndpointPreservesExistingRemote(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	first := "git://127.0.0.1:1234/demo"
	if err := reconcileCloneRemote(context.Background(), root, "sandbox-demo", "sandbox-id", first, runGitConfig); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	runner := &Runner{cloneDial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}}
	if _, err := runner.activateCloneSandbox(context.Background(), cloneTestSandbox("demo", 5678), root); err == nil {
		t.Fatal("unreachable endpoint unexpectedly succeeded")
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("unreachable endpoint changed an existing managed remote")
	}
	values := gitConfigValues(t, configPath, "remote.sandbox-demo.url")
	if len(values) != 1 || values[0] != first {
		t.Fatalf("managed remote = %#v, want %q", values, first)
	}
}

func TestActivateCloneSandboxRetriesTransientDialFailure(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	calls := 0
	runner := &Runner{cloneDial: func(context.Context, string, string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("connection reset")
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}}
	if _, err := runner.activateCloneSandbox(context.Background(), cloneTestSandbox("demo", 4321), root); err != nil {
		t.Fatalf("activateCloneSandbox() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("probe attempts = %d, want 2", calls)
	}
	values := gitConfigValues(t, filepath.Join(root, ".git", "config"), "remote.sandbox-demo.url")
	if len(values) != 1 || values[0] != cloneTestEndpointURL(4321, "demo") {
		t.Fatalf("managed remote = %#v", values)
	}
}

func TestActivateCloneSandboxDialTimeoutIsUnreachable(t *testing.T) {
	t.Parallel()
	root := initCloneTestRepo(t)
	configPath := filepath.Join(root, ".git", "config")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	runner := &Runner{cloneDial: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, context.DeadlineExceeded
	}}
	_, err = runner.activateCloneSandbox(context.Background(), cloneTestSandbox("demo", 4321), root)
	want := "the clone endpoint for sandbox demo is not reachable; run 'rsbx stop demo' and 'rsbx run --name demo' to republish it"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if calls != cloneEndpointProbeAttempts {
		t.Fatalf("probe attempts = %d, want %d", calls, cloneEndpointProbeAttempts)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dial timeout changed .git/config")
	}
}

func cloneTestSandbox(name string, port uint32) *sdk.Sandbox {
	return &sdk.Sandbox{
		ID: "sandbox-id", Name: name,
		Clone: &sdk.CloneInfo{
			RemoteName: "sandbox-" + name, GuestWorkdir: "/workspace/" + name,
			GitEndpoint: &sdk.GitEndpoint{HostIP: "127.0.0.1", Port: port, Repository: cloneTestEndpointPath(name)},
		},
	}
}

func testCloneDial(calls *int) cloneDialFunc {
	return func(context.Context, string, string) (net.Conn, error) {
		if calls != nil {
			*calls = *calls + 1
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
}

func failingCloneDial(calls *int, err error) cloneDialFunc {
	return func(context.Context, string, string) (net.Conn, error) {
		if calls != nil {
			*calls = *calls + 1
		}
		return nil, err
	}
}

func initCloneTestRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	cmd := exec.Command("git", "-C", root, "init", "-q")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	return root
}

func gitConfigSet(t *testing.T, config string, args ...string) error {
	t.Helper()
	commandArgs := append([]string{"config", "--file", config}, args...)
	cmd := exec.Command("git", commandArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return &testCommandError{err: err, output: string(output)}
	}
	return nil
}

func gitConfigValues(t *testing.T, config, key string) []string {
	t.Helper()
	cmd := exec.Command("git", "config", "--file", config, "--get-all", key)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("git config --get-all %s: %v", key, err)
	}
	return strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
}

type testCommandError struct {
	err    error
	output string
}

func (e *testCommandError) Error() string { return e.err.Error() + ": " + e.output }
func (e *testCommandError) Unwrap() error { return e.err }
func (e *testCommandError) ExitCode() int {
	var exit *exec.ExitError
	if errors.As(e.err, &exit) {
		return exit.ExitCode()
	}
	return -1
}

func TestCloneAdditionalWorkspaceRequiresReadOnly(t *testing.T) {
	source := initCloneTestRepo(t)
	other := t.TempDir()
	workspaces, options, err := prepareCreateWorkspaces(context.Background(), []string{source, other + ":ro"}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspaces) != 2 || !workspaces[0].ReadOnly || !workspaces[1].ReadOnly || options == nil {
		t.Fatalf("invalid clone workspace mapping: %+v, %+v", workspaces, options)
	}
	if _, _, err := prepareCreateWorkspaces(context.Background(), []string{source, other}, nil, true); err == nil {
		t.Fatal("writable additional clone workspace accepted")
	}
	if _, err := resolveRunCloneSource(context.Background(), true, []string{source, other + ":ro"}); err != nil {
		t.Fatalf("read-only extra workspace rejected by run: %v", err)
	}
	if _, err := resolveRunCloneSource(context.Background(), true, []string{source, other}); err == nil {
		t.Fatal("writable extra workspace accepted by run")
	}
}

func TestCloneReuseComparesReadOnlyExtras(t *testing.T) {
	existing := &sdk.Sandbox{Workspaces: []sdk.Workspace{
		{Path: "/host/source", ReadOnly: true, GuestPath: cloneSourceGuestPath},
		{Path: "/host/reference", ReadOnly: true},
	}}
	requested := []sdk.Workspace{{Path: "/host/source"}, {Path: "/host/reference", ReadOnly: true}}
	if !runWorkspacesMatch(existing, requested, true) {
		t.Fatal("matching read-only extra workspace was not reused")
	}
	requested[1].ReadOnly = false
	if runWorkspacesMatch(existing, requested, true) {
		t.Fatal("writable extra workspace matched a read-only sandbox")
	}
}
