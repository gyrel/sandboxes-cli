package command

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rheic/sandboxes-core/ids"
	sdk "github.com/rheic/sandboxes-go-sdk"

	"github.com/rheic/sandboxes-cli/internal/settings"
)

type bundleApprovalService struct {
	items []sdk.Approval
	err   error
}

func (s bundleApprovalService) ListApprovals(context.Context, string) ([]sdk.Approval, error) {
	return s.items, s.err
}

func (s bundleApprovalService) InspectApproval(context.Context, string, string) (sdk.Approval, error) {
	return sdk.Approval{}, s.err
}

func (s bundleApprovalService) RespondApproval(context.Context, string, sdk.ApprovalDecision, sdk.ApprovalPersistScope) (sdk.Approval, string, error) {
	return sdk.Approval{}, "", s.err
}

func bundleClient(approvals sdk.ApprovalService) fakeClient {
	return fakeClient{
		sandbox: diagnoseSandbox{items: []sdk.Sandbox{{
			ID:            "sb-1",
			Name:          "dev-shell",
			State:         sdk.StateRunning,
			Agent:         "claude",
			Image:         "alpine:3.21",
			PolicyProfile: "balanced",
			Allow:         []sdk.NetworkRule{{Domain: "api.example.com", Port: 443}},
			Deny:          []sdk.NetworkRule{{CIDR: "203.0.113.0/24"}},
			CreatedAt:     time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC),
		}}},
		versions:  diagnoseVersionService{},
		approvals: approvals,
	}
}

func bundleFixtures(t *testing.T, logLines ...string) string {
	t.Helper()
	state := t.TempDir()
	socket := filepath.Join(state, "sandboxesd.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	log := strings.Join(logLines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(state, "daemon.log"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	settingsFile := filepath.Join(t.TempDir(), "settings.toml")
	body := "dns_upstream = \"8.8.8.8\"\ndefault_policy_profile = \"balanced\"\nssh.workspaceRoot = \"/Users/testuser/workspaces\"\n"
	if err := os.WriteFile(settingsFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RHEIC_SETTINGS_FILE", settingsFile)
	return socket
}

func bundleRunner(socket string, client sdk.Client, clientErr error) (*Runner, *bytes.Buffer, *bytes.Buffer) {
	var out, stderr bytes.Buffer
	return &Runner{
		Out:    &out,
		Err:    &stderr,
		Socket: socket,
		NewClient: func(string) (sdk.Client, error) {
			if clientErr != nil {
				return nil, clientErr
			}
			return client, nil
		},
	}, &out, &stderr
}

func untarMembers(t *testing.T, raw io.Reader) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	reader := tar.NewReader(gz)
	members := map[string][]byte{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return members
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		members[header.Name] = data
	}
}

func extractBundleMembers(t *testing.T, path string) map[string][]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	return untarMembers(t, file)
}

func parseBundleManifest(t *testing.T, members map[string][]byte) diagnoseManifest {
	t.Helper()
	var manifest diagnoseManifest
	if err := json.Unmarshal(members[bundleMemberManifest], &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func benignLog(ts time.Time, msg string) string {
	return `{"ts":"` + ts.UTC().Format(time.RFC3339) + `","level":"info","msg":"` + msg + `"}`
}

func collectBundle(t *testing.T, runner *Runner, client sdk.Client, opts diagnoseBundleOptions) *diagnoseBundleBuild {
	t.Helper()
	build := newDiagnoseBundleBuild(opts.paranoid)
	ctx := context.Background()
	sandboxes := build.addSandboxes(ctx, client, opts.sandbox)
	build.addVersions(ctx, client)
	build.addPolicies(ctx, client, sandboxes)
	build.addApprovals(ctx, client, opts.sandbox)
	build.addPlatform()
	build.addConfig(runner.settingsPath())
	runner.addDaemonTail(build, opts.since)
	return build
}

// (a) clean fixture publishes the expected member tree, correct manifest
// digests, and a passing --verify run.
func TestDiagnoseBundleCleanArchive(t *testing.T) {
	socket := bundleFixtures(t,
		benignLog(time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC), "sandbox ready"),
		benignLog(time.Date(2026, 11, 25, 10, 0, 1, 0, time.UTC), "gateway listening"),
	)
	approvals := bundleApprovalService{items: []sdk.Approval{{
		ID:        "apr-1",
		Kind:      sdk.ApprovalKindMCPCall,
		State:     sdk.ApprovalStatePending,
		SandboxID: "sb-1",
		Headers:   []sdk.ApprovalHeader{{Name: "Authorization", ValueClass: sdk.HeaderValueClassVault}},
		EnvNames:  []string{"OPENAI_API_KEY"},
		CreatedAt: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC),
	}}}
	runner, out, stderr := bundleRunner(socket, bundleClient(approvals), nil)
	target := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if code := runner.Run(context.Background(), []string{"diagnose", "--bundle", "--out", target}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	members := extractBundleMembers(t, target)
	t.Logf("fixture member tree: %v", bundleMemberNames(members))
	want := []string{
		"manifest.json", "versions.json", "platform.json", "config.redacted.json",
		"sandboxes.redacted.json", "policies.redacted.json", "approvals.pending.redacted.json",
		"logs/daemon.tail.jsonl", "errors.json", "README.txt",
	}
	if len(members) != len(want) {
		t.Fatalf("members=%d (%v), want %d (%v)", len(members), bundleMemberNames(members), len(want), want)
	}
	for _, name := range want {
		if _, ok := members[name]; !ok {
			t.Errorf("member %q missing; have %v", name, bundleMemberNames(members))
		}
	}
	manifest := parseBundleManifest(t, members)
	if manifest.SchemaVersion != 1 || manifest.RedactionContract != 1 {
		t.Fatalf("manifest versions=%+v", manifest)
	}
	if err := ids.Validate(manifest.BundleOpID); err != nil {
		t.Fatalf("bundle_op_id=%q: %v", manifest.BundleOpID, err)
	}
	if _, err := time.Parse(time.RFC3339, manifest.GeneratedAt); err != nil {
		t.Fatalf("generated_at=%q: %v", manifest.GeneratedAt, err)
	}
	if !strings.Contains(strings.Join(manifest.Limits, "\n"), diagnoseJournalLimitText) {
		t.Fatalf("limits=%v lack the journal summary limit", manifest.Limits)
	}
	if len(manifest.Files) != len(want)-1 {
		t.Fatalf("manifest files=%d, want %d", len(manifest.Files), len(want)-1)
	}
	for _, file := range manifest.Files {
		data, ok := members[file.Path]
		if !ok {
			t.Fatalf("manifest lists unknown member %q", file.Path)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != file.SHA256 {
			t.Errorf("sha mismatch for %s: manifest=%s actual=%s", file.Path, file.SHA256, got)
		}
		if file.SizeBytes != int64(len(data)) {
			t.Errorf("size mismatch for %s: manifest=%d actual=%d", file.Path, file.SizeBytes, len(data))
		}
	}
	var config diagnoseConfigFile
	if err := json.Unmarshal(members[bundleMemberConfig], &config); err != nil {
		t.Fatal(err)
	}
	normalized := false
	for _, entry := range config.Settings {
		if entry.Key == "ssh.workspaceRoot" {
			normalized = entry.Value == "~/workspaces"
		}
	}
	if runtime.GOOS == "windows" {
		// Documented fail-closed stance (settings_windows_test.go): Load
		// refuses all files on Windows until ACL validation lands, so the
		// config member must be empty with an explicit limit instead of
		// containing normalized settings.
		if len(config.Settings) != 0 {
			t.Errorf("windows config settings must be empty under the fail-closed stance: %+v", config.Settings)
		}
		if !strings.Contains(strings.Join(manifest.Limits, "\n"), "config: settings unavailable") {
			t.Errorf("missing settings limit under windows stance: %v", manifest.Limits)
		}
	} else if !normalized {
		t.Errorf("home path not normalized: %+v", config.Settings)
	}
	if strings.Contains(string(members[bundleMemberConfig]), "/Users/testuser") {
		t.Error("config still contains an absolute home path")
	}
	verifier, vout, verr := bundleRunner(socket, nil, nil)
	if code := verifier.Run(context.Background(), []string{"diagnose", "--verify", target}); code != 0 {
		t.Fatalf("verify exit=%d stdout=%q stderr=%q", code, vout.String(), verr.String())
	}
}

func bundleMemberNames(members map[string][]byte) []string {
	keys := make([]string, 0, len(members))
	for key := range members {
		keys = append(keys, key)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

// (b) canary fixture: planted bearer and openai-key material makes the builder
// refuse with rc=1, leave no archive, and quote only rule ids on stderr.
func TestDiagnoseBundleCanaryRefusal(t *testing.T) {
	socket := bundleFixtures(t,
		`{"ts":"2026-11-25T10:00:00Z","level":"info","msg":"auth header Bearer abcdefghijklmnop"}`,
		`{"ts":"2026-11-25T10:00:01Z","level":"info","msg":"using key sk-abcdefghijklmnopqrstuvwxyz"}`,
	)
	runner, out, stderr := bundleRunner(socket, bundleClient(bundleApprovalService{}), nil)
	target := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if code := runner.Run(context.Background(), []string{"diagnose", "--bundle", "--out", target}); code != 1 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused bundle still exists: err=%v", err)
	}
	messages := stderr.String()
	t.Logf("refusal stderr (canary redacted):\n%s", messages)
	for _, want := range []string{"bearer", "openai_key", "logs/daemon.tail.jsonl", "diagnostic bundle refused"} {
		if !strings.Contains(messages, want) {
			t.Errorf("stderr lacks %q: %s", want, messages)
		}
	}
	for _, leak := range []string{"abcdefghijklmnop", "abcdefghijklmnopqrstuvwxyz"} {
		if strings.Contains(messages, leak) || strings.Contains(out.String(), leak) {
			t.Fatal("canary bytes leaked into output")
		}
	}
}

// (c) caps: a 9 MiB daemon log is truncated by the bounded tail reader; a
// synthetic cap exercises the trim-then-drop order before refusal.
func TestDiagnoseBundleCaps(t *testing.T) {
	t.Run("tail reader caps 9MiB input", func(t *testing.T) {
		socket := bundleFixtures(t)
		prefix := `{"ts":"2026-11-25T00:00:00Z","level":"info","msg":"`
		line := prefix + strings.Repeat("a", 2002-len(prefix)-2) + `"}`
		var log strings.Builder
		for i := 0; i < 4800; i++ {
			log.WriteString(line)
			log.WriteString("\n")
		}
		if int64(log.Len()) < 9<<20 {
			t.Fatalf("fixture=%d bytes, want >= 9MiB", log.Len())
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(socket), "daemon.log"), []byte(log.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		runner, out, stderr := bundleRunner(socket, bundleClient(bundleApprovalService{}), nil)
		target := filepath.Join(t.TempDir(), "bundle.tar.gz")
		if code := runner.Run(context.Background(), []string{"diagnose", "--bundle", "--out", target}); code != 0 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
		}
		members := extractBundleMembers(t, target)
		tail := members[bundleMemberTail]
		if int64(len(tail)) > diagnoseTailBytes {
			t.Fatalf("tail bytes=%d, want <= %d", len(tail), diagnoseTailBytes)
		}
		if lines := bytes.Count(tail, []byte("\n")); lines > diagnoseTailLines {
			t.Fatalf("tail lines=%d, want <= %d", lines, diagnoseTailLines)
		}
		limits := strings.Join(parseBundleManifest(t, members).Limits, "\n")
		if !strings.Contains(limits, diagnoseTailRecordsLimit) {
			t.Errorf("limits lack the record cap note: %s", limits)
		}
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > diagnoseBundleMaxBytes {
			t.Fatalf("archive size=%d, want <= %d", info.Size(), diagnoseBundleMaxBytes)
		}
	})

	t.Run("overflow trims then drops optional members in order", func(t *testing.T) {
		socket := bundleFixtures(t, benignLog(time.Now(), "gateway listening"))
		approvals := bundleApprovalService{items: makeApprovals(300)}
		runner, _, _ := bundleRunner(socket, bundleClient(approvals), nil)
		build := collectBundle(t, runner, bundleClient(approvals), diagnoseBundleOptions{})
		full, err := build.assemble()
		if err != nil {
			t.Fatal(err)
		}
		stripped := *build
		stripped.approvals, stripped.policies, stripped.config = nil, nil, nil
		small, err := stripped.assemble()
		if err != nil {
			t.Fatal(err)
		}
		if len(small) >= len(full) {
			t.Fatal("optional members did not contribute to archive size")
		}
		original := diagnoseBundleMaxBytes
		t.Cleanup(func() { diagnoseBundleMaxBytes = original })

		budget := int64(len(small)) + int64(len(full)-len(small))/2
		diagnoseBundleMaxBytes = budget
		archive, err := build.finalArchive()
		if err != nil {
			t.Fatalf("budget %d (full %d, stripped %d): %v", budget, len(full), len(small), err)
		}
		if int64(len(archive)) > budget {
			t.Fatalf("archive=%d exceeds budget=%d", len(archive), budget)
		}
		members := untarMembers(t, bytes.NewReader(archive))
		limits := parseBundleManifest(t, members).Limits
		text := strings.Join(limits, "\n")
		if !strings.Contains(text, "bundle cap: trimmed daemon tail") {
			t.Errorf("limits lack the tail trim note: %s", text)
		}
		if !strings.Contains(text, "bundle cap: omitted "+bundleMemberApprovals) {
			t.Errorf("limits lack the approvals omission: %s", text)
		}
		if _, ok := members[bundleMemberApprovals]; ok {
			t.Error("approvals member survived the cap drop")
		}
		assertDropOrder(t, limits)

		// An impossible cap refuses after the full order is exhausted.
		exhausted := collectBundle(t, runner, bundleClient(approvals), diagnoseBundleOptions{})
		diagnoseBundleMaxBytes = 16
		if _, err := exhausted.finalArchive(); err == nil {
			t.Fatal("impossible cap published anyway")
		}
		if !strings.Contains(strings.Join(exhausted.limitStrings(), "\n"), "bundle cap: omitted "+bundleMemberConfig) {
			t.Errorf("refusal did not exhaust the drop order: %v", exhausted.limitStrings())
		}
	})
}

func assertDropOrder(t *testing.T, limits []string) {
	t.Helper()
	lastTrim := -1
	var omitSeen []int
	order := map[string]int{bundleMemberApprovals: 0, bundleMemberPolicies: 1, bundleMemberConfig: 2}
	for i, limit := range limits {
		if strings.HasPrefix(limit, "bundle cap: trimmed") {
			lastTrim = i
		}
		if name := strings.TrimPrefix(limit, "bundle cap: omitted "); name != limit {
			rank, ok := order[name]
			if !ok {
				t.Fatalf("unexpected omitted member %q", name)
			}
			omitSeen = append(omitSeen, rank)
			if lastTrim < 0 {
				t.Fatalf("omission %q recorded before any tail trim", name)
			}
		}
	}
	for i := 1; i < len(omitSeen); i++ {
		if omitSeen[i] <= omitSeen[i-1] {
			t.Fatalf("drop order violated: %v", omitSeen)
		}
	}
}

func makeApprovals(count int) []sdk.Approval {
	items := make([]sdk.Approval, 0, count)
	for i := 0; i < count; i++ {
		items = append(items, sdk.Approval{
			ID:        "apr-" + strconv.Itoa(i),
			Kind:      sdk.ApprovalKindHostCommand,
			State:     sdk.ApprovalStatePending,
			SandboxID: "sb-1",
			CreatedAt: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC),
		})
	}
	return items
}

// (d) paranoid hashing is stable across runs and matches sha256(name)[:12].
func TestDiagnoseBundleParanoidStability(t *testing.T) {
	socket := bundleFixtures(t, benignLog(time.Now(), "sandbox ready"))
	runner, _, _ := bundleRunner(socket, bundleClient(bundleApprovalService{}), nil)
	first := filepath.Join(t.TempDir(), "first.tar.gz")
	second := filepath.Join(t.TempDir(), "second.tar.gz")
	for _, target := range []string{first, second} {
		if _, err := runner.buildDiagnoseBundle(context.Background(), diagnoseBundleOptions{outPath: target, paranoid: true}); err != nil {
			t.Fatal(err)
		}
	}
	left := extractBundleMembers(t, first)[bundleMemberSandboxes]
	right := extractBundleMembers(t, second)[bundleMemberSandboxes]
	if !bytes.Equal(left, right) {
		t.Fatalf("paranoid sandboxes differ across runs:\n%s\n%s", left, right)
	}
	sum := sha256.Sum256([]byte("dev-shell"))
	imageSum := sha256.Sum256([]byte("alpine:3.21"))
	want := hex.EncodeToString(sum[:6])
	wantImage := hex.EncodeToString(imageSum[:6])
	var file diagnoseSandboxesFile
	if err := json.Unmarshal(left, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Sandboxes) != 1 || file.Sandboxes[0].Name != want || file.Sandboxes[0].Image != wantImage {
		t.Fatalf("hashed entries=%+v, want name=%s image=%s", file.Sandboxes, want, wantImage)
	}
	if strings.Contains(string(left), "dev-shell") {
		t.Fatal("plain sandbox name leaked in paranoid mode")
	}
}

// (e) publication guards: O_EXCL overwrite refusal, symlinked parent refusal
// and refusal inside the daemon state directory.
func TestDiagnoseBundlePublicationGuards(t *testing.T) {
	socket := bundleFixtures(t, benignLog(time.Now(), "sandbox ready"))
	runner, _, _ := bundleRunner(socket, bundleClient(bundleApprovalService{}), nil)
	ctx := context.Background()
	target := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if _, err := runner.buildDiagnoseBundle(ctx, diagnoseBundleOptions{outPath: target}); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.buildDiagnoseBundle(ctx, diagnoseBundleOptions{outPath: target}); err == nil {
		t.Fatal("overwrite of an existing target was not refused")
	}
	after, err := os.Stat(target)
	if err != nil || after.Size() != before.Size() {
		t.Fatalf("existing target changed: err=%v", err)
	}

	bundleSymlinkRefusal(t, runner, ctx)

	insideState := filepath.Join(filepath.Dir(socket), "bundle.tar.gz")
	if _, err := runner.buildDiagnoseBundle(ctx, diagnoseBundleOptions{outPath: insideState}); err == nil {
		t.Fatal("bundle inside the daemon state directory was not refused")
	}
}

func bundleSymlinkRefusal(t *testing.T, runner *Runner, ctx context.Context) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	root := t.TempDir()
	baseDir := filepath.Join(root, "base")
	if err := os.Mkdir(baseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(baseDir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.buildDiagnoseBundle(ctx, diagnoseBundleOptions{outPath: filepath.Join(link, "bundle.tar.gz")}); err == nil {
		t.Fatal("symlinked parent directory was not refused")
	}
	if entries, _ := os.ReadDir(baseDir); len(entries) != 0 {
		t.Fatal("bundle was written into the symlinked directory")
	}
}

// (f) --since reaches the tail reader cutoff in RFC 3339 and duration forms.
func TestDiagnoseBundleSince(t *testing.T) {
	now := time.Now().UTC()
	oldLine := benignLog(now.Add(-2*time.Hour), "cold start")
	newLine := benignLog(now.Add(-30*time.Second), "gateway listening")
	socket := bundleFixtures(t, oldLine, newLine)

	if at, err := parseDiagnoseSince("30m", now); err != nil || !at.Equal(now.Add(-30*time.Minute)) {
		t.Fatalf("duration parse=%v err=%v", at, err)
	}
	if at, err := parseDiagnoseSince(now.Format(time.RFC3339), now); err != nil || !at.Equal(now.Truncate(time.Second)) {
		t.Fatalf("rfc parse=%v err=%v", at, err)
	}
	if _, err := parseDiagnoseSince("nonsense", now); err == nil {
		t.Fatal("nonsense since parsed")
	}

	for _, since := range []string{now.Add(-time.Hour).Format(time.RFC3339), "1h"} {
		runner, out, stderr := bundleRunner(socket, bundleClient(bundleApprovalService{}), nil)
		target := filepath.Join(t.TempDir(), "bundle.tar.gz")
		if code := runner.Run(context.Background(), []string{"diagnose", "--bundle", "--since", since, "--out", target}); code != 0 {
			t.Fatalf("since=%s exit=%d stdout=%q stderr=%q", since, code, out.String(), stderr.String())
		}
		tail := string(extractBundleMembers(t, target)[bundleMemberTail])
		if strings.Contains(tail, "cold start") || !strings.Contains(tail, "gateway listening") {
			t.Fatalf("since=%s tail=%q", since, tail)
		}
	}
}

// (g) daemon unreachable: versions.json keeps only the error class, the other
// daemon members are empty with limit strings, and the bundle still publishes.
func TestDiagnoseBundleDaemonUnreachable(t *testing.T) {
	socket := bundleFixtures(t, benignLog(time.Now(), "host only"))
	runner, out, stderr := bundleRunner(socket, nil, errors.New("dial failed"))
	target := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if code := runner.Run(context.Background(), []string{"diagnose", "--bundle", "--out", target}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	members := extractBundleMembers(t, target)
	var versions diagnoseVersionsFile
	if err := json.Unmarshal(members[bundleMemberVersions], &versions); err != nil {
		t.Fatal(err)
	}
	if versions.Daemon == nil || versions.Daemon.ErrorClass == "" || versions.Daemon.Version != "" {
		t.Fatalf("daemon entry=%+v, want error class only", versions.Daemon)
	}
	var sandboxes diagnoseSandboxesFile
	if err := json.Unmarshal(members[bundleMemberSandboxes], &sandboxes); err != nil || len(sandboxes.Sandboxes) != 0 {
		t.Fatalf("sandboxes=%+v err=%v", sandboxes, err)
	}
	limits := strings.Join(parseBundleManifest(t, members).Limits, "\n")
	if !strings.Contains(limits, "versions: daemon version unavailable") {
		t.Errorf("limits lack the versions fallback: %s", limits)
	}
	if !strings.Contains(limits, diagnoseUnreachableLimit) {
		t.Errorf("limits lack the unreachable note: %s", limits)
	}
	if strings.Contains(string(members[bundleMemberVersions]), "dial failed") {
		t.Error("daemon error message text leaked into versions.json")
	}
}

func TestDiagnoseBundleFlagComposition(t *testing.T) {
	socket := bundleFixtures(t, benignLog(time.Now(), "sandbox ready"))
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"bundle with format", []string{"diagnose", "--bundle", "--format", "json"}, 2},
		{"bundle with json", []string{"diagnose", "--bundle", "--json"}, 2},
		{"verify with bundle", []string{"diagnose", "--verify", "x.tar.gz", "--bundle"}, 2},
		{"sandbox without bundle", []string{"diagnose", "--sandbox", "sb"}, 2},
		{"bad since", []string{"diagnose", "--bundle", "--since", "garbage"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner, out, stderr := bundleRunner(socket, bundleClient(bundleApprovalService{}), nil)
			if code := runner.Run(context.Background(), tc.args); code != tc.want {
				t.Fatalf("exit=%d want=%d stdout=%q stderr=%q", code, tc.want, out.String(), stderr.String())
			}
		})
	}
}

func TestDiagnoseConfigRedaction(t *testing.T) {
	build := newDiagnoseBundleBuild(false)
	entries := diagnoseConfigEntries(build, settings.Values{
		Extra: map[string]string{
			"kit.shortcuts.tokenish": "hunter2",
			"ssh.workspaceRoot":      "/Users/testuser/work",
			"dns.upstream":           "127.0.0.1:5353",
		},
	})
	byKey := map[string]diagnoseConfigEntry{}
	for _, entry := range entries {
		byKey[entry.Key] = entry
		// D7: keys naming secret material are wholesale redacted.
		if diagnoseSecretKeyPattern.MatchString(entry.Key) && !entry.Redacted {
			t.Fatalf("secret-bearing key not redacted: %+v", entry)
		}
	}
	if entry, ok := byKey["kit.shortcuts.tokenish"]; !ok || entry.Value != diagnoseRedactedValue || !entry.Redacted {
		t.Fatalf("token entry=%+v", entry)
	}
	if entry, ok := byKey["ssh.workspaceRoot"]; !ok || entry.Value != "~/work" {
		t.Fatalf("workspace entry=%+v", entry)
	}
	for _, entry := range entries {
		if entry.Value == "hunter2" {
			t.Fatalf("secret value leaked: %+v", entry)
		}
	}
}
