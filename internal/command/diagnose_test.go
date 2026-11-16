package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"

	"github.com/rheic/sandboxes-cli/internal/version"
)

type diagnoseVersionService struct{ err error }

func (s diagnoseVersionService) Get(context.Context) (sdk.VersionInfo, error) {
	if s.err != nil {
		return sdk.VersionInfo{}, s.err
	}
	return sdk.VersionInfo{Version: version.Version, APIVersion: "0.0.16"}, nil
}

type diagnoseSandbox struct {
	fakeSandbox
	items []sdk.Sandbox
	err   error
}

func (s diagnoseSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	if s.err != nil {
		return nil, s.err
	}
	return &sdk.Page[sdk.Sandbox]{Items: s.items}, nil
}

func diagnoseRunner(t *testing.T, socket string, sandbox sdk.SandboxService, statuses sdk.AccountStatusService, versionErr error) (*Runner, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, Socket: socket, NewClient: func(string) (sdk.Client, error) {
		return fakeClient{sandbox: sandbox, accountStatuses: statuses, versions: diagnoseVersionService{err: versionErr}}, nil
	}}
	return runner, &out
}

func findFlatDiagnoseCheck(t *testing.T, report diagnoseFlatReport, name string) diagnoseOutputCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			return check
		}
	}
	t.Fatalf("check %q not found in %#v", name, report)
	return diagnoseOutputCheck{}
}

func TestDiagnoseFlatSchemaAndSummary(t *testing.T) {
	originalVirtualizationSupport := hostVirtualizationSupport
	t.Cleanup(func() { hostVirtualizationSupport = originalVirtualizationSupport })
	hostVirtualizationSupport = func() (bool, string) { return true, "test hypervisor present" }

	socket := filepath.Join(t.TempDir(), "sandboxd.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runner, out := diagnoseRunner(t, socket, diagnoseSandbox{}, fakeAccountStatus{statuses: map[string]bool{"docker": true}}, nil)
	if code := runner.Run(context.Background(), []string{"diagnose", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}

	var raw struct {
		Version string                       `json:"version"`
		Checks  []map[string]json.RawMessage `json:"checks"`
		Summary diagnoseSummary              `json:"summary"`
	}
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	if raw.Version != diagnoseReportVersion {
		t.Fatalf("version = %q, want %q", raw.Version, diagnoseReportVersion)
	}
	if len(raw.Checks) != 18 {
		t.Fatalf("checks=%d, want 18 like the sbx baseline", len(raw.Checks))
	}

	counted := diagnoseSummary{}
	for i, rawCheck := range raw.Checks {
		for _, field := range []string{"name", "status", "message", "detail", "hint"} {
			if _, ok := rawCheck[field]; !ok {
				t.Fatalf("check %d missing field %q: %#v", i, field, rawCheck)
			}
		}
		var status, detail, hint string
		if err := json.Unmarshal(rawCheck["status"], &status); err != nil {
			t.Fatalf("check %d status: %v", i, err)
		}
		if err := json.Unmarshal(rawCheck["detail"], &detail); err != nil {
			t.Fatalf("check %d detail: %v", i, err)
		}
		if err := json.Unmarshal(rawCheck["hint"], &hint); err != nil {
			t.Fatalf("check %d hint: %v", i, err)
		}
		if hint != "" {
			t.Fatalf("check %d hint=%q, want empty", i, hint)
		}
		switch status {
		case diagnosePass:
			counted.Pass++
		case diagnoseWarn:
			counted.Warn++
		case diagnoseFail:
			counted.Fail++
		case diagnoseSkip:
			counted.Skip++
		default:
			t.Fatalf("check %d has unknown status %q", i, status)
		}
	}
	if raw.Summary != counted {
		t.Fatalf("summary=%#v, counted=%#v", raw.Summary, counted)
	}

	var flat diagnoseFlatReport
	if err := json.Unmarshal(out.Bytes(), &flat); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	if check := findFlatDiagnoseCheck(t, flat, "Authentication"); check.Status != diagnosePass {
		t.Fatalf("authentication = %#v", check)
	}
	if check := findFlatDiagnoseCheck(t, flat, "Version match"); check.Status != diagnosePass {
		t.Fatalf("version match = %#v", check)
	}
	if check := findFlatDiagnoseCheck(t, flat, "Socket"); check.Status != diagnosePass {
		t.Fatalf("socket = %#v", check)
	}
	if check := findFlatDiagnoseCheck(t, flat, "ZFS offset sync"); check.Status != diagnoseSkip {
		t.Fatalf("zfs = %#v", check)
	}
}

func TestDiagnosePreservesSectionsInternally(t *testing.T) {
	originalVirtualizationSupport := hostVirtualizationSupport
	t.Cleanup(func() { hostVirtualizationSupport = originalVirtualizationSupport })
	hostVirtualizationSupport = func() (bool, string) { return true, "test hypervisor present" }

	socket := filepath.Join(t.TempDir(), "sandboxd.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runner, _ := diagnoseRunner(t, socket, diagnoseSandbox{}, fakeAccountStatus{statuses: map[string]bool{"docker": true}}, nil)
	report := runner.collectDiagnoseReport(context.Background())
	wantTitles := []string{"INSTALLATION", "PLATFORM", "STORAGE", "CONNECTION"}
	if len(report.Sections) != len(wantTitles) {
		t.Fatalf("sections=%#v", report.Sections)
	}
	total := 0
	for i, section := range report.Sections {
		if section.Title != wantTitles[i] {
			t.Fatalf("section %d = %q, want %q", i, section.Title, wantTitles[i])
		}
		total += len(section.Checks)
	}
	if total != 18 {
		t.Fatalf("checks=%d, want 18 like the sbx baseline", total)
	}
}

func TestDiagnoseFailsWhenDaemonUnreachable(t *testing.T) {
	runner, out := diagnoseRunner(t, filepath.Join(t.TempDir(), "missing.sock"), diagnoseSandbox{err: errors.New("dial failed")}, nil, errors.New("dial failed"))
	if code := runner.Run(context.Background(), []string{"diagnose"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	for _, expected := range []string{"INSTALLATION", "CONNECTION", "✗ Version match", "daemon unreachable", "skipped"} {
		if !strings.Contains(out.String(), expected) {
			t.Errorf("output lacks %q: %s", expected, out.String())
		}
	}
}

func TestDiagnoseFailsWhenNotSignedIn(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "sandboxd.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runner, out := diagnoseRunner(t, socket, diagnoseSandbox{}, fakeAccountStatus{statuses: map[string]bool{"docker": false}}, nil)
	if code := runner.Run(context.Background(), []string{"diagnose", "--format", "table"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "✗ Authentication") || !strings.Contains(out.String(), "rsbx login") {
		t.Fatalf("authentication failure not reported: %s", out.String())
	}
}

func TestDiagnoseUsesInjectableProcessCount(t *testing.T) {
	original := hostProcessCount
	t.Cleanup(func() { hostProcessCount = original })
	hostProcessCount = func() (int, int, error) { return 2, 1, nil }
	check := checkHostProcesses()
	if check.Status != diagnosePass || check.Detail != "2 rheicd, 1 containerd-shim-nerdbox-v1" {
		t.Fatalf("check = %#v", check)
	}
	hostProcessCount = func() (int, int, error) { return 0, 0, errors.New("pgrep missing") }
	check = checkHostProcesses()
	if check.Status != diagnoseSkip {
		t.Fatalf("check = %#v", check)
	}
}

func TestDiagnoseStateDirDerivesFromSocket(t *testing.T) {
	if dir := diagnoseStateDir(filepath.Join("state", "sandboxesd.sock")); dir != "state" {
		t.Fatalf("state dir = %q", dir)
	}
	if dir := diagnoseStateDir(""); !strings.HasSuffix(dir, ".sandboxes") {
		t.Fatalf("default state dir = %q", dir)
	}
}

func TestDiagnoseGitHubIssueFormatting(t *testing.T) {
	report := diagnoseReport{Sections: []diagnoseSection{{
		Title: "TEST",
		Checks: []diagnoseCheck{
			{Name: "Pass check", Status: diagnosePass, Detail: "all good"},
			{Name: "Warn|check", Status: diagnoseWarn, Detail: "line one\nline two <b>"},
			{Name: "Fail check", Status: diagnoseFail, Detail: "bad"},
			{Name: "Skip check", Status: diagnoseSkip, Detail: "later"},
		},
	}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if err := runner.writeDiagnoseGitHubIssue(report); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, expected := range []string{
		"### sbx diagnose report",
		"**OS:** " + runtime.GOOS,
		"**Arch:** " + runtime.GOARCH,
		"**DS Version:** unknown",
		"| Check | Status | Message |",
		"| Pass check | ✓ | all good |",
		"| Warn\\|check | ! | line one<br>line two &lt;b&gt; |",
		"| Fail check | ✗ | bad |",
		"| Skip check | ⊘ | later |",
		"<summary>Full JSON output</summary>",
		"```json",
		"</details>",
	} {
		if !strings.Contains(got, expected) {
			t.Errorf("output lacks %q:\n%s", expected, got)
		}
	}
	jsonStart := strings.Index(got, "```json\n")
	if jsonStart < 0 {
		t.Fatalf("output lacks JSON fence:\n%s", got)
	}
	jsonStart += len("```json\n")
	jsonEnd := strings.Index(got[jsonStart:], "\n```")
	if jsonEnd < 0 {
		t.Fatalf("output lacks JSON fence end:\n%s", got)
	}
	var flat diagnoseFlatReport
	if err := json.Unmarshal([]byte(got[jsonStart:jsonStart+jsonEnd]), &flat); err != nil {
		t.Fatalf("embedded json: %v\n%s", err, got)
	}
	if flat.Version != diagnoseReportVersion {
		t.Fatalf("version = %q", flat.Version)
	}
	if len(flat.Checks) != 4 {
		t.Fatalf("checks = %#v", flat.Checks)
	}
	wantSummary := diagnoseSummary{Pass: 1, Warn: 1, Fail: 1, Skip: 1}
	if flat.Summary != wantSummary {
		t.Fatalf("summary = %#v, want %#v", flat.Summary, wantSummary)
	}
}

func TestDiagnoseGitHubIssueCommand(t *testing.T) {
	originalVirtualizationSupport := hostVirtualizationSupport
	t.Cleanup(func() { hostVirtualizationSupport = originalVirtualizationSupport })
	hostVirtualizationSupport = func() (bool, string) { return true, "test hypervisor present" }

	socket := filepath.Join(t.TempDir(), "sandboxd.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runner, out := diagnoseRunner(t, socket, diagnoseSandbox{}, fakeAccountStatus{statuses: map[string]bool{"docker": true}}, nil)
	if code := runner.Run(context.Background(), []string{"diagnose", "--format", "github-issue"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	for _, expected := range []string{"### sbx diagnose report", "| Check | Status | Message |", "<summary>Full JSON output</summary>"} {
		if !strings.Contains(out.String(), expected) {
			t.Errorf("output lacks %q: %s", expected, out.String())
		}
	}
}

func TestDiagnoseWarningsDoNotFail(t *testing.T) {
	originalVirtualizationSupport := hostVirtualizationSupport
	t.Cleanup(func() { hostVirtualizationSupport = originalVirtualizationSupport })
	hostVirtualizationSupport = func() (bool, string) { return true, "test hypervisor present" }
	t.Setenv("SSL_CERT_FILE", "/tmp/diagnose-ca.pem")

	socket := filepath.Join(t.TempDir(), "sandboxd.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runner, out := diagnoseRunner(t, socket, diagnoseSandbox{}, fakeAccountStatus{statuses: map[string]bool{"docker": true}}, nil)
	if code := runner.Run(context.Background(), []string{"diagnose", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var flat diagnoseFlatReport
	if err := json.Unmarshal(out.Bytes(), &flat); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	if flat.Summary.Fail != 0 {
		t.Fatalf("summary=%#v", flat.Summary)
	}
	if flat.Summary.Warn == 0 {
		t.Fatalf("expected a warning from SSL_CERT_FILE, summary=%#v", flat.Summary)
	}
}

func TestDiagnoseInvalidArgumentsMatchReferenceExit(t *testing.T) {
	for _, args := range [][]string{{"diagnose", "extra"}, {"diagnose", "--format", "garbage"}, {"diagnose", "--json", "--format", "json"}} {
		var output bytes.Buffer
		runner := &Runner{Out: &output, Err: &output}
		if code := runner.Run(context.Background(), args); code != 1 {
			t.Fatalf("args=%v exit=%d output=%q", args, code, output.String())
		}
	}
}

type failingDiagnoseWriter struct{}

func (failingDiagnoseWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic write failure")
}
func TestDiagnoseIssueWriterPropagatesErrors(t *testing.T) {
	runner := &Runner{Out: failingDiagnoseWriter{}}
	if err := runner.writeDiagnoseGitHubIssue(diagnoseReport{}); err == nil {
		t.Fatal("write error was ignored")
	}
}

func TestDiagnoseFlatMessageAndDetail(t *testing.T) {
	flat := flattenDiagnoseReport(diagnoseReport{Sections: []diagnoseSection{{Checks: []diagnoseCheck{{Name: "CLI binary", Status: diagnosePass, Detail: "/tmp/rsbx"}}}}})
	if flat.Checks[0].Message != "found" || flat.Checks[0].Detail != "/tmp/rsbx" {
		t.Fatalf("check=%+v", flat.Checks[0])
	}
}

func TestDiagnoseIssueShowsActualDaemonVersion(t *testing.T) {
	report := diagnoseReport{DaemonVersion: "v9.8.7"}
	var out bytes.Buffer
	runner := &Runner{Out: &out}
	if err := runner.writeDiagnoseGitHubIssue(report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "**DS Version:** v9.8.7") {
		t.Fatalf("output=%q", out.String())
	}
}
