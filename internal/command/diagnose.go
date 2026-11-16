package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	sdk "github.com/rheic/sandboxes-go-sdk"

	"github.com/rheic/sandboxes-cli/internal/version"
)

const (
	diagnosePass  = "pass"
	diagnoseFail  = "fail"
	diagnoseWarn  = "warn"
	diagnoseSkip  = "skip"
	diagnoseUsage = `usage: rsbx diagnose [--format table|json|yaml|github-issue] [--json]

Diagnose host installation, platform, storage and daemon connection checks.
JSON and YAML use sbx's flat report schema: version, checks[] with name, status,
message, detail and hint, plus a summary. github-issue emits a Markdown issue
body with the JSON report embedded.

Exit 0 when every check passes, warns or is skipped; unconfigured optional
state such as a signed-out daemon is a warning. Exit 1 only when a check fails,
for example when the daemon cannot be reached or the state directory is not
writable.`

	diagnoseFormatGitHubIssue = "github-issue"
	diagnoseReportVersion     = "1.0"
)

type diagnoseCheck struct {
	Name   string `json:"name" yaml:"name"`
	Status string `json:"status" yaml:"status"`
	Detail string `json:"detail,omitempty" yaml:"detail,omitempty"`
}

type diagnoseSection struct {
	Title  string          `json:"title" yaml:"title"`
	Checks []diagnoseCheck `json:"checks" yaml:"checks"`
}

type diagnoseReport struct {
	Sections      []diagnoseSection `json:"sections" yaml:"sections"`
	DaemonVersion string            `json:"-" yaml:"-"`
}

// diagnoseOutputCheck is the flattened, externally visible check shape. Every
// field is always present so consumers can rely on a stable schema.
type diagnoseOutputCheck struct {
	Name    string `json:"name" yaml:"name"`
	Status  string `json:"status" yaml:"status"`
	Message string `json:"message" yaml:"message"`
	Detail  string `json:"detail" yaml:"detail"`
	Hint    string `json:"hint" yaml:"hint"`
}

type diagnoseSummary struct {
	Pass int `json:"pass" yaml:"pass"`
	Warn int `json:"warn" yaml:"warn"`
	Fail int `json:"fail" yaml:"fail"`
	Skip int `json:"skip" yaml:"skip"`
}

// diagnoseFlatReport is the external JSON/YAML representation. Sections are
// kept internally for text rendering but flattened for machine formats.
type diagnoseFlatReport struct {
	Version string                `json:"version" yaml:"version"`
	Checks  []diagnoseOutputCheck `json:"checks" yaml:"checks"`
	Summary diagnoseSummary       `json:"summary" yaml:"summary"`
}

func (r *Runner) diagnose(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool(listFormatJSON, false, "output in JSON format")
	format := fs.String("format", listFormatTable, "output format: table, json, yaml or github-issue")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(r.Out, diagnoseUsage)
			return 0
		}
		return r.flagParseFailure("diagnose", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, diagnoseUsage)
		return 1
	}
	selected, err := resolveDiagnoseFormat(fs, *format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 1
	}
	report := r.collectDiagnoseReport(ctx)
	if err := r.renderDiagnose(report, selected); err != nil {
		r.error(err)
		return 1
	}
	return diagnoseExitCode(report)
}

func resolveDiagnoseFormat(fs *flag.FlagSet, format string, jsonOutput bool) (string, error) {
	var jsonSet, formatSet bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == listFormatJSON {
			jsonSet = true
		}
		if f.Name == "format" {
			formatSet = true
		}
	})
	if jsonSet && formatSet {
		return "", errors.New("--json and --format cannot be combined")
	}
	if format == diagnoseFormatGitHubIssue {
		return format, nil
	}
	return resolveOperationFormat(format, jsonOutput)
}

func (r *Runner) renderDiagnose(report diagnoseReport, selected string) error {
	switch selected {
	case diagnoseFormatGitHubIssue:
		return r.writeDiagnoseGitHubIssue(report)
	case listFormatJSON:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(flattenDiagnoseReport(report))
	case listFormatYAML:
		data, err := yaml.Marshal(flattenDiagnoseReport(report))
		if err != nil {
			return err
		}
		n, err := r.Out.Write(data)
		if err != nil {
			return err
		}
		if n != len(data) {
			return io.ErrShortWrite
		}
		return nil
	default:
		r.writeDiagnoseText(report)
		return nil
	}
}

func flattenDiagnoseReport(report diagnoseReport) diagnoseFlatReport {
	flat := diagnoseFlatReport{
		Version: diagnoseReportVersion,
		Checks:  make([]diagnoseOutputCheck, 0),
	}
	for _, section := range report.Sections {
		for _, check := range section.Checks {
			message, detail := diagnoseMessage(check)
			flat.Checks = append(flat.Checks, diagnoseOutputCheck{Name: check.Name, Status: check.Status, Message: message, Detail: detail})
			switch check.Status {
			case diagnosePass:
				flat.Summary.Pass++
			case diagnoseWarn:
				flat.Summary.Warn++
			case diagnoseFail:
				flat.Summary.Fail++
			case diagnoseSkip:
				flat.Summary.Skip++
			}
		}
	}
	return flat
}

// diagnoseMessage separates the short result from its useful supporting data.
func diagnoseMessage(check diagnoseCheck) (string, string) {
	if check.Status == diagnosePass {
		switch check.Name {
		case "CLI binary", "mkfs.erofs", "mkfs.ext4":
			return "found", check.Detail
		case "Virtualization":
			return "supported", check.Detail
		}
	}
	return check.Detail, ""
}

func diagnoseExitCode(report diagnoseReport) int {
	for _, section := range report.Sections {
		for _, check := range section.Checks {
			if check.Status == diagnoseFail {
				return 1
			}
		}
	}
	return 0
}

// collectDiagnoseReport mirrors the sbx diagnose structure: four sections of
// individually graded checks. Host-side checks never fail closed on optional
// tooling; only daemon connectivity and version agreement are failures.
func (r *Runner) collectDiagnoseReport(ctx context.Context) diagnoseReport {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	installation := diagnoseSection{Title: "INSTALLATION"}
	installation.Checks = append(installation.Checks,
		r.checkCLIBinary(),
		diagnoseCheck{Name: "Binary version", Status: diagnosePass, Detail: "v" + version.Version},
		checkHostProcesses(),
		diagnoseCheck{Name: "Daemon diagnostics", Status: diagnoseSkip, Detail: "diagnostic bundle upload is not implemented"})

	platform := diagnoseSection{Title: "PLATFORM"}
	platform.Checks = append(platform.Checks,
		checkVirtualization(),
		checkFilesystemTool("mkfs.erofs"),
		checkFilesystemTool("mkfs.ext4"))

	storage := diagnoseSection{Title: "STORAGE"}
	storage.Checks = append(storage.Checks,
		r.checkStorageDirectories(),
		r.checkStoragePermissions(),
		checkDiskSpace(diagnoseStateDir(r.Socket)),
		diagnoseCheck{Name: "ZFS offset sync", Status: diagnoseSkip, Detail: "ZFS filesystem detection is not implemented"})

	connection := diagnoseSection{Title: "CONNECTION"}
	health, daemonVersion := r.checkDaemonHealth(checkCtx)
	connection.Checks = append(connection.Checks, health)
	connection.Checks = append(connection.Checks, r.checkDaemon(checkCtx)...)

	return diagnoseReport{Sections: []diagnoseSection{installation, platform, storage, connection}, DaemonVersion: daemonVersion}
}

func (r *Runner) checkCLIBinary() diagnoseCheck {
	check := diagnoseCheck{Name: "CLI binary"}
	binary, err := os.Executable()
	if err != nil || binary == "" {
		check.Status = diagnoseFail
		check.Detail = "not found"
		return check
	}
	check.Status = diagnosePass
	check.Detail = binary
	return check
}

// checkHostProcesses counts daemon and shim processes when pgrep is available.
var hostProcessCount = countHostProcesses

func checkHostProcesses() diagnoseCheck {
	check := diagnoseCheck{Name: "Host processes"}
	daemons, shims, err := hostProcessCount()
	if err != nil {
		check.Status = diagnoseSkip
		check.Detail = err.Error()
		return check
	}
	check.Status = diagnosePass
	check.Detail = fmt.Sprintf("%d rheicd, %d containerd-shim-nerdbox-v1", daemons, shims)
	return check
}

func checkVirtualization() diagnoseCheck {
	check := diagnoseCheck{Name: "Virtualization"}
	supported, detail := hostVirtualizationSupport()
	switch {
	case supported:
		check.Status = diagnosePass
	case detail == "":
		check.Status = diagnoseSkip
	default:
		check.Status = diagnoseFail
	}
	check.Detail = detail
	return check
}

var hostVirtualizationSupport = virtualizationSupport

func checkFilesystemTool(name string) diagnoseCheck {
	check := diagnoseCheck{Name: name}
	path, err := lookPath(name)
	if err != nil || path == "" {
		check.Status = diagnoseWarn
		check.Detail = "not found on PATH; filesystem images are built inside the pinned runtime container"
		return check
	}
	check.Status = diagnosePass
	check.Detail = path
	return check
}

func (r *Runner) checkStorageDirectories() diagnoseCheck {
	check := diagnoseCheck{Name: "Storage directories"}
	stateDir := diagnoseStateDir(r.Socket)
	paths := []string{stateDir, filepath.Dir(r.Socket)}
	missing := make([]string, 0, len(paths))
	for _, path := range paths {
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			missing = append(missing, path)
		}
	}
	if len(missing) != 0 {
		check.Status = diagnoseWarn
		check.Detail = "missing: " + joinComma(missing)
		return check
	}
	check.Status = diagnosePass
	check.Detail = fmt.Sprintf("all %d paths present", len(paths))
	return check
}

func (r *Runner) checkStoragePermissions() diagnoseCheck {
	check := diagnoseCheck{Name: "Directory permissions"}
	stateDir := diagnoseStateDir(r.Socket)
	probe, err := os.MkdirTemp(stateDir, ".diagnose-perm-*")
	if err != nil {
		check.Status = diagnoseFail
		check.Detail = "state directory is not writable: " + err.Error()
		return check
	}
	_ = os.Remove(probe)
	check.Status = diagnosePass
	check.Detail = "state directory is writable"
	return check
}

// checkDaemon grades the connection section against the local daemon. It
// always appends the same check count so the report shape is stable whether
// or not the daemon answers.
func (r *Runner) checkDaemon(ctx context.Context) []diagnoseCheck {
	checks := []diagnoseCheck{
		{Name: "Version match"},
		{Name: "Socket"},
		{Name: "SSH client config"},
		{Name: "Authentication"},
		{Name: "Global network policy"},
		{Name: "TLS trust store"},
	}
	client, err := r.client()
	if err != nil {
		return markDaemonUnreachable(checks, err)
	}
	defer func() { _ = client.Close() }()
	info, err := sdk.Version(client).Get(ctx)
	if err != nil {
		return markDaemonUnreachable(checks, err)
	}
	checks[0].Status = diagnosePass
	checks[0].Detail = "v" + info.Version
	if "v"+info.Version == "v"+version.Version {
		checks[0].Detail = "match (v" + info.Version + ")"
	} else {
		checks[0].Status = diagnoseWarn
		checks[0].Detail = fmt.Sprintf("client v%s, server v%s", version.Version, info.Version)
	}
	if _, err := os.Stat(r.Socket); err == nil {
		checks[1].Status = diagnosePass
		checks[1].Detail = "responsive"
	} else {
		checks[1].Status = diagnoseFail
		checks[1].Detail = "missing at " + r.Socket
	}
	checks[2] = checkSSHClientConfig()
	checks[3] = r.checkAuthentication(ctx, client)
	checks[4] = r.checkGlobalPolicy(ctx, client)
	checks[5] = checkTLSTrustStore()
	return checks
}

// checkDaemonHealth grades daemon reachability separately so the connection
// section carries the same check count as the sbx baseline.
func (r *Runner) checkDaemonHealth(ctx context.Context) (diagnoseCheck, string) {
	check := diagnoseCheck{Name: "Daemon"}
	client, err := r.client()
	if err != nil {
		check.Status = diagnoseFail
		check.Detail = err.Error()
		return check, ""
	}
	defer func() { _ = client.Close() }()
	info, err := sdk.Version(client).Get(ctx)
	if err != nil {
		check.Status = diagnoseFail
		check.Detail = err.Error()
		return check, ""
	}
	check.Status = diagnosePass
	check.Detail = "healthy (v" + info.Version + ")"
	return check, "v" + info.Version
}

func markDaemonUnreachable(checks []diagnoseCheck, err error) []diagnoseCheck {
	checks[0].Status = diagnoseFail
	checks[0].Detail = "daemon unreachable: " + err.Error()
	checks[1].Status = diagnoseFail
	checks[1].Detail = "not responsive"
	for i := 2; i < len(checks); i++ {
		checks[i].Status = diagnoseSkip
		checks[i].Detail = "daemon unreachable"
	}
	return checks
}

func checkSSHClientConfig() diagnoseCheck {
	check := diagnoseCheck{Name: "SSH client config"}
	home, err := os.UserHomeDir()
	if err != nil {
		check.Status = diagnoseSkip
		return check
	}
	data, err := os.ReadFile(filepath.Join(home, ".ssh", "config")) // #nosec G304 -- fixed host path, read-only diagnostic
	if errors.Is(err, os.ErrNotExist) {
		check.Status = diagnosePass
		check.Detail = "not configured"
		return check
	}
	if err != nil {
		check.Status = diagnoseWarn
		check.Detail = "cannot read ~/.ssh/config"
		return check
	}
	if containsRheicSSHConfig(string(data)) {
		check.Status = diagnosePass
		check.Detail = "rsbx managed entries present"
		return check
	}
	check.Status = diagnosePass
	check.Detail = "not configured"
	return check
}

func (r *Runner) checkAuthentication(ctx context.Context, client sdk.Client) diagnoseCheck {
	check := diagnoseCheck{Name: "Authentication"}
	status := sdk.AccountStatus(client)
	present, err := status.Status(ctx, "docker")
	if err != nil {
		check.Status = diagnoseSkip
		check.Detail = "credential status unavailable: " + err.Error()
		return check
	}
	if !present {
		// A signed-out installation is unconfigured, not broken. sbx reports a
		// warning and still exits 0; only hard failures make the report fail.
		check.Status = diagnoseWarn
		check.Detail = "not signed in; run rsbx login to enable registry and account features"
		return check
	}
	check.Status = diagnosePass
	detail, err := status.StatusDetail(ctx, "docker")
	if err == nil && detail.RefreshPresent {
		if detail.RefreshCoordinated {
			check.Detail = "signed in; token refresh coordinated"
		} else {
			check.Detail = "signed in; manual re-login required after token expiry"
		}
		return check
	}
	check.Detail = "signed in"
	return check
}

func (r *Runner) checkGlobalPolicy(ctx context.Context, client sdk.Client) diagnoseCheck {
	check := diagnoseCheck{Name: "Global network policy"}
	_, _, err := globalPolicyForList(ctx, client)
	if err != nil {
		check.Status = diagnoseWarn
		check.Detail = err.Error()
		return check
	}
	check.Status = diagnosePass
	check.Detail = "initialized"
	return check
}

func checkTLSTrustStore() diagnoseCheck {
	check := diagnoseCheck{Name: "TLS trust store"}
	for _, key := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if value := os.Getenv(key); value != "" {
			check.Status = diagnoseWarn
			check.Detail = key + " is set to " + value + " in this shell"
			return check
		}
	}
	check.Status = diagnosePass
	check.Detail = "not overridden in this shell"
	return check
}

func diagnoseStateDir(socket string) string {
	if socket != "" {
		if dir := filepath.Dir(socket); dir != "." && dir != string(filepath.Separator) {
			return dir
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".sandboxes")
}

func joinComma(values []string) string {
	out := ""
	for i, value := range values {
		if i > 0 {
			out += ", "
		}
		out += value
	}
	return out
}

func diagnoseStatusMarker(status string) string {
	switch status {
	case diagnosePass:
		return "✓"
	case diagnoseFail:
		return "✗"
	case diagnoseWarn:
		return "!"
	case diagnoseSkip:
		return "⊘"
	default:
		return "?"
	}
}

func escapeDiagnoseMarkdown(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"\\", "\\\\",
		"|", "\\|",
		"<", "&lt;",
		">", "&gt;",
		"`", "\\`",
		"\r\n", "<br>",
		"\r", "<br>",
		"\n", "<br>",
	)
	return replacer.Replace(value)
}

func (r *Runner) writeDiagnoseGitHubIssue(report diagnoseReport) error {
	flat := flattenDiagnoseReport(report)
	var out bytes.Buffer
	_, _ = fmt.Fprintln(&out, "### sbx diagnose report")
	_, _ = fmt.Fprintln(&out)
	_, _ = fmt.Fprintf(&out, "**OS:** %s\n", escapeDiagnoseMarkdown(runtime.GOOS))
	_, _ = fmt.Fprintf(&out, "**Arch:** %s\n", escapeDiagnoseMarkdown(runtime.GOARCH))
	daemonVersion := report.DaemonVersion
	if daemonVersion == "" {
		daemonVersion = "unknown"
	}
	_, _ = fmt.Fprintf(&out, "**DS Version:** %s\n", escapeDiagnoseMarkdown(daemonVersion))
	_, _ = fmt.Fprintln(&out)
	_, _ = fmt.Fprintln(&out, "| Check | Status | Message |")
	_, _ = fmt.Fprintln(&out, "|-------|--------|---------|")
	for _, check := range flat.Checks {
		_, _ = fmt.Fprintf(&out, "| %s | %s | %s |\n",
			escapeDiagnoseMarkdown(check.Name),
			diagnoseStatusMarker(check.Status),
			escapeDiagnoseMarkdown(check.Message))
	}
	data, err := json.MarshalIndent(flat, "", "  ")
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(&out)
	_, _ = fmt.Fprintln(&out, "<details>")
	_, _ = fmt.Fprintln(&out, "<summary>Full JSON output</summary>")
	_, _ = fmt.Fprintln(&out)
	_, _ = fmt.Fprintln(&out, "```json")
	_, _ = fmt.Fprintln(&out, string(data))
	_, _ = fmt.Fprintln(&out, "```")
	_, _ = fmt.Fprintln(&out)
	_, _ = fmt.Fprintln(&out, "</details>")
	n, err := r.Out.Write(out.Bytes())
	if err != nil {
		return err
	}
	if n != out.Len() {
		return io.ErrShortWrite
	}
	return nil
}

func (r *Runner) writeDiagnoseText(report diagnoseReport) {
	passed, failed, warned, skipped := 0, 0, 0, 0
	for _, section := range report.Sections {
		_, _ = fmt.Fprintln(r.Out, section.Title)
		for _, check := range section.Checks {
			switch check.Status {
			case diagnosePass:
				passed++
			case diagnoseFail:
				failed++
			case diagnoseWarn:
				warned++
			case diagnoseSkip:
				skipped++
			}
			_, _ = fmt.Fprintf(r.Out, "  %s %s", diagnoseStatusMarker(check.Status), check.Name)
			if check.Detail != "" {
				_, _ = fmt.Fprintf(r.Out, " — %s", check.Detail)
			}
			_, _ = fmt.Fprintln(r.Out)
		}
		_, _ = fmt.Fprintln(r.Out)
	}
	_, _ = fmt.Fprintf(r.Out, "%d passed · %d failed · %d warning · %d skipped\n", passed, failed, warned, skipped)
}
