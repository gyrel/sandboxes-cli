package command

import (
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
)

const (
	setupScopeHost     = "host"
	setupSchemaVersion = 1
	setupStatusPass    = "pass"
	setupStatusFail    = "fail"
	setupStatusWarn    = "warn"
	setupStatusSkip    = "skip"
	setupDaemonTimeout = 3 * time.Second
	setupRuntimeDirEnv = "RHEIC_RUNTIME_DIR"
)

const setupUsage = `Usage: rsbx setup [--format table|json|yaml] [--json]

EXPERIMENTAL: this command may change or be removed in future releases.

Description:
  Check whether this host has the components needed by local Rheic sandboxes.
  The check is read-only: it never installs software, changes settings, writes
  files, or starts a VM. Files being present does not prove a sandbox can boot.

Checks:
  platform         host operating system and architecture
  daemon socket    reachability of the local sandboxesd endpoint
  runtime assets   kernel, root filesystem and nerdbox shim under
                   $RHEIC_RUNTIME_DIR or ~/.sandboxes/runtime
  binaries         sandboxesd, containerd and ctr on PATH
  Docker CLI       optional; reported as a warning when absent

Exit status is non-zero only when a required host component is missing.
`

type setupPlatform struct {
	OS   string `json:"os" yaml:"os"`
	Arch string `json:"arch" yaml:"arch"`
}

type setupDaemon struct {
	Socket    string `json:"socket" yaml:"socket"`
	Reachable bool   `json:"reachable" yaml:"reachable"`
	Version   string `json:"version,omitempty" yaml:"version,omitempty"`
	Error     string `json:"error,omitempty" yaml:"error,omitempty"`
}

type setupCheck struct {
	Name     string `json:"name" yaml:"name"`
	Status   string `json:"status" yaml:"status"`
	Required bool   `json:"required" yaml:"required"`
	Detail   string `json:"detail,omitempty" yaml:"detail,omitempty"`
}

type setupReport struct {
	SchemaVersion int           `json:"schema_version" yaml:"schema_version"`
	Experimental  bool          `json:"experimental" yaml:"experimental"`
	Scope         string        `json:"scope" yaml:"scope"`
	Platform      setupPlatform `json:"platform" yaml:"platform"`
	Daemon        setupDaemon   `json:"daemon" yaml:"daemon"`
	Checks        []setupCheck  `json:"checks" yaml:"checks"`
	Ready         bool          `json:"ready" yaml:"ready"`
}

// setupDetector makes host probing explicit so tests can replace every
// side effect with a fake result.
type setupDetector struct {
	goos          string
	goarch        string
	socket        string
	runtimeDir    string
	lookPath      func(string) (string, error)
	stat          func(string) (os.FileInfo, error)
	readDir       func(string) ([]os.DirEntry, error)
	daemonVersion func(context.Context) (string, error)
}

func (r *Runner) setup(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet(setupCommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return r.showCommandHelp(setupHelp())
		}
		return r.flagParseFailure(setupCommand, err)
	}
	if fs.NArg() != 0 {
		return r.setupPositionalFailure(fs.Arg(0))
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	collector := r.setupCollector
	if collector == nil {
		collector = r.collectSetupReport
	}
	report := collector(ctx)
	if code := r.renderSetupReport(report, selected); code != 0 {
		return code
	}
	if !report.Ready {
		return 1
	}
	return 0
}

func (r *Runner) setupPositionalFailure(arg string) int {
	if arg == "ssh" {
		_, _ = fmt.Fprintln(r.Err, "rsbx setup ssh: unsupported: SSH client configuration is not implemented; this build performs a read-only host check only")
		return 1
	}
	_, _ = fmt.Fprint(r.Err, setupUsage)
	return 2
}

func (r *Runner) renderSetupReport(report setupReport, format string) int {
	switch format {
	case listFormatJSON:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			r.error(err)
			return 1
		}
	case listFormatYAML:
		data, err := yaml.Marshal(report)
		if err != nil {
			r.error(err)
			return 1
		}
		if _, err := r.Out.Write(data); err != nil {
			r.error(err)
			return 1
		}
	default:
		r.writeSetupText(report)
	}
	return 0
}

func (r *Runner) collectSetupReport(ctx context.Context) setupReport {
	return buildSetupReport(ctx, defaultSetupDetector(r))
}

func defaultSetupDetector(r *Runner) setupDetector {
	return setupDetector{
		goos:       runtime.GOOS,
		goarch:     runtime.GOARCH,
		socket:     r.Socket,
		runtimeDir: defaultSetupRuntimeDir(),
		lookPath:   lookPath,
		stat:       os.Stat,
		readDir:    os.ReadDir,
		daemonVersion: func(ctx context.Context) (string, error) {
			client, err := r.client()
			if err != nil {
				return "", err
			}
			defer func() { _ = client.Close() }()
			info, err := sdk.Version(client).Get(ctx)
			if err != nil {
				return "", err
			}
			return info.Version, nil
		},
	}
}

func defaultSetupRuntimeDir() string {
	if dir := strings.TrimSpace(os.Getenv(setupRuntimeDirEnv)); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".sandboxes", "runtime")
}

func buildSetupReport(ctx context.Context, detector setupDetector) setupReport {
	report := setupReport{
		SchemaVersion: setupSchemaVersion,
		Experimental:  true,
		Scope:         setupScopeHost,
		Platform:      setupPlatform{OS: detector.goos, Arch: detector.goarch},
	}
	daemonCheck, daemon := setupDaemonCheck(ctx, detector)
	report.Daemon = daemon
	report.Checks = append(report.Checks,
		setupPlatformCheck(detector),
		daemonCheck,
	)
	report.Checks = append(report.Checks, setupRuntimeChecks(detector)...)
	report.Checks = append(report.Checks, setupBinaryChecks(detector)...)
	report.Checks = append(report.Checks, setupDockerCheck(detector))
	report.Ready = true
	for _, check := range report.Checks {
		if check.Required && check.Status == setupStatusFail {
			report.Ready = false
			break
		}
	}
	return report
}

func setupPlatformCheck(detector setupDetector) setupCheck {
	check := setupCheck{Name: "Platform", Required: true, Status: setupStatusPass}
	check.Detail = detector.goos + "/" + detector.goarch
	if !supportedSetupOS(detector.goos) || !supportedSetupArch(detector.goarch) {
		check.Status = setupStatusFail
		check.Detail += " (unsupported host platform)"
	}
	return check
}

func supportedSetupOS(value string) bool {
	return value == "darwin" || value == "linux" || value == "windows"
}

func supportedSetupArch(value string) bool {
	return value == "amd64" || value == "arm64"
}

func setupDaemonCheck(ctx context.Context, detector setupDetector) (setupCheck, setupDaemon) {
	check := setupCheck{Name: "Daemon socket", Required: true}
	daemon := setupDaemon{Socket: detector.socket}
	if detector.socket == "" {
		check.Status = setupStatusFail
		check.Detail = "socket path is empty"
		daemon.Error = check.Detail
		return check, daemon
	}
	if detector.daemonVersion == nil {
		check.Status = setupStatusFail
		check.Detail = "daemon detector is unavailable"
		daemon.Error = check.Detail
		return check, daemon
	}
	probeCtx, cancel := context.WithTimeout(ctx, setupDaemonTimeout)
	defer cancel()
	version, err := detector.daemonVersion(probeCtx)
	if err != nil {
		check.Status = setupStatusFail
		check.Detail = "unreachable: " + err.Error()
		daemon.Error = err.Error()
		return check, daemon
	}
	check.Status = setupStatusPass
	daemon.Reachable = true
	daemon.Version = version
	check.Detail = "reachable"
	if version != "" {
		check.Detail = "reachable (v" + strings.TrimPrefix(version, "v") + ")"
	}
	return check, daemon
}

func setupRuntimeChecks(detector setupDetector) []setupCheck {
	directory := setupCheck{Name: "Runtime directory", Required: true}
	if detector.runtimeDir == "" {
		directory.Status = setupStatusFail
		directory.Detail = "not configured; set " + setupRuntimeDirEnv + " or install the runtime bundle"
		return []setupCheck{directory, skippedSetupCheck("Runtime assets", "runtime directory is unavailable")}
	}
	info, err := detector.stat(detector.runtimeDir)
	switch {
	case err != nil:
		directory.Status = setupStatusFail
		directory.Detail = "missing at " + detector.runtimeDir + ": " + err.Error()
		return []setupCheck{directory, skippedSetupCheck("Runtime assets", "runtime directory is unavailable")}
	case !info.IsDir():
		directory.Status = setupStatusFail
		directory.Detail = detector.runtimeDir + " is not a directory"
		return []setupCheck{directory, skippedSetupCheck("Runtime assets", "runtime directory is unavailable")}
	default:
		directory.Status = setupStatusPass
		directory.Detail = detector.runtimeDir
	}
	return []setupCheck{directory, setupRuntimeAssetsCheck(detector)}
}

func skippedSetupCheck(name, detail string) setupCheck {
	return setupCheck{Name: name, Status: setupStatusSkip, Detail: detail}
}

func setupRuntimeAssetsCheck(detector setupDetector) setupCheck {
	check := setupCheck{Name: "Runtime assets", Required: true}
	entries, err := detector.readDir(detector.runtimeDir)
	if err != nil {
		check.Status = setupStatusFail
		check.Detail = "cannot list runtime directory: " + err.Error()
		return check
	}
	kernel, rootfs, shim := classifySetupAssets(entries)
	var missing []string
	if !kernel {
		missing = append(missing, "kernel image")
	}
	if !rootfs {
		missing = append(missing, "root filesystem")
	}
	if !shim {
		missing = append(missing, "nerdbox shim")
	}
	if len(missing) != 0 {
		check.Status = setupStatusFail
		check.Detail = "missing: " + strings.Join(missing, ", ")
		return check
	}
	check.Status = setupStatusPass
	check.Detail = "kernel, root filesystem and nerdbox shim present"
	return check
}

func classifySetupAssets(entries []os.DirEntry) (kernel, rootfs, shim bool) {
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if strings.Contains(name, "kernel") || strings.HasPrefix(name, "vmlinuz") {
			kernel = true
		}
		if strings.Contains(name, "rootfs") && strings.HasSuffix(name, ".erofs") {
			rootfs = true
		}
		if strings.Contains(name, "containerd-shim-nerdbox") {
			shim = true
		}
	}
	return kernel, rootfs, shim
}

func setupBinaryChecks(detector setupDetector) []setupCheck {
	checks := make([]setupCheck, 0, len(setupRequiredBinaries))
	for _, name := range setupRequiredBinaries {
		check := setupCheck{Name: name, Required: true}
		path, err := detector.lookPath(name)
		if err != nil || path == "" {
			check.Status = setupStatusFail
			check.Detail = "not found on PATH"
		} else {
			check.Status = setupStatusPass
			check.Detail = path
		}
		checks = append(checks, check)
	}
	return checks
}

var setupRequiredBinaries = []string{"sandboxesd", "containerd", "ctr"}

func setupDockerCheck(detector setupDetector) setupCheck {
	check := setupCheck{Name: "Docker CLI", Required: false}
	path, err := detector.lookPath("docker")
	if err != nil || path == "" {
		check.Status = setupStatusWarn
		check.Detail = "not found on PATH; optional for local Rheic sandboxes"
		return check
	}
	check.Status = setupStatusPass
	check.Detail = path
	return check
}

func (r *Runner) writeSetupText(report setupReport) {
	_, _ = fmt.Fprintln(r.Out, "Rheic Sandboxes host check (experimental, read-only)")
	_, _ = fmt.Fprintf(r.Out, "Scope: %s\nPlatform: %s/%s\nDaemon socket: %s\n\n",
		report.Scope, report.Platform.OS, report.Platform.Arch, report.Daemon.Socket)
	for _, check := range report.Checks {
		_, _ = fmt.Fprintf(r.Out, "  %s %s", setupStatusMarker(check.Status), check.Name)
		if check.Required {
			_, _ = fmt.Fprint(r.Out, " [required]")
		}
		if check.Detail != "" {
			_, _ = fmt.Fprintf(r.Out, " — %s", check.Detail)
		}
		_, _ = fmt.Fprintln(r.Out)
	}
	_, _ = fmt.Fprintln(r.Out)
	if report.Ready {
		_, _ = fmt.Fprintln(r.Out, "Host readiness: ready")
	} else {
		_, _ = fmt.Fprintln(r.Out, "Host readiness: not ready")
	}
	_, _ = fmt.Fprintln(r.Out, "This check is read-only; it does not install software, start a VM, or prove that a sandbox can boot.")
}

func setupStatusMarker(status string) string {
	switch status {
	case setupStatusPass:
		return "✓"
	case setupStatusFail:
		return "✗"
	case setupStatusWarn:
		return "!"
	case setupStatusSkip:
		return "⊘"
	default:
		return "?"
	}
}
