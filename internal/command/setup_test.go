package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeSetupOptions struct {
	runtimeDir    string
	daemonVersion string
	daemonErr     error
	binaries      map[string]string
}

func fakeSetupDetector(options fakeSetupOptions) setupDetector {
	binaries := options.binaries
	if binaries == nil {
		binaries = map[string]string{
			"sandboxesd": "/usr/local/bin/sandboxesd",
			"containerd": "/usr/local/bin/containerd",
			"ctr":        "/usr/local/bin/ctr",
			"docker":     "/usr/local/bin/docker",
		}
	}
	return setupDetector{
		goos:       "darwin",
		goarch:     "arm64",
		socket:     "/tmp/rsbx-test/sandboxesd.sock",
		runtimeDir: options.runtimeDir,
		lookPath: func(name string) (string, error) {
			if path, ok := binaries[name]; ok {
				return path, nil
			}
			return "", errors.New("executable file not found in $PATH")
		},
		stat:    os.Stat,
		readDir: os.ReadDir,
		daemonVersion: func(context.Context) (string, error) {
			return options.daemonVersion, options.daemonErr
		},
	}
}

func setupRuntimeAssets(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"nerdbox-kernel-arm64", "nerdbox-rootfs-arm64.erofs", "containerd-shim-nerdbox-v1"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("synthetic"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func setupCheckByName(report setupReport, name string) (setupCheck, bool) {
	for _, check := range report.Checks {
		if check.Name == name {
			return check, true
		}
	}
	return setupCheck{}, false
}

func TestSetupReportScenarios(t *testing.T) {
	binariesWithoutDocker := map[string]string{
		"sandboxesd": "/usr/local/bin/sandboxesd",
		"containerd": "/usr/local/bin/containerd",
		"ctr":        "/usr/local/bin/ctr",
	}
	binariesWithoutCTR := map[string]string{
		"sandboxesd": "/usr/local/bin/sandboxesd",
		"containerd": "/usr/local/bin/containerd",
		"docker":     "/usr/local/bin/docker",
	}
	tests := []struct {
		name               string
		options            fakeSetupOptions
		withAssets         bool
		absentRuntimeDir   bool
		wantReady          bool
		wantStatus         map[string]string
		wantDaemonReady    bool
		wantDaemonError    string
		wantDetailContains []string
	}{
		{
			name:            "all present",
			options:         fakeSetupOptions{daemonVersion: "0.0.20"},
			withAssets:      true,
			wantReady:       true,
			wantDaemonReady: true,
			wantStatus: map[string]string{
				"Platform": setupStatusPass, "Daemon socket": setupStatusPass,
				"Runtime directory": setupStatusPass, "Runtime assets": setupStatusPass,
				"sandboxesd": setupStatusPass, "containerd": setupStatusPass,
				"ctr": setupStatusPass, "Docker CLI": setupStatusPass,
			},
		},
		{
			name:            "daemon unreachable",
			options:         fakeSetupOptions{daemonErr: errors.New("connection refused")},
			withAssets:      true,
			wantReady:       false,
			wantDaemonError: "connection refused",
			wantStatus:      map[string]string{"Daemon socket": setupStatusFail},
		},
		{
			name:               "missing assets",
			options:            fakeSetupOptions{daemonVersion: "0.0.20"},
			wantReady:          false,
			wantDaemonReady:    true,
			wantStatus:         map[string]string{"Runtime assets": setupStatusFail},
			wantDetailContains: []string{"kernel image", "root filesystem", "nerdbox shim"},
		},
		{
			name:             "missing runtime directory",
			options:          fakeSetupOptions{daemonVersion: "0.0.20"},
			absentRuntimeDir: true,
			wantReady:        false,
			wantDaemonReady:  true,
			wantStatus:       map[string]string{"Runtime directory": setupStatusFail, "Runtime assets": setupStatusSkip},
		},
		{
			name:            "missing optional Docker CLI",
			options:         fakeSetupOptions{daemonVersion: "0.0.20", binaries: binariesWithoutDocker},
			withAssets:      true,
			wantReady:       true,
			wantDaemonReady: true,
			wantStatus:      map[string]string{"Docker CLI": setupStatusWarn},
		},
		{
			name:            "missing required ctr binary",
			options:         fakeSetupOptions{daemonVersion: "0.0.20", binaries: binariesWithoutCTR},
			withAssets:      true,
			wantReady:       false,
			wantDaemonReady: true,
			wantStatus:      map[string]string{"ctr": setupStatusFail},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := test.options
			switch {
			case test.withAssets:
				options.runtimeDir = setupRuntimeAssets(t)
			case test.absentRuntimeDir:
				options.runtimeDir = filepath.Join(t.TempDir(), "absent")
			default:
				options.runtimeDir = t.TempDir()
			}
			report := buildSetupReport(context.Background(), fakeSetupDetector(options))
			if report.Ready != test.wantReady {
				t.Fatalf("ready = %t, want %t: %+v", report.Ready, test.wantReady, report)
			}
			if report.Daemon.Reachable != test.wantDaemonReady {
				t.Errorf("daemon reachable = %t, want %t", report.Daemon.Reachable, test.wantDaemonReady)
			}
			if test.wantDaemonError != "" && report.Daemon.Error != test.wantDaemonError {
				t.Errorf("daemon error = %q, want %q", report.Daemon.Error, test.wantDaemonError)
			}
			for name, want := range test.wantStatus {
				check, ok := setupCheckByName(report, name)
				if !ok {
					t.Errorf("report lacks %q check", name)
					continue
				}
				if check.Status != want {
					t.Errorf("%s status = %q, want %q (detail %q)", name, check.Status, want, check.Detail)
				}
				for _, part := range test.wantDetailContains {
					if !strings.Contains(check.Detail, part) {
						t.Errorf("%s detail lacks %q: %q", name, part, check.Detail)
					}
				}
			}
		})
	}
}

func TestSetupCommandJSONOutput(t *testing.T) {
	report := buildSetupReport(context.Background(), fakeSetupDetector(fakeSetupOptions{
		runtimeDir:    setupRuntimeAssets(t),
		daemonVersion: "0.0.20",
	}))
	var out, errOut bytes.Buffer
	runner := &Runner{Out: &out, Err: &errOut, setupCollector: func(context.Context) setupReport { return report }}
	if code := runner.Run(context.Background(), []string{"setup", "--format", "json"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out.String())
	}
	for _, key := range []string{"schema_version", "experimental", "scope", "platform", "daemon", "checks", "ready"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("JSON output lacks stable field %q: %s", key, out.String())
		}
	}
	platform, ok := decoded["platform"].(map[string]any)
	if !ok || platform["os"] != "darwin" || platform["arch"] != "arm64" {
		t.Fatalf("platform JSON = %#v", decoded["platform"])
	}
	daemon, ok := decoded["daemon"].(map[string]any)
	if !ok {
		t.Fatalf("daemon JSON = %#v", decoded["daemon"])
	}
	for _, key := range []string{"socket", "reachable"} {
		if _, ok := daemon[key]; !ok {
			t.Errorf("daemon JSON lacks %q: %#v", key, daemon)
		}
	}
	checks, ok := decoded["checks"].([]any)
	if !ok || len(checks) == 0 {
		t.Fatalf("checks JSON = %#v", decoded["checks"])
	}
	first, ok := checks[0].(map[string]any)
	if !ok {
		t.Fatalf("check JSON = %#v", checks[0])
	}
	for _, key := range []string{"name", "status", "required"} {
		if _, ok := first[key]; !ok {
			t.Errorf("check JSON lacks %q: %#v", key, first)
		}
	}
	if decoded["ready"] != true {
		t.Errorf("ready = %#v, want true", decoded["ready"])
	}
}

func TestSetupCommandExitsNonZeroWhenRequiredComponentMissing(t *testing.T) {
	report := buildSetupReport(context.Background(), fakeSetupDetector(fakeSetupOptions{
		runtimeDir:    t.TempDir(),
		daemonVersion: "0.0.20",
	}))
	var out, errOut bytes.Buffer
	runner := &Runner{Out: &out, Err: &errOut, setupCollector: func(context.Context) setupReport { return report }}
	if code := runner.Run(context.Background(), []string{"setup"}); code == 0 {
		t.Fatalf("exit=%d stdout=%q", code, out.String())
	}
	for _, want := range []string{"experimental, read-only", "Runtime assets", "Host readiness: not ready", "does not install software"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("text output lacks %q: %s", want, out.String())
		}
	}
}

func TestSetupCommandHelpAndInvalidArguments(t *testing.T) {
	t.Run("help", func(t *testing.T) {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		if code := runner.Run(context.Background(), []string{"setup", "--help"}); code != 0 {
			t.Fatalf("exit=%d output=%q", code, out.String())
		}
		for _, want := range []string{"EXPERIMENTAL", "rsbx setup", "--format", "read-only"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("help lacks %q: %s", want, out.String())
			}
		}
	})
	t.Run("unsupported ssh subcommand", func(t *testing.T) {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		if code := runner.Run(context.Background(), []string{"setup", "ssh"}); code == 0 {
			t.Fatalf("exit=%d output=%q", code, out.String())
		}
		if !strings.Contains(out.String(), "unsupported") || !strings.Contains(out.String(), "setup ssh") {
			t.Errorf("unexpected output: %q", out.String())
		}
	})
	t.Run("invalid format", func(t *testing.T) {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out, setupCollector: func(context.Context) setupReport {
			t.Fatal("invalid format should not run host checks")
			return setupReport{}
		}}
		if code := runner.Run(context.Background(), []string{"setup", "--format", "xml"}); code != 2 {
			t.Fatalf("exit=%d output=%q", code, out.String())
		}
		if !strings.Contains(out.String(), "invalid format") {
			t.Errorf("unexpected output: %q", out.String())
		}
	})
}
