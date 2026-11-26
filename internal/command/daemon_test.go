package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"

	"github.com/gyrel/sandboxes-cli/internal/daemonctl"
)

type fakeDaemonSupervisor struct {
	events        []string
	startOptions  daemonctl.StartOptions
	startResult   daemonctl.StartResult
	startErr      error
	stopErr       error
	restartResult daemonctl.StartResult
	restartErr    error
	levels        daemonctl.Levels
	levelsErr     error
	levelTarget   string
	levelValue    string
	setErr        error
	inspection    daemonctl.Inspection
}

func (f *fakeDaemonSupervisor) Start(_ context.Context, opts daemonctl.StartOptions) (daemonctl.StartResult, error) {
	f.events = append(f.events, "start")
	f.startOptions = opts
	return f.startResult, f.startErr
}

func (f *fakeDaemonSupervisor) Stop(context.Context) error {
	f.events = append(f.events, "stop")
	return f.stopErr
}

func (f *fakeDaemonSupervisor) Restart(_ context.Context, opts daemonctl.StartOptions) (daemonctl.StartResult, error) {
	f.events = append(f.events, "restart")
	f.startOptions = opts
	return f.restartResult, f.restartErr
}

func (f *fakeDaemonSupervisor) Levels(context.Context) (daemonctl.Levels, error) {
	return f.levels, f.levelsErr
}

func (f *fakeDaemonSupervisor) SetLevel(_ context.Context, target, level string) (daemonctl.Levels, error) {
	f.events = append(f.events, "set")
	f.levelTarget, f.levelValue = target, level
	return f.levels, f.setErr
}

func (f *fakeDaemonSupervisor) Inspect() daemonctl.Inspection { return f.inspection }

func (f *fakeDaemonSupervisor) LogPath() string { return "/state/daemon.log" }

type daemonVersionService struct{ err error }

func (s daemonVersionService) Get(context.Context) (sdk.VersionInfo, error) {
	if s.err != nil {
		return sdk.VersionInfo{}, s.err
	}
	return sdk.VersionInfo{Version: "1.2.3", APIVersion: "local/v1"}, nil
}

func daemonRunner(supervisor *fakeDaemonSupervisor) (*Runner, *bytes.Buffer) {
	var out bytes.Buffer
	return &Runner{
		Out: &out, Err: &out, In: strings.NewReader(""), Socket: "/state/sandboxesd.sock",
		NewDaemonSupervisor: func(string) (daemonSupervisor, error) { return supervisor, nil },
		NewClient:           func(string) (sdk.Client, error) { return nil, errors.New("offline") },
	}, &out
}

func TestDaemonGrammarAndExitCodes(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		setup       func(*fakeDaemonSupervisor)
		wantCode    int
		wantEvents  string
		wantTarget  string
		wantLevel   string
		wantOut     []string
		wantDetach  bool
		wantPolicy  string
		wantNoEvent bool
	}{
		{name: "no subcommand", args: []string{"daemon"}, wantCode: 2, wantOut: []string{"Usage: rsbx daemon COMMAND"}},
		{name: "root help", args: []string{"daemon", "--help"}, wantOut: []string{"Description:", "  rsbx daemon COMMAND", "log-level"}},
		{name: "start help", args: []string{"daemon", "start", "--help"}, wantOut: []string{"Usage:", "  rsbx daemon start", "--detach"}},
		{name: "stop help", args: []string{"daemon", "stop", "-h"}, wantOut: []string{"  rsbx daemon stop", "Flags:"}},
		{name: "restart help", args: []string{"daemon", "restart", "--help"}, wantOut: []string{"  rsbx daemon restart", "--policy string"}},
		{name: "log-level help", args: []string{"daemon", "log-level", "--help"}, wantOut: []string{"  rsbx daemon log-level", "general, proxy or all"}},
		{name: "status help", args: []string{"daemon", "status", "--help"}, wantOut: []string{"  rsbx daemon status", "status, socket and logs"}},
		{name: "unknown subcommand", args: []string{"daemon", "bogus"}, wantCode: 2, wantOut: []string{"unknown daemon subcommand", "rsbx daemon --help"}},
		{
			name: "start detached with policy", args: []string{"daemon", "start", "--detach", "--policy", "balanced"},
			setup: func(s *fakeDaemonSupervisor) {
				s.startResult = daemonctl.StartResult{PID: 8000, Socket: "/state/sandboxesd.sock", LogPath: "/state/daemon.log"}
			},
			wantEvents: "start", wantDetach: true, wantPolicy: "balanced", wantOut: []string{"Started daemon (PID 8000)", "logs /state/daemon.log"},
		},
		{
			name: "start foreground", args: []string{"daemon", "start"},
			setup:      func(s *fakeDaemonSupervisor) { s.startResult = daemonctl.StartResult{PID: 8000, Foreground: true} },
			wantEvents: "start", wantOut: []string{"daemon exited (PID 8000)"},
		},
		{
			name: "start already running", args: []string{"daemon", "start"},
			setup: func(s *fakeDaemonSupervisor) {
				s.startResult = daemonctl.StartResult{PID: 8000, AlreadyRunning: true, Socket: "/state/sandboxesd.sock"}
			},
			wantEvents: "start", wantOut: []string{"already running (PID 8000)"},
		},
		{name: "start rejects invalid policy", args: []string{"daemon", "start", "--policy", "nope"}, wantCode: 2, wantNoEvent: true, wantOut: []string{"--policy must be"}},
		{name: "start rejects positional", args: []string{"daemon", "start", "extra"}, wantCode: 2, wantNoEvent: true, wantOut: []string{"unexpected argument"}},
		{name: "start failure", args: []string{"daemon", "start"}, setup: func(s *fakeDaemonSupervisor) { s.startErr = errors.New("no binary") }, wantCode: 1, wantEvents: "start", wantOut: []string{"start daemon: no binary"}},
		{name: "stop", args: []string{"daemon", "stop"}, wantEvents: "stop", wantOut: []string{"Stopped daemon"}},
		{name: "stop rejects positional", args: []string{"daemon", "stop", "extra"}, wantCode: 2, wantNoEvent: true, wantOut: []string{"Usage: rsbx daemon stop"}},
		{name: "stop failure", args: []string{"daemon", "stop"}, setup: func(s *fakeDaemonSupervisor) { s.stopErr = errors.New("identity mismatch") }, wantCode: 1, wantEvents: "stop", wantOut: []string{"stop daemon: identity mismatch"}},
		{
			name: "restart", args: []string{"daemon", "restart", "--detach"},
			setup: func(s *fakeDaemonSupervisor) {
				s.restartResult = daemonctl.StartResult{PID: 8001, Socket: "/state/sandboxesd.sock", LogPath: "/state/daemon.log"}
			},
			wantEvents: "restart", wantDetach: true, wantOut: []string{"Started daemon (PID 8001)"},
		},
		{name: "restart failure", args: []string{"daemon", "restart"}, setup: func(s *fakeDaemonSupervisor) { s.restartErr = errors.New("did not stop") }, wantCode: 1, wantEvents: "restart", wantOut: []string{"restart daemon: did not stop"}},
		{
			name: "show log levels", args: []string{"daemon", "log-level"},
			setup:   func(s *fakeDaemonSupervisor) { s.levels = daemonctl.Levels{General: "debug", Proxy: "warn"} },
			wantOut: []string{"CATEGORY", "general", "debug", "proxy", "warn"}, wantNoEvent: true,
		},
		{name: "show log levels failure", args: []string{"daemon", "log-level"}, setup: func(s *fakeDaemonSupervisor) { s.levelsErr = daemonctl.ErrNotRunning }, wantCode: 1, wantOut: []string{"daemon is not running"}},
		{name: "shorthand sets all", args: []string{"daemon", "log-level", "debug"}, wantEvents: "set", wantTarget: "all", wantLevel: "debug", wantOut: []string{"Set all log levels to debug"}},
		{name: "set general", args: []string{"daemon", "log-level", "set", "general", "warn"}, wantEvents: "set", wantTarget: "general", wantLevel: "warn", wantOut: []string{"Set general log level to warn"}},
		{name: "set proxy", args: []string{"daemon", "log-level", "set", "proxy", "error"}, wantEvents: "set", wantTarget: "proxy", wantLevel: "error", wantOut: []string{"Set proxy log level to error"}},
		{name: "set missing arguments", args: []string{"daemon", "log-level", "set"}, wantCode: 2, wantNoEvent: true, wantOut: []string{"requires 2 arguments", "rsbx daemon log-level --help"}},
		{name: "set invalid level", args: []string{"daemon", "log-level", "set", "general", "loud"}, wantCode: 2, wantNoEvent: true, wantOut: []string{"invalid log level"}},
		{name: "set invalid target", args: []string{"daemon", "log-level", "set", "network", "debug"}, wantCode: 2, wantNoEvent: true, wantOut: []string{"invalid log category"}},
		{name: "shorthand rejects extra argument", args: []string{"daemon", "log-level", "debug", "extra"}, wantCode: 2, wantNoEvent: true, wantOut: []string{"Usage: rsbx daemon log-level"}},
		{name: "set failure", args: []string{"daemon", "log-level", "set", "general", "debug"}, setup: func(s *fakeDaemonSupervisor) { s.setErr = errors.New("foreign installation") }, wantCode: 1, wantEvents: "set", wantOut: []string{"set daemon log level: foreign installation"}},
		{
			name: "status stopped", args: []string{"daemon", "status"},
			setup:   func(s *fakeDaemonSupervisor) { s.inspection = daemonctl.Inspection{State: daemonctl.StateStopped} },
			wantOut: []string{"Status:  stopped", "Logs:    /state/daemon.log"},
		},
		{name: "status rejects positional", args: []string{"daemon", "status", "extra"}, wantCode: 2, wantOut: []string{"Usage: rsbx daemon status"}},
		{name: "status rejects invalid format", args: []string{"daemon", "status", "--format", "xml"}, wantCode: 2, wantOut: []string{"invalid format"}},
		{name: "status rejects conflicting format", args: []string{"daemon", "status", "--json", "--format", "yaml"}, wantCode: 2, wantOut: []string{"cannot be combined"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			supervisor := &fakeDaemonSupervisor{levels: daemonctl.DefaultLevels()}
			if tt.setup != nil {
				tt.setup(supervisor)
			}
			runner, out := daemonRunner(supervisor)
			if code := runner.Run(context.Background(), tt.args); code != tt.wantCode {
				t.Fatalf("exit=%d want=%d output=%q", code, tt.wantCode, out.String())
			}
			if got := strings.Join(supervisor.events, ","); got != tt.wantEvents {
				t.Fatalf("events=%q want=%q output=%q", got, tt.wantEvents, out.String())
			}
			if tt.wantNoEvent && len(supervisor.events) != 0 {
				t.Fatalf("unexpected events %v", supervisor.events)
			}
			if tt.wantDetach && !supervisor.startOptions.Detach {
				t.Fatalf("detach=false")
			}
			if tt.wantPolicy != "" && supervisor.startOptions.Policy != tt.wantPolicy {
				t.Fatalf("policy=%q want=%q", supervisor.startOptions.Policy, tt.wantPolicy)
			}
			if tt.wantTarget != "" && supervisor.levelTarget != tt.wantTarget {
				t.Fatalf("target=%q want=%q", supervisor.levelTarget, tt.wantTarget)
			}
			if tt.wantLevel != "" && supervisor.levelValue != tt.wantLevel {
				t.Fatalf("level=%q want=%q", supervisor.levelValue, tt.wantLevel)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("output lacks %q: %q", want, out.String())
				}
			}
		})
	}
}

func TestDaemonStatusJSONUsesSbxFieldNames(t *testing.T) {
	supervisor := &fakeDaemonSupervisor{inspection: daemonctl.Inspection{
		State: daemonctl.StateRunning,
		PID:   9000,
		Record: daemonctl.Record{
			Version: "v0.0.1-recorded",
		},
	}}
	var out bytes.Buffer
	runner := &Runner{
		Out: &out, Err: &out, In: strings.NewReader(""), Socket: "/state/sandboxesd.sock",
		NewDaemonSupervisor: func(string) (daemonSupervisor, error) { return supervisor, nil },
		NewClient: func(string) (sdk.Client, error) {
			return fakeClient{sandbox: fakeSandbox{}, versions: daemonVersionService{}}, nil
		},
	}
	if code := runner.Run(context.Background(), []string{"daemon", "status", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	for _, key := range []string{"status", "socket", "logs", "pid", "version", "api_version", "sandboxes", "running", "stopped"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("JSON lacks %q: %#v", key, decoded)
		}
	}
	if decoded["status"] != "running" || decoded["socket"] != "/state/sandboxesd.sock" || decoded["logs"] != "/state/daemon.log" {
		t.Fatalf("JSON = %#v", decoded)
	}
	if decoded["version"] != "v1.2.3" || decoded["api_version"] != "local/v1" {
		t.Fatalf("version JSON = %#v", decoded)
	}
	if decoded["pid"] != float64(9000) {
		t.Fatalf("pid = %#v", decoded["pid"])
	}
}

func TestDaemonStopNeverReportsSuccessWhenIdentityIsUnproven(t *testing.T) {
	supervisor := &fakeDaemonSupervisor{stopErr: errors.New("daemon state is ambiguous: daemon at /state/sandboxesd.sock was started outside 'rsbx daemon start' and its identity cannot be verified")}
	runner, out := daemonRunner(supervisor)
	if code := runner.Run(context.Background(), []string{"daemon", "stop"}); code != 1 {
		t.Fatalf("exit=%d want=1 output=%q", code, out.String())
	}
	if strings.Contains(out.String(), "Stopped daemon") {
		t.Fatalf("refused stop reported success: %q", out.String())
	}
	for _, want := range []string{"stop daemon:", "started outside 'rsbx daemon start'", "cannot be verified"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q: %q", want, out.String())
		}
	}
}

func TestDaemonStatusUnavailableFailsClosed(t *testing.T) {
	supervisor := &fakeDaemonSupervisor{inspection: daemonctl.Inspection{State: daemonctl.StateAmbiguous, Err: errors.New("PID was reused")}}
	runner, out := daemonRunner(supervisor)
	if code := runner.Run(context.Background(), []string{"daemon", "status", "--json"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	if decoded["status"] != "unavailable" || !strings.Contains(decoded["error"].(string), "PID was reused") {
		t.Fatalf("JSON = %#v", decoded)
	}
}

func TestDaemonStatusReportsLiveProcessWhenEndpointIsUnreachable(t *testing.T) {
	supervisor := &fakeDaemonSupervisor{inspection: daemonctl.Inspection{
		State:  daemonctl.StateRunning,
		PID:    9000,
		Record: daemonctl.Record{Version: "v0.0.1-recorded"},
	}}
	runner, out := daemonRunner(supervisor)
	if code := runner.Run(context.Background(), []string{"daemon", "status"}); code != 1 {
		t.Fatalf("exit=%d want=1 output=%q", code, out.String())
	}
	for _, want := range []string{"Status:  running", "PID:     9000", "endpoint is unreachable"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q: %q", want, out.String())
		}
	}
	for _, unwanted := range []string{"Version:", "Sandboxes:", "v0.0.1-recorded"} {
		if strings.Contains(out.String(), unwanted) {
			t.Fatalf("unreachable status reported %q: %q", unwanted, out.String())
		}
	}
}

func TestDaemonStatusStoppedOmitsRecordedVersion(t *testing.T) {
	supervisor := &fakeDaemonSupervisor{inspection: daemonctl.Inspection{
		State:  daemonctl.StateStopped,
		Record: daemonctl.Record{Version: "v0.0.1-recorded"},
	}}
	runner, out := daemonRunner(supervisor)
	if code := runner.Run(context.Background(), []string{"daemon", "status"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	for _, unwanted := range []string{"Version:", "v0.0.1-recorded"} {
		if strings.Contains(out.String(), unwanted) {
			t.Fatalf("stopped status reported %q: %q", unwanted, out.String())
		}
	}
}

func TestDaemonStatusYAML(t *testing.T) {
	supervisor := &fakeDaemonSupervisor{inspection: daemonctl.Inspection{State: daemonctl.StateStopped}}
	runner, out := daemonRunner(supervisor)
	if code := runner.Run(context.Background(), []string{"daemon", "status", "--format", "yaml"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	for _, want := range []string{"status: stopped", "socket: /state/sandboxesd.sock", "logs: /state/daemon.log"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("YAML lacks %q: %q", want, out.String())
		}
	}
}
