package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"

	"github.com/gyrel/sandboxes-cli/internal/version"
)

type versionCallCounter struct{ calls int }

type countingVersionClient struct {
	runClient
	info    sdk.VersionInfo
	err     error
	counter *versionCallCounter
}

func (c countingVersionClient) VersionService() sdk.VersionService {
	return countingVersionService{c}
}

type countingVersionService struct{ client countingVersionClient }

func (s countingVersionService) Get(context.Context) (sdk.VersionInfo, error) {
	s.client.counter.calls++
	return s.client.info, s.client.err
}

func TestVersionAcceptedFlagForms(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
		json bool
		yaml bool
	}{
		{name: "default", args: []string{"version"}, want: "plain"},
		{name: "table", args: []string{"version", "--format", "table"}, want: "plain"},
		{name: "table uppercase", args: []string{"version", "--format", "TABLE"}, want: "plain"},
		{name: "table padded", args: []string{"version", "--format", " table "}, want: "plain"},
		{name: "table empty", args: []string{"version", "--format="}, want: "plain"},
		{name: "json format", args: []string{"version", "--format", "json"}, want: "json", json: true},
		{name: "json format uppercase", args: []string{"version", "--format", "JSON"}, want: "json", json: true},
		{name: "yaml format", args: []string{"version", "--format", "yaml"}, want: "yaml", yaml: true},
		{name: "json alias", args: []string{"version", "--json"}, want: "json", json: true},
		{name: "json true", args: []string{"version", "--json=true"}, want: "json", json: true},
		{name: "debug short", args: []string{"version", "-D"}, want: "table"},
		{name: "debug long", args: []string{"version", "--debug"}, want: "table"},
		{name: "debug repeated", args: []string{"version", "-DD"}, want: "table"},
		{name: "debug true", args: []string{"version", "-D=TRUE"}, want: "table"},
		{name: "debug false", args: []string{"version", "--debug=false"}, want: "plain"},
		{name: "debug zero", args: []string{"version", "-D=0"}, want: "plain"},
		{name: "debug last false", args: []string{"version", "-D", "--debug=false"}, want: "plain"},
		{name: "debug last true", args: []string{"version", "--debug=false", "--debug"}, want: "table"},
		{name: "debug after format", args: []string{"version", "--format", "table", "--debug"}, want: "table"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counter := &versionCallCounter{}
			client := countingVersionClient{
				info:    sdk.VersionInfo{Version: "0.0.9", APIVersion: "0.0.5"},
				counter: counter,
			}
			runner, out, stderr := runTestRunner(t, client, "")
			if code := runner.Run(context.Background(), tt.args); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			if counter.calls != 1 {
				t.Fatalf("version RPC calls=%d", counter.calls)
			}
			if tt.want == "table" {
				if !strings.Contains(stderr.String(), "msg=version.check") {
					t.Fatalf("debug stderr lacks version.check: %q", stderr.String())
				}
			} else if stderr.Len() != 0 {
				t.Fatalf("stderr=%q", stderr.String())
			}
			switch {
			case tt.json:
				var report versionOutput
				if err := json.Unmarshal(out.Bytes(), &report); err != nil {
					t.Fatalf("json %q: %v", out.String(), err)
				}
				if report.Server.State != "running" || report.Server.Version != "v0.0.9" {
					t.Fatalf("report=%+v", report)
				}
			case tt.yaml:
				if !strings.Contains(out.String(), "client:\n  version:") || !strings.Contains(out.String(), "  state: running") {
					t.Fatalf("yaml=%q", out.String())
				}
			case tt.want == "table":
				for _, want := range []string{"  Client Version:  v" + version.Version, "  Server Version:  v0.0.9"} {
					if !strings.Contains(out.String(), want) {
						t.Fatalf("table output lacks %q: %q", want, out.String())
					}
				}
			default:
				if !strings.Contains(out.String(), "rsbx version v"+version.Version) || strings.Contains(out.String(), "Client Version:") {
					t.Fatalf("plain output=%q", out.String())
				}
			}
		})
	}
}

func TestVersionFlagErrorsMatchReference(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
		hint string
	}{
		{
			name: "format text",
			args: []string{"version", "--format", "text"},
			want: `error: invalid argument "text" for "--format" flag: unknown format "text"; use table, json or yaml`,
			hint: "try: rsbx version --help",
		},
		{
			name: "format unknown",
			args: []string{"version", "--format", "bogus"},
			want: `error: invalid argument "bogus" for "--format" flag: unknown format "bogus"; use table, json or yaml`,
			hint: "try: rsbx version --help",
		},
		{
			name: "format missing value",
			args: []string{"version", "--format"},
			want: "error: flag needs an argument: --format",
			hint: "try: rsbx version --help",
		},
		{
			name: "unknown long flag",
			args: []string{"version", "--nope"},
			want: "error: unknown flag: --nope",
			hint: "try: rsbx version --help",
		},
		{
			name: "unknown short flag",
			args: []string{"version", "-j"},
			want: "error: unknown shorthand flag: 'j' in -j",
			hint: "try: rsbx version --help",
		},
		{
			name: "single dash long flag",
			args: []string{"version", "-format", "table"},
			want: "error: unknown shorthand flag: 'f' in -format",
			hint: "try: rsbx version --help",
		},
		{
			name: "invalid debug long",
			args: []string{"version", "--debug=maybe"},
			want: `error: invalid argument "maybe" for "-D, --debug" flag: strconv.ParseBool: parsing "maybe": invalid syntax`,
			hint: "try: rsbx version --help",
		},
		{
			name: "invalid debug short",
			args: []string{"version", "-D=maybe"},
			want: `error: invalid argument "maybe" for "-D, --debug" flag: strconv.ParseBool: parsing "maybe": invalid syntax`,
			hint: "try: rsbx version --help",
		},
		{
			name: "invalid json",
			args: []string{"version", "--json=maybe"},
			want: `error: invalid argument "maybe" for "--json" flag: strconv.ParseBool: parsing "maybe": invalid syntax`,
			hint: "try: rsbx version --help",
		},
		{
			name: "invalid help",
			args: []string{"version", "--help=maybe"},
			want: `error: invalid argument "maybe" for "-h, --help" flag: strconv.ParseBool: parsing "maybe": invalid syntax`,
			hint: "try: rsbx version --help",
		},
		{
			name: "positional argument",
			args: []string{"version", "extra"},
			want: "error: " + versionNoArgsMessage,
			hint: "try: rsbx version --help",
		},
		{
			name: "after terminator",
			args: []string{"version", "--", "--debug"},
			want: "error: " + versionNoArgsMessage,
			hint: "try: rsbx version --help",
		},
		{
			name: "group conflict",
			args: []string{"version", "--json", "--format", "yaml"},
			want: "error: " + versionFlagGroupError,
			hint: "try: rsbx version --help",
		},
		{
			name: "group conflict explicit false",
			args: []string{"version", "--json=false", "--format", "table"},
			want: "error: " + versionFlagGroupError,
			hint: "try: rsbx version --help",
		},
		{
			name: "invalid format beats help",
			args: []string{"version", "--format", "bogus", "--help"},
			want: `error: invalid argument "bogus" for "--format" flag: unknown format "bogus"; use table, json or yaml`,
			hint: "try: rsbx version --help",
		},
		{
			name: "unknown beats help",
			args: []string{"version", "--help", "--nope"},
			want: "error: unknown flag: --nope",
			hint: "try: rsbx version --help",
		},
		{
			name: "global invalid debug",
			args: []string{"--debug=maybe", "version"},
			want: `error: invalid argument "maybe" for "-D, --debug" flag: strconv.ParseBool: parsing "maybe": invalid syntax`,
			hint: "try: rsbx --help",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			runner, out, stderr := runTestRunner(t, versionFakeClient{}, "")
			runner.NewClient = func(string) (sdk.Client, error) {
				called = true
				return versionFakeClient{}, nil
			}
			if code := runner.Run(context.Background(), tt.args); code != 1 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			if called {
				t.Fatal("flag error dialed the daemon")
			}
			if out.Len() != 0 {
				t.Fatalf("stdout=%q", out.String())
			}
			if want := tt.want + "\n  " + tt.hint + "\n"; stderr.String() != want {
				t.Fatalf("stderr=%q want=%q", stderr.String(), want)
			}
			if runner.Debug {
				t.Fatal("flag error enabled debug mode")
			}
		})
	}
}

func TestVersionHelpPrecedesPositionalAndGroupErrors(t *testing.T) {
	for _, args := range [][]string{
		{"version", "--help", "extra"},
		{"version", "--json", "--format", "yaml", "--help"},
		{"version", "--format", "json", "--help"},
	} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v: exit=%d output=%q", args, code, out.String())
		}
		if !strings.Contains(out.String(), "Show Gyrel Sandboxes version information") || !strings.Contains(out.String(), "--format string") {
			t.Fatalf("%v: help=%q", args, out.String())
		}
	}
}

func TestVersionStructuredOutputRedactsDaemonFailure(t *testing.T) {
	raw := "dial unix /Users/alice/Library/Application Support/private.sock: connect: connection refused token=secret-value"
	tests := []struct {
		name string
		args []string
	}{
		{name: "json", args: []string{"version", "--format", "json"}},
		{name: "yaml", args: []string{"version", "--format", "yaml"}},
		{name: "debug text", args: []string{"version", "--debug"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, out, stderr := runTestRunner(t, versionFakeClient{err: errors.New(raw)}, "")
			if code := runner.Run(context.Background(), tt.args); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			for _, forbidden := range []string{"alice", "/Users/", "private.sock", "secret-value", "connection refused", "dial unix"} {
				if strings.Contains(out.String(), forbidden) {
					t.Fatalf("output leaked %q: %q", forbidden, out.String())
				}
			}
			if !strings.Contains(out.String(), "daemon not running") {
				t.Fatalf("output lacks stable reason: %q", out.String())
			}
		})
	}
}

func TestVersionStructuredOutputUsesGenericUnavailableReason(t *testing.T) {
	raw := "unexpected daemon failure under /home/bob"
	runner, out, stderr := runTestRunner(t, versionFakeClient{err: errors.New(raw)}, "")
	if code := runner.Run(context.Background(), []string{"version", "--format", "json"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	var report versionOutput
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	if report.Server.State != stateUnavailable || report.Server.Error != "daemon unavailable" {
		t.Fatalf("report=%+v", report)
	}
	if strings.Contains(out.String(), "/home/bob") || strings.Contains(out.String(), raw) {
		t.Fatalf("output leaked raw error: %q", out.String())
	}
}

func TestVersionFlagValuesAndTerminatorArePreserved(t *testing.T) {
	t.Run("format value looks like debug", func(t *testing.T) {
		runner, out, stderr := runTestRunner(t, versionFakeClient{}, "")
		if code := runner.Run(context.Background(), []string{"version", "--format", "--debug"}); code != 1 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), `unknown format "--debug"`) {
			t.Fatalf("stderr=%q", stderr.String())
		}
		if runner.Debug {
			t.Fatal("format value enabled debug mode")
		}
	})

	t.Run("json does not consume separated value", func(t *testing.T) {
		called := false
		runner, out, stderr := runTestRunner(t, versionFakeClient{}, "")
		runner.NewClient = func(string) (sdk.Client, error) {
			called = true
			return versionFakeClient{}, nil
		}
		if code := runner.Run(context.Background(), []string{"version", "--json", "false"}); code != 1 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
		}
		if called {
			t.Fatal("positional error dialed the daemon")
		}
		if !strings.Contains(stderr.String(), versionNoArgsMessage) {
			t.Fatalf("stderr=%q", stderr.String())
		}
	})

	t.Run("terminator keeps flag-like positionals", func(t *testing.T) {
		runner, out, stderr := runTestRunner(t, versionFakeClient{}, "")
		if code := runner.Run(context.Background(), []string{"version", "--format", "table", "--", "--json"}); code != 1 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), versionNoArgsMessage) || runner.Debug {
			t.Fatalf("stderr=%q debug=%t", stderr.String(), runner.Debug)
		}
	})

	t.Run("socket value looks like debug", func(t *testing.T) {
		var got string
		runner, out, stderr := runTestRunner(t, versionFakeClient{}, "")
		runner.NewClient = func(address string) (sdk.Client, error) {
			got = address
			return versionFakeClient{info: sdk.VersionInfo{Version: "0.0.9"}}, nil
		}
		if code := runner.Run(context.Background(), []string{"version", "--socket", "--debug"}); code != 0 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
		}
		if got != "--debug" || runner.Socket != "--debug" || runner.Debug {
			t.Fatalf("socket=%q runner.Socket=%q debug=%t", got, runner.Socket, runner.Debug)
		}
	})
}
