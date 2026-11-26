package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	sdk "github.com/gyrel/sandboxes-go-sdk"

	"github.com/gyrel/sandboxes-cli/internal/version"
)

const (
	versionNoArgsMessage  = "rsbx: 'rsbx version' accepts no arguments"
	versionFlagGroupError = "if any flags in the group [format json] are set none of the others can be; [format json] were all set"
)

type versionClientOutput struct {
	Version  string `json:"version" yaml:"version"`
	Revision string `json:"revision,omitempty" yaml:"revision,omitempty"`
}

type versionServerOutput struct {
	State      string `json:"state" yaml:"state"`
	Version    string `json:"version,omitempty" yaml:"version,omitempty"`
	APIVersion string `json:"api_version,omitempty" yaml:"api_version,omitempty"`
	Error      string `json:"error,omitempty" yaml:"error,omitempty"`
}

type versionOutput struct {
	Client versionClientOutput `json:"client" yaml:"client"`
	Server versionServerOutput `json:"server" yaml:"server"`
}

type versionOptions struct {
	format     string
	socket     string
	socketSet  bool
	json       bool
	debug      bool
	help       bool
	formatSet  bool
	jsonSet    bool
	positional bool
}

func (r *Runner) version(ctx context.Context, args []string) int {
	opts, err := parseVersionOptions(args, r.Debug)
	if err != nil {
		if err.Error() == "flag needs an argument: --socket" {
			return r.flagParseFailure(versionCommand, err)
		}
		return r.commandError(versionCommand, err.Error())
	}
	r.Debug = opts.debug
	if opts.socketSet {
		r.Socket = opts.socket
	}
	if opts.help {
		return r.showCommandHelp(versionHelp())
	}

	selected := opts.format
	if opts.json {
		selected = listFormatJSON
	}
	report := versionOutput{Client: versionClientOutput{Version: "v" + version.Version, Revision: version.Commit}}
	r.debug(ctx, debugEventVersionCheck, debugOperationField(versionCommand))
	report.Server = r.serverVersion(ctx)
	r.debug(ctx, debugEventVersionReady,
		debugStateField(report.Server.State),
		debugBoolean("api_version", report.Server.APIVersion != ""))

	switch selected {
	case listFormatJSON:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		encoder := yaml.NewEncoder(r.Out)
		encoder.SetIndent(2)
		if err := encoder.Encode(report); err != nil {
			r.error(err)
			return 1
		}
		if err := encoder.Close(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatTable:
		// continue below
	default:
		// parseVersionOptions validates the value; this is unreachable.
		return r.commandError(versionCommand, fmt.Sprintf("unknown format %q", selected))
	}

	if opts.debug {
		writeVersionTable(r.Out, report)
		return 0
	}

	if report.Client.Revision != "" {
		_, _ = fmt.Fprintf(r.Out, "rsbx version %s %s\n", report.Client.Version, report.Client.Revision)
	} else {
		_, _ = fmt.Fprintf(r.Out, "rsbx version %s\n", report.Client.Version)
	}
	return 0
}

// parseVersionOptions mirrors the reference command's pflag grammar for the
// version command. Flags are interspersed, a literal -- stops parsing, and all
// syntax failures exit through commandError. Values are never rewritten except
// for case/space normalization of the --format value.
//
//nolint:gocognit // one branch per accepted option shape.
func parseVersionOptions(args []string, debug bool) (versionOptions, error) {
	opts := versionOptions{format: listFormatTable, debug: debug}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			opts.positional = opts.positional || i+1 < len(args)
			break
		}
		if strings.HasPrefix(arg, "--") {
			consumed, err := parseVersionLongFlag(arg, args[i+1:], &opts)
			if err != nil {
				return opts, err
			}
			i += consumed
			continue
		}
		if strings.HasPrefix(arg, "-socket") {
			consumed, err := parseVersionSocket(arg, args[i+1:], &opts)
			if err != nil {
				return opts, err
			}
			i += consumed
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			if err := parseVersionShortFlags(arg[1:], &opts); err != nil {
				return opts, err
			}
			continue
		}
		opts.positional = true
	}
	if opts.help {
		return opts, nil
	}
	if opts.positional {
		return opts, errors.New(versionNoArgsMessage)
	}
	if opts.formatSet && opts.jsonSet {
		return opts, errors.New(versionFlagGroupError)
	}
	return opts, nil
}

//nolint:cyclop // one branch per documented long flag.
func parseVersionLongFlag(arg string, rest []string, opts *versionOptions) (int, error) {
	body := strings.TrimPrefix(arg, "--")
	name, raw, hasValue := strings.Cut(body, "=")
	switch name {
	case helpNameFormat:
		consumed := 0
		if !hasValue {
			if len(rest) == 0 {
				return 0, errors.New("flag needs an argument: --format")
			}
			raw = rest[0]
			consumed = 1
		}
		format, err := normalizeVersionFormat(raw)
		if err != nil {
			return 0, fmt.Errorf(`invalid argument %q for "--format" flag: %w`, raw, err)
		}
		opts.format = format
		opts.formatSet = true
		return consumed, nil
	case listFormatJSON:
		value, err := parseVersionBool("--json", raw, hasValue)
		if err != nil {
			return 0, err
		}
		opts.json = value
		opts.jsonSet = true
	case "socket":
		consumed := 0
		if !hasValue {
			if len(rest) == 0 {
				return 0, errors.New("flag needs an argument: --socket")
			}
			raw = rest[0]
			consumed = 1
		}
		opts.socket = raw
		opts.socketSet = true
		return consumed, nil
	case "debug":
		value, err := parseVersionBool("-D, --debug", raw, hasValue)
		if err != nil {
			return 0, err
		}
		opts.debug = value
	case helpCommand:
		value, err := parseVersionBool("-h, --help", raw, hasValue)
		if err != nil {
			return 0, err
		}
		opts.help = value
	case "":
		return 0, errors.New("unknown flag: --")
	default:
		return 0, fmt.Errorf("unknown flag: --%s", name)
	}
	return 0, nil
}

// parseVersionSocket accepts the single-dash spelling used by the legacy
// global parser, including a value that looks like another flag.
func parseVersionSocket(arg string, rest []string, opts *versionOptions) (int, error) {
	const name = "-socket"
	if arg == name {
		if len(rest) == 0 {
			return 0, errors.New("flag needs an argument: --socket")
		}
		opts.socket = rest[0]
		opts.socketSet = true
		return 1, nil
	}
	value, ok := strings.CutPrefix(arg, name+"=")
	if !ok {
		return 0, fmt.Errorf("unknown shorthand flag: %q in %s", 's', strings.TrimPrefix(arg, "-"))
	}
	opts.socket = value
	opts.socketSet = true
	return 0, nil
}

// parseVersionShortFlags handles pflag-style shorthand clusters such as -DD
// and -D=false. An unknown shorthand reports the remaining cluster text.
func parseVersionShortFlags(body string, opts *versionOptions) error {
	for body != "" {
		short := body[0]
		switch short {
		case 'D':
			value, consumed, err := parseVersionShorthandValue("-D, --debug", body)
			if err != nil {
				return err
			}
			opts.debug = value
			body = body[consumed:]
		case 'h':
			value, consumed, err := parseVersionShorthandValue("-h, --help", body)
			if err != nil {
				return err
			}
			opts.help = value
			body = body[consumed:]
		default:
			return fmt.Errorf("unknown shorthand flag: %q in -%s", rune(short), body)
		}
	}
	return nil
}

func parseVersionShorthandValue(display, body string) (bool, int, error) {
	if len(body) > 1 && body[1] == '=' {
		value, err := parseVersionBool(display, body[2:], true)
		if err != nil {
			return false, 0, err
		}
		return value, len(body), nil
	}
	return true, 1, nil
}

func parseVersionBool(display, raw string, hasValue bool) (bool, error) {
	if !hasValue {
		return true, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, errors.New(invalidBoolFlagMessage(display, raw, err))
	}
	return value, nil
}

func normalizeVersionFormat(raw string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(raw))
	switch format {
	case "", listFormatTable:
		return listFormatTable, nil
	case listFormatJSON, listFormatYAML:
		return format, nil
	default:
		return "", fmt.Errorf("unknown format %q; use table, json or yaml", raw)
	}
}

// writeVersionTable prints the client/server table for debug text output.
// The local daemon contract does not expose its build revision, so the server
// row contains only the version. The unavailable reason is already redacted
// by serverVersion.
func writeVersionTable(out io.Writer, report versionOutput) {
	client := report.Client.Version
	if report.Client.Revision != "" {
		client += " " + report.Client.Revision
	}
	_, _ = fmt.Fprintf(out, "  Client Version:  %s\n", client)
	if report.Server.State != "running" {
		reason := report.Server.Error
		if reason == "" {
			reason = "daemon unavailable"
		}
		_, _ = fmt.Fprintf(out, "  Server Version:  Unavailable (%s)\n", reason)
		return
	}
	server := report.Server.Version
	if server == "" {
		server = "Unknown"
	}
	_, _ = fmt.Fprintf(out, "  Server Version:  %s\n", server)
}

// serverUnavailableReason maps daemon failures to stable wording. The raw
// error can contain a local socket path, so it is never shown in any output
// format.
func serverUnavailableReason(errText string) string {
	lower := strings.ToLower(errText)
	for _, fragment := range []string{"dial", "connect", "no such file", "not running"} {
		if strings.Contains(lower, fragment) {
			return "daemon not running"
		}
	}
	return "daemon unavailable"
}

func (r *Runner) serverVersion(ctx context.Context) versionServerOutput {
	client, err := r.client()
	if err != nil {
		return unavailableVersionServer(err)
	}
	defer func() { _ = client.Close() }()
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	info, err := sdk.Version(client).Get(checkCtx)
	if err != nil {
		return unavailableVersionServer(err)
	}
	return versionServerOutput{State: "running", Version: "v" + info.Version, APIVersion: info.APIVersion}
}

func unavailableVersionServer(err error) versionServerOutput {
	return versionServerOutput{State: stateUnavailable, Error: serverUnavailableReason(err.Error())}
}
