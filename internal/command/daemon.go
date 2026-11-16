package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	sdk "github.com/rheic/sandboxes-go-sdk"
	"gopkg.in/yaml.v3"

	"github.com/rheic/sandboxes-cli/internal/daemonctl"
)

const (
	daemonRestartCommand  = "restart"
	daemonLogLevelCommand = "log-level"
	daemonStatusCommand   = "status"
	logCategoryAll        = "all"
)

const daemonUsage = `Usage: rsbx daemon COMMAND

Manage the local sandboxesd daemon.

Commands:
  start [--detach] [--policy PROFILE]   Start the local daemon
  stop                                  Stop the local daemon
  restart [--detach] [--policy PROFILE] Stop, then start the local daemon
  log-level [LEVEL]                     Show log levels, or set every category
  log-level set TARGET LEVEL            Set one category: general, proxy or all
  status [--format table|json|yaml]     Show daemon status

The daemon state directory and log path are derived from --socket. The CLI
starts sandboxesd with --state and --socket; set SANDBOXES_DAEMON_BINARY when
sandboxesd is not on PATH. stop and restart refuse to signal a PID unless its
recorded process start identity and installation match the selected state
directory.

Log levels: debug, info, warn, error
Targets:    general, proxy, all

Examples:
  rsbx daemon start --detach
  rsbx daemon status --json
  rsbx daemon log-level
  rsbx daemon log-level set general debug
  rsbx daemon log-level debug

Flags:
  -h, --help   Show this help
`

const daemonStartUsage = `Usage: rsbx daemon start [flags]

Start the local daemon in the foreground; use --detach to run it in the
background with logs in <state>/daemon.log.

Flags:
  -d, --detach          Run the daemon in the background
      --policy string   Initialize policy: allow-all, balanced or deny-all
  -h, --help            Show this help
`

const daemonStopUsage = `Usage: rsbx daemon stop [flags]

Stop the local daemon. A stopped daemon is not an error.

Flags:
  -h, --help   Show this help
`

const daemonRestartUsage = `Usage: rsbx daemon restart [flags]

Stop the proven local daemon process, then start a new one.

Flags:
  -d, --detach          Run the daemon in the background
      --policy string   Initialize policy: allow-all, balanced or deny-all
  -h, --help            Show this help
`

const daemonLogLevelUsage = `Usage: rsbx daemon log-level [LEVEL]
       rsbx daemon log-level set TARGET LEVEL

Show the general and proxy log levels, or persist a new level. TARGET is
general, proxy or all. LEVEL is debug, info, warn or error. A single LEVEL
sets every category.

Examples:
  rsbx daemon log-level
  rsbx daemon log-level set general debug
  rsbx daemon log-level set all info
  rsbx daemon log-level warn

Flags:
  -h, --help   Show this help
`

const daemonStatusUsage = `Usage: rsbx daemon status [flags]

Show daemon status. JSON uses the sbx field names status, socket and logs, plus
pid, version, api_version, sandboxes, running, stopped and error when available.

Flags:
      --format string   Output format: table, json or yaml
  -h, --help            Show this help
      --json            Output in JSON format
`

type daemonSupervisor interface {
	Start(context.Context, daemonctl.StartOptions) (daemonctl.StartResult, error)
	Stop(context.Context) error
	Restart(context.Context, daemonctl.StartOptions) (daemonctl.StartResult, error)
	Levels(context.Context) (daemonctl.Levels, error)
	SetLevel(context.Context, string, string) (daemonctl.Levels, error)
	Inspect() daemonctl.Inspection
	LogPath() string
}

func (r *Runner) daemon(args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, daemonUsage)
		return 2
	}
	switch args[0] {
	case helpCommand, helpShort, helpFlag:
		_, _ = fmt.Fprint(r.Out, daemonUsage)
		return 0
	case startCommand:
		return r.daemonStart(args[1:])
	case stopCommand:
		return r.daemonStop(args[1:])
	case daemonRestartCommand:
		return r.daemonRestart(args[1:])
	case daemonLogLevelCommand:
		return r.daemonLogLevel(args[1:])
	case daemonStatusCommand:
		return r.daemonStatus(args[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "error: unknown daemon subcommand %q\n  try: rsbx daemon --help\n", args[0])
		return 2
	}
}

func (r *Runner) supervisor() (daemonSupervisor, error) {
	if r.NewDaemonSupervisor != nil {
		return r.NewDaemonSupervisor(r.Socket)
	}
	return daemonctl.New(r.Socket)
}

func (r *Runner) daemonStart(args []string) int {
	opts, help, err := parseDaemonStartOptions("daemon start", args, r.Err)
	if help {
		_, _ = fmt.Fprint(r.Out, daemonStartUsage)
		return 0
	}
	if err != nil {
		return r.flagParseFailure("daemon start", err)
	}
	return r.runDaemonStart(context.Background(), "start", opts)
}

func (r *Runner) daemonRestart(args []string) int {
	opts, help, err := parseDaemonStartOptions("daemon restart", args, r.Err)
	if help {
		_, _ = fmt.Fprint(r.Out, daemonRestartUsage)
		return 0
	}
	if err != nil {
		return r.flagParseFailure("daemon restart", err)
	}
	return r.runDaemonStart(context.Background(), "restart", opts)
}

func (r *Runner) runDaemonStart(ctx context.Context, operation string, opts daemonctl.StartOptions) int {
	supervisor, err := r.supervisor()
	if err != nil {
		r.error(err)
		return 1
	}
	opts.Stdout, opts.Stderr = r.Out, r.Err
	var result daemonctl.StartResult
	if operation == "restart" {
		result, err = supervisor.Restart(ctx, opts)
	} else {
		result, err = supervisor.Start(ctx, opts)
	}
	if err != nil {
		r.error(fmt.Errorf("%s daemon: %w", operation, err))
		return 1
	}
	switch {
	case result.AlreadyRunning:
		_, _ = fmt.Fprintf(r.Out, "daemon already running (PID %d) at %s\n", result.PID, result.Socket)
	case result.Foreground:
		_, _ = fmt.Fprintf(r.Out, "daemon exited (PID %d)\n", result.PID)
	default:
		_, _ = fmt.Fprintf(r.Out, "Started daemon (PID %d)\n  socket %s\n  logs %s\n", result.PID, result.Socket, result.LogPath)
	}
	return 0
}

func parseDaemonStartOptions(name string, args []string, errOut io.Writer) (daemonctl.StartOptions, bool, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	var opts daemonctl.StartOptions
	fs.BoolVar(&opts.Detach, "detach", false, "run the daemon in the background")
	fs.BoolVar(&opts.Detach, "d", false, "run the daemon in the background")
	fs.StringVar(&opts.Policy, "policy", "", "initialize policy: allow-all, balanced or deny-all")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"--policy": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return daemonctl.StartOptions{}, true, nil
		}
		return daemonctl.StartOptions{}, false, err
	}
	if fs.NArg() != 0 {
		return daemonctl.StartOptions{}, false, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	switch opts.Policy {
	case "", "allow-all", "balanced", "deny-all":
	default:
		return daemonctl.StartOptions{}, false, errors.New(`--policy must be "allow-all", "balanced" or "deny-all"`)
	}
	return opts, false, nil
}

func (r *Runner) daemonStop(args []string) int {
	fs := flag.NewFlagSet("daemon stop", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	if err := fs.Parse(reorderFlagArgs(args, nil)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(r.Out, daemonStopUsage)
			return 0
		}
		return r.flagParseFailure("daemon stop", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprint(r.Err, daemonStopUsage)
		return 2
	}
	supervisor, err := r.supervisor()
	if err != nil {
		r.error(err)
		return 1
	}
	if err := supervisor.Stop(context.Background()); err != nil {
		r.error(fmt.Errorf("stop daemon: %w", err))
		return 1
	}
	_, _ = fmt.Fprintln(r.Out, "Stopped daemon")
	return 0
}

func (r *Runner) daemonLogLevel(args []string) int {
	if len(args) > 0 && (args[0] == helpCommand || args[0] == helpShort || args[0] == helpFlag) {
		_, _ = fmt.Fprint(r.Out, daemonLogLevelUsage)
		return 0
	}
	if len(args) == 0 {
		return r.showDaemonLogLevels()
	}
	if args[0] == "set" {
		return r.setDaemonLogLevel(args[1:])
	}
	if len(args) == 1 {
		return r.setDaemonLogLevel([]string{logCategoryAll, args[0]})
	}
	_, _ = fmt.Fprint(r.Err, daemonLogLevelUsage)
	return 2
}

func (r *Runner) showDaemonLogLevels() int {
	supervisor, err := r.supervisor()
	if err != nil {
		r.error(err)
		return 1
	}
	levels, err := supervisor.Levels(context.Background())
	if err != nil {
		r.error(fmt.Errorf("show daemon log levels: %w", err))
		return 1
	}
	writer := tabwriter.NewWriter(r.Out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(writer, "CATEGORY\tLEVEL")
	_, _ = fmt.Fprintf(writer, "general\t%s\n", levels.General)
	_, _ = fmt.Fprintf(writer, "proxy\t%s\n", levels.Proxy)
	if err := writer.Flush(); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) setDaemonLogLevel(args []string) int {
	if len(args) != 2 {
		_, _ = fmt.Fprintln(r.Err, "error: 'rsbx daemon log-level set' requires 2 arguments")
		_, _ = fmt.Fprintln(r.Err, "  try: rsbx daemon log-level --help")
		return 2
	}
	target, level := args[0], args[1]
	if err := daemonctl.ValidateCategory(target); err != nil {
		r.error(err)
		_, _ = fmt.Fprintln(r.Err, "  try: rsbx daemon log-level --help")
		return 2
	}
	if err := daemonctl.ValidateLevel(level); err != nil {
		r.error(err)
		_, _ = fmt.Fprintln(r.Err, "  try: rsbx daemon log-level --help")
		return 2
	}
	supervisor, err := r.supervisor()
	if err != nil {
		r.error(err)
		return 1
	}
	if _, err := supervisor.SetLevel(context.Background(), target, level); err != nil {
		r.error(fmt.Errorf("set daemon log level: %w", err))
		return 1
	}
	if target == logCategoryAll {
		_, _ = fmt.Fprintf(r.Out, "Set all log levels to %s\n", level)
	} else {
		_, _ = fmt.Fprintf(r.Out, "Set %s log level to %s\n", target, level)
	}
	return 0
}

type daemonStatusOutput struct {
	Status  string `json:"status" yaml:"status"`
	Socket  string `json:"socket" yaml:"socket"`
	Logs    string `json:"logs" yaml:"logs"`
	PID     int    `json:"pid,omitempty" yaml:"pid,omitempty"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
	API     string `json:"api_version,omitempty" yaml:"api_version,omitempty"`
	Total   int    `json:"sandboxes" yaml:"sandboxes"`
	Running int    `json:"running" yaml:"running"`
	Stopped int    `json:"stopped" yaml:"stopped"`
	Error   string `json:"error,omitempty" yaml:"error,omitempty"`
}

func (r *Runner) daemonStatus(args []string) int {
	fs := flag.NewFlagSet("daemon status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{formatFlag: true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(r.Out, daemonStatusUsage)
			return 0
		}
		return r.flagParseFailure("daemon status", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprint(r.Err, daemonStatusUsage)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	out, code := r.collectDaemonStatus(context.Background())
	if renderErr := renderDaemonStatus(r.Out, selected, out); renderErr != nil {
		r.error(renderErr)
		return 1
	}
	return code
}

func (r *Runner) collectDaemonStatus(ctx context.Context) (daemonStatusOutput, int) {
	out := daemonStatusOutput{Socket: r.Socket, Status: stateUnavailable}
	if supervisor, err := r.supervisor(); err == nil {
		out.Logs = supervisor.LogPath()
	}
	client, err := r.client()
	if err == nil {
		defer func() { _ = client.Close() }()
		out, err = r.probeDaemon(ctx, client, out)
	}
	if err != nil {
		out = r.classifyUnreachable(out, err)
	}
	if out.Status == sandboxStateRunning {
		return out, 0
	}
	if out.Status == sandboxStateStopped {
		return out, 0
	}
	return out, 1
}

func (r *Runner) probeDaemon(ctx context.Context, client sdk.Client, out daemonStatusOutput) (daemonStatusOutput, error) {
	info, err := sdk.Version(client).Get(ctx)
	if err != nil {
		return out, err
	}
	out.Status = sandboxStateRunning
	out.Version = "v" + info.Version
	out.API = info.APIVersion
	if items, listErr := collectSandboxes(ctx, client, 1000, 0); listErr == nil {
		out.Total = len(items)
		for i := range items {
			switch items[i].State {
			case sdk.StateRunning:
				out.Running++
			case sdk.StateStopped:
				out.Stopped++
			}
		}
	}
	if supervisor, supErr := r.supervisor(); supErr == nil {
		if inspection := supervisor.Inspect(); inspection.State == daemonctl.StateRunning {
			out.PID = inspection.PID
		}
	}
	return out, nil
}

func (r *Runner) classifyUnreachable(out daemonStatusOutput, probeErr error) daemonStatusOutput {
	supervisor, err := r.supervisor()
	if err != nil {
		out.Status = stateUnavailable
		out.Error = probeErr.Error()
		return out
	}
	inspection := supervisor.Inspect()
	switch inspection.State {
	case daemonctl.StateStopped:
		out.Status = sandboxStateStopped
		out.Error = ""
	case daemonctl.StateRunning:
		out.Status = stateUnavailable
		out.PID = inspection.PID
		out.Error = "daemon process is running but the endpoint is unreachable: " + probeErr.Error()
	default:
		out.Status = stateUnavailable
		if inspection.Err != nil {
			out.Error = inspection.Err.Error()
		} else {
			out.Error = probeErr.Error()
		}
	}
	return out
}

func renderDaemonStatus(out io.Writer, format string, status daemonStatusOutput) error {
	switch format {
	case listFormatJSON:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(status)
	case listFormatYAML:
		data, err := yaml.Marshal(status)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		_, _ = fmt.Fprintf(out, "Status:  %s\nSocket:  %s\nLogs:    %s\n", status.Status, status.Socket, status.Logs)
		if status.PID != 0 {
			_, _ = fmt.Fprintf(out, "PID:     %d\n", status.PID)
		}
		if status.Status == sandboxStateRunning {
			_, _ = fmt.Fprintf(out, "Version: %s (api %s)\nSandboxes: %d (running %d, stopped %d)\n", status.Version, status.API, status.Total, status.Running, status.Stopped)
		}
		if status.Error != "" {
			_, _ = fmt.Fprintf(out, "Error:   %s\n", status.Error)
		}
		return nil
	}
}
