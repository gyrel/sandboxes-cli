package command

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/rheic/slogx"
)

// Debug events are a closed set. Logging an event that is not listed here is
// dropped, so a future call site cannot accidentally log free-form text.
const (
	debugEventCommandStart  = "command.start"
	debugEventCommandFinish = "command.finish"
	debugEventClientConnect = "client.connect"
	debugEventClientReady   = "client.ready"
	debugEventVersionCheck  = "version.check"
	debugEventVersionReady  = "version.ready"
	debugEventExecPrepare   = "exec.prepare"
	debugEventExecSandbox   = "exec.sandbox"
	debugEventExecFinish    = "exec.finish"
	debugEventRunPrepare    = "run.prepare"
	debugEventRunSandbox    = "run.sandbox"
	debugEventRunAttach     = "run.attach"
	debugEventListFetch     = "list.fetch"
	debugEventListRender    = "list.render"
	debugEventLifecycle     = "lifecycle.start"
	debugEventCreatePrepare = "create.prepare"
)

var debugAllowedEvents = map[string]struct{}{
	debugEventCommandStart:  {},
	debugEventCommandFinish: {},
	debugEventClientConnect: {},
	debugEventClientReady:   {},
	debugEventVersionCheck:  {},
	debugEventVersionReady:  {},
	debugEventExecPrepare:   {},
	debugEventExecSandbox:   {},
	debugEventExecFinish:    {},
	debugEventRunPrepare:    {},
	debugEventRunSandbox:    {},
	debugEventRunAttach:     {},
	debugEventListFetch:     {},
	debugEventListRender:    {},
	debugEventLifecycle:     {},
	debugEventCreatePrepare: {},
}

// Attribute keys are allowlisted as well. Values are numbers, booleans or
// strings that passed a closed value set before they reach the logger.
var debugAllowedAttrs = map[string]struct{}{
	commandName:       {},
	"operation":       {},
	"result":          {},
	"state":           {},
	"format":          {},
	"transport":       {},
	"exit_code":       {},
	"duration_ms":     {},
	"count":           {},
	"target_count":    {},
	"workspace_count": {},
	"port_count":      {},
	"rule_count":      {},
	"env_count":       {},
	"has_name":        {},
	"has_agent":       {},
	"has_image":       {},
	"has_workdir":     {},
	"user_set":        {},
	interactiveName:   {},
	"quiet":           {},
	ttyName:           {},
	"detached":        {},
	privilegedName:    {},
	cloneName:         {},
	"new":             {},
	"created":         {},
	"api_version":     {},
}

var (
	debugCommands = stringSet(
		"run", "attach", "exec", "cp", "ls", "list", "stop", "rm", "remove",
		"delete", "create", "prune", "diagnose", "ports", "policy", "settings",
		"kit", "daemon", "template", "agents", "env", "mcp", "reset", "skills",
		"tui", "setup", "completion", "version", "help", "login", "logout",
		"secret", "secrets", "move", "ttl", "volume", "unknown",
	)
	debugOperations = stringSet(
		"run", "create", "exec", "attach", "cp", "list", "stop", "remove",
		"reset", "prune", "version", "login", "logout", "secret", "completion",
	)
	debugResults    = stringSet("ok", "error", "canceled", "unsupported")
	debugStates     = stringSet(stateUnavailable, "running")
	debugFormats    = stringSet(listFormatTable, listFormatJSON, listFormatYAML)
	debugTransports = stringSet("unix", "tcp", "other")
	debugUnknown    = "unknown"
)

func stringSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

type debugField struct {
	key   string
	value slog.Value
}

func debugText(key, value string) debugField {
	return debugField{key: key, value: slog.StringValue(value)}
}

func debugNumber(key string, value int) debugField {
	return debugField{key: key, value: slog.IntValue(value)}
}

func debugDuration(key string, value time.Duration) debugField {
	return debugField{key: key, value: slog.Int64Value(value.Milliseconds())}
}

func debugBoolean(key string, value bool) debugField {
	return debugField{key: key, value: slog.BoolValue(value)}
}

func debugSafeText(key, value string, allowed map[string]struct{}) debugField {
	if _, ok := allowed[value]; !ok {
		value = debugUnknown
	}
	return debugText(key, value)
}

// beginDebug resets invocation-scoped state and installs the per-Runner
// logger. It never touches slog's package-level default logger.
func (r *Runner) beginDebug() {
	r.Debug = false
	r.debugInvalidRaw = ""
	r.debugInvalidErr = nil
	if r.Logger != nil {
		r.debugLogger = r.Logger
		return
	}
	out := r.Err
	if out == nil {
		out = io.Discard
	}
	r.debugLogger = slogx.New(
		slogx.WithOutput(out),
		slogx.WithLevel(slog.LevelDebug),
		slogx.WithFormat(slogx.FormatText),
	)
}

// debug writes one allowlisted structured event. It is a no-op unless --debug
// enabled this invocation, and it silently drops unknown events or fields.
func (r *Runner) debug(ctx context.Context, event string, fields ...debugField) {
	if !r.Debug || r.debugLogger == nil {
		return
	}
	if _, ok := debugAllowedEvents[event]; !ok {
		return
	}
	attrs := make([]slog.Attr, 0, len(fields))
	for _, field := range fields {
		if _, ok := debugAllowedAttrs[field.key]; ok {
			attrs = append(attrs, slog.Attr{Key: field.key, Value: field.value})
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.debugLogger.LogAttrs(ctx, slog.LevelDebug, event, attrs...)
}

// bindGlobalFlags registers the global flags on a command FlagSet. The values
// update only this Runner, so repeated Runner use does not leak state.
func (r *Runner) bindGlobalFlags(fs *flag.FlagSet) {
	debug := &debugFlagValue{runner: r}
	fs.Var(debug, "D", "enable debug logging")
	fs.Var(debug, "debug", "enable debug logging")
	fs.Var(&socketFlagValue{runner: r}, "socket", "local daemon endpoint")
}

func (r *Runner) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	r.bindGlobalFlags(fs)
	return fs
}

// extractGlobalFlags handles commands whose whole argument grammar is known
// to have no value-taking flags of its own. It stops at -- so positional
// arguments keep any flag-like text after the terminator.
func (r *Runner) extractGlobalFlags(args []string, valueFlags map[string]bool) ([]string, error) {
	return r.extractGlobalFlagsUntil(args, valueFlags, false)
}

// extractGlobalFlagsUntil implements the shared scan. When stopAtSubcommand is
// set the scan ends at the first positional token and appends that token plus
// every later argument unchanged.
func (r *Runner) extractGlobalFlagsUntil(args []string, valueFlags map[string]bool, stopAtSubcommand bool) ([]string, error) {
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || stopAtSubcommand && isFamilySubcommand(arg) {
			filtered = append(filtered, args[i:]...)
			break
		}
		name, _, hasValue := strings.Cut(arg, "=")
		if !hasValue && valueFlags[name] {
			filtered = append(filtered, arg)
			if i+1 < len(args) {
				i++
				filtered = append(filtered, args[i])
			}
			continue
		}
		next, keep, err := r.consumeGlobalFlag(args, i)
		if err != nil {
			return nil, err
		}
		if next > i {
			i = next
			continue
		}
		if keep {
			filtered = append(filtered, arg)
		}
	}
	return filtered, nil
}

func isFamilySubcommand(arg string) bool {
	return !strings.HasPrefix(arg, "-") || arg == "-"
}

// consumeGlobalFlag handles one global flag token. It returns the index of a
// consumed value (otherwise index), whether the token should be kept for the
// command parser, and any parse error.
func (r *Runner) consumeGlobalFlag(args []string, index int) (next int, keep bool, err error) {
	arg := args[index]
	switch {
	case arg == debugFlag || arg == debugShortFlag:
		err = (&debugFlagValue{runner: r}).Set("true")
	case strings.HasPrefix(arg, debugFlag+"="):
		err = (&debugFlagValue{runner: r}).Set(strings.TrimPrefix(arg, debugFlag+"="))
	case strings.HasPrefix(arg, debugShortFlag+"="):
		err = (&debugFlagValue{runner: r}).Set(strings.TrimPrefix(arg, debugShortFlag+"="))
	case arg == socketFlag || arg == socketShortFlag:
		if index+1 >= len(args) {
			return index, false, errors.New("flag needs an argument: --socket")
		}
		r.Socket = args[index+1]
		return index + 1, false, nil
	case strings.HasPrefix(arg, socketFlag+"="):
		r.Socket = strings.TrimPrefix(arg, socketFlag+"=")
	case strings.HasPrefix(arg, socketShortFlag+"="):
		r.Socket = strings.TrimPrefix(arg, socketShortFlag+"=")
	default:
		return index, true, nil
	}
	return index, false, err
}

// prepareFamilyArgs accepts global flags only in the prefix before a command
// family's subcommand. Once the subcommand is seen, every later argument is
// left untouched for that command's parser, so a child flag value such as
// "--debug" is never reinterpreted as a global flag. Child parsers register
// the global flags through newFlagSet where they use the standard flag package;
// commands with bespoke parsers do not accept post-command global flags.
func (r *Runner) prepareFamilyArgs(path string, args []string) ([]string, int, bool) {
	filtered, err := r.extractGlobalFlagsUntil(args, nil, true)
	if err != nil {
		if message, ok := r.takeDebugFlagError(); ok {
			return nil, r.commandError(path, message), true
		}
		r.error(err)
		return nil, 2, true
	}
	return filtered, 0, false
}

func (r *Runner) takeDebugFlagError() (string, bool) {
	if r.debugInvalidErr == nil {
		return "", false
	}
	message := invalidBoolFlagMessage("-D, --debug", r.debugInvalidRaw, r.debugInvalidErr)
	r.debugInvalidRaw = ""
	r.debugInvalidErr = nil
	return message, true
}

// debugFlagValue is a boolean flag that updates the owning Runner as soon as
// its grammar consumes the token. That keeps a value such as --debug=false
// effective for the rest of the invocation and preserves last-value-wins.
type debugFlagValue struct {
	runner *Runner
	value  bool
}

func (v *debugFlagValue) String() string { return strconv.FormatBool(v.value) }

func (v *debugFlagValue) Set(raw string) error {
	value, err := strconv.ParseBool(raw)
	if err != nil {
		if v.runner != nil {
			v.runner.debugInvalidRaw = raw
			v.runner.debugInvalidErr = err
		}
		return err
	}
	v.value = value
	if v.runner != nil {
		v.runner.Debug = value
	}
	return nil
}

func (v *debugFlagValue) IsBoolFlag() bool { return true }

type socketFlagValue struct{ runner *Runner }

func (v *socketFlagValue) String() string {
	if v.runner == nil {
		return ""
	}
	return v.runner.Socket
}

func (v *socketFlagValue) Set(raw string) error {
	if v.runner != nil {
		v.runner.Socket = raw
	}
	return nil
}

func debugCommandField(name string) debugField {
	return debugSafeText(commandName, name, debugCommands)
}

func debugOperationField(name string) debugField {
	return debugSafeText("operation", name, debugOperations)
}

func debugResultField(name string) debugField {
	return debugSafeText("result", name, debugResults)
}

func debugStateField(name string) debugField {
	return debugSafeText("state", name, debugStates)
}

func debugFormatField(name string) debugField {
	return debugSafeText("format", name, debugFormats)
}

func debugTransportField(address string) debugField {
	return debugSafeText("transport", classifyDebugTransport(address), debugTransports)
}

func classifyDebugTransport(address string) string {
	switch {
	case address == "":
		return "other"
	case address != "" && address[0] == '/':
		return "unix"
	case len(address) > len("unix://") && address[:len("unix://")] == "unix://":
		return "unix"
	case containsColon(address):
		return "tcp"
	default:
		return "other"
	}
}

func containsColon(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == ':' {
			return true
		}
	}
	return false
}
