package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

const execUsage = `usage: rsbx exec [-i] [-t] [-w DIR] [-e KEY=VALUE] [--env-file FILE] [-u uid[:gid]] SANDBOX COMMAND [ARG...]

Run a command in an existing sandbox, starting it first if it is stopped.
Flags may appear before, between or after arguments; use -- to end flag parsing.

Flags:
  -i, --interactive        keep stdin open
  -t, --tty                allocate a terminal
  -w, --workdir DIR        guest working directory
  -e, --env KEY=VALUE      environment override (repeatable)
      --env-file FILE      read environment overrides from a file (repeatable)
  -u, --user USER          uid[:gid] or name[:group]
      --privileged         per-exec privilege escalation (unsupported by the local runtime)
      --detach-keys KEYS   detach key sequence (cloud interactive exec only)
  -h, --help               show this help
`

const privilegedUnsupportedMessage = "error: --privileged is not supported by the local daemon/runtime; per-exec privilege escalation is unavailable and was not applied\n  try: rsbx exec --help"

type execOptions struct {
	workdir    string
	env        []string
	user       string
	privileged bool
}

type stringListFlag []string

func (f *stringListFlag) String() string { return strings.Join(*f, ",") }

func (f *stringListFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

// exec runs a command in an existing sandbox.
//
//nolint:funlen // one command parses the full exec flag surface and launches the session.
func (r *Runner) exec(ctx context.Context, args []string) int {
	fs := r.newFlagSet("exec")
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	var opts execOptions
	var envFlags, envFiles stringListFlag
	var interactive, tty, detached bool
	registerExecFlags(fs, &opts, &envFlags, &envFiles, &interactive, &tty, &detached)
	err := fs.Parse(reorderExecArgs(args))
	if detached {
		_, _ = fmt.Fprintln(r.Err, "error: --detach is not supported for exec; omit -d to run the command in the foreground\n  try: rsbx exec --help")
		return 125
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return r.showCommandHelp(execHelp())
		}
		return r.flagParseFailure("exec", err)
	}
	if fs.NArg() < 2 {
		_, _ = fmt.Fprint(r.Err, execUsage)
		return 125
	}
	if opts.privileged {
		_, _ = fmt.Fprintln(r.Err, privilegedUnsupportedMessage)
		return 125
	}
	env, err := buildExecEnv(envFlags, envFiles)
	if err != nil {
		r.error(err)
		return 125
	}
	if err := validateExecUser(opts.user); err != nil {
		r.error(err)
		return 125
	}
	opts.env = env
	r.debug(ctx, debugEventExecPrepare,
		debugBoolean(interactiveName, interactive),
		debugBoolean(ttyName, tty),
		debugBoolean("detached", detached),
		debugBoolean(privilegedName, opts.privileged),
		debugBoolean("has_workdir", opts.workdir != ""),
		debugBoolean("user_set", opts.user != ""),
		debugNumber("env_count", len(opts.env)))
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 125
	}
	defer func() { _ = client.Close() }()
	id, err := findExecSandbox(ctx, client, fs.Arg(0))
	if err != nil {
		r.error(err)
		return 125
	}
	r.debug(ctx, debugEventExecSandbox, debugResultField("ok"))
	if interactive || tty {
		code := r.execSession(ctx, client, id, fs.Args()[1:], opts, interactive, tty)
		r.debug(ctx, debugEventExecFinish, debugNumber("exit_code", code), debugResultField("ok"))
		return code
	}
	started := time.Now()
	code, err := sdk.ExecService(client).Exec(ctx, sdk.ExecRequest{
		SandboxID: id, Argv: fs.Args()[1:], Workdir: opts.workdir, Env: opts.env, User: opts.user, Stdout: r.Out, Stderr: r.Err,
	})
	if err != nil {
		r.debug(ctx, debugEventExecFinish,
			debugResultField("error"),
			debugDuration("duration_ms", time.Since(started)))
		r.error(err)
		return 125
	}
	r.debug(ctx, debugEventExecFinish,
		debugNumber("exit_code", code),
		debugResultField("ok"),
		debugDuration("duration_ms", time.Since(started)))
	return code
}

func registerExecFlags(fs *flag.FlagSet, opts *execOptions, envFlags, envFiles *stringListFlag, interactive, tty, detached *bool) {
	fs.BoolVar(detached, "d", false, "detached exec is unsupported")
	fs.BoolVar(detached, "detach", false, "detached exec is unsupported")
	fs.BoolVar(interactive, "i", false, "keep stdin open")
	fs.BoolVar(interactive, "interactive", false, "keep stdin open")
	fs.BoolVar(tty, "t", false, "allocate a terminal")
	fs.BoolVar(tty, "tty", false, "allocate a terminal")
	fs.StringVar(&opts.workdir, "workdir", "", "guest working directory")
	fs.StringVar(&opts.workdir, "w", "", "guest working directory")
	fs.Var(envFlags, "e", "KEY=VALUE environment override")
	fs.Var(envFlags, "env", "KEY=VALUE environment override")
	fs.Var(envFiles, "env-file", "read KEY=VALUE overrides from a file")
	fs.StringVar(&opts.user, "u", "", "uid[:gid] or name[:group]")
	fs.StringVar(&opts.user, "user", "", "uid[:gid] or name[:group]")
	fs.BoolVar(&opts.privileged, "privileged", false, "request per-exec privilege escalation")
	// The reference CLI advertises --detach-keys locally but applies it only to
	// interactive cloud exec. Local exec has no detach sequence, so accepting
	// the value keeps the flag surface compatible without pretending to act on it.
	fs.String("detach-keys", "", "detach key sequence for interactive cloud exec")
}

func expandExecFlags(args []string) []string {
	expanded := make([]string, 0, len(args)+1)
	for i, arg := range args {
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			return append(expanded, args[i:]...)
		}
		if execFlagTakesValue(arg) && !strings.Contains(arg, "=") && i+1 < len(args) {
			return append(expanded, append([]string{arg, args[i+1]}, expandExecFlags(args[i+2:])...)...)
		}
		if arg == combinedTTYFlag || arg == combinedTTYRev {
			expanded = append(expanded, "-i", "-t")
		} else {
			expanded = append(expanded, arg)
		}
	}
	return expanded
}

// reorderExecArgs accepts exec flags before, between or after positional
// arguments while keeping the command and its arguments in order. Known exec
// flags are moved ahead of the sandbox; unknown dash-prefixed tokens after the
// sandbox stay with the command so command flags are not consumed. A literal
// -- ends flag parsing, exactly like the other commands.
func reorderExecArgs(args []string) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	endOfFlags := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			endOfFlags = true
			break
		}
		if arg == combinedTTYFlag || arg == combinedTTYRev {
			flags = append(flags, "-i", "-t")
			continue
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		name, _, hasValue := strings.Cut(arg, "=")
		switch {
		case isExecBooleanFlag(name):
			flags = append(flags, arg)
		case execFlagTakesValue(name):
			flags = append(flags, arg)
			if !hasValue && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		case len(positionals) == 0:
			// An unknown flag before the sandbox is still an error.
			flags = append(flags, arg)
		default:
			// After the sandbox, leave unknown dash-prefixed tokens to the
			// command; users can use -- to be explicit.
			positionals = append(positionals, arg)
		}
	}
	reordered := make([]string, 0, len(flags)+len(positionals)+1)
	reordered = append(reordered, flags...)
	if endOfFlags {
		reordered = append(reordered, "--")
	}
	return append(reordered, positionals...)
}

func isExecBooleanFlag(name string) bool {
	switch name {
	case "-i", interactiveFlag, "-t", ttyFlag, "-d", detachFlag, privilegedFlag, helpShort, helpFlag, debugShortFlag, debugFlag:
		return true
	default:
		return false
	}
}

func execFlagTakesValue(arg string) bool {
	switch arg {
	case "-w", workdirFlag, "-workdir", "-e", envFlag, "--env-file", "-u", userFlag, detachKeysFlag, socketFlag, socketShortFlag:
		return true
	default:
		return false
	}
}

func findExecSandbox(ctx context.Context, client sdk.Client, name string) (string, error) {
	seen := make(map[string]struct{})
	token := ""
	for pages := 0; pages < 10000; pages++ {
		page, err := client.Sandboxes().List(ctx, sdk.ListOptions{PageSize: 100, PageToken: token})
		if err != nil {
			return "", err
		}
		for i := range page.Items {
			item := &page.Items[i]
			if item.ID == name || item.Name == name {
				return item.ID, nil
			}
		}
		if page.NextPageToken == "" {
			return "", sandboxNotFoundError{name: name}
		}
		if _, ok := seen[page.NextPageToken]; ok {
			return "", fmt.Errorf("invalid sandbox pagination")
		}
		seen[page.NextPageToken] = struct{}{}
		token = page.NextPageToken
	}
	return "", fmt.Errorf("too many sandbox pages")
}

func (r *Runner) execSession(ctx context.Context, client sdk.Client, id string, argv []string, opts execOptions, interactive, tty bool) int {
	return r.execSessionMode(ctx, client, id, argv, opts, interactive, tty, true)
}

func (r *Runner) execSessionMode(ctx context.Context, client sdk.Client, id string, argv []string, opts execOptions, interactive, tty, closeOnEOF bool) int {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	size, file, restore, err := prepareExecTerminal(r.In, interactive, tty)
	if err != nil {
		r.error(err)
		return 125
	}
	defer restore()
	session, err := sdk.Sessions(client).OpenSession(ctx, sdk.SessionRequest{
		SandboxID: id, Argv: argv, Workdir: opts.workdir, Env: opts.env, User: opts.user, TTY: tty, Size: size,
	})
	if err != nil {
		r.error(err)
		return 125
	}
	if file != nil {
		stop := watchTerminalResize(ctx, file, session)
		defer stop()
	}
	if interactive {
		go forwardSessionInput(r.In, session, cancel, closeOnEOF)
	} else if !tty {
		if err := session.CloseInput(); err != nil {
			r.error(err)
			return 125
		}
	}
	return r.receiveSession(session)
}

func prepareExecTerminal(input io.Reader, interactive, tty bool) (sdk.TerminalSize, *os.File, func(), error) {
	noop := func() {}
	file, ok := input.(*os.File)
	if !tty || !ok || !term.IsTerminal(int(file.Fd())) {
		return sdk.TerminalSize{}, nil, noop, nil
	}
	cols, rows, err := term.GetSize(int(file.Fd()))
	if err != nil {
		return sdk.TerminalSize{}, nil, noop, err
	}
	size, err := terminalSize(rows, cols)
	if err != nil {
		return sdk.TerminalSize{}, nil, noop, err
	}
	if !interactive {
		return size, file, noop, nil
	}
	previous, err := term.MakeRaw(int(file.Fd()))
	if err != nil {
		return sdk.TerminalSize{}, nil, noop, err
	}
	return size, file, func() { _ = term.Restore(int(file.Fd()), previous) }, nil
}

func terminalSize(rows, cols int) (sdk.TerminalSize, error) {
	if rows < 0 || rows > 65535 || cols < 0 || cols > 65535 {
		return sdk.TerminalSize{}, errors.New("invalid terminal size")
	}
	return sdk.TerminalSize{Rows: uint32(rows), Cols: uint32(cols)}, nil
}

func forwardSessionInput(input io.Reader, session sdk.ExecSession, cancel context.CancelFunc, closeOnEOF bool) {
	buffer := make([]byte, 32*1024)
	for {
		n, err := input.Read(buffer)
		if n > 0 {
			if sendErr := session.SendInput(buffer[:n]); sendErr != nil {
				cancel()
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				cancel()
				return
			}
			// Some non-terminal inputs (for example /dev/null) report EOF
			// forever; closing the session input would kill an attached
			// agent immediately, so callers decide whether EOF is final.
			if closeOnEOF {
				_ = session.CloseInput()
			}
			return
		}
		if n == 0 {
			cancel()
			return
		}
	}
}

func (r *Runner) receiveSession(session sdk.ExecSession) int {
	for {
		frame, err := session.Receive()
		if err != nil {
			r.error(err)
			return 125
		}
		for _, output := range []struct {
			writer io.Writer
			data   []byte
		}{{r.Out, frame.Stdout}, {r.Err, frame.Stderr}} {
			if len(output.data) > 0 {
				n, err := output.writer.Write(output.data)
				if err == nil && n != len(output.data) {
					err = io.ErrShortWrite
				}
				if err != nil {
					r.error(err)
					return 125
				}
			}
		}
		if frame.ExitCode != nil {
			return *frame.ExitCode
		}
	}
}
