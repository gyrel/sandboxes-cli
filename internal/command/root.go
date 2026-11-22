// Package command implements the CLI command tree.
package command

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gdamore/tcell/v3"
	"golang.org/x/term"

	sdk "github.com/rheic/sandboxes-go-sdk"
	"github.com/rheic/slogx"

	"github.com/rheic/sandboxes-cli/internal/daemonctl"
	"github.com/rheic/sandboxes-cli/internal/kit"
)

const (
	answerShortYes = "y"
	answerYes      = "yes"

	actionAllow       = "allow"
	actionDeny        = "deny"
	cloneName         = "clone"
	commandName       = "command"
	commandCreate     = "create"
	commandExec       = "exec"
	commandRun        = "run"
	envArgFlag        = "--env-arg"
	envArgsFileFlag   = "--env-args-file"
	commandGet        = "get"
	commandInspect    = "inspect"
	commandReset      = "reset"
	stateUnavailable  = "unavailable"
	commandAgents     = "agents"
	commandImport     = "import"
	versionCommand    = "version"
	commandList       = "list"
	commandDelete     = "delete"
	commandRemove     = "remove"
	commandUnset      = "unset"
	commandSet        = "set"
	commandSetCustom  = "set-custom"
	debugFlag         = "--debug"
	debugShortFlag    = "-D"
	interactiveName   = "interactive"
	privilegedName    = "privileged"
	schemeHTTPS       = "https"
	reasonDefaultDeny = "default deny"
	orgScope          = "org"
	originLocal       = "local"
	socketFlag        = "--socket"
	socketShortFlag   = "-socket"
	ttyName           = "tty"
)

var errMissingSandboxTargets = errors.New("requires at least 1 argument")

// Runner executes commands against a local daemon.
type Runner struct {
	Out    io.Writer
	Err    io.Writer
	In     io.Reader
	Socket string
	// Debug records the -D/--debug flag for the current Run invocation. It
	// enables structured debug events on Err and selects the version table.
	// Run resets it so a reused Runner cannot inherit debug mode.
	Debug bool
	// Logger is an optional per-Runner debug logger. When nil, Run creates a
	// slogx logger on Err. The CLI never installs a package-level logger.
	Logger    *slogx.Logger
	NewClient func(address string) (sdk.Client, error)
	// NewDaemonSupervisor controls the local daemon process. Tests inject a
	// fake to verify start/stop/restart sequencing without signaling a real
	// process.
	NewDaemonSupervisor func(address string) (daemonSupervisor, error)
	// NewOrgPolicyClient reads the read-only organization policy view. It is a
	// separate RPC client because the SDK release predates the additive API
	// contract; tests inject a fake here.
	NewOrgPolicyClient func(address string) (orgPolicyClient, error)
	SecretScreen       func() tcell.Screen
	gitConfig          gitConfigCommand
	cloneDial          cloneDialFunc

	// removalPrompt overrides interactive removal confirmation in tests. A nil
	// prompt requires a terminal, like the production path.
	removalPrompt func(count int) (bool, error)

	// confirmTerminal overrides the terminal check for destructive
	// confirmations in tests. A nil override requires a real terminal, like the
	// production path.
	confirmTerminal func() bool

	// setupCollector overrides read-only host detection in tests. A nil
	// collector uses the real host.
	setupCollector func(context.Context) setupReport

	debugLogger     *slogx.Logger
	debugInvalidRaw string
	debugInvalidErr error
}

// NewRunner creates a CLI runner.
func NewRunner(out, errOut io.Writer) *Runner {
	return &Runner{
		Out:       out,
		Err:       errOut,
		In:        os.Stdin,
		Socket:    defaultSocket(),
		NewClient: func(address string) (sdk.Client, error) { return sdk.New(sdk.Config{Address: address}) },
		NewDaemonSupervisor: func(address string) (daemonSupervisor, error) {
			return daemonctl.New(address)
		},
		NewOrgPolicyClient: newOrgPolicyClient,
	}
}

// Run executes the CLI.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return NewRunner(stdout, stderr).Run(ctx, args)
}

// Run executes the command tree and returns a process exit code.
func (r *Runner) Run(ctx context.Context, args []string) (code int) {
	// Debug is invocation-scoped output selection, not sticky Runner state.
	// Reset it so a reused Runner cannot carry -D into an unrelated command.
	r.beginDebug()
	command := ""
	started := time.Now()
	defer func() {
		if command != "" {
			r.debug(ctx, debugEventCommandFinish,
				debugCommandField(command),
				debugNumber("exit_code", code),
				debugDuration("duration_ms", time.Since(started)))
		}
	}()

	rest, code, done := r.parseGlobalArgs(args)
	if done {
		return code
	}
	if len(rest) == 0 {
		r.usage()
		return 2
	}
	command = rest[0]
	r.debug(ctx, debugEventCommandStart, debugCommandField(command))
	if code, handled := r.runAuxiliaryCommand(ctx, rest[0], rest[1:]); handled {
		return code
	}

	switch rest[0] {
	case helpCommand, helpShort, helpFlag:
		return r.help(ctx, rest[1:])
	case versionCommand:
		return r.version(ctx, rest[1:])
	case commandCreate:
		return r.create(ctx, rest[1:])
	case "ls", commandList:
		return r.list(ctx, rest[1:])
	case stopCommand:
		return r.stop(ctx, rest[1:])
	case "rm", commandRemove, commandDelete:
		return r.remove(ctx, rest[1:])
	default:
		return r.commandError("", fmt.Sprintf("rsbx: unknown command: rsbx %s", rest[0]))
	}
}

// parseGlobalArgs extracts the global flags before dispatch. It reports
// done=true when the caller should return code. Command parsers register the
// same flags so they are also accepted after the subcommand.
func (r *Runner) parseGlobalArgs(args []string) (rest []string, code int, done bool) {
	global := flag.NewFlagSet("rsbx", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	r.bindGlobalFlags(global)
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			r.usage()
			return nil, 0, true
		}
		return nil, r.flagParseFailure("", err), true
	}
	return global.Args(), 0, false
}

// invalidBoolFlagMessage matches the reference CLI's pflag wording.
func invalidBoolFlagMessage(display, raw string, err error) string {
	return fmt.Sprintf("invalid argument %q for %q flag: %v", raw, display, err)
}

// help prints top-level usage or, with a command path, that command's help.
// Subcommands implement --help, so dispatch the full path through Run to keep
// one handler, including nested forms such as "help policy allow network".
func (r *Runner) help(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == helpCommand || args[0] == helpShort || args[0] == helpFlag {
		r.usage()
		return 0
	}
	dispatched := append(append([]string(nil), args...), helpFlag)
	return r.Run(ctx, dispatched)
}

// flagParseFailure normalizes stdlib flag parse errors to the shared CLI
// error contract: unknown flags exit 1 with a Cobra-style hint, other parse
// failures exit 2. Callers handle flag.ErrHelp before invoking it.
func (r *Runner) flagParseFailure(cmdPath string, err error) int {
	if message, ok := r.takeDebugFlagError(); ok {
		return r.commandError(cmdPath, message)
	}
	message := err.Error()
	if name, ok := strings.CutPrefix(message, "flag provided but not defined: -"); ok {
		return r.commandError(cmdPath, "unknown flag: --"+name)
	}
	_, _ = fmt.Fprintf(r.Err, "error: %s\n  try: rsbx %s--help\n", message, commandHintPath(cmdPath))
	return 2
}

// commandError prints a reference-compatible command error with its help hint.
func (r *Runner) commandError(cmdPath, message string) int {
	_, _ = fmt.Fprintf(r.Err, "error: %s\n  try: rsbx %s--help\n", message, commandHintPath(cmdPath))
	return 1
}

// accountError reports account failures with actionable wording. A local
// daemon that is not running is the most common cause and is reported as such
// instead of exposing the raw gRPC dial error.
func (r *Runner) accountError(err error) int {
	r.error(daemonStartHint(err))
	return 1
}

func daemonStartHint(err error) error {
	var typed *sdk.Error
	if errors.As(err, &typed) && typed.Code == stateUnavailable &&
		(strings.Contains(typed.Message, "dial") || strings.Contains(typed.Message, "connect")) {
		return errors.New("local daemon is not running; start it with: rsbx daemon start --detach")
	}
	return err
}

func commandHintPath(cmdPath string) string {
	if cmdPath == "" {
		return ""
	}
	return cmdPath + " "
}

//nolint:cyclop,gocyclo // one dispatch switch is the command router.
func (r *Runner) runAuxiliaryCommand(ctx context.Context, name string, args []string) (int, bool) {
	switch name {
	case commandRun:
		return r.run(ctx, args), true
	case "attach":
		return r.attach(ctx, args), true
	case commandExec:
		return r.exec(ctx, args), true
	case "cp":
		return r.cp(ctx, args), true
	case "login":
		return r.accountLogin(ctx, args), true
	case "logout":
		return r.accountLogout(ctx, args), true
	case secretCommand, secretsCommand:
		return r.secret(ctx, args), true
	case "prune":
		return r.prune(ctx, args), true
	case "diagnose":
		return r.diagnose(ctx, args), true
	case "ports":
		return r.ports(ctx, args), true
	case policyCommand:
		return r.policy(ctx, args), true
	case settingsCommand:
		return r.settings(args), true
	case kitCommand:
		return r.kit(args), true
	case daemonCommand:
		return r.daemon(args), true
	case templateCommand:
		return r.template(ctx, args), true
	case commandAgents:
		return r.agents(args), true
	case envCommand:
		return r.environment(ctx, args), true
	case mcpCommand:
		return r.mcp(ctx, args), true
	case commandReset:
		return r.reset(ctx, args), true
	case skillsCommand:
		return r.skills(ctx, args), true
	case "tui":
		return r.tui(ctx, args), true
	case setupCommand:
		return r.setup(ctx, args), true
	default:
		return r.fallbackCommand(name, args)
	}
}

// fallbackCommand handles families that are either unimplemented Docker
// commands or pure host-side generators.
func (r *Runner) fallbackCommand(name string, args []string) (int, bool) {
	switch name {
	case volumeCommand, moveCommand, ttlCommand:
		return r.unsupportedFamily(name), true
	case completionCommand:
		return r.completion(args), true
	default:
		return 0, false
	}
}

func (r *Runner) accountLogin(ctx context.Context, args []string) int {
	username, passwordStdin, code, ok := r.parseLoginFlags(args)
	if !ok {
		return code
	}
	var password []byte
	if passwordStdin {
		var err error
		password, err = readDockerPassword(r.In)
		if err != nil {
			r.error(err)
			return 2
		}
		defer clear(password)
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if passwordStdin {
		if err := sdk.DockerPATAccounts(client).LoginWithPAT(ctx, username, password); err != nil {
			return r.accountError(err)
		}
		_, _ = fmt.Fprintln(r.Out, "Signed in.")
		return 0
	}
	signedIn, err := r.dockerAccountSignedIn(ctx, client)
	if err != nil {
		return r.accountError(err)
	}
	if signedIn {
		_, _ = fmt.Fprintln(r.Out, "You are signed in")
		return 0
	}
	if err := sdk.InteractiveAccounts(client).LoginInteractive(ctx, dockerAccountProvider, func(ctx context.Context, info sdk.DeviceLoginInfo) error {
		return r.deviceLoginHandoff(info)
	}); err != nil {
		return r.accountError(err)
	}
	_, _ = fmt.Fprintln(r.Out, "Signed in.")
	return 0
}

// parseLoginFlags validates the reference login flag contract and reports the
// exit code when the invocation is invalid.
func (r *Runner) parseLoginFlags(args []string) (username string, passwordStdin bool, code int, ok bool) {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		r.loginUsage()
		return "", false, 0, false
	}
	fs := r.newFlagSet("login")
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	usernameFlag := fs.String("username", "", "Docker Hub username for PAT login")
	passwordStdinFlag := fs.Bool("password-stdin", false, "read Docker Hub password or PAT from stdin")
	if err := fs.Parse(args); err != nil {
		return "", false, r.flagParseFailure("login", err), false
	}
	if fs.NArg() != 0 {
		return "", false, r.commandError("login", fmt.Sprintf("unknown command %q for %q", fs.Arg(0), "rsbx login")), false
	}
	switch {
	case *usernameFlag != "" && !*passwordStdinFlag:
		return "", false, r.commandError("login", "--username requires --password-stdin"), false
	case *usernameFlag == "" && *passwordStdinFlag:
		return "", false, r.commandError("login", "--password-stdin requires --username"), false
	}
	return *usernameFlag, *passwordStdinFlag, 0, true
}

const (
	dockerAccountProvider          = "docker"
	dockerSubscriptionAgreementURL = "https://www.docker.com/legal/docker-subscription-service-agreement/"
)

// dockerAccountSignedIn reports whether host credentials for the Docker account
// already exist, so login matches the reference behavior of stating that the
// user is signed in instead of starting a new device authorization.
func (r *Runner) dockerAccountSignedIn(ctx context.Context, client sdk.Client) (bool, error) {
	present, err := sdk.AccountStatus(client).Status(ctx, dockerAccountProvider)
	if err == nil {
		return present, nil
	}
	var typed *sdk.Error
	if errors.As(err, &typed) && typed.Code == "unsupported" {
		return false, nil
	}
	return false, err
}

// deviceLoginHandoff prints the device authorization details and opens the
// browser the same way the reference client does: the sign-in continues in the
// browser and the terminal only waits for the authorization result.
func (r *Runner) deviceLoginHandoff(info sdk.DeviceLoginInfo) error {
	var out strings.Builder
	out.WriteString("By logging in, you agree to our Subscription Service Agreement. For more details, see ")
	out.WriteString(dockerSubscriptionAgreementURL)
	out.WriteString("\n\n")
	fmt.Fprintf(&out, "Your one-time device confirmation code is: %s\n", info.UserCode)
	out.WriteString("Complete sign-in in your browser, then return to this terminal.\n")
	fmt.Fprintf(&out, "Open this URL to sign in: %s\n\n", info.VerificationURI)
	out.WriteString("Waiting for authentication...\n")
	if _, err := io.WriteString(r.Err, out.String()); err != nil {
		return errors.New("write Docker device authorization details failed")
	}
	r.openLoginBrowser(info.VerificationURI)
	return nil
}

// openLoginBrowser best-effort opens the verification URL on an interactive
// terminal. Failures are ignored because the URL is printed as a fallback.
func (r *Runner) openLoginBrowser(url string) {
	if url == "" || !r.stdinIsTerminal() {
		return
	}
	_ = openBrowser(url)
}

func (r *Runner) loginUsage() {
	_ = r.showCommandHelp(loginHelp())
}

func readDockerPassword(input io.Reader) ([]byte, error) {
	if input == nil {
		return nil, errors.New("password stdin is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 2049))
	if err != nil {
		clear(raw)
		return nil, errors.New("read Docker Hub password from stdin failed")
	}
	defer clear(raw)
	if len(raw) > 2048 {
		return nil, errors.New("password exceeds 2048 bytes for Docker Hub")
	}
	end := len(raw)
	if end > 0 && raw[end-1] == '\n' {
		end--
		if end > 0 && raw[end-1] == '\r' {
			end--
		}
	}
	password := raw[:end]
	if len(password) == 0 || bytes.ContainsAny(password, "\r\n\x00") {
		return nil, errors.New("stdin must contain one non-empty Docker Hub password line")
	}
	return append([]byte(nil), password...), nil
}

func (r *Runner) accountLogout(ctx context.Context, args []string) int {
	fs := r.newFlagSet("logout")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { _ = r.showCommandHelp(logoutHelp()) }
	force := fs.Bool("force", false, "skip confirmation")
	forceShort := fs.Bool("f", false, "skip confirmation")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("logout", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx logout [--force]")
		return 2
	}
	if !*force && !*forceShort {
		confirmed, err := r.confirmLogout()
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "Logout canceled")
			return 0
		}
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	stopped, err := r.stopRunningSandboxes(ctx, client)
	if err != nil {
		r.error(err)
		return 1
	}
	removed, err := sdk.Accounts(client).Logout(ctx, "docker")
	if err != nil {
		r.error(err)
		return 1
	}
	if removed {
		_, _ = fmt.Fprintln(r.Out, "Signed out.")
	} else {
		_, _ = fmt.Fprintln(r.Out, "Not signed in.")
	}
	if stopped > 0 {
		_, _ = fmt.Fprintf(r.Out, "Stopped %d running local sandbox(es)\n", stopped)
	}
	return 0
}

func (r *Runner) confirmLogout() (bool, error) {
	if !r.stdinIsTerminal() {
		return false, fmt.Errorf("logout confirmation requires a terminal; use --force to skip confirmation")
	}
	if _, err := fmt.Fprint(r.Err, "Stop running local sandboxes and sign out? [y/N] "); err != nil {
		return false, fmt.Errorf("write logout prompt: %w", err)
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read logout confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == answerShortYes || answer == answerYes, nil
}

func (r *Runner) stopRunningSandboxes(ctx context.Context, client sdk.Client) (int, error) {
	stopped, seenPages := 0, make(map[string]struct{})
	token := ""
	for pages := 0; pages < 10000; pages++ {
		page, err := client.Sandboxes().List(ctx, sdk.ListOptions{PageSize: 100, PageToken: token})
		if err != nil {
			return stopped, fmt.Errorf("list local sandboxes before logout: %w", err)
		}
		pageCount, err := r.stopSandboxesOnPage(ctx, client, page.Items)
		stopped += pageCount
		if err != nil {
			return stopped, err
		}
		if page.NextPageToken == "" {
			return stopped, nil
		}
		if _, ok := seenPages[page.NextPageToken]; ok {
			return stopped, fmt.Errorf("daemon returned a repeated sandbox page token")
		}
		seenPages[page.NextPageToken] = struct{}{}
		token = page.NextPageToken
	}
	return stopped, fmt.Errorf("daemon returned too many sandbox pages")
}

func (r *Runner) stopSandboxesOnPage(ctx context.Context, client sdk.Client, items []sdk.Sandbox) (int, error) {
	stopped := 0
	for i := range items {
		sandbox := &items[i]
		if sandbox.State != sdk.StateRunning {
			continue
		}
		if err := r.stopSandbox(ctx, client, sandbox); err != nil {
			return stopped, err
		}
		stopped++
	}
	return stopped, nil
}

func (r *Runner) stopSandbox(ctx context.Context, client sdk.Client, sandbox *sdk.Sandbox) error {
	op, err := client.Sandboxes().Stop(ctx, sandbox.ID, sdk.StopOptions{})
	if err != nil {
		return fmt.Errorf("stop sandbox %s before logout: %w", sandbox.Name, err)
	}
	if op == nil || op.ID == "" {
		return nil
	}
	completed, err := client.Operations().Wait(ctx, op.ID)
	if err != nil {
		return fmt.Errorf("wait for sandbox %s to stop: %w", sandbox.Name, err)
	}
	if completed != nil && completed.State == sdk.StateFailed {
		return fmt.Errorf("sandbox %s failed to stop", sandbox.Name)
	}
	return nil
}

func (r *Runner) secret(ctx context.Context, args []string) int {
	args, code, done := r.prepareFamilyArgs(secretCommand, args)
	if done {
		return code
	}
	if len(args) == 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx secret <import|set|ls|list|rm|remove|delete|unset> [flags]")
		return 2
	}
	switch args[0] {
	case helpCommand, helpShort, helpFlag:
		return r.secretHelp()
	case commandSet:
		return r.secretSetCommand(ctx, args[1:])
	case "rm", commandRemove, commandDelete, commandUnset:
		return r.secretRemoveCommand(ctx, args[1:])
	case "ls", commandList:
		if hasFlag(args[1:], "--help") || hasFlag(args[1:], "-h") {
			return r.secretListHelp()
		}
		return r.serviceSecretList(ctx, args[1:])
	case commandImport, commandSetCustom:
		return r.secretExtendedCommand(ctx, args)
	default:
		_, _ = fmt.Fprintln(r.Err, "unknown secret command")
		return 2
	}
}

func (r *Runner) secretHelp() int {
	return r.showCommandHelp(secretHelp())
}

func (r *Runner) secretSetCommand(ctx context.Context, args []string) int {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		return r.secretSetHelp()
	}
	if hasFlag(args, registryFlag) {
		return r.registrySet(ctx, args)
	}
	return r.serviceSecretSet(ctx, args)
}

func (r *Runner) secretRemoveCommand(ctx context.Context, args []string) int {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		return r.secretRemoveHelp()
	}
	if hasFlag(args, allFlag) && hasFlag(args, globalFlag) {
		_, _ = fmt.Fprintln(r.Err, "error: if any flags in the group [all global] are set none of the others can be; [all global] were all set\n  try: rsbx secret rm --help")
		return 1
	}
	if hasFlag(args, allFlag) {
		return r.serviceSecretRemoveAll(ctx, args)
	}
	if hasFlag(args, allSandboxesFlag) && !hasFlag(args, registryFlag) {
		_, _ = fmt.Fprintln(r.Err, "error: --all-sandboxes requires --registry\n  try: rsbx secret rm --help")
		return 1
	}
	if hasFlag(args, registryFlag) || hasFlag(args, allSandboxesFlag) {
		return r.registryRemove(ctx, args)
	}
	return r.serviceSecretRemove(ctx, args)
}

func (r *Runner) secretExtendedCommand(ctx context.Context, args []string) int {
	if args[0] == commandSetCustom {
		if hasFlag(args[1:], "--help") || hasFlag(args[1:], "-h") {
			return r.secretCustomHelp()
		}
		_, _ = fmt.Fprintln(r.Err, "rsbx secret set-custom: unsupported: custom secret storage and proxy substitution are not implemented; no secret was stored")
		return 1
	}
	if hasFlag(args[1:], "--help") || hasFlag(args[1:], "-h") {
		return r.secretImportHelp()
	}
	return r.serviceSecretImport(ctx, args[1:])
}

func (r *Runner) secretCustomHelp() int {
	return r.showCommandHelp(secretCustomHelp())
}

func (r *Runner) secretSetHelp() int {
	return r.showCommandHelp(secretSetHelp())
}

func (r *Runner) secretRemoveHelp() int {
	return r.showCommandHelp(secretRemoveHelp())
}

func (r *Runner) secretListHelp() int {
	return r.showCommandHelp(secretListHelp())
}

func (r *Runner) serviceSecretRemoveAll(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{allFlag: false, forceFlag: false, "-f": false})
	fs := r.newFlagSet("secret rm")
	fs.SetOutput(r.Err)
	all := fs.Bool("all", false, "remove inventoried host credentials")
	force := fs.Bool("force", false, "delete without confirmation prompt")
	fs.BoolVar(force, "f", false, "delete without confirmation prompt")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("secret rm", err)
	}
	if !*all || fs.NArg() != 0 {
		if *all && fs.NArg() != 0 {
			_, _ = fmt.Fprintln(r.Err, "error: cannot specify a SERVICE argument when using --all\n  try: rsbx secret rm --help")
			return 1
		}
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx secret rm --all [--force]")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	inventory, err := loadSecretRemovalInventory(ctx, client)
	if err != nil {
		r.error(err)
		return 1
	}
	confirmed, code := r.confirmSecretRemoval(fmt.Sprintf("all %d inventoried host credentials", inventory.count()), *force)
	if code != 0 {
		return code
	}
	if !confirmed {
		return 0
	}
	removed, err := removeSecretRemovalInventory(ctx, client, inventory)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Removed %d inventoried Rheic-managed host credentials\n", removed)
	_, _ = fmt.Fprintln(r.Out, "Custom-secret storage is unavailable and was not included.")
	return 0
}

type secretRemovalInventory struct {
	services   []sdk.ServiceSecret
	registries []sdk.RegistryCredentialSummary
	accounts   []string
}

func (i secretRemovalInventory) count() int {
	return len(i.services) + len(i.registries) + len(i.accounts)
}

func loadSecretRemovalInventory(ctx context.Context, client sdk.Client) (secretRemovalInventory, error) {
	services, err := sdk.Secrets(client).List(ctx)
	if err != nil {
		return secretRemovalInventory{}, fmt.Errorf("list service credentials before removal: %w", err)
	}
	registryLister, ok := sdk.RegistryCredentialList(client)
	if !ok {
		return secretRemovalInventory{}, errors.New("this client cannot list registry credentials; refusing incomplete --all removal")
	}
	registries, err := registryLister.ListRegistryCredentials(ctx)
	if err != nil {
		return secretRemovalInventory{}, fmt.Errorf("list registry credentials before removal: %w", err)
	}
	inventory := secretRemovalInventory{services: services, registries: registries}
	for _, provider := range []string{"docker", openAIService} {
		present, err := sdk.AccountStatus(client).Status(ctx, provider)
		if err != nil {
			return secretRemovalInventory{}, fmt.Errorf("check %s account credentials before removal: %w", provider, err)
		}
		if present {
			inventory.accounts = append(inventory.accounts, provider)
		}
	}
	return inventory, nil
}

func removeSecretRemovalInventory(ctx context.Context, client sdk.Client, inventory secretRemovalInventory) (int, error) {
	removed, err := removeServiceSecretInventory(ctx, sdk.Secrets(client), inventory.services)
	if err != nil {
		return removed, err
	}
	removed, err = removeRegistrySecretInventory(ctx, client.RegistryCredentials(), inventory.registries, removed)
	if err != nil {
		return removed, err
	}
	return removeAccountInventory(ctx, sdk.Accounts(client), inventory.accounts, removed)
}

func removeServiceSecretInventory(ctx context.Context, secrets sdk.SecretService, items []sdk.ServiceSecret) (int, error) {
	removed := 0
	for _, item := range items { //nolint:gocritic // SDK secret records are read-only here; indexing would obscure the filter logic.
		ok, err := secrets.Remove(ctx, item.Service, item.Scope, item.SandboxName)
		if err != nil {
			return removed, fmt.Errorf("partial credential removal after %d entries: %w", removed, err)
		}
		if ok {
			removed++
		}
	}
	return removed, nil
}

func removeRegistrySecretInventory(ctx context.Context, registries sdk.RegistryCredentialService, items []sdk.RegistryCredentialSummary, removed int) (int, error) {
	for _, item := range items { //nolint:gocritic // SDK secret records are read-only here; indexing would obscure the filter logic.
		response, err := registries.Logout(ctx, sdk.RegistryLogoutRequest{
			Registry: item.Registry, Scope: sdk.RegistryCredentialScope(item.Scope), SandboxName: item.SandboxName,
		})
		if err != nil {
			return removed, fmt.Errorf("partial credential removal after %d entries: %w", removed, err)
		}
		if response != nil && response.Removed {
			removed++
		}
	}
	return removed, nil
}

func removeAccountInventory(ctx context.Context, accounts sdk.AccountService, providers []string, removed int) (int, error) {
	for _, provider := range providers {
		ok, err := accounts.Logout(ctx, provider)
		if err != nil {
			return removed, fmt.Errorf("partial credential removal after %d entries: %w", removed, err)
		}
		if ok {
			removed++
		}
	}
	return removed, nil
}

// reorderFlagArgs moves flags and their values before positionals so the
// standard library flag parser accepts the Docker sbx interspersed grammar:
// flags may appear before, between, or after positional arguments. A literal
// "--" ends flag parsing; it is preserved so tokens after it stay positional
// even when they look like flags. The helper never interprets flag values as
// flags.
func reorderFlagArgs(args []string, valueFlags map[string]bool) []string {
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
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		flags = append(flags, arg)
		name, _, hasValue := strings.Cut(arg, "=")
		if hasValue {
			continue
		}
		// --socket is a global value flag in every command; --debug/-D are
		// boolean, so a following token is never their value.
		if name == socketFlag || name == socketShortFlag || valueFlags[name] {
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	reordered := make([]string, 0, len(flags)+len(positionals)+1)
	reordered = append(reordered, flags...)
	if endOfFlags {
		reordered = append(reordered, "--")
	}
	return append(reordered, positionals...)
}

func (r *Runner) unsupportedFamily(name string) int {
	reasons := map[string]string{
		"volume": "persistent volumes are cloud-only in this build",
		"move":   "cloud move is unavailable without a tenant",
		"ttl":    "cloud TTL is unavailable without a tenant",
	}
	_, _ = fmt.Fprintf(r.Err, "rsbx %s: unsupported: %s\n", name, reasons[name])
	return 1
}

func hasFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == name || strings.HasPrefix(arg, name+"=") {
			return true
		}
		if arg == "--" {
			return false
		}
	}
	return false
}

func (r *Runner) confirmSecretRemoval(target string, force bool) (bool, int) {
	if force {
		return true, 0
	}
	input, ok := r.In.(*os.File)
	if !ok || !term.IsTerminal(int(input.Fd())) {
		_, _ = fmt.Fprintln(r.Err, "error: stdin is not a terminal; use --force to skip confirmation")
		return false, 1
	}
	if _, err := fmt.Fprintf(r.Err, "Remove %s? [y/N] ", sanitizeTerminalText(target)); err != nil {
		r.error(err)
		return false, 1
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && answer == "" {
		r.error(errors.New("could not read confirmation"))
		return false, 1
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, 0
	default:
		_, _ = fmt.Fprintln(r.Err, "Removal canceled")
		return false, 0
	}
}

func (r *Runner) registryRemove(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{registryFlag: true, sandboxFlag: true, allSandboxesFlag: false, globalFlag: false, forceFlag: false, "-f": false})
	fs := r.newFlagSet("secret rm")
	fs.SetOutput(r.Err)
	registry := fs.String("registry", "", "registry host")
	allSandboxes := fs.Bool("all-sandboxes", false, "remove all-sandboxes credential")
	sandboxName := fs.String("sandbox", "", "remove credential for one sandbox")
	global := fs.Bool("global", false, "deprecated: remove global credential")
	force := fs.Bool("force", false, "delete without confirmation prompt")
	fs.BoolVar(force, "f", false, "delete without confirmation prompt")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("secret rm", err)
	}
	if message, code := registryRemovalArgumentError(*registry, fs.NArg(), *sandboxName, *global, *allSandboxes); code != 0 {
		_, _ = fmt.Fprintln(r.Err, message)
		return code
	}
	if fs.NArg() == 1 {
		*sandboxName = fs.Arg(0)
		_, _ = fmt.Fprintf(r.Err, "warning: the positional sandbox scope is deprecated and will be removed in a future release; use --sandbox %s with --registry\n", sanitizeTerminalText(*sandboxName))
	}
	if *global {
		_, _ = fmt.Fprintln(r.Err, "warning: --global is deprecated; global is now the default for service secrets; omit --global, use --sandbox to target one sandbox, or use --all-sandboxes with --registry")
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	scopes := registryRemovalScopes(*sandboxName, *global, *allSandboxes)
	lister, ok := sdk.RegistryCredentialList(client)
	if !ok {
		r.error(errors.New("registry credential inventory is unavailable; refusing removal before confirmation"))
		return 1
	}
	items, err := lister.ListRegistryCredentials(ctx)
	if err != nil {
		r.error(fmt.Errorf("list registry credentials before removal: %w", err))
		return 1
	}
	if !registryCredentialPresent(items, *registry, *sandboxName, scopes) {
		_, _ = fmt.Fprint(r.Out, registryRemovalAbsentMessage(*registry, *sandboxName, scopes))
		return 0
	}
	confirmed, code := r.confirmSecretRemoval(fmt.Sprintf("registry credentials for %s", *registry), *force)
	if code != 0 {
		return code
	}
	if !confirmed {
		return 0
	}
	return r.removeRegistryScopes(ctx, client, *registry, *sandboxName, scopes)
}

func registryCredentialPresent(items []sdk.RegistryCredentialSummary, registry, sandboxName string, scopes []sdk.RegistryCredentialScope) bool {
	for _, item := range items { //nolint:gocritic // SDK secret records are read-only here; indexing would obscure the filter logic.
		if item.Registry != registry || item.SandboxName != sandboxName {
			continue
		}
		for _, scope := range scopes {
			if item.Scope == string(scope) {
				return true
			}
		}
	}
	return false
}

func registryRemovalAbsentMessage(registry, sandboxName string, scopes []sdk.RegistryCredentialScope) string {
	if len(scopes) > 1 && sandboxName == "" {
		return fmt.Sprintf("No registry credentials stored for %q\n", sanitizeTerminalText(registry))
	}
	labels := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		labels = append(labels, registryScopeDisplay(scope, sandboxName))
	}
	return fmt.Sprintf("No registry credentials stored for %q (%s)\n", sanitizeTerminalText(registry), strings.Join(labels, ", "))
}

func registryScopeDisplay(scope sdk.RegistryCredentialScope, sandboxName string) string {
	if scope == sdk.RegistryScopeSandbox && sandboxName != "" {
		return fmt.Sprintf("%s %s", scope, sanitizeTerminalText(sandboxName))
	}
	return string(scope)
}

func registryRemovalArgumentError(registry string, positionals int, sandboxName string, global, allSandboxes bool) (string, int) {
	if conflict := registryRemovalScopeConflict(global, allSandboxes, sandboxName != ""); conflict != "" {
		return conflict, 1
	}
	if registry == "" || positionals > 1 {
		return "usage: rsbx secret rm [--registry HOST] [--all-sandboxes | --sandbox NAME]", 2
	}
	if positionals == 1 && (sandboxName != "" || global || allSandboxes) {
		return "error: cannot combine a positional sandbox name with a scope flag\n  try: rsbx secret rm --help", 1
	}
	return "", 0
}

func registryRemovalScopes(sandboxName string, global, allSandboxes bool) []sdk.RegistryCredentialScope {
	if allSandboxes {
		return []sdk.RegistryCredentialScope{sdk.RegistryScopeAllSandboxes}
	}
	if sandboxName != "" {
		return []sdk.RegistryCredentialScope{sdk.RegistryScopeSandbox}
	}
	if global {
		return []sdk.RegistryCredentialScope{sdk.RegistryScopeHostOnly}
	}
	return []sdk.RegistryCredentialScope{sdk.RegistryScopeHostOnly, sdk.RegistryScopeAllSandboxes}
}

func registryRemovalScopeConflict(global, allSandboxes, sandbox bool) string {
	if global && allSandboxes {
		return "error: cannot specify both --global and --all-sandboxes\n  try: rsbx secret rm --help"
	}
	if sandbox && (global || allSandboxes) {
		return "error: cannot combine --sandbox with --global or --all-sandboxes\n  try: rsbx secret rm --help"
	}
	return ""
}

func (r *Runner) removeRegistryScopes(ctx context.Context, client sdk.Client, registry, sandboxName string, scopes []sdk.RegistryCredentialScope) int {
	removedAny := false
	for _, scope := range scopes {
		response, err := client.RegistryCredentials().Logout(ctx, sdk.RegistryLogoutRequest{
			Registry: registry, Scope: scope, SandboxName: sandboxName,
		})
		if err != nil {
			if removedAny {
				r.error(fmt.Errorf("partial registry credential removal for %s: %w", registry, err))
			} else {
				r.error(err)
			}
			return 1
		}
		if response == nil || !response.Removed {
			continue
		}
		removedAny = true
		_, _ = fmt.Fprintf(r.Out, "Removed registry credentials for %s (%s)\n", sanitizeTerminalText(registry), registryScopeDisplay(scope, sandboxName))
	}
	if !removedAny {
		_, _ = fmt.Fprint(r.Out, registryRemovalAbsentMessage(registry, sandboxName, scopes))
	}
	return 0
}

func (r *Runner) registrySet(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{registryFlag: true, usernameFlag: true, sandboxFlag: true, passwordStdinFlag: false, allSandboxesFlag: false})
	fs := r.newFlagSet("secret set")
	fs.SetOutput(r.Err)
	registry := fs.String("registry", "", "registry host")
	username := fs.String("username", "", "registry username")
	passwordStdin := fs.Bool("password-stdin", false, "read password from stdin")
	allSandboxes := fs.Bool("all-sandboxes", false, "allow future brokered use in all sandboxes")
	sandboxName := fs.String("sandbox", "", "allow future brokered use in one sandbox")
	force := fs.Bool("force", false, "overwrite an existing registry credential")
	fs.BoolVar(force, "f", false, "overwrite an existing registry credential")
	if code, done := r.parseFlagsOrFail("secret set", fs, args); done {
		return code
	}
	if !validRegistryArguments(fs.NArg(), *registry) {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx secret set [--registry HOST] --username USER [--password-stdin] [--all-sandboxes | --sandbox NAME]")
		return 2
	}
	if *allSandboxes && *sandboxName != "" {
		_, _ = fmt.Fprintln(r.Err, "--all-sandboxes and --sandbox cannot be combined")
		return 2
	}
	if *username == "" && *passwordStdin {
		_, _ = fmt.Fprintln(r.Err, "--username is required with --password-stdin")
		return 2
	}
	scope := sdk.RegistryScopeHostOnly
	if *allSandboxes {
		scope = sdk.RegistryScopeAllSandboxes
	} else if *sandboxName != "" {
		scope = sdk.RegistryScopeSandbox
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if !*force {
		if code := r.checkRegistryCredentialAbsent(ctx, client, *registry, *sandboxName, scope); code != 0 {
			return code
		}
	}
	if *username == "" {
		if code := r.promptRegistryUsername(username); code != 0 {
			return code
		}
	}
	password, err := r.readLoginPassword(*passwordStdin)
	if err != nil {
		r.error(err)
		return 2
	}
	defer clear(password)
	return r.loginRegistryCredential(ctx, client, *registry, *username, password, scope, *sandboxName)
}

func (r *Runner) loginRegistryCredential(ctx context.Context, client sdk.Client, registry, username string, password []byte, scope sdk.RegistryCredentialScope, sandboxName string) int {
	response, err := client.RegistryCredentials().Login(ctx, sdk.RegistryLoginRequest{
		Registry: registry, Username: username, Password: password,
		Scope: scope, SandboxName: sandboxName,
	})
	if err != nil {
		var sdkErr *sdk.Error
		if errors.As(err, &sdkErr) && sdkErr.Code == sdkAlreadyExists {
			r.error(registrySecretAlreadyExistsError(registry, registrySetScopeLabel(scope, sandboxName)))
			return 1
		}
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Credentials stored (not verified) in host keychain for %s as %s (%s); sandbox registry access is not enabled yet\n", response.Registry, response.Username, response.Scope)
	return 0
}

func (r *Runner) promptRegistryUsername(username *string) int {
	if _, err := fmt.Fprint(r.Err, "Username: "); err != nil {
		r.error(err)
		return 1
	}
	line, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && line == "" {
		r.error(fmt.Errorf("read username: %w", err))
		return 1
	}
	*username = strings.TrimSpace(line)
	return 0
}

func (r *Runner) checkRegistryCredentialAbsent(ctx context.Context, client sdk.Client, registry, sandboxName string, scope sdk.RegistryCredentialScope) int {
	lister, ok := sdk.RegistryCredentialList(client)
	if !ok {
		r.error(errors.New("registry credential inventory is unavailable; refusing a non-atomic overwrite"))
		return 1
	}
	items, err := lister.ListRegistryCredentials(ctx)
	if err != nil {
		r.error(fmt.Errorf("list registry credentials before storage: %w", err))
		return 1
	}
	if registryCredentialPresent(items, registry, sandboxName, []sdk.RegistryCredentialScope{scope}) {
		r.error(registrySecretAlreadyExistsError(registry, registrySetScopeLabel(scope, sandboxName)))
		return 1
	}
	return 0
}

func registrySecretAlreadyExistsError(registry, scope string) error {
	return fmt.Errorf("registry secret already exists for %q in scope %q; pass --force to overwrite", registry, scope)
}

func registrySetScopeLabel(scope sdk.RegistryCredentialScope, sandboxName string) string {
	switch scope {
	case sdk.RegistryScopeHostOnly:
		return "(host only)"
	case sdk.RegistryScopeAllSandboxes:
		return "(all sandboxes)"
	case sdk.RegistryScopeSandbox:
		return fmt.Sprintf("(sandbox %s)", sandboxName)
	default:
		return string(scope)
	}
}

type flagParseError struct{ err error }

func (e flagParseError) Error() string { return e.err.Error() }

func asFlagParseError(err error) (flagParseError, bool) {
	var parseErr flagParseError
	if errors.As(err, &parseErr) {
		return parseErr, true
	}
	return flagParseError{}, false
}

// parseFlagsOrFail parses a flag set and reports failures through the shared
// error contract, returning done=true when the caller should return code.
func (r *Runner) parseFlagsOrFail(cmdPath string, fs *flag.FlagSet, args []string) (code int, done bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		return r.flagParseFailure(cmdPath, err), true
	}
	return 0, false
}

func validRegistryArguments(count int, registry string) bool {
	return count == 0 && registry != ""
}

func (r *Runner) readLoginPassword(fromStdin bool) ([]byte, error) {
	if file, ok := r.In.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		if fromStdin {
			return nil, fmt.Errorf("refusing to read --password-stdin from an interactive terminal; omit the flag for hidden prompt")
		}
		if _, err := fmt.Fprint(r.Err, "Password: "); err != nil {
			return nil, fmt.Errorf("write password prompt: %w", err)
		}
		password, err := term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(r.Err)
		if err != nil {
			return nil, fmt.Errorf("read password from terminal: %w", err)
		}
		return password, nil
	}
	if !fromStdin {
		return nil, fmt.Errorf("password input is not a terminal; use --password-stdin")
	}
	data, err := io.ReadAll(io.LimitReader(r.In, 2050))
	if err != nil {
		clear(data)
		return nil, fmt.Errorf("read password from stdin: %w", err)
	}
	if len(data) > 2049 {
		clear(data)
		return nil, fmt.Errorf("password exceeds the 2048-byte limit")
	}
	data = bytes.TrimSuffix(bytes.TrimSuffix(data, []byte("\n")), []byte("\r"))
	if len(data) == 0 || len(data) > 2048 || bytes.ContainsAny(data, "\r\n") {
		clear(data)
		return nil, fmt.Errorf("password input must contain one non-empty line up to 2048 bytes")
	}
	return data, nil
}

type createOptions struct {
	name             string
	agent            string
	image            string
	workspace        string
	idempotencyKey   string
	workspaces       []sdk.Workspace
	ports            []sdk.Port
	allow            []sdk.NetworkRule
	deny             []sdk.NetworkRule
	cpus             uint32
	memoryMiB        uint32
	env              []string
	oauthCredentials []sdk.OAuthCredential
	profile          string
	privileged       bool
	clone            *sdk.CloneOptions
	skills           *sdk.SkillsOptions
}

func (r *Runner) create(ctx context.Context, args []string) int {
	opts, help, err := r.parseCreateOptions(ctx, args)
	if help {
		return r.showCommandHelp(createHelp())
	}
	if parseErr, ok := asFlagParseError(err); ok {
		return r.flagParseFailure(commandCreate, parseErr.err)
	}
	if err != nil {
		r.error(err)
		if errors.Is(err, errPrimaryWorkspaceReadOnly) {
			return 1
		}
		return 2
	}
	r.debug(ctx, debugEventCreatePrepare,
		debugBoolean("has_name", opts.name != ""),
		debugBoolean("has_agent", opts.agent != ""),
		debugBoolean("has_image", opts.image != ""),
		debugNumber("workspace_count", len(opts.workspaces)),
		debugNumber("port_count", len(opts.ports)),
		debugNumber("rule_count", len(opts.allow)+len(opts.deny)),
		debugNumber("env_count", len(opts.env)),
		debugBoolean(cloneName, opts.clone != nil),
		debugBoolean(privilegedName, opts.privileged))
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	name := opts.name
	if name == "" {
		base := ""
		if len(opts.workspaces) > 0 {
			base = sanitizeNameBase(opts.workspaces[0].Path)
		}
		name, err = runSandboxName(ctx, client, "", opts.agent, base)
		if err != nil {
			r.error(err)
			return 1
		}
	}
	op, err := client.Sandboxes().Create(ctx, sdk.CreateRequest{
		Name:             name,
		Image:            opts.image,
		Workspace:        opts.workspace,
		Workspaces:       opts.workspaces,
		Ports:            opts.ports,
		Allow:            opts.allow,
		Deny:             opts.deny,
		IdempotencyKey:   opts.idempotencyKey,
		Agent:            opts.agent,
		CPUs:             opts.cpus,
		MemoryMiB:        opts.memoryMiB,
		PolicyProfile:    opts.profile,
		Privileged:       opts.privileged,
		Env:              envMap(opts.env),
		OAuthCredentials: opts.oauthCredentials,
		Clone:            opts.clone,
		Skills:           opts.skills,
	})
	if err != nil {
		r.error(err)
		return 1
	}
	if opts.clone != nil {
		if err := r.activateCreatedClone(ctx, client, op, name, &opts); err != nil {
			r.error(err)
			return 1
		}
	}
	r.printCreatedSandbox(ctx, client, name, op)
	return 0
}

func (r *Runner) activateCreatedClone(ctx context.Context, client sdk.Client, op *sdk.Operation, name string, opts *createOptions) error {
	sandbox, err := lookupSandboxForReport(ctx, client, opSandboxID(op), name)
	if err != nil {
		if opts.idempotencyKey == "" {
			return errors.Join(err, cleanupCloneSandbox(ctx, client, op, sandbox, r.gitConfigCommand()))
		}
		return errors.Join(err, errors.New("sandbox retained because idempotency may have reused a pre-existing resource"))
	}
	if _, err := r.activateCloneSandbox(ctx, sandbox, opts.clone.SourceWorkspacePath); err != nil {
		if opts.idempotencyKey != "" {
			return errors.Join(err, errors.New("sandbox retained because idempotency may have reused a pre-existing resource"))
		}
		return errors.Join(err, cleanupCloneSandbox(ctx, client, op, sandbox, r.gitConfigCommand()))
	}
	return nil
}

// printCreatedSandbox renders the human create summary; operation records stay
// available through --format json on lifecycle commands.
func (r *Runner) printCreatedSandbox(ctx context.Context, client sdk.Client, name string, op *sdk.Operation) {
	id := ""
	if op != nil {
		id = op.SandboxID
	}
	sb, err := lookupSandboxForReport(ctx, client, id, name)
	if err != nil || sb == nil {
		_, _ = fmt.Fprintf(r.Out, "Created sandbox %s\n", name)
		return
	}
	_, _ = fmt.Fprint(r.Out, sandboxReport(sb))
	_, _ = fmt.Fprintf(r.Out, "Created sandbox %s\n", sb.Name)
}

// lookupSandboxForReport resolves a sandbox by ID first and falls back to name.
func lookupSandboxForReport(ctx context.Context, client sdk.Client, id, name string) (*sdk.Sandbox, error) {
	if id != "" {
		sb, err := client.Sandboxes().Get(ctx, id)
		if err == nil {
			return sb, nil
		}
	}
	sb, found, err := lookupSandboxByName(ctx, client, name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, sandboxNotFoundError{name: name}
	}
	return sb, nil
}

// sandboxReport formats a created sandbox like the Docker sbx baseline.
func sandboxReport(sb *sdk.Sandbox) string {
	agent := formatAgent(sb.Agent)
	return fmt.Sprintf(`
SANDBOX
  Name:       %s
  Agent:      %s
  Workspace:  %s
  Image:      %s
  CPU:        %d
  Memory:     %s

`, sb.Name, agent, formatWorkspaces(sb), sb.Image, sb.CPUs, formatMemoryMiB(sb.MemoryMiB))
}

// formatMemoryMiB renders memory sizes like the Docker sbx baseline.
func formatMemoryMiB(mib uint32) string {
	if mib == 0 {
		return "-"
	}
	if mib%1024 == 0 {
		return fmt.Sprintf("%d GiB", mib/1024)
	}
	return fmt.Sprintf("%d MiB", mib)
}

func parseCreatePositionals(positionals []string, nameFlag string) (string, string, []string, error) {
	if len(positionals) == 0 {
		return "", "", nil, errors.New("usage: rsbx create AGENT [PATH...] [--name NAME] [--cpus N] [--memory SIZE] [--image REF]")
	}
	agent := positionals[0]
	if err := validateRunAgent(agent); err != nil {
		return "", "", nil, err
	}
	return nameFlag, agent, positionals[1:], nil
}

// resolveTemplateImage applies the Docker sbx baseline --template alias.
func resolveTemplateImage(image, template string) (string, error) {
	if template == "" {
		return image, nil
	}
	if image != "" {
		return "", errors.New("--template and --image cannot be combined")
	}
	return template, nil
}

func validateCreateResources(cpus uint, memory string) (uint32, uint32, error) {
	cpuCount, err := validateCPUs(cpus)
	if err != nil {
		return 0, 0, err
	}
	memoryMiB, err := parseMemoryMiB(memory)
	if err != nil {
		return 0, 0, err
	}
	return cpuCount, memoryMiB, nil
}

//nolint:gocyclo,cyclop,funlen // create accepts the full documented flag matrix.
func (r *Runner) parseCreateOptions(ctx context.Context, args []string) (createOptions, bool, error) {
	fs := r.newFlagSet(commandCreate)
	fs.SetOutput(io.Discard)
	image := fs.String("image", "", "image reference")
	template := fs.String("template", "", "container image to use for the sandbox (alias for --image)")
	fs.StringVar(template, "t", "", "container image to use for the sandbox (alias for --image)")
	nameFlag := fs.String("name", "", "sandbox name")
	var publishFlags stringListFlag
	fs.Var(&publishFlags, "publish", "publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6] (repeatable)")
	fs.Var(&publishFlags, "p", "publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6] (repeatable; alias for --publish)")
	var allowFlags, denyFlags stringListFlag
	fs.Var(&allowFlags, "allow-network", "allow egress CIDR[:PORT] (repeatable; optional udp: prefix)")
	fs.Var(&denyFlags, "deny-network", "deny egress CIDR[:PORT] (repeatable; optional udp: prefix)")
	var envFlags, envFileFlags stringListFlag
	fs.Var(&envFlags, "env", "environment KEY=VALUE for every process (repeatable)")
	fs.Var(&envFlags, "e", "environment KEY=VALUE for every process (repeatable)")
	fs.Var(&envFileFlags, "env-file", "read environment from a file (repeatable)")
	idempotency := fs.String("idempotency-key", "", "idempotency key")
	cpus := fs.Uint("cpus", 0, "CPUs (0 selects the daemon default)")
	memory := fs.String("memory", "", "memory limit such as 512m or 2g (empty selects the daemon default)")
	fs.StringVar(memory, "m", "", "memory limit (alias for --memory)")
	profile := fs.String("policy-profile", "", "egress profile: allow-all, balanced, deny-all or sbx-compat")
	privileged := fs.Bool("docker", false, "run the dedicated Docker profile")
	cloneMode := fs.Bool("clone", false, "run the agent on a private in-guest clone of PATH")
	fs.Bool("no-progress", false, "suppress progress output")
	kitPath := fs.String("kit", "", "apply a local kit definition")
	skillsMode := fs.String("skills", "", "shared skills mode: off, readonly or readwrite (empty uses skills.defaultMode)")
	var denyWriteFlags stringListFlag
	fs.Var(&denyWriteFlags, "deny-write", "mount PATH read-only (repeatable)")
	if err := fs.Parse(reorderCreateArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return createOptions{}, true, nil
		}
		return createOptions{}, false, flagParseError{err: err}
	}
	positionals := fs.Args()
	if *kitPath != "" && len(positionals) == 0 {
		doc, err := kit.Load(*kitPath)
		if err != nil {
			return createOptions{}, false, err
		}
		if doc.Spec.Agent == "" {
			return createOptions{}, false, fmt.Errorf("kit %s does not define an agent", *kitPath)
		}
		positionals = []string{doc.Spec.Agent}
	}
	name, agent, paths, err := parseCreatePositionals(positionals, *nameFlag)
	if err != nil {
		return createOptions{}, false, err
	}
	imageRef, err := resolveTemplateImage(*image, *template)
	if err != nil {
		return createOptions{}, false, err
	}
	var oauthCredentials []sdk.OAuthCredential
	if *kitPath != "" {
		kitPaths := make([]string, 0, len(paths))
		kitEnv := []string(envFlags)
		if err := applyKit(ctx, *kitPath, &agent, &imageRef, profile, &kitPaths, &kitEnv, &oauthCredentials); err != nil {
			return createOptions{}, false, err
		}
		paths = append(kitPaths, paths...)
		envFlags = stringListFlag(kitEnv)
	}
	applyAgentDefaults(agent, &imageRef, privileged)
	cpuCount, memoryMiB, err := validateCreateResources(*cpus, *memory)
	if err != nil {
		return createOptions{}, false, err
	}
	workspaces, cloneOptions, err := prepareCreateWorkspaces(ctx, paths, denyWriteFlags, *cloneMode)
	if err != nil {
		return createOptions{}, false, err
	}
	env, err := buildExecEnv(envFlags, envFileFlags)
	if err != nil {
		return createOptions{}, false, err
	}
	ports, allow, deny, err := resolveCreateNetwork(publishFlags, allowFlags, denyFlags)
	if err != nil {
		return createOptions{}, false, err
	}
	skills, err := r.prepareSkillsOption(*skillsMode)
	if err != nil {
		return createOptions{}, false, err
	}
	workspace := ""
	if len(workspaces) > 0 {
		workspace = workspaces[0].Path
	}
	return createOptions{
		name: name, agent: agent, image: imageRef, workspace: workspace, idempotencyKey: *idempotency,
		workspaces: workspaces, ports: ports, allow: allow, deny: deny,
		cpus: cpuCount, memoryMiB: memoryMiB, env: env, oauthCredentials: oauthCredentials, profile: *profile, privileged: *privileged, clone: cloneOptions,
		skills: skills,
	}, false, nil
}

// reorderCreateArgs accepts options after the agent and workspace paths, as
// advertised by create's command grammar. Preserve -- as the end of flags.
func reorderCreateArgs(fs *flag.FlagSet, args []string) []string {
	valueFlags := make(map[string]bool)
	fs.VisitAll(func(f *flag.Flag) {
		boolFlag, isBool := f.Value.(interface{ IsBoolFlag() bool })
		takesValue := !isBool || !boolFlag.IsBoolFlag()
		valueFlags["-"+f.Name] = takesValue
		valueFlags["--"+f.Name] = takesValue
	})
	return reorderFlagArgs(args, valueFlags)
}

var errPrimaryWorkspaceReadOnly = errors.New("primary workspace must be read/write (remove ':ro' or ':readonly')")

func prepareCreateWorkspaces(ctx context.Context, paths, denyWrites []string, clone bool) ([]sdk.Workspace, *sdk.CloneOptions, error) {
	for _, target := range denyWrites {
		paths = append(paths, target+":ro")
	}
	workspaces, err := resolveWorkspaces(paths, false)
	if err != nil {
		return nil, nil, err
	}
	if len(workspaces) > 0 && workspaces[0].ReadOnly {
		return nil, nil, errPrimaryWorkspaceReadOnly
	}
	return applyCreateCloneMode(ctx, clone, workspaces)
}

func applyCreateCloneMode(ctx context.Context, clone bool, workspaces []sdk.Workspace) ([]sdk.Workspace, *sdk.CloneOptions, error) {
	if !clone {
		return workspaces, nil, nil
	}
	if len(workspaces) == 0 {
		return nil, nil, errors.New("--clone requires a primary Git workspace path")
	}
	if err := validateCloneExtraWorkspaces(workspaces); err != nil {
		return nil, nil, err
	}
	workspace, err := cloneWorkspaceForMount(ctx, workspaces[0])
	if err != nil {
		return nil, nil, err
	}
	workspaces[0] = workspace
	return workspaces, &sdk.CloneOptions{SourceWorkspacePath: workspace.Path}, nil
}

func validateCloneExtraWorkspaces(workspaces []sdk.Workspace) error {
	for _, workspace := range workspaces[1:] {
		if !workspace.ReadOnly {
			return errors.New("--clone additional workspaces must be read-only")
		}
	}
	return nil
}

func (r *Runner) stop(ctx context.Context, args []string) int {
	return r.lifecycle(ctx, args)
}

type removeOptions struct {
	force   bool
	all     bool
	format  string
	targets []string
}

func (r *Runner) remove(ctx context.Context, args []string) int {
	opts, help, err := r.parseRemoveOptions(args)
	if help {
		return r.showCommandHelp(removeHelp())
	}
	if parseErr, ok := asFlagParseError(err); ok {
		return r.flagParseFailure("rm", parseErr.err)
	}
	if errors.Is(err, errMissingSandboxTargets) {
		return r.commandError("rm", "requires at least 1 argument")
	}
	if err != nil {
		r.error(err)
		return 2
	}
	r.debug(ctx, debugEventLifecycle,
		debugOperationField("remove"),
		debugNumber("target_count", len(opts.targets)),
		debugFormatField(opts.format))
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	targets, resolveFailed, code := r.prepareRemoval(ctx, client, opts)
	if code >= 0 {
		return code
	}
	_, removed, deleteFailed := r.deleteSandboxes(ctx, client, targets, opts.force)
	if code := r.renderRemoval(opts.format, removed); code >= 0 {
		return code
	}
	if resolveFailed || deleteFailed {
		return 1
	}
	return 0
}

// removalTarget is a sandbox resolved before removal. Resolving the whole batch
// first lets rm reject every non-stopped sandbox before deleting anything.
type removalTarget struct {
	name    string
	sandbox *sdk.Sandbox
}

func (r *Runner) prepareRemoval(ctx context.Context, client sdk.Client, opts removeOptions) ([]removalTarget, bool, int) {
	targets := opts.targets
	if opts.all {
		var err error
		targets, err = allSandboxIDs(ctx, client)
		if err != nil {
			r.error(err)
			return nil, true, 1
		}
	}
	if len(targets) == 0 {
		if err := renderMutations(r.Out, opts.format, nil); err != nil {
			r.error(err)
			return nil, true, 1
		}
		return nil, false, 0
	}
	resolved, blocked, failed := r.resolveRemovalTargets(ctx, client, targets, !opts.force)
	if blocked {
		return nil, true, 1
	}
	if opts.force {
		return resolved, failed, -1
	}
	if len(resolved) == 0 {
		return nil, failed, -1
	}
	confirm := r.confirmRemoval
	if r.removalPrompt != nil {
		confirm = r.removalPrompt
	}
	confirmed, err := confirm(len(resolved))
	if err != nil {
		r.error(err)
		return nil, true, 1
	}
	if !confirmed {
		_, _ = fmt.Fprintln(r.Out, "Removal canceled")
		return nil, false, 0
	}
	return resolved, failed, -1
}

// resolveRemovalTargets looks up every target and, when requireStopped is set,
// reports and collects every sandbox that is not stopped. A blocked batch must
// not be deleted even partially.
func (r *Runner) resolveRemovalTargets(ctx context.Context, client sdk.Client, targets []string, requireStopped bool) ([]removalTarget, bool, bool) {
	resolved := make([]removalTarget, 0, len(targets))
	blocked, failed := false, false
	for _, name := range targets {
		id, err := findExecSandbox(ctx, client, name)
		if err != nil {
			r.error(err)
			failed = true
			continue
		}
		sandbox, err := client.Sandboxes().Get(ctx, id)
		if err != nil {
			r.error(err)
			failed = true
			continue
		}
		if requireStopped && sandbox.State != sdk.StateStopped {
			r.error(removalStateError(sandbox))
			blocked = true
			continue
		}
		resolved = append(resolved, removalTarget{name: name, sandbox: sandbox})
	}
	return resolved, blocked, failed
}

func removalStateError(sandbox *sdk.Sandbox) error {
	switch sandbox.State {
	case "", sdk.StateUnknown:
		return fmt.Errorf("sandbox %s is not stopped; stop it first or pass --force", sandbox.Name)
	case sdk.StateRunning:
		return fmt.Errorf("sandbox %s is running; stop it first or pass --force", sandbox.Name)
	default:
		return fmt.Errorf("sandbox %s is %s; wait until it is stopped or pass --force", sandbox.Name, sandbox.State)
	}
}

func (r *Runner) renderRemoval(format string, removed []string) int {
	if format != listFormatTable {
		if err := renderMutations(r.Out, format, sandboxMutations("removed", removed)); err != nil {
			r.error(err)
			return 1
		}
		return -1
	}
	for _, name := range removed {
		_, _ = fmt.Fprintf(r.Out, "Removed sandbox %s\n", name)
	}
	return -1
}

func (r *Runner) parseRemoveOptions(args []string) (removeOptions, bool, error) {
	fs := r.newFlagSet("rm")
	fs.SetOutput(io.Discard)
	force := fs.Bool("force", false, "delete without confirmation and allow running sandboxes")
	fs.BoolVar(force, "f", false, "delete without confirmation and allow running sandboxes")
	all := fs.Bool("all", false, "remove all sandboxes")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{formatFlag: true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return removeOptions{}, true, nil
		}
		return removeOptions{}, false, flagParseError{err: err}
	}
	if *all && fs.NArg() != 0 {
		return removeOptions{}, false, errors.New("usage: rsbx rm [-f|--force] [--format table|json|yaml] SANDBOX... | --all")
	}
	if !*all && fs.NArg() < 1 {
		return removeOptions{}, false, errMissingSandboxTargets
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		return removeOptions{}, false, err
	}
	return removeOptions{force: *force, all: *all, format: selected, targets: fs.Args()}, false, nil
}

func allSandboxIDs(ctx context.Context, client sdk.Client) ([]string, error) {
	items, err := collectSandboxes(ctx, client, sandboxPageSize, 0)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(items))
	for i := range items {
		ids = append(ids, items[i].ID)
	}
	return ids, nil
}

func (r *Runner) deleteSandboxes(ctx context.Context, client sdk.Client, targets []removalTarget, force bool) ([]*sdk.Operation, []string, bool) {
	return r.deleteResolvedSandboxes(ctx, client, targets, force, false)
}

// deleteSandboxesBestEffort removes sandboxes and treats managed clone remote
// cleanup as a warning, so failed cleanup cannot mask successful deletion in
// the final exit code. It keeps reset's semantics: running sandboxes are
// deleted because reset is explicitly destructive and confirmed.
func (r *Runner) deleteSandboxesBestEffort(ctx context.Context, client sdk.Client, targets []string) ([]*sdk.Operation, []string, bool) {
	resolved, _, failed := r.resolveRemovalTargets(ctx, client, targets, false)
	operations, removed, deleteFailed := r.deleteResolvedSandboxes(ctx, client, resolved, true, true)
	return operations, removed, failed || deleteFailed
}

func (r *Runner) deleteResolvedSandboxes(ctx context.Context, client sdk.Client, targets []removalTarget, force, warnOnCloneCleanup bool) ([]*sdk.Operation, []string, bool) {
	failed := false
	operations := make([]*sdk.Operation, 0, len(targets))
	removed := make([]string, 0, len(targets))
	for _, target := range targets {
		sandbox := target.sandbox
		r.warnCloneRemoval(sandbox)
		op, err := client.Sandboxes().Delete(ctx, sandbox.ID, sdk.DeleteOptions{Force: force})
		if err != nil {
			r.error(err)
			failed = true
			continue
		}
		if op != nil && op.State == sdk.StateFailed {
			r.error(fmt.Errorf("remove sandbox %s failed: %s", target.name, op.Error))
			failed = true
			continue
		}
		if r.cleanupDeletedCloneRemote(ctx, sandbox, warnOnCloneCleanup) {
			failed = true
		}
		operations = append(operations, op)
		removed = append(removed, target.name)
	}
	return operations, removed, failed
}

func (r *Runner) confirmRemoval(count int) (bool, error) {
	if r.removalPrompt != nil {
		return r.removalPrompt(count)
	}
	return r.confirmDestructive("removal", fmt.Sprintf("Remove %d sandbox(es)?", count))
}

// confirmDestructive requires a terminal before prompting and treats an empty
// answer, or anything other than y/yes, as no. Callers skip it with --force.
func (r *Runner) confirmDestructive(subject, prompt string) (bool, error) {
	if !r.stdinIsTerminal() {
		return false, fmt.Errorf("%s confirmation requires a terminal; use --force to skip confirmation", subject)
	}
	if _, err := fmt.Fprintf(r.Err, "%s [y/N] ", prompt); err != nil {
		return false, fmt.Errorf("write %s prompt: %w", subject, err)
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read %s confirmation: %w", subject, err)
	}
	return affirmativeAnswer(answer), nil
}

func (r *Runner) stdinIsTerminal() bool {
	if r.confirmTerminal != nil {
		return r.confirmTerminal()
	}
	file, ok := r.In.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func affirmativeAnswer(answer string) bool {
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == answerShortYes || answer == answerYes
}

func lifecycleUsage() string {
	return `usage: rsbx stop [--format table|json|yaml] [--json] [flags] SANDBOX...

Stop one or more sandboxes. Flags may appear before, between or after sandbox
names; use -- to end flag parsing.

Structured output is an array of {action, resource, name} records, matching
sbx stop --json.

Examples:
  rsbx stop --format json api
  rsbx stop api --format json
  rsbx stop api --format json worker

Flags:
      --grace DURATION            stop grace period
      --format table|json|yaml    output format
      --json                      output in JSON format
`
}

func (r *Runner) lifecycle(ctx context.Context, args []string) int {
	fs := r.newFlagSet(stopCommand)
	fs.SetOutput(io.Discard)
	grace := fs.Duration("grace", 0, "grace period")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{graceFlag: true, formatFlag: true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return r.showCommandHelp(stopHelp())
		}
		return r.flagParseFailure(stopCommand, err)
	}
	if fs.NArg() < 1 {
		_, _ = fmt.Fprint(r.Err, lifecycleUsage())
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	r.debug(ctx, debugEventLifecycle,
		debugOperationField("stop"),
		debugNumber("target_count", fs.NArg()),
		debugFormatField(selected))
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	failed := false
	completed := make([]string, 0, len(fs.Args()))
	for _, target := range fs.Args() {
		if _, err := r.runLifecycleTarget(ctx, client, target, *grace); err != nil {
			r.error(err)
			failed = true
			continue
		}
		completed = append(completed, target)
		if selected == listFormatTable {
			_, _ = fmt.Fprintf(r.Out, "Stopped sandbox %s\n", target)
		}
	}
	if selected != listFormatTable {
		if err := renderMutations(r.Out, selected, sandboxMutations("stopped", completed)); err != nil {
			r.error(err)
			return 1
		}
	}
	if failed {
		return 1
	}
	return 0
}

// runLifecycleTarget stops one sandbox and returns its operation.
func (r *Runner) runLifecycleTarget(ctx context.Context, client sdk.Client, target string, grace time.Duration) (*sdk.Operation, error) {
	id, err := findExecSandbox(ctx, client, target)
	if err != nil {
		return nil, err
	}
	op, err := client.Sandboxes().Stop(ctx, id, sdk.StopOptions{Grace: grace})
	if err != nil {
		return nil, err
	}
	if op != nil && op.State == sdk.StateFailed {
		return nil, fmt.Errorf("%s sandbox %s failed: %s", stopCommand, target, op.Error)
	}
	if err := r.reconcileCloneLifecycle(ctx, client, id); err != nil {
		return nil, err
	}
	return op, nil
}

func (r *Runner) client() (sdk.Client, error) {
	r.debug(context.Background(), debugEventClientConnect, debugTransportField(r.Socket))
	var (
		client sdk.Client
		err    error
	)
	if r.NewClient == nil {
		client, err = sdk.New(sdk.Config{Address: r.Socket})
	} else {
		client, err = r.NewClient(r.Socket)
	}
	if err != nil {
		r.debug(context.Background(), debugEventClientReady,
			debugTransportField(r.Socket), debugResultField("error"))
		return nil, err
	}
	r.debug(context.Background(), debugEventClientReady,
		debugTransportField(r.Socket), debugResultField("ok"))
	return client, nil
}

func (r *Runner) usage() {
	const help = `Description:
  Rheic Sandboxes manages isolated local environments for coding agents.

Usage:
  rsbx COMMAND

Sandbox Commands:
  run, attach, create, exec, cp, ls, stop, rm, prune, ports

Management Commands:
  agents, daemon, diagnose, env, login, logout, mcp, policy, reset, secret, settings, tui

Experimental Commands:
  kit, setup, skills, template

Other Commands:
  completion  Generate a shell completion script (bash, zsh, fish, powershell)
  version     Show client and daemon versions

Unsupported Docker Sandboxes Commands:
  move, ttl, volume

Flags:
  -h, --help   help for rsbx

Global Flags:
  -D, --debug         Enable debug logging (structured events on stderr)
      --socket PATH   Local daemon endpoint

Use "rsbx COMMAND --help" for more information about a command.
`
	if _, err := io.WriteString(r.Out, help); err != nil {
		r.error(err)
	}
}

// sandboxNotFoundError reports an unknown sandbox with the reference wording so
// every command prints the same message and the `try: rsbx ls` hint.
type sandboxNotFoundError struct{ name string }

func (e sandboxNotFoundError) Error() string { return fmt.Sprintf("sandbox '%s' not found", e.name) }

func (r *Runner) error(err error) {
	var missing sandboxNotFoundError
	if errors.As(err, &missing) {
		_, _ = fmt.Fprintf(r.Err, "error: %s\n  try: rsbx ls\n", missing.Error())
		return
	}
	var typed *sdk.Error
	if errors.As(err, &typed) && typed.Message != "" {
		_, _ = fmt.Fprintf(r.Err, "error: %s\n", typed.Message)
		return
	}
	_, _ = fmt.Fprintf(r.Err, "error: %s\n", err)
}

func defaultSocket() string {
	if socket := strings.TrimSpace(os.Getenv("SANDBOXES_SOCKET")); socket != "" {
		return socket
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".sandboxes/sandboxesd.sock"
	}
	return filepath.Join(home, ".sandboxes", "sandboxesd.sock")
}

func formatWorkspaces(sb *sdk.Sandbox) string {
	workspaces := sb.Workspaces
	if len(workspaces) == 0 && sb.Workspace != "" {
		workspaces = []sdk.Workspace{{Path: sb.Workspace}}
	}
	if len(workspaces) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(workspaces))
	for i := range workspaces {
		mode := "rw"
		if workspaces[i].ReadOnly {
			mode = "ro"
		}
		parts = append(parts, workspaces[i].Path+" ("+mode+")")
	}
	return strings.Join(parts, ", ")
}

func formatPorts(sb *sdk.Sandbox) string {
	if len(sb.Ports) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(sb.Ports))
	for i := range sb.Ports {
		protocol := sb.Ports[i].Protocol
		if protocol == "" {
			protocol = tcpProtocol
		}
		parts = append(parts, fmt.Sprintf("%d->%d/%s", sb.Ports[i].Host, sb.Ports[i].Guest, protocol))
	}
	return strings.Join(parts, ", ")
}

func resolveCreateNetwork(publish, allow, deny []string) ([]sdk.Port, []sdk.NetworkRule, []sdk.NetworkRule, error) {
	ports, err := resolvePorts(publish)
	if err != nil {
		return nil, nil, nil, err
	}
	allowRules, err := resolveNetworkRules(allow)
	if err != nil {
		return nil, nil, nil, err
	}
	denyRules, err := resolveNetworkRules(deny)
	if err != nil {
		return nil, nil, nil, err
	}
	return ports, allowRules, denyRules, nil
}
