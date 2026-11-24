package command

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	sdk "github.com/rheic/sandboxes-go-sdk"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

type mcpArgsFlag []string
type stringSliceFlag []string

func (f *stringSliceFlag) String() string { return strings.Join(*f, ",") }
func (f *stringSliceFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

const mcpFormatYAML = "yaml"

func (f *mcpArgsFlag) String() string { return strings.Join(*f, ",") }
func (f *mcpArgsFlag) Set(value string) error {
	reader := csv.NewReader(strings.NewReader(value))
	reader.FieldsPerRecord = -1
	values, err := reader.Read()
	if err != nil {
		return err
	}
	*f = append(*f, values...)
	return nil
}

func (r *Runner) mcp(ctx context.Context, args []string) int {
	args, code, done := r.prepareFamilyArgs(mcpCommand, args)
	if done {
		return code
	}
	if len(args) == 0 || args[0] == helpCommand || args[0] == helpShort || args[0] == helpFlag {
		return r.showCommandHelp(mcpHelp())
	}
	switch args[0] {
	case "ls":
		return r.mcpList(ctx, args[1:])
	case "add":
		return r.mcpAdd(ctx, args[1:])
	case "call":
		return r.mcpCall(ctx, args[1:])
	case "rm":
		return r.mcpRemove(ctx, args[1:])
	case commandLoad:
		return r.mcpLoad(ctx, args[1:])
	case commandUnload:
		return r.mcpUnload(ctx, args[1:])
	case commandInspect:
		return r.mcpInspect(ctx, args[1:])
	case commandAuth:
		return r.mcpAuth(ctx, args[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "rsbx mcp: unknown command %q\n", args[0])
		return 2
	}
}

const mcpListUsage = `usage: rsbx mcp ls [--format table|json|yaml] [--json] [--quiet]

List registered MCP servers.
`

const mcpRemoveUsage = `usage: rsbx mcp rm [--force] NAME

Remove an MCP server registration.
`

func (r *Runner) mcpList(ctx context.Context, args []string) int {
	fs := r.newFlagSet("mcp ls")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(mcpListHelp()) }
	jsonOutput := fs.Bool("json", false, "write JSON")
	quiet := fs.Bool("quiet", false, "print server names only")
	format := fs.String("format", "", "output format: table or json")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"--format": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp ls", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprint(r.Err, mcpListUsage)
		return 2
	}
	if *format != "" {
		if *format != listFormatTable && *format != listFormatJSON && *format != mcpFormatYAML {
			_, _ = fmt.Fprintln(r.Err, "mcp ls: --format must be table, json, or yaml")
			return 2
		}
		*jsonOutput = *jsonOutput || *format == listFormatJSON
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	servers, err := sdk.MCP(client).List(ctx, "")
	if err != nil {
		r.error(err)
		return 1
	}
	if err := writeMCPList(r.Out, servers, *format, *jsonOutput, *quiet); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func writeMCPList(out io.Writer, servers []sdk.MCPServer, format string, jsonOutput, quiet bool) error {
	if jsonOutput || format == mcpFormatYAML {
		rows := mcpServerRows(servers)
		var output []byte
		var err error
		if format == mcpFormatYAML && !jsonOutput {
			output, err = yaml.Marshal(rows)
		} else {
			output, err = json.Marshal(rows)
		}
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(output))
		return err
	}
	for _, server := range servers {
		var err error
		if quiet {
			_, err = fmt.Fprintln(out, server.Name)
		} else {
			_, err = fmt.Fprintf(out, "%-24s %-12s %-18s %s\n", server.Name, server.Gateway, server.Transport, mcpUsability(server))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

//nolint:gocyclo,cyclop // flag parsing and validation for the full MCP registration surface.
func (r *Runner) mcpAdd(ctx context.Context, args []string) int {
	var serverArgs, headerArgs, secretHeaderArgs mcpArgsFlag
	var scopes stringSliceFlag
	fs := r.newFlagSet("mcp add")
	fs.SetOutput(io.Discard)
	command := fs.String("command", "", "absolute or PATH-resolved local stdio executable")
	directory := fs.String("dir", "", "working directory")
	remoteURL := fs.String("url", "", "remote streamable-HTTPS MCP endpoint (mutually exclusive with --command)")
	oauthAuthorizationServer := fs.String("oauth-authorization-server", "", "path or http(s) URL to an RFC 8414 oauth-authorization-server metadata JSON document")
	clientID := fs.String("client-id", "", "OAuth client id for a pre-registered client")
	resource := fs.String("resource", "", "RFC 8707 resource indicator")
	callbackPort := fs.Int("callback-port", 0, "local port to bind the OAuth callback listener to")
	disableHTTP2 := fs.Bool("disable-http2", false, "do not negotiate HTTP/2 for this remote server")
	noScope := fs.Bool("no-scope", false, "request no scopes during add-time authorization")
	skipAuth := fs.Bool("skip-auth", false, "register an OAuth server without starting the hosted OAuth flow")
	fs.Var(&serverArgs, "args", "comma-separated MCP executable arguments (repeatable)")
	fs.Var(&headerArgs, "header", "Docker-compatible alias for a host-vault remote header; values must contain ${placeholder}")
	fs.Var(&secretHeaderArgs, "secret-header", "host-vault remote header as Name:Value with ${placeholder}")
	fs.Var(&scopes, "scope", "default OAuth scope to request at consent time (repeatable)")
	fs.Usage = func() { r.showCommandHelp(mcpAddHelp()) }
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{commandFlag: true, "--dir": true, mcpArgsFlagName: true, "--url": true, "--header": true, "--secret-header": true, "--oauth-authorization-server": true, "--client-id": true, resourceFlag: true, scopeFlag: true, "--callback-port": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp add", err)
	}
	if fs.NArg() != 1 || (*command == "" && *remoteURL == "") || (*command != "" && *remoteURL != "") {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp add NAME (--command EXECUTABLE [--args ARG] [--dir PATH] | --url https://HOST/mcp [--header|--secret-header 'Name: value with ${PLACEHOLDER}'])")
		return 2
	}
	if *remoteURL == "" && (len(headerArgs)+len(secretHeaderArgs) > 0) {
		r.error(errors.New("MCP headers are supported only for remote servers"))
		return 2
	}
	if len(scopes) > 0 && *noScope {
		r.error(errors.New("MCP scopes and no scope are mutually exclusive"))
		return 2
	}
	if *callbackPort < 0 || *callbackPort > 65535 {
		r.error(errors.New("MCP callback port must be between 0 and 65535"))
		return 2
	}
	if err := requireMCPApprovalTerminal(r.In); err != nil {
		r.error(err)
		return 1
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if *remoteURL != "" {
		return r.mcpAddRemote(ctx, client, fs.Arg(0), *remoteURL, headerArgs, secretHeaderArgs, *oauthAuthorizationServer, *clientID, *resource, scopes, *noScope, *callbackPort, *disableHTTP2, *skipAuth)
	}
	return r.mcpAddStdio(ctx, client, fs.Arg(0), *command, *directory, serverArgs)
}

func (r *Runner) mcpAddRemote(ctx context.Context, client sdk.Client, name, rawURL string, headerArgs, secretHeaderArgs []string, oauthAuthorizationServer, clientID, resource string, scopes []string, noScope bool, callbackPort int, disableHTTP2, skipAuth bool) int {
	headers, secretHeaders, err := parseMCPRemoteHeaders(headerArgs, secretHeaderArgs)
	if err != nil {
		r.error(err)
		return 2
	}
	if err := r.registerMCPRemoteServer(ctx, client, name, rawURL, headers, secretHeaders, oauthAuthorizationServer, clientID, resource, scopes, noScope, callbackPort, disableHTTP2, skipAuth); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func mcpHeaderSetsOverlap(static, secret map[string]string) bool {
	for name := range static {
		for secretName := range secret {
			if strings.EqualFold(name, secretName) {
				return true
			}
		}
	}
	return false
}

func (r *Runner) mcpAddStdio(ctx context.Context, client sdk.Client, name, command, directory string, args []string) int {
	resolved, resolvedDir, err := prepareMCPCommand(command, directory)
	if err != nil {
		r.error(err)
		return 2
	}
	if err := r.registerMCPServer(ctx, client, name, resolved, args, resolvedDir); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

// parseMCPRemoteHeaders treats Docker's --header syntax as an alias for
// --secret-header. Every remote value still has to use a host-vault reference.
func parseMCPRemoteHeaders(headerArgs, secretHeaderArgs []string) (map[string]string, map[string]string, error) {
	aliasHeaders, err := parseMCPSecretHeaders(headerArgs)
	if err != nil {
		return nil, nil, err
	}
	secretHeaders, err := parseMCPSecretHeaders(secretHeaderArgs)
	if err != nil {
		return nil, nil, err
	}
	if mcpHeaderSetsOverlap(aliasHeaders, secretHeaders) {
		return nil, nil, errors.New("MCP header names must be unique, ignoring case")
	}
	for name, value := range aliasHeaders {
		secretHeaders[name] = value
	}
	return map[string]string{}, secretHeaders, nil
}

func parseMCPSecretHeaders(values []string) (map[string]string, error) {
	headers := make(map[string]string, len(values))
	for _, value := range values {
		name, headerValue, ok := strings.Cut(value, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.ContainsAny(name, "\r\n\x00") || strings.ContainsAny(headerValue, "\r\n\x00") {
			return nil, errors.New("invalid secret MCP header, want Name:Value")
		}
		headerValue = strings.TrimSpace(headerValue)
		refs, err := mcpHeaderPlaceholderNames(headerValue)
		if err != nil || len(refs) == 0 {
			return nil, errors.New("secret MCP headers must contain valid host-vault ${placeholder} references")
		}
		canonicalName := strings.ToLower(name)
		for oldName := range headers {
			if strings.EqualFold(oldName, canonicalName) {
				return nil, errors.New("MCP header names must be unique, ignoring case")
			}
		}
		headers[name] = headerValue
	}
	return headers, nil
}

func mcpHeaderPlaceholderNames(value string) ([]string, error) {
	var names []string
	for offset := 0; ; {
		start := strings.Index(value[offset:], "${")
		if start < 0 {
			if strings.Contains(value[offset:], "}") {
				return nil, errors.New("invalid MCP header placeholder")
			}
			return names, nil
		}
		start += offset
		if strings.Contains(value[offset:start], "}") {
			return nil, errors.New("invalid MCP header placeholder")
		}
		end := strings.IndexByte(value[start+2:], '}')
		if end < 0 {
			return nil, errors.New("invalid MCP header placeholder")
		}
		end += start + 2
		name := value[start+2 : end]
		if !validMCPSecretPart(name, false) {
			return nil, errors.New("invalid MCP header placeholder")
		}
		names = append(names, name)
		offset = end + 1
	}
}

func (r *Runner) registerMCPRemoteServer(ctx context.Context, client sdk.Client, name, rawURL string, headers, secretHeaders map[string]string, oauthAuthorizationServer, clientID, resource string, scopes []string, noScope bool, callbackPort int, disableHTTP2, skipAuth bool) error {
	service := sdk.MCP(client)
	registration, err := service.Register(ctx, sdk.MCPServerConfig{Name: name, URL: rawURL, Headers: headers, SecretHeaders: secretHeaders, OAuthAuthorizationServer: oauthAuthorizationServer, ClientID: clientID, Resource: resource, Scopes: append([]string(nil), scopes...), NoScope: noScope, CallbackPort: callbackPort, DisableHTTP2: disableHTTP2, SkipAuth: skipAuth})
	if err != nil {
		return err
	}
	if registration == nil || !registration.ApprovalRequired || registration.ApprovalID == "" {
		return errors.New("daemon returned an invalid MCP registration challenge")
	}
	_, _ = fmt.Fprintf(r.Out, "MCP server %q requires host approval (challenge %s).\n", name, registration.ApprovalID)
	return nil
}

func prepareMCPCommand(command, directory string) (string, string, error) {
	resolved, err := exec.LookPath(command)
	if err != nil {
		return "", "", fmt.Errorf("resolve MCP command: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", "", err
	}
	if directory == "" {
		directory, err = os.Getwd()
		if err != nil {
			return "", "", err
		}
	}
	if !filepath.IsAbs(directory) {
		directory, err = filepath.Abs(directory)
	}
	return resolved, directory, err
}

func (r *Runner) registerMCPServer(ctx context.Context, client sdk.Client, name, command string, args []string, directory string) error {
	service := sdk.MCP(client)
	registration, err := service.Register(ctx, sdk.MCPServerConfig{Name: name, Command: command, Arguments: append([]string(nil), args...), WorkingDirectory: directory})
	if err != nil {
		return err
	}
	if registration == nil || !registration.ApprovalRequired || registration.ApprovalID == "" {
		return errors.New("daemon returned an invalid MCP registration challenge")
	}
	message := mcpRegistrationApprovalMessage(name, command, args, directory)
	approved, err := r.confirmMCPApproval(message)
	if err != nil {
		return err
	}
	if !approved {
		_, _ = fmt.Fprintln(r.Out, "MCP registration canceled")
		return nil
	}
	server, err := service.ApproveRegistration(ctx, registration.ApprovalID)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(r.Out, "Registered MCP server %s\n", server.Name)
	return err
}

func mcpRegistrationApprovalMessage(name, command string, args []string, directory string) string {
	return fmt.Sprintf("Register host MCP server %q\n  command: %s\n  argument count: %d (values hidden; do not configure secrets here)\n  directory: %s", name, command, len(args), directory)
}

func (r *Runner) mcpCall(ctx context.Context, args []string) int {
	var raw string
	fs := r.newFlagSet("mcp call")
	fs.SetOutput(io.Discard)
	fs.StringVar(&raw, strings.TrimPrefix(mcpArgsFlagName, "--"), "{}", "JSON object passed to the tool")
	fs.Usage = func() { r.showCommandHelp(mcpCallHelp()) }
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{mcpArgsFlagName: true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp call", err)
	}
	if fs.NArg() != 3 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp call SANDBOX SERVER TOOL [--args JSON]")
		return 2
	}
	object, err := validateMCPCallArguments(raw)
	if err != nil {
		_, _ = fmt.Fprintln(r.Err, err)
		return 2
	}
	if err := requireMCPApprovalTerminal(r.In); err != nil {
		r.error(err)
		return 1
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	service := sdk.MCP(client)
	result, err := service.Call(ctx, fs.Arg(0), fs.Arg(1), fs.Arg(2), json.RawMessage(raw))
	if err == nil {
		_, _ = fmt.Fprintln(r.Out, string(result))
		return 0
	}
	var challenge *sdk.MCPApprovalRequiredError
	if !errors.As(err, &challenge) {
		r.error(err)
		return 1
	}
	message := mcpCallApprovalMessage(fs.Arg(1), fs.Arg(2), fs.Arg(0), object)
	approved, confirmErr := r.confirmMCPApproval(message)
	if confirmErr != nil {
		r.error(confirmErr)
		return 1
	}
	if !approved {
		_, _ = fmt.Fprintln(r.Out, "MCP tool call canceled")
		return 0
	}
	result, err = service.ApproveCall(ctx, challenge.ApprovalID)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintln(r.Out, string(result))
	return 0
}

func validateMCPCallArguments(raw string) (map[string]json.RawMessage, error) {
	if len(raw) > 16<<10 {
		return nil, errors.New("mcp call: approval display is limited to 16 KiB of arguments")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &object); err != nil || object == nil {
		return nil, errors.New("mcp call: --args must be a JSON object")
	}
	return object, nil
}

func mcpCallApprovalMessage(server, tool, sandbox string, arguments map[string]json.RawMessage) string {
	return fmt.Sprintf("Request trusted host approval to run MCP tool %s.%s in sandbox %s?\n  argument fields: %d (values hidden)", server, tool, sandbox, len(arguments))
}

func (r *Runner) mcpRemove(ctx context.Context, args []string) int {
	fs := r.newFlagSet("mcp rm")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(mcpRemoveHelp()) }
	force := fs.Bool("force", false, "skip confirmation")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp rm", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, mcpRemoveUsage)
		return 2
	}
	if !*force {
		confirmed, err := r.confirmMCPApproval("Remove MCP server registration " + fs.Arg(0) + "?")
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "MCP removal canceled")
			return 0
		}
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	removed, err := sdk.MCP(client).Remove(ctx, fs.Arg(0))
	if err != nil {
		r.error(err)
		return 1
	}
	if removed {
		_, _ = fmt.Fprintf(r.Out, "Removed MCP server %s\n", fs.Arg(0))
	} else {
		_, _ = fmt.Fprintf(r.Out, "MCP server %s not found\n", fs.Arg(0))
	}
	return 0
}

func (r *Runner) confirmMCPApproval(message string) (bool, error) {
	if err := requireMCPApprovalTerminal(r.In); err != nil {
		return false, err
	}
	if _, err := fmt.Fprintf(r.Err, "%s\nApprove? [y/N] ", message); err != nil {
		return false, err
	}
	var answer string
	if _, err := fmt.Fscanln(r.In, &answer); err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == answerShortYes || answer == answerYes, nil
}

// requireMCPApprovalTerminal is replaceable in tests; production requires a
// real interactive terminal before any host-side MCP action.
var requireMCPApprovalTerminal = func(input io.Reader) error {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return errors.New("MCP approval requires an interactive terminal; no host action was approved")
	}
	return nil
}

type mcpServerRow struct {
	Name                          string `json:"name" yaml:"name"`
	Gateway                       string `json:"gateway" yaml:"gateway"`
	Transport                     string `json:"transport" yaml:"transport"`
	Loaded                        bool   `json:"loaded" yaml:"loaded"`
	Usable                        bool   `json:"usable" yaml:"usable"`
	AuthRequired                  bool   `json:"auth_required" yaml:"auth_required"`
	AuthConfigured                bool   `json:"auth_configured" yaml:"auth_configured"`
	HasCustomHeaders              bool   `json:"has_custom_headers" yaml:"has_custom_headers"`
	CustomHeadersSupported        bool   `json:"custom_headers_supported" yaml:"custom_headers_supported"`
	CustomHeaderSecretsConfigured bool   `json:"custom_header_secrets_configured" yaml:"custom_header_secrets_configured"`
}

func mcpServerRows(servers []sdk.MCPServer) []mcpServerRow {
	out := make([]mcpServerRow, 0, len(servers))
	for _, s := range servers {
		out = append(out, mcpServerRow{s.Name, s.Gateway, s.Transport, s.Loaded, s.Usable, s.AuthRequired, s.AuthConfigured, s.HasCustomHeaders, s.CustomHeadersSupported, s.CustomHeaderSecretsConfigured})
	}
	return out
}
func mcpUsability(server sdk.MCPServer) string {
	if !server.Usable {
		return "unusable"
	}
	if server.AuthRequired && !server.AuthConfigured {
		return "auth required"
	}
	return "usable"
}

const mcpLoadUsage = `usage: rsbx mcp load NAME --sandbox SANDBOX

Attach a previously-registered MCP server to a sandbox's gateway.
`

const mcpUnloadUsage = `usage: rsbx mcp unload NAME --sandbox SANDBOX

Detach an MCP server from a running sandbox's gateway.
`

const mcpInspectUsage = `usage: rsbx mcp inspect NAME [flags]

Show MCP server details.
`

type mcpInspectOutput struct {
	Name                string `json:"name" yaml:"name"`
	SandboxID           string `json:"sandbox_id,omitempty" yaml:"sandbox_id,omitempty"`
	IdentityDisplayName string `json:"identity_display_name,omitempty" yaml:"identity_display_name,omitempty"`
	IdentityKind        string `json:"identity_kind,omitempty" yaml:"identity_kind,omitempty"`
	IdentityIssuerHost  string `json:"identity_issuer_host,omitempty" yaml:"identity_issuer_host,omitempty"`
	ToolsCount          int    `json:"tools_count,omitempty" yaml:"tools_count,omitempty"`
	LastSyncAt          string `json:"last_sync_at,omitempty" yaml:"last_sync_at,omitempty"`
	AuthStatus          string `json:"auth_status" yaml:"auth_status"`
	GatewayState        string `json:"gateway_state" yaml:"gateway_state"`
}

type mcpAuthStatusOutput struct {
	Name   string `json:"name" yaml:"name"`
	Status string `json:"status" yaml:"status"`
}

//nolint:dupl // load and unload share the same gateway-attach grammar by design.
func (r *Runner) mcpLoad(ctx context.Context, args []string) int {
	fs := r.newFlagSet("mcp load")
	fs.SetOutput(io.Discard)
	sandbox := fs.String("sandbox", "", "Target sandbox name (required)")
	fs.Usage = func() { r.showCommandHelp(mcpLoadHelp()) }
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{sandboxFlag: true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp load", err)
	}
	if fs.NArg() != 1 || *sandbox == "" {
		_, _ = fmt.Fprint(r.Err, mcpLoadUsage)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if err := sdk.MCPServerManagement(client).Load(ctx, fs.Arg(0), *sandbox); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

//nolint:dupl // load and unload share the same gateway-attach grammar by design.
func (r *Runner) mcpUnload(ctx context.Context, args []string) int {
	fs := r.newFlagSet("mcp unload")
	fs.SetOutput(io.Discard)
	sandbox := fs.String("sandbox", "", "Target sandbox name (required)")
	fs.Usage = func() { r.showCommandHelp(mcpUnloadHelp()) }
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{sandboxFlag: true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp unload", err)
	}
	if fs.NArg() != 1 || *sandbox == "" {
		_, _ = fmt.Fprint(r.Err, mcpUnloadUsage)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if err := sdk.MCPServerManagement(client).Unload(ctx, fs.Arg(0), *sandbox); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) mcpInspect(ctx context.Context, args []string) int {
	fs := r.newFlagSet("mcp inspect")
	fs.SetOutput(io.Discard)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	fs.Usage = func() { r.showCommandHelp(mcpInspectHelp()) }
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{formatFlag: true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp inspect", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, mcpInspectUsage)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	detail, err := sdk.MCPServerManagement(client).Inspect(ctx, fs.Arg(0), "")
	if err != nil {
		r.error(err)
		return 1
	}
	out := mcpInspectOutput{
		Name:                detail.Name,
		SandboxID:           detail.SandboxID,
		IdentityDisplayName: detail.IdentityDisplayName,
		IdentityKind:        detail.IdentityKind,
		IdentityIssuerHost:  detail.IdentityIssuerHost,
		ToolsCount:          detail.ToolsCount,
		AuthStatus:          mcpAuthStatusText(detail.AuthStatus),
		GatewayState:        mcpGatewayStateText(detail.GatewayState),
	}
	if !detail.LastSyncAt.IsZero() {
		out.LastSyncAt = detail.LastSyncAt.UTC().Format(time.RFC3339)
	}
	if err := r.renderMCPInspect(out, selected); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) renderMCPInspect(out mcpInspectOutput, format string) error {
	switch format {
	case listFormatJSON:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(out)
	case listFormatYAML:
		data, err := yaml.Marshal(out)
		if err != nil {
			return err
		}
		_, err = r.Out.Write(data)
		return err
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "name: %s\n", out.Name)
		if out.SandboxID != "" {
			fmt.Fprintf(&b, "sandbox_id: %s\n", out.SandboxID)
		}
		if out.IdentityDisplayName != "" {
			fmt.Fprintf(&b, "identity_display_name: %s\n", out.IdentityDisplayName)
		}
		if out.IdentityKind != "" {
			fmt.Fprintf(&b, "identity_kind: %s\n", out.IdentityKind)
		}
		if out.IdentityIssuerHost != "" {
			fmt.Fprintf(&b, "identity_issuer_host: %s\n", out.IdentityIssuerHost)
		}
		if out.ToolsCount != 0 {
			fmt.Fprintf(&b, "tools_count: %d\n", out.ToolsCount)
		}
		if out.LastSyncAt != "" {
			fmt.Fprintf(&b, "last_sync_at: %s\n", out.LastSyncAt)
		}
		fmt.Fprintf(&b, "auth_status: %s\n", out.AuthStatus)
		fmt.Fprintf(&b, "gateway_state: %s\n", out.GatewayState)
		_, err := io.WriteString(r.Out, b.String())
		return err
	}
}

func (r *Runner) mcpAuth(ctx context.Context, args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case daemonStatusCommand:
			return r.mcpAuthStatus(ctx, args[1:])
		case "rm":
			return r.mcpAuthRm(ctx, args[1:])
		}
	}
	return r.mcpAuthStart(ctx, args)
}

//nolint:gocognit,gocyclo,cyclop,funlen // auth status renders both text and JSON forms.
func (r *Runner) mcpAuthStatus(ctx context.Context, args []string) int {
	fs := r.newFlagSet("mcp auth status")
	fs.SetOutput(io.Discard)
	all := fs.Bool("all", false, "apply to all registered OAuth servers")
	format := fs.String("format", listFormatTable, "output format: text or json")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	fs.Usage = func() { r.showCommandHelp(mcpAuthStatusHelp()) }
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{formatFlag: true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp auth status", err)
	}
	name := ""
	if fs.NArg() > 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp auth status [SERVER] [flags]")
		return 2
	}
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	}
	if *all && name != "" {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp auth status [SERVER] [flags]")
		return 2
	}
	selected := listFormatTable
	if *format != "" {
		switch *format {
		case mcpAuthTextFormat, listFormatTable:
			selected = listFormatTable
		case listFormatJSON:
			selected = listFormatJSON
		default:
			r.error(fmt.Errorf("invalid format %q; use text or json", *format))
			return 2
		}
	}
	if *jsonOutput {
		if *format != "" && *format != mcpAuthTextFormat && *format != listFormatTable {
			r.error(errors.New("--json cannot be combined with an explicit --format"))
			return 2
		}
		selected = listFormatJSON
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	statuses, err := sdk.MCPServerManagement(client).AuthStatus(ctx, name, *all)
	if err != nil {
		r.error(err)
		return 1
	}
	rows := make([]mcpAuthStatusOutput, 0, len(statuses))
	for _, s := range statuses {
		rows = append(rows, mcpAuthStatusOutput{Name: s.Name, Status: mcpAuthStatusText(s.Status)})
	}
	if selected == listFormatJSON {
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(rows); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
	for _, row := range rows {
		_, _ = fmt.Fprintf(r.Out, "%-24s %s\n", row.Name, row.Status)
	}
	return 0
}

//nolint:gocognit,gocyclo,cyclop,nestif,funlen // auth removal handles all/single and text/JSON forms.
func (r *Runner) mcpAuthRm(ctx context.Context, args []string) int {
	fs := r.newFlagSet("mcp auth rm")
	fs.SetOutput(io.Discard)
	all := fs.Bool("all", false, "apply to all registered OAuth servers")
	force := fs.Bool("force", false, "skip confirmation prompts")
	format := fs.String("format", listFormatTable, "output format: text or json")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	fs.Usage = func() { r.showCommandHelp(mcpAuthRmHelp()) }
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{formatFlag: true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp auth rm", err)
	}
	name := ""
	if fs.NArg() > 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp auth rm [SERVER] [flags]")
		return 2
	}
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	}
	if *all && name != "" {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp auth rm [SERVER] [flags]")
		return 2
	}
	if !*all && name == "" {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp auth rm [SERVER] [flags]")
		return 2
	}
	if !*force {
		target := name
		if *all {
			target = "all registered OAuth servers"
		}
		confirmed, err := r.confirmMCPApproval("Remove MCP OAuth credentials for " + target + "?")
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "MCP OAuth removal canceled")
			return 0
		}
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if *all {
		statuses, err := sdk.MCPServerManagement(client).AuthStatus(ctx, "", true)
		if err != nil {
			r.error(err)
			return 1
		}
		for _, s := range statuses {
			removed, err := sdk.MCPServerManagement(client).RemoveAuth(ctx, s.Name)
			if err != nil {
				r.error(err)
				return 1
			}
			if !*jsonOutput && *format != listFormatJSON {
				if removed {
					_, _ = fmt.Fprintf(r.Out, "Removed MCP OAuth credentials for %s\n", s.Name)
				} else {
					_, _ = fmt.Fprintf(r.Out, "No MCP OAuth credentials stored for %s\n", s.Name)
				}
			}
		}
		return 0
	}
	removed, err := sdk.MCPServerManagement(client).RemoveAuth(ctx, name)
	if err != nil {
		r.error(err)
		return 1
	}
	jsonRequested := *jsonOutput
	if *format == listFormatJSON {
		jsonRequested = true
	}
	if *format != "" && *format != mcpAuthTextFormat && *format != listFormatTable && *format != listFormatJSON {
		r.error(fmt.Errorf("invalid format %q; use text or json", *format))
		return 2
	}
	if *jsonOutput && *format != "" && *format != mcpAuthTextFormat && *format != listFormatTable {
		r.error(errors.New("--json cannot be combined with an explicit --format"))
		return 2
	}
	if jsonRequested {
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(map[string]any{"removed": removed, "name": name}); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
	if removed {
		_, _ = fmt.Fprintf(r.Out, "Removed MCP OAuth credentials for %s\n", sanitizeTerminalText(name))
	} else {
		_, _ = fmt.Fprintf(r.Out, "No MCP OAuth credentials stored for %s\n", sanitizeTerminalText(name))
	}
	return 0
}

func (r *Runner) mcpAuthStart(ctx context.Context, args []string) int {
	var scopes stringSliceFlag
	fs := r.newFlagSet("mcp auth")
	fs.SetOutput(io.Discard)
	all := fs.Bool("all", false, "apply to all registered OAuth servers")
	format := fs.String("format", listFormatTable, "output format: text or json")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	noScope := fs.Bool("no-scope", false, "request no scopes at all for this run")
	verbose := fs.Bool("verbose", false, "print authorization polling progress")
	fs.Var(&scopes, "scope", "OAuth scope to authorize for this run (repeatable)")
	fs.Usage = func() { r.showCommandHelp(mcpAuthHelp()) }
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{formatFlag: true, "--scope": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("mcp auth", err)
	}
	if len(scopes) > 0 && *noScope {
		r.error(errors.New("MCP scopes and no scope are mutually exclusive"))
		return 2
	}
	name := ""
	if fs.NArg() > 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp auth [SERVER] [flags]")
		return 2
	}
	if fs.NArg() == 1 {
		name = fs.Arg(0)
	}
	if *all && name != "" {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx mcp auth [SERVER] [flags]")
		return 2
	}
	_ = verbose
	_ = format
	_ = jsonOutput
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	challenge, err := sdk.MCPServerManagement(client).StartAuth(ctx, sdk.MCPAuthStartRequest{Name: name, All: *all, Scopes: scopes, NoScope: *noScope})
	if err != nil {
		r.error(err)
		return 1
	}
	if challenge.ApprovalID != "" {
		_, _ = fmt.Fprintf(r.Out, "Authorization started (%s)\n", sanitizeTerminalText(challenge.ApprovalID))
	}
	return 0
}

func mcpAuthStatusText(status sdk.MCPAuthStatus) string {
	switch status {
	case sdk.MCPAuthStatusUnspecified:
		return debugUnknown
	default:
		return string(status)
	}
}

func mcpGatewayStateText(state sdk.MCPGatewayState) string {
	switch state {
	case sdk.MCPGatewayStateUnspecified:
		return debugUnknown
	default:
		return string(state)
	}
}
