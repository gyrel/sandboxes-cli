package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

type policyRuleOutput struct {
	RuleID       string `json:"rule_id" yaml:"rule_id"`
	Scope        string `json:"scope" yaml:"scope"`
	ResourceType string `json:"resource_type" yaml:"resource_type"`
	Action       string `json:"action" yaml:"action"`
	Provenance   string `json:"provenance" yaml:"provenance"`
	Origin       string `json:"origin" yaml:"origin"`
	Protocol     string `json:"protocol" yaml:"protocol"`
	CIDR         string `json:"cidr,omitempty" yaml:"cidr,omitempty"`
	Domain       string `json:"domain,omitempty" yaml:"domain,omitempty"`
	Path         string `json:"path,omitempty" yaml:"path,omitempty"`
	Access       string `json:"access,omitempty" yaml:"access,omitempty"`
	Port         uint16 `json:"port" yaml:"port"`
}

const policyListUsage = `usage: rsbx policy ls [SANDBOX] [--format table|json|yaml] [--json]

List global and sandbox allow/deny rules.
`

const policyCheckUsage = `usage: rsbx policy check SANDBOX IP PORT [PROTOCOL]

Evaluate a request against a sandbox's stored network rules.
`

const policyCheckNetworkUsage = `usage: rsbx policy check network [--sandbox NAME] [--protocol tcp|udp] [--format table|json|yaml] [--json] TARGET

Evaluate an IPv4[:PORT], IPv6[:PORT], domain[:PORT], or http(s) URL target.
Bare targets without a port default to 443.
The SDK does not expose governance.active or deny_kind, so those fields are omitted.
`

const policyCheckFilesystemUsage = `usage: rsbx policy check filesystem --sandbox NAME [--write] PATH

Evaluate whether a guest path is readable or writable.
`

const policyInitUsage = `usage: rsbx policy init allow-all|balanced|deny-all

Set the global default policy profile.
`

const policyProfileUsage = `usage: rsbx policy profile [ls]

Show the global default profile and the available profiles.
`

func policyMutateUsage(action string) string {
	return fmt.Sprintf(`usage: rsbx policy %s SANDBOX CIDR[:PORT]
       rsbx policy %s network [--sandbox NAME] CIDR[:PORT]|DOMAIN

Add or remove a network policy rule.
`, action, action)
}

func policyMutateNetworkUsage(action string) string {
	return fmt.Sprintf(`usage: rsbx policy %s network [--sandbox NAME] CIDR[:PORT]|DOMAIN

Flags may appear before, between or after arguments; use -- to end flag parsing.
`, action)
}

//nolint:cyclop,gocyclo // one command dispatch switch with one case per subcommand.
func (r *Runner) policy(ctx context.Context, args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, policyUsage)
		return 2
	}
	switch args[0] {
	case "ls":
		return r.policyList(ctx, args[1:])
	case commandInspect:
		return r.policyInspect(ctx, args[1:])
	case "check":
		if len(args) > 1 && args[1] == networkKeyword {
			return r.policyCheckNetwork(ctx, args[2:])
		}
		if len(args) > 1 && args[1] == filesystemKeyword {
			return r.policyCheckFilesystem(ctx, args[2:])
		}
		return r.policyCheck(ctx, args[1:])
	case actionAllow, actionDeny, "rm":
		if len(args) > 1 && args[1] == networkKeyword {
			return r.policyMutateNetwork(ctx, args[0], args[2:])
		}
		return r.policyMutate(ctx, args[0], args[1:])
	case "init":
		return r.policyInit(ctx, args[1:])
	case "profile":
		return r.policyProfile(ctx, args[1:])
	case orgScope:
		return r.policyOrg(ctx, args[1:])
	case "log":
		return r.policyLog(ctx, args[1:])
	case "refresh":
		return r.policyRefresh(ctx, args[1:])
	case commandReset:
		return r.policyReset(ctx, args[1:])
	case "approval":
		if hasFlag(args[1:], helpFlag) || hasFlag(args[1:], helpShort) {
			_, _ = fmt.Fprint(r.Out, policyUsage)
			return 0
		}
		return r.policyUnsupported("approval", "approval-gated operations are not implemented, so no approvals can be pending")
	case helpCommand, helpShort, helpFlag:
		_, _ = fmt.Fprint(r.Out, policyUsage)
		return 0
	default:
		_, _ = fmt.Fprintf(r.Err, "rsbx policy: unknown subcommand %q\n", args[0])
		_, _ = fmt.Fprint(r.Err, policyUsage)
		return 2
	}
}

// policyRefresh forces the daemon to re-apply effective policy to running
// sandboxes immediately.
func (r *Runner) policyRefresh(ctx context.Context, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		_, _ = fmt.Fprintln(r.Out, "usage: rsbx policy refresh")
		_, _ = fmt.Fprintln(r.Out, "Re-apply the effective policy to running sandboxes.")
		return 0
	}
	if len(args) != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx policy refresh")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	applied, err := sdk.Policies(client).Refresh(ctx)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "refreshed policy on %d running sandbox(s)\n", applied)
	return 0
}

// policyReset removes all custom global rules and restores the default
// profile. Sandbox-scoped rules are kept. Confirmation is required unless
// --force is given.
func (r *Runner) policyReset(ctx context.Context, args []string) int {
	force := false
	for _, arg := range args {
		if arg == "--force" || arg == "-f" {
			force = true
			continue
		}
		if arg == helpFlag || arg == helpShort {
			_, _ = fmt.Fprintln(r.Out, "usage: rsbx policy reset [--force]")
			return 0
		}
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx policy reset [--force]")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	policies := sdk.Policies(client)
	allow, deny, err := policies.GetGlobalPolicy(ctx)
	if err != nil {
		r.error(err)
		return 1
	}
	if !force && len(allow)+len(deny) > 0 {
		confirmed, err := r.confirmResetPolicy(len(allow) + len(deny))
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "reset canceled")
			return 0
		}
	}
	remainingAllow, remainingDeny, profile, err := policies.ResetGlobal(ctx)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "reset global policy (profile=%s, allow=%d, deny=%d)\n", profile, len(remainingAllow), len(remainingDeny))
	return 0
}

func (r *Runner) confirmResetPolicy(count int) (bool, error) {
	return r.confirmDestructive("policy reset", fmt.Sprintf("Remove all %d custom global policy rule(s)? Sandbox rules are kept.", count))
}

func (r *Runner) policyUnsupported(name, reason string) int {
	_, _ = fmt.Fprintf(r.Err, "rsbx policy %s: %s\n", name, reason)
	return 1
}

// policyNetworkScope parses the shared `policy <verb> network [--sandbox NAME]`
// grammar used by the Docker sbx baseline. An empty sandbox name means the
// global scope, which the local runtime does not implement.
func (r *Runner) policyNetworkScope(cmdPath string, args []string) (sandboxName string, rest []string, code int) {
	args = reorderFlagArgs(args, map[string]bool{sandboxFlag: true})
	fs := flag.NewFlagSet(cmdPath, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&sandboxName, "sandbox", "", "scope the rule to one sandbox (global scope is not implemented locally)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", nil, 0
		}
		return "", nil, r.flagParseFailure(cmdPath, err)
	}
	return sandboxName, fs.Args(), -1
}

func (r *Runner) policyMutateNetwork(ctx context.Context, action string, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		_, _ = fmt.Fprint(r.Out, policyMutateNetworkUsage(action))
		return 0
	}
	sandboxName, rest, code := r.policyNetworkScope("policy "+action+" network", args)
	if code >= 0 {
		return code
	}
	if len(rest) != 1 {
		_, _ = fmt.Fprint(r.Err, policyMutateNetworkUsage(action))
		return 2
	}
	if sandboxName == "" {
		return r.policyMutateGlobal(ctx, action, rest[0])
	}
	return r.policyMutate(ctx, action, []string{sandboxName, rest[0]})
}

func globalPolicyForList(ctx context.Context, client sdk.Client) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	allow, deny, err := sdk.Policies(client).GetGlobalPolicy(ctx)
	var sdkErr *sdk.Error
	if errors.As(err, &sdkErr) && sdkErr.Code == "unsupported" {
		return nil, nil, nil
	}
	return allow, deny, err
}

func (r *Runner) policyMutateGlobal(ctx context.Context, action, value string) int {
	rule, err := parseNetworkRule(value)
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
	allow, deny, err := sdk.Policies(client).MutateGlobalPolicy(ctx, action, rule)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "updated global policy (allow=%d deny=%d)\n", len(allow), len(deny))
	return 0
}

//nolint:funlen,gocyclo,cyclop // one command parses flags, resolves the target and reports.
func (r *Runner) policyCheckNetwork(ctx context.Context, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		_, _ = fmt.Fprint(r.Out, policyCheckNetworkUsage)
		return 0
	}
	args = reorderFlagArgs(args, map[string]bool{sandboxFlag: true, formatFlag: true, "--protocol": true})
	fs := flag.NewFlagSet("policy check network", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { _, _ = fmt.Fprint(r.Out, policyCheckNetworkUsage) }
	sandboxName := fs.String("sandbox", "", "scope the check to one sandbox")
	protocol := fs.String("protocol", tcpProtocol, "protocol to evaluate: tcp or udp")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("policy check network", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, policyCheckNetworkUsage)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	selectedProtocol := strings.ToLower(*protocol)
	if selectedProtocol != tcpProtocol && selectedProtocol != udpProtocol {
		r.error(errors.New("protocol must be tcp or udp"))
		return 2
	}
	address, domain, port, err := parsePolicyCheckNetworkTarget(fs.Arg(0))
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
	id := ""
	if *sandboxName != "" {
		id, err = findExecSandbox(ctx, client, *sandboxName)
		if err != nil {
			r.error(err)
			return 1
		}
	}
	decision, err := sdk.Policies(client).Check(ctx, id, selectedProtocol, address, domain, port)
	if err != nil {
		r.error(err)
		return 1
	}
	policyContext := "global"
	if *sandboxName != "" {
		policyContext = sandboxPrefix + ":" + *sandboxName
	}
	host := address
	if host == "" {
		host = domain
	}
	if err := renderPolicyCheckNetwork(r.Out, selected, newPolicyCheckNetworkOutput(decision, selectedProtocol, policyContext, host, port)); err != nil {
		r.error(err)
		return 1
	}
	if decision.Allowed {
		return 0
	}
	return 1
}

// parsePolicyCheckNetworkTarget resolves an IP or domain target. A bare target
// without an explicit port defaults to 443; URL targets keep their scheme
// default (80/443).
func parsePolicyCheckNetworkTarget(target string) (string, string, uint16, error) {
	host, port, err := parsePolicyTarget(target)
	if err != nil {
		return "", "", 0, err
	}
	address := ""
	domain := ""
	if host == nil {
		domain, port, err = parsePolicyNameTarget(target)
		if err != nil {
			return "", "", 0, err
		}
	} else {
		address = host.String()
	}
	if port == 0 {
		port = 443
	}
	return address, domain, port, nil
}

// policyCheckNetworkOutput mirrors the Docker sbx check result. action,
// context, resource_type, resource_value, target and type are derived from the
// checked target, while rule_id and reason are retained only when the SDK
// supplies them. The current SDK exposes neither governance.active nor
// deny_kind, so those fields are intentionally omitted.
type policyCheckNetworkOutput struct {
	Action        string `json:"action" yaml:"action"`
	Allowed       bool   `json:"allowed" yaml:"allowed"`
	Context       string `json:"context" yaml:"context"`
	ResourceType  string `json:"resource_type" yaml:"resource_type"`
	ResourceValue string `json:"resource_value" yaml:"resource_value"`
	Target        string `json:"target" yaml:"target"`
	Type          string `json:"type" yaml:"type"`
	RuleID        string `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
	Reason        string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

const (
	policyNetworkActionPrefix = "net:connect:"
	policyNetworkResourceType = "net:domain"
	policyNetworkType         = "network"
)

func newPolicyCheckNetworkOutput(decision sdk.PolicyDecision, protocol, policyContext, host string, port uint16) policyCheckNetworkOutput {
	portText := strconv.FormatUint(uint64(port), 10)
	resourceValue := host + ":" + portText
	normalizedTarget := net.JoinHostPort(host, portText)
	return policyCheckNetworkOutput{
		Action:        policyNetworkActionPrefix + protocol,
		Allowed:       decision.Allowed,
		Context:       policyContext,
		ResourceType:  policyNetworkResourceType,
		ResourceValue: resourceValue,
		Target:        normalizedTarget,
		Type:          policyNetworkType,
		RuleID:        decision.RuleID,
		Reason:        decision.Reason,
	}
}

func renderPolicyCheckNetwork(out io.Writer, format string, result policyCheckNetworkOutput) error {
	switch format {
	case listFormatTable:
		verb := "denied"
		if result.Allowed {
			verb = "allowed"
		}
		if result.Reason == "" {
			_, _ = fmt.Fprintln(out, verb)
			return nil
		}
		_, _ = fmt.Fprintf(out, "%s: %s\n", verb, result.Reason)
		return nil
	case listFormatYAML:
		data, err := yaml.Marshal(result)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
}

//nolint:nestif // parsing URL and host:port forms is inherently branchy.
func parsePolicyNameTarget(target string) (string, uint16, error) {
	var host string
	port := uint16(0)
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
			return "", 0, fmt.Errorf("unsupported policy target %q", target)
		}
		host = parsed.Hostname()
		switch {
		case parsed.Port() != "":
			value, err := strconv.ParseUint(parsed.Port(), 10, 16)
			if err != nil || value == 0 {
				return "", 0, errors.New("URL port must be 1..65535")
			}
			port = uint16(value)
		case parsed.Scheme == schemeHTTPS:
			port = 443
		case parsed.Scheme == "http":
			port = 80
		default:
			return "", 0, fmt.Errorf("URL scheme %q requires an explicit port", parsed.Scheme)
		}
	} else {
		host = target
		if index := strings.LastIndexByte(host, ':'); index > 0 {
			if value, err := strconv.ParseUint(host[index+1:], 10, 16); err == nil && value > 0 {
				port = uint16(value)
				host = host[:index]
			}
		}
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if err := validateCLIDomain(host); err != nil {
		return "", 0, fmt.Errorf("unsupported policy target %q", target)
	}
	return host, port, nil
}

// evaluatePolicyName evaluates domain rules for a hostname. Deny rules win
// across both scopes.
func evaluatePolicyName(allow, deny []sdk.NetworkRule, protocol, name string, port uint16) (bool, string) {
	matches := func(rules []sdk.NetworkRule) string {
		for i := range rules {
			rule := rules[i]
			if rule.Domain == "" {
				continue
			}
			ruleProtocol := rule.Protocol
			if ruleProtocol == "" {
				ruleProtocol = tcpProtocol
			}
			if ruleProtocol != protocol || (rule.Port != 0 && rule.Port != port) {
				continue
			}
			if domainRuleMatches(rule.Domain, name) {
				return rule.Domain
			}
		}
		return ""
	}
	if domain := matches(deny); domain != "" {
		return false, "deny rule " + domain
	}
	if domain := matches(allow); domain != "" {
		return true, "allow rule " + domain
	}
	return false, reasonDefaultDeny
}

func domainRuleMatches(pattern, name string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	switch {
	case strings.HasPrefix(pattern, "**."):
		suffix := strings.TrimPrefix(pattern, "**.")
		return name != suffix && strings.HasSuffix(name, "."+suffix)
	case strings.HasPrefix(pattern, "*."):
		suffix := strings.TrimPrefix(pattern, "*.")
		label, rest, found := strings.Cut(name, ".")
		return found && label != "" && rest == suffix
	}
	patternLabels := strings.Split(pattern, ".")
	nameLabels := strings.Split(name, ".")
	if len(patternLabels) != len(nameLabels) {
		return false
	}
	for i := range patternLabels {
		glob := strings.ReplaceAll(patternLabels[i], "[!", "[^")
		ok, err := path.Match(glob, nameLabels[i])
		if err != nil || !ok {
			return false
		}
	}
	return true
}

// parsePolicyTarget extracts a host and optional port from an IPv4/IPv6
// literal or an http(s) URL. A zero port means "any port".
func parsePolicyTarget(target string) (net.IP, uint16, error) {
	if strings.Contains(target, "://") {
		return parseURLPolicyTarget(target)
	}
	if host, portText, err := net.SplitHostPort(target); err == nil {
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, 0, errors.New("port must be 1..65535")
		}
		return net.ParseIP(host), uint16(port), nil
	}
	if strings.Count(target, ":") >= 1 && net.ParseIP(target) == nil {
		return nil, 0, fmt.Errorf("unsupported policy target %q; use IPv4[:PORT], IPv6[:PORT], or an http(s) URL", target)
	}
	return net.ParseIP(target), 0, nil
}

func parseURLPolicyTarget(target string) (net.IP, uint16, error) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return nil, 0, fmt.Errorf("unsupported policy target %q", target)
	}
	host := parsed.Hostname()
	if parsed.Port() != "" {
		port, err := strconv.ParseUint(parsed.Port(), 10, 16)
		if err != nil || port == 0 {
			return nil, 0, errors.New("URL port must be 1..65535")
		}
		return net.ParseIP(host), uint16(port), nil
	}
	if parsed.Scheme == "https" {
		return net.ParseIP(host), 443, nil
	}
	if parsed.Scheme == "http" {
		return net.ParseIP(host), 80, nil
	}
	return nil, 0, fmt.Errorf("URL scheme %q requires an explicit port", parsed.Scheme)
}

// evaluatePolicyTarget evaluates rules for a host; a zero port matches rules
// for any port (deny still wins over a narrower allow).
func evaluatePolicyTarget(allow, deny []sdk.NetworkRule, protocol string, ip net.IP, port uint16) (bool, string) {
	if port != 0 {
		return evaluatePolicy(allow, deny, protocol, ip, port)
	}
	matches := func(rules []sdk.NetworkRule) string {
		for i := range rules {
			rule := rules[i]
			ruleProtocol := rule.Protocol
			if ruleProtocol == "" {
				ruleProtocol = tcpProtocol
			}
			if ruleProtocol != protocol {
				continue
			}
			_, network, err := net.ParseCIDR(rule.CIDR)
			if err != nil || !network.Contains(ip) {
				continue
			}
			return rule.CIDR
		}
		return ""
	}
	if cidr := matches(deny); cidr != "" {
		return false, "deny rule " + cidr
	}
	if cidr := matches(allow); cidr != "" {
		return true, "allow rule " + cidr
	}
	return false, reasonDefaultDeny
}

func (r *Runner) policyList(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{formatFlag: true})
	fs := flag.NewFlagSet("policy ls", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { _, _ = fmt.Fprint(r.Out, policyListUsage) }
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("policy ls", err)
	}
	if fs.NArg() > 1 {
		_, _ = fmt.Fprint(r.Err, policyListUsage)
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
	globalAllow, globalDeny, err := globalPolicyForList(ctx, client)
	if err != nil {
		r.error(err)
		return 1
	}
	rules := policyRulesFrom("global", globalAllow, globalDeny)
	if fs.NArg() == 1 {
		id, err := findExecSandbox(ctx, client, fs.Arg(0))
		if err != nil {
			r.error(err)
			return 1
		}
		sb, err := client.Sandboxes().Get(ctx, id)
		if err != nil {
			r.error(err)
			return 1
		}
		rules = append(rules, policyRules(sb)...)
	}
	rules = r.appendOrgPolicyRules(ctx, rules)
	if err := renderPolicyRules(r.Out, selected, rules); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) policyInit(ctx context.Context, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		_, _ = fmt.Fprint(r.Out, policyInitUsage)
		return 0
	}
	if len(args) != 1 {
		_, _ = fmt.Fprint(r.Err, policyInitUsage)
		return 2
	}
	profile := args[0]
	if profile != "allow-all" && profile != policyProfileBalanced && profile != policyProfileDenyAll {
		_, _ = fmt.Fprintln(r.Err, "profile must be allow-all, balanced or deny-all")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	applied, err := sdk.Policies(client).SetPolicyProfile(ctx, profile)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "global policy profile: %s\n", applied)
	return 0
}

func (r *Runner) policyProfile(ctx context.Context, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		_, _ = fmt.Fprint(r.Out, policyProfileUsage)
		return 0
	}
	if len(args) > 1 || (len(args) == 1 && args[0] != "ls" && args[0] != commandList) {
		_, _ = fmt.Fprint(r.Err, policyProfileUsage)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	profile, err := sdk.Policies(client).GetPolicyProfile(ctx)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "global: %s\navailable: deny-all, balanced, allow-all\n", profile)
	return 0
}

func (r *Runner) policyMutate(ctx context.Context, action string, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		_, _ = fmt.Fprint(r.Out, policyMutateUsage(action))
		return 0
	}
	if len(args) != 2 {
		_, _ = fmt.Fprint(r.Err, policyMutateUsage(action))
		return 2
	}
	rule, err := parseNetworkRule(args[1])
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
	id, err := findExecSandbox(ctx, client, args[0])
	if err != nil {
		r.error(err)
		return 1
	}
	updated, err := sdk.Policies(client).MutatePolicy(ctx, id, action, rule)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "updated policy for %s (allow=%d deny=%d)\n", updated.Name, len(updated.Allow), len(updated.Deny))
	return 0
}

func (r *Runner) policyCheck(ctx context.Context, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		_, _ = fmt.Fprint(r.Out, policyCheckUsage)
		return 0
	}
	if len(args) != 3 && len(args) != 4 {
		_, _ = fmt.Fprint(r.Err, policyCheckUsage)
		return 2
	}
	protocol := tcpProtocol
	if len(args) == 4 {
		protocol = strings.ToLower(args[3])
	}
	if protocol != tcpProtocol && protocol != udpProtocol {
		r.error(errors.New("protocol must be tcp or udp"))
		return 2
	}
	ip, err := parsePolicyDestination(args[1])
	if err != nil {
		r.error(err)
		return 2
	}
	port, err := strconv.ParseUint(args[2], 10, 16)
	if err != nil || port == 0 {
		r.error(errors.New("port must be 1..65535"))
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	id, err := findExecSandbox(ctx, client, args[0])
	if err != nil {
		r.error(err)
		return 1
	}
	sb, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		r.error(err)
		return 1
	}
	allowed, reason := evaluatePolicy(sb.Allow, sb.Deny, protocol, ip, uint16(port))
	if allowed {
		_, _ = fmt.Fprintf(r.Out, "allowed: %s\n", reason)
		return 0
	}
	_, _ = fmt.Fprintf(r.Out, "denied: %s\n", reason)
	return 1
}

func parsePolicyDestination(value string) (net.IP, error) {
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, errors.New("destination must be a single IP address")
	}
	return ip, nil
}

func policyRules(sb *sdk.Sandbox) []policyRuleOutput {
	out := policyRulesFrom("sandbox", sb.Allow, sb.Deny)
	for _, workspace := range sb.Workspaces {
		readID := filesystemRuleID(workspace.Path, "read")
		out = append(out, policyRuleOutput{RuleID: readID, Scope: sandboxPrefix, ResourceType: filesystemKeyword,
			Action: actionAllow, Provenance: workspaceLabel, Origin: originLocal, Path: workspace.Path, Access: "read"})
		action := actionAllow
		if workspace.ReadOnly {
			action = actionDeny
		}
		out = append(out, policyRuleOutput{RuleID: filesystemRuleID(workspace.Path, "write"), Scope: sandboxPrefix, ResourceType: filesystemKeyword,
			Action: action, Provenance: workspaceLabel, Origin: originLocal, Path: workspace.Path, Access: "write"})
	}
	return out
}

func filesystemRuleID(targetPath, access string) string {
	sum := sha256.Sum256([]byte("filesystem\x00" + targetPath + "\x00" + access))
	return "rul_" + hex.EncodeToString(sum[:8])
}

// policyCheckFilesystem evaluates the workspace mount policy. The guest rootfs
// is read-only, so only declared workspaces can be written.
//
//nolint:gocyclo,cyclop,funlen // one command parses flags, selects the most specific workspace and reports.
func (r *Runner) policyCheckFilesystem(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{sandboxFlag: true})
	fs := flag.NewFlagSet("policy check filesystem", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { _, _ = fmt.Fprint(r.Out, policyCheckFilesystemUsage) }
	sandboxName := fs.String("sandbox", "", "scope the check to one sandbox")
	write := fs.Bool("write", false, "check write access instead of read")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("policy check filesystem", err)
	}
	if *sandboxName == "" || fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, policyCheckFilesystemUsage)
		return 2
	}
	target := path.Clean(fs.Arg(0))
	if !path.IsAbs(target) {
		r.error(errors.New("filesystem target must be an absolute guest path"))
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	id, err := findExecSandbox(ctx, client, *sandboxName)
	if err != nil {
		r.error(err)
		return 1
	}
	sb, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		r.error(err)
		return 1
	}
	var selected *sdk.Workspace
	selectedRoot := ""
	for i := range sb.Workspaces {
		root := path.Clean(sb.Workspaces[i].Path)
		if target != root && !strings.HasPrefix(target, root+"/") {
			continue
		}
		if len(root) > len(selectedRoot) {
			selected = &sb.Workspaces[i]
			selectedRoot = root
		}
	}
	if selected == nil {
		_, _ = fmt.Fprintln(r.Out, "denied: path is outside every writable workspace")
		return 1
	}
	if !*write {
		_, _ = fmt.Fprintf(r.Out, "allowed: workspace %s (read)\n", selectedRoot)
		return 0
	}
	if !selected.ReadOnly {
		_, _ = fmt.Fprintf(r.Out, "allowed: workspace %s (read-write)\n", selectedRoot)
		return 0
	}
	_, _ = fmt.Fprintf(r.Out, "denied: workspace %s is read-only\n", selectedRoot)
	return 1
}

func policyRulesFrom(scope string, allow, deny []sdk.NetworkRule) []policyRuleOutput {
	out := make([]policyRuleOutput, 0, len(allow)+len(deny))
	appendRules := func(action string, rules []sdk.NetworkRule) {
		for i := range rules {
			protocol := rules[i].Protocol
			if protocol == "" {
				protocol = tcpProtocol
			}
			out = append(out, policyRuleOutput{RuleID: rules[i].RuleID, Scope: scope, ResourceType: networkKeyword,
				Action: action, Provenance: "user", Origin: originLocal, Protocol: protocol, CIDR: rules[i].CIDR, Domain: rules[i].Domain, Port: rules[i].Port})
		}
	}
	appendRules("allow", allow)
	appendRules("deny", deny)
	return out
}

//nolint:gocognit // one renderer covers both resource sections and three formats.
func renderPolicyRules(out io.Writer, format string, rules []policyRuleOutput) error {
	switch format {
	case listFormatTable:
		if len(rules) == 0 {
			_, err := fmt.Fprintln(out, "No policy rules (default deny)")
			return err
		}
		_, _ = fmt.Fprintln(out, "NETWORK")
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		printedNetwork := false
		printedFilesystem := false
		for i := range rules {
			rule := rules[i]
			switch rule.ResourceType {
			case "filesystem":
				if !printedFilesystem {
					if printedNetwork {
						_, _ = fmt.Fprintln(tw)
					}
					_, _ = fmt.Fprintln(tw, "FILESYSTEM")
					_, _ = fmt.Fprintln(tw, "RULE ID\tSCOPE\tACTION\tPATH\tACCESS")
					printedFilesystem = true
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", rule.RuleID, rule.Scope, rule.Action, rule.Path, rule.Access)
			default:
				if !printedNetwork {
					if printedFilesystem {
						_, _ = fmt.Fprintln(tw)
					}
					_, _ = fmt.Fprintln(tw, "NETWORK")
					_, _ = fmt.Fprintln(tw, "RULE ID\tSCOPE\tORIGIN\tACTION\tPROTOCOL\tTARGET\tPORT")
					printedNetwork = true
				}
				target := rule.CIDR
				if rule.Domain != "" {
					target = rule.Domain
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\n", rule.RuleID, rule.Scope, rule.Origin, rule.Action, rule.Protocol, target, rule.Port)
			}
		}
		return tw.Flush()
	case listFormatYAML:
		data, err := yaml.Marshal(rules)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(rules)
	}
}

func evaluatePolicy(allow, deny []sdk.NetworkRule, protocol string, ip net.IP, port uint16) (bool, string) {
	matches := func(rules []sdk.NetworkRule) string {
		for i := range rules {
			rule := rules[i]
			ruleProtocol := rule.Protocol
			if ruleProtocol == "" {
				ruleProtocol = tcpProtocol
			}
			if ruleProtocol != protocol {
				continue
			}
			if rule.Port != 0 && rule.Port != port {
				continue
			}
			_, network, err := net.ParseCIDR(rule.CIDR)
			if err != nil || !network.Contains(ip) {
				continue
			}
			return rule.CIDR
		}
		return ""
	}
	if cidr := matches(deny); cidr != "" {
		return false, "deny rule " + cidr
	}
	if cidr := matches(allow); cidr != "" {
		return true, "allow rule " + cidr
	}
	return false, reasonDefaultDeny
}

const filesystemKeyword = "filesystem"

const policyUsage = `Usage: rsbx policy COMMAND

Commands:
  ls [SANDBOX] [--format table|json|yaml] list global and sandbox allow/deny rules
  inspect RULE_ID|SANDBOX [--format ...]  show one rule or sandbox policy
  log [SANDBOX] [--type all|network] [--limit N]
                                          show gateway audit decisions
  refresh/reset/approval                  not implemented; fail closed
  allow SANDBOX CIDR[:PORT]               add an allow rule (legacy local grammar)
  deny SANDBOX CIDR[:PORT]                add a deny rule (legacy local grammar)
  rm SANDBOX CIDR[:PORT]                  remove an allow or deny rule
  allow|deny|rm network [--sandbox NAME] RESOURCES
                                          Docker sbx grammar; omit --sandbox for
                                          global rules
  check SANDBOX IP PORT [PROTOCOL]        evaluate a request against stored rules
  check network [--sandbox NAME] [--protocol tcp|udp] [--format table|json|yaml] [--json] TARGET
                                          evaluate IPv4[:PORT], IPv6[:PORT], domain or URL
  check filesystem --sandbox NAME [--write] PATH
                                          evaluate a guest workspace path
  init allow-all|balanced|deny-all        set the global default profile
  profile [ls]                            show the global default and available profiles
  org [--format table|json|yaml]          show the effective organization policy,
                                          enforced vs advisory rules, or an empty state

policy refresh/reset/approval need daemon support and fail closed.
Default is deny-all.
`
