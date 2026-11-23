package command

import (
	"bufio"
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
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

// policyRuleOutput is the internal rule representation used by the table
// renderer and by rule lookup. Machine output is converted to the sbx schema
// by policyRuleJSONFrom.
type policyRuleOutput struct {
	RuleID       string
	Name         string
	SandboxID    string
	Scope        string
	ResourceType string
	Action       string
	Provenance   string
	Origin       string
	Protocol     string
	CIDR         string
	Domain       string
	Path         string
	Access       string
	Port         uint16
	Methods      []string
	HTTPPath     string
	Query        []sdk.QueryCondition
	Status       string
}

type policyProvenanceOutput struct {
	CreatedVia string `json:"created_via" yaml:"created_via"`
	Source     string `json:"source,omitempty" yaml:"source,omitempty"`
}

// policyRuleJSON is the rule shape emitted by `sbx policy ls --json`.
type policyRuleJSON struct {
	ID           string                 `json:"id" yaml:"id"`
	Name         string                 `json:"name" yaml:"name"`
	PolicyID     string                 `json:"policy_id" yaml:"policy_id"`
	Scope        string                 `json:"scope" yaml:"scope"`
	AppliesTo    string                 `json:"applies_to" yaml:"applies_to"`
	ResourceType string                 `json:"resource_type" yaml:"resource_type"`
	Decision     string                 `json:"decision" yaml:"decision"`
	Resources    []string               `json:"resources" yaml:"resources"`
	Origin       string                 `json:"origin" yaml:"origin"`
	Layer        string                 `json:"layer" yaml:"layer"`
	Status       string                 `json:"status" yaml:"status"`
	Editable     bool                   `json:"editable" yaml:"editable"`
	SandboxID    string                 `json:"sandbox_id,omitempty" yaml:"sandbox_id,omitempty"`
	Provenance   policyProvenanceOutput `json:"provenance" yaml:"provenance"`
	Actions      []string               `json:"actions" yaml:"actions"`
	// HTTP conditions are emitted only when present. The sbx JSON shape for
	// conditioned rules is not yet confirmed by a version-matched fixture, so
	// these are documented local extensions until the shared policy fixture
	// acceptance fixes the exact schema (PLAN §23.4 P1.2 acceptance).
	Methods []string          `json:"methods,omitempty" yaml:"methods,omitempty"`
	Path    string            `json:"path,omitempty" yaml:"path,omitempty"`
	Query   []policyQueryJSON `json:"query,omitempty" yaml:"query,omitempty"`
}

type policyQueryJSON struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
}

// policyListOutput is the top-level `sbx policy ls --json` object.
type policyListOutput struct {
	Rules []policyRuleJSON `json:"rules" yaml:"rules"`
}

const (
	policyCreatedViaDefault     = "default"
	policyCreatedViaAdded       = "added"
	policyCreatedViaProvisioned = "provisioned"
	policyCreatedViaApproval    = "approval"
	policyApprovalCommand       = "approval"
	policyProvenanceUser        = "user"
	policyStatusActive          = "active"
	policyStatusInactive        = "inactive"
	schemeHTTP                  = "http"
)

const policyCheckUsage = `usage: rsbx policy check SANDBOX IP PORT [PROTOCOL]

Evaluate a request against a sandbox's stored network rules.
`

const policyCheckNetworkUsage = `usage: rsbx policy check network [--sandbox NAME] [--protocol tcp|udp] [--method METHOD] [--format table|json|yaml] [--json] TARGET

Evaluate an IPv4[:PORT], IPv6[:PORT], domain[:PORT], or http(s) URL target.
Bare targets without a port default to 443. JSON and YAML emit sbx's verdict
shape: action, allowed, context, governance, resource_type, resource_value,
target and type. Exit 0 when allowed, 1 when denied.
`

const policyCheckFilesystemUsage = `usage: rsbx policy check filesystem --sandbox NAME [--write] PATH

Evaluate whether a guest path is readable or writable.
`

const policyInitUsage = `usage: rsbx policy init allow-all|balanced|deny-all

Set the global default policy profile.
`

const policyProfileUsage = `usage: rsbx policy profile [ls]

Show the global default policy profile. ls lists governance profiles.
`

func policyMutateUsage(action string) string {
	return fmt.Sprintf(`usage: rsbx policy %s SANDBOX CIDR[:PORT]
       rsbx policy %s network [--sandbox NAME] CIDR[:PORT]|DOMAIN

Add or remove a network policy rule.
`, action, action)
}

func policyMutateNetworkUsage(action string) string {
	return fmt.Sprintf(`usage: rsbx policy %s network [--sandbox NAME] [--method M[,M...]] [--path GLOB] [--query NAME=GLOB] CIDR[:PORT]|DOMAIN

Flags may appear before, between or after arguments; use -- to end flag parsing.
HTTP selectors require daemon API 0.0.31 or newer.
`, action)
}

//nolint:cyclop,gocyclo // one command dispatch switch with one case per subcommand.
func (r *Runner) policy(ctx context.Context, args []string) int {
	args, code, done := r.prepareFamilyArgs(policyCommand, args)
	if done {
		return code
	}
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
		return r.policyMutate(ctx, args[0], args[1:], networkHTTPSelectors{})
	case "init":
		return r.policyInit(ctx, args[1:])
	case helpNameProfile:
		return r.policyProfile(ctx, args[1:])
	case orgScope:
		return r.policyOrg(ctx, args[1:])
	case "log":
		return r.policyLog(ctx, args[1:])
	case "refresh":
		return r.policyRefresh(ctx, args[1:])
	case commandReset:
		return r.policyReset(ctx, args[1:])
	case policyApprovalCommand:
		if hasFlag(args[1:], helpFlag) || hasFlag(args[1:], helpShort) {
			return r.showCommandHelp(policyApprovalHelp())
		}
		return r.policyUnsupported(policyApprovalCommand, "approval-gated operations are not implemented, so no approvals can be pending")
	case helpCommand, helpShort, helpFlag:
		return r.showCommandHelp(policyHelp())
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
		return r.showCommandHelp(policyRefreshHelp())
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
			return r.showCommandHelp(policyResetHelp())
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
func (r *Runner) policyNetworkScope(cmdPath string, args []string) (sandboxName string, sel networkHTTPSelectors, rest []string, code int) {
	args = reorderFlagArgs(args, map[string]bool{
		sandboxFlag: true, methodFlag: true, "--path": true, "--query": true,
	})
	fs := r.newFlagSet(cmdPath)
	fs.SetOutput(io.Discard)
	fs.StringVar(&sandboxName, "sandbox", "", "scope the rule to one sandbox (global scope is not implemented locally)")
	fs.Var(&sel.methods, helpNameMethod, "restrict the rule to these HTTP methods (comma list or repeats)")
	fs.StringVar(&sel.path, "path", "", "restrict the rule to this HTTP path glob (** spans segments)")
	fs.Var(&sel.queries, "query", "require an HTTP query parameter name=glob (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", networkHTTPSelectors{}, nil, 0
		}
		return "", networkHTTPSelectors{}, nil, r.flagParseFailure(cmdPath, err)
	}
	return sandboxName, sel, fs.Args(), -1
}

func (r *Runner) policyMutateNetwork(ctx context.Context, action string, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		return r.showCommandHelp(policyMutateNetworkHelp(action))
	}
	if action == "rm" {
		return r.policyRemoveNetwork(ctx, args)
	}
	sandboxName, sel, rest, code := r.policyNetworkScope("policy "+action+" network", args)
	if code >= 0 {
		return code
	}
	if len(rest) != 1 {
		_, _ = fmt.Fprint(r.Err, policyMutateNetworkUsage(action))
		return 2
	}
	if sandboxName == "" {
		return r.policyMutateGlobal(ctx, action, rest[0], sel)
	}
	return r.policyMutate(ctx, action, []string{sandboxName, rest[0]}, sel)
}

// policyRemoveNetwork implements the reference `policy rm network` selectors
// that the local policy model can resolve: rule ID and resource. HTTP selectors
// are rejected explicitly because this build has no HTTP policy rules.
func (r *Runner) policyRemoveNetwork(ctx context.Context, args []string) int {
	opts, positional, code := r.parsePolicyRemoveNetworkArgs(args)
	if code != 0 {
		return code
	}
	resources, err := splitPolicyResources(opts.resource)
	if err != nil {
		return r.policyRemoveError(err.Error())
	}
	if positional != "" {
		rule, err := parseNetworkRule(positional)
		if err != nil {
			return r.policyRemoveError(err.Error())
		}
		resources = []sdk.NetworkRule{rule}
	}
	for i := range resources {
		if err := applyNetworkHTTPSelectors(&resources[i], opts.sel); err != nil {
			return r.policyRemoveError(err.Error())
		}
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	target, code := r.resolvePolicyRemovalTarget(ctx, client, opts.sandboxName)
	if code != 0 {
		return code
	}
	removals, err := resolvePolicyRemovals(target.scope, target.allow, target.deny, opts.id, resources)
	if err != nil {
		return r.policyRemoveError(err.Error())
	}
	confirmed, code := r.confirmPolicyRemovals(len(removals), opts.force)
	if code != 0 {
		return code
	}
	if !confirmed {
		_, _ = fmt.Fprintln(r.Out, "Removal canceled")
		return 0
	}
	return r.applyPolicyRemovals(ctx, client, target, removals)
}

type policyRemoveOptions struct {
	sandboxName string
	resource    string
	id          string
	force       bool
	sel         networkHTTPSelectors
}

//nolint:gocyclo,cyclop // one parser mirrors the reference selector flags.
func (r *Runner) parsePolicyRemoveNetworkArgs(args []string) (policyRemoveOptions, string, int) {
	args = reorderFlagArgs(args, map[string]bool{
		"--sandbox": true, "--resource": true, "--id": true,
		methodFlag: true, "--path": true, "--query": true,
	})
	fs := r.newFlagSet("policy rm network")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(policyMutateNetworkHelp("rm")) }
	var opts policyRemoveOptions
	var pathValue string
	var methods, queries stringListFlag
	var forceShort bool
	fs.StringVar(&opts.sandboxName, "sandbox", "", "scope the removal to a specific sandbox")
	fs.StringVar(&opts.resource, "resource", "", "remove by resource value(s), comma-separated")
	fs.StringVar(&opts.id, "id", "", "remove by rule ID")
	fs.StringVar(&pathValue, "path", "", "restrict the removal to this HTTP path glob")
	fs.Var(&methods, helpNameMethod, "restrict the removal to these HTTP methods")
	fs.Var(&queries, "query", "require an HTTP query parameter name=glob")
	fs.BoolVar(&opts.force, "force", false, "skip confirmation prompts")
	fs.BoolVar(&forceShort, "f", false, "skip confirmation prompts")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return policyRemoveOptions{}, "", 0
		}
		return policyRemoveOptions{}, "", r.policyRemoveFlagError(err)
	}
	opts.force = opts.force || forceShort
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if (set["method"] || set["path"] || set["query"]) && opts.id != "" {
		return policyRemoveOptions{}, "", r.policyRemoveError("--id cannot be combined with HTTP selectors; remove by ID alone")
	}
	if fs.NArg() > 1 {
		return policyRemoveOptions{}, "", r.policyRemoveError(fmt.Sprintf("accepts at most 1 positional argument, received %d", fs.NArg()))
	}
	positional := ""
	if fs.NArg() == 1 {
		positional = fs.Arg(0)
	}
	if positional != "" && (opts.id != "" || opts.resource != "") {
		return policyRemoveOptions{}, "", r.policyRemoveError("positional target cannot be combined with --id or --resource")
	}
	if opts.id != "" && opts.resource != "" {
		return policyRemoveOptions{}, "", r.policyRemoveError("--id and --resource cannot be combined; pass one selector")
	}
	if positional == "" && opts.id == "" && opts.resource == "" {
		return policyRemoveOptions{}, "", r.policyRemoveError("at least one selector is required: use --id or --resource")
	}
	opts.sel = networkHTTPSelectors{methods: methods, path: pathValue, queries: queries}
	return opts, positional, 0
}

type policyRemovalTarget struct {
	scope     string
	sandboxID string
	allow     []sdk.NetworkRule
	deny      []sdk.NetworkRule
}

func (r *Runner) resolvePolicyRemovalTarget(ctx context.Context, client sdk.Client, sandboxName string) (policyRemovalTarget, int) {
	if sandboxName == "" {
		allow, deny, err := globalPolicyForList(ctx, client)
		if err != nil {
			r.error(err)
			return policyRemovalTarget{}, 1
		}
		return policyRemovalTarget{scope: policyGlobalScope, allow: allow, deny: deny}, 0
	}
	sandboxID, err := findExecSandbox(ctx, client, sandboxName)
	if err != nil {
		r.error(err)
		return policyRemovalTarget{}, 1
	}
	sb, err := client.Sandboxes().Get(ctx, sandboxID)
	if err != nil {
		r.error(err)
		return policyRemovalTarget{}, 1
	}
	return policyRemovalTarget{
		scope: sandboxPrefix + ":" + sandboxName, sandboxID: sandboxID,
		allow: sb.Allow, deny: sb.Deny,
	}, 0
}

func (r *Runner) confirmPolicyRemovals(count int, force bool) (bool, int) {
	if force {
		return true, 0
	}
	if !r.stdinIsTerminal() {
		return false, r.policyRemoveError("stdin is not a terminal; pass --force to skip the confirmation")
	}
	_, _ = fmt.Fprintf(r.Err, "Remove %d network rule(s) from policy local? [y/N] ", count)
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		r.error(err)
		return false, 1
	}
	return affirmativeAnswer(answer), 0
}

func (r *Runner) applyPolicyRemovals(ctx context.Context, client sdk.Client, target policyRemovalTarget, removals []policyRemoval) int {
	for i := range removals {
		removal := removals[i]
		var err error
		if target.sandboxID == "" {
			_, _, err = sdk.Policies(client).MutateGlobalPolicy(ctx, "rm", removal.Rule)
		} else {
			_, err = sdk.Policies(client).MutatePolicy(ctx, target.sandboxID, "rm", removal.Rule)
		}
		if err != nil {
			r.error(err)
			return 1
		}
		if target.sandboxID == "" {
			_, _ = fmt.Fprintf(r.Out, "Removed rule from policy local: id=%s\n", removal.ID)
			continue
		}
		_, _ = fmt.Fprintf(r.Out, "Removed rule from policy local: id=%s (scope: %s)\n", removal.ID, target.scope)
	}
	return 0
}

func (r *Runner) policyRemoveError(message string) int {
	_, _ = fmt.Fprintf(r.Err, "error: %s\n  try: rsbx policy rm network --help\n", message)
	return 1
}

func (r *Runner) policyRemoveFlagError(err error) int {
	message := err.Error()
	if name, ok := strings.CutPrefix(message, "flag provided but not defined: -"); ok {
		message = "unknown flag: --" + name
	}
	return r.policyRemoveError(message)
}

type policyRemoval struct {
	ID   string
	Rule sdk.NetworkRule
}

func splitPolicyResources(value string) ([]sdk.NetworkRule, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]sdk.NetworkRule, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("--resource contains an empty value")
		}
		rule, err := parseNetworkRule(part)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

// resolvePolicyRemovals resolves selectors before any mutation so a partial
// selector set never removes only some of the requested rules.
func resolvePolicyRemovals(scope string, allow, deny []sdk.NetworkRule, ruleID string, resources []sdk.NetworkRule) ([]policyRemoval, error) {
	candidates := make([]policyRemoval, 0, len(allow)+len(deny))
	appendRules := func(action string, rules []sdk.NetworkRule) {
		for i := range rules {
			rule := rules[i]
			candidates = append(candidates, policyRemoval{ID: policyRuleIDForRemoval(scope, action, rule), Rule: rule})
		}
	}
	appendRules(actionAllow, allow)
	appendRules(actionDeny, deny)
	selected := make([]policyRemoval, 0, len(resources)+1)
	seen := map[string]bool{}
	add := func(removal policyRemoval) {
		if seen[removal.ID] {
			return
		}
		seen[removal.ID] = true
		selected = append(selected, removal)
	}
	if ruleID != "" {
		matched, err := policyRemovalByID(candidates, ruleID)
		if err != nil {
			return nil, err
		}
		add(matched)
	}
	for i := range resources {
		matched, err := policyRemovalByResource(candidates, resources[i])
		if err != nil {
			return nil, err
		}
		for i := range matched {
			add(matched[i])
		}
	}
	return selected, nil
}

func policyRemovalByID(candidates []policyRemoval, ruleID string) (policyRemoval, error) {
	for i := range candidates {
		if candidates[i].ID == ruleID || candidates[i].Rule.RuleID == ruleID {
			return candidates[i], nil
		}
	}
	return policyRemoval{}, fmt.Errorf("remove network rule: rule %q not found; use \"rsbx policy ls --wide\" to find rule IDs", ruleID)
}

func policyRemovalByResource(candidates []policyRemoval, resource sdk.NetworkRule) ([]policyRemoval, error) {
	matched := make([]policyRemoval, 0, 1)
	for i := range candidates {
		if networkRuleMatches(candidates[i].Rule, resource) {
			matched = append(matched, candidates[i])
		}
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("remove network rule: no rule matches resource %q; use \"rsbx policy ls --wide\" to find rule IDs", policyRemovalResource(resource))
	}
	return matched, nil
}

func policyRuleIDForRemoval(scope, action string, rule sdk.NetworkRule) string {
	tmp := policyRuleOutput{
		RuleID: rule.RuleID, Scope: scope, ResourceType: policyNetworkType, Action: action,
		Provenance: policyProvenanceUser, Origin: originLocal, Protocol: rule.Protocol,
		CIDR: rule.CIDR, Domain: rule.Domain, Port: rule.Port,
		Methods: rule.Methods, HTTPPath: rule.Path, Query: rule.Query,
	}
	return policyRuleJSONFrom(&tmp).ID
}

func networkRuleMatches(stored, target sdk.NetworkRule) bool {
	storedProtocol := stored.Protocol
	if storedProtocol == "" {
		storedProtocol = tcpProtocol
	}
	targetProtocol := target.Protocol
	if targetProtocol == "" {
		targetProtocol = tcpProtocol
	}
	if storedProtocol != targetProtocol || stored.CIDR != target.CIDR ||
		stored.Domain != target.Domain || stored.Port != target.Port {
		return false
	}
	// An authored selector must match the stored canonical form. Compare
	// case- and order-insensitively on methods; path and query compare
	// verbatim because the daemon rejects malformed globs at authoring.
	if canonicalMethodsKey(stored.Methods) != canonicalMethodsKey(target.Methods) {
		return false
	}
	if stored.Path != target.Path {
		return false
	}
	return canonicalQueryKey(stored.Query) == canonicalQueryKey(target.Query)
}

func policyRemovalResource(rule sdk.NetworkRule) string {
	target := rule.Domain
	if target == "" {
		target = rule.CIDR
	}
	if rule.Port != 0 {
		return target + ":" + strconv.FormatUint(uint64(rule.Port), 10)
	}
	return target
}

func globalPolicyForList(ctx context.Context, client sdk.Client) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	allow, deny, err := sdk.Policies(client).GetGlobalPolicy(ctx)
	var sdkErr *sdk.Error
	if errors.As(err, &sdkErr) && sdkErr.Code == "unsupported" {
		return nil, nil, nil
	}
	return allow, deny, err
}

func (r *Runner) policyMutateGlobal(ctx context.Context, action, value string, sel networkHTTPSelectors) int {
	rule, err := parseNetworkRule(value)
	if err != nil {
		r.error(err)
		return 2
	}
	if err := applyNetworkHTTPSelectors(&rule, sel); err != nil {
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
		return r.showCommandHelp(policyCheckNetworkHelp())
	}
	args = reorderFlagArgs(args, map[string]bool{sandboxFlag: true, formatFlag: true, protocolFlag: true, methodFlag: true})
	fs := r.newFlagSet("policy check network")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(policyCheckNetworkHelp()) }
	sandboxName := fs.String("sandbox", "", "scope the check to one sandbox")
	protocol := fs.String("protocol", tcpProtocol, "protocol to evaluate: tcp or udp")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	method := fs.String(helpNameMethod, "", "HTTP method to evaluate against method-conditioned rules")
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
	target := fs.Arg(0)
	address, domain, port, err := parsePolicyCheckNetworkTarget(target)
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
	prepared, err := preparePolicyCheckTarget(target, address, domain, port, *method)
	if err != nil {
		r.error(err)
		return 2
	}
	checkURL, checkMethod, displayHost, displayPort := prepared.url, prepared.method, prepared.host, prepared.port
	address, domain, port = prepared.address, prepared.domain, prepared.l4Port
	decision, err := sdk.Policies(client).Check(ctx, id, selectedProtocol, address, domain, port, checkURL, checkMethod)
	if err != nil {
		r.error(err)
		return 1
	}
	policyContext := policyGlobalScope
	if *sandboxName != "" {
		policyContext = sandboxPrefix + ":" + *sandboxName
	}
	if err := renderPolicyCheckNetwork(r.Out, selected, newPolicyCheckNetworkOutput(decision, selectedProtocol, policyContext, displayHost, displayPort)); err != nil {
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
// preparedPolicyCheckTarget carries both wire halves (L4 fields or URL) and
// the rendering host/port so the CLI never sends a URL together with an
// address (the daemon refuses that combination).
type preparedPolicyCheckTarget struct {
	address, domain string
	l4Port          uint16
	url, method     string
	host            string
	port            uint16
}

func preparePolicyCheckTarget(target, address, domain string, port uint16, method string) (preparedPolicyCheckTarget, error) {
	prepared := preparedPolicyCheckTarget{address: address, domain: domain, l4Port: port, host: address, port: port}
	if prepared.host == "" {
		prepared.host = domain
	}
	if !strings.Contains(target, "://") {
		if strings.TrimSpace(method) != "" {
			return prepared, errors.New("--method applies only to http(s) URL targets")
		}
		return prepared, nil
	}
	prepared.url = target
	prepared.method = strings.TrimSpace(method)
	// The daemon derives host, port, path and query from the URL; the parsed
	// values stay in host/port only for the human/JSON target rendering.
	prepared.address, prepared.domain, prepared.l4Port = "", "", 0
	return prepared, nil
}

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

type policyGovernanceOutput struct {
	Active bool `json:"active" yaml:"active"`
}

// policyCheckNetworkOutput mirrors the Docker sbx verdict shape exactly:
// action, allowed, context, governance, resource_type, resource_value, target
// and type. RuleID and Reason are kept for the human table only.
type policyCheckNetworkOutput struct {
	Action        string                 `json:"action" yaml:"action"`
	Allowed       bool                   `json:"allowed" yaml:"allowed"`
	Context       string                 `json:"context" yaml:"context"`
	Governance    policyGovernanceOutput `json:"governance" yaml:"governance"`
	ResourceType  string                 `json:"resource_type" yaml:"resource_type"`
	ResourceValue string                 `json:"resource_value" yaml:"resource_value"`
	Target        string                 `json:"target" yaml:"target"`
	Type          string                 `json:"type" yaml:"type"`
	RuleID        string                 `json:"-" yaml:"-"`
	Reason        string                 `json:"-" yaml:"-"`
}

const (
	policyGlobalScope         = "global"
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
		Governance:    policyGovernanceOutput{Active: false},
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
		verb := "Denied:"
		if result.Allowed {
			verb = "Allowed:"
		}
		governance := "Local policy only"
		if result.Governance.Active {
			governance = "Remote governance active"
		}
		_, _ = fmt.Fprintf(out, "  %-12s %s\n", verb, result.Target)
		_, _ = fmt.Fprintf(out, "  %-12s %s\n", "Governance:", governance)
		_, _ = fmt.Fprintf(out, "  %-12s %s\n", "Context:", result.Context)
		if !result.Allowed && result.Reason != "" {
			_, _ = fmt.Fprintf(out, "  %-12s %s\n", "Reason:", result.Reason)
		}
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
		case parsed.Scheme == schemeHTTP:
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
	if parsed.Scheme == schemeHTTP {
		return net.ParseIP(host), 80, nil
	}
	return nil, 0, fmt.Errorf("URL scheme %q requires an explicit port", parsed.Scheme)
}

// policyListOptions is the local subset of the Docker sbx `policy ls` filter
// surface. Governance-only fields are rejected explicitly instead of being
// silently ignored.
type policyListOptions struct {
	resourceType    string
	source          string
	decision        string
	createdVia      string
	protocol        string
	profile         string
	format          string
	wide            bool
	quiet           bool
	includeInactive bool
	json            bool
	hiddenInactive  int
}

func (o policyListOptions) hasFilters() bool {
	return o.resourceType != policyTypeAll || o.source != "" || o.decision != "" ||
		o.createdVia != "" || o.protocol != ""
}

func (o policyListOptions) filterRules(rules []policyRuleJSON) []policyRuleJSON {
	out := make([]policyRuleJSON, 0, len(rules))
	for i := range rules {
		if o.matches(&rules[i]) {
			out = append(out, rules[i])
		}
	}
	return out
}

func (o policyListOptions) matches(rule *policyRuleJSON) bool {
	if rule.Status == policyStatusInactive && !o.includeInactive {
		return false
	}
	switch o.resourceType {
	case "", policyTypeAll:
	case policyNetworkType:
		if rule.ResourceType != policyNetworkType {
			return false
		}
	case filesystemKeyword:
		if !strings.HasPrefix(rule.ResourceType, filesystemKeyword+":") {
			return false
		}
	}
	if o.source != "" && policyRuleSource(rule) != o.source {
		return false
	}
	if o.decision != "" && rule.Decision != o.decision {
		return false
	}
	if o.createdVia != "" && rule.Provenance.CreatedVia != o.createdVia {
		return false
	}
	if o.protocol != "" && !slices.Contains(policyRuleProtocols(rule), o.protocol) {
		return false
	}
	return true
}

const (
	policyTypeAll = "all"
)

// policyRuleSource classifies a rule the way `sbx policy ls` prints SOURCE.
// A scoped local rule is still a local rule; organization rules are read-only
// and kit-provisioned network rules are the only local rules with a kit source.
func policyRuleSource(rule *policyRuleJSON) string {
	if rule.Origin == orgScope {
		return orgScope
	}
	if rule.ResourceType == policyNetworkType && rule.Provenance.CreatedVia == policyCreatedViaProvisioned &&
		rule.Provenance.Source == "sandboxes" {
		return kitCommand
	}
	return originLocal
}

func policyRuleProtocols(rule *policyRuleJSON) []string {
	protocols := make([]string, 0, len(rule.Actions))
	for _, action := range rule.Actions {
		if protocol, ok := strings.CutPrefix(action, policyNetworkActionPrefix); ok {
			protocols = append(protocols, protocol)
		}
	}
	return protocols
}

func (r *Runner) policyListError(message string) int {
	_, _ = fmt.Fprintf(r.Err, "error: %s\n  try: rsbx policy ls --help\n", message)
	return 1
}

func (r *Runner) policyListFlagError(err error) int {
	message := err.Error()
	if name, ok := strings.CutPrefix(message, "flag provided but not defined: -"); ok {
		message = "unknown flag: --" + name
	}
	return r.policyListError(message)
}

//nolint:funlen // flag parsing and validation mirror the reference contract.
func (r *Runner) policyList(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{
		"--format": true, "--type": true, "--source": true, "--decision": true,
		"--profile": true, "--created-via": true, "--protocol": true,
	})
	fs := r.newFlagSet("policy ls")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(policyListHelp()) }
	var opts policyListOptions
	var quietShort bool
	fs.StringVar(&opts.format, "format", listFormatTable, "output format: table, json or yaml")
	fs.BoolVar(&opts.json, "json", false, "output in JSON format")
	fs.StringVar(&opts.resourceType, "type", policyTypeAll, "filter policies by type: all, network or filesystem")
	fs.StringVar(&opts.source, "source", "", "filter policies by source: local, org or kit")
	fs.StringVar(&opts.decision, "decision", "", "filter policies by decision: allow or deny")
	fs.StringVar(&opts.createdVia, "created-via", "", "filter policies by creation method: default, added or provisioned")
	fs.StringVar(&opts.protocol, "protocol", "", "filter network rules by protocol: tcp or udp")
	fs.StringVar(&opts.profile, "profile", "", "filter policies by governance profile (unsupported)")
	fs.BoolVar(&opts.wide, "wide", false, "show detailed rule-level output with rule IDs and resources")
	fs.BoolVar(&opts.quiet, "quiet", false, "only display rule IDs")
	fs.BoolVar(&quietShort, "q", false, "only display rule IDs")
	fs.BoolVar(&opts.includeInactive, "include-inactive", false, "show inactive policy rules hidden by remote governance")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.policyListFlagError(err)
	}
	opts.quiet = opts.quiet || quietShort
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if fs.NArg() > 1 {
		return r.policyListError(fmt.Sprintf("accepts at most 1 arg(s), received %d", fs.NArg()))
	}
	if err := validatePolicyListOptions(opts, set); err != nil {
		return r.policyListError(err.Error())
	}
	selected, err := resolveOperationFormat(opts.format, opts.json)
	if err != nil {
		return r.policyListError(err.Error())
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
	rules := policyRulesFrom(policyGlobalScope, globalAllow, globalDeny)
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
	list := policyRulesOutput(rules)
	if fs.NArg() == 0 {
		if profile, err := sdk.Policies(client).GetPolicyProfile(ctx); err == nil && profile == policyProfileAllowAll {
			list.Rules = append(defaultGlobalPolicyRules(), list.Rules...)
		}
	}
	if !opts.includeInactive {
		opts.hiddenInactive = countInactivePolicyRules(list.Rules)
	}
	list.Rules = opts.filterRules(list.Rules)
	return r.renderPolicyListOutput(selected, opts, list)
}

func countInactivePolicyRules(rules []policyRuleJSON) int {
	count := 0
	for i := range rules {
		if rules[i].Status == policyStatusInactive {
			count++
		}
	}
	return count
}

func (r *Runner) renderPolicyListOutput(selected string, opts policyListOptions, list policyListOutput) int {
	if opts.quiet {
		renderPolicyQuiet(r.Out, list)
		return 0
	}
	emptyMessage := policyEmptyMessage(opts)
	if selected == listFormatTable && opts.wide {
		if err := renderPolicyWideTable(r.Out, list, emptyMessage); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
	if err := renderPolicyRules(r.Out, selected, list, emptyMessage); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func validatePolicyListOptions(opts policyListOptions, set map[string]bool) error {
	if err := validatePolicyListOutputOptions(opts, set); err != nil {
		return err
	}
	return validatePolicyListFilters(opts)
}

func validatePolicyListOutputOptions(opts policyListOptions, set map[string]bool) error {
	if opts.profile != "" || set["profile"] {
		return errors.New("--profile requires remote governance, which is not implemented")
	}
	if opts.quiet && (opts.wide || opts.json || set["format"]) {
		return errors.New("--quiet cannot be combined with --wide, --json or --format")
	}
	if opts.json && set["format"] {
		return errors.New("--json cannot be combined with --format")
	}
	return nil
}

func validatePolicyListFilters(opts policyListOptions) error {
	switch opts.resourceType {
	case policyTypeAll, policyNetworkType, filesystemKeyword:
	case schemeHTTP:
		return errors.New("--type http is not supported: HTTP policy rules are not implemented")
	default:
		return fmt.Errorf("invalid type %q: must be one of: all, network, filesystem", opts.resourceType)
	}
	switch opts.source {
	case "", originLocal, orgScope, kitCommand:
	default:
		return fmt.Errorf("invalid source %q: must be one of: local, org, kit", opts.source)
	}
	switch opts.decision {
	case "", actionAllow, actionDeny:
	default:
		return fmt.Errorf("invalid decision %q: must be one of: allow, deny", opts.decision)
	}
	switch opts.createdVia {
	case "", policyCreatedViaDefault, policyCreatedViaAdded, policyCreatedViaProvisioned:
	case policyCreatedViaApproval:
		return errors.New("--created-via approval is not supported: approval-gated policies are not implemented")
	default:
		return fmt.Errorf("invalid creation method %q: must be one of: default, added, provisioned, approval", opts.createdVia)
	}
	switch opts.protocol {
	case "":
	case tcpProtocol, udpProtocol:
		if opts.resourceType == filesystemKeyword {
			return errors.New("--protocol is only compatible with --type all or --type network")
		}
	default:
		return fmt.Errorf("invalid protocol %q: must be tcp or udp", opts.protocol)
	}
	return nil
}

func policyEmptyMessage(opts policyListOptions) string {
	if opts.hiddenInactive > 0 {
		return fmt.Sprintf("No active policy rules match; %d inactive rule(s) hidden by remote governance (use --include-inactive to show them)", opts.hiddenInactive)
	}
	if !opts.hasFilters() {
		return "No policy rules (default deny)"
	}
	if opts.protocol != "" {
		return "No network policy rules match the selected filters; network access is denied unless allowed by an applicable policy"
	}
	return "No policies match the selected filters"
}

func renderPolicyQuiet(out io.Writer, list policyListOutput) {
	for i := range list.Rules {
		_, _ = fmt.Fprintln(out, list.Rules[i].ID)
	}
}

// renderPolicyWideTable mirrors the reference wide rule table, including the
// METHOD and PATH columns for HTTP-conditioned rules.
func renderPolicyWideTable(out io.Writer, list policyListOutput, emptyMessage string) error {
	if len(list.Rules) == 0 {
		_, err := fmt.Fprintln(out, emptyMessage)
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SOURCE\tCREATED VIA\tAPPLIES TO\tPOLICY\tPOLICY_ID\tRULE\tRULE_ID\tTYPE\tMETHOD\tPATH\tDECISION\tPROTOCOLS\tSTATUS\tRESOURCES")
	for i := range list.Rules {
		rule := list.Rules[i]
		name := rule.Name
		if name == "" || name == rule.ID {
			name = "-"
		}
		protocols := "-"
		if values := policyRuleProtocols(&rule); len(values) > 0 {
			protocols = strings.Join(values, ",")
		}
		resources := rule.Resources
		if len(resources) == 0 {
			resources = []string{"-"}
		}
		methodText := "-"
		if len(rule.Methods) > 0 {
			methodText = strings.Join(rule.Methods, ",")
		}
		pathText := "-"
		if rule.Path != "" {
			pathText = rule.Path
		}
		for j, resource := range resources {
			if j == 0 {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t-\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					policyRuleSource(&rule), rule.Provenance.CreatedVia, rule.AppliesTo, rule.PolicyID,
					name, rule.ID, rule.ResourceType, methodText, pathText, rule.Decision, protocols, rule.Status, resource)
				continue
			}
			_, _ = fmt.Fprintf(tw, "\t\t\t\t\t\t\t\t\t\t\t\t\t%s\n", resource)
		}
	}
	return tw.Flush()
}

func (r *Runner) policyInit(ctx context.Context, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		return r.showCommandHelp(policyInitHelp())
	}
	if len(args) != 1 {
		_, _ = fmt.Fprint(r.Err, policyInitUsage)
		return 2
	}
	profile := args[0]
	if profile != policyProfileAllowAll && profile != policyProfileBalanced && profile != policyProfileDenyAll {
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

// policyProfileList lists governance policy profiles. The daemon API exposes
// only the global default profile, not governance profile names or their
// policy attachments, so the listing fails closed rather than guessing.
func (r *Runner) policyProfileList(args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		return r.showCommandHelp(policyProfileListHelp())
	}
	args = reorderFlagArgs(args, map[string]bool{"--format": true})
	fs := r.newFlagSet("policy profile ls")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(policyProfileListHelp()) }
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	quiet := fs.Bool("quiet", false, "only display profile names")
	quietShort := fs.Bool("q", false, "only display profile names")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("policy profile ls", err)
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if fs.NArg() != 0 {
		return r.commandError("policy profile ls", fmt.Sprintf("accepts 0 arg(s), received %d", fs.NArg()))
	}
	if (*quiet || *quietShort) && (*jsonOutput || set["format"]) {
		return r.commandError("policy profile ls", "--quiet cannot be combined with --json or --format")
	}
	if _, err := resolveOperationFormat(*format, *jsonOutput); err != nil {
		return r.commandError("policy profile ls", err.Error())
	}
	return r.commandError("policy profile ls", "governance policy profiles are not available: the daemon does not expose profile names or their policy attachments")
}

func (r *Runner) policyProfile(ctx context.Context, args []string) int {
	if len(args) > 0 && (args[0] == "ls" || args[0] == commandList) {
		return r.policyProfileList(args[1:])
	}
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		if slices.Contains(args, "ls") || slices.Contains(args, commandList) {
			return r.showCommandHelp(policyProfileListHelp())
		}
		return r.showCommandHelp(policyProfileHelp())
	}
	if len(args) > 0 {
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
	_, _ = fmt.Fprintf(r.Out, "global: %s\nchoices: deny-all, balanced, allow-all\n", profile)
	return 0
}

func (r *Runner) policyMutate(ctx context.Context, action string, args []string, sel networkHTTPSelectors) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		return r.showCommandHelp(policyMutateHelp(action))
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
	if err := applyNetworkHTTPSelectors(&rule, sel); err != nil {
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
		return r.showCommandHelp(policyCheckHelp())
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
	scope := sandboxPrefix + ":" + sb.Name
	out := policyRulesFrom(scope, sb.Allow, sb.Deny)
	for _, workspace := range sb.Workspaces {
		readID := filesystemRuleID(workspace.Path, "read")
		out = append(out, policyRuleOutput{RuleID: readID, SandboxID: sb.Name, Scope: scope, ResourceType: filesystemKeyword,
			Action: actionAllow, Provenance: "workspace", Origin: originLocal, Path: workspace.Path, Access: "read"})
		action := actionAllow
		if workspace.ReadOnly {
			action = actionDeny
		}
		out = append(out, policyRuleOutput{RuleID: filesystemRuleID(workspace.Path, "write"), SandboxID: sb.Name, Scope: scope, ResourceType: filesystemKeyword,
			Action: action, Provenance: "workspace", Origin: originLocal, Path: workspace.Path, Access: "write"})
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
	fs := r.newFlagSet("policy check filesystem")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(policyCheckFilesystemHelp()) }
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
	sandboxID := ""
	if strings.HasPrefix(scope, sandboxPrefix+":") {
		sandboxID = strings.TrimPrefix(scope, sandboxPrefix+":")
	}
	appendRules := func(action string, rules []sdk.NetworkRule) {
		for i := range rules {
			protocol := rules[i].Protocol
			if protocol == "" {
				protocol = tcpProtocol
			}
			out = append(out, policyRuleOutput{RuleID: rules[i].RuleID, SandboxID: sandboxID, Scope: scope, ResourceType: networkKeyword,
				Action: action, Provenance: policyProvenanceUser, Origin: originLocal, Protocol: protocol, CIDR: rules[i].CIDR, Domain: rules[i].Domain, Port: rules[i].Port,
				Methods: rules[i].Methods, HTTPPath: rules[i].Path, Query: rules[i].Query})
		}
	}
	appendRules("allow", allow)
	appendRules("deny", deny)
	return out
}

// policyRuleJSONFrom maps an internal rule onto the sbx rule schema.
func policyRuleJSONFrom(rule *policyRuleOutput) policyRuleJSON {
	id := rule.RuleID
	if id == "" {
		summary := rule.Scope + "\x00" + rule.Action + "\x00" + rule.Target()
		if len(rule.Methods) > 0 || rule.HTTPPath != "" || len(rule.Query) > 0 {
			summary += "\x00" + canonicalMethodsKey(rule.Methods) + "\x00" + rule.HTTPPath + "\x00" + canonicalQueryKey(rule.Query)
		}
		sum := sha256.Sum256([]byte(summary))
		id = "rul_" + hex.EncodeToString(sum[:8])
	}
	name := rule.Name
	if name == "" {
		name = id
	}
	scope, appliesTo := policyScopeOutput(rule)
	resourceType := rule.ResourceType
	actions := []string{}
	resources := []string{}
	origin := rule.Origin
	if origin == "" {
		origin = originLocal
	}
	editable := false
	provenance := policyProvenanceOutput{CreatedVia: policyCreatedViaAdded}
	switch rule.ResourceType {
	case filesystemKeyword:
		resourceType = "filesystem:" + rule.Access
		resources = append(resources, rule.Path)
		switch rule.Access {
		case "read":
			actions = append(actions, "fs:mount:read")
		case "write":
			if rule.Action == actionAllow {
				actions = append(actions, "fs:mount:read")
			}
			actions = append(actions, "fs:mount:write")
		}
		provenance = policyProvenanceOutput{CreatedVia: policyCreatedViaProvisioned, Source: "sandboxes"}
	default:
		actions = append(actions, policyNetworkActionPrefix+networkRuleProtocol(rule))
		resources = append(resources, rule.NetworkResource())
		editable = rule.Origin != orgScope
		if rule.Origin == orgScope {
			provenance = policyProvenanceOutput{CreatedVia: policyCreatedViaAdded, Source: orgScope}
		}
	}
	if strings.HasPrefix(scope, sandboxPrefix+":") {
		origin = "scoped"
	}
	decision := actionDeny
	if rule.Action == actionAllow {
		decision = actionAllow
	}
	out := policyRuleJSON{
		ID:           id,
		Name:         name,
		PolicyID:     policyIDForScope(scope),
		Scope:        scope,
		AppliesTo:    appliesTo,
		ResourceType: resourceType,
		Decision:     decision,
		Resources:    resources,
		Origin:       origin,
		Layer:        originLocal,
		Status:       policyStatusOrActive(rule.Status),
		Editable:     editable,
		SandboxID:    rule.SandboxID,
		Provenance:   provenance,
		Actions:      actions,
		Methods:      conditionMethods(rule),
		Path:         conditionPath(rule),
		Query:        policyQueryJSONFrom(rule.Query),
	}
	return out
}

func policyStatusOrActive(status string) string {
	if status == "" {
		return policyStatusActive
	}
	return status
}

func networkRuleProtocol(rule *policyRuleOutput) string {
	if rule.Protocol == "" {
		return tcpProtocol
	}
	return rule.Protocol
}

func conditionMethods(rule *policyRuleOutput) []string {
	if rule.ResourceType == filesystemKeyword {
		return nil
	}
	return rule.Methods
}

func conditionPath(rule *policyRuleOutput) string {
	if rule.ResourceType == filesystemKeyword {
		return ""
	}
	return rule.HTTPPath
}

func policyQueryJSONFrom(query []sdk.QueryCondition) []policyQueryJSON {
	if len(query) == 0 {
		return nil
	}
	out := make([]policyQueryJSON, 0, len(query))
	for _, q := range query {
		out = append(out, policyQueryJSON{Name: q.Name, Value: q.Value})
	}
	return out
}

func policyScopeOutput(rule *policyRuleOutput) (string, string) {
	scope := rule.Scope
	if scope == "" {
		scope = policyGlobalScope
	}
	switch scope {
	case policyGlobalScope, orgScope:
		return scope, "all"
	}
	if strings.HasPrefix(scope, sandboxPrefix+":") {
		return scope, scope
	}
	if rule.SandboxID != "" {
		scoped := sandboxPrefix + ":" + rule.SandboxID
		return scoped, scoped
	}
	return scope, scope
}

func policyIDForScope(scope string) string {
	if scope == orgScope {
		return "org-policy"
	}
	return "local-policy"
}

// Target returns the network target without a port.
func (rule *policyRuleOutput) Target() string {
	if rule.Domain != "" {
		return rule.Domain
	}
	if rule.CIDR != "" {
		return rule.CIDR
	}
	return rule.Path
}

// NetworkResource renders the sbx resources entry for a network rule.
func (rule *policyRuleOutput) NetworkResource() string {
	target := rule.Target()
	if target != "" && rule.Port != 0 {
		return target + ":" + strconv.FormatUint(uint64(rule.Port), 10)
	}
	return target
}

// defaultGlobalPolicyRules is the baseline the reference client reports for the
// allow-all profile. The filesystem defaults are not editable there because the
// guest rootfs is read-only and the workspace policy is provisioned separately.
func defaultGlobalPolicyRules() []policyRuleJSON {
	mk := func(id, resourceType string, actions []string, editable bool) policyRuleJSON {
		return policyRuleJSON{
			ID: id, Name: id, PolicyID: policyIDForScope(policyGlobalScope),
			Scope: policyGlobalScope, AppliesTo: "all", ResourceType: resourceType,
			Decision: actionAllow, Resources: []string{"**"}, Origin: originLocal,
			Layer: originLocal, Status: "active", Editable: editable,
			Provenance: policyProvenanceOutput{CreatedVia: policyCreatedViaDefault}, Actions: actions,
		}
	}
	return []policyRuleJSON{
		mk("default-allow-all", networkKeyword, []string{policyNetworkActionPrefix + tcpProtocol}, true),
		mk("default-fs-read-allow-all", "filesystem:read", []string{"fs:mount:read"}, false),
		mk("default-fs-write-allow-all", "filesystem:write", []string{"fs:mount:read", "fs:mount:write"}, false),
	}
}

func policyRulesOutput(rules []policyRuleOutput) policyListOutput {
	out := policyListOutput{Rules: make([]policyRuleJSON, 0, len(rules))}
	for i := range rules {
		out.Rules = append(out.Rules, policyRuleJSONFrom(&rules[i]))
	}
	return out
}

// renderPolicyRules renders the reference table or machine output for a list.
func renderPolicyRules(out io.Writer, format string, list policyListOutput, emptyMessage string) error {
	if format == listFormatTable {
		return renderPolicyTable(out, list, emptyMessage)
	}
	if len(list.Rules) == 0 {
		list.Rules = []policyRuleJSON{}
	}
	switch format {
	case listFormatYAML:
		data, err := yaml.Marshal(list)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(list)
	}
}

// renderPolicyTable groups rules the way the reference client does: one row per
// policy with a summary of its allow/deny counts per resource type.
func renderPolicyTable(out io.Writer, list policyListOutput, emptyMessage string) error {
	if len(list.Rules) == 0 {
		_, err := fmt.Fprintln(out, emptyMessage)
		return err
	}
	type policyRow struct {
		source, appliesTo string
		order             []string
		counts            map[string]map[string]int
	}
	rows := make([]*policyRow, 0, 4)
	index := make(map[string]*policyRow)
	keys := make([]string, 0, 4)
	for i := range list.Rules {
		rule := &list.Rules[i]
		key := rule.PolicyID + "\x00" + rule.Origin + "\x00" + rule.AppliesTo
		row, ok := index[key]
		if !ok {
			row = &policyRow{source: policyRuleSource(rule), appliesTo: rule.AppliesTo, counts: map[string]map[string]int{}}
			index[key] = row
			rows = append(rows, row)
			keys = append(keys, key)
		}
		decisions, ok := row.counts[rule.ResourceType]
		if !ok {
			decisions = map[string]int{}
			row.counts[rule.ResourceType] = decisions
			row.order = append(row.order, rule.ResourceType)
		}
		decisions[rule.Decision]++
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "POLICY\tSOURCE\tAPPLIES TO\tSUMMARY")
	for i, key := range keys {
		row := rows[i]
		policyID, _, _ := strings.Cut(key, "\x00")
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", policyID, row.source, row.appliesTo, summarizePolicyCounts(row.order, row.counts))
	}
	return tw.Flush()
}

func summarizePolicyCounts(order []string, counts map[string]map[string]int) string {
	parts := make([]string, 0, len(order))
	for _, resource := range order {
		decisions := counts[resource]
		names := make([]string, 0, len(decisions))
		for decision := range decisions {
			names = append(names, decision)
		}
		sort.Strings(names)
		countsText := make([]string, 0, len(names))
		for _, decision := range names {
			countsText = append(countsText, fmt.Sprintf("%d %s", decisions[decision], decision))
		}
		label := resource
		if strings.HasPrefix(resource, filesystemKeyword+":") {
			label = filesystemKeyword + " " + strings.TrimPrefix(resource, filesystemKeyword+":")
		}
		parts = append(parts, label+": "+strings.Join(countsText, ", "))
	}
	return strings.Join(parts, "; ")
}

// renderPolicyRuleDetail keeps the per-rule view used by `policy inspect`,
// where the grouped summary table would hide the rule the user asked for.
//
//nolint:gocognit // one renderer covers the per-rule table and three formats.
func renderPolicyRuleDetail(out io.Writer, format string, rules []policyRuleOutput) error {
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
		data, err := yaml.Marshal(policyRulesOutput(rules))
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(policyRulesOutput(rules))
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
  ls [SANDBOX] [--type all|network|filesystem] [--source local|org|kit]
     [--decision allow|deny] [--created-via default|added|provisioned]
     [--protocol tcp|udp] [--wide|-q] [--format table|json|yaml] [--json]
                                          list global and sandbox allow/deny rules
                                          JSON/YAML emit sbx's {"rules":[...]} with
                                          id, name, policy_id, scope, applies_to,
                                          resource_type, decision, resources,
                                          origin, status, provenance and actions
  inspect RULE_ID|SANDBOX [--format ...]  show one rule or sandbox policy
  log [SANDBOX] [--type all|network] [--limit N]
                                          show gateway audit decisions
  refresh                                 re-apply policy to running sandboxes
  reset [--force]                         remove custom global rules
  approval                                not implemented; fails closed
  allow SANDBOX CIDR[:PORT]               add an allow rule (legacy local grammar)
  deny SANDBOX CIDR[:PORT]                add a deny rule (legacy local grammar)
  rm SANDBOX CIDR[:PORT]                  remove an allow or deny rule
  allow|deny network [--sandbox NAME] RESOURCES
                                          Docker sbx grammar; omit --sandbox for
                                          global rules
  rm network [--sandbox NAME] (--id ID | --resource RESOURCES | TARGET) [--force]
                                          remove local network rules by stable
                                          rule ID or resource; L7 selectors are
                                          rejected
  check SANDBOX IP PORT [PROTOCOL]        evaluate a request against stored rules
  check network [--sandbox NAME] [--protocol tcp|udp] [--format table|json|yaml] [--json] TARGET
                                          evaluate IPv4[:PORT], IPv6[:PORT], domain or URL
  check filesystem --sandbox NAME [--write] PATH
                                          evaluate a guest workspace path
  init allow-all|balanced|deny-all        set the global default profile
  profile [ls]                            show the global default and available profiles
  org [--format table|json|yaml]          show the effective organization policy,
                                          enforced vs advisory rules, or an empty state

policy approval needs daemon support and fails closed.
Default is allow-all, matching the Docker sbx baseline; deny-all remains selectable.
`
