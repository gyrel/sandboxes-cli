package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type orgPolicyRuleOutput struct {
	RuleID         string `json:"rule_id" yaml:"rule_id"`
	Action         string `json:"action" yaml:"action"`
	Source         string `json:"source" yaml:"source"`
	ResourceType   string `json:"resource_type" yaml:"resource_type"`
	Protocol       string `json:"protocol" yaml:"protocol"`
	CIDR           string `json:"cidr,omitempty" yaml:"cidr,omitempty"`
	Domain         string `json:"domain,omitempty" yaml:"domain,omitempty"`
	Port           uint16 `json:"port" yaml:"port"`
	Enforcement    string `json:"enforcement" yaml:"enforcement"`
	AdvisoryReason string `json:"advisory_reason,omitempty" yaml:"advisory_reason,omitempty"`
}

type orgPolicyOutput struct {
	Loaded             bool                  `json:"loaded" yaml:"loaded"`
	Org                string                `json:"org,omitempty" yaml:"org,omitempty"`
	SchemaVersion      uint32                `json:"schema_version,omitempty" yaml:"schema_version,omitempty"`
	Revision           uint64                `json:"revision,omitempty" yaml:"revision,omitempty"`
	BundleID           string                `json:"bundle_id,omitempty" yaml:"bundle_id,omitempty"`
	EnforcementEnabled bool                  `json:"enforcement_enabled" yaml:"enforcement_enabled"`
	LoadedAt           string                `json:"loaded_at,omitempty" yaml:"loaded_at,omitempty"`
	IssuedAt           string                `json:"issued_at,omitempty" yaml:"issued_at,omitempty"`
	ExpiresAt          string                `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	IgnoredRules       int32                 `json:"ignored_rules" yaml:"ignored_rules"`
	Rules              []orgPolicyRuleOutput `json:"rules" yaml:"rules"`
}

// policyOrg shows the effective organization policy bundle without changing
// it. A missing bundle is an empty state, not an error; an invalid bundle is a
// typed daemon failure and is reported as such.
func (r *Runner) policyOrg(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{formatFlag: true})
	fs := r.newFlagSet("policy org")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(policyOrgHelp()) }
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("policy org", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx policy org [--format table|json|yaml]")
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	client, err := r.orgPolicyClient()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	response, err := client.GetOrgPolicy(ctx)
	if err != nil {
		return r.reportOrgPolicyError(selected, err)
	}
	if err := renderOrgPolicy(r.Out, selected, orgPolicyOutputFrom(response)); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) reportOrgPolicyError(format string, err error) int {
	if status.Code(err) == codes.NotFound {
		if renderErr := renderOrgPolicy(r.Out, format, emptyOrgPolicyOutput()); renderErr != nil {
			r.error(renderErr)
			return 1
		}
		return 0
	}
	if status.Code(err) == codes.Unimplemented {
		r.error(errors.New("daemon does not expose organization policy; upgrade the daemon and API contract to 0.0.26"))
		return 1
	}
	r.error(err)
	return 1
}

func (r *Runner) orgPolicyClient() (orgPolicyClient, error) {
	if r.NewOrgPolicyClient != nil {
		return r.NewOrgPolicyClient(r.Socket)
	}
	return newOrgPolicyClient(r.Socket)
}

// appendOrgPolicyRules adds organization rules to policy listings on a
// best-effort basis. A missing or unsupported org policy must not break the
// existing local listing behavior.
func (r *Runner) appendOrgPolicyRules(ctx context.Context, rules []policyRuleOutput) []policyRuleOutput {
	if r.NewOrgPolicyClient == nil {
		return rules
	}
	client, err := r.NewOrgPolicyClient(r.Socket)
	if err != nil {
		return rules
	}
	defer func() { _ = client.Close() }()
	response, err := client.GetOrgPolicy(ctx)
	if err != nil {
		return rules
	}
	for _, rule := range response.GetRules() {
		protocol := rule.GetProtocol()
		if protocol == "" {
			protocol = "any"
		}
		rules = append(rules, policyRuleOutput{
			RuleID: rule.GetRuleId(), Scope: orgScope, ResourceType: networkKeyword,
			Action: rule.GetAction(), Provenance: orgScope, Origin: orgScope,
			Protocol: protocol, CIDR: rule.GetCidr(), Domain: rule.GetDomain(), Port: uint16(rule.GetPort()), //nolint:gosec // daemon bounds ports to 65535.
		})
	}
	return rules
}

func emptyOrgPolicyOutput() orgPolicyOutput {
	return orgPolicyOutput{Rules: []orgPolicyRuleOutput{}}
}

func orgPolicyOutputFrom(response *localv1.GetOrgPolicyResponse) orgPolicyOutput {
	rules := make([]orgPolicyRuleOutput, 0, len(response.GetRules()))
	for _, rule := range response.GetRules() {
		source := rule.GetSource()
		if source == "" {
			source = orgScope
		}
		enforcement := "advisory"
		if rule.GetEnforced() {
			enforcement = "enforced"
		}
		rules = append(rules, orgPolicyRuleOutput{
			RuleID: rule.GetRuleId(), Action: rule.GetAction(), Source: source,
			ResourceType: rule.GetResourceType(), Protocol: rule.GetProtocol(),
			CIDR: rule.GetCidr(), Domain: rule.GetDomain(), Port: uint16(rule.GetPort()), //nolint:gosec // daemon bounds ports to 65535.
			Enforcement: enforcement, AdvisoryReason: rule.GetAdvisoryReason(),
		})
	}
	return orgPolicyOutput{
		Loaded: true, Org: response.GetOrg(), SchemaVersion: response.GetSchemaVersion(),
		Revision: response.GetRevision(), BundleID: response.GetBundleId(),
		EnforcementEnabled: response.GetEnforcementEnabled(),
		LoadedAt:           formatUnixTime(response.GetLoadedAtUnix()),
		IssuedAt:           formatUnixTime(response.GetIssuedAtUnix()),
		ExpiresAt:          formatUnixTime(response.GetExpiresAtUnix()),
		IgnoredRules:       response.GetIgnoredRules(),
		Rules:              rules,
	}
}

func formatUnixTime(seconds int64) string {
	if seconds == 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

func renderOrgPolicy(out io.Writer, format string, policy orgPolicyOutput) error {
	switch format {
	case listFormatTable:
		return renderOrgPolicyTable(out, policy)
	case listFormatYAML:
		data, err := yaml.Marshal(policy)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(policy)
	}
}

func renderOrgPolicyTable(out io.Writer, policy orgPolicyOutput) error {
	if !policy.Loaded {
		_, err := fmt.Fprintln(out, "No organization policy bundle is loaded.\nNo organization rules are in effect.")
		return err
	}
	enforcement := "disabled"
	if policy.EnforcementEnabled {
		enforcement = "enabled"
	}
	_, _ = fmt.Fprintf(out, "org: %s\nschema: %d\nrevision: %d\nbundle: %s\nenforcement: %s\nloaded: %s\nissued: %s\nexpires: %s\nignored rules: %d\n",
		policy.Org, policy.SchemaVersion, policy.Revision, policy.BundleID, enforcement,
		orDash(policy.LoadedAt), orDash(policy.IssuedAt), orDash(policy.ExpiresAt), policy.IgnoredRules)
	if len(policy.Rules) == 0 {
		_, err := fmt.Fprintln(out, "\nNo organization network rules.")
		return err
	}
	_, _ = fmt.Fprintln(out, "\nRULE ID\tACTION\tSOURCE\tPROTOCOL\tTARGET\tPORT\tSTATUS\tREASON")
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	for i := range policy.Rules {
		rule := &policy.Rules[i]
		target := rule.CIDR
		if rule.Domain != "" {
			target = rule.Domain
		}
		protocol := rule.Protocol
		if protocol == "" {
			protocol = "any"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			rule.RuleID, rule.Action, rule.Source, protocol, orDash(target), rule.Port, rule.Enforcement, orDash(rule.AdvisoryReason))
	}
	return tw.Flush()
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
