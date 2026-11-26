package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

type policyApprovalListOutput struct {
	Approvals []policyApprovalOutput `json:"approvals" yaml:"approvals"`
}

type policyApprovalOutput struct {
	ID                string                       `json:"id" yaml:"id"`
	Kind              string                       `json:"kind" yaml:"kind"`
	State             string                       `json:"state" yaml:"state"`
	SandboxID         string                       `json:"sandbox_id,omitempty" yaml:"sandbox_id,omitempty"`
	ActionSummary     string                       `json:"action_summary,omitempty" yaml:"action_summary,omitempty"`
	DestinationHost   string                       `json:"destination_host,omitempty" yaml:"destination_host,omitempty"`
	DestinationPath   string                       `json:"destination_path,omitempty" yaml:"destination_path,omitempty"`
	Headers           []policyApprovalHeaderOutput `json:"headers,omitempty" yaml:"headers,omitempty"`
	EnvNames          []string                     `json:"env_names,omitempty" yaml:"env_names,omitempty"`
	EnvNamesTruncated bool                         `json:"env_names_truncated,omitempty" yaml:"env_names_truncated,omitempty"`
	CwdSummary        string                       `json:"cwd_summary,omitempty" yaml:"cwd_summary,omitempty"`
	CreatedAt         string                       `json:"created_at,omitempty" yaml:"created_at,omitempty"`
}

type policyApprovalHeaderOutput struct {
	Name              string   `json:"name" yaml:"name"`
	ValueClass        string   `json:"value_class" yaml:"value_class"`
	VaultReferenceIDs []string `json:"vault_reference_ids,omitempty" yaml:"vault_reference_ids,omitempty"`
}

func (r *Runner) policyApproval(ctx context.Context, args []string) int {
	if len(args) == 0 {
		return r.showCommandHelp(policyApprovalHelp())
	}
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		// Top-level help when no concrete subcommand is present.
		if args[0] == helpCommand || args[0] == helpShort || args[0] == helpFlag {
			return r.showCommandHelp(policyApprovalHelp())
		}
	}
	switch args[0] {
	case "ls":
		return r.policyApprovalList(ctx, args[1:])
	case commandInspect:
		return r.policyApprovalInspect(ctx, args[1:])
	case "respond":
		return r.policyApprovalRespond(ctx, args[1:])
	case helpCommand, helpShort, helpFlag:
		return r.showCommandHelp(policyApprovalHelp())
	default:
		// Allow "policy approval --help".
		if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
			return r.showCommandHelp(policyApprovalHelp())
		}
		_, _ = fmt.Fprintf(r.Err, "rsbx policy approval: unknown subcommand %q\n", args[0])
		return 2
	}
}

//nolint:gocognit,gocyclo,cyclop,funlen // command flag parsing and output handling
func (r *Runner) policyApprovalList(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{formatFlag: true, sandboxFlag: true})
	fs := r.newFlagSet("policy approval ls")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(policyApprovalLsHelp()) }
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	quiet := fs.Bool("quiet", false, "only display approval IDs")
	fs.BoolVar(quiet, "q", false, "only display approval IDs")
	sandbox := fs.String("sandbox", "", "limit to one sandbox")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("policy approval ls", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx policy approval ls [flags]")
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
	items, err := sdk.Approvals(client).ListApprovals(ctx, *sandbox)
	if err != nil {
		r.error(err)
		return 1
	}
	out := make([]policyApprovalOutput, 0, len(items))
	for i := range items {
		out = append(out, policyApprovalFromSDK(items[i]))
	}
	if *quiet {
		for i := range out {
			_, _ = fmt.Fprintln(r.Out, out[i].ID)
		}
		return 0
	}
	switch selected {
	case listFormatTable:
		if len(out) == 0 {
			_, _ = fmt.Fprintln(r.Out, "No pending approvals")
			return 0
		}
		tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "ID\tKIND\tSTATE\tSANDBOX\tDESTINATION")
		for i := range out {
			item := &out[i]
			dest := item.DestinationHost
			if item.DestinationPath != "" {
				dest += item.DestinationPath
			}
			if dest == "" {
				dest = "-"
			}
			sandbox := item.SandboxID
			if sandbox == "" {
				sandbox = globalScopeLabel
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", item.ID, item.Kind, item.State, sandbox, dest)
		}
		if err := tw.Flush(); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(policyApprovalListOutput{Approvals: out})
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	default:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(policyApprovalListOutput{Approvals: out}); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
}

func (r *Runner) policyApprovalInspect(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{sandboxFlag: true})
	fs := r.newFlagSet("policy approval inspect")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(policyApprovalInspectHelp()) }
	sandbox := fs.String("sandbox", "", "sandbox scope")
	_ = sandbox
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("policy approval inspect", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx policy approval inspect APPROVAL-ID [flags]")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	approval, err := sdk.Approvals(client).InspectApproval(ctx, fs.Arg(0), *sandbox)
	if err != nil {
		r.error(err)
		return 1
	}
	item := policyApprovalFromSDK(approval)
	// Print a human-readable inspection.
	_, _ = fmt.Fprintf(r.Out, "ID: %s\n", item.ID)
	_, _ = fmt.Fprintf(r.Out, "Kind: %s\n", item.Kind)
	_, _ = fmt.Fprintf(r.Out, "State: %s\n", item.State)
	if item.SandboxID != "" {
		_, _ = fmt.Fprintf(r.Out, "Sandbox: %s\n", item.SandboxID)
	}
	if item.ActionSummary != "" {
		_, _ = fmt.Fprintf(r.Out, "Action: %s\n", item.ActionSummary)
	}
	if item.DestinationHost != "" {
		_, _ = fmt.Fprintf(r.Out, "Destination: %s%s\n", item.DestinationHost, item.DestinationPath)
	}
	if len(item.Headers) > 0 {
		_, _ = fmt.Fprintln(r.Out, "Headers:")
		for _, h := range item.Headers {
			_, _ = fmt.Fprintf(r.Out, "  %s (%s)\n", h.Name, h.ValueClass)
		}
	}
	if len(item.EnvNames) > 0 {
		_, _ = fmt.Fprintf(r.Out, "Env: %s\n", strings.Join(item.EnvNames, ", "))
		if item.EnvNamesTruncated {
			_, _ = fmt.Fprintln(r.Out, "Env: (truncated)")
		}
	}
	if item.CwdSummary != "" {
		_, _ = fmt.Fprintf(r.Out, "Cwd: %s\n", item.CwdSummary)
	}
	if item.CreatedAt != "" {
		_, _ = fmt.Fprintf(r.Out, "Created: %s\n", item.CreatedAt)
	}
	return 0
}

func (r *Runner) policyApprovalRespond(ctx context.Context, args []string) int {
	args = reorderFlagArgs(args, map[string]bool{"--option": true, sandboxFlag: true})
	fs := r.newFlagSet("policy approval respond")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { r.showCommandHelp(policyApprovalRespondHelp()) }
	option := fs.String("option", "", "Option ID offered by the approval")
	sandbox := fs.String("sandbox", "", "sandbox scope")
	_ = sandbox
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("policy approval respond", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: rsbx policy approval respond APPROVAL-ID --option OPTION-ID [flags]")
		return 2
	}
	if *option == "" {
		_, _ = fmt.Fprintln(r.Err, "error: --option is required\n  try: rsbx policy approval respond --help")
		return 2
	}
	decision, persist, err := mapApprovalOption(*option)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "error: %v\n  try: rsbx policy approval respond --help\n", err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	approval, ruleID, err := sdk.Approvals(client).RespondApproval(ctx, fs.Arg(0), decision, persist)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Responded to approval %s: %s\n", approval.ID, approval.State)
	if ruleID != "" {
		_, _ = fmt.Fprintf(r.Out, "Persisted rule: %s\n", ruleID)
	}
	return 0
}

func mapApprovalOption(option string) (sdk.ApprovalDecision, sdk.ApprovalPersistScope, error) {
	value := strings.ToLower(strings.TrimSpace(option))
	if value == "" {
		return "", "", errors.New("--option requires a value")
	}
	var decision sdk.ApprovalDecision
	switch {
	case strings.Contains(value, "deny"):
		decision = sdk.ApprovalDecisionDeny
	case strings.Contains(value, "approve"):
		decision = sdk.ApprovalDecisionApprove
	default:
		return "", "", fmt.Errorf("unknown approval option %q", option)
	}
	persist := sdk.ApprovalPersistScopeOnce
	if strings.Contains(value, "exact") || strings.Contains(value, "remember") {
		persist = sdk.ApprovalPersistScopeExact
	}
	return decision, persist, nil
}

func policyApprovalFromSDK(in sdk.Approval) policyApprovalOutput {
	out := policyApprovalOutput{
		ID:                in.ID,
		Kind:              string(in.Kind),
		State:             string(in.State),
		SandboxID:         in.SandboxID,
		ActionSummary:     in.ActionSummary,
		DestinationHost:   in.DestinationHost,
		DestinationPath:   in.DestinationPath,
		EnvNames:          append([]string(nil), in.EnvNames...),
		EnvNamesTruncated: in.EnvNamesTruncated,
		CwdSummary:        in.CwdSummary,
	}
	if !in.CreatedAt.IsZero() {
		out.CreatedAt = in.CreatedAt.UTC().Format(time.RFC3339)
	}
	for _, h := range in.Headers {
		out.Headers = append(out.Headers, policyApprovalHeaderOutput{
			Name:              h.Name,
			ValueClass:        string(h.ValueClass),
			VaultReferenceIDs: append([]string(nil), h.VaultReferenceIDs...),
		})
	}
	return out
}
