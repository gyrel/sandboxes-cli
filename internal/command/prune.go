package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	sdk "github.com/gyrel/sandboxes-go-sdk"
	"gopkg.in/yaml.v3"
)

type pruneOptions struct {
	dryRun           bool
	force            bool
	all              bool
	allowUnknownSkip bool
	format           string
	filter           *pruneFilter
}

func (r *Runner) prune(ctx context.Context, args []string) int {
	opts, code, done := r.parsePruneCommand(args)
	if done {
		return code
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	return r.runPrune(ctx, client, opts)
}

func (r *Runner) parsePruneCommand(args []string) (pruneOptions, int, bool) {
	opts, help, err := r.parsePruneOptions(args)
	if help {
		return pruneOptions{}, r.showCommandHelp(pruneHelp()), true
	}
	if parseErr, ok := asFlagParseError(err); ok {
		return pruneOptions{}, r.flagParseFailure("prune", parseErr.err), true
	}
	var filterErr *pruneFilterError
	if errors.As(err, &filterErr) {
		_, _ = fmt.Fprintf(r.Err, "error: %s\n", filterErr.Error())
		return pruneOptions{}, 2, true
	}
	if err != nil {
		r.error(err)
		return pruneOptions{}, 2, true
	}
	// A bare non-interactive prune must not guess a match-all scope (PR-5).
	// Dry-run is safe and remains usable without --filter for planning.
	if opts.filter == nil && !opts.all && !opts.dryRun && !r.stdinIsTerminal() {
		r.error(newPruneFilterError(pruneCodeFilterReq, "prune without --filter or --all requires a terminal; use --filter status=stopped or --all"))
		return pruneOptions{}, 2, true
	}
	return opts, 0, false
}

func (r *Runner) runPrune(ctx context.Context, client sdk.Client, opts pruneOptions) int {
	items, err := collectSandboxes(ctx, client, sandboxPageSize, 0)
	if err != nil {
		r.error(err)
		return 1
	}
	plan := buildPrunePlan(items, opts)
	plan, abort := r.probePrunePlan(ctx, client, plan)
	if abort {
		if code, handled := r.handlePruneAbort(plan, opts); handled {
			return code
		}
	}
	if opts.dryRun {
		return r.pruneDryRun(plan, opts.format)
	}
	selected := selectedPruneItems(plan)
	if len(selected) == 0 {
		r.renderPruneResults(plan, opts.format, false)
		return pruneExitCode(plan, false)
	}
	if !opts.force {
		confirmed, err := r.confirmPrune(len(selected))
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "Prune canceled")
			return 0
		}
	}
	return r.executePrunePlan(ctx, client, plan, opts)
}

// handlePruneAbort implements A2: the default run refuses with zero deletions;
// --allow-unknown-skip excludes the records and reports them as skipped.
func (r *Runner) handlePruneAbort(plan []prunePlanItem, opts pruneOptions) (int, bool) {
	if !opts.allowUnknownSkip {
		for i := range plan {
			if plan[i].selected() {
				plan[i].Action = pruneActionSkipped
				plan[i].Code = pruneCodeNone
			}
		}
		if opts.dryRun {
			r.renderPruneDryRunPlan(plan, opts.format)
			return 2, true
		}
		r.renderPruneResults(plan, opts.format, false)
		return 2, true
	}
	for i := range plan {
		if plan[i].Action == pruneActionUnclassified {
			plan[i].Action = pruneActionSkipped
		}
	}
	return 0, false
}

func (r *Runner) renderPruneDryRunPlan(plan []prunePlanItem, format string) {
	if format == listFormatTable {
		for i := range plan {
			if plan[i].selected() {
				_, _ = fmt.Fprintln(r.Out, plan[i].ID)
			}
		}
		return
	}
	if err := renderPruneDryRun(r.Out, format, plan); err != nil {
		r.error(err)
	}
}

func selectedPruneItems(plan []prunePlanItem) []prunePlanItem {
	selected := make([]prunePlanItem, 0, len(plan))
	for i := range plan {
		if plan[i].selected() {
			selected = append(selected, plan[i])
		}
	}
	return selected
}

func (r *Runner) pruneDryRun(plan []prunePlanItem, format string) int {
	if format == listFormatTable {
		for i := range plan {
			if plan[i].selected() {
				_, _ = fmt.Fprintln(r.Out, plan[i].ID)
			}
		}
		return 0
	}
	if err := renderPruneDryRun(r.Out, format, plan); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

// executePrunePlan re-lists the inventory and deletes only items whose record
// hash, id, name and updated_at still match the plan (PR-3).
func (r *Runner) executePrunePlan(ctx context.Context, client sdk.Client, plan []prunePlanItem, opts pruneOptions) int {
	items, err := collectSandboxes(ctx, client, sandboxPageSize, 0)
	if err != nil {
		r.error(err)
		return 2
	}
	current := make(map[string]sdk.Sandbox, len(items))
	for i := range items {
		current[items[i].ID] = items[i]
	}
	results := make([]prunePlanItem, 0, len(plan))
	for i := range plan {
		results = append(results, r.executePruneItem(ctx, client, plan[i], current, opts))
	}
	r.renderPruneResults(results, opts.format, true)
	return pruneExitCode(results, false)
}

func (r *Runner) executePruneItem(ctx context.Context, client sdk.Client, item prunePlanItem, current map[string]sdk.Sandbox, opts pruneOptions) prunePlanItem {
	if !item.selected() {
		return item
	}
	sandbox, ok := current[item.ID]
	if !ok || sandbox.Name != item.Name || !sandbox.UpdatedAt.Equal(item.updatedAt) ||
		pruneRecordHash(&sandbox) != item.RecordHash {
		item.Action = pruneActionStale
		item.Code = pruneCodeStale
		return item
	}
	if item.stopRequired && sandbox.State == sdk.StateRunning && r.stopPruneItem(ctx, client, &item, &sandbox) {
		return item
	}
	r.deletePruneItem(ctx, client, &item, &sandbox, opts.force)
	return item
}

func (r *Runner) stopPruneItem(ctx context.Context, client sdk.Client, item *prunePlanItem, sandbox *sdk.Sandbox) bool {
	op, err := client.Sandboxes().Stop(ctx, sandbox.ID, sdk.StopOptions{})
	if err != nil {
		item.Action, item.Code = pruneFailureAction(err)
		return true
	}
	if op != nil && op.State == sdk.StateFailed {
		item.Action = pruneActionFailed
		item.Code = operationMachineCode(op)
		return true
	}
	return false
}

func (r *Runner) deletePruneItem(ctx context.Context, client sdk.Client, item *prunePlanItem, sandbox *sdk.Sandbox, force bool) bool {
	r.warnCloneRemoval(sandbox)
	op, err := client.Sandboxes().Delete(ctx, sandbox.ID, sdk.DeleteOptions{Force: force})
	if err != nil {
		item.Action, item.Code = pruneFailureAction(err)
		return true
	}
	if op != nil && op.State == sdk.StateFailed {
		item.Action = pruneActionFailed
		item.Code = operationMachineCode(op)
		return true
	}
	item.Action = pruneActionRemoved
	item.Code = pruneCodeNone
	r.cleanupDeletedCloneRemote(ctx, sandbox, true)
	return false
}

func pruneFailureAction(err error) (string, string) {
	code := machineCodeOf(err)
	if isUnclassifiedCode(code) {
		return pruneActionUnclassified, code
	}
	if code == "" {
		code = pruneCodeError
	}
	return pruneActionFailed, code
}

func operationMachineCode(op *sdk.Operation) string {
	if op == nil {
		return pruneCodeError
	}
	if code := machineCodeOf(errors.New(op.Error)); code != "" {
		return code
	}
	return pruneCodeError
}

func (r *Runner) renderPruneResults(plan []prunePlanItem, format string, executed bool) {
	if format != listFormatTable {
		r.renderPruneStructured(plan, format)
		return
	}
	for i := range plan {
		_, _ = fmt.Fprintf(r.Out, "%s|%s|%s|%s\n", plan[i].ID, plan[i].Name, plan[i].Action, joinPlanCode(plan[i].Code))
	}
	summary := summarizePrune(plan, executed)
	_, _ = fmt.Fprintf(r.Out, "summary: pruned=%d skipped=%d stale=%d unclassified=%d failure=%d\n",
		summary.Pruned, summary.Skipped, summary.Stale, summary.Unclassified, summary.Failure)
}

func (r *Runner) renderPruneStructured(plan []prunePlanItem, format string) {
	items := make([]mutationOutput, 0, len(plan))
	for i := range plan {
		items = append(items, mutationOutput{
			Action: plan[i].Action, Resource: resourceSandbox, Name: plan[i].Name,
			ID: plan[i].ID, Code: joinPlanCode(plan[i].Code),
		})
	}
	if err := renderMutations(r.Out, format, items); err != nil {
		r.error(err)
	}
}

func (r *Runner) parsePruneOptions(args []string) (pruneOptions, bool, error) {
	fs := r.newFlagSet("prune")
	fs.SetOutput(io.Discard)
	dryRun := fs.Bool("dry-run", false, "list the validated plan without removing anything")
	force := fs.Bool("force", false, "remove without confirmation; escalates teardown of owned running sandboxes")
	fs.BoolVar(force, "f", false, "remove without confirmation")
	all := fs.Bool("all", false, "include running sandboxes (stop then delete)")
	allowUnknownSkip := fs.Bool("allow-unknown-skip", false, "exclude unclassifiable items and continue")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	filterValue := fs.String("filter", "", "filter candidates: status=STATE, label=KEY=VALUE, name=NAME, name~^REGEX, until=DURATION")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return pruneOptions{}, true, nil
		}
		return pruneOptions{}, false, flagParseError{err: err}
	}
	if fs.NArg() != 0 {
		return pruneOptions{}, false, errors.New("usage: rsbx prune [--dry-run] [-f|--force] [--all] [--filter FILTER] [--allow-unknown-skip] [--format table|json|yaml]")
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		return pruneOptions{}, false, err
	}
	filterSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "filter" {
			filterSet = true
		}
	})
	var filter *pruneFilter
	if filterSet {
		filter, err = parsePruneFilter(*filterValue, time.Now())
		if err != nil {
			return pruneOptions{}, false, err
		}
	}
	return pruneOptions{
		dryRun: *dryRun, force: *force, all: *all, allowUnknownSkip: *allowUnknownSkip,
		format: selected, filter: filter,
	}, false, nil
}

// pruneDryRunEnvelope is the structured plan. would_remove keeps the sbx
// field name; skipped_running and unclassified are new fail-closed sections.
type pruneDryRunEnvelope struct {
	WouldRemove        []prunePlanItem `json:"would_remove" yaml:"would_remove"`
	SkippedUnknownStop []string        `json:"skipped_unknown_stop" yaml:"skipped_unknown_stop"`
	SkippedRunning     []string        `json:"skipped_running" yaml:"skipped_running"`
	Unclassified       []prunePlanItem `json:"unclassified" yaml:"unclassified"`
	Summary            pruneSummary    `json:"summary" yaml:"summary"`
}

func renderPruneDryRun(out io.Writer, format string, plan []prunePlanItem) error {
	output := pruneDryRunEnvelope{
		WouldRemove:        make([]prunePlanItem, 0),
		SkippedUnknownStop: make([]string, 0),
		SkippedRunning:     make([]string, 0),
		Unclassified:       make([]prunePlanItem, 0),
	}
	for i := range plan {
		switch plan[i].Action {
		case pruneActionRemoved:
			output.WouldRemove = append(output.WouldRemove, plan[i])
		case pruneActionSkippedRunning:
			output.SkippedRunning = append(output.SkippedRunning, plan[i].Name)
		case pruneActionUnclassified, pruneActionFailed:
			output.Unclassified = append(output.Unclassified, plan[i])
		case pruneActionSkipped:
			if plan[i].Code == pruneCodeUnknown {
				output.SkippedUnknownStop = append(output.SkippedUnknownStop, plan[i].Name)
				break
			}
			output.Unclassified = append(output.Unclassified, plan[i])
		}
	}
	output.Summary = summarizePrune(plan, false)
	switch format {
	case listFormatJSON:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	case listFormatYAML:
		data, err := yaml.Marshal(output)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		return fmt.Errorf("unsupported format %q for structured prune output", format)
	}
}

func (r *Runner) confirmPrune(count int) (bool, error) {
	return r.confirmDestructive("prune", fmt.Sprintf("Remove %d stopped sandbox(es)?", count))
}
