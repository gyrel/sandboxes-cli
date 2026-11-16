package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	sdk "github.com/rheic/sandboxes-go-sdk"
	"gopkg.in/yaml.v3"
)

type pruneOptions struct {
	dryRun bool
	force  bool
	format string
	until  *time.Time
}

func (r *Runner) prune(ctx context.Context, args []string) int {
	opts, help, err := parsePruneOptions(args)
	if help {
		_, _ = fmt.Fprint(r.Out, pruneUsage)
		return 0
	}
	if parseErr, ok := asFlagParseError(err); ok {
		return r.flagParseFailure("prune", parseErr.err)
	}
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
	items, err := collectSandboxes(ctx, client, sandboxPageSize, 0)
	if err != nil {
		r.error(err)
		return 1
	}
	stopped, skippedUnknownStop := selectPruneCandidates(items, opts.until)
	if opts.dryRun {
		return r.pruneDryRun(opts, stopped, skippedUnknownStop)
	}
	return r.pruneRemove(ctx, client, opts, stopped)
}

func (r *Runner) pruneDryRun(opts pruneOptions, stopped []sdk.Sandbox, skippedUnknownStop []string) int {
	if opts.format == listFormatTable {
		if len(stopped) == 0 {
			_, _ = fmt.Fprintln(r.Out, "No stopped sandboxes")
			return 0
		}
		printPruneCandidates(r.Out, stopped)
		return 0
	}
	if err := renderPruneDryRun(r.Out, opts.format, stopped, skippedUnknownStop); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func (r *Runner) pruneRemove(ctx context.Context, client sdk.Client, opts pruneOptions, stopped []sdk.Sandbox) int {
	if len(stopped) == 0 {
		if opts.format == listFormatTable {
			_, _ = fmt.Fprintln(r.Out, "No stopped sandboxes")
			return 0
		}
		if err := renderMutations(r.Out, opts.format, nil); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
	if !opts.force {
		confirmed, err := r.confirmPrune(len(stopped))
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "Prune canceled")
			return 0
		}
	}
	removed, failures := r.deletePrunedSandboxes(ctx, client, stopped)
	names := make([]string, 0, len(removed))
	for i := range removed {
		names = append(names, removed[i].Name)
	}
	if opts.format == listFormatTable {
		_, _ = fmt.Fprintf(r.Out, "Removed %d stopped sandboxes:\n", len(removed))
		printPruneTable(r.Out, removed)
	} else if err := renderMutations(r.Out, opts.format, sandboxMutations("removed", names)); err != nil {
		r.error(err)
		return 1
	}
	if failures != nil {
		r.error(failures)
		return 1
	}
	return 0
}

func parsePruneOptions(args []string) (pruneOptions, bool, error) {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dryRun := fs.Bool("dry-run", false, "list stopped sandboxes without removing them")
	force := fs.Bool("force", false, "remove without confirmation")
	fs.BoolVar(force, "f", false, "remove without confirmation")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	filter := fs.String("filter", "", "until=TIMESTAMP or until=DURATION")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return pruneOptions{}, true, nil
		}
		return pruneOptions{}, false, flagParseError{err: err}
	}
	if fs.NArg() != 0 {
		return pruneOptions{}, false, errors.New("usage: rsbx prune [--dry-run] [-f|--force] [--format table|json|yaml]")
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		return pruneOptions{}, false, err
	}
	until, hasUntil, err := parsePruneFilter(*filter, time.Now())
	if err != nil {
		return pruneOptions{}, false, err
	}
	var untilPtr *time.Time
	if hasUntil {
		untilPtr = &until
	}
	return pruneOptions{dryRun: *dryRun, force: *force, format: selected, until: untilPtr}, false, nil
}

// pruneCandidateOutput mirrors one sbx prune --dry-run candidate.
type pruneCandidateOutput struct {
	Name       string   `json:"name" yaml:"name"`
	Agent      string   `json:"agent,omitempty" yaml:"agent,omitempty"`
	StoppedAt  string   `json:"stopped_at,omitempty" yaml:"stopped_at,omitempty"`
	Workspaces []string `json:"workspaces,omitempty" yaml:"workspaces,omitempty"`
}

// pruneDryRunOutput mirrors the sbx prune --dry-run envelope.
type pruneDryRunOutput struct {
	WouldRemove        []pruneCandidateOutput `json:"would_remove" yaml:"would_remove"`
	SkippedUnknownStop []string               `json:"skipped_unknown_stop" yaml:"skipped_unknown_stop"`
}

func pruneCandidateFor(sb *sdk.Sandbox) pruneCandidateOutput {
	var workspaces []string
	if len(sb.Workspaces) > 0 {
		workspaces = workspacePaths(sb.Workspaces)
	} else if sb.Workspace != "" {
		workspaces = []string{sb.Workspace}
	}
	return pruneCandidateOutput{
		Name:       sb.Name,
		Agent:      sb.Agent,
		StoppedAt:  listTime(sb.StoppedAt),
		Workspaces: workspaces,
	}
}

func renderPruneDryRun(out io.Writer, format string, stopped []sdk.Sandbox, skippedUnknownStop []string) error {
	output := pruneDryRunOutput{
		WouldRemove:        make([]pruneCandidateOutput, 0, len(stopped)),
		SkippedUnknownStop: append([]string{}, skippedUnknownStop...),
	}
	for i := range stopped {
		output.WouldRemove = append(output.WouldRemove, pruneCandidateFor(&stopped[i]))
	}
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

// selectPruneCandidates returns stopped sandboxes with known stop times and
// names the sandboxes whose stop time the daemon could not report. Like sbx,
// unknown stop times are left alone because their age cannot be established.
func selectPruneCandidates(items []sdk.Sandbox, until *time.Time) ([]sdk.Sandbox, []string) {
	stopped := make([]sdk.Sandbox, 0, len(items))
	skipped := make([]string, 0)
	for i := range items {
		if items[i].State != sdk.StateStopped {
			continue
		}
		if items[i].StoppedAt.IsZero() {
			skipped = append(skipped, items[i].Name)
			continue
		}
		if until != nil && !items[i].StoppedAt.Before(*until) {
			continue
		}
		stopped = append(stopped, items[i])
	}
	return stopped, skipped
}

func parsePruneFilter(value string, now time.Time) (time.Time, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false, nil
	}
	if !strings.HasPrefix(value, "until=") {
		return time.Time{}, false, errors.New("prune filter must be until=TIMESTAMP or until=DURATION")
	}
	value = strings.TrimPrefix(value, "until=")
	if value == "" {
		return time.Time{}, false, errors.New("prune filter value is empty")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, true, nil
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(seconds, 0).UTC(), true, nil
	}
	if duration, err := time.ParseDuration(value); err == nil && duration >= 0 {
		return now.Add(-duration), true, nil
	}
	return time.Time{}, false, errors.New("prune filter must be an RFC3339 timestamp, Unix seconds, or a non-negative duration")
}

func (r *Runner) deletePrunedSandboxes(ctx context.Context, client sdk.Client, stopped []sdk.Sandbox) ([]sdk.Sandbox, error) {
	var failures []error
	removed := make([]sdk.Sandbox, 0, len(stopped))
	for i := range stopped {
		r.warnCloneRemoval(&stopped[i])
		op, err := client.Sandboxes().Delete(ctx, stopped[i].ID, sdk.DeleteOptions{Force: true})
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if op != nil && op.State == sdk.StateFailed {
			failures = append(failures, fmt.Errorf("prune sandbox %s failed: %s", stopped[i].Name, op.Error))
			continue
		}
		removed = append(removed, stopped[i])
		r.cleanupDeletedCloneRemote(ctx, &stopped[i], true)
	}
	return removed, errors.Join(failures...)
}

func printPruneCandidates(out io.Writer, items []sdk.Sandbox) {
	_, _ = fmt.Fprintf(out, "Would remove %d stopped sandboxes:\n", len(items))
	printPruneTable(out, items)
}

func printPruneTable(out io.Writer, items []sdk.Sandbox) {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SANDBOX\tAGENT\tSTOPPED\tWORKSPACE")
	for i := range items {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", items[i].Name, formatAgent(items[i].Agent), formatStoppedAge(items[i].StoppedAt), formatWorkspaces(&items[i]))
	}
	_ = tw.Flush()
}

func formatStoppedAge(stopped time.Time) string {
	if stopped.IsZero() {
		return "-"
	}
	return formatAge(stopped)
}

func (r *Runner) confirmPrune(count int) (bool, error) {
	return r.confirmDestructive("prune", fmt.Sprintf("Remove %d stopped sandbox(es)?", count))
}
