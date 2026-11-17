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

	sdk "github.com/rheic/sandboxes-go-sdk"
)

const listUsage = `usage: rsbx ls [--format table|json|yaml] [--json] [-q] [--limit N]

List sandboxes. table is the default; --json is equivalent to --format json;
-q prints only names. --limit N returns at most N sandboxes (1-1000); without
it every sandbox is listed. JSON/YAML use the sbx ls schema: name, id, agent,
status, last_used_at, workspaces and created_at. Flags may appear in any
order; use -- to end flag parsing.

Examples:
  rsbx ls
  rsbx ls --json
  rsbx ls -q --limit 100
  rsbx ls --limit 10 --format yaml
`

// sandboxPageSize is the daemon page size used when listing sandboxes. It is
// independent of --limit, which caps the number of returned rows.
const sandboxPageSize = 200

const (
	listFormatTable = "table"
	listFormatJSON  = "json"
	listFormatYAML  = "yaml"
)

type listOptions struct {
	limit  int // 0 means no limit
	format string
	quiet  bool
}

// sandboxOutput mirrors the sbx ls JSON entry: name, id, agent, status,
// last_used_at, workspaces and created_at, in that order. Fields sbx omits
// when empty keep the same omitempty behavior here.
type sandboxOutput struct {
	Name       string   `json:"name" yaml:"name"`
	ID         string   `json:"id" yaml:"id"`
	Agent      string   `json:"agent" yaml:"agent"`
	Status     string   `json:"status" yaml:"status"`
	LastUsedAt string   `json:"last_used_at,omitempty" yaml:"last_used_at,omitempty"`
	Workspaces []string `json:"workspaces,omitempty" yaml:"workspaces,omitempty"`
	CreatedAt  string   `json:"created_at,omitempty" yaml:"created_at,omitempty"`
}

func (r *Runner) list(ctx context.Context, args []string) int {
	opts, help, err := parseListOptions(args)
	if help {
		_, _ = fmt.Fprint(r.Out, listUsage)
		return 0
	}
	if parseErr, ok := asFlagParseError(err); ok {
		return r.flagParseFailure("ls", parseErr.err)
	}
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx ls: %v\n", err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	items, err := collectSandboxes(ctx, client, sandboxPageSize, opts.limit)
	if err != nil {
		r.error(err)
		return 1
	}
	if opts.quiet {
		for i := range items {
			_, _ = fmt.Fprintln(r.Out, items[i].Name)
		}
		return 0
	}
	if err := renderSandboxes(r.Out, opts.format, items); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func parseListOptions(args []string) (listOptions, bool, error) {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	limit := fs.Int("limit", 0, "maximum number of sandboxes to return (1-1000; default all)")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	quiet := fs.Bool("q", false, "only display sandbox names")
	fs.BoolVar(quiet, "quiet", false, "only display sandbox names")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{limitFlag: true, formatFlag: true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return listOptions{}, true, nil
		}
		return listOptions{}, false, flagParseError{err: err}
	}
	limitValue, ok := parseListLimit(fs, limit)
	if !ok {
		return listOptions{}, false, errors.New("--limit must be between 1 and 1000")
	}
	if fs.NArg() != 0 {
		return listOptions{}, false, errors.New("usage: rsbx ls [--format table|json|yaml] [--json] [-q] [--limit N]")
	}
	selected := *format
	if *jsonOutput {
		if *format != listFormatTable {
			return listOptions{}, false, errors.New("--json cannot be combined with an explicit --format")
		}
		selected = listFormatJSON
	}
	if selected != listFormatTable && selected != listFormatJSON && selected != listFormatYAML {
		return listOptions{}, false, fmt.Errorf("invalid format %q; use table, json or yaml", selected)
	}
	if *quiet && selected != listFormatTable {
		return listOptions{}, false, errors.New("--quiet cannot be combined with a non-table format")
	}
	return listOptions{limit: limitValue, format: selected, quiet: *quiet}, false, nil
}

// parseListLimit reports the result cap. An unset flag means no cap; an
// explicit value must be between 1 and 1000.
func parseListLimit(fs *flag.FlagSet, limit *int) (int, bool) {
	limitSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "limit" {
			limitSet = true
		}
	})
	if !limitSet {
		return 0, true
	}
	if *limit <= 0 || *limit > 1000 {
		return 0, false
	}
	return *limit, true
}

// collectSandboxes fetches every page with pageSize rows per request. A
// positive limit stops fetching once that many rows are collected.
func collectSandboxes(ctx context.Context, client sdk.Client, pageSize, limit int) ([]sdk.Sandbox, error) {
	if pageSize <= 0 {
		pageSize = sandboxPageSize
	}
	items := make([]sdk.Sandbox, 0, pageSize)
	seen := make(map[string]struct{})
	token := ""
	for pages := 0; pages < 10000; pages++ {
		page, err := client.Sandboxes().List(ctx, sdk.ListOptions{PageSize: pageSize, PageToken: token})
		if err != nil {
			return nil, err
		}
		items = append(items, page.Items...)
		if limit > 0 && len(items) >= limit {
			return items[:limit], nil
		}
		if page.NextPageToken == "" {
			return items, nil
		}
		if _, exists := seen[page.NextPageToken]; exists {
			return nil, errors.New("invalid sandbox pagination")
		}
		seen[page.NextPageToken] = struct{}{}
		token = page.NextPageToken
	}
	return nil, errors.New("too many sandbox pages")
}

func renderSandboxes(out io.Writer, format string, items []sdk.Sandbox) error {
	switch format {
	case listFormatJSON:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(sandboxOutputs(items))
	case listFormatYAML:
		data, err := yaml.Marshal(sandboxOutputs(items))
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		return writeSandboxTable(out, items)
	}
}

func sandboxOutputs(items []sdk.Sandbox) []sandboxOutput {
	output := make([]sandboxOutput, 0, len(items))
	for i := range items {
		output = append(output, sandboxOutputFor(&items[i]))
	}
	return output
}

func sandboxOutputFor(sb *sdk.Sandbox) sandboxOutput {
	var workspaces []string
	if len(sb.Workspaces) > 0 {
		workspaces = workspacePaths(sb.Workspaces)
	} else if sb.Workspace != "" {
		workspaces = []string{sb.Workspace}
	}
	return sandboxOutput{
		Name:       sb.Name,
		ID:         sb.ID,
		Agent:      sb.Agent,
		Status:     sb.State,
		LastUsedAt: listTime(sb.LastUsedAt),
		Workspaces: workspaces,
		CreatedAt:  listTime(sb.CreatedAt),
	}
}

func listTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func writeSandboxTable(out io.Writer, items []sdk.Sandbox) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SANDBOX\tAGENT\tSTATUS\tPORTS\tWORKSPACE\tCREATED")
	for i := range items {
		sb := &items[i]
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", sb.Name, formatAgent(sb.Agent), formatStatus(sb.State), formatPorts(sb), formatWorkspaces(sb), formatAge(sb.CreatedAt))
	}
	return tw.Flush()
}

// formatStatus renders the state with the reference status markers so the
// table reads the same way as the Docker Sandboxes table.
func formatStatus(state string) string {
	switch state {
	case sdk.StateRunning:
		return "● " + state
	case sdk.StateStopped:
		return "○ " + state
	case "":
		return "-"
	default:
		return "◌ " + state
	}
}

func formatAgent(agent string) string {
	if agent == "" {
		return "-"
	}
	return agent
}

func formatAge(created time.Time) string {
	if created.IsZero() {
		return "-"
	}
	age := time.Since(created)
	if age < 0 {
		age = 0
	}
	switch {
	case age < time.Minute:
		return "now"
	case age < time.Hour:
		return fmt.Sprintf("%dm", int(age.Minutes()))
	case age < 24*time.Hour:
		return fmt.Sprintf("%dh", int(age.Hours()))
	case age < 7*24*time.Hour:
		return fmt.Sprintf("%dd", int(age.Hours()/24))
	default:
		return fmt.Sprintf("%dw", int(age.Hours()/(24*7)))
	}
}
