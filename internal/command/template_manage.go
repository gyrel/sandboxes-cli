package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

// Template management commands (ADR-0008): save/load/rm/export against the
// daemon TemplateService. Grammar mirrors the sbx baseline help captured
// 2026-11-21: `template save SANDBOX TAG [--output PATH]`,
// `template load FILE [NAME]`, `template rm NAME [-f]`,
// `template export NAME OUTPUT`.

const templateSaveUsage = `usage: rsbx template save SANDBOX TAG [--output PATH]

Capture a sandbox filesystem into a new template image. Stopped sandboxes
are restored to stopped after the capture; running sandboxes are captured
in place. Requires daemon template support (API 0.0.33 or newer).
`

const templateLoadUsage = `usage: rsbx template load FILE [NAME]

Import an OCI or docker-save template archive. NAME overrides the archived
reference.
`

const templateRemoveUsage = `usage: rsbx template rm [-f] NAME

Remove a recorded template. Sandboxes that still boot from it block the
removal; -f skips the confirmation prompt, not the reference guard.
`

const templateExportUsage = `usage: rsbx template export NAME OUTPUT

Write a docker-save archive of a recorded template. Existing OUTPUT files
are refused.
`

func (r *Runner) templateSave(ctx context.Context, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		_, _ = fmt.Fprint(r.Err, templateSaveUsage)
		return 0
	}
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, templateSaveUsage)
		return 2
	}
	fs := r.newFlagSet("template save")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { _, _ = fmt.Fprint(r.Err, templateSaveUsage) }
	output := fs.String("output", "", "also write a docker-save tar to this host path")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"--output": true})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("template save", err)
	}
	if fs.NArg() != 2 {
		_, _ = fmt.Fprint(r.Err, templateSaveUsage)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	id, err := findExecSandbox(ctx, client, fs.Arg(0))
	if err != nil {
		r.error(err)
		return 1
	}
	info, err := sdk.Templates(client).Save(ctx, id, fs.Arg(1), *output)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Saved template %s (%d layers, %s)\n", info.Template.Name, info.Template.Layers, formatBytes(info.Template.SizeBytes))
	if info.Notice != "" {
		_, _ = fmt.Fprintf(r.Err, "%s\n", info.Notice)
	}
	return 0
}

func (r *Runner) templateLoad(ctx context.Context, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		_, _ = fmt.Fprint(r.Err, templateLoadUsage)
		return 0
	}
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, templateLoadUsage)
		return 2
	}
	fs := r.newFlagSet("template load")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { _, _ = fmt.Fprint(r.Err, templateLoadUsage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("template load", err)
	}
	if fs.NArg() != 1 && fs.NArg() != 2 {
		_, _ = fmt.Fprint(r.Err, templateLoadUsage)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	name := ""
	if fs.NArg() == 2 {
		name = fs.Arg(1)
	}
	info, err := sdk.Templates(client).Load(ctx, fs.Arg(0), name)
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Loaded template %s (%d layers, %s)\n", info.Name, info.Layers, formatBytes(info.SizeBytes))
	return 0
}

func (r *Runner) templateRemove(ctx context.Context, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		_, _ = fmt.Fprint(r.Err, templateRemoveUsage)
		return 0
	}
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, templateRemoveUsage)
		return 2
	}
	fs := r.newFlagSet("template rm")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { _, _ = fmt.Fprint(r.Err, templateRemoveUsage) }
	force := fs.Bool("force", false, "skip the confirmation prompt")
	forceShort := fs.Bool("f", false, "skip the confirmation prompt")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{"--force": false, "-f": false})); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("template rm", err)
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprint(r.Err, templateRemoveUsage)
		return 2
	}
	name := fs.Arg(0)
	if !*force && !*forceShort {
		_, _ = fmt.Fprintf(r.Out, "Remove template %s? [y/N] ", name)
		var answer string
		if _, err := fmt.Fscanln(r.In, &answer); err != nil || !strings.EqualFold(answer, "y") {
			_, _ = fmt.Fprintln(r.Out, "Removal canceled")
			return 0
		}
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if _, err := sdk.Templates(client).Remove(ctx, name, *force || *forceShort); err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Removed template %s\n", name)
	return 0
}

func (r *Runner) templateExport(ctx context.Context, args []string) int {
	if hasFlag(args, helpFlag) || hasFlag(args, helpShort) {
		_, _ = fmt.Fprint(r.Err, templateExportUsage)
		return 0
	}
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, templateExportUsage)
		return 2
	}
	fs := r.newFlagSet("template export")
	fs.SetOutput(io.Discard)
	fs.Usage = func() { _, _ = fmt.Fprint(r.Err, templateExportUsage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("template export", err)
	}
	if fs.NArg() != 2 {
		_, _ = fmt.Fprint(r.Err, templateExportUsage)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	size, err := sdk.Templates(client).Export(ctx, fs.Arg(0), fs.Arg(1))
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Exported %s to %s (%s)\n", fs.Arg(0), fs.Arg(1), formatBytes(size))
	return 0
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/float64(1<<30), 'f', 1, 64) + " GiB"
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/float64(1<<20), 'f', 1, 64) + " MiB"
	case n >= 1<<10:
		return strconv.FormatFloat(float64(n)/float64(1<<10), 'f', 1, 64) + " KiB"
	default:
		return strconv.FormatInt(n, 10) + " bytes"
	}
}
