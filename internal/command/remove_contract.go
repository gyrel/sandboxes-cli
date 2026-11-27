package command

import (
	"context"
	"errors"
	"fmt"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

const removeActionRefused = "refused"

// removeRecord is one per-target result for a multi-target rm. Single-target
// rm keeps its historical output path; this path implements the SR-1
// partial-failure aggregation contract.
type removeRecord struct {
	id      string
	name    string
	action  string
	code    string
	message string
	sandbox *sdk.Sandbox
}

func (r *Runner) removeMany(ctx context.Context, client sdk.Client, opts removeOptions) int {
	records := make([]removeRecord, 0, len(opts.targets))
	removable := make([]int, 0, len(opts.targets))
	for _, target := range opts.targets {
		record, canRemove := r.resolveRemoveRecord(ctx, client, target, opts.force)
		records = append(records, record)
		if canRemove {
			removable = append(removable, len(records)-1)
		}
	}
	if !opts.force && len(removable) > 0 {
		confirmed, err := r.confirmRemoval(len(removable))
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "Removal canceled")
			return 0
		}
	}
	for _, index := range removable {
		r.deleteRemoveRecord(ctx, client, &records[index], opts.force)
	}
	r.renderRemoveRecords(records, opts.format)
	for i := range records {
		if records[i].action != pruneActionRemoved {
			return 1
		}
	}
	return 0
}

func (r *Runner) resolveRemoveRecord(ctx context.Context, client sdk.Client, target string, force bool) (removeRecord, bool) {
	id, err := findExecSandbox(ctx, client, target)
	if err != nil {
		return removeRecord{name: target, action: removeActionRefused, code: removeResolveCode(err), message: err.Error()}, false
	}
	sandbox, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		return removeRecord{id: id, name: target, action: removeActionRefused, code: removeResolveCode(err), message: err.Error()}, false
	}
	if !force && sandbox.State != sdk.StateStopped {
		return removeRecord{
			id: id, name: sandbox.Name, action: removeActionRefused, code: "BUSY",
			message: removalStateError(sandbox).Error(), sandbox: sandbox,
		}, false
	}
	return removeRecord{id: id, name: sandbox.Name, action: pruneActionRemoved, code: pruneCodeNone, sandbox: sandbox}, true
}

func removeResolveCode(err error) string {
	if code := machineCodeOf(err); code != "" {
		return code
	}
	var missing sandboxNotFoundError
	if errors.As(err, &missing) {
		return pruneCodeNotFound
	}
	return pruneCodeError
}

func (r *Runner) deleteRemoveRecord(ctx context.Context, client sdk.Client, record *removeRecord, force bool) {
	r.warnCloneRemoval(record.sandbox)
	op, err := client.Sandboxes().Delete(ctx, record.id, sdk.DeleteOptions{Force: force})
	if err != nil {
		record.code = removeResolveCode(err)
		record.message = err.Error()
		record.action = removeFailureAction(record.code)
		return
	}
	if op != nil && op.State == sdk.StateFailed {
		record.code = operationMachineCode(op)
		record.action = removeFailureAction(record.code)
		record.message = op.Error
		return
	}
	record.action = pruneActionRemoved
	record.code = pruneCodeNone
	r.cleanupDeletedCloneRemote(ctx, record.sandbox, false)
}

func removeFailureAction(code string) string {
	if isUnclassifiedCode(code) {
		return removeActionRefused
	}
	return pruneActionFailed
}

func (r *Runner) renderRemoveRecords(records []removeRecord, format string) {
	if format != listFormatTable {
		r.renderRemoveStructured(records, format)
		return
	}
	summary := struct{ pruned, skipped, unclassified, failure int }{}
	for i := range records {
		id := records[i].id
		if id == "" {
			id = "-"
		}
		_, _ = fmt.Fprintf(r.Out, "%s|%s|%s|%s\n", id, records[i].name, records[i].action, joinPlanCode(records[i].code))
		switch {
		case records[i].action == pruneActionRemoved:
			summary.pruned++
		case isUnclassifiedCode(records[i].code):
			summary.unclassified++
		case records[i].action == removeActionRefused:
			summary.skipped++
		default:
			summary.failure++
		}
	}
	_, _ = fmt.Fprintf(r.Out, "summary: pruned=%d skipped=%d stale=0 unclassified=%d failure=%d\n",
		summary.pruned, summary.skipped, summary.unclassified, summary.failure)
}

func (r *Runner) renderRemoveStructured(records []removeRecord, format string) {
	items := make([]mutationOutput, 0, len(records))
	for i := range records {
		items = append(items, mutationOutput{
			Action: records[i].action, Resource: resourceSandbox, Name: records[i].name,
			ID: records[i].id, Code: joinPlanCode(records[i].code), Error: records[i].message,
		})
	}
	if err := renderMutations(r.Out, format, items); err != nil {
		r.error(err)
	}
}
