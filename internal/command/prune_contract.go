package command

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

// Stable machine codes emitted by the CLI for the prune contract. The daemon
// registry owns the transport-level refusal reasons; the filter codes are
// CLI-preflight only (PR-4).
const (
	pruneCodeNone       = "-"
	pruneCodeFilterReq  = "FILTER_REQUIRED"
	pruneCodeFilterBad  = "FILTER_UNKNOWN"
	pruneCodeNotOwned   = "NOT_OWNED"
	pruneCodePathEscape = "PATH_ESCAPE"
	pruneCodeUnknown    = "UNKNOWN_STATE"
	pruneCodeNotFound   = "NOT_FOUND"
	pruneCodeStale      = "STALE"
	pruneCodeError      = "ERROR"
)

// Result actions. skipped_running is an observed exclusion from the default
// scope, not a planned deletion, so it does not by itself fail the run
// (PR-1 POS: pruned=2 skipped_running=1 exits 0).
const (
	pruneActionRemoved        = "removed"
	pruneActionSkipped        = "skipped"
	pruneActionSkippedRunning = "skipped_running"
	pruneActionStale          = "stale"
	pruneActionUnclassified   = "unclassified"
	pruneActionFailed         = "failed"
)

type pruneFilterKind int

const (
	pruneFilterStatus pruneFilterKind = iota
	pruneFilterLabel
	pruneFilterName
	pruneFilterNameRegex
	pruneFilterUntil
)

type pruneFilter struct {
	raw    string
	kind   pruneFilterKind
	status string
	label  string
	name   string
	re     *regexp.Regexp
	until  *time.Time
}

type pruneFilterError struct {
	code    string
	message string
}

func (e *pruneFilterError) Error() string { return e.code + ": " + e.message }

func newPruneFilterError(code, message string) error {
	return &pruneFilterError{code: code, message: message}
}

// pruneStatusValues is the pinned status set accepted by --filter status=.
// It mirrors the public SDK sandbox states; operation-only values (done) are
// deliberately excluded.
var pruneStatusValues = map[string]struct{}{
	sdk.StatePending:  {},
	sdk.StateCreating: {},
	sdk.StateRunning:  {},
	sdk.StateStopping: {},
	sdk.StateStopped:  {},
	sdk.StateDeleting: {},
	sdk.StateDeleted:  {},
	sdk.StateFailed:   {},
	sdk.StateUnknown:  {},
}

// parsePruneFilter validates the whole filter grammar before any RPC. An empty
// or whitespace-only expression is FILTER_REQUIRED; every other grammar or
// value error is FILTER_UNKNOWN. No expression means default scope.
func parsePruneFilter(raw string, now time.Time) (*pruneFilter, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, newPruneFilterError(pruneCodeFilterReq, "prune requires --filter or --all in non-interactive mode")
	}
	if strings.HasPrefix(raw, "name~") {
		return parsePruneNameRegex(raw)
	}
	key, value, ok := strings.Cut(raw, "=")
	if !ok {
		return nil, newPruneFilterError(pruneCodeFilterBad, "filter must be KEY=VALUE")
	}
	return parsePruneKeyValue(strings.TrimSpace(key), strings.TrimSpace(value), now)
}

func parsePruneNameRegex(raw string) (*pruneFilter, error) {
	pattern := strings.TrimSpace(strings.TrimPrefix(raw, "name~"))
	if !strings.HasPrefix(pattern, "^") || len(pattern) == 1 {
		return nil, newPruneFilterError(pruneCodeFilterBad, "name~ requires an anchored expression like name~^tmp-")
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, newPruneFilterError(pruneCodeFilterBad, "invalid name expression: "+err.Error())
	}
	return &pruneFilter{raw: raw, kind: pruneFilterNameRegex, re: compiled}, nil
}

func parsePruneKeyValue(key, value string, now time.Time) (*pruneFilter, error) {
	if value == "" {
		return nil, newPruneFilterError(pruneCodeFilterBad, "filter value is empty")
	}
	filter := &pruneFilter{raw: key + "=" + value}
	switch key {
	case "status":
		if _, ok := pruneStatusValues[value]; !ok {
			return nil, newPruneFilterError(pruneCodeFilterBad, "unknown status value "+strconv.Quote(value))
		}
		filter.kind = pruneFilterStatus
		filter.status = value
	case "label":
		labelKey, labelValue, ok := strings.Cut(value, "=")
		labelKey = strings.TrimSpace(labelKey)
		labelValue = strings.TrimSpace(labelValue)
		if !ok || labelKey == "" || labelValue == "" {
			return nil, newPruneFilterError(pruneCodeFilterBad, "label filter must be label=KEY=VALUE")
		}
		filter.kind = pruneFilterLabel
		filter.label = labelKey + "=" + labelValue
	case "name":
		if strings.Contains(value, "~") {
			return nil, newPruneFilterError(pruneCodeFilterBad, "name= accepts a plain name; use name~^prefix for a regex")
		}
		filter.kind = pruneFilterName
		filter.name = value
	case "until":
		cutoff, err := parsePruneUntil(value, now)
		if err != nil {
			return nil, err
		}
		filter.kind = pruneFilterUntil
		filter.until = &cutoff
	default:
		return nil, newPruneFilterError(pruneCodeFilterBad, "unknown filter key "+strconv.Quote(key)+" (supported: status, label, name, until)")
	}
	return filter, nil
}

func parsePruneUntil(value string, now time.Time) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return time.Time{}, newPruneFilterError(pruneCodeFilterBad, "until must not be negative")
		}
		return time.Unix(seconds, 0).UTC(), nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return time.Time{}, newPruneFilterError(pruneCodeFilterBad, "until must be an RFC3339 timestamp, Unix seconds, or a non-negative duration")
	}
	return now.Add(-duration), nil
}

// matches applies the filter to one inventory record. label filters always
// report false because the pinned list RPC exposes no labels; the expression
// is still validated so a typo cannot become match-all.
func (f *pruneFilter) matches(sb *sdk.Sandbox) bool {
	if f == nil {
		return true
	}
	switch f.kind {
	case pruneFilterStatus:
		return sb.State == f.status
	case pruneFilterLabel:
		return false
	case pruneFilterName:
		return sb.Name == f.name
	case pruneFilterNameRegex:
		return f.re.MatchString(sb.Name)
	case pruneFilterUntil:
		return !sb.StoppedAt.IsZero() && sb.StoppedAt.Before(*f.until)
	default:
		return false
	}
}

// prunePlanItem is one record in the two-phase plan. record_hash is computed
// from the canonical JSON of the list RPC record because the pinned list
// payload has no daemon-supplied record hash.
type prunePlanItem struct {
	ID         string   `json:"id" yaml:"id"`
	Name       string   `json:"name" yaml:"name"`
	Action     string   `json:"action" yaml:"action"`
	Code       string   `json:"code" yaml:"code"`
	Agent      string   `json:"agent,omitempty" yaml:"agent,omitempty"`
	StoppedAt  string   `json:"stopped_at,omitempty" yaml:"stopped_at,omitempty"`
	Workspaces []string `json:"workspaces,omitempty" yaml:"workspaces,omitempty"`
	RecordHash string   `json:"record_hash,omitempty" yaml:"record_hash,omitempty"`

	state        string
	updatedAt    time.Time
	stopRequired bool
}

func (p *prunePlanItem) selected() bool { return p.Action == pruneActionRemoved }

func pruneCandidateFor(sb *sdk.Sandbox) prunePlanItem {
	var workspaces []string
	if len(sb.Workspaces) > 0 {
		workspaces = workspacePaths(sb.Workspaces)
	} else if sb.Workspace != "" {
		workspaces = []string{sb.Workspace}
	}
	return prunePlanItem{
		ID:         sb.ID,
		Name:       sb.Name,
		Agent:      sb.Agent,
		StoppedAt:  listTime(sb.StoppedAt),
		Workspaces: workspaces,
		RecordHash: pruneRecordHash(sb),
		state:      sb.State,
		updatedAt:  sb.UpdatedAt,
	}
}

// pruneRecordHash is a SHA-256 over the canonical JSON encoding of the state
// record exactly as the list RPC returned it.
func pruneRecordHash(sb *sdk.Sandbox) string {
	data, err := json.Marshal(sb)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// buildPrunePlan classifies the whole inventory before anything is deleted.
// Foreign records never reach this stage because the daemon gates List; the
// probe pass below still handles a daemon that leaks one.
func buildPrunePlan(items []sdk.Sandbox, opts pruneOptions) []prunePlanItem {
	plan := make([]prunePlanItem, 0, len(items))
	for i := range items {
		sb := &items[i]
		if !opts.filter.matches(sb) {
			continue
		}
		if sb.State == sdk.StateRunning && opts.filter != nil && opts.filter.kind == pruneFilterUntil {
			continue
		}
		item := pruneCandidateFor(sb)
		switch sb.State {
		case sdk.StateStopped:
			if sb.StoppedAt.IsZero() {
				item.Action = pruneActionSkipped
				item.Code = pruneCodeUnknown
				break
			}
			item.Action = pruneActionRemoved
			item.Code = pruneCodeNone
		case sdk.StateRunning:
			if opts.all || (opts.filter != nil && opts.filter.kind == pruneFilterStatus && opts.filter.status == sdk.StateRunning) {
				item.Action = pruneActionRemoved
				item.Code = pruneCodeNone
				item.stopRequired = true
				break
			}
			item.Action = pruneActionSkippedRunning
			item.Code = pruneCodeNone
		default:
			item.Action = pruneActionUnclassified
			item.Code = pruneCodeUnknown
		}
		plan = append(plan, item)
	}
	return plan
}

// probePrunePlan performs the read/list validation pass. Any unclassifiable
// record aborts the default run before the first deletion (A2).
func (r *Runner) probePrunePlan(ctx context.Context, client sdk.Client, plan []prunePlanItem) ([]prunePlanItem, bool) {
	abort := false
	for i := range plan {
		if !plan[i].selected() {
			continue
		}
		sandbox, err := client.Sandboxes().Get(ctx, plan[i].ID)
		if err == nil {
			if sandbox.State != plan[i].state || sandbox.Name != plan[i].Name {
				plan[i].Action = pruneActionStale
				plan[i].Code = pruneCodeStale
			}
			continue
		}
		code := machineCodeOf(err)
		switch code {
		case pruneCodeNotFound:
			plan[i].Action = pruneActionStale
			plan[i].Code = pruneCodeStale
		default:
			plan[i].Action = pruneActionUnclassified
			if code == "" {
				code = pruneCodeError
			}
			plan[i].Code = code
			abort = true
		}
	}
	return plan, abort
}

// pruneSummary is the per-run aggregate. planned counts selected deletions;
// skipped includes skipped_running and any selected item that could not be
// removed without a failure.
type pruneSummary struct {
	Planned      int `json:"planned" yaml:"planned"`
	Pruned       int `json:"pruned" yaml:"pruned"`
	Skipped      int `json:"skipped" yaml:"skipped"`
	Stale        int `json:"stale" yaml:"stale"`
	Unclassified int `json:"unclassified" yaml:"unclassified"`
	Failure      int `json:"failure" yaml:"failure"`
}

func summarizePrune(plan []prunePlanItem, executed bool) pruneSummary {
	var summary pruneSummary
	for i := range plan {
		switch plan[i].Action {
		case pruneActionRemoved:
			summary.Planned++
			if executed {
				summary.Pruned++
			}
		case pruneActionSkipped, pruneActionSkippedRunning:
			summary.Skipped++
		case pruneActionStale:
			summary.Planned++
			summary.Stale++
		case pruneActionUnclassified:
			summary.Planned++
			summary.Unclassified++
		case pruneActionFailed:
			summary.Planned++
			summary.Failure++
		}
	}
	return summary
}

// pruneExitCode implements PR-7: 0 only when every planned item was removed,
// 1 on any selected skip/stale/error, 2 on a pre-flight abort. skipped_running
// is outside the planned set and therefore does not fail a default run.
func pruneExitCode(plan []prunePlanItem, preflightAbort bool) int {
	if preflightAbort {
		return 2
	}
	for i := range plan {
		switch plan[i].Action {
		case pruneActionRemoved, pruneActionSkippedRunning:
			continue
		default:
			return 1
		}
	}
	return 0
}

// machineCodeOf extracts a daemon machine reason from an error. The pinned
// SDK maps gRPC status details to *sdk.Error and drops ErrorInfo, so the CLI
// accepts a typed carrier when present and falls back to a registered token
// in the message. It never guesses a code from a transport status class.
func machineCodeOf(err error) string {
	if err == nil {
		return ""
	}
	var coded interface{ MachineCode() string }
	if errors.As(err, &coded) {
		if code := normalizeMachineCode(coded.MachineCode()); code != "" {
			return code
		}
	}
	var reasoned interface{ Reason() string }
	if errors.As(err, &reasoned) {
		if code := normalizeMachineCode(reasoned.Reason()); code != "" {
			return code
		}
	}
	var typed *sdk.Error
	if errors.As(err, &typed) {
		if code := normalizeMachineCode(typed.Code); code != "" && isMachineCode(code) {
			return code
		}
	}
	for _, token := range machineCodeToken.FindAllString(err.Error(), -1) {
		if isMachineCode(token) {
			return token
		}
	}
	return ""
}

var machineCodeToken = regexp.MustCompile(`\b[A-Z][A-Z_]{3,}\b`)

var machineCodes = map[string]struct{}{
	pruneCodeNotOwned: {}, pruneCodePathEscape: {}, "PARTIAL_REMOVAL": {}, "STALE": {},
	"SPEC_INVALID": {}, "POLICY_DENY": {}, pruneCodeUnknown: {}, pruneCodeNotFound: {},
	"NAME_INVALID": {}, "NAME_CONFLICT": {}, "ENV_INVALID": {}, "BUSY": {}, "QUOTA_EXCEEDED": {},
	"BIND_FORBIDDEN": {}, "PORT_IN_USE": {}, "PROBE_UNAVAILABLE": {}, "SESSION_UNREAPED": {},
	pruneCodeFilterReq: {}, pruneCodeFilterBad: {}, "MEMBER_TYPE_REFUSED": {}, "LINK_ESCAPE": {},
	"COPY_ROLLBACK": {}, "HOST_PATH_NOT_ALLOWED": {}, "LEASE_DRAINING": {}, "PORT_RESERVED": {},
	"SETTINGS_INVALID": {}, "AUDIT_CAP_EXCEEDED": {}, "LIMITS_UNAVAILABLE": {},
	"PRIVILEGED_UNSUPPORTED": {}, "APPROVAL_PROVIDER_UNAVAILABLE": {},
}

func isMachineCode(code string) bool {
	_, ok := machineCodes[code]
	return ok
}

func normalizeMachineCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

func isUnclassifiedCode(code string) bool {
	switch code {
	case pruneCodeNotOwned, pruneCodePathEscape, pruneCodeUnknown:
		return true
	default:
		return false
	}
}

func joinPlanCode(code string) string {
	if code == "" {
		return pruneCodeNone
	}
	return code
}
