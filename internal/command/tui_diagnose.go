package command

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// diagnoseRunResult is the outcome of an in-process diagnose bundle build for
// the dashboard. On a redaction-guard refusal, Rules holds the rule ids that
// fired (never matched values); on success, Target and SHA256 identify the
// published archive.
type diagnoseRunResult struct {
	Target string
	SHA256 string
	Rules  []string
	Err    error
}

// diagnoseRunFunc builds a redacted diagnostic bundle to outPath in-process.
// It is injectable so the d hotkey can be exercised without a terminal or a
// real daemon.
type diagnoseRunFunc func(ctx context.Context, outPath string) diagnoseRunResult

// diagnoseRuleIDPattern matches the redaction guard's rule ids (lowercase
// snake_case). It is used only to validate the first field of a guard line, so
// a member name or other text can never be mistaken for a rule id.
var diagnoseRuleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// diagnoseRun runs the bundle builder against outPath, captures the guard's
// refusal output, and reports the archive path plus its SHA-256, or the
// refusal rule ids. It reuses the command Runner and never spawns a process.
func (r *Runner) diagnoseRun(ctx context.Context, outPath string) diagnoseRunResult {
	var guardOut bytes.Buffer
	saved := r.Err
	r.Err = &guardOut
	target, err := r.buildDiagnoseBundle(ctx, diagnoseBundleOptions{outPath: outPath})
	r.Err = saved
	if err != nil {
		return diagnoseRunResult{Err: err, Rules: diagnoseRefusalRules(guardOut.String())}
	}
	sum, err := sha256File(target)
	if err != nil {
		return diagnoseRunResult{Err: err}
	}
	return diagnoseRunResult{Target: target, SHA256: sum}
}

// diagnoseRefusalRules extracts the redaction rule ids from a bundle refusal.
// The guard writes one "<rule> <member> line <n> offset <m>" line per hit, so
// the first field of each line is the rule id. The result contains ids only and
// never matched values or member payloads.
func diagnoseRefusalRules(output string) []string {
	seen := make(map[string]struct{})
	var rules []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[2] != "line" || fields[4] != "offset" {
			continue
		}
		rule := fields[0]
		if !diagnoseRuleIDPattern.MatchString(rule) {
			continue
		}
		if _, ok := seen[rule]; ok {
			continue
		}
		seen[rule] = struct{}{}
		rules = append(rules, rule)
	}
	return rules
}

// sha256File returns the hex SHA-256 of a file.
func sha256File(path string) (string, error) {
	file, err := os.Open(path) // #nosec G304 -- path is produced by this process
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// runDiagnoseBundle runs the redacted diagnostic bundle in-process for the d
// hotkey and writes a one-line result to the status line: the archive path and
// its SHA-256 on success, or the refusal rule ids (never values) on a
// redaction-guard refusal.
func (m *dashboardModel) runDiagnoseBundle(ctx context.Context) {
	if m == nil || m.diagnoseBundle == nil {
		m.notice = "diagnose bundle unavailable"
		return
	}
	dir, err := os.MkdirTemp("", "rheic-tui-bundle-*")
	if err != nil {
		m.notice = "diagnose bundle: " + err.Error()
		return
	}
	out := filepath.Join(dir, diagnoseBundlePrefix+time.Now().UTC().Format(diagnoseBundleTimeLayout)+diagnoseBundleSuffix)
	result := m.diagnoseBundle(ctx, out)
	switch {
	case result.Err != nil && len(result.Rules) > 0:
		m.notice = "diagnose refused: " + strings.Join(result.Rules, ", ")
	case result.Err != nil:
		m.notice = "diagnose bundle: " + result.Err.Error()
	default:
		m.notice = fmt.Sprintf("bundle %s sha256:%s", result.Target, result.SHA256)
	}
}
