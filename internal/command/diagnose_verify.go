package command

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/rheic/slogx/redact"
)

// Archive member names are untrusted. Only display the expected bundle names;
// otherwise an attacker could put a secret in a member name or terminal escape.
var diagnoseSafeMember = regexp.MustCompile(`^(manifest\.json|versions\.json|platform\.json|config\.redacted\.json|sandboxes\.redacted\.json|policies\.redacted\.json|approvals\.pending\.redacted\.json|logs/daemon\.tail\.jsonl|journal\.summary\.json|errors\.json|README\.txt)$`)

func (r *Runner) verifyDiagnoseBundle(path string) int {
	f, err := os.Open(path) // #nosec G304 -- explicitly requested input archive
	if err != nil {
		_, _ = fmt.Fprintln(r.Err, "error: cannot open diagnostic archive")
		return 1
	}
	defer func() { _ = f.Close() }()
	home, _ := os.UserHomeDir()
	username := ""
	if home != "" {
		username = filepath.Base(home)
	}
	violations, stats, err := redact.BundleGuard(f, redact.Options{HomeUser: username})
	if err != nil {
		// Guard errors can contain archive-controlled names; do not print them.
		_, _ = fmt.Fprintln(r.Err, "error: diagnostic archive verification failed")
		return 1
	}
	if len(violations) != 0 {
		for _, v := range violations {
			name := v.Path
			if !diagnoseSafeMember.MatchString(name) {
				name = "[unrecognized member]"
			}
			_, _ = fmt.Fprintf(r.Err, "%s %s:%d\n", v.Rule, name, v.Line)
		}
		return 1
	}
	var total int64
	for _, stat := range stats {
		total += stat.Bytes
	}
	_, _ = fmt.Fprintf(r.Out, "verified: %d files, %d bytes, 0 violations\n", len(stats), total)
	return 0
}
