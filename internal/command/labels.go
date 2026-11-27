package command

import (
	"errors"
	"strings"
)

const labelFlag = "--label"

// parseLabelAssignments collects repeated --label KEY=VALUE values. The daemon
// owns the full label grammar; this is only the cheap shape guard that keeps
// obviously malformed input away from the RPC. Duplicate keys keep the last
// value, matching Docker's --label behavior.
func parseLabelAssignments(values []string) (map[string]string, error) {
	var labels map[string]string
	for _, raw := range values {
		key, value, ok := strings.Cut(raw, "=")
		if !ok {
			return nil, errors.New("SPEC_INVALID: label must use KEY=VALUE syntax")
		}
		if key == "" {
			return nil, errors.New("SPEC_INVALID: label key must not be empty")
		}
		if strings.ContainsAny(value, " \t\n\r\v\f") {
			return nil, errors.New("SPEC_INVALID: label value must not contain whitespace")
		}
		if labels == nil {
			labels = make(map[string]string, len(values))
		}
		labels[key] = value
	}
	return labels, nil
}
