package command

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDiagnoseLogTailLimitsAndSince(t *testing.T) {
	var input strings.Builder
	for i := range 2500 {
		fmt.Fprintf(&input, "{\"ts\":\"2026-01-01T00:00:00Z\",\"n\":%d}\n", i)
	}
	out, err := diagnoseLogTail(strings.NewReader(input.String()), time.Time{})
	if err != nil || bytes.Count(out, []byte("\n")) != diagnoseTailLines || bytes.Contains(out, []byte(`"n":499}`)) || !bytes.Contains(out, []byte(`"n":2499}`)) {
		t.Fatalf("unexpected tail: %d bytes, err %v", len(out), err)
	}
	out, err = diagnoseLogTail(strings.NewReader(input.String()), time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil || len(out) != 0 {
		t.Fatalf("since: %d bytes, %v", len(out), err)
	}
	large := strings.Repeat("x", diagnoseTailBytes+1) + "\nlast\n"
	out, err = diagnoseLogTail(strings.NewReader(large), time.Time{})
	if err != nil || string(out) != "last\n" {
		t.Fatalf("oversize: %d bytes, %v", len(out), err)
	}
}
