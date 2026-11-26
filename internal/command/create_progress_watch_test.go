package command

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

type scriptedEventStream struct {
	events []sdk.Event
	idx    int
	closed bool
}

func (s *scriptedEventStream) Recv() (*sdk.Event, error) {
	if s.idx >= len(s.events) {
		return nil, io.EOF
	}
	event := s.events[s.idx]
	s.idx++
	return &event, nil
}

func (s *scriptedEventStream) Close() error {
	s.closed = true
	return nil
}

func TestFollowCreateProgressCorrelatesByNameThenID(t *testing.T) {
	stream := &scriptedEventStream{events: []sdk.Event{
		{Type: "sandbox", Sandbox: &sdk.Sandbox{ID: "sb_other", Name: "other"}},
		{Type: "operation", Operation: &sdk.Operation{SandboxID: "sb_wanted", Progress: &sdk.Progress{Phase: "pulling", Completed: 1, Total: 7}}},
		{Type: "sandbox", Sandbox: &sdk.Sandbox{ID: "sb_wanted", Name: "wanted", State: sdk.StateCreating}},
		{Type: "operation", Operation: &sdk.Operation{SandboxID: "sb_other", Progress: &sdk.Progress{Phase: "pulling", Completed: 9, Total: 9}}},
		{Type: "operation", Operation: &sdk.Operation{SandboxID: "sb_wanted", Progress: &sdk.Progress{Phase: "preparing"}}},
		{Type: "operation", Operation: &sdk.Operation{SandboxID: "sb_wanted", Progress: &sdk.Progress{Phase: "pulling", Completed: 5, Total: 7}}},
		{Type: "operation", Operation: &sdk.Operation{SandboxID: "sb_wanted"}},
	}}
	var details []string
	followCreateProgress(stream, "wanted", func(d string) { details = append(details, d) })
	if strings.Join(details, ",") != "5/7 layers" {
		t.Fatalf("details=%v, want only the matching pulling event", details)
	}
}

func TestFollowCreateProgressStopsOnStreamError(t *testing.T) {
	stream := &errorEventStream{}
	followCreateProgress(stream, "wanted", func(string) { t.Fatal("callback after error") })
}

type errorEventStream struct{}

func (errorEventStream) Recv() (*sdk.Event, error) { return nil, errors.New("stream closed") }
func (errorEventStream) Close() error              { return nil }

func TestDeployProgressSetDetailRendersAndClears(t *testing.T) {
	var buf bytes.Buffer
	p := newDeployProgress(&buf, true, false, 80)
	p.begin("sandbox — creating…")
	p.setDetail("5/7 layers")
	if !strings.HasSuffix(stripANSI(buf.String()), "sandbox — creating… 5/7 layers") {
		t.Fatalf("detail missing from spinner row: %q", buf.String())
	}
	erases := strings.Count(buf.String(), ansiEraseLine)
	p.setDetail("5/7 layers") // unchanged detail must not redraw
	if got := strings.Count(buf.String(), ansiEraseLine); got != erases {
		t.Fatalf("unchanged detail redrew the row: before=%d after=%d", erases, got)
	}
	p.next("sandbox — ready")
	settled := stripANSI(buf.String())
	if strings.Contains(settled[strings.Index(settled, "✓"):], "5/7 layers") {
		t.Fatalf("detail must not leak into committed history: %q", settled)
	}
	// Outside an active stage setDetail is a no-op.
	buf.Reset()
	p.setDetail("9/9 layers")
	if buf.Len() != 0 {
		t.Fatalf("inactive setDetail wrote %q", buf.String())
	}
}
