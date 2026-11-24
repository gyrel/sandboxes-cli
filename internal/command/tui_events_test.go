package command

import (
	"context"
	"sync"
	"testing"
	"time"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestRingBufferBoundsDropCounterAndOrdering(t *testing.T) {
	ring := newRingBuffer[int](3)
	for i := 1; i <= 5; i++ {
		ring.Push(i)
	}
	if ring.Len() != 3 {
		t.Fatalf("len=%d, want 3", ring.Len())
	}
	if ring.Dropped() != 2 {
		t.Fatalf("dropped=%d, want 2", ring.Dropped())
	}
	if ring.DropCount() != 2 || ring.Drops() != 2 {
		t.Fatal("drop aliases disagree")
	}
	got := ring.Snapshot()
	want := []int{3, 4, 5}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("snapshot=%v, want %v", got, want)
		}
	}
	// Mutating the snapshot must not affect the ring.
	got[0] = 999
	if ring.Snapshot()[0] == 999 {
		t.Fatal("snapshot is not a copy")
	}
}

func TestRingBufferConcurrency(t *testing.T) {
	ring := newRingBuffer[int](100)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			ring.Push(v)
		}(i)
	}
	wg.Wait()
	if ring.Len() != 50 {
		t.Fatalf("len=%d, want 50", ring.Len())
	}
}

func TestEventRowFromEventRendersAndSanitizes(t *testing.T) {
	event := sdk.Event{
		Type:     "sandbox\x1b[31m",
		Revision: 7,
		Sandbox:  &sdk.Sandbox{Name: "dev", State: "running", Workspace: "/secret/path"},
		Operation: &sdk.Operation{
			ID:       "op-1",
			Kind:     "pull",
			State:    "running",
			Progress: &sdk.Progress{Phase: "pulling", Completed: 3, Total: 7},
		},
	}
	row := eventRowFromEvent(event)
	if row.Revision != 7 {
		t.Fatalf("revision=%d", row.Revision)
	}
	if row.Type != "sandbox�[31m" {
		t.Fatalf("type not sanitized: %q", row.Type)
	}
	if row.Sandbox != "dev" {
		t.Fatalf("sandbox=%q", row.Sandbox)
	}
	if row.State != "running" {
		t.Fatalf("state=%q", row.State)
	}
	if !containsStr(row.Message, "pulling 3/7") {
		t.Fatalf("message=%q", row.Message)
	}
	// Host workspace path must not appear in the row.
	for _, cell := range row.Cells() {
		if containsStr(cell, "/secret/path") {
			t.Fatalf("host path leaked: %q", cell)
		}
	}
	// aliases
	if eventToRow(event).Revision != row.Revision {
		t.Fatal("eventToRow alias mismatch")
	}
	if renderEvent(event).Revision != row.Revision {
		t.Fatal("renderEvent alias mismatch")
	}
}

func TestDeduplicateEventsByRevision(t *testing.T) {
	events := []sdk.Event{
		{Type: "sandbox", Revision: 1, Sandbox: &sdk.Sandbox{ID: "a"}},
		{Type: "sandbox", Revision: 1, Sandbox: &sdk.Sandbox{ID: "a"}},
		{Type: "operation", Revision: 2, Operation: &sdk.Operation{ID: "op"}},
		{Type: "sandbox", Revision: 0, Sandbox: &sdk.Sandbox{ID: "b"}},
		{Type: "sandbox", Revision: 0, Sandbox: &sdk.Sandbox{ID: "b"}},
	}
	got := deduplicateEvents(events)
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3 (%+v)", len(got), got)
	}
	alias := dedupEvents(events)
	if len(alias) != len(got) {
		t.Fatal("dedupEvents alias mismatch")
	}
}

type blockingEventStream struct {
	ctx context.Context
}

func (s *blockingEventStream) Recv() (*sdk.Event, error) {
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}
func (s *blockingEventStream) Close() error { return nil }

type blockingSandbox struct {
	fakeSandbox
	mu     sync.Mutex
	ctx    context.Context
	stream *blockingEventStream
}

func (s *blockingSandbox) setCtx(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx = ctx
}

func (s *blockingSandbox) getCtx() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx
}

func (s *blockingSandbox) Watch(ctx context.Context, _ sdk.WatchOptions) (sdk.EventStream, error) {
	s.setCtx(ctx)
	st := &blockingEventStream{ctx: ctx}
	s.mu.Lock()
	s.stream = st
	s.mu.Unlock()
	return st, nil
}

type blockingClient struct {
	fakeClient
	mu      sync.Mutex
	execCtx context.Context
}

func (c *blockingClient) setExecCtx(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.execCtx = ctx
}

func (c *blockingClient) getExecCtx() context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.execCtx
}

func (c *blockingClient) Executor() sdk.Executor {
	return blockingExecutor{c: c}
}

type blockingExecutor struct {
	c *blockingClient
}

func (e blockingExecutor) Exec(ctx context.Context, _ sdk.ExecRequest) (int, error) {
	e.c.setExecCtx(ctx)
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestEventsPanelSwitchCancelsStream(t *testing.T) {
	sb := &blockingSandbox{}
	bc := &blockingClient{fakeClient: fakeClient{sandbox: sb}}
	model := &dashboardModel{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: "running"}}, selected: 0}
	ctx := context.Background()

	setDashboardPanel(ctx, bc, model, panelEvents)
	time.Sleep(50 * time.Millisecond)
	ec := sb.getCtx()
	if ec == nil {
		t.Fatal("event stream did not start")
	}
	setDashboardPanel(ctx, bc, model, panelSandboxes)
	select {
	case <-ec.Done():
	case <-time.After(time.Second):
		t.Fatal("event stream context not canceled on panel switch")
	}
}

func TestLogsPanelSwitchCancelsStream(t *testing.T) {
	sb := &blockingSandbox{}
	bc := &blockingClient{fakeClient: fakeClient{sandbox: sb}}
	model := &dashboardModel{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: "running"}}, selected: 0}
	ctx := context.Background()

	setDashboardPanel(ctx, bc, model, panelLogs)
	time.Sleep(50 * time.Millisecond)
	ec := bc.getExecCtx()
	if ec == nil {
		t.Fatal("logs stream did not start")
	}
	setDashboardPanel(ctx, bc, model, panelSandboxes)
	select {
	case <-ec.Done():
	case <-time.After(time.Second):
		t.Fatal("logs stream context not canceled on panel switch")
	}
}

func TestDrawDashboardEventsPanelSmoke(t *testing.T) {
	screen := newDashboardTestScreen(100, 24)
	model := &dashboardModel{panel: panelEvents, items: []sdk.Sandbox{{Name: "dev", State: "running"}}}
	model.eventRingBuf().Push(sdk.Event{Type: "sandbox", Revision: 1, Sandbox: &sdk.Sandbox{Name: "dev", State: "running"}})
	drawDashboard(screen, model)
	output := screen.text()
	for _, want := range []string{"EVENTS", "RHEIC", "dropped"} {
		_ = want
	}
	if !containsStr(output, "EVENTS") {
		t.Fatalf("events panel not rendered: %q", output)
	}
}

func TestDrawDashboardLogsPanelSmoke(t *testing.T) {
	screen := newDashboardTestScreen(100, 24)
	model := &dashboardModel{panel: panelLogs, items: []sdk.Sandbox{{Name: "dev", State: "running"}}}
	model.logRingBuf().Push("hello log line")
	drawDashboard(screen, model)
	output := screen.text()
	if !containsStr(output, "hello log line") {
		t.Fatalf("logs not rendered: %q", output)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
