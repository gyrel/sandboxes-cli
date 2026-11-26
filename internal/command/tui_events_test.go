package command

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

func TestRingBufferBoundsDropCounterAndOrdering(t *testing.T) {
	ring := newRingBuffer[int](3)
	for i := 1; i <= 5; i++ {
		ring.Add(i)
	}
	if ring.Len() != 3 {
		t.Fatalf("len=%d, want 3", ring.Len())
	}
	if ring.Dropped() != 2 {
		t.Fatalf("dropped=%d, want 2", ring.Dropped())
	}
	got := ring.Snapshot()
	want := []int{3, 4, 5}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("snapshot=%v, want %v", got, want)
		}
	}
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
			ring.Add(v)
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
	if strings.ContainsRune(row.Event, 0x1b) {
		t.Fatalf("event not sanitized: %q", row.Event)
	}
	if row.Sandbox != "dev" || row.Correlation != "op-1" {
		t.Fatalf("identity cells = %+v", row)
	}
	if row.Reason != "running" {
		t.Fatalf("reason = %q", row.Reason)
	}
	for _, cell := range []string{row.Time, row.Event, row.Correlation, row.Reason, row.Sandbox} {
		if strings.Contains(cell, "/secret/path") {
			t.Fatalf("host path leaked: %q", cell)
		}
	}
	errEvent := sdk.Event{Type: "operation", Revision: 8, Operation: &sdk.Operation{ID: "op-2", Kind: "pull", Error: "boom"}}
	if reason := eventRowFromEvent(errEvent).Reason; !strings.Contains(reason, "boom") {
		t.Fatalf("error reason = %q", reason)
	}
}

func TestLogRingWriterSplitsAndCaps(t *testing.T) {
	ring := newRingBuffer[string](50)
	writer := &logRingWriter{ring: ring}
	if _, err := writer.Write([]byte("line one\nline two\npartial")); err != nil {
		t.Fatal(err)
	}
	if ring.Len() != 2 {
		t.Fatalf("lines=%d want 2", ring.Len())
	}
	writer.Flush()
	if got := ring.Snapshot(); len(got) != 3 || got[2] != "partial" {
		t.Fatalf("flush result=%v", got)
	}
	ring2 := newRingBuffer[string](10)
	writer2 := &logRingWriter{ring: ring2}
	if _, err := writer2.Write([]byte(strings.Repeat("x", maxLogPartialBytes+1))); err != nil {
		t.Fatal(err)
	}
	if ring2.Len() == 0 {
		t.Fatal("oversized unterminated line was not flushed")
	}
	for _, line := range ring2.Snapshot() {
		if len(line) > maxLogPartialBytes*2 {
			t.Fatalf("unbounded partial leaked: %d bytes", len(line))
		}
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
	mu  sync.Mutex
	ctx context.Context
}

func (s *blockingSandbox) Watch(ctx context.Context, _ sdk.WatchOptions) (sdk.EventStream, error) {
	s.mu.Lock()
	s.ctx = ctx
	s.mu.Unlock()
	return &blockingEventStream{ctx: ctx}, nil
}

func (s *blockingSandbox) watchedCtx() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx
}

type blockingClient struct {
	fakeClient
	mu      sync.Mutex
	execCtx context.Context
}

func (c *blockingClient) Executor() sdk.Executor { return blockingExecutor{c: c} }

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

type blockingExecutor struct{ c *blockingClient }

func (e blockingExecutor) Exec(ctx context.Context, _ sdk.ExecRequest) (int, error) {
	e.c.setExecCtx(ctx)
	<-ctx.Done()
	return 0, ctx.Err()
}

func newPanelTestModel() *dashboardModel {
	return &dashboardModel{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: "running"}}, selected: 0}
}

func TestEventsPanelSwitchCancelsStream(t *testing.T) {
	sb := &blockingSandbox{}
	client := &blockingClient{fakeClient: fakeClient{sandbox: sb}}
	model := newPanelTestModel()
	ctx := context.Background()

	model.setPanel(ctx, client, dashboardPanelEvents)
	time.Sleep(50 * time.Millisecond)
	ec := sb.watchedCtx()
	if ec == nil {
		t.Fatal("event stream did not start")
	}
	model.setPanel(ctx, client, dashboardPanelSandboxes)
	select {
	case <-ec.Done():
	case <-time.After(time.Second):
		t.Fatal("event stream context not canceled on panel switch")
	}
	if model.eventCancel != nil {
		t.Fatal("stream handles not cleared after stop")
	}
}

func TestLogsPanelSwitchCancelsStream(t *testing.T) {
	sb := &blockingSandbox{}
	client := &blockingClient{fakeClient: fakeClient{sandbox: sb}}
	model := newPanelTestModel()
	ctx := context.Background()

	model.setPanel(ctx, client, dashboardPanelLogs)
	time.Sleep(50 * time.Millisecond)
	ec := client.getExecCtx()
	if ec == nil {
		t.Fatal("logs stream did not start")
	}
	model.setPanel(ctx, client, dashboardPanelSandboxes)
	select {
	case <-ec.Done():
	case <-time.After(time.Second):
		t.Fatal("logs stream context not canceled on panel switch")
	}
}

func TestSelectedSandboxID(t *testing.T) {
	model := &dashboardModel{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}, {Name: "named-only"}}}
	if got := model.selectedSandboxID(); got != "sb-1" {
		t.Fatalf("first selection = %q", got)
	}
	model.selected = 1
	if got := model.selectedSandboxID(); got != "named-only" {
		t.Fatalf("fallback to name = %q", got)
	}
	model.selected = 9
	if got := model.selectedSandboxID(); got != "sb-1" {
		t.Fatalf("out-of-range reset = %q", got)
	}
}

func TestDashboardErrorConcurrentWithDraw(t *testing.T) {
	model := &dashboardModel{}
	screen := newDashboardTestScreen(100, 24)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			model.setError("stream\x1b[31m failure")
		}
	}()
	for i := 0; i < 1000; i++ {
		drawDashboard(screen, model)
	}
	wg.Wait()
	if got := model.errorText(); strings.Contains(got, "\x1b") {
		t.Fatalf("error text not sanitized: %q", got)
	}
}

func TestSanitizeTerminalTextIdempotent(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"plain text", "daemon offline"},
		{"escape sequence", "stream\x1b[31m failure"},
		{"control characters", "line\x07\nbreak\t"},
		{"direction override", "safe\u202eevil"},
		{"already sanitized", "already \ufffd sanitized"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			once := sanitizeTerminalText(tc.input)
			twice := sanitizeTerminalText(once)
			if once != twice {
				t.Fatalf("not idempotent: first=%q second=%q", once, twice)
			}
		})
	}
}

func TestDrawDashboardEventsPanelSmoke(t *testing.T) {
	screen := newDashboardTestScreen(100, 24)
	model := &dashboardModel{panel: dashboardPanelEvents, items: []sdk.Sandbox{{Name: "dev", State: "running"}}}
	model.events().Add(sdk.Event{Type: "sandbox", Revision: 1, Sandbox: &sdk.Sandbox{Name: "dev", State: "running"}})
	drawDashboard(screen, model)
	if !strings.Contains(screen.text(), "EVENTS") {
		t.Fatalf("events panel not rendered: %q", screen.text())
	}
}

func TestDrawDashboardLogsPanelSmoke(t *testing.T) {
	screen := newDashboardTestScreen(100, 24)
	model := &dashboardModel{panel: dashboardPanelLogs, items: []sdk.Sandbox{{Name: "dev", State: "running"}}}
	model.logLines().Add("hello log line")
	drawDashboard(screen, model)
	if !strings.Contains(screen.text(), "hello log line") {
		t.Fatalf("logs not rendered: %q", screen.text())
	}
}
