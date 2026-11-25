package command

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/gdamore/tcell/v3"
	sdk "github.com/rheic/sandboxes-go-sdk"
)

const (
	dashboardEventLimit = 200
	dashboardLogLimit   = 200
	// maxLogPartialBytes bounds an unterminated log line before it is flushed
	// so a hostile or binary stream cannot grow the buffer unbounded.
	maxLogPartialBytes = 4 << 10
)

// dashboardPanel selects which pane the dashboard left column renders.
type dashboardPanel int

const (
	dashboardPanelSandboxes dashboardPanel = iota
	dashboardPanelEvents
	dashboardPanelLogs
)

// ringBuffer is a bounded FIFO that counts dropped entries.
type ringBuffer[T any] struct {
	mu       sync.Mutex
	capacity int
	items    []T
	dropped  int
}

func newRingBuffer[T any](capacity int) *ringBuffer[T] {
	if capacity < 1 {
		capacity = 1
	}
	return &ringBuffer[T]{capacity: capacity, items: make([]T, 0, capacity)}
}

func (r *ringBuffer[T]) Add(value T) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.items) >= r.capacity {
		r.items = r.items[1:]
		r.dropped++
	}
	r.items = append(r.items, value)
}

func (r *ringBuffer[T]) Snapshot() []T {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]T, len(r.items))
	copy(out, r.items)
	return out
}

func (r *ringBuffer[T]) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.items)
}

func (r *ringBuffer[T]) Dropped() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}

// eventRow is one rendered dashboard event line. Every field is already
// sanitized; raw payloads never reach the struct.
type eventRow struct {
	Time        string
	Event       string
	Correlation string
	Reason      string
	Sandbox     string
	Revision    int64
}

func eventRowFromEvent(event sdk.Event) eventRow {
	row := eventRow{
		Revision: event.Revision,
		Time:     fmt.Sprintf("rev %d", event.Revision),
		Event:    catalogEventName(event.Type),
	}
	if event.Sandbox != nil {
		row.Sandbox = sandboxLabel(event.Sandbox)
	}
	if event.Operation != nil {
		row.Correlation = sanitizeTerminalText(event.Operation.ID)
	}
	row.Reason = catalogEventReason(event)
	return row
}

// catalogEventName normalizes a structured daemon catalog event type (rheic.*)
// into a compact display name. Legacy type strings pass through unchanged and
// an empty type renders as "event".
func catalogEventName(eventType string) string {
	name := sanitizeTerminalText(strings.TrimSpace(eventType))
	switch {
	case name == "":
		return "event"
	case strings.HasPrefix(name, "rheic."):
		return strings.TrimPrefix(name, "rheic.")
	default:
		return name
	}
}

// sandboxLabel returns the sandbox display name, falling back to its id.
func sandboxLabel(sandbox *sdk.Sandbox) string {
	if sandbox == nil {
		return ""
	}
	name := sanitizeTerminalText(sandbox.Name)
	if name == "" {
		name = sanitizeTerminalText(sandbox.ID)
	}
	return name
}

// catalogEventReason extracts the structured reason for an event: an operation
// error, then an operation or sandbox state, and finally the advisory progress
// message ("msg") as a fallback when no structured reason field is present.
func catalogEventReason(event sdk.Event) string {
	if event.Operation != nil {
		if reason := sanitizeTerminalText(event.Operation.Error); reason != "" {
			return reason
		}
		if state := sanitizeTerminalText(event.Operation.State); state != "" {
			return state
		}
	}
	if event.Sandbox != nil {
		if state := sanitizeTerminalText(event.Sandbox.State); state != "" {
			return state
		}
	}
	return eventMessage(event)
}

// eventMessage composes the advisory progress/error message for an event.
func eventMessage(event sdk.Event) string {
	if event.Operation == nil {
		return ""
	}
	message := ""
	if event.Operation.Progress != nil {
		p := event.Operation.Progress
		message = sanitizeTerminalText(fmt.Sprintf("%s %d/%d", p.Phase, p.Completed, p.Total))
	}
	if event.Operation.Error != "" {
		if message != "" {
			message += " "
		}
		message += sanitizeTerminalText(event.Operation.Error)
	}
	return message
}

// eventRowMatches reports whether the row matches the live filter. The filter
// is pure display: it matches any substring of the rendered cells and is never
// a security boundary.
func eventRowMatches(row eventRow, filter string) bool {
	if filter == "" {
		return true
	}
	haystack := strings.Join([]string{
		row.Time, row.Event, row.Correlation, row.Reason, row.Sandbox,
	}, " ")
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(filter))
}

// logRingWriter splits an exec stream into sanitized ring lines, flushing an
// unterminated tail once maxLogPartialBytes is exceeded.
type logRingWriter struct {
	ring   *ringBuffer[string]
	buffer strings.Builder
}

func (w *logRingWriter) Write(p []byte) (int, error) {
	if w.ring == nil {
		return len(p), nil
	}
	w.buffer.Write(p)
	for {
		s := w.buffer.String()
		idx := strings.IndexByte(s, '\n')
		if idx < 0 {
			if w.buffer.Len() > maxLogPartialBytes {
				w.ring.Add(sanitizeTerminalText(s))
				w.buffer.Reset()
			}
			break
		}
		w.ring.Add(sanitizeTerminalText(s[:idx]))
		w.buffer.Reset()
		w.buffer.WriteString(s[idx+1:])
	}
	return len(p), nil
}

func (w *logRingWriter) Flush() {
	if w == nil || w.ring == nil {
		return
	}
	if w.buffer.Len() > 0 {
		w.ring.Add(sanitizeTerminalText(w.buffer.String()))
		w.buffer.Reset()
	}
}

// events returns the model's event ring, initializing it on first use.
func (m *dashboardModel) events() *ringBuffer[sdk.Event] {
	if m.eventsRing == nil {
		m.eventsRing = newRingBuffer[sdk.Event](dashboardEventLimit)
	}
	return m.eventsRing
}

// logLines returns the model's log ring, initializing it on first use.
func (m *dashboardModel) logLines() *ringBuffer[string] {
	if m.logsRing == nil {
		m.logsRing = newRingBuffer[string](dashboardLogLimit)
	}
	return m.logsRing
}

// startEventStream subscribes the resilient Watch feed into the events ring.
// It is idempotent while a stream is active.
func (m *dashboardModel) startEventStream(ctx context.Context, client sdk.Client) {
	if m == nil || m.eventCancel != nil {
		return
	}
	streamCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	m.eventCancel = cancel
	m.eventDone = done
	ring := m.events()
	go func() {
		defer close(done)
		stream, err := sdk.WatchResilient(streamCtx, client, sdk.WatchOptions{})
		if err != nil {
			m.mu.Lock()
			m.err = sanitizeTerminalText(err.Error())
			m.mu.Unlock()
			return
		}
		defer func() { _ = stream.Close() }()
		for {
			ev, err := stream.Recv()
			if err != nil || streamCtx.Err() != nil {
				return
			}
			if ev == nil {
				continue
			}
			m.mu.Lock()
			fresh := ev.Revision == 0 || ev.Revision > m.lastEventRevision
			if ev.Revision > m.lastEventRevision {
				m.lastEventRevision = ev.Revision
			}
			m.mu.Unlock()
			if fresh {
				ring.Add(*ev)
			}
		}
	}()
}

// stopEventStream cancels the watch feed and waits for its goroutine.
func (m *dashboardModel) stopEventStream() {
	if m == nil || m.eventCancel == nil {
		return
	}
	m.eventCancel()
	if m.eventDone != nil {
		<-m.eventDone
	}
	m.eventCancel = nil
	m.eventDone = nil
}

// startLogsStream tails the selected sandbox log over exec; a missing file
// yields an empty stream rather than an error row flood.
func (m *dashboardModel) startLogsStream(ctx context.Context, client sdk.Client, sandboxID string) {
	if m == nil || sandboxID == "" || m.logsCancel != nil {
		return
	}
	streamCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	m.logsCancel = cancel
	m.logsDone = done
	ring := m.logLines()
	go func() {
		defer close(done)
		writer := &logRingWriter{ring: ring}
		_, err := sdk.ExecService(client).Exec(streamCtx, sdk.ExecRequest{
			SandboxID: sandboxID,
			Argv:      []string{"sh", "-c", "tail -n 200 -f /var/log/sandbox.log 2>/dev/null || true"},
			Stdout:    writer,
			Stderr:    io.Discard,
		})
		writer.Flush()
		if err != nil && streamCtx.Err() == nil {
			ring.Add("logs: " + sanitizeTerminalText(err.Error()))
		}
	}()
}

func (m *dashboardModel) stopLogsStream() {
	if m == nil || m.logsCancel == nil {
		return
	}
	m.logsCancel()
	if m.logsDone != nil {
		<-m.logsDone
	}
	m.logsCancel = nil
	m.logsDone = nil
}

// setPanel switches the rendered pane, stopping streams that left the screen.
func (m *dashboardModel) setPanel(ctx context.Context, client sdk.Client, panel dashboardPanel) {
	if m == nil {
		return
	}
	if panel != dashboardPanelEvents {
		m.stopEventStream()
	}
	if panel != dashboardPanelLogs {
		m.stopLogsStream()
	}
	m.panel = panel
	if panel == dashboardPanelEvents {
		m.startEventStream(ctx, client)
	}
	if panel == dashboardPanelLogs {
		m.startLogsStream(ctx, client, m.selectedSandboxID())
	}
}

// selectedSandboxID resolves the highlighted list row to its sandbox ID.
func (m *dashboardModel) selectedSandboxID() string {
	if m == nil || len(m.items) == 0 {
		return ""
	}
	if m.selected < 0 || m.selected >= len(m.items) {
		m.selected = 0
	}
	item := m.items[m.selected]
	if item.ID != "" {
		return item.ID
	}
	return item.Name
}

func drawDashboardPanels(screen dashboardScreen, model *dashboardModel, width int, accent, muted tcell.Style, y int) {
	labels := []struct {
		key   string
		label string
		panel dashboardPanel
	}{
		{"1", "SANDBOXES", dashboardPanelSandboxes},
		{"2", "EVENTS", dashboardPanelEvents},
		{"3", "LOGS", dashboardPanelLogs},
	}
	x := 3
	for _, l := range labels {
		style := muted
		if model != nil && model.panel == l.panel {
			style = accent
		}
		text := fmt.Sprintf("[%s] %s", l.key, l.label)
		if x+len(text) > width-2 {
			break
		}
		drawText(screen, x, y, text, style, 24)
		x += len(text) + 2
	}
}

func drawEventPanel(screen dashboardScreen, model *dashboardModel, x, width, height int, primary, muted tcell.Style) {
	if model == nil {
		return
	}
	ring := model.events()
	rows := make([]eventRow, 0, ring.Len())
	for _, event := range ring.Snapshot() {
		rows = append(rows, eventRowFromEvent(event))
	}
	rows = filterEventRows(rows, model.eventFilter)
	visible := max(height-16, 1)
	start := max(len(rows)-visible, 0)
	start = max(start-model.eventScroll, 0)
	for i := 0; i < visible && start+i < len(rows); i++ {
		row := rows[start+i]
		y := 13 + i
		if y >= height-4 {
			break
		}
		line := fmt.Sprintf("%-6s %-18s %-12s %-14s %s",
			clipCell(row.Time, 6), clipCell(row.Event, 18), clipCell(row.Correlation, 12),
			clipCell(row.Sandbox, 14), clipCell(row.Reason, max(width-x-58, 4)))
		drawText(screen, x, y, sanitizeTerminalText(line), primary, width-x-2)
	}
	if ring.Dropped() > 0 {
		drawText(screen, x, height-4, fmt.Sprintf("dropped %d events", ring.Dropped()), muted, width-x-2)
	}
}

// filterEventRows applies the live display filter to rendered event rows.
func filterEventRows(rows []eventRow, filter string) []eventRow {
	if filter == "" {
		return rows
	}
	filtered := make([]eventRow, 0, len(rows))
	for _, row := range rows {
		if eventRowMatches(row, filter) {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func drawLogPanel(screen dashboardScreen, model *dashboardModel, x, width, height int, primary, muted tcell.Style) {
	if model == nil {
		return
	}
	ring := model.logLines()
	lines := ring.Snapshot()
	visible := max(height-16, 1)
	start := max(len(lines)-visible, 0)
	start = max(start-model.logScroll, 0)
	for i := 0; i < visible && start+i < len(lines); i++ {
		y := 13 + i
		if y >= height-4 {
			break
		}
		drawText(screen, x, y, sanitizeTerminalText(clipCell(lines[start+i], max(width-x-2, 4))), primary, width-x-2)
	}
	if ring.Dropped() > 0 {
		drawText(screen, x, height-4, fmt.Sprintf("dropped %d lines", ring.Dropped()), muted, width-x-2)
	}
}
