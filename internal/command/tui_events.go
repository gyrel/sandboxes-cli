//nolint:unused,unparam,gocognit,gocritic,nestif
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
)

type dashboardPanel int

const (
	dashboardPanelSandboxes dashboardPanel = iota
	dashboardPanelEvents
	dashboardPanelLogs
)

type panel = dashboardPanel
type view = dashboardPanel
type tab = dashboardPanel

const (
	panelSandboxes = dashboardPanelSandboxes
	panelEvents    = dashboardPanelEvents
	panelLogs      = dashboardPanelLogs

	viewSandboxes = dashboardPanelSandboxes
	viewEvents    = dashboardPanelEvents
	viewLogs      = dashboardPanelLogs

	tabSandboxes = dashboardPanelSandboxes
	tabEvents    = dashboardPanelEvents
	tabLogs      = dashboardPanelLogs
)

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

func (r *ringBuffer[T]) Capacity() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.capacity
}

func (r *ringBuffer[T]) Cap() int { return r.Capacity() }

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

func (r *ringBuffer[T]) DropCount() int { return r.Dropped() }
func (r *ringBuffer[T]) Drops() int     { return r.Dropped() }

func (r *ringBuffer[T]) Push(value T)   { r.Add(value) }
func (r *ringBuffer[T]) Append(value T) { r.Add(value) }
func (r *ringBuffer[T]) Add(value T) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.capacity < 1 {
		r.capacity = 1
	}
	if len(r.items) >= r.capacity {
		r.items = r.items[1:]
		r.dropped++
	}
	r.items = append(r.items, value)
}
func (r *ringBuffer[T]) Write(value T) { r.Push(value) }

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
func (r *ringBuffer[T]) Items() []T   { return r.Snapshot() }
func (r *ringBuffer[T]) All() []T     { return r.Snapshot() }
func (r *ringBuffer[T]) Tail() []T    { return r.Snapshot() }
func (r *ringBuffer[T]) Entries() []T { return r.Snapshot() }
func (r *ringBuffer[T]) Lines() []string {
	snap := r.Snapshot()
	out := make([]string, 0, len(snap))
	for _, v := range snap {
		out = append(out, fmt.Sprint(v))
	}
	return out
}

type eventRing = ringBuffer[sdk.Event]
type eventRingBuffer = ringBuffer[sdk.Event]
type logRing = ringBuffer[string]
type logRingBuffer = ringBuffer[string]
type textRing = ringBuffer[string]
type textRingBuffer = ringBuffer[string]

type eventRow struct {
	Time      string
	Type      string
	Sandbox   string
	Operation string
	State     string
	Message   string
	Revision  int64
	Columns   []string
}

func (r eventRow) Cells() []string {
	if r.Columns != nil {
		return r.Columns
	}
	return []string{r.Time, r.Type, r.Sandbox, r.Operation, r.State, r.Message}
}

func eventRowFromEvent(event sdk.Event) eventRow {
	row := eventRow{
		Revision: event.Revision,
		Type:     sanitizeTerminalText(event.Type),
	}
	if row.Type == "" {
		row.Type = "event"
	}
	if event.Sandbox != nil {
		name := sanitizeTerminalText(event.Sandbox.Name)
		if name == "" {
			name = sanitizeTerminalText(event.Sandbox.ID)
		}
		row.Sandbox = name
		row.State = sanitizeTerminalText(event.Sandbox.State)
	}
	if event.Operation != nil {
		op := sanitizeTerminalText(event.Operation.Kind)
		if op == "" {
			op = "operation"
		}
		if id := sanitizeTerminalText(event.Operation.ID); id != "" {
			op = op + " " + id
		}
		row.Operation = strings.TrimSpace(op)
		if row.State == "" {
			row.State = sanitizeTerminalText(event.Operation.State)
		}
		if event.Operation.Progress != nil {
			p := event.Operation.Progress
			row.Message = sanitizeTerminalText(fmt.Sprintf("%s %d/%d", p.Phase, p.Completed, p.Total))
		}
		if event.Operation.Error != "" {
			if row.Message != "" {
				row.Message += " "
			}
			row.Message += sanitizeTerminalText(event.Operation.Error)
		}
	}
	row.Time = fmt.Sprintf("rev %d", event.Revision)
	row.Columns = []string{row.Time, row.Type, row.Sandbox, row.Operation, row.State, row.Message}
	return row
}

func eventToRow(event sdk.Event) eventRow           { return eventRowFromEvent(event) }
func renderEvent(event sdk.Event) eventRow          { return eventRowFromEvent(event) }
func eventRowFromSDKEvent(event sdk.Event) eventRow { return eventRowFromEvent(event) }
func eventRowFromWatchEvent(event sdk.Event) eventRow {
	return eventRowFromEvent(event)
}

func eventRowsFromEvents(events []sdk.Event) []eventRow {
	out := make([]eventRow, 0, len(events))
	for _, e := range events {
		out = append(out, eventRowFromEvent(e))
	}
	return out
}

func eventRowStrings(event sdk.Event) []string {
	return eventRowFromEvent(event).Cells()
}

func dedupEvents(events []sdk.Event) []sdk.Event {
	return deduplicateEvents(events)
}

func deduplicateEvents(events []sdk.Event) []sdk.Event {
	seen := make(map[string]struct{})
	out := make([]sdk.Event, 0, len(events))
	for _, e := range events {
		key := fmt.Sprintf("%d|%s|%s", e.Revision, e.Type, sandboxKey(e.Sandbox))
		if e.Revision == 0 {
			key = fmt.Sprintf("0|%s|%s|%s", e.Type, sandboxKey(e.Sandbox), operationKey(e.Operation))
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	return out
}

func sandboxKey(s *sdk.Sandbox) string {
	if s == nil {
		return ""
	}
	return s.ID + "|" + s.Name
}

func operationKey(o *sdk.Operation) string {
	if o == nil {
		return ""
	}
	return o.ID + "|" + o.State
}

func redactSensitiveText(value string) string {
	return sanitizeTerminalText(value)
}

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
			if w.buffer.Len() > 4096 {
				line := sanitizeTerminalText(w.buffer.String())
				w.ring.Push(line)
				w.buffer.Reset()
			}
			break
		}
		line := sanitizeTerminalText(s[:idx])
		w.ring.Push(line)
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
		w.ring.Push(sanitizeTerminalText(w.buffer.String()))
		w.buffer.Reset()
	}
}

func (m *dashboardModel) eventRingBuf() *ringBuffer[sdk.Event] {
	if m == nil {
		return newRingBuffer[sdk.Event](dashboardEventLimit)
	}
	for _, r := range []*ringBuffer[sdk.Event]{m.events, m.eventRing, m.eventBuffer, m.eventLog, m.eventStream2} {
		if r != nil {
			m.events = r
			m.eventRing = r
			m.eventBuffer = r
			m.eventLog = r
			m.eventStream2 = r
			return r
		}
	}
	r := newRingBuffer[sdk.Event](dashboardEventLimit)
	m.events = r
	m.eventRing = r
	m.eventBuffer = r
	m.eventLog = r
	m.eventStream2 = r
	return r
}

func (m *dashboardModel) logRingBuf() *ringBuffer[string] {
	if m == nil {
		return newRingBuffer[string](dashboardLogLimit)
	}
	for _, r := range []*ringBuffer[string]{m.logs, m.logRing, m.logBuffer, m.logLines, m.logTail} {
		if r != nil {
			m.logs = r
			m.logRing = r
			m.logBuffer = r
			m.logLines = r
			m.logTail = r
			return r
		}
	}
	r := newRingBuffer[string](dashboardLogLimit)
	m.logs = r
	m.logRing = r
	m.logBuffer = r
	m.logLines = r
	m.logTail = r
	return r
}

type dashboardStream struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (m *dashboardModel) eventStreamHandle() *dashboardStream {
	if m.eventCancel == nil && m.eventDone == nil {
		return nil
	}
	return &dashboardStream{cancel: m.eventCancel, done: m.eventDone}
}

func startEventStream(ctx context.Context, client sdk.Client, model *dashboardModel) {
	if model == nil {
		return
	}
	if model.eventCancel != nil {
		return
	}
	streamCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	model.eventCancel = cancel
	model.eventDone = done
	model.eventStreamCtx = streamCtx
	go func() {
		defer close(done)
		stream, err := sdk.WatchResilient(streamCtx, client, sdk.WatchOptions{})
		if err != nil {
			model.mu.Lock()
			model.err = sanitizeTerminalText(err.Error())
			model.mu.Unlock()
			return
		}
		model.mu.Lock()
		model.eventStream = stream
		model.mu.Unlock()
		defer func() { _ = stream.Close() }()
		for {
			ev, err := stream.Recv()
			if err != nil {
				if streamCtx.Err() != nil {
					return
				}
				return
			}
			if ev == nil {
				continue
			}
			ring := model.eventRingBuf()
			last := model.lastEventRevision
			if ev.Revision > 0 && ev.Revision <= last {
				continue
			}
			if ev.Revision > 0 {
				model.lastEventRevision = ev.Revision
			}
			ring.Push(*ev)
		}
	}()
}

func startEventWatch(ctx context.Context, client sdk.Client, model *dashboardModel) {
	startEventStream(ctx, client, model)
}
func startEventsStream(ctx context.Context, client sdk.Client, model *dashboardModel) {
	startEventStream(ctx, client, model)
}
func startWatchStream(ctx context.Context, client sdk.Client, model *dashboardModel) {
	startEventStream(ctx, client, model)
}

func stopEventStream(model *dashboardModel) {
	if model == nil || model.eventCancel == nil {
		return
	}
	model.eventCancel()
	if model.eventDone != nil {
		<-model.eventDone
	}
	model.eventCancel = nil
	model.eventDone = nil
	model.eventStream = nil
	model.eventStreamCtx = nil
}

func stopEventWatch(model *dashboardModel)   { stopEventStream(model) }
func stopEventsStream(model *dashboardModel) { stopEventStream(model) }

func startLogsStream(ctx context.Context, client sdk.Client, model *dashboardModel, sandboxID string) {
	if model == nil || sandboxID == "" {
		return
	}
	if model.logsCancel != nil {
		return
	}
	streamCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	model.logsCancel = cancel
	model.logsDone = done
	model.logsStreamCtx = streamCtx
	go func() {
		defer close(done)
		ring := model.logRingBuf()
		writer := &logRingWriter{ring: ring}
		_, err := sdk.ExecService(client).Exec(streamCtx, sdk.ExecRequest{
			SandboxID: sandboxID,
			Argv:      []string{"sh", "-c", "tail -n 200 -f /var/log/sandbox.log 2>/dev/null || true"},
			Stdout:    writer,
			Stderr:    io.Discard,
		})
		writer.Flush()
		if err != nil && streamCtx.Err() == nil {
			ring.Push("logs: " + sanitizeTerminalText(err.Error()))
		}
	}()
}

func startLogStream(ctx context.Context, client sdk.Client, model *dashboardModel, sandboxID string) {
	startLogsStream(ctx, client, model, sandboxID)
}
func startLogsView(ctx context.Context, client sdk.Client, model *dashboardModel, sandboxID string) {
	startLogsStream(ctx, client, model, sandboxID)
}
func startLogView(ctx context.Context, client sdk.Client, model *dashboardModel, sandboxID string) {
	startLogsStream(ctx, client, model, sandboxID)
}

func stopLogsStream(model *dashboardModel) {
	if model == nil || model.logsCancel == nil {
		return
	}
	model.logsCancel()
	if model.logsDone != nil {
		<-model.logsDone
	}
	model.logsCancel = nil
	model.logsDone = nil
	model.logsStreamCtx = nil
}

func stopLogStream(model *dashboardModel) { stopLogsStream(model) }
func stopLogsView(model *dashboardModel)  { stopLogsStream(model) }

func (m *dashboardModel) setPanel(ctx context.Context, client sdk.Client, panel dashboardPanel) {
	if m == nil {
		return
	}
	if panel != dashboardPanelEvents {
		stopEventStream(m)
	}
	if panel != dashboardPanelLogs {
		stopLogsStream(m)
	}
	m.panel = panel
	m.view = panel
	m.tab = panel
	m.activePanel = panel
	if panel == dashboardPanelEvents {
		startEventStream(ctx, client, m)
	}
	if panel == dashboardPanelLogs {
		id := selectedSandboxID(m)
		startLogsStream(ctx, client, m, id)
	}
}

func selectedSandboxID(m *dashboardModel) string {
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

func setDashboardPanel(ctx context.Context, client sdk.Client, model *dashboardModel, panel dashboardPanel) {
	if model != nil {
		model.setPanel(ctx, client, panel)
	}
}
func switchDashboardPanel(ctx context.Context, client sdk.Client, model *dashboardModel, panel dashboardPanel) {
	setDashboardPanel(ctx, client, model, panel)
}
func switchPanel(ctx context.Context, client sdk.Client, model *dashboardModel, panel dashboardPanel) {
	setDashboardPanel(ctx, client, model, panel)
}
func changeDashboardPanel(ctx context.Context, client sdk.Client, model *dashboardModel, panel dashboardPanel) {
	setDashboardPanel(ctx, client, model, panel)
}
func (m *dashboardModel) SwitchPanel(ctx context.Context, client sdk.Client, panel dashboardPanel) {
	m.setPanel(ctx, client, panel)
}
func (m *dashboardModel) SetPanel(ctx context.Context, client sdk.Client, panel dashboardPanel) {
	m.setPanel(ctx, client, panel)
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
		drawText(screen, x, y, text, style, 24)
		x += len(text) + 2
	}
}

func drawEventPanel(screen dashboardScreen, model *dashboardModel, x, width, height int, primary, muted tcell.Style) {
	ring := model.eventRingBuf()
	events := ring.Snapshot()
	rows := eventRowsFromEvents(events)
	visible := height - 16
	if visible < 1 {
		visible = 1
	}
	start := 0
	if len(rows) > visible {
		start = len(rows) - visible
	}
	if model != nil && model.eventScroll > 0 {
		start -= model.eventScroll
		if start < 0 {
			start = 0
		}
	}
	for i := 0; i < visible && start+i < len(rows); i++ {
		row := rows[start+i]
		y := 13 + i
		if y >= height-4 {
			break
		}
		line := fmt.Sprintf("%-6s %-8s %-14s %-18s %-10s %s",
			clipCell(row.Time, 6), clipCell(row.Type, 8), clipCell(row.Sandbox, 14),
			clipCell(row.Operation, 18), clipCell(row.State, 10), clipCell(row.Message, width-x-70))
		drawText(screen, x, y, sanitizeTerminalText(line), primary, width-x-2)
	}
	if model != nil && ring.Dropped() > 0 {
		drawText(screen, x, height-4, fmt.Sprintf("dropped %d events", ring.Dropped()), muted, width-x-2)
	}
}

func drawLogPanel(screen dashboardScreen, model *dashboardModel, x, width, height int, primary, muted tcell.Style) {
	ring := model.logRingBuf()
	lines := ring.Snapshot()
	visible := height - 16
	if visible < 1 {
		visible = 1
	}
	start := 0
	if len(lines) > visible {
		start = len(lines) - visible
	}
	if model != nil && model.logScroll > 0 {
		start -= model.logScroll
		if start < 0 {
			start = 0
		}
	}
	for i := 0; i < visible && start+i < len(lines); i++ {
		y := 13 + i
		if y >= height-4 {
			break
		}
		drawText(screen, x, y, sanitizeTerminalText(clipCell(lines[start+i], width-x-2)), primary, width-x-2)
	}
	if model != nil && ring.Dropped() > 0 {
		drawText(screen, x, height-4, fmt.Sprintf("dropped %d lines", ring.Dropped()), muted, width-x-2)
	}
}
