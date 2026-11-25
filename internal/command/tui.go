package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v3"
	sdk "github.com/rheic/sandboxes-go-sdk"
)

const (
	dashboardMinWidth   = 64
	dashboardMinHeight  = 20
	dashboardPageSize   = 100
	dashboardStateLabel = "STATE"
	sandboxStateRunning = "running"
	sandboxStateStopped = "stopped"
)

var (
	brandBackground = tcell.NewRGBColor(8, 13, 32)
	brandPrimary    = tcell.NewRGBColor(38, 82, 245)   // #2652F5
	brandAccent     = tcell.NewRGBColor(72, 122, 255)  // #487AFF
	brandWarm       = tcell.NewRGBColor(255, 111, 53)  // #FF6F35
	brandLavender   = tcell.NewRGBColor(235, 241, 255) // #EBF1FF
	brandMuted      = tcell.NewRGBColor(156, 174, 219)
)

type dashboardScreen interface {
	Init() error
	Fini()
	Size() (int, int)
	Clear()
	SetStyle(tcell.Style)
	PutStrStyled(x, y int, text string, style tcell.Style)
	Show()
	EventQ() chan tcell.Event
	Sync()
	SetTitle(string)
}

type dashboardModel struct {
	items         []sdk.Sandbox
	selected      int
	updated       time.Time
	err           string
	mode          dashboardMode
	form          createFormModel
	pendingCreate sdk.CreateRequest
	notice        string

	// Panel state.
	panel dashboardPanel

	// Bounded streams (lazily initialized via events()/logLines()).
	eventsRing *ringBuffer[sdk.Event]
	logsRing   *ringBuffer[string]

	// Stream control. mu guards err and lastEventRevision across the
	// dashboard tick and the stream goroutines.
	mu                sync.Mutex
	eventCancel       context.CancelFunc
	eventDone         chan struct{}
	logsCancel        context.CancelFunc
	logsDone          chan struct{}
	lastEventRevision int64

	// Scroll offsets.
	eventScroll int
	logScroll   int

	// Events panel live display filter (f key). It is pure display: it never
	// gates data access and is never a security boundary.
	eventFilter string

	// pendingApprovals is the count of pending host approvals shown in the
	// footer. -1 means the count is unknown (the approvals call errored) and
	// the indicator is hidden silently.
	pendingApprovals int

	// diagnoseBundle runs the redacted diagnostic bundle in-process for the
	// d hotkey. It is injected by the Runner in production and faked in tests.
	diagnoseBundle diagnoseRunFunc
}

func (r *Runner) tui(ctx context.Context, args []string) int {
	refreshEvery, help, err := r.parseTUIOptions(args)
	if help {
		return r.showCommandHelp(tuiHelp())
	}
	if parseErr, ok := asFlagParseError(err); ok {
		return r.flagParseFailure("tui", parseErr.err)
	}
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx tui: %v\n", err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()

	screen, err := tcell.NewScreen()
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx tui: terminal unavailable: %v\n", err)
		return 1
	}
	if err := screen.Init(); err != nil {
		_, _ = fmt.Fprintf(r.Err, "rsbx tui: terminal initialization failed: %v\n", err)
		return 1
	}
	return runDashboard(ctx, screen, client, refreshEvery, r)
}

func (r *Runner) parseTUIOptions(args []string) (time.Duration, bool, error) {
	fs := r.newFlagSet("tui")
	fs.SetOutput(io.Discard)
	refresh := fs.Duration("refresh", 5*time.Second, "dashboard refresh interval")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true, nil
		}
		return 0, false, flagParseError{err: err}
	}
	if fs.NArg() != 0 {
		return 0, false, errors.New("unexpected argument")
	}
	if *refresh < time.Second || *refresh > time.Minute {
		return 0, false, errors.New("--refresh must be between 1s and 1m")
	}
	return *refresh, false, nil
}

func runDashboard(ctx context.Context, screen dashboardScreen, client sdk.Client, refreshEvery time.Duration, runner *Runner) int {
	defer screen.Fini()
	screen.SetTitle("RHEIC | Sandboxes")
	model := &dashboardModel{}
	if runner != nil {
		model.diagnoseBundle = runner.diagnoseRun
	}
	defer func() {
		model.stopEventStream()
		model.stopLogsStream()
	}()
	refreshDashboard(ctx, client, model)
	drawDashboard(screen, model)

	done := make(chan struct{})
	events := make(chan tcell.Event, 1)
	go forwardDashboardEvents(done, dashboardScreenStopQ(screen), screen.EventQ(), events)
	defer close(done)

	ticker := time.NewTicker(refreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-ticker.C:
			refreshAndDrawDashboard(ctx, screen, client, model)
		case ev, ok := <-events:
			if handleDashboardEvent(ev, ok, screen, client, ctx, model) {
				return 0
			}
		}
	}
}

func dashboardScreenStopQ(screen dashboardScreen) <-chan struct{} {
	stopper, ok := screen.(interface{ StopQ() <-chan struct{} })
	if !ok {
		return nil
	}
	return stopper.StopQ()
}

func forwardDashboardEvents(done, screenStopped <-chan struct{}, eventQueue <-chan tcell.Event, events chan<- tcell.Event) {
	defer close(events)
	for {
		select {
		case <-done:
			return
		case <-screenStopped:
			return
		case event, ok := <-eventQueue:
			if !ok {
				return
			}
			select {
			case events <- event:
			case <-done:
				return
			case <-screenStopped:
				return
			}
		}
	}
}

func refreshAndDrawDashboard(ctx context.Context, screen dashboardScreen, client sdk.Client, model *dashboardModel) {
	refreshDashboard(ctx, client, model)
	drawDashboard(screen, model)
}

func handleDashboardEvent(ev tcell.Event, ok bool, screen dashboardScreen, client sdk.Client, ctx context.Context, model *dashboardModel) bool {
	if !ok {
		return true
	}
	switch event := ev.(type) {
	case *tcell.EventResize:
		screen.Sync()
		drawDashboard(screen, model)
	case *tcell.EventKey:
		if dashboardKey(event, model, ctx, client) {
			return true
		}
		drawDashboard(screen, model)
	}
	return false
}

func dashboardKey(event *tcell.EventKey, model *dashboardModel, ctx context.Context, client sdk.Client) bool {
	switch model.mode {
	case modeCreate:
		if dashboardKeyInCreate(event, model) {
			model.mode = modeList
			if model.pendingCreate.Name != "" {
				submitCreate(ctx, client, model)
				model.pendingCreate = sdk.CreateRequest{}
			}
		}
		return false
	case modeConfirmDelete:
		return dashboardKeyConfirmDelete(event, model, ctx, client)
	case modeEventFilter:
		dashboardKeyEventFilter(event, model)
		return false
	}
	return dashboardKeyList(event, model, ctx, client)
}

// dashboardKeyEventFilter handles the live events filter input. Esc clears the
// filter, Enter keeps it and returns to the panel, and backspace edits it.
func dashboardKeyEventFilter(event *tcell.EventKey, model *dashboardModel) {
	switch {
	case event.Key() == tcell.KeyEscape:
		model.eventFilter = ""
		model.mode = modeList
	case event.Key() == tcell.KeyEnter:
		model.mode = modeList
	case event.Key() == tcell.KeyBackspace || event.Key() == tcell.KeyBackspace2:
		model.filterBackspace()
	case event.Key() == tcell.KeyRune:
		model.filterInsert(event.Str())
	}
}

// filterInsert appends sanitized text to the live filter, capped for display.
func (m *dashboardModel) filterInsert(text string) {
	if m == nil || text == "" || len(m.eventFilter)+len(text) > 64 {
		return
	}
	m.eventFilter += sanitizeTerminalText(text)
}

// filterBackspace removes the last rune of the live filter.
func (m *dashboardModel) filterBackspace() {
	if m == nil || m.eventFilter == "" {
		return
	}
	runes := []rune(m.eventFilter)
	m.eventFilter = string(runes[:len(runes)-1])
}

// dashboardKeyConfirmDelete handles the delete confirmation prompt.
func dashboardKeyConfirmDelete(event *tcell.EventKey, model *dashboardModel, ctx context.Context, client sdk.Client) bool {
	if event.Key() == tcell.KeyEscape || event.Str() == "n" || event.Str() == "N" {
		model.mode = modeList
		model.notice = "delete canceled"
		return false
	}
	if event.Str() == "y" || event.Str() == "Y" {
		model.mode = modeList
		dashboardAction(ctx, client, model, "rm")
	}
	return false
}

// dashboardKeyList handles keys in the sandbox list mode and reports whether
// the dashboard should quit.
func dashboardKeyList(event *tcell.EventKey, model *dashboardModel, ctx context.Context, client sdk.Client) bool {
	if event.Key() == tcell.KeyEscape || event.Str() == "q" || event.Str() == "Q" {
		return true
	}
	if dashboardPanelSwitchKey(event, model, ctx, client) {
		return false
	}
	if model.panel != dashboardPanelSandboxes {
		dashboardAuxPanelKey(event, model, ctx, client)
		return false
	}
	switch {
	case event.Key() == tcell.KeyUp || event.Str() == "k":
		if model.selected > 0 {
			model.selected--
		}
	case event.Key() == tcell.KeyDown || event.Str() == "j":
		if model.selected+1 < len(model.items) {
			model.selected++
		}
	case event.Str() == "r" || event.Str() == "R":
		refreshDashboard(ctx, client, model)
	default:
		return dashboardKeyAction(event, model, ctx, client)
	}
	return false
}

// dashboardPanelSwitchKey handles global panel selection keys and reports
// whether the event was consumed.
func dashboardPanelSwitchKey(event *tcell.EventKey, model *dashboardModel, ctx context.Context, client sdk.Client) bool {
	panel := dashboardPanelSandboxes
	switch event.Str() {
	case "1":
	case "2", "e", "E":
		panel = dashboardPanelEvents
	case "3", "l", "L":
		panel = dashboardPanelLogs
	case "b", "B", "o", "O":
	default:
		switch event.Key() {
		case tcell.KeyTab:
			panel = dashboardPanel((int(model.panel) + 1) % 3)
		case tcell.KeyBacktab:
			panel = dashboardPanel((int(model.panel) + 2) % 3)
		default:
			return false
		}
	}
	model.setPanel(ctx, client, panel)
	return true
}

// dashboardAuxPanelKey handles scroll, reconnect and the events-panel filter
// and diagnose-bundle hotkeys inside the events and logs panels.
func dashboardAuxPanelKey(event *tcell.EventKey, model *dashboardModel, ctx context.Context, client sdk.Client) {
	events := model.panel == dashboardPanelEvents
	switch {
	case event.Key() == tcell.KeyUp || event.Str() == "k":
		model.scrollAuxPanel(1)
	case event.Key() == tcell.KeyDown || event.Str() == "j":
		model.scrollAuxPanel(-1)
	case event.Str() == "r" || event.Str() == "R":
		if events {
			// Reconnect is handled by the resilient watcher; reset dedup tail.
			model.mu.Lock()
			model.lastEventRevision = 0
			model.mu.Unlock()
			return
		}
		model.stopLogsStream()
		model.startLogsStream(ctx, client, model.selectedSandboxID())
	case events && (event.Str() == "f" || event.Str() == "F"):
		model.mode = modeEventFilter
		model.eventFilter = ""
	case events && (event.Str() == "d" || event.Str() == "D"):
		model.runDiagnoseBundle(ctx)
	}
}

// scrollAuxPanel moves the scroll offset of the active auxiliary panel by
// delta, clamped at zero.
func (m *dashboardModel) scrollAuxPanel(delta int) {
	if m.panel == dashboardPanelEvents {
		m.eventScroll = max(m.eventScroll+delta, 0)
		return
	}
	m.logScroll = max(m.logScroll+delta, 0)
}

// dashboardKeyAction handles single-letter list actions (new, start, stop,
// remove, attach hint).
func dashboardKeyAction(event *tcell.EventKey, model *dashboardModel, ctx context.Context, client sdk.Client) bool {
	switch event.Str() {
	case "n", "N":
		model.mode = modeCreate
		model.form = newCreateFormModel()
	case "s", "S":
		dashboardAction(ctx, client, model, "start")
	case "x", "X":
		dashboardAction(ctx, client, model, "stop")
	case "d", "D":
		if len(model.items) > 0 {
			model.mode = modeConfirmDelete
		}
	case "a", "A":
		if len(model.items) > 0 {
			model.notice = "attach: run rsbx attach " + model.items[model.selected].Name + " from a shell"
		}
	}
	return false
}

func refreshDashboard(ctx context.Context, client sdk.Client, model *dashboardModel) {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	items, err := collectSandboxes(callCtx, client, dashboardPageSize, 0)
	if err != nil {
		model.err = err.Error()
		return
	}
	model.items = items
	model.err = ""
	model.updated = time.Now()
	if model.selected >= len(items) {
		model.selected = max(0, len(items)-1)
	}
	model.refreshPendingApprovals(callCtx, client)
}

// refreshPendingApprovals updates the pending approvals count, hiding the
// indicator silently when the approvals list call errors. The count is the
// only value surfaced; approval ids and boundaries are never rendered.
func (m *dashboardModel) refreshPendingApprovals(ctx context.Context, client sdk.Client) {
	if m == nil {
		return
	}
	m.pendingApprovals = -1
	if client == nil {
		return
	}
	items, err := sdk.Approvals(client).ListApprovals(ctx, "")
	if err != nil {
		return
	}
	m.pendingApprovals = len(items)
}

func drawDashboard(screen dashboardScreen, model *dashboardModel) {
	width, height := screen.Size()
	background := tcell.StyleDefault.Foreground(brandLavender).Background(brandBackground)
	primary := tcell.StyleDefault.Foreground(brandLavender).Background(brandBackground)
	muted := tcell.StyleDefault.Foreground(brandMuted).Background(brandBackground)
	accent := tcell.StyleDefault.Foreground(brandAccent).Background(brandBackground).Bold(true)
	warm := tcell.StyleDefault.Foreground(brandWarm).Background(brandBackground)
	selected := tcell.StyleDefault.Foreground(brandLavender).Background(brandPrimary).Bold(true)
	screen.SetStyle(background)
	screen.Clear()
	if width < dashboardMinWidth || height < dashboardMinHeight {
		drawText(screen, 2, 1, "RHEIC", accent, width-4)
		drawText(screen, 2, 3, "Resize terminal to at least 64 x 20", muted, width-4)
		screen.Show()
		return
	}

	drawBrand(screen, primary, accent, width)
	drawText(screen, 2, 9, strings.Repeat("─", width-4), tcell.StyleDefault.Foreground(brandPrimary).Background(brandBackground), width-4)
	drawDashboardPanels(screen, model, width, accent, muted, 10)

	leftWidth := width * 3 / 5
	if leftWidth < 42 {
		leftWidth = 42
	}
	detailX := leftWidth + 3

	switch model.panel {
	case dashboardPanelSandboxes:
		drawSandboxPanel(screen, model, leftWidth, detailX, width, height, primary, accent, muted, warm, selected)
	case dashboardPanelEvents:
		drawText(screen, 3, 11, "EVENTS", muted, leftWidth-4)
		drawEventPanel(screen, model, 3, leftWidth, height, primary, muted)
		if detailX < width-22 {
			drawText(screen, detailX, 11, "EVENT TAIL", muted, width-detailX-2)
			drawText(screen, detailX, 13, fmt.Sprintf("%d buffered (max %d)", model.events().Len(), dashboardEventLimit), primary, width-detailX-2)
			drawText(screen, detailX, 15, "f filter · d diagnose bundle", muted, width-detailX-2)
			if model.eventFilter != "" {
				drawText(screen, detailX, 17, "filter: "+sanitizeTerminalText(model.eventFilter), accent, width-detailX-2)
			}
		}
	default:
		drawText(screen, 3, 11, "LOGS", muted, leftWidth-4)
		drawLogPanel(screen, model, 3, leftWidth, height, primary, muted)
		if detailX < width-22 {
			drawText(screen, detailX, 11, "LOGS", muted, width-detailX-2)
			if len(model.items) > 0 {
				drawText(screen, detailX, 13, sanitizeTerminalText(model.items[model.selected].Name), primary, width-detailX-2)
			}
		}
	}
	drawDashboardFooter(screen, model, width, height, accent, muted, warm)
	screen.Show()
}

// drawSandboxPanel renders the sandbox list and its detail column.
func drawSandboxPanel(screen dashboardScreen, model *dashboardModel, leftWidth, detailX, width, height int, primary, accent, muted, warm, selected tcell.Style) {
	drawText(screen, 3, 11, "SANDBOXES", muted, leftWidth-4)
	drawText(screen, 3, 12, "NAME", accent, 22)
	drawText(screen, 27, 12, dashboardStateLabel, accent, 12)
	drawText(screen, 40, 12, "AGENT", accent, leftWidth-43)
	for y := 13; y < height-3; y++ {
		drawText(screen, 3, y, strings.Repeat(" ", leftWidth-4), primary, leftWidth-4)
		index := y - 13
		if index >= len(model.items) {
			continue
		}
		item := model.items[index]
		style := primary
		marker := " "
		if index == model.selected {
			style = selected
			marker = "›"
		}
		drawText(screen, 2, y, marker, accent, 1)
		drawText(screen, 3, y, clipCell(item.Name, 22), style, 22)
		drawText(screen, 27, y, clipCell(item.State, 12), style, 12)
		drawText(screen, 40, y, clipCell(item.Agent, leftWidth-43), style, leftWidth-43)
	}
	if detailX >= width-22 {
		return
	}
	drawText(screen, detailX, 11, "SELECTED SANDBOX", muted, width-detailX-2)
	switch {
	case len(model.items) > 0:
		drawDashboardDetails(screen, &model.items[model.selected], detailX, width, height, primary, accent, muted, warm)
	case model.err == "":
		drawText(screen, detailX, 13, "No sandboxes yet", primary, width-detailX-2)
		drawText(screen, detailX, 15, "Start one with rsbx run", muted, width-detailX-2)
	}
}

// drawDashboardFooter renders the status, notice, mode overlay and key hints.
func drawDashboardFooter(screen dashboardScreen, model *dashboardModel, width, height int, accent, muted, warm tcell.Style) {
	if model.err != "" {
		drawText(screen, 3, height-3, "DAEMON  "+clipCell(model.err, width-13), warm, width-6)
	} else {
		status := fmt.Sprintf("%d SANDBOXES", len(model.items))
		if model.pendingApprovals >= 0 {
			status += fmt.Sprintf("   %d PENDING APPROVALS", model.pendingApprovals)
		}
		if !model.updated.IsZero() {
			status += "   UPDATED " + model.updated.Format("15:04:05")
		}
		drawText(screen, 3, height-3, status, muted, width-6)
	}
	if model.notice != "" {
		drawText(screen, 3, height-5, clipCell(model.notice, width-6), warm, width-6)
	}
	switch model.mode {
	case modeCreate:
		drawCreateForm(screen, model.form, width, height,
			tcell.StyleDefault.Foreground(brandLavender).Background(brandBackground),
			accent, muted, warm)
	case modeConfirmDelete:
		if len(model.items) > 0 {
			prompt := "Remove " + model.items[model.selected].Name + "? Sandbox files on the host are kept. [y/N]"
			drawText(screen, 3, height-5, clipCell(prompt, width-6), warm.Bold(true), width-6)
		}
	case modeEventFilter:
		prompt := "filter: " + model.eventFilter
		drawText(screen, 3, height-5, clipCell(prompt, width-6), accent.Bold(true), width-6)
	}
	drawText(screen, 3, height-2, dashboardKeyHints(model.panel), accent, width-6)
}

// dashboardKeyHints returns the footer key hint line for the active panel.
func dashboardKeyHints(panel dashboardPanel) string {
	switch panel {
	case dashboardPanelEvents:
		return "1/2/3 or Tab panels   ↑/↓ or j/k  scroll   f  filter   d  diagnose bundle   r  reconnect   q  quit"
	case dashboardPanelLogs:
		return "1/2/3 or Tab panels   ↑/↓ or j/k  scroll   r  reconnect   q  quit"
	default:
		return "1/2/3 or Tab panels   ↑/↓ or j/k  scroll/move   n  new   s/x  start/stop   d  remove   a  attach   r  refresh   q  quit"
	}
}

// drawCreateForm renders the create-flow landing form.
func drawCreateForm(screen dashboardScreen, form createFormModel, width, height int, primary, accent, muted, warm tcell.Style) {
	boxWidth := min(width-8, 64)
	boxX := (width - boxWidth) / 2
	if boxX < 2 {
		boxX = 2
	}
	for y := 6; y < height-6; y++ {
		drawText(screen, boxX, y, strings.Repeat(" ", boxWidth), primary, boxWidth)
	}
	drawText(screen, boxX+2, 7, "NEW SANDBOX", accent, boxWidth-4)
	for i, label := range createFormFields {
		y := 9 + i*2
		style := muted
		if i == form.focus {
			style = accent.Bold(true)
		}
		drawText(screen, boxX+2, y, label, style, 16)
		drawText(screen, boxX+20, y, clipCell(form.values[i], boxWidth-22), primary, boxWidth-22)
	}
	if form.err != "" {
		drawText(screen, boxX+2, height-8, clipCell(form.err, boxWidth-4), warm, boxWidth-4)
	}
	drawText(screen, boxX+2, height-7, "Tab/↑↓ move · Enter create · Esc cancel", muted, boxWidth-4)
}

func drawBrand(screen dashboardScreen, primary, accent tcell.Style, width int) {
	logoStyle := tcell.StyleDefault.Foreground(brandPrimary).Background(brandBackground)
	mask := []string{
		"                         #####  ",
		"                     #######    ",
		"                   ########     ",
		"                 #########      ",
		"          ################      ",
		"     ########################   ",
		"  ####### ####################  ",
		" ################### ## # ##### ",
		"   ##            ##############  ",
		"      ##            ############",
		"                     #  #######  ",
		"                         ######  ",
		"           ####         ######   ",
		"            #######   ######     ",
		"              ###########        ",
		"              ####               ",
	}
	for y := 0; y < len(mask); y += 2 {
		for x := 0; x < len(mask[y]); x++ {
			top := mask[y][x] == '#'
			bottom := y+1 < len(mask) && x < len(mask[y+1]) && mask[y+1][x] == '#'
			glyph := ' '
			switch {
			case top && bottom:
				glyph = '█'
			case top:
				glyph = '▀'
			case bottom:
				glyph = '▄'
			}
			screen.PutStrStyled(2+x, y/2, string(glyph), logoStyle)
		}
	}
	drawText(screen, 38, 1, "RHEIC", primary.Bold(true), width-40)
	drawText(screen, 38, 3, "LOCAL SANDBOXES", accent, width-40)
}

func drawDashboardDetails(screen dashboardScreen, item *sdk.Sandbox, x, width, height int, primary, accent, muted, warm tcell.Style) {
	available := width - x - 2
	rows := []struct{ label, value string }{
		{"NAME", item.Name},
		{dashboardStateLabel, item.State},
		{"AGENT", item.Agent},
		{"IMAGE", item.Image},
		{"ID", item.ID},
		{"WORKSPACE", item.Workspace},
	}
	for i, row := range rows {
		y := 13 + i*2
		if y >= height-5 {
			break
		}
		drawText(screen, x, y, row.label, muted, available)
		style := primary
		if row.label == dashboardStateLabel && item.State != sandboxStateRunning && item.State != sandboxStateStopped {
			style = warm
		} else if row.label == dashboardStateLabel {
			style = accent
		}
		drawText(screen, x, y+1, clipCell(row.value, available), style, available)
	}
}

func drawText(screen dashboardScreen, x, y int, text string, style tcell.Style, maxWidth int) {
	if x < 0 || y < 0 || maxWidth <= 0 {
		return
	}
	text = clipCell(text, maxWidth)
	screen.PutStrStyled(x, y, text, style)
}

func clipCell(text string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= width {
		return text
	}
	if width == 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}
