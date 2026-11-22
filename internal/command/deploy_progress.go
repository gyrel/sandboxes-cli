package command

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// deployProgress renders a live deployment indicator for rsbx run on the
// error stream, styled to match the Docker sbx v0.50.1 baseline captured in
// docs/REVERSE-ENGINEERING.md (2026-11-20 PTY comparison): a SANDBOX summary
// block, magenta braille spinner stages with em-dash grammar settled as green
// check rows, blank-line-separated notices, and an 8-space sub-row. The
// daemon creates and starts sandboxes synchronously inside the RPC, so the
// indicator brackets each blocking stage. Rendering is enabled only when the
// error stream is a terminal; scripts and CI keep the byte-stable
// stdout/stderr contract. TERM=dumb and NO_COLOR suppress ANSI styling.

const (
	progressTick      = 100 * time.Millisecond
	progressDefaultWD = 120
	progressIndent    = "    "
)

var progressFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ANSI styling taken from the observed sbx v0.50.1 progress UI: bright-blue
// section headings, magenta spinner, green check marks, gray labels and
// separators.
const (
	ansiReset      = "\x1b[0m"
	ansiEraseLine  = "\r\x1b[2K"
	ansiHideCursor = "\x1b[?25l"
	ansiShowCursor = "\x1b[?25h"
	ansiHeading    = "\x1b[94m"
	ansiSpinner    = "\x1b[35m"
	ansiCheck      = "\x1b[32m"
	ansiCross      = "\x1b[31m"
	ansiGray       = "\x1b[90m"
)

// progressLabelWidth matches the sbx summary column: values start at column
// 16 ("    " + 11-char label field + 1 space).
const progressLabelWidth = 11

// deployProgress owns one in-place status row (spinnerOpen). A row is drawn
// without a trailing newline, rewritten on every tick, and either committed
// with a settled line or erased on halt. All row writes keep the visible text
// one cell short of the terminal width so the in-place rewrite stays reliable.
type deployProgress struct {
	mu      sync.Mutex
	w       io.Writer
	enabled bool
	colors  bool
	width   int

	spinnerOpen  bool
	cursorHidden bool
	detail       string
	active       bool
	gen          uint64
	step         int
	label        string
	stopCh       chan struct{}
	doneCh       chan struct{}
}

// newDeployProgress builds an indicator writer. Tests pass a buffered writer
// with enabled=true to observe rendering without a terminal.
func newDeployProgress(w io.Writer, enabled, colors bool, width int) *deployProgress {
	if width <= 0 {
		width = progressDefaultWD
	}
	return &deployProgress{w: w, enabled: enabled, colors: colors, width: width}
}

// deployProgressForRunner decides the terminal contract for the current
// invocation: a real TTY on the error stream renders the indicator, everything
// else (pipes, files, --no-progress, TERM=dumb) stays silent.
func (r *Runner) deployProgressForRunner(disabled bool) *deployProgress {
	if disabled {
		return newDeployProgress(r.Err, false, false, 0)
	}
	file, isFile := r.Err.(*os.File)
	if !isFile || !term.IsTerminal(int(file.Fd())) || os.Getenv("TERM") == "dumb" {
		return newDeployProgress(r.Err, false, false, 0)
	}
	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil || width <= 0 {
		width = progressDefaultWD
	}
	colors := os.Getenv("NO_COLOR") == ""
	return newDeployProgress(r.Err, true, colors, width)
}

// summary prints the sbx request block before the stages:
//
//	SANDBOX
//	  Name:       opencode-projects
//	  Agent:      opencode
//	  Workspace:  /path (rw)
//	  Image:      ref (when known)
func (p *deployProgress) summary(name, agent, workspace string, readOnly bool, image string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writef("  %s\n", p.paint(ansiHeading, "SANDBOX"))
	p.summaryRow("Name:", name)
	if agent != "" {
		p.summaryRow("Agent:", agent)
	}
	if workspace != "" {
		mode := "(rw)"
		if readOnly {
			mode = "(ro)"
		}
		p.summaryRow("Workspace:", workspace+" "+mode)
	}
	if image != "" {
		p.summaryRow("Image:", shortImageRef(image))
	}
	p.writef("\n")
}

func (p *deployProgress) summaryRow(label, value string) {
	padded := label + strings.Repeat(" ", max(progressLabelWidth-len(label), 1))
	p.writef("    %s %s\n", p.paint(ansiGray, padded), clipCell(value, max(p.width-progressLabelWidth-6, 0)))
}

// begin starts (or replaces) the active spinner for a blocking stage.
func (p *deployProgress) begin(label string) {
	if p == nil || !p.enabled {
		return
	}
	p.stopSpin()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.cursorHidden {
		p.cursorHidden = true
		p.writef(ansiHideCursor)
	}
	p.label = label
	p.active = true
	p.gen++
	p.step = 0
	p.renderLocked()
	p.startSpinLocked()
}

// next commits the active stage. The done text replaces the active spinner
// wording (sbx model: "image — pulling…" settles as "image — ready"). An
// empty done keeps the active label.
func (p *deployProgress) next(done string) {
	if p == nil || !p.enabled {
		return
	}
	p.stopSpin()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.label == "" {
		return
	}
	if done == "" {
		done = p.label
	}
	p.settleLocked(p.paint(ansiCheck, "✓"), done)
	p.label = ""
	p.detail = ""
}

// notice prints a blank-line-separated settled row, matching the sbx notices
// "✓ Created sandbox <name>" and "✓ sandbox <name> — running detached".
func (p *deployProgress) notice(text string) {
	if p == nil || !p.enabled {
		return
	}
	p.stopSpin()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writef("\n%s%s %s\n", progressIndent, p.paint(ansiCheck, "✓"), clipCell(text, max(p.width-len(progressIndent)-3, 0)))
	p.spinnerOpen = false
	p.active = false
	p.label = ""
	p.detail = ""
	p.showCursorLocked()
}

// sub prints an indented gray detail row below a settled stage (sbx shows the
// workspace path this way).
func (p *deployProgress) sub(text string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writef("        %s\n", p.paint(ansiGray, clipCell(text, max(p.width-9, 0))))
}

// fail commits the active stage with a failure marker. The caller still owns
// the error message written afterwards.
func (p *deployProgress) fail() {
	if p == nil || !p.enabled {
		return
	}
	p.stopSpin()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.label == "" {
		return
	}
	p.settleLocked(p.paint(ansiCross, "✗"), p.label)
	p.label = ""
	p.detail = ""
}

// line prints an informational settled line without an active stage, for
// example a reuse notice.
func (p *deployProgress) line(text string) {
	if p == nil || !p.enabled {
		return
	}
	p.stopSpin()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writef("%s%s %s\n", progressIndent, p.paint(ansiGray, "·"), clipCell(text, max(p.width-len(progressIndent)-3, 0)))
	p.spinnerOpen = false
	p.detail = ""
	p.active = false
	p.label = ""
	p.showCursorLocked()
}

// halt erases the active spinner without printing, so an attached session or
// a raw exec stream starts on a clean line. halt is idempotent and deferred
// from run() so every exit path restores the terminal.
func (p *deployProgress) halt() {
	if p == nil || !p.enabled {
		return
	}
	p.stopSpin()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.spinnerOpen {
		p.writef(ansiEraseLine)
		p.spinnerOpen = false
	}
	if p.cursorHidden {
		p.cursorHidden = false
		p.writef(ansiShowCursor)
	}
	p.label = ""
	p.detail = ""
	p.active = false
}

// setDetail updates the advisory suffix of the active spinner row (for
// example "5/7 layers" from daemon pull progress). It is display data only:
// it never appears on committed history lines and a nil or disabled
// indicator ignores it.
func (p *deployProgress) setDetail(detail string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active || p.detail == detail {
		return
	}
	p.detail = detail
	if p.spinnerOpen {
		p.renderLocked()
	}
}

// paint applies ANSI styling when colors are enabled and returns plain text
// otherwise.
func (p *deployProgress) paint(style, text string) string {
	if !p.colors || style == "" {
		return text
	}
	return style + text + ansiReset
}

// erase returns the in-place clear prefix only when a spinner row is open, so
// committed history lines never carry redundant control sequences.
func (p *deployProgress) erase() string {
	if p.spinnerOpen {
		return ansiEraseLine
	}
	return ""
}

// renderLocked rewrites the active spinner row in place (no trailing newline).
// The row is clipped one cell short of the terminal width: a glyph written in
// the last cell triggers pending-wrap on terminals that wrap immediately, and
// an in-place row that wrapped cannot be erased reliably afterwards.
// runeWidth counts runes, not display cells: double-width characters (CJK,
// emoji) in user data can still exceed the budget. Stage labels are static
// ASCII today; summary values carry user paths and accept the overestimate
// until a display-width helper is shared with the dashboard.
func (p *deployProgress) renderLocked() {
	frame := progressFrames[p.step%len(progressFrames)]
	trailer := ""
	if p.detail != "" {
		trailer = p.paint(ansiGray, " "+p.detail)
	}
	overhead := runeWidth(progressIndent) + runeWidth(frame) + runeWidth(" "+p.detail) + 2
	label := clipCell(p.label, max(p.width-overhead-1, 0))
	p.writef("%s%s%s %s%s", p.erase(), progressIndent, p.paint(ansiSpinner, frame), label, trailer)
	p.spinnerOpen = true
}

// settleLocked commits the open spinner row as a finished history line.
func (p *deployProgress) settleLocked(styledMarker, label string) {
	clipped := clipCell(label, max(p.width-len(progressIndent)-3, 0))
	p.writef("%s%s%s %s\n", p.erase(), progressIndent, styledMarker, clipped)
	p.spinnerOpen = false
	p.active = false
	p.showCursorLocked()
}

// showCursorLocked restores the cursor after a committed row. The sbx baseline
// hides the cursor only while a block animates, so every settled history line
// re-shows it and begin() hides it again for the next stage. This also makes
// the terminal safe on paths that forget halt().
func (p *deployProgress) showCursorLocked() {
	if p.cursorHidden {
		p.cursorHidden = false
		p.writef(ansiShowCursor)
	}
}

func (p *deployProgress) writef(format string, args ...any) {
	_, _ = fmt.Fprintf(p.w, format, args...)
}

// stopSpin ends the current spinner goroutine outside the render lock so the
// goroutine can finish an in-flight frame without deadlocking on the join.
func (p *deployProgress) stopSpin() {
	p.mu.Lock()
	if !p.active {
		p.mu.Unlock()
		return
	}
	p.active = false
	p.gen++
	stop, done := p.stopCh, p.doneCh
	p.stopCh, p.doneCh = nil, nil
	p.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if done != nil {
		<-done
	}
}

func (p *deployProgress) startSpinLocked() {
	p.stopCh = make(chan struct{})
	p.doneCh = make(chan struct{})
	gen := p.gen
	stop, done := p.stopCh, p.doneCh
	go func() {
		defer close(done)
		ticker := time.NewTicker(progressTick)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				p.mu.Lock()
				if p.active && p.gen == gen {
					p.step++
					p.renderLocked()
				}
				p.mu.Unlock()
			}
		}
	}()
}

// shortImageRef keeps digest-pinned references readable in the summary column
// the way sbx shows tag references: the digest is shortened, not hidden.
func shortImageRef(image string) string {
	root, digest, found := strings.Cut(image, "@sha256:")
	if !found {
		return image
	}
	if len(digest) > 12 {
		digest = digest[:12]
	}
	return root + "@sha256:" + digest
}

func runeWidth(s string) int { return len([]rune(s)) }
