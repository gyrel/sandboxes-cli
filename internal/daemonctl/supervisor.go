package daemonctl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const defaultWaitTimeout = 30 * time.Second

var (
	// ErrNotRunning means the local daemon is not running.
	ErrNotRunning = errors.New("daemon is not running")
	// ErrAmbiguousState means the control record and endpoint disagree or the
	// process identity cannot be proven. Callers must not signal anything.
	ErrAmbiguousState = errors.New("daemon state is ambiguous")
)

// StartOptions controls starting the local daemon.
type StartOptions struct {
	Detach bool
	Policy string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// StartResult reports a successful start or an already-running daemon.
type StartResult struct {
	PID            int
	AlreadyRunning bool
	Foreground     bool
	Socket         string
	LogPath        string
}

// InspectionState classifies the local daemon process.
type InspectionState string

const (
	// StateRunning means the control record names a live, proven process.
	StateRunning InspectionState = "running"
	// StateStopped means no daemon process is running.
	StateStopped InspectionState = "stopped"
	// StateAmbiguous means the local state cannot be proven safe to act on.
	StateAmbiguous InspectionState = "ambiguous"
)

// Inspection is the result of checking the local control record.
type Inspection struct {
	State  InspectionState
	PID    int
	Record Record
	Err    error
}

type process interface {
	PID() int
	Signal(os.Signal) error
	Kill() error
	Wait() error
}

type launchOptions struct {
	Dir    string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Detach bool
}

type launcher interface {
	Start(path string, args []string, opts launchOptions) (process, error)
	Find(pid int) (process, error)
}

// Supervisor controls one local daemon installation. It is the only component
// that starts or signals a daemon process.
type Supervisor struct {
	Scope             Scope
	Binary            string
	Inspector         ProcessInspector
	EndpointInspector EndpointInspector
	WaitTimeout       time.Duration
	launcher          launcher
}

// New creates a supervisor for the installation selected by --socket.
func New(socket string) (*Supervisor, error) {
	scope, err := ScopeForSocket(socket)
	if err != nil {
		return nil, err
	}
	return &Supervisor{
		Scope:             scope,
		Inspector:         SystemInspector{},
		EndpointInspector: SystemEndpointInspector{},
		WaitTimeout:       defaultWaitTimeout,
		launcher:          osLauncher{},
	}, nil
}

// LogPath returns the daemon log file for this installation.
func (s *Supervisor) LogPath() string {
	return LogPath(s.Scope)
}

// Start spawns or adopts the local daemon process.
func (s *Supervisor) Start(ctx context.Context, opts StartOptions) (StartResult, error) {
	record, running, err := s.prepareStart()
	if err != nil {
		return StartResult{}, err
	}
	if running {
		return s.runningResult(record), nil
	}
	binary, err := ResolveBinary(s.Binary)
	if err != nil {
		return StartResult{}, err
	}
	args := []string{"--state", s.Scope.StateDir, "--socket", s.Scope.Socket}
	if opts.Policy != "" {
		args = append(args, "--policy", opts.Policy)
	}
	launch, cleanup, err := s.launchOptions(opts)
	if err != nil {
		return StartResult{}, err
	}
	defer cleanup()
	proc, err := s.launcher.Start(binary, args, launch)
	if err != nil {
		return StartResult{}, fmt.Errorf("start %s: %w", binary, err)
	}
	waited := waitAsync(proc)
	record, err = s.waitForRecord(ctx, waited)
	if err != nil {
		terminateSpawned(proc)
		return StartResult{}, err
	}
	result := StartResult{PID: record.PID, Socket: s.Scope.Socket, LogPath: s.LogPath()}
	if opts.Detach {
		return result, nil
	}
	result.Foreground = true
	select {
	case err := <-waited:
		if err != nil {
			return result, fmt.Errorf("daemon exited: %w", err)
		}
		return result, nil
	case <-ctx.Done():
		return result, ctx.Err()
	}
}

func (s *Supervisor) prepareStart() (Record, bool, error) {
	record, err := LoadVerified(s.Scope, s.Inspector)
	if err == nil {
		return record, true, nil
	}
	switch {
	case errors.Is(err, ErrNoRecord):
		if socketPathExists(s.Scope.Socket) {
			return Record{}, false, fmt.Errorf("%w: socket %s exists without a verified control record; remove it only after confirming no daemon is running", ErrAmbiguousState, s.Scope.Socket)
		}
	case errors.Is(err, ErrProcessNotFound):
		if socketPathExists(s.Scope.Socket) {
			return Record{}, false, fmt.Errorf("%w: endpoint exists but the recorded process is gone; stop the external daemon manually and verify the endpoint before removing stale state", ErrAmbiguousState)
		}
	default:
		return Record{}, false, fmt.Errorf("refusing to start daemon: %w", err)
	}
	if err := ensurePrivateDir(s.Scope.StateDir); err != nil {
		return Record{}, false, err
	}
	if _, err := EnsureInstallationID(s.Scope.StateDir); err != nil {
		return Record{}, false, err
	}
	return Record{}, false, nil
}

func (s *Supervisor) runningResult(record Record) StartResult {
	return StartResult{
		PID:            record.PID,
		AlreadyRunning: true,
		Socket:         s.Scope.Socket,
		LogPath:        s.LogPath(),
	}
}

func (s *Supervisor) launchOptions(opts StartOptions) (launchOptions, func(), error) {
	if !opts.Detach {
		launch := launchOptions{Dir: s.Scope.StateDir, Stdin: opts.Stdin, Stdout: opts.Stdout, Stderr: opts.Stderr}
		if launch.Stdin == nil {
			launch.Stdin = os.Stdin
		}
		if launch.Stdout == nil {
			launch.Stdout = os.Stdout
		}
		if launch.Stderr == nil {
			launch.Stderr = os.Stderr
		}
		return launch, func() {}, nil
	}
	if err := ensurePrivateDir(s.Scope.StateDir); err != nil {
		return launchOptions{}, nil, err
	}
	logFile, err := openLogFile(s.LogPath())
	if err != nil {
		return launchOptions{}, nil, err
	}
	launch := launchOptions{Dir: s.Scope.StateDir, Stdout: logFile, Stderr: logFile, Detach: true}
	return launch, func() { _ = logFile.Close() }, nil
}

func openLogFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- path is derived from the private state directory.
	if err != nil {
		return nil, fmt.Errorf("open daemon log: %w", err)
	}
	return file, nil
}

func waitAsync(proc process) <-chan error {
	waited := make(chan error, 1)
	go func() { waited <- proc.Wait() }()
	return waited
}

func terminateSpawned(proc process) {
	if proc == nil {
		return
	}
	if err := signalStop(proc); err != nil {
		_ = proc.Kill()
	}
}

func (s *Supervisor) waitForRecord(ctx context.Context, waited <-chan error) (Record, error) {
	timeout := s.WaitTimeout
	if timeout <= 0 {
		timeout = defaultWaitTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return Record{}, ctx.Err()
		case err := <-waited:
			if err != nil {
				return Record{}, fmt.Errorf("daemon exited during startup: %w", err)
			}
			return Record{}, errors.New("daemon exited during startup")
		case <-timer.C:
			return Record{}, fmt.Errorf("daemon did not publish a verified control record within %s", timeout)
		case <-ticker.C:
			record, err := LoadVerified(s.Scope, s.Inspector)
			if err == nil {
				return record, nil
			}
			if errors.Is(err, ErrNoRecord) || errors.Is(err, ErrProcessNotFound) {
				continue
			}
			return Record{}, err
		}
	}
}

// Stop signals the proven daemon process and waits for it to exit.
func (s *Supervisor) Stop(ctx context.Context) error {
	record, err := LoadVerified(s.Scope, s.Inspector)
	if err == nil {
		return s.stopRecorded(ctx, record)
	}
	return s.stopUnrecorded(ctx, err)
}

func (s *Supervisor) stopRecorded(ctx context.Context, record Record) error {
	proc, err := s.launcher.Find(record.PID)
	if err != nil {
		return fmt.Errorf("%w: find daemon PID %d: %w", ErrIdentityUnverifiable, record.PID, err)
	}
	// Re-verify immediately before signaling. This narrows the PID-reuse window
	// without ever treating an unproven PID as safe to signal.
	if err := Verify(record, s.Scope, record.InstallationID, s.Inspector); err != nil {
		return fmt.Errorf("refusing to stop daemon: %w", err)
	}
	return s.signalAndWait(ctx, record, proc)
}

func (s *Supervisor) stopUnrecorded(ctx context.Context, cause error) error {
	record, err := s.liveEndpointIdentity()
	if err != nil {
		return s.stopEndpointError(cause, err)
	}
	proc, err := s.launcher.Find(record.PID)
	if err != nil {
		return fmt.Errorf("%w: find endpoint PID %d: %w", ErrIdentityUnverifiable, record.PID, err)
	}
	if err := s.verifyStartIdentity(record.PID, record.ProcessStartID); err != nil {
		return fmt.Errorf("refusing to stop daemon: %w", err)
	}
	// Re-read the endpoint owner immediately before signaling so a replaced
	// socket cannot make an earlier proof name a different process.
	current, err := s.liveEndpointIdentity()
	if err != nil {
		return fmt.Errorf("refusing to stop daemon: %w", err)
	}
	if current.PID != record.PID || current.ProcessStartID != record.ProcessStartID {
		return fmt.Errorf("%w: endpoint ownership changed before signaling", ErrIdentityMismatch)
	}
	return s.signalAndWait(ctx, record, proc)
}

func (s *Supervisor) stopEndpointError(cause, liveErr error) error {
	if errors.Is(liveErr, ErrEndpointNotRunning) {
		if errors.Is(cause, ErrNoRecord) || errors.Is(cause, ErrProcessNotFound) {
			return nil
		}
		return fmt.Errorf("refusing to stop daemon: %w", cause)
	}
	if errors.Is(cause, ErrInvalidRecord) {
		return fmt.Errorf("refusing to stop daemon: %w", cause)
	}
	return fmt.Errorf("%w: daemon at %s was started outside 'rsbx daemon start' and its identity cannot be verified; inspect the process that owns the socket, stop it manually with SIGTERM, and verify the endpoint before removing it: %w", ErrAmbiguousState, s.Scope.Socket, liveErr)
}

func (s *Supervisor) signalAndWait(ctx context.Context, record Record, proc process) error {
	if err := signalStop(proc); err != nil {
		return fmt.Errorf("stop daemon PID %d: %w", record.PID, err)
	}
	if err := s.waitStopped(ctx, record); err != nil {
		return err
	}
	if socketPathExists(s.Scope.Socket) {
		return fmt.Errorf("%w: recorded daemon stopped but its endpoint still exists; verify the endpoint before removing stale state", ErrAmbiguousState)
	}
	// The daemon removes its own record during shutdown. Do not remove it here:
	// another daemon may have published a replacement while this one exited.
	return nil
}

func (s *Supervisor) waitStopped(ctx context.Context, record Record) error {
	timeout := s.WaitTimeout
	if timeout <= 0 {
		timeout = defaultWaitTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if lastErr != nil {
				return fmt.Errorf("daemon PID %d did not stop within %s: %w; refusing to signal it again", record.PID, timeout, lastErr)
			}
			return fmt.Errorf("daemon PID %d did not stop within %s; refusing to signal it again", record.PID, timeout)
		case <-ticker.C:
			stopped, err := s.processGone(record)
			if err != nil {
				// A process that is exiting can briefly fail identity lookup
				// (for example EIO on Darwin). Keep polling and fail closed at
				// the deadline instead of treating the transition as proof.
				lastErr = err
				continue
			}
			lastErr = nil
			if stopped {
				return nil
			}
		}
	}
}

func (s *Supervisor) processGone(record Record) (bool, error) {
	current, err := s.Inspector.StartIdentity(record.PID)
	if errors.Is(err, ErrProcessNotFound) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: PID %d: %w", ErrIdentityUnverifiable, record.PID, err)
	}
	return current != record.ProcessStartID, nil
}

// Restart stops the verified daemon and starts a new one.
func (s *Supervisor) Restart(ctx context.Context, opts StartOptions) (StartResult, error) {
	if err := s.Stop(ctx); err != nil {
		return StartResult{}, err
	}
	return s.Start(ctx, opts)
}

// Inspect classifies the local daemon without signaling it. A fully verified
// control record is preferred; otherwise the live socket peer is used as proof
// for a daemon that was started outside the CLI.
func (s *Supervisor) Inspect() Inspection {
	record, err := LoadVerified(s.Scope, s.Inspector)
	if err == nil {
		return Inspection{State: StateRunning, PID: record.PID, Record: record}
	}
	live, liveErr := s.liveEndpointIdentity()
	if liveErr == nil {
		return Inspection{State: StateRunning, PID: live.PID, Record: live}
	}
	if errors.Is(liveErr, ErrEndpointNotRunning) {
		if errors.Is(err, ErrNoRecord) || errors.Is(err, ErrProcessNotFound) {
			return Inspection{State: StateStopped}
		}
		return Inspection{State: StateAmbiguous, Err: err}
	}
	if socketPathExists(s.Scope.Socket) {
		return Inspection{State: StateAmbiguous, Err: fmt.Errorf("%w: %w", ErrAmbiguousState, liveErr)}
	}
	return Inspection{State: StateAmbiguous, Err: err}
}

// Levels returns the persisted log levels of a running daemon.
func (s *Supervisor) Levels(context.Context) (Levels, error) {
	if inspection := s.Inspect(); inspection.State != StateRunning {
		if inspection.Err != nil {
			return Levels{}, fmt.Errorf("%w: %w", ErrNotRunning, inspection.Err)
		}
		return Levels{}, ErrNotRunning
	}
	return LoadLevels(s.Scope.StateDir)
}

// SetLevel validates and persists a category change. A stopped daemon picks the
// change up on its next start, matching sbx.
func (s *Supervisor) SetLevel(_ context.Context, category, level string) (Levels, error) {
	if err := s.checkScopeOwnership(); err != nil {
		return Levels{}, err
	}
	current, err := LoadLevels(s.Scope.StateDir)
	if err != nil {
		return Levels{}, err
	}
	next, err := ApplyLevel(current, category, level)
	if err != nil {
		return Levels{}, err
	}
	if err := WriteLevels(s.Scope.StateDir, next); err != nil {
		return Levels{}, err
	}
	return next, nil
}

func (s *Supervisor) checkScopeOwnership() error {
	record, err := ReadRecord(s.Scope.StateDir)
	if errors.Is(err, ErrNoRecord) {
		return ensurePrivateDir(s.Scope.StateDir)
	}
	if err != nil {
		return err
	}
	installationID, err := readInstallationID(InstallationPath(s.Scope.StateDir))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInstallationMismatch, err)
	}
	return CheckInstallation(record, s.Scope, installationID)
}
