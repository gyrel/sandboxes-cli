package daemonctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakeInspector struct {
	identities map[int]string
	errors     map[int]error
	transient  map[int][]error
}

func (f *fakeInspector) StartIdentity(pid int) (string, error) {
	if queue := f.transient[pid]; len(queue) > 0 {
		f.transient[pid] = queue[1:]
		return "", queue[0]
	}
	if err := f.errors[pid]; err != nil {
		return "", err
	}
	identity, ok := f.identities[pid]
	if !ok {
		return "", ErrProcessNotFound
	}
	return identity, nil
}

func newFakeInspector() *fakeInspector {
	return &fakeInspector{identities: make(map[int]string), errors: make(map[int]error), transient: make(map[int][]error)}
}

type fakeProcess struct {
	pid      int
	done     chan struct{}
	signals  int
	kills    int
	onSignal func()
}

func (p *fakeProcess) PID() int { return p.pid }

func (p *fakeProcess) Signal(os.Signal) error {
	p.signals++
	if p.onSignal != nil {
		p.onSignal()
	}
	return nil
}

func (p *fakeProcess) Kill() error {
	p.kills++
	if p.onSignal != nil {
		p.onSignal()
	}
	return nil
}

func (p *fakeProcess) Wait() error {
	<-p.done
	return nil
}

type fakeLauncher struct {
	scope       Scope
	inspector   *fakeInspector
	nextPID     int
	processes   map[int]*fakeProcess
	events      []string
	startArgs   [][]string
	findErr     error
	skipRecord  bool
	startedPath string
}

func newFakeLauncher(scope Scope, inspector *fakeInspector) *fakeLauncher {
	return &fakeLauncher{scope: scope, inspector: inspector, nextPID: 5000, processes: make(map[int]*fakeProcess)}
}

func (f *fakeLauncher) Start(path string, args []string, _ launchOptions) (process, error) {
	f.startedPath = path
	f.startArgs = append(f.startArgs, append([]string(nil), args...))
	f.events = append(f.events, "start")
	f.nextPID++
	proc := &fakeProcess{pid: f.nextPID, done: make(chan struct{})}
	proc.onSignal = func() {
		f.events = append(f.events, "signal")
		delete(f.inspector.identities, proc.pid)
		close(proc.done)
	}
	f.processes[proc.pid] = proc
	identity := "fixture:" + strconv.Itoa(proc.pid)
	f.inspector.identities[proc.pid] = identity
	if f.skipRecord {
		return proc, nil
	}
	if err := f.writeRecord(proc.pid, identity); err != nil {
		return nil, err
	}
	return proc, nil
}

func (f *fakeLauncher) Find(pid int) (process, error) {
	f.events = append(f.events, "find")
	if f.findErr != nil {
		return nil, f.findErr
	}
	proc, ok := f.processes[pid]
	if !ok {
		return nil, ErrProcessNotFound
	}
	return proc, nil
}

func (f *fakeLauncher) writeRecord(pid int, identity string) error {
	installationID, err := EnsureInstallationID(f.scope.StateDir)
	if err != nil {
		return err
	}
	return WriteRecord(f.scope.StateDir, Record{
		SchemaVersion:  SchemaVersion,
		InstallationID: installationID,
		StateDir:       f.scope.StateDir,
		Socket:         f.scope.Socket,
		PID:            pid,
		ProcessStartID: identity,
		StartedAt:      time.Now().UTC(),
	})
}

func testSupervisor(t *testing.T) (*Supervisor, *fakeLauncher, *fakeInspector) {
	t.Helper()
	stateDir := t.TempDir()
	scope, err := (Scope{StateDir: stateDir, Socket: filepath.Join(stateDir, "daemon.sock")}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	inspector := newFakeInspector()
	launcher := newFakeLauncher(scope, inspector)
	supervisor := &Supervisor{
		Scope:       scope,
		Binary:      fakeDaemonBinary(t),
		Inspector:   inspector,
		WaitTimeout: 2 * time.Second,
		launcher:    launcher,
	}
	return supervisor, launcher, inspector
}

func fakeDaemonBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sandboxesd")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeLiveRecord(t *testing.T, scope Scope, inspector *fakeInspector, pid int, identity string) Record {
	t.Helper()
	if err := ensurePrivateDir(scope.StateDir); err != nil {
		t.Fatal(err)
	}
	installationID, err := EnsureInstallationID(scope.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	record := Record{
		SchemaVersion:  SchemaVersion,
		InstallationID: installationID,
		StateDir:       scope.StateDir,
		Socket:         scope.Socket,
		PID:            pid,
		ProcessStartID: identity,
		StartedAt:      time.Now().UTC(),
	}
	if err := WriteRecord(scope.StateDir, record); err != nil {
		t.Fatal(err)
	}
	inspector.identities[pid] = identity
	return record
}

func TestStartSpawnsWithScopeAndPolicy(t *testing.T) {
	supervisor, launcher, _ := testSupervisor(t)
	result, err := supervisor.Start(context.Background(), StartOptions{Detach: true, Policy: "balanced"})
	if err != nil {
		t.Fatal(err)
	}
	if result.PID != 5001 || result.AlreadyRunning || result.LogPath == "" {
		t.Fatalf("result = %+v", result)
	}
	if len(launcher.startArgs) != 1 {
		t.Fatalf("start calls = %d", len(launcher.startArgs))
	}
	args := strings.Join(launcher.startArgs[0], " ")
	for _, want := range []string{"--state " + supervisor.Scope.StateDir, "--socket " + supervisor.Scope.Socket, "--policy balanced"} {
		if !strings.Contains(args, want) {
			t.Fatalf("start args %q lack %q", args, want)
		}
	}
	record, err := ReadRecord(supervisor.Scope.StateDir)
	if err != nil || record.PID != result.PID {
		t.Fatalf("record = %+v, %v", record, err)
	}
}

func TestStartAdoptsAlreadyRunningDaemon(t *testing.T) {
	supervisor, launcher, inspector := testSupervisor(t)
	writeLiveRecord(t, supervisor.Scope, inspector, 7000, "fixture:live")
	result, err := supervisor.Start(context.Background(), StartOptions{Detach: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.AlreadyRunning || result.PID != 7000 || len(launcher.startArgs) != 0 {
		t.Fatalf("result=%+v starts=%v", result, launcher.startArgs)
	}
}

func TestStartRefusesReusedPID(t *testing.T) {
	supervisor, launcher, inspector := testSupervisor(t)
	writeLiveRecord(t, supervisor.Scope, inspector, 7000, "fixture:old")
	inspector.identities[7000] = "fixture:new"
	_, err := supervisor.Start(context.Background(), StartOptions{Detach: true})
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("Start() = %v, want ErrIdentityMismatch", err)
	}
	if len(launcher.startArgs) != 0 {
		t.Fatalf("started despite identity mismatch: %v", launcher.startArgs)
	}
}

func TestStartRefusesSocketWithoutRecord(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket fixture")
	}
	supervisor, launcher, _ := testSupervisor(t)
	if err := ensurePrivateDir(supervisor.Scope.StateDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(supervisor.Scope.Socket, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := supervisor.Start(context.Background(), StartOptions{Detach: true})
	if !errors.Is(err, ErrAmbiguousState) {
		t.Fatalf("Start() = %v, want ErrAmbiguousState", err)
	}
	if len(launcher.startArgs) != 0 {
		t.Fatal("started despite an unverified socket")
	}
}

func TestStopSignalsOnlyVerifiedProcessAndRemovesRecord(t *testing.T) {
	supervisor, launcher, inspector := testSupervisor(t)
	record := writeLiveRecord(t, supervisor.Scope, inspector, 7000, "fixture:live")
	proc := &fakeProcess{pid: 7000, done: make(chan struct{})}
	proc.onSignal = func() {
		delete(inspector.identities, 7000)
		close(proc.done)
	}
	launcher.processes[7000] = proc
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if proc.signals+proc.kills != 1 {
		t.Fatalf("signals=%d kills=%d", proc.signals, proc.kills)
	}
	if _, err := ReadRecord(supervisor.Scope.StateDir); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("record remains: %v", err)
	}
	if record.PID != 7000 {
		t.Fatalf("record = %+v", record)
	}
}

func TestStopRefusesIdentityMismatch(t *testing.T) {
	supervisor, launcher, inspector := testSupervisor(t)
	writeLiveRecord(t, supervisor.Scope, inspector, 7000, "fixture:old")
	inspector.identities[7000] = "fixture:new"
	err := supervisor.Stop(context.Background())
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("Stop() = %v, want ErrIdentityMismatch", err)
	}
	if len(launcher.events) != 0 {
		t.Fatalf("launcher was touched: %v", launcher.events)
	}
}

func TestStopWithoutDaemonRemovesStaleState(t *testing.T) {
	supervisor, _, inspector := testSupervisor(t)
	writeLiveRecord(t, supervisor.Scope, inspector, 7000, "fixture:gone")
	delete(inspector.identities, 7000)
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecord(supervisor.Scope.StateDir); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("record remains: %v", err)
	}
}

func TestStopWaitsThroughTransientIdentityLookupErrors(t *testing.T) {
	supervisor, launcher, inspector := testSupervisor(t)
	writeLiveRecord(t, supervisor.Scope, inspector, 7000, "fixture:live")
	proc := &fakeProcess{pid: 7000, done: make(chan struct{})}
	proc.onSignal = func() {
		delete(inspector.identities, 7000)
		inspector.transient[7000] = []error{errors.New("input/output error")}
		close(proc.done)
	}
	launcher.processes[7000] = proc
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() = %v", err)
	}
	if _, err := ReadRecord(supervisor.Scope.StateDir); !errors.Is(err, ErrNoRecord) {
		t.Fatalf("record remains: %v", err)
	}
}

func TestRestartStopsThenStarts(t *testing.T) {
	supervisor, launcher, inspector := testSupervisor(t)
	record := writeLiveRecord(t, supervisor.Scope, inspector, 7000, "fixture:live")
	proc := &fakeProcess{pid: 7000, done: make(chan struct{})}
	proc.onSignal = func() {
		launcher.events = append(launcher.events, "signal")
		delete(inspector.identities, 7000)
		close(proc.done)
	}
	launcher.processes[7000] = proc
	result, err := supervisor.Restart(context.Background(), StartOptions{Detach: true})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(launcher.events, ",")
	if got != "find,signal,start" {
		t.Fatalf("events = %q", got)
	}
	if result.PID != 5001 || result.PID == record.PID {
		t.Fatalf("result = %+v", result)
	}
}

func TestInspectClassifiesState(t *testing.T) {
	supervisor, _, inspector := testSupervisor(t)
	if inspection := supervisor.Inspect(); inspection.State != StateStopped {
		t.Fatalf("empty state = %+v", inspection)
	}
	writeLiveRecord(t, supervisor.Scope, inspector, 7000, "fixture:live")
	if inspection := supervisor.Inspect(); inspection.State != StateRunning || inspection.PID != 7000 {
		t.Fatalf("live state = %+v", inspection)
	}
	inspector.identities[7000] = "fixture:new"
	if inspection := supervisor.Inspect(); inspection.State != StateAmbiguous {
		t.Fatalf("ambiguous state = %+v", inspection)
	}
}

func TestLevelsRequireRunningDaemonAndSetPersistsWhileStopped(t *testing.T) {
	supervisor, _, inspector := testSupervisor(t)
	if _, err := supervisor.Levels(context.Background()); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Levels() = %v, want ErrNotRunning", err)
	}
	levels, err := supervisor.SetLevel(context.Background(), "general", "debug")
	if err != nil || levels.General != "debug" || levels.Proxy != "info" {
		t.Fatalf("SetLevel() = %+v, %v", levels, err)
	}
	if _, err := supervisor.Levels(context.Background()); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Levels() while stopped = %v", err)
	}
	writeLiveRecord(t, supervisor.Scope, inspector, 7000, "fixture:live")
	levels, err = supervisor.Levels(context.Background())
	if err != nil || levels.General != "debug" {
		t.Fatalf("Levels() = %+v, %v", levels, err)
	}
}

func TestSetLevelRefusesForeignInstallation(t *testing.T) {
	supervisor, _, inspector := testSupervisor(t)
	record := writeLiveRecord(t, supervisor.Scope, inspector, 7000, "fixture:live")
	record.InstallationID = strings.Repeat("0", 32)
	if err := WriteRecord(supervisor.Scope.StateDir, record); err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.SetLevel(context.Background(), "general", "debug"); !errors.Is(err, ErrInstallationMismatch) {
		t.Fatalf("SetLevel() = %v, want ErrInstallationMismatch", err)
	}
}
