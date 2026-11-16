package daemonctl

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestVerifyRequiresMatchingIdentityAndInstallation(t *testing.T) {
	stateDir := t.TempDir()
	scope, err := ScopeForSocket(filepath.Join(stateDir, "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	installationID, err := EnsureInstallationID(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	record := Record{
		SchemaVersion:  SchemaVersion,
		InstallationID: installationID,
		StateDir:       scope.StateDir,
		Socket:         scope.Socket,
		PID:            4242,
		ProcessStartID: "fixture:start",
		StartedAt:      time.Now().UTC(),
	}
	inspector := newFakeInspector()
	inspector.identities[4242] = "fixture:start"
	if err := Verify(record, scope, installationID, inspector); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	inspector.identities[4242] = "fixture:reused"
	if err := Verify(record, scope, installationID, inspector); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("Verify() reused = %v, want ErrIdentityMismatch", err)
	}
	delete(inspector.identities, 4242)
	if err := Verify(record, scope, installationID, inspector); !errors.Is(err, ErrProcessNotFound) {
		t.Fatalf("Verify() missing = %v, want ErrProcessNotFound", err)
	}
	inspector.errors[4242] = errors.New("permission denied")
	if err := Verify(record, scope, installationID, inspector); !errors.Is(err, ErrIdentityUnverifiable) {
		t.Fatalf("Verify() unverifiable = %v, want ErrIdentityUnverifiable", err)
	}
	if err := Verify(record, scope, strings.Repeat("0", 32), inspector); !errors.Is(err, ErrInstallationMismatch) {
		t.Fatalf("Verify() installation = %v, want ErrInstallationMismatch", err)
	}
	if err := Verify(record, Scope{StateDir: t.TempDir(), Socket: scope.Socket}, installationID, inspector); !errors.Is(err, ErrInstallationMismatch) {
		t.Fatalf("Verify() state dir = %v, want ErrInstallationMismatch", err)
	}
}

func TestScopeForSocketUsesSocketDirectory(t *testing.T) {
	stateDir := t.TempDir()
	scope, err := ScopeForSocket(filepath.Join(stateDir, "daemon.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if scope.StateDir != stateDir || scope.Socket != filepath.Join(stateDir, "daemon.sock") {
		t.Fatalf("scope = %+v", scope)
	}
	if LogPath(scope) != filepath.Join(stateDir, "daemon.log") {
		t.Fatalf("log path = %q", LogPath(scope))
	}
}

func TestCurrentProcessStartIDIsStable(t *testing.T) {
	first, err := CurrentProcessStartID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := CurrentProcessStartID()
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("start identities = %q, %q", first, second)
	}
}

func TestEnsureInstallationIDIsStableAndPrivate(t *testing.T) {
	stateDir := t.TempDir()
	first, err := EnsureInstallationID(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnsureInstallationID(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || !installationIDPattern.MatchString(first) {
		t.Fatalf("identifiers = %q, %q", first, second)
	}
	info, err := os.Stat(InstallationPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("installation file mode = %o", info.Mode().Perm())
	}
}
