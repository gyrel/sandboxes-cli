//go:build !windows

package daemonctl

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestStopRefusesLiveUnverifiedUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rsbx-endpoint-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove owned test directory: %v", err)
		}
	})
	socket := filepath.Join(dir, "d.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
	})
	supervisor, err := New(socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Stop(context.Background()); !errors.Is(err, ErrAmbiguousState) {
		t.Fatalf("Stop() = %v, want ambiguous state", err)
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("listener was disturbed: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}
