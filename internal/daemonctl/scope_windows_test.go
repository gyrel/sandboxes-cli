//go:build windows

package daemonctl

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

func TestNamedPipeEndpointDetection(t *testing.T) {
	path := fmt.Sprintf(`\\.\pipe\rheic-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	if socketPathExists(path) {
		t.Fatal("nonexistent pipe reported as present")
	}
	listener, err := winio.ListenPipe(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close listener: %v", err)
		}
	}()
	if !socketPathExists(path) {
		t.Fatal("listening pipe reported as absent")
	}
}
