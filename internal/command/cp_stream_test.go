package command

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

func TestGuestCopyConsumesPaddedTarStream(t *testing.T) {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	body := []byte("synthetic fixture")
	if err := tw.WriteHeader(&tar.Header{Name: "probe.txt", Mode: 0600, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	archive.Write(make([]byte, 16<<10)) // GNU tar record padding after EOF markers.
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(writer, &archive)
		if closeErr := writer.Close(); err == nil {
			err = closeErr
		}
		done <- err
	}()
	target := filepath.Join(t.TempDir(), "out.txt")
	if err := extractCopyTar(reader, target, "probe.txt"); err != nil {
		t.Fatal(err)
	}
	if err := drainCopyArchiveTail(reader); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("archive producer failed: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(body) {
		t.Fatalf("copied content %q: %v", got, err)
	}
}

func TestGuestCopyRejectsExcessiveTrailingData(t *testing.T) {
	if err := drainCopyArchiveTail(bytes.NewReader(make([]byte, (1<<20)+1))); err == nil {
		t.Fatal("accepted excessive trailing data")
	}
}

func TestCopyAcceptsFollowFlagAfterPaths(t *testing.T) {
	called := false
	var output bytes.Buffer
	runner := &Runner{Out: &output, Err: &output, NewClient: func(string) (sdk.Client, error) { called = true; return nil, errors.New("synthetic connection error") }}
	code := runner.Run(context.Background(), []string{"cp", "sandbox:/tmp/file", "/tmp/copy", "-L"})
	if !called || code != 1 {
		t.Fatalf("exit=%d called=%v output=%q", code, called, output.String())
	}
}
