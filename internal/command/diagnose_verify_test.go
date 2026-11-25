package command

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyDiagnoseBundle(t *testing.T) {
	for _, tc := range []struct {
		name, member, content string
		code                  int
	}{
		{"clean", "README.txt", "diagnostic data\n", 0},
		{"secret", "logs/daemon.tail.jsonl", "Bearer abcdefghijklmnop\n", 1},
		{"untrusted name", "Bearer abcdefghijklmnop", "Bearer abcdefghijklmnop\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var archive bytes.Buffer
			gz := gzip.NewWriter(&archive)
			tw := tar.NewWriter(gz)
			if err := tw.WriteHeader(&tar.Header{Name: tc.member, Mode: 0o600, Size: int64(len(tc.content))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(tc.content)); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "test.tar.gz")
			if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			r := &Runner{Out: &out, Err: &stderr}
			if code := r.verifyDiagnoseBundle(path); code != tc.code {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), "abcdefghijklmnop") {
				t.Fatal("secret leaked in stderr")
			}
		})
	}
}
