package command

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

type cpSpyWriter struct {
	mu     sync.Mutex
	writes []string
	buf    bytes.Buffer
}

func (w *cpSpyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writes = append(w.writes, string(p))
	return w.buf.Write(p)
}

func (w *cpSpyWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func (w *cpSpyWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

type cpWarningSandbox struct {
	fakeSandbox
	items []sdk.Sandbox
}

func (s *cpWarningSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: append([]sdk.Sandbox(nil), s.items...)}, nil
}

func (s *cpWarningSandbox) Get(_ context.Context, id string) (*sdk.Sandbox, error) {
	for i := range s.items {
		if s.items[i].ID == id || s.items[i].Name == id {
			item := s.items[i]
			return &item, nil
		}
	}
	return nil, fmt.Errorf("sandbox %s not found", id)
}

type cpWarningSessions struct {
	mu       sync.Mutex
	requests []sdk.SessionRequest
	archive  []byte
}

func (s *cpWarningSessions) OpenSession(_ context.Context, req sdk.SessionRequest) (sdk.ExecSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
	frames := []sdk.SessionFrame{{ExitCode: intPointer(0)}}
	if len(req.Argv) > 0 && req.Argv[0] == "tar" {
		frames = []sdk.SessionFrame{{Stdout: append([]byte(nil), s.archive...)}, {ExitCode: intPointer(0)}}
	}
	return &cpWarningSession{frames: frames}, nil
}

func (s *cpWarningSessions) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func intPointer(value int) *int { return &value }

type cpWarningSession struct {
	mu     sync.Mutex
	frames []sdk.SessionFrame
	input  []byte
	closed bool
}

func (s *cpWarningSession) SendInput(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.input = append(s.input, data...)
	return nil
}

func (s *cpWarningSession) CloseInput() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *cpWarningSession) Resize(sdk.TerminalSize) error { return nil }

func (s *cpWarningSession) Receive() (sdk.SessionFrame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.frames) == 0 {
		return sdk.SessionFrame{}, io.EOF
	}
	frame := s.frames[0]
	s.frames = s.frames[1:]
	return frame, nil
}

type cpWarningClient struct {
	fakeClient
	sandbox  *cpWarningSandbox
	sessions *cpWarningSessions
}

func (c cpWarningClient) Sandboxes() sdk.SandboxService { return c.sandbox }
func (c cpWarningClient) SessionExecutor() sdk.SessionExecutor {
	return c.sessions
}

func newCpWarningRunner(t *testing.T, sessionArchive []byte) (*Runner, *cpSpyWriter, *cpSpyWriter, *cpWarningSessions) {
	t.Helper()
	sandbox := &cpWarningSandbox{items: []sdk.Sandbox{{ID: "sb-dev", Name: "dev"}}}
	sessions := &cpWarningSessions{archive: sessionArchive}
	client := cpWarningClient{sandbox: sandbox, sessions: sessions}
	stdout := &cpSpyWriter{}
	stderr := &cpSpyWriter{}
	runner := &Runner{
		Out: stdout,
		Err: stderr,
		NewClient: func(string) (sdk.Client, error) {
			return client, nil
		},
	}
	return runner, stdout, stderr, sessions
}

func cpWarningFixture(t *testing.T, names ...string) (string, []string) {
	t.Helper()
	root := t.TempDir()
	sources := make([]string, 0, len(names))
	for _, name := range names {
		path := filepath.Join(root, name)
		if strings.HasPrefix(name, "dir-") {
			if err := os.MkdirAll(filepath.Join(path, "nested"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, "nested", "file.txt"), []byte("payload"), 0o600); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
			t.Fatal(err)
		}
		sources = append(sources, path)
	}
	return root, sources
}

func cpWarningGuestArchive(t *testing.T, name, content string) []byte {
	t.Helper()
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func cpWarningArgs(sources []string, destination string) []string {
	args := []string{"cp"}
	args = append(args, sources...)
	return append(args, destination)
}

func TestCpHostToGuestDisclosureLines(t *testing.T) {
	tenSources := []string{"s01.txt", "s02.txt", "s03.txt", "s04.txt", "s05.txt", "s06.txt", "s07.txt", "s08.txt", "s09.txt", "s10.txt"}
	tests := []struct {
		name      string
		sources   []string
		wantNames string
	}{
		{name: "one file", sources: []string{"fixture.txt"}, wantNames: "fixture.txt"},
		{name: "one directory", sources: []string{"dir-tree"}, wantNames: "dir-tree"},
		{name: "three sources", sources: []string{"alpha.txt", "beta.txt", "gamma.txt"}, wantNames: "alpha.txt, beta.txt, gamma.txt"},
		{name: "more than eight sources", sources: tenSources, wantNames: "s01.txt, s02.txt, s03.txt, s04.txt, s05.txt, s06.txt, s07.txt, s08.txt, +2 more"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, sources := cpWarningFixture(t, tt.sources...)
			runner, stdout, stderr, sessions := newCpWarningRunner(t, nil)
			code := runner.Run(context.Background(), cpWarningArgs(sources, "dev:/workspace/"))
			want := fmt.Sprintf("note: copying host content into sandbox dev: %s (the daemon user can read this path)\n", tt.wantNames)
			if !cpHostSourceCopySupported {
				// Fail-closed platform contract (cp_hardlink_other.go): the note is
				// emitted first, then the copy refuses with the typed unsupported
				// error and no exec session starts. Assert the refusal rather than
				// relaxing the stub (AGENTS section 5: enforced or explicitly
				// unsupported).
				if code != 1 {
					t.Fatalf("unsupported platform exit=%d want=1 stderr=%q", code, stderr.String())
				}
				if got := stderr.String(); !strings.HasPrefix(got, want) || !strings.Contains(got, "source hard link validation is unsupported on this platform") {
					t.Fatalf("unsupported-platform output=%q want note prefix %q plus typed refusal", got, want)
				}
				if got := stdout.String(); got != "" {
					t.Fatalf("stdout=%q want empty", got)
				}
				if strings.Contains(stdout.String()+stderr.String(), root) {
					t.Fatalf("absolute host fixture path leaked: %q", stderr.String())
				}
				if got := sessions.requestCount(); got != 0 {
					t.Fatalf("copy sessions=%d want=0 on unsupported platform", got)
				}
				return
			}
			if code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if got := stderr.String(); got != want {
				t.Fatalf("disclosure=%q want=%q", got, want)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout=%q want empty", got)
			}
			if strings.Contains(stdout.String(), root) || strings.Contains(stderr.String(), root) {
				t.Fatalf("absolute host fixture path leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if got, want := sessions.requestCount(), len(tt.sources); got != want {
				t.Fatalf("copy sessions=%d want=%d", got, want)
			}
		})
	}
}

func TestCpGuestToHostPrintsNoDisclosure(t *testing.T) {
	archive := cpWarningGuestArchive(t, "output.log", "guest payload")
	runner, stdout, stderr, _ := newCpWarningRunner(t, archive)
	target := t.TempDir()
	if code := runner.Run(context.Background(), []string{"cp", "dev:/home/user/output.log", target}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if got := stdout.String() + stderr.String(); got != "" {
		t.Fatalf("guest-to-host printed new output: %q", got)
	}
	data, err := os.ReadFile(filepath.Join(target, "output.log"))
	if err != nil || string(data) != "guest payload" {
		t.Fatalf("copied content=%q err=%v", data, err)
	}
}

func TestCpJSONHostSourceBasename(t *testing.T) {
	tests := []struct {
		name        string
		args        func(root string, source string) []string
		wantPresent bool
	}{
		{
			name: "host to guest includes basename",
			args: func(_ string, source string) []string {
				return []string{"cp", source, "dev:/workspace/", "--json"}
			},
			wantPresent: true,
		},
		{
			name: "guest to host omits basename",
			args: func(_ string, _ string) []string {
				return []string{"cp", "dev:/home/user/output.log", filepath.Join(os.TempDir(), "cp-guest-target"), "--json"}
			},
			wantPresent: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := cpWarningGuestArchive(t, "output.log", "guest payload")
			runner, stdout, stderr, _ := newCpWarningRunner(t, archive)
			root, sources := cpWarningFixture(t, "fixture.txt")
			args := tt.args(root, sources[0])
			if !tt.wantPresent {
				target := filepath.Join(t.TempDir(), "target")
				args = []string{"cp", "dev:/home/user/output.log", target, "--json"}
			}
			if code := runner.Run(context.Background(), args); code != 0 {
				if tt.wantPresent && !cpHostSourceCopySupported {
					// Fail-closed platform contract: disclosure note emitted, then the
					// typed unsupported refusal; no JSON success record on failure.
					if !strings.Contains(stderr.String(), "sandbox dev: fixture.txt") ||
						!strings.Contains(stderr.String(), "source hard link validation is unsupported on this platform") {
						t.Fatalf("unsupported-platform output=%q", stderr.String())
					}
					if stdout.String() != "" {
						t.Fatalf("stdout=%q want empty on refused copy", stdout.String())
					}
					if strings.Contains(stdout.String()+stderr.String(), root) {
						t.Fatalf("absolute host fixture path leaked: %q", stderr.String())
					}
					return
				}
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			var got map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
			}
			value, present := got["host_source_basename"]
			if present != tt.wantPresent {
				t.Fatalf("host_source_basename present=%t want=%t output=%q", present, tt.wantPresent, stdout.String())
			}
			if tt.wantPresent && value != "fixture.txt" {
				t.Fatalf("host_source_basename=%v want=fixture.txt", value)
			}
			if tt.wantPresent {
				if !strings.Contains(stderr.String(), "sandbox dev: fixture.txt") {
					t.Fatalf("JSON mode lost disclosure: %q", stderr.String())
				}
			} else if stderr.String() != "" {
				t.Fatalf("guest-to-host JSON stderr=%q", stderr.String())
			}
			if strings.Contains(stdout.String()+stderr.String(), root) {
				t.Fatalf("absolute host fixture path leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestCpHelpMentionsHostDisclosure(t *testing.T) {
	runner, stdout, stderr, _ := newCpWarningRunner(t, nil)
	if code := runner.Run(context.Background(), []string{"cp", "--help"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Copying host content into a sandbox prints a note naming the copied basenames") {
		t.Fatalf("help lacks disclosure sentence: %q", stdout.String())
	}
}

// TestParseCopySpecDriveLetters pins that Windows drive-letter paths are host
// paths, never SANDBOX:PATH references (Windows CI failure on r7-era parser).
func TestParseCopySpecDriveLetters(t *testing.T) {
	tests := []struct {
		value    string
		wantHost bool
	}{
		{`C:\Users\me\a.txt`, true},
		{`c:/temp/b`, true},
		{`Z:\x`, true},
		{`C:`, true},
		{`a:/x`, true}, // single-letter sandbox names are already invalid (grammar needs >=2 chars)
		{"dev:/x", false},
		{"web2:/data/out.tar", false},
		{"ab:/x", false},
	}
	for _, tc := range tests {
		_, guest := parseCopySpec(tc.value)
		if guest == tc.wantHost {
			t.Fatalf("parseCopySpec(%q) guest=%t, want host-only=%t", tc.value, guest, tc.wantHost)
		}
	}
}
