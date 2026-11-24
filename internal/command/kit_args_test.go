package command

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

const argKitSpec = `schemaVersion: "3"
kind: mixin
args:
  region:
    env: KIT_REGION
    enum: [eu, us]
    required: true
  tier:
    env: KIT_TIER
    default: basic
    pattern: '^[a-z]+$'
`

// writeArgKit writes a synthetic v3 kit directory named argkit under a fresh
// temporary root and returns its path.
func writeArgKit(t *testing.T, spec string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "argkit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "spec.yaml"), []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeArgsFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kit-args.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// expandKitArgs substitutes the {kit}, {ws} and {file} placeholders.
func expandKitArgs(args []string, vars map[string]string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		for key, value := range vars {
			arg = strings.ReplaceAll(arg, "{"+key+"}", value)
		}
		out = append(out, arg)
	}
	return out
}

func TestCreateKitArgumentsReachCreateRequest(t *testing.T) {
	kitDir := writeArgKit(t, argKitSpec)
	workspace := t.TempDir()
	argsFile := writeArgsFile(t, "region=eu\ntier=pro\n")
	yamlFile := writeArgsFile(t, "region: us\ntier: pro\n")
	vars := map[string]string{"kit": kitDir, "ws": workspace, "file": argsFile, "yaml": yamlFile}
	tests := []struct {
		name    string
		args    []string
		wantEnv map[string]string
	}{
		{
			name:    "flag value and default",
			args:    []string{"shell", "{ws}", "--kit", "{kit}", "--kit-arg", "region=eu"},
			wantEnv: map[string]string{"KIT_REGION": "eu", "KIT_TIER": "basic"},
		},
		{
			name:    "interspersed flags before agent and workspace",
			args:    []string{"--kit", "{kit}", "shell", "--kit-arg", "region=us", "{ws}", "--kit-arg", "tier=pro"},
			wantEnv: map[string]string{"KIT_REGION": "us", "KIT_TIER": "pro"},
		},
		{
			name:    "assignment forms",
			args:    []string{"shell", "{ws}", "--kit={kit}", "--kit-arg=region=eu", "--kit-arg=tier=dev"},
			wantEnv: map[string]string{"KIT_REGION": "eu", "KIT_TIER": "dev"},
		},
		{
			name:    "file lines overridden by flag",
			args:    []string{"shell", "{ws}", "--kit", "{kit}", "--kit-args-file", "{file}", "--kit-arg", "region=us"},
			wantEnv: map[string]string{"KIT_REGION": "us", "KIT_TIER": "pro"},
		},
		{
			name:    "YAML map file",
			args:    []string{"shell", "{ws}", "--kit", "{kit}", "--kit-args-file", "{yaml}"},
			wantEnv: map[string]string{"KIT_REGION": "us", "KIT_TIER": "pro"},
		},
		{
			name:    "qualified key beats unqualified regardless of order",
			args:    []string{"shell", "{ws}", "--kit", "{kit}", "--kit-arg", "argkit.region=us", "--kit-arg", "region=eu"},
			wantEnv: map[string]string{"KIT_REGION": "us", "KIT_TIER": "basic"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, sandbox, output := runCreateWithKit(t, expandKitArgs(tc.args, vars)...)
			if code != 0 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			for key, want := range tc.wantEnv {
				if got := sandbox.request.Env[key]; got != want {
					t.Fatalf("env %s=%q, want %q (env=%v)", key, got, want, sandbox.request.Env)
				}
			}
		})
	}
}

func TestCreateKitArgumentsRefusals(t *testing.T) {
	kitDir := writeArgKit(t, argKitSpec)
	workspace := t.TempDir()
	vars := map[string]string{"kit": kitDir, "ws": workspace, "file": writeArgsFile(t, "region=eu\n")}
	tests := []struct {
		name   string
		args   []string
		stderr string
	}{
		{name: "missing required", args: []string{"shell", "{ws}", "--kit", "{kit}"}, stderr: `required kit argument "region" is not set`},
		{name: "outside enum", args: []string{"shell", "{ws}", "--kit", "{kit}", "--kit-arg", "region=xx"}, stderr: `kit argument "region" is not one of its allowed values`},
		{name: "pattern", args: []string{"shell", "{ws}", "--kit", "{kit}", "--kit-arg", "region=eu", "--kit-arg", "tier=S3CR3T-VALUE"}, stderr: `kit argument "tier" does not match its pattern`},
		{name: "undeclared", args: []string{"shell", "{ws}", "--kit", "{kit}", "--kit-arg", "region=eu", "--kit-arg", "extra=1"}, stderr: `kit argument "extra" is not declared by this kit`},
		{name: "malformed", args: []string{"shell", "{ws}", "--kit", "{kit}", "--kit-arg", "region"}, stderr: "kit argument must use name=value"},
		{name: "missing file", args: []string{"shell", "{ws}", "--kit", "{kit}", "--kit-args-file", "/nonexistent/kit-args.txt"}, stderr: "read kit arguments file"},
		{name: "arguments without kit", args: []string{"shell", "{ws}", "--kit-arg", "region=eu"}, stderr: "--kit-arg and --kit-args-file require --kit"},
		{name: "file without kit", args: []string{"shell", "{ws}", "--kit-args-file", "{file}"}, stderr: "--kit-arg and --kit-args-file require --kit"},
		{name: "duplicate kit", args: []string{"shell", "{ws}", "--kit", "{kit}", "--kit", "{kit}"}, stderr: "--kit can be given only once"},
		{name: "env collision", args: []string{"shell", "{ws}", "-e", "KIT_REGION=us", "--kit", "{kit}", "--kit-arg", "region=eu"}, stderr: "environment variable KIT_REGION is set by a kit argument and by --env or --env-file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, sandbox, output := runCreateWithKit(t, expandKitArgs(tc.args, vars)...)
			if code == 0 {
				t.Fatalf("exit=0 output=%q", output)
			}
			if !strings.Contains(output, tc.stderr) {
				t.Fatalf("output=%q, want %q", output, tc.stderr)
			}
			if sandbox.request.Name != "" || sandbox.request.Agent != "" {
				t.Fatalf("sandbox created despite refusal: %+v", sandbox.request)
			}
			if strings.Contains(output, "S3CR3T-VALUE") {
				t.Fatalf("argument value leaked into output: %q", output)
			}
		})
	}
}

func TestCreateKitArgumentsRefuseBuilderOnlyKits(t *testing.T) {
	tests := map[string]struct {
		spec   string
		stderr string
	}{
		"buildArg": {
			spec:   "schemaVersion: \"3\"\nkind: mixin\nargs:\n  version: {buildArg: GH_VERSION, default: \"2.98.0\"}\n",
			stderr: `kit argument "version" is a build argument; building kits is not implemented`,
		},
		"buildSecret": {
			spec:   "schemaVersion: \"3\"\nkind: mixin\nargs:\n  token: {buildSecret: id}\n",
			stderr: `kit argument "token" is a build argument`,
		},
		"capabilities need builder": {
			spec:   "schemaVersion: \"3\"\nkind: mixin\ncapabilities:\n  - type: com.docker.sandbox/privileged@1\n",
			stderr: "require a kit builder",
		},
		"provides need builder": {
			spec:   "schemaVersion: \"3\"\nkind: mixin\nprovides:\n  - jq@1.7\nargs:\n  region: {env: REGION}\n",
			stderr: "require a kit builder",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			code, sandbox, output := runCreateWithKit(t, "shell", t.TempDir(), "--kit", writeArgKit(t, tc.spec))
			if code == 0 || !strings.Contains(output, tc.stderr) {
				t.Fatalf("exit=%d output=%q, want %q", code, output, tc.stderr)
			}
			if sandbox.request.Name != "" || sandbox.request.Agent != "" {
				t.Fatalf("sandbox created despite refusal: %+v", sandbox.request)
			}
		})
	}
}

func TestCreateKitArgumentsRejectedForV2Kit(t *testing.T) {
	dir := writeArgKit(t, "apiVersion: rheic.dev/v1alpha1\nkind: Kit\nmetadata: {name: argkit}\nspec:\n  agent: shell\n")
	code, _, output := runCreateWithKit(t, "shell", t.TempDir(), "--kit", dir, "--kit-arg", "region=eu")
	if code == 0 || !strings.Contains(output, `kit argument "region" is not declared by this kit`) {
		t.Fatalf("exit=%d output=%q", code, output)
	}
}

func runCreateWithKit(t *testing.T, args ...string) (int, *recordingCreateSandbox, string) {
	t.Helper()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	code := runner.Run(context.Background(), append([]string{"create"}, args...))
	return code, sandbox, out.String()
}

func TestRunKitArgumentsReachCreateRequest(t *testing.T) {
	kitDir := writeArgKit(t, argKitSpec)
	workspace := t.TempDir()
	argsFile := writeArgsFile(t, "region=us\n")
	tests := []struct {
		name    string
		args    []string
		wantEnv map[string]string
	}{
		{
			name:    "flags after workspace",
			args:    []string{"--detach", "--name", "dev", "--kit", kitDir, "shell", workspace, "--kit-arg", "region=eu"},
			wantEnv: map[string]string{"KIT_REGION": "eu", "KIT_TIER": "basic"},
		},
		{
			name:    "assignment forms and file",
			args:    []string{"--detach", "--name", "dev", "--kit=" + kitDir, "--kit-args-file=" + argsFile, "--kit-arg=tier=pro", "shell", workspace},
			wantEnv: map[string]string{"KIT_REGION": "us", "KIT_TIER": "pro"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sandboxes := &runSandbox{}
			runner, out, stderr := runTestRunner(t, runClient{
				fakeClient: fakeClient{accounts: &fakeAccounts{}}, sandboxes: sandboxes, sessions: &fakeSessions{},
			}, "")
			if code := runner.Run(context.Background(), append([]string{"run"}, tc.args...)); code != 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			for key, want := range tc.wantEnv {
				if got := sandboxes.created.Env[key]; got != want {
					t.Fatalf("env %s=%q, want %q (env=%v)", key, got, want, sandboxes.created.Env)
				}
			}
		})
	}
}

func TestRunKitArgumentRefusals(t *testing.T) {
	kitDir := writeArgKit(t, argKitSpec)
	workspace := t.TempDir()
	tests := []struct {
		name   string
		args   []string
		stderr string
	}{
		{name: "missing required", args: []string{"--detach", "--name", "dev", "--kit", kitDir, "shell", workspace}, stderr: `required kit argument "region" is not set`},
		{name: "arguments without kit", args: []string{"--detach", "--name", "dev", "shell", workspace, "--kit-arg", "region=eu"}, stderr: "--kit-arg and --kit-args-file require --kit"},
		{name: "duplicate kit", args: []string{"--detach", "--name", "dev", "--kit", kitDir, "--kit=" + kitDir, "shell", workspace, "--kit-arg", "region=eu"}, stderr: "--kit can be given only once"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sandboxes := &runSandbox{}
			runner, out, stderr := runTestRunner(t, runClient{
				fakeClient: fakeClient{accounts: &fakeAccounts{}}, sandboxes: sandboxes, sessions: &fakeSessions{},
			}, "")
			if code := runner.Run(context.Background(), append([]string{"run"}, tc.args...)); code == 0 {
				t.Fatalf("exit=0 stdout=%q stderr=%q", out.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("stderr=%q, want %q", stderr.String(), tc.stderr)
			}
			if sandboxes.createCalls != 0 {
				t.Fatalf("sandbox created despite refusal: calls=%d", sandboxes.createCalls)
			}
		})
	}
}

func TestRunAndCreateHelpListKitArgumentFlags(t *testing.T) {
	for _, command := range []string{"run", "create"} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		if code := runner.Run(context.Background(), []string{command, "--help"}); code != 0 {
			t.Fatalf("%s --help exit=%d", command, code)
		}
		for _, expected := range []string{"--kit-arg stringArray", "--kit-args-file stringArray"} {
			if !strings.Contains(out.String(), expected) {
				t.Errorf("%s help omitted %q", command, expected)
			}
		}
	}
}
