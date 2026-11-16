package command

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

// documentedHelpPaths lists every command and subcommand that exposes help.
var documentedHelpPaths = [][]string{
	{"run"}, {"attach"}, {"create"}, {"exec"}, {"cp"}, {"login"}, {"logout"},
	{"ls"}, {"get"}, {"start"}, {"stop"}, {"rm"}, {"prune"}, {"wait"},
	{"ports"}, {"diagnose"}, {"reset"}, {"tui"}, {"setup"}, {"completion"},
	{"version"}, {"agents"}, {"agents", "ls"},
	{"secret"}, {"secret", "import"}, {"secret", "ls"}, {"secret", "set"},
	{"secret", "rm"}, {"secret", "set-custom"},
	{"settings"}, {"settings", "ls"}, {"settings", "get"},
	{"settings", "set"}, {"settings", "unset"},
	{"policy"}, {"policy", "ls"}, {"policy", "inspect"}, {"policy", "log"},
	{"policy", "refresh"}, {"policy", "reset"}, {"policy", "approval"},
	{"policy", "allow"}, {"policy", "deny"}, {"policy", "rm"},
	{"policy", "check"}, {"policy", "check", "network"},
	{"policy", "check", "filesystem"}, {"policy", "init"},
	{"policy", "profile"}, {"policy", "org"},
	{"kit"}, {"kit", "inspect"}, {"kit", "ls"},
	{"daemon"}, {"daemon", "status"},
	{"template"}, {"template", "ls"}, {"template", "inspect"},
	{"env"}, {"env", "plan"}, {"env", "create"}, {"env", "run"},
	{"env", "exec"}, {"env", "rm"},
	{"mcp"}, {"mcp", "ls"}, {"mcp", "add"}, {"mcp", "call"}, {"mcp", "rm"},
	{"skills"}, {"skills", "ls"}, {"skills", "import"}, {"skills", "rm"},
}

func TestHelpWritesStdoutAndExitsZeroForEveryCommand(t *testing.T) {
	for _, path := range documentedHelpPaths {
		path := append([]string(nil), path...)
		t.Run(strings.Join(path, " "), func(t *testing.T) {
			invocations := [][]string{
				append(append([]string(nil), path...), helpFlag),
				append([]string{"help"}, path...),
			}
			for _, args := range invocations {
				var stdout, stderr bytes.Buffer
				runner := &Runner{Out: &stdout, Err: &stderr, In: strings.NewReader("")}
				if code := runner.Run(context.Background(), args); code != 0 {
					t.Fatalf("%v: exit=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
				}
				if strings.TrimSpace(stdout.String()) == "" {
					t.Fatalf("%v: empty help on stdout", args)
				}
				if stderr.Len() != 0 {
					t.Fatalf("%v: help wrote to stderr: %q", args, stderr.String())
				}
			}
		})
	}
}

// positionalHelpProbes move the help flag from before to after the first
// positional argument for every command that accepts positionals.
var positionalHelpProbes = []struct {
	path       []string
	positional string
}{
	{[]string{"run"}, "shell"},
	{[]string{"attach"}, "dev"},
	{[]string{"create"}, "shell"},
	{[]string{"exec"}, "dev"},
	{[]string{"cp"}, "dev:/tmp/file"},
	{[]string{"get"}, "dev"},
	{[]string{"start"}, "dev"},
	{[]string{"stop"}, "dev"},
	{[]string{"rm"}, "dev"},
	{[]string{"wait"}, "op-1"},
	{[]string{"ports"}, "dev"},
	{[]string{"agents", "ls"}, "arg"},
	{[]string{"secret", "import"}, "github"},
	{[]string{"secret", "ls"}, "arg"},
	{[]string{"secret", "set"}, "github"},
	{[]string{"secret", "rm"}, "github"},
	{[]string{"settings", "ls"}, "arg"},
	{[]string{"settings", "get"}, "dns.upstream"},
	{[]string{"settings", "set"}, "dns.upstream"},
	{[]string{"settings", "unset"}, "dns.upstream"},
	{[]string{"policy", "ls"}, "dev"},
	{[]string{"policy", "inspect"}, "rule-1"},
	{[]string{"policy", "log"}, "dev"},
	{[]string{"policy", "allow"}, "dev"},
	{[]string{"policy", "deny"}, "dev"},
	{[]string{"policy", "rm"}, "dev"},
	{[]string{"policy", "check"}, "dev"},
	{[]string{"policy", "check", "network"}, "192.0.2.1"},
	{[]string{"policy", "check", "filesystem"}, "/workspace"},
	{[]string{"policy", "init"}, "deny-all"},
	{[]string{"policy", "profile"}, "ls"},
	{[]string{"kit", "inspect"}, "spec.yaml"},
	{[]string{"kit", "ls"}, "dir"},
	{[]string{"daemon", "status"}, "arg"},
	{[]string{"template", "ls"}, "arg"},
	{[]string{"template", "inspect"}, "shell"},
	{[]string{"env", "plan"}, "sbxenv.yaml"},
	{[]string{"env", "create"}, "sbxenv.yaml"},
	{[]string{"env", "run"}, "sbxenv.yaml"},
	{[]string{"env", "rm"}, "sbxenv.yaml"},
	{[]string{"mcp", "ls"}, "arg"},
	{[]string{"mcp", "add"}, "server"},
	{[]string{"mcp", "call"}, "sandbox"},
	{[]string{"mcp", "rm"}, "server"},
}

func TestHelpFlagAfterPositionalMatchesBefore(t *testing.T) {
	for _, probe := range positionalHelpProbes {
		name := strings.Join(probe.path, " ")
		t.Run(name, func(t *testing.T) {
			before := append(append([]string(nil), probe.path...), helpFlag, probe.positional)
			after := append(append([]string(nil), probe.path...), probe.positional, helpFlag)
			beforeCode, beforeOut, beforeErr := runCommandForOutput(t, before)
			afterCode, afterOut, afterErr := runCommandForOutput(t, after)
			if beforeCode != 0 || afterCode != 0 {
				t.Fatalf("before=%v exit=%d after=%v exit=%d", before, beforeCode, after, afterCode)
			}
			if beforeErr != "" || afterErr != "" {
				t.Fatalf("before stderr=%q after stderr=%q", beforeErr, afterErr)
			}
			if beforeOut == "" || beforeOut != afterOut {
				t.Fatalf("help differs by flag position:\nbefore=%q\nafter=%q", beforeOut, afterOut)
			}
		})
	}
}

func TestInterspersedOptionsParseLikeLeadingOptions(t *testing.T) {
	t.Run("exec", func(t *testing.T) {
		beforeExecutor := &recordingExecutor{}
		beforeRunner, _, _ := runTestRunner(t, recordingExecClient{executor: beforeExecutor}, "")
		if code := beforeRunner.Run(context.Background(), []string{"exec", "--env", "A=1", "--workdir", "/tmp", "dev", "true"}); code != 0 {
			t.Fatalf("before exit=%d", code)
		}
		afterExecutor := &recordingExecutor{}
		afterRunner, _, _ := runTestRunner(t, recordingExecClient{executor: afterExecutor}, "")
		if code := afterRunner.Run(context.Background(), []string{"exec", "dev", "true", "--env", "A=1", "--workdir", "/tmp"}); code != 0 {
			t.Fatalf("after exit=%d", code)
		}
		if !reflect.DeepEqual(beforeExecutor.request, afterExecutor.request) {
			t.Fatalf("exec request differs: before=%+v after=%+v", beforeExecutor.request, afterExecutor.request)
		}
	})

	settingsFile := filepath.Join(t.TempDir(), "settings.toml")
	t.Setenv("RHEIC_SETTINGS_FILE", settingsFile)

	kitDir := t.TempDir()
	kitPath := filepath.Join(kitDir, "spec.yaml")
	kitSpec := "schemaVersion: 2\nkind: sandbox\nname: cli-inspect\nsandbox: {image: ubuntu:latest}\n"
	if err := os.WriteFile(kitPath, []byte(kitSpec), 0o600); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(t.TempDir(), "sbxenv.yaml")
	envSpec := "schemaVersion: \"1\"\nname: interspersed\nagent: shell\nworkspace: .\n"
	if err := os.WriteFile(envPath, []byte(envSpec), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		client sdk.Client
		before []string
		after  []string
	}{
		{
			name:   "ports",
			client: runClient{sandboxes: &runSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}},
			before: []string{"ports", "--format", "json", "dev"},
			after:  []string{"ports", "dev", "--format", "json"},
		},
		{
			name:   "policy ls",
			client: runClient{sandboxes: &runSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}},
			before: []string{"policy", "ls", "--format", "json", "dev"},
			after:  []string{"policy", "ls", "dev", "--format", "json"},
		},
		{
			name: "policy check network",
			client: runClient{sandboxes: &runSandbox{items: []sdk.Sandbox{{
				ID: "sb-1", Name: "dev",
				Allow: []sdk.NetworkRule{{Protocol: tcpProtocol, CIDR: "192.0.2.0/24", Port: 443}},
			}}}},
			before: []string{"policy", "check", "network", "--sandbox", "dev", "192.0.2.1:443"},
			after:  []string{"policy", "check", "network", "192.0.2.1:443", "--sandbox", "dev"},
		},
		{
			name:   "policy allow network",
			client: runClient{sandboxes: &runSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}},
			before: []string{"policy", "allow", "network", "--sandbox", "dev", "1.2.3.4/32"},
			after:  []string{"policy", "allow", "network", "1.2.3.4/32", "--sandbox", "dev"},
		},
		{
			name:   "settings get",
			before: []string{"settings", "get", "--format", "json", "dns.upstream"},
			after:  []string{"settings", "get", "dns.upstream", "--format", "json"},
		},
		{
			name:   "template inspect",
			before: []string{"template", "inspect", "--json", "shell"},
			after:  []string{"template", "inspect", "shell", "--json"},
		},
		{
			name:   "agents",
			before: []string{"agents", "--format", "json", "ls"},
			after:  []string{"agents", "ls", "--format", "json"},
		},
		{
			name:   "kit inspect",
			before: []string{"kit", "inspect", "--format", "json", kitPath},
			after:  []string{"kit", "inspect", kitPath, "--format", "json"},
		},
		{
			name:   "env plan",
			before: []string{"env", "plan", "--name", "interspersed", envPath},
			after:  []string{"env", "plan", envPath, "--name", "interspersed"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforeCode, beforeOut, beforeErr := runProbe(t, tt.client, tt.before)
			afterCode, afterOut, afterErr := runProbe(t, tt.client, tt.after)
			if beforeCode != afterCode {
				t.Fatalf("exit differs: before=%d after=%d", beforeCode, afterCode)
			}
			if beforeOut != afterOut || beforeErr != afterErr {
				t.Fatalf("output differs:\nbefore stdout=%q stderr=%q\nafter stdout=%q stderr=%q", beforeOut, beforeErr, afterOut, afterErr)
			}
			if beforeOut == "" && beforeErr == "" {
				t.Fatalf("probe produced no output")
			}
		})
	}
}

func runCommandForOutput(t *testing.T, args []string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	runner := &Runner{Out: &stdout, Err: &stderr, In: strings.NewReader("")}
	code := runner.Run(context.Background(), args)
	return code, stdout.String(), stderr.String()
}

func runProbe(t *testing.T, client sdk.Client, args []string) (int, string, string) {
	t.Helper()
	if client == nil {
		return runCommandForOutput(t, args)
	}
	runner, stdout, stderr := runTestRunner(t, client, "")
	code := runner.Run(context.Background(), args)
	return code, stdout.String(), stderr.String()
}
