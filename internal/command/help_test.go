package command

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestHelpDoesNotReturnEmptyUsage(t *testing.T) {
	for _, args := range [][]string{
		{"--help"},
		{"create", "--help"},
		{"create", "-h"},
		{"prune", "--help"},
		{"rm", "--help"},
		{"completion", "--help"},
		{"daemon", "--help"},
		{"daemon", "log-level", "--help"},
		{"setup", "--help"},
	} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("")}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v exit=%d output=%q", args, code, out.String())
		}
		if strings.TrimSpace(out.String()) == "" {
			t.Fatalf("%v produced empty help", args)
		}
		sections := []string{"Usage:"}
		if args[0] != "--help" {
			sections = append(sections, "Description:", "Flags:")
		}
		for _, section := range sections {
			if !strings.Contains(out.String(), section) {
				t.Fatalf("%v output lacks %q: %q", args, section, out.String())
			}
		}
	}
}

func TestHelpSubcommandPrintsCommandUsage(t *testing.T) {
	tests := []struct {
		command string
		want    string
	}{
		{command: "run", want: "  rsbx run"},
		{command: "rm", want: "  rsbx rm"},
		{command: "ls", want: "  rsbx ls"},
		{command: "stop", want: "  rsbx stop"},
		{command: "version", want: "  rsbx version"},
		{command: "policy", want: "  rsbx policy"},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			var out bytes.Buffer
			runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("")}
			if code := runner.Run(context.Background(), []string{"help", tt.command}); code != 0 {
				t.Fatalf("exit=%d output=%q", code, out.String())
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Fatalf("help %s output=%q", tt.command, out.String())
			}
		})
	}
}

func TestHelpWithoutCommandPrintsTopLevelUsage(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("")}
	if code := runner.Run(context.Background(), []string{"help"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out.String(), "Sandbox Commands:") || !strings.Contains(out.String(), "--socket PATH") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestRootHelpListsCommandsAndSocket(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"--help"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	for _, want := range []string{"Sandbox Commands:", "run", "create", "--socket"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help missing %q: %q", want, out.String())
		}
	}
}

func TestCommandHelpUsesReferenceLayout(t *testing.T) {
	tests := []struct {
		args []string
		flag string
	}{
		{[]string{"run"}, "-t, --template string"},
		{[]string{"attach"}, "--shell"},
		{[]string{"create"}, "--idempotency-key string"},
		{[]string{"exec"}, "-i, --interactive"},
		{[]string{"exec"}, "--privileged"},
		{[]string{"exec"}, "--detach-keys string"},
		{[]string{"cp"}, "-L, --follow-link"},
		{[]string{"ls"}, "--limit int"},
		{[]string{"stop"}, "--grace duration"},
		{[]string{"rm"}, "-f, --force"},
		{[]string{"prune"}, "--dry-run"},
		{[]string{"ports"}, "--unpublish stringArray"},
		{[]string{"daemon"}, "log-level"},
		{[]string{"daemon", "start"}, "-d, --detach"},
		{[]string{"daemon", "stop"}, "-h, --help"},
		{[]string{"daemon", "restart"}, "--policy string"},
		{[]string{"daemon", "log-level"}, "-h, --help"},
		{[]string{"daemon", "status"}, "--json"},
		{[]string{"diagnose"}, "--format string"},
		{[]string{"env"}, "create"},
		{[]string{"env", "plan"}, "--env-arg stringArray"},
		{[]string{"env", "create"}, "-f, --force"},
		{[]string{"env", "exec"}, "--name string"},
		{[]string{"env", "exec"}, "--privileged"},
		{[]string{"env", "exec"}, "--detach-keys string"},
		{[]string{"env", "exec"}, "--env-arg stringArray"},
		{[]string{"env", "exec"}, "--env-args-file stringArray"},
		{[]string{"env", "run"}, "-d, --detach"},
		{[]string{"env", "rm"}, "--env-args-file stringArray"},
		{[]string{"login"}, "--password-stdin"},
		{[]string{"logout"}, "-f, --force"},
		{[]string{"mcp"}, "add"},
		{[]string{"mcp", "ls"}, "--quiet"},
		{[]string{"mcp", "add"}, "--secret-header stringArray"},
		{[]string{"mcp", "call"}, "--args string"},
		{[]string{"mcp", "rm"}, "--force"},
		{[]string{"policy"}, "check"},
		{[]string{"policy", "ls"}, "--format string"},
		{[]string{"policy", "inspect"}, "--json"},
		{[]string{"policy", "log"}, "--limit int"},
		{[]string{"policy", "refresh"}, "-h, --help"},
		{[]string{"policy", "reset"}, "-f, --force"},
		{[]string{"policy", "approval"}, "-h, --help"},
		{[]string{"policy", "allow"}, "network"},
		{[]string{"policy", "deny", "network"}, "--sandbox string"},
		{[]string{"policy", "rm"}, "-h, --help"},
		{[]string{"policy", "check"}, "-h, --help"},
		{[]string{"policy", "check", "network"}, "--protocol string"},
		{[]string{"policy", "check", "filesystem"}, "--write"},
		{[]string{"policy", "init"}, "-h, --help"},
		{[]string{"policy", "profile"}, "-h, --help"},
		{[]string{"policy", "org"}, "--format string"},
		{[]string{"reset"}, "--format string"},
		{[]string{"secret"}, "set-custom"},
		{[]string{"secret", "set"}, "--ref string"},
		{[]string{"secret", "rm"}, "--all"},
		{[]string{"secret", "ls"}, "--service string"},
		{[]string{"secret", "import"}, "--dry-run"},
		{[]string{"secret", "set-custom"}, "-h, --help"},
		{[]string{"settings"}, "unset"},
		{[]string{"settings", "ls"}, "--format string"},
		{[]string{"settings", "get"}, "--json"},
		{[]string{"settings", "set"}, "-h, --help"},
		{[]string{"settings", "unset"}, "-h, --help"},
		{[]string{"template"}, "inspect"},
		{[]string{"template", "ls"}, "--json"},
		{[]string{"template", "inspect"}, "--json"},
		{[]string{"kit"}, "inspect"},
		{[]string{"kit", "inspect"}, "--format string"},
		{[]string{"kit", "ls"}, "-h, --help"},
		{[]string{"tui"}, "--refresh duration"},
		{[]string{"setup"}, "--json"},
		{[]string{"skills"}, "import"},
		{[]string{"skills", "ls"}, "-q, --quiet"},
		{[]string{"skills", "import"}, "-f, --force"},
		{[]string{"skills", "rm"}, "--force"},
		{[]string{"completion"}, "powershell"},
		{[]string{"version"}, "--format string"},
	}
	for _, tt := range tests {
		name := strings.Join(tt.args, " ")
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("")}
			args := append(append([]string(nil), tt.args...), "--help")
			if code := runner.Run(context.Background(), args); code != 0 {
				t.Fatalf("%v: exit=%d output=%q", args, code, out.String())
			}
			for _, want := range []string{"Description:", "Usage:", "Flags:", "Global Flags:", "--socket PATH", tt.flag} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("%v help lacks %q: %q", args, want, out.String())
				}
			}
		})
	}
}

func TestCommandHelpAliasSections(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"ls"}, "Aliases:\n  ls, list"},
		{[]string{"rm"}, "Aliases:\n  rm, remove, delete"},
		{[]string{"secret"}, "Aliases:\n  secret, secrets"},
		{[]string{"secret", "ls"}, "Aliases:\n  ls, list"},
		{[]string{"secret", "rm"}, "Aliases:\n  rm, remove, delete, unset"},
	}
	for _, tt := range tests {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("")}
		args := append(append([]string(nil), tt.args...), "--help")
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v: exit=%d output=%q", args, code, out.String())
		}
		if !strings.Contains(out.String(), tt.want) {
			t.Fatalf("%v help lacks %q: %q", args, tt.want, out.String())
		}
	}
}
