package command

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
)

func TestCompletionCommandScripts(t *testing.T) {
	tests := []struct {
		name     string
		shell    string
		wantCode int
		wants    []string
	}{
		{
			name:     "bash",
			shell:    "bash",
			wantCode: 0,
			wants:    []string{"rsbx", "create", "setup", "completion", "--token", "-t", "--all", "-f", "--force", "--socket"},
		},
		{
			name:     "zsh",
			shell:    "zsh",
			wantCode: 0,
			wants:    []string{"rsbx", "create", "setup", "completion", "--token", "-t", "--all", "-f", "--force", "--socket"},
		},
		{
			name:     "fish",
			shell:    "fish",
			wantCode: 0,
			wants:    []string{"rsbx", "create", "setup", "completion", "-l token", "-s t", "-l all", "-s f", "-l force", "-l socket"},
		},
		{
			name:     "powershell",
			shell:    "powershell",
			wantCode: 0,
			wants:    []string{"rsbx", "create", "setup", "completion", "--token", "-t", "--all", "-f", "--force"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			runner := &Runner{Out: &out, Err: &out}
			if code := runner.Run(context.Background(), []string{"completion", test.shell}); code != test.wantCode {
				t.Fatalf("exit=%d output=%q", code, out.String())
			}
			for _, want := range test.wants {
				if !strings.Contains(out.String(), want) {
					t.Errorf("%s output lacks %q: %s", test.shell, want, out.String())
				}
			}
		})
	}
}

func TestCompletionRejectsUnknownShell(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"completion", "tcsh"}); code == 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	for _, want := range []string{"unsupported shell", "tcsh", "bash", "zsh", "fish", "powershell"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("error lacks %q: %q", want, out.String())
		}
	}
}

func TestCompletionCoversTopLevelCommandSurface(t *testing.T) {
	expected := []string{
		"agents", "attach", "completion", "cp", "create", "daemon", "diagnose", "env",
		"exec", "help", "kit", "login", "logout", "ls", "mcp", "move", "policy",
		"ports", "prune", "reset", "rm", "run", "secret", "settings", "setup", "skills",
		"stop", "template", "ttl", "tui", "version", "volume",
	}
	got := completionCommands()
	for _, name := range expected {
		if !slices.Contains(got, name) {
			t.Errorf("completion tree lacks top-level command %q", name)
		}
	}
	for _, name := range got {
		if !slices.Contains(expected, name) {
			t.Errorf("completion tree contains unexpected command %q", name)
		}
	}
}

func TestExecFlagsAreInCompletionTree(t *testing.T) {
	for _, expected := range []string{"--interactive", "-i", "--tty", "-t", "--workdir", "-w", "--env", "-e", "--env-file", "--user", "-u", "--detach", "-d", "--detach-keys", "--privileged"} {
		if !slices.Contains(completionTree[commandExec], expected) {
			t.Errorf("exec %s flag is missing from completion tree", expected)
		}
	}
	for _, expected := range []string{"--detach-keys", "--privileged"} {
		if !slices.Contains(completionTree[envCommand], expected) {
			t.Errorf("env %s flag is missing from completion tree", expected)
		}
	}
}

func TestSecretFlagsAndAliasesAreInCompletionTree(t *testing.T) {
	for _, expected := range []string{"--oauth", "--token", "-t", "--force", "-f", "--all", "--all-sandboxes", "--dry-run", "--sandbox", "--registry", "--global", "--quiet", "--service"} {
		if !slices.Contains(completionTree[secretCommand], expected) {
			t.Errorf("secret %s flag is missing from completion tree", expected)
		}
	}
	for _, expected := range []string{"import", "ls", "list", "set", "rm", "remove", "delete", "unset"} {
		if !slices.Contains(completionSubcommands[secretCommand], expected) {
			t.Errorf("secret %s command is missing from completion tree", expected)
		}
	}
}

func TestCompletionOmitsUnimplementedStubs(t *testing.T) {
	if slices.Contains(completionSubcommands[secretCommand], "set-custom") {
		t.Error("secret set-custom is not implemented and must not be suggested")
	}
	for _, name := range []string{"save", "load", "rm"} {
		if slices.Contains(completionSubcommands[templateCommand], name) {
			t.Errorf("template %s is not implemented and must not be suggested", name)
		}
	}
}

func TestCompletionOmitsUndocumentedListAliases(t *testing.T) {
	for _, command := range []string{kitCommand, settingsCommand, templateCommand} {
		if slices.Contains(completionSubcommands[command], commandList) {
			t.Errorf("%s list alias is undocumented and must not be suggested", command)
		}
	}
}

func TestCompletionListsImplementedPolicySubcommands(t *testing.T) {
	for _, expected := range []string{"filesystem", "init", "profile", "log", "refresh", "reset"} {
		if !slices.Contains(completionSubcommands[policyCommand], expected) {
			t.Errorf("policy %s subcommand is missing from completion tree", expected)
		}
	}
}

func TestSetupFlagsAreInCompletionTree(t *testing.T) {
	for _, expected := range []string{"--format", "--json", "--help", "-h"} {
		if !slices.Contains(completionTree["setup"], expected) {
			t.Errorf("setup %s flag is missing from completion tree", expected)
		}
	}
}

func TestLogoutForceFlagsAreInCompletionTree(t *testing.T) {
	for _, expected := range []string{"-f", "--force"} {
		if !slices.Contains(completionTree["logout"], expected) {
			t.Errorf("logout %s flag is missing from completion tree", expected)
		}
	}
}

func TestFishCompletionUsesShortFlagSyntax(t *testing.T) {
	script := fishCompletionScript()
	for _, expected := range []string{"-l token", "-s t", "-s f", "-s g", "-s q"} {
		if !strings.Contains(script, expected) {
			t.Errorf("fish completion lacks %q", expected)
		}
	}
	if strings.Contains(script, "-l t\n") || strings.Contains(script, "-l f\n") {
		t.Fatalf("short flag is emitted as a long flag: %s", script)
	}
}
