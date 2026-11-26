package command

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

func runSecretParityCommand(t *testing.T, client sdk.Client, input string, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	runner := &Runner{
		Out: &out, Err: &out, In: strings.NewReader(input), Socket: "unused",
		NewClient: func(string) (sdk.Client, error) { return client, nil },
	}
	code := runner.Run(context.Background(), args)
	return code, out.String()
}

func TestRegistrySecretSetRequiresForceInEveryScope(t *testing.T) {
	scopes := []struct {
		name      string
		extraArgs []string
		scope     sdk.RegistryCredentialScope
		sandbox   string
		label     string
	}{
		{name: "host-only", scope: sdk.RegistryScopeHostOnly, label: "(host only)"},
		{name: "all-sandboxes", extraArgs: []string{"--all-sandboxes"}, scope: sdk.RegistryScopeAllSandboxes, label: "(all sandboxes)"},
		{name: "sandbox", extraArgs: []string{"--sandbox", "dev"}, scope: sdk.RegistryScopeSandbox, sandbox: "dev", label: "(sandbox dev)"},
	}
	for _, test := range scopes {
		t.Run(test.name+"/new", func(t *testing.T) {
			registry := &fakeRegistryCredentials{}
			args := []string{"secret", "set", "--registry", "ghcr.io", "--username", "alice", "--password-stdin"}
			args = append(args, test.extraArgs...)
			code, output := runSecretParityCommand(t, fakeClient{registry: registry}, "synthetic-token\n", args...)
			if code != 0 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			if registry.loginCalls != 1 || registry.request.Scope != test.scope || registry.request.SandboxName != test.sandbox {
				t.Fatalf("login calls=%d request=%+v want scope=%q sandbox=%q", registry.loginCalls, registry.request, test.scope, test.sandbox)
			}
		})

		t.Run(test.name+"/duplicate without force", func(t *testing.T) {
			registry := &fakeRegistryCredentials{items: []sdk.RegistryCredentialSummary{{
				Registry: "ghcr.io", Scope: string(test.scope), SandboxName: test.sandbox,
			}}}
			args := []string{"secret", "set", "--registry", "ghcr.io", "--username", "alice", "--password-stdin"}
			args = append(args, test.extraArgs...)
			code, output := runSecretParityCommand(t, fakeClient{registry: registry}, "replacement-token\n", args...)
			if code != 1 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			want := "error: registry secret already exists for \"ghcr.io\" in scope \"" + test.label + "\"; pass --force to overwrite\n"
			if output != want {
				t.Fatalf("output=%q want=%q", output, want)
			}
			if strings.Count(output, "\n") != 1 {
				t.Fatalf("duplicate refusal must print one line: %q", output)
			}
			if registry.loginCalls != 0 {
				t.Fatalf("duplicate without --force reached Login")
			}
		})

		t.Run(test.name+"/duplicate with force", func(t *testing.T) {
			registry := &fakeRegistryCredentials{items: []sdk.RegistryCredentialSummary{{
				Registry: "ghcr.io", Scope: string(test.scope), SandboxName: test.sandbox,
			}}}
			args := []string{"secret", "set", "--registry", "ghcr.io", "--username", "alice", "--password-stdin", "--force"}
			args = append(args, test.extraArgs...)
			code, output := runSecretParityCommand(t, fakeClient{registry: registry}, "replacement-token\n", args...)
			if code != 0 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			if registry.loginCalls != 1 || registry.request.Scope != test.scope || registry.request.SandboxName != test.sandbox {
				t.Fatalf("login calls=%d request=%+v want scope=%q sandbox=%q", registry.loginCalls, registry.request, test.scope, test.sandbox)
			}
			if !strings.Contains(output, "Credentials stored") {
				t.Fatalf("missing success output: %q", output)
			}
		})
	}
}

func TestServiceSecretSetRequiresForceInEveryScope(t *testing.T) {
	scopes := []struct {
		name      string
		extraArgs []string
		scope     sdk.SecretScope
		sandbox   string
		label     string
	}{
		{name: "global", scope: sdk.SecretScopeGlobal, label: "(global)"},
		{name: "sandbox", extraArgs: []string{"--sandbox", "dev"}, scope: sdk.SecretScopeSandbox, sandbox: "dev", label: "dev"},
	}
	for _, test := range scopes {
		t.Run(test.name+"/new", func(t *testing.T) {
			secrets := &fakeServiceSecrets{}
			args := []string{"secret", "set", "openai", "--token", "new-token"}
			args = append(args, test.extraArgs...)
			code, output := runSecretParityCommand(t, fakeClient{secrets: secrets}, "", args...)
			if code != 0 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			if secrets.createCalls != 1 || secrets.setCalls != 0 || secrets.scope != test.scope || secrets.name != test.sandbox {
				t.Fatalf("create=%d set=%d scope=%q sandbox=%q", secrets.createCalls, secrets.setCalls, secrets.scope, secrets.name)
			}
		})

		t.Run(test.name+"/duplicate without force", func(t *testing.T) {
			secrets := &fakeServiceSecrets{items: []sdk.ServiceSecret{{
				Service: "openai", Scope: test.scope, SandboxName: test.sandbox,
			}}}
			args := []string{"secret", "set", "openai", "--token", "replacement-token"}
			args = append(args, test.extraArgs...)
			code, output := runSecretParityCommand(t, fakeClient{secrets: secrets}, "", args...)
			if code != 1 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			want := "error: service secret already exists for \"openai\" in scope \"" + test.label + "\"; pass --force to overwrite\n"
			if output != want {
				t.Fatalf("output=%q want=%q", output, want)
			}
			if secrets.setCalls != 0 || secrets.value != nil {
				t.Fatalf("duplicate was overwritten without --force: set=%d value=%q", secrets.setCalls, secrets.value)
			}
		})

		t.Run(test.name+"/duplicate with force", func(t *testing.T) {
			secrets := &fakeServiceSecrets{items: []sdk.ServiceSecret{{
				Service: "openai", Scope: test.scope, SandboxName: test.sandbox,
			}}}
			args := []string{"secret", "set", "openai", "--token", "replacement-token", "--force"}
			args = append(args, test.extraArgs...)
			code, output := runSecretParityCommand(t, fakeClient{secrets: secrets}, "", args...)
			if code != 0 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			if secrets.setCalls != 1 || secrets.createCalls != 0 || string(secrets.value) != "replacement-token" {
				t.Fatalf("--force did not overwrite: set=%d create=%d value=%q", secrets.setCalls, secrets.createCalls, secrets.value)
			}
			if strings.Contains(output, "replacement-token") {
				t.Fatalf("output disclosed the secret: %q", output)
			}
		})
	}
}

func TestRegistrySecretRemovalPrintsOneLineForRemovedScope(t *testing.T) {
	registry := &fakeRegistryCredentials{items: []sdk.RegistryCredentialSummary{{
		Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly),
	}}}
	code, output := runSecretParityCommand(t, fakeClient{registry: registry}, "", "secret", "rm", "--registry", "ghcr.io", "--force")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	want := "Removed registry credentials for ghcr.io (host-only)\n"
	if output != want {
		t.Fatalf("output=%q want=%q", output, want)
	}
	if len(registry.requests) != 2 || registry.requests[0].Scope != sdk.RegistryScopeHostOnly {
		t.Fatalf("requests=%+v", registry.requests)
	}
}

func TestRegistrySecretRemovalAbsentSucceedsWithOneLine(t *testing.T) {
	tests := []struct {
		name      string
		extraArgs []string
		items     []sdk.RegistryCredentialSummary
		want      string
	}{
		{
			name: "default scopes",
			want: "No registry credentials stored for \"ghcr.io\"\n",
		},
		{
			name:      "all-sandboxes only",
			extraArgs: []string{"--all-sandboxes"},
			items:     []sdk.RegistryCredentialSummary{{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly)}},
			want:      "No registry credentials stored for \"ghcr.io\" (all-sandboxes)\n",
		},
		{
			name:      "sandbox only",
			extraArgs: []string{"--sandbox", "dev"},
			items:     []sdk.RegistryCredentialSummary{{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly)}},
			want:      "No registry credentials stored for \"ghcr.io\" (sandbox dev)\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := &fakeRegistryCredentials{items: test.items}
			args := []string{"secret", "rm", "--registry", "ghcr.io"}
			args = append(args, test.extraArgs...)
			code, output := runSecretParityCommand(t, fakeClient{registry: registry}, "", args...)
			if code != 0 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			if output != test.want {
				t.Fatalf("output=%q want=%q", output, test.want)
			}
			if strings.Count(output, "\n") != 1 {
				t.Fatalf("absent removal must print one line: %q", output)
			}
			if len(registry.requests) != 0 {
				t.Fatalf("absent removal attempted Logout: %+v", registry.requests)
			}
		})
	}
}

func TestRegistrySecretRemovalKeepsRealFailuresAtExitOne(t *testing.T) {
	registry := &fakeRegistryCredentials{
		items:     []sdk.RegistryCredentialSummary{{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly)}},
		logoutErr: errors.New("synthetic logout failure"),
	}
	code, output := runSecretParityCommand(t, fakeClient{registry: registry}, "", "secret", "rm", "--registry", "ghcr.io", "--force")
	if code != 1 {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	if !strings.Contains(output, "synthetic logout failure") {
		t.Fatalf("missing failure detail: %q", output)
	}
}

func TestServiceSecretRemovalAbsentSucceedsWithOneLine(t *testing.T) {
	code, output := runSecretParityCommand(t, fakeClient{secrets: &fakeServiceSecrets{}}, "", "secret", "rm", "github", "--sandbox", "dev", "--force")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	want := "No service credentials stored for \"github\" in scope \"dev\"\n"
	if output != want {
		t.Fatalf("output=%q want=%q", output, want)
	}
	if strings.Count(output, "\n") != 1 {
		t.Fatalf("absent removal must print one line: %q", output)
	}
}
