package command

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

type secretListClient struct {
	fakeClient
	items []sdk.RegistryCredentialSummary
}

func (s secretListClient) ListRegistryCredentials(context.Context) ([]sdk.RegistryCredentialSummary, error) {
	return s.items, nil
}

func runSecretList(t *testing.T, client sdk.Client, args ...string) (string, int) {
	t.Helper()
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	code := runner.Run(context.Background(), append([]string{"secret", "ls"}, args...))
	return out.String(), code
}

func TestSecretListMachineOutput(t *testing.T) {
	client := secretListClient{
		fakeClient: fakeClient{secrets: &fakeServiceSecrets{items: []sdk.ServiceSecret{
			{Service: "github", Scope: sdk.SecretScopeSandbox, SandboxName: "dev"},
			{Service: "openai", Scope: sdk.SecretScopeGlobal},
		}}},
		items: []sdk.RegistryCredentialSummary{
			{Registry: "ghcr.io", Username: "alice", Scope: string(sdk.RegistryScopeSandbox), SandboxName: "dev"},
			{Registry: "quay.io", Scope: string(sdk.RegistryScopeHostOnly)},
		},
	}
	output, code := runSecretList(t, client, "--json")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	var list secretListOutput
	if err := json.Unmarshal([]byte(output), &list); err != nil {
		t.Fatalf("decode output=%q err=%v", output, err)
	}
	if len(list.Secrets) != 4 {
		t.Fatalf("secrets=%+v", list.Secrets)
	}
	want := []secretListItem{
		{Scope: "dev", Type: "service", Name: "github", Secret: storedSecretDisplay},
		{Scope: "global", Type: "service", Name: "openai", Secret: storedSecretDisplay},
		{Scope: "dev", Type: "registry", Name: "ghcr.io", Username: "alice", Secret: storedSecretDisplay},
		{Scope: "host-only", Type: "registry", Name: "quay.io", Secret: storedSecretDisplay},
	}
	for index, item := range want {
		if list.Secrets[index] != item {
			t.Errorf("item %d=%+v, want %+v", index, list.Secrets[index], item)
		}
	}
	if list.CustomSecrets != nil || list.ShadowedServices != nil || list.EnvOnlyCount != nil {
		t.Fatalf("unsourced metadata=%+v", list)
	}
}

func TestSecretListMachineOutputEmpty(t *testing.T) {
	for _, format := range []string{"json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			output, code := runSecretList(t, secretListClient{fakeClient: fakeClient{secrets: &fakeServiceSecrets{}}}, "--format", format)
			if code != 0 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			var list secretListOutput
			var err error
			if format == "json" {
				err = json.Unmarshal([]byte(output), &list)
			} else {
				err = yaml.Unmarshal([]byte(output), &list)
			}
			if err != nil {
				t.Fatalf("decode output=%q err=%v", output, err)
			}
			if len(list.Secrets) != 0 || list.CustomSecrets != nil || list.ShadowedServices != nil || list.EnvOnlyCount != nil {
				t.Fatalf("empty output=%+v", list)
			}
			for _, key := range []string{"secrets", "custom_secrets", "shadowed_services", "env_only_count"} {
				value := "null"
				if key == "secrets" {
					value = "[]"
				}
				want := key + ": " + value
				if format == "json" {
					want = `"` + key + `": ` + value
				}
				if !strings.Contains(output, want) {
					t.Errorf("output lacks empty %s list: %q", key, output)
				}
			}
		})
	}
}

func TestSecretListFiltersAndQuietOutput(t *testing.T) {
	client := secretListClient{
		fakeClient: fakeClient{secrets: &fakeServiceSecrets{items: []sdk.ServiceSecret{
			{Service: "openai", Scope: sdk.SecretScopeGlobal},
			{Service: "github", Scope: sdk.SecretScopeSandbox, SandboxName: "dev"},
		}}},
		items: []sdk.RegistryCredentialSummary{
			{Registry: "ghcr.io", Scope: string(sdk.RegistryScopeHostOnly)},
			{Registry: "quay.io", Scope: string(sdk.RegistryScopeSandbox), SandboxName: "dev"},
		},
	}
	output, code := runSecretList(t, client, "-q", "--service", "openai", "-g")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	if output != "openai\n" {
		t.Fatalf("quiet filtered output=%q, want only global openai", output)
	}

	output, code = runSecretList(t, client, "--json", "--service", "openai")
	if code != 0 {
		t.Fatalf("filtered exit=%d output=%q", code, output)
	}
	var filtered map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &filtered); err != nil || len(filtered) != 1 || filtered["secrets"] == nil {
		t.Fatalf("filtered output=%q fields=%v err=%v", output, filtered, err)
	}

	output, code = runSecretList(t, client, "--sandbox", "dev", "--json")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	var sandboxList secretListOutput
	if err := json.Unmarshal([]byte(output), &sandboxList); err != nil || len(sandboxList.Secrets) != 2 {
		t.Fatalf("sandbox filtered list=%+v err=%v output=%s", sandboxList, err, output)
	}
	for _, item := range sandboxList.Secrets {
		if item.Scope != "dev" {
			t.Errorf("sandbox item scope=%q, want dev", item.Scope)
		}
	}
	if sandboxList.Secrets[0].Name != "github" || sandboxList.Secrets[1].Name != "quay.io" {
		t.Errorf("sandbox filtered names=%+v", sandboxList.Secrets)
	}

	output, code = runSecretList(t, client, "--json", "-g")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	var globalList secretListOutput
	if err := json.Unmarshal([]byte(output), &globalList); err != nil || len(globalList.Secrets) != 2 {
		t.Fatalf("global filtered list=%+v err=%v output=%s", globalList, err, output)
	}
	if globalList.Secrets[0].Name != "openai" || globalList.Secrets[1].Name != "ghcr.io" {
		t.Errorf("global filtered names=%+v", globalList.Secrets)
	}

	output, code = runSecretList(t, client)
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	for _, expected := range []string{"TYPE", "SERVICE", "USERNAME", "SCOPE", "SANDBOX", "SECRET", "openai", "github", "ghcr.io", "quay.io"} {
		if !strings.Contains(output, expected) {
			t.Errorf("table output lacks %q: %q", expected, output)
		}
	}
	if strings.Contains(output, `"secrets"`) {
		t.Errorf("table output unexpectedly contains machine JSON: %q", output)
	}
}

func TestSecretListMachineOutputDoesNotExposeSecretValues(t *testing.T) {
	const syntheticValue = "synthetic-secret-value-do-not-print"
	client := secretListClient{
		fakeClient: fakeClient{secrets: &fakeServiceSecrets{
			value: []byte(syntheticValue),
			items: []sdk.ServiceSecret{{Service: "github", Scope: sdk.SecretScopeSandbox, SandboxName: "dev"}},
		}},
		items: []sdk.RegistryCredentialSummary{
			{Registry: "ghcr.io", Username: "alice", Scope: string(sdk.RegistryScopeSandbox), SandboxName: "dev"},
		},
	}
	for _, args := range [][]string{{"--json"}, {"--format", "yaml"}} {
		output, code := runSecretList(t, client, args...)
		if code != 0 {
			t.Fatalf("args=%v exit=%d output=%q", args, code, output)
		}
		if strings.Contains(output, syntheticValue) {
			t.Fatalf("args=%v output exposed a secret value: %q", args, output)
		}
		for _, forbidden := range []string{"password", "token", `"value"`, "value:"} {
			if strings.Contains(output, forbidden) {
				t.Errorf("args=%v output contains %q: %q", args, forbidden, output)
			}
		}
	}

	output, code := runSecretList(t, client, "--json")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, output)
	}
	var raw struct {
		Secrets []map[string]json.RawMessage `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		t.Fatalf("decode output=%q err=%v", output, err)
	}
	if len(raw.Secrets) != 2 {
		t.Fatalf("secrets=%+v", raw.Secrets)
	}
	allowed := map[string]bool{"scope": true, "type": true, "name": true, "secret": true, "username": true}
	for index, item := range raw.Secrets {
		for key := range item {
			if !allowed[key] {
				t.Errorf("item %d has unexpected field %q", index, key)
			}
		}
		if string(item["secret"]) != `"(stored)"` {
			t.Errorf("item %d secret=%s, want fixed placeholder", index, item["secret"])
		}
	}
	if _, ok := raw.Secrets[0]["username"]; ok {
		t.Errorf("service item unexpectedly has username: %+v", raw.Secrets[0])
	}
	if _, ok := raw.Secrets[1]["username"]; !ok {
		t.Errorf("registry item lacks username: %+v", raw.Secrets[1])
	}
}

func TestSecretListAlias(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
		return secretListClient{fakeClient: fakeClient{secrets: &fakeServiceSecrets{}}}, nil
	}}
	if code := runner.Run(context.Background(), []string{"secret", "list"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("No secrets stored")) {
		t.Fatalf("output=%q", out.String())
	}
}

func TestSecretListRejectsUnsupportedInventory(t *testing.T) {
	for _, client := range []sdk.Client{
		secretListClient{},
	} {
		output, code := runSecretList(t, client, "--json")
		if code == 0 || !strings.Contains(output, "not supported") {
			t.Fatalf("client=%T exit=%d output=%q", client, code, output)
		}
		if strings.Contains(output, `"secrets"`) {
			t.Fatalf("unsupported inventory rendered as complete: %q", output)
		}
	}
}
