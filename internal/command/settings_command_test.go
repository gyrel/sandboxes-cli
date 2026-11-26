package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

func runSettings(t *testing.T, envPath string, args ...string) (*bytes.Buffer, int) {
	t.Helper()
	out, errOut, code := runSettingsSplit(t, envPath, args...)
	out.Write(errOut.Bytes())
	return out, code
}

func runSettingsSplit(t *testing.T, envPath string, args ...string) (*bytes.Buffer, *bytes.Buffer, int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL validation is not implemented; Load remains fail closed")
	}
	var out, errOut bytes.Buffer
	runner := &Runner{Out: &out, Err: &errOut, Socket: filepath.Join(t.TempDir(), "sandboxesd.sock"),
		NewClient: func(string) (sdk.Client, error) { return nil, errors.New("settings does not need a daemon") }}
	t.Setenv("GYREL_SETTINGS_FILE", envPath)
	return &out, &errOut, runner.Run(context.Background(), append([]string{"settings"}, args...))
}

func TestSettingsListsFullCatalogWithDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	out, code := runSettings(t, path, "ls", "--json")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var rows []settingOutput
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("json: %v output=%q", err, out.String())
	}
	if len(rows) != 54 {
		t.Fatalf("rows=%d, want 54", len(rows))
	}
	byKey := map[string]settingOutput{}
	for _, row := range rows {
		byKey[row.Key] = row
	}
	if row := byKey["proxy.daemon"]; row.Source != "default" || row.Value != "" || !row.RequiresRestart {
		t.Fatalf("proxy.daemon row = %+v", row)
	}
	if row := byKey["kit.requireSignature"]; row.Type != "bool" || row.Default != false || row.Value != false {
		t.Fatalf("kit.requireSignature row = %+v", row)
	}
	if row := byKey["daemon.log.maxBackups"]; row.Value != float64(3) || row.Default != float64(3) {
		t.Fatalf("daemon.log.maxBackups typed values = %+v", row)
	}
	if row := byKey["sandbox.disk.dockerVolume"]; row.Default != "10g" {
		t.Fatalf("docker volume row = %+v", row)
	}
	if row := byKey["mcp.remote.allowedHosts"]; !row.RequiresRestart || row.Source != "default" {
		t.Fatalf("remote MCP host allowlist row = %+v", row)
	}
	if row := byKey["clipboard.imagePaste"]; row.EnvVar != "DOCKER_SANDBOXES_CLIPBOARD_IMAGE_PASTE" {
		t.Fatalf("clipboard env var row = %+v", row)
	}
	if row := byKey["browser.enabled"]; row.EnvVar != "" {
		t.Fatalf("browser.enabled must not invent an env var: %+v", row)
	}
	var rawRows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rawRows); err != nil {
		t.Fatalf("json: %v", err)
	}
	rawByKey := map[string]map[string]any{}
	for _, row := range rawRows {
		key, _ := row["key"].(string)
		rawByKey[key] = row
	}
	if _, ok := rawByKey["browser.enabled"]["requires_restart"]; ok {
		t.Fatalf("false requires_restart must be omitted: %v", rawByKey["browser.enabled"])
	}
	if restart, ok := rawByKey["proxy.daemon"]["requires_restart"].(bool); !ok || !restart {
		t.Fatalf("proxy.daemon requires_restart = %v", rawByKey["proxy.daemon"]["requires_restart"])
	}
}

func TestSettingsSetValidatesCatalogTypesAndPersistsExtras(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	out, code := runSettings(t, path, "set", "ssh.autoCreate", "true")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	out, code = runSettings(t, path, "set", "kit.allowedSources", `["registry.example/"]`)
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	out, code = runSettings(t, path, "set", "mcp.remote.allowedHosts", "mcp.example.com,api.example.com")
	if code != 0 {
		t.Fatalf("set MCP host allowlist exit=%d output=%q", code, out.String())
	}
	if _, code := runSettings(t, path, "set", "mcp.remote.allowedHosts", "*.example.com"); code == 0 {
		t.Fatal("wildcard MCP host allowlist accepted")
	}
	if _, code := runSettings(t, path, "set", "mcp.remote.allowedHosts", "127.0.0.1"); code == 0 {
		t.Fatal("IP-literal MCP host allowlist accepted")
	}
	if _, code := runSettings(t, path, "set", "ssh.autoCreate", "yes"); code == 0 {
		t.Fatal("invalid bool accepted")
	}
	if _, code := runSettings(t, path, "set", "no.such.key", "x"); code == 0 {
		t.Fatal("unknown key accepted")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test-owned settings file.
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `ssh.autoCreate = "true"`) || !strings.Contains(text, `kit.allowedSources = "[\"registry.example/\"]"`) || !strings.Contains(text, `mcp_remote_allowed_hosts = "mcp.example.com,api.example.com"`) {
		t.Fatalf("file=%q", text)
	}
	out, code = runSettings(t, path, "get", "ssh.autoCreate")
	if code != 0 || strings.TrimSpace(out.String()) != "true" {
		t.Fatalf("get exit=%d output=%q", code, out.String())
	}
	if _, code := runSettings(t, path, "unset", "ssh.autoCreate"); code != 0 {
		t.Fatalf("unset exit=%d", code)
	}
	out, code = runSettings(t, path, "get", "ssh.autoCreate", "--json")
	if code != 0 || !strings.Contains(out.String(), `"source": "default"`) || !strings.Contains(out.String(), `"value": false`) {
		t.Fatalf("get --json exit=%d output=%q", code, out.String())
	}
}

func TestSettingsMarksRestartRequiredKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	out, code := runSettings(t, path, "set", "proxy.daemon", "http://proxy.example:3128")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "restart gyreld to apply proxy.daemon") {
		t.Fatalf("restart notice missing: %q", out.String())
	}
	if !strings.Contains(out.String(), "note: proxy.daemon takes effect after the daemon restarts") {
		t.Fatalf("restart stderr note missing: %q", out.String())
	}
}

func TestSettingsSetRestartKeyPrintsStderrNote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	out, errOut, code := runSettingsSplit(t, path, "set", "daemon.log.maxSizeMB", "100")
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	want := "note: daemon.log.maxSizeMB takes effect after the daemon restarts"
	if !strings.Contains(errOut.String(), want) {
		t.Fatalf("stderr note missing: %q", errOut.String())
	}
	if strings.Contains(out.String(), "note:") {
		t.Fatalf("restart note must go to stderr only: %q", out.String())
	}
	if !strings.Contains(out.String(), "set daemon.log.maxSizeMB") {
		t.Fatalf("confirmation missing: %q", out.String())
	}
	out, code = runSettings(t, path, "get", "daemon.log.maxSizeMB")
	if code != 0 || strings.TrimSpace(out.String()) != "100" {
		t.Fatalf("get exit=%d output=%q", code, out.String())
	}
}

func TestSettingsSetNonRestartKeyPrintsNoNote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	out, errOut, code := runSettingsSplit(t, path, "set", "kit.requireSignature", "true")
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if strings.Contains(errOut.String(), "note:") {
		t.Fatalf("unexpected restart note: %q", errOut.String())
	}
	if strings.Contains(out.String(), "restart gyreld") {
		t.Fatalf("unexpected restart confirmation: %q", out.String())
	}
}

func TestSettingsSetJSONRequiresRestartField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	out, errOut, code := runSettingsSplit(t, path, "set", "daemon.log.maxSizeMB", "75", "--json")
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatalf("json: %v output=%q", err, out.String())
	}
	if restart, ok := record["requires_restart"].(bool); !ok || !restart {
		t.Fatalf("requires_restart = %v, want true", record["requires_restart"])
	}
	if value, ok := record["value"].(float64); !ok || value != 75 {
		t.Fatalf("value = %v, want 75", record["value"])
	}
	if !strings.Contains(errOut.String(), "note: daemon.log.maxSizeMB takes effect after the daemon restarts") {
		t.Fatalf("stderr note missing: %q", errOut.String())
	}

	out, errOut, code = runSettingsSplit(t, path, "set", "kit.requireSignature", "true", "--format", "json")
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	record = nil
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatalf("json: %v output=%q", err, out.String())
	}
	if _, ok := record["requires_restart"]; ok {
		t.Fatalf("false requires_restart must be omitted: %v", record)
	}
}

func TestSettingsSetNonCatalogKeyKeepsCurrentOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	out, errOut, code := runSettingsSplit(t, path, "set", "no.such.key", "x")
	if code != 2 {
		t.Fatalf("exit=%d, want 2 (stdout=%q stderr=%q)", code, out.String(), errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", out.String())
	}
	if !strings.Contains(errOut.String(), `error: unknown setting "no.such.key"`) {
		t.Fatalf("unknown setting error missing: %q", errOut.String())
	}
	if strings.Contains(errOut.String(), "note:") {
		t.Fatalf("unexpected restart note: %q", errOut.String())
	}
}
