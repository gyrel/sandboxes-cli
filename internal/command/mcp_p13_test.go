package command

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

type fakeMCPServerManagement struct {
	loadErr, unloadErr, authStartErr error
	loaded, unloaded                 []string
	detail                           sdk.MCPServerDetail
	inspectName, inspectSandbox      string
	statuses                         []sdk.MCPServerAuthStatus
	statusName                       string
	statusAll                        bool
	removedName                      string
	removed                          bool
	startReq                         sdk.MCPAuthStartRequest
	startChallenge                   sdk.MCPAuthChallenge
}

func (f *fakeMCPServerManagement) Load(_ context.Context, name, sandbox string) error {
	f.loaded = append(f.loaded, name+"@"+sandbox)
	return f.loadErr
}

func (f *fakeMCPServerManagement) Unload(_ context.Context, name, sandbox string) error {
	f.unloaded = append(f.unloaded, name+"@"+sandbox)
	return f.unloadErr
}

func (f *fakeMCPServerManagement) Inspect(_ context.Context, name, sandbox string) (sdk.MCPServerDetail, error) {
	f.inspectName, f.inspectSandbox = name, sandbox
	return f.detail, nil
}

func (f *fakeMCPServerManagement) AuthStatus(_ context.Context, name string, all bool) ([]sdk.MCPServerAuthStatus, error) {
	f.statusName, f.statusAll = name, all
	return f.statuses, nil
}

func (f *fakeMCPServerManagement) RemoveAuth(_ context.Context, name string) (bool, error) {
	f.removedName = name
	return f.removed, nil
}

func (f *fakeMCPServerManagement) StartAuth(_ context.Context, req sdk.MCPAuthStartRequest) (sdk.MCPAuthChallenge, error) {
	f.startReq = req
	if f.authStartErr != nil {
		return sdk.MCPAuthChallenge{}, f.authStartErr
	}
	return f.startChallenge, nil
}

func runMCPP13(t *testing.T, mgmt *fakeMCPServerManagement, args ...string) (int, string, string) {
	t.Helper()
	var out, stderr strings.Builder
	runner := &Runner{Out: &out, Err: &stderr, In: strings.NewReader(""),
		NewClient: func(string) (sdk.Client, error) { return fakeClient{mcpManagement: mgmt}, nil }}
	code := runner.Run(context.Background(), append([]string{"mcp"}, args...))
	return code, out.String(), stderr.String()
}

func TestMCPP13LoadUnloadGrammarAndResults(t *testing.T) {
	t.Run("load requires sandbox", func(t *testing.T) {
		mgmt := &fakeMCPServerManagement{}
		code, _, stderr := runMCPP13(t, mgmt, "load", "notion")
		if code != 2 || !strings.Contains(stderr, "usage: rsbx mcp load") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
	})
	t.Run("load success silent", func(t *testing.T) {
		mgmt := &fakeMCPServerManagement{}
		code, out, stderr := runMCPP13(t, mgmt, "load", "notion", "--sandbox", "dev")
		if code != 0 || out != "" || stderr != "" {
			t.Fatalf("code=%d out=%q stderr=%q", code, out, stderr)
		}
		if len(mgmt.loaded) != 1 || mgmt.loaded[0] != "notion@dev" {
			t.Fatalf("loaded = %v", mgmt.loaded)
		}
	})
	t.Run("load daemon error", func(t *testing.T) {
		mgmt := &fakeMCPServerManagement{loadErr: errors.New("sandbox not running")}
		code, _, stderr := runMCPP13(t, mgmt, "load", "notion", "--sandbox", "dev")
		if code != 1 || !strings.Contains(stderr, "sandbox not running") {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
	})
	t.Run("unload grammar and idempotent success", func(t *testing.T) {
		mgmt := &fakeMCPServerManagement{}
		if code, _, _ := runMCPP13(t, mgmt, "unload", "notion", "--sandbox", "dev"); code != 0 {
			t.Fatalf("unload code=%d", code)
		}
		if len(mgmt.unloaded) != 1 || mgmt.unloaded[0] != "notion@dev" {
			t.Fatalf("unloaded = %v", mgmt.unloaded)
		}
		if code, _, stderr := runMCPP13(t, mgmt, "unload", "notion"); code != 2 || !strings.Contains(stderr, "usage: rsbx mcp unload") {
			t.Fatalf("missing sandbox: code=%d stderr=%q", code, stderr)
		}
	})
}

func TestMCPP13InspectRendering(t *testing.T) {
	mgmt := &fakeMCPServerManagement{detail: sdk.MCPServerDetail{
		Name: "notion", IdentityKind: "oauth", IdentityIssuerHost: "auth.example.com",
		AuthStatus: sdk.MCPAuthStatusReady, GatewayState: sdk.MCPGatewayStateLoaded,
	}}
	code, out, stderr := runMCPP13(t, mgmt, "inspect", "notion")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(out, "auth_status: ready") || !strings.Contains(out, "gateway_state: loaded") || !strings.Contains(out, "identity_issuer_host: auth.example.com") {
		t.Fatalf("table output = %q", out)
	}
	if strings.Contains(out, "tools_count") || strings.Contains(out, "last_sync_at") {
		t.Fatalf("zero fields rendered: %q", out)
	}
	mgmt.detail.LastSyncAt = time.Unix(1730000000, 0).UTC()
	mgmt.detail.ToolsCount = 7
	code, out, _ = runMCPP13(t, mgmt, "inspect", "notion", "--json")
	if code != 0 || !strings.Contains(out, "\"tools_count\": 7") {
		t.Fatalf("json code=%d out=%q", code, out)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("json decode: %v out=%q", err, out)
	}
}

func TestMCPP13AuthStatusAndRm(t *testing.T) {
	mgmt := &fakeMCPServerManagement{statuses: []sdk.MCPServerAuthStatus{
		{Name: "notion", Status: sdk.MCPAuthStatusExpired},
		{Name: "github", Status: sdk.MCPAuthStatusNotConfigured},
	}}
	code, out, stderr := runMCPP13(t, mgmt, "auth", "status", "--all")
	if code != 0 || !strings.Contains(out, "notion") || !strings.Contains(out, "expired") || stderr != "" {
		t.Fatalf("code=%d out=%q stderr=%q", code, out, stderr)
	}
	if !mgmt.statusAll {
		t.Fatal("--all not forwarded")
	}
	if code, _, stderr := runMCPP13(t, mgmt, "auth", "status", "notion", "--all"); code != 2 || !strings.Contains(stderr, "usage: rsbx mcp auth status") {
		t.Fatalf("all+name must be refused: code=%d stderr=%q", code, stderr)
	}
	mgmt.removed = true
	if code, _, _ := runMCPP13(t, mgmt, "auth", "rm", "notion", "--force"); code != 0 || mgmt.removedName != "notion" {
		t.Fatalf("auth rm code=%d removedName=%q", code, mgmt.removedName)
	}
}

func TestMCPP13AuthStartNoFabrication(t *testing.T) {
	mgmt := &fakeMCPServerManagement{authStartErr: errors.New("interactive OAuth flow requires a trusted approval provider")}
	code, _, stderr := runMCPP13(t, mgmt, "auth", "notion")
	if code != 1 || !strings.Contains(stderr, "interactive OAuth flow") {
		t.Fatalf("fabrication check: code=%d stderr=%q", code, stderr)
	}
	mgmt2 := &fakeMCPServerManagement{startChallenge: sdk.MCPAuthChallenge{ApprovalRequired: true, ApprovalID: "ap-77"}}
	code, out, _ := runMCPP13(t, mgmt2, "auth", "notion")
	if code != 0 || !strings.Contains(out, "ap-77") {
		t.Fatalf("challenge path: code=%d out=%q", code, out)
	}
}

func TestMCPP13AddOAuthValidation(t *testing.T) {
	mgmt := &fakeMCPServerManagement{}
	if code, _, stderr := runMCPP13(t, mgmt, "add", "svc", "--url", "https://mcp.example.test", "--scope", "a", "--no-scope"); code == 0 || !strings.Contains(stderr, "scope") {
		t.Fatalf("scopes+no-scope must be refused: code=%d stderr=%q", code, stderr)
	}
}
