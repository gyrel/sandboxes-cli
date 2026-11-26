package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

func TestEvaluatePolicy(t *testing.T) {
	ip := net.ParseIP("10.2.3.4")
	allow := []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}}
	deny := []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.2.0.0/16", Port: 443}}
	if allowed, reason := evaluatePolicy(allow, nil, "tcp", ip, 443); !allowed || !strings.Contains(reason, "allow") {
		t.Fatalf("allow=%v reason=%s", allowed, reason)
	}
	if allowed, reason := evaluatePolicy(allow, deny, "tcp", ip, 443); allowed || !strings.Contains(reason, "deny") {
		t.Fatalf("deny precedence=%v reason=%s", allowed, reason)
	}
	if allowed, _ := evaluatePolicy(allow, nil, "tcp", ip, 80); allowed {
		t.Fatal("port mismatch allowed")
	}
	anyPort := []sdk.NetworkRule{{Protocol: "udp", CIDR: "10.0.0.0/8"}}
	if allowed, _ := evaluatePolicy(anyPort, nil, "udp", ip, 53); !allowed {
		t.Fatal("port zero did not match")
	}
	if allowed, reason := evaluatePolicy(nil, nil, "tcp", ip, 443); allowed || reason != "default deny" {
		t.Fatalf("default=%v %s", allowed, reason)
	}
	emptyProtocol := []sdk.NetworkRule{{CIDR: "10.0.0.0/8", Port: 443}}
	if allowed, _ := evaluatePolicy(emptyProtocol, nil, "tcp", ip, 443); !allowed {
		t.Fatal("empty protocol must default to tcp")
	}
	if allowed, _ := evaluatePolicy(emptyProtocol, nil, "udp", ip, 443); allowed {
		t.Fatal("empty protocol incorrectly matched udp")
	}
}

func TestParsePolicyDestinationAcceptsSingleAddress(t *testing.T) {
	if _, err := parsePolicyDestination("10.0.0.0/8"); err == nil {
		t.Fatal("CIDR destination accepted")
	}
	ip, err := parsePolicyDestination("2001:db8::1")
	if err != nil || ip.To4() != nil {
		t.Fatalf("IPv6 destination = %v, %v", ip, err)
	}
}

func TestPolicyListAndCheck(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Allow: []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}},
		Deny:  []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.9.0.0/16", Port: 443}},
	}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "ls", "dev"}); code != 0 {
		t.Fatalf("ls exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "sandbox:dev") || !strings.Contains(out.String(), "network: 1 allow, 1 deny") {
		t.Fatalf("ls output=%q", out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "ls", "--json", "dev"}); code != 0 {
		t.Fatalf("json exit=%d output=%q", code, out.String())
	}
	var list policyListOutput
	if err := json.Unmarshal(out.Bytes(), &list); err != nil || len(list.Rules) != 2 || list.Rules[0].Decision != "allow" {
		t.Fatalf("rules=%+v err=%v", list, err)
	}
	if list.Rules[0].Scope != "sandbox:dev" || list.Rules[0].AppliesTo != "sandbox:dev" || list.Rules[0].SandboxID != "dev" {
		t.Fatalf("scoped rule shape=%+v", list.Rules[0])
	}
	if list.Rules[0].PolicyID != "local-policy" || list.Rules[0].ResourceType != "network" {
		t.Fatalf("rule identity shape=%+v", list.Rules[0])
	}
	if len(list.Rules[0].Resources) != 1 || list.Rules[0].Resources[0] != "10.0.0.0/8:443" {
		t.Fatalf("rule resources=%+v", list.Rules[0].Resources)
	}
	if len(list.Rules[0].Actions) != 1 || list.Rules[0].Actions[0] != "net:connect:tcp" {
		t.Fatalf("rule actions=%+v", list.Rules[0].Actions)
	}
	if list.Rules[0].Provenance.CreatedVia != "added" || list.Rules[0].Origin != "scoped" {
		t.Fatalf("rule provenance=%+v origin=%q", list.Rules[0].Provenance, list.Rules[0].Origin)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "check", "dev", "10.1.2.3", "443"}); code != 0 {
		t.Fatalf("allowed check exit=%d output=%q", code, out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "check", "dev", "10.9.1.2", "443"}); code != 1 {
		t.Fatalf("denied check exit=%d output=%q", code, out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "allow", "dev", "10.0.0.0/8"}); code != 1 {
		t.Fatalf("dynamic policy exit=%d output=%q", code, out.String())
	}
}

type policyUpdateClient struct {
	fakeClient
	base        *lifecycleSandbox
	allow, deny []sdk.NetworkRule
	profile     string
}

func (p *policyUpdateClient) PolicyService() sdk.PolicyService { return p }

func (p *policyUpdateClient) GetPolicyProfile(context.Context) (string, error) {
	if p.profile == "" {
		return "deny-all", nil
	}
	return p.profile, nil
}

func (p *policyUpdateClient) SetPolicyProfile(_ context.Context, profile string) (string, error) {
	p.profile = profile
	return profile, nil
}

func (p *policyUpdateClient) UpdatePolicy(_ context.Context, id string, allow, deny []sdk.NetworkRule) (*sdk.Sandbox, error) {
	_ = id
	p.allow = append([]sdk.NetworkRule(nil), allow...)
	p.deny = append([]sdk.NetworkRule(nil), deny...)
	if p.base != nil && len(p.base.items) > 0 {
		p.base.items[0].Allow = p.allow
		p.base.items[0].Deny = p.deny
	}
	return &sdk.Sandbox{ID: "sb-1", Name: "dev", Allow: allow, Deny: deny}, nil
}

func (p *policyUpdateClient) Check(ctx context.Context, id, protocol, address, domain string, port uint16, url, method string) (sdk.PolicyDecision, error) {
	return fakePolicyCheck{sandboxes: p.fakeClient.sandbox}.Check(ctx, id, protocol, address, domain, port, url, method)
}

func (p *policyUpdateClient) GetGlobalPolicy(context.Context) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	return nil, nil, nil
}

func (p *policyUpdateClient) MutateGlobalPolicy(context.Context, string, sdk.NetworkRule) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	return nil, nil, nil
}

func (p *policyUpdateClient) Refresh(context.Context) (int, error) { return 0, nil }

func (p *policyUpdateClient) ResetGlobal(context.Context) ([]sdk.NetworkRule, []sdk.NetworkRule, string, error) {
	return nil, nil, "deny-all", nil
}

func (p *policyUpdateClient) MutatePolicy(ctx context.Context, id, action string, rule sdk.NetworkRule) (*sdk.Sandbox, error) {
	allow := append([]sdk.NetworkRule(nil), p.base.items[0].Allow...)
	deny := append([]sdk.NetworkRule(nil), p.base.items[0].Deny...)
	switch action {
	case "allow":
		allow = append(allow, rule)
	case "deny":
		deny = append(deny, rule)
	case "rm":
		if !containsRuleForFake(allow, rule) && !containsRuleForFake(deny, rule) {
			return nil, errors.New("policy rule not found")
		}
		allow = slices.DeleteFunc(allow, func(r sdk.NetworkRule) bool { return sameRuleForFake(r, rule) })
		deny = slices.DeleteFunc(deny, func(r sdk.NetworkRule) bool { return sameRuleForFake(r, rule) })
	}
	return p.UpdatePolicy(ctx, id, allow, deny)
}

func TestPolicyDynamicUpdates(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Allow: []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}},
	}}}
	client := &policyUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "allow", "dev", "0.0.0.0/0:80"}); code != 0 {
		t.Fatalf("allow exit=%d output=%q", code, out.String())
	}
	if len(client.allow) != 2 || client.allow[1].Port != 80 {
		t.Fatalf("allow=%+v", client.allow)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "deny", "dev", "10.9.0.0/16:443"}); code != 0 {
		t.Fatalf("deny exit=%d output=%q", code, out.String())
	}
	if len(client.deny) != 1 {
		t.Fatalf("deny=%+v", client.deny)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "rm", "dev", "10.0.0.0/8:443"}); code != 0 {
		t.Fatalf("rm exit=%d output=%q", code, out.String())
	}
	if len(client.allow) != 1 || client.allow[0].Port != 80 {
		t.Fatalf("allow after rm=%+v", client.allow)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "rm", "dev", "192.0.2.0/24"}); code != 1 {
		t.Fatalf("missing rm exit=%d output=%q", code, out.String())
	}
}

func TestPolicyInitAndProfile(t *testing.T) {
	client := &policyUpdateClient{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "init", "balanced"}); code != 0 {
		t.Fatalf("init exit=%d output=%q", code, out.String())
	}
	if client.profile != "balanced" {
		t.Fatalf("profile=%q", client.profile)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "profile"}); code != 0 {
		t.Fatalf("profile exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "global: balanced") {
		t.Fatalf("output=%q", out.String())
	}
	if code := runner.Run(context.Background(), []string{"policy", "init", "unknown"}); code != 2 {
		t.Fatalf("unknown init exit=%d", code)
	}
}

func TestFilesystemPolicyOutputAndCheck(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Workspaces: []sdk.Workspace{
			{Path: "/work"},
			{Path: "/readonly", ReadOnly: true},
		},
	}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "ls", "dev", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var list policyListOutput
	if err := json.Unmarshal(out.Bytes(), &list); err != nil || len(list.Rules) != 4 {
		t.Fatalf("rules=%+v err=%v", list, err)
	}
	if list.Rules[0].ResourceType != "filesystem:read" || list.Rules[0].Decision != "allow" || list.Rules[0].Resources[0] != "/work" {
		t.Fatalf("first rule=%+v", list.Rules[0])
	}
	if list.Rules[0].Editable || list.Rules[0].Provenance.CreatedVia != "provisioned" {
		t.Fatalf("filesystem rule must not be editable: %+v", list.Rules[0])
	}
	if list.Rules[3].ResourceType != "filesystem:write" || list.Rules[3].Decision != "deny" {
		t.Fatalf("read-only workspace rule=%+v", list.Rules[3])
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"policy", "check", "filesystem", "--sandbox", "dev", "/work/a"}, 0, "workspace /work (read)"},
		{[]string{"policy", "check", "filesystem", "--sandbox", "dev", "--write", "/work/a"}, 0, "read-write"},
		{[]string{"policy", "check", "filesystem", "--sandbox", "dev", "--write", "/readonly/a"}, 1, "read-only"},
		{[]string{"policy", "check", "filesystem", "--sandbox", "dev", "/outside"}, 1, "outside"},
	} {
		out.Reset()
		if code := runner.Run(context.Background(), tc.args); code != tc.code || !strings.Contains(out.String(), tc.want) {
			t.Fatalf("%v exit=%d output=%q want %q", tc.args, code, out.String(), tc.want)
		}
	}
}

func TestFilesystemCheckUsesMostSpecificWorkspace(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Workspaces: []sdk.Workspace{{Path: "/work"}, {Path: "/work/protected", ReadOnly: true}},
	}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"policy", "check", "filesystem", "--sandbox", "dev", "--write", "/work/protected/file"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "/work/protected") || !strings.Contains(out.String(), "read-only") {
		t.Fatalf("output=%q", out.String())
	}
}

type fakePolicyCheck struct{ sandboxes sdk.SandboxService }

func (f fakePolicyCheck) UpdatePolicy(context.Context, string, []sdk.NetworkRule, []sdk.NetworkRule) (*sdk.Sandbox, error) {
	return nil, errors.New("not implemented")
}
func (f fakePolicyCheck) MutatePolicy(context.Context, string, string, sdk.NetworkRule) (*sdk.Sandbox, error) {
	return nil, errors.New("not implemented")
}
func (f fakePolicyCheck) GetPolicyProfile(context.Context) (string, error)             { return "", nil }
func (f fakePolicyCheck) SetPolicyProfile(_ context.Context, p string) (string, error) { return p, nil }
func (f fakePolicyCheck) GetGlobalPolicy(context.Context) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	return nil, nil, nil
}
func (f fakePolicyCheck) Refresh(context.Context) (int, error) { return 0, nil }

func (f fakePolicyCheck) ResetGlobal(context.Context) ([]sdk.NetworkRule, []sdk.NetworkRule, string, error) {
	return nil, nil, "deny-all", nil
}

func (f fakePolicyCheck) MutateGlobalPolicy(context.Context, string, sdk.NetworkRule) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	return nil, nil, &sdk.Error{Code: "unsupported", Message: "global policy is not supported by this client"}
}
func (f fakePolicyCheck) Check(ctx context.Context, id, protocol, address, domain string, port uint16, url, method string) (sdk.PolicyDecision, error) {
	if id == "" {
		return sdk.PolicyDecision{Allowed: false, Reason: "default deny"}, nil
	}
	page, err := f.sandboxes.List(ctx, sdk.ListOptions{})
	if err != nil {
		return sdk.PolicyDecision{}, err
	}
	for i := range page.Items {
		item := &page.Items[i]
		if id != "" && item.ID != id && item.Name != id {
			continue
		}
		if domain != "" {
			return sdk.PolicyDecision{Allowed: false, Reason: reasonDefaultDeny}, nil
		}
		ip := net.ParseIP(address)
		if ip == nil {
			return sdk.PolicyDecision{}, errors.New("invalid address")
		}
		allowed, reason := evaluatePolicy(item.Allow, item.Deny, protocol, ip, port)
		return sdk.PolicyDecision{Allowed: allowed, Reason: reason}, nil
	}
	return sdk.PolicyDecision{Allowed: false, Reason: "default deny"}, nil
}

func (f fakeClient) PolicyService() sdk.PolicyService { return fakePolicyCheck{sandboxes: f.sandbox} }

type policyCheckNetworkCall struct {
	ID       string
	Protocol string
	Address  string
	Domain   string
	Port     uint16

	URL    string
	Method string
}

// policyCheckNetworkRecorder reuses the fake policy client and records the
// arguments the CLI sends to the SDK.
type policyCheckNetworkRecorder struct {
	decision sdk.PolicyDecision
	err      error
	calls    []policyCheckNetworkCall
}

func (p *policyCheckNetworkRecorder) Check(_ context.Context, id, protocol, address, domain string, port uint16, url, method string) (sdk.PolicyDecision, error) {
	p.calls = append(p.calls, policyCheckNetworkCall{ID: id, Protocol: protocol, Address: address, Domain: domain, Port: port, URL: url, Method: method})
	return p.decision, p.err
}

type policyCheckNetworkService struct {
	fakePolicyCheck
	recorder *policyCheckNetworkRecorder
}

func (s policyCheckNetworkService) Check(ctx context.Context, id, protocol, address, domain string, port uint16, url, method string) (sdk.PolicyDecision, error) {
	return s.recorder.Check(ctx, id, protocol, address, domain, port, url, method)
}

type policyCheckNetworkClient struct {
	fakeClient
	recorder *policyCheckNetworkRecorder
}

func (c policyCheckNetworkClient) PolicyService() sdk.PolicyService {
	return policyCheckNetworkService{recorder: c.recorder, fakePolicyCheck: fakePolicyCheck{sandboxes: c.sandbox}}
}

func newPolicyCheckNetworkRunner(t *testing.T, decision sdk.PolicyDecision) (*Runner, *bytes.Buffer, *policyCheckNetworkRecorder) {
	t.Helper()
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}
	recorder := &policyCheckNetworkRecorder{decision: decision}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) {
		return policyCheckNetworkClient{fakeClient: fakeClient{sandbox: sandbox}, recorder: recorder}, nil
	}}
	return runner, &out, recorder
}

func TestPolicyCheckNetworkProtocolAndPortDefaults(t *testing.T) {
	cases := []struct {
		args     []string
		id       string
		protocol string
		address  string
		domain   string
		port     uint16
		url      string
		method   string
	}{
		{[]string{"192.0.2.1"}, "", "tcp", "192.0.2.1", "", 443, "", ""},
		{[]string{"192.0.2.1:8443"}, "", "tcp", "192.0.2.1", "", 8443, "", ""},
		{[]string{"http://192.0.2.1/path"}, "", "tcp", "", "", 0, "http://192.0.2.1/path", ""},
		{[]string{"https://192.0.2.1/path"}, "", "tcp", "", "", 0, "https://192.0.2.1/path", ""},
		{[]string{"https://api.example.com/v1", "--method", "get"}, "", "tcp", "", "", 0, "https://api.example.com/v1", "get"},
		{[]string{"example.com"}, "", "tcp", "", "example.com", 443, "", ""},
		{[]string{"example.com:8443"}, "", "tcp", "", "example.com", 8443, "", ""},
		{[]string{"--protocol", "udp", "192.0.2.1"}, "", "udp", "192.0.2.1", "", 443, "", ""},
		{[]string{"192.0.2.1", "--protocol", "udp"}, "", "udp", "192.0.2.1", "", 443, "", ""},
		{[]string{"--sandbox", "dev", "192.0.2.1", "--protocol", "udp"}, "sb-1", "udp", "192.0.2.1", "", 443, "", ""},
	}
	for _, tc := range cases {
		runner, out, recorder := newPolicyCheckNetworkRunner(t, sdk.PolicyDecision{Allowed: true, RuleID: "rul_net", Reason: "allow rule 192.0.2.0/24"})
		if code := runner.Run(context.Background(), append([]string{"policy", "check", "network"}, tc.args...)); code != 0 {
			t.Fatalf("%v: exit=%d output=%q", tc.args, code, out.String())
		}
		if len(recorder.calls) != 1 {
			t.Fatalf("%v: calls=%+v", tc.args, recorder.calls)
		}
		call := recorder.calls[0]
		if call.ID != tc.id || call.Protocol != tc.protocol || call.Address != tc.address || call.Domain != tc.domain || call.Port != tc.port || call.URL != tc.url || call.Method != tc.method {
			t.Fatalf("%v: call=%+v want id=%q protocol=%q address=%q domain=%q port=%d url=%q method=%q", tc.args, call, tc.id, tc.protocol, tc.address, tc.domain, tc.port, tc.url, tc.method)
		}
	}
}

func TestPolicyCheckNetworkOutputFormats(t *testing.T) {
	allowed := sdk.PolicyDecision{Allowed: true, RuleID: "rul_net", Reason: "allow rule 192.0.2.0/24"}
	runner, out, _ := newPolicyCheckNetworkRunner(t, allowed)
	if code := runner.Run(context.Background(), []string{"policy", "check", "network", "--format", "table", "192.0.2.1"}); code != 0 {
		t.Fatalf("table exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "Allowed:") || !strings.Contains(out.String(), "192.0.2.1:443") {
		t.Fatalf("table output=%q", out.String())
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "check", "network", "--json", "192.0.2.1"}); code != 0 {
		t.Fatalf("json exit=%d output=%q", code, out.String())
	}
	var entry policyCheckNetworkOutput
	if err := json.Unmarshal(out.Bytes(), &entry); err != nil {
		t.Fatalf("json output=%q: %v", out.String(), err)
	}
	if !entry.Allowed || entry.Governance.Active || entry.Target != "192.0.2.1:443" {
		t.Fatalf("json entry=%+v", entry)
	}
	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("json output=%q: %v", out.String(), err)
	}
	if governance, ok := raw["governance"].(map[string]any); !ok || governance["active"] != false {
		t.Fatalf("governance = %v, want {active:false}", raw["governance"])
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "check", "network", "--format", "yaml", "192.0.2.1"}); code != 0 {
		t.Fatalf("yaml exit=%d output=%q", code, out.String())
	}
	for _, want := range []string{"allowed: true", "active: false", "target: 192.0.2.1:443"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("yaml output=%q missing %q", out.String(), want)
		}
	}

	denied := sdk.PolicyDecision{Allowed: false, Reason: reasonDefaultDeny}
	runner, out, _ = newPolicyCheckNetworkRunner(t, denied)
	if code := runner.Run(context.Background(), []string{"policy", "check", "network", "--json", "192.0.2.1"}); code != 1 {
		t.Fatalf("denied exit=%d output=%q", code, out.String())
	}
	entry = policyCheckNetworkOutput{}
	if err := json.Unmarshal(out.Bytes(), &entry); err != nil {
		t.Fatalf("denied json output=%q: %v", out.String(), err)
	}
	if entry.Allowed || entry.Governance.Active {
		t.Fatalf("denied entry=%+v", entry)
	}
	if strings.Contains(out.String(), "rule_id") || strings.Contains(out.String(), "reason") {
		t.Fatalf("verdict must match sbx and omit internal metadata: %q", out.String())
	}
}

func TestPolicyCheckNetworkOutputFields(t *testing.T) {
	decision := sdk.PolicyDecision{Allowed: true, RuleID: "rul_net", Reason: "allow rule 192.0.2.0/24"}
	cases := []struct {
		name          string
		args          []string
		action        string
		context       string
		resourceValue string
		target        string
	}{
		{
			name:          "global IPv4",
			args:          []string{"policy", "check", "network", "--json", "192.0.2.1"},
			action:        "net:connect:tcp",
			context:       "global",
			resourceValue: "192.0.2.1:443",
		},
		{
			name:          "scoped domain with UDP",
			args:          []string{"policy", "check", "network", "--sandbox", "dev", "--protocol", "udp", "--json", "example.com:8443"},
			action:        "net:connect:udp",
			context:       "sandbox:dev",
			resourceValue: "example.com:8443",
		},
		{
			name:          "global IPv6 normalized",
			args:          []string{"policy", "check", "network", "--json", "2001:db8::1"},
			action:        "net:connect:tcp",
			context:       "global",
			resourceValue: "2001:db8::1:443",
			target:        "[2001:db8::1]:443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, out, _ := newPolicyCheckNetworkRunner(t, decision)
			if code := runner.Run(context.Background(), tc.args); code != 0 {
				t.Fatalf("exit=%d output=%q", code, out.String())
			}
			var raw map[string]any
			if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
				t.Fatalf("json output=%q: %v", out.String(), err)
			}
			target := tc.target
			if target == "" {
				target = tc.resourceValue
			}
			for field, want := range map[string]string{
				"action":         tc.action,
				"context":        tc.context,
				"resource_type":  "net:domain",
				"resource_value": tc.resourceValue,
				"target":         target,
				"type":           "network",
			} {
				if got, ok := raw[field].(string); !ok || got != want {
					t.Fatalf("%s = %v, want %q", field, raw[field], want)
				}
			}
			if allowed, ok := raw["allowed"].(bool); !ok || !allowed {
				t.Fatalf("allowed = %v", raw["allowed"])
			}
			governance, ok := raw["governance"].(map[string]any)
			if !ok || governance["active"] != false {
				t.Fatalf("governance = %v, want {active:false}", raw["governance"])
			}
			for _, field := range []string{"rule_id", "reason", "deny_kind"} {
				if _, ok := raw[field]; ok {
					t.Fatalf("unexpected %q in verdict: %v", field, raw)
				}
			}
		})
	}
}

func TestPolicyCheckNetworkVerdictOmitsInternalMetadata(t *testing.T) {
	runner, out, _ := newPolicyCheckNetworkRunner(t, sdk.PolicyDecision{Allowed: true, RuleID: "rul_net", Reason: "allow rule"})
	if code := runner.Run(context.Background(), []string{"policy", "check", "network", "--sandbox", "dev", "--json", "example.com"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("json output=%q: %v", out.String(), err)
	}
	for _, field := range []string{"rule_id", "reason", "deny_kind"} {
		if _, ok := raw[field]; ok {
			t.Fatalf("unexpected %q in verdict: %v", field, raw)
		}
	}
	if raw["context"] != "sandbox:dev" {
		t.Fatalf("context = %v, want sandbox:dev", raw["context"])
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "check", "network", "--sandbox", "dev", "--format", "yaml", "example.com"}); code != 0 {
		t.Fatalf("yaml exit=%d output=%q", code, out.String())
	}
	for _, field := range []string{"rule_id:", "reason:", "deny_kind:"} {
		if strings.Contains(out.String(), field) {
			t.Fatalf("unexpected %q in YAML output: %q", field, out.String())
		}
	}
	if !strings.Contains(out.String(), "context: sandbox:dev") {
		t.Fatalf("yaml output=%q missing scoped context", out.String())
	}
}

func TestPolicyCheckNetworkFlagErrors(t *testing.T) {
	runner, out, recorder := newPolicyCheckNetworkRunner(t, sdk.PolicyDecision{Allowed: true, Reason: "allow"})
	cases := []struct {
		args     []string
		code     int
		contains string
	}{
		{[]string{"policy", "check", "network", "--protocol", "sctp", "192.0.2.1"}, 2, "protocol must be tcp or udp"},
		{[]string{"policy", "check", "network", "--format", "xml", "192.0.2.1"}, 2, "invalid format"},
		{[]string{"policy", "check", "network", "--json", "--format", "yaml", "192.0.2.1"}, 2, "cannot be combined"},
		{[]string{"policy", "check", "network"}, 2, "usage: rsbx policy check network"},
		{[]string{"policy", "check", "network", "--sandbox"}, 2, "flag needs an argument"},
	}
	for _, tc := range cases {
		out.Reset()
		if code := runner.Run(context.Background(), tc.args); code != tc.code || !strings.Contains(out.String(), tc.contains) {
			t.Fatalf("%v: exit=%d output=%q want %d/%q", tc.args, code, out.String(), tc.code, tc.contains)
		}
	}
	if len(recorder.calls) != 0 {
		t.Fatalf("flag errors reached the SDK: %+v", recorder.calls)
	}
}

func TestPolicyCheckNetworkOtherSchemeExplicitPort(t *testing.T) {
	address, domain, port, err := parsePolicyCheckNetworkTarget("ssh://example.invalid:22/path")
	if err != nil || address != "" || domain != "example.invalid" || port != 22 {
		t.Fatalf("target: %q %q %d %v", address, domain, port, err)
	}
	if _, _, _, err := parsePolicyCheckNetworkTarget("ssh://example.invalid/path"); err == nil {
		t.Fatal("accepted scheme with no default or explicit port")
	}
}

// sameRuleForFake mirrors the daemon's canonical selector identity so the
// fake behaves like the production delete path for conditioned rules.
func sameRuleForFake(a, b sdk.NetworkRule) bool {
	return canonicalMethodsKey(a.Methods) == canonicalMethodsKey(b.Methods) &&
		a.Path == b.Path && canonicalQueryKey(a.Query) == canonicalQueryKey(b.Query) &&
		a.Protocol == b.Protocol && a.CIDR == b.CIDR && a.Domain == b.Domain && a.Port == b.Port
}

func containsRuleForFake(rules []sdk.NetworkRule, rule sdk.NetworkRule) bool {
	for i := range rules {
		if sameRuleForFake(rules[i], rule) {
			return true
		}
	}
	return false
}
