package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
)

// policyFilterFake serves a deterministic global and sandbox policy so list
// filters and remove selectors can be exercised without a daemon.
type policyFilterFake struct {
	policyRefreshFake
	sandbox         *lifecycleSandbox
	globalRemovals  []sdk.NetworkRule
	sandboxRemovals []sdk.NetworkRule
}

func (p *policyFilterFake) PolicyService() sdk.PolicyService { return p }

func (p *policyFilterFake) MutateGlobalPolicy(_ context.Context, action string, rule sdk.NetworkRule) ([]sdk.NetworkRule, []sdk.NetworkRule, error) {
	if action != "rm" {
		return nil, nil, errors.New("unexpected action")
	}
	p.globalRemovals = append(p.globalRemovals, rule)
	p.allow = removeNetworkRule(p.allow, rule)
	p.deny = removeNetworkRule(p.deny, rule)
	return p.allow, p.deny, nil
}

func (p *policyFilterFake) MutatePolicy(_ context.Context, id, action string, rule sdk.NetworkRule) (*sdk.Sandbox, error) {
	if action != "rm" {
		return nil, errors.New("unexpected action")
	}
	p.sandboxRemovals = append(p.sandboxRemovals, rule)
	for i := range p.sandbox.items {
		if p.sandbox.items[i].ID != id && p.sandbox.items[i].Name != id {
			continue
		}
		item := &p.sandbox.items[i]
		item.Allow = removeNetworkRule(item.Allow, rule)
		item.Deny = removeNetworkRule(item.Deny, rule)
		result := *item
		return &result, nil
	}
	return nil, errors.New("not found")
}

func removeNetworkRule(rules []sdk.NetworkRule, target sdk.NetworkRule) []sdk.NetworkRule {
	out := rules[:0]
	for i := range rules {
		if networkRuleMatches(rules[i], target) {
			continue
		}
		out = append(out, rules[i])
	}
	return out
}

func newPolicyFilterRunner(t *testing.T, fake *policyFilterFake) (*Runner, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	runner := &Runner{
		Out: &out, Err: &out, In: strings.NewReader(""), Socket: t.TempDir() + "/sandboxesd.sock",
		NewClient: func(string) (sdk.Client, error) { return fake, nil },
	}
	return runner, &out
}

func policyFilterFixture(t *testing.T) (*policyFilterFake, []policyRuleJSON) {
	t.Helper()
	allow := []sdk.NetworkRule{
		{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443, RuleID: "rul_allow_tcp"},
		{Protocol: "udp", CIDR: "192.0.2.0/24", Port: 53, RuleID: "rul_allow_udp"},
	}
	deny := []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.9.0.0/16", Port: 443, RuleID: "rul_deny_tcp"}}
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Allow:      []sdk.NetworkRule{{Protocol: "tcp", Domain: "api.example.com", Port: 8443, RuleID: "rul_sbx_domain"}},
		Workspaces: []sdk.Workspace{{Path: "/work"}, {Path: "/readonly", ReadOnly: true}},
	}}}
	fake := &policyFilterFake{sandbox: sandbox}
	fake.policyRefreshFake = policyRefreshFake{
		fakeClient: fakeClient{sandbox: sandbox},
		allow:      allow,
		deny:       deny,
	}
	return fake, policyRulesOutput(append(
		policyRulesFrom(policyGlobalScope, allow, deny),
		policyRules(&sandbox.items[0])...,
	)).Rules
}

func runPolicyFilterJSON(t *testing.T, fake *policyFilterFake, args ...string) (policyListOutput, int, string) {
	t.Helper()
	runner, out := newPolicyFilterRunner(t, fake)
	code := runner.Run(context.Background(), append(append([]string{"policy", "ls", "--json"}, args...), "dev"))
	var list policyListOutput
	if code == 0 {
		if err := json.Unmarshal(out.Bytes(), &list); err != nil {
			t.Fatalf("%v: json decode: %v output=%q", args, err, out.String())
		}
	}
	return list, code, out.String()
}

func TestPolicyListFilters(t *testing.T) {
	fake, allRules := policyFilterFixture(t)
	if len(allRules) != 8 {
		t.Fatalf("fixture rules=%d, want 8", len(allRules))
	}
	cases := []struct {
		name string
		args []string
		want int
		keep func(policyRuleJSON) bool
	}{
		{name: "type network", args: []string{"--type", "network"}, want: 4, keep: func(r policyRuleJSON) bool { return r.ResourceType == "network" }},
		{name: "type filesystem", args: []string{"--type", "filesystem"}, want: 4, keep: func(r policyRuleJSON) bool { return strings.HasPrefix(r.ResourceType, "filesystem:") }},
		{name: "source local", args: []string{"--source", "local"}, want: 8},
		{name: "source org", args: []string{"--source", "org"}, want: 0},
		{name: "source kit", args: []string{"--source", "kit"}, want: 0},
		{name: "decision deny", args: []string{"--decision", "deny"}, want: 2, keep: func(r policyRuleJSON) bool { return r.Decision == "deny" }},
		{name: "created-via provisioned", args: []string{"--created-via", "provisioned"}, want: 4},
		{name: "created-via added", args: []string{"--created-via", "added"}, want: 4},
		{name: "protocol udp", args: []string{"--protocol", "udp"}, want: 1, keep: func(r policyRuleJSON) bool { return r.ResourceType == "network" && r.Decision == "allow" }},
		{name: "protocol tcp", args: []string{"--protocol", "tcp"}, want: 3, keep: func(r policyRuleJSON) bool { return r.ResourceType == "network" }},
		{name: "network deny tcp", args: []string{"--type", "network", "--decision", "deny", "--protocol", "tcp"}, want: 1},
		{name: "filesystem allow", args: []string{"--type", "filesystem", "--decision", "allow"}, want: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list, code, output := runPolicyFilterJSON(t, fake, tc.args...)
			if code != 0 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			if len(list.Rules) != tc.want {
				t.Fatalf("rules=%d want %d: %q", len(list.Rules), tc.want, output)
			}
			if tc.keep != nil {
				for i := range list.Rules {
					if !tc.keep(list.Rules[i]) {
						t.Fatalf("rule %d does not match filter: %+v", i, list.Rules[i])
					}
				}
			}
		})
	}
}

func TestPolicyListIncludeInactiveOrgRules(t *testing.T) {
	fake, _ := policyFilterFixture(t)
	orgClient := &fakeOrgPolicyClient{response: &localv1.GetOrgPolicyResponse{
		Org: "acme", SchemaVersion: 1, Revision: 3, BundleId: "sha256:abcd", EnforcementEnabled: true,
		Rules: []*localv1.OrgPolicyRule{
			{RuleId: "rule-enforced", Action: "deny", Source: "org", ResourceType: "network",
				Protocol: "tcp", Cidr: "203.0.113.7/32", Port: 8443, Enforced: true},
			{RuleId: "rule-advisory", Action: "allow", Source: "org", ResourceType: "network",
				Domain: "api.example.test", Port: 443, AdvisoryReason: "organization allow rules are advisory"},
		},
	}}
	listOrg := func(t *testing.T, args ...string) (policyListOutput, int, string) {
		t.Helper()
		var out bytes.Buffer
		runner := &Runner{
			Out: &out, Err: &out, In: strings.NewReader(""), Socket: t.TempDir() + "/sandboxesd.sock",
			NewClient:          func(string) (sdk.Client, error) { return fake, nil },
			NewOrgPolicyClient: func(string) (orgPolicyClient, error) { return orgClient, nil },
		}
		code := runner.Run(context.Background(), append(append([]string{"policy", "ls", "--json"}, args...), "dev"))
		var list policyListOutput
		if code == 0 {
			if err := json.Unmarshal(out.Bytes(), &list); err != nil {
				t.Fatalf("%v: json decode: %v output=%q", args, err, out.String())
			}
		}
		return list, code, out.String()
	}
	statusByID := func(list policyListOutput) map[string]string {
		got := map[string]string{}
		for i := range list.Rules {
			got[list.Rules[i].ID] = list.Rules[i].Status
		}
		return got
	}

	list, code, output := listOrg(t)
	if code != 0 {
		t.Fatalf("default exit=%d output=%q", code, output)
	}
	got := statusByID(list)
	if _, ok := got["rule-advisory"]; ok {
		t.Fatalf("inactive rule shown by default: %q", output)
	}
	if got["rule-enforced"] != policyStatusActive {
		t.Fatalf("enforced org rule status=%q want active: %q", got["rule-enforced"], output)
	}

	list, code, output = listOrg(t, "--include-inactive")
	if code != 0 {
		t.Fatalf("include-inactive exit=%d output=%q", code, output)
	}
	got = statusByID(list)
	if got["rule-advisory"] != policyStatusInactive || got["rule-enforced"] != policyStatusActive {
		t.Fatalf("include-inactive statuses=%v output=%q", got, output)
	}

	list, code, output = listOrg(t, "--source", "org", "--decision", "allow")
	if code != 0 || len(list.Rules) != 0 {
		t.Fatalf("org allow filter exit=%d rules=%d output=%q", code, len(list.Rules), output)
	}

	var out bytes.Buffer
	runner := &Runner{
		Out: &out, Err: &out, In: strings.NewReader(""), Socket: t.TempDir() + "/sandboxesd.sock",
		NewClient:          func(string) (sdk.Client, error) { return fake, nil },
		NewOrgPolicyClient: func(string) (orgPolicyClient, error) { return orgClient, nil },
	}
	if code := runner.Run(context.Background(), []string{"policy", "ls", "--source", "org", "--decision", "allow"}); code != 0 {
		t.Fatalf("table exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "1 inactive rule(s) hidden by remote governance") {
		t.Fatalf("hidden-rule hint missing: %q", out.String())
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "ls", "-q", "dev"}); code != 0 || strings.Contains(out.String(), "rule-advisory") {
		t.Fatalf("quiet default exit=%d output=%q", code, out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "ls", "-q", "--include-inactive", "--decision", "allow", "dev"}); code != 0 || !strings.Contains(out.String(), "rule-advisory") {
		t.Fatalf("quiet include-inactive exit=%d output=%q", code, out.String())
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "ls", "--wide", "--include-inactive", "dev"}); code != 0 {
		t.Fatalf("wide exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "inactive") || !strings.Contains(out.String(), "api.example.test:443") {
		t.Fatalf("wide include-inactive output=%q", out.String())
	}
}

func TestPolicyListEmptyJSONIsAnArray(t *testing.T) {
	fake, _ := policyFilterFixture(t)
	list, code, output := runPolicyFilterJSON(t, fake, "--source", "org")
	if code != 0 || len(list.Rules) != 0 {
		t.Fatalf("exit=%d rules=%d output=%q", code, len(list.Rules), output)
	}
	if !strings.Contains(output, `"rules": []`) {
		t.Fatalf("empty rules must encode as []: %q", output)
	}
}

func TestPolicyListFiltersDefaultProfileRules(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "created via default",
			args: []string{"--created-via", "default"},
			want: []string{"default-allow-all", "default-fs-read-allow-all", "default-fs-write-allow-all"},
		},
		{
			name: "default network only",
			args: []string{"--type", "network", "--created-via", "default"},
			want: []string{"default-allow-all"},
		},
		{
			name: "default filesystem only",
			args: []string{"--type", "filesystem", "--created-via", "default"},
			want: []string{"default-fs-read-allow-all", "default-fs-write-allow-all"},
		},
		{
			name: "added does not match defaults",
			args: []string{"--created-via", "added"},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output, code := runPolicyListForProfile(t, policyProfileAllowAll, append(tc.args, "--json")...)
			if code != 0 {
				t.Fatalf("exit=%d output=%q", code, output)
			}
			var list policyListOutput
			if err := json.Unmarshal([]byte(output), &list); err != nil {
				t.Fatalf("decode: %v output=%q", err, output)
			}
			got := make([]string, 0, len(list.Rules))
			for i := range list.Rules {
				got = append(got, list.Rules[i].ID)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("ids=%v want %v", got, tc.want)
			}
		})
	}
}

func TestPolicyListQuietAndWideOutput(t *testing.T) {
	fake, allRules := policyFilterFixture(t)
	runner, out := newPolicyFilterRunner(t, fake)
	if code := runner.Run(context.Background(), []string{"policy", "ls", "--quiet", "dev"}); code != 0 {
		t.Fatalf("quiet exit=%d output=%q", code, out.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != len(allRules) {
		t.Fatalf("quiet lines=%d want %d: %q", len(lines), len(allRules), out.String())
	}
	for i, line := range lines {
		if line != allRules[i].ID {
			t.Fatalf("quiet line %d=%q want %q", i, line, allRules[i].ID)
		}
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "ls", "--quiet", "--type", "network", "dev"}); code != 0 {
		t.Fatalf("quiet filtered exit=%d output=%q", code, out.String())
	}
	if strings.Contains(out.String(), "POLICY") || strings.Count(out.String(), "\n") != 4 {
		t.Fatalf("quiet filtered output=%q", out.String())
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "ls", "--wide", "dev"}); code != 0 {
		t.Fatalf("wide exit=%d output=%q", code, out.String())
	}
	for _, want := range []string{"SOURCE", "CREATED VIA", "RULE_ID", "TYPE", "DECISION", "PROTOCOLS", "STATUS", "RESOURCES", "rul_allow_tcp", "10.0.0.0/8:443", "api.example.com:8443"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("wide output missing %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if code := runner.Run(context.Background(), []string{"policy", "ls", "--wide", "--json", "dev"}); code != 0 {
		t.Fatalf("wide json exit=%d output=%q", code, out.String())
	}
	var list policyListOutput
	if err := json.Unmarshal(out.Bytes(), &list); err != nil || len(list.Rules) != len(allRules) {
		t.Fatalf("wide json rules=%d err=%v output=%q", len(list.Rules), err, out.String())
	}
}

func TestPolicyListInvalidCombinations(t *testing.T) {
	fake, _ := policyFilterFixture(t)
	cases := []struct {
		name     string
		args     []string
		contains string
	}{
		{name: "quiet wide", args: []string{"--quiet", "--wide"}, contains: "cannot be combined"},
		{name: "quiet json", args: []string{"--quiet", "--json"}, contains: "cannot be combined"},
		{name: "quiet format", args: []string{"--quiet", "--format", "table"}, contains: "cannot be combined"},
		{name: "json format", args: []string{"--json", "--format", "yaml"}, contains: "cannot be combined"},
		{name: "type http", args: []string{"--type", "http"}, contains: "HTTP policy rules are not implemented"},
		{name: "type invalid", args: []string{"--type", "bogus"}, contains: "invalid type"},
		{name: "source invalid", args: []string{"--source", "bogus"}, contains: "invalid source"},
		{name: "decision invalid", args: []string{"--decision", "maybe"}, contains: "invalid decision"},
		{name: "created-via approval", args: []string{"--created-via", "approval"}, contains: "approval-gated policies are not implemented"},
		{name: "created-via invalid", args: []string{"--created-via", "bogus"}, contains: "invalid creation method"},
		{name: "protocol invalid", args: []string{"--protocol", "sctp"}, contains: "invalid protocol"},
		{name: "protocol filesystem", args: []string{"--protocol", "tcp", "--type", "filesystem"}, contains: "only compatible with --type all or --type network"},
		{name: "profile unsupported", args: []string{"--profile", "default"}, contains: "requires remote governance"},
		{name: "profile unsupported with include inactive", args: []string{"--profile", "default", "--include-inactive"}, contains: "requires remote governance"},
		{name: "format invalid", args: []string{"--format", "xml"}, contains: "invalid format"},
		{name: "too many args", args: []string{"one", "two"}, contains: "accepts at most 1 arg"},
		{name: "unknown flag", args: []string{"--bogus"}, contains: "unknown flag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, out := newPolicyFilterRunner(t, fake)
			code := runner.Run(context.Background(), append([]string{"policy", "ls"}, tc.args...))
			if code != 1 || !strings.Contains(out.String(), tc.contains) {
				t.Fatalf("exit=%d output=%q want 1/%q", code, out.String(), tc.contains)
			}
		})
	}
}

func TestPolicyRemoveNetworkByIDAndResource(t *testing.T) {
	fake, _ := policyFilterFixture(t)
	runner, out := newPolicyFilterRunner(t, fake)
	if code := runner.Run(context.Background(), []string{"policy", "rm", "network", "--id", "rul_allow_tcp", "--force"}); code != 0 {
		t.Fatalf("id exit=%d output=%q", code, out.String())
	}
	if len(fake.globalRemovals) != 1 || fake.globalRemovals[0].RuleID != "rul_allow_tcp" {
		t.Fatalf("global removals=%+v", fake.globalRemovals)
	}
	if !strings.Contains(out.String(), "Removed rule from policy local: id=rul_allow_tcp") {
		t.Fatalf("output=%q", out.String())
	}

	fake, _ = policyFilterFixture(t)
	runner, out = newPolicyFilterRunner(t, fake)
	if code := runner.Run(context.Background(), []string{"policy", "rm", "network", "--resource", "10.0.0.0/8:443,udp:192.0.2.0/24:53", "--force"}); code != 0 {
		t.Fatalf("resource exit=%d output=%q", code, out.String())
	}
	if len(fake.globalRemovals) != 2 {
		t.Fatalf("global removals=%+v", fake.globalRemovals)
	}
	if len(fake.allow) != 0 || len(fake.deny) != 1 {
		t.Fatalf("remaining allow=%+v deny=%+v", fake.allow, fake.deny)
	}

	fake, _ = policyFilterFixture(t)
	runner, out = newPolicyFilterRunner(t, fake)
	if code := runner.Run(context.Background(), []string{"policy", "rm", "network", "--sandbox", "dev", "--resource", "api.example.com:8443", "--force"}); code != 0 {
		t.Fatalf("sandbox exit=%d output=%q", code, out.String())
	}
	if len(fake.sandboxRemovals) != 1 || fake.sandboxRemovals[0].Domain != "api.example.com" {
		t.Fatalf("sandbox removals=%+v", fake.sandboxRemovals)
	}
	if !strings.Contains(out.String(), "scope: sandbox:dev") {
		t.Fatalf("output=%q", out.String())
	}

	fake, _ = policyFilterFixture(t)
	runner, out = newPolicyFilterRunner(t, fake)
	if code := runner.Run(context.Background(), []string{"policy", "rm", "network", "--sandbox", "dev", "api.example.com:8443", "--force"}); code != 0 {
		t.Fatalf("positional exit=%d output=%q", code, out.String())
	}
	if len(fake.sandboxRemovals) != 1 {
		t.Fatalf("sandbox removals=%+v", fake.sandboxRemovals)
	}
}

func TestPolicyRemoveNetworkRejectsPartialOrInvalidSelectors(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		contains   string
		wantMutate bool
	}{
		{name: "no selector", args: []string{"policy", "rm", "network"}, contains: "at least one selector"},
		{name: "id and resource", args: []string{"policy", "rm", "network", "--id", "rul_allow_tcp", "--resource", "10.0.0.0/8:443", "--force"}, contains: "cannot be combined"},
		{name: "positional plus id", args: []string{"policy", "rm", "network", "--id", "rul_allow_tcp", "10.0.0.0/8:443", "--force"}, contains: "cannot be combined"},
		{name: "unknown id", args: []string{"policy", "rm", "network", "--id", "rul_missing", "--force"}, contains: "not found"},
		{name: "unknown resource", args: []string{"policy", "rm", "network", "--resource", "203.0.113.0/24:443", "--force"}, contains: "no rule matches"},
		{name: "mixed resources are atomic", args: []string{"policy", "rm", "network", "--resource", "10.0.0.0/8:443,203.0.113.0/24:443", "--force"}, contains: "no rule matches"},
		{name: "method narrows", args: []string{"policy", "rm", "network", "--method", "GET", "--resource", "10.0.0.0/8:443", "--force"}, contains: "no rule matches"},
		{name: "path narrows", args: []string{"policy", "rm", "network", "--path", "/v1/**", "--resource", "10.0.0.0/8:443", "--force"}, contains: "no rule matches"},
		{name: "query narrows", args: []string{"policy", "rm", "network", "--query", "a=b", "--resource", "10.0.0.0/8:443", "--force"}, contains: "no rule matches"},
		{name: "id with selectors", args: []string{"policy", "rm", "network", "--id", "rul_allow_tcp", "--method", "GET", "--force"}, contains: "cannot be combined"},
		{name: "non terminal needs force", args: []string{"policy", "rm", "network", "--resource", "10.0.0.0/8:443"}, contains: "pass --force"},
		{name: "unknown flag", args: []string{"policy", "rm", "network", "--bogus"}, contains: "unknown flag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake, _ := policyFilterFixture(t)
			runner, out := newPolicyFilterRunner(t, fake)
			code := runner.Run(context.Background(), tc.args)
			if code != 1 || !strings.Contains(out.String(), tc.contains) {
				t.Fatalf("exit=%d output=%q want 1/%q", code, out.String(), tc.contains)
			}
			if len(fake.globalRemovals) != 0 || len(fake.sandboxRemovals) != 0 {
				t.Fatalf("invalid selector mutated policy: global=%+v sandbox=%+v", fake.globalRemovals, fake.sandboxRemovals)
			}
		})
	}
}
