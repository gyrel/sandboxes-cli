package command

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	sdk "github.com/rheic/sandboxes-go-sdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeOrgPolicyClient struct {
	response *localv1.GetOrgPolicyResponse
	err      error
	calls    int
}

func (f *fakeOrgPolicyClient) GetOrgPolicy(context.Context) (*localv1.GetOrgPolicyResponse, error) {
	f.calls++
	return f.response, f.err
}

func (f *fakeOrgPolicyClient) Close() error { return nil }

func orgPolicyRunner(out *bytes.Buffer, client orgPolicyClient) *Runner {
	return &Runner{
		Out: out, Err: out,
		NewOrgPolicyClient: func(string) (orgPolicyClient, error) { return client, nil },
	}
}

func TestPolicyOrgTableMarksEnforcedAndAdvisory(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	client := &fakeOrgPolicyClient{response: &localv1.GetOrgPolicyResponse{
		Org: "acme", SchemaVersion: 1, Revision: 9, BundleId: "sha256:abcd", EnforcementEnabled: true,
		LoadedAtUnix: now.Unix(), IssuedAtUnix: now.Add(-time.Hour).Unix(), ExpiresAtUnix: now.Add(time.Hour).Unix(),
		Rules: []*localv1.OrgPolicyRule{
			{RuleId: "rule-001", Action: "allow", Source: "org", ResourceType: "network",
				Domain: "api.example.test", Port: 443, AdvisoryReason: "organization allow rules are advisory"},
			{RuleId: "rule-002", Action: "deny", Source: "org", ResourceType: "network",
				Protocol: "tcp", Cidr: "203.0.113.7/32", Port: 8443, Enforced: true},
		},
	}}
	var out bytes.Buffer
	runner := orgPolicyRunner(&out, client)
	if code := runner.Run(context.Background(), []string{"policy", "org"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	rendered := out.String()
	for _, want := range []string{"org: acme", "enforcement: enabled", "sha256:abcd", "rule-001", "rule-002", "advisory", "enforced", "api.example.test", "203.0.113.7/32"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("table output missing %q:\n%s", want, rendered)
		}
	}
	if client.calls != 1 {
		t.Fatalf("org policy calls = %d", client.calls)
	}
}

func TestPolicyOrgJSONShape(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	client := &fakeOrgPolicyClient{response: &localv1.GetOrgPolicyResponse{
		Org: "acme", SchemaVersion: 1, Revision: 9, BundleId: "sha256:abcd", EnforcementEnabled: false,
		LoadedAtUnix: now.Unix(), IssuedAtUnix: now.Add(-time.Hour).Unix(), ExpiresAtUnix: now.Add(time.Hour).Unix(),
		IgnoredRules: 1,
		Rules: []*localv1.OrgPolicyRule{{
			RuleId: "rule-001", Action: "deny", Source: "org", ResourceType: "network",
			Protocol: "tcp", Cidr: "203.0.113.7/32", Port: 8443,
			AdvisoryReason: "org_policy.enforce is disabled",
		}},
	}}
	var out bytes.Buffer
	runner := orgPolicyRunner(&out, client)
	if code := runner.Run(context.Background(), []string{"policy", "org", "--format", "json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var got orgPolicyOutput
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Loaded || got.Org != "acme" || got.SchemaVersion != 1 || got.Revision != 9 || got.BundleID != "sha256:abcd" ||
		got.EnforcementEnabled || got.LoadedAt != now.Format(time.RFC3339) || got.IgnoredRules != 1 || len(got.Rules) != 1 {
		t.Fatalf("json output = %+v", got)
	}
	rule := got.Rules[0]
	if rule.RuleID != "rule-001" || rule.Action != "deny" || rule.Source != "org" || rule.Enforcement != "advisory" ||
		rule.AdvisoryReason != "org_policy.enforce is disabled" || rule.CIDR != "203.0.113.7/32" || rule.Port != 8443 {
		t.Fatalf("json rule = %+v", rule)
	}
}

func TestPolicyOrgEmptyState(t *testing.T) {
	for _, format := range []string{"table", "json"} {
		t.Run(format, func(t *testing.T) {
			var out bytes.Buffer
			runner := orgPolicyRunner(&out, &fakeOrgPolicyClient{err: status.Error(codes.NotFound, "organization policy bundle is not stored")})
			args := []string{"policy", "org"}
			if format == "json" {
				args = append(args, "--format", "json")
			}
			if code := runner.Run(context.Background(), args); code != 0 {
				t.Fatalf("exit=%d output=%q", code, out.String())
			}
			if format == "table" {
				if !strings.Contains(out.String(), "No organization policy bundle is loaded.") ||
					!strings.Contains(out.String(), "No organization rules are in effect.") {
					t.Fatalf("empty table = %q", out.String())
				}
				return
			}
			var got orgPolicyOutput
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.Loaded || got.EnforcementEnabled || got.Rules == nil || len(got.Rules) != 0 {
				t.Fatalf("empty json = %+v (rules nil=%t)", got, got.Rules == nil)
			}
		})
	}
}

func TestPolicyOrgInvalidBundleFailsClosed(t *testing.T) {
	var out bytes.Buffer
	runner := orgPolicyRunner(&out, &fakeOrgPolicyClient{err: status.Error(codes.FailedPrecondition, "organization policy bundle is invalid")})
	if code := runner.Run(context.Background(), []string{"policy", "org"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "organization policy bundle is invalid") {
		t.Fatalf("error output = %q", out.String())
	}
}

func TestPolicyListAnnotatesOrigin(t *testing.T) {
	client := &policyRefreshFake{allow: []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}}}
	orgClient := &fakeOrgPolicyClient{response: &localv1.GetOrgPolicyResponse{
		Org: "acme", SchemaVersion: 1, Revision: 9, BundleId: "sha256:abcd", EnforcementEnabled: true,
		Rules: []*localv1.OrgPolicyRule{{
			RuleId: "rule-001", Action: "deny", Source: "org", ResourceType: "network",
			Protocol: "tcp", Cidr: "203.0.113.7/32", Port: 8443, Enforced: true,
		}},
	}}
	var out bytes.Buffer
	runner := &Runner{
		Out: &out, Err: &out,
		NewClient:          func(string) (sdk.Client, error) { return client, nil },
		NewOrgPolicyClient: func(string) (orgPolicyClient, error) { return orgClient, nil },
	}
	if code := runner.Run(context.Background(), []string{"policy", "ls"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	rendered := out.String()
	for _, want := range []string{"POLICY", "SOURCE", "APPLIES TO", "SUMMARY", "local", "org", "network: 1 allow", "network: 1 deny"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("policy ls output missing %q:\n%s", want, rendered)
		}
	}
}

func TestPolicyListIgnoresMissingOrgPolicy(t *testing.T) {
	client := &policyRefreshFake{allow: []sdk.NetworkRule{{Protocol: "tcp", CIDR: "10.0.0.0/8", Port: 443}}}
	var out bytes.Buffer
	runner := &Runner{
		Out: &out, Err: &out,
		NewClient: func(string) (sdk.Client, error) { return client, nil },
		NewOrgPolicyClient: func(string) (orgPolicyClient, error) {
			return &fakeOrgPolicyClient{err: status.Error(codes.NotFound, "organization policy bundle is not stored")}, nil
		},
	}
	if code := runner.Run(context.Background(), []string{"policy", "ls"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Contains(out.String(), "203.0.113.7/32") {
		t.Fatalf("missing org bundle added rules:\n%s", out.String())
	}
}
