package command

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

func TestApplyNetworkHTTPSelectors(t *testing.T) {
	rule := sdk.NetworkRule{Protocol: "tcp", Domain: "api.example.com", Port: 443}
	sel := networkHTTPSelectors{
		methods: stringListFlag{"GET,post", "ANY"},
		path:    "/v1/**",
		queries: stringListFlag{"trace=*", "page=2"},
	}
	if err := applyNetworkHTTPSelectors(&rule, sel); err != nil {
		t.Fatal(err)
	}
	if strings.Join(rule.Methods, ",") != "GET,post,ANY" || rule.Path != "/v1/**" || len(rule.Query) != 2 {
		t.Fatalf("rule=%+v", rule)
	}
	if rule.Query[0].Name != "trace" || rule.Query[0].Value != "*" || rule.Query[1].Name != "page" {
		t.Fatalf("query=%+v", rule.Query)
	}
	bad := []networkHTTPSelectors{
		{methods: stringListFlag{"GET,,POST"}},
		{queries: stringListFlag{"novalue"}},
		{queries: stringListFlag{"=x"}},
	}
	for i, sel := range bad {
		var r sdk.NetworkRule
		if err := applyNetworkHTTPSelectors(&r, sel); err == nil {
			t.Fatalf("case %d accepted malformed selector: %+v", i, r)
		}
	}
	var plain sdk.NetworkRule
	if err := applyNetworkHTTPSelectors(&plain, networkHTTPSelectors{}); err != nil || plain.Path != "" || len(plain.Methods) != 0 {
		t.Fatalf("empty selectors must not touch the rule: %+v %v", plain, err)
	}
}

func TestNetworkRuleMatchesWithConditions(t *testing.T) {
	stored := sdk.NetworkRule{Protocol: "tcp", Domain: "api.example.com", Port: 443,
		Methods: []string{"GET", "POST"}, Path: "/v1/**",
		Query: []sdk.QueryCondition{{Name: "trace", Value: "*"}}}
	target := sdk.NetworkRule{Protocol: "tcp", Domain: "api.example.com", Port: 443,
		Methods: []string{"post", "GET"}, Path: "/v1/**",
		Query: []sdk.QueryCondition{{Name: "trace", Value: "*"}}}
	if !networkRuleMatches(stored, target) {
		t.Fatal("canonical case/order-insensitive match failed")
	}
	if networkRuleMatches(stored, sdk.NetworkRule{Protocol: "tcp", Domain: "api.example.com", Port: 443}) {
		t.Fatal("unconditioned target must not match a conditioned rule")
	}
	if networkRuleMatches(sdk.NetworkRule{Protocol: "tcp", Domain: "api.example.com", Port: 443}, target) {
		t.Fatal("a conditioned target must not remove an unconditioned rule")
	}
	if networkRuleMatches(stored, sdk.NetworkRule{Protocol: "tcp", Domain: "api.example.com", Port: 443,
		Methods: []string{"GET"}, Path: "/v1/**", Query: []sdk.QueryCondition{{Name: "trace", Value: "*"}}}) {
		t.Fatal("method subset must not match")
	}
}

func TestPolicyNetworkFlagFlowToSDK(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Allow: []sdk.NetworkRule{{Protocol: "tcp", Domain: "api.example.com", Port: 443, RuleID: "rul_a"}},
	}}}
	client := &policyUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	code := runner.Run(context.Background(), []string{
		"policy", "allow", "network", "--sandbox", "dev",
		"--method", "GET,post", "--path", "/v1/**", "--query", "trace=*",
		"api.example.com:443",
	})
	if code != 0 {
		t.Fatalf("allow network exit=%d output=%q", code, out.String())
	}
	if len(client.allow) != 2 {
		t.Fatalf("allow=%+v", client.allow)
	}
	added := client.allow[1]
	if strings.Join(added.Methods, ",") != "GET,post" || added.Path != "/v1/**" ||
		len(added.Query) != 1 || added.Query[0] != (sdk.QueryCondition{Name: "trace", Value: "*"}) {
		t.Fatalf("conditions lost on the way to the SDK: %+v", added)
	}
	// Removal with the same selectors resolves against the conditioned rule.
	out.Reset()
	code = runner.Run(context.Background(), []string{
		"policy", "rm", "network", "--sandbox", "dev",
		"--method", "post,GET", "--path", "/v1/**", "--query", "trace=*",
		"api.example.com:443", "--force",
	})
	if code != 0 {
		t.Fatalf("rm network exit=%d output=%q", code, out.String())
	}
}

func TestPolicyLSJSONCarriesHTTPConditions(t *testing.T) {
	rules := policyRulesFrom(policyGlobalScope, []sdk.NetworkRule{
		{Protocol: "tcp", Domain: "api.example.com", Port: 443, RuleID: "rul_http",
			Methods: []string{"GET"}, Path: "/v1/**", Query: []sdk.QueryCondition{{Name: "trace", Value: "*"}}},
		{Protocol: "tcp", Domain: "plain.example.com", Port: 443, RuleID: "rul_plain"},
	}, nil)
	list := policyRulesOutput(rules)
	encoded, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if !strings.Contains(text, `"methods":["GET"]`) || !strings.Contains(text, `"path":"/v1/**"`) ||
		!strings.Contains(text, `"query":[{"name":"trace","value":"*"}]`) {
		t.Fatalf("conditions missing from JSON: %s", text)
	}
	if strings.Count(text, `"methods"`) != 1 || strings.Count(text, `"path"`) != 1 {
		t.Fatalf("unconditioned rules must omit empty condition fields: %s", text)
	}
	var wide strings.Builder
	if err := renderPolicyWideTable(&wide, list, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wide.String(), "GET") || !strings.Contains(wide.String(), "/v1/**") {
		t.Fatalf("wide table lost HTTP columns:\n%s", wide.String())
	}
}
