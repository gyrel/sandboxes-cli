package command

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

// policyProfileFake serves the global policy for one fixed profile.
type policyProfileFake struct {
	policyRefreshFake
	profile string
}

func (p *policyProfileFake) PolicyService() sdk.PolicyService { return p }

func (p *policyProfileFake) GetPolicyProfile(context.Context) (string, error) { return p.profile, nil }

func runPolicyListForProfile(t *testing.T, profile string, args ...string) (string, int) {
	t.Helper()
	fake := &policyProfileFake{profile: profile}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader(""), Socket: t.TempDir() + "/sandboxesd.sock",
		NewClient: func(string) (sdk.Client, error) { return fake, nil }}
	code := runner.Run(context.Background(), append([]string{"policy", "ls"}, args...))
	return out.String(), code
}

func TestPolicyListReportsReferenceDefaultsForAllowAll(t *testing.T) {
	out, code := runPolicyListForProfile(t, policyProfileAllowAll, "--json")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out)
	}
	var list policyListOutput
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("decode: %v output=%q", err, out)
	}
	if len(list.Rules) != 3 {
		t.Fatalf("rules=%d, want 3: %q", len(list.Rules), out)
	}
	wantIDs := []string{"default-allow-all", "default-fs-read-allow-all", "default-fs-write-allow-all"}
	for i, rule := range list.Rules {
		if rule.ID != wantIDs[i] {
			t.Fatalf("rule %d id=%q want %q", i, rule.ID, wantIDs[i])
		}
		if rule.Provenance.CreatedVia != "default" || rule.Decision != "allow" || rule.Scope != "global" {
			t.Fatalf("rule %d shape=%+v", i, rule)
		}
	}
	if !list.Rules[0].Editable || list.Rules[1].Editable || list.Rules[2].Editable {
		t.Fatalf("editable flags=%v/%v/%v", list.Rules[0].Editable, list.Rules[1].Editable, list.Rules[2].Editable)
	}

	text, code := runPolicyListForProfile(t, policyProfileAllowAll)
	if code != 0 {
		t.Fatalf("table exit=%d", code)
	}
	for _, want := range []string{"POLICY", "SOURCE", "APPLIES TO", "SUMMARY", "local-policy", "network: 1 allow", "filesystem read: 1 allow"} {
		if !strings.Contains(text, want) {
			t.Fatalf("table missing %q:\n%s", want, text)
		}
	}
}

func TestPolicyListOmitsDefaultsForNonAllowAllProfiles(t *testing.T) {
	out, code := runPolicyListForProfile(t, policyProfileDenyAll, "--json")
	if code != 0 {
		t.Fatalf("exit=%d output=%q", code, out)
	}
	var list policyListOutput
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("decode: %v output=%q", err, out)
	}
	if len(list.Rules) != 0 {
		t.Fatalf("deny-all should not synthesize allow defaults: %q", out)
	}
}
