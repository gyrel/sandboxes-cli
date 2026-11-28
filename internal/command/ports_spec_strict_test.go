package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

// TestPortSpecStrictCanonicalForms pins the six canonical sbx port-spec forms
// against the strict CLI parser. parsePortSpecStrict never allocates an
// ephemeral host port, so omitted HOST_PORT stays zero in the result.
func TestPortSpecStrictCanonicalForms(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want sdk.Port
	}{
		{
			name: "guest only allocates ephemeral host",
			spec: "8080",
			want: sdk.Port{Guest: 8080, Protocol: tcpProtocol, HostIP: loopbackHost},
		},
		{
			name: "host and guest",
			spec: "3000:8080",
			want: sdk.Port{Host: 3000, Guest: 8080, Protocol: tcpProtocol, HostIP: loopbackHost},
		},
		{
			name: "host IP host and guest",
			spec: "127.0.0.1:3000:8080",
			want: sdk.Port{Host: 3000, Guest: 8080, Protocol: tcpProtocol, HostIP: loopbackHost},
		},
		{
			name: "specific non-loopback host IP host and guest",
			spec: "10.0.0.5:3000:8080/tcp4",
			want: sdk.Port{Host: 3000, Guest: 8080, Protocol: tcpProtocol, HostIP: "10.0.0.5"},
		},
		{
			name: "guest and protocol",
			spec: "8080/udp",
			want: sdk.Port{Guest: 8080, Protocol: udpProtocol, HostIP: loopbackHost},
		},
		{
			name: "host guest and protocol",
			spec: "3000:8080/udp",
			want: sdk.Port{Host: 3000, Guest: 8080, Protocol: udpProtocol, HostIP: loopbackHost},
		},
		{
			name: "bracketed IPv6 host IP host guest and protocol",
			spec: "[::1]:3000:8080/tcp6",
			want: sdk.Port{Host: 3000, Guest: 8080, Protocol: tcpProtocol, HostIP: "::1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePortSpecStrict(tc.spec)
			if err != nil {
				t.Fatalf("parsePortSpecStrict(%q) error = %v", tc.spec, err)
			}
			if got != tc.want {
				t.Fatalf("parsePortSpecStrict(%q) = %+v, want %+v", tc.spec, got, tc.want)
			}
			// Accepted forms must remain byte-compatible with the legacy
			// no-allocation path used by unpublish validation.
			legacy, err := parsePortSpec(tc.spec, false)
			if err != nil {
				t.Fatalf("parsePortSpec(%q, false) error = %v", tc.spec, err)
			}
			if legacy != got {
				t.Fatalf("parsePortSpec(%q, false) = %+v, want strict result %+v", tc.spec, legacy, got)
			}
		})
	}
}

// TestPortSpecStrictMalformed pins the design reject list plus the documented
// empty/whitespace/negative cases. Every rejection must carry the local
// preflight code prefix SPEC_INVALID: and must not return a partial port.
func TestPortSpecStrictMalformed(t *testing.T) {
	tests := []struct {
		name string
		spec string
	}{
		{name: "empty", spec: ""},
		{name: "spaces only", spec: "  "},
		{name: "embedded space", spec: "80 80"},
		{name: "leading colon", spec: ":80"},
		{name: "trailing colon", spec: "80:"},
		{name: "trailing slash", spec: "80/"},
		{name: "protocol only", spec: "/tcp"},
		{name: "zero host port", spec: "0:80"},
		{name: "zero guest port", spec: "80:0"},
		{name: "zero guest only", spec: "0"},
		{name: "sctp protocol", spec: "80:80/sctp"},
		{name: "host port out of range", spec: "99999:80"},
		{name: "guest port out of range", spec: "80:99999"},
		{name: "too many colon fields", spec: "80:80:80"},
		{name: "four colon fields", spec: "80:80:80:80"},
		{name: "non numeric ports", spec: "a:b"},
		{name: "negative host port", spec: "-1:80"},
		{name: "negative guest port", spec: "80:-1"},
		{name: "IPv4 wildcard host IP", spec: "0.0.0.0:8080:80"},
		{name: "IPv6 wildcard host IP", spec: "[::]:8080:80/tcp6"},
		{name: "bare IPv6 host IP", spec: "::1:8080:80"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePortSpecStrict(tc.spec)
			if err == nil {
				t.Fatalf("parsePortSpecStrict(%q) = %+v, want SPEC_INVALID error", tc.spec, got)
			}
			if got != (sdk.Port{}) {
				t.Fatalf("parsePortSpecStrict(%q) returned partial port %+v on error", tc.spec, got)
			}
			if !strings.HasPrefix(err.Error(), "SPEC_INVALID:") {
				t.Fatalf("parsePortSpecStrict(%q) error = %q, want SPEC_INVALID: prefix", tc.spec, err)
			}
		})
	}
}

// TestPortSpecStrictCommandRejectsBeforeRPC proves that malformed specs fail
// during command parsing, before the client factory is called, so a rejected
// spec can never reach an RPC.
func TestPortSpecStrictCommandRejectsBeforeRPC(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "ports publish leading colon", args: []string{"ports", "--publish", ":80", "dev"}},
		{name: "ports unpublish trailing colon", args: []string{"ports", "--unpublish", "80:", "dev"}},
		{name: "ports publish zero guest", args: []string{"ports", "--publish", "80:0", "dev"}},
		{name: "run publish sctp", args: []string{"run", "--publish", "80:80/sctp", "shell"}},
		{name: "run publish out of range", args: []string{"run", "--publish", "99999:80", "shell"}},
		{name: "create publish protocol only", args: []string{"create", "--publish", "/tcp", "shell"}},
		{name: "create publish three columns", args: []string{"create", "--publish", "80:80:80", "shell"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			clientCalls := 0
			runner := &Runner{
				Out: &out,
				Err: &out,
				NewClient: func(string) (sdk.Client, error) {
					clientCalls++
					return fakeClient{}, nil
				},
			}
			if code := runner.Run(context.Background(), tc.args); code != 2 {
				t.Fatalf("%v: exit = %d, want 2 (output %q)", tc.args, code, out.String())
			}
			if clientCalls != 0 {
				t.Fatalf("%v: NewClient called %d times before rejecting the spec", tc.args, clientCalls)
			}
			if !strings.Contains(out.String(), "SPEC_INVALID:") {
				t.Fatalf("%v: output %q does not contain SPEC_INVALID: prefix", tc.args, out.String())
			}
		})
	}
}
