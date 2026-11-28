package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

func TestParsePublishSpec(t *testing.T) {
	for _, tc := range []struct {
		value string
		host  uint16
		guest uint16
		ok    bool
	}{
		{"8080:3000", 8080, 3000, true},
		{"8080:3000/tcp", 8080, 3000, true},
		{"8080:3000/udp", 8080, 3000, true},
		{"0:3000", 0, 0, false},
		{"8080", 0, 8080, true},
		{"8080:0", 0, 0, false},
		{"a:b", 0, 0, false},
	} {
		port, err := parsePublishSpec(tc.value)
		if (err == nil) != tc.ok || port.Guest != tc.guest || (tc.host != 0 && port.Host != tc.host) || (tc.host == 0 && tc.ok && port.Host == 0) {
			t.Fatalf("parsePublishSpec(%q)=%+v,%v", tc.value, port, err)
		}
	}
}

func TestParsePortSpecHostIPAndIPv6(t *testing.T) {
	for _, tc := range []struct {
		value  string
		hostIP string
		host   uint16
		guest  uint16
		proto  string
		ok     bool
	}{
		{value: "127.0.0.1:8080:3000/tcp4", hostIP: "127.0.0.1", host: 8080, guest: 3000, proto: "tcp", ok: true},
		{value: "[::1]:8080:3000/tcp6", hostIP: "::1", host: 8080, guest: 3000, proto: "tcp", ok: true},
		{value: "[::1]:3000/udp6", hostIP: "::1", guest: 3000, proto: "udp", ok: true},
		{value: "8080/tcp6", hostIP: "::1", guest: 8080, proto: "tcp", ok: true},
		{value: "10.0.0.5:8080:3000/tcp4", hostIP: "10.0.0.5", host: 8080, guest: 3000, proto: "tcp", ok: true},
		{value: "100.64.5.9:8080:3000", hostIP: "100.64.5.9", host: 8080, guest: 3000, proto: "tcp", ok: true},
		{value: "::1:8080:3000/tcp6", ok: false},
		{value: "0.0.0.0:8080:3000", ok: false},
		{value: "[::]:8080:3000/tcp6", ok: false},
		{value: "127.0.0.1:8080:3000/tcp6", ok: false},
		{value: "[::1]:8080:3000/tcp4", ok: false},
	} {
		port, err := parsePortSpec(tc.value, false)
		if (err == nil) != tc.ok {
			t.Fatalf("parsePortSpec(%q)=%+v,%v", tc.value, port, err)
		}
		if !tc.ok {
			continue
		}
		if port.HostIP != tc.hostIP || port.Host != tc.host || port.Guest != tc.guest || port.Protocol != tc.proto {
			t.Fatalf("parsePortSpec(%q)=%+v", tc.value, port)
		}
	}
}

func TestPortNormalizeHostIP(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		family  string
		want    string
		wantErr string
	}{
		{name: "loopback IPv4", value: "127.0.0.1", want: "127.0.0.1"},
		{name: "loopback IPv6", value: "::1", want: "::1"},
		{name: "specific non-loopback IPv4", value: "10.0.0.5", family: "4", want: "10.0.0.5"},
		{name: "carrier-grade NAT IPv4", value: "100.64.5.9", family: "4", want: "100.64.5.9"},
		{name: "specific non-loopback IPv6", value: "2001:db8::5", family: "6", want: "2001:db8::5"},
		{name: "unparseable", value: "not-an-ip", wantErr: "host IP must be a valid IP address"},
		{name: "IPv4 wildcard", value: "0.0.0.0", wantErr: "host IP must be a specific address, not 0.0.0.0 or ::"},
		{name: "IPv6 wildcard", value: "::", wantErr: "host IP must be a specific address, not 0.0.0.0 or ::"},
		{name: "IPv4 wildcard with family", value: "0.0.0.0", family: "4", wantErr: "host IP must be a specific address, not 0.0.0.0 or ::"},
		{name: "IPv6 wildcard with family", value: "::", family: "6", wantErr: "host IP must be a specific address, not 0.0.0.0 or ::"},
		{name: "tcp4 with IPv6", value: "::1", family: "4", wantErr: "host IP family does not match port protocol"},
		{name: "tcp6 with IPv4", value: "10.0.0.5", family: "6", wantErr: "host IP family does not match port protocol"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizePortHostIP(tc.value, tc.family)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("normalizePortHostIP(%q, %q) error = %v, want %q", tc.value, tc.family, err, tc.wantErr)
				}
				if got != "" {
					t.Fatalf("normalizePortHostIP(%q, %q) = %q on error, want empty", tc.value, tc.family, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("normalizePortHostIP(%q, %q) = %q, %v, want %q", tc.value, tc.family, got, err, tc.want)
			}
		})
	}
}

func TestPortsForDisplaysIPv6Family(t *testing.T) {
	ports := portsFor(&sdk.Sandbox{Ports: []sdk.Port{{Host: 8080, Guest: 3000, Protocol: "tcp", HostIP: "::1"}}})
	if len(ports) != 1 || ports[0].HostIP != "::1" || ports[0].Protocol != "tcp6" {
		t.Fatalf("ports=%+v", ports)
	}
}

func TestApplyPortChangesSeparatesHostIPAndProtocol(t *testing.T) {
	existing := []sdk.Port{{Host: 8080, Guest: 3000, Protocol: "tcp", HostIP: "127.0.0.1"}}
	added, err := applyPortChanges(existing, []sdk.Port{{Host: 8080, Guest: 3001, Protocol: "tcp", HostIP: "::1"}}, nil)
	if err != nil || len(added) != 2 {
		t.Fatalf("added=%+v err=%v", added, err)
	}
	if _, err := applyPortChanges(added, []sdk.Port{{Host: 8080, Guest: 3002, Protocol: "tcp", HostIP: "::1"}}, nil); err == nil {
		t.Fatal("duplicate IPv6 host port accepted")
	}
	removed, err := applyPortChanges(added, nil, []sdk.Port{{Host: 8080, Guest: 3001, Protocol: "tcp", HostIP: "::1"}})
	if err != nil || len(removed) != 1 || portHostIP(removed[0]) != "127.0.0.1" {
		t.Fatalf("removed=%+v err=%v", removed, err)
	}
}

func TestCreatePassesPublishedPorts(t *testing.T) {
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--publish", "8080:3000", "--publish", "8443:443/tcp", "shell"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.request.Ports) != 2 || sandbox.request.Ports[0].Host != 8080 || sandbox.request.Ports[1].Guest != 443 {
		t.Fatalf("ports=%+v", sandbox.request.Ports)
	}
	if code := runner.Run(context.Background(), []string{"create", "--publish", "8080:3000", "--publish", "8080:4000", "shell"}); code != 2 {
		t.Fatalf("duplicate host exit=%d", code)
	}
}

func TestRunPassesPublishedPortsOnCreate(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--publish", "8080:3000", "--name", "dev", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if len(sandboxes.created.Ports) != 1 || sandboxes.created.Ports[0].Host != 8080 {
		t.Fatalf("ports=%+v", sandboxes.created.Ports)
	}
	if sandboxes.created.Ports[0].HostIP != loopbackHost {
		t.Fatalf("host IP=%q, want %q", sandboxes.created.Ports[0].HostIP, loopbackHost)
	}
}

func TestRunPublishNonLoopbackReachesDaemonAndBindForbiddenExits2(t *testing.T) {
	workspace := t.TempDir()
	base := &runSandbox{}
	spy := &bindRefusalSandbox{
		runSandbox: base,
		createErr: &sdk.Error{
			Code:        "InvalidArgument",
			Message:     "publish denied by the server allowlist",
			MachineCode: "BIND_FORBIDDEN",
		},
	}
	client := bindRefusalClient{
		runClient:      runClient{sandboxes: base, sessions: &fakeSessions{}},
		sandboxService: spy,
	}
	runner, out, stderr := runTestRunner(t, client, "")
	code := runner.Run(context.Background(), []string{"run", "--detach", "--publish", "10.0.0.5:9000:80", "shell", workspace})
	if code != 2 {
		t.Fatalf("exit=%d, want 2 (stdout=%q stderr=%q)", code, out.String(), stderr.String())
	}
	if spy.createCalls != 1 {
		t.Fatalf("Create calls=%d, want 1", spy.createCalls)
	}
	if len(spy.created.Ports) != 1 {
		t.Fatalf("ports=%+v", spy.created.Ports)
	}
	port := spy.created.Ports[0]
	if port.HostIP != "10.0.0.5" || port.Host != 9000 || port.Guest != 80 {
		t.Fatalf("port=%+v, want host IP 10.0.0.5 host 9000 guest 80", port)
	}
	output := out.String() + stderr.String()
	if strings.Contains(output, "must be loopback") {
		t.Fatalf("CLI pre-empted the daemon allowlist: %q", output)
	}
	if !strings.Contains(output, "publish denied by the server allowlist") {
		t.Fatalf("output lacks the daemon refusal: %q", output)
	}
}

func TestRunPublishWildcardRefusedBeforeClient(t *testing.T) {
	workspace := t.TempDir()
	clientCalls := 0
	var out bytes.Buffer
	runner := &Runner{
		Out: &out,
		Err: &out,
		NewClient: func(string) (sdk.Client, error) {
			clientCalls++
			return fakeClient{}, nil
		},
	}
	code := runner.Run(context.Background(), []string{"run", "--detach", "--publish", "0.0.0.0:9000:80", "shell", workspace})
	if code != 2 {
		t.Fatalf("exit=%d, want 2 (output=%q)", code, out.String())
	}
	if clientCalls != 0 {
		t.Fatalf("NewClient called %d times before rejecting the wildcard", clientCalls)
	}
	if !strings.Contains(out.String(), "host IP must be a specific address, not 0.0.0.0 or ::") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestPortsCommandListsPorts(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev", Ports: []sdk.Port{{Host: 8080, Guest: 3000, Protocol: "tcp"}},
	}}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "dev"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "HOST IP") || !strings.Contains(out.String(), "SANDBOX PORT") ||
		!strings.Contains(out.String(), "127.0.0.1") || !strings.Contains(out.String(), "tcp4") {
		t.Fatalf("unexpected output: %q", out.String())
	}
	var jsonOut bytes.Buffer
	runner.Out, runner.Err = &jsonOut, &jsonOut
	if code := runner.Run(context.Background(), []string{"ports", "--json", "dev"}); code != 0 {
		t.Fatalf("json exit=%d output=%q", code, jsonOut.String())
	}
	var ports []portOutput
	if err := json.Unmarshal(jsonOut.Bytes(), &ports); err != nil || len(ports) != 1 || ports[0].HostPort != 8080 {
		t.Fatalf("ports=%+v err=%v", ports, err)
	}
}

type portUpdateClient struct {
	fakeClient
	base                *lifecycleSandbox
	ports               []sdk.Port
	updates             int
	startedBeforeUpdate bool
}

func (p *portUpdateClient) PortService() sdk.PortService { return p }

func (p *portUpdateClient) UpdatePorts(_ context.Context, _ string, ports []sdk.Port) (*sdk.Sandbox, error) {
	p.updates++
	p.startedBeforeUpdate = p.base != nil && len(p.base.starts) > 0
	p.ports = append([]sdk.Port(nil), ports...)
	if p.base != nil && len(p.base.items) > 0 {
		p.base.items[0].Ports = p.ports
	}
	return &sdk.Sandbox{ID: "sb-1", Name: "dev", Ports: ports}, nil
}

func TestPortsDynamicPublishAndUnpublish(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--publish", "18090:8080", "dev"}); code != 0 {
		t.Fatalf("publish exit=%d output=%q", code, out.String())
	}
	if len(client.ports) != 1 || client.ports[0].Host != 18090 {
		t.Fatalf("ports=%+v", client.ports)
	}
	if !strings.Contains(out.String(), "Published 127.0.0.1:18090 -> 8080/tcp4") {
		t.Fatalf("publish output=%q", out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"ports", "--publish", "18090:8081", "dev"}); code != 1 {
		t.Fatalf("duplicate publish exit=%d", code)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "18090:8080", "dev"}); code != 0 {
		t.Fatalf("unpublish exit=%d output=%q", code, out.String())
	}
	if len(client.ports) != 0 {
		t.Fatalf("ports after unpublish=%+v", client.ports)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "18090:8080", "dev"}); code != 1 {
		t.Fatalf("missing unpublish exit=%d", code)
	}
}

func TestPortsDynamicEphemeralPublish(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--publish", "8080", "dev"}); code != 0 {
		t.Fatalf("publish exit=%d output=%q", code, out.String())
	}
	if len(client.ports) != 1 || client.ports[0].Host == 0 || client.ports[0].Guest != 8080 {
		t.Fatalf("ports=%+v", client.ports)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "8080", "dev"}); code != 0 {
		t.Fatalf("guest-only unpublish exit=%d output=%q", code, out.String())
	}
	if len(client.ports) != 0 || out.String() != "Unpublish requested for all host ports -> 8080\n" {
		t.Fatalf("ports=%+v output=%q", client.ports, out.String())
	}
}

func TestPortsGuestOnlyUnpublishRepeatIsIdempotentNoOp(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev", State: sdk.StateStopped,
		Ports: []sdk.Port{{Host: 49153, Guest: 8080, Protocol: "tcp", HostIP: "127.0.0.1"}},
	}}}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "8080", "dev"}); code != 0 {
		t.Fatalf("unpublish exit=%d output=%q", code, out.String())
	}
	if client.updates != 1 || len(client.ports) != 0 {
		t.Fatalf("updates=%d ports=%+v", client.updates, client.ports)
	}
	if len(base.starts) != 0 || base.items[0].State != sdk.StateStopped {
		t.Fatalf("starts=%+v state=%q", base.starts, base.items[0].State)
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "8080", "dev"}); code != 0 {
		t.Fatalf("repeat unpublish exit=%d output=%q", code, out.String())
	}
	if out.String() != "Unpublish requested for all host ports -> 8080\n" {
		t.Fatalf("repeat output=%q", out.String())
	}
	if client.updates != 1 || len(client.ports) != 0 {
		t.Fatalf("repeat updates=%d ports=%+v", client.updates, client.ports)
	}
	if len(base.starts) != 0 || base.items[0].State != sdk.StateStopped {
		t.Fatalf("repeat starts=%+v state=%q", base.starts, base.items[0].State)
	}
}

func TestPortsPublishStartsStoppedSandboxBeforeUpdate(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: sdk.StateStopped}}}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--publish", "18090:8080", "dev"}); code != 0 {
		t.Fatalf("publish exit=%d output=%q", code, out.String())
	}
	if len(base.starts) != 1 || base.starts[0] != "sb-1" {
		t.Fatalf("starts=%+v", base.starts)
	}
	if client.updates != 1 || !client.startedBeforeUpdate {
		t.Fatalf("updates=%d startedBeforeUpdate=%v", client.updates, client.startedBeforeUpdate)
	}
	if len(client.ports) != 1 || client.ports[0].Host != 18090 || client.ports[0].Guest != 8080 {
		t.Fatalf("ports=%+v", client.ports)
	}
}

func TestPortsPublishRunningSandboxDoesNotStart(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: sdk.StateRunning}}}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--publish", "18090:8080", "dev"}); code != 0 {
		t.Fatalf("publish exit=%d output=%q", code, out.String())
	}
	if len(base.starts) != 0 {
		t.Fatalf("starts=%+v", base.starts)
	}
	if client.updates != 1 || client.startedBeforeUpdate {
		t.Fatalf("updates=%d startedBeforeUpdate=%v", client.updates, client.startedBeforeUpdate)
	}
	if len(client.ports) != 1 || client.ports[0].Host != 18090 {
		t.Fatalf("ports=%+v", client.ports)
	}
}

func TestPortsUnpublishStoppedSandboxDoesNotStart(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev", State: sdk.StateStopped,
		Ports: []sdk.Port{{Host: 18090, Guest: 8080, Protocol: "tcp", HostIP: "127.0.0.1"}},
	}}}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "18090:8080", "dev"}); code != 0 {
		t.Fatalf("unpublish exit=%d output=%q", code, out.String())
	}
	if len(base.starts) != 0 {
		t.Fatalf("starts=%+v", base.starts)
	}
	if client.updates != 1 || client.startedBeforeUpdate {
		t.Fatalf("updates=%d startedBeforeUpdate=%v", client.updates, client.startedBeforeUpdate)
	}
	if len(client.ports) != 0 {
		t.Fatalf("ports=%+v", client.ports)
	}
}

func TestPortsGuestOnlyUnpublishRemovesAllHostPorts(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev", State: sdk.StateStopped,
		Ports: []sdk.Port{
			{Host: 49153, Guest: 8080, Protocol: "tcp", HostIP: "127.0.0.1"},
			{Host: 49154, Guest: 8080, Protocol: "tcp", HostIP: "127.0.0.1"},
			{Host: 49155, Guest: 8080, Protocol: "udp", HostIP: "127.0.0.1"},
			{Host: 49156, Guest: 8080, Protocol: "tcp", HostIP: "::1"},
			{Host: 49157, Guest: 9090, Protocol: "tcp", HostIP: "127.0.0.1"},
		},
	}}}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "8080", "dev"}); code != 0 {
		t.Fatalf("unpublish exit=%d output=%q", code, out.String())
	}
	if out.String() != "Unpublish requested for all host ports -> 8080\n" {
		t.Fatalf("output=%q", out.String())
	}
	if len(base.starts) != 0 {
		t.Fatalf("starts=%+v", base.starts)
	}
	if len(client.ports) != 3 ||
		client.ports[0].Host != 49155 || client.ports[0].Protocol != "udp" ||
		client.ports[1].Host != 49156 || portHostIP(client.ports[1]) != "::1" ||
		client.ports[2].Host != 49157 || client.ports[2].Guest != 9090 {
		t.Fatalf("ports=%+v", client.ports)
	}
}

func TestPortsExplicitUnpublishRemovesOnlyRequestedHostPort(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev", State: sdk.StateStopped,
		Ports: []sdk.Port{
			{Host: 49153, Guest: 8080, Protocol: "tcp", HostIP: "127.0.0.1"},
			{Host: 49154, Guest: 8080, Protocol: "tcp", HostIP: "127.0.0.1"},
			{Host: 49155, Guest: 8080, Protocol: "udp", HostIP: "127.0.0.1"},
			{Host: 49156, Guest: 9090, Protocol: "tcp", HostIP: "127.0.0.1"},
		},
	}}}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "49153:8080", "dev"}); code != 0 {
		t.Fatalf("unpublish exit=%d output=%q", code, out.String())
	}
	if out.String() != "Unpublish requested for port 127.0.0.1:49153 -> 8080\n" {
		t.Fatalf("output=%q", out.String())
	}
	if len(base.starts) != 0 {
		t.Fatalf("starts=%+v", base.starts)
	}
	if len(client.ports) != 3 ||
		client.ports[0].Host != 49154 ||
		client.ports[1].Host != 49155 || client.ports[1].Protocol != "udp" ||
		client.ports[2].Host != 49156 || client.ports[2].Guest != 9090 {
		t.Fatalf("ports=%+v", client.ports)
	}
}

func TestPortsUnpublishOverlappingFlagsRemoveEachPortOnce(t *testing.T) {
	base := &lifecycleSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev",
		Ports: []sdk.Port{
			{Host: 49153, Guest: 8080, Protocol: "tcp", HostIP: "127.0.0.1"},
			{Host: 49154, Guest: 8080, Protocol: "tcp", HostIP: "127.0.0.1"},
		},
	}}}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--unpublish", "8080", "--unpublish", "49153:8080", "dev"}); code != 0 {
		t.Fatalf("unpublish exit=%d output=%q", code, out.String())
	}
	if out.String() != "Unpublish requested for all host ports -> 8080\nUnpublish requested for port 127.0.0.1:49153 -> 8080\n" {
		t.Fatalf("output=%q", out.String())
	}
	if len(client.ports) != 0 {
		t.Fatalf("ports=%+v", client.ports)
	}
}

func TestPortsPublishStoppedSandboxStartFailureSkipsUpdate(t *testing.T) {
	base := &lifecycleSandbox{
		items:    []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: sdk.StateStopped}},
		startErr: errors.New("start failed"),
	}
	client := &portUpdateClient{fakeClient: fakeClient{sandbox: base}, base: base}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"ports", "--publish", "18090:8080", "dev"}); code != 1 {
		t.Fatalf("publish exit=%d output=%q", code, out.String())
	}
	if len(base.starts) != 1 || base.starts[0] != "sb-1" {
		t.Fatalf("starts=%+v", base.starts)
	}
	if client.updates != 0 || len(client.ports) != 0 {
		t.Fatalf("updates=%d ports=%+v", client.updates, client.ports)
	}
	if len(base.items[0].Ports) != 0 {
		t.Fatalf("sandbox ports changed: %+v", base.items[0].Ports)
	}
	if !strings.Contains(out.String(), "start failed") {
		t.Fatalf("output=%q", out.String())
	}
}
