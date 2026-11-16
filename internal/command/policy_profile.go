package command

import (
	"fmt"

	sdk "github.com/rheic/sandboxes-go-sdk"
)

const (
	anyIPv4CIDR           = "0.0.0.0/0"
	policyProfileDenyAll  = "deny-all"
	policyProfileBalanced = "balanced"
	policyProfileAllowAll = "allow-all"
	policyProfileCompat   = "sbx-compat"
)

// profileRules returns the built-in egress allowlist for a policy profile. The
// omitted profile follows the daemon default: allow-all, matching the Docker
// sbx baseline. Explicit deny-all never has profile rules.
func profileRules(profile string) ([]sdk.NetworkRule, error) {
	switch profile {
	case "", policyProfileAllowAll, policyProfileCompat:
		return []sdk.NetworkRule{
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR, Port: 0},
			{Protocol: udpProtocol, CIDR: anyIPv4CIDR, Port: 0},
		}, nil
	case policyProfileDenyAll:
		return nil, nil
	case policyProfileBalanced:
		return []sdk.NetworkRule{
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR, Port: 80},
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR, Port: 443},
			{Protocol: tcpProtocol, CIDR: anyIPv4CIDR, Port: 53},
			{Protocol: udpProtocol, CIDR: anyIPv4CIDR, Port: 53},
		}, nil
	default:
		return nil, fmt.Errorf("unknown policy profile %q (want allow-all, deny-all, balanced or sbx-compat)", profile)
	}
}
