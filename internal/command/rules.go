package command

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	sdk "github.com/gyrel/sandboxes-go-sdk"
)

func parseNetworkRule(value string) (sdk.NetworkRule, error) {
	protocol := tcpProtocol
	if strings.HasPrefix(value, "udp:") {
		protocol = udpProtocol
		value = strings.TrimPrefix(value, "udp:")
	}
	target := value
	port := uint16(0)
	// A bare IP literal has no port; IPv6 ports require brackets.
	if ip := net.ParseIP(target); ip != nil {
		bits := "128"
		if ip.To4() != nil {
			bits = "32"
		}
		return sdk.NetworkRule{Protocol: protocol, CIDR: ip.String() + "/" + bits, Port: 0}, nil
	}
	if index := strings.LastIndexByte(target, ':'); index > 0 {
		parsed, err := strconv.ParseUint(target[index+1:], 10, 16)
		if err == nil {
			if parsed == 0 {
				return sdk.NetworkRule{}, errors.New("network rule port must be 1..65535")
			}
			port = uint16(parsed)
			target = target[:index]
		}
	}
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		target = strings.TrimSuffix(strings.TrimPrefix(target, "["), "]")
	}
	if _, network, err := net.ParseCIDR(target); err == nil {
		return sdk.NetworkRule{Protocol: protocol, CIDR: network.String(), Port: port}, nil
	}
	// A bare IP literal must become a /32 CIDR. Storing it as a domain rule
	// would silently never match an IP flow (including a deny).

	if ip := net.ParseIP(target); ip != nil {
		bits := "128"
		if ip.To4() != nil {
			bits = "32"
		}
		return sdk.NetworkRule{Protocol: protocol, CIDR: ip.String() + "/" + bits, Port: port}, nil
	}
	if target == "**" {
		return sdk.NetworkRule{Protocol: protocol, CIDR: "0.0.0.0/0", Port: port}, nil
	}
	if err := validateCLIDomain(target); err != nil {
		return sdk.NetworkRule{}, err
	}
	return sdk.NetworkRule{Protocol: protocol, Domain: strings.ToLower(target), Port: port}, nil
}

func validateCLIDomain(target string) error {
	if target == "" || len(target) > 253 || strings.ContainsAny(target, "\\ ") {
		return errors.New("network rule must be an IPv4 CIDR or a domain")
	}
	if net.ParseIP(target) != nil {
		return errors.New("network rule domain must not be an IP literal; use a CIDR")
	}
	base := strings.TrimPrefix(strings.TrimPrefix(target, "**."), "*.")
	if base == "" || strings.Contains(base, "*") || strings.Contains(base, "://") {
		return errors.New("invalid domain rule")
	}
	for _, label := range strings.Split(base, ".") {
		if !validCLIDomainLabel(label) {
			return errors.New("invalid domain rule")
		}
	}
	return nil
}

func validCLIDomainLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '?' || r == '[' || r == ']' || r == '!' {
			continue
		}
		return false
	}
	return true
}

func resolveNetworkRules(values []string) ([]sdk.NetworkRule, error) {
	if len(values) > 64 {
		return nil, errors.New("at most 64 network rules are supported")
	}
	rules := make([]sdk.NetworkRule, 0, len(values))
	for _, value := range values {
		rule, err := parseNetworkRule(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", value, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// networkHTTPSelectors carries the raw HTTP L7 flag values of
// `policy allow|deny|rm network`. Values stay as authored: canonicalization
// (upper-case methods, ANY sentinel, glob validation) is the daemon's job and
// older daemons refuse them outright through the SDK contract gate, so the
// CLI never needs to normalize or guess here.
type networkHTTPSelectors struct {
	methods stringListFlag
	path    string
	queries stringListFlag
}

func (s networkHTTPSelectors) empty() bool {
	return len(s.methods) == 0 && s.path == "" && len(s.queries) == 0
}

// applyNetworkHTTPSelectors attaches authored HTTP selectors to one rule.
// Method values may be comma lists (the gateway grammar); query values are
// single name=glob pairs because a comma can legitimately appear inside a
// glob value.
func applyNetworkHTTPSelectors(rule *sdk.NetworkRule, sel networkHTTPSelectors) error {
	if sel.empty() {
		return nil
	}
	for _, item := range sel.methods {
		for _, method := range strings.Split(item, ",") {
			trimmed := strings.TrimSpace(method)
			if trimmed == "" {
				return errors.New("HTTP method list contains an empty entry")
			}
			rule.Methods = append(rule.Methods, trimmed)
		}
	}
	if sel.path != "" {
		rule.Path = sel.path
	}
	for _, item := range sel.queries {
		name, value, found := strings.Cut(strings.TrimSpace(item), "=")
		if !found || name == "" {
			return fmt.Errorf("query condition %q must be name=value", item)
		}
		rule.Query = append(rule.Query, sdk.QueryCondition{Name: name, Value: strings.TrimSpace(value)})
	}
	return nil
}

// canonicalMethodsKey renders methods for selector comparison independent of
// authoring order and case. ANY alone conditions the rule, so it survives as
// a sentinel entry.
func canonicalMethodsKey(methods []string) string {
	if len(methods) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var parts []string
	for _, m := range methods {
		upper := strings.ToUpper(strings.TrimSpace(m))
		if upper == "" || seen[upper] {
			continue
		}
		seen[upper] = true
		parts = append(parts, upper)
	}
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

func canonicalQueryKey(query []sdk.QueryCondition) string {
	if len(query) == 0 {
		return ""
	}
	parts := make([]string, 0, len(query))
	for _, q := range query {
		parts = append(parts, q.Name+"="+q.Value)
	}
	slices.Sort(parts)
	return strings.Join(parts, ";")
}
