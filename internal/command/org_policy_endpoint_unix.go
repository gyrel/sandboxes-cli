//go:build !windows

package command

func orgPolicyEndpoint(address string) (string, orgPolicyEndpointFunc, error) {
	return "unix:" + address, nil, nil
}
