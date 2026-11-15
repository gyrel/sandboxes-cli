package command

import (
	"context"
	"errors"
	"net"

	localv1 "github.com/rheic/sandboxes-api/gen/go/sandboxes/local/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// orgPolicyClient is the minimal read-only RPC surface for policy org. Keeping
// it separate from sdk.Client lets tests use a fake without a daemon and lets
// the CLI consume the additive API contract before the SDK release catches up.
type orgPolicyClient interface {
	GetOrgPolicy(ctx context.Context) (*localv1.GetOrgPolicyResponse, error)
	Close() error
}

type grpcOrgPolicyClient struct {
	conn   *grpc.ClientConn
	client localv1.SandboxServiceClient
}

func newOrgPolicyClient(address string) (orgPolicyClient, error) {
	if address == "" {
		return nil, errors.New("sandbox daemon address is required")
	}
	target, dialer, err := orgPolicyEndpoint(address)
	if err != nil {
		return nil, err
	}
	options := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if dialer != nil {
		options = append(options, grpc.WithContextDialer(dialer))
	}
	conn, err := grpc.NewClient(target, options...)
	if err != nil {
		return nil, err
	}
	return &grpcOrgPolicyClient{conn: conn, client: localv1.NewSandboxServiceClient(conn)}, nil
}

func (c *grpcOrgPolicyClient) GetOrgPolicy(ctx context.Context) (*localv1.GetOrgPolicyResponse, error) {
	return c.client.GetOrgPolicy(ctx, &localv1.GetOrgPolicyRequest{})
}

func (c *grpcOrgPolicyClient) Close() error { return c.conn.Close() }

type orgPolicyEndpointFunc func(ctx context.Context, address string) (net.Conn, error)
