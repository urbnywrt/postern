package reconcile

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/gen/go/postern/edge/v1/edgev1connect"
)

// EdgeClient is the reconciler's view of one edge generation's control
// service (the unix socket data/run/edge-g<N>.sock).
type EdgeClient interface {
	// SetConfig replaces the edge's whole configuration. An edge that cannot
	// apply it keeps the previous one and the call fails with its reason, a
	// refusal (ErrRefused); an edge that does not answer is no refusal. An
	// edge that applied it returns the listeners it could not bind, which
	// fail nothing else: the others serve, and the edge retries them.
	SetConfig(ctx context.Context, cfg *edgev1.EdgeConfig) ([]*edgev1.ListenerFailure, error)
	// Snapshot returns the traffic counters and the egress member health.
	Snapshot(ctx context.Context) (*edgev1.SnapshotResponse, error)
	// Health returns the generation of the edge and what it is bound to.
	Health(ctx context.Context) (*edgev1.HealthResponse, error)
	// Drain asks an outgoing generation to close its listeners and SOCKS
	// ports, wait at most maxSeconds for its connections, and exit (spec 7).
	Drain(ctx context.Context, maxSeconds uint32) error
}

// NewEdgeClient adapts a generated EdgeControlService client.
func NewEdgeClient(c edgev1connect.EdgeControlServiceClient) EdgeClient {
	return edgeClient{c: c}
}

type edgeClient struct {
	c edgev1connect.EdgeControlServiceClient
}

func (e edgeClient) SetConfig(ctx context.Context, cfg *edgev1.EdgeConfig) ([]*edgev1.ListenerFailure, error) {
	resp, err := e.c.SetConfig(ctx, connect.NewRequest(&edgev1.SetConfigRequest{Config: cfg}))
	if err != nil {
		return nil, fmt.Errorf("edge SetConfig: %w", err)
	}
	if !resp.Msg.GetApplied() {
		reason := resp.Msg.GetError()
		if reason == "" {
			reason = "no reason given"
		}
		return nil, refusal{errors.New("the edge did not apply the config: " + reason)}
	}
	return resp.Msg.GetListenerFailures(), nil
}

func (e edgeClient) Snapshot(ctx context.Context) (*edgev1.SnapshotResponse, error) {
	resp, err := e.c.Snapshot(ctx, connect.NewRequest(&edgev1.SnapshotRequest{}))
	if err != nil {
		return nil, fmt.Errorf("edge Snapshot: %w", err)
	}
	return resp.Msg, nil
}

func (e edgeClient) Health(ctx context.Context) (*edgev1.HealthResponse, error) {
	resp, err := e.c.Health(ctx, connect.NewRequest(&edgev1.HealthRequest{}))
	if err != nil {
		return nil, fmt.Errorf("edge Health: %w", err)
	}
	return resp.Msg, nil
}

func (e edgeClient) Drain(ctx context.Context, maxSeconds uint32) error {
	if _, err := e.c.Drain(ctx, connect.NewRequest(&edgev1.DrainRequest{MaxSeconds: maxSeconds})); err != nil {
		return fmt.Errorf("edge Drain: %w", err)
	}
	return nil
}
