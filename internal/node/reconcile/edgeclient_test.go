package reconcile

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/gen/go/postern/edge/v1/edgev1connect"
)

// stubControl is an in-memory EdgeControlServiceClient.
type stubControl struct {
	setResp *edgev1.SetConfigResponse
	err     error
	got     []proto.Message
}

var _ edgev1connect.EdgeControlServiceClient = (*stubControl)(nil)

func (s *stubControl) SetConfig(_ context.Context, req *connect.Request[edgev1.SetConfigRequest]) (*connect.Response[edgev1.SetConfigResponse], error) {
	s.got = append(s.got, req.Msg)
	if s.err != nil {
		return nil, s.err
	}
	return connect.NewResponse(s.setResp), nil
}

func (s *stubControl) Snapshot(_ context.Context, req *connect.Request[edgev1.SnapshotRequest]) (*connect.Response[edgev1.SnapshotResponse], error) {
	s.got = append(s.got, req.Msg)
	if s.err != nil {
		return nil, s.err
	}
	return connect.NewResponse(&edgev1.SnapshotResponse{Generation: 4}), nil
}

func (s *stubControl) Health(_ context.Context, req *connect.Request[edgev1.HealthRequest]) (*connect.Response[edgev1.HealthResponse], error) {
	s.got = append(s.got, req.Msg)
	if s.err != nil {
		return nil, s.err
	}
	return connect.NewResponse(&edgev1.HealthResponse{Generation: 4, Listening: true}), nil
}

func (s *stubControl) Drain(_ context.Context, req *connect.Request[edgev1.DrainRequest]) (*connect.Response[edgev1.DrainResponse], error) {
	s.got = append(s.got, req.Msg)
	if s.err != nil {
		return nil, s.err
	}
	return connect.NewResponse(&edgev1.DrainResponse{}), nil
}

func TestEdgeClientSetConfig(t *testing.T) {
	cfg := &edgev1.EdgeConfig{Generation: 4, DeviceIdleSeconds: 120}

	s := &stubControl{setResp: &edgev1.SetConfigResponse{Applied: true}}
	if failed, err := NewEdgeClient(s).SetConfig(context.Background(), cfg); err != nil || len(failed) != 0 {
		t.Fatalf("SetConfig = %v, %v", failed, err)
	}
	if len(s.got) != 1 || !proto.Equal(s.got[0], &edgev1.SetConfigRequest{Config: cfg}) {
		t.Errorf("request = %v", s.got)
	}

	// applied=false is an error that carries the edge's reason. It is a
	// refusal of the configuration, not a failure of the node.
	s = &stubControl{setResp: &edgev1.SetConfigResponse{Applied: false, Error: "listen tcp 0.0.0.0:443: bind: address already in use"}}
	_, err := NewEdgeClient(s).SetConfig(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Errorf("SetConfig = %v, want the edge's reason", err)
	}
	if !errors.Is(err, ErrRefused) {
		t.Errorf("SetConfig = %v, want a refusal (ErrRefused)", err)
	}
	if want := "the edge did not apply the config: listen tcp 0.0.0.0:443: bind: address already in use"; err.Error() != want {
		t.Errorf("SetConfig = %q, want %q", err, want)
	}

	// Transport errors come through, and are no refusal: the edge did not
	// answer.
	s = &stubControl{err: connect.NewError(connect.CodeUnavailable, errors.New("no socket"))}
	_, err = NewEdgeClient(s).SetConfig(context.Background(), cfg)
	if err == nil {
		t.Error("SetConfig = nil, want the transport error")
	}
	if errors.Is(err, ErrRefused) {
		t.Errorf("SetConfig = %v: a transport error taken for a refusal", err)
	}

	// The listeners the edge could not bind come through with an applied
	// configuration.
	s = &stubControl{setResp: &edgev1.SetConfigResponse{Applied: true, ListenerFailures: []*edgev1.ListenerFailure{
		{ListenerId: "L2", Reason: "listen tcp4 0.0.0.0:8443: bind: address already in use"},
	}}}
	failed, err := NewEdgeClient(s).SetConfig(context.Background(), cfg)
	if err != nil || len(failed) != 1 || failed[0].GetListenerId() != "L2" {
		t.Errorf("SetConfig = %v, %v; want the failure of L2", failed, err)
	}
}

func TestEdgeClientCalls(t *testing.T) {
	s := &stubControl{}
	c := NewEdgeClient(s)
	h, err := c.Health(context.Background())
	if err != nil || h.GetGeneration() != 4 || !h.GetListening() {
		t.Errorf("Health = %v, %v", h, err)
	}
	snap, err := c.Snapshot(context.Background())
	if err != nil || snap.GetGeneration() != 4 {
		t.Errorf("Snapshot = %v, %v", snap, err)
	}
	if err := c.Drain(context.Background(), 3600); err != nil {
		t.Errorf("Drain = %v", err)
	}
	if last := s.got[len(s.got)-1]; !proto.Equal(last, &edgev1.DrainRequest{MaxSeconds: 3600}) {
		t.Errorf("Drain request = %v", last)
	}

	s.err = errors.New("boom")
	if _, err := c.Health(context.Background()); err == nil {
		t.Error("Health = nil error, want boom")
	}
	if _, err := c.Snapshot(context.Background()); err == nil {
		t.Error("Snapshot = nil error, want boom")
	}
	if err := c.Drain(context.Background(), 1); err == nil {
		t.Error("Drain = nil, want boom")
	}
}
