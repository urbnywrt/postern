package nodes

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// sourceWriter writes the artifact source straight to the store, refusing
// direct for a node without the capability, as proxies.Service does.
type sourceWriter struct{ db *store.DB }

func (w sourceWriter) WriteArtifactSource(ctx context.Context, nodeID, source string) error {
	_, err := w.db.ModifyNode(ctx, nodeID, func(n *store.Node) error {
		if source == store.ArtifactSourceDirect && len(n.HostInfo.Capabilities) == 0 {
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("no capability artifact-direct"))
		}
		n.ArtifactSource = source
		return nil
	})
	return err
}

func TestUpdateNodeArtifactSource(t *testing.T) {
	a := newAPI(t)
	ctx := context.Background()
	id := a.create(&panelv1.CreateNodeRequest{Name: "edge", MgmtHost: "192.0.2.10", MgmtPort: 61443}).GetNode().GetId()
	if got := a.node(id).ArtifactSource; got != "" {
		t.Fatalf("a new node has artifact source %q, want the default", got)
	}
	update := func(source string) (*panelv1.Node, error) {
		resp, err := a.nodes.UpdateNode(ctx, connect.NewRequest(&panelv1.UpdateNodeRequest{Id: id, ArtifactSource: proto.String(source)}))
		if err != nil {
			return nil, err
		}
		return resp.Msg.GetNode(), nil
	}
	if _, err := update(store.ArtifactSourceDirect); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("without a writer: %v, want Unimplemented", err)
	}
	a.svc.SetArtifactSourceWriter(sourceWriter{a.db})

	if _, err := update("bogus"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("artifact_source bogus: %v, want InvalidArgument", err)
	}
	if _, err := update(store.ArtifactSourceDirect); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("direct without the capability: %v, want FailedPrecondition", err)
	}
	a.modify(id, func(n *store.Node) { n.HostInfo.Capabilities = []string{"artifact-direct"} })
	n, err := update(store.ArtifactSourceDirect)
	if err != nil || n.GetArtifactSource() != store.ArtifactSourceDirect {
		t.Fatalf("direct: %v, %q; want direct", err, n.GetArtifactSource())
	}
	got, err := a.nodes.GetNode(ctx, connect.NewRequest(&panelv1.GetNodeRequest{Id: id}))
	if err != nil || got.Msg.GetNode().GetArtifactSource() != store.ArtifactSourceDirect {
		t.Errorf("GetNode after the change: %v, %q; want direct", err, got.Msg.GetNode().GetArtifactSource())
	}
	if n, err := update(""); err != nil || n.GetArtifactSource() != store.ArtifactSourcePanel {
		t.Errorf("empty: %v, %q; want panel", err, n.GetArtifactSource())
	}
}
