package proxies

import (
	"cmp"
	"context"
	"errors"
	"slices"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// CapArtifactDirect is the capability of a node that downloads the artifacts
// of its state from their url itself (NodeSettings.artifact_source direct).
const CapArtifactDirect = "artifact-direct"

// WriteArtifactSource stores where a node gets its artifacts: "panel" (also
// for ""), uploaded by the panel, or "direct", downloaded by the node itself,
// which needs a node that reports CapArtifactDirect. A change raises the
// desired generation of the node and notifies the manager (WriteVersions).
// It is what nodes.Service.UpdateNode writes artifact_source with
// (nodes.ArtifactSourceWriter). Errors are Connect errors whose message says
// why.
func (s *Service) WriteArtifactSource(ctx context.Context, nodeID, source string) error {
	source = cmp.Or(source, store.ArtifactSourcePanel)
	if source != store.ArtifactSourcePanel && source != store.ArtifactSourceDirect {
		return invalid("artifact_source must be %s or %s", store.ArtifactSourcePanel, store.ArtifactSourceDirect)
	}
	err := s.WriteVersions(ctx, func(ctx context.Context) ([]string, error) {
		changed := false
		_, err := s.db.ModifyNode(ctx, nodeID, func(n *store.Node) error {
			if cmp.Or(n.ArtifactSource, store.ArtifactSourcePanel) == source {
				return nil
			}
			if source == store.ArtifactSourceDirect && !slices.Contains(n.HostInfo.Capabilities, CapArtifactDirect) {
				return connect.NewError(connect.CodeFailedPrecondition,
					errors.New("the agent of the node cannot download artifacts itself (no capability artifact-direct); update it first"))
			}
			n.ArtifactSource, changed = source, true
			return nil
		})
		if err != nil || !changed {
			return nil, err
		}
		return []string{nodeID}, nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return connect.NewError(connect.CodeNotFound, errors.New("no such node"))
	}
	return err
}
