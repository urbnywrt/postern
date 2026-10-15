package nodes

import (
	"context"
	"errors"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
)

// multiEnsurer runs several ArtifactEnsurers.
type multiEnsurer []ArtifactEnsurer

// MultiEnsurer returns an ArtifactEnsurer that runs each of es, in order, also
// after one failed, and joins their errors. A nil ensurer is skipped.
func MultiEnsurer(es ...ArtifactEnsurer) ArtifactEnsurer {
	var out multiEnsurer
	for _, e := range es {
		if e != nil {
			out = append(out, e)
		}
	}
	return out
}

func (m multiEnsurer) EnsureArtifacts(ctx context.Context, nodeID string, info *nodev1.GetInfoResponse, state *nodev1.NodeState, client nodev1connect.NodeServiceClient) error {
	var errs []error
	for _, e := range m {
		if err := e.EnsureArtifacts(ctx, nodeID, info, state, client); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
