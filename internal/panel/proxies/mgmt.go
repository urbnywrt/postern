package proxies

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// WriteMgmt stores the management settings of a node (spec §5.3): its mode, its
// management SNI and the public port that the panel reaches it through in mode
// hidden. It is what nodes.Manager switches a node with (nodes.MgmtWriter),
// and the only writer of the three.
//
// It goes through MutateEgresses, so the new state of the node is checked by
// the rules of the node before anything is written (a management SNI that is
// a domain of a proxy or of the pool on a tls listener of the node is
// refused), and the desired generation is raised and the manager told when the
// state changes. A publicPort other than 0 must be the port of a tls listener
// of the node (the plain management port has none: checkMgmtPort). Errors are
// Connect errors whose message says why.
func (s *Service) WriteMgmt(ctx context.Context, nodeID, mode, sni string, publicPort uint32) error {
	if mode != store.MgmtModePort && mode != store.MgmtModeHidden {
		return invalid("mode must be %s or %s", store.MgmtModePort, store.MgmtModeHidden)
	}
	_, err := s.MutateEgresses(ctx, func(w *World) (func(context.Context) error, error) {
		nd := w.nodeData(nodeID)
		if nd == nil {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("no such node"))
		}
		n := nd.node
		if n.MgmtMode == mode && n.MgmtSNI == sni && n.MgmtPublicPort == publicPort {
			return nil, nil
		}
		if publicPort != 0 && !hasTLSListener(nd.listeners, publicPort) {
			return nil, connect.NewError(connect.CodeFailedPrecondition,
				fmt.Errorf("port %d is not a public tls listener of the node", publicPort))
		}
		n.MgmtMode, n.MgmtSNI, n.MgmtPublicPort = mode, sni, publicPort
		return func(ctx context.Context) error {
			_, err := s.db.ModifyNode(ctx, nodeID, func(n *store.Node) error {
				n.MgmtMode, n.MgmtSNI, n.MgmtPublicPort = mode, sni, publicPort
				return nil
			})
			return err
		}, nil
	})
	return err
}

// nodeData returns the data of a node, nil when there is none.
func (w *World) nodeData(id string) *nodeData {
	for _, nd := range w.nodes {
		if nd.node.ID == id {
			return nd
		}
	}
	return nil
}

// hasTLSListener reports whether one of listeners is a tls listener on port.
func hasTLSListener(listeners []*store.Listener, port uint32) bool {
	for _, l := range listeners {
		if l.Kind == store.ListenerKindTLS && l.Port == port {
			return true
		}
	}
	return false
}

// checkHiddenMgmt refuses to delete a listener, or to change its port or
// address, while it carries the hidden management of its node (a tls listener
// on Node.MgmtPublicPort): the panel reaches the agent only through it, and
// would lose the node, with no way left to push the state that switches it
// back.
func checkHiddenMgmt(n *store.Node, l *store.Listener) error {
	if n.MgmtPublicPort != 0 && l.Kind == store.ListenerKindTLS && l.Port == n.MgmtPublicPort {
		return connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("port %d carries the hidden management of the node; switch it to port first", l.Port))
	}
	return nil
}
