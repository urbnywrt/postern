package egress

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// The bounds of a chain.
const (
	maxMembers   = 64
	maxInterval  = 3600 // seconds
	maxTimeout   = 60   // seconds
	maxThreshold = 100
	maxDCAddrs   = 16
)

// checkCheck returns the check of a request as the store keeps it: nil is the
// defaults of the node. A value out of its bounds is invalid.
func checkCheck(c *panelv1.ChainCheck) (store.ChainCheck, error) {
	if c == nil {
		return store.ChainCheck{}, nil
	}
	switch {
	case c.GetIntervalSeconds() > maxInterval:
		return store.ChainCheck{}, invalid("check.interval_seconds must be 0 (the default) or 1 to %d", maxInterval)
	case c.GetTimeoutSeconds() > maxTimeout:
		return store.ChainCheck{}, invalid("check.timeout_seconds must be 0 (the default) or 1 to %d", maxTimeout)
	case c.GetFailThreshold() > maxThreshold:
		return store.ChainCheck{}, invalid("check.fail_threshold must be 0 (the default) or 1 to %d", maxThreshold)
	case c.GetRecoverThreshold() > maxThreshold:
		return store.ChainCheck{}, invalid("check.recover_threshold must be 0 (the default) or 1 to %d", maxThreshold)
	case len(c.GetDcAddrs()) > maxDCAddrs:
		return store.ChainCheck{}, invalid("check.dc_addrs: at most %d", maxDCAddrs)
	}
	out := store.ChainCheck{
		IntervalSeconds:  c.GetIntervalSeconds(),
		TimeoutSeconds:   c.GetTimeoutSeconds(),
		FailThreshold:    c.GetFailThreshold(),
		RecoverThreshold: c.GetRecoverThreshold(),
	}
	for _, a := range c.GetDcAddrs() {
		a = strings.TrimSpace(a)
		if err := state.CheckHostPort(a); err != nil { // the node's own rule
			return store.ChainCheck{}, invalid("check.dc_addrs: %.70q: %v", a, err)
		}
		out.DCAddrs = append(out.DCAddrs, a)
	}
	return out, nil
}

// sameCheck reports whether two checks are the same.
func sameCheck(a, b store.ChainCheck) bool {
	return a.IntervalSeconds == b.IntervalSeconds && a.TimeoutSeconds == b.TimeoutSeconds &&
		a.FailThreshold == b.FailThreshold && a.RecoverThreshold == b.RecoverThreshold && slices.Equal(a.DCAddrs, b.DCAddrs)
}

// memberIDs returns the ids of the members of a request without the spaces
// around them.
func memberIDs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, id := range in {
		out = append(out, strings.TrimSpace(id))
	}
	return out
}

// checkMembers checks the members of a chain against the World: 1 to 64
// egresses that exist, each once, and that the node of the chain can use (a
// chain of every node has egresses of every node only).
func checkMembers(w *proxies.World, c *store.EgressChain) error {
	if len(c.Members) == 0 || len(c.Members) > maxMembers {
		return invalid("a chain has 1 to %d members", maxMembers)
	}
	seen := map[string]bool{}
	for _, id := range c.Members {
		if seen[id] {
			return invalid("egress %.70q is a member twice", id)
		}
		seen[id] = true
		e := w.Egress(id)
		switch {
		case e == nil:
			return connect.NewError(connect.CodeNotFound, fmt.Errorf("no such egress: %.70q", id))
		case e.NodeID == "" || e.NodeID == c.NodeID:
		case c.NodeID == "":
			return invalid("egress %q belongs to a node: a chain of every node has egresses of every node only", e.Name)
		default:
			return invalid("egress %q belongs to another node", e.Name)
		}
	}
	return nil
}

// chainProto is the API form of a chain, with the nodes whose default chain
// it is and the proxies that use it.
func chainProto(c *store.EgressChain, ns []*store.Node, ps []*store.Proxy) *panelv1.Chain {
	out := &panelv1.Chain{
		Id:        c.ID,
		Name:      c.Name,
		NodeId:    c.NodeID,
		MemberIds: slices.Clone(c.Members),
		Check: &panelv1.ChainCheck{
			IntervalSeconds:  c.Check.IntervalSeconds,
			TimeoutSeconds:   c.Check.TimeoutSeconds,
			FailThreshold:    c.Check.FailThreshold,
			RecoverThreshold: c.Check.RecoverThreshold,
			DcAddrs:          slices.Clone(c.Check.DCAddrs),
		},
		CreatedUnix: c.CreatedAt.Unix(),
		UpdatedUnix: c.UpdatedAt.Unix(),
	}
	for _, n := range ns {
		if n.DefaultChainID == c.ID {
			out.DefaultOf = append(out.DefaultOf, n.ID)
		}
	}
	for _, p := range ps {
		if usesChain(p, c.ID) {
			out.ProxyIds = append(out.ProxyIds, p.ID)
		}
	}
	return out
}

// usesChain reports whether a proxy uses a chain, as its chain or for a scope.
func usesChain(p *store.Proxy, chainID string) bool {
	if p.EgressChainID == chainID {
		return true
	}
	for _, c := range p.EgressScopeChains {
		if c == chainID {
			return true
		}
	}
	return false
}

// chainProtos are the API forms of chains, with who uses them.
func (s *Service) chainProtos(ctx context.Context, cs []*store.EgressChain) ([]*panelv1.Chain, error) {
	ns, err := s.db.ListNodes(ctx)
	if err != nil {
		return nil, s.fail("could not list the nodes", err)
	}
	ps, err := s.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return nil, s.fail("could not list the proxies", err)
	}
	out := make([]*panelv1.Chain, 0, len(cs))
	for _, c := range cs {
		out = append(out, chainProto(c, ns, ps))
	}
	return out, nil
}

// chainByID is the API form of the chain with this id.
func (s *Service) chainByID(ctx context.Context, id string) (*panelv1.Chain, error) {
	c, err := s.db.ChainByID(ctx, id)
	if err != nil {
		return nil, s.readError("chain", err)
	}
	out, err := s.chainProtos(ctx, []*store.EgressChain{c})
	if err != nil {
		return nil, err
	}
	return out[0], nil
}

// ListChains returns the chains, or those that a node can use.
func (s *Service) ListChains(ctx context.Context, req *connect.Request[panelv1.ListChainsRequest]) (*connect.Response[panelv1.ListChainsResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	nodeID := req.Msg.GetNodeId()
	if nodeID != "" {
		if _, err := s.db.NodeByID(ctx, nodeID); err != nil {
			return nil, s.readError("node", err)
		}
	}
	cs, err := s.db.ListChains(ctx)
	if err != nil {
		return nil, s.fail("could not list the chains", err)
	}
	cs = slices.DeleteFunc(cs, func(c *store.EgressChain) bool { return nodeID != "" && c.NodeID != "" && c.NodeID != nodeID })
	out, err := s.chainProtos(ctx, cs)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.ListChainsResponse{Chains: out}), nil
}

// GetChain returns one chain.
func (s *Service) GetChain(ctx context.Context, req *connect.Request[panelv1.GetChainRequest]) (*connect.Response[panelv1.GetChainResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	out, err := s.chainByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.GetChainResponse{Chain: out}), nil
}

// CreateChain makes a chain.
func (s *Service) CreateChain(ctx context.Context, req *connect.Request[panelv1.CreateChainRequest]) (*connect.Response[panelv1.CreateChainResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg
	name, err := checkName(msg.GetName())
	if err != nil {
		return nil, err
	}
	check, err := checkCheck(msg.GetCheck())
	if err != nil {
		return nil, err
	}
	c := &store.EgressChain{
		ID: ids.New(), Name: name, NodeID: strings.TrimSpace(msg.GetNodeId()), Members: memberIDs(msg.GetMemberIds()), Check: check,
	}
	_, err = s.states.MutateEgresses(ctx, func(w *proxies.World) (func(context.Context) error, error) {
		if c.NodeID != "" && w.Node(c.NodeID) == nil {
			return nil, notFound("node")
		}
		if err := checkMembers(w, c); err != nil {
			return nil, err
		}
		w.SetChain(c)
		return func(ctx context.Context) error { return s.db.CreateChain(ctx, c) }, nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, admin.ID, "chain.create", "chain:"+c.ID, c.NodeID)
	s.log.Info("egress chain created", "chain", c.ID, "node", c.NodeID, "members", len(c.Members), "admin", admin.ID)
	return connect.NewResponse(&panelv1.CreateChainResponse{Chain: chainProto(c, nil, nil)}), nil
}

// UpdateChain changes the fields of a chain that the request sets.
func (s *Service) UpdateChain(ctx context.Context, req *connect.Request[panelv1.UpdateChainRequest]) (*connect.Response[panelv1.UpdateChainResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	msg := req.Msg
	var name *string
	if msg.Name != nil {
		n, err := checkName(msg.GetName())
		if err != nil {
			return nil, err
		}
		name = &n
	}
	var check *store.ChainCheck
	if msg.Check != nil {
		c, err := checkCheck(msg.GetCheck())
		if err != nil {
			return nil, err
		}
		check = &c
	}
	id := msg.GetId()
	changed := false
	var nodeID string
	_, err = s.states.MutateEgresses(ctx, func(w *proxies.World) (func(context.Context) error, error) {
		cur := w.Chain(id)
		if cur == nil {
			return nil, notFound("chain")
		}
		nodeID = cur.NodeID
		next := *cur
		next.Members = slices.Clone(cur.Members)
		if name != nil {
			next.Name = *name
		}
		if check != nil {
			next.Check = *check
		}
		if msg.Members != nil {
			next.Members = memberIDs(msg.GetMembers().GetIds())
			if err := checkMembers(w, &next); err != nil {
				return nil, err
			}
		}
		if next.Name == cur.Name && slices.Equal(next.Members, cur.Members) && sameCheck(next.Check, cur.Check) {
			return nil, nil
		}
		w.SetChain(&next)
		changed = true
		return func(ctx context.Context) error { return s.db.UpdateChain(ctx, &next) }, nil
	})
	if err != nil {
		return nil, err
	}
	if changed {
		s.audit(ctx, admin.ID, "chain.update", "chain:"+id, nodeID)
	}
	out, err := s.chainByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&panelv1.UpdateChainResponse{Chain: out}), nil
}

// DeleteChain deletes a chain that no node and no proxy uses.
func (s *Service) DeleteChain(ctx context.Context, req *connect.Request[panelv1.DeleteChainRequest]) (*connect.Response[panelv1.DeleteChainResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	id := req.Msg.GetId()
	var nodeID string
	_, err = s.states.MutateEgresses(ctx, func(w *proxies.World) (func(context.Context) error, error) {
		cur := w.Chain(id)
		if cur == nil {
			return nil, notFound("chain")
		}
		nodeID = cur.NodeID
		var users []string
		for _, n := range w.Nodes() {
			if n.DefaultChainID == id {
				users = append(users, fmt.Sprintf("the default chain of node %q", n.Name))
			}
		}
		count := 0
		for _, p := range w.Proxies() {
			if usesChain(p, id) {
				count++
			}
		}
		if count > 0 {
			users = append(users, fmt.Sprintf("the chain of %d proxies", count))
		}
		if len(users) > 0 {
			return nil, failedPrecondition("the chain is in use (%s): change those first", strings.Join(users, "; "))
		}
		w.RemoveChain(id)
		return func(ctx context.Context) error { return s.db.DeleteChain(ctx, id) }, nil
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, admin.ID, "chain.delete", "chain:"+id, nodeID)
	s.log.Info("egress chain deleted", "chain", id, "admin", admin.ID)
	return connect.NewResponse(&panelv1.DeleteChainResponse{}), nil
}

// SetNodeDefaultChain sets the chain that a node goes out through.
func (s *Service) SetNodeDefaultChain(ctx context.Context, req *connect.Request[panelv1.SetNodeDefaultChainRequest]) (*connect.Response[panelv1.SetNodeDefaultChainResponse], error) {
	admin, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}
	chainID := strings.TrimSpace(req.Msg.GetChainId())
	n, changed, before, err := s.modifyNode(ctx, req.Msg.GetNodeId(), "node.default_chain "+cmp.Or(chainID, "none"), func(w *proxies.World, n *store.Node) (bool, error) {
		if chainID != "" {
			c := w.Chain(chainID)
			switch {
			case c == nil:
				return false, notFound("chain")
			case c.NodeID != "" && c.NodeID != n.ID:
				return false, invalid("the chain belongs to another node")
			}
		}
		if n.DefaultChainID == chainID {
			return false, nil
		}
		n.DefaultChainID = chainID
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if changed {
		s.audit(ctx, admin.ID, "node.default_chain", "node:"+n.ID, n.ID)
	}
	return connect.NewResponse(&panelv1.SetNodeDefaultChainResponse{Node: nodes.ToProto(ctx, s.db, n), BeforeRunId: before}), nil
}
