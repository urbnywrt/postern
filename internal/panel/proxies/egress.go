package proxies

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// This file holds what the desired state of a node takes of the egresses and
// the egress chains of the panel, the capabilities that a state asks of its
// node, and MutateEgresses, by which the egress services change them.

// errParams marks parameters of an egress that cannot be opened: a fault of
// the panel (another master key), not of the data.
var errParams = errors.New("the parameters of an egress cannot be opened")

// egressAAD is the additional data that the parameters of an egress are
// sealed with: they open for their own egress only.
func egressAAD(egressID string) []byte {
	return []byte("egress:" + egressID)
}

// SealEgressParams seals the parameters of an egress, its JSON, for the
// database. They hold credentials.
func SealEgressParams(key seal.Key, egressID, params string) ([]byte, error) {
	return seal.Seal(key, []byte(params), egressAAD(egressID))
}

// OpenEgressParams opens the sealed parameters of an egress: its JSON, "" when
// it has none. An error wraps errParams and holds nothing of the parameters.
func OpenEgressParams(key seal.Key, e *store.Egress) (string, error) {
	if len(e.ParamsEnc) == 0 {
		return "", nil
	}
	plain, err := seal.Open(key, e.ParamsEnc, egressAAD(e.ID))
	if err != nil {
		return "", fmt.Errorf("%w: egress %s: %w", errParams, e.ID, err)
	}
	defer clear(plain)
	return string(plain), nil
}

// egressData is what the egress chains of the nodes are made of: every chain
// and every egress of the panel, with the parameters of the egresses opened.
type egressData struct {
	chains   map[string]*store.EgressChain
	egresses map[string]*store.Egress
	params   map[string]string // egress id → its parameters; they hold credentials
	bad      map[string]error  // egress id → why its parameters cannot be opened
}

// loadEgressData reads every chain and every egress, and opens the parameters
// of the egresses. Parameters that cannot be opened are noted rather than an
// error, so that the egress can still be deleted.
func loadEgressData(ctx context.Context, db *store.DB, key seal.Key) (*egressData, error) {
	cs, err := db.ListChains(ctx)
	if err != nil {
		return nil, err
	}
	es, err := db.ListEgresses(ctx)
	if err != nil {
		return nil, err
	}
	d := &egressData{
		chains:   make(map[string]*store.EgressChain, len(cs)),
		egresses: make(map[string]*store.Egress, len(es)),
		params:   make(map[string]string, len(es)),
		bad:      map[string]error{},
	}
	for _, c := range cs {
		d.chains[c.ID] = c
	}
	for _, e := range es {
		d.egresses[e.ID] = e
		p, err := OpenEgressParams(key, e)
		if err != nil {
			d.bad[e.ID] = err
			continue
		}
		d.params[e.ID] = p
	}
	return d, nil
}

// paramsOf returns the parameters of an egress.
func (d *egressData) paramsOf(id string) (string, error) {
	if err := d.bad[id]; err != nil {
		return "", err
	}
	return d.params[id], nil
}

// egressKind is the kind of an egress as the node has it. A stored kind that
// this version does not know is an error that names it (see unknownValue).
func egressKind(k string) (nodev1.EgressKind, error) {
	switch k {
	case store.EgressKindDirect:
		return nodev1.EgressKind_EGRESS_KIND_DIRECT, nil
	case store.EgressKindSOCKS5:
		return nodev1.EgressKind_EGRESS_KIND_SOCKS5, nil
	case store.EgressKindHTTP:
		return nodev1.EgressKind_EGRESS_KIND_HTTP, nil
	case store.EgressKindXrayURI:
		return nodev1.EgressKind_EGRESS_KIND_XRAY_URI, nil
	case store.EgressKindXraySubscription:
		return nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, nil
	case store.EgressKindWARP:
		return nodev1.EgressKind_EGRESS_KIND_WARP, nil
	case store.EgressKindPsiphon:
		return nodev1.EgressKind_EGRESS_KIND_PSIPHON, nil
	}
	return 0, unknownValue("egress kind", k)
}

// healthCheckOf is the check of a chain as the node has it; nil for the
// defaults of the node.
func healthCheckOf(c store.ChainCheck) *nodev1.HealthCheck {
	if c.IntervalSeconds == 0 && c.TimeoutSeconds == 0 && c.FailThreshold == 0 && c.RecoverThreshold == 0 && len(c.DCAddrs) == 0 {
		return nil
	}
	return &nodev1.HealthCheck{
		IntervalSeconds:  c.IntervalSeconds,
		TimeoutSeconds:   c.TimeoutSeconds,
		FailThreshold:    c.FailThreshold,
		RecoverThreshold: c.RecoverThreshold,
		DcAddrs:          slices.Clone(c.DCAddrs),
	}
}

// usableBy reports whether a node can use a chain or an egress of node
// owner: one of every node ("") or its own.
func usableBy(owner, nodeID string) bool {
	return owner == "" || owner == nodeID
}

// addEgresses adds the egresses and the chains of a node to its state: the
// chains that it uses (its default chain, and the chain and the scope chains of
// each of its proxies, paused ones too, since the node checks that they exist),
// in the order of their ids, and the egresses that they have, in the order of
// their ids; and, for a node without a default chain of its own, the implicit
// direct chain first. A chain or an egress that is missing, or that is of
// another node, is an error: the services never store such a reference.
func (nd *nodeData) addEgresses(st *nodev1.NodeState) error {
	used := map[string]bool{}
	if id := nd.node.DefaultChainID; id != "" {
		used[id] = true
	}
	for _, p := range nd.proxies {
		if p.EgressChainID != "" {
			used[p.EgressChainID] = true
		}
		for _, c := range p.EgressScopeChains {
			if c != "" {
				used[c] = true
			}
		}
	}
	if nd.node.DefaultChainID == "" {
		st.Egresses = append(st.Egresses, &nodev1.Egress{Id: ImplicitEgressID, Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT})
		st.Chains = append(st.Chains, &nodev1.EgressChain{Id: ImplicitChainID, MemberEgressIds: []string{ImplicitEgressID}})
	}
	members := map[string]bool{}
	for _, id := range slices.Sorted(maps.Keys(used)) {
		c := nd.eg.chains[id]
		switch {
		case c == nil:
			return fmt.Errorf("egress chain %.70q does not exist", id)
		case !usableBy(c.NodeID, nd.node.ID):
			return fmt.Errorf("egress chain %s belongs to another node", id)
		}
		st.Chains = append(st.Chains, &nodev1.EgressChain{
			Id:              c.ID,
			MemberEgressIds: slices.Clone(c.Members),
			Check:           healthCheckOf(c.Check),
		})
		for _, m := range c.Members {
			members[m] = true
		}
	}
	for _, id := range slices.Sorted(maps.Keys(members)) {
		e := nd.eg.egresses[id]
		switch {
		case e == nil:
			return fmt.Errorf("egress %.70q of a chain does not exist", id)
		case !usableBy(e.NodeID, nd.node.ID):
			return fmt.Errorf("egress %s of a chain belongs to another node", id)
		}
		kind, err := egressKind(e.Kind)
		if err != nil {
			return fmt.Errorf("egress %s: %w", id, err)
		}
		params, err := nd.eg.paramsOf(id)
		if err != nil {
			return err
		}
		st.Egresses = append(st.Egresses, &nodev1.Egress{
			Id:           e.ID,
			Kind:         kind,
			ParamsJson:   params,
			RefreshNonce: e.RefreshNonce,
		})
	}
	return nil
}

// The capabilities that a node reports (GetInfoResponse.capabilities) for what
// a desired state can ask of it beyond the baseline of slice 1, which a node
// that reports none has: fake-TLS proxies on telemt, direct egresses (from an
// address of the node, but not through an interface of it: Ruling S2-19),
// SOCKS5 and HTTP egresses.
const (
	CapEgressXray      = "egress-xray"
	CapEgressWARP      = "egress-warp"
	CapEgressPsiphon   = "egress-psiphon-core" // on Psiphon's own client; "egress-psiphon" was warp-plus
	CapEgressInterface = "egress-interface"
	CapDNSForwarder    = "dns-forwarder"
	CapMERouting       = "me-routing"
	CapEngineMtg       = "engine-mtg"
)

// features returns what a state asks of its node beyond the baseline, as the
// capability that it takes and what it is, in the words of a refusal. A nil
// state asks nothing.
func features(st *nodev1.NodeState) map[string]string {
	out := map[string]string{}
	for _, e := range st.GetEgresses() {
		switch e.GetKind() {
		case nodev1.EgressKind_EGRESS_KIND_XRAY_URI, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION:
			out[CapEgressXray] = "Xray egresses"
		case nodev1.EgressKind_EGRESS_KIND_WARP:
			out[CapEgressWARP] = "WARP egresses"
		case nodev1.EgressKind_EGRESS_KIND_PSIPHON:
			out[CapEgressPsiphon] = "Psiphon egresses"
		case nodev1.EgressKind_EGRESS_KIND_DIRECT:
			// A node of slice 1 refuses its whole state for a direct egress
			// through an interface; one from an address, and the implicit
			// direct egress, it takes.
			if p, err := state.ParseDirectParams(e.GetParamsJson()); err == nil && p.Interface != "" {
				out[CapEgressInterface] = "egresses through an interface of the node"
			}
		}
	}
	// "" is the default of the node, which an older node does not have and a
	// newer one has as doh: it asks for nothing. doh is asked for.
	if st.GetSettings().GetDnsMode() == "doh" {
		out[CapDNSForwarder] = "the DNS forwarder of the edge"
	}
	for _, p := range st.GetProxies() {
		if _, ok := p.GetEgressScopeChains()["me"]; ok {
			out[CapMERouting] = "a chain for the middle proxies"
		}
		if p.GetEngine() == nodev1.Engine_ENGINE_MTG {
			out[CapEngineMtg] = "the mtg engine"
		}
	}
	return out
}

// checkCapabilities refuses a change of the state of a node from before to
// after that asks something of the node that the state did not ask before, and
// that the node does not report (Ruling 43). What a state asked before is not
// judged again, so that a node that stops reporting a capability (an older
// build) can still be changed otherwise. A nil before is a state that could not
// be made: everything is asked anew.
//
// A node that has never connected has reported nothing: it may well be of this
// version, so the refusal says that it has not reported its capabilities yet,
// rather than to upgrade it.
func checkCapabilities(n *store.Node, before, after *nodev1.NodeState) error {
	had := features(before)
	need := features(after)
	for _, c := range slices.Sorted(maps.Keys(need)) {
		if _, ok := had[c]; ok || slices.Contains(n.HostInfo.Capabilities, c) {
			continue
		}
		unseen := len(n.HostInfo.Capabilities) == 0 && n.LastSeenAt == nil
		return &capabilityError{node: n.Name, feature: need[c] + " (" + c + ")", unseen: unseen}
	}
	return nil
}

// newFeatures returns the capabilities that after asks of a node and before did
// not, sorted, each as "<what> (<capability>)".
func newFeatures(before, after *nodev1.NodeState) []string {
	had, need := features(before), features(after)
	var out []string
	for _, c := range slices.Sorted(maps.Keys(need)) {
		if _, ok := had[c]; !ok {
			out = append(out, need[c]+" ("+c+")")
		}
	}
	return out
}

// capabilityError is a change that needs what its node cannot do yet, or has
// not said that it can.
type capabilityError struct {
	node, feature string
	unseen        bool // the node has never connected
}

func (e *capabilityError) Error() string {
	if e.unseen {
		return "node " + e.node + " has not reported its capabilities yet: connect it before it uses " + e.feature
	}
	return "upgrade node " + e.node + " to use " + e.feature
}

// ---- MutateEgresses ---------------------------------------------------------------

// World is the data that the desired states of the nodes are made of, as
// MutateEgresses reads it under the lock of the node data: every node with its
// listeners and proxies, and every egress and chain. A plan changes it in
// memory to what it is to be once the change is written, through these
// methods and through the records that they return.
type World struct {
	nodes []*nodeData
	eg    *egressData
}

// loadWorld reads the World. A listener or a proxy of a node that is gone by
// the time the nodes are read is left out.
func loadWorld(ctx context.Context, db *store.DB, key seal.Key) (*World, error) {
	eg, err := loadEgressData(ctx, db, key)
	if err != nil {
		return nil, err
	}
	ch, err := loadChannelData(ctx, db)
	if err != nil {
		return nil, err
	}
	ls, err := db.ListListeners(ctx, "")
	if err != nil {
		return nil, err
	}
	ps, err := db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return nil, err
	}
	ns, err := db.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	w := &World{eg: eg}
	byID := make(map[string]*nodeData, len(ns))
	for _, n := range ns {
		nd := &nodeData{node: n, secrets: map[string]string{}, bad: map[string]error{}, eg: eg, ch: ch}
		if nd.pool, err = db.NodeDomainPool(ctx, n.ID); err != nil {
			return nil, err
		}
		if nd.blacklist, err = db.NodeBlacklist(ctx, n.ID); err != nil {
			return nil, err
		}
		w.nodes = append(w.nodes, nd)
		byID[n.ID] = nd
	}
	for _, l := range ls {
		if nd := byID[l.NodeID]; nd != nil {
			nd.listeners = append(nd.listeners, l)
		}
	}
	for _, p := range ps {
		nd := byID[p.NodeID]
		if nd == nil {
			continue
		}
		nd.proxies = append(nd.proxies, p)
		s, err := openSecret(key, p)
		if err != nil {
			nd.bad[p.ID] = err
			continue
		}
		nd.secrets[p.ID] = s
	}
	return w, nil
}

// Node returns a node, nil when there is none. The plan may change its default
// chain and its DNS mode.
func (w *World) Node(id string) *store.Node {
	for _, nd := range w.nodes {
		if nd.node.ID == id {
			return nd.node
		}
	}
	return nil
}

// Nodes returns every node, in the order they were created.
func (w *World) Nodes() []*store.Node {
	out := make([]*store.Node, 0, len(w.nodes))
	for _, nd := range w.nodes {
		out = append(out, nd.node)
	}
	return out
}

// Proxies returns the proxies of every node, the paused ones too.
func (w *World) Proxies() []*store.Proxy {
	var out []*store.Proxy
	for _, nd := range w.nodes {
		out = append(out, nd.proxies...)
	}
	return out
}

// Egress returns an egress, nil when there is none. The plan may change its
// name and its refresh nonce.
func (w *World) Egress(id string) *store.Egress { return w.eg.egresses[id] }

// EgressParams returns the parameters of an egress: its JSON, "" for none. An
// error wraps errParams.
func (w *World) EgressParams(id string) (string, error) { return w.eg.paramsOf(id) }

// SetEgress adds an egress, or replaces the one with its id, with its
// parameters.
func (w *World) SetEgress(e *store.Egress, params string) {
	w.eg.egresses[e.ID] = e
	w.SetEgressParams(e.ID, params)
}

// SetEgressParams replaces the parameters of an egress.
func (w *World) SetEgressParams(id, params string) {
	w.eg.params[id] = params
	delete(w.eg.bad, id)
}

// RemoveEgress removes an egress.
func (w *World) RemoveEgress(id string) {
	delete(w.eg.egresses, id)
	delete(w.eg.params, id)
	delete(w.eg.bad, id)
}

// Chain returns a chain, nil when there is none. The plan may change its name,
// its members and its check.
func (w *World) Chain(id string) *store.EgressChain { return w.eg.chains[id] }

// Chains returns every chain, in the order they were created.
func (w *World) Chains() []*store.EgressChain {
	out := slices.Collect(maps.Values(w.eg.chains))
	slices.SortFunc(out, func(a, b *store.EgressChain) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ID, b.ID))
	})
	return out
}

// SetChain adds a chain, or replaces the one with its id.
func (w *World) SetChain(c *store.EgressChain) { w.eg.chains[c.ID] = c }

// RemoveChain removes a chain.
func (w *World) RemoveChain(id string) { delete(w.eg.chains, id) }

// An EgressPlan changes the World in memory to what it is to be after a change,
// and returns the write that makes the change in the database. A nil write
// with a nil error is no change. Its errors are Connect errors, which
// MutateEgresses returns as they are.
type EgressPlan func(w *World) (write func(ctx context.Context) error, err error)

// built is the state of a node as assemble made it, or why it could not.
type built struct {
	st  *nodev1.NodeState
	err error
}

// MutateEgresses changes the egresses, the chains, or the egress settings of
// nodes (their default chains and DNS modes). Under the lock of the node data
// it reads the World and makes the desired state of every node, lets plan
// change the World and say what to write, and makes every state again. A node
// whose state the change changes must take its new state: by the rules of the
// node (validateState), and by its capabilities (checkCapabilities). Otherwise
// the change is refused, FAILED_PRECONDITION, and nothing is written. Then the
// change is written, the desired generation of every node whose state changed
// is raised, and the notifier is told about each, in this order. It returns
// those nodes.
//
// A node whose state could not be made before the change, and cannot after it
// for the same reason, is broken by something else (a row that the services
// never write): the change is not judged by it, and does not raise its
// generation.
func (s *Service) MutateEgresses(ctx context.Context, plan EgressPlan) ([]string, error) {
	return s.mutateEgresses(ctx, plan, "", nil)
}

// mutateEgresses is MutateEgresses, except that the capabilities of the node
// deferNode are not checked: what its new state asks of it that its old one
// did not goes to deferred instead, sorted.
func (s *Service) mutateEgresses(ctx context.Context, plan EgressPlan, deferNode string, deferred *[]string) ([]string, error) {
	nodeDataMu.Lock()
	defer nodeDataMu.Unlock()
	changed, write, err := s.planEgresses(ctx, plan, deferNode, deferred)
	if err != nil || write == nil {
		return nil, err
	}
	raised, _, err := s.commitEgresses(ctx, changed, write)
	return raised, err
}

// MutateEgressesChange is MutateEgresses for an operator's edit (R6-3): while
// h is set, it plans and checks the change, releases the lock of the node data
// for the before-runs (h.Before, scope node, on every node whose state the
// change changes, at once), takes it again, plans and checks again against the
// data as it is now (a change that no longer passes is refused,
// FAILED_PRECONDITION "the data changed meanwhile"), commits, and tells h.After
// of the generation of each node. Besides the nodes raised, it returns the
// ids of their before-runs by node (none for a node whose Before gave "").
func (s *Service) MutateEgressesChange(ctx context.Context, change string, h ChangeHooks, plan EgressPlan) ([]string, map[string]string, error) {
	if !h.set() || hooksOff(ctx) {
		raised, err := s.MutateEgresses(ctx, plan)
		return raised, nil, err
	}
	nodeDataMu.Lock()
	first, write, err := s.planEgresses(ctx, plan, "", nil)
	nodeDataMu.Unlock()
	if err != nil || write == nil {
		return nil, nil, err
	}
	befores := make(map[string]string, len(first))
	if h.Before != nil {
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, id := range first {
			wg.Go(func() {
				run := h.Before(ctx, id, "node", change)
				mu.Lock()
				befores[id] = run
				mu.Unlock()
			})
		}
		wg.Wait()
	}
	nodeDataMu.Lock()
	changed, write, err := s.planEgresses(ctx, plan, "", nil)
	if err != nil {
		nodeDataMu.Unlock()
		return nil, nil, changedMeanwhile(err)
	}
	if write == nil {
		nodeDataMu.Unlock()
		return nil, nil, nil
	}
	raised, gens, err := s.commitEgresses(ctx, changed, write)
	nodeDataMu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	runs := make(map[string]string, len(raised))
	for _, id := range raised {
		if h.After != nil {
			h.After(id, "node", change, befores[id], gens[id])
		}
		if run := befores[id]; run != "" {
			runs[id] = run
		}
	}
	return raised, runs, nil
}

// planEgresses reads the World, lets plan change it, and checks the state of
// every node that the change changes. It returns those nodes and the write.
// The caller holds the lock of the node data.
func (s *Service) planEgresses(ctx context.Context, plan EgressPlan, deferNode string, deferred *[]string) ([]string, func(context.Context) error, error) {
	w, err := loadWorld(ctx, s.db, s.key)
	if err != nil {
		return nil, nil, s.fail("could not read the data of the nodes", err)
	}
	before := make([]built, len(w.nodes))
	for i, nd := range w.nodes {
		before[i].st, before[i].err = assemble(nd, s.pool)
	}
	write, err := plan(w)
	if err != nil || write == nil {
		return nil, nil, err
	}
	var changed []string
	for i, nd := range w.nodes {
		b := before[i]
		after, err := assemble(nd, s.pool)
		switch {
		case err != nil && b.err != nil && err.Error() == b.err.Error():
			continue
		case err == nil && b.err == nil && proto.Equal(b.st, after):
			continue
		case err == nil:
			err = validateState(after)
		}
		if err == nil && nd.node.ID == deferNode && deferred != nil {
			*deferred = newFeatures(b.st, after)
		} else if err == nil {
			err = checkCapabilities(nd.node, b.st, after)
		}
		if err != nil {
			return nil, nil, s.refusal(nd.node, err)
		}
		changed = append(changed, nd.node.ID)
	}
	return changed, write, nil
}

// commitEgresses writes a planned change, raises the desired generation of
// every node that it changed and notifies the notifier of each. It returns
// those nodes and their new generations. The caller holds the lock of the
// node data.
func (s *Service) commitEgresses(ctx context.Context, changed []string, write func(context.Context) error) ([]string, map[string]uint64, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	if err := write(ctx); err != nil {
		var ce *connect.Error
		switch {
		case errors.As(err, &ce):
			return nil, nil, err
		case errors.Is(err, store.ErrNotFound):
			return nil, nil, connect.NewError(connect.CodeNotFound, errors.New("the egress, the chain or the node is gone"))
		case errors.Is(err, store.ErrConflict):
			return nil, nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the change collides with data that changed meanwhile"))
		}
		return nil, nil, s.fail("could not store a change", err)
	}
	var raised []string
	gens := make(map[string]uint64, len(changed))
	for _, id := range changed {
		gen, err := s.nextGen(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue // deleted meanwhile, with its state
			}
			return nil, nil, s.fail("a change is stored, but the desired generation of a node could not be raised", err)
		}
		raised = append(raised, id)
		gens[id] = gen
		if s.notifier != nil {
			s.notifier.Notify(id)
		}
	}
	return raised, gens, nil
}

// refusal is the error for a change that the state of node n refuses: why, in
// the words of the node, with the name of the node; or an internal error, for
// a secret or parameters that the panel cannot open.
func (s *Service) refusal(n *store.Node, err error) error {
	var ce *capabilityError
	switch {
	case errors.Is(err, errSecret), errors.Is(err, errParams):
		return s.fail("could not open a secret of a node", err)
	case errors.As(err, &ce):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	return connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("node %s: %w", n.Name, err))
}
