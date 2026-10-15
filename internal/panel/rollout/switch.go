package rollout

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// SwitchChecker checks that proxies of a node may run an engine, as
// CreateProxy would check them (proxies.Service.CheckEngineSwitch).
type SwitchChecker interface {
	CheckEngineSwitch(ctx context.Context, nodeID string, proxyIDs []string, engine, version string) error
}

// maxSwitchProxies is the most proxies one switch takes.
const maxSwitchProxies = 1000

// Switch is the executor of switch rollouts: selected proxies to an engine,
// pinned at ToVersion when the request gives one (they end pinned), else at
// the channel version of the engine on the node of each (they end following
// the channel). The links of a proxy do not change: a switch writes only its
// engine and version.
type Switch struct {
	base
	checker SwitchChecker
}

var (
	_ Executor = (*Switch)(nil)
	_ Preparer = (*Switch)(nil)
	_ Skipper  = (*Switch)(nil)
)

// NewSwitch returns the executor of switch rollouts.
func NewSwitch(cfg EngineConfig, checker SwitchChecker) *Switch {
	return &Switch{base: newBase(cfg), checker: checker}
}

// channelData is the channel versions and the default channel.
type channelData struct {
	versions map[string]map[string]string
	def      string
}

func (e *base) channels(ctx context.Context) (*channelData, error) {
	versions, err := e.db.ChannelVersions(ctx)
	if err != nil {
		return nil, err
	}
	def, err := e.defaultChannel(ctx)
	if err != nil {
		return nil, err
	}
	return &channelData{versions: versions, def: def}, nil
}

// version is the version of a component on the channel of a node; a channel
// without a row takes the default channel's.
func (c *channelData) version(component string, n *store.Node) string {
	if v := c.versions[component][cmp.Or(n.EngineChannel, c.def)]; v != "" {
		return v
	}
	return c.versions[component][c.def]
}

// message is what an error of another service says, without its code.
func message(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Message()
	}
	return err.Error()
}

// targetOf is the version that a switch gives the proxies of a node.
func targetOf(r *store.Rollout, ch *channelData, n *store.Node) string {
	return cmp.Or(r.ToVersion, ch.version(r.ToEngine, n))
}

// Plan checks every proxy as CreateProxy would with the engine (the rules of
// mtg, the capability engine-mtg), and refuses a proxy that runs the target
// already, a version below a proxy's minimum or without a pinned SHA-256 for
// an architecture of its nodes, and nodes without rollout-status. The first
// proxy given goes first (unless the request names the canary, or it cannot).
func (e *Switch) Plan(ctx context.Context, r *store.Rollout, req *Request) ([]string, []store.RolloutStep, []store.RolloutItem, error) {
	engine := r.Component
	if !isEngine(engine) {
		return nil, nil, nil, invalid("%.32q is not an engine", engine)
	}
	r.ToEngine, r.Channel = engine, ""
	var ids []string
	for _, id := range req.GetProxyIds() {
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, nil, nil, invalid("no proxy to switch")
	}
	if len(ids) > maxSwitchProxies {
		return nil, nil, nil, invalid("at most %d proxies at once", maxSwitchProxies)
	}
	ch, err := e.channels(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	nodes := map[string]*store.Node{}
	var cands []candidate
	for _, id := range ids {
		p, err := e.db.ProxyByID(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, nil, invalid("no proxy %.40q", id)
		}
		if err != nil {
			return nil, nil, nil, err
		}
		n := nodes[p.NodeID]
		if n == nil {
			if n, err = e.db.NodeByID(ctx, p.NodeID); err != nil {
				return nil, nil, nil, err
			}
			nodes[n.ID] = n
		}
		target := targetOf(r, ch, n)
		if target == "" {
			return nil, nil, nil, refuse("%s has no version on the channel of node %s", engine, n.Name)
		}
		same := cmp.Or(p.Engine, store.EngineTelemt) == engine
		if same && (r.ToVersion == "" || (p.EngineVersionPolicy == store.EnginePolicyPinned && p.EngineVersion == r.ToVersion)) {
			return nil, nil, nil, refuse("proxy %s runs %s already", p.Name, engine)
		}
		if minimum := minimumVersion(engine, p); minimum != "" && release.Compare(target, minimum) < 0 {
			return nil, nil, nil, refuse("proxy %s needs %s %s or later", p.Name, engine, minimum)
		}
		cands = append(cands, candidate{proxy: p, node: n})
	}
	scope := make([]*store.Node, 0, len(nodes))
	for _, n := range nodes {
		scope = append(scope, n)
	}
	slices.SortFunc(scope, func(a, b *store.Node) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.ID, b.ID))
	})
	var old []string
	for _, n := range scope {
		if !slices.Contains(n.HostInfo.Capabilities, CapRolloutStatus) {
			old = append(old, n.Name)
		}
	}
	if len(old) > 0 {
		return nil, nil, nil, refuse("upgrade node %s to use rollouts", strings.Join(old, ", "))
	}
	for _, n := range scope {
		if n.Arch == "" {
			return nil, nil, nil, refuse("node %s has not reported its architecture yet", n.Name)
		}
		target := targetOf(r, ch, n)
		if _, err := e.catalog.Ref(ctx, engine, target, n.Arch); err != nil {
			if errors.Is(err, releases.ErrNoPin) || errors.Is(err, releases.ErrUnknown) {
				return nil, nil, nil, refuse("%s %s has no pinned SHA-256 for %s; prepare it first", engine, target, n.Arch)
			}
			return nil, nil, nil, err
		}
		var mine []string
		for _, c := range cands {
			if c.node.ID == n.ID {
				mine = append(mine, c.proxy.ID)
			}
		}
		if err := e.checker.CheckEngineSwitch(ctx, n.ID, mine, engine, r.ToVersion); err != nil {
			return nil, nil, nil, refuse("node %s: %s", n.Name, message(err))
		}
	}
	canary := req.GetCanaryProxyId()
	if canary == "" && cands[0].proxy.Enabled && cands[0].node.Status == store.NodeStatusOnline {
		canary = cands[0].proxy.ID
	}
	p, err := proxySteps(cands, canary)
	if err != nil {
		return nil, nil, nil, err
	}
	r.Options.CanaryProxyID, r.Options.CanaryNodeID = p.canary.proxy.ID, p.canary.node.ID
	return p.nodeIDs, p.steps, p.items, nil
}

// Prepare fetches and checks the target of every node of the rollout.
func (e *Switch) Prepare(ctx context.Context, r *store.Rollout) error {
	items, err := e.itemsOf(ctx, r.ID, -1)
	if err != nil {
		return err
	}
	ch, err := e.channels(ctx)
	if err != nil {
		return err
	}
	archs := map[string][]string{} // version → architectures
	for _, it := range items {
		n, err := e.db.NodeByID(ctx, it.NodeID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		v := targetOf(r, ch, n)
		if n.Arch != "" && !slices.Contains(archs[v], n.Arch) {
			archs[v] = append(archs[v], n.Arch)
		}
	}
	var errs []error
	for _, v := range slices.Sorted(maps.Keys(archs)) {
		slices.Sort(archs[v])
		errs = append(errs, e.catalog.Prepare(ctx, r.ToEngine, v, archs[v]))
	}
	return errors.Join(errs...)
}

// Apply writes the engine and its version into the proxies of the step.
func (e *Switch) Apply(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error {
	return e.applyStep(ctx, r, s, r.ToEngine, func(n *store.Node) (string, error) {
		ch, err := e.channels(ctx)
		if err != nil {
			return "", err
		}
		return targetOf(r, ch, n), nil
	})
}

// Complete settles the items: pinned at ToVersion when the switch named one,
// else following their channel; deferred ones stay on what they ran.
func (e *Switch) Complete(ctx context.Context, r *store.Rollout) error {
	policy := store.EnginePolicyChannel
	if r.ToVersion != "" {
		policy = store.EnginePolicyPinned
	}
	return e.completeItems(ctx, r, policy)
}
