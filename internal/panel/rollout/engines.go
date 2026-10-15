package rollout

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// CapRolloutStatus is the capability of a node whose reports a rollout can
// judge (structured failures, the running engine and version).
const CapRolloutStatus = "rollout-status"

// The limits of a step of an engine rollout (Global Constraints, Rollouts).
const (
	engineStepBase    = 2 * time.Minute
	engineStepPerItem = 2 * time.Minute
	engineStepMax     = 60 * time.Minute
	offlineGrace      = 5 * time.Minute
)

// eventStateRejected is the event of the node manager for a state that a node
// refused, with the generation in its details.
const eventStateRejected = "node.state_rejected"

// Catalog is what the engine executor asks of the release catalog
// (releases.Catalog).
type Catalog interface {
	InChannel(ctx context.Context, component, channel, version string) (bool, error)
	Ref(ctx context.Context, component, version, arch string) (*nodev1.ArtifactRef, error)
	Prepare(ctx context.Context, component, version string, archs []string) error
}

// Reports is what nodes last reported about their proxies (proxies.Ingestor).
type Reports interface {
	ProxyReport(nodeID, proxyID string) (proxies.ProxyReport, bool)
}

// Writer is the locked write path of the proxies service (proxies.Service).
type Writer interface {
	WriteVersions(ctx context.Context, write func(ctx context.Context) (bump []string, err error)) error
	NotifyChannel(ctx context.Context, component, channel string) error
}

// EngineConfig is what the engine version executor works with.
type EngineConfig struct {
	DB      *store.DB
	Catalog Catalog
	Reports Reports
	Writer  Writer
	Log     *slog.Logger     // nil discards
	Now     func() time.Time // nil is time.Now; the clock of the runner
}

// base is what the executors of rollouts of proxies (engine versions,
// switches) and of providers share: their dependencies, and the steps of
// proxies (apply, check, revert, skip).
type base struct {
	db      *store.DB
	catalog Catalog
	reports Reports
	writer  Writer
	log     *slog.Logger
	now     func() time.Time
}

func newBase(cfg EngineConfig) base {
	b := base{db: cfg.DB, catalog: cfg.Catalog, reports: cfg.Reports, writer: cfg.Writer, log: cfg.Log, now: cfg.Now}
	if b.log == nil {
		b.log = slog.New(slog.DiscardHandler)
	}
	if b.now == nil {
		b.now = time.Now
	}
	return b
}

// EngineVersions is the executor of version rollouts of an engine: a channel
// of telemt or mtg to a version, through the proxies that follow it.
type EngineVersions struct{ base }

var (
	_ Executor = (*EngineVersions)(nil)
	_ Preparer = (*EngineVersions)(nil)
	_ Skipper  = (*EngineVersions)(nil)
)

// NewEngineVersions returns the executor of engine version rollouts.
func NewEngineVersions(cfg EngineConfig) *EngineVersions {
	return &EngineVersions{base: newBase(cfg)}
}

// Apply writes the target version into the proxies of the step.
func (e *EngineVersions) Apply(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error {
	return e.applyStep(ctx, r, s, r.Component, func(*store.Node) (string, error) { return r.ToVersion, nil })
}

// minimumVersion is the lowest version of an engine that a proxy can run, ""
// for any: a WEB proxy with a base path needs telemt 3.5.8 (spec §4).
func minimumVersion(engine string, p *store.Proxy) string {
	if engine == store.EngineTelemt && p.Type == store.ProxyTypeWeb && p.WebBasePath != "" {
		return "3.5.8"
	}
	return ""
}

func (e *base) defaultChannel(ctx context.Context) (string, error) {
	def := store.ChannelStable
	if _, err := e.db.GetSetting(ctx, store.SettingDefaultChannel, &def); err != nil {
		return "", err
	}
	return cmp.Or(def, store.ChannelStable), nil
}

// FollowsEngine reports whether proxy p on node n follows the channel of the
// engine comp: p runs comp with the policy channel, and channel is the one of
// n, or def, the default channel of the panel, when n has none.
func FollowsEngine(n *store.Node, p *store.Proxy, def, comp, channel string) bool {
	return cmp.Or(n.EngineChannel, def) == channel && cmp.Or(p.Engine, store.EngineTelemt) == comp &&
		cmp.Or(p.EngineVersionPolicy, store.EnginePolicyChannel) == store.EnginePolicyChannel
}

// Plan takes the proxies that follow the channel of the engine (policy
// channel, on a node whose channel it is) and refuses a target that is not in
// the channel, has no pinned SHA-256 for an architecture of their nodes, or is
// below the minimum of one of them, and nodes without rollout-status. A
// channel that no proxy follows is errMoveNow, once the target is checked.
func (e *EngineVersions) Plan(ctx context.Context, r *store.Rollout, req *Request) ([]string, []store.RolloutStep, []store.RolloutItem, error) {
	comp, channel, to := r.Component, r.Channel, r.ToVersion
	if !isEngine(comp) {
		return nil, nil, nil, invalid("%.32q is not an engine", comp)
	}
	if channel != store.ChannelStable && channel != store.ChannelLatest {
		return nil, nil, nil, invalid("channel %.32q is not %s or %s", channel, store.ChannelStable, store.ChannelLatest)
	}
	if to == "" {
		return nil, nil, nil, invalid("no version to roll out")
	}
	versions, err := e.db.ChannelVersions(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	from := versions[comp][channel]
	if from == "" {
		return nil, nil, nil, refuse("the %s channel of %s has no version", channel, comp)
	}
	if from == to {
		return nil, nil, nil, refuse("the %s channel of %s is at %s already", channel, comp, to)
	}
	in, err := e.catalog.InChannel(ctx, comp, channel, to)
	if err != nil {
		return nil, nil, nil, err
	}
	if !in {
		return nil, nil, nil, refuse("%s %s is not in the %s channel", comp, to, channel)
	}
	def, err := e.defaultChannel(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	nodes, err := e.db.ListNodes(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	byID := map[string]*store.Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	ps, err := e.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return nil, nil, nil, err
	}
	var cands []candidate
	for _, p := range ps {
		n := byID[p.NodeID]
		if n == nil || !FollowsEngine(n, p, def, comp, channel) {
			continue
		}
		cands = append(cands, candidate{proxy: p, node: n})
	}
	if len(cands) == 0 {
		// Nothing runs the channel: it moves at once (Runner.Start).
		r.FromVersion = from
		return nil, nil, nil, errMoveNow
	}
	var scope []*store.Node
	for _, c := range cands {
		if !slices.Contains(scope, c.node) {
			scope = append(scope, c.node)
		}
	}
	slices.SortFunc(scope, func(a, b *store.Node) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.ID, b.ID))
	})
	var old, noArch, archs []string
	for _, n := range scope {
		if !slices.Contains(n.HostInfo.Capabilities, CapRolloutStatus) {
			old = append(old, n.Name)
		}
		switch {
		case n.Arch == "":
			noArch = append(noArch, n.Name)
		case !slices.Contains(archs, n.Arch):
			archs = append(archs, n.Arch)
		}
	}
	if len(old) > 0 {
		return nil, nil, nil, refuse("upgrade node %s to use rollouts", strings.Join(old, ", "))
	}
	if len(noArch) > 0 {
		return nil, nil, nil, refuse("node %s has not reported its architecture yet", strings.Join(noArch, ", "))
	}
	slices.Sort(archs)
	for _, arch := range archs {
		if _, err := e.catalog.Ref(ctx, comp, to, arch); err != nil {
			if errors.Is(err, releases.ErrNoPin) || errors.Is(err, releases.ErrUnknown) {
				return nil, nil, nil, refuse("%s %s has no pinned SHA-256 for %s; prepare it first", comp, to, arch)
			}
			return nil, nil, nil, err
		}
	}
	for _, c := range cands {
		if minimum := minimumVersion(comp, c.proxy); minimum != "" && release.Compare(to, minimum) < 0 {
			return nil, nil, nil, refuse("proxy %s needs %s %s or later", c.proxy.Name, comp, minimum)
		}
	}
	p, err := proxySteps(cands, req.GetCanaryProxyId())
	if err != nil {
		return nil, nil, nil, err
	}
	r.FromVersion = from
	r.Options.CanaryProxyID, r.Options.CanaryNodeID = p.canary.proxy.ID, p.canary.node.ID
	return p.nodeIDs, p.steps, p.items, nil
}

// itemsOf returns the items of a rollout, those of one step when step ≥ 0.
func (e *base) itemsOf(ctx context.Context, id string, step int64) ([]store.RolloutItem, error) {
	_, _, items, err := e.db.Rollout(ctx, id)
	if err != nil || step < 0 {
		return items, err
	}
	var out []store.RolloutItem
	for _, it := range items {
		if int64(it.StepIndex) == step {
			out = append(out, it)
		}
	}
	return out, nil
}

// Prepare fetches and checks the target for every architecture of the nodes
// of the rollout.
func (e *EngineVersions) Prepare(ctx context.Context, r *store.Rollout) error {
	items, err := e.itemsOf(ctx, r.ID, -1)
	if err != nil {
		return err
	}
	var archs []string
	for _, it := range items {
		n, err := e.db.NodeByID(ctx, it.NodeID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if n.Arch != "" && !slices.Contains(archs, n.Arch) {
			archs = append(archs, n.Arch)
		}
	}
	slices.Sort(archs)
	return e.catalog.Prepare(ctx, r.Component, r.ToVersion, archs)
}

func proxyIDs(items []store.RolloutItem) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.ProxyID
	}
	return out
}

func applied(items []store.RolloutItem) []store.RolloutItem {
	var out []store.RolloutItem
	for _, it := range items {
		if it.State == store.ItemApplied {
			out = append(out, it)
		}
	}
	return out
}

// applyStep writes engine and the version that version gives for the node of
// the step into the enabled proxies of the step and defers its disabled ones
// (one that was applied is reverted first; one deferred before and enabled
// again is taken again), under the lock of the node data, and raises the
// generation of the node of the step, which the step then waits for.
func (e *base) applyStep(ctx context.Context, r *store.Rollout, s *store.RolloutStep, engine string, version func(*store.Node) (string, error)) error {
	items, err := e.itemsOf(ctx, r.ID, int64(s.Index))
	if err != nil {
		return err
	}
	err = e.writer.WriteVersions(ctx, func(ctx context.Context) ([]string, error) {
		n, err := e.db.NodeByID(ctx, s.NodeID)
		if err != nil {
			return nil, err
		}
		target, err := version(n)
		if err != nil {
			return nil, err
		}
		var on, off, again []store.RolloutItem
		for _, it := range items {
			p, err := e.db.ProxyByID(ctx, it.ProxyID)
			switch {
			case errors.Is(err, store.ErrNotFound):
				on = append(on, it) // ApplyItems detaches it
			case err != nil:
				return nil, err
			case p.Enabled:
				on = append(on, it)
				if it.State == store.ItemDeferred {
					again = append(again, it)
				}
			default:
				off = append(off, it)
			}
		}
		if len(again) > 0 {
			if err := e.db.UndeferItems(ctx, r.ID, proxyIDs(again)); err != nil {
				return nil, err
			}
		}
		if len(off) > 0 {
			if back := applied(off); len(back) > 0 {
				if _, err := e.db.RevertItems(ctx, r.ID, back); err != nil {
					return nil, err
				}
			}
			if err := e.db.DeferItems(ctx, r.ID, proxyIDs(off)); err != nil {
				return nil, err
			}
		}
		if len(on) > 0 {
			if _, err := e.db.ApplyItems(ctx, r.ID, on, engine, store.EnginePolicyRollout, target); err != nil {
				return nil, err
			}
		}
		return []string{s.NodeID}, nil
	})
	if err != nil {
		return err
	}
	n, err := e.db.NodeByID(ctx, s.NodeID)
	if err != nil {
		return err
	}
	// The generation that was raised for the write, or a later one: a state
	// of either has the write.
	s.Generation = n.DesiredGeneration
	return nil
}

// stepTimeout is the time a step of n items has, from its start.
func stepTimeout(n int) time.Duration {
	return min(engineStepBase+time.Duration(n)*engineStepPerItem, engineStepMax)
}

func engineName(e nodev1.Engine) string {
	switch e {
	case nodev1.Engine_ENGINE_TELEMT:
		return store.EngineTelemt
	case nodev1.Engine_ENGINE_MTG:
		return store.EngineMtg
	}
	return ""
}

// rejection returns why the node refused a state of the generation gen or
// later, if it did and still does.
func (e *base) rejection(ctx context.Context, n *store.Node, gen uint64) (string, bool, error) {
	if n.StateRejection == "" || n.AppliedGeneration >= gen {
		return "", false, nil
	}
	events, err := e.db.ListEvents(ctx, 200, n.ID)
	if err != nil {
		return "", false, err
	}
	for _, ev := range events {
		if ev.Kind != eventStateRejected {
			continue
		}
		if g, err := strconv.ParseUint(ev.Details["generation"], 10, 64); err == nil && g >= gen {
			return cmp.Or(ev.Message, n.StateRejection), true, nil
		}
	}
	return "", false, nil
}

// Check judges the step from the reports of its node whose generation is the
// step's or later: a refusal of that state fails it, as does a proxy that
// failed the target; every applied proxy serving the target makes it done (a
// step without applied proxies is done once the node has its generation).
// Past its timeout, or with its node offline beyond the grace, it fails (or
// the node is skipped).
func (e *base) Check(ctx context.Context, r *store.Rollout, s *store.RolloutStep) (bool, error) {
	n, err := e.db.NodeByID(ctx, s.NodeID)
	if err != nil {
		return false, err
	}
	items, err := e.itemsOf(ctx, r.ID, int64(s.Index))
	if err != nil {
		return false, err
	}
	gen := s.Generation
	if reason, ok, err := e.rejection(ctx, n, gen); err != nil {
		return false, err
	} else if ok {
		return false, fmt.Errorf("node %s refused its state: %s", n.Name, reason)
	}
	on := applied(items)
	done := len(on) > 0 || n.AppliedGeneration >= gen
	engine := cmp.Or(r.ToEngine, r.Component)
	for _, it := range on {
		rep, ok := e.reports.ProxyReport(n.ID, it.ProxyID)
		if !ok || rep.ReportGeneration < gen {
			done = false
			continue
		}
		// The version the rollout wrote: its target, or for a switch that
		// follows the channel the channel version it wrote at Apply.
		name, version := it.ProxyID, r.ToVersion
		if p, err := e.db.ProxyByID(ctx, it.ProxyID); err == nil {
			name = p.Name
			if version == "" {
				version = p.EngineVersion
			}
		}
		failedTarget := rep.FailedVersion == version && (rep.FailedEngine == nodev1.Engine_ENGINE_UNSPECIFIED || engineName(rep.FailedEngine) == engine)
		if failedTarget || rep.Phase == nodev1.ProxyPhase_PROXY_PHASE_FAILED {
			return false, fmt.Errorf("proxy %s on node %s: %s", name, n.Name, cmp.Or(rep.Reason, "failed"))
		}
		if rep.Phase != nodev1.ProxyPhase_PROXY_PHASE_SERVING || engineName(rep.RunningEngine) != engine || rep.RunningVersion != version {
			done = false
		}
	}
	if done {
		return true, nil
	}
	return false, e.overdue(r, s, n, stepTimeout(len(items)))
}

// overdue is the error of a step that is not done: its node offline for more
// than the grace (ErrSkipNode when the rollout skips offline nodes and the
// step is not one of the canary), or the step past its timeout; nil while
// neither.
func (e *base) overdue(r *store.Rollout, s *store.RolloutStep, n *store.Node, limit time.Duration) error {
	now := e.now()
	if s.StartedAt == nil {
		return nil
	}
	if n.Status != store.NodeStatusOnline {
		since := *s.StartedAt
		if n.LastSeenAt != nil && n.LastSeenAt.After(since) {
			since = *n.LastSeenAt
		}
		if now.Sub(since) > offlineGrace {
			// The node of the canary is never skipped: the other nodes get the
			// version only after a canary that went through.
			if r.Options.SkipOffline && !canaryStep(r, s) {
				return ErrSkipNode
			}
			return fmt.Errorf("node %s is offline for more than %s", n.Name, offlineGrace)
		}
	}
	if now.Sub(*s.StartedAt) > limit {
		return fmt.Errorf("the step did not finish within %s", limit)
	}
	return nil
}

// Revert puts the applied proxies of the step back to what they held.
func (e *base) Revert(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error {
	items, err := e.itemsOf(ctx, r.ID, int64(s.Index))
	if err != nil {
		return err
	}
	return e.writer.WriteVersions(ctx, func(ctx context.Context) ([]string, error) {
		return e.db.RevertItems(ctx, r.ID, items)
	})
}

// Skip leaves the node of the step on its previous version: what was applied
// is reverted, and every item is deferred (pinned at its previous version
// when the rollout completes).
func (e *base) Skip(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error {
	items, err := e.itemsOf(ctx, r.ID, int64(s.Index))
	if err != nil {
		return err
	}
	return e.writer.WriteVersions(ctx, func(ctx context.Context) ([]string, error) {
		var bump []string
		if back := applied(items); len(back) > 0 {
			if bump, err = e.db.RevertItems(ctx, r.ID, back); err != nil {
				return nil, err
			}
		}
		if len(items) > 0 {
			if err := e.db.DeferItems(ctx, r.ID, proxyIDs(items)); err != nil {
				return nil, err
			}
		}
		return bump, nil
	})
}

// Complete moves the channel, settles the items (applied ones follow the
// channel again, deferred ones are pinned at their previous version) in one
// transaction, and tells every node on the channel.
func (e *EngineVersions) Complete(ctx context.Context, r *store.Rollout) error {
	if err := e.completeItems(ctx, r, store.EnginePolicyChannel); err != nil {
		return err
	}
	// The rollout is completed: a failure to tell the nodes is logged, and
	// their next change of state carries the moved channel.
	if err := e.writer.NotifyChannel(ctx, r.Component, r.Channel); err != nil {
		e.log.Error("could not tell the nodes on a channel that it moved", "component", r.Component, "channel", r.Channel, "err", err)
	}
	return nil
}

// canaryStep reports whether a step is one of the canary: the canary proxy,
// or the rest of its node.
func canaryStep(r *store.Rollout, s *store.RolloutStep) bool {
	return s.ProxyID != "" || s.NodeID == r.Options.CanaryNodeID
}

// keptRecorded reports whether the rollout_items_kept event of a rollout is
// stored already: a completion that runs again does not record it twice.
func (e *base) keptRecorded(ctx context.Context, id string) bool {
	has, err := e.db.HasEvent(ctx, EventItemsKept, "rollout", id)
	if err != nil {
		e.log.Error("could not look for a rollout event", "kind", EventItemsKept, "rollout", id, "err", err)
	}
	return has
}

// completeItems completes the rollout (CompleteRollout: a version rollout
// moves its channel; the items are settled with appliedPolicy) under the lock
// of the node data, and records the proxies left on their previous version,
// once.
func (e *base) completeItems(ctx context.Context, r *store.Rollout, appliedPolicy string) error {
	items, err := e.itemsOf(ctx, r.ID, -1)
	if err != nil {
		return err
	}
	var kept []string
	for _, it := range items {
		if it.State == store.ItemDeferred {
			name := it.ProxyID
			if p, err := e.db.ProxyByID(ctx, it.ProxyID); err == nil {
				name = p.Name
			}
			kept = append(kept, name)
		}
	}
	err = e.writer.WriteVersions(ctx, func(ctx context.Context) ([]string, error) {
		return e.db.CompleteRollout(ctx, r.ID, appliedPolicy)
	})
	if err != nil {
		return err
	}
	if len(kept) > 0 && !e.keptRecorded(ctx, r.ID) {
		ev := &store.Event{
			TS: e.now(), Kind: EventItemsKept, Severity: "warning",
			Message: fmt.Sprintf("proxies kept on what they ran before the rollout of %s: %s", cmp.Or(r.ToEngine, r.Component), strings.Join(kept, ", ")),
			Details: map[string]string{"rollout": r.ID, "component": r.Component, "proxies": strings.Join(kept, ",")},
		}
		if err := e.db.AppendEvent(context.WithoutCancel(ctx), ev); err != nil {
			e.log.Error("could not record a rollout event", "kind", EventItemsKept, "rollout", r.ID, "err", err)
		}
	}
	return nil
}
