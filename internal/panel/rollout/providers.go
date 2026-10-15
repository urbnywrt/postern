package rollout

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// providerStepTimeout is the time a step of a provider rollout has.
const providerStepTimeout = 10 * time.Minute

// The phases of an egress instance that Check reads.
const (
	phaseServing = "serving"
	phaseFailed  = "failed"
)

// ProviderNodes says which providers a node runs (proxies.Service).
type ProviderNodes interface {
	NodeProviders(ctx context.Context, nodeID string) ([]string, error)
}

// EgressReports are what nodes last reported of their egress instances
// (proxies.Ingestor).
type EgressReports interface {
	EgressReports(nodeID string) []proxies.EgressReport
}

// ProviderVersions is the executor of version rollouts of a provider (xray,
// psiphon-core): a channel to a version, node by node. A step pins the version on
// its node (Node.ProviderVersions); the completion moves the channel and lets
// the nodes that went through follow it again, while a skipped node keeps the
// version it had pinned.
type ProviderVersions struct {
	base
	nodes  ProviderNodes
	egress EgressReports
}

var (
	_ Executor = (*ProviderVersions)(nil)
	_ Preparer = (*ProviderVersions)(nil)
	_ Skipper  = (*ProviderVersions)(nil)
)

// NewProviderVersions returns the executor of provider version rollouts.
func NewProviderVersions(cfg EngineConfig, nodes ProviderNodes, egress EgressReports) *ProviderVersions {
	return &ProviderVersions{base: newBase(cfg), nodes: nodes, egress: egress}
}

func isProvider(component string) bool {
	return component == proxies.EngineXray || component == proxies.EnginePsiphonCore
}

// Plan takes the nodes on the channel that run an egress of the provider and
// follow the channel for it (no version of their own), and refuses a target
// that is not in the channel or has no pinned SHA-256 for their
// architectures, and nodes without rollout-status. The canary node goes
// first: the one given, else the first online node by name.
func (e *ProviderVersions) Plan(ctx context.Context, r *store.Rollout, req *Request) ([]string, []store.RolloutStep, []store.RolloutItem, error) {
	comp, channel, to := r.Component, r.Channel, r.ToVersion
	if !isProvider(comp) {
		return nil, nil, nil, invalid("%.32q is not a provider", comp)
	}
	if channel != store.ChannelStable && channel != store.ChannelLatest {
		return nil, nil, nil, invalid("channel %.32q is not %s or %s", channel, store.ChannelStable, store.ChannelLatest)
	}
	if to == "" {
		return nil, nil, nil, invalid("no version to roll out")
	}
	ch, err := e.channels(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	from := ch.versions[comp][channel]
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
	all, err := e.db.ListNodes(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	var scope []*store.Node
	for _, n := range all {
		if cmp.Or(n.EngineChannel, ch.def) != channel || n.ProviderVersions[comp] != "" {
			continue
		}
		runs, err := e.nodes.NodeProviders(ctx, n.ID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("the providers of node %s: %w", n.Name, err)
		}
		if slices.Contains(runs, comp) {
			scope = append(scope, n)
		}
	}
	if len(scope) == 0 {
		return nil, nil, nil, refuse("no node on the %s channel runs %s", channel, comp)
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
		if _, err := e.catalog.Ref(ctx, comp, to, n.Arch); err != nil {
			if errors.Is(err, releases.ErrNoPin) || errors.Is(err, releases.ErrUnknown) {
				return nil, nil, nil, refuse("%s %s has no pinned SHA-256 for %s; prepare it first", comp, to, n.Arch)
			}
			return nil, nil, nil, err
		}
	}
	var at int
	if id := req.GetCanaryNodeId(); id != "" {
		if at = slices.IndexFunc(scope, func(n *store.Node) bool { return n.ID == id }); at < 0 {
			return nil, nil, nil, invalid("the canary node %.40q is not one that the rollout changes", id)
		}
	} else if at = slices.IndexFunc(scope, func(n *store.Node) bool { return n.Status == store.NodeStatusOnline }); at < 0 {
		return nil, nil, nil, refuse("no node of the rollout is online to go first")
	}
	order := append([]*store.Node{scope[at]}, slices.Delete(slices.Clone(scope), at, at+1)...)
	nodeIDs := make([]string, len(order))
	steps := make([]store.RolloutStep, len(order))
	for i, n := range order {
		nodeIDs[i] = n.ID
		steps[i] = store.RolloutStep{Index: uint32(i), NodeID: n.ID}
	}
	r.FromVersion = from
	r.Options.CanaryNodeID = scope[at].ID
	return nodeIDs, steps, nil, nil
}

// Prepare fetches and checks the target for the architectures of the nodes.
func (e *ProviderVersions) Prepare(ctx context.Context, r *store.Rollout) error {
	_, steps, _, err := e.db.Rollout(ctx, r.ID)
	if err != nil {
		return err
	}
	var archs []string
	for _, s := range steps {
		n, err := e.db.NodeByID(ctx, s.NodeID)
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

// foreign reports whether a node has a version of its own for the provider
// that the rollout did not set: an admin set it after the rollout was planned.
// The rollout leaves such a node alone.
func foreign(r *store.Rollout, n *store.Node) (string, bool) {
	v := n.ProviderVersions[r.Component]
	return v, v != "" && v != r.ToVersion
}

// setVersion sets the version of the provider on the node of the step ("" to
// follow the channel again) under the lock of the node data, and raises its
// generation; only while the node has no version of its own that the rollout
// did not set (foreign). It reports whether it wrote.
func (e *ProviderVersions) setVersion(ctx context.Context, r *store.Rollout, s *store.RolloutStep, version string) (bool, error) {
	wrote := false
	err := e.writer.WriteVersions(ctx, func(ctx context.Context) ([]string, error) {
		n, err := e.db.NodeByID(ctx, s.NodeID)
		if err != nil {
			return nil, err
		}
		if _, ok := foreign(r, n); ok {
			return nil, nil
		}
		if err := e.db.SetNodeProviderVersion(ctx, s.NodeID, r.Component, version); err != nil {
			return nil, err
		}
		wrote = true
		return []string{s.NodeID}, nil
	})
	return wrote, err
}

// Apply pins the target on the node of the step. A node that an admin gave a
// version of its own since the rollout was planned is left alone, with an
// event that says so, and its step is done at once (Check).
func (e *ProviderVersions) Apply(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error {
	wrote, err := e.setVersion(ctx, r, s, r.ToVersion)
	if err != nil {
		return err
	}
	n, err := e.db.NodeByID(ctx, s.NodeID)
	if err != nil {
		return err
	}
	s.Generation = n.DesiredGeneration
	if v, ok := foreign(r, n); !wrote && ok {
		ev := &store.Event{
			TS: e.now(), NodeID: n.ID, Kind: EventNodeKept, Severity: "warning",
			Message: fmt.Sprintf("node %s has %s %s of its own, set after the rollout was planned; the rollout leaves it alone", n.Name, r.Component, v),
			Details: map[string]string{"rollout": r.ID, "component": r.Component, "version": v},
		}
		if err := e.db.AppendEvent(context.WithoutCancel(ctx), ev); err != nil {
			e.log.Error("could not record a rollout event", "kind", EventNodeKept, "rollout", r.ID, "err", err)
		}
	}
	return nil
}

// Check judges the step from the egress instances of the provider that the
// node reported in a state of the generation of the step or later: one that
// failed the target, or failed, fails the step; every one serving the target
// makes it done. Without a report of the provider (the reports are kept in
// memory: a panel that restarted has none until the node reports again) the
// step waits, unless the node no longer runs the provider at all. A node left
// alone (foreign) is done at once.
func (e *ProviderVersions) Check(ctx context.Context, r *store.Rollout, s *store.RolloutStep) (bool, error) {
	n, err := e.db.NodeByID(ctx, s.NodeID)
	if err != nil {
		return false, err
	}
	if _, ok := foreign(r, n); ok {
		return true, nil
	}
	gen := s.Generation
	if reason, ok, err := e.rejection(ctx, n, gen); err != nil {
		return false, err
	} else if ok {
		return false, fmt.Errorf("node %s refused its state: %s", n.Name, reason)
	}
	done := n.AppliedGeneration >= gen
	reported := false
	for _, rep := range e.egress.EgressReports(n.ID) {
		if rep.Provider != r.Component {
			continue
		}
		reported = true
		if rep.ReportGeneration < gen {
			done = false
			continue
		}
		if rep.FailedVersion == r.ToVersion || rep.Phase == phaseFailed {
			return false, fmt.Errorf("%s of egress %s on node %s: %s", r.Component, rep.EgressID, n.Name, cmp.Or(rep.Reason, "failed"))
		}
		if rep.Phase != phaseServing || rep.Version != r.ToVersion {
			done = false
		}
	}
	if done && !reported {
		runs, err := e.nodes.NodeProviders(ctx, n.ID)
		if err != nil {
			return false, err
		}
		done = !slices.Contains(runs, r.Component)
	}
	if done {
		return true, nil
	}
	return false, e.overdue(r, s, n, providerStepTimeout)
}

// Revert lets the node follow the channel again (it followed it before), as
// long as the version it has is the one the rollout set.
func (e *ProviderVersions) Revert(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error {
	_, err := e.setVersion(ctx, r, s, "")
	return err
}

// Skip keeps the node at the version it ran: pinned at the version the
// channel had, which it keeps when the channel moves.
func (e *ProviderVersions) Skip(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error {
	_, err := e.setVersion(ctx, r, s, r.FromVersion)
	return err
}

// Complete moves the channel, lets the nodes that went through follow it
// again (a skipped node keeps its version), and tells every node on the
// channel.
func (e *ProviderVersions) Complete(ctx context.Context, r *store.Rollout) error {
	_, steps, _, err := e.db.Rollout(ctx, r.ID)
	if err != nil {
		return err
	}
	err = e.writer.WriteVersions(ctx, func(ctx context.Context) ([]string, error) {
		if _, err := e.db.CompleteRollout(ctx, r.ID, store.EnginePolicyChannel); err != nil {
			return nil, err
		}
		var bump []string
		for _, s := range steps {
			if s.Status != store.StepDone {
				continue
			}
			n, err := e.db.NodeByID(ctx, s.NodeID)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if n.ProviderVersions[r.Component] != r.ToVersion {
				continue // changed by someone else, or done already
			}
			if err := e.db.SetNodeProviderVersion(ctx, n.ID, r.Component, ""); err != nil {
				return nil, err
			}
			bump = append(bump, n.ID)
		}
		return bump, nil
	})
	if err != nil {
		return err
	}
	if err := e.writer.NotifyChannel(ctx, r.Component, r.Channel); err != nil {
		e.log.Error("could not tell the nodes on a channel that it moved", "component", r.Component, "channel", r.Channel, "err", err)
	}
	return nil
}
