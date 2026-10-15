// Package nodeupdate is the executor of node rollouts: it updates the agent
// and the edge of nodes to a signed Postern release, node by node, through the
// node's UpdateSelf and UpdateEdge (Global Constraints, Self-update; R5-3).
package nodeupdate

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/rollout"
	"github.com/urbnywrt/postern/internal/panel/selfupdate"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/version"
)

// The capabilities of a node that a node rollout needs.
const (
	CapUpdateSelf = "update-self"
	CapUpdateEdge = "update-edge"
)

// The limits of a step (Global Constraints, Rollouts: 10 min for the agent, 5
// to upload and 5 until it is healthy, and 3 min for the edge).
const (
	defaultUploadTimeout = 5 * time.Minute
	defaultHealthTimeout = 5 * time.Minute
	defaultEdgeTimeout   = 3 * time.Minute
	defaultPoll          = 2 * time.Second
	offlineGrace         = 5 * time.Minute
)

// errRestarted is the failure of a step whose node rolled back or restarted
// while the step ran or in the pause after it.
const errRestarted = "the node rolled back or restarted"

// Nodes is the connection manager of the panel (nodes.Manager).
type Nodes interface {
	Client(nodeID string) (nodev1connect.NodeServiceClient, error)
	AgentSignal(nodeID string) nodes.AgentSignal
	// StoreInfo keeps what an answer of GetInfo says in the record of the node.
	StoreInfo(ctx context.Context, nodeID string, info *nodev1.GetInfoResponse) error
}

// Binaries gives the signed node binaries (nodes.PanelKit).
type Binaries interface {
	// Known says, without a download, whether the binary of the version for
	// arch can be had: nil when the image kit is that version, signed, or
	// when the cache of releases can fetch it.
	Known(version, arch string) error
	// Signed opens the signed binary of the version for arch and its
	// signature, fetching it on demand.
	Signed(ctx context.Context, version, arch string) (io.ReadCloser, []byte, error)
}

// Config is what the executor works with.
type Config struct {
	DB       *store.DB
	Nodes    Nodes
	Binaries Binaries
	// PanelVersion is the version of the running panel; "" is version.Version.
	PanelVersion string
	Log          *slog.Logger     // nil discards
	Now          func() time.Time // nil is time.Now
	// Poll is how often a wait asks the node; 0 is 2 s.
	Poll time.Duration
	// The limits of the phases of a step; 0 is the default (5 min, 5 min,
	// 3 min). Tests make them short.
	UploadTimeout, HealthTimeout, EdgeTimeout time.Duration
}

// Executor is the executor of node rollouts (rollout.KeyNode). Each step
// updates one node: the agent (UpdateSelf, then the wait until the node
// answers healthy on the target), then the edge (UpdateEdge, then the edge
// reports the target). It does that in a job of its own, which Check looks
// at, so that a long upload holds no lock of the runner. Nothing is reverted:
// the launcher and the edge handoff cancel a failed update themselves.
type Executor struct {
	cfg Config

	mu   sync.Mutex
	jobs map[string]*job // by rollout and step
}

var (
	_ rollout.Executor = (*Executor)(nil)
	_ rollout.Preparer = (*Executor)(nil)
	_ rollout.Skipper  = (*Executor)(nil)
)

// New returns the executor of node rollouts.
func New(cfg Config) *Executor {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PanelVersion == "" {
		cfg.PanelVersion = version.Version
	}
	cfg.Poll = cmp.Or(cfg.Poll, defaultPoll)
	cfg.UploadTimeout = cmp.Or(cfg.UploadTimeout, defaultUploadTimeout)
	cfg.HealthTimeout = cmp.Or(cfg.HealthTimeout, defaultHealthTimeout)
	cfg.EdgeTimeout = cmp.Or(cfg.EdgeTimeout, defaultEdgeTimeout)
	return &Executor{cfg: cfg, jobs: map[string]*job{}}
}

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", rollout.ErrRefused, fmt.Sprintf(format, args...))
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", rollout.ErrInvalid, fmt.Sprintf(format, args...))
}

// needs says what a rollout to version with the options does on a node.
func needs(o store.RolloutOptions, n *store.Node, to string) (agent, edge bool) {
	return o.Agent && n.AgentVersion != to, o.Edge && n.EdgeVersion != to
}

// Plan checks a node rollout: the target is a version that the panel can
// send (never above the panel's version nor below its previous minor, and
// older than a node's agent only as the rollback to its recorded previous
// version), and every node it changes has the capabilities and, for an
// edge-only update, the agent binary of the target. The canary node goes
// first: the one given, else the first online node by name. A node that runs
// the target already is left out.
func (e *Executor) Plan(ctx context.Context, r *store.Rollout, req *rollout.Request) ([]string, []store.RolloutStep, []store.RolloutItem, error) {
	switch r.Component {
	case "":
		r.Component = selfupdate.ComponentPostern
	case selfupdate.ComponentPostern:
	default:
		return nil, nil, nil, invalid("a node rollout is of %s, not %.32q", selfupdate.ComponentPostern, r.Component)
	}
	if !r.Options.Agent && !r.Options.Edge {
		return nil, nil, nil, invalid("a node rollout updates the agent, the edge or both")
	}
	pv := e.cfg.PanelVersion
	to := cmp.Or(r.ToVersion, pv)
	if !release.ValidVersion(to) {
		return nil, nil, nil, invalid("%.64q is not a version", to)
	}
	r.ToVersion = to
	if release.Compare(to, pv) > 0 {
		return nil, nil, nil, refuse("%s is above the version of the panel (%s): a node never runs a newer version than its panel", to, pv)
	}
	if floor, ok := selfupdate.MinorFloor(pv); ok && release.Compare(to, floor) < 0 {
		return nil, nil, nil, refuse("%s is below %s, the previous minor of the panel's version %s", to, floor, pv)
	}
	scope, err := e.scope(ctx, req.GetNodeIds())
	if err != nil {
		return nil, nil, nil, err
	}
	var plan, old []*store.Node
	for _, n := range scope {
		agent, edge := needs(r.Options, n, to)
		if !agent && !edge {
			continue
		}
		caps := n.HostInfo.Capabilities
		if (agent && !slices.Contains(caps, CapUpdateSelf)) || (edge && !slices.Contains(caps, CapUpdateEdge)) {
			old = append(old, n)
			continue
		}
		plan = append(plan, n)
	}
	if len(old) > 0 {
		return nil, nil, nil, refuse("node %s cannot update itself: update them once with install.sh and the node kit", names(old))
	}
	if len(plan) == 0 {
		return nil, nil, nil, refuse("every node of the rollout runs %s already", to)
	}
	for _, n := range plan {
		if err := e.checkNode(r, n, to); err != nil {
			return nil, nil, nil, err
		}
	}
	at := 0
	if id := req.GetCanaryNodeId(); id != "" {
		if at = slices.IndexFunc(plan, func(n *store.Node) bool { return n.ID == id }); at < 0 {
			return nil, nil, nil, invalid("the canary node %.40q is not one that the rollout changes", id)
		}
	} else if at = slices.IndexFunc(plan, func(n *store.Node) bool { return n.Status == store.NodeStatusOnline }); at < 0 {
		return nil, nil, nil, refuse("no node of the rollout is online to go first")
	}
	order := append([]*store.Node{plan[at]}, slices.Delete(slices.Clone(plan), at, at+1)...)
	nodeIDs := make([]string, len(order))
	steps := make([]store.RolloutStep, len(order))
	for i, n := range order {
		nodeIDs[i] = n.ID
		steps[i] = store.RolloutStep{Index: uint32(i), NodeID: n.ID}
	}
	r.Options.CanaryNodeID = plan[at].ID
	return nodeIDs, steps, nil, nil
}

// scope returns the nodes of the rollout, sorted by name: the ones given,
// else every node.
func (e *Executor) scope(ctx context.Context, ids []string) ([]*store.Node, error) {
	all, err := e.cfg.DB.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	var scope []*store.Node
	if len(ids) == 0 {
		scope = all
	} else {
		for _, id := range ids {
			i := slices.IndexFunc(all, func(n *store.Node) bool { return n.ID == id })
			if i < 0 {
				return nil, invalid("there is no node %.40q", id)
			}
			if !slices.Contains(scope, all[i]) {
				scope = append(scope, all[i])
			}
		}
	}
	slices.SortFunc(scope, func(a, b *store.Node) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.ID, b.ID))
	})
	return scope, nil
}

// checkNode refuses what one node cannot take: an agent older than the one
// it runs that is not its recorded previous version, an architecture that is
// not known or whose binary the panel cannot have, and an edge-only update to
// a version whose agent binary the node does not hold, or holds without its
// kept signature (unless it is the running agent's own).
func (e *Executor) checkNode(r *store.Rollout, n *store.Node, to string) error {
	agent, edge := needs(r.Options, n, to)
	if agent {
		if release.Compare(to, n.AgentVersion) < 0 && to != n.HostInfo.Binaries.Previous {
			return refuse("node %s runs agent %s: it goes back only to its previous version (%s), not to %s",
				n.Name, n.AgentVersion, cmp.Or(n.HostInfo.Binaries.Previous, "none"), to)
		}
		if n.Arch == "" {
			return refuse("node %s has not reported its architecture yet", n.Name)
		}
		if err := e.cfg.Binaries.Known(to, n.Arch); err != nil {
			return refuse("the panel has no signed node binary %s for %s: %v", to, n.Arch, err)
		}
	}
	if edge && !r.Options.Agent && n.AgentVersion != to {
		if !slices.Contains(n.HostInfo.Binaries.Versions, to) {
			return refuse("node %s has no agent binary %s installed for its edge: update its agent first", n.Name, to)
		}
		// The node rolls its edge only to a binary whose signature it kept
		// (UpdateSelf and install.sh keep one), or to its agent's own.
		if !slices.Contains(n.HostInfo.Binaries.Signed, to) {
			return refuse("node %s has no signature kept for its agent binary %s, which its edge needs: update its agent and edge together to %s",
				n.Name, to, to)
		}
	}
	return nil
}

func names(list []*store.Node) string {
	out := make([]string, len(list))
	for i, n := range list {
		out[i] = n.Name
	}
	return strings.Join(out, ", ")
}

// Prepare fetches the binary of the target for the architectures of the
// nodes whose agent the rollout updates, and checks it.
func (e *Executor) Prepare(ctx context.Context, r *store.Rollout) error {
	if !r.Options.Agent {
		return nil
	}
	_, steps, _, err := e.cfg.DB.Rollout(ctx, r.ID)
	if err != nil {
		return err
	}
	var archs []string
	for _, s := range steps {
		n, err := e.cfg.DB.NodeByID(ctx, s.NodeID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if agent, _ := needs(r.Options, n, r.ToVersion); agent && n.Arch != "" && !slices.Contains(archs, n.Arch) {
			archs = append(archs, n.Arch)
		}
	}
	slices.Sort(archs)
	for _, arch := range archs {
		rc, _, err := e.cfg.Binaries.Signed(ctx, r.ToVersion, arch)
		if err != nil {
			return err
		}
		_ = rc.Close()
	}
	return nil
}

func jobKey(r *store.Rollout, s *store.RolloutStep) string {
	return fmt.Sprintf("%s/%d", r.ID, s.Index)
}

// Apply starts the step: the node of the step before it must not have rolled
// back or restarted in the pause after it. The update itself runs in the job
// that Check starts. The step's generation is the node's desired one (the
// step writes none): a mark that Apply ran.
func (e *Executor) Apply(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error {
	if s.Index > 0 {
		prev := &store.RolloutStep{Index: s.Index - 1}
		if j := e.job(jobKey(r, prev)); j != nil {
			err := j.watchErr(e.cfg.Nodes)
			e.drop(jobKey(r, prev))
			if err != nil {
				return fmt.Errorf("node %s of the step before, after its update: %w", j.nodeName, err)
			}
		}
	}
	n, err := e.cfg.DB.NodeByID(ctx, s.NodeID)
	if err != nil {
		return err
	}
	s.Generation = max(n.DesiredGeneration, 1)
	return nil
}

func (e *Executor) job(key string) *job {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.jobs[key]
}

// drop stops the job of a step and forgets it.
func (e *Executor) drop(key string) {
	e.mu.Lock()
	j := e.jobs[key]
	delete(e.jobs, key)
	e.mu.Unlock()
	if j != nil {
		j.cancel()
	}
}

// Check starts the job of the step when none runs (a panel that restarted
// starts it again: what is done already is not done twice) and judges it: a
// job that failed, or a node that rolled back or restarted, fails the step;
// one that is through is done, after the last step only once the pause of
// the rollout passed without a restart. A node offline for longer than the
// grace fails the step, or skips it when the rollout skips offline nodes.
func (e *Executor) Check(ctx context.Context, r *store.Rollout, s *store.RolloutStep) (bool, error) {
	n, err := e.cfg.DB.NodeByID(ctx, s.NodeID)
	if err != nil {
		return false, err
	}
	key := jobKey(r, s)
	e.mu.Lock()
	j := e.jobs[key]
	if j == nil {
		_, steps, _, err := e.cfg.DB.Rollout(ctx, r.ID)
		if err != nil {
			e.mu.Unlock()
			return false, err
		}
		j = e.startJob(ctx, r, n, int(s.Index) == len(steps)-1)
		e.jobs[key] = j
	}
	e.mu.Unlock()

	if err := j.result(); err != nil {
		return false, err
	}
	if err := j.watchErr(e.cfg.Nodes); err != nil {
		return false, err
	}
	if at, ok := j.finished(); ok {
		hold := time.Duration(r.PauseSeconds) * time.Second
		if !j.last || e.cfg.Now().Sub(at) >= hold {
			return true, nil
		}
		return false, nil
	}
	return false, e.offline(r, s, n)
}

// offline is the error of a step whose node is offline for more than the
// grace: rollout.ErrSkipNode when the rollout skips offline nodes (the runner
// never skips the canary).
func (e *Executor) offline(r *store.Rollout, s *store.RolloutStep, n *store.Node) error {
	if n.Status == store.NodeStatusOnline || s.StartedAt == nil {
		return nil
	}
	since := *s.StartedAt
	if n.LastSeenAt != nil && n.LastSeenAt.After(since) {
		since = *n.LastSeenAt
	}
	if e.cfg.Now().Sub(since) <= offlineGrace {
		return nil
	}
	if r.Options.SkipOffline {
		return rollout.ErrSkipNode
	}
	return fmt.Errorf("node %s is offline for more than %s", n.Name, offlineGrace)
}

// Revert stops the job of the step. Nothing else is undone: a failed agent
// update is rolled back by the launcher, and a failed edge roll leaves the old
// edge serving.
func (e *Executor) Revert(_ context.Context, r *store.Rollout, s *store.RolloutStep) error {
	e.drop(jobKey(r, s))
	return nil
}

// Skip stops the job of the step whose node is offline: the node stays on
// what it runs.
func (e *Executor) Skip(_ context.Context, r *store.Rollout, s *store.RolloutStep) error {
	e.drop(jobKey(r, s))
	return nil
}

// Complete forgets the jobs of the rollout; there is nothing to settle.
func (e *Executor) Complete(_ context.Context, r *store.Rollout) error {
	e.mu.Lock()
	var keys []string
	for k := range e.jobs {
		if strings.HasPrefix(k, r.ID+"/") {
			keys = append(keys, k)
		}
	}
	e.mu.Unlock()
	for _, k := range keys {
		e.drop(k)
	}
	return nil
}

// job is the update of one node.
type job struct {
	nodeID, nodeName string
	to               string
	agent            bool // the rollout updates the agent: a reconnection on another version fails the step
	last             bool // the last step: the pause is held in Check
	cancel           context.CancelFunc

	mu    sync.Mutex
	base  *nodes.AgentSignal // what the manager had seen when the job started; nil before
	allow uint64             // agent starts that the update brings: 1 after UpdateSelf
	// uploaded says that an UpdateSelf upload started; connects is the count
	// of connections then. A reconnection before it (a network blip) is to the
	// agent that still runs the old version, and no restart.
	uploaded bool
	connects uint64
	err      error
	doneAt   time.Time
	through  bool
}

func (j *job) result() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.err
}

func (j *job) finished() (time.Time, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.doneAt, j.through
}

// watchErr says whether the node rolled back or restarted since the job
// started, beyond the one start that its UpdateSelf brings, or reconnected on
// another version than the target of an agent update after its upload started.
func (j *job) watchErr(m Nodes) error {
	j.mu.Lock()
	base, allow, uploaded, connects := j.base, j.allow, j.uploaded, j.connects
	j.mu.Unlock()
	if base == nil {
		return nil
	}
	now := m.AgentSignal(j.nodeID)
	switch {
	case now.RolledBack > base.RolledBack:
		return fmt.Errorf("%s: the launcher rolled the agent back", errRestarted)
	case now.Starts > base.Starts+allow:
		return fmt.Errorf("%s: the agent started again", errRestarted)
	case j.agent && uploaded && now.Connects > connects && now.Version != "" && now.Version != j.to:
		return fmt.Errorf("%s: it reconnected with agent %s, not %s", errRestarted, now.Version, j.to)
	}
	return nil
}

// startJob starts the update of the node of a step. Called with e.mu held.
func (e *Executor) startJob(ctx context.Context, r *store.Rollout, n *store.Node, last bool) *job {
	ctx, cancel := context.WithCancel(ctx)
	j := &job{nodeID: n.ID, nodeName: n.Name, to: r.ToVersion, agent: r.Options.Agent, last: last, cancel: cancel}
	opts := r.Options
	go func() {
		err := e.run(ctx, j, opts, n.Arch)
		if ctx.Err() != nil && err != nil {
			return // stopped: the runner stops, or the step was dropped
		}
		j.mu.Lock()
		defer j.mu.Unlock()
		if err != nil {
			if j.err == nil {
				j.err = err
			}
			return
		}
		j.through, j.doneAt = true, e.cfg.Now()
	}()
	return j
}

// run updates the node: its agent, then its edge.
func (e *Executor) run(ctx context.Context, j *job, o store.RolloutOptions, arch string) error {
	base := e.cfg.Nodes.AgentSignal(j.nodeID)
	j.mu.Lock()
	j.base = &base
	j.mu.Unlock()
	log := e.cfg.Log.With("node", j.nodeID, "to", j.to)

	info, err := e.ask(ctx, j, time.Now().Add(e.cfg.UploadTimeout), func(*nodev1.GetInfoResponse) bool { return true })
	if err != nil {
		return fmt.Errorf("the node did not answer: %w", err)
	}
	if o.Agent {
		if info.GetAgentVersion() != j.to {
			if err := e.updateAgent(ctx, j, info, arch); err != nil {
				return err
			}
			log.Info("the node installed the agent; waiting for it to be healthy")
		}
		if _, err := e.ask(ctx, j, time.Now().Add(e.cfg.HealthTimeout), func(i *nodev1.GetInfoResponse) bool {
			return i.GetAgentVersion() == j.to && i.GetHealthy()
		}); err != nil {
			return fmt.Errorf("the agent did not answer healthy on %s within %s: %w", j.to, e.cfg.HealthTimeout, err)
		}
		log.Info("the agent is healthy on the target")
	}
	if o.Edge {
		if err := e.updateEdge(ctx, j); err != nil {
			return err
		}
		log.Info("the edge runs the target")
	}
	return nil
}

// ask asks the node about itself every poll until ok holds of its answer, the
// deadline passes, or the node rolled back or restarted. A node that is not
// connected, or does not answer, is asked again: an agent that restarts, and a
// panel that finds its path again (hidden management), take a while.
func (e *Executor) ask(ctx context.Context, j *job, deadline time.Time, ok func(*nodev1.GetInfoResponse) bool) (*nodev1.GetInfoResponse, error) {
	var last error
	for {
		if err := j.watchErr(e.cfg.Nodes); err != nil {
			return nil, err
		}
		if c, err := e.cfg.Nodes.Client(j.nodeID); err != nil {
			last = err
		} else {
			callCtx, cancel := context.WithTimeout(ctx, max(e.cfg.Poll, 10*time.Second))
			info, err := getInfo(callCtx, c)
			cancel()
			if err == nil {
				if serr := e.cfg.Nodes.StoreInfo(ctx, j.nodeID, info); serr != nil && ctx.Err() == nil {
					e.cfg.Log.Error("could not store the info of a node", "node", j.nodeID, "err", serr)
				}
				if ok(info) {
					return info, nil
				}
			}
			last = cmp.Or(err, last)
		}
		if !time.Now().Before(deadline) {
			if last == nil {
				last = errors.New("its answers did not change")
			}
			return nil, last
		}
		if !sleep(ctx, e.cfg.Poll) {
			return nil, ctx.Err()
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// updateAgent sends the signed binary of the target with UpdateSelf, within
// the upload timeout, and expects the node to restart into it. rollback is
// set only for the node's recorded previous version, older than its agent.
func (e *Executor) updateAgent(ctx context.Context, j *job, info *nodev1.GetInfoResponse, arch string) error {
	ctx, cancel := context.WithTimeout(ctx, e.cfg.UploadTimeout)
	defer cancel()
	arch = cmp.Or(info.GetArch(), arch)
	running := info.GetAgentVersion()
	rollback := info.GetBinaries().GetPrevious() == j.to && release.Compare(j.to, running) < 0
	for {
		rc, sig, err := e.cfg.Binaries.Signed(ctx, j.to, arch)
		if err != nil {
			return fmt.Errorf("the binary of %s for %s: %w", j.to, arch, err)
		}
		resp, err := e.sendAgent(ctx, j, rc, sig, arch, rollback)
		_ = rc.Close()
		if err == nil {
			if !resp.GetRestarting() && resp.GetVersion() != j.to {
				return fmt.Errorf("the node installed %s, not %s", resp.GetVersion(), j.to)
			}
			return nil
		}
		if !transient(err) && !errors.Is(err, nodes.ErrNotConnected) {
			return fmt.Errorf("the node refused agent %s: %s: %s", j.to, connect.CodeOf(err), messageOf(err))
		}
		if !sleep(ctx, e.cfg.Poll) {
			return fmt.Errorf("the node did not take agent %s within %s: %w", j.to, e.cfg.UploadTimeout, err)
		}
	}
}

func (e *Executor) sendAgent(ctx context.Context, j *job, rc io.Reader, sig []byte, arch string, rollback bool) (*nodev1.UpdateSelfResponse, error) {
	c, err := e.cfg.Nodes.Client(j.nodeID)
	if err != nil {
		return nil, err
	}
	b, err := measure(rc)
	if err != nil {
		return nil, err
	}
	meta := &nodev1.NodeBinary{Version: j.to, Arch: arch, Sha256: b.sha, Size: b.size, Signature: string(sig), Rollback: rollback}
	// The agent restarts after it answers: from here on one start is its, and
	// a reconnection on another version than the target is a failed update.
	connects := e.cfg.Nodes.AgentSignal(j.nodeID).Connects
	j.mu.Lock()
	j.allow, j.uploaded, j.connects = 1, true, connects
	j.mu.Unlock()
	return updateSelf(ctx, c, meta, b)
}

// updateEdge rolls the edge to the target with UpdateEdge, within the edge
// timeout, and waits until the node reports the edge on it. A busy node
// (Unavailable) is asked again; an aborted roll fails the step.
func (e *Executor) updateEdge(ctx context.Context, j *job) error {
	deadline := time.Now().Add(e.cfg.EdgeTimeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	for {
		info, err := e.ask(ctx, j, deadline, func(*nodev1.GetInfoResponse) bool { return true })
		if err != nil {
			return fmt.Errorf("the edge did not roll to %s within %s: %w", j.to, e.cfg.EdgeTimeout, err)
		}
		if info.GetEdgeVersion() == j.to {
			return nil
		}
		c, err := e.cfg.Nodes.Client(j.nodeID)
		if err == nil {
			_, err = updateEdge(ctx, c, j.to, release.Compare(j.to, info.GetEdgeVersion()) < 0)
		}
		switch {
		case err == nil:
			if _, err := e.ask(ctx, j, deadline, func(i *nodev1.GetInfoResponse) bool { return i.GetEdgeVersion() == j.to }); err != nil {
				return fmt.Errorf("the node did not report its edge on %s within %s: %w", j.to, e.cfg.EdgeTimeout, err)
			}
			return nil
		case connect.CodeOf(err) == connect.CodeAborted:
			return fmt.Errorf("the edge did not roll to %s: %s", j.to, messageOf(err))
		case !transient(err) && !errors.Is(err, nodes.ErrNotConnected):
			return fmt.Errorf("the node refused to roll its edge to %s: %s: %s", j.to, connect.CodeOf(err), messageOf(err))
		}
		if !sleep(ctx, e.cfg.Poll) {
			return fmt.Errorf("the edge did not roll to %s within %s: %w", j.to, e.cfg.EdgeTimeout, err)
		}
	}
}

// messageOf is the message of an error of a call, without the code.
func messageOf(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Message()
	}
	return err.Error()
}
