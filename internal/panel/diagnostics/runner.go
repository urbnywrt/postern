// Package diagnostics runs the checks of a node (spec 5.7): the panel's own
// checks and the node's (RunDiagnostics), stores the runs, keeps the light
// checks that the nodes report, and serves them through the
// DiagnosticsService.
package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/panel/geodb"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// The statuses of a result.
const (
	StatusOK   = "ok"
	StatusWarn = "warn"
	StatusFail = "fail"
	StatusSkip = "skip"
)

// The vantages of a result.
const (
	VantagePanel = "panel"
	VantageNode  = "node"
)

// ScopeNode is the scope of every check of every target of a node; a proxy's
// is "proxy:<id>".
const ScopeNode = "node"

const (
	maxSummary     = 200      // bytes of a summary
	maxEvidence    = 2 << 10  // bytes of the evidence of a result
	maxRunEvidence = 64 << 10 // bytes of the evidence of a run or a report
	maxName        = 128      // bytes of the id, layer, target and fix of a result
	maxHint        = 512      // bytes of a hint
	maxResults     = 500      // results of a run or a light report
	// defaultRunTimeout bounds a run: the node's 3 minutes and the panel's
	// own checks before them.
	defaultRunTimeout = 3*time.Minute + 30*time.Second
	// capDiagnostics is the capability of a node that runs RunDiagnostics.
	capDiagnostics = "diagnostics"
)

// Errors of the runner.
var (
	// ErrScope is a scope that is not "node" or "proxy:<id>" of a proxy of
	// the node.
	ErrScope = errors.New("diagnostics: the scope is \"node\" or \"proxy:<id>\" of a proxy of the node")
	// ErrReason is a reason that is not manual, before_change or after_change.
	ErrReason = errors.New("diagnostics: unknown reason")
	// errTooMany ends a run whose node sent more than maxResults results.
	errTooMany = errors.New("the node sent more than 500 results; the rest were dropped")
)

// NodeClients gives a client of a connected node (nodes.Manager.Client).
type NodeClients interface {
	Client(nodeID string) (nodev1connect.NodeServiceClient, error)
}

// Prober probes a proxy from the panel now (probes.Scheduler.Probe).
type Prober interface {
	Probe(ctx context.Context, proxyID string) (store.Probe, bool, error)
}

// Resolver resolves the link hosts (net.Resolver).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Config is what a Runner works with. DB and Nodes are required.
type Config struct {
	DB    *store.DB
	Nodes NodeClients
	// Probes probes the proxies for ingress.external; nil skips it.
	Probes Prober
	// Resolver resolves link hosts; nil is the system resolver.
	Resolver Resolver
	// GeoIP tells about the country database for panel.geoip; nil skips it.
	GeoIP func(ctx context.Context) (geodb.Status, error)
	Log   *slog.Logger
	Now   func() time.Time
	// RunTimeout bounds a run; 0 is 3 min 30 s.
	RunTimeout time.Duration
}

// active is a run in progress.
type active struct {
	id      string
	ready   chan struct{} // closed once its row is stored, or its start failed
	created bool          // its row is stored; set before ready is closed
	done    chan struct{}
}

// Runner runs the checks of nodes, one run per node at a time. Each run has a
// goroutine of its own and outlives the call that started it.
type Runner struct {
	cfg Config

	mu     sync.Mutex
	base   context.Context
	byNode map[string]*active
	byRun  map[string]*active
	wg     sync.WaitGroup
}

// NewRunner returns a runner. Its runs live until the context of Start ends.
func NewRunner(cfg Config) *Runner {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RunTimeout <= 0 {
		cfg.RunTimeout = defaultRunTimeout
	}
	if cfg.Resolver == nil {
		cfg.Resolver = netResolver{}
	}
	return &Runner{cfg: cfg, base: context.Background(), byNode: map[string]*active{}, byRun: map[string]*active{}}
}

// Start ends, as failed, the runs that a panel that stopped left running, and
// makes the runs from now on end when ctx ends (as partial).
func (r *Runner) Start(ctx context.Context) {
	r.mu.Lock()
	r.base = ctx
	r.mu.Unlock()
	if n, err := r.cfg.DB.FailUnfinishedDiagnosticRuns(ctx, "the panel stopped during the run"); err != nil {
		r.cfg.Log.Error("could not end the diagnostic runs that were left running", "err", err)
	} else if n > 0 {
		r.cfg.Log.Info("ended the diagnostic runs that were left running", "runs", n)
	}
}

// Drain waits for the runs in progress, which end once the context of Start
// has ended.
func (r *Runner) Drain() { r.wg.Wait() }

// Run starts a run of the checks of a scope of a node and returns its id. When
// the node has a run in progress, it waits for it to end first, at most as long
// as ctx lasts. The run itself does not end with ctx.
func (r *Runner) Run(ctx context.Context, nodeID, scope, reason, change, relatedRunID string) (string, error) {
	id, _, err := r.start(ctx, spec{nodeID: nodeID, scope: scope, reason: reason, change: change, related: relatedRunID}, true, nil)
	return id, err
}

// RunUntil is Run for a run that ends, as partial, at deadline at the latest
// (and within the runner's own bound): the before-run of a change.
func (r *Runner) RunUntil(ctx context.Context, nodeID, scope, reason, change, relatedRunID string, deadline time.Time) (string, error) {
	id, _, err := r.start(ctx, spec{nodeID: nodeID, scope: scope, reason: reason, change: change, related: relatedRunID, deadline: deadline}, true, nil)
	return id, err
}

// Skipped stores a run of a node that did not run, done at once as skipped,
// with why, and returns its id.
func (r *Runner) Skipped(ctx context.Context, nodeID, scope, reason, change, relatedRunID, why string) (string, error) {
	ctx = context.WithoutCancel(ctx)
	run := &store.DiagnosticRun{NodeID: nodeID, Scope: scope, Reason: reason, Change: change, RelatedRunID: relatedRunID, StartedAt: r.cfg.Now()}
	if err := r.cfg.DB.CreateDiagnosticRun(ctx, run); err != nil {
		return "", err
	}
	if err := r.cfg.DB.FinishDiagnosticRun(ctx, run.ID, store.RunSkipped, clip(why, 1024), false, r.cfg.Now()); err != nil {
		return "", err
	}
	return run.ID, nil
}

// StartManual starts a manual run, or returns the id of the node's run in
// progress (and joined) without starting one. audit, if set, is called before
// a run is started; its error starts none.
func (r *Runner) StartManual(ctx context.Context, nodeID, scope, adminID string, audit func() error) (id string, joined bool, err error) {
	return r.start(ctx, spec{nodeID: nodeID, scope: scope, reason: store.RunManual, admin: adminID}, false, audit)
}

// Wait waits for a run to end, at most as long as ctx lasts, and returns it
// with its results. When ctx ends first it returns the run as it is then, and
// the error of ctx.
func (r *Runner) Wait(ctx context.Context, runID string) (*store.DiagnosticRun, error) {
	r.mu.Lock()
	a := r.byRun[runID]
	r.mu.Unlock()
	var waitErr error
	if a != nil {
		select {
		case <-a.done:
		case <-ctx.Done():
			waitErr = ctx.Err()
		}
	}
	run, err := r.cfg.DB.DiagnosticRun(context.WithoutCancel(ctx), runID)
	if err != nil {
		return nil, err
	}
	return run, waitErr
}

// Running returns the id of the run in progress of a node, if any.
func (r *Runner) Running(nodeID string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a := r.byNode[nodeID]; a != nil {
		return a.id, true
	}
	return "", false
}

// spec is what a run is to do.
type spec struct {
	nodeID, scope, reason, change, related, admin string
	deadline                                      time.Time // the run ends by it; zero for the runner's bound only
}

// scopeOf is the resolved scope of a run: the node, and the proxy of a proxy
// scope.
type scopeOf struct {
	node  *store.Node
	proxy *store.Proxy // nil for the scope node
}

// resolveScope checks a scope against the node.
func resolveScope(ctx context.Context, db *store.DB, nodeID, scope string) (scopeOf, error) {
	n, err := db.NodeByID(ctx, nodeID)
	if err != nil {
		return scopeOf{}, err
	}
	if scope == ScopeNode {
		return scopeOf{node: n}, nil
	}
	id, ok := strings.CutPrefix(scope, "proxy:")
	if !ok || id == "" {
		return scopeOf{}, ErrScope
	}
	p, err := db.ProxyByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return scopeOf{}, fmt.Errorf("%w: no such proxy", ErrScope)
	}
	if err != nil {
		return scopeOf{}, err
	}
	if p.NodeID != nodeID {
		return scopeOf{}, fmt.Errorf("%w: the proxy is on another node", ErrScope)
	}
	return scopeOf{node: n, proxy: p}, nil
}

func (r *Runner) start(ctx context.Context, s spec, wait bool, audit func() error) (string, bool, error) {
	switch s.reason {
	case store.RunManual, store.RunBeforeChange, store.RunAfterChange:
	default:
		return "", false, ErrReason
	}
	sc, err := resolveScope(ctx, r.cfg.DB, s.nodeID, s.scope)
	if err != nil {
		return "", false, err
	}
	for {
		r.mu.Lock()
		if a := r.byNode[s.nodeID]; a != nil {
			r.mu.Unlock()
			select {
			case <-a.ready:
			case <-ctx.Done():
				return "", false, ctx.Err()
			}
			if !a.created {
				continue // its start failed, and its slot is free again
			}
			if !wait {
				return a.id, true, nil
			}
			select {
			case <-a.done:
				continue
			case <-ctx.Done():
				return "", false, ctx.Err()
			}
		}
		// The slot of the node is taken under the lock; the audit and the row
		// are written after it.
		a := &active{id: ids.New(), ready: make(chan struct{}), done: make(chan struct{})}
		r.byNode[s.nodeID] = a
		base := r.base
		r.mu.Unlock()
		if err := r.launch(ctx, base, s, sc, audit, a); err != nil {
			return "", false, err
		}
		return a.id, false, nil
	}
}

// launch stores the run of a slot taken in start and starts its goroutine.
// When it cannot, it frees the slot.
func (r *Runner) launch(ctx, base context.Context, s spec, sc scopeOf, audit func() error, a *active) error {
	err := func() error {
		if audit != nil {
			if err := audit(); err != nil {
				return err
			}
		}
		run := &store.DiagnosticRun{ID: a.id, NodeID: s.nodeID, Scope: s.scope, Reason: s.reason, Change: s.change,
			RelatedRunID: s.related, AdminID: s.admin, StartedAt: r.cfg.Now()}
		return r.cfg.DB.CreateDiagnosticRun(ctx, run)
	}()
	r.mu.Lock()
	if err != nil {
		delete(r.byNode, s.nodeID)
	} else {
		r.byRun[a.id] = a
		a.created = true
	}
	r.mu.Unlock()
	close(a.ready)
	if err != nil {
		close(a.done)
		return err
	}
	run := &store.DiagnosticRun{ID: a.id, NodeID: s.nodeID, Scope: s.scope, Reason: s.reason, Change: s.change, RelatedRunID: s.related}
	limit := r.cfg.RunTimeout
	if !s.deadline.IsZero() {
		limit = max(min(limit, time.Until(s.deadline)), 0)
	}
	runCtx, cancel := context.WithTimeout(base, limit)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer cancel()
		r.execute(runCtx, run, sc)
		r.mu.Lock()
		delete(r.byNode, s.nodeID)
		delete(r.byRun, a.id)
		r.mu.Unlock()
		close(a.done)
	}()
	return nil
}

// recorder stores the results of a run as they come, in order, with the
// evidence limits.
type recorder struct {
	db     *store.DB
	runID  string
	seq    int
	budget budget
	now    func() time.Time
}

func (w *recorder) add(ctx context.Context, x store.DiagnosticResult) error {
	if w.seq >= maxResults {
		return errTooMany
	}
	x.Seq = w.seq
	x = clipped(x)
	x.Evidence = w.budget.take(x.Status, x.Evidence)
	if x.CheckedAt.IsZero() {
		x.CheckedAt = w.now()
	}
	if err := w.db.AddDiagnosticResult(context.WithoutCancel(ctx), w.runID, x); err != nil {
		return err
	}
	w.seq++
	return nil
}

// execute runs the checks of a run and ends it.
func (r *Runner) execute(ctx context.Context, run *store.DiagnosticRun, sc scopeOf) {
	w := &recorder{db: r.cfg.DB, runID: run.ID, budget: budget{left: maxRunEvidence}, now: r.cfg.Now}
	client, why := r.nodeClient(sc.node)
	state, errText := store.RunDone, ""
	err := r.panelChecks(ctx, sc, why, w)
	switch {
	case err != nil:
	case why != "":
		state = store.RunSkipped
	default:
		err = r.nodeChecks(ctx, client, run.Scope, w)
	}
	switch {
	case err == nil:
	case errors.Is(err, errTooMany):
		state, errText = store.RunPartial, err.Error()
	case ctx.Err() != nil, connect.CodeOf(err) == connect.CodeDeadlineExceeded:
		// The node gets the run's deadline with the call and may report it a
		// moment before the panel's own timer fires: the run ran out of time
		// all the same.
		state, errText = store.RunPartial, "the run ended before every check finished"
	default:
		state, errText = store.RunFailed, err.Error()
		r.cfg.Log.Warn("a diagnostic run failed", "run", run.ID, "node", run.NodeID, "err", err)
	}
	bg := context.WithoutCancel(ctx)
	regressed, failed := false, []string(nil)
	if run.Reason == store.RunAfterChange && run.RelatedRunID != "" {
		regressed, failed = r.regression(bg, run.ID, run.RelatedRunID)
	}
	if err := r.cfg.DB.FinishDiagnosticRun(bg, run.ID, state, errText, regressed, r.cfg.Now()); err != nil {
		r.cfg.Log.Error("could not end a diagnostic run", "run", run.ID, "err", err)
		return
	}
	if regressed {
		r.recordRegression(bg, run, failed)
	}
}

// nodeClient returns a client of the node for its checks, or why there is
// none.
func (r *Runner) nodeClient(n *store.Node) (nodev1connect.NodeServiceClient, string) {
	if n.Status != store.NodeStatusOnline {
		return nil, "the node is " + n.Status + ": its checks did not run"
	}
	c, err := r.cfg.Nodes.Client(n.ID)
	if err != nil {
		return nil, "the panel is not connected to the node: its checks did not run"
	}
	if !slices.Contains(n.HostInfo.Capabilities, capDiagnostics) {
		return nil, "the node's agent does not run diagnostics (update it): its checks did not run"
	}
	return c, ""
}

// nodeChecks streams the node's results into the run.
func (r *Runner) nodeChecks(ctx context.Context, c nodev1connect.NodeServiceClient, scope string, w *recorder) error {
	stream, err := c.RunDiagnostics(ctx, connect.NewRequest(&nodev1.RunDiagnosticsRequest{Scope: scope}))
	if err != nil {
		return fmt.Errorf("the node did not run its checks: %w", err)
	}
	defer func() { _ = stream.Close() }()
	for stream.Receive() {
		if err := w.add(ctx, fromNode(stream.Msg())); err != nil {
			return err
		}
	}
	if err := stream.Err(); err != nil {
		return fmt.Errorf("the node's checks stopped: %w", err)
	}
	return nil
}

// statusName is the name of a node's status.
func statusName(s nodev1.CheckStatus) string {
	switch s {
	case nodev1.CheckStatus_CHECK_STATUS_OK:
		return StatusOK
	case nodev1.CheckStatus_CHECK_STATUS_WARN:
		return StatusWarn
	case nodev1.CheckStatus_CHECK_STATUS_FAIL:
		return StatusFail
	default:
		return StatusSkip
	}
}

// fromNode is a node's result as the panel stores it.
func fromNode(m *nodev1.DiagnosticResult) store.DiagnosticResult {
	x := store.DiagnosticResult{
		CheckID: m.GetId(), Layer: m.GetLayer(), Target: m.GetTarget(), Status: statusName(m.GetStatus()),
		Summary: m.GetSummary(), Evidence: m.GetEvidence(), Hint: m.GetHint(), Fix: m.GetFix(),
		Vantage: VantageNode, DurationMS: m.GetDurationMs(),
	}
	if u := m.GetCheckedUnix(); u > 0 {
		x.CheckedAt = time.Unix(u, 0)
	}
	return clipped(x)
}

// clipped is a result within the limits of what is stored of it, whatever
// the node sent: names of 128 bytes, a summary of 200, a hint of 512 (the
// evidence is the budget's).
func clipped(x store.DiagnosticResult) store.DiagnosticResult {
	x.CheckID, x.Layer, x.Target, x.Fix = clip(x.CheckID, maxName), clip(x.Layer, maxName), clip(x.Target, maxName), clip(x.Fix, maxName)
	x.Summary, x.Hint = clip(x.Summary, maxSummary), clip(x.Hint, maxHint)
	return x
}

// regression compares a run with its related run: a check that was ok or warn
// there and is fail here. It returns the ones that regressed.
func (r *Runner) regression(ctx context.Context, runID, relatedID string) (bool, []string) {
	before, err := r.cfg.DB.DiagnosticRun(ctx, relatedID)
	if err != nil {
		r.cfg.Log.Warn("could not read the related run", "run", runID, "related", relatedID, "err", err)
		return false, nil
	}
	after, err := r.cfg.DB.DiagnosticRun(ctx, runID)
	if err != nil {
		r.cfg.Log.Warn("could not read the run", "run", runID, "err", err)
		return false, nil
	}
	return regressed(before.Results, after.Results)
}

// regressed lists the checks (id and target) that are fail in after and were
// ok or warn in before.
func regressed(before, after []store.DiagnosticResult) (bool, []string) {
	type key struct{ id, target string }
	was := map[key]string{}
	for _, x := range before {
		was[key{x.CheckID, x.Target}] = x.Status
	}
	var out []string
	for _, x := range after {
		if x.Status != StatusFail {
			continue
		}
		if s := was[key{x.CheckID, x.Target}]; s == StatusOK || s == StatusWarn {
			out = append(out, checkLabel(x.CheckID, x.Target))
		}
	}
	return len(out) > 0, out
}

// checkLabel names a check of a target.
func checkLabel(id, target string) string {
	if target == "" {
		return id
	}
	return id + " (" + target + ")"
}

func (r *Runner) recordRegression(ctx context.Context, run *store.DiagnosticRun, failed []string) {
	change := run.Change
	if change == "" {
		change = "a change"
	}
	e := &store.Event{
		NodeID: run.NodeID, Kind: "diagnostics.regressed", Severity: "error",
		Message: clip(fmt.Sprintf("after %s, checks that passed before fail: %s", change, strings.Join(failed, ", ")), 1024),
		Details: map[string]string{"run_id": run.ID, "related_run_id": run.RelatedRunID, "change": run.Change, "scope": run.Scope},
	}
	if id, ok := strings.CutPrefix(run.Scope, "proxy:"); ok {
		e.ProxyID = id
	}
	if err := r.cfg.DB.AppendEvent(ctx, e); err != nil {
		r.cfg.Log.Error("could not record a regression", "run", run.ID, "err", err)
	}
}

// CopyLight stores a before_change run made of the node's light checks of a
// scope as they are now, done at once, and returns its id.
func (r *Runner) CopyLight(ctx context.Context, nodeID, scope, change string) (string, error) {
	sc, err := resolveScope(ctx, r.cfg.DB, nodeID, scope)
	if err != nil {
		return "", err
	}
	checks, err := r.cfg.DB.NodeChecks(ctx, nodeID)
	if err != nil {
		return "", err
	}
	run := &store.DiagnosticRun{NodeID: nodeID, Scope: scope, Reason: store.RunBeforeChange, Change: change, StartedAt: r.cfg.Now()}
	if err := r.cfg.DB.CreateDiagnosticRun(ctx, run); err != nil {
		return "", err
	}
	w := &recorder{db: r.cfg.DB, runID: run.ID, budget: budget{left: maxRunEvidence}, now: r.cfg.Now}
	in := targetsOf(sc)
	for _, c := range checks {
		if !in(c.Target) {
			continue
		}
		x := store.DiagnosticResult{CheckID: c.CheckID, Layer: c.Layer, Target: c.Target, Status: c.Status, Summary: c.Summary,
			Evidence: c.Evidence, Hint: c.Hint, Fix: c.Fix, Vantage: VantageNode, CheckedAt: c.CheckedAt}
		if err := w.add(ctx, x); err != nil {
			return "", err
		}
	}
	if err := r.cfg.DB.FinishDiagnosticRun(ctx, run.ID, store.RunDone, "", false, r.cfg.Now()); err != nil {
		return "", err
	}
	return run.ID, nil
}

// targetsOf reports whether a target is in a scope: every target for the
// scope node; for a proxy, the node itself, its listener, the proxy and the
// members of its chains (its own or the node's default, and its scope
// chains).
func targetsOf(sc scopeOf) func(target string) bool {
	if sc.proxy == nil {
		return func(string) bool { return true }
	}
	p := sc.proxy
	chains := map[string]bool{}
	if p.EgressChainID != "" {
		chains[p.EgressChainID] = true
	} else if sc.node.DefaultChainID != "" {
		chains[sc.node.DefaultChainID] = true
	}
	for _, c := range p.EgressScopeChains {
		if c != "" {
			chains[c] = true
		}
	}
	return func(t string) bool {
		switch t {
		case "", "listener:" + p.ListenerID, "proxy:" + p.ID:
			return true
		}
		if m, ok := strings.CutPrefix(t, "member:"); ok {
			chain, _, _ := strings.Cut(m, "/")
			return chains[chain]
		}
		return false
	}
}

// budget is what is left of the evidence of a run or a report.
type budget struct{ left int }

// take returns the evidence of a result as it is kept: none but for warn and
// fail, at most 2 KiB, and within what is left of the run's 64 KiB.
func (b *budget) take(status, evidence string) string {
	if status != StatusWarn && status != StatusFail {
		return ""
	}
	evidence = clip(evidence, min(maxEvidence, b.left))
	b.left -= len(evidence)
	return evidence
}

// clip cuts s to at most n bytes, at a boundary of a UTF-8 sequence.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 0 {
		return ""
	}
	i := n
	for i > 0 && i < len(s) && s[i]&0xC0 == 0x80 {
		i--
	}
	return s[:i]
}
