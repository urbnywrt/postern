package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// The bounds of the runs around changes (R6-3).
const (
	defaultBeforeWait = 90 * time.Second // a before-run, waited for at most
	defaultAfterDelay = 60 * time.Second // from the applied change to the after-run
	defaultApplyWait  = 10 * time.Minute // waited for the node to apply a change
	defaultApplyPoll  = 2 * time.Second  // how often the applied generation is read
	defaultAutoEvery  = 5 * time.Minute  // one automatic after-run per node and scope
	// coalesceAbove is the number of proxies of a node changing by themselves
	// within one window above which they get one run of the node.
	coalesceAbove = 3
)

// ChangesConfig is what Changes works with. Runner and DB are required; a
// zero duration is its default.
type ChangesConfig struct {
	Runner *Runner
	DB     *store.DB
	Log    *slog.Logger
	// Now is the clock of the automatic pairs' limit; nil is time.Now.
	Now func() time.Time
	// BeforeWait bounds a before-run (90 s); AfterDelay is the time from a
	// change, applied, to its after-run (60 s), and the window in which the
	// node's own changes are coalesced; ApplyWait bounds the wait for the
	// node to apply a change (10 min), read every ApplyPoll (2 s); AutoEvery
	// is the least time between two automatic after-runs of a node and scope
	// (5 min).
	BeforeWait, AfterDelay, ApplyWait, ApplyPoll, AutoEvery time.Duration
}

// Changes runs the checks before and after changes: the operator's edits
// (Before and After, the change hooks of the proxy and egress services), the
// fixes, and the changes that the nodes make by themselves (auto.go). Its
// after-runs outlive the calls that ask for them, until the context of Start
// ends.
type Changes struct {
	cfg ChangesConfig

	mu   sync.Mutex
	base context.Context
	wg   sync.WaitGroup
	// heldUntil and afters say that a node has an operator's change in
	// progress: its before-run (until a time) or its after-run (a count).
	heldUntil map[string]time.Time
	afters    map[string]int
	// lastAuto is when an automatic after-run of a node and scope started.
	lastAuto map[autoKey]time.Time
	// windows are the node's own changes being gathered, by node.
	windows map[string]*window
	// pending are the after-runs of the operator's changes that wait, one
	// per node and scope.
	pending map[autoKey]*pendingAfter
	// suppressed are the long changes of a node in progress (a rollout step,
	// a switchover), by key, each until a time at the latest.
	suppressed map[string]map[string]time.Time
}

// pendingAfter is an after-run that waits for its node to apply a
// generation: the latest of the changes that it covers. It is related to the
// before-run of the first of them.
type pendingAfter struct {
	generation uint64
	before     string
	change     string
	more       int // the changes after the first
}

// NewChanges returns the runs around changes.
func NewChanges(cfg ChangesConfig) *Changes {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&cfg.BeforeWait, defaultBeforeWait)
	def(&cfg.AfterDelay, defaultAfterDelay)
	def(&cfg.ApplyWait, defaultApplyWait)
	def(&cfg.ApplyPoll, defaultApplyPoll)
	def(&cfg.AutoEvery, defaultAutoEvery)
	return &Changes{cfg: cfg, base: context.Background(), heldUntil: map[string]time.Time{}, afters: map[string]int{},
		lastAuto: map[autoKey]time.Time{}, windows: map[string]*window{}, pending: map[autoKey]*pendingAfter{},
		suppressed: map[string]map[string]time.Time{}}
}

// Start makes the after-runs from now on end when ctx ends.
func (c *Changes) Start(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.base = ctx
}

// Drain waits for the after-runs that are waiting or running; they end once
// the context of Start has ended.
func (c *Changes) Drain() { c.wg.Wait() }

// Before runs the checks of a scope of a node before a change and returns the
// run's id; the signature of proxies.ChangeHooks.Before. It returns within
// BeforeWait: the run as it is then (partial when the time was over, skipped
// when the node is offline or lacks diagnostics, or was busy with another run
// all along). It never refuses the change: "" only when not even a skipped
// run could be stored.
func (c *Changes) Before(ctx context.Context, nodeID, scope, change string) string {
	return c.before(ctx, nodeID, scope, change, c.cfg.BeforeWait)
}

// before is Before within wait.
func (c *Changes) before(ctx context.Context, nodeID, scope, change string, wait time.Duration) string {
	ctx = context.WithoutCancel(ctx)
	start := time.Now()
	c.hold(nodeID, c.cfg.Now().Add(wait+time.Minute))
	end := start.Add(wait)
	// The run ends a little before the wait does, to be stored as partial
	// in time.
	grace := min(2*time.Second, wait/10)
	wctx, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	id, err := c.cfg.Runner.RunUntil(wctx, nodeID, scope, store.RunBeforeChange, change, "", end.Add(-grace))
	if err != nil {
		why := "the before-run could not start: " + err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			why = "the node was busy with another run until the change: its checks did not run before it"
		}
		c.cfg.Log.Warn("a before-run did not start", "node", nodeID, "scope", scope, "change", change, "err", err)
		id, err = c.cfg.Runner.Skipped(ctx, nodeID, scope, store.RunBeforeChange, change, "", why)
		if err != nil {
			c.cfg.Log.Error("could not store a skipped before-run", "node", nodeID, "err", err)
			return ""
		}
		return id
	}
	if _, err := c.cfg.Runner.Wait(wctx, id); err != nil {
		c.cfg.Log.Info("a before-run was not over in time; the change goes on", "node", nodeID, "run", id, "err", err)
	}
	return id
}

// After runs the checks of a scope of a node once the node has applied the
// generation of a change, AfterDelay after that, related to the before-run;
// the signature of proxies.ChangeHooks.After. It returns at once. A node and
// scope has one after-run waiting at a time: a change while one waits moves
// it to the change's generation, and it stays related to the first
// before-run.
func (c *Changes) After(nodeID, scope, change, beforeRunID string, generation uint64) {
	key := autoKey{nodeID, scope}
	c.mu.Lock()
	if p := c.pending[key]; p != nil {
		p.generation = max(p.generation, generation)
		p.more++
		c.mu.Unlock()
		return
	}
	p := &pendingAfter{generation: generation, before: beforeRunID, change: change}
	c.pending[key] = p
	c.afters[nodeID]++
	base := c.base
	c.wg.Add(1)
	c.mu.Unlock()
	go func() {
		defer c.wg.Done()
		defer c.release(nodeID)
		for {
			c.mu.Lock()
			gen := p.generation
			c.mu.Unlock()
			if !c.waitApplied(base, nodeID, gen) || !sleep(base, c.cfg.AfterDelay) {
				c.mu.Lock()
				delete(c.pending, key)
				c.mu.Unlock()
				return
			}
			c.mu.Lock()
			if p.generation != gen { // a later change came: wait for it too
				c.mu.Unlock()
				continue
			}
			delete(c.pending, key)
			words := p.change
			if p.more > 0 {
				words = fmt.Sprintf("%s; and %d later changes", words, p.more)
			}
			c.mu.Unlock()
			c.runAfter(base, nodeID, scope, clip(words, 1024), p.before)
			return
		}
	}()
}

// hold notes an operator's change of a node in progress until a time.
func (c *Changes) hold(nodeID string, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if until.After(c.heldUntil[nodeID]) {
		c.heldUntil[nodeID] = until
	}
}

// release ends the after-run of an operator's change of a node.
func (c *Changes) release(nodeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.afters[nodeID]--; c.afters[nodeID] <= 0 {
		delete(c.afters, nodeID)
	}
}

// pendingLocked says whether a node has an operator's change in progress.
// The caller holds c.mu.
func (c *Changes) pendingLocked(nodeID string) bool {
	if c.afters[nodeID] > 0 || c.cfg.Now().Before(c.heldUntil[nodeID]) {
		return true
	}
	now := c.cfg.Now()
	for key, until := range c.suppressed[nodeID] {
		if now.Before(until) {
			return true
		}
		delete(c.suppressed[nodeID], key)
	}
	delete(c.suppressed, nodeID)
	return false
}

// Suppress holds back the automatic pairs of a node while a long change of it
// (key) is in progress: until Lift, or until a time of the clock at the
// latest.
func (c *Changes) Suppress(nodeID, key string, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.suppressed[nodeID]
	if m == nil {
		m = map[string]time.Time{}
		c.suppressed[nodeID] = m
	}
	m[key] = until
}

// Lift ends a hold of Suppress.
func (c *Changes) Lift(nodeID, key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.suppressed[nodeID], key)
	if len(c.suppressed[nodeID]) == 0 {
		delete(c.suppressed, nodeID)
	}
}

// waitApplied waits until the node has applied the generation, at most
// ApplyWait: the after-run then shows what is wrong (an offline node's is
// skipped). It is false when ctx ended.
func (c *Changes) waitApplied(ctx context.Context, nodeID string, generation uint64) bool {
	end := time.Now().Add(c.cfg.ApplyWait)
	for {
		n, err := c.cfg.DB.NodeByID(ctx, nodeID)
		switch {
		case ctx.Err() != nil:
			return false
		case errors.Is(err, store.ErrNotFound):
			return false
		case err == nil && n.AppliedGeneration >= generation:
			return true
		case time.Now().After(end):
			c.cfg.Log.Info("the node has not applied a change in time; its after-run starts anyway", "node", nodeID, "generation", generation)
			return true
		}
		if !sleep(ctx, c.cfg.ApplyPoll) {
			return false
		}
	}
}

// runAfter starts the after-run of a change, waiting for a run of the node in
// progress first.
func (c *Changes) runAfter(ctx context.Context, nodeID, scope, change, beforeRunID string) {
	rctx, cancel := context.WithTimeout(ctx, 2*c.cfg.Runner.cfg.RunTimeout)
	defer cancel()
	if _, err := c.cfg.Runner.Run(rctx, nodeID, scope, store.RunAfterChange, change, beforeRunID); err != nil && ctx.Err() == nil {
		c.cfg.Log.Warn("an after-run did not start", "node", nodeID, "scope", scope, "change", change, "err", err)
	}
}

// sleep waits for d, or until ctx ends (false).
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
