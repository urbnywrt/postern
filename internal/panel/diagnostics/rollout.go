package diagnostics

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// The bounds of the runs around a rollout step (R6-3).
const (
	defaultStepWait     = 3 * time.Minute  // the runs of a hook, waited for at most
	defaultStepSuppress = 60 * time.Minute // the automatic pairs held back from BeforeStep at most
)

// StepRunner is what the rollout hooks need of a Runner.
type StepRunner interface {
	RunUntil(ctx context.Context, nodeID, scope, reason, change, relatedRunID string, deadline time.Time) (string, error)
	Wait(ctx context.Context, runID string) (*store.DiagnosticRun, error)
	Skipped(ctx context.Context, nodeID, scope, reason, change, relatedRunID, why string) (string, error)
}

// Suppressor holds back the automatic pairs of a node; *Changes is one.
type Suppressor interface {
	Suppress(nodeID, key string, until time.Time)
	Lift(nodeID, key string)
}

// RolloutConfig is what the rollout hooks work with. Runner is required.
type RolloutConfig struct {
	Runner StepRunner
	// Suppress holds back the automatic pairs of the step's nodes; nil: none
	// are.
	Suppress Suppressor
	// Items are the items of a rollout, whose nodes a step covers with its
	// own; nil: the step's node only.
	Items func(ctx context.Context, rolloutID string) ([]store.RolloutItem, error)
	// BeforeRun finds the before-run of a node and change that this panel
	// does not remember (it restarted between the hooks); nil: none.
	BeforeRun func(ctx context.Context, nodeID, change string) string
	Log       *slog.Logger
	// Now is the clock of the suppression; nil is time.Now.
	Now func() time.Time
	// Wait bounds the runs of a hook (3 min) and Hold the suppression from
	// BeforeStep (60 min).
	Wait, Hold time.Duration
}

// RolloutHooks are the full runs before and after every rollout step: the
// hooks of rollout.Config. They inform and never decide: both return nil.
type RolloutHooks struct {
	cfg RolloutConfig

	mu      sync.Mutex
	befores map[stepNode]string // the before-runs of the steps in progress
}

type stepNode struct{ change, node string }

// NewRolloutHooks returns the hooks.
func NewRolloutHooks(cfg RolloutConfig) *RolloutHooks {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Wait <= 0 {
		cfg.Wait = defaultStepWait
	}
	if cfg.Hold <= 0 {
		cfg.Hold = defaultStepSuppress
	}
	return &RolloutHooks{cfg: cfg, befores: map[stepNode]string{}}
}

// BeforeStep runs the checks of every node of the step, all at once, reason
// before_change, and waits for them within its bound; from now the automatic
// pairs of those nodes are held back. It always returns nil.
func (h *RolloutHooks) BeforeStep(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error {
	change := store.RolloutStepChange(r.ID, s.Index)
	nodes := h.nodes(ctx, r, s)
	if h.cfg.Suppress != nil {
		until := h.cfg.Now().Add(h.cfg.Hold)
		for _, n := range nodes {
			h.cfg.Suppress.Suppress(n, change, until)
		}
	}
	ids := h.runAll(ctx, nodes, store.RunBeforeChange, change, func(string) string { return "" })
	h.mu.Lock()
	for n, id := range ids {
		h.befores[stepNode{change, n}] = id
	}
	h.mu.Unlock()
	return nil
}

// AfterStep runs the same checks, reason after_change, each related to its
// node's before-run, after a step that went through or was reverted, and
// waits for them within its bound; then the automatic pairs come back. It
// always returns nil.
func (h *RolloutHooks) AfterStep(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error {
	change := store.RolloutStepChange(r.ID, s.Index)
	nodes := h.nodes(ctx, r, s)
	before := func(n string) string {
		h.mu.Lock()
		id, ok := h.befores[stepNode{change, n}]
		delete(h.befores, stepNode{change, n})
		h.mu.Unlock()
		if !ok && h.cfg.BeforeRun != nil {
			id = h.cfg.BeforeRun(context.WithoutCancel(ctx), n, change)
		}
		return id
	}
	defer func() {
		if h.cfg.Suppress != nil {
			for _, n := range nodes {
				h.cfg.Suppress.Lift(n, change)
			}
		}
	}()
	h.runAll(ctx, nodes, store.RunAfterChange, change, before)
	return nil
}

// nodes are the step's node and the nodes of its items.
func (h *RolloutHooks) nodes(ctx context.Context, r *store.Rollout, s *store.RolloutStep) []string {
	out := []string{}
	if s.NodeID != "" {
		out = append(out, s.NodeID)
	}
	if h.cfg.Items != nil {
		items, err := h.cfg.Items(context.WithoutCancel(ctx), r.ID)
		if err != nil {
			h.cfg.Log.Warn("could not read the items of a rollout for its diagnostics", "rollout", r.ID, "err", err)
		}
		for _, it := range items {
			if it.StepIndex == s.Index && it.NodeID != "" && !slices.Contains(out, it.NodeID) {
				out = append(out, it.NodeID)
			}
		}
	}
	return out
}

// runAll runs the checks of the nodes at once and waits for them until the
// bound, or a little before ctx ends (the runner's hook timeout), whichever
// is first. A run that cannot start (the node is busy with another run all
// along, or gone) is stored skipped; one that is not over in time ends as
// partial. It returns the run of each node.
func (h *RolloutHooks) runAll(ctx context.Context, nodes []string, reason, change string, related func(string) string) map[string]string {
	start := time.Now()
	end := start.Add(h.cfg.Wait)
	if d, ok := ctx.Deadline(); ok {
		// Return before the hook's timeout makes it an error.
		grace := min(2*time.Second, d.Sub(start)/10)
		end = minTime(end, d.Add(-grace))
	}
	// The runs end a little before the wait does, to be stored in time.
	runEnd := end.Add(-min(2*time.Second, end.Sub(start)/10))
	// The wait ends with ctx (the rollout's Abort or Pause ends it); the
	// runs go on in the runner and are recorded, and a skipped one is stored
	// whatever ctx says.
	base := context.WithoutCancel(ctx)
	wctx, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = map[string]string{}
	)
	for _, n := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel := related(n)
			id, err := h.cfg.Runner.RunUntil(wctx, n, ScopeNode, reason, change, rel, runEnd)
			if err != nil {
				why := "the run could not start: " + err.Error()
				switch {
				case ctx.Err() != nil:
					why = "the rollout was paused or aborted before the checks could run"
				case wctx.Err() != nil:
					why = "the node was busy with another run until the rollout step went on: its checks did not run"
				}
				h.cfg.Log.Warn("a run around a rollout step did not start", "node", n, "change", change, "reason", reason, "err", err)
				if id, err = h.cfg.Runner.Skipped(base, n, ScopeNode, reason, change, rel, why); err != nil {
					h.cfg.Log.Error("could not store a skipped run around a rollout step", "node", n, "err", err)
					return
				}
			} else if _, err := h.cfg.Runner.Wait(wctx, id); err != nil {
				h.cfg.Log.Info("a run around a rollout step was not over in time; the rollout goes on", "node", n, "run", id, "err", err)
			}
			mu.Lock()
			out[n] = id
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
