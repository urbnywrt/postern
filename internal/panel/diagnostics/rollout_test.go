package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// fakeStepRunner records the runs that the hooks ask for. Each RunUntil waits
// until gate is closed (when set) or ctx ends; fail makes it fail at once.
type fakeStepRunner struct {
	mu       sync.Mutex
	runs     []fakeStepRun
	skipped  []fakeStepRun
	inFlight int
	maxIn    int
	gate     chan struct{}
	fail     error
	waitHang bool // Wait never sees the run end
}

type fakeStepRun struct {
	id, node, scope, reason, change, related, why string
	deadline                                      time.Time
}

func (f *fakeStepRunner) RunUntil(ctx context.Context, nodeID, scope, reason, change, related string, deadline time.Time) (string, error) {
	f.mu.Lock()
	f.inFlight++
	f.maxIn = max(f.maxIn, f.inFlight)
	gate, fail := f.gate, f.fail
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if fail != nil {
		return "", fail
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	id := fmt.Sprintf("run-%d", len(f.runs)+1)
	f.runs = append(f.runs, fakeStepRun{id: id, node: nodeID, scope: scope, reason: reason, change: change, related: related, deadline: deadline})
	return id, nil
}

func (f *fakeStepRunner) Wait(ctx context.Context, runID string) (*store.DiagnosticRun, error) {
	if f.waitHang {
		<-ctx.Done()
		return &store.DiagnosticRun{ID: runID, State: store.RunRunning}, ctx.Err()
	}
	return &store.DiagnosticRun{ID: runID, State: store.RunDone}, nil
}

func (f *fakeStepRunner) Skipped(_ context.Context, nodeID, scope, reason, change, related, why string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := fmt.Sprintf("skip-%d", len(f.skipped)+1)
	f.skipped = append(f.skipped, fakeStepRun{id: id, node: nodeID, scope: scope, reason: reason, change: change, related: related, why: why})
	return id, nil
}

func (f *fakeStepRunner) ofReason(reason string) []fakeStepRun {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeStepRun
	for _, r := range append(slices.Clone(f.runs), f.skipped...) {
		if r.reason == reason {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b fakeStepRun) int {
		if a.node < b.node {
			return -1
		}
		if a.node > b.node {
			return 1
		}
		return 0
	})
	return out
}

func stepItems(items ...store.RolloutItem) func(context.Context, string) ([]store.RolloutItem, error) {
	return func(context.Context, string) ([]store.RolloutItem, error) { return items, nil }
}

// Every node of a step gets one run of the scope node, all at once, before the
// step and after it; each after-run is related to its node's before-run, also
// after a reverted step.
func TestRolloutHooksRunEveryNodeBeforeAndAfter(t *testing.T) {
	for _, status := range []string{store.StepVerifying, store.StepReverted} {
		t.Run(status, func(t *testing.T) {
			f := &fakeStepRunner{gate: make(chan struct{})}
			h := NewRolloutHooks(RolloutConfig{Runner: f, Items: stepItems(
				store.RolloutItem{NodeID: "n2", StepIndex: 1}, store.RolloutItem{NodeID: "n1", StepIndex: 1},
				store.RolloutItem{NodeID: "n3", StepIndex: 2}, // another step's
			)})
			ro := &store.Rollout{ID: "r1"}
			st := &store.RolloutStep{RolloutID: "r1", Index: 1, NodeID: "n1", Status: store.StepPending}
			done := make(chan error, 1)
			go func() { done <- h.BeforeStep(context.Background(), ro, st) }()
			eventually(t, "both runs in flight", func() bool {
				f.mu.Lock()
				defer f.mu.Unlock()
				return f.inFlight == 2
			})
			close(f.gate)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			st.Status = status
			if err := h.AfterStep(context.Background(), ro, st); err != nil {
				t.Fatal(err)
			}
			before, after := f.ofReason(store.RunBeforeChange), f.ofReason(store.RunAfterChange)
			if len(before) != 2 || len(after) != 2 || f.maxIn != 2 {
				t.Fatalf("before %+v after %+v, at once %d", before, after, f.maxIn)
			}
			for i, node := range []string{"n1", "n2"} {
				b, a := before[i], after[i]
				if b.node != node || b.scope != ScopeNode || b.change != "rollout r1 step 2" || b.related != "" {
					t.Errorf("before-run %+v", b)
				}
				if a.node != node || a.scope != ScopeNode || a.change != b.change || a.related != b.id {
					t.Errorf("after-run %+v, before %s", a, b.id)
				}
			}
		})
	}
}

// The hooks return nil when the runs cannot start, and within their bound
// (or a little before the hook's own timeout) when the runs do not end.
func TestRolloutHooksNeverFail(t *testing.T) {
	ro := &store.Rollout{ID: "r1"}
	st := &store.RolloutStep{RolloutID: "r1", Index: 0, NodeID: "n1"}

	f := &fakeStepRunner{fail: errors.New("no such node")}
	h := NewRolloutHooks(RolloutConfig{Runner: f})
	if err := h.BeforeStep(context.Background(), ro, st); err != nil {
		t.Fatal(err)
	}
	if err := h.AfterStep(context.Background(), ro, st); err != nil {
		t.Fatal(err)
	}
	if s := f.ofReason(store.RunAfterChange); len(s) != 1 || s[0].related != "skip-1" || s[0].id != "skip-2" {
		t.Fatalf("skipped after-runs %+v", s)
	}

	// The 3-minute bound (here 300 ms): the node is busy all along.
	f = &fakeStepRunner{gate: make(chan struct{})}
	h = NewRolloutHooks(RolloutConfig{Runner: f, Wait: 300 * time.Millisecond})
	start := time.Now()
	if err := h.BeforeStep(context.Background(), ro, st); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 250*time.Millisecond || d > 2*time.Second {
		t.Fatalf("BeforeStep took %s, want about 300 ms", d)
	}
	if s := f.ofReason(store.RunBeforeChange); len(s) != 1 || s[0].why == "" {
		t.Fatalf("a busy node's before-run %+v", s)
	}

	// A run that does not end: the hook's timeout comes before the bound,
	// and the hook returns before it; the run is to end before the hook
	// returns.
	f = &fakeStepRunner{waitHang: true}
	h = NewRolloutHooks(RolloutConfig{Runner: f})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := h.AfterStep(ctx, ro, st); err != nil {
		t.Fatal(err)
	}
	if time.Now().After(deadline) {
		t.Fatal("AfterStep returned after the hook's timeout")
	}
	if r := f.ofReason(store.RunAfterChange); len(r) != 1 || !r[0].deadline.Before(deadline) {
		t.Fatalf("after-run %+v, the hook's deadline %s", r, deadline)
	}
}

// From BeforeStep the node gets no automatic pair, until AfterStep or, at the
// latest, 60 minutes later.
func TestRolloutHooksHoldTheAutomaticPairs(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	p := e.proxy(e.listener(n.ID, 443, ""), nil)
	e.agent(n.ID, &fakeNode{})
	clock := &fixedClock{t: time.Now()}
	c := e.changes(e.runner(0), func(c *ChangesConfig) { c.Now = clock.now; c.AutoEvery = time.Minute })
	f := &fakeStepRunner{}
	h := NewRolloutHooks(RolloutConfig{Runner: f, Suppress: c, Now: clock.now})
	ro := &store.Rollout{ID: "r1"}
	st := &store.RolloutStep{RolloutID: "r1", Index: 0, NodeID: n.ID}
	gen := uint64(1)
	serving := func() {
		c.OnServingChange(n.ID, p.ID, gen, gen+1)
		gen++
	}

	// Inside a step: none.
	if err := h.BeforeStep(e.ctx, ro, st); err != nil {
		t.Fatal(err)
	}
	serving()
	time.Sleep(200 * time.Millisecond)
	if got := len(e.runsOf(n.ID)); got != 0 {
		t.Fatalf("%d runs inside a step", got)
	}
	// After the step: a pair.
	if err := h.AfterStep(e.ctx, ro, st); err != nil {
		t.Fatal(err)
	}
	serving()
	eventually(t, "the pair after the step", func() bool { return len(ofReason(e.runsOf(n.ID), store.RunAfterChange)) == 1 })

	// A step whose AfterStep never comes: held for 60 minutes.
	clock.add(2 * time.Minute)
	if err := h.BeforeStep(e.ctx, &store.Rollout{ID: "r2"}, st); err != nil {
		t.Fatal(err)
	}
	clock.add(59 * time.Minute)
	serving()
	time.Sleep(200 * time.Millisecond)
	if got := len(ofReason(e.runsOf(n.ID), store.RunAfterChange)); got != 1 {
		t.Fatalf("%d after-runs within the hold, want 1", got)
	}
	clock.add(2 * time.Minute)
	serving()
	eventually(t, "the pair after the hold", func() bool { return len(ofReason(e.runsOf(n.ID), store.RunAfterChange)) == 2 })
}

// With the real runner: a check that was ok before the step and fails after
// it marks the after-run regressed, and the hooks still return nil. A panel
// that restarted between the hooks finds the before-run by its change.
func TestRolloutHooksRegression(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	fn := &fakeNode{results: []*nodev1.DiagnosticResult{nodeResult("engine.ready", "", nodev1.CheckStatus_CHECK_STATUS_OK, "")}}
	e.agent(n.ID, fn)
	r := e.runner(0)
	ro := &store.Rollout{ID: "r1"}
	st := &store.RolloutStep{RolloutID: "r1", Index: 0, NodeID: n.ID}
	if err := NewRolloutHooks(RolloutConfig{Runner: r}).BeforeStep(e.ctx, ro, st); err != nil {
		t.Fatal(err)
	}
	fn.mu.Lock()
	fn.results = []*nodev1.DiagnosticResult{nodeResult("engine.ready", "", nodev1.CheckStatus_CHECK_STATUS_FAIL, "down")}
	fn.mu.Unlock()
	// Another panel's hooks: the before-run is found in the store.
	h := NewRolloutHooks(RolloutConfig{Runner: r, BeforeRun: func(ctx context.Context, nodeID, change string) string {
		runs, err := e.db.DiagnosticRunsByChange(ctx, change)
		if err != nil || len(runs) == 0 {
			return ""
		}
		return runs[0].ID
	}})
	st.Status = store.StepReverted
	if err := h.AfterStep(e.ctx, ro, st); err != nil {
		t.Fatal(err)
	}
	runs := e.runsOf(n.ID)
	before, after := ofReason(runs, store.RunBeforeChange), ofReason(runs, store.RunAfterChange)
	if len(before) != 1 || len(after) != 1 {
		t.Fatalf("runs %+v", runs)
	}
	if after[0].RelatedRunID != before[0].ID || !after[0].Regressed || before[0].Regressed {
		t.Fatalf("before %+v after %+v", before[0], after[0])
	}
	if len(events(t, e.db, "diagnostics.regressed")) != 1 {
		t.Fatal("no event diagnostics.regressed")
	}
}

// The hooks' wait ends with their context (an Abort or a Pause of the
// rollout): a node busy all along gets a skipped run that says so, and a run
// that goes on is left to the runner.
func TestRolloutHooksEndWithTheirContext(t *testing.T) {
	ro := &store.Rollout{ID: "r1"}
	st := &store.RolloutStep{RolloutID: "r1", Index: 0, NodeID: "n1"}
	for name, f := range map[string]*fakeStepRunner{"busy": {gate: make(chan struct{})}, "running": {waitHang: true}} {
		t.Run(name, func(t *testing.T) {
			h := NewRolloutHooks(RolloutConfig{Runner: f})
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(100*time.Millisecond, cancel)
			start := time.Now()
			if err := h.BeforeStep(ctx, ro, st); err != nil {
				t.Fatal(err)
			}
			if d := time.Since(start); d > time.Second {
				t.Fatalf("BeforeStep took %s after its context ended", d)
			}
			runs := f.ofReason(store.RunBeforeChange)
			if len(runs) != 1 {
				t.Fatalf("runs %+v", runs)
			}
			if name == "busy" && !strings.Contains(runs[0].why, "paused or aborted") {
				t.Errorf("skipped run %+v", runs[0])
			}
		})
	}
}
