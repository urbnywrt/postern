package diagnostics

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// changes returns the runs around changes of a runner, with short waits, and
// ends them with the test.
func (e *env) changes(r *Runner, change func(*ChangesConfig)) *Changes {
	cfg := ChangesConfig{Runner: r, DB: e.db, BeforeWait: 2 * time.Second, AfterDelay: 50 * time.Millisecond,
		ApplyWait: 5 * time.Second, ApplyPoll: 10 * time.Millisecond, AutoEvery: time.Hour}
	if change != nil {
		change(&cfg)
	}
	c := NewChanges(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	c.Start(ctx)
	e.t.Cleanup(func() { cancel(); c.Drain() })
	return c
}

// runsOf lists the runs of a node, oldest first.
func (e *env) runsOf(nodeID string) []*store.DiagnosticRun {
	e.t.Helper()
	runs, err := e.db.ListDiagnosticRuns(e.ctx, nodeID, nil, 50)
	if err != nil {
		e.t.Fatal(err)
	}
	slices.Reverse(runs)
	return runs
}

// eventually waits for cond, at most 10 s.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ofReason are the runs of a reason.
func ofReason(runs []*store.DiagnosticRun, reason string) []*store.DiagnosticRun {
	var out []*store.DiagnosticRun
	for _, r := range runs {
		if r.Reason == reason {
			out = append(out, r)
		}
	}
	return out
}

func TestBeforeRunsTheScopeAndWaitsForIt(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	p := e.proxy(e.listener(n.ID, 443, ""), nil)
	f := &fakeNode{results: []*nodev1.DiagnosticResult{nodeResult("host.docker", "", nodev1.CheckStatus_CHECK_STATUS_OK, "")}}
	e.agent(n.ID, f)
	c := e.changes(e.runner(0), nil)

	id := c.Before(e.ctx, n.ID, "proxy:"+p.ID, "proxy.update egress_chain_id")
	run := e.wait(c.cfg.Runner, id)
	if run.State != store.RunDone || run.Reason != store.RunBeforeChange || run.Scope != "proxy:"+p.ID || run.Change != "proxy.update egress_chain_id" {
		t.Errorf("before-run %+v", run)
	}
	if got := f.calls(); len(got) != 1 || got[0] != "proxy:"+p.ID {
		t.Errorf("the node ran %v", got)
	}
}

// A before-run is waited for at most BeforeWait (90 s): the run is cut off
// as partial and the change goes on.
func TestBeforeIsBounded(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	f := &fakeNode{hold: make(chan struct{})}
	e.agent(n.ID, f)
	t.Cleanup(func() { close(f.hold) })
	c := e.changes(e.runner(0), func(c *ChangesConfig) { c.BeforeWait = 400 * time.Millisecond })

	start := time.Now()
	id := c.Before(e.ctx, n.ID, ScopeNode, "node.dns_mode doh")
	if d := time.Since(start); d > 400*time.Millisecond+300*time.Millisecond {
		t.Errorf("Before took %v", d)
	}
	run := e.wait(c.cfg.Runner, id)
	if run.State != store.RunPartial {
		t.Errorf("the before-run is %s, want partial", run.State)
	}
}

func TestBeforeOfAnOfflineOrBusyNode(t *testing.T) {
	e := newEnv(t)
	off := e.node(func(n *store.Node) { n.Status = store.NodeStatusOffline })
	r := e.runner(0)
	// A skipped run ends as soon as the panel's own checks are stored, which
	// a short wait (its deadline a tenth of it) could cut off as partial
	// under load: these get a long wait (a deadline of 28 s), and return as
	// soon as the run ends.
	c := e.changes(r, func(c *ChangesConfig) { c.BeforeWait = 30 * time.Second })
	if run := e.wait(r, c.Before(e.ctx, off.ID, ScopeNode, "x")); run.State != store.RunSkipped {
		t.Errorf("offline: %s", run.State)
	}
	noDiag := e.node(func(n *store.Node) { n.HostInfo.Capabilities = nil })
	if run := e.wait(r, c.Before(e.ctx, noDiag.ID, ScopeNode, "x")); run.State != store.RunSkipped {
		t.Errorf("without diagnostics: %s", run.State)
	}

	busy := e.node(nil)
	f := &fakeNode{hold: make(chan struct{}), started: make(chan struct{}, 1)}
	e.agent(busy.ID, f)
	t.Cleanup(func() { close(f.hold) }) // before the agent's server closes
	if _, _, err := r.StartManual(e.ctx, busy.ID, ScopeNode, "", nil); err != nil {
		t.Fatal(err)
	}
	<-f.started
	// A busy node is waited for the whole wait: a short one.
	c = e.changes(r, func(c *ChangesConfig) { c.BeforeWait = 300 * time.Millisecond })
	run := e.wait(r, c.Before(e.ctx, busy.ID, ScopeNode, "x"))
	if run.State != store.RunSkipped || !strings.Contains(run.Error, "busy") || run.Reason != store.RunBeforeChange {
		t.Errorf("busy: %+v", run)
	}
}

// After waits for the node to apply the generation, then AfterDelay, and runs
// the scope, related to the before-run.
func TestAfterRunsOnceTheNodeAppliedTheChange(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	p := e.proxy(e.listener(n.ID, 443, ""), nil)
	f := &fakeNode{results: []*nodev1.DiagnosticResult{nodeResult("host.docker", "", nodev1.CheckStatus_CHECK_STATUS_OK, "")}}
	e.agent(n.ID, f)
	r := e.runner(0)
	c := e.changes(r, nil)
	before := c.Before(e.ctx, n.ID, "proxy:"+p.ID, "proxy.update egress_chain_id")
	e.wait(r, before)
	gen, err := e.db.NextNodeGeneration(e.ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.After(n.ID, "proxy:"+p.ID, "proxy.update egress_chain_id", before, gen)
	time.Sleep(200 * time.Millisecond)
	if got := ofReason(e.runsOf(n.ID), store.RunAfterChange); len(got) != 0 {
		t.Fatalf("an after-run before the node applied the change: %+v", got[0])
	}
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error { n.AppliedGeneration = gen; return nil }); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the after-run", func() bool { return len(ofReason(e.runsOf(n.ID), store.RunAfterChange)) == 1 })
	after := ofReason(e.runsOf(n.ID), store.RunAfterChange)[0]
	if after.RelatedRunID != before || after.Scope != "proxy:"+p.ID || after.Change != "proxy.update egress_chain_id" {
		t.Errorf("after-run %+v", after)
	}
}

// fixedClock is a clock that a test moves.
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fixedClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// lights stores the light checks of a node.
func (e *env) lights(nodeID string, checks ...store.NodeCheck) {
	e.t.Helper()
	if _, err := e.db.ReplaceNodeChecks(e.ctx, nodeID, checks, time.Now()); err != nil {
		e.t.Fatal(err)
	}
}

// A change that the node makes by itself gets a copy of the light checks as
// its before-run and a full after-run, related to it, AfterDelay later; the
// same node and scope again within AutoEvery gets none.
func TestNodeChangesGetAutomaticPairs(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	p := e.proxy(e.listener(n.ID, 443, ""), nil)
	e.lights(n.ID, store.NodeCheck{CheckID: "engine.ready", Target: "proxy:" + p.ID, Layer: "engine", Status: StatusOK})
	e.agent(n.ID, &fakeNode{})
	clock := &fixedClock{t: time.Now()}
	c := e.changes(e.runner(0), func(c *ChangesConfig) { c.Now = clock.now; c.AutoEvery = 5 * time.Minute })

	c.OnServingChange(n.ID, p.ID, 1, 2)
	eventually(t, "the after-run", func() bool { return len(ofReason(e.runsOf(n.ID), store.RunAfterChange)) == 1 })
	runs := e.runsOf(n.ID)
	before := ofReason(runs, store.RunBeforeChange)
	if len(before) != 1 || before[0].State != store.RunDone {
		t.Fatalf("before-runs %+v", before)
	}
	got, err := e.db.DiagnosticRun(e.ctx, before[0].ID)
	if err != nil || len(got.Results) != 1 || got.Results[0].CheckID != "engine.ready" {
		t.Errorf("the light copy: %+v, %v", got, err)
	}
	after := ofReason(runs, store.RunAfterChange)[0]
	if after.RelatedRunID != before[0].ID || after.Scope != "proxy:"+p.ID || !strings.Contains(after.Change, "generation 1 → 2") {
		t.Errorf("after-run %+v", after)
	}

	// Within 5 minutes: nothing more.
	clock.add(4 * time.Minute)
	c.OnServingChange(n.ID, p.ID, 2, 3)
	time.Sleep(300 * time.Millisecond)
	if got := len(e.runsOf(n.ID)); got != 2 {
		t.Errorf("%d runs within the limit, want 2", got)
	}
	// After it: a new pair.
	clock.add(2 * time.Minute)
	c.OnServingChange(n.ID, p.ID, 3, 4)
	eventually(t, "the second pair", func() bool { return len(ofReason(e.runsOf(n.ID), store.RunAfterChange)) == 2 })
}

// More than 3 proxies of a node within the window make one run of the node; 3
// make one run each.
func TestNodeChangesCoalesce(t *testing.T) {
	for _, tc := range []struct {
		proxies int
		want    []string
	}{{4, []string{ScopeNode}}, {3, nil}} {
		e := newEnv(t)
		n := e.node(nil)
		l := e.listener(n.ID, 443, "")
		e.agent(n.ID, &fakeNode{})
		c := e.changes(e.runner(0), func(c *ChangesConfig) { c.AfterDelay = 300 * time.Millisecond })
		var scopes []string
		for i := range tc.proxies {
			p := e.proxy(l, func(p *store.Proxy) { p.Domain = "p" + string(rune('a'+i)) + ".example.com" })
			scopes = append(scopes, "proxy:"+p.ID)
			c.OnServingChange(n.ID, p.ID, 1, 2)
		}
		want := tc.want
		if want == nil {
			want = slices.Sorted(slices.Values(scopes))
		}
		eventually(t, "the after-runs", func() bool { return len(ofReason(e.runsOf(n.ID), store.RunAfterChange)) == len(want) })
		time.Sleep(100 * time.Millisecond)
		runs := e.runsOf(n.ID)
		var got []string
		for _, r := range ofReason(runs, store.RunAfterChange) {
			got = append(got, r.Scope)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%d proxies: after-runs of %v, want %v", tc.proxies, got, want)
		}
		if b := ofReason(runs, store.RunBeforeChange); len(b) != 1 {
			t.Errorf("%d proxies: %d light copies, want 1", tc.proxies, len(b))
		}
	}
}

// A member that fails over, as the light checks report it, is a change of the
// node; and none is automatic while an operator's change is in progress.
func TestFailoverAndOperatorChanges(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	p := e.proxy(e.listener(n.ID, 443, ""), nil)
	e.agent(n.ID, &fakeNode{})
	r := e.runner(0)
	c := e.changes(r, nil)
	lights := NewLights(e.db, nil, nil)
	lights.OnChanges(c.OnLightChanges)
	report := func(st nodev1.CheckStatus) {
		t.Helper()
		rep := &nodev1.DiagnosticsReport{Results: []*nodev1.DiagnosticResult{{Id: "egress.member", Layer: "egress", Target: "member:C1/E1", Status: st}}}
		if err := lights.OnDiagnostics(e.ctx, n.ID, time.Now(), rep); err != nil {
			t.Fatal(err)
		}
	}
	report(nodev1.CheckStatus_CHECK_STATUS_OK) // the first report is no change
	time.Sleep(150 * time.Millisecond)
	if got := len(e.runsOf(n.ID)); got != 0 {
		t.Fatalf("%d runs after the first report", got)
	}
	report(nodev1.CheckStatus_CHECK_STATUS_WARN)
	eventually(t, "the failover's after-run", func() bool { return len(ofReason(e.runsOf(n.ID), store.RunAfterChange)) == 1 })
	if after := ofReason(e.runsOf(n.ID), store.RunAfterChange)[0]; after.Scope != ScopeNode || !strings.Contains(after.Change, "failover") {
		t.Errorf("after-run %+v", after)
	}

	// An operator's change of the node is in progress: the node's own
	// replacement of an instance gets no pair.
	e.wait(r, c.Before(e.ctx, n.ID, "proxy:"+p.ID, "proxy.update egress_chain_id"))
	count := len(e.runsOf(n.ID))
	c.OnServingChange(n.ID, p.ID, 1, 2)
	time.Sleep(200 * time.Millisecond)
	if got := len(e.runsOf(n.ID)); got != count {
		t.Errorf("%d runs, want %d: an automatic pair during an operator's change", got, count)
	}
}

func TestFailoverRule(t *testing.T) {
	ch := func(id, from, to string) store.CheckChange {
		return store.CheckChange{Check: store.NodeCheck{CheckID: id, Status: to}, From: from}
	}
	for _, tc := range []struct {
		c    store.CheckChange
		want bool
	}{
		{ch("egress.member", StatusOK, StatusWarn), true},
		{ch("egress.member", StatusFail, StatusWarn), true},
		{ch("egress.member", StatusWarn, StatusOK), true},
		{ch("egress.member", StatusOK, StatusFail), false},
		{ch("egress.member", "", StatusWarn), false},
		{ch("engine.ready", StatusOK, StatusWarn), false},
	} {
		if got := failover(tc.c); got != tc.want {
			t.Errorf("failover(%s %s → %s) = %v", tc.c.Check.CheckID, tc.c.From, tc.c.Check.Status, got)
		}
	}
}
