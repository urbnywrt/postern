package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// rolloutFixture is two nodes with a listener and two proxies each, all on
// telemt at the version of their channel, as the proxies of a fleet are before
// a rollout.
type rolloutFixture struct {
	db             *DB
	n1, n2         *Node
	p1, p2, p3, p4 *Proxy // p1 and p2 on n1, p3 and p4 on n2
}

func newRolloutFixture(t *testing.T) *rolloutFixture {
	t.Helper()
	db := newTestDB(t)
	f := &rolloutFixture{db: db}
	f.n1, f.n2 = mustNode(t, db, "n1"), mustNode(t, db, "n2")
	l1, l2 := mustListener(t, db, f.n1.ID, 443), mustListener(t, db, f.n2.ID, 443)
	f.p1, f.p2 = mustProxy(t, db, f.n1.ID, l1.ID, "p1"), mustProxy(t, db, f.n1.ID, l1.ID, "p2")
	f.p3, f.p4 = mustProxy(t, db, f.n2.ID, l2.ID, "p3"), mustProxy(t, db, f.n2.ID, l2.ID, "p4")
	return f
}

// versionRollout is a rollout of the stable channel of telemt from 3.5.13 to
// 3.5.14 over the fixture: the canary p1, then the rest of n1 (p2), then n2
// (p3 and p4). The items record what the proxies hold now.
func (f *rolloutFixture) versionRollout() (*Rollout, []RolloutStep, []RolloutItem) {
	r := &Rollout{
		Kind: RolloutVersion, Component: EngineTelemt, Channel: ChannelStable,
		FromVersion: "3.5.13", ToVersion: "3.5.14", Mode: RolloutModeAuto, PauseSeconds: 120,
		Options:   RolloutOptions{SkipOffline: true, CanaryProxyID: f.p1.ID},
		CreatedBy: "01ADMIN",
	}
	steps := []RolloutStep{
		{Index: 0, NodeID: f.n1.ID, ProxyID: f.p1.ID, Status: StepPending},
		{Index: 1, NodeID: f.n1.ID, Status: StepPending},
		{Index: 2, NodeID: f.n2.ID, Status: StepPending},
	}
	items := []RolloutItem{f.item(f.p1, 0), f.item(f.p2, 1), f.item(f.p3, 2), f.item(f.p4, 2)}
	return r, steps, items
}

// item is the rollout item of a proxy as it is now.
func (f *rolloutFixture) item(p *Proxy, step uint32) RolloutItem {
	return RolloutItem{
		ProxyID: p.ID, NodeID: p.NodeID, StepIndex: step,
		PrevEngine: p.Engine, PrevPolicy: p.EngineVersionPolicy, PrevVersion: p.EngineVersion,
		State: ItemPending,
	}
}

// switchRollout is a rollout of another kind, holding the given nodes and
// nothing else: enough to take part in a conflict.
func switchRollout(component string) *Rollout {
	return &Rollout{Kind: RolloutSwitch, Component: component, ToEngine: component, Mode: RolloutModeManual, Status: RolloutRunning}
}

func (f *rolloutFixture) create(t *testing.T, r *Rollout, nodes []string, steps []RolloutStep, items []RolloutItem) *Rollout {
	t.Helper()
	if err := f.db.CreateRollout(context.Background(), r, nodes, steps, items); err != nil {
		t.Fatalf("CreateRollout: %v", err)
	}
	return r
}

// setStatus moves a rollout to a status.
func (f *rolloutFixture) setStatus(t *testing.T, r *Rollout, status string) {
	t.Helper()
	r.Status = status
	if err := f.db.UpdateRollout(context.Background(), r); err != nil {
		t.Fatalf("UpdateRollout(%s): %v", status, err)
	}
}

// engineOf returns the engine, the version policy and the version of a proxy as
// they are stored.
func (f *rolloutFixture) engineOf(t *testing.T, id string) [3]string {
	t.Helper()
	p, err := f.db.ProxyByID(context.Background(), id)
	if err != nil {
		t.Fatalf("ProxyByID(%s): %v", id, err)
	}
	return [3]string{p.Engine, p.EngineVersionPolicy, p.EngineVersion}
}

// repin is the operator pinning a proxy at a version.
func (f *rolloutFixture) repin(t *testing.T, p *Proxy, version string) {
	t.Helper()
	p.EngineVersionPolicy, p.EngineVersion = EnginePolicyPinned, version
	if err := f.db.UpdateProxy(context.Background(), p); err != nil {
		t.Fatalf("UpdateProxy(%s): %v", p.Name, err)
	}
}

// states returns the state of every item of a rollout, by proxy.
func (f *rolloutFixture) states(t *testing.T, rolloutID string) map[string]string {
	t.Helper()
	_, _, items, err := f.db.Rollout(context.Background(), rolloutID)
	if err != nil {
		t.Fatalf("Rollout: %v", err)
	}
	out := map[string]string{}
	for _, it := range items {
		out[it.ProxyID] = it.State
	}
	return out
}

// wantStates checks the states of the items of a rollout, by the name of the
// proxy.
func (f *rolloutFixture) wantStates(t *testing.T, rolloutID string, want map[*Proxy]string) {
	t.Helper()
	got := f.states(t, rolloutID)
	for p, state := range want {
		if got[p.ID] != state {
			t.Errorf("item of %s is %q, want %q", p.Name, got[p.ID], state)
		}
	}
}

// activeNodes counts the rollout_nodes rows of a rollout that are active.
func activeNodes(t *testing.T, db *DB, rolloutID string) int {
	t.Helper()
	return count(t, db, `SELECT count(*) FROM rollout_nodes WHERE rollout_id = ? AND active = 1`, rolloutID)
}

// byStep orders items as the store returns them.
func byStep(items []RolloutItem) []RolloutItem {
	out := slices.Clone(items)
	slices.SortFunc(out, func(a, b RolloutItem) int {
		if a.StepIndex != b.StepIndex {
			return int(a.StepIndex) - int(b.StepIndex)
		}
		return strings.Compare(a.ProxyID, b.ProxyID)
	})
	return out
}

func sorted(ids []string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

func TestRolloutRoundTrip(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	f.db.now = fixedClock(testNow)
	r, steps, items := f.versionRollout()
	// n1 twice: a node is held once.
	f.create(t, r, []string{f.n1.ID, f.n2.ID, f.n1.ID}, steps, items)

	if len(r.ID) != 26 {
		t.Errorf("ID = %q, want a ULID", r.ID)
	}
	if r.Status != RolloutPreparing || r.CreatedAt != testNow || r.UpdatedAt != testNow {
		t.Errorf("status %q, created %v, updated %v; want preparing at the clock", r.Status, r.CreatedAt, r.UpdatedAt)
	}
	for i, s := range steps {
		if s.RolloutID != r.ID {
			t.Errorf("step %d has rollout id %q, want %q", i, s.RolloutID, r.ID)
		}
	}
	for i, it := range items {
		if it.RolloutID != r.ID {
			t.Errorf("item %d has rollout id %q, want %q", i, it.RolloutID, r.ID)
		}
	}

	gotR, gotSteps, gotItems, err := f.db.Rollout(ctx, r.ID)
	if err != nil {
		t.Fatalf("Rollout: %v", err)
	}
	if !reflect.DeepEqual(gotR, r) {
		t.Errorf("rollout = %+v\nwant    %+v", gotR, r)
	}
	if !reflect.DeepEqual(gotSteps, steps) {
		t.Errorf("steps = %+v\nwant  %+v", gotSteps, steps)
	}
	if want := byStep(items); !reflect.DeepEqual(gotItems, want) {
		t.Errorf("items = %+v\nwant  %+v", gotItems, want)
	}
	if n := activeNodes(t, f.db, r.ID); n != 2 {
		t.Errorf("%d active rollout_nodes rows, want 2", n)
	}
	if _, _, _, err := f.db.Rollout(ctx, "01NOPE"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Rollout of an unknown id: err = %v, want ErrNotFound", err)
	}
}

func TestRolloutWithoutStepsOrItems(t *testing.T) {
	f := newRolloutFixture(t)
	r := f.create(t, switchRollout(EngineMtg), nil, nil, nil)
	got, steps, items, err := f.db.Rollout(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, r) || steps != nil || items != nil {
		t.Errorf("rollout = %+v, %v, %v; want %+v and none", got, steps, items, r)
	}
}

func TestUpdateRollout(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	f.db.now = fixedClock(testNow)
	r, steps, items := f.versionRollout()
	f.create(t, r, []string{f.n1.ID, f.n2.ID}, steps, items)

	later := testNow.Add(time.Minute)
	f.db.now = fixedClock(later)
	resume := later.Add(2 * time.Minute)
	r.Status, r.CurrentStep, r.ResumeAt, r.Error = RolloutRunning, 1, &resume, "step 0: the node did not report"
	r.Options.SkipOffline = false
	if err := f.db.UpdateRollout(ctx, r); err != nil {
		t.Fatalf("UpdateRollout: %v", err)
	}
	if r.UpdatedAt != later || r.CreatedAt != testNow {
		t.Errorf("updated %v, created %v; want %v and %v", r.UpdatedAt, r.CreatedAt, later, testNow)
	}
	got, _, _, err := f.db.Rollout(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, r) {
		t.Errorf("rollout = %+v\nwant    %+v", got, r)
	}
	if n := activeNodes(t, f.db, r.ID); n != 2 {
		t.Errorf("%d active nodes while running, want 2", n)
	}

	// Completed: the time it finished is now unless it is given, and the nodes
	// are let go, in the same transaction.
	end := later.Add(time.Hour)
	f.db.now = fixedClock(end)
	r.Status, r.ResumeAt, r.Error = RolloutCompleted, nil, ""
	if err := f.db.UpdateRollout(ctx, r); err != nil {
		t.Fatal(err)
	}
	if r.FinishedAt == nil || *r.FinishedAt != end {
		t.Errorf("FinishedAt = %v, want %v", r.FinishedAt, end)
	}
	got, _, _, err = f.db.Rollout(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, r) {
		t.Errorf("completed rollout = %+v\nwant %+v", got, r)
	}
	if n := activeNodes(t, f.db, r.ID); n != 0 {
		t.Errorf("%d active nodes after completing, want 0", n)
	}
	if n := count(t, f.db, `SELECT count(*) FROM rollout_nodes WHERE rollout_id = ?`, r.ID); n != 2 {
		t.Errorf("%d rollout_nodes rows after completing, want the 2 kept, inactive", n)
	}

	if err := f.db.UpdateRollout(ctx, &Rollout{ID: "01NOPE", Status: RolloutRunning, Mode: RolloutModeAuto}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateRollout of an unknown id: err = %v, want ErrNotFound", err)
	}
}

func TestRolloutConflictPerChannel(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	// a holds n1 alone: its steps and items are those of n1.
	a, steps, items := f.versionRollout()
	f.create(t, a, []string{f.n1.ID}, steps[:2], items[:2])

	// A second version rollout of the same component and channel, on nodes
	// that are free: refused, and nothing of it is stored.
	b, _, _ := f.versionRollout()
	b.ToVersion = "3.5.15"
	err := f.db.CreateRollout(ctx, b, []string{f.n2.ID}, nil, nil)
	if !errors.Is(err, ErrRolloutConflict) || !errors.Is(err, ErrConflict) {
		t.Fatalf("second version rollout of (telemt, stable): err = %v, want ErrRolloutConflict, which is a conflict", err)
	}
	var rc *RolloutConflict
	if !errors.As(err, &rc) {
		t.Fatalf("err = %v, want a *RolloutConflict", err)
	}
	if rc.Holder != a.ID || rc.NodeID != "" || rc.Component != EngineTelemt || rc.Channel != ChannelStable {
		t.Errorf("conflict = %+v, want the holder %s of (telemt, stable)", rc, a.ID)
	}
	for _, want := range []string{a.ID, "telemt", "stable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to name %s", err, want)
		}
	}
	if n := count(t, f.db, `SELECT count(*) FROM rollouts`); n != 1 {
		t.Errorf("%d rollouts stored, want 1", n)
	}
	if n := count(t, f.db, `SELECT count(*) FROM rollout_nodes`); n != 1 {
		t.Errorf("%d rollout_nodes rows, want 1", n)
	}

	// The other channel is free, and so is another kind on the same channel.
	c, _, _ := f.versionRollout()
	c.Channel = ChannelLatest
	f.create(t, c, []string{f.n2.ID}, nil, nil)
	d := switchRollout(EngineTelemt)
	d.Channel = ChannelStable
	f.create(t, d, nil, nil, nil)

	// Once a is over, its channel is free again.
	f.setStatus(t, a, RolloutCompleted)
	e, _, _ := f.versionRollout()
	f.create(t, e, nil, nil, nil)
}

func TestRolloutConflictPerNode(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	a := f.create(t, switchRollout(EngineMtg), []string{f.n1.ID}, nil, nil)

	// Any rollout that touches n1 is refused while a holds it, whatever its
	// kind, and nothing of it is stored.
	b := &Rollout{Kind: RolloutNode, Component: "postern", ToVersion: "v0.6.0", Mode: RolloutModeAuto, Status: RolloutPreparing}
	err := f.db.CreateRollout(ctx, b, []string{f.n2.ID, f.n1.ID}, []RolloutStep{{Index: 0, NodeID: f.n2.ID, Status: StepPending}}, nil)
	var rc *RolloutConflict
	if !errors.As(err, &rc) {
		t.Fatalf("a rollout on a node that another holds: err = %v, want a *RolloutConflict", err)
	}
	if rc.Holder != a.ID || rc.NodeID != f.n1.ID {
		t.Errorf("conflict = %+v, want holder %s of node %s", rc, a.ID, f.n1.ID)
	}
	if !strings.Contains(err.Error(), a.ID) || !strings.Contains(err.Error(), f.n1.ID) {
		t.Errorf("err = %v, want it to name the holder and the node", err)
	}
	if n := count(t, f.db, `SELECT count(*) FROM rollouts`); n != 1 {
		t.Errorf("%d rollouts stored, want 1", n)
	}
	if n := count(t, f.db, `SELECT count(*) FROM rollout_nodes`) + count(t, f.db, `SELECT count(*) FROM rollout_steps`); n != 1 {
		t.Errorf("%d rows of nodes and steps, want the 1 of the first rollout", n)
	}

	// n2 is free.
	c, _, _ := f.versionRollout()
	c.Component, c.Channel = "xray", ChannelStable
	f.create(t, c, []string{f.n2.ID}, nil, nil)

	// An aborted rollout lets its nodes go.
	f.setStatus(t, a, RolloutAborted)
	if n := activeNodes(t, f.db, a.ID); n != 0 {
		t.Errorf("%d active nodes after aborting, want 0", n)
	}
	f.create(t, switchRollout(EngineMtg), []string{f.n1.ID}, nil, nil)
}

// A rollout holds its nodes in every status that is not over: a failed one
// waits for Retry or Abort, and must not be run over by another.
func TestFailedRolloutHoldsNodes(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	a := f.create(t, switchRollout(EngineMtg), []string{f.n1.ID}, nil, nil)
	for _, status := range []string{RolloutPaused, RolloutFailed} {
		f.setStatus(t, a, status)
		err := f.db.CreateRollout(ctx, switchRollout(EngineMtg), []string{f.n1.ID}, nil, nil)
		var rc *RolloutConflict
		if !errors.As(err, &rc) || rc.Holder != a.ID {
			t.Errorf("while a is %s: err = %v, want a conflict with %s", status, err, a.ID)
		}
	}
	f.setStatus(t, a, RolloutCompleted)
	f.create(t, switchRollout(EngineMtg), []string{f.n1.ID}, nil, nil)
}

// Several rollouts that touch one node are created at the same time: exactly one
// is stored, and the others are told which one.
func TestRolloutConflictConcurrent(t *testing.T) {
	const rounds, racers = 10, 4
	db := newTestDB(t)
	ctx := context.Background()
	for round := range rounds {
		node := mustNode(t, db, fmt.Sprintf("node-%d", round))
		errs := make([]error, racers)
		ids := make([]string, racers)
		var wg sync.WaitGroup
		for i := range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := switchRollout(EngineMtg)
				errs[i] = db.CreateRollout(ctx, r, []string{node.ID}, []RolloutStep{{Index: 0, NodeID: node.ID, Status: StepPending}}, nil)
				ids[i] = r.ID
			}()
		}
		wg.Wait()
		var winners []string
		for i, err := range errs {
			if err == nil {
				winners = append(winners, ids[i])
			}
		}
		if len(winners) != 1 {
			t.Fatalf("round %d: %d of %d rollouts were created (%v), want exactly one", round, len(winners), racers, errs)
		}
		for i, err := range errs {
			if err == nil {
				continue
			}
			var rc *RolloutConflict
			if !errors.As(err, &rc) || rc.Holder != winners[0] || rc.NodeID != node.ID {
				t.Errorf("round %d, racer %d: err = %v, want a conflict with %s on %s", round, i, err, winners[0], node.ID)
			}
		}
		if n := count(t, db, `SELECT count(*) FROM rollout_nodes WHERE node_id = ?`, node.ID); n != 1 {
			t.Errorf("round %d: %d rollout_nodes rows for the node, want 1", round, n)
		}
	}
	if n := count(t, db, `SELECT count(*) FROM rollouts`); n != rounds {
		t.Errorf("%d rollouts, want %d", n, rounds)
	}
}

// A step keeps the time it started: a resume after a restart of the panel has no
// start time of its own, and another one is not taken either.
func TestUpdateRolloutStepKeepsStartedAt(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	r, steps, items := f.versionRollout()
	f.create(t, r, []string{f.n1.ID, f.n2.ID}, steps, items)
	s := &steps[0]
	t1 := testNow.Add(time.Minute)
	t2 := t1.Add(time.Minute)

	s.Status, s.StartedAt, s.Generation = StepApplying, &t1, 7
	if err := f.db.UpdateRolloutStep(ctx, s); err != nil {
		t.Fatalf("UpdateRolloutStep: %v", err)
	}
	_, got, _, err := f.db.Rollout(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got[0], *s) {
		t.Errorf("step = %+v\nwant %+v", got[0], *s)
	}

	// A resume: no start time in the record; the stored one stays and comes
	// back in the record.
	s.Status, s.StartedAt = StepVerifying, nil
	if err := f.db.UpdateRolloutStep(ctx, s); err != nil {
		t.Fatal(err)
	}
	if s.StartedAt == nil || *s.StartedAt != t1 {
		t.Errorf("StartedAt in the record after a resume = %v, want the stored %v", s.StartedAt, t1)
	}
	_, got, _, _ = f.db.Rollout(ctx, r.ID)
	if got[0].StartedAt == nil || *got[0].StartedAt != t1 || got[0].Status != StepVerifying {
		t.Errorf("stored step after a resume = %+v, want started at %v and verifying", got[0], t1)
	}

	// Another start time is not taken either; the rest is written.
	s.Status, s.StartedAt, s.FinishedAt, s.Error = StepDone, &t2, &t2, "none"
	if err := f.db.UpdateRolloutStep(ctx, s); err != nil {
		t.Fatal(err)
	}
	if *s.StartedAt != t1 {
		t.Errorf("StartedAt in the record = %v, want the stored %v kept", *s.StartedAt, t1)
	}
	_, got, _, _ = f.db.Rollout(ctx, r.ID)
	if *got[0].StartedAt != t1 || got[0].FinishedAt == nil || *got[0].FinishedAt != t2 || got[0].Status != StepDone || got[0].Error != "none" || got[0].Generation != 7 {
		t.Errorf("stored step = %+v, want started %v, finished %v, done, error none, generation 7", got[0], t1, t2)
	}
	if !reflect.DeepEqual(got[1], steps[1]) || !reflect.DeepEqual(got[2], steps[2]) {
		t.Errorf("the other steps changed: %+v", got[1:])
	}

	if err := f.db.UpdateRolloutStep(ctx, &RolloutStep{RolloutID: r.ID, Index: 9, Status: StepDone}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateRolloutStep of an unknown step: err = %v, want ErrNotFound", err)
	}
}

func TestApplyItems(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	r, steps, items := f.versionRollout()
	f.create(t, r, []string{f.n1.ID, f.n2.ID}, steps, items)
	before := f.engineOf(t, f.p4.ID) // channel, no version of its own
	target := [3]string{EngineTelemt, EnginePolicyRollout, "3.5.14"}
	apply := func(items []RolloutItem) []string {
		t.Helper()
		nodeIDs, err := f.db.ApplyItems(ctx, r.ID, items, EngineTelemt, EnginePolicyRollout, "3.5.14")
		if err != nil {
			t.Fatalf("ApplyItems: %v", err)
		}
		return nodeIDs
	}

	// The operator pinned p3 after the rollout was made and before its step.
	f.repin(t, f.p3, "3.5.12")

	// The first two steps: the items of n1 are written, and n1 is to be told.
	if got := apply(items[:2]); !reflect.DeepEqual(got, []string{f.n1.ID}) {
		t.Errorf("nodes = %v, want [%s]", got, f.n1.ID)
	}
	for _, p := range []*Proxy{f.p1, f.p2} {
		if got := f.engineOf(t, p.ID); got != target {
			t.Errorf("%s = %v, want %v", p.Name, got, target)
		}
	}
	if got := f.engineOf(t, f.p4.ID); got != before {
		t.Errorf("p4, not in the step, = %v, want it as it was", got)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p1: ItemApplied, f.p2: ItemApplied, f.p3: ItemPending, f.p4: ItemPending})
	if items[0].State != ItemApplied || items[1].State != ItemApplied {
		t.Errorf("states in the records = %q, %q; want applied", items[0].State, items[1].State)
	}

	// The operator pins p2 again while the rollout runs. An apply of the same
	// items again (a retry, or a step whose generation was not stored) writes p1
	// again, and leaves p2 as the operator wants it: detached.
	f.repin(t, f.p2, "3.5.13")
	if got := apply(items[:2]); !reflect.DeepEqual(got, []string{f.n1.ID}) {
		t.Errorf("nodes of the second apply = %v, want [%s]", got, f.n1.ID)
	}
	if got := f.engineOf(t, f.p1.ID); got != target {
		t.Errorf("p1 after the second apply = %v, want %v", got, target)
	}
	if got, want := f.engineOf(t, f.p2.ID), [3]string{EngineTelemt, EnginePolicyPinned, "3.5.13"}; got != want {
		t.Errorf("p2, pinned by the operator, = %v, want %v", got, want)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p1: ItemApplied, f.p2: ItemDetached})
	if items[1].State != ItemDetached {
		t.Errorf("state of p2 in the record = %q, want detached", items[1].State)
	}

	// The last step: p3, changed before its first apply, is detached; p4 goes.
	if got := apply(items[2:]); !reflect.DeepEqual(got, []string{f.n2.ID}) {
		t.Errorf("nodes of the last step = %v, want [%s]", got, f.n2.ID)
	}
	if got, want := f.engineOf(t, f.p3.ID), [3]string{EngineTelemt, EnginePolicyPinned, "3.5.12"}; got != want {
		t.Errorf("p3 = %v, want %v", got, want)
	}
	if got := f.engineOf(t, f.p4.ID); got != target {
		t.Errorf("p4 = %v, want %v", got, target)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p3: ItemDetached, f.p4: ItemApplied})

	// A detached item is left alone from then on, and no node is to be told.
	if got := apply(items[1:2]); len(got) != 0 {
		t.Errorf("nodes of an apply of a detached item = %v, want none", got)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p2: ItemDetached})

	// Items of both nodes at once: both nodes, in order.
	if got := apply(items); !reflect.DeepEqual(got, sorted([]string{f.n1.ID, f.n2.ID})) {
		t.Errorf("nodes of an apply of everything = %v, want both", got)
	}

	// A proxy that is gone: its item is detached.
	if err := f.db.DeleteProxy(ctx, f.p1.ID); err != nil {
		t.Fatal(err)
	}
	if got := apply(items[:1]); len(got) != 0 {
		t.Errorf("nodes of an apply of a deleted proxy = %v, want none", got)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p1: ItemDetached})

	// An item that is not of the rollout: nothing is written.
	_, err := f.db.ApplyItems(ctx, r.ID, []RolloutItem{items[3], {ProxyID: "01NOPE", NodeID: f.n2.ID}}, EngineTelemt, EnginePolicyRollout, "3.5.14")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("ApplyItems with an item that is not of the rollout: err = %v, want ErrNotFound", err)
	}
}

func TestRevertItems(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	r, steps, items := f.versionRollout()
	f.create(t, r, []string{f.n1.ID, f.n2.ID}, steps, items)
	prev := f.engineOf(t, f.p1.ID)
	if _, err := f.db.ApplyItems(ctx, r.ID, items[:2], EngineTelemt, EnginePolicyRollout, "3.5.14"); err != nil {
		t.Fatal(err)
	}
	// The operator pins p2 after the apply.
	f.repin(t, f.p2, "3.5.13")

	nodeIDs, err := f.db.RevertItems(ctx, r.ID, items[:3])
	if err != nil {
		t.Fatalf("RevertItems: %v", err)
	}
	if !reflect.DeepEqual(nodeIDs, []string{f.n1.ID}) {
		t.Errorf("nodes = %v, want [%s]", nodeIDs, f.n1.ID)
	}
	if got := f.engineOf(t, f.p1.ID); got != prev {
		t.Errorf("p1 after the revert = %v, want what it had, %v", got, prev)
	}
	if got, want := f.engineOf(t, f.p2.ID), [3]string{EngineTelemt, EnginePolicyPinned, "3.5.13"}; got != want {
		t.Errorf("p2, pinned by the operator, = %v, want %v", got, want)
	}
	if got := f.engineOf(t, f.p3.ID); got != prev {
		t.Errorf("p3, never applied, = %v, want %v", got, prev)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p1: ItemReverted, f.p2: ItemDetached, f.p3: ItemPending, f.p4: ItemPending})
	if items[0].State != ItemReverted || items[1].State != ItemDetached || items[2].State != ItemPending {
		t.Errorf("states in the records = %q, %q, %q", items[0].State, items[1].State, items[2].State)
	}

	// A reverted item can be applied again (Retry).
	nodeIDs, err = f.db.ApplyItems(ctx, r.ID, items[:1], EngineTelemt, EnginePolicyRollout, "3.5.14")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nodeIDs, []string{f.n1.ID}) || f.engineOf(t, f.p1.ID) != [3]string{EngineTelemt, EnginePolicyRollout, "3.5.14"} {
		t.Errorf("after a retry: nodes %v, p1 %v", nodeIDs, f.engineOf(t, f.p1.ID))
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p1: ItemApplied})

	// Reverting what was never applied is nothing, and an unknown item is an
	// error that writes nothing.
	if nodeIDs, err := f.db.RevertItems(ctx, r.ID, items[2:]); err != nil || len(nodeIDs) != 0 {
		t.Errorf("RevertItems of pending items = %v, %v; want none and no error", nodeIDs, err)
	}
	if _, err := f.db.RevertItems(ctx, r.ID, []RolloutItem{items[0], {ProxyID: "01NOPE"}}); !errors.Is(err, ErrNotFound) {
		t.Errorf("RevertItems with an unknown item: err = %v, want ErrNotFound", err)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p1: ItemApplied})
}

// Items of a node that was skipped are deferred: when the rollout completes,
// they are pinned at the version they had, which for a proxy on its channel is
// the version the channel had, and the applied items follow the channel.
func TestDeferAndFinishItemsOnChannel(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	// p4 was pinned at 3.5.12 before the rollout: its item says so.
	f.repin(t, f.p4, "3.5.12")
	r, steps, items := f.versionRollout()
	f.create(t, r, []string{f.n1.ID, f.n2.ID}, steps, items)

	// n2 is offline during its step.
	if err := f.db.DeferItems(ctx, r.ID, []string{f.p3.ID, f.p4.ID}); err != nil {
		t.Fatalf("DeferItems: %v", err)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p3: ItemDeferred, f.p4: ItemDeferred})
	if _, err := f.db.ApplyItems(ctx, r.ID, items[:2], EngineTelemt, EnginePolicyRollout, "3.5.14"); err != nil {
		t.Fatal(err)
	}
	// An applied item is not deferred; an unknown one is an error.
	if err := f.db.DeferItems(ctx, r.ID, []string{f.p1.ID}); err != nil {
		t.Fatalf("DeferItems of an applied item: %v", err)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p1: ItemApplied})
	if err := f.db.DeferItems(ctx, r.ID, []string{f.p2.ID, "01NOPE"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeferItems with an unknown proxy: err = %v, want ErrNotFound", err)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p2: ItemApplied})
	// A deferred item is left alone by an apply.
	if nodeIDs, err := f.db.ApplyItems(ctx, r.ID, items[2:3], EngineTelemt, EnginePolicyRollout, "3.5.14"); err != nil || len(nodeIDs) != 0 {
		t.Errorf("ApplyItems of a deferred item = %v, %v; want none", nodeIDs, err)
	}

	nodeIDs, err := f.db.FinishItems(ctx, r.ID, EnginePolicyChannel)
	if err != nil {
		t.Fatalf("FinishItems: %v", err)
	}
	if !reflect.DeepEqual(nodeIDs, sorted([]string{f.n1.ID, f.n2.ID})) {
		t.Errorf("nodes = %v, want both", nodeIDs)
	}
	for _, p := range []*Proxy{f.p1, f.p2} {
		if got, want := f.engineOf(t, p.ID), [3]string{EngineTelemt, EnginePolicyChannel, ""}; got != want {
			t.Errorf("%s = %v, want %v", p.Name, got, want)
		}
	}
	if got, want := f.engineOf(t, f.p3.ID), [3]string{EngineTelemt, EnginePolicyPinned, "3.5.13"}; got != want {
		t.Errorf("p3, deferred from the channel, = %v, want it pinned at the version the channel had, %v", got, want)
	}
	if got, want := f.engineOf(t, f.p4.ID), [3]string{EngineTelemt, EnginePolicyPinned, "3.5.12"}; got != want {
		t.Errorf("p4, deferred from its pin, = %v, want %v", got, want)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p1: ItemApplied, f.p2: ItemApplied, f.p3: ItemDeferred, f.p4: ItemDeferred})

	if _, err := f.db.FinishItems(ctx, r.ID, EnginePolicyRollout); err == nil {
		t.Error("FinishItems with the rollout policy succeeded")
	}
	if _, err := f.db.FinishItems(ctx, "01NOPE", EnginePolicyChannel); !errors.Is(err, ErrNotFound) {
		t.Errorf("FinishItems of an unknown rollout: err = %v, want ErrNotFound", err)
	}
}

// Finishing with a pin keeps the version that was rolled out; whatever the
// operator changed in the meantime is left alone.
func TestFinishItemsPinned(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	r, steps, items := f.versionRollout()
	f.create(t, r, []string{f.n1.ID, f.n2.ID}, steps, items)
	if err := f.db.DeferItems(ctx, r.ID, []string{f.p3.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ApplyItems(ctx, r.ID, []RolloutItem{items[0], items[1], items[3]}, EngineTelemt, EnginePolicyRollout, "3.5.14"); err != nil {
		t.Fatal(err)
	}
	// The operator pins an applied proxy and a deferred one.
	f.repin(t, f.p2, "3.5.13")
	f.repin(t, f.p3, "3.5.11")

	nodeIDs, err := f.db.FinishItems(ctx, r.ID, EnginePolicyPinned)
	if err != nil {
		t.Fatalf("FinishItems: %v", err)
	}
	if !reflect.DeepEqual(nodeIDs, sorted([]string{f.n1.ID, f.n2.ID})) {
		t.Errorf("nodes = %v, want both", nodeIDs)
	}
	for _, p := range []*Proxy{f.p1, f.p4} {
		if got, want := f.engineOf(t, p.ID), [3]string{EngineTelemt, EnginePolicyPinned, "3.5.14"}; got != want {
			t.Errorf("%s = %v, want %v", p.Name, got, want)
		}
	}
	if got, want := f.engineOf(t, f.p2.ID), [3]string{EngineTelemt, EnginePolicyPinned, "3.5.13"}; got != want {
		t.Errorf("p2 = %v, want the pin of the operator, %v", got, want)
	}
	if got, want := f.engineOf(t, f.p3.ID), [3]string{EngineTelemt, EnginePolicyPinned, "3.5.11"}; got != want {
		t.Errorf("p3 = %v, want the pin of the operator, %v", got, want)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p1: ItemApplied, f.p2: ItemDetached, f.p3: ItemDetached, f.p4: ItemApplied})
}

func TestListRollouts(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	f.db.now = fixedClock(testNow)
	a, _, _ := f.versionRollout()
	f.create(t, a, nil, nil, nil)
	f.db.now = fixedClock(testNow.Add(time.Minute))
	b, _, _ := f.versionRollout()
	b.Component = EngineMtg
	f.create(t, b, nil, nil, nil)
	f.setStatus(t, b, RolloutCompleted)
	f.db.now = fixedClock(testNow.Add(2 * time.Minute))
	c := f.create(t, switchRollout(EngineMtg), nil, nil, nil)
	f.setStatus(t, c, RolloutFailed)

	ids := func(list []*Rollout) []string {
		var out []string
		for _, r := range list {
			out = append(out, r.ID)
		}
		return out
	}
	for _, tt := range []struct {
		name       string
		activeOnly bool
		limit      int
		want       []string
	}{
		{"everything, newest first", false, 0, []string{c.ID, b.ID, a.ID}},
		{"active only", true, 0, []string{c.ID, a.ID}},
		{"a limit", false, 2, []string{c.ID, b.ID}},
		{"active with a limit", true, 1, []string{c.ID}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := f.db.ListRollouts(ctx, tt.activeOnly, tt.limit)
			if err != nil {
				t.Fatalf("ListRollouts: %v", err)
			}
			if !reflect.DeepEqual(ids(got), tt.want) {
				t.Errorf("rollouts = %v, want %v", ids(got), tt.want)
			}
		})
	}
	// What the list returns is what Rollout returns.
	list, err := f.db.ListRollouts(ctx, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(list[0], c) || !reflect.DeepEqual(list[1], b) || !reflect.DeepEqual(list[2], a) {
		t.Errorf("list = %+v\nwant %+v, %+v, %+v", list, c, b, a)
	}
}

// A step that failed and is retried is queued again: it has no start any more,
// so its next start, and the deadline counted from it, are fresh; a resume of a
// step that is under way still keeps the start it has.
func TestRetriedStepGetsAFreshStart(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	r, steps, items := f.versionRollout()
	f.create(t, r, []string{f.n1.ID, f.n2.ID}, steps, items)
	s := &steps[1]
	t1 := testNow.Add(time.Minute)
	t2 := t1.Add(2 * time.Hour) // the operator clicks Retry two hours later
	started := func() *time.Time {
		t.Helper()
		_, got, _, err := f.db.Rollout(ctx, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got[1].StartedAt
	}
	update := func() {
		t.Helper()
		if err := f.db.UpdateRolloutStep(ctx, s); err != nil {
			t.Fatalf("UpdateRolloutStep(%s): %v", s.Status, err)
		}
	}

	s.Status, s.StartedAt, s.Generation = StepApplying, &t1, 3
	update()
	s.Status, s.Error = StepFailed, "the step timed out"
	update()
	if got := started(); got == nil || !got.Equal(t1) {
		t.Fatalf("after the failure: started_at = %v, want %v", got, t1)
	}

	// Retry: the step goes back to pending, and has no start, whatever the
	// record says.
	s.Status, s.Error, s.Generation, s.StartedAt, s.FinishedAt = StepPending, "", 0, &t2, nil
	update()
	if s.StartedAt != nil {
		t.Errorf("StartedAt in the record of a pending step = %v, want none", s.StartedAt)
	}
	if got := started(); got != nil {
		t.Errorf("stored started_at of a pending step = %v, want NULL", got)
	}

	// The next start is fresh.
	s.Status, s.StartedAt = StepApplying, &t2
	update()
	if got := started(); got == nil || !got.Equal(t2) {
		t.Errorf("after the retry started: started_at = %v, want %v", got, t2)
	}
	if s.StartedAt == nil || !s.StartedAt.Equal(t2) {
		t.Errorf("StartedAt in the record = %v, want %v", s.StartedAt, t2)
	}

	// A resume (after a restart of the panel) keeps it, and so does a write with
	// another time.
	s.Status, s.StartedAt = StepVerifying, nil
	update()
	t3 := t2.Add(time.Minute)
	s.StartedAt = &t3
	update()
	if got := started(); got == nil || !got.Equal(t2) {
		t.Errorf("after a resume: started_at = %v, want the stored %v", got, t2)
	}
	if s.StartedAt == nil || !s.StartedAt.Equal(t2) {
		t.Errorf("StartedAt in the record after a resume = %v, want %v", s.StartedAt, t2)
	}
}

// A rollout that is over stays over: a stale record with an active status is
// refused, so that the nodes it let go are not held twice.
func TestTerminalRolloutIsFinal(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	a := f.create(t, switchRollout(EngineMtg), []string{f.n1.ID}, nil, nil)
	f.setStatus(t, a, RolloutAborted)
	finished := *a.FinishedAt

	a.Status = RolloutRunning // the stale write
	err := f.db.UpdateRollout(ctx, a)
	if !errors.Is(err, ErrRolloutOver) || !errors.Is(err, ErrConflict) {
		t.Fatalf("UpdateRollout(aborted -> running): err = %v, want ErrRolloutOver, which is a conflict", err)
	}
	if !strings.Contains(err.Error(), a.ID) || !strings.Contains(err.Error(), RolloutAborted) {
		t.Errorf("err = %v, want it to name the rollout and its status", err)
	}
	got, _, _, err := f.db.Rollout(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != RolloutAborted || got.FinishedAt == nil || !got.FinishedAt.Equal(finished) {
		t.Errorf("stored rollout = %+v, want it still aborted at %v", got, finished)
	}
	if n := activeNodes(t, f.db, a.ID); n != 0 {
		t.Errorf("%d active nodes of an aborted rollout, want 0", n)
	}

	// The node is free for exactly one other rollout.
	b := f.create(t, switchRollout(EngineMtg), []string{f.n1.ID}, nil, nil)
	err = f.db.CreateRollout(ctx, switchRollout(EngineMtg), []string{f.n1.ID}, nil, nil)
	var rc *RolloutConflict
	if !errors.As(err, &rc) || rc.Holder != b.ID {
		t.Errorf("a third rollout on the node: err = %v, want a conflict with %s", err, b.ID)
	}

	// Over to over is idempotent, and keeps the time it finished.
	f.setStatus(t, b, RolloutCompleted)
	end := *b.FinishedAt
	f.db.now = fixedClock(end.Add(time.Hour))
	b.FinishedAt = nil
	if err := f.db.UpdateRollout(ctx, b); err != nil {
		t.Fatalf("UpdateRollout(completed -> completed): %v", err)
	}
	if b.FinishedAt == nil || !b.FinishedAt.Equal(end) {
		t.Errorf("FinishedAt after writing a completed rollout again = %v, want the stored %v", b.FinishedAt, end)
	}
	got, _, _, _ = f.db.Rollout(ctx, b.ID)
	if got.Status != RolloutCompleted || !got.FinishedAt.Equal(end) {
		t.Errorf("stored = %+v, want completed at %v", got, end)
	}

	// Not found is still not found, not "over".
	err = f.db.UpdateRollout(ctx, &Rollout{ID: "01NOPE", Status: RolloutCompleted, Mode: RolloutModeAuto})
	if !errors.Is(err, ErrNotFound) || errors.Is(err, ErrRolloutOver) {
		t.Errorf("UpdateRollout of an unknown rollout: err = %v, want ErrNotFound only", err)
	}
}

// A rollout that is over keeps the end it has: a stale write of the other end
// (an Abort that arrives after the completion moved the channel, a completion
// after an Abort) is refused, and only the same end is written again.
func TestOverRolloutKeepsItsEnd(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	for _, tt := range []struct{ end, other string }{
		{RolloutCompleted, RolloutAborted},
		{RolloutAborted, RolloutCompleted},
	} {
		t.Run(tt.end+" then "+tt.other, func(t *testing.T) {
			r := f.create(t, switchRollout(EngineMtg), nil, nil, nil)
			f.setStatus(t, r, tt.end)
			finished := *r.FinishedAt

			r.Status = tt.other
			err := f.db.UpdateRollout(ctx, r)
			if !errors.Is(err, ErrRolloutOver) {
				t.Fatalf("UpdateRollout(%s -> %s): err = %v, want ErrRolloutOver", tt.end, tt.other, err)
			}
			got, _, _, err := f.db.Rollout(ctx, r.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tt.end || !got.FinishedAt.Equal(finished) {
				t.Errorf("stored = %s at %v, want still %s at %v", got.Status, got.FinishedAt, tt.end, finished)
			}

			// The same end again is fine.
			r.Status = tt.end
			if err := f.db.UpdateRollout(ctx, r); err != nil {
				t.Errorf("UpdateRollout(%s -> %s): %v", tt.end, tt.end, err)
			}
		})
	}
}

// FinishItems can run again, after a restart between it and the completed
// write: the second run finds every proxy settled, changes nothing, relabels
// nothing and names no node.
func TestFinishItemsTwice(t *testing.T) {
	for _, policy := range []string{EnginePolicyChannel, EnginePolicyPinned} {
		t.Run(policy, func(t *testing.T) {
			f := newRolloutFixture(t)
			ctx := context.Background()
			r, steps, items := f.versionRollout()
			f.create(t, r, []string{f.n1.ID, f.n2.ID}, steps, items)
			if err := f.db.DeferItems(ctx, r.ID, []string{f.p3.ID, f.p4.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.ApplyItems(ctx, r.ID, items[:2], EngineTelemt, EnginePolicyRollout, "3.5.14"); err != nil {
				t.Fatal(err)
			}

			first, err := f.db.FinishItems(ctx, r.ID, policy)
			if err != nil {
				t.Fatalf("first FinishItems: %v", err)
			}
			if !reflect.DeepEqual(first, sorted([]string{f.n1.ID, f.n2.ID})) {
				t.Errorf("first FinishItems: nodes = %v, want both", first)
			}
			want := map[*Proxy]string{f.p1: ItemApplied, f.p2: ItemApplied, f.p3: ItemDeferred, f.p4: ItemDeferred}
			f.wantStates(t, r.ID, want)
			var before []*Proxy
			for _, p := range []*Proxy{f.p1, f.p2, f.p3, f.p4} {
				got, err := f.db.ProxyByID(ctx, p.ID)
				if err != nil {
					t.Fatal(err)
				}
				before = append(before, got)
			}

			f.db.now = fixedClock(testNow.Add(time.Hour))
			second, err := f.db.FinishItems(ctx, r.ID, policy)
			if err != nil {
				t.Fatalf("second FinishItems: %v", err)
			}
			if len(second) != 0 {
				t.Errorf("second FinishItems: nodes = %v, want none", second)
			}
			f.wantStates(t, r.ID, want)
			for i, p := range []*Proxy{f.p1, f.p2, f.p3, f.p4} {
				got, err := f.db.ProxyByID(ctx, p.ID)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, before[i]) {
					t.Errorf("%s changed by the second FinishItems:\n%+v\nwas %+v", p.Name, got, before[i])
				}
			}
		})
	}
}

// CompleteRollout is the completion in one transaction: the channel moves, the
// proxies are settled and the rollout is over, or nothing of it is.
func TestCompleteRollout(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	f.db.now = fixedClock(testNow)
	r, steps, items := f.versionRollout()
	f.create(t, r, []string{f.n1.ID, f.n2.ID}, steps, items)
	if err := f.db.DeferItems(ctx, r.ID, []string{f.p3.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ApplyItems(ctx, r.ID, []RolloutItem{items[0], items[1], items[3]}, EngineTelemt, EnginePolicyRollout, "3.5.14"); err != nil {
		t.Fatal(err)
	}
	channels := func() map[string]map[string]string {
		t.Helper()
		got, err := f.db.ChannelVersions(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	end := testNow.Add(time.Hour)
	f.db.now = fixedClock(end)
	nodes, err := f.db.CompleteRollout(ctx, r.ID, EnginePolicyChannel)
	if err != nil {
		t.Fatalf("CompleteRollout: %v", err)
	}
	if !reflect.DeepEqual(nodes, sorted([]string{f.n1.ID, f.n2.ID})) {
		t.Errorf("nodes = %v, want both", nodes)
	}
	if got := channels()["telemt"]; got[ChannelStable] != "3.5.14" || got[ChannelLatest] != "3.5.13" {
		t.Errorf("telemt channels = %v, want stable moved to 3.5.14 and latest as it was", got)
	}
	for _, p := range []*Proxy{f.p1, f.p2, f.p4} {
		if got, want := f.engineOf(t, p.ID), [3]string{EngineTelemt, EnginePolicyChannel, ""}; got != want {
			t.Errorf("%s = %v, want %v", p.Name, got, want)
		}
	}
	if got, want := f.engineOf(t, f.p3.ID), [3]string{EngineTelemt, EnginePolicyPinned, "3.5.13"}; got != want {
		t.Errorf("p3, deferred, = %v, want %v", got, want)
	}
	got, _, _, err := f.db.Rollout(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != RolloutCompleted || got.FinishedAt == nil || !got.FinishedAt.Equal(end) || !got.UpdatedAt.Equal(end) || got.ResumeAt != nil {
		t.Errorf("rollout after completing = %+v, want completed and finished at %v", got, end)
	}
	if n := activeNodes(t, f.db, r.ID); n != 0 {
		t.Errorf("%d active nodes after completing, want 0", n)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p1: ItemApplied, f.p2: ItemApplied, f.p3: ItemDeferred, f.p4: ItemApplied})

	// Again (a restart between the commit and whatever came after): nothing
	// changes, nothing is named, the time it finished stays.
	f.db.now = fixedClock(end.Add(time.Hour))
	nodes, err = f.db.CompleteRollout(ctx, r.ID, EnginePolicyChannel)
	if err != nil || len(nodes) != 0 {
		t.Errorf("second CompleteRollout = %v, %v; want no nodes and no error", nodes, err)
	}
	again, _, _, _ := f.db.Rollout(ctx, r.ID)
	if !reflect.DeepEqual(again, got) {
		t.Errorf("rollout after the second completion = %+v\nwant unchanged %+v", again, got)
	}

	// An aborted rollout cannot be completed, and its channel does not move.
	b, bSteps, bItems := f.versionRollout()
	b.Channel, b.ToVersion = ChannelLatest, "3.5.15"
	f.create(t, b, nil, bSteps, bItems)
	f.setStatus(t, b, RolloutAborted)
	if _, err := f.db.CompleteRollout(ctx, b.ID, EnginePolicyChannel); !errors.Is(err, ErrRolloutOver) {
		t.Errorf("CompleteRollout of an aborted rollout: err = %v, want ErrRolloutOver", err)
	}
	if got := channels()["telemt"][ChannelLatest]; got != "3.5.13" {
		t.Errorf("telemt latest after completing an aborted rollout = %q, want 3.5.13", got)
	}
	if _, err := f.db.CompleteRollout(ctx, "01NOPE", EnginePolicyChannel); !errors.Is(err, ErrNotFound) {
		t.Errorf("CompleteRollout of an unknown rollout: err = %v, want ErrNotFound", err)
	}

	// A switch rollout moves no channel.
	c := switchRollout(EngineMtg)
	f.create(t, c, []string{f.n2.ID}, nil, nil)
	nodes, err = f.db.CompleteRollout(ctx, c.ID, EnginePolicyChannel)
	if err != nil || len(nodes) != 0 {
		t.Errorf("CompleteRollout of a switch rollout without items = %v, %v", nodes, err)
	}
	if !reflect.DeepEqual(channels(), func() map[string]map[string]string {
		want := map[string]map[string]string{}
		for e, m := range seededChannels {
			want[e] = map[string]string{}
			for ch, v := range m {
				want[e][ch] = v
			}
		}
		want["telemt"][ChannelStable] = "3.5.14"
		return want
	}()) {
		t.Errorf("channels after a switch rollout = %v, want only telemt stable moved", channels())
	}
	if got, _, _, _ := f.db.Rollout(ctx, c.ID); got.Status != RolloutCompleted {
		t.Errorf("switch rollout = %s, want completed", got.Status)
	}
}

// CreateRollout checks what the indexes and the completion depend on, and holds
// every node that the rollout touches.
func TestCreateRolloutValidation(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	for _, tt := range []struct {
		name  string
		tweak func(*Rollout)
	}{
		{"a kind that is not one of the three", func(r *Rollout) { r.Kind = "Version" }},
		{"no mode", func(r *Rollout) { r.Mode = "" }},
		{"a mode that is not one of the two", func(r *Rollout) { r.Mode = "fast" }},
		{"no component", func(r *Rollout) { r.Component = "" }},
		{"a version rollout without the version the channel has", func(r *Rollout) { r.FromVersion = "" }},
		{"a version rollout without a channel", func(r *Rollout) { r.Channel = "" }},
		{"a version rollout without a version to go to", func(r *Rollout) { r.ToVersion = "" }},
		{"a status that is not one of the six", func(r *Rollout) { r.Status = "done" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, steps, items := f.versionRollout()
			tt.tweak(r)
			err := f.db.CreateRollout(ctx, r, []string{f.n1.ID}, steps, items)
			if err == nil || errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
				t.Fatalf("CreateRollout: err = %v, want a plain refusal", err)
			}
			if n := count(t, f.db, `SELECT count(*) FROM rollouts`) + count(t, f.db, `SELECT count(*) FROM rollout_nodes`); n != 0 {
				t.Errorf("%d rows stored by a refused rollout", n)
			}
		})
	}

	// A switch rollout needs neither a channel nor versions.
	f.create(t, switchRollout(EngineMtg), nil, nil, nil)

	// A pending step has no start, whatever the record says.
	start := testNow
	g, gSteps, gItems := f.versionRollout()
	gSteps[0].StartedAt = &start
	f.create(t, g, nil, gSteps, gItems)
	if gSteps[0].StartedAt != nil {
		t.Errorf("a pending step was created with a start: %v", gSteps[0].StartedAt)
	}
	f.setStatus(t, g, RolloutCompleted)

	// The rollout holds every node that a step or an item names, with those of
	// nodeIDs: a step on n1 and an item on n2 hold both, although nodeIDs is
	// empty.
	a := f.create(t, switchRollout(EngineMtg), nil,
		[]RolloutStep{{Index: 0, NodeID: f.n1.ID, Status: StepPending}},
		[]RolloutItem{f.item(f.p1, 0), f.item(f.p3, 0)})
	if n := activeNodes(t, f.db, a.ID); n != 2 {
		t.Errorf("%d active nodes held, want 2 (the node of the step and the node of the other item)", n)
	}
	for _, node := range []*Node{f.n1, f.n2} {
		err := f.db.CreateRollout(ctx, switchRollout(EngineMtg), []string{node.ID}, nil, nil)
		var rc *RolloutConflict
		if !errors.As(err, &rc) || rc.Holder != a.ID || rc.NodeID != node.ID {
			t.Errorf("a rollout on %s: err = %v, want a conflict with %s", node.Name, err, a.ID)
		}
	}
	f.setStatus(t, a, RolloutCompleted)

	// A rollout created over holds nothing, and its nodes are free.
	e := switchRollout(EngineMtg)
	e.Status = RolloutCompleted
	f.create(t, e, []string{f.n1.ID}, nil, nil)
	if n := activeNodes(t, f.db, e.ID); n != 0 {
		t.Errorf("%d active nodes of a rollout created completed, want 0", n)
	}
	if n := count(t, f.db, `SELECT count(*) FROM rollout_nodes WHERE rollout_id = ?`, e.ID); n != 1 {
		t.Errorf("%d rollout_nodes rows of a rollout created completed, want 1, inactive", n)
	}
	f.create(t, switchRollout(EngineMtg), []string{f.n1.ID}, nil, nil)
}

func TestUndeferItems(t *testing.T) {
	f := newRolloutFixture(t)
	ctx := context.Background()
	r, steps, items := f.versionRollout()
	f.create(t, r, []string{f.n1.ID, f.n2.ID}, steps, items)
	if err := f.db.DeferItems(ctx, r.ID, []string{f.p3.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ApplyItems(ctx, r.ID, items[:1], EngineTelemt, EnginePolicyRollout, "3.5.14"); err != nil {
		t.Fatal(err)
	}
	if err := f.db.UndeferItems(ctx, r.ID, []string{f.p3.ID, f.p1.ID, f.p4.ID}); err != nil {
		t.Fatalf("UndeferItems: %v", err)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p3: ItemPending, f.p1: ItemApplied, f.p4: ItemPending})
	if err := f.db.UndeferItems(ctx, r.ID, []string{"01NOPE"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UndeferItems of an unknown proxy: %v", err)
	}
	// Undeferred, it is applied like any pending item.
	if _, err := f.db.ApplyItems(ctx, r.ID, items[2:3], EngineTelemt, EnginePolicyRollout, "3.5.14"); err != nil {
		t.Fatal(err)
	}
	f.wantStates(t, r.ID, map[*Proxy]string{f.p3: ItemApplied})
}
