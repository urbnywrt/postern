package reconcile

import (
	"errors"
	"slices"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

// The restart nonce is a field at the end of the instance hash, only when it
// is not 0: an update of the agent rolls no engine (as the resolv.conf field
// does), and a new value rolls it.
func TestRestartNonceInTheInstanceHash(t *testing.T) {
	pr := &nodev1.Proxy{UseMiddleProxy: true, NatIp: "203.0.113.9"}
	files := map[string][]byte{"config.toml": []byte("a"), "x": []byte("b")}
	old := slice1Hash("telemt", "3.5.13", "abc", runnerImage, pr, files)
	if got := instanceHash("telemt", "3.5.13", "abc", runnerImage, false, nil, pr, files); got != old {
		t.Errorf("nonce 0: %s, want the hash of slice 1 %s", got, old)
	}
	pr.RestartNonce = 1
	one := instanceHash("telemt", "3.5.13", "abc", runnerImage, false, nil, pr, files)
	if one == old {
		t.Error("nonce 1 does not change the hash")
	}
	pr.RestartNonce = 2
	if two := instanceHash("telemt", "3.5.13", "abc", runnerImage, false, nil, pr, files); two == one || two == old {
		t.Error("nonce 2 is not a hash of its own")
	}
}

// A new restart nonce rolls the engine by blue-green: a new generation beside
// the old one, the gate, the route moved, the old one draining.
func TestRestartNonceRollsTheEngineBlueGreen(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	old := h.runtime().Instances[proxyID]
	h.fakeEdge(1).setActive(proxyID, old.ListenPort, 2)

	st := h.baseState(2)
	st.Proxies[0].RestartNonce = 7
	h.apply(st)
	h.pass()

	if c := h.container(engName2); c == nil || c.State != "running" {
		t.Fatalf("g2 = %+v, want running", c)
	}
	if g1 := h.container(engName1); g1 == nil || g1.State != "running" || g1.RestartPolicy != "no" {
		t.Fatalf("g1 = %+v, want running out its drain", g1)
	}
	rec := h.runtime().Instances[proxyID]
	if rec.Generation != 2 || rec.Hash == old.Hash || len(rec.Draining) != 1 || rec.Draining[0].Generation != 1 {
		t.Fatalf("runtime instance = %+v (old %+v)", rec, old)
	}
	if got := routeBackends(h.fakeEdge(1).lastConfig(t)); !slices.Equal(got, []string{proxyID + "->" + addr(rec.ListenPort)}) {
		t.Errorf("routes = %v, want g2", got)
	}
	if n := len(h.prober.callList()); n < 2 {
		t.Errorf("the gate probed %d times, want the new generation probed too", n)
	}

	// The same nonce again rolls nothing.
	st = h.baseState(3)
	st.Proxies[0].RestartNonce = 7
	h.apply(st)
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 2 {
		t.Errorf("generation = %d after the same nonce, want 2", rec.Generation)
	}
}

// A restart whose new generation fails the gate keeps the old one serving.
func TestRestartNonceWithAFailingGateKeepsTheOldGeneration(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	old := h.runtime().Instances[proxyID]
	h.prober.setFail(func(c probeCall) error {
		if c.addr != addr(old.ListenPort) {
			return errors.New("the new generation does not answer")
		}
		return nil
	})

	st := h.baseState(2)
	st.Proxies[0].RestartNonce = 1
	h.apply(st)
	h.pass()

	if c := h.container(engName2); c != nil {
		t.Errorf("g2 still exists: %+v", c)
	}
	if g1 := h.container(engName1); g1 == nil || g1.State != "running" || g1.RestartPolicy != "unless-stopped" {
		t.Errorf("g1 = %+v, want running as before", g1)
	}
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 1 || rec.Hash != old.Hash || len(rec.Draining) != 0 {
		t.Errorf("runtime instance = %+v, want g1 untouched", rec)
	}
	if kinds := h.eventKinds(); !slices.Contains(kinds, "upgrade_aborted") {
		t.Errorf("events = %v, want an upgrade_aborted", kinds)
	}
}

// A new edge roll nonce is taken like the operator's roll file: a new edge
// generation beside the running one, which then drains, with the agent's own
// binary; the nonce is recorded and the event sent.
func TestEdgeRollNonceStartsANewEdgeBesideTheRunningOne(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	if rt := h.runtime(); rt.EdgeRollNonce != 0 {
		t.Fatalf("edge roll nonce = %d before any, want 0", rt.EdgeRollNonce)
	}

	st := h.baseState(2)
	st.Settings.EdgeRollNonce = 5
	h.apply(st)
	h.takeTrace()
	h.pass()
	trace := h.takeTrace()

	if c := h.container("postern-edge-g2"); c == nil || c.State != "running" {
		t.Fatalf("g2 = %+v, want running", c)
	}
	if spec, ok := h.docker.Spec("postern-edge-g2"); !ok || spec.Binds[0] != h.nodeBinary+":/opt/postern/bin/postern-node:ro" {
		t.Errorf("g2 runs %v, want the agent's binary %s", spec.Binds, h.nodeBinary)
	}
	rt := h.runtime()
	if rt.EdgeGeneration != 2 || rt.EdgeRollNonce != 5 {
		t.Errorf("edge generation %d, nonce %d; want 2 and 5", rt.EdgeGeneration, rt.EdgeRollNonce)
	}
	if g1 := h.container("postern-edge-g1"); g1 == nil || g1.State != "running" || g1.RestartPolicy != "no" {
		t.Errorf("g1 = %+v, want it running out its drain with restart policy no", g1)
	}
	if got := h.fakeEdge(1).drainCalls(); !slices.Equal(got, []uint32{3600}) {
		t.Errorf("Drain calls on g1 = %v, want [3600]", got)
	}
	order := []string{"create postern-edge-g2", "start postern-edge-g2", "health g2", "drain g1"}
	last := -1
	for _, step := range order {
		i := indexOf(trace, step)
		if i < 0 || i < last {
			t.Fatalf("trace = %q, want %q in this order", trace, order)
		}
		last = i
	}
	ev := h.eventsOf("edge_roll_requested")
	if len(ev) != 1 || ev[0].GetDetails()["nonce"] != "5" {
		t.Errorf("edge_roll_requested events = %v, want one with the nonce", ev)
	}

	// The nonce was taken: the next pass rolls nothing.
	h.pass()
	if rt := h.runtime(); rt.EdgeGeneration != 2 || rt.EdgeLastGeneration != 2 {
		t.Errorf("after the roll: edge generation %d, last %d; want 2 and 2", rt.EdgeGeneration, rt.EdgeLastGeneration)
	}
}

// A roll by nonce that fails records the nonce all the same: it is not tried
// again on every pass (the operator clicks again).
func TestFailedEdgeRollByNonceIsRecordedAndNotRetried(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	h.r.edgeStartTimeout = 50 * time.Millisecond
	h.fakeEdge(2).setHealthErr(errors.New("dial unix: no such file or directory"))

	st := h.baseState(2)
	st.Settings.EdgeRollNonce = 9
	h.apply(st)
	h.pass()

	if c := h.container("postern-edge-g2"); c != nil {
		t.Errorf("g2 = %+v, want it removed", c)
	}
	rt := h.runtime()
	if rt.EdgeGeneration != 1 || rt.EdgeRollNonce != 9 || rt.AppliedGeneration != 2 {
		t.Errorf("edge generation %d, nonce %d, applied %d; want 1, 9 and 2", rt.EdgeGeneration, rt.EdgeRollNonce, rt.AppliedGeneration)
	}
	if ev := h.eventsOf("edge_roll_failed"); len(ev) != 1 {
		t.Errorf("edge_roll_failed events = %v, want one", ev)
	}

	h.pass()
	h.pass()
	if n := len(h.creates("edge")); n != 2 {
		t.Errorf("created %d edges, want 2 (g1 and the failed g2): the failed roll is not retried", n)
	}
	if g1 := h.container("postern-edge-g1"); g1 == nil || g1.State != "running" || g1.RestartPolicy != "unless-stopped" {
		t.Errorf("g1 = %+v, want it running as before", g1)
	}

	// A new value rolls again: generation 3, since 2 was used.
	st = h.baseState(3)
	st.Settings.EdgeRollNonce = 10
	h.apply(st)
	h.pass()
	if c := h.container("postern-edge-g3"); c == nil || c.State != "running" {
		t.Errorf("g3 = %+v, want running", c)
	}
	if rt := h.runtime(); rt.EdgeGeneration != 3 || rt.EdgeRollNonce != 10 {
		t.Errorf("edge generation %d, nonce %d; want 3 and 10", rt.EdgeGeneration, rt.EdgeRollNonce)
	}
}

// A fresh node whose first state carries a nonce records it and makes its
// first edge as it would anyway: no roll, no roll event.
func TestEdgeRollNonceOnAFreshNodeIsRecordedWithoutARoll(t *testing.T) {
	h := newHarness(t)
	st := h.baseState(1)
	st.Settings.EdgeRollNonce = 3
	h.apply(st)
	h.pass()

	if n := len(h.creates("edge")); n != 1 {
		t.Errorf("created %d edges, want 1", n)
	}
	rt := h.runtime()
	if rt.EdgeGeneration != 1 || rt.EdgeRollNonce != 3 {
		t.Errorf("edge generation %d, nonce %d; want 1 and 3", rt.EdgeGeneration, rt.EdgeRollNonce)
	}
	for _, kind := range []string{"edge_roll", "edge_roll_requested"} {
		if ev := h.eventsOf(kind); len(ev) != 0 {
			t.Errorf("%s events = %v, want none", kind, ev)
		}
	}
	h.pass()
	if n := len(h.creates("edge")); n != 1 {
		t.Errorf("created %d edges after another pass, want 1", n)
	}
}
