package reconcile

import (
	"context"
	"strings"
	"testing"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

const proxyID2 = "01J9ZZPROXY0000000000000P2"

// twoListenerState is baseState with a second listener, L2 on 0.0.0.0:8443,
// and a second proxy on it.
func (h *harness) twoListenerState(gen uint64) *nodev1.NodeState {
	st := h.baseState(gen)
	st.Listeners = append(st.Listeners, &nodev1.Listener{
		Id: "L2", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "0.0.0.0", Port: 8443,
		StrangerAction: nodev1.StrangerAction_STRANGER_ACTION_REJECT,
	})
	st.Proxies = append(st.Proxies, &nodev1.Proxy{
		Id: proxyID2, ListenerId: "L2", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Enabled: true,
		Secret: secret2, Domain: "b.example.com",
		Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
	})
	return st
}

// A listener the edge cannot bind fails the proxies on it, with the reason,
// and no other: the proxies of the other listeners keep their state, and the
// report's last_error stays empty while some listener serves. When every
// listener fails, the pass fails and last_error says why. A listener that
// binds later clears its proxies.
func TestListenerBindFailureFailsOnlyItsProxies(t *testing.T) {
	h := newHarness(t)
	h.fakeEdge(1).setFailures("L2")
	h.apply(h.twoListenerState(1))
	h.pass()

	if ps := h.proxyStatus(proxyID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
		t.Errorf("proxy on L1 = %v, want serving", ps)
	}
	ps := h.proxyStatus(proxyID2)
	want := "listener L2 could not bind: listen tcp4 L2: bind: address already in use"
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || ps.GetReason() != want {
		t.Errorf("proxy on L2 = %v, want FAILED with reason %q", ps, want)
	}
	if st := h.r.Status(); st.GetLastError() != "" || st.GetAppliedGeneration() != 1 {
		t.Errorf("last_error = %q, applied %d; want none and 1", st.GetLastError(), st.GetAppliedGeneration())
	}

	// Every listener fails: the pass fails, and last_error carries the reasons.
	h.fakeEdge(1).setFailures("L1", "L2")
	err := h.r.reconcileOnce(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "no listener could be bound") || !strings.Contains(err.Error(), "listener L1 could not bind") {
		t.Fatalf("pass = %v, want a failure that names every listener", err)
	}
	if st := h.r.Status(); !strings.Contains(st.GetLastError(), "no listener could be bound") {
		t.Errorf("last_error = %q, want the bind failure", st.GetLastError())
	}
	for _, id := range []string{proxyID, proxyID2} {
		if ps := h.proxyStatus(id); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || !strings.Contains(ps.GetReason(), "could not bind") {
			t.Errorf("proxy %s = %v, want FAILED for the bind", id, ps)
		}
	}

	// The listeners bind: everything serves again, and last_error is clear.
	h.fakeEdge(1).setFailures()
	h.pass()
	for _, id := range []string{proxyID, proxyID2} {
		if ps := h.proxyStatus(id); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
			t.Errorf("proxy %s = %v, want serving", id, ps)
		}
	}
	if st := h.r.Status(); st.GetLastError() != "" {
		t.Errorf("last_error = %q, want none", st.GetLastError())
	}
}

// A new generation that cannot bind a listener the running one serves is not
// made the current one: it is removed, the running one goes on, and the event
// says which listener. A listener that fails in both does not block the roll.
func TestRollNeedsTheListenersOfTheRunningEdge(t *testing.T) {
	h := newHarness(t)
	h.apply(h.twoListenerState(1))
	h.pass()
	h.fakeEdge(2).setFailures("L2")

	h.requestRoll()
	h.pass()

	if c := h.container("postern-edge-g2"); c != nil {
		t.Errorf("g2 = %+v, want it removed", c)
	}
	if g1 := h.container("postern-edge-g1"); g1 == nil || g1.State != "running" {
		t.Errorf("g1 = %+v, want it running", g1)
	}
	if got := h.fakeEdge(1).drainCalls(); len(got) != 0 {
		t.Errorf("g1 was asked to drain: %v", got)
	}
	if rt := h.runtime(); rt.EdgeGeneration != 1 {
		t.Errorf("edge generation = %d, want 1", rt.EdgeGeneration)
	}
	ev := h.eventsOf("edge_roll_failed")
	if len(ev) != 1 || !strings.Contains(ev[0].GetMessage(), "listener L2 could not bind in generation 2 while generation 1 serves it") {
		t.Errorf("edge_roll_failed events = %v, want one that names L2", ev)
	}
	if ps := h.proxyStatus(proxyID2); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
		t.Errorf("proxy on L2 = %v, want serving: g1 binds L2", ps)
	}

	// L2 fails in the running generation too: the next roll goes through.
	h.fakeEdge(1).setFailures("L2")
	h.fakeEdge(3).setFailures("L2")
	h.pass() // g1 reports the failure
	h.requestRoll()
	h.pass()
	if c := h.container("postern-edge-g3"); c == nil || c.State != "running" {
		t.Errorf("g3 = %+v, want running", c)
	}
	if rt := h.runtime(); rt.EdgeGeneration != 3 {
		t.Errorf("edge generation = %d, want 3", rt.EdgeGeneration)
	}
	if got := h.fakeEdge(1).drainCalls(); len(got) != 1 {
		t.Errorf("g1 drain calls = %v, want one", got)
	}
	if ps := h.proxyStatus(proxyID2); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED {
		t.Errorf("proxy on L2 = %v, want FAILED: no generation binds L2", ps)
	}
}

// A listener that is new to the configuration may fail in the new generation
// without blocking the roll: the running one never served it.
func TestRollTakesANewListenerThatFails(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	h.fakeEdge(2).setFailures("L2")

	h.requestRoll()
	h.apply(h.twoListenerState(2)) // L2 comes with the roll
	h.pass()

	if c := h.container("postern-edge-g2"); c == nil || c.State != "running" {
		t.Errorf("g2 = %+v, want running", c)
	}
	if ev := h.eventsOf("edge_roll_failed"); len(ev) != 0 {
		t.Errorf("edge_roll_failed events = %v, want none", ev)
	}
	if ps := h.proxyStatus(proxyID2); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED {
		t.Errorf("proxy on L2 = %v, want FAILED", ps)
	}
	if ps := h.proxyStatus(proxyID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
		t.Errorf("proxy on L1 = %v, want serving", ps)
	}
}

// The bind_ip of a listener may be written in a non-canonical form; the roll
// check compares addresses, not text, so such a listener is still seen as one
// the running generation serves (the node refuses IPv6 listeners today, so
// this is checked on the comparison itself).
func TestRollBlockedByComparesAddressesNotText(t *testing.T) {
	listeners := []*edgev1.EdgeListener{
		{Id: "L1", BindIp: "0.0.0.0", Port: 443},
		{Id: "L2", BindIp: "2001:DB8:0000::0001", Port: 8443},
		{Id: "L3", BindIp: "0.0.0.0", Port: 8080},
	}
	bound := []string{"0.0.0.0:443", "[2001:db8::1]:8443"} // as the edge prints them
	l2 := &edgev1.ListenerFailure{ListenerId: "L2", Reason: "bind: cannot assign requested address"}
	cases := map[string]struct {
		failures []*edgev1.ListenerFailure
		want     *edgev1.ListenerFailure
	}{
		"a bound listener in another spelling blocks": {[]*edgev1.ListenerFailure{l2}, l2},
		"a new listener does not":                     {[]*edgev1.ListenerFailure{{ListenerId: "L3"}}, nil},
		"an unknown listener does not":                {[]*edgev1.ListenerFailure{{ListenerId: "L9"}}, nil},
		"nothing failed":                              {nil, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := rollBlockedBy(listeners, bound, c.failures); got != c.want {
				t.Errorf("rollBlockedBy = %v, want %v", got, c.want)
			}
		})
	}
}

// A paused proxy has no route on its listener: the listener's failure does not
// touch it, and it stays paused.
func TestListenerBindFailureLeavesPausedProxiesAlone(t *testing.T) {
	h := newHarness(t)
	h.fakeEdge(1).setFailures("L2")
	st := h.twoListenerState(1)
	st.Proxies[1].Enabled = false
	h.apply(st)
	h.pass()

	if ps := h.proxyStatus(proxyID2); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_PAUSED || ps.GetReason() != "" {
		t.Errorf("paused proxy on L2 = %v, want PAUSED with no reason", ps)
	}
	if ps := h.proxyStatus(proxyID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
		t.Errorf("proxy on L1 = %v, want serving", ps)
	}
}
