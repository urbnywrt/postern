package reconcile

import (
	"errors"
	"maps"
	"strings"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

// A route is keyed by what its engine generation was rendered for: during a
// domain change the old SNI keeps routing to the old generation, and the key
// moves only when the new generation takes over.

// The new generation fails its probe: the old SNI still reaches g1, the new
// one reaches nothing, and the status says why.
func TestDomainChangeFailingProbeKeepsOldRoute(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	g1 := h.runtime().Instances[proxyID]
	h.prober.setFail(func(probeCall) error { return errors.New("probe: server digest mismatch") })

	st := h.baseState(2)
	st.Proxies[0].Domain = "b.example.com"
	h.apply(st)
	h.pass()

	want := map[string]string{"L1/a.example.com": proxyID + "->" + addr(g1.ListenPort)}
	if got := routeMap(h.fakeEdge(1).lastConfig(t)); !maps.Equal(got, want) {
		t.Errorf("routes = %v, want %v", got, want)
	}
	rec := h.runtime().Instances[proxyID]
	if rec.Generation != 1 || rec.ListenerID != "L1" || rec.Domain != "a.example.com" {
		t.Errorf("runtime instance = %+v, want g1 still keyed L1/a.example.com", rec)
	}
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING || !strings.Contains(ps.GetReason(), "upgrade aborted") {
		t.Errorf("status = %v", ps)
	}
}

// The new generation passes: while it is probed the old SNI still reaches
// g1; afterwards only the new SNI routes, to g2.
func TestDomainChangeMovesRouteAtSwitch(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	g1 := h.runtime().Instances[proxyID]
	var during map[string]string
	h.prober.setFail(func(probeCall) error {
		during = routeMap(h.fakeEdge(1).lastConfig(t))
		return nil
	})

	st := h.baseState(2)
	st.Proxies[0].Domain = "b.example.com"
	h.apply(st)
	h.pass()

	if want := map[string]string{"L1/a.example.com": proxyID + "->" + addr(g1.ListenPort)}; !maps.Equal(during, want) {
		t.Errorf("routes during the probe = %v, want %v", during, want)
	}
	g2 := h.runtime().Instances[proxyID]
	if g2.Generation != 2 || g2.ListenerID != "L1" || g2.Domain != "b.example.com" {
		t.Fatalf("runtime instance = %+v, want g2 keyed L1/b.example.com", g2)
	}
	if got, want := routeMap(h.fakeEdge(1).lastConfig(t)), map[string]string{"L1/b.example.com": proxyID + "->" + addr(g2.ListenPort)}; !maps.Equal(got, want) {
		t.Errorf("routes after the switch = %v, want %v", got, want)
	}
}

// Two proxies swap their domains. While the first one changes, both old routes
// stay. Once it has switched, its new generation owns the SNI the second one
// still serves (the desired route of the switched instance wins); the other
// SNI has no route until the second one switches too.
func TestDomainSwapBetweenProxies(t *testing.T) {
	h := newHarness(t)
	withP2 := func(gen uint64, d1, d2 string) *nodev1.NodeState {
		st := h.baseState(gen)
		st.Proxies[0].Domain = d1
		st.Proxies = append(st.Proxies, &nodev1.Proxy{
			Id: "P2", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Enabled: true,
			Secret: secret2, Domain: d2, Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
		})
		return st
	}
	h.apply(withP2(1, "a.example.com", "b.example.com"))
	h.pass()
	rt := h.runtime()
	p1g1, p2g1 := rt.Instances[proxyID], rt.Instances["P2"]

	var seen []map[string]string
	h.prober.setFail(func(probeCall) error {
		seen = append(seen, routeMap(h.fakeEdge(1).lastConfig(t)))
		return nil
	})
	h.apply(withP2(2, "b.example.com", "a.example.com"))
	h.pass()

	rt = h.runtime()
	p1g2, p2g2 := rt.Instances[proxyID], rt.Instances["P2"]
	if p1g2.Generation != 2 || p2g2.Generation != 2 {
		t.Fatalf("generations = %d, %d; want 2, 2", p1g2.Generation, p2g2.Generation)
	}
	if len(seen) != 2 {
		t.Fatalf("probes = %d, want 2", len(seen))
	}
	// proxyID sorts before P2, so it goes first.
	if want := map[string]string{
		"L1/a.example.com": proxyID + "->" + addr(p1g1.ListenPort),
		"L1/b.example.com": "P2->" + addr(p2g1.ListenPort),
	}; !maps.Equal(seen[0], want) {
		t.Errorf("routes while the first proxy is probed = %v, want %v", seen[0], want)
	}
	if want := map[string]string{"L1/b.example.com": proxyID + "->" + addr(p1g2.ListenPort)}; !maps.Equal(seen[1], want) {
		t.Errorf("routes while the second proxy is probed = %v, want %v", seen[1], want)
	}
	if got, want := routeMap(h.fakeEdge(1).lastConfig(t)), map[string]string{
		"L1/a.example.com": "P2->" + addr(p2g2.ListenPort),
		"L1/b.example.com": proxyID + "->" + addr(p1g2.ListenPort),
	}; !maps.Equal(got, want) {
		t.Errorf("routes after the swap = %v, want %v", got, want)
	}
}

// Moving a proxy to another listener changes nothing in the engine: the route
// moves at once, without a new generation.
func TestListenerChangeMovesRouteWithoutNewGeneration(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	st := h.baseState(2)
	st.Listeners = append(st.Listeners, &nodev1.Listener{
		Id: "L2", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "203.0.113.10", Port: 8443,
	})
	st.Proxies[0].ListenerId = "L2"
	h.apply(st)
	h.pass()
	rec := h.runtime().Instances[proxyID]
	if rec.Generation != 1 || rec.ListenerID != "L2" {
		t.Fatalf("runtime instance = %+v, want g1 keyed on L2", rec)
	}
	if got, want := routeMap(h.fakeEdge(1).lastConfig(t)), map[string]string{"L2/a.example.com": proxyID + "->" + addr(rec.ListenPort)}; !maps.Equal(got, want) {
		t.Errorf("routes = %v, want %v", got, want)
	}
}

// A route whose recorded listener is gone is left out: the edge must never get
// a route for a listener it does not have.
func TestRouteOnDeletedListenerIsDropped(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	h.prober.setFail(func(probeCall) error { return errors.New("probe: server digest mismatch") })
	st := h.baseState(2)
	st.Listeners = []*nodev1.Listener{{Id: "L2", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "203.0.113.10", Port: 8443}}
	st.Proxies[0].ListenerId = "L2"
	st.Proxies[0].Domain = "b.example.com"
	h.apply(st)
	h.pass()
	cfg := h.fakeEdge(1).lastConfig(t)
	listeners := map[string]bool{}
	for _, l := range cfg.GetListeners() {
		listeners[l.GetId()] = true
	}
	for _, r := range cfg.GetRoutes() {
		if !listeners[r.GetListenerId()] {
			t.Errorf("route %v names a listener the edge does not have", r)
		}
	}
	if len(cfg.GetRoutes()) != 0 {
		t.Errorf("routes = %v, want none", cfg.GetRoutes())
	}
}
