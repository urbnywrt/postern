package reconcile

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/probe/probetest"
	"github.com/urbnywrt/postern/internal/socks5"
)

// Before the route moves to a new generation, its way out is checked through
// the edge (spec 5.5): a datacenter answers req_pq_multi through its SOCKS
// port, and then L2 goes through the test listener of its listener, where a
// probe route of the edge leads to the new generation and to no other; the
// route of the proxy moves after that, and the probe route goes.
func TestGateChecksTheWayOutOfTheNewGeneration(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()

	rec := h.runtime().Instances[proxyID]
	dcs := h.gate.callsOf("dc")
	if len(dcs) != 1 || dcs[0].addr != addr(rec.SocksPort) || dcs[0].target != "149.154.175.50:443" {
		t.Fatalf("datacenter checks = %+v, want DC1 through SOCKS port %d", dcs, rec.SocksPort)
	}
	l2 := h.gate.callsOf("l2")
	if len(l2) != 1 {
		t.Fatalf("L2 probes = %+v, want one", l2)
	}
	testPort := h.runtime().Ports["svc:test:L1"]
	if c := l2[0]; c.addr != addr(testPort) || c.sni != "a.example.com" || hex.EncodeToString(c.secret) != secret1 || c.dc != 1 || c.src.IsValid() {
		t.Errorf("L2 = %+v, want the test listener %d, the domain, the secret, DC1, no PROXY header", c, testPort)
	}
	if p := l2[0].probes; len(p) != 1 || p[0].GetSni() != "a.example.com" || p[0].GetListenerId() != "L1" ||
		p[0].GetBackend() != addr(rec.ListenPort) || !p[0].GetProxyProtocol() || p[0].GetProxyId() != proxyID {
		t.Errorf("probe routes during L2 = %v, want one to the new generation", p)
	}
	if n := len(h.gate.callsOf("secret")); n != 0 {
		t.Errorf("the proxy secret was fetched %d times for a proxy without the middle proxy", n)
	}
	cfg := h.fakeEdge(1).lastConfig(t)
	if len(cfg.GetProbeRoutes()) != 0 {
		t.Errorf("probe routes after the switch = %v", cfg.GetProbeRoutes())
	}
	if got := routeBackends(cfg); len(got) != 1 || got[0] != proxyID+"->"+addr(rec.ListenPort) {
		t.Errorf("routes = %v", got)
	}
}

// The checks go on to the next datacenter when one does not answer, and L2
// asks for the one that did.
func TestGateTriesTheDatacentersInTurn(t *testing.T) {
	h := newHarness(t)
	h.gate.set(func(g *fakeGate) {
		g.dialErr = func(target string) error {
			if target == "149.154.175.50:443" {
				return errors.New("socks5: the proxy refused: general failure")
			}
			return nil
		}
	})
	h.apply(h.baseState(1))
	h.pass()
	if ps := h.proxyStatus(proxyID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
		t.Fatalf("status = %v", ps)
	}
	dcs := h.gate.callsOf("dc")
	if len(dcs) != 2 || dcs[1].target != "149.154.167.51:443" {
		t.Errorf("datacenter checks = %+v, want DC1 then DC2", dcs)
	}
	if l2 := h.gate.callsOf("l2"); len(l2) != 1 || l2[0].dc != 2 {
		t.Errorf("L2 = %+v, want DC2", l2)
	}
}

// The datacenters of the health check of the proxy's chain are the ones asked.
func TestGateAsksTheDatacentersOfTheChain(t *testing.T) {
	h := newHarness(t)
	st := h.baseState(1)
	st.Chains[0].Check = &nodev1.HealthCheck{DcAddrs: []string{"149.154.167.91:443"}}
	h.apply(st)
	h.pass()
	if dcs := h.gate.callsOf("dc"); len(dcs) != 1 || dcs[0].target != "149.154.167.91:443" {
		t.Errorf("datacenter checks = %+v", dcs)
	}
	if l2 := h.gate.callsOf("l2"); len(l2) != 1 || l2[0].dc != 4 {
		t.Errorf("L2 = %+v, want DC4", l2)
	}
}

// A new generation whose way out reaches no datacenter does not get the
// route: a new proxy fails, and a proxy that serves stays on its generation.
func TestGateFailsWhenNoDatacenterAnswers(t *testing.T) {
	for name, mode := range map[string]probetest.Mode{"hangs up": probetest.HangsUp, "wrong nonce": probetest.WrongNonce} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.apply(h.baseState(1))
			h.pass()
			old := h.runtime().Instances[proxyID]

			h.gate.set(func(g *fakeGate) { g.dcMode = mode })
			st := h.baseState(2)
			st.Proxies[0].Secret = secret2
			h.apply(st)
			h.pass()
			if c := h.container(engName2); c != nil {
				t.Errorf("g2 = %+v, want removed", c)
			}
			if rec := h.runtime().Instances[proxyID]; rec.Generation != 1 || rec.ListenPort != old.ListenPort {
				t.Errorf("record = %+v, want g1", rec)
			}
			evs := h.eventsOf("upgrade_aborted")
			if len(evs) != 1 || !strings.Contains(evs[0].GetMessage(), "datacenter") {
				t.Errorf("upgrade_aborted events = %v", evs)
			}
			if n := len(h.gate.callsOf("l2")); n != 1 {
				t.Errorf("L2 probes = %d, want only that of g1", n)
			}
			if p := h.fakeEdge(1).lastConfig(t).GetProbeRoutes(); len(p) != 0 {
				t.Errorf("probe routes after the abort = %v", p)
			}
		})
	}

	h := newHarness(t)
	h.gate.set(func(g *fakeGate) {
		g.dialErr = func(string) error { return errors.New("every member of the chain is down") }
	})
	h.apply(h.baseState(1))
	h.pass()
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || !strings.Contains(ps.GetReason(), "datacenter") {
		t.Errorf("status = %v, want failed for its way out", ps)
	}
	if dcs := h.gate.callsOf("dc"); len(dcs) != 5 {
		t.Errorf("datacenter checks = %d, want all five", len(dcs))
	}
}

// L2 through the test listener must pass too.
func TestGateFailsWhenL2Fails(t *testing.T) {
	h := newHarness(t)
	h.gate.set(func(g *fakeGate) { g.l2Err = errors.New("probe: the answer is not a valid resPQ") })
	h.apply(h.baseState(1))
	h.pass()
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || !strings.Contains(ps.GetReason(), "L2") {
		t.Errorf("status = %v", ps)
	}
	if h.container(engName1) != nil {
		t.Error("the generation that failed L2 is still there")
	}
}

// With the middle proxy, the proxy secret must come through the SOCKS port of
// the new generation too.
func TestGateFetchesTheProxySecretForTheMiddleProxy(t *testing.T) {
	h := newHarness(t)
	st := h.baseState(1)
	st.Proxies[0].UseMiddleProxy = true
	h.apply(st)
	h.pass()
	rec := h.runtime().Instances[proxyID]
	if s := h.gate.callsOf("secret"); len(s) != 1 || s[0].addr != addr(rec.SocksPort) {
		t.Fatalf("proxy secret fetches = %+v, want one through SOCKS port %d", s, rec.SocksPort)
	}

	h2 := newHarness(t)
	h2.gate.set(func(g *fakeGate) { g.secretErr = errors.New("HTTP 403") })
	h2.apply(st)
	h2.pass()
	if ps := h2.proxyStatus(proxyID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || !strings.Contains(ps.GetReason(), "middle proxy") {
		t.Errorf("status = %v", ps)
	}
}

// An edge that runs another version than the agent may not know probe routes:
// L2 then goes straight to the new generation, with a PROXY header as the edge
// sends it.
func TestGateGoesStraightToTheEngineThroughAnOlderEdge(t *testing.T) {
	h := newHarness(t)
	h.r.Version = "v0.2.0"
	h.fakeEdge(1).setVersion("v0.1.0")
	h.apply(h.baseState(1))
	h.pass()
	rec := h.runtime().Instances[proxyID]
	l2 := h.gate.callsOf("l2")
	if len(l2) != 1 || l2[0].addr != addr(rec.ListenPort) || l2[0].src != netip.MustParseAddrPort("127.0.0.1:1") {
		t.Fatalf("L2 = %+v, want the engine's port with a PROXY header from 127.0.0.1:1", l2)
	}
	if len(l2[0].probes) != 0 {
		t.Errorf("probe routes went to an older edge: %v", l2[0].probes)
	}
}

// The fetch of the proxy secret: an HTTPS GET through the SOCKS port that must
// answer 200.
func TestProxySecretThroughSOCKS(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/getProxySecret" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte{1, 2, 3})
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	socks := startSOCKSTo(t, srv.Listener.Addr().String())
	r := &Reconciler{proxySecretURL: "https://example.com/getProxySecret", gateTLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	if err := r.checkProxySecret(context.Background(), socks); err != nil {
		t.Fatalf("checkProxySecret = %v", err)
	}
	status = http.StatusForbidden
	if err := r.checkProxySecret(context.Background(), socks); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("checkProxySecret = %v, want the status", err)
	}
}

// The CONNECT of the checks to a datacenter goes through the SOCKS port without
// a user name, and DCPing runs on what it gets.
func TestDatacenterThroughSOCKS(t *testing.T) {
	dc, err := probetest.NewServer(probetest.Answers, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dc.Close() })
	socks := startSOCKSTo(t, dc.Addr())
	r := &Reconciler{}
	if err := r.pingDC(context.Background(), socks, "149.154.175.50:443"); err != nil {
		t.Errorf("pingDC = %v", err)
	}
}

// startSOCKSTo is a SOCKS5 server on the loopback that takes every CONNECT
// to addr, without a user name.
func startSOCKSTo(t *testing.T, to string) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := &socks5.Server{
		Dial: func(ctx context.Context, req socks5.Request) (net.Conn, error) {
			if req.Username != "" {
				return nil, errors.New("a user name")
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", to)
		},
		Logger: slog.New(slog.DiscardHandler),
	}
	go func() { _ = srv.Serve(l) }()
	return l.Addr().String()
}

// The exported checks the diagnostics use: PingDC answers through a member
// that reaches a datacenter, and fails through one that acknowledges the
// CONNECT at once and then closes (a dead member of a provider does that).
func TestExportedPingDC(t *testing.T) {
	dc, err := probetest.NewServer(probetest.Answers, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dc.Close() })
	if err := PingDC(context.Background(), startSOCKSTo(t, dc.Addr()), "149.154.167.51:443"); err != nil {
		t.Errorf("PingDC through a working member = %v", err)
	}
	early := startEarlyAckSOCKS(t)
	if err := PingDC(context.Background(), early, "149.154.167.51:443"); err == nil {
		t.Error("PingDC through a member that acknowledges and closes = nil, want an error")
	}
	if err := ProxySecretCheck(context.Background(), early); err == nil {
		t.Error("ProxySecretCheck through a member that acknowledges and closes = nil, want an error")
	}
	if got := ProxyDCs(&nodev1.NodeState{}, &nodev1.Proxy{}); len(got) != 5 {
		t.Errorf("ProxyDCs without a chain = %v, want the five default datacenters", got)
	}
}

// startEarlyAckSOCKS is a SOCKS5 server that acknowledges every CONNECT and
// then closes the connection.
func startEarlyAckSOCKS(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := &socks5.Server{
		Dial: func(context.Context, socks5.Request) (net.Conn, error) {
			a, b := net.Pipe()
			_ = b.Close()
			return a, nil
		},
		Logger: slog.New(slog.DiscardHandler),
	}
	go func() { _ = srv.Serve(l) }()
	return l.Addr().String()
}
