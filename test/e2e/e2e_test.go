//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
)

// TestPanelToNodeFakeTLS runs the chain of slices 0 and 1 for real:
//
//  1. the panel binary serves on 127.0.0.1; the first admin is made with the
//     setup token that it prints, and signs in;
//  2. a node is created (management at 127.0.0.1, links to 203.0.113.10),
//     its bundle downloaded and installed into a directory of the test, and
//     the agent container started like deploy/node/compose.yaml starts it;
//     the panel reaches the agent over mTLS and the node is online;
//  3. a TLS listener on 127.0.0.1 and a fake-TLS proxy on it: the panel
//     downloads telemt from GitHub, uploads it to the node and sends the
//     state; the agent starts the edge and the engine, and the proxy serves;
//  4. a fake-TLS client with the secret and the domain of the proxy's link
//     gets through the edge to the engine, and one with a wrong secret is
//     refused by the server: no proof of the secret, a TLS alert, the
//     connection closed or reset after the ClientHello, or no answer;
//  5. the agent container restarts: a new client gets through within 10 s,
//     and once the new agent process has made its first reconcile pass (the
//     launcher's healthy marker is back), the edge and the engine are the
//     containers of before, and a connection that went through the handshake
//     before the restart is still open (with POSTERN_E2E_ONLINE=1 an L2
//     session that asks DC2 all along, as in TestVersions);
//  6. the proxy is paused: a client with its secret is refused; resumed, it
//     is served again by the same engine;
//  7. the proxy gets a new secret: the node starts a new generation of the
//     engine beside the old one and moves the route of the edge to it
//     (blue-green); the new link gets through, the old one is refused, and
//     the old generation, which has no connection left, goes;
//  8. the panel works with the new agent process: a change of the listener
//     is applied on the node, the proxy serves on, and the panel stops
//     cleanly;
//  9. no log of the run holds a secret of it (the secrets of the proxy, the
//     admin password, the setup token outside the setup URL, the node's
//     private key): the panel's stdout and log, and the logs of the agent,
//     the edge and both generations of the engine.
func TestPanelToNodeFakeTLS(t *testing.T) {
	e := newEnv(t)

	// 1.-3. The panel, the node, and the listener with the proxy, serving
	// (setUpFakeTLS).
	s := e.setUpFakeTLS(fakeTLSSetup{})
	p, a, node, proxy := s.panel, s.api, s.node, s.proxy
	lr, lport, secret, domain := s.listener, s.port, s.secret, s.domain

	// 4. Through the edge with the link's secret, and with a wrong one.
	addr := s.addr
	attempts, err := probeUntil(e.ctx, addr, domain, secret, 30*time.Second)
	if err != nil {
		e.fatalf("probe.FakeTLS through the edge with the secret of the proxy's link: %v (%d attempts)", err, attempts)
	}
	e.logf("probe.FakeTLS through the edge with the secret of the proxy's link: the engine proved the secret (attempt %d)", attempts)

	wrong := slices.Clone(secret)
	wrong[0] ^= 0xff
	e.secret(hex.EncodeToString(wrong))
	how := e.expectRefused(addr, domain, wrong, "probe.FakeTLS with a wrong secret")
	e.logf("probe.FakeTLS with a wrong secret fails: %s", how)

	// 5. A connection held open over a restart of the agent: idle after its
	// fake-TLS handshake, or with POSTERN_E2E_ONLINE=1 an L2 session that asks
	// DC2 every l2Every, as TestVersions holds them (versions_test.go).
	held := e.hold(&vproxy{addr: addr, domain: domain, secret: secret}, "the listener (held over the restart of the agent)")
	if held.conn != nil {
		e.expectOpen(held.conn, 500*time.Millisecond, "before the restart of the agent")
	}
	edge, edgeStarted := e.nodeContainer("edge", "edge")
	engine, engineStarted := e.nodeContainer("engine", proxy.GetId())
	marker, ok := e.healthyMarker(e.ctx)
	if !ok {
		e.fatalf("the agent has not written the launcher's healthy marker")
	}
	e.logf("a connection went through the handshake and is open; edge %s, engine %s", edge.name(), engine.name())

	e.restartAgent()
	restarted := time.Now()
	// The edge serves on while the agent is down and starts again.
	attempts, err = probeUntil(e.ctx, addr, domain, secret, 10*time.Second)
	if err != nil {
		e.fatalf("probe.FakeTLS after the restart of the agent: %v (%d attempts within 10 s)", err, attempts)
	}
	e.logf("probe.FakeTLS right after the restart: the engine proved the secret, %.1fs after the restart (attempt %d)",
		time.Since(restarted).Seconds(), attempts)

	// The new agent process takes the node over: its first reconcile pass
	// adopts the edge and the engine and sends the edge its table. Only then
	// is the restart over, and the containers and the connection are looked
	// at. An L2 session keeps traffic flowing, so the pass may take as long as
	// it takes under load. An idle connection is closed by telemt telemtIdle
	// after its handshake: the wait for the pass then gets what is left of that
	// time, so that the check of the connection is never a race with telemt,
	// and a first pass that comes later fails the test here, and says why.
	wait, why := firstPassWithin, "the held L2 session asks DC2 every "+l2Every.String()
	if held.conn != nil {
		wait = telemtIdle - heldMargin - time.Since(held.at)
		why = fmt.Sprintf("the held connection is idle, and telemt closes it %v after its handshake", telemtIdle)
		if wait <= 0 {
			e.fatalf("the restart of the agent ended %.1fs after the handshake of the held connection: no time is left "+
				"to check it before telemt closes it, %v after the handshake", time.Since(held.at).Seconds(), telemtIdle)
		}
	}
	e.waitHealthy(marker, wait, why)
	if edge2, started := e.nodeContainer("edge", "edge"); edge2.ID != edge.ID || !started.Equal(edgeStarted) {
		e.fatalf("the edge is not the same container after the restart of the agent: %s (%s) started %v, before %s (%s) started %v",
			edge2.name(), edge2.ID[:12], started, edge.name(), edge.ID[:12], edgeStarted)
	}
	if engine2, started := e.nodeContainer("engine", proxy.GetId()); engine2.ID != engine.ID || !started.Equal(engineStarted) {
		e.fatalf("the engine is not the same container after the restart of the agent: %s, before %s", engine2.name(), engine.name())
	}
	// The check closes the connection, which has done its part: open, it would
	// keep this generation of the engine draining after the change of the
	// secret (7).
	held.check("after the first pass of the new agent, on the edge and the engine of before")
	attempts, err = probeUntil(e.ctx, addr, domain, secret, 10*time.Second)
	if err != nil {
		e.fatalf("probe.FakeTLS after the first pass of the new agent: %v (%d attempts within 10 s)", err, attempts)
	}
	e.logf("probe.FakeTLS after the first pass of the new agent: the engine proved the secret (attempt %d)", attempts)

	// 6. A pause and a resume.
	e.pauseAndResume(a, node.GetId(), proxy.GetId(), addr, domain, secret)

	// 7. A new secret: blue-green.
	secret = e.changeSecret(a, node.GetId(), proxy.GetId(), lport, addr, domain, secret)

	// 8. The panel works with the new agent process: a change of the listener
	// goes to the node, which applies it and says so, and the proxy serves on.
	// (The times that the panel shows cannot tell the new process from the
	// old one: the clock may step back.) Then the panel stops cleanly.
	desired := e.change(a, node.GetId(), "UpdateListener", func(ctx context.Context) error {
		_, err := a.listeners.UpdateListener(ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{
			Id: lr.GetId(), StrangerAction: ptr("reject"),
		}))
		return err
	})
	e.waitApplied(a, node.GetId(), proxy.GetId(), desired, "serving", nil)
	if attempts, err := probeUntil(e.ctx, addr, domain, secret, 10*time.Second); err != nil {
		e.fatalf("probe.FakeTLS after the change of the listener: %v (%d attempts within 10 s)", err, attempts)
	}
	e.logf("probe.FakeTLS after the change of the listener: the engine proved the secret")
	if err := p.stop(15 * time.Second); err != nil {
		e.errorf("the panel did not stop cleanly with a node connected: %v", err)
	} else {
		e.logf("the panel stopped cleanly")
	}

	// 9. No secret in any log: the panel has stopped, so its output is all
	// there, and the logs of the node's containers have been kept since the
	// agent started, those of the engine that went in step 7 included.
	e.checkLogs()
}

const (
	// telemtIdle is how long telemt keeps a client that went through the
	// fake-TLS handshake and has sent nothing since.
	telemtIdle = 60 * time.Second
	// heldMargin is what the check of the held connection needs before
	// telemtIdle is over: a look at the containers, and a read of 2 s.
	heldMargin = 10 * time.Second
	// firstPassWithin is how long the first reconcile pass of a new agent
	// process may take while an L2 session is held over the restart.
	firstPassWithin = 2 * time.Minute
	// drainWithin is how long the old generation of an engine without
	// connections may take to go: the node removes it in the pass that moves
	// the route, or in the next one, 30 s later.
	drainWithin = 75 * time.Second
)

// pauseAndResume pauses the proxy and resumes it (step 6). A paused proxy is
// not served: the edge takes its domain for a stranger's, so a client with
// its secret is refused. The node keeps its engine for a quick resume, so the
// resumed proxy is served by the same generation as before.
func (e *env) pauseAndResume(a *api, nodeID, proxyID, addr, sni string, secret []byte) {
	e.t.Helper()
	gen := e.proxyOf(a, proxyID).GetStatus().GetInstanceGeneration()
	setEnabled := func(enabled bool) func(ctx context.Context) error {
		return func(ctx context.Context) error {
			_, err := a.proxies.SetProxyEnabled(ctx, connect.NewRequest(&panelv1.SetProxyEnabledRequest{Id: proxyID, Enabled: enabled}))
			return err
		}
	}

	desired := e.change(a, nodeID, "SetProxyEnabled(false)", setEnabled(false))
	e.waitApplied(a, nodeID, proxyID, desired, "paused", nil)
	how := e.expectRefused(addr, sni, secret, "probe.FakeTLS with the secret of the paused proxy")
	e.logf("the paused proxy is not served: a client with its secret is refused (%s)", how)

	desired = e.change(a, nodeID, "SetProxyEnabled(true)", setEnabled(true))
	e.waitApplied(a, nodeID, proxyID, desired, "serving", nil)
	attempts, err := probeUntil(e.ctx, addr, sni, secret, 10*time.Second)
	if err != nil {
		e.fatalf("probe.FakeTLS after the resume: %v (%d attempts within 10 s)", err, attempts)
	}
	if g := e.proxyOf(a, proxyID).GetStatus().GetInstanceGeneration(); g != gen {
		e.errorf("the resume moved the proxy from generation %d of its engine to generation %d: a pause keeps the engine", gen, g)
	}
	e.logf("the resumed proxy is served again by generation %d of its engine (attempt %d)", gen, attempts)
}

// changeSecret gives the proxy a new secret (step 7) and returns it as the new
// link carries it. The engine needs a new configuration for it, so the node
// starts a new generation of the engine beside the one that serves, and moves
// the route of the edge over once the new one answers: a client gets through
// with the one secret or the other all along. Then the new link gets through,
// the old one is refused, and the old generation, which has no connection
// left, goes.
func (e *env) changeSecret(a *api, nodeID, proxyID string, port int, addr, sni string, old []byte) []byte {
	e.t.Helper()
	gen := e.proxyOf(a, proxyID).GetStatus().GetInstanceGeneration()
	engines, err := e.engineContainers(e.ctx, proxyID)
	if err != nil {
		e.fatalf("listing the engines of the proxy: %v", err)
	}
	if c, ok := engines[gen]; !ok || c.State != "running" || len(engines) != 1 {
		e.fatalf("before the change of the secret the engines of the proxy are %s, want generation %d alone, running",
			describeEngines(engines), gen)
	}

	newHex := hex.EncodeToString(randomBytes(16))
	e.mustNotLeak("the second secret of the proxy", newHex)
	watch := e.watchSwitch(addr, sni, old, mustHex(newHex))
	desired := e.change(a, nodeID, "UpdateProxy with a new secret", func(ctx context.Context) error {
		_, err := a.proxies.UpdateProxy(ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: proxyID, Secret: &newHex}))
		return err
	})
	secret, _ := e.checkLinks(a, proxyID, port, newHex)
	var next uint64
	e.waitApplied(a, nodeID, proxyID, desired, "serving", func(p *panelv1.Proxy) (bool, string) {
		next = p.GetStatus().GetInstanceGeneration()
		return next > gen, fmt.Sprintf("engine generation %d", next)
	})
	watch.end()
	for _, gap := range watch.gaps {
		e.errorf("while the node moved the proxy to a new generation, neither secret got through: %s", gap)
	}
	// The first round came before the change, and the last ones after the
	// switch: each secret got through at least once, or the probes did not
	// see what they were to see.
	if watch.oldOK == 0 || watch.newOK == 0 {
		e.errorf("the probes during the change of the secret did not see the switch: in %d rounds the old secret got "+
			"through %d times, the new one %d times", watch.rounds, watch.oldOK, watch.newOK)
	}
	e.logf("while the node moved the proxy from generation %d of its engine to generation %d: %d rounds of a probe "+
		"with the old secret and then the new one; the old got through in %d, the new in %d, neither in %d",
		gen, next, watch.rounds, watch.oldOK, watch.newOK, len(watch.gaps))

	attempts, err := probeUntil(e.ctx, addr, sni, secret, 10*time.Second)
	if err != nil {
		e.fatalf("probe.FakeTLS with the new secret: %v (%d attempts within 10 s)", err, attempts)
	}
	how := e.expectRefused(addr, sni, old, "probe.FakeTLS with the first secret, after the change")
	e.logf("the new link gets through (attempt %d), and the first one is refused (%s)", attempts, how)

	e.waitFor(fmt.Sprintf("generation %d of the engine to go", gen), drainWithin, time.Second,
		func(ctx context.Context) (bool, string, error) {
			engines, err := e.engineContainers(ctx, proxyID)
			if err != nil {
				return false, "", err
			}
			if c, ok := engines[next]; !ok || c.State != "running" {
				return false, "", fmt.Errorf("generation %d of the engine is not running: the engines of the proxy are %s",
					next, describeEngines(engines))
			}
			return len(engines) == 1, describeEngines(engines), nil
		})
	return secret
}

func ptr[T any](v T) *T { return &v }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails
	return b
}
