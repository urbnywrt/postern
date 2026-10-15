//go:build e2e

package e2e

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/server"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/probe"
)

// TestVersions changes what a node runs, with one action each, while clients
// use it, and proves that no client notices (R5-2). One node, on channel
// latest, and two telemt proxies on it, A and B, that follow the channel:
//
//  1. the panel gets its releases from the release host of the run
//     (releasehost.go): telemt 3.5.90 (the real 3.5.13 under another
//     version), telemt 3.5.91 (a stand-in that passes the trial run and exits
//     as an engine) and postern-node v0.90.1-e2e, signed with the throwaway
//     key of the run; the node runs v0.90.0-e2e, the panel v0.90.1-e2e. A
//     prober runs an L1 probe every 250 ms through the edge, A and B in turn,
//     for the whole test;
//  2. a version rollout of telemt on latest to 3.5.90, A first: both proxies
//     run it, and the channel moves;
//  3. a version rollout to 3.5.91: its first step fails as the stand-in
//     exits, A goes back to 3.5.90 on the generation that it had and B is not
//     touched; the rollout is failed, and Abort ends it;
//  4. B switches to mtg (v2.2.8, from GitHub) and back to telemt: its links
//     never change, and mtg proves B's secret;
//  5. with net.ipv4.tcp_migrate_req = 1, a node rollout updates the agent
//     (UpdateSelf) and the edge (UpdateEdge) to v0.90.1-e2e while a flood of
//     short connections runs: none of them fails;
//  6. with the sysctl at 0, edge-only rollouts back to v0.90.0-e2e and on,
//     until the flood fails once (the prober is paused): the flood reaches
//     the accept queue, so its run at 1 proves something (a control: when it
//     never fails, a logged warning); at 1 again, an edge-only rollout and
//     the flood: no failure;
//  7. the prober saw no failure; no log of the run holds a secret.
//
// Before each change that moves a proxy, a connection to it goes through the
// fake-TLS handshake (a held connection), and it is still open once the
// change is through: telemt closes an idle client telemtIdle after its
// handshake (F11), so the change has to be through within telemtIdle −
// heldMargin, or the test fails and says so. With POSTERN_E2E_ONLINE=1 the
// held connections are L2 sessions instead, which ask DC2 every 10 s.
func TestVersions(t *testing.T) {
	e := newEnv(t)
	e.versionBinaries()
	host := e.startReleaseHost()
	// B's domain resolves to the gateway of this network (setUp).
	e.createNetwork()
	// The steps set net.ipv4.tcp_migrate_req of the host network; it is
	// restored at the end.
	migrate := e.migrateReq()
	t.Cleanup(func() {
		if got := e.migrateReq(); got != migrate {
			e.setMigrateReq(migrate)
		}
	})

	p := e.startPanel("POSTERN_GITHUB_API=" + host.base)
	a := newAPI(p.base)
	e.signIn(a, p.token)
	node := e.newNode(a)
	if node.GetAgentVersion() != nodeVersion {
		n, err := e.getNode(e.ctx, a, node.GetId())
		if err != nil {
			e.fatalf("%v", err)
		}
		if n.GetAgentVersion() != nodeVersion {
			e.fatalf("the node runs agent %q, want %s", n.GetAgentVersion(), nodeVersion)
		}
	}
	v := &versions{e: e, a: a, nodeID: node.GetId()}

	defer v.stopProber()
	// The steps build on each other: the first that fails ends the test.
	for _, step := range []struct {
		name string
		run  func(e *env)
	}{
		{"1 latest channel and two proxies", v.setUp},
		{"2 version rollout", v.versionRollout},
		{"3 failed rollout", v.failedRollout},
		{"4 engine switch", v.engineSwitch},
		{"5 node update", v.nodeUpdate},
		{"6 accept queue", v.acceptQueue},
		{"7 prober and logs", func(e *env) { v.finish(e, p) }},
	} {
		if !t.Run(step.name, func(t *testing.T) { step.run(e.sub(t)) }) {
			return
		}
	}
}

// versions is the state of TestVersions that its steps share.
type versions struct {
	e      *env
	a      *api
	nodeID string
	px     [2]*vproxy // A and B
	prober *prober

	failedRolloutID string
}

// vproxy is one of the proxies of TestVersions.
type vproxy struct {
	name   string
	id     string
	port   int
	addr   string
	domain string
	secret []byte
	links  *panelv1.GetProxyLinksResponse
}

func (x *vproxy) target() floodTarget {
	return floodTarget{addr: x.addr, sni: x.domain, secret: x.secret}
}

// ---- 1 -------------------------------------------------------------------------

func (v *versions) setUp(e *env) {
	a := v.a
	r, err := a.versions.SetNodeChannel(e.ctx, connect.NewRequest(&panelv1.SetNodeChannelRequest{
		NodeId: v.nodeID, Channel: store.ChannelLatest, Confirm: true,
	}))
	if err != nil || !r.Msg.GetApplied() {
		e.fatalf("SetNodeChannel(latest): applied %v, %v", r.Msg.GetApplied(), err)
	}
	for i, name := range []string{"A", "B"} {
		port := e.freePort("127.0.0.1", 10000, 19999)
		req := &panelv1.CreateListenerRequest{NodeId: v.nodeID, Kind: "tls", BindIp: "127.0.0.1", Port: uint32(port)}
		domain := proxyDomain
		if name == "B" {
			// mtg fronts to an address of the proxy domain, which it dials
			// itself (F6): B's domain resolves (sslip.io) to the gateway of the
			// run's network, a public address of the host where nothing
			// listens on 443, so the look-up works and a connection to it is
			// refused at once.
			domain = mtgDomain
		}
		lr, err := a.listeners.CreateListener(e.ctx, connect.NewRequest(req))
		if err != nil {
			e.fatalf("CreateListener: %v", err)
		}
		secretHex := hex.EncodeToString(randomBytes(16))
		e.mustNotLeak("the secret of proxy "+name, secretHex)
		pr, err := a.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
			NodeId: v.nodeID, ListenerId: lr.Msg.GetListener().GetId(), Name: "e2e-" + strings.ToLower(name),
			Domain: domain, Secret: secretHex,
		}))
		if err != nil {
			e.fatalf("CreateProxy %s: %v", name, err)
		}
		x := &vproxy{name: name, id: pr.Msg.GetProxy().GetId(), port: port, addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), domain: domain}
		x.secret, _ = e.checkLinksOf(a, x.id, port, secretHex, domain)
		x.links = v.links(e, x)
		v.px[i] = x
	}
	for _, x := range v.px {
		e.waitServing(a, x.id, 8*time.Minute)
		pr := e.proxyOf(a, x.id)
		switch {
		case pr.GetEngine() != "telemt" || pr.GetVersionSource() != "channel" || pr.GetEngineVersion() != proxies.DefaultTelemtVersion:
			e.fatalf("proxy %s is %s %s by %q, want telemt %s by the channel", x.name, pr.GetEngine(), pr.GetEngineVersion(),
				pr.GetVersionSource(), proxies.DefaultTelemtVersion)
		case pr.GetStatus().GetRunningVersion() != proxies.DefaultTelemtVersion:
			e.fatalf("proxy %s runs telemt %s, want %s", x.name, pr.GetStatus().GetRunningVersion(), proxies.DefaultTelemtVersion)
		}
		if n, err := probeUntil(e.ctx, x.addr, x.domain, x.secret, 30*time.Second); err != nil {
			e.fatalf("L1 through proxy %s: %v (%d attempts)", x.name, err, n)
		}
	}
	e.logf("proxies A and B serve on telemt %s, following channel latest", proxies.DefaultTelemtVersion)

	// The releases of the release host, as the panel's first poll finds them.
	e.waitFor("telemt "+goodTelemt+" and "+badTelemt+" in the catalog", 3*time.Minute, 2*time.Second,
		func(ctx context.Context) (bool, string, error) {
			r, err := a.versions.ListReleases(ctx, connect.NewRequest(&panelv1.ListReleasesRequest{Component: "telemt"}))
			if err != nil {
				return false, "", fmt.Errorf("ListReleases: %w", err)
			}
			var have []string
			for _, rel := range r.Msg.GetReleases() {
				have = append(have, rel.GetVersion())
			}
			slices.Sort(have)
			return slices.Contains(have, goodTelemt) && slices.Contains(have, badTelemt), strings.Join(have, ", "), nil
		})
	if mtgVersion != builtinMTG {
		e.prepareRelease(a, "mtg", mtgVersion)
	}
	// The panel pins the SHA-256 of a release that is not built in when it
	// prepares it: from the checksum file of the release host.
	for _, ver := range []string{goodTelemt, badTelemt} {
		r, err := a.versions.PrepareRelease(e.ctx, connect.NewRequest(&panelv1.PrepareReleaseRequest{Component: "telemt", Version: ver}))
		if err != nil {
			e.fatalf("PrepareRelease(telemt %s): %v", ver, err)
		}
		for _, as := range r.Msg.GetRelease().GetAssets() {
			e.logf("telemt %s for %s: %s, SHA-256 from %s", ver, as.GetArch(), as.GetState(), as.GetShaSource())
		}
	}

	v.prober = e.startProber(v.px[:])
}

// ---- 2 -------------------------------------------------------------------------

func (v *versions) versionRollout(e *env) {
	A, B := v.px[0], v.px[1]
	genA, genB := v.generation(e, A), v.generation(e, B)
	ro := v.start(e, &panelv1.StartRolloutRequest{
		Kind: "version", Component: "telemt", Channel: store.ChannelLatest, ToVersion: goodTelemt,
		Mode: "auto", PauseSeconds: 2, CanaryProxyId: A.id,
	})
	// The first step moves A: the held connection goes to A as soon as the
	// rollout has prepared the release, before the new generation serves.
	v.waitRollout(e, ro, "the first step to start", 5*time.Minute, func(r *panelv1.Rollout) bool {
		return r.GetStatus() != "preparing"
	})
	// The diagnostics before and after every step (Task 15 of slice 6) add
	// up to 3 minutes to each side of a step. telemt ends an idle client
	// about 30 s after its handshake, so a held connection is opened once
	// its step's before-run is over (the step is applied right after it),
	// and checked as soon as its proxy has moved, not once its step is done.
	v.waitRollout(e, ro, "the before-run of the first step (A)", stepWait, func(r *panelv1.Rollout) bool { return beforeRunOver(r, 0) })
	heldA := e.hold(A, "A (opened before its step)")
	v.waitRollout(e, ro, "the first step (A) to apply", stepWait, func(r *panelv1.Rollout) bool { return stepApplied(r, 0) })
	v.waitMoved(e, A, genA, goodTelemt)
	heldA.check("after A moved to telemt " + goodTelemt)
	v.waitRollout(e, ro, "the first step (A)", stepWait, func(r *panelv1.Rollout) bool { return stepDone(r, 0) })
	v.waitRollout(e, ro, "the before-run of the second step (B)", stepWait, func(r *panelv1.Rollout) bool { return beforeRunOver(r, 1) })
	heldB := e.hold(B, "B (opened before its step)")
	v.waitRollout(e, ro, "the second step (B) to apply", stepWait, func(r *panelv1.Rollout) bool { return stepApplied(r, 1) })
	v.waitMoved(e, B, genB, goodTelemt)
	heldB.check("after B moved to telemt " + goodTelemt)
	r := v.waitRollout(e, ro, "the rollout to complete", stepWait, func(r *panelv1.Rollout) bool { return r.GetStatus() == "completed" })
	if len(r.GetSteps()) != 2 || r.GetSteps()[0].GetProxyId() != A.id {
		e.errorf("the rollout had %d steps, the first for proxy %q; want 2, the first for A", len(r.GetSteps()), r.GetSteps()[0].GetProxyId())
	}
	for _, x := range v.px {
		pr := e.proxyOf(v.a, x.id)
		if pr.GetEngineVersion() != goodTelemt || pr.GetVersionSource() != "channel" {
			e.errorf("proxy %s is on %s by %q after the rollout, want %s by the channel", x.name, pr.GetEngineVersion(), pr.GetVersionSource(), goodTelemt)
		}
	}
	if ch := v.channelVersion(e, "telemt"); ch != goodTelemt {
		e.errorf("the channel latest of telemt is %s after the rollout, want %s", ch, goodTelemt)
	}
	e.logf("telemt %s on A, then on the rest of the node; the channel latest is %s", goodTelemt, goodTelemt)
}

// ---- 3 -------------------------------------------------------------------------

func (v *versions) failedRollout(e *env) {
	A, B := v.px[0], v.px[1]
	genA, genB := v.generation(e, A), v.generation(e, B)
	ro := v.start(e, &panelv1.StartRolloutRequest{
		Kind: "version", Component: "telemt", Channel: store.ChannelLatest, ToVersion: badTelemt,
		Mode: "auto", PauseSeconds: 2, CanaryProxyId: A.id,
	})
	v.failedRolloutID = ro
	r := v.waitRollout(e, ro, "the rollout to fail", 8*time.Minute, func(r *panelv1.Rollout) bool {
		return r.GetStatus() == "failed" || r.GetStatus() == "completed"
	})
	if r.GetStatus() != "failed" || r.GetCurrentStep() != 0 {
		e.fatalf("the rollout to the stand-in is %s at step %d, want failed at step 0", r.GetStatus(), r.GetCurrentStep())
	}
	e.logf("the rollout failed at its first step: %s", r.GetError())
	e.waitFor("A back on telemt "+goodTelemt, 2*time.Minute, time.Second, func(ctx context.Context) (bool, string, error) {
		pr, err := v.a.proxies.GetProxy(ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: A.id}))
		if err != nil {
			return false, "", err
		}
		p := pr.Msg.GetProxy()
		st := p.GetStatus()
		return p.GetEngineVersion() == goodTelemt && p.GetVersionSource() == "channel" && st.GetPhase() == "serving" &&
				st.GetRunningVersion() == goodTelemt,
			fmt.Sprintf("%s by %q, %s on %s, generation %d", p.GetEngineVersion(), p.GetVersionSource(), st.GetPhase(),
				st.GetRunningVersion(), st.GetInstanceGeneration()), nil
	})
	if g := v.generation(e, A); g != genA {
		e.errorf("A serves on generation %d after the failed step, want the generation that it had, %d", g, genA)
	}
	if g := v.generation(e, B); g != genB {
		e.errorf("B is on generation %d after the failed rollout, want %d: the rollout stopped before it", g, genB)
	}
	if _, err := v.a.versions.AbortRollout(e.ctx, connect.NewRequest(&panelv1.AbortRolloutRequest{Id: ro})); err != nil {
		e.fatalf("AbortRollout: %v", err)
	}
	r = v.waitRollout(e, ro, "the rollout to be aborted", 2*time.Minute, func(r *panelv1.Rollout) bool { return r.GetStatus() == "aborted" })
	if ch := v.channelVersion(e, "telemt"); ch != goodTelemt {
		e.errorf("the channel latest of telemt is %s after the failed rollout, want %s", ch, goodTelemt)
	}
	active, err := v.a.versions.ListRollouts(e.ctx, connect.NewRequest(&panelv1.ListRolloutsRequest{ActiveOnly: true}))
	if err != nil {
		e.fatalf("ListRollouts: %v", err)
	}
	if n := len(active.Msg.GetRollouts()); n != 0 {
		e.errorf("%d rollouts are active after the abort, want none", n)
	}
	e.logf("A is back on telemt %s, generation %d; B on generation %d; the rollout is %s", goodTelemt, genA, genB, r.GetStatus())
}

// ---- 4 -------------------------------------------------------------------------

func (v *versions) engineSwitch(e *env) {
	B := v.px[1]
	for _, to := range []string{"mtg", "telemt"} {
		gen := v.generation(e, B)
		// The built-in mtg follows the channel; an override is pinned.
		pin := ""
		if to == "mtg" && mtgVersion != builtinMTG {
			pin = mtgVersion
		}
		ro := v.start(e, &panelv1.StartRolloutRequest{Kind: "switch", Component: to, ToVersion: pin, ProxyIds: []string{B.id}, Mode: "auto", PauseSeconds: 2})
		v.waitRollout(e, ro, "the switch to start", 5*time.Minute, func(r *panelv1.Rollout) bool { return r.GetStatus() != "preparing" })
		// A connection to the generation that serves B. mtg ends a client
		// that has sent nothing 10 s after its handshake (its handshake
		// timeout, internal/engines/mtg), so only an L2 session, which keeps
		// asking DC2, outlasts the switch back from it; offline the prober
		// watches B through that switch instead.
		v.waitRollout(e, ro, "the before-run of the switch of B to "+to, stepWait, func(r *panelv1.Rollout) bool { return beforeRunOver(r, 0) })
		var held *heldConn
		if to == "mtg" || online() {
			held = e.hold(B, "B (opened before its switch to "+to+")")
		} else {
			e.logf("no held connection on B's mtg generation: mtg ends a silent client 10 s after its handshake, and an L2 " +
				"session needs POSTERN_E2E_ONLINE=1")
		}
		v.waitRollout(e, ro, "the switch of B to "+to+" to apply", stepWait, func(r *panelv1.Rollout) bool { return stepApplied(r, 0) })
		want := goodTelemt
		if to == "mtg" {
			want = mtgVersion
		}
		v.waitFor(e, B, "B on "+to+" "+want, func(p *panelv1.Proxy) bool {
			st := p.GetStatus()
			return st.GetPhase() == "serving" && st.GetRunningEngine() == to && st.GetRunningVersion() == want && st.GetInstanceGeneration() > gen
		})
		if held != nil {
			held.check(fmt.Sprintf("after B moved to %s (its connection is on the generation before)", to))
		}
		r := v.waitRollout(e, ro, "the switch of B to "+to, stepWait, func(r *panelv1.Rollout) bool { return r.GetStatus() == "completed" })
		if links := v.links(e, B); links.GetTg() != B.links.GetTg() || links.GetHttps() != B.links.GetHttps() {
			e.errorf("the links of B changed with its switch to %s", to)
		}
		if n, err := probeUntil(e.ctx, B.addr, B.domain, B.secret, 30*time.Second); err != nil {
			e.fatalf("L1 with B's secret after its switch to %s: %v (%d attempts)", to, err, n)
		}
		e.logf("B runs %s %s (rollout %s): its links are the same, and %s proves its secret", to, want, r.GetStatus(), to)
	}
}

// ---- 5 -------------------------------------------------------------------------

func (v *versions) nodeUpdate(e *env) {
	e.agentUpdates = true
	e.setMigrateReq(1)
	v.nodeRollout(e, updateVersion, true, true)
}

// nodeRollout runs a node rollout of the edge to ver, and of the agent first
// when agent is set: the held connections and the flood go with the edge roll
// (edgeRoll), which comes once the agent is healthy on ver. Then the node runs
// ver, its agent healthy. With zero the flood may not fail. It returns the
// flood.
func (v *versions) nodeRollout(e *env, ver string, agent, zero bool) *flood {
	e.t.Helper()
	before, err := e.getNode(e.ctx, v.a, v.nodeID)
	if err != nil {
		e.fatalf("%v", err)
	}
	edge, _ := e.nodeContainer("edge", "edge")
	ro := v.start(e, &panelv1.StartRolloutRequest{
		Kind: "node", ToVersion: ver, NodeIds: []string{v.nodeID}, Agent: agent, Edge: true, Mode: "auto", PauseSeconds: 2,
	})
	wantAgent := before.GetAgentVersion()
	if agent {
		wantAgent = ver
		// The agent goes first; the edge rolls once the new agent is healthy.
		e.waitFor("the agent on "+ver, 10*time.Minute, 250*time.Millisecond, func(ctx context.Context) (bool, string, error) {
			n, err := e.getNode(ctx, v.a, v.nodeID)
			if err != nil {
				return false, "", nil // the panel may be between two connections of the node
			}
			return n.GetAgentVersion() == ver && n.GetHealthy(),
				fmt.Sprintf("agent %s, healthy %v, edge %s", n.GetAgentVersion(), n.GetHealthy(), n.GetEdgeVersion()), nil
		})
	}
	f := v.edgeRoll(e, ro, ver, edge, zero)
	n, err := e.getNode(e.ctx, v.a, v.nodeID)
	if err != nil {
		e.fatalf("%v", err)
	}
	if n.GetAgentVersion() != wantAgent || !n.GetHealthy() || n.GetEdgeVersion() != ver {
		e.errorf("the node is on agent %s (healthy %v), edge %s after the rollout; want agent %s, healthy, edge %s",
			n.GetAgentVersion(), n.GetHealthy(), n.GetEdgeVersion(), wantAgent, ver)
	}
	return f
}

// edgeRoll follows a node rollout of the edge to ver: right before the roll,
// a held connection to each proxy and the flood; then the rollout completes,
// the edge is a new container, the held connections are open, and with zero
// the flood saw no failure. It returns the flood.
func (v *versions) edgeRoll(e *env, ro, ver string, edge rawContainer, zero bool) *flood {
	// After the step's before-run: telemt ends an idle client about 30 s
	// after its handshake.
	v.waitRollout(e, ro, "the before-run of the edge roll to "+ver, stepWait, func(r *panelv1.Rollout) bool { return beforeRunOver(r, 0) })
	held := []*heldConn{e.hold(v.px[0], "A (opened before the edge roll)"), e.hold(v.px[1], "B (opened before the edge roll)")}
	f := e.startFlood([]floodTarget{v.px[0].target(), v.px[1].target()})
	stopped := false
	defer func() {
		if !stopped {
			f.end()
		}
	}()
	e.waitFor("the edge on "+ver, 5*time.Minute, 250*time.Millisecond, func(ctx context.Context) (bool, string, error) {
		n, err := e.getNode(ctx, v.a, v.nodeID)
		if err != nil {
			return false, "", nil
		}
		return n.GetEdgeVersion() == ver, "edge " + n.GetEdgeVersion(), nil
	})
	for _, h := range held {
		h.check("after the edge rolled to " + ver)
	}
	r := v.waitRollout(e, ro, "the node rollout to complete", 5*time.Minute, func(r *panelv1.Rollout) bool { return r.GetStatus() == "completed" })
	f.end()
	stopped = true
	if e2, _ := e.nodeContainer("edge", "edge"); e2.ID == edge.ID {
		e.errorf("the edge is the container of before the roll to %s", ver)
	}
	if zero && f.failures.Load() != 0 {
		e.errorf("the flood during the edge roll to %s failed: %s", ver, f)
	}
	e.logf("the edge rolled to %s (rollout %s); the flood: %s", ver, r.GetStatus(), f)
	return f
}

// ---- 6 -------------------------------------------------------------------------

// acceptQueue rolls the edge with net.ipv4.tcp_migrate_req at 0, where the
// flood has to fail, and at 1 again, where it may not.
//
// A roll resets only what is in the accept queue, or half open, at the old
// edge's listeners at the moment they close, so one roll at 0 fails the
// flood in about one run of two here (256 workers, some 14 000 connections a
// second, one or two failures when it does): the rolls at 0 go on, back and
// forth, until the flood has failed, maxRollsAtZero at the most. That is a
// control, not a verdict: when no roll at 0 failed the flood, the test logs a
// warning and goes on, so that chance never fails a good candidate (the
// stable job). The roll at 1 has to see no failure at all.
//
// Every roll is edge-only, the first one back to nodeVersion, which the node
// was installed with: installNode keeps its signature beside the binary, as
// install.sh does, and the agent's UpdateSelf kept one for updateVersion.
func (v *versions) acceptQueue(e *env) {
	e.agentUpdates = true
	v.prober.pause()
	e.setMigrateReq(0)
	var failures int64
	rolls, at := 0, updateVersion
	for ; failures == 0 && rolls < maxRollsAtZero; rolls++ {
		at = otherVersion(at)
		failures += v.nodeRollout(e, at, false, false).failures.Load()
	}
	if failures == 0 {
		e.logf("WARNING: the flood saw no failure in %d edge rolls at net.ipv4.tcp_migrate_req = 0, so it is not shown to "+
			"reach the accept queue, and the zero-failure roll at 1 may prove nothing (expected about one run in 150; "+
			"not a failure)", rolls)
	} else {
		e.logf("at net.ipv4.tcp_migrate_req = 0 the flood saw %d failed connections in %d edge rolls", failures, rolls)
	}
	v.prober.resume()

	e.setMigrateReq(1)
	v.nodeRollout(e, otherVersion(at), false, true)
}

// maxRollsAtZero bounds the edge rolls at net.ipv4.tcp_migrate_req = 0
// (acceptQueue). Seven local runs needed 1, 1, 2, 5, 3, 2 and 1 rolls (7
// of 15 rolls failed the flood): with about one in two failing, all eight
// pass by chance once in some 150 runs, which is then a logged warning.
const maxRollsAtZero = 8

// otherVersion is the node version that is not ver.
func otherVersion(ver string) string {
	if ver == nodeVersion {
		return updateVersion
	}
	return nodeVersion
}

// ---- 7 -------------------------------------------------------------------------

func (v *versions) finish(e *env, p *panel) {
	pr := v.stopProber()
	if pr.failures.Load() != 0 {
		e.errorf("the prober failed: %s", pr)
	} else {
		e.logf("the prober: %s", pr)
	}
	if err := p.stop(15 * time.Second); err != nil {
		e.errorf("the panel did not stop cleanly: %v", err)
	}
	// The events are not in the API: the database of the stopped panel has
	// them.
	db, err := store.Open(filepath.Join(p.data, server.DatabaseFile))
	if err != nil {
		e.fatalf("opening the database of the panel: %v", err)
	}
	defer func() { _ = db.Close() }()
	events, err := db.ListEvents(e.ctx, 1000, "")
	if err != nil {
		e.fatalf("ListEvents: %v", err)
	}
	if !slices.ContainsFunc(events, func(ev *store.Event) bool {
		return ev.Kind == "rollout_failed" && ev.Details["rollout"] == v.failedRolloutID
	}) {
		e.errorf("no event rollout_failed for the rollout to %s", badTelemt)
	}
	e.checkLogs()
}

// ---- helpers ---------------------------------------------------------------------

// mtgDomain is the domain of proxy B, which switches to mtg: sslip.io resolves
// it to testGateway.
const mtgDomain = "198-51-100-1.sslip.io"

func (v *versions) stopProber() *prober {
	if v.prober != nil {
		v.prober.stop()
	}
	return v.prober
}

// start starts a rollout and returns its id.
func (v *versions) start(e *env, req *panelv1.StartRolloutRequest) string {
	e.t.Helper()
	r, err := v.a.versions.StartRollout(e.ctx, connect.NewRequest(req))
	if err != nil {
		e.fatalf("StartRollout(%s %s %s): %v", req.GetKind(), req.GetComponent(), req.GetToVersion(), err)
	}
	ro := r.Msg.GetRollout()
	e.logf("rollout %s: %s of %s to %s%s, %d steps", ro.GetId(), ro.GetKind(), ro.GetComponent(), ro.GetToVersion(), ro.GetToEngine(), len(ro.GetSteps()))
	return ro.GetId()
}

// waitRollout waits until done holds of the rollout, polling fast: a held
// connection waits on it. A rollout that failed or was aborted when done
// does not hold fails the test.
func (v *versions) waitRollout(e *env, id, what string, timeout time.Duration, done func(*panelv1.Rollout) bool) *panelv1.Rollout {
	e.t.Helper()
	var last *panelv1.Rollout
	e.waitFor(what, timeout, 100*time.Millisecond, func(ctx context.Context) (bool, string, error) {
		r, err := v.a.versions.GetRollout(ctx, connect.NewRequest(&panelv1.GetRolloutRequest{Id: id}))
		if err != nil {
			return false, "", fmt.Errorf("GetRollout: %w", err)
		}
		last = r.Msg.GetRollout()
		if done(last) {
			return true, describeRollout(last), nil
		}
		if s := last.GetStatus(); s == "failed" || s == "aborted" || s == "completed" {
			return false, "", fmt.Errorf("the rollout is %s: %s (%s)", s, last.GetError(), describeRollout(last))
		}
		return false, describeRollout(last), nil
	})
	return last
}

func describeRollout(r *panelv1.Rollout) string {
	var steps []string
	for _, s := range r.GetSteps() {
		st := s.GetStatus()
		if s.GetError() != "" {
			st += " (" + s.GetError() + ")"
		}
		steps = append(steps, st)
	}
	return fmt.Sprintf("%s, step %d; steps: %s", r.GetStatus(), r.GetCurrentStep(), strings.Join(steps, ", "))
}

func stepDone(r *panelv1.Rollout, i int) bool {
	return len(r.GetSteps()) > i && r.GetSteps()[i].GetStatus() == "done"
}

// stepApplied says that a step is past its before-step diagnostics: applied
// or later.
func stepApplied(r *panelv1.Rollout, i int) bool {
	return len(r.GetSteps()) > i && r.GetSteps()[i].GetStatus() != "pending"
}

// beforeRunOver says that the diagnostics before a step are over (or that
// the step went on already): the step is applied right after them.
func beforeRunOver(r *panelv1.Rollout, i int) bool {
	if len(r.GetSteps()) <= i {
		return false
	}
	s := r.GetSteps()[i]
	return (s.GetBeforeRunId() != "" && s.GetBeforeRunState() != "running") || s.GetStatus() != "pending"
}

// stepWait bounds the wait for a step: the diagnostics before and after it
// take up to 3 minutes each.
const stepWait = 10 * time.Minute

// generation is the instance generation of the engine that serves the proxy.
func (v *versions) generation(e *env, x *vproxy) uint64 {
	e.t.Helper()
	return e.proxyOf(v.a, x.id).GetStatus().GetInstanceGeneration()
}

// waitMoved waits until the proxy serves on ver on a generation after gen.
func (v *versions) waitMoved(e *env, x *vproxy, gen uint64, ver string) {
	e.t.Helper()
	v.waitFor(e, x, x.name+" on telemt "+ver, func(p *panelv1.Proxy) bool {
		st := p.GetStatus()
		return st.GetPhase() == "serving" && st.GetRunningVersion() == ver && st.GetInstanceGeneration() > gen
	})
}

// waitFor waits a minute at the most until ok holds of the proxy, polling fast.
func (v *versions) waitFor(e *env, x *vproxy, what string, ok func(*panelv1.Proxy) bool) {
	e.t.Helper()
	e.waitFor(what, time.Minute, 100*time.Millisecond, func(ctx context.Context) (bool, string, error) {
		r, err := v.a.proxies.GetProxy(ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: x.id}))
		if err != nil {
			return false, "", fmt.Errorf("GetProxy: %w", err)
		}
		p := r.Msg.GetProxy()
		st := p.GetStatus()
		return ok(p), fmt.Sprintf("%s, %s %s, generation %d", st.GetPhase(), st.GetRunningEngine(), st.GetRunningVersion(), st.GetInstanceGeneration()), nil
	})
}

func (v *versions) channelVersion(e *env, component string) string {
	e.t.Helper()
	r, err := v.a.versions.ListComponents(e.ctx, connect.NewRequest(&panelv1.ListComponentsRequest{}))
	if err != nil {
		e.fatalf("ListComponents: %v", err)
	}
	for _, c := range r.Msg.GetComponents() {
		if c.GetName() == component {
			return c.GetChannelVersions()[store.ChannelLatest]
		}
	}
	return ""
}

func (v *versions) links(e *env, x *vproxy) *panelv1.GetProxyLinksResponse {
	e.t.Helper()
	r, err := v.a.proxies.GetProxyLinks(e.ctx, connect.NewRequest(&panelv1.GetProxyLinksRequest{Id: x.id}))
	if err != nil {
		e.fatalf("GetProxyLinks: %v", err)
	}
	return r.Msg
}

// ---- held connections --------------------------------------------------------------

// online reports whether the run checks what a client gets from Telegram
// (POSTERN_E2E_ONLINE=1).
func online() bool { return os.Getenv("POSTERN_E2E_ONLINE") == "1" }

// l2Every is how often an L2 session asks the datacenter.
const l2Every = 10 * time.Second

// heldConn is a connection opened right before a change: a fake-TLS
// connection that sends nothing after its handshake, or online an L2 session
// that asks DC2 every l2Every.
type heldConn struct {
	e    *env
	what string
	conn net.Conn
	at   time.Time // the handshake

	l2   *probe.L2Session
	stop chan struct{}
	done chan struct{}
	mu   sync.Mutex
	err  error // of the session
	asks int
}

// hold opens a held connection to the proxy.
func (e *env) hold(x *vproxy, what string) *heldConn {
	e.t.Helper()
	h := &heldConn{e: e, what: what}
	if online() {
		s, err := probe.OpenL2(e.ctx, x.addr, x.domain, x.secret, 2, probe.Options{Timeout: 15 * time.Second})
		if err != nil {
			e.fatalf("an L2 session to %s: %v", what, err)
		}
		h.l2, h.at, h.stop, h.done = s, time.Now(), make(chan struct{}), make(chan struct{})
		go h.ask()
		e.t.Cleanup(func() { h.close() })
		return h
	}
	conn, err := net.DialTimeout("tcp", x.addr, 5*time.Second)
	if err != nil {
		e.fatalf("connecting to %s: %v", what, err)
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	if err := probe.Handshake(conn, x.domain, x.secret, probe.Options{Timeout: 10 * time.Second}); err != nil {
		e.fatalf("the handshake of a held connection to %s: %v", what, err)
	}
	h.conn, h.at = conn, time.Now()
	return h
}

// ask asks the datacenter through the L2 session every l2Every, until close.
func (h *heldConn) ask() {
	defer close(h.done)
	for {
		select {
		case <-h.stop:
			return
		case <-time.After(l2Every):
		}
		ctx, cancel := context.WithTimeout(h.e.ctx, 15*time.Second)
		err := h.l2.Ping(ctx)
		cancel()
		h.mu.Lock()
		h.asks++
		if err != nil && h.err == nil {
			h.err = err
		}
		h.mu.Unlock()
		if err != nil {
			return
		}
	}
}

func (h *heldConn) close() {
	if h.l2 == nil {
		return
	}
	select {
	case <-h.stop:
	default:
		close(h.stop)
	}
	_ = h.l2.Close()
	<-h.done
}

// check fails the test unless the held connection is open, when within is
// what happened since it was opened. A fake-TLS connection is checked within
// telemtIdle − heldMargin of its handshake, or the test fails: the change
// took too long for the check to mean anything. An L2 session asks the
// datacenter once more.
func (h *heldConn) check(within string) {
	e := h.e
	e.t.Helper()
	since := time.Since(h.at)
	if h.l2 != nil {
		h.mu.Lock()
		err, asks := h.err, h.asks
		h.mu.Unlock()
		if err == nil {
			ctx, cancel := context.WithTimeout(e.ctx, 15*time.Second)
			err = h.l2.Ping(ctx)
			cancel()
			asks++
		}
		if err != nil {
			e.fatalf("the L2 session to %s, %s: %v (after %d answers, %.1fs)", h.what, within, err, asks, since.Seconds())
		}
		e.logf("the L2 session to %s is alive %s: DC2 answered %d times in %.1fs", h.what, within, asks, since.Seconds())
		h.close()
		return
	}
	if left := telemtIdle - heldMargin - since; left <= 0 {
		e.fatalf("the held connection to %s: the change took %.1fs from its handshake, too long to check it %s before telemt "+
			"closes an idle client (%v after its handshake)", h.what, since.Seconds(), within, telemtIdle)
	}
	e.expectOpen(h.conn, 2*time.Second, fmt.Sprintf("the held connection to %s, %s, %.1fs after its handshake", h.what, within, since.Seconds()))
	e.logf("the held connection to %s is open %s, %.1fs after its handshake", h.what, within, since.Seconds())
	_ = h.conn.Close()
}

// ---- the prober ------------------------------------------------------------------

// proberEvery is how often the prober runs an L1 probe.
const proberEvery = 250 * time.Millisecond

// prober runs L1 (probe.FakeTLS) every proberEvery, through the proxies in
// turn, and counts the failures.
type prober struct {
	stopc  chan struct{}
	done   chan struct{}
	paused atomic.Bool
	mu     sync.Mutex // held while a probe runs

	probes, failures atomic.Int64
	smu              sync.Mutex
	samples          []string
	once             sync.Once
}

func (e *env) startProber(px []*vproxy) *prober {
	p := &prober{stopc: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		for i := 0; ; i++ {
			select {
			case <-p.stopc:
				return
			case <-e.ctx.Done():
				return
			case <-time.After(proberEvery):
			}
			if p.paused.Load() {
				continue
			}
			p.mu.Lock()
			x := px[i%len(px)]
			err := probe.FakeTLS(e.ctx, x.addr, x.domain, x.secret, probe.Options{Timeout: 5 * time.Second})
			p.mu.Unlock()
			if e.ctx.Err() != nil {
				return
			}
			p.probes.Add(1)
			if err != nil {
				p.failures.Add(1)
				p.smu.Lock()
				if len(p.samples) < floodSamples {
					p.samples = append(p.samples, fmt.Sprintf("%s at %s: %v", x.name, time.Now().Format("15:04:05.000"), err))
				}
				p.smu.Unlock()
			}
		}
	}()
	return p
}

// pause stops the probes once the one that runs is over.
func (p *prober) pause() {
	p.paused.Store(true)
	p.mu.Lock()
	defer p.mu.Unlock()
}

func (p *prober) resume() { p.paused.Store(false) }

func (p *prober) stop() {
	p.once.Do(func() {
		close(p.stopc)
		<-p.done
	})
}

func (p *prober) String() string {
	p.smu.Lock()
	defer p.smu.Unlock()
	s := fmt.Sprintf("%d L1 probes, %d failed", p.probes.Load(), p.failures.Load())
	if len(p.samples) > 0 {
		s += " (" + strings.Join(p.samples, "; ") + ")"
	}
	return s
}
