package reconcile

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/mtg"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/providers"
)

const engName3 = "postern-eng-01j9zzproxy0000000000000p1-g3"

func notReady(context.Context, engines.Instance) error { return errors.New("not ready") }

// A change of engine is a new instance hash, so the existing blue-green does
// the switch: generation 2 is mtg's container from the mtg driver's spec, with
// the mask override as its fronting address, beside telemt's generation 1; the
// route moves to it only after it is ready and probed, with the same domain
// and secret, and generation 1 drains.
func TestEngineSwitchTelemtToMTGIsBlueGreen(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	old := h.runtime().Instances[proxyID]
	h.fakeEdge(1).setActive(proxyID, old.ListenPort, 2)

	var routeAtProbe []string
	h.prober.setFail(func(probeCall) error {
		routeAtProbe = routeBackends(h.lastSetConfig())
		return nil
	})
	h.apply(h.mtgState(2, "192.0.2.10:8443"))
	h.pass()

	rec := h.runtime().Instances[proxyID]
	if rec.Generation != 2 || rec.Engine != "mtg" || rec.Version != mtg.DefaultVersion || rec.Hash == old.Hash {
		t.Fatalf("runtime instance = %+v, want generation 2 on mtg", rec)
	}
	if len(rec.Draining) != 1 || rec.Draining[0].Generation != 1 {
		t.Errorf("draining = %+v, want generation 1", rec.Draining)
	}
	creates := h.creates("engine")
	if len(creates) != 2 || creates[1].Name != engName2 {
		t.Fatalf("engine creates = %v, want g2 second", creates)
	}
	g2 := creates[1]
	if !slices.Equal(g2.Entrypoint, []string{"/opt/engine/mtg", "run", "/etc/mtg/config.toml"}) {
		t.Errorf("g2 entrypoint = %v, want mtg's", g2.Entrypoint)
	}
	a := h.mtgArtifact
	bin := h.arts.BinaryPath(artifacts.Ref{Engine: a.Engine, Version: a.Version, Arch: a.Arch, SHA256: a.Sha256, FileName: a.FileName, Binary: a.Binary})
	if !slices.Contains(g2.Binds, bin+":/opt/engine/mtg:ro") {
		t.Errorf("g2 binds = %v, want the mtg binary %s", g2.Binds, bin)
	}
	cfg := h.engineConfig(2)
	for _, want := range []string{`ip = "192.0.2.10"`, "port = 8443", `proxies = ["socks5://` + addr(rec.SocksPort) + `"]`, `bind-to = "` + addr(rec.ListenPort) + `"`} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config.toml lacks %q:\n%s", want, cfg)
		}
	}

	// The probe went to g2 with the same domain and secret, while the route
	// still pointed at g1; now it points at g2.
	probes := h.prober.callList()
	last := probes[len(probes)-1]
	if last.addr != addr(rec.ListenPort) || last.sni != "a.example.com" || hex.EncodeToString(last.secret) != secret1 {
		t.Errorf("probe = %+v, want g2 with the proxy's domain and secret", last)
	}
	if !slices.Equal(routeAtProbe, []string{proxyID + "->" + addr(old.ListenPort)}) {
		t.Errorf("routes at the probe = %v, want still g1", routeAtProbe)
	}
	if got := routeBackends(h.fakeEdge(1).lastConfig(t)); !slices.Equal(got, []string{proxyID + "->" + addr(rec.ListenPort)}) {
		t.Errorf("routes = %v, want g2", got)
	}
	if g1 := h.container(engName1); g1 == nil || g1.State != "running" || g1.RestartPolicy != "no" {
		t.Errorf("g1 = %+v, want draining (running, restart policy no)", g1)
	}
	ps := h.proxyStatus(proxyID)
	want := &nodev1.ProxyStatus{ProxyId: proxyID, Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_MTG, RunningVersion: mtg.DefaultVersion, InstanceGeneration: 2}
	if !proto.Equal(ps, want) {
		t.Errorf("status = %v, want %v", ps, want)
	}

	// g1 drains away like any other generation.
	h.fakeEdge(1).setActive(proxyID, old.ListenPort, 0)
	h.pass()
	if c := h.container(engName1); c != nil {
		t.Errorf("g1 still exists: %+v", c)
	}
	assertNoSecretsInEvents(t, h)
}

// A failing mtg generation keeps telemt serving and the report says so: the
// engine is the serving one, failed_engine and failed_version the desired
// instance's; back on telemt they are cleared and nothing new is started; mtg
// again right after is attempted at once (the failure memory went with the
// desired hash); another version reports its own failed_version; and once mtg
// serves the fields are cleared.
func TestFailingMTGGenerationKeepsTelemtAndReportsIt(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	h.mtg.setReady(notReady)

	h.apply(h.mtgState(2, "192.0.2.10"))
	h.pass()
	if c := h.container(engName2); c != nil {
		t.Errorf("g2 still exists: %+v", c)
	}
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING || ps.GetEngine() != nodev1.Engine_ENGINE_TELEMT ||
		ps.GetRunningVersion() != "3.5.13" || ps.GetInstanceGeneration() != 1 ||
		ps.GetFailedEngine() != nodev1.Engine_ENGINE_MTG || ps.GetFailedVersion() != mtg.DefaultVersion ||
		!strings.Contains(ps.GetReason(), "upgrade aborted") {
		t.Errorf("status = %v, want telemt 3.5.13 serving with failed mtg %s", ps, mtg.DefaultVersion)
	}
	if n := len(h.eventsOf("upgrade_aborted")); n != 1 {
		t.Errorf("upgrade_aborted events = %d, want 1", n)
	}

	// Back on telemt: cleared, and generation 1 goes on as it is.
	h.docker.ResetCalls()
	h.apply(h.baseState(3))
	h.pass()
	ps = h.proxyStatus(proxyID)
	want := &nodev1.ProxyStatus{ProxyId: proxyID, Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_TELEMT, RunningVersion: "3.5.13", InstanceGeneration: 1}
	if !proto.Equal(ps, want) {
		t.Errorf("status = %v, want %v", ps, want)
	}
	if n := len(h.creates("engine")); n != 0 {
		t.Errorf("%d engine creates on the way back to telemt, want none", n)
	}

	// mtg again, at once: attempted (generation 3), not held by the backoff.
	h.docker.ResetCalls()
	h.apply(h.mtgState(4, "192.0.2.10"))
	h.pass()
	if creates := h.creates("engine"); len(creates) != 1 || creates[0].Name != engName3 {
		t.Errorf("engine creates = %v, want generation 3 attempted at once", creates)
	}
	if ps := h.proxyStatus(proxyID); ps.GetFailedEngine() != nodev1.Engine_ENGINE_MTG || ps.GetFailedVersion() != mtg.DefaultVersion || ps.GetEngine() != nodev1.Engine_ENGINE_TELEMT {
		t.Errorf("status = %v, want telemt serving with failed mtg", ps)
	}

	// Within the backoff the same target is not tried again...
	h.docker.ResetCalls()
	h.pass()
	if n := len(h.creates("engine")); n != 0 {
		t.Errorf("%d engine creates within the backoff, want none", n)
	}
	// ...but another version is, and reports its own failed_version.
	st := h.mtgState(5, "192.0.2.10")
	st.Proxies[0].EngineVersion = "v2.2.9"
	st.Artifacts = append(st.Artifacts, h.storeArtifact("mtg", "v2.2.9", "mtg"))
	h.apply(st)
	h.pass()
	if creates := h.creates("engine"); len(creates) != 1 {
		t.Errorf("engine creates = %v, want the new version attempted at once", creates)
	}
	if ps := h.proxyStatus(proxyID); ps.GetFailedVersion() != "v2.2.9" || ps.GetFailedEngine() != nodev1.Engine_ENGINE_MTG || ps.GetRunningVersion() != "3.5.13" {
		t.Errorf("status = %v, want failed_version v2.2.9", ps)
	}

	// mtg ready at last: after the backoff it serves, and the fields are
	// cleared.
	h.mtg.setReady(nil)
	h.clock.Advance(defaultRetryAfter + time.Second)
	h.pass()
	ps = h.proxyStatus(proxyID)
	want = &nodev1.ProxyStatus{ProxyId: proxyID, Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_MTG, RunningVersion: "v2.2.9", InstanceGeneration: 5}
	if !proto.Equal(ps, want) {
		t.Errorf("status = %v, want %v", ps, want)
	}
	assertNoSecretsInEvents(t, h)
}

// Without a mask override the fronting address of an mtg proxy is an address
// of its domain that the agent resolves: the first IPv4 address the policy
// allows, kept while the answer still names it, looked up again after five
// minutes, and a new address is a new generation. A domain without an
// allowed address fails the plan with a clear reason, once, and is not looked
// up again before the interval.
func TestMTGFrontingAddressFollowsTheDomain(t *testing.T) {
	h := newHarness(t)
	h.setLookup("a.example.com", "10.0.0.1", "2001:db8::1", "203.0.113.80", "203.0.113.90")
	h.apply(h.mtgState(1, ""))
	h.pass()
	if cfg := h.engineConfig(1); !strings.Contains(cfg, `ip = "203.0.113.80"`) || !strings.Contains(cfg, "port = 443") {
		t.Errorf("config.toml names the wrong fronting address:\n%s", cfg)
	}
	h.pass()
	if n := h.lookupsOf("a.example.com"); n != 1 {
		t.Errorf("lookups = %d, want 1 (cached)", n)
	}

	// The answer rotates but still names the address in use: nothing rolls.
	h.setLookup("a.example.com", "203.0.113.90", "203.0.113.80")
	h.clock.Advance(frontingTTL + time.Second)
	h.docker.ResetCalls()
	h.pass()
	if n := h.lookupsOf("a.example.com"); n != 2 {
		t.Errorf("lookups = %d, want 2", n)
	}
	if n := len(h.creates("engine")); n != 0 {
		t.Errorf("%d engine creates for an answer that still names the address in use", n)
	}

	// The address is gone from the answer: generation 2 with the new one.
	h.setLookup("a.example.com", "203.0.113.90")
	h.clock.Advance(frontingTTL + time.Second)
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 2 {
		t.Fatalf("generation = %d, want 2 after the fronting address changed", rec.Generation)
	}
	if cfg := h.engineConfig(2); !strings.Contains(cfg, `ip = "203.0.113.90"`) {
		t.Errorf("config.toml of g2 names the wrong fronting address:\n%s", cfg)
	}

	// The resolver fails: the address in use stays, nothing is reported, and
	// a later answer with the same address rolls nothing.
	h.clearLookup("a.example.com")
	h.clock.Advance(frontingTTL + time.Second)
	h.docker.ResetCalls()
	h.pass()
	if ps := h.proxyStatus(proxyID); ps.GetReason() != "" || ps.GetInstanceGeneration() != 2 || ps.GetFailedEngine() != nodev1.Engine_ENGINE_UNSPECIFIED {
		t.Errorf("status after a failed lookup = %v, want g2 serving without a reason", ps)
	}
	h.setLookup("a.example.com", "203.0.113.90")
	h.clock.Advance(frontingTTL + time.Second)
	h.pass()
	if n := len(h.creates("engine")); n != 0 || len(h.eventsOf("render_failed")) != 0 {
		t.Errorf("%d engine creates and %d render_failed events around a resolver failure, want none", n, len(h.eventsOf("render_failed")))
	}

	// No allowed address: generation 2 keeps serving, the reason says why,
	// and the lookup is not repeated before the interval.
	h.setLookup("a.example.com", "127.0.0.1", "10.0.0.1")
	h.clock.Advance(frontingTTL + time.Second)
	h.pass()
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING || ps.GetInstanceGeneration() != 2 ||
		!strings.Contains(ps.GetReason(), "no address that the node may front to") || !strings.Contains(ps.GetReason(), "127.0.0.1 (loopback)") ||
		ps.GetFailedEngine() != nodev1.Engine_ENGINE_MTG || ps.GetFailedVersion() != mtg.DefaultVersion {
		t.Errorf("status = %v, want g2 serving with the reason and the failed instance", ps)
	}
	if n := len(h.eventsOf("render_failed")); n != 1 {
		t.Errorf("render_failed events = %d, want 1", n)
	}
	n := h.lookupsOf("a.example.com")
	h.pass()
	if h.lookupsOf("a.example.com") != n || len(h.eventsOf("render_failed")) != 1 {
		t.Errorf("a failed lookup was repeated at once, or reported twice")
	}

	// A domain that does not resolve at all, on a proxy that has nothing yet.
	st := h.mtgState(9, "")
	st.Proxies[0].Id, st.Proxies[0].Domain = "P9", "nowhere.example.com"
	h.apply(st)
	h.pass()
	if ps := h.proxyStatus("P9"); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || !strings.Contains(ps.GetReason(), "cannot resolve the proxy domain nowhere.example.com") ||
		ps.GetFailedEngine() != nodev1.Engine_ENGINE_MTG || ps.GetEngine() != nodev1.Engine_ENGINE_MTG {
		t.Errorf("status = %v, want failed with the resolver's reason", ps)
	}
	assertNoSecretsInEvents(t, h)
}

func TestFrontingHostIsPunycode(t *testing.T) {
	for in, want := range map[string]string{"a.example.com": "a.example.com", "a.example.com.": "a.example.com", "пример.example": "xn--e1afmkfd.example"} {
		got, err := frontingHost(in)
		if err != nil || got != want {
			t.Errorf("frontingHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := frontingHost(""); err == nil {
		t.Error("frontingHost(\"\") = nil, want an error")
	}
}

// The engine of a status is the serving instance's; the desired proxy's only
// while nothing serves (F3).
func TestProxyStatusEngineIsTheServingOnes(t *testing.T) {
	pr := &nodev1.Proxy{Engine: nodev1.Engine_ENGINE_MTG}
	serving := state.InstanceRecord{Generation: 3, Engine: "telemt", Version: "3.5.13"}
	if ps := proxyStatus("P", nodev1.ProxyPhase_PROXY_PHASE_SERVING, "", serving, pr); ps.GetEngine() != nodev1.Engine_ENGINE_TELEMT {
		t.Errorf("engine = %v, want the serving telemt", ps.GetEngine())
	}
	if ps := proxyStatus("P", nodev1.ProxyPhase_PROXY_PHASE_PENDING, "", state.InstanceRecord{}, pr); ps.GetEngine() != nodev1.Engine_ENGINE_MTG {
		t.Errorf("engine = %v, want the desired mtg while nothing serves", ps.GetEngine())
	}
	// The seeded status before the first pass says the same.
	r := &Reconciler{}
	rt := state.NewRuntime()
	rt.Instances["P"] = serving
	r.Seed(&nodev1.NodeState{Proxies: []*nodev1.Proxy{{Id: "P", Enabled: true, Engine: nodev1.Engine_ENGINE_MTG}}}, rt)
	if ps := r.Status().GetProxies()[0]; ps.GetEngine() != nodev1.Engine_ENGINE_TELEMT || ps.GetRunningVersion() != "3.5.13" {
		t.Errorf("seeded status = %v, want telemt 3.5.13", ps)
	}
}

// EgressReason (egress.member's cause, F3 of the real-server pass) is why an
// egress's instance does not start: a provider binary that is not on the node
// is named; one that serves has none.
func TestEgressReasonNamesAMissingArtifact(t *testing.T) {
	h := newHarness(t)
	st := h.providerState(1, uriEgress("nl", vless("vpn.example.com", 443, "a")))
	for i, a := range st.Artifacts {
		if a.GetEngine() == "xray" {
			missing := proto.Clone(a).(*nodev1.ArtifactRef)
			missing.Version, missing.Sha256 = "v26.9.9", strings.Repeat("ab", 32)
			st.Artifacts[i] = missing
		}
	}
	h.apply(st)
	h.pass()
	if got := h.r.EgressReason("nl"); !strings.HasPrefix(got, "artifact missing:") || !strings.Contains(got, "xray v26.9.9") {
		t.Errorf("EgressReason = %q, want the missing xray named", got)
	}
	h.apply(h.providerState(2, uriEgress("nl", vless("vpn.example.com", 443, "a"))))
	h.pass()
	if got := h.r.EgressReason("nl"); got != "" {
		t.Errorf("serving: EgressReason = %q", got)
	}
}

// The provider instances are reported: the serving version and generation,
// and after a version change that fails, the version that failed beside the
// one that serves; an egress that is no longer needed drains, and one that is
// gone has no status.
func TestEgressInstancesAreReported(t *testing.T) {
	h := newHarness(t)
	h.apply(h.providerState(1, uriEgress("nl", vless("vpn.example.com", 443, "a"))))
	h.pass()
	got := h.r.Status().GetEgressInstances()
	want := []*nodev1.EgressInstanceStatus{{EgressId: "nl", Provider: "xray", Version: "v26.3.27", Generation: 1, Phase: "serving"}}
	if !protoSliceEqual(got, want) {
		t.Errorf("egress_instances = %v, want %v", got, want)
	}

	// A new xray version whose generation does not become ready.
	h.xray.setReady(func(context.Context, providers.Instance) error { return errors.New("not ready") })
	st := h.providerState(2, uriEgress("nl", vless("vpn.example.com", 443, "a")))
	st.Artifacts = slices.DeleteFunc(st.Artifacts, func(a *nodev1.ArtifactRef) bool { return a.GetEngine() == "xray" })
	st.Artifacts = append(st.Artifacts, h.storeArtifact("xray", "v26.4.0", "xray"))
	h.apply(st)
	h.pass()
	got = h.r.Status().GetEgressInstances()
	if len(got) != 1 || got[0].GetPhase() != "serving" || got[0].GetVersion() != "v26.3.27" || got[0].GetGeneration() != 1 ||
		got[0].GetFailedVersion() != "v26.4.0" || got[0].GetReason() == "" || got[0].GetProvider() != "xray" {
		t.Errorf("egress_instances = %v, want generation 1 of v26.3.27 serving with failed_version v26.4.0", got)
	}
	if c := h.container("postern-egr-nl-g1"); c == nil || c.State != "running" {
		t.Errorf("g1 of the egress = %+v, want running", c)
	}

	// The egress is no longer taken by any chain: it drains, then goes.
	st = h.baseState(3)
	st.Egresses = append(st.Egresses, uriEgress("nl", vless("vpn.example.com", 443, "a")))
	h.apply(st)
	h.pass()
	got = h.r.Status().GetEgressInstances()
	if len(got) != 1 || got[0].GetPhase() != "draining" || got[0].GetGeneration() != 0 {
		t.Errorf("egress_instances = %v, want nl draining", got)
	}
	h.clock.Advance(egressDrainAfter + time.Second)
	h.apply(h.baseState(4))
	h.pass()
	if got := h.r.Status().GetEgressInstances(); len(got) != 0 {
		t.Errorf("egress_instances = %v, want none", got)
	}
}
