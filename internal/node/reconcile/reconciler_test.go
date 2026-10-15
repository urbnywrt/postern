package reconcile

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/node/state"
)

// The first pass on an empty node pulls the runner image, writes the edge
// config, creates the edge and waits for it, then starts the engine behind a
// SOCKS port, probes it, and routes the proxy's SNI to it.
func TestFirstPassCreatesEdgeAndEngine(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))

	var socksBeforeEngine []uint32
	h.docker.onCreate = func(spec dockerapi.ContainerSpec) {
		switch spec.Labels["postern.role"] {
		case "edge":
			// Spec 7: the configuration is on disk before the edge starts.
			data, err := os.ReadFile(h.paths.EdgeConfigPath(1))
			if err != nil {
				t.Errorf("edge created before its config was written: %v", err)
				return
			}
			cfg := &edgev1.EdgeConfig{}
			if err := protojson.Unmarshal(data, cfg); err != nil {
				t.Errorf("edge config: %v", err)
			}
			if cfg.GetGeneration() != 1 || len(cfg.GetListeners()) != 1 || len(cfg.GetTestListeners()) != 1 {
				t.Errorf("edge config at creation = %v", cfg)
			}
		case "engine":
			dir := filepath.Join(h.paths.InstancesDir(), "eng-01j9zzproxy0000000000000p1-g1")
			if _, err := os.Stat(filepath.Join(dir, "config.toml")); err != nil {
				t.Errorf("engine created before its config was written: %v", err)
			}
			e := h.fakeEdge(1)
			e.mu.Lock()
			if n := len(e.configs); n > 0 {
				socksBeforeEngine = socksPorts(e.configs[n-1])
			}
			e.mu.Unlock()
		}
	}
	h.pass()

	// The runner image is checked (and pulled) before anything is created.
	var order []string
	for _, c := range h.docker.Calls() {
		switch c.Method {
		case "ImageExists", "Pull":
			order = append(order, c.Method+" "+c.Target)
		case "Create":
			order = append(order, "Create "+c.Spec.Labels["postern.role"])
		}
	}
	wantOrder := []string{"ImageExists " + runnerImage, "Pull " + runnerImage, "Create edge", "Create engine"}
	if !slices.Equal(order, wantOrder) {
		t.Errorf("docker calls = %q, want %q", order, wantOrder)
	}

	// The edge container (spec 5.1, brief step 3).
	edges := h.creates("edge")
	if len(edges) != 1 {
		t.Fatalf("created %d edges, want 1", len(edges))
	}
	es := edges[0]
	wantEdge := dockerapi.ContainerSpec{
		Name:          "postern-edge-g1",
		Image:         runnerImage,
		User:          "0:0",
		NetworkMode:   "host",
		RestartPolicy: "unless-stopped",
		Entrypoint: []string{
			"/opt/postern/bin/postern-node", "edge",
			"--config", "/opt/postern/data/edge/config-g1.json",
			"--socket", "/opt/postern/data/run/edge-g1.sock",
		},
		Binds: []string{
			h.nodeBinary + ":/opt/postern/bin/postern-node:ro",
			h.paths.EdgeDir() + ":/opt/postern/data/edge",
			h.paths.RunDir() + ":/opt/postern/data/run",
			h.paths.CertsDir() + ":/opt/postern/data/certs:ro",
		},
		CapAdd:      []string{"NET_BIND_SERVICE"},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Labels: map[string]string{
			"postern.managed": "true", "postern.role": "edge", "postern.id": "edge", "postern.generation": "1",
		},
		ReadOnly:    true,
		Ulimits:     []dockerapi.Ulimit{{Name: "nofile", Soft: 1048576, Hard: 1048576}},
		LogMaxSize:  "10m",
		LogMaxFile:  3,
		StopTimeout: new(35), // on SIGTERM the edge drains for up to 30 s
	}
	if !specEqual(es, wantEdge) {
		t.Errorf("edge spec =\n%+v\nwant\n%+v", es, wantEdge)
	}
	if d := h.container("postern-edge-g1"); d == nil || d.State != "running" {
		t.Errorf("edge container = %+v, want running", d)
	}

	// The engine container and its files.
	eng := h.container(engName1)
	if eng == nil || eng.State != "running" {
		t.Fatalf("engine container = %+v, want running", eng)
	}
	for k, v := range map[string]string{"postern.managed": "true", "postern.role": "engine", "postern.id": proxyID, "postern.generation": "1"} {
		if eng.Labels[k] != v {
			t.Errorf("engine label %s = %q, want %q", k, eng.Labels[k], v)
		}
	}
	rt := h.runtime()
	rec, ok := rt.Instances[proxyID]
	if !ok || rec.Generation != 1 || rec.Hash == "" || rec.Version != "3.5.13" || rec.Engine != "telemt" {
		t.Fatalf("runtime instance = %+v", rec)
	}
	for role, port := range map[string]uint16{state.PortListen: rec.ListenPort, state.PortAPI: rec.APIPort, state.PortSocks: rec.SocksPort} {
		if port == 0 || rt.Ports[state.EnginePortKey(proxyID, 1, role)] != port {
			t.Errorf("%s port %d not recorded in %v", role, port, rt.Ports)
		}
	}
	if rec.APIToken == "" || !rec.ServingSince.Equal(h.clock.Now()) {
		t.Errorf("runtime instance = %+v", rec)
	}
	if rt.AppliedGeneration != 1 || rt.EdgeGeneration != 1 {
		t.Errorf("runtime generations = applied %d, edge %d; want 1, 1", rt.AppliedGeneration, rt.EdgeGeneration)
	}
	checkInstanceDir(t, filepath.Join(h.paths.InstancesDir(), "eng-01j9zzproxy0000000000000p1-g1"), rec)

	// The SOCKS port of the instance was in the edge before the engine started.
	if !slices.Contains(socksBeforeEngine, uint32(rec.SocksPort)) {
		t.Errorf("SOCKS ports before the engine was created = %v, want %d among them", socksBeforeEngine, rec.SocksPort)
	}

	// The probe went straight to the engine, with a PROXY header from 127.0.0.1:1.
	probes := h.prober.callList()
	if len(probes) != 1 {
		t.Fatalf("got %d probes, want 1", len(probes))
	}
	p := probes[0]
	if p.addr != addr(rec.ListenPort) || p.sni != "a.example.com" || hex.EncodeToString(p.secret) != secret1 ||
		p.src != netip.MustParseAddrPort("127.0.0.1:1") {
		t.Errorf("probe = %+v", p)
	}

	// The edge routes the SNI to the engine.
	cfg := h.fakeEdge(1).lastConfig(t)
	if cfg.GetGeneration() != 1 {
		t.Errorf("config generation = %d, want 1", cfg.GetGeneration())
	}
	if len(cfg.GetRoutes()) != 1 {
		t.Fatalf("routes = %v, want 1", cfg.GetRoutes())
	}
	route := cfg.GetRoutes()[0]
	wantRoute := &edgev1.Route{
		ListenerId: "L1", Sni: "a.example.com", ProxyId: proxyID, Kind: "engine",
		Backend: addr(rec.ListenPort), ProxyProtocol: true, Limits: &edgev1.EdgeLimits{Devices: 3},
	}
	if !proto.Equal(route, wantRoute) {
		t.Errorf("route = %v, want %v", route, wantRoute)
	}
	wantSocks := []*edgev1.SocksPort{{Port: uint32(rec.SocksPort), ProxyId: proxyID, DefaultChainId: "default"}}
	if !protoSliceEqual(cfg.GetSocks(), wantSocks) {
		t.Errorf("socks = %v, want %v", cfg.GetSocks(), wantSocks)
	}

	// Status and events.
	st := h.r.Status()
	if st.GetAppliedGeneration() != 1 {
		t.Errorf("status applied = %d, want 1", st.GetAppliedGeneration())
	}
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING || ps.GetInstanceGeneration() != 1 ||
		ps.GetRunningVersion() != "3.5.13" || ps.GetEngine() != nodev1.Engine_ENGINE_TELEMT {
		t.Errorf("proxy status = %v", ps)
	}
	for _, kind := range []string{"edge_started", "instance_starting", "instance_serving"} {
		if !slices.Contains(h.eventKinds(), kind) {
			t.Errorf("events %q lack %s", h.eventKinds(), kind)
		}
	}
	assertNoSecretsInEvents(t, h)
}

// A pass with nothing to change creates nothing and keeps the route.
func TestSecondPassIsANoop(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	h.docker.ResetCalls()
	h.pass()
	for _, c := range h.docker.Calls() {
		switch c.Method {
		case "Create", "Start", "Stop", "Remove", "Pull":
			t.Errorf("unexpected %s %s on a pass without changes", c.Method, c.Target)
		}
	}
	if got := len(h.prober.callList()); got != 1 {
		t.Errorf("probes = %d, want 1 (no new instance)", got)
	}
	rec := h.runtime().Instances[proxyID]
	if got := routeBackends(h.fakeEdge(1).lastConfig(t)); !slices.Equal(got, []string{proxyID + "->" + addr(rec.ListenPort)}) {
		t.Errorf("routes = %v", got)
	}
}

// The runner image is not pulled when it is there.
func TestImagePresentIsNotPulled(t *testing.T) {
	h := newHarness(t)
	h.docker.AddImage(runnerImage)
	h.apply(h.baseState(1))
	h.pass()
	for _, c := range h.docker.Calls() {
		if c.Method == "Pull" {
			t.Errorf("pulled %s although it was present", c.Target)
		}
	}
}

// A new secret needs a new engine generation: g2 starts beside g1, is probed
// with the new secret, takes the route, and g1 drains (restart policy "no")
// until it has no connections left.
func TestSecretChangeBlueGreen(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	old := h.runtime().Instances[proxyID]
	h.fakeEdge(1).setActive(proxyID, old.ListenPort, 2)

	st := h.baseState(2)
	st.Proxies[0].Secret = secret2
	h.apply(st)
	h.pass()

	if c := h.container(engName2); c == nil || c.State != "running" {
		t.Fatalf("g2 = %+v, want running", c)
	}
	g1 := h.container(engName1)
	if g1 == nil || g1.State != "running" || g1.RestartPolicy != "no" {
		t.Fatalf("g1 = %+v, want running with restart policy no", g1)
	}
	rt := h.runtime()
	rec := rt.Instances[proxyID]
	if rec.Generation != 2 || rec.Hash == old.Hash || rec.ListenPort == old.ListenPort || rec.SocksPort == old.SocksPort {
		t.Fatalf("runtime instance = %+v (old %+v)", rec, old)
	}
	if len(rec.Draining) != 1 || rec.Draining[0].Generation != 1 || rec.Draining[0].ContainerName != engName1 ||
		rec.Draining[0].ListenPort != old.ListenPort || !rec.Draining[0].Since.Equal(h.clock.Now()) {
		t.Errorf("draining = %+v", rec.Draining)
	}
	probes := h.prober.callList()
	if last := probes[len(probes)-1]; hex.EncodeToString(last.secret) != secret2 || last.addr != addr(rec.ListenPort) {
		t.Errorf("last probe = %+v, want the new secret on g2", last)
	}
	cfg := h.fakeEdge(1).lastConfig(t)
	if got := routeBackends(cfg); !slices.Equal(got, []string{proxyID + "->" + addr(rec.ListenPort)}) {
		t.Errorf("routes = %v, want g2", got)
	}
	// The draining generation keeps its way out until it is gone.
	if got := socksPorts(cfg); !slices.Contains(got, uint32(old.SocksPort)) || !slices.Contains(got, uint32(rec.SocksPort)) {
		t.Errorf("socks ports = %v, want both generations", got)
	}
	if ps := h.proxyStatus(proxyID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING || ps.GetInstanceGeneration() != 2 {
		t.Errorf("status = %v", ps)
	}

	// No connections left on g1: it is stopped, removed and forgotten.
	h.fakeEdge(1).setActive(proxyID, old.ListenPort, 0)
	h.pass()
	if c := h.container(engName1); c != nil {
		t.Errorf("g1 still exists: %+v", c)
	}
	rt = h.runtime()
	if d := rt.Instances[proxyID].Draining; len(d) != 0 {
		t.Errorf("draining = %+v, want none", d)
	}
	for k := range rt.Ports {
		if strings.HasPrefix(k, state.EnginePortPrefix(proxyID, 1)) {
			t.Errorf("port %s of g1 still allocated", k)
		}
	}
	if _, err := os.Stat(filepath.Join(h.paths.InstancesDir(), "eng-01j9zzproxy0000000000000p1-g1")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("instance dir of g1 still there: %v", err)
	}
	if got := socksPorts(h.fakeEdge(1).lastConfig(t)); slices.Contains(got, uint32(old.SocksPort)) {
		t.Errorf("socks ports = %v, still with g1's", got)
	}
}

// A new generation that fails the probe is removed; the old one keeps the
// route, an upgrade_aborted event is sent, and the attempt is not repeated
// before the retry delay.
func TestProbeFailureKeepsOldGeneration(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	old := h.runtime().Instances[proxyID]
	h.prober.setFail(failSecret(secret2))

	st := h.baseState(2)
	st.Proxies[0].Secret = secret2
	h.apply(st)
	h.pass()

	if c := h.container(engName2); c != nil {
		t.Errorf("g2 still exists: %+v", c)
	}
	g1 := h.container(engName1)
	if g1 == nil || g1.State != "running" || g1.RestartPolicy != "unless-stopped" {
		t.Errorf("g1 = %+v, want running with unless-stopped", g1)
	}
	rt := h.runtime()
	rec := rt.Instances[proxyID]
	if rec.Generation != 1 || rec.Hash != old.Hash || len(rec.Draining) != 0 {
		t.Errorf("runtime instance = %+v, want g1 untouched", rec)
	}
	for k := range rt.Ports {
		if strings.HasPrefix(k, state.EnginePortPrefix(proxyID, 2)) {
			t.Errorf("port %s of the aborted g2 still allocated", k)
		}
	}
	if _, err := os.Stat(filepath.Join(h.paths.InstancesDir(), "eng-01j9zzproxy0000000000000p1-g2")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("instance dir of g2 still there: %v", err)
	}
	cfg := h.fakeEdge(1).lastConfig(t)
	if got := routeBackends(cfg); !slices.Equal(got, []string{proxyID + "->" + addr(old.ListenPort)}) {
		t.Errorf("routes = %v, want g1", got)
	}
	if got := socksPorts(cfg); !slices.Equal(got, []uint32{uint32(old.SocksPort)}) {
		t.Errorf("socks ports = %v, want g1's only", got)
	}
	aborted := h.eventsOf("upgrade_aborted")
	if len(aborted) != 1 || aborted[0].GetProxyId() != proxyID {
		t.Fatalf("upgrade_aborted events = %v", aborted)
	}
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING || ps.GetInstanceGeneration() != 1 ||
		!strings.Contains(ps.GetReason(), "upgrade aborted") {
		t.Errorf("status = %v, want serving g1 with the reason", ps)
	}
	if st := h.r.Status(); st.GetAppliedGeneration() != 2 {
		t.Errorf("applied = %d, want 2 (the pass went through)", st.GetAppliedGeneration())
	}
	assertNoSecretsInEvents(t, h)

	// Within the retry delay nothing is attempted again.
	h.docker.ResetCalls()
	h.pass()
	if n := len(h.creates("engine")); n != 0 {
		t.Errorf("retried at once: %d creates", n)
	}
	if n := len(h.eventsOf("upgrade_aborted")); n != 1 {
		t.Errorf("upgrade_aborted events = %d, want still 1", n)
	}
	// After it, the attempt is made again (and the probe now passes).
	h.prober.setFail(nil)
	h.clock.Advance(defaultRetryAfter)
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 3 {
		t.Errorf("after the retry delay the instance is g%d, want g3", rec.Generation)
	}
}

// An engine that never becomes ready fails its first start: the container is
// removed and the proxy is FAILED.
func TestReadyTimeoutFailsNewProxy(t *testing.T) {
	h := newHarness(t)
	h.r.readyTimeout = 50 * time.Millisecond
	h.driver.setReady(func(context.Context, engines.Instance) error { return errors.New("telemt is not ready (HTTP 503)") })
	h.apply(h.baseState(1))
	h.pass()

	if c := h.container(engName1); c != nil {
		t.Errorf("engine still exists: %+v", c)
	}
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || !strings.Contains(ps.GetReason(), "not ready") {
		t.Errorf("status = %v", ps)
	}
	if n := len(h.eventsOf("instance_failed")); n != 1 {
		t.Errorf("instance_failed events = %d, want 1", n)
	}
	if len(h.prober.callList()) != 0 {
		t.Error("probed an engine that was not ready")
	}
	if got := routeBackends(h.fakeEdge(1).lastConfig(t)); len(got) != 0 {
		t.Errorf("routes = %v, want none", got)
	}
	rt := h.runtime()
	if rec := rt.Instances[proxyID]; rec.Generation != 0 || len(rec.Draining) != 0 {
		t.Errorf("runtime instance = %+v, want nothing serving or draining", rec)
	}
	for k := range rt.Ports {
		if strings.HasPrefix(k, "eng:") {
			t.Errorf("port %s still allocated", k)
		}
	}
}

// An engine container that exits while the reconciler waits for it fails at
// once, with its exit code, instead of after the whole readiness timeout.
func TestEngineExitDuringStartFailsFast(t *testing.T) {
	h := newHarness(t)
	h.r.readyTimeout = time.Minute
	h.driver.setReady(func(_ context.Context, in engines.Instance) error {
		_ = h.docker.Exit(engName1, 1)
		return errors.New("connection refused")
	})
	h.apply(h.baseState(1))
	start := time.Now()
	h.pass()
	if time.Since(start) > 10*time.Second {
		t.Errorf("the pass took %v", time.Since(start))
	}
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || !strings.Contains(ps.GetReason(), "exited") {
		t.Errorf("status = %v", ps)
	}
	if c := h.container(engName1); c != nil {
		t.Errorf("engine still exists: %+v", c)
	}
}

// Disabling a proxy removes its route at once and keeps its engine running.
func TestDisableRemovesRouteKeepsContainer(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	rec := h.runtime().Instances[proxyID]

	st := h.baseState(2)
	st.Proxies[0].Enabled = false
	h.apply(st)
	h.pass()

	cfg := h.fakeEdge(1).lastConfig(t)
	if len(cfg.GetRoutes()) != 0 {
		t.Errorf("routes = %v, want none", cfg.GetRoutes())
	}
	if !slices.Contains(socksPorts(cfg), uint32(rec.SocksPort)) {
		t.Errorf("socks ports = %v, want the paused instance's", socksPorts(cfg))
	}
	if c := h.container(engName1); c == nil || c.State != "running" || c.RestartPolicy != "unless-stopped" {
		t.Errorf("engine = %+v, want running", c)
	}
	if ps := h.proxyStatus(proxyID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_PAUSED {
		t.Errorf("status = %v, want paused", ps)
	}

	// Enabling it again brings the route back without a new instance.
	h.apply(h.baseState(3))
	h.pass()
	if got := routeBackends(h.fakeEdge(1).lastConfig(t)); !slices.Equal(got, []string{proxyID + "->" + addr(rec.ListenPort)}) {
		t.Errorf("routes = %v", got)
	}
	if n := len(h.creates("engine")); n != 1 {
		t.Errorf("engine creates = %d, want 1", n)
	}
}

// Deleting a proxy removes its route, then its engine drains: it lives on with
// its connections until DrainAfter is over.
func TestDeleteDrainsAfterDrainAfter(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	rec := h.runtime().Instances[proxyID]
	h.fakeEdge(1).setActive(proxyID, rec.ListenPort, 1)

	st := h.baseState(2)
	st.Proxies = nil
	h.apply(st)
	h.pass()

	if routes := h.fakeEdge(1).lastConfig(t).GetRoutes(); len(routes) != 0 {
		t.Errorf("routes = %v, want none", routes)
	}
	c := h.container(engName1)
	if c == nil || c.State != "running" || c.RestartPolicy != "no" {
		t.Fatalf("engine = %+v, want running and draining", c)
	}
	rt := h.runtime()
	if r := rt.Instances[proxyID]; r.Generation != 0 || len(r.Draining) != 1 {
		t.Errorf("runtime instance = %+v, want only a draining g1", r)
	}
	if ps := h.proxyStatus(proxyID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_DRAINING {
		t.Errorf("status = %v, want draining", ps)
	}

	h.clock.Advance(30*time.Minute - time.Second)
	h.pass()
	if h.container(engName1) == nil {
		t.Fatal("removed before DrainAfter")
	}

	h.clock.Advance(2 * time.Second)
	h.pass()
	if c := h.container(engName1); c != nil {
		t.Errorf("engine = %+v, want removed after DrainAfter", c)
	}
	rt = h.runtime()
	if _, ok := rt.Instances[proxyID]; ok {
		t.Errorf("runtime still has the proxy: %+v", rt.Instances)
	}
	for k := range rt.Ports {
		if strings.HasPrefix(k, "eng:") {
			t.Errorf("port %s still allocated", k)
		}
	}
	if ps := h.proxyStatus(proxyID); ps != nil {
		t.Errorf("status of a removed proxy = %v", ps)
	}
	if n := len(h.eventsOf("instance_removed")); n != 1 {
		t.Errorf("instance_removed events = %d, want 1", n)
	}
	// The stop came before the removal.
	var seq []string
	for _, call := range h.docker.Calls() {
		if call.Target == engName1 && (call.Method == "Stop" || call.Method == "Remove") {
			seq = append(seq, call.Method)
		}
	}
	if !slices.Equal(seq, []string{"Stop", "Remove"}) {
		t.Errorf("calls on g1 = %v, want Stop, Remove", seq)
	}
}

// When the edge's counters cannot be read, nobody knows that a draining
// generation is idle: it stays until DrainAfter.
func TestDrainWaitsWhenCountersUnknown(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	e := h.fakeEdge(1)
	e.mu.Lock()
	e.snapErr = errors.New("edge Snapshot: unavailable")
	e.mu.Unlock()

	st := h.baseState(2)
	st.Proxies[0].Secret = secret2
	h.apply(st)
	h.pass()
	if h.container(engName1) == nil {
		t.Fatal("g1 removed although its connections are unknown")
	}
	h.clock.Advance(30 * time.Minute)
	h.pass()
	if c := h.container(engName1); c != nil {
		t.Errorf("g1 = %+v, want removed after DrainAfter", c)
	}
}

// A proxy that arrives disabled gets no instance until it is enabled.
func TestNewDisabledProxyIsNotStarted(t *testing.T) {
	h := newHarness(t)
	st := h.baseState(1)
	st.Proxies[0].Enabled = false
	h.apply(st)
	h.pass()
	if n := len(h.creates("engine")); n != 0 {
		t.Errorf("created %d engines for a disabled proxy", n)
	}
	if ps := h.proxyStatus(proxyID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_PAUSED {
		t.Errorf("status = %v, want paused", ps)
	}
}

// An edge container that an earlier agent created but did not start is
// started (and waited for), not replaced.
func TestCreatedEdgeIsStarted(t *testing.T) {
	h := newHarness(t)
	h.addContainer("postern-edge-g4", "edge", "edge", 4, false)
	h.apply(h.baseState(1))
	h.docker.ResetCalls()

	// Started, it is waited for like a new one.
	h.r.edgeStartTimeout = 50 * time.Millisecond
	e := h.fakeEdge(4)
	e.mu.Lock()
	e.healthErr = errors.New("dial unix: no such file")
	e.mu.Unlock()
	if err := h.r.reconcileOnce(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "does not answer") {
		t.Fatalf("pass = %v, want an edge health error", err)
	}
	// Back to a created container, as the agent found it.
	if err := h.docker.Remove(context.Background(), "postern-edge-g4", true); err != nil {
		t.Fatal(err)
	}
	h.addContainer("postern-edge-g4", "edge", "edge", 4, false)
	h.docker.ResetCalls()
	e.mu.Lock()
	e.healthErr = nil
	e.mu.Unlock()

	h.pass()
	if n := len(h.creates("edge")); n != 0 {
		t.Errorf("created %d edges, want none", n)
	}
	if c := h.container("postern-edge-g4"); c == nil || c.State != "running" {
		t.Errorf("g4 = %+v, want running", c)
	}
	if h.fakeEdge(4).setCount() == 0 {
		t.Error("g4 got no config")
	}
}

// A new edge that never answers fails the pass before any engine starts.
func TestEdgeNotAnsweringFailsThePass(t *testing.T) {
	h := newHarness(t)
	h.r.edgeStartTimeout = 50 * time.Millisecond
	e := h.fakeEdge(1)
	e.mu.Lock()
	e.healthErr = errors.New("dial unix: no such file")
	e.mu.Unlock()
	h.apply(h.baseState(1))
	err := h.r.reconcileOnce(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "does not answer") {
		t.Fatalf("pass = %v, want an edge health error", err)
	}
	if n := len(h.creates("engine")); n != 0 {
		t.Errorf("created %d engines without an edge", n)
	}
	// The next pass waits for the same edge instead of making another one.
	e.mu.Lock()
	e.healthErr = nil
	e.mu.Unlock()
	h.pass()
	if n := len(h.creates("edge")); n != 1 {
		t.Errorf("created %d edges, want 1", n)
	}
}

// A serving engine container that was stopped is started again.
func TestStoppedEngineIsStartedAgain(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	if err := h.docker.Stop(context.Background(), engName1, 0); err != nil {
		t.Fatal(err)
	}
	h.pass()
	if c := h.container(engName1); c == nil || c.State != "running" {
		t.Errorf("g1 = %+v, want running again", c)
	}
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 1 {
		t.Errorf("instance = g%d, want g1 kept", rec.Generation)
	}
	if n := len(h.eventsOf("instance_restarted")); n != 1 {
		t.Errorf("instance_restarted events = %d, want 1", n)
	}
}

// What a crash can leave behind is tidied up: ports of no instance, instance
// directories of no instance, and the test listener of a removed listener.
func TestLeftoversAreTidied(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	rt := h.runtime()
	rt.Ports[state.EnginePortKey(proxyID, 7, state.PortListen)] = 20077
	rt.Ports[state.TestListenerPortKey("gone")] = 40077
	if err := h.store.SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(h.paths.InstancesDir(), "eng-01j9zzproxy0000000000000p1-g7")
	other := filepath.Join(h.paths.InstancesDir(), "something-else")
	// The directory of an egress that is neither desired nor recorded.
	staleEgress := filepath.Join(h.paths.InstancesDir(), "egr-gone", "g3")
	for _, dir := range []string{stale, other, staleEgress} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	h.apply(h.baseState(2))
	h.pass()
	rt = h.runtime()
	for _, key := range []string{state.EnginePortKey(proxyID, 7, state.PortListen), state.TestListenerPortKey("gone")} {
		if _, ok := rt.Ports[key]; ok {
			t.Errorf("port %s still allocated", key)
		}
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale instance dir still there: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(staleEgress)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the directory of an unknown egress is still there: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("a directory that is not an instance's was touched: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.paths.InstancesDir(), "eng-01j9zzproxy0000000000000p1-g1")); err != nil {
		t.Errorf("the serving instance's directory is gone: %v", err)
	}
}

// After a restart of the agent, the containers found by their labels are
// adopted: nothing is created or removed.
func TestRestartAdoptsContainers(t *testing.T) {
	h := newHarness(t)
	st := h.baseState(1)
	st.Proxies = append(st.Proxies, &nodev1.Proxy{
		Id: "P2", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Enabled: true,
		Secret: secret2, Domain: "b.example.com", Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
	})
	h.apply(st)
	h.pass()
	before := h.runtime()

	h.r = h.newReconciler() // a new agent process: nothing in memory
	h.docker.ResetCalls()
	h.pass()

	for _, c := range h.docker.Calls() {
		switch c.Method {
		case "Create", "Remove", "Stop", "Start":
			t.Errorf("unexpected %s %s after a restart", c.Method, c.Target)
		}
	}
	after := h.runtime()
	if len(after.Instances) != 2 || after.Instances[proxyID].Generation != before.Instances[proxyID].Generation ||
		after.Instances["P2"].Generation != before.Instances["P2"].Generation {
		t.Errorf("runtime after restart = %+v, before %+v", after.Instances, before.Instances)
	}
	if got := routeBackends(h.fakeEdge(1).lastConfig(t)); len(got) != 2 {
		t.Errorf("routes = %v, want both proxies", got)
	}
	if ps := h.proxyStatus("P2"); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
		t.Errorf("status = %v", ps)
	}
}

// An engine container that the runtime does not know is removed.
func TestOrphanEngineContainerRemoved(t *testing.T) {
	h := newHarness(t)
	h.addContainer("postern-eng-ghost-g7", "engine", "GHOST", 7, true)
	h.apply(h.baseState(1))
	h.pass()
	if c := h.container("postern-eng-ghost-g7"); c != nil {
		t.Errorf("orphan still exists: %+v", c)
	}
	if n := len(h.eventsOf("orphan_removed")); n != 1 {
		t.Errorf("orphan_removed events = %d, want 1", n)
	}
	// Containers of other roles are not touched.
	h.addContainer("postern-agent", "agent", "agent", 0, true)
	h.pass()
	if c := h.container("postern-agent"); c == nil {
		t.Error("the agent container was removed")
	}
}

// The sysctl helper of the node image's bootstrap (managed, role helper, no
// generation) is not the reconciler's: the inventory skips it, and no pass
// stops, removes or adopts it.
func TestHelperContainerIsIgnored(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, c := range []struct {
		name    string
		running bool
	}{{"postern-sysctl-0a1b2c3d", true}, {"postern-sysctl-deadbeef", false}} {
		if _, err := h.docker.Fake.Create(ctx, dockerapi.ContainerSpec{
			Name: c.name, Image: runnerImage, NetworkMode: "host", Privileged: true,
			Labels: map[string]string{"postern.managed": "true", "postern.role": "helper"},
		}); err != nil {
			t.Fatal(err)
		}
		if c.running {
			if err := h.docker.Start(ctx, c.name); err != nil {
				t.Fatal(err)
			}
		}
	}
	h.apply(h.baseState(1))
	h.docker.ResetCalls()
	h.pass()
	h.pass()
	for _, c := range h.docker.Calls() {
		if strings.HasPrefix(c.Target, "postern-sysctl-") && c.Method != "Inspect" {
			t.Errorf("the reconciler called %s on the helper %s", c.Method, c.Target)
		}
	}
	if c := h.container("postern-sysctl-0a1b2c3d"); c == nil || c.State != "running" {
		t.Errorf("the running helper = %+v", c)
	}
	if c := h.container("postern-sysctl-deadbeef"); c == nil {
		t.Error("the exited helper was removed")
	}
	if n := len(h.eventsOf("orphan_removed")); n != 0 {
		t.Errorf("orphan_removed events = %d", n)
	}
	for id := range h.runtime().Instances {
		if strings.Contains(id, "sysctl") {
			t.Errorf("the helper was adopted as %s", id)
		}
	}
}

// A serving instance whose container disappeared is started again as a new
// generation.
func TestMissingServingContainerIsRecreated(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	if err := h.docker.Remove(context.Background(), engName1, true); err != nil {
		t.Fatal(err)
	}
	h.pass()
	rec := h.runtime().Instances[proxyID]
	if rec.Generation != 2 {
		t.Fatalf("instance = g%d, want g2", rec.Generation)
	}
	if c := h.container(engName2); c == nil || c.State != "running" {
		t.Errorf("g2 = %+v", c)
	}
	if n := len(h.eventsOf("instance_missing")); n != 1 {
		t.Errorf("instance_missing events = %d, want 1", n)
	}
	for k := range h.runtime().Ports {
		if strings.HasPrefix(k, state.EnginePortPrefix(proxyID, 1)) {
			t.Errorf("port %s of the vanished g1 still allocated", k)
		}
	}
}

// With two running edge generations the older one drains: restart policy
// "no", Drain over its control socket, and removal once it has exited.
func TestTwoEdgeGenerationsOlderDrained(t *testing.T) {
	h := newHarness(t)
	h.addContainer("postern-edge-g1", "edge", "edge", 1, true)
	h.addContainer("postern-edge-g2", "edge", "edge", 2, true)
	if err := os.MkdirAll(h.paths.EdgeDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.paths.EdgeConfigPath(1), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.apply(h.baseState(1))
	h.docker.ResetCalls()
	h.pass()

	if n := len(h.creates("edge")); n != 0 {
		t.Errorf("created %d edges, want none", n)
	}
	g1 := h.container("postern-edge-g1")
	if g1 == nil || g1.RestartPolicy != "no" {
		t.Errorf("g1 = %+v, want restart policy no", g1)
	}
	if got := h.fakeEdge(1).drainCalls(); !slices.Equal(got, []uint32{3600}) {
		t.Errorf("Drain calls on g1 = %v, want [3600]", got)
	}
	if h.fakeEdge(2).setCount() == 0 {
		t.Error("the newest edge got no config")
	}
	if h.fakeEdge(1).setCount() != 0 {
		t.Error("the draining edge got a config")
	}
	if rt := h.runtime(); rt.EdgeGeneration != 2 {
		t.Errorf("edge generation = %d, want 2", rt.EdgeGeneration)
	}

	// Drain is asked once; the old edge exits by itself and is then removed.
	h.pass()
	if got := h.fakeEdge(1).drainCalls(); len(got) != 1 {
		t.Errorf("Drain calls = %v, want one", got)
	}
	if err := h.docker.Exit("postern-edge-g1", 0); err != nil {
		t.Fatal(err)
	}
	h.pass()
	if c := h.container("postern-edge-g1"); c != nil {
		t.Errorf("g1 = %+v, want removed", c)
	}
	if _, err := os.Stat(h.paths.EdgeConfigPath(1)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config-g1.json still there: %v", err)
	}
	if c := h.container("postern-edge-g2"); c == nil || c.State != "running" {
		t.Errorf("g2 = %+v, want running", c)
	}
}

// An old edge that does not exit after the drain time is stopped and removed.
func TestDrainingEdgeRemovedAfterDrainLimit(t *testing.T) {
	h := newHarness(t)
	h.addContainer("postern-edge-g1", "edge", "edge", 1, true)
	h.addContainer("postern-edge-g2", "edge", "edge", 2, true)
	h.apply(h.baseState(1))
	h.pass()
	h.clock.Advance(time.Hour)
	h.pass()
	if h.container("postern-edge-g1") == nil {
		t.Fatal("removed before the drain limit")
	}
	h.clock.Advance(10 * time.Minute)
	h.pass()
	if c := h.container("postern-edge-g1"); c != nil {
		t.Errorf("g1 = %+v, want removed", c)
	}
}

// When the edge of the recorded generation is gone, a new generation is made;
// generation numbers are never reused.
func TestStoppedEdgeIsReplacedByNewGeneration(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	if err := h.docker.Stop(context.Background(), "postern-edge-g1", 0); err != nil {
		t.Fatal(err)
	}
	h.pass()
	if c := h.container("postern-edge-g2"); c == nil || c.State != "running" {
		t.Fatalf("g2 = %+v, want running", c)
	}
	if c := h.container("postern-edge-g1"); c != nil {
		t.Errorf("g1 = %+v, want removed", c)
	}
	rec := h.runtime().Instances[proxyID]
	if got := routeBackends(h.fakeEdge(2).lastConfig(t)); !slices.Equal(got, []string{proxyID + "->" + addr(rec.ListenPort)}) {
		t.Errorf("routes of g2 = %v", got)
	}
	// The config of g2 written before it started already routes the proxy.
	data, err := os.ReadFile(h.paths.EdgeConfigPath(2))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(addr(rec.ListenPort))) {
		t.Errorf("config-g2.json does not route to the engine:\n%s", data)
	}
}

// The edge holds CAP_NET_RAW only while a member of a chain is tied to an
// interface (SO_BINDTODEVICE needs it on a kernel older than 5.7). The
// capabilities of a container are fixed when it is created, so a change either
// way is a new edge generation, and the old one drains.
func TestEdgeHasNetRawOnlyWhileAMemberIsTiedToAnInterface(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	if edges := h.creates("edge"); len(edges) != 1 || !slices.Equal(edges[0].CapAdd, []string{"NET_BIND_SERVICE"}) {
		t.Fatalf("edges created: %+v, want g1 with NET_BIND_SERVICE only", edges)
	}

	// The direct egress of the default chain goes out through wg0.
	st := h.baseState(2)
	st.Egresses[0].ParamsJson = `{"interface":"wg0"}`
	h.apply(st)
	h.pass()
	edges := h.creates("edge")
	if len(edges) != 2 || edges[1].Name != "postern-edge-g2" || !slices.Equal(edges[1].CapAdd, []string{"NET_BIND_SERVICE", "NET_RAW"}) {
		t.Fatalf("edges created: %+v, want g2 with NET_RAW", edges)
	}
	if g1 := h.container("postern-edge-g1"); g1 == nil || g1.RestartPolicy != "no" {
		t.Errorf("g1 = %+v, want it draining (restart policy no)", g1)
	}
	if got := h.fakeEdge(1).drainCalls(); len(got) != 1 {
		t.Errorf("Drain calls on g1 = %v, want one", got)
	}
	if rt := h.runtime(); rt.EdgeGeneration != 2 {
		t.Errorf("edge generation = %d, want 2", rt.EdgeGeneration)
	}
	if cfg := h.fakeEdge(2).lastConfig(t); cfg.GetChains()[0].GetMembers()[0].GetBindDevice() != "wg0" {
		t.Errorf("g2 got the chains %v", cfg.GetChains())
	}

	// Nothing changes: no new generation, also for an agent that starts again.
	h.pass()
	h.r = h.newReconciler()
	h.pass()
	if n := len(h.creates("edge")); n != 2 {
		t.Fatalf("%d edges created, want still 2", n)
	}

	// The interface goes, and the capability with it.
	h.apply(h.baseState(3))
	h.pass()
	edges = h.creates("edge")
	if len(edges) != 3 || edges[2].Name != "postern-edge-g3" || !slices.Equal(edges[2].CapAdd, []string{"NET_BIND_SERVICE"}) {
		t.Fatalf("edges created: %+v, want g3 without NET_RAW", edges)
	}
	h.pass()
	if n := len(h.creates("edge")); n != 3 {
		t.Errorf("%d edges created, want still 3", n)
	}
}

// An edge that an older agent made (without CAP_NET_RAW, which no agent gave
// before) is replaced when a member needs the capability, and kept when none
// does.
func TestAdoptedEdgeGetsNetRawByANewGeneration(t *testing.T) {
	h := newHarness(t)
	h.addContainer("postern-edge-g4", "edge", "edge", 4, true)
	h.docker.ResetCalls()
	h.apply(h.baseState(1))
	h.pass()
	if n := len(h.creates("edge")); n != 0 {
		t.Fatalf("%d edges created next to an adopted one that is fine", n)
	}

	st := h.baseState(2)
	st.Egresses[0].ParamsJson = `{"interface":"tun0"}`
	h.apply(st)
	h.pass()
	if edges := h.creates("edge"); len(edges) != 1 || edges[0].Name != "postern-edge-g5" || !slices.Contains(edges[0].CapAdd, "NET_RAW") {
		t.Errorf("edges created: %+v, want g5 with NET_RAW", edges)
	}
}

// A proxy whose artifact the node does not have fails with "artifact missing";
// the edge is still set up.
func TestArtifactMissing(t *testing.T) {
	h := newHarness(t)
	st := h.baseState(1)
	st.Proxies[0].EngineVersion = "9.9.9"
	h.apply(st)
	h.pass()

	if n := len(h.creates("engine")); n != 0 {
		t.Errorf("created %d engines, want none", n)
	}
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || !strings.Contains(ps.GetReason(), "artifact missing") {
		t.Errorf("status = %v", ps)
	}
	ev := h.eventsOf("artifact_missing")
	if len(ev) != 1 || ev[0].GetProxyId() != proxyID {
		t.Errorf("artifact_missing events = %v", ev)
	}
	if h.container("postern-edge-g1") == nil {
		t.Error("no edge")
	}
	// The event is not repeated on every pass.
	h.pass()
	if n := len(h.eventsOf("artifact_missing")); n != 1 {
		t.Errorf("artifact_missing events = %d, want 1", n)
	}
}

// A serving instance whose artifact disappeared from the node keeps serving,
// with a warning: its container could not be started again.
func TestArtifactGoneUnderServingInstance(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	if err := os.RemoveAll(filepath.Join(h.paths.ArtifactsDir(), "telemt")); err != nil {
		t.Fatal(err)
	}
	h.pass()
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING || !strings.Contains(ps.GetReason(), "artifact missing") {
		t.Errorf("status = %v, want serving with the warning", ps)
	}
	ev := h.eventsOf("artifact_missing")
	if len(ev) != 1 || ev[0].GetSeverity() != "warning" {
		t.Errorf("artifact_missing events = %v, want one warning", ev)
	}
	if c := h.container(engName1); c == nil || c.State != "running" {
		t.Errorf("g1 = %+v, want running", c)
	}
}

// The status carries the egress health the current edge reports, with the
// time of the last check of each member.
func TestStatusCarriesEgressHealth(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	e := h.fakeEdge(1)
	e.mu.Lock()
	e.health = []*edgev1.MemberHealth{{ChainId: "default", MemberKey: "direct", Status: "up", LatencyMs: 42, ExitIp: "203.0.113.9", CheckedUnix: 1759650000}}
	e.mu.Unlock()
	h.pass()
	got := h.r.Status().GetEgress()
	want := []*nodev1.EgressMemberHealth{{ChainId: "default", MemberKey: "direct", Status: "up", LatencyMs: 42, ExitIp: "203.0.113.9", CheckedUnix: 1759650000}}
	if !protoSliceEqual(got, want) {
		t.Errorf("egress health = %v, want %v", got, want)
	}
}

// The engine overrides are part of the rendered config, so a change of them makes
// a new generation of the engine, like any other change of the config does; the
// same overrides in another order make the same config, and do not.
func TestEngineOverridesChangeIsBlueGreen(t *testing.T) {
	h := newHarness(t)
	configOf := func(gen int) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(h.paths.InstancesDir(), "eng-01j9zzproxy0000000000000p1-g"+strconv.Itoa(gen), "config.toml"))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	st := h.baseState(1)
	st.Proxies[0].EngineOverridesJson = `{"fast_mode":false,"tg_connect":10,"tls_emulation":false}`
	h.apply(st)
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 1 {
		t.Fatalf("instance = g%d, want g1", rec.Generation)
	}
	for _, want := range []string{"fast_mode = false\n", "tg_connect = 10\n", "tls_emulation = false\n"} {
		if cfg := configOf(1); !strings.Contains(cfg, want) {
			t.Errorf("config of g1 lacks %q:\n%s", want, cfg)
		}
	}

	st = h.baseState(2)
	st.Proxies[0].EngineOverridesJson = `{"tls_emulation":false,"tg_connect":10,"fast_mode":false}`
	h.apply(st)
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 1 {
		t.Errorf("the same overrides in another order: instance = g%d, want g1", rec.Generation)
	}

	st = h.baseState(3)
	st.Proxies[0].EngineOverridesJson = `{"fast_mode":false,"tg_connect":20,"tls_emulation":false}`
	h.apply(st)
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 2 {
		t.Fatalf("a changed override: instance = g%d, want g2", rec.Generation)
	}
	if cfg := configOf(2); !strings.Contains(cfg, "tg_connect = 20\n") {
		t.Errorf("config of g2 lacks the new value:\n%s", cfg)
	}
}

// A state with an override that is not on the whitelist is not applied, as a
// whole, whatever else it changes; the node says why.
func TestEngineOverridesThatAreNotOnTheWhitelistAreNotApplied(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	st := h.baseState(2)
	st.Proxies[0].Limits = &nodev1.Limits{Devices: 9}
	st.Proxies[0].EngineOverridesJson = `{"log_level":"debug"}`
	h.apply(st)
	err := h.r.reconcileOnce(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "owned by Postern") {
		t.Fatalf("pass = %v, want a validation error that says the key is owned by Postern", err)
	}
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 1 {
		t.Errorf("instance = g%d, want g1", rec.Generation)
	}
}

// Limits and egress chains live in the edge: changing them needs no new
// engine generation.
func TestEdgeOnlyChangesKeepTheInstance(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	st := h.baseState(2)
	st.Proxies[0].Limits = &nodev1.Limits{Devices: 9, ConnsTotal: 100, ConnsPerIp: 5}
	st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "sock", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"198.51.100.9:1080"}`})
	st.Chains = append(st.Chains, &nodev1.EgressChain{Id: "alt", MemberEgressIds: []string{"sock", "direct"}})
	st.Proxies[0].EgressChainId = "alt"
	h.apply(st)
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 1 {
		t.Errorf("instance = g%d, want g1", rec.Generation)
	}
	cfg := h.fakeEdge(1).lastConfig(t)
	if l := cfg.GetRoutes()[0].GetLimits(); l.GetDevices() != 9 || l.GetConnsTotal() != 100 || l.GetConnsPerIp() != 5 {
		t.Errorf("limits = %v", l)
	}
	if c := cfg.GetSocks()[0].GetDefaultChainId(); c != "alt" {
		t.Errorf("socks chain = %q, want alt", c)
	}
}

// A desired state that does not validate is not applied.
func TestInvalidDesiredStateIsNotApplied(t *testing.T) {
	h := newHarness(t)
	st := h.baseState(1)
	st.Proxies[0].Secret = "short"
	h.apply(st)
	err := h.r.reconcileOnce(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("pass = %v, want a validation error", err)
	}
	if n := len(h.creates("edge")) + len(h.creates("engine")); n != 0 {
		t.Errorf("created %d containers", n)
	}
	if n := len(h.eventsOf("reconcile_failed")); n != 1 {
		t.Errorf("reconcile_failed events = %d, want 1", n)
	}
}

// Without a desired state there is nothing to do.
func TestNoDesiredState(t *testing.T) {
	h := newHarness(t)
	h.pass()
	for _, c := range h.docker.Calls() {
		if c.Method == "Create" {
			t.Errorf("created %s without a desired state", c.Target)
		}
	}
}

// When the edge refuses the configuration the pass fails and nothing drains.
func TestSetConfigFailureFailsThePass(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()

	e := h.fakeEdge(1)
	e.mu.Lock()
	e.setErr = errors.New("edge did not apply the config: bind 0.0.0.0:443: address in use")
	e.mu.Unlock()
	st := h.baseState(2)
	st.Proxies = nil
	h.apply(st)
	if err := h.r.reconcileOnce(context.Background(), nil); err == nil {
		t.Fatal("pass = nil, want the SetConfig error")
	}
	c := h.container(engName1)
	if c == nil || c.RestartPolicy != "unless-stopped" {
		t.Errorf("engine = %+v: it must stay as it was while the edge still routes to it", c)
	}
	if rt := h.runtime(); rt.AppliedGeneration != 1 || rt.Instances[proxyID].Generation != 1 {
		t.Errorf("runtime = %+v, want generation 1 applied and g1 serving", rt)
	}

	// Once the edge takes the config, the deleted proxy's engine drains.
	e.mu.Lock()
	e.setErr = nil
	e.mu.Unlock()
	h.pass()
	if c := h.container(engName1); c != nil {
		t.Errorf("engine = %+v, want removed (no connections)", c)
	}
}

// The status says why the last pass failed, so that a node that cannot apply
// its state is not silent about it (I1): the text of the pass's error, as
// OnPass gets it too, until a pass goes through.
func TestStatusCarriesTheErrorOfTheLastPass(t *testing.T) {
	h := newHarness(t)
	var reported []string
	h.r.OnPass = func(rep *nodev1.StateReport, err error) {
		reported = append(reported, rep.GetLastError())
	}
	h.apply(h.baseState(1))
	h.pass()
	if got := h.r.Status().GetLastError(); got != "" {
		t.Fatalf("last error after a good pass = %q, want none", got)
	}

	e := h.fakeEdge(1)
	e.mu.Lock()
	e.setErr = errors.New("the edge did not apply the config: edge: listener \"L1\": listen tcp 0.0.0.0:443: bind: address already in use")
	e.mu.Unlock()
	h.apply(h.baseState(2))
	err := h.r.reconcileOnce(context.Background(), nil)
	if err == nil {
		t.Fatal("pass = nil, want the refusal of the edge")
	}
	if got := h.r.Status().GetLastError(); got != err.Error() || !strings.Contains(got, "address already in use") {
		t.Errorf("last error = %q, want the error of the pass, %q", got, err)
	}

	// Docker gone: another failure, another text.
	h.docker.SetError("List", errors.New("docker is down"))
	if err := h.r.reconcileOnce(context.Background(), nil); err == nil {
		t.Fatal("pass = nil, want the Docker error")
	}
	if got := h.r.Status().GetLastError(); !strings.Contains(got, "docker is down") {
		t.Errorf("last error = %q, want the Docker error", got)
	}

	h.docker.SetError("List", nil)
	e.mu.Lock()
	e.setErr = nil
	e.mu.Unlock()
	h.pass()
	if got := h.r.Status().GetLastError(); got != "" {
		t.Errorf("last error after a pass that went through = %q, want none", got)
	}
	if len(reported) != 4 || reported[0] != "" || !strings.Contains(reported[1], "address already in use") ||
		!strings.Contains(reported[2], "docker is down") || reported[3] != "" {
		t.Errorf("last errors in OnPass = %q", reported)
	}
}

// A pass that fails because its desired state is refused, as one that does not
// validate or whose configuration the edge refuses (a listener it cannot bind),
// says so (ErrRefused): the node works, its state has to change. A failure of
// the node's own machinery is no refusal: Docker that does not answer, a new
// edge that does not come up.
func TestPassErrorsTellRefusalsFromFailures(t *testing.T) {
	ctx := context.Background()

	h := newHarness(t)
	st := h.baseState(1)
	st.Proxies[0].Secret = "short"
	h.apply(st)
	if err := h.r.reconcileOnce(ctx, nil); !errors.Is(err, ErrRefused) {
		t.Errorf("pass of a state that does not validate = %v, want a refusal", err)
	}

	h = newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	e := h.fakeEdge(1)
	e.mu.Lock()
	e.setErr = refusal{errors.New(`the edge did not apply the config: edge: listener "L1": listen tcp 0.0.0.0:443: bind: address already in use`)}
	e.mu.Unlock()
	h.apply(h.baseState(2))
	err := h.r.reconcileOnce(ctx, nil)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "edge g1: the edge did not apply the config") {
		t.Errorf("pass of a configuration the edge refuses = %v, want a refusal that says so", err)
	}
	e.mu.Lock()
	e.setErr = errors.New("edge SetConfig: unavailable: dial unix: connection refused")
	e.mu.Unlock()
	if err := h.r.reconcileOnce(ctx, nil); err == nil || errors.Is(err, ErrRefused) {
		t.Errorf("pass with an edge that does not answer = %v, want a failure that is no refusal", err)
	}
	e.mu.Lock()
	e.setErr = nil
	e.mu.Unlock()
	h.docker.SetError("List", errors.New("docker is down"))
	if err := h.r.reconcileOnce(ctx, nil); err == nil || errors.Is(err, ErrRefused) {
		t.Errorf("pass without Docker = %v, want a failure that is no refusal", err)
	}

	h = newHarness(t)
	h.r.edgeStartTimeout = 50 * time.Millisecond
	h.fakeEdge(1).setHealthErr(errors.New("dial unix: no such file or directory"))
	h.apply(h.baseState(1))
	if err := h.r.reconcileOnce(ctx, nil); err == nil || errors.Is(err, ErrRefused) {
		t.Errorf("pass with a new edge that does not come up = %v, want a failure that is no refusal", err)
	}
}

// Before its first pass the reconciler reports what the runtime record and the
// desired state on disk say (M1): the applied generation, a proxy with a
// serving instance as serving, a paused one as paused, one without an instance
// as pending, and the instance of a deleted proxy as draining. The panel's
// first look at a node that just started is not an empty report. The first
// pass replaces all of it.
func TestSeedReportsTheRecordBeforeTheFirstPass(t *testing.T) {
	h := newHarness(t)
	st := h.baseState(4)
	st.Proxies = append(st.Proxies,
		&nodev1.Proxy{Id: "PAUSED", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Secret: secret2,
			Domain: "b.example.com", Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13"},
		&nodev1.Proxy{Id: "NEW", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Enabled: true, Secret: secret2,
			Domain: "c.example.com", Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13"},
	)
	rt := state.NewRuntime()
	rt.AppliedGeneration = 3
	rt.Instances[proxyID] = state.InstanceRecord{Generation: 5, Engine: "telemt", Version: "3.5.13", ListenPort: 20005}
	rt.Instances["PAUSED"] = state.InstanceRecord{Generation: 2, Engine: "telemt", Version: "3.5.12", ListenPort: 20002}
	rt.Instances["GONE"] = state.InstanceRecord{Engine: "telemt", Draining: []state.DrainingInstance{{Generation: 7, ContainerName: "postern-eng-gone-g7"}}}

	h.r.Seed(st, rt)
	rep := h.r.Status()
	if rep.GetAppliedGeneration() != 3 {
		t.Errorf("applied generation = %d, want 3, the record's", rep.GetAppliedGeneration())
	}
	want := []*nodev1.ProxyStatus{
		{ProxyId: proxyID, Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_TELEMT, RunningVersion: "3.5.13", InstanceGeneration: 5},
		{ProxyId: "GONE", Phase: nodev1.ProxyPhase_PROXY_PHASE_DRAINING, Reason: "the proxy was deleted", Engine: nodev1.Engine_ENGINE_TELEMT, InstanceGeneration: 7},
		{ProxyId: "NEW", Phase: nodev1.ProxyPhase_PROXY_PHASE_PENDING, Engine: nodev1.Engine_ENGINE_TELEMT},
		{ProxyId: "PAUSED", Phase: nodev1.ProxyPhase_PROXY_PHASE_PAUSED, Engine: nodev1.Engine_ENGINE_TELEMT, RunningVersion: "3.5.12", InstanceGeneration: 2},
	}
	if !protoSliceEqual(rep.GetProxies(), want) {
		t.Errorf("seeded proxies = %v\nwant %v", rep.GetProxies(), want)
	}

	// Without a desired state, the record alone.
	h.r = h.newReconciler()
	h.r.Seed(nil, rt)
	if got := len(h.r.Status().GetProxies()); got != 3 {
		t.Errorf("proxies seeded from the record alone = %d, want 3", got)
	}

	// The first pass has the last word.
	h.r = h.newReconciler()
	h.r.Seed(st, rt)
	h.apply(h.baseState(4))
	h.pass()
	for _, ps := range h.r.Status().GetProxies() {
		if ps.GetProxyId() != proxyID {
			t.Errorf("after the first pass: %v, want only the proxies of the pass", ps)
		}
	}
}

// Engine instance files (Ruling 14): the directory and config stay root's
// (group 65534 can read), only data/ belongs to 65534.
func checkInstanceDir(t *testing.T, dir string, rec state.InstanceRecord) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	for path, want := range map[string]os.FileMode{
		dir:                               0o750,
		filepath.Join(dir, "config.toml"): 0o640,
		filepath.Join(dir, "data"):        0o750,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Error(err)
			continue
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s: mode %v, want %v", path, got, want)
		}
	}
	if os.Geteuid() == 0 {
		for path, want := range map[string][2]int{
			dir:                               {0, 65534},
			filepath.Join(dir, "config.toml"): {0, 65534},
			filepath.Join(dir, "data"):        {65534, 65534},
		} {
			uid, gid, ok := fileOwner(path)
			if ok && (uid != want[0] || gid != want[1]) {
				t.Errorf("%s: owner %d:%d, want %d:%d", path, uid, gid, want[0], want[1])
			}
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"port = " + itoa(rec.ListenPort), `listen = "127.0.0.1:` + itoa(rec.APIPort) + `"`, `address = "127.0.0.1:` + itoa(rec.SocksPort) + `"`, `auth_header = "` + rec.APIToken + `"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("config.toml lacks %s", want)
		}
	}
}

func assertNoSecretsInEvents(t *testing.T, h *harness) {
	t.Helper()
	secrets := []string{secret1, secret2, adTag}
	for _, rec := range h.runtime().Instances {
		if rec.APIToken != "" {
			secrets = append(secrets, rec.APIToken)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ev := range h.events {
		text := protojson.Format(ev)
		for _, s := range secrets {
			if strings.Contains(text, s) {
				t.Errorf("event reveals a secret: %s", text)
			}
		}
	}
}

func specEqual(a, b dockerapi.ContainerSpec) bool {
	return a.Name == b.Name && a.Image == b.Image && a.User == b.User && a.NetworkMode == b.NetworkMode &&
		a.RestartPolicy == b.RestartPolicy && a.PidMode == b.PidMode &&
		slices.Equal(a.Entrypoint, b.Entrypoint) && slices.Equal(a.Cmd, b.Cmd) && slices.Equal(a.Env, b.Env) &&
		slices.Equal(a.Binds, b.Binds) && slices.Equal(a.CapAdd, b.CapAdd) && slices.Equal(a.CapDrop, b.CapDrop) &&
		slices.Equal(a.SecurityOpt, b.SecurityOpt) && mapsEqual(a.Labels, b.Labels) && mapsEqual(a.Tmpfs, b.Tmpfs) &&
		a.ReadOnly == b.ReadOnly && a.MemoryBytes == b.MemoryBytes && a.PidsLimit == b.PidsLimit &&
		slices.Equal(a.Ulimits, b.Ulimits) &&
		a.LogMaxSize == b.LogMaxSize && a.LogMaxFile == b.LogMaxFile && intPtrEqual(a.StopTimeout, b.StopTimeout)
}

// intPtrEqual compares what the pointers point to; two nil pointers are equal,
// and nil is not equal to a pointer to 0.
func intPtrEqual(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func protoSliceEqual[T proto.Message](a, b []T) bool {
	return slices.EqualFunc(a, b, func(x, y T) bool { return proto.Equal(x, y) })
}

func itoa(p uint16) string { return strconv.Itoa(int(p)) }

// ---- the worker ---------------------------------------------------------------

// Run makes a pass at once, another one for every trigger, and returns when
// its context ends, leaving no goroutine behind.
func TestRunPassesOnTriggerAndStops(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	passes := make(chan *nodev1.StateReport, 10)
	h.r.OnPass = func(rep *nodev1.StateReport, err error) {
		if err != nil {
			t.Errorf("pass: %v", err)
		}
		passes <- rep
	}
	baseline := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	trigger := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.r.Run(ctx, trigger)
	}()

	waitPass(t, passes)
	h.apply(h.baseState(2))
	trigger <- struct{}{}
	if rep := waitPass(t, passes); rep.GetAppliedGeneration() != 2 {
		t.Errorf("applied = %d, want 2", rep.GetAppliedGeneration())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline {
		t.Errorf("%d goroutines after Run returned, %d before", n, baseline)
	}
}

// A newer state that arrives during a pass stops it at the next step boundary;
// the restarted pass applies the newest generation (the older one is never
// reported as applied).
func TestNewerTriggerRestartsPass(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	h.prober.setFail(func(probeCall) error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	})
	passes := make(chan *nodev1.StateReport, 10)
	h.r.OnPass = func(rep *nodev1.StateReport, err error) {
		if err != nil {
			t.Errorf("pass: %v", err)
		}
		passes <- rep
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	trigger := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.r.Run(ctx, trigger)
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the probe was never called")
	}
	st := h.baseState(2)
	st.Proxies[0].Limits = &nodev1.Limits{Devices: 42}
	h.apply(st)
	trigger <- struct{}{}
	close(release)

	rep := waitPass(t, passes)
	if rep.GetAppliedGeneration() != 2 {
		t.Errorf("first reported pass applied %d, want 2", rep.GetAppliedGeneration())
	}
	if l := h.fakeEdge(1).lastConfig(t).GetRoutes()[0].GetLimits().GetDevices(); l != 42 {
		t.Errorf("devices limit = %d, want 42", l)
	}
	cancel()
	<-done
}

// When the agent stops during a start, the half-made generation is removed and
// nothing is reported as the engine's failure.
func TestShutdownDuringStartCleansUp(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	ctx, cancel := context.WithCancel(context.Background())
	h.prober.setFail(func(probeCall) error {
		cancel()
		return context.Canceled
	})
	reported := 0
	h.r.OnPass = func(*nodev1.StateReport, error) { reported++ }
	err := h.r.reconcileOnce(ctx, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pass = %v, want context.Canceled", err)
	}
	if c := h.container(engName1); c != nil {
		t.Errorf("the half-made generation is still there: %+v", c)
	}
	for _, kind := range []string{"instance_failed", "upgrade_aborted", "reconcile_failed"} {
		if n := len(h.eventsOf(kind)); n != 0 {
			t.Errorf("%d %s events on shutdown", n, kind)
		}
	}
	if reported != 0 {
		t.Errorf("OnPass called %d times on shutdown", reported)
	}
	for k := range h.runtime().Ports {
		if strings.HasPrefix(k, "eng:") {
			t.Errorf("port %s still allocated", k)
		}
	}
	// The next start goes ahead at once: no backoff was recorded.
	h.prober.setFail(nil)
	h.pass()
	if c := h.container(engName2); c == nil || c.State != "running" {
		t.Errorf("g2 = %+v, want running", c)
	}
}

// Status may be read while a pass runs.
func TestStatusDuringPass(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	seen := make(chan nodev1.ProxyPhase, 1)
	h.prober.setFail(func(probeCall) error {
		seen <- h.proxyStatus(proxyID).GetPhase()
		return nil
	})
	h.pass()
	if phase := <-seen; phase != nodev1.ProxyPhase_PROXY_PHASE_STARTING {
		t.Errorf("phase during the probe = %v, want starting", phase)
	}
}

func waitPass(t *testing.T, passes <-chan *nodev1.StateReport) *nodev1.StateReport {
	t.Helper()
	select {
	case rep := <-passes:
		return rep
	case <-time.After(10 * time.Second):
		t.Fatal("no pass finished")
		return nil
	}
}
