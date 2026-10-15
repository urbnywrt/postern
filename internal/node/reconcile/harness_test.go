package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/mtg"
	"github.com/urbnywrt/postern/internal/engines/telemt"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/node/trial"
	"github.com/urbnywrt/postern/internal/probe/probetest"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/psiphoncore"
	"github.com/urbnywrt/postern/internal/providers/warp"
	"github.com/urbnywrt/postern/internal/providers/xray"
)

// runnerImage is the image every node container runs (Global Constraints).
const runnerImage = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

const (
	secret1 = "00112233445566778899aabbccddeeff" // gitleaks:allow (a fake secret)
	secret2 = "ffeeddccbbaa99887766554433221100" // gitleaks:allow (a fake secret)
	adTag   = "0123456789abcdef0123456789abcdef"

	proxyID = "01J9ZZPROXY0000000000000P1"
	// engName is the container name of generation 1 of proxyID.
	engName1 = "postern-eng-01j9zzproxy0000000000000p1-g1"
	engName2 = "postern-eng-01j9zzproxy0000000000000p1-g2"
)

// ---- clock ------------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// ---- edge -------------------------------------------------------------------

// fakeEdge is the control client of one edge generation.
type fakeEdge struct {
	gen      uint64
	onHealth func()                   // called on every Health call, outside the lock (a test's hook)
	note     func(string)             // the harness's trace of what happens, in order
	set      func(*edgev1.EdgeConfig) // told every configuration that is applied

	mu        sync.Mutex
	configs   []*edgev1.EdgeConfig
	setErr    error
	healthErr error
	snapErr   error
	drainErr  error
	version   string // what Health says the edge runs
	// active is backend_active by proxy id and backend address.
	active  map[string]map[string]uint32
	health  []*edgev1.MemberHealth
	drained []uint32
	onSet   func(cfg *edgev1.EdgeConfig)
	dns     bool // what Health says of the DNS forwarder
	// failures are the listeners this edge cannot bind, by id: SetConfig
	// returns those of the configuration, and Health leaves their addresses
	// out of bound.
	failures map[string]string
}

func (e *fakeEdge) SetConfig(_ context.Context, cfg *edgev1.EdgeConfig) ([]*edgev1.ListenerFailure, error) {
	e.mu.Lock()
	onSet := e.onSet
	if e.setErr != nil {
		err := e.setErr
		e.mu.Unlock()
		return nil, err
	}
	e.configs = append(e.configs, proto.Clone(cfg).(*edgev1.EdgeConfig))
	set := e.set
	failed := e.failedLocked(cfg)
	e.mu.Unlock()
	if set != nil {
		set(cfg)
	}
	if onSet != nil {
		onSet(cfg)
	}
	return failed, nil
}

// failedLocked returns the listeners of cfg that this edge cannot bind.
func (e *fakeEdge) failedLocked(cfg *edgev1.EdgeConfig) []*edgev1.ListenerFailure {
	var out []*edgev1.ListenerFailure
	for _, l := range cfg.GetListeners() {
		if reason, ok := e.failures[l.GetId()]; ok {
			out = append(out, &edgev1.ListenerFailure{ListenerId: l.GetId(), Reason: reason})
		}
	}
	return out
}

// setFailures makes the listeners with the given ids fail to bind, with a
// reason that names the id; none makes every listener bind again.
func (e *fakeEdge) setFailures(ids ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failures = map[string]string{}
	for _, id := range ids {
		e.failures[id] = "listen tcp4 " + id + ": bind: address already in use"
	}
}

func (e *fakeEdge) Snapshot(context.Context) (*edgev1.SnapshotResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.snapErr != nil {
		return nil, e.snapErr
	}
	resp := &edgev1.SnapshotResponse{Generation: e.gen}
	for id, backends := range e.active {
		pc := &edgev1.ProxyCounters{ProxyId: id, BackendActive: map[string]uint32{}}
		for addr, n := range backends {
			pc.BackendActive[addr] = n
		}
		resp.Proxies = append(resp.Proxies, pc)
	}
	for _, h := range e.health {
		resp.Health = append(resp.Health, proto.Clone(h).(*edgev1.MemberHealth))
	}
	return resp, nil
}

func (e *fakeEdge) Health(context.Context) (*edgev1.HealthResponse, error) {
	e.mu.Lock()
	hook := e.onHealth
	e.mu.Unlock()
	if hook != nil {
		hook()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.healthErr != nil {
		return nil, e.healthErr
	}
	e.trace("health g" + genString(e.gen))
	h := &edgev1.HealthResponse{Generation: e.gen, Listening: true, Dns: e.dns, Version: e.version}
	// bound has the listeners of the last configuration that did not fail. An
	// edge that has no configuration from the agent yet came up from its file,
	// which the fake does not see: it reports its failures by id.
	if len(e.configs) == 0 {
		for _, id := range slices.Sorted(maps.Keys(e.failures)) {
			h.ListenerFailures = append(h.ListenerFailures, &edgev1.ListenerFailure{ListenerId: id, Reason: e.failures[id]})
		}
	} else {
		cfg := e.configs[len(e.configs)-1]
		h.ListenerFailures = e.failedLocked(cfg)
		for _, l := range cfg.GetListeners() {
			if _, failed := e.failures[l.GetId()]; !failed {
				// Canonical, as the edge prints a netip.AddrPort.
				h.Bound = append(h.Bound, netip.AddrPortFrom(netip.MustParseAddr(l.GetBindIp()), uint16(l.GetPort())).String())
			}
		}
	}
	return h, nil
}

func (e *fakeEdge) setDNS(up bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dns = up
}

func (e *fakeEdge) Drain(_ context.Context, maxSeconds uint32) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.drained = append(e.drained, maxSeconds)
	e.trace("drain g" + genString(e.gen))
	return e.drainErr
}

func (e *fakeEdge) trace(what string) {
	if e.note != nil {
		e.note(what)
	}
}

func (e *fakeEdge) setHealthErr(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.healthErr = err
}

func (e *fakeEdge) setVersion(v string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.version = v
}

func (e *fakeEdge) setDrainErr(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.drainErr = err
}

func (e *fakeEdge) setActive(proxy string, port uint16, n uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.active == nil {
		e.active = map[string]map[string]uint32{}
	}
	if e.active[proxy] == nil {
		e.active[proxy] = map[string]uint32{}
	}
	e.active[proxy]["127.0.0.1:"+strconv.Itoa(int(port))] = n
}

func (e *fakeEdge) lastConfig(t *testing.T) *edgev1.EdgeConfig {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.configs) == 0 {
		t.Fatalf("edge g%d got no SetConfig", e.gen)
	}
	return e.configs[len(e.configs)-1]
}

func (e *fakeEdge) setHealth(hs ...*edgev1.MemberHealth) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.health = hs
}

func (e *fakeEdge) setCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.configs)
}

func (e *fakeEdge) drainCalls() []uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.drained)
}

// ---- engine driver ------------------------------------------------------------

// fakeDriver renders and describes containers like telemt, but its readiness
// is up to the test.
type fakeDriver struct {
	engines.Driver

	mu    sync.Mutex
	ready func(ctx context.Context, in engines.Instance) error
	calls int
}

// LogEnv is the wrapped driver's log environment (engines.LogLeveler), none// for a driver without one.func (d *fakeDriver) LogEnv() []string {	if ll, ok := d.Driver.(engines.LogLeveler); ok {		return ll.LogEnv()	}	return nil}
func (d *fakeDriver) Ready(ctx context.Context, in engines.Instance) error {
	d.mu.Lock()
	d.calls++
	ready := d.ready
	d.mu.Unlock()
	if ready == nil {
		return nil
	}
	return ready(ctx, in)
}

func (d *fakeDriver) setReady(f func(ctx context.Context, in engines.Instance) error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ready = f
}

// Trial is the wrapped driver's: the wrapper embeds the interface, which
// hides it from a type assertion.
func (d *fakeDriver) Trial(version string) engines.Trial {
	return d.Driver.(engines.Trialer).Trial(version)
}

// ---- provider driver ----------------------------------------------------------

// fakeProvider renders and describes containers like the provider it wraps
// (Xray, Psiphon), but its readiness is up to the test.
type fakeProvider struct {
	providers.Driver

	mu      sync.Mutex
	ready   func(ctx context.Context, in providers.Instance) error
	readies []providers.Instance
}

func (d *fakeProvider) Ready(ctx context.Context, in providers.Instance) error {
	d.mu.Lock()
	d.readies = append(d.readies, in)
	ready := d.ready
	d.mu.Unlock()
	if ready == nil {
		return nil
	}
	return ready(ctx, in)
}

func (d *fakeProvider) setReady(f func(ctx context.Context, in providers.Instance) error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ready = f
}

// FilesOwnedByRunner is the wrapped driver's (providers.RunnerOwnedFiles).
func (d *fakeProvider) FilesOwnedByRunner() bool {
	o, ok := d.Driver.(providers.RunnerOwnedFiles)
	return ok && o.FilesOwnedByRunner()
}

// Trial is the wrapped driver's (see fakeDriver.Trial).
func (d *fakeProvider) Trial(version string) engines.Trial {
	return d.Driver.(engines.Trialer).Trial(version)
}

func (d *fakeProvider) readyCalls() []providers.Instance {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.readies)
}

// ---- the checks of a new generation on its way out ---------------------------

// gateCall is a check of the way out of a new engine generation.
type gateCall struct {
	what   string // "dc", "secret" or "l2"
	addr   string // the SOCKS port, or where L2 connected
	target string // the datacenter (dc)
	sni    string
	secret []byte
	dc     int16
	src    netip.AddrPort
	probes []*edgev1.Route // the probe routes the edge had when L2 ran
}

// fakeGate stands in for the network of the checks: a CONNECT through a SOCKS
// port of the edge reaches a fake datacenter (probetest), and L2 and the fetch
// of the proxy secret say what the test wants.
type fakeGate struct {
	h *harness

	mu    sync.Mutex
	calls []gateCall
	// dcMode is how the datacenters answer through the SOCKS ports.
	dcMode probetest.Mode
	// dialErr, when set, is the error of a CONNECT to a datacenter.
	dialErr func(target string) error
	l2Err   error
	// secretErr is the error of the fetch of the proxy secret.
	secretErr error
}

func (g *fakeGate) record(c gateCall) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, c)
}

func (g *fakeGate) socksDial(_ context.Context, socks, target string) (net.Conn, error) {
	g.record(gateCall{what: "dc", addr: socks, target: target})
	g.mu.Lock()
	mode, dialErr := g.dcMode, g.dialErr
	g.mu.Unlock()
	if dialErr != nil {
		if err := dialErr(target); err != nil {
			return nil, err
		}
	}
	return probetest.Pipe(mode), nil
}

func (g *fakeGate) proxySecret(_ context.Context, socks string) error {
	g.record(gateCall{what: "secret", addr: socks})
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.secretErr
}

func (g *fakeGate) l2(_ context.Context, addr, sni string, secret []byte, dc int16, src netip.AddrPort) error {
	probes := g.h.lastSetConfig().GetProbeRoutes()
	g.record(gateCall{what: "l2", addr: addr, sni: sni, secret: slices.Clone(secret), dc: dc, src: src, probes: probes})
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.l2Err
}

func (g *fakeGate) callsOf(what string) []gateCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []gateCall
	for _, c := range g.calls {
		if c.what == what {
			out = append(out, c)
		}
	}
	return out
}

func (g *fakeGate) set(f func(g *fakeGate)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f(g)
}

// ---- WARP ---------------------------------------------------------------------

// fakeWARP stands in for Cloudflare's API: a registration writes the test's
// account to the file (as warp.LoadOrRegister keeps it), and a deletion is
// noted.
type fakeWARP struct {
	mu         sync.Mutex
	registered []string // the paths of the account files
	deleted    []string // the ids of the deleted devices
	regErr     error
	// deleteHook, when set, is called first by a deletion, which fails with
	// its error.
	deleteHook func(ctx context.Context) error
}

func testWARPAccount() *warp.Account {
	return &warp.Account{
		PrivateKey:    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", // gitleaks:allow (a fake key)
		PeerPublicKey: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=",
		Endpoint:      "warp.example.com:2408",
		AddrV4:        "192.0.2.2",
		AddrV6:        "2001:db8::2",
		ID:            "t-device-1",
		Token:         "t-token-0123456789", // gitleaks:allow (a fake token)
	}
}

func (w *fakeWARP) account(_ context.Context, path string) (*warp.Account, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.registered = append(w.registered, path)
	if w.regErr != nil {
		return nil, w.regErr
	}
	if a, err := warp.Load(path); err == nil {
		return a, nil
	}
	a := testWARPAccount()
	if err := warp.Save(path, a); err != nil {
		return nil, err
	}
	return a, nil
}

func (w *fakeWARP) delete(ctx context.Context, a *warp.Account) error {
	w.mu.Lock()
	hook := w.deleteHook
	w.mu.Unlock()
	if hook != nil {
		if err := hook(ctx); err != nil {
			return err
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deleted = append(w.deleted, a.ID)
	return nil
}

func (w *fakeWARP) setDeleteHook(f func(ctx context.Context) error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deleteHook = f
}

// ---- prober -----------------------------------------------------------------

type probeCall struct {
	addr, sni string
	secret    []byte
	src       netip.AddrPort
}

type fakeProber struct {
	mu    sync.Mutex
	calls []probeCall
	// fail decides the result; nil means success.
	fail func(c probeCall) error
}

func (p *fakeProber) probe(ctx context.Context, addr, sni string, secret []byte, src netip.AddrPort) error {
	c := probeCall{addr: addr, sni: sni, secret: slices.Clone(secret), src: src}
	p.mu.Lock()
	p.calls = append(p.calls, c)
	fail := p.fail
	p.mu.Unlock()
	if fail != nil {
		return fail(c)
	}
	return ctx.Err()
}

func (p *fakeProber) setFail(f func(c probeCall) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fail = f
}

func (p *fakeProber) callList() []probeCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.calls)
}

// failSecret makes probes with the given hex secret fail.
func failSecret(hexSecret string) func(c probeCall) error {
	return func(c probeCall) error {
		if hex.EncodeToString(c.secret) == hexSecret {
			return errors.New("probe: server digest mismatch")
		}
		return nil
	}
}

// ---- docker -----------------------------------------------------------------

// checkingDocker lets a test look at the world at the moment a container is
// created, and notes the calls that change a container in the harness's trace.
type checkingDocker struct {
	*dockerapi.Fake
	note     func(string)
	mu       sync.Mutex
	onCreate func(spec dockerapi.ContainerSpec)
}

func (d *checkingDocker) Create(ctx context.Context, spec dockerapi.ContainerSpec) (string, error) {
	d.mu.Lock()
	f := d.onCreate
	d.mu.Unlock()
	if f != nil {
		f(spec)
	}
	d.note("create " + spec.Name)
	return d.Fake.Create(ctx, spec)
}

func (d *checkingDocker) Start(ctx context.Context, id string) error {
	d.note("start " + id)
	return d.Fake.Start(ctx, id)
}

func (d *checkingDocker) Stop(ctx context.Context, id string, timeout time.Duration) error {
	d.note("stop " + id)
	return d.Fake.Stop(ctx, id, timeout)
}

func (d *checkingDocker) Remove(ctx context.Context, id string, force bool) error {
	d.note("remove " + id)
	return d.Fake.Remove(ctx, id, force)
}

func (d *checkingDocker) SetRestartPolicy(ctx context.Context, id, policy string) error {
	d.note("restart policy " + id + " " + policy)
	return d.Fake.SetRestartPolicy(ctx, id, policy)
}

// ---- trials -------------------------------------------------------------------

// fakeTrials stands in for the node's trial runner: Run returns result (the
// zero value is a trial that did not run) and remembers what was tried;
// InFlight is whatever the test says it is.
type fakeTrials struct {
	mu       sync.Mutex
	result   trial.Result
	runs     []string // the paths of the binaries tried, in order
	inFlight map[string]bool
}

func (f *fakeTrials) Run(_ context.Context, binaryPath, _ string, _ engines.Trial) trial.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, binaryPath)
	return f.result
}

func (f *fakeTrials) InFlight() map[string]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.inFlight)
}

func (f *fakeTrials) set(res trial.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.result = res
}

func (f *fakeTrials) tried() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.runs)
}

// ---- harness ------------------------------------------------------------------

type harness struct {
	t       *testing.T
	paths   state.Paths
	store   *state.Store
	arts    *artifacts.Store
	docker  *checkingDocker
	driver  *fakeDriver
	mtg     *fakeDriver
	xray    *fakeProvider
	psiphon *fakeProvider
	prober  *fakeProber
	gate    *fakeGate
	warp    *fakeWARP
	clock   *fakeClock
	trials  *fakeTrials
	r       *Reconciler

	nodeBinary string
	artifact   *nodev1.ArtifactRef
	// mtgArtifact is the stored binary of mtg v2.2.8.
	mtgArtifact *nodev1.ArtifactRef
	// xrayArtifact and psiphonArtifact are the stored binaries of the
	// providers.
	xrayArtifact, psiphonArtifact *nodev1.ArtifactRef

	mu    sync.Mutex
	edges map[uint64]*fakeEdge
	// lookups is what lookupIP answers by host; lookupCalls the hosts asked.
	lookups     map[string][]netip.Addr
	lookupCalls []string
	events      []*nodev1.NodeEvent
	lastSet     *edgev1.EdgeConfig // what an edge got last (see recordSet)
	// nrOpen is what the reconciler reads in /proc/sys/fs/nr_open of the
	// host; "" for a file that cannot be read.
	nrOpen string
	// trace is what the edges and Docker were asked to do, in order: see
	// fakeEdge and checkingDocker.
	trace []string
}

// note adds to the trace.
func (h *harness) note(what string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.trace = append(h.trace, what)
}

// takeTrace returns the trace and starts a new one.
func (h *harness) takeTrace() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.trace
	h.trace = nil
	return out
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	home := t.TempDir()
	h := &harness{
		t:       t,
		paths:   state.Paths{Home: home},
		docker:  &checkingDocker{Fake: dockerapi.NewFake()},
		driver:  &fakeDriver{Driver: telemt.New()},
		mtg:     &fakeDriver{Driver: mtg.New()},
		xray:    &fakeProvider{Driver: xray.New()},
		psiphon: &fakeProvider{Driver: psiphoncore.New()},
		prober:  &fakeProber{},
		warp:    &fakeWARP{},
		clock:   newClock(),
		trials:  &fakeTrials{result: trial.Result{Ran: true, OK: true}},
		edges:   map[uint64]*fakeEdge{},
		nrOpen:  "1048576\n", // the default of Linux
	}
	h.gate = &fakeGate{h: h}
	h.store = &state.Store{Paths: h.paths}
	h.docker.Now = h.clock.Now
	h.docker.note = h.note
	h.arts = &artifacts.Store{Root: h.paths.ArtifactsDir()}

	// Stand-ins for the binaries of telemt and of the providers, stored like an
	// upload from the panel.
	binary := []byte("#!/bin/sh\nexit 0\n")
	sum := sha256.Sum256(binary)
	store := func(engine, version, name string) *nodev1.ArtifactRef {
		ref := &nodev1.ArtifactRef{
			Engine: engine, Version: version, Arch: "amd64",
			Sha256: hex.EncodeToString(sum[:]), FileName: name, Binary: name,
		}
		if err := h.arts.Put(artifacts.Ref{
			Engine: engine, Version: version, Arch: "amd64", SHA256: ref.Sha256, FileName: name, Binary: name,
		}, bytes.NewReader(binary)); err != nil {
			t.Fatal(err)
		}
		return ref
	}
	h.artifact = store("telemt", "3.5.13", "telemt")
	h.mtgArtifact = store("mtg", mtg.DefaultVersion, "mtg")
	h.xrayArtifact = store("xray", "v26.3.27", "xray")
	h.psiphonArtifact = store("psiphon-core", "20261005-c4a09096ab", "psiphon-core")

	h.nodeBinary = filepath.Join(home, "bin", "postern-node")
	if err := os.MkdirAll(filepath.Dir(h.nodeBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.nodeBinary, binary, 0o755); err != nil {
		t.Fatal(err)
	}

	h.r = h.newReconciler()
	return h
}

// newReconciler is a reconciler over the harness's world, as a fresh agent
// process would make it.
func (h *harness) newReconciler() *Reconciler {
	r := &Reconciler{
		Docker:    h.docker,
		Store:     h.store,
		Artifacts: h.arts,
		Drivers:   map[nodev1.Engine]engines.Driver{nodev1.Engine_ENGINE_TELEMT: h.driver, nodev1.Engine_ENGINE_MTG: h.mtg},
		Providers: map[nodev1.EgressKind]providers.Driver{
			nodev1.EgressKind_EGRESS_KIND_XRAY_URI:          h.xray,
			nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION: h.xray,
			nodev1.EgressKind_EGRESS_KIND_WARP:              h.xray,
			nodev1.EgressKind_EGRESS_KIND_PSIPHON:           h.psiphon,
		},
		Alloc:          &state.Allocator{IsFree: func(uint16) bool { return true }},
		EdgeFactory:    h.edge,
		Probe:          h.prober.probe,
		L2:             h.gate.l2,
		Now:            h.clock.Now,
		RunnerImage:    runnerImage,
		NodeBinaryPath: h.nodeBinary,
		Arch:           "amd64",
		DrainAfter:     30 * time.Minute,
		Events:         h.recordEvent,
		Trials:         h.trials,
	}
	r.readyTimeout = 2 * time.Second
	r.egressReadyTimeout = 2 * time.Second
	r.readyPoll = time.Millisecond
	r.edgeStartTimeout = 2 * time.Second
	r.edgePoll = time.Millisecond
	r.probeTimeout = time.Second
	r.readFile = h.readFile
	// Nothing goes out to the network: the checks of a new generation reach
	// fake datacenters, no middle-proxy list is fetched (a test that wants one
	// names the sources), and WARP devices are the test's.
	r.socksDial = h.gate.socksDial
	r.proxySecret = h.gate.proxySecret
	r.MEConfigURLs = []string{}
	r.warpAccount = h.warp.account
	r.warpDelete = h.warp.delete
	r.frontingLookup = h.lookupIP
	// The subscription servers of the tests listen on loopback.
	r.fetchAllowDial = func(ap netip.AddrPort) bool { return ap.Addr().IsLoopback() }
	return r
}

// lastSetConfig is the configuration that an edge got last, of whatever
// generation; nil before the first.
func (h *harness) lastSetConfig() *edgev1.EdgeConfig {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastSet
}

func (h *harness) recordSet(cfg *edgev1.EdgeConfig) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastSet = proto.Clone(cfg).(*edgev1.EdgeConfig)
}

// readFile stands in for the files of the host the reconciler reads:
// /proc/sys/fs/nr_open holds h.nrOpen, and nothing else can be read.
func (h *harness) readFile(name string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if name == "/proc/sys/fs/nr_open" && h.nrOpen != "" {
		return []byte(h.nrOpen), nil
	}
	return nil, fs.ErrNotExist
}

func (h *harness) edge(gen uint64) EdgeClient {
	return h.fakeEdge(gen)
}

func (h *harness) fakeEdge(gen uint64) *fakeEdge {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.edges[gen]
	if !ok {
		e = &fakeEdge{gen: gen, note: h.note, set: h.recordSet}
		h.edges[gen] = e
	}
	return e
}

func (h *harness) recordEvent(ev *nodev1.NodeEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, proto.Clone(ev).(*nodev1.NodeEvent))
}

func (h *harness) eventKinds() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var kinds []string
	for _, ev := range h.events {
		kinds = append(kinds, ev.GetKind())
	}
	return kinds
}

func (h *harness) eventsOf(kind string) []*nodev1.NodeEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*nodev1.NodeEvent
	for _, ev := range h.events {
		if ev.GetKind() == kind {
			out = append(out, ev)
		}
	}
	return out
}

// baseState has one listener, one enabled fake-TLS proxy and the implicit
// direct egress and default chain the panel sends.
func (h *harness) baseState(gen uint64) *nodev1.NodeState {
	return &nodev1.NodeState{
		Generation: gen,
		Settings:   &nodev1.NodeSettings{DefaultChainId: "default", DomainPool: []string{"pool.example.com"}},
		Listeners: []*nodev1.Listener{{
			Id: "L1", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "0.0.0.0", Port: 443,
			StrangerAction: nodev1.StrangerAction_STRANGER_ACTION_MASK,
		}},
		Proxies: []*nodev1.Proxy{{
			Id: proxyID, ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Enabled: true,
			Secret: secret1, Domain: "a.example.com",
			Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
			Limits: &nodev1.Limits{Devices: 3},
		}},
		Egresses: []*nodev1.Egress{{Id: "direct", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT}},
		Chains:   []*nodev1.EgressChain{{Id: "default", MemberEgressIds: []string{"direct"}}},
		Artifacts: []*nodev1.ArtifactRef{
			proto.Clone(h.artifact).(*nodev1.ArtifactRef),
			proto.Clone(h.mtgArtifact).(*nodev1.ArtifactRef),
			proto.Clone(h.xrayArtifact).(*nodev1.ArtifactRef),
			proto.Clone(h.psiphonArtifact).(*nodev1.ArtifactRef),
		},
	}
}

// mtgState is the base state with the proxy on mtg, its mask target override
// set to mask (none when empty).
func (h *harness) mtgState(gen uint64, mask string) *nodev1.NodeState {
	st := h.baseState(gen)
	st.Proxies[0].Engine, st.Proxies[0].EngineVersion, st.Proxies[0].MaskTargetOverride = nodev1.Engine_ENGINE_MTG, mtg.DefaultVersion, mask
	return st
}

// lookupIP stands in for the node's resolver in the lookup of a fronting
// address: h.lookups by host, or an error for a host it does not know. The
// hosts looked up are counted in h.lookupCalls.
func (h *harness) lookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lookupCalls = append(h.lookupCalls, host)
	addrs, ok := h.lookups[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return slices.Clone(addrs), nil
}

// setLookup sets what the resolver answers for a host.
func (h *harness) setLookup(host string, addrs ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lookups == nil {
		h.lookups = map[string][]netip.Addr{}
	}
	var out []netip.Addr
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	h.lookups[host] = out
}

// clearLookup makes the resolver fail for a host.
func (h *harness) clearLookup(host string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.lookups, host)
}

// lookupsOf counts the lookups of a host.
func (h *harness) lookupsOf(host string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, l := range h.lookupCalls {
		if l == host {
			n++
		}
	}
	return n
}

func (h *harness) apply(st *nodev1.NodeState) {
	h.t.Helper()
	if err := h.store.SaveDesired(st); err != nil {
		h.t.Fatal(err)
	}
}

// pass runs one reconcile pass and fails the test on an error.
func (h *harness) pass() {
	h.t.Helper()
	if err := h.r.reconcileOnce(context.Background(), nil); err != nil {
		h.t.Fatalf("reconcile pass: %v", err)
	}
}

func (h *harness) runtime() *state.Runtime {
	h.t.Helper()
	rt, err := h.store.LoadRuntime()
	if err != nil {
		h.t.Fatal(err)
	}
	return rt
}

// container returns the details of a container, or nil when it does not exist.
func (h *harness) container(name string) *dockerapi.ContainerDetails {
	h.t.Helper()
	d, err := h.docker.Inspect(context.Background(), name)
	if errors.Is(err, dockerapi.ErrNotFound) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return d
}

func (h *harness) creates(role string) []dockerapi.ContainerSpec {
	var out []dockerapi.ContainerSpec
	for _, c := range h.docker.Calls() {
		if c.Method == "Create" && c.Spec != nil && c.Spec.Labels["postern.role"] == role {
			out = append(out, *c.Spec)
		}
	}
	return out
}

func (h *harness) proxyStatus(id string) *nodev1.ProxyStatus {
	h.t.Helper()
	for _, ps := range h.r.Status().GetProxies() {
		if ps.GetProxyId() == id {
			return ps
		}
	}
	return nil
}

// addContainer creates (and starts, if running) a container in the fake as if
// an earlier agent had made it.
func (h *harness) addContainer(name, role, id string, gen uint64, running bool) {
	h.t.Helper()
	ctx := context.Background()
	_, err := h.docker.Fake.Create(ctx, dockerapi.ContainerSpec{
		Name: name, Image: runnerImage, NetworkMode: "host", RestartPolicy: "unless-stopped",
		Labels: map[string]string{
			"postern.managed": "true", "postern.role": role, "postern.id": id,
			"postern.generation": strconv.FormatUint(gen, 10),
		},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	if running {
		if err := h.docker.Start(ctx, name); err != nil {
			h.t.Fatal(err)
		}
	}
}

// routeMap is the routing table of a config: "listener/sni" → "proxy->backend".
func routeMap(cfg *edgev1.EdgeConfig) map[string]string {
	m := map[string]string{}
	for _, r := range cfg.GetRoutes() {
		m[r.GetListenerId()+"/"+r.GetSni()] = r.GetProxyId() + "->" + r.GetBackend()
	}
	return m
}

func routeBackends(cfg *edgev1.EdgeConfig) []string {
	var out []string
	for _, r := range cfg.GetRoutes() {
		out = append(out, r.GetProxyId()+"->"+r.GetBackend())
	}
	return out
}

func socksPorts(cfg *edgev1.EdgeConfig) []uint32 {
	var out []uint32
	for _, s := range cfg.GetSocks() {
		out = append(out, s.GetPort())
	}
	return out
}

func addr(port uint16) string { return "127.0.0.1:" + strconv.Itoa(int(port)) }
