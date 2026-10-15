package rollout

import (
	"cmp"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
)

const (
	fromVersion = "3.5.12"
	toVersion   = "3.5.13"
)

// fakeClock is the clock of the runner and the executor.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeWriter is the locked write path of the proxies service: it runs the
// write, raises the generations of the nodes it names and records them.
type fakeWriter struct {
	db       *store.DB
	mu       sync.Mutex
	notified []string
	channels []string
	// crash makes every write fail after it was stored: the panel stopped
	// right after the write.
	crash bool
}

func (w *fakeWriter) WriteVersions(ctx context.Context, write func(ctx context.Context) ([]string, error)) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	ids, err := write(ctx)
	if err != nil {
		return err
	}
	if w.crash {
		return errors.New("the panel stopped")
	}
	for _, id := range slices.Compact(slices.Sorted(slices.Values(ids))) {
		if _, err := w.db.NextNodeGeneration(ctx, id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return err
		}
		w.notified = append(w.notified, id)
	}
	return nil
}

func (w *fakeWriter) NotifyChannel(_ context.Context, component, channel string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.channels = append(w.channels, component+"/"+channel)
	return nil
}

// fakeCatalog answers for the releases.
type fakeCatalog struct {
	mu         sync.Mutex
	notIn      bool
	noPin      map[string]bool
	prepareErr error
	prepared   [][]string
}

func (c *fakeCatalog) InChannel(context.Context, string, string, string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.notIn, nil
}

func (c *fakeCatalog) Ref(_ context.Context, component, version, arch string) (*nodev1.ArtifactRef, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.noPin[arch] {
		return nil, releases.ErrNoPin
	}
	return &nodev1.ArtifactRef{Engine: component, Version: version, Arch: arch, Sha256: "00"}, nil
}

func (c *fakeCatalog) Prepare(_ context.Context, _, _ string, archs []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prepared = append(c.prepared, archs)
	return c.prepareErr
}

// fakeReports are the reports of the proxies.
type fakeReports struct {
	mu sync.Mutex
	m  map[[2]string]proxies.ProxyReport
	eg map[string][]proxies.EgressReport
}

func (r *fakeReports) ProxyReport(nodeID, proxyID string) (proxies.ProxyReport, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rep, ok := r.m[[2]string{nodeID, proxyID}]
	return rep, ok
}

func (r *fakeReports) EgressReports(nodeID string) []proxies.EgressReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.eg[nodeID])
}

func (r *fakeReports) setEgress(nodeID string, reps []proxies.EgressReport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eg[nodeID] = reps
}

func (r *fakeReports) set(nodeID, proxyID string, rep proxies.ProxyReport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[[2]string{nodeID, proxyID}] = rep
}

// behaviour is how a fake node takes its states.
type behaviour int

const (
	healthy   behaviour = iota // applies every state and serves what it says
	failing                    // applies, but the target fails its trial: the old version keeps serving
	rejecting                  // refuses every state
	silent                     // does nothing
)

type fixture struct {
	t           *testing.T
	ctx         context.Context
	db          *store.DB
	clock       *fakeClock
	writer      *fakeWriter
	catalog     *fakeCatalog
	reports     *fakeReports
	exec        *EngineVersions
	runner      *Runner
	nodes       map[string]*store.Node  // by name
	proxies     map[string]*store.Proxy // by name
	hooks       Hooks
	checker     *fakeChecker
	provs       map[string][]string // by node id: the providers it runs
	hookTimeout time.Duration
	stop        func()
	mu          sync.Mutex
	behave      map[string]behaviour // by node id
	rejected    map[string]uint64    // the last generation a rejecting node refused
}

// newFixture makes nodes with proxies: layout maps a node name to the names of
// its proxies. Every node is online, amd64, with rollout-status; every proxy is
// on telemt, enabled, following the stable channel at fromVersion.
func newFixture(t *testing.T, layout map[string][]string) *fixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := &fixture{
		t: t, ctx: ctx, db: db, clock: &fakeClock{t: time.Now().Truncate(time.Second)}, // the store stamps finished_at with the real clock
		writer: &fakeWriter{db: db}, catalog: &fakeCatalog{noPin: map[string]bool{}},
		reports: &fakeReports{m: map[[2]string]proxies.ProxyReport{}, eg: map[string][]proxies.EgressReport{}},
		checker: &fakeChecker{refuse: map[string]string{}}, provs: map[string][]string{},
		nodes: map[string]*store.Node{}, proxies: map[string]*store.Proxy{},
		behave: map[string]behaviour{}, rejected: map[string]uint64{},
	}
	if err := db.SetChannelVersion(ctx, store.EngineTelemt, store.ChannelStable, fromVersion); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(layout))
	for name := range layout {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		seen := f.clock.Now()
		n := &store.Node{Name: name, Status: store.NodeStatusOnline, Arch: "amd64", LastSeenAt: &seen,
			HostInfo: store.HostInfo{Capabilities: []string{CapRolloutStatus}}}
		if err := db.CreateNode(ctx, n); err != nil {
			t.Fatalf("CreateNode: %v", err)
		}
		f.nodes[name] = n
		l := &store.Listener{NodeID: n.ID, Port: 443}
		if err := db.CreateListener(ctx, l); err != nil {
			t.Fatalf("CreateListener: %v", err)
		}
		for _, pn := range layout[name] {
			p := &store.Proxy{NodeID: n.ID, ListenerID: l.ID, Name: pn, SecretEnc: []byte("sealed"), Enabled: true}
			if err := db.CreateProxy(ctx, p); err != nil {
				t.Fatalf("CreateProxy: %v", err)
			}
			f.proxies[pn] = p
		}
	}
	return f
}

// fiveProxies is three nodes and five proxies.
func fiveProxies() map[string][]string {
	return map[string][]string{"A": {"a1", "a2"}, "B": {"b1", "b2"}, "C": {"c1"}}
}

// start makes the runner, with the hooks of the fixture, and runs it.
func (f *fixture) start() {
	f.build()
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.runner.Run(ctx)
	}()
	stop := sync.OnceFunc(func() {
		cancel()
		<-done
	})
	f.stop = stop
	f.t.Cleanup(stop)
}

// restart stops the runner and runs a new one, as a restart of the panel.
func (f *fixture) restart() {
	f.stop()
	f.runner = nil
	f.start()
}

// build makes the runner without running it.
func (f *fixture) build() {
	if f.runner != nil {
		return
	}
	deps := EngineConfig{DB: f.db, Catalog: f.catalog, Reports: f.reports, Writer: f.writer, Now: f.clock.Now}
	f.exec = NewEngineVersions(deps)
	f.runner = NewRunner(Config{
		DB: f.db, Executors: map[string]Executor{
			KeyEngineVersion:   f.exec,
			KeySwitch:          NewSwitch(deps, f.checker),
			KeyProviderVersion: NewProviderVersions(deps, f, f.reports),
		}, Hooks: f.hooks,
		Now: f.clock.Now, Tick: time.Millisecond, HookTimeout: f.hookTimeout,
	})
}

func (f *fixture) set(node string, b behaviour) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.behave[f.nodes[node].ID] = b
}

// request is a version rollout of telemt stable to toVersion.
func request(mode string) *Request {
	return &Request{Kind: store.RolloutVersion, Component: store.EngineTelemt, Channel: store.ChannelStable, ToVersion: toVersion, Mode: mode}
}

func (f *fixture) startRollout(req *Request) *store.Rollout {
	f.t.Helper()
	f.build()
	ro, err := f.runner.Start(f.ctx, "admin1", req)
	if err != nil {
		f.t.Fatalf("Start: %v", err)
	}
	return ro
}

// sync plays the nodes: each does with its desired state what its behaviour
// says.
func (f *fixture) sync() {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.nodes {
		b := f.behave[n.ID]
		if b == silent {
			continue
		}
		cur, err := f.db.NodeByID(f.ctx, n.ID)
		if err != nil {
			f.t.Fatalf("NodeByID: %v", err)
		}
		if b == rejecting {
			if cur.DesiredGeneration > f.rejected[n.ID] {
				f.rejected[n.ID] = cur.DesiredGeneration
				f.reject(n.ID, cur.DesiredGeneration)
			}
			continue
		}
		if cur.AppliedGeneration < cur.DesiredGeneration {
			if _, err := f.db.ModifyNode(f.ctx, n.ID, func(m *store.Node) error {
				m.AppliedGeneration = m.DesiredGeneration
				return nil
			}); err != nil {
				f.t.Fatalf("ModifyNode: %v", err)
			}
		}
		ps, err := f.db.ListProxies(f.ctx, store.ProxyFilter{NodeID: n.ID})
		if err != nil {
			f.t.Fatal(err)
		}
		chans, err := f.db.ChannelVersions(f.ctx)
		if err != nil {
			f.t.Fatal(err)
		}
		for _, p := range ps {
			engine := cmp.Or(p.Engine, store.EngineTelemt)
			want := chans[engine][store.ChannelStable]
			if p.EngineVersionPolicy != store.EnginePolicyChannel && p.EngineVersion != "" {
				want = p.EngineVersion
			}
			rep := proxies.ProxyReport{Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, RunningEngine: engineEnum(engine),
				RunningVersion: want, ReportGeneration: cur.DesiredGeneration}
			if b == failing && p.EngineVersionPolicy == store.EnginePolicyRollout {
				// The blue-green kept the old instance: what the item held.
				rep.RunningEngine, rep.RunningVersion = nodev1.Engine_ENGINE_TELEMT, fromVersion
				rep.FailedEngine, rep.FailedVersion, rep.Reason = engineEnum(engine), want, "the trial of the binary failed"
			}
			f.reports.set(n.ID, p.ID, rep)
		}
		var egress []proxies.EgressReport
		for _, comp := range f.provs[n.ID] {
			want := cmp.Or(cur.ProviderVersions[comp], chans[comp][store.ChannelStable])
			rep := proxies.EgressReport{EgressID: "e-" + comp, Provider: comp, Version: want, Phase: phaseServing, ReportGeneration: cur.DesiredGeneration}
			if b == failing && cur.ProviderVersions[comp] != "" {
				rep.Version, rep.FailedVersion, rep.Reason = chans[comp][store.ChannelStable], want, "the trial of the binary failed"
			}
			egress = append(egress, rep)
		}
		f.reports.setEgress(n.ID, egress)
	}
}

func engineEnum(engine string) nodev1.Engine {
	if engine == store.EngineMtg {
		return nodev1.Engine_ENGINE_MTG
	}
	return nodev1.Engine_ENGINE_TELEMT
}

// fakeChecker refuses the proxies it names, with the reason given.
type fakeChecker struct {
	mu     sync.Mutex
	refuse map[string]string
}

func (c *fakeChecker) CheckEngineSwitch(_ context.Context, _ string, proxyIDs []string, _, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range proxyIDs {
		if why := c.refuse[id]; why != "" {
			return connect.NewError(connect.CodeFailedPrecondition, errors.New(why))
		}
	}
	return nil
}

// NodeProviders is what the fixture says each node runs.
func (f *fixture) NodeProviders(_ context.Context, nodeID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.provs[nodeID]), nil
}

// reject has a node refuse the state of a generation, as the node manager
// records it.
func (f *fixture) reject(nodeID string, gen uint64) {
	if _, err := f.db.ModifyNode(f.ctx, nodeID, func(m *store.Node) error {
		m.StateRejection = "bad state"
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	if err := f.db.AppendEvent(f.ctx, &store.Event{NodeID: nodeID, Kind: eventStateRejected, Severity: "warning",
		Message: "bad state", Details: map[string]string{"generation": strconv.FormatUint(gen, 10)}}); err != nil {
		f.t.Fatal(err)
	}
}

// until plays the nodes until cond holds. The bound is generous: what must
// happen takes far less, but a runner that runs the whole suite with -race
// can take more than ten seconds for it.
func (f *fixture) until(what string, cond func() bool) {
	f.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		f.sync()
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	f.t.Fatalf("timed out waiting for %s", what)
}

// settle plays the nodes for a while, for what must not happen.
func (f *fixture) settle() {
	f.t.Helper()
	for range 30 {
		f.sync()
		time.Sleep(2 * time.Millisecond)
	}
}

func (f *fixture) load(id string) (*store.Rollout, []store.RolloutStep, []store.RolloutItem) {
	f.t.Helper()
	ro, steps, items, err := f.db.Rollout(f.ctx, id)
	if err != nil {
		f.t.Fatalf("Rollout: %v", err)
	}
	return ro, steps, items
}

func (f *fixture) status(id string) string {
	ro, _, _ := f.load(id)
	return ro.Status
}

func (f *fixture) step(id string, i int) store.RolloutStep {
	_, steps, _ := f.load(id)
	return steps[i]
}

// waitStatus waits for a rollout status (and current step, when ≥ 0).
func (f *fixture) waitStatus(id, status string, step int) {
	f.t.Helper()
	f.until(status+" at step "+strconv.Itoa(step), func() bool {
		ro, _, _ := f.load(id)
		return ro.Status == status && (step < 0 || int(ro.CurrentStep) == step)
	})
}

func (f *fixture) proxy(name string) *store.Proxy {
	f.t.Helper()
	p, err := f.db.ProxyByID(f.ctx, f.proxies[name].ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

// holds checks the engine policy and version of proxies.
func (f *fixture) holds(policy, version string, names ...string) {
	f.t.Helper()
	for _, n := range names {
		p := f.proxy(n)
		if p.EngineVersionPolicy != policy || p.EngineVersion != version {
			f.t.Errorf("proxy %s holds %s %q, want %s %q", n, p.EngineVersionPolicy, p.EngineVersion, policy, version)
		}
	}
}

func (f *fixture) events(kind string) []*store.Event {
	f.t.Helper()
	evs, err := f.db.ListEvents(f.ctx, 500, "")
	if err != nil {
		f.t.Fatal(err)
	}
	var out []*store.Event
	for _, e := range evs {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func (f *fixture) channelVersion() string {
	f.t.Helper()
	v, err := f.db.ChannelVersions(f.ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	return v[store.EngineTelemt][store.ChannelStable]
}

// runManual continues a manual rollout until it is completed or failed.
func (f *fixture) runManual(id string) string {
	f.t.Helper()
	var last string
	f.until("the rollout to stop", func() bool {
		ro, _, _ := f.load(id)
		switch ro.Status {
		case store.RolloutPaused:
			if err := f.runner.Continue(f.ctx, id); err != nil {
				f.t.Fatalf("Continue: %v", err)
			}
		case store.RolloutCompleted:
			last = ro.Status
			return f.completed()
		case store.RolloutFailed:
			last = ro.Status
			return len(f.events(EventFailed)) > 0 // recorded after the status
		}
		return false
	})
	return last
}

// completed reports whether the runner is through with completing: its
// event is the last thing it does.
func (f *fixture) completed() bool {
	return len(f.events(EventCompleted)) > 0
}
