package diagnostics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/panel/geodb"
	"github.com/urbnywrt/postern/internal/panel/probes"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// fakeNode is a node's agent that answers RunDiagnostics with its results,
// and then, when hold is set, waits for it to close (or for the call to end);
// the call ends with err.
type fakeNode struct {
	nodev1connect.UnimplementedNodeServiceHandler

	mu      sync.Mutex
	results []*nodev1.DiagnosticResult
	hold    chan struct{}
	err     error
	scopes  []string
	started chan struct{} // gets a value when a call starts
}

func (f *fakeNode) RunDiagnostics(ctx context.Context, req *connect.Request[nodev1.RunDiagnosticsRequest], s *connect.ServerStream[nodev1.DiagnosticResult]) error {
	f.mu.Lock()
	f.scopes = append(f.scopes, req.Msg.GetScope())
	results, hold := f.results, f.hold
	f.mu.Unlock()
	if f.started != nil {
		select {
		case f.started <- struct{}{}:
		default:
		}
	}
	for _, r := range results {
		if err := s.Send(r); err != nil {
			return err
		}
	}
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return f.err
}

func (f *fakeNode) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.scopes...)
}

// clients gives the client of each node that has a fake agent.
type clients struct {
	mu sync.Mutex
	by map[string]nodev1connect.NodeServiceClient
}

func (c *clients) Client(id string) (nodev1connect.NodeServiceClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.by[id]; ok {
		return cl, nil
	}
	return nil, errors.New("not connected")
}

// fakeProber answers the probes of proxies by id.
type fakeProber struct {
	mu    sync.Mutex
	by    map[string]proberAnswer
	paths map[string]basePathAnswer
	calls int
}

type proberAnswer struct {
	p   store.Probe
	l1  bool
	err error
}

// CheckBasePath answers web.base_path from paths (ErrNotProbeable without).
func (f *fakeProber) CheckBasePath(_ context.Context, id string) (probes.BasePath, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.paths[id]
	if !ok {
		return probes.BasePath{}, probes.ErrNotProbeable
	}
	return a.bp, a.err
}

type basePathAnswer struct {
	bp  probes.BasePath
	err error
}

func (f *fakeProber) Probe(_ context.Context, id string) (store.Probe, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	a, ok := f.by[id]
	if !ok {
		return store.Probe{}, false, probes.ErrNotProbeable
	}
	return a.p, a.l1, a.err
}

// fakeResolver resolves names from a table.
type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("lookup " + host + ": no such host")
}

type env struct {
	t       *testing.T
	ctx     context.Context
	db      *store.DB
	dbPath  string
	clients *clients
	prober  *fakeProber
	res     fakeResolver
	geo     geodb.Status
	now     time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &env{t: t, ctx: context.Background(), db: db, dbPath: path,
		clients: &clients{by: map[string]nodev1connect.NodeServiceClient{}},
		prober:  &fakeProber{by: map[string]proberAnswer{}},
		res:     fakeResolver{},
		geo:     geodb.Status{Enabled: true, Present: true, Month: "2026-10", Built: time.Now().Add(-24 * time.Hour)},
		now:     time.Now(),
	}
}

func (e *env) runner(timeout time.Duration) *Runner {
	r := NewRunner(Config{DB: e.db, Nodes: e.clients, Probes: e.prober, Resolver: e.res,
		GeoIP: func(context.Context) (geodb.Status, error) { return e.geo, nil },
		Now:   func() time.Time { return e.now }, RunTimeout: timeout})
	e.t.Cleanup(r.Drain)
	return r
}

// node stores an online node with the capability diagnostics, its public IP
// 198.51.100.5 as its link host, and the same version of agent and edge.
func (e *env) node(change func(*store.Node)) *store.Node {
	e.t.Helper()
	n := &store.Node{Name: "n-" + ids.New()[:6], MgmtHost: "198.51.100.1", MgmtPort: 61000, LinkHost: "198.51.100.5",
		Status: store.NodeStatusOnline, AgentVersion: "1.2.0", EdgeVersion: "1.2.0", PublicIPs: []string{"198.51.100.5"},
		HostInfo: store.HostInfo{Capabilities: []string{"diagnostics", "restart-nonce"}}}
	if change != nil {
		change(n)
	}
	if err := e.db.CreateNode(e.ctx, n); err != nil {
		e.t.Fatal(err)
	}
	got, err := e.db.NodeByID(e.ctx, n.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	// CreateNode does not write every column: UpdateNode writes the rest.
	got.Status, got.HostInfo, got.AgentVersion, got.EdgeVersion, got.PublicIPs = n.Status, n.HostInfo, n.AgentVersion, n.EdgeVersion, n.PublicIPs
	got.LastError, got.StateRejection = n.LastError, n.StateRejection
	if err := e.db.UpdateNode(e.ctx, got); err != nil {
		e.t.Fatal(err)
	}
	return got
}

// agent gives the node a fake agent.
func (e *env) agent(nodeID string, f *fakeNode) {
	e.t.Helper()
	mux := http.NewServeMux()
	mux.Handle(nodev1connect.NewNodeServiceHandler(f))
	srv := httptest.NewServer(mux)
	e.t.Cleanup(srv.Close)
	e.clients.mu.Lock()
	e.clients.by[nodeID] = nodev1connect.NewNodeServiceClient(srv.Client(), srv.URL)
	e.clients.mu.Unlock()
}

func (e *env) listener(nodeID string, port uint32, linkHost string) *store.Listener {
	e.t.Helper()
	l := &store.Listener{NodeID: nodeID, BindIP: "0.0.0.0", Port: port, LinkHostOverride: linkHost}
	if err := e.db.CreateListener(e.ctx, l); err != nil {
		e.t.Fatal(err)
	}
	return l
}

func (e *env) proxy(l *store.Listener, change func(*store.Proxy)) *store.Proxy {
	e.t.Helper()
	p := &store.Proxy{ID: ids.New(), NodeID: l.NodeID, ListenerID: l.ID, Type: store.ProxyTypeFakeTLS, Name: "p", Enabled: true,
		Domain: "www.example.com", SecretEnc: []byte("sealed")}
	if change != nil {
		change(p)
	}
	if err := e.db.CreateProxy(e.ctx, p); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func nodeResult(id, target string, st nodev1.CheckStatus, evidence string) *nodev1.DiagnosticResult {
	return &nodev1.DiagnosticResult{Id: id, Layer: "host", Target: target, Status: st, Summary: id + " summary",
		Evidence: evidence, CheckedUnix: 1_790_000_000, DurationMs: 3}
}

// wait waits for a run to end.
func (e *env) wait(r *Runner, id string) *store.DiagnosticRun {
	e.t.Helper()
	return e.waitWithin(r, id, 10*time.Second)
}

// waitWithin waits for a run for at most d.
func (e *env) waitWithin(r *Runner, id string, d time.Duration) *store.DiagnosticRun {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(e.ctx, d)
	defer cancel()
	run, err := r.Wait(ctx, id)
	if err != nil {
		e.t.Fatalf("Wait: %v", err)
	}
	return run
}

// ids of the results, as "id target status vantage".
func summary(run *store.DiagnosticRun) []string {
	out := make([]string, 0, len(run.Results))
	for _, x := range run.Results {
		out = append(out, x.CheckID+" "+x.Target+" "+x.Status+" "+x.Vantage)
	}
	return out
}

func events(t *testing.T, db *store.DB, kind string) []*store.Event {
	t.Helper()
	all, err := db.ListEvents(context.Background(), 1000, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []*store.Event
	for _, e := range all {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}
