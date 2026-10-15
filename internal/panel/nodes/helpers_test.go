package nodes

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
	"github.com/urbnywrt/postern/internal/seal"
)

// waitTimeout bounds every wait of these tests, so that a regression is a
// failure and not a hang.
const waitTimeout = 10 * time.Second

// testProxySecret is the proxy secret in the states that the tests push. It
// must never show up in a log.
const testProxySecret = "0123456789abcdef0123456789abcdef" // gitleaks:allow (a made-up test value)

// testTiming makes the connection manager quick enough for tests.
var testTiming = timing{
	minBackoff:     5 * time.Millisecond,
	maxBackoff:     50 * time.Millisecond,
	offlineAfter:   150 * time.Millisecond,
	stableAfter:    time.Second,
	dialTimeout:    2 * time.Second,
	callTimeout:    5 * time.Second,
	resyncEvery:    time.Hour,
	ingestAttempts: 3,
	switchTimeout:  5 * time.Second,
	switchPoll:     2 * time.Millisecond,
}

// waitFor polls cond until it holds and fails the test if it does not within
// waitTimeout.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// lockedBuffer is a bytes.Buffer that goroutines may write at the same time:
// the log of a test.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// testPanel is the part of a panel that the nodes package uses: a database,
// a master key, the CA, a log and the node service.
type testPanel struct {
	t      *testing.T
	db     *store.DB
	dbPath string
	key    seal.Key
	ca     *pki.CA
	logs   *lockedBuffer
	log    *slog.Logger
	svc    *Service
}

func newTestPanel(t *testing.T) *testPanel {
	t.Helper()
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	p := &testPanel{t: t, db: db, dbPath: path, logs: &lockedBuffer{}}
	if _, err := rand.Read(p.key[:]); err != nil {
		t.Fatal(err)
	}
	p.log = slog.New(slog.NewTextHandler(p.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("panel log:\n%s", p.logs.String())
		}
	})
	p.ca, err = LoadOrCreateCA(context.Background(), db, p.key)
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	p.svc = NewService(db, p.key, p.ca, nil, p.log)
	return p
}

// newManager is a connection manager on the panel with the quick timing of
// the tests. It is closed when the test ends.
func (p *testPanel) newManager() *Manager {
	p.t.Helper()
	m := NewManager(p.db, p.key, p.ca, p.log)
	m.cfg = testTiming
	p.t.Cleanup(m.Close)
	return m
}

// addNode creates a node whose agent is f, and has f serve the bundle of the
// node.
func (p *testPanel) addNode(name string, f *fakeNode) *store.Node {
	p.t.Helper()
	n := p.createNode(name, f.port())
	f.serve(p.bundle(n.ID))
	return n
}

// createNode creates a node on 127.0.0.1 and a port, as CreateNode does.
func (p *testPanel) createNode(name string, port uint32) *store.Node {
	p.t.Helper()
	n, err := p.svc.createNode(context.Background(), &panelv1.CreateNodeRequest{
		Name:     name,
		MgmtHost: "127.0.0.1",
		MgmtPort: port,
		LinkHost: "203.0.113.10",
	})
	if err != nil {
		p.t.Fatalf("createNode: %v", err)
	}
	return n
}

// bundle is the bundle that an admin would download for a node.
func (p *testPanel) bundle(id string) *pki.Bundle {
	p.t.Helper()
	b, err := p.svc.bundle(context.Background(), id)
	if err != nil {
		p.t.Fatalf("bundle: %v", err)
	}
	return b
}

// node reads a node from the database.
func (p *testPanel) node(id string) *store.Node {
	p.t.Helper()
	n, err := p.db.NodeByID(context.Background(), id)
	if err != nil {
		p.t.Fatalf("NodeByID: %v", err)
	}
	return n
}

// modify changes a node in the database, as an admin or a bug would.
func (p *testPanel) modify(id string, fn func(*store.Node)) {
	p.t.Helper()
	_, err := p.db.ModifyNode(context.Background(), id, func(n *store.Node) error {
		fn(n)
		return nil
	})
	if err != nil {
		p.t.Fatalf("ModifyNode: %v", err)
	}
}

// bump raises the desired generation of a node n times, as mutators do.
func (p *testPanel) bump(id string, n int) uint64 {
	p.t.Helper()
	var gen uint64
	for range n {
		var err error
		if gen, err = p.db.NextNodeGeneration(context.Background(), id); err != nil {
			p.t.Fatalf("NextNodeGeneration: %v", err)
		}
	}
	return gen
}

// waitStatus waits until the stored status of a node is want.
func (p *testPanel) waitStatus(id, want string) {
	p.t.Helper()
	waitFor(p.t, "node status "+want, func() bool { return p.node(id).Status == want })
}

// events returns the kinds of the events of a node, oldest first.
func (p *testPanel) eventKinds(id string) []string {
	p.t.Helper()
	evs, err := p.db.ListEvents(context.Background(), 1000, id)
	if err != nil {
		p.t.Fatalf("ListEvents: %v", err)
	}
	kinds := make([]string, 0, len(evs))
	for i := len(evs) - 1; i >= 0; i-- {
		kinds = append(kinds, evs[i].Kind)
	}
	return kinds
}

// cheapHash is the argon2id hash of a password at the smallest cost that
// passwd.Verify accepts, so that signing in costs a test nothing.
func cheapHash(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	key := argon2.IDKey([]byte(password), salt, 1, 8, 1, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=8,t=1,p=1$%s$%s", argon2.Version, enc.EncodeToString(salt), enc.EncodeToString(key))
}

// trace is the order in which things happened, across goroutines.
type trace struct {
	mu    sync.Mutex
	steps []string
}

func (tr *trace) add(step string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.steps = append(tr.steps, step)
}

func (tr *trace) get() []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]string(nil), tr.steps...)
}

// fakeBuilder is a StateBuilder: a state with one proxy and its secret.
type fakeBuilder struct {
	mu    sync.Mutex
	calls []uint64
	err   error
}

func (b *fakeBuilder) Build(_ context.Context, nodeID string, generation uint64) (*nodev1.NodeState, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, generation)
	if b.err != nil {
		return nil, b.err
	}
	return &nodev1.NodeState{
		Generation: generation,
		Proxies: []*nodev1.Proxy{{
			Id:      "proxy-of-" + nodeID,
			Enabled: true,
			Secret:  testProxySecret,
			Domain:  "cdn.example.com",
		}},
	}, nil
}

func (b *fakeBuilder) generations() []uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]uint64(nil), b.calls...)
}

func (b *fakeBuilder) setErr(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.err = err
}

// fakeEnsurer is an ArtifactEnsurer that notes what it was asked.
type fakeEnsurer struct {
	trace *trace

	mu     sync.Mutex
	agents []string // the agent version in the info that it was given, per call
	err    error
}

func (e *fakeEnsurer) EnsureArtifacts(_ context.Context, _ string, info *nodev1.GetInfoResponse, state *nodev1.NodeState, client nodev1connect.NodeServiceClient) error {
	if client == nil {
		return errors.New("no client")
	}
	e.trace.add("ensure:" + strconv.FormatUint(state.GetGeneration(), 10))
	e.mu.Lock()
	defer e.mu.Unlock()
	e.agents = append(e.agents, info.GetAgentVersion())
	return e.err
}

func (e *fakeEnsurer) agentVersions() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.agents...)
}

func (e *fakeEnsurer) setErr(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.err = err
}

// ingested is one record that an ingestor was given.
type ingested struct {
	nodeID string
	seq    uint64
	kind   string
}

// recordingIngestor is an Ingestor that notes what it was given, and the nodes
// it was told to forget. fail, when set, decides whether a call fails.
type recordingIngestor struct {
	mu        sync.Mutex
	got       []ingested
	fail      func(ev *nodev1.WatchResponse, attempt int) error
	seen      map[uint64]int
	forgotten []string
}

func (r *recordingIngestor) ForgetNode(nodeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forgotten = append(r.forgotten, nodeID)
}

// forgot reports whether the ingestor was told to forget the node.
func (r *recordingIngestor) forgot(nodeID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.forgotten, nodeID)
}

func (r *recordingIngestor) OnWatch(_ context.Context, nodeID string, ev *nodev1.WatchResponse) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[uint64]int{}
	}
	r.seen[ev.GetSeq()]++
	r.got = append(r.got, ingested{nodeID: nodeID, seq: ev.GetSeq(), kind: recordKind(ev)})
	if r.fail != nil {
		return r.fail(ev, r.seen[ev.GetSeq()])
	}
	return nil
}

func (r *recordingIngestor) records() []ingested {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ingested(nil), r.got...)
}

// seqs returns the sequence numbers of the records, in the order given.
func (r *recordingIngestor) seqs() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]uint64, 0, len(r.got))
	for _, g := range r.got {
		out = append(out, g.seq)
	}
	return out
}

// attempts is how many times the record with this sequence number was given.
func (r *recordingIngestor) attempts(seq uint64) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen[seq]
}

// recordKind names the payload of a record, for the assertions of the tests.
func recordKind(ev *nodev1.WatchResponse) string {
	switch {
	case ev.GetState() != nil:
		return "state"
	case ev.GetStats() != nil:
		return "stats"
	case ev.GetEvent() != nil:
		return "event"
	}
	return "unknown"
}

// fakeNode is the agent of a node: NodeService over HTTP/2 and mTLS on a port
// of 127.0.0.1 that it holds for the whole test. It behaves like the agent
// where the panel can tell: ApplyState refuses generations it already has, and
// Watch replays the records after the cursor and then streams new ones.
//
// While it is down, it accepts connections and closes them at once, and it
// drops those it had.
type fakeNode struct {
	t     *testing.T
	ln    net.Listener
	inner *chanListener
	srv   *http.Server
	trace *trace

	dials atomic.Int32 // connections accepted, up or down

	mu         sync.Mutex
	up         bool
	serving    bool
	conns      map[net.Conn]struct{}
	info       *nodev1.GetInfoResponse
	desired    uint64 // the generation that the node accepted last
	applied    uint64
	applies    []uint64 // the generation of every ApplyState call
	rejectNext int      // ApplyState calls to reject, after the stale check
	getInfos   int
	cursors    []uint64          // the cursor of every Watch call
	policies   []nodev1.IpPolicy // the IP policy of every Watch call
	records    []*nodev1.WatchResponse
	seq        uint64
	wake       chan struct{} // closed when a record is added
	drop       chan struct{} // closed to end the Watch streams
	hidden     *fakeHidden   // hidden management, see enableHidden; nil without
}

func newFakeNode(t *testing.T, tr *trace) *fakeNode {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeNode{
		t:     t,
		ln:    ln,
		inner: &chanListener{addr: ln.Addr(), conns: make(chan net.Conn), done: make(chan struct{})},
		trace: tr,
		conns: map[net.Conn]struct{}{},
		info: &nodev1.GetInfoResponse{
			AgentVersion: "1.2.3",
			EdgeVersion:  "1.2.3",
			Arch:         "amd64",
			Os:           "Debian GNU/Linux 13 (trixie)",
			PublicIps:    []string{"203.0.113.10", "2001:db8::10"},
		},
		wake: make(chan struct{}),
		drop: make(chan struct{}),
	}
	if f.trace == nil {
		f.trace = &trace{}
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		f.acceptLoop()
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		f.mu.Lock()
		srv := f.srv
		f.mu.Unlock()
		if srv != nil {
			_ = srv.Close()
		}
		_ = f.inner.Close()
		f.closeConns()
		wg.Wait()
	})
	return f
}

func (f *fakeNode) port() uint32 {
	return uint32(f.ln.Addr().(*net.TCPAddr).Port)
}

// serve starts serving with the credentials of a bundle, and brings the node
// up.
func (f *fakeNode) serve(b *pki.Bundle) {
	f.t.Helper()
	cfg, err := pki.ServerTLSConfig(b.CAPEM, b.CertPEM, b.KeyPEM)
	if err != nil {
		f.t.Fatalf("ServerTLSConfig: %v", err)
	}
	cfg.NextProtos = []string{"h2"}
	cfg.GetConfigForClient = f.checkSNI
	path, handler := nodev1connect.NewNodeServiceHandler(f)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := &http.Server{
		Handler:           mux,
		TLSConfig:         cfg,
		ReadHeaderTimeout: waitTimeout,
		ErrorLog:          log.New(io.Discard, "", 0), // handshakes that tests make fail
	}
	f.mu.Lock()
	if f.serving {
		f.mu.Unlock()
		f.t.Fatal("the fake node serves already")
	}
	f.srv, f.serving, f.up = srv, true, true
	f.mu.Unlock()
	go func() { _ = srv.ServeTLS(f.inner, "", "") }()
}

// down makes the node unreachable: open connections are closed, and new ones
// are closed as soon as they are accepted.
func (f *fakeNode) down() {
	f.mu.Lock()
	f.up = false
	f.mu.Unlock()
	f.closeConns()
}

// back brings the node up again.
func (f *fakeNode) back() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.up = true
}

func (f *fakeNode) closeConns() {
	f.mu.Lock()
	conns := make([]net.Conn, 0, len(f.conns))
	for c := range f.conns {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (f *fakeNode) acceptLoop() {
	for {
		raw, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.dials.Add(1)
		c := &trackedConn{Conn: raw, f: f}
		f.mu.Lock()
		up := f.up && f.serving && (f.hidden == nil || !f.hidden.plainClosed)
		if up {
			f.conns[c] = struct{}{}
		}
		f.mu.Unlock()
		if !up {
			_ = raw.Close()
			continue
		}
		select {
		case f.inner.conns <- c:
		case <-f.inner.done:
			_ = c.Close()
			return
		}
	}
}

// trackedConn is a connection of the fake node that leaves the set of open
// connections when it is closed.
type trackedConn struct {
	net.Conn
	f    *fakeNode
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.f.mu.Lock()
		delete(c.f.conns, c)
		c.f.mu.Unlock()
	})
	return c.Conn.Close()
}

// openConns is the number of connections that the node holds open.
func (f *fakeNode) openConns() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.conns)
}

// setGenerations sets what the node says it has: the generation it accepted
// last and the one it applied.
func (f *fakeNode) setGenerations(desired, applied uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.desired, f.applied = desired, applied
}

func (f *fakeNode) setInfo(info *nodev1.GetInfoResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.info = info
}

func (f *fakeNode) setRejectNext(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejectNext = n
}

func (f *fakeNode) acceptedGeneration() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.desired
}

func (f *fakeNode) applyCalls() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.applies...)
}

func (f *fakeNode) getInfoCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getInfos
}

func (f *fakeNode) watchCursors() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.cursors...)
}

// emit adds a record to the buffer of the node and returns its sequence
// number. Watch streams send it at once.
func (f *fakeNode) emit(ev *nodev1.WatchResponse) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.emitLocked(ev)
}

// emitLocked is emit with f.mu held.
func (f *fakeNode) emitLocked(ev *nodev1.WatchResponse) uint64 {
	f.seq++
	ev.Seq = f.seq
	ev.TsUnix = time.Now().Unix()
	f.records = append(f.records, ev)
	close(f.wake)
	f.wake = make(chan struct{})
	return f.seq
}

// dropWatch ends the Watch streams that are open, as an agent that restarts
// its stream would.
func (f *fakeNode) dropWatch() {
	f.mu.Lock()
	defer f.mu.Unlock()
	close(f.drop)
	f.drop = make(chan struct{})
}

func stateRecord(applied uint64) *nodev1.WatchResponse {
	return &nodev1.WatchResponse{Payload: &nodev1.WatchResponse_State{State: &nodev1.StateReport{AppliedGeneration: applied}}}
}

func statsRecord() *nodev1.WatchResponse {
	return &nodev1.WatchResponse{Payload: &nodev1.WatchResponse_Stats{Stats: &nodev1.StatsBatch{
		MinuteUnix: time.Now().Truncate(time.Minute).Unix(),
		Node:       &nodev1.NodeMinute{Cpu: 0.5, Conns: 3},
	}}}
}

func eventRecord(kind string) *nodev1.WatchResponse {
	return &nodev1.WatchResponse{Payload: &nodev1.WatchResponse_Event{Event: &nodev1.NodeEvent{
		Kind: kind, Severity: "info", Message: "something happened",
	}}}
}

func (f *fakeNode) GetInfo(context.Context, *connect.Request[nodev1.GetInfoRequest]) (*connect.Response[nodev1.GetInfoResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getInfos++
	info := proto.Clone(f.info).(*nodev1.GetInfoResponse)
	info.DesiredGeneration, info.AppliedGeneration = f.desired, f.applied
	return connect.NewResponse(info), nil
}

func (f *fakeNode) ApplyState(_ context.Context, req *connect.Request[nodev1.ApplyStateRequest]) (*connect.Response[nodev1.ApplyStateResponse], error) {
	gen := req.Msg.GetState().GetGeneration()
	f.trace.add("apply:" + strconv.FormatUint(gen, 10))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies = append(f.applies, gen)
	switch {
	case gen <= f.desired:
		return connect.NewResponse(&nodev1.ApplyStateResponse{Reason: "stale generation", Generation: f.desired}), nil
	case f.rejectNext > 0:
		f.rejectNext--
		return connect.NewResponse(&nodev1.ApplyStateResponse{Reason: "listener l1: port 70000 is out of range", Generation: f.desired}), nil
	}
	f.desired = gen
	if f.hidden != nil {
		f.hidden.take(req.Msg.GetState().GetSettings())
		f.applied = gen
		f.emitLocked(stateRecord(gen))
	}
	return connect.NewResponse(&nodev1.ApplyStateResponse{Accepted: true, Generation: gen}), nil
}

func (f *fakeNode) Watch(ctx context.Context, req *connect.Request[nodev1.WatchRequest], stream *connect.ServerStream[nodev1.WatchResponse]) error {
	f.mu.Lock()
	f.cursors = append(f.cursors, req.Msg.GetCursor())
	f.policies = append(f.policies, req.Msg.GetIpPolicy())
	drop := f.drop
	f.mu.Unlock()

	next := req.Msg.GetCursor()
	for {
		f.mu.Lock()
		var pending []*nodev1.WatchResponse
		for _, ev := range f.records {
			if ev.GetSeq() > next {
				pending = append(pending, ev)
			}
		}
		wake := f.wake
		f.mu.Unlock()
		for _, ev := range pending {
			if err := stream.Send(ev); err != nil {
				return err
			}
			next = ev.GetSeq()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-drop:
			return connect.NewError(connect.CodeUnavailable, errors.New("the stream was dropped"))
		case <-wake:
		}
	}
}

func (f *fakeNode) UploadArtifact(context.Context, *connect.ClientStream[nodev1.UploadArtifactRequest]) (*connect.Response[nodev1.UploadArtifactResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not in the fake"))
}

func (f *fakeNode) UpdateSelf(context.Context, *connect.ClientStream[nodev1.UpdateSelfRequest]) (*connect.Response[nodev1.UpdateSelfResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not in the fake"))
}

func (f *fakeNode) UpdateEdge(context.Context, *connect.Request[nodev1.UpdateEdgeRequest]) (*connect.Response[nodev1.UpdateEdgeResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not in the fake"))
}

func (f *fakeNode) StreamLogs(context.Context, *connect.Request[nodev1.StreamLogsRequest], *connect.ServerStream[nodev1.StreamLogsResponse]) error {
	return connect.NewError(connect.CodeUnimplemented, errors.New("not in the fake"))
}

func (f *fakeNode) PutCertificate(context.Context, *connect.Request[nodev1.PutCertificateRequest]) (*connect.Response[nodev1.PutCertificateResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not in the fake"))
}

func (f *fakeNode) RunDiagnostics(context.Context, *connect.Request[nodev1.RunDiagnosticsRequest], *connect.ServerStream[nodev1.DiagnosticResult]) error {
	return connect.NewError(connect.CodeUnimplemented, errors.New("not in the fake"))
}

func (f *fakeNode) UploadGeoIP(context.Context, *connect.ClientStream[nodev1.UploadGeoIPRequest]) (*connect.Response[nodev1.UploadGeoIPResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not in the fake"))
}

// chanListener is a net.Listener whose connections come from a channel: the
// fake node hands it the connections that it lets through.
type chanListener struct {
	addr  net.Addr
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }
