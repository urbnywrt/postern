package nodeupdate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/rollout"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
	"github.com/urbnywrt/postern/internal/seal"
)

const (
	waitTimeout  = 15 * time.Second
	panelVersion = "v0.5.0"
	oldVersion   = "v0.4.0"
)

// allCaps are the capabilities of a node that takes node rollouts.
var allCaps = []string{"rollout-status", CapUpdateEdge, CapUpdateSelf}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

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

// fakeBinaries are signed node binaries by version and arch, as nodes.PanelKit
// gives them.
type fakeBinaries struct {
	mu     sync.Mutex
	have   map[string][]byte // version/arch
	opened []string
}

func newBinaries(versions ...string) *fakeBinaries {
	b := &fakeBinaries{have: map[string][]byte{}}
	for _, v := range versions {
		for _, arch := range []string{"amd64", "arm64"} {
			b.have[v+"/"+arch] = []byte("postern-node " + v + " " + arch + strings.Repeat("x", 300<<10))
		}
	}
	return b
}

func (b *fakeBinaries) Known(version, arch string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.have[version+"/"+arch]; !ok {
		return errors.New("not in the cache")
	}
	return nil
}

func (b *fakeBinaries) Signed(_ context.Context, version, arch string) (io.ReadCloser, []byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.opened = append(b.opened, version+"/"+arch)
	data, ok := b.have[version+"/"+arch]
	if !ok {
		return nil, nil, errors.New("not in the cache")
	}
	return io.NopCloser(bytes.NewReader(data)), []byte("sig of " + version + " " + arch), nil
}

func (b *fakeBinaries) opens() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.opened...)
}

// fakeAgent is a node agent over mTLS that updates itself as the real one
// does, in a few milliseconds: UpdateSelf answers restarting, then the agent
// "restarts" (its connections drop, agent_started is recorded) on the new
// version, and is healthy a moment later unless the test holds it.
type fakeAgent struct {
	nodev1connect.UnimplementedNodeServiceHandler
	t  *testing.T
	ln net.Listener

	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	info      *nodev1.GetInfoResponse
	records   []*nodev1.WatchResponse
	seq       uint64
	wake      chan struct{}
	metas     []*nodev1.NodeBinary
	shaOK     []bool
	edgeCalls []*nodev1.UpdateEdgeRequest
	healthyIn int // GetInfo answers that were healthy

	// What the agent does; the tests change these before the update.
	selfErr      error  // UpdateSelf answers with it
	comeBackAs   string // the version it restarts on; "" is the one it was sent
	holdHealthy  bool   // stays unhealthy after the restart
	edgeErr      error  // UpdateEdge answers with it
	restartDelay time.Duration
	blip         bool // the next GetInfo fails and drops the connections: a network blip
}

func newFakeAgent(t *testing.T, agent, edge string) *fakeAgent {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAgent{
		t: t, ln: ln, conns: map[net.Conn]struct{}{}, wake: make(chan struct{}), restartDelay: 30 * time.Millisecond,
		info: &nodev1.GetInfoResponse{
			AgentVersion: agent, EdgeVersion: edge, Arch: "amd64", Os: "Debian",
			Capabilities: allCaps, Healthy: true,
			Binaries: &nodev1.NodeBinaries{Versions: []string{agent}, Current: agent},
		},
	}
	t.Cleanup(func() { _ = ln.Close(); f.dropConns() })
	return f
}

func (f *fakeAgent) port() uint32 { return uint32(f.ln.Addr().(*net.TCPAddr).Port) }

func (f *fakeAgent) serve(b *pki.Bundle) {
	cfg, err := pki.ServerTLSConfig(b.CAPEM, b.CertPEM, b.KeyPEM)
	if err != nil {
		f.t.Fatal(err)
	}
	cfg.NextProtos = []string{"h2"}
	mux := http.NewServeMux()
	mux.Handle(nodev1connect.NewNodeServiceHandler(f))
	srv := &http.Server{Handler: mux, TLSConfig: cfg, ReadHeaderTimeout: waitTimeout, ErrorLog: log.New(io.Discard, "", 0)}
	f.t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.ServeTLS(&trackingListener{Listener: f.ln, f: f}, "", "") }()
}

type trackingListener struct {
	net.Listener
	f *fakeAgent
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.f.mu.Lock()
		l.f.conns[c] = struct{}{}
		l.f.mu.Unlock()
	}
	return c, err
}

func (f *fakeAgent) dropConns() {
	f.mu.Lock()
	conns := f.conns
	f.conns = map[net.Conn]struct{}{}
	f.mu.Unlock()
	for c := range conns {
		_ = c.Close()
	}
}

func (f *fakeAgent) set(fn func(f *fakeAgent)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// emitLocked records an event of the agent.
func (f *fakeAgent) emitLocked(kind string) {
	f.seq++
	f.records = append(f.records, &nodev1.WatchResponse{Seq: f.seq, TsUnix: time.Now().Unix(),
		Payload: &nodev1.WatchResponse_Event{Event: &nodev1.NodeEvent{Kind: kind, Severity: "info", Message: kind}}})
	close(f.wake)
	f.wake = make(chan struct{})
}

func (f *fakeAgent) emit(kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.emitLocked(kind)
}

// restart is what the agent does after it answered UpdateSelf: its process
// ends, the launcher starts the new one.
func (f *fakeAgent) restart(to string) {
	time.Sleep(f.restartDelay)
	f.mu.Lock()
	if f.comeBackAs != "" {
		to = f.comeBackAs
	}
	f.info.AgentVersion, f.info.Healthy = to, false
	f.info.Binaries.Previous, f.info.Binaries.Current = f.info.Binaries.Current, to
	if !slices.Contains(f.info.Binaries.SignedVersions, to) { // UpdateSelf keeps the signature
		f.info.Binaries.SignedVersions = append(f.info.Binaries.SignedVersions, to)
	}
	f.emitLocked("agent_started")
	f.mu.Unlock()
	f.dropConns()
	time.Sleep(f.restartDelay)
	f.mu.Lock()
	if !f.holdHealthy {
		f.info.Healthy = true
	}
	f.mu.Unlock()
}

func (f *fakeAgent) GetInfo(context.Context, *connect.Request[nodev1.GetInfoRequest]) (*connect.Response[nodev1.GetInfoResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.blip {
		f.blip = false
		go f.dropConns()
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("a network blip"))
	}
	if f.info.GetHealthy() {
		f.healthyIn++
	}
	return connect.NewResponse(proto.Clone(f.info).(*nodev1.GetInfoResponse)), nil
}

func (f *fakeAgent) Watch(ctx context.Context, req *connect.Request[nodev1.WatchRequest], stream *connect.ServerStream[nodev1.WatchResponse]) error {
	next := req.Msg.GetCursor()
	for {
		f.mu.Lock()
		var pending []*nodev1.WatchResponse
		for _, r := range f.records {
			if r.GetSeq() > next {
				pending = append(pending, r)
			}
		}
		wake := f.wake
		f.mu.Unlock()
		for _, r := range pending {
			if err := stream.Send(r); err != nil {
				return err
			}
			next = r.GetSeq()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		}
	}
}

func (f *fakeAgent) UpdateSelf(_ context.Context, stream *connect.ClientStream[nodev1.UpdateSelfRequest]) (*connect.Response[nodev1.UpdateSelfResponse], error) {
	var meta *nodev1.NodeBinary
	h := sha256.New()
	var size uint64
	for stream.Receive() {
		switch p := stream.Msg().GetPart().(type) {
		case *nodev1.UpdateSelfRequest_Meta:
			meta = p.Meta
		case *nodev1.UpdateSelfRequest_Chunk:
			h.Write(p.Chunk)
			size += uint64(len(p.Chunk))
		}
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.metas = append(f.metas, meta)
	f.shaOK = append(f.shaOK, meta.GetSha256() == hex.EncodeToString(h.Sum(nil)) && meta.GetSize() == size)
	err := f.selfErr
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	go f.restart(meta.GetVersion())
	return connect.NewResponse(&nodev1.UpdateSelfResponse{Version: meta.GetVersion(), Restarting: true}), nil
}

func (f *fakeAgent) UpdateEdge(_ context.Context, req *connect.Request[nodev1.UpdateEdgeRequest]) (*connect.Response[nodev1.UpdateEdgeResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.edgeCalls = append(f.edgeCalls, req.Msg)
	if f.edgeErr != nil {
		return nil, f.edgeErr
	}
	f.info.EdgeVersion = req.Msg.GetVersion()
	return connect.NewResponse(&nodev1.UpdateEdgeResponse{Generation: 2, Version: req.Msg.GetVersion()}), nil
}

func (f *fakeAgent) updates() ([]*nodev1.NodeBinary, []bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*nodev1.NodeBinary(nil), f.metas...), append([]bool(nil), f.shaOK...)
}

func (f *fakeAgent) edges() []*nodev1.UpdateEdgeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*nodev1.UpdateEdgeRequest(nil), f.edgeCalls...)
}

// env is a panel with its node manager, the rollout runner and the executor.
type env struct {
	t        *testing.T
	ctx      context.Context
	db       *store.DB
	nodeSvc  *nodes.Service
	nodesAPI panelv1connect.NodeServiceClient
	mgr      *nodes.Manager
	runner   *rollout.Runner
	exec     *Executor
	bins     *fakeBinaries
	logs     *lockedBuffer
}

func newEnv(t *testing.T, bins Binaries) *env {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, ctx: ctx, db: db, logs: &lockedBuffer{}}
	var key seal.Key
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	lg := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("panel log:\n%s", e.logs.String())
		}
	})
	ca, err := nodes.LoadOrCreateCA(ctx, db, key)
	if err != nil {
		t.Fatal(err)
	}
	e.mgr = nodes.NewManager(db, key, ca, lg)
	e.mgr.SetBackoff(5*time.Millisecond, 50*time.Millisecond)
	e.nodeSvc = nodes.NewService(db, key, ca, e.mgr, lg)
	e.nodesAPI = adminClient(t, db, key, lg, e.nodeSvc)
	if fb, ok := bins.(*fakeBinaries); ok {
		e.bins = fb
	}
	e.exec = New(Config{DB: db, Nodes: e.mgr, Binaries: bins, PanelVersion: panelVersion, Log: lg,
		Poll: 10 * time.Millisecond, UploadTimeout: 3 * time.Second, HealthTimeout: 3 * time.Second, EdgeTimeout: 3 * time.Second})
	e.runner = rollout.NewRunner(rollout.Config{DB: db, Log: lg, Tick: 10 * time.Millisecond})
	e.runner.Register(rollout.KeyNode, e.exec)
	e.mgr.Start(ctx)
	done := make(chan struct{})
	go func() { e.runner.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
		e.mgr.Close()
		_ = db.Close()
	})
	return e
}

// adminClient is a NodeService client signed in as an admin.
func adminClient(t *testing.T, db *store.DB, key seal.Key, lg *slog.Logger, svc *nodes.Service) panelv1connect.NodeServiceClient {
	t.Helper()
	ctx := context.Background()
	if err := db.CreateAdmin(ctx, &store.Admin{Username: "admin", PasswordHash: cheapHash(t, "a long password")}); err != nil {
		t.Fatal(err)
	}
	authSvc := auth.NewService(db, key, lg)
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(panelv1connect.NewNodeServiceHandler(svc))
	srv := httptest.NewServer(authSvc.Middleware(mux))
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	web := &http.Client{Jar: jar, Timeout: time.Minute}
	if _, err := panelv1connect.NewAuthServiceClient(web, srv.URL).Login(ctx,
		connect.NewRequest(&panelv1.LoginRequest{Username: "admin", Password: "a long password"})); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return panelv1connect.NewNodeServiceClient(web, srv.URL)
}

func cheapHash(t *testing.T, password string) string {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	k := argon2.IDKey([]byte(password), salt, 1, 8, 1, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=8,t=1,p=1$%s$%s", argon2.Version, enc.EncodeToString(salt), enc.EncodeToString(k))
}

// addNode creates a node whose agent is f, serves it, and waits until the
// panel has it online with its capabilities.
func (e *env) addNode(name string, f *fakeAgent) *store.Node {
	e.t.Helper()
	resp, err := e.nodesAPI.CreateNode(e.ctx, connect.NewRequest(&panelv1.CreateNodeRequest{Name: name, MgmtHost: "127.0.0.1", MgmtPort: f.port()}))
	if err != nil {
		e.t.Fatalf("CreateNode: %v", err)
	}
	id := resp.Msg.GetNode().GetId()
	b, err := e.nodeSvc.Bundle(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	f.serve(b)
	waitFor(e.t, "node "+name+" online", func() bool {
		n := e.node(id)
		return n.Status == store.NodeStatusOnline && len(n.HostInfo.Capabilities) > 0
	})
	return e.node(id)
}

func (e *env) node(id string) *store.Node {
	e.t.Helper()
	n, err := e.db.NodeByID(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return n
}

// start starts a node rollout.
func (e *env) start(req *rollout.Request) (*store.Rollout, error) {
	if req.Kind == "" {
		req.Kind = store.RolloutNode
	}
	if req.Mode == "" {
		req.Mode = store.RolloutModeAuto
	}
	if req.PauseSeconds == 0 {
		req.PauseSeconds = 1
	}
	return e.runner.Start(e.ctx, "admin", req)
}

// waitOver waits until the rollout is completed or failed and returns it.
func (e *env) waitOver(id string) *store.Rollout {
	e.t.Helper()
	var ro *store.Rollout
	waitFor(e.t, "rollout "+id+" over", func() bool {
		var err error
		if ro, _, _, err = e.db.Rollout(e.ctx, id); err != nil {
			e.t.Fatal(err)
		}
		return ro.Status == store.RolloutCompleted || ro.Status == store.RolloutFailed
	})
	return ro
}

func (e *env) status(id string) string {
	ro, _, _, err := e.db.Rollout(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return ro.Status
}
