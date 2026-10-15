package egress

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/argon2"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

const (
	adminUser     = "admin"
	adminPassword = "correct horse battery staple"

	// Made-up credentials of egresses: a UUID, a password and the token of a
	// subscription that are obviously fake. None of them may ever show up in a
	// response, a log or the database in plain text.
	fakeUUID     = "00000000-0000-4000-8000-000000000001"
	fakePassword = "pass-word-not-real"   // gitleaks:allow (a made-up test value)
	fakeSubToken = "sub-token-not-real-0" // gitleaks:allow (a made-up test value)
	fakeVLESS    = "vless://" + fakeUUID + "@vless.example.com:443?security=reality&sni=www.example.com&fp=chrome" +
		"&pbk=fake-public-key-for-tests-0000000000000&sid=0123456789abcdef&type=tcp#exit"
	fakeTrojan = "trojan://" + fakePassword + "@[2001:db8::7]:8443?security=tls&sni=t.example.com#t"
	fakeSubURL = "https://sub.example.com:8443/path/" + fakeSubToken + "?token=" + fakeSubToken

	waitTimeout = 10 * time.Second
)

// secrets are the made-up credentials that must never leave the panel.
var secrets = []string{fakeUUID, fakePassword, fakeSubToken}

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

// notifyRecorder is a Notifier that notes the nodes it was told about.
type notifyRecorder struct {
	mu  sync.Mutex
	ids []string
}

func (n *notifyRecorder) Notify(nodeID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ids = append(n.ids, nodeID)
}

func (n *notifyRecorder) got() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.ids...)
}

// env is the package as the panel runs it: a database, the egress services and
// the proxy services behind the auth middleware, with an admin signed in.
type env struct {
	t      *testing.T
	ctx    context.Context
	db     *store.DB
	dbPath string
	key    seal.Key
	logs   *lockedBuffer
	ingest *proxies.Ingestor
	states *proxies.StateBuilder
	notes  *notifyRecorder
	svc    *Service

	egresses  panelv1connect.EgressServiceClient
	chains    panelv1connect.ChainServiceClient
	listeners panelv1connect.ListenerServiceClient
	proxies   panelv1connect.ProxyServiceClient

	anonEgresses panelv1connect.EgressServiceClient
	anonChains   panelv1connect.ChainServiceClient
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	e := &env{t: t, ctx: ctx, db: db, dbPath: path, logs: &lockedBuffer{}, notes: &notifyRecorder{}}
	if _, err := rand.Read(e.key[:]); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log:\n%s", e.logs.String())
		}
	})
	relCatalog := releases.New(releases.Config{DB: db, Key: e.key, Dir: filepath.Join(t.TempDir(), "releases"), Log: log})
	if err := relCatalog.Seed(ctx); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	catalog := proxies.NewCatalog(relCatalog, log)
	e.ingest = proxies.NewIngestor(db, log)
	e.states = proxies.NewStateBuilder(db, e.key, catalog, log)
	proxySvc := proxies.NewService(db, e.key, catalog, e.ingest, e.notes, log)
	svc := NewService(db, e.key, proxySvc, e.ingest, log)
	e.svc = svc

	admin := &store.Admin{Username: adminUser, PasswordHash: cheapHash(t, adminPassword)}
	if err := db.CreateAdmin(ctx, admin); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	authSvc := auth.NewService(db, e.key, log)
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(panelv1connect.NewEgressServiceHandler(svc))
	mux.Handle(panelv1connect.NewChainServiceHandler(svc))
	mux.Handle(panelv1connect.NewListenerServiceHandler(proxySvc))
	mux.Handle(panelv1connect.NewProxyServiceHandler(proxySvc))
	srv := httptest.NewServer(authSvc.Middleware(mux))
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	web := &http.Client{Jar: jar, Timeout: waitTimeout}
	login := panelv1connect.NewAuthServiceClient(web, srv.URL)
	if _, err := login.Login(ctx, connect.NewRequest(&panelv1.LoginRequest{Username: adminUser, Password: adminPassword})); err != nil {
		t.Fatalf("Login: %v", err)
	}
	e.egresses = panelv1connect.NewEgressServiceClient(web, srv.URL)
	e.chains = panelv1connect.NewChainServiceClient(web, srv.URL)
	e.listeners = panelv1connect.NewListenerServiceClient(web, srv.URL)
	e.proxies = panelv1connect.NewProxyServiceClient(web, srv.URL)
	anon := &http.Client{Timeout: waitTimeout}
	e.anonEgresses = panelv1connect.NewEgressServiceClient(anon, srv.URL)
	e.anonChains = panelv1connect.NewChainServiceClient(anon, srv.URL)
	return e
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

// addNode stores a node that has connected and reports the capabilities (none
// is a node of slice 1), with a listener and an enabled proxy, which goes out
// through the default chain of the node.
func (e *env) addNode(name string, capabilities ...string) *store.Node {
	e.t.Helper()
	seen := time.Now().Add(-time.Minute)
	n := &store.Node{Name: name, MgmtHost: "198.51.100.1", MgmtPort: 61000, LinkHost: "203.0.113.10", LastSeenAt: &seen}
	n.HostInfo.Capabilities = capabilities
	if err := e.db.CreateNode(e.ctx, n); err != nil {
		e.t.Fatalf("CreateNode: %v", err)
	}
	l, err := e.listeners.CreateListener(e.ctx, connect.NewRequest(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443}))
	if err != nil {
		e.t.Fatalf("CreateListener: %v", err)
	}
	if _, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: n.ID, ListenerId: l.Msg.GetListener().GetId(), Domain: "cdn.example.com",
	})); err != nil {
		e.t.Fatalf("CreateProxy: %v", err)
	}
	return e.node(n.ID)
}

// node reads a node.
func (e *env) node(id string) *store.Node {
	e.t.Helper()
	n, err := e.db.NodeByID(e.ctx, id)
	if err != nil {
		e.t.Fatalf("NodeByID: %v", err)
	}
	return n
}

// generation is the desired generation of a node.
func (e *env) generation(id string) uint64 {
	e.t.Helper()
	return e.node(id).DesiredGeneration
}

// createEgress calls CreateEgress and fails the test on an error.
func (e *env) createEgress(req *panelv1.CreateEgressRequest) *panelv1.Egress {
	e.t.Helper()
	resp, err := e.egresses.CreateEgress(e.ctx, connect.NewRequest(req))
	if err != nil {
		e.t.Fatalf("CreateEgress(%s %s): %v", req.GetKind(), req.GetName(), err)
	}
	return resp.Msg.GetEgress()
}

// createChain calls CreateChain and fails the test on an error.
func (e *env) createChain(req *panelv1.CreateChainRequest) *panelv1.Chain {
	e.t.Helper()
	resp, err := e.chains.CreateChain(e.ctx, connect.NewRequest(req))
	if err != nil {
		e.t.Fatalf("CreateChain(%s): %v", req.GetName(), err)
	}
	return resp.Msg.GetChain()
}

// setDefaultChain calls SetNodeDefaultChain and fails the test on an error.
func (e *env) setDefaultChain(nodeID, chainID string) {
	e.t.Helper()
	if _, err := e.chains.SetNodeDefaultChain(e.ctx, connect.NewRequest(&panelv1.SetNodeDefaultChainRequest{NodeId: nodeID, ChainId: chainID})); err != nil {
		e.t.Fatalf("SetNodeDefaultChain: %v", err)
	}
}

// exec runs a statement on the database through a connection of its own, for
// rows that the services never write.
func (e *env) exec(query string, args ...any) {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath)+"?_pragma=foreign_keys(1)")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(query, args...); err != nil {
		e.t.Fatalf("exec %q: %v", query, err)
	}
}

// setStatus sets the status of a node, as the connection manager does.
func (e *env) setStatus(nodeID, status string) {
	e.t.Helper()
	if _, err := e.db.ModifyNode(e.ctx, nodeID, func(n *store.Node) error { n.Status = status; return nil }); err != nil {
		e.t.Fatal(err)
	}
}

// storedParams opens the stored parameters of an egress.
func (e *env) storedParams(id string) string {
	e.t.Helper()
	eg, err := e.db.EgressByID(e.ctx, id)
	if err != nil {
		e.t.Fatalf("EgressByID: %v", err)
	}
	p, err := proxies.OpenEgressParams(e.key, eg)
	if err != nil {
		e.t.Fatalf("OpenEgressParams: %v", err)
	}
	return p
}

// assertNoSecretsLogged fails the test if a made-up credential is in the log.
func (e *env) assertNoSecretsLogged() {
	e.t.Helper()
	logs := e.logs.String()
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			e.t.Errorf("the log contains a credential of an egress")
		}
	}
}

// wantCode fails the test unless err is a Connect error with this code.
func wantCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %v", want)
	}
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a Connect error, want %v", err, want)
	}
	if ce.Code() != want {
		t.Fatalf("error = %v (code %v), want code %v", err, ce.Code(), want)
	}
}
