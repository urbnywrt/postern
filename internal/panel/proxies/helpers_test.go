package proxies

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
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

const (
	adminUser     = "admin"
	adminPassword = "correct horse battery staple"

	// Made-up proxy secrets and an ad tag. None of them may ever show up in a
	// log.
	secret1 = "00112233445566778899aabbccddeeff" // gitleaks:allow (a made-up test value)
	secret2 = "FFEEDDCCBBAA99887766554433221100" // gitleaks:allow (a made-up test value)
	adTag1  = "aabbccddeeff00112233445566778899" // gitleaks:allow (a made-up test value)

	waitTimeout = 10 * time.Second
)

// testPool is the domain pool of the tests: documentation names, not the real
// default pool.
var testPool = []string{"a.example", "b.example", "c.example"}

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

// notifyRecorder is a Notifier that notes the nodes it was told about and the
// desired generation that each node had at that moment.
type notifyRecorder struct {
	db *store.DB

	mu    sync.Mutex
	ids   []string
	gens  []uint64
	calls int
}

func (n *notifyRecorder) Notify(nodeID string) {
	var gen uint64
	if node, err := n.db.NodeByID(context.Background(), nodeID); err == nil {
		gen = node.DesiredGeneration
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ids = append(n.ids, nodeID)
	n.gens = append(n.gens, gen)
	n.calls++
}

func (n *notifyRecorder) got() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.ids...)
}

func (n *notifyRecorder) generations() []uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]uint64(nil), n.gens...)
}

func (n *notifyRecorder) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.calls
}

// env is the package as the panel runs it: a database, the services behind
// the auth middleware with an admin signed in, a state builder, a catalog and
// an ingestor.
type env struct {
	t       *testing.T
	ctx     context.Context
	db      *store.DB
	dbPath  string
	key     seal.Key
	logs    *lockedBuffer
	log     *slog.Logger
	catalog *Catalog
	rel     *releases.Catalog
	relDir  string
	ingest  *Ingestor
	// prepared records what the catalog was asked to prepare in the
	// background (the test env never downloads).
	prepared *lockedBuffer
	svc      *Service
	builder  *StateBuilder
	notes    *notifyRecorder
	srv      *httptest.Server

	listeners panelv1connect.ListenerServiceClient
	proxies   panelv1connect.ProxyServiceClient
	stats     panelv1connect.StatsServiceClient
	dns       panelv1connect.DnsCredentialServiceClient
	anonDNS   panelv1connect.DnsCredentialServiceClient

	// pushes are the nodes whose certificates the service asked to push.
	pushes *pushRecorder

	anonListeners panelv1connect.ListenerServiceClient
	anonProxies   panelv1connect.ProxyServiceClient
	anonStats     panelv1connect.StatsServiceClient

	adminID string
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

	e := &env{t: t, ctx: ctx, db: db, dbPath: path, logs: &lockedBuffer{}}
	if _, err := rand.Read(e.key[:]); err != nil {
		t.Fatal(err)
	}
	e.log = slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log:\n%s", e.logs.String())
		}
	})

	e.relDir = filepath.Join(t.TempDir(), "releases")
	e.rel = releases.New(releases.Config{DB: db, Key: e.key, Dir: e.relDir, HTTP: noNetwork(), Log: e.log})
	if err := e.rel.Seed(ctx); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	e.catalog = NewCatalog(e.rel, e.log)
	e.prepared = &lockedBuffer{}
	e.catalog.prepare = func(component, version, arch string) <-chan struct{} {
		_, _ = fmt.Fprintf(e.prepared, "%s %s %s\n", component, version, arch)
		done := make(chan struct{})
		close(done)
		return done
	}
	e.ingest = NewIngestor(db, e.log)
	e.notes = &notifyRecorder{db: db}
	e.svc = NewService(db, e.key, e.catalog, e.ingest, e.notes, e.log)
	e.svc.pool = testPool
	e.builder = NewStateBuilder(db, e.key, e.catalog, e.log)
	e.builder.SetReports(e.ingest)
	e.builder.pool = testPool

	admin := &store.Admin{Username: adminUser, PasswordHash: cheapHash(t, adminPassword)}
	if err := db.CreateAdmin(ctx, admin); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	e.adminID = admin.ID

	authSvc := auth.NewService(db, e.key, e.log)
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(panelv1connect.NewListenerServiceHandler(e.svc))
	mux.Handle(panelv1connect.NewProxyServiceHandler(e.svc))
	mux.Handle(panelv1connect.NewStatsServiceHandler(e.svc))
	mux.Handle(panelv1connect.NewDnsCredentialServiceHandler(e.svc))
	e.pushes = &pushRecorder{}
	e.svc.SetCertPusher(e.pushes)
	e.srv = httptest.NewServer(authSvc.Middleware(mux))
	t.Cleanup(e.srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	web := &http.Client{Jar: jar, Timeout: waitTimeout}
	login := panelv1connect.NewAuthServiceClient(web, e.srv.URL)
	if _, err := login.Login(ctx, connect.NewRequest(&panelv1.LoginRequest{Username: adminUser, Password: adminPassword})); err != nil {
		t.Fatalf("Login: %v", err)
	}
	e.listeners = panelv1connect.NewListenerServiceClient(web, e.srv.URL)
	e.proxies = panelv1connect.NewProxyServiceClient(web, e.srv.URL)
	e.stats = panelv1connect.NewStatsServiceClient(web, e.srv.URL)
	e.dns = panelv1connect.NewDnsCredentialServiceClient(web, e.srv.URL)

	anon := &http.Client{Timeout: waitTimeout}
	e.anonListeners = panelv1connect.NewListenerServiceClient(anon, e.srv.URL)
	e.anonProxies = panelv1connect.NewProxyServiceClient(anon, e.srv.URL)
	e.anonStats = panelv1connect.NewStatsServiceClient(anon, e.srv.URL)
	e.anonDNS = panelv1connect.NewDnsCredentialServiceClient(anon, e.srv.URL)
	return e
}

// noNetwork is an HTTP client that refuses every request: the tests never
// download a release.
func noNetwork() *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("no network in tests: %s", r.URL)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// pushRecorder is a CertPusher that notes the nodes it was told about.
type pushRecorder struct {
	mu  sync.Mutex
	ids []string
}

func (p *pushRecorder) PushCertificates(nodeID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ids = append(p.ids, nodeID)
}

func (p *pushRecorder) got() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.ids...)
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

// addNode stores a node as CreateNode would, without a certificate.
func (e *env) addNode(name, linkHost string) *store.Node {
	e.t.Helper()
	n := &store.Node{Name: name, MgmtHost: "198.51.100.1", MgmtPort: 61000, LinkHost: linkHost}
	if err := e.db.CreateNode(e.ctx, n); err != nil {
		e.t.Fatalf("CreateNode: %v", err)
	}
	return n
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

// createListener calls CreateListener and fails the test on an error.
func (e *env) createListener(req *panelv1.CreateListenerRequest) *panelv1.Listener {
	e.t.Helper()
	resp, err := e.listeners.CreateListener(e.ctx, connect.NewRequest(req))
	if err != nil {
		e.t.Fatalf("CreateListener(%v): %v", req, err)
	}
	return resp.Msg.GetListener()
}

// createProxy calls CreateProxy and fails the test on an error.
func (e *env) createProxy(req *panelv1.CreateProxyRequest) *panelv1.Proxy {
	e.t.Helper()
	resp, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(req))
	if err != nil {
		e.t.Fatalf("CreateProxy(%v): %v", req, err)
	}
	return resp.Msg.GetProxy()
}

// storedProxy reads a proxy from the database.
func (e *env) storedProxy(id string) *store.Proxy {
	e.t.Helper()
	p, err := e.db.ProxyByID(e.ctx, id)
	if err != nil {
		e.t.Fatalf("ProxyByID: %v", err)
	}
	return p
}

// secretOf opens the stored secret of a proxy.
func (e *env) secretOf(id string) string {
	e.t.Helper()
	p := e.storedProxy(id)
	plain, err := seal.Open(e.key, p.SecretEnc, []byte("proxy:"+id))
	if err != nil {
		e.t.Fatalf("open the secret of proxy %s: %v", id, err)
	}
	return string(plain)
}

// events returns the events of a node, oldest first.
func (e *env) events(nodeID string) []*store.Event {
	e.t.Helper()
	evs, err := e.db.ListEvents(e.ctx, 1000, nodeID)
	if err != nil {
		e.t.Fatalf("ListEvents: %v", err)
	}
	out := make([]*store.Event, 0, len(evs))
	for i := len(evs) - 1; i >= 0; i-- {
		out = append(out, evs[i])
	}
	return out
}

// eventsOfKind returns the events of a node of one kind, oldest first.
func (e *env) eventsOfKind(nodeID, kind string) []*store.Event {
	e.t.Helper()
	var out []*store.Event
	for _, ev := range e.events(nodeID) {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

// auditLog returns the audit log as "action target admin" lines, oldest first.
func auditLog(t *testing.T, e *env) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT action, target, admin_id FROM audit_log WHERE action NOT LIKE 'auth.%' ORDER BY ts, rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var action, target, admin string
		if err := rows.Scan(&action, &target, &admin); err != nil {
			t.Fatal(err)
		}
		out = append(out, action+" "+target+" "+admin)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// assertNoSecretsLogged fails the test if a secret is in the log: one of the
// made-up ones of the tests, or the secret of a proxy in the database, which
// may be a random one.
func (e *env) assertNoSecretsLogged() {
	e.t.Helper()
	secrets := []string{secret1, secret2, strings.ToLower(secret2)}
	stored, err := e.db.ListProxies(e.ctx, store.ProxyFilter{})
	if err != nil {
		e.t.Fatalf("ListProxies: %v", err)
	}
	for _, p := range stored {
		secrets = append(secrets, e.secretOf(p.ID))
	}
	logs := e.logs.String()
	for _, s := range secrets {
		if strings.Contains(logs, s) || strings.Contains(strings.ToLower(logs), strings.ToLower(s)) {
			e.t.Errorf("the log contains a proxy secret")
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
