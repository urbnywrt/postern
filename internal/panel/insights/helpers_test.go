package insights

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/argon2"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

const (
	adminUser     = "admin"
	adminPassword = "correct horse battery staple"
)

// lockedBuffer is a buffer that the log of several goroutines can share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// notes is a Notifier that records the nodes it is told of.
type notes struct {
	mu  sync.Mutex
	ids []string
}

func (n *notes) Notify(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ids = append(n.ids, id)
}

// take returns the nodes notified since the last take, sorted.
func (n *notes) take() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := slices.Sorted(slices.Values(n.ids))
	n.ids = nil
	return out
}

// An env is the SettingsService on a database of its own, mounted behind the
// real sign-in, with a client that has signed in and one that has not.
type env struct {
	t      *testing.T
	ctx    context.Context
	db     *store.DB
	dbPath string
	logs   *lockedBuffer
	notes  *notes
	svc    *SettingsService
	api    panelv1connect.SettingsServiceClient
	anon   panelv1connect.SettingsServiceClient
	admin  string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, ctx: context.Background(), logs: &lockedBuffer{}, notes: &notes{}}
	e.dbPath = filepath.Join(t.TempDir(), "panel.db")
	db, err := store.Open(e.dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.db = db
	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log:\n%s", e.logs.String())
		}
	})
	e.svc = NewSettingsService(db, e.notes, log)

	admin := &store.Admin{Username: adminUser, PasswordHash: cheapHash(t, adminPassword)}
	if err := db.CreateAdmin(e.ctx, admin); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	e.admin = admin.ID
	var key seal.Key
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	authSvc := auth.NewService(db, key, log)
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(panelv1connect.NewSettingsServiceHandler(e.svc))
	srv := httptest.NewServer(authSvc.Middleware(mux))
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	web := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	login := panelv1connect.NewAuthServiceClient(web, srv.URL)
	if _, err := login.Login(e.ctx, connect.NewRequest(&panelv1.LoginRequest{Username: adminUser, Password: adminPassword})); err != nil {
		t.Fatalf("Login: %v", err)
	}
	e.api = panelv1connect.NewSettingsServiceClient(web, srv.URL)
	e.anon = panelv1connect.NewSettingsServiceClient(&http.Client{Timeout: 30 * time.Second}, srv.URL)
	return e
}

// node stores a node with the capabilities and the panel addresses given.
func (e *env) node(name string, caps []string, panelAddrs ...string) *store.Node {
	e.t.Helper()
	n := &store.Node{Name: name, MgmtHost: "198.51.100.1", MgmtPort: 61000, LinkHost: "203.0.113.10",
		HostInfo: store.HostInfo{Capabilities: caps}, PanelAddrs: panelAddrs}
	if err := e.db.CreateNode(e.ctx, n); err != nil {
		e.t.Fatalf("CreateNode: %v", err)
	}
	return n
}

// generation is the desired generation of a node.
func (e *env) generation(id string) uint64 {
	e.t.Helper()
	n, err := e.db.NodeByID(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return n.DesiredGeneration
}

// query reads one value.
func (e *env) query(dst any, q string, args ...any) {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath)+"?mode=ro")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.QueryRow(q, args...).Scan(dst); err != nil {
		e.t.Fatalf("%q: %v", q, err)
	}
}

// cheapHash is the argon2id hash of a password at the smallest cost that the
// sign-in accepts.
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
