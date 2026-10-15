package geodb

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/argon2"
	"google.golang.org/protobuf/proto"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/geoip/geoiptest"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

const (
	adminUser     = "admin"
	adminPassword = "correct horse battery staple"

	// waitFor is how long a test waits for something that happens in the
	// background.
	waitFor = 10 * time.Second
)

// t0 is where the clock of the tests starts: the 5th of October 2026, when the
// file of that month has been published for days.
var t0 = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// A lockedBuffer is a log that goroutines write to together.
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

// A clock is a clock that moves when a test says so.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// eventually polls cond until it holds, or fails the test.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("gave up waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// monthDB is a country database that says that 198.51.100.0/24 and 2001:db8::/32
// are in country, built at the start of month ("2026-10"); the country is how a
// test tells one database from another.
func monthDB(t *testing.T, month, country string, opts ...geoiptest.Option) []byte {
	t.Helper()
	built, err := time.Parse("2006-01", month)
	if err != nil {
		t.Fatal(err)
	}
	opts = append([]geoiptest.Option{geoiptest.WithBuilt(built.Add(6 * time.Hour))}, opts...)
	data, err := geoiptest.Bytes(map[string]string{"198.51.100.0/24": country, "2001:db8::/32": country}, opts...)
	if err != nil {
		t.Fatalf("geoiptest.Bytes: %v", err)
	}
	return data
}

// gzipped compresses data.
func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// sumOf is the lower-case hex SHA-256 of data.
func sumOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// A source is the download site of DB-IP: it serves the files that a test
// publishes, as /dbip-country-lite-<month>.mmdb.gz, and says 404 for the rest.
type source struct {
	srv *httptest.Server

	mu       sync.Mutex
	files    map[string][]byte // by month: the body as it is served
	codes    map[string]int    // by month: a status to answer with instead
	hook     func(w http.ResponseWriter, r *http.Request, month string) bool
	requests []string // the paths asked for, in order
	agents   []string // the User-Agent of each request
}

func newSource(t *testing.T) *source {
	t.Helper()
	s := &source{files: map[string][]byte{}, codes: map[string]int{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *source) serve(w http.ResponseWriter, r *http.Request) {
	month := strings.TrimSuffix(strings.TrimPrefix(path.Base(r.URL.Path), "dbip-country-lite-"), ".mmdb.gz")
	s.mu.Lock()
	s.requests = append(s.requests, r.URL.Path)
	s.agents = append(s.agents, r.UserAgent())
	body, ok := s.files[month]
	code := s.codes[month]
	hook := s.hook
	s.mu.Unlock()

	switch {
	case hook != nil && hook(w, r, month):
	case code != 0:
		http.Error(w, "answer of the test", code)
	case !ok || r.Method != http.MethodGet:
		http.NotFound(w, r)
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}
}

// publish makes the file of a month available, as the body that is served.
func (s *source) publish(month string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[month] = body
	delete(s.codes, month)
}

// answer makes the source answer a month with a status.
func (s *source) answer(month string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[month] = code
}

// handle sets a handler that is asked first and says whether it answered.
func (s *source) handle(h func(w http.ResponseWriter, r *http.Request, month string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hook = h
}

// asked returns the paths that were asked for, in order.
func (s *source) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

func (s *source) userAgents() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.agents)
}

// file is the path that a month is asked for.
func file(month string) string { return "/dbip-country-lite-" + month + ".mmdb.gz" }

// An env is a manager on a database and a directory of its own, with a source of
// files and a clock that a test moves.
type env struct {
	t      *testing.T
	ctx    context.Context
	db     *store.DB
	dbPath string
	dir    string
	src    *source
	clock  *clock
	logs   *lockedBuffer
	m      *Manager
}

// newEnv makes a manager that downloads from a source of the test. opts come
// after the options that point it at the source and at the clock.
func newEnv(t *testing.T, opts ...Option) *env {
	t.Helper()
	e := &env{t: t, ctx: context.Background(), logs: &lockedBuffer{}, clock: &clock{t: t0}}
	root := t.TempDir()
	e.dbPath = filepath.Join(root, "panel.db")
	db, err := store.Open(e.dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.db = db
	e.dir = filepath.Join(root, "geoip")
	e.src = newSource(t)
	e.m = e.manager(opts...)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log:\n%s", e.logs.String())
		}
	})
	return e
}

// manager makes another manager on the same database, directory and source.
func (e *env) manager(opts ...Option) *Manager {
	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	all := append([]Option{WithBaseURL(e.src.srv.URL), WithHTTPClient(e.src.srv.Client()), WithNow(e.clock.Now)}, opts...)
	return NewManager(e.db, e.dir, log, all...)
}

// refresh refreshes and fails the test on an error that the panel itself makes.
func (e *env) refresh() Status {
	e.t.Helper()
	st, err := e.m.Refresh(e.ctx)
	if err != nil {
		e.t.Fatalf("Refresh: %v", err)
	}
	return st
}

// events returns the events of a kind, oldest first.
func (e *env) events(kind string) []*store.Event {
	e.t.Helper()
	all, err := e.db.ListEvents(e.ctx, 1000, "")
	if err != nil {
		e.t.Fatalf("ListEvents: %v", err)
	}
	var out []*store.Event
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Kind == kind {
			out = append(out, all[i])
		}
	}
	return out
}

// state reads the geoip_state setting as the manager keeps it.
func (e *env) state() state {
	e.t.Helper()
	var st state
	if _, err := e.db.GetSetting(e.ctx, "geoip_state", &st); err != nil {
		e.t.Fatalf("GetSetting: %v", err)
	}
	return st
}

// names lists the entries of the directory of the databases, sorted.
func (e *env) names() []string {
	e.t.Helper()
	return dirNames(e.t, e.dir)
}

// audit returns the audit log as "action target admin" lines, oldest first.
func (e *env) audit() []string { return auditLog(e.t, e.dbPath) }

// auditLog reads the audit log of the database at dbPath.
func auditLog(t *testing.T, dbPath string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT action, target, admin_id, details FROM audit_log ORDER BY ts, rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var action, target, admin, details string
		if err := rows.Scan(&action, &target, &admin, &details); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s %s %s %s", action, target, admin, details))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
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

// A panel is what the package is mounted in: the sign-in of the real auth
// service, the GeoIPService and the route of the upload behind it, as the
// server mounts them, over an HTTP test server.
type panel struct {
	*env
	adminID string
	srv     *httptest.Server
	// web is a client that has signed in; plain has no session.
	web   *http.Client
	plain *http.Client
	geoip panelv1connect.GeoIPServiceClient
	// anon calls the service without a session.
	anon panelv1connect.GeoIPServiceClient
}

func newPanel(t *testing.T, opts ...Option) *panel {
	t.Helper()
	e := newEnv(t, opts...)
	p := &panel{env: e}

	admin := &store.Admin{Username: adminUser, PasswordHash: cheapHash(t, adminPassword)}
	if err := e.db.CreateAdmin(e.ctx, admin); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	p.adminID = admin.ID

	var key seal.Key
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(e.logs, nil))
	authSvc := auth.NewService(e.db, key, log)
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(panelv1connect.NewGeoIPServiceHandler(NewService(e.m, log)))
	mux.Handle("/api/geoip", e.m.UploadHandler())
	p.srv = httptest.NewServer(authSvc.Middleware(mux))
	t.Cleanup(p.srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	p.web = &http.Client{Jar: jar, Timeout: waitFor}
	login := panelv1connect.NewAuthServiceClient(p.web, p.srv.URL)
	if _, err := login.Login(e.ctx, connect.NewRequest(&panelv1.LoginRequest{Username: adminUser, Password: adminPassword})); err != nil {
		t.Fatalf("Login: %v", err)
	}
	p.plain = &http.Client{Timeout: waitFor}
	p.geoip = panelv1connect.NewGeoIPServiceClient(p.web, p.srv.URL)
	p.anon = panelv1connect.NewGeoIPServiceClient(p.plain, p.srv.URL)
	return p
}

// dirNames lists the names in a directory, sorted; a directory that is not there
// has none.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out
}

// checkStatus compares two statuses; the times are compared as instants.
func checkStatus(t *testing.T, got, want Status) {
	t.Helper()
	if got.Enabled != want.Enabled || got.Present != want.Present || got.Month != want.Month ||
		got.Size != want.Size || got.SHA256 != want.SHA256 || got.Error != want.Error ||
		!got.Built.Equal(want.Built) || !got.Fetched.Equal(want.Fetched) || !got.Checked.Equal(want.Checked) {
		t.Errorf("status = %+v, want %+v", got, want)
	}
}

// protoEqual reports whether two messages are equal.
func protoEqual(a, b proto.Message) bool { return proto.Equal(a, b) }

// idle waits until no refresh or upload of the manager is under way.
func idle(t *testing.T, m *Manager) {
	t.Helper()
	eventually(t, "the refresh or upload that was under way to end", func() bool {
		select {
		case m.op <- struct{}{}:
			m.release()
			return true
		default:
			return false
		}
	})
}

// importsOfPackage returns the paths that the files of the package, but not its
// tests, import.
func importsOfPackage(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, path)
		}
	}
	return out
}
