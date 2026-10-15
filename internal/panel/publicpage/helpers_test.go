package publicpage

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/argon2"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/links"
	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// update rewrites the goldens under testdata instead of comparing to them.
var update = flag.Bool("update", false, "rewrite the golden files")

const (
	adminUser     = "admin"
	adminPassword = "correct horse battery staple"

	// Made-up proxy secrets. None may show up in a log, and the one of the
	// paused proxy may not show up on the page.
	secretTLS    = "00112233445566778899aabbccddeeff" // gitleaks:allow (a made-up test value)
	secretWeb    = "ffeeddccbbaa99887766554433221100" // gitleaks:allow (a made-up test value)
	secretPaused = "0f0e0d0c0b0a09080706050403020100" // gitleaks:allow (a made-up test value)
	secretGhost  = "123456789abcdef0123456789abcdef0" // gitleaks:allow (a made-up test value)

	publicHost = "proxies.example.test"
	adminHost  = "panel.example.test"
)

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

// env is the package as the panel runs it: a database, the service behind the
// auth middleware and RecordAdminHosts with an admin signed in, and the public
// handler behind a server of its own.
type env struct {
	t      *testing.T
	ctx    context.Context
	db     *store.DB
	dbPath string
	key    seal.Key
	logs   *lockedBuffer
	log    *slog.Logger
	svc    *Service

	// What the probes say: a proxy in down is down. gate, when set, is waited
	// for by every probe lookup, which holds a page render until it is closed.
	downMu sync.Mutex
	down   map[string]bool
	gate   chan struct{}
	probed chan string // every lookup sends the proxy id, when set

	// What the GeoIP database says: the country of an address, by address.
	countryMu sync.Mutex
	countries map[string]string

	api     *httptest.Server // the admin API
	pub     *httptest.Server // the public site
	jar     http.CookieJar
	admin   panelv1connect.PublicPageServiceClient
	anon    panelv1connect.PublicPageServiceClient
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

	e := &env{t: t, ctx: ctx, db: db, dbPath: path, logs: &lockedBuffer{}, down: map[string]bool{}, countries: map[string]string{}}
	if _, err := rand.Read(e.key[:]); err != nil {
		t.Fatal(err)
	}
	e.log = slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log:\n%s", e.logs.String())
		}
	})
	e.svc = NewService(db, e.key, e.log, WithProbeDown(e.probeDown), WithCountry(e.country))

	admin := &store.Admin{Username: adminUser, PasswordHash: cheapHash(t, adminPassword)}
	if err := db.CreateAdmin(ctx, admin); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	e.adminID = admin.ID

	authSvc := auth.NewService(db, e.key, e.log)
	mux := http.NewServeMux()
	mux.Handle(panelv1connect.NewAuthServiceHandler(authSvc))
	mux.Handle(panelv1connect.NewPublicPageServiceHandler(e.svc))
	e.api = httptest.NewServer(authSvc.Middleware(e.svc.RecordAdminHosts(mux)))
	t.Cleanup(e.api.Close)
	e.pub = httptest.NewServer(e.svc.Handler())
	t.Cleanup(e.pub.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	e.jar = jar
	web := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	login := panelv1connect.NewAuthServiceClient(web, e.api.URL)
	if _, err := login.Login(ctx, connect.NewRequest(&panelv1.LoginRequest{Username: adminUser, Password: adminPassword})); err != nil {
		t.Fatalf("Login: %v", err)
	}
	e.admin = panelv1connect.NewPublicPageServiceClient(web, e.api.URL)
	e.anon = panelv1connect.NewPublicPageServiceClient(&http.Client{Timeout: 10 * time.Second}, e.api.URL)
	return e
}

// probeDown is the probe function of the service of the env.
func (e *env) probeDown(id string) bool {
	e.downMu.Lock()
	gate, probed := e.gate, e.probed
	e.downMu.Unlock()
	if probed != nil {
		probed <- id
	}
	if gate != nil {
		<-gate
	}
	e.downMu.Lock()
	defer e.downMu.Unlock()
	return e.down[id]
}

// setDown makes the probes of a proxy fail, or not.
func (e *env) setDown(id string, down bool) {
	e.downMu.Lock()
	defer e.downMu.Unlock()
	e.down[id] = down
}

// country is the GeoIP lookup of the service of the env.
func (e *env) country(ip netip.Addr) string {
	e.countryMu.Lock()
	defer e.countryMu.Unlock()
	return e.countries[ip.String()]
}

// setCountry makes the GeoIP database say that ip is in country.
func (e *env) setCountry(ip, country string) {
	e.countryMu.Lock()
	defer e.countryMu.Unlock()
	e.countries[ip] = country
}

// setPublicIPs sets the public IPs that the panel knows for a node.
func (e *env) setPublicIPs(nodeID string, ips ...string) {
	e.t.Helper()
	if _, err := e.db.ModifyNode(e.ctx, nodeID, func(n *store.Node) error { n.PublicIPs = ips; return nil }); err != nil {
		e.t.Fatalf("ModifyNode: %v", err)
	}
}

// hostTransport sends every request with another Host.
type hostTransport struct {
	host string
	base http.RoundTripper
}

func (h hostTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = h.host
	return h.base.RoundTrip(r)
}

// adminAs is the admin's client with requests that carry host as their Host.
func (e *env) adminAs(host string) panelv1connect.PublicPageServiceClient {
	c := &http.Client{Jar: e.jar, Timeout: 10 * time.Second, Transport: hostTransport{host: host, base: http.DefaultTransport}}
	return panelv1connect.NewPublicPageServiceClient(c, e.api.URL)
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

// node stores a node with a link host, online or offline.
func (e *env) node(name, linkHost string, online bool) *store.Node {
	e.t.Helper()
	n := &store.Node{Name: name, MgmtHost: "198.51.100.1", MgmtPort: 61000, LinkHost: linkHost, Status: store.NodeStatusOffline}
	if online {
		n.Status = store.NodeStatusOnline
	}
	if err := e.db.CreateNode(e.ctx, n); err != nil {
		e.t.Fatalf("CreateNode: %v", err)
	}
	return n
}

// setNodeStatus changes the status of a node.
func (e *env) setNodeStatus(id, status string) {
	e.t.Helper()
	if _, err := e.db.ModifyNode(e.ctx, id, func(n *store.Node) error { n.Status = status; return nil }); err != nil {
		e.t.Fatalf("ModifyNode: %v", err)
	}
}

// listener stores a listener on a node.
func (e *env) listener(nodeID string, port uint32) *store.Listener {
	e.t.Helper()
	l := &store.Listener{NodeID: nodeID, BindIP: "0.0.0.0", Port: port}
	if err := e.db.CreateListener(e.ctx, l); err != nil {
		e.t.Fatalf("CreateListener: %v", err)
	}
	return l
}

// proxy stores a proxy with its secret sealed. p needs NodeID, ListenerID and
// Domain; the rest is filled in.
func (e *env) proxy(p *store.Proxy, secret string) *store.Proxy {
	e.t.Helper()
	p.ID = ids.New()
	if p.Type == "" {
		p.Type = store.ProxyTypeFakeTLS
	}
	sealed, err := seal.Seal(e.key, []byte(secret), []byte("proxy:"+p.ID))
	if err != nil {
		e.t.Fatal(err)
	}
	p.SecretEnc = sealed
	if err := e.db.CreateProxy(e.ctx, p); err != nil {
		e.t.Fatalf("CreateProxy: %v", err)
	}
	return p
}

// setEnabled pauses or resumes a proxy.
func (e *env) setEnabled(id string, enabled bool) {
	e.t.Helper()
	p, err := e.db.ProxyByID(e.ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	p.Enabled = enabled
	if err := e.db.UpdateProxy(e.ctx, p); err != nil {
		e.t.Fatalf("UpdateProxy: %v", err)
	}
}

// fixture is a node with a fake-TLS proxy, a WEB proxy and a paused proxy, and
// a second node without a link host with a proxy that cannot be linked.
type fixture struct {
	node, ghostNode  *store.Node
	listener         *store.Listener
	tls, web, paused *store.Proxy
	ghost            *store.Proxy
	page             *panelv1.PublicPage
}

// fixture builds the fixture of the goldens and saves its page through the API.
func (e *env) fixture() *fixture {
	e.t.Helper()
	f := &fixture{}
	f.node = e.node("node-one", "proxy.example.com", true)
	f.listener = e.listener(f.node.ID, 443)
	f.tls = e.proxy(&store.Proxy{NodeID: f.node.ID, ListenerID: f.listener.ID, Name: "admin-name-alpha", Note: "admin note alpha",
		Domain: "www.example.com", Enabled: true}, secretTLS)
	f.web = e.proxy(&store.Proxy{NodeID: f.node.ID, ListenerID: f.listener.ID, Type: store.ProxyTypeWeb, Name: "admin-name-web",
		Domain: "web.example.com", WebBasePath: "telegram/web", WebSecretMode: links.ModeDD, Enabled: true}, secretWeb)
	f.paused = e.proxy(&store.Proxy{NodeID: f.node.ID, ListenerID: f.listener.ID, Name: "admin-name-paused",
		Domain: "paused.example.com", Enabled: false}, secretPaused)
	f.ghostNode = e.node("node-ghost", "", true)
	l2 := e.listener(f.ghostNode.ID, 443)
	f.ghost = e.proxy(&store.Proxy{NodeID: f.ghostNode.ID, ListenerID: l2.ID, Name: "admin-name-ghost",
		Domain: "ghost.example.com", Enabled: true}, secretGhost)

	f.page = &panelv1.PublicPage{
		Enabled: true, Host: publicHost, Title: "Our proxies",
		BodyMd:      "Welcome! Pick a proxy below.\n\n## How to connect\n\nTap a row, or enter it by hand; see [the FAQ](https://example.com/faq).\n",
		Unavailable: store.PublicUnavailableMark, DefaultLocale: localeRU, // allow_indexing left out: noindex stays on
		Items: []*panelv1.PublicPageItem{
			{ProxyId: f.tls.ID, PublicName: "Alpha", PublicNote: "Fast and stable"},
			{ProxyId: f.web.ID, PublicName: "Web proxy"},
			{ProxyId: f.paused.ID, PublicName: "Paused one", PublicNote: "Back soon"},
			{ProxyId: f.ghost.ID, PublicName: "Ghost"},
		},
	}
	e.setPage(f.page)
	return f
}

// setPage saves a page through the API, as the admin UI does.
func (e *env) setPage(p *panelv1.PublicPage) *panelv1.PublicPage {
	e.t.Helper()
	resp, err := e.admin.UpdatePublicPage(e.ctx, connect.NewRequest(&panelv1.UpdatePublicPageRequest{Page: p}))
	if err != nil {
		e.t.Fatalf("UpdatePublicPage: %v", err)
	}
	return resp.Msg.GetPage()
}

// get requests a path of the public site with host as the Host.
func (e *env) get(method, path, host string, header map[string]string) (*http.Response, string) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.pub.URL+path, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Host = host
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := e.pub.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, string(data)
}

// page requests the page in a language.
func (e *env) page(lang string) string {
	e.t.Helper()
	path := "/"
	if lang != "" {
		path += "?lang=" + lang
	}
	resp, body := e.get(http.MethodGet, path, publicHost, nil)
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("GET %s: status %d, body %.200q", path, resp.StatusCode, body)
	}
	return body
}

// golden compares got to the golden file, or rewrites it with -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the golden: %v (run with -update to write it)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden (run with -update to rewrite it):\n%s", name, diffLines(string(want), got))
	}
}

// diffLines shows the first lines that differ.
func diffLines(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	for i := 0; i < max(len(w), len(g)); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			fmt.Fprintf(&b, "line %d:\n  want %q\n  got  %q\n", i+1, wl, gl)
			if b.Len() > 2000 {
				break
			}
		}
	}
	return b.String()
}

// auditLog returns the audit log as "action target admin" lines, oldest first.
func (e *env) auditLog() []string {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath)+"?mode=ro")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT action, target, admin_id FROM audit_log WHERE action NOT LIKE 'auth.%' ORDER BY ts, rowid`) // not the sign-in of the test
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var action, target, admin string
		if err := rows.Scan(&action, &target, &admin); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, action+" "+target+" "+admin)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// assertNoSecretsLogged fails the test if a made-up secret is in the log.
func (e *env) assertNoSecretsLogged() {
	e.t.Helper()
	logs := strings.ToLower(e.logs.String())
	for _, s := range []string{secretTLS, secretWeb, secretPaused, secretGhost} {
		if strings.Contains(logs, s) {
			e.t.Errorf("the log contains a proxy secret")
		}
	}
}

// wantCode fails the test unless err is a Connect error with this code.
func wantCode(t *testing.T, err error, want connect.Code) *connect.Error {
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
	return ce
}
