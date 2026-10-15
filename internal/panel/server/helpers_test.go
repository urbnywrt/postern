package server

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/auth"
)

const (
	adminName     = "admin"
	adminPassword = "correct horse battery staple"

	// waitFor is how long a test waits for something that happens in the
	// background.
	waitFor = 10 * time.Second
)

// Paths of the procedures that the tests call by hand.
const (
	healthCheck    = "/api/postern.panel.v1.HealthService/Check"
	listProxies    = "/api/postern.panel.v1.ProxyService/ListProxies"
	createNodePath = "/api/postern.panel.v1.NodeService/CreateNode"
	loginPath      = "/api/postern.panel.v1.AuthService/Login"
)

// closedBase is the address of a directory on a loopback port that nothing
// listens on: where the panels of the tests look for their country database, so
// that none of them makes a request to DB-IP.
func closedBase(t *testing.T) string {
	t.Helper()
	ln := listener(t)
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return "http://" + addr
}

// lockedBuffer is a buffer that several goroutines may write to and read.
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

// panel is a panel in temporary directories, with its handler behind an HTTP
// test server.
type panel struct {
	t       *testing.T
	srv     *Server
	cfg     Config
	dataDir string
	keysDir string
	logs    *lockedBuffer
	out     *lockedBuffer
	ts      *httptest.Server
	plain   *http.Client // no cookies, does not follow redirects
}

// newPanel builds a panel as the serve command does, in fresh directories.
// tweak changes the configuration first.
func newPanel(t *testing.T, tweak ...func(*Config)) *panel {
	t.Helper()
	dir := t.TempDir()
	p := &panel{
		t:       t,
		dataDir: filepath.Join(dir, "data"),
		keysDir: filepath.Join(dir, "keys"),
		logs:    &lockedBuffer{},
		out:     &lockedBuffer{},
	}
	return p.start(tweak...)
}

// start builds the server from the directories of the panel, which it makes
// again after a stop.
func (p *panel) start(tweak ...func(*Config)) *panel {
	p.t.Helper()
	p.out = &lockedBuffer{} // what the operator sees of this start; the logs go on
	p.cfg = Config{
		DataDir: p.dataDir,
		KeysDir: p.keysDir,
		Listen:  "127.0.0.1:0",
		Log:     slog.New(slog.NewTextHandler(p.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Out:     p.out,
		// A panel that serves looks for its country database: not at DB-IP.
		GeoIPBaseURL:         closedBase(p.t),
		CloudflareRangesURLs: []string{closedBase(p.t) + "/ips-v4"},
	}
	for _, f := range tweak {
		f(&p.cfg)
	}
	srv, err := New(p.cfg)
	if err != nil {
		p.t.Fatalf("New: %v", err)
	}
	// A panel of a test does not look for its country database unless the test
	// says so (enableGeoIP): a closed port is no source, and the look that fails
	// would be an event in every list of events.
	if err := srv.db.PutSetting(context.Background(), "geoip", map[string]bool{"enabled": false}); err != nil {
		p.t.Fatalf("PutSetting: %v", err)
	}
	p.srv = srv
	p.t.Cleanup(func() { _ = srv.Close() })
	p.ts = httptest.NewServer(srv.Handler())
	p.t.Cleanup(p.ts.Close)
	p.plain = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return p
}

func (p *panel) url(path string) string { return p.ts.URL + path }

// do sends a request without cookies and returns the response with its body.
func (p *panel) do(method, path string, body io.Reader, header map[string]string) (*http.Response, string) {
	p.t.Helper()
	return send(p.t, p.plain, method, p.url(path), body, header)
}

func (p *panel) get(path string) (*http.Response, string) {
	p.t.Helper()
	return p.do(http.MethodGet, path, nil, nil)
}

// post sends a JSON request to a procedure.
func (p *panel) post(path, body string) (*http.Response, string) {
	p.t.Helper()
	return p.do(http.MethodPost, path, strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
}

func send(t *testing.T, client *http.Client, method, url string, body io.Reader, header map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: reading the body: %v", method, url, err)
	}
	return resp, string(data)
}

// gzipped compresses s.
func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := io.WriteString(zw, s); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A browser is a client with a cookie jar, as the SPA is.
type browser struct {
	t    *testing.T
	p    *panel
	http *http.Client
	auth panelv1connect.AuthServiceClient
	node panelv1connect.NodeServiceClient
}

func (p *panel) browser() *browser {
	p.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		p.t.Fatal(err)
	}
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &browser{
		t:    p.t,
		p:    p,
		http: c,
		auth: panelv1connect.NewAuthServiceClient(c, p.ts.URL+"/api"),
		node: panelv1connect.NewNodeServiceClient(c, p.ts.URL+"/api"),
	}
}

// signIn sets the panel up and signs in, as an operator does: with the setup
// token that the panel made, Setup, Login.
func (p *panel) signIn() *browser {
	p.t.Helper()
	token, ok := p.srv.auth.SetupToken()
	if !ok {
		p.t.Fatal("the panel has no setup token")
	}
	b := p.browser()
	ctx := context.Background()
	if _, err := b.auth.Setup(ctx, connect.NewRequest(&panelv1.SetupRequest{
		SetupToken: token, Username: adminName, Password: adminPassword,
	})); err != nil {
		p.t.Fatalf("Setup: %v", err)
	}
	resp, err := b.auth.Login(ctx, connect.NewRequest(&panelv1.LoginRequest{Username: adminName, Password: adminPassword}))
	if err != nil {
		p.t.Fatalf("Login: %v", err)
	}
	if resp.Msg.GetTotpRequired() {
		p.t.Fatal("Login wants a TOTP code")
	}
	return b
}

func (b *browser) do(method, path string, body io.Reader, header map[string]string) (*http.Response, string) {
	b.t.Helper()
	return send(b.t, b.http, method, b.p.url(path), body, header)
}

func (b *browser) get(path string) (*http.Response, string) {
	b.t.Helper()
	return b.do(http.MethodGet, path, nil, nil)
}

// cookieHeader is the Cookie header that the browser sends to the panel: the
// session cookie, for a request that goes to the handler without the client.
func (b *browser) cookieHeader() string {
	b.t.Helper()
	u, err := url.Parse(b.p.ts.URL)
	if err != nil {
		b.t.Fatal(err)
	}
	for _, c := range b.http.Jar.Cookies(u) {
		if c.Name == auth.CookieName {
			return c.Name + "=" + c.Value
		}
	}
	b.t.Fatal("the browser has no session cookie")
	return ""
}

func (b *browser) post(path, body string) (*http.Response, string) {
	b.t.Helper()
	return b.do(http.MethodPost, path, strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
}

// createNode creates a node through the API and returns its id and the path of
// its bundle.
func (b *browser) createNode(name string) (id, bundleURL string) {
	b.t.Helper()
	resp, err := b.node.CreateNode(context.Background(), connect.NewRequest(&panelv1.CreateNodeRequest{
		Name: name, MgmtHost: "192.0.2.10", MgmtPort: 61443,
	}))
	if err != nil {
		b.t.Fatalf("CreateNode: %v", err)
	}
	return resp.Msg.GetNode().GetId(), resp.Msg.GetBundleUrl()
}

// listener is a TCP listener on a free loopback port.
func listener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// loginRequest is the login of the admin that signIn makes.
func loginRequest() *connect.Request[panelv1.LoginRequest] {
	return connect.NewRequest(&panelv1.LoginRequest{Username: adminName, Password: adminPassword})
}

// logoutLast moves the procedure that ends the session of the admin to the end of
// a list of procedures that a test calls with that session.
func logoutLast(procedures []string) {
	slices.SortStableFunc(procedures, func(x, y string) int {
		return cmp.Compare(boolToInt(strings.HasSuffix(x, "/Logout")), boolToInt(strings.HasSuffix(y, "/Logout")))
	})
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
