package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/argon2"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/totp"
)

const (
	testUser      = "admin"
	testPassword  = "correct horse battery staple"
	otherPassword = "another long passphrase here"
	wrongPassword = "this is not the password"
)

// t0 is where the clock of a test starts.
var t0 = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// fakeClock is a clock that only moves when a test says so.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock { return &fakeClock{now: t0} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// cheapHash is passwd.Hash at a cost that a test can afford to pay many times:
// the same format, so passwd.Verify reads it, with the smallest parameters that
// Verify accepts. Tests that are about the real cost do not use it.
func cheapHash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 1, 8, 1, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=8,t=1,p=1$%s$%s", argon2.Version, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// lockedBuffer is a bytes.Buffer that handlers on several goroutines may write.
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

// env is a panel: a database, a service on a fake clock, and an HTTP server
// with the auth service, a health service and stand-ins for other services
// behind the middleware.
type env struct {
	t       *testing.T
	db      *store.DB
	dbPath  string
	reader  *sql.DB // a second connection, to count what the store has no method to count
	key     seal.Key
	clock   *fakeClock
	logs    *lockedBuffer
	svc     *Service
	mux     *http.ServeMux
	handler http.Handler // the mux behind the middleware
	srv     *httptest.Server

	protectedCalls int // calls that got through to the stand-in of another service, guarded by mu
	downloads      int // calls that got through to the stand-in of a route behind RequireAdmin, guarded by mu
	mu             sync.Mutex
}

// newEnv is a panel that has not been set up: it has no admin, and so a setup
// token.
func newEnv(t *testing.T) *env { return buildEnv(t, false) }

// newEnvAdmin is a panel that has an admin, testUser with testPassword, from
// before the service started.
func newEnvAdmin(t *testing.T) *env { return buildEnv(t, true) }

// newEnvAdminWith is newEnvAdmin with options for the service.
func newEnvAdminWith(t *testing.T, opts ...Option) *env { return buildEnv(t, true, opts...) }

func buildEnv(t *testing.T, withAdmin bool, opts ...Option) *env {
	t.Helper()
	e := &env{t: t, clock: newClock(), logs: &lockedBuffer{}}
	e.dbPath = filepath.Join(t.TempDir(), "panel.db")
	db, err := store.Open(e.dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.db = db
	if _, err := rand.Read(e.key[:]); err != nil {
		t.Fatal(err)
	}
	if withAdmin {
		e.createAdmin(testUser, testPassword)
	}

	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.svc = newService(db, e.key, log, e.clock.Now, opts...)
	e.svc.hash = cheapHash
	// The dummy hash is made once for the whole process at its real cost.
	// Tests that look at it use the service as it comes; the others do not want
	// to wait for it.
	e.svc.dummy, _ = cheapHash("not a password of anybody")

	e.mux = http.NewServeMux()
	path, h := panelv1connect.NewAuthServiceHandler(e.svc)
	e.mux.Handle(path, h)
	path, h = panelv1connect.NewHealthServiceHandler(healthStub{})
	e.mux.Handle(path, h)
	// Stand-ins for the other services of the panel, which are behind the
	// middleware too, and for a route that is not a procedure.
	e.mux.HandleFunc("/postern.panel.v1.NodeService/", func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.protectedCalls++
		e.mu.Unlock()
		name := "nobody"
		if a, ok := AdminFrom(r.Context()); ok {
			name = a.Username
		}
		_, _ = io.WriteString(w, "admin:"+name)
	})
	e.mux.HandleFunc("/assets/app.js", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "js") })
	e.mux.Handle("/download", RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.downloads++
		e.mu.Unlock()
		a, _ := AdminFrom(r.Context())
		_, _ = io.WriteString(w, "admin:"+a.Username)
	})))
	e.handler = e.svc.Middleware(e.mux)
	e.srv = httptest.NewServer(e.handler)
	t.Cleanup(e.srv.Close)

	reader, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	e.reader = reader
	return e
}

type healthStub struct{}

func (healthStub) Check(context.Context, *connect.Request[panelv1.CheckRequest]) (*connect.Response[panelv1.CheckResponse], error) {
	return connect.NewResponse(&panelv1.CheckResponse{}), nil
}

// createAdmin stores an admin directly, as if it had been set up earlier.
func (e *env) createAdmin(username, password string) *store.Admin {
	e.t.Helper()
	h, err := cheapHash(password)
	if err != nil {
		e.t.Fatal(err)
	}
	a := &store.Admin{Username: username, PasswordHash: h, CreatedAt: e.clock.Now()}
	if err := e.db.CreateAdmin(context.Background(), a); err != nil {
		e.t.Fatalf("CreateAdmin: %v", err)
	}
	return a
}

func (e *env) admin(username string) *store.Admin {
	e.t.Helper()
	a, err := e.db.AdminByUsername(context.Background(), username)
	if err != nil {
		e.t.Fatalf("AdminByUsername(%q): %v", username, err)
	}
	return a
}

// count runs a query that returns one integer.
func (e *env) count(query string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.reader.QueryRow(query, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", query, err)
	}
	return n
}

func (e *env) sessions() int { return e.count(`SELECT count(*) FROM sessions`) }

// session returns the stored session of a cookie value.
func (e *env) session(token string) (*store.Session, error) {
	return e.db.SessionByTokenHash(context.Background(), hashToken(token))
}

func (e *env) protectedCallCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.protectedCalls
}

func (e *env) downloadCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.downloads
}

// secretOf returns the TOTP secret of an admin, opened.
func (e *env) secretOf(adminID string) string {
	e.t.Helper()
	a, err := e.db.AdminByID(context.Background(), adminID)
	if err != nil {
		e.t.Fatal(err)
	}
	if len(a.TOTPSecretEnc) == 0 {
		e.t.Fatal("the admin has no TOTP secret")
	}
	plain, err := seal.Open(e.key, a.TOTPSecretEnc, []byte("totp:"+adminID))
	if err != nil {
		e.t.Fatalf("seal.Open: %v", err)
	}
	return string(plain)
}

// code is the TOTP code of a secret at the time of the fake clock.
func (e *env) code(secret string) string {
	e.t.Helper()
	c, err := totp.Code(secret, e.clock.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// badCode is a code that is not valid for the secret now, nor a step before or
// after, so a test that needs a wrong code does not fail once in a million runs.
func (e *env) badCode(secret string) string {
	e.t.Helper()
	valid := map[string]bool{}
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		c, err := totp.Code(secret, e.clock.Now().Add(d))
		if err != nil {
			e.t.Fatal(err)
		}
		valid[c] = true
	}
	for _, c := range []string{"000000", "111111", "222222"} {
		if !valid[c] {
			return c
		}
	}
	e.t.Fatal("no code left to be wrong with")
	return ""
}

// codeAt is the TOTP code of a secret at a time.
func codeAt(secret string, at time.Time) (string, error) { return totp.Code(secret, at) }

// sealOpen opens a sealed value of the test panel with the additional data aad.
func sealOpen(e *env, sealed []byte, aad string) ([]byte, error) {
	return seal.Open(e.key, sealed, []byte(aad))
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// errMessage is the message of a Connect error, without the code.
func errMessage(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Message()
	}
	return ""
}

// roundTripFunc is an http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// browser is a client with a cookie jar, as the SPA is.
type browser struct {
	t    *testing.T
	env  *env
	jar  *cookiejar.Jar
	http *http.Client
	auth panelv1connect.AuthServiceClient
	base *url.URL

	mu  sync.Mutex
	hdr http.Header // sent with every request
}

func (e *env) browser() *browser { return e.browserFor(e.srv) }

func (e *env) browserFor(srv *httptest.Server) *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.t.Fatal(err)
	}
	base, err := url.Parse(srv.URL)
	if err != nil {
		e.t.Fatal(err)
	}
	b := &browser{t: e.t, env: e, jar: jar, hdr: http.Header{}, base: base}
	inner := srv.Client().Transport
	b.http = &http.Client{
		Jar: jar,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			b.mu.Lock()
			for k, vs := range b.hdr {
				r.Header[k] = append([]string(nil), vs...)
			}
			b.mu.Unlock()
			return inner.RoundTrip(r)
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	b.auth = panelv1connect.NewAuthServiceClient(b.http, srv.URL)
	return b
}

// header sets a header that goes with every request of the browser.
func (b *browser) header(k, v string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.hdr.Set(k, v)
}

// token returns the value of the session cookie that the browser holds.
func (b *browser) token() string {
	for _, c := range b.jar.Cookies(b.base) {
		if c.Name == CookieName {
			return c.Value
		}
	}
	return ""
}

// setToken puts a session cookie into the jar, as if the browser had got it
// earlier.
func (b *browser) setToken(token string) {
	b.jar.SetCookies(b.base, []*http.Cookie{{Name: CookieName, Value: token, Path: "/"}})
}

func (b *browser) login(username, password, code string) (*connect.Response[panelv1.LoginResponse], error) {
	return b.auth.Login(context.Background(), connect.NewRequest(&panelv1.LoginRequest{
		Username: username, Password: password, TotpCode: code,
	}))
}

// mustLogin signs testUser in, and fails the test if that does not work.
func (b *browser) mustLogin() string {
	b.t.Helper()
	resp, err := b.login(testUser, testPassword, "")
	if err != nil {
		b.t.Fatalf("Login: %v", err)
	}
	if resp.Msg.GetTotpRequired() {
		b.t.Fatal("Login wants a TOTP code")
	}
	tok := b.token()
	if tok == "" {
		b.t.Fatal("Login set no session cookie")
	}
	return tok
}

func (b *browser) me() (*connect.Response[panelv1.MeResponse], error) {
	return b.auth.Me(context.Background(), connect.NewRequest(&panelv1.MeRequest{}))
}

func (b *browser) logout() (*connect.Response[panelv1.LogoutResponse], error) {
	return b.auth.Logout(context.Background(), connect.NewRequest(&panelv1.LogoutRequest{}))
}

func (b *browser) changePassword(current, next string) (*connect.Response[panelv1.ChangePasswordResponse], error) {
	return b.changePasswordWithCode(current, next, "")
}

func (b *browser) changePasswordWithCode(current, next, code string) (*connect.Response[panelv1.ChangePasswordResponse], error) {
	return b.auth.ChangePassword(context.Background(), connect.NewRequest(&panelv1.ChangePasswordRequest{
		CurrentPassword: current, NewPassword: next, TotpCode: code,
	}))
}

func (b *browser) beginTotp() (*connect.Response[panelv1.BeginTotpResponse], error) {
	return b.auth.BeginTotp(context.Background(), connect.NewRequest(&panelv1.BeginTotpRequest{}))
}

// confirmTotp confirms with the password that the admin of the tests has.
func (b *browser) confirmTotp(code string) (*connect.Response[panelv1.ConfirmTotpResponse], error) {
	return b.confirmTotpWith(code, testPassword)
}

func (b *browser) confirmTotpWith(code, password string) (*connect.Response[panelv1.ConfirmTotpResponse], error) {
	return b.auth.ConfirmTotp(context.Background(), connect.NewRequest(&panelv1.ConfirmTotpRequest{Code: code, Password: password}))
}

func (b *browser) disableTotp(password, code string) (*connect.Response[panelv1.DisableTotpResponse], error) {
	return b.auth.DisableTotp(context.Background(), connect.NewRequest(&panelv1.DisableTotpRequest{Password: password, Code: code}))
}

func (b *browser) setupStatus() bool {
	b.t.Helper()
	resp, err := b.auth.GetSetupStatus(context.Background(), connect.NewRequest(&panelv1.GetSetupStatusRequest{}))
	if err != nil {
		b.t.Fatalf("GetSetupStatus: %v", err)
	}
	return resp.Msg.GetNeedsSetup()
}

func (b *browser) setup(token, username, password string) (*connect.Response[panelv1.SetupResponse], error) {
	return b.auth.Setup(context.Background(), connect.NewRequest(&panelv1.SetupRequest{
		SetupToken: token, Username: username, Password: password,
	}))
}

// enableTotp turns TOTP on for the admin that the browser is signed in as, and
// returns the secret. The clock is moved on by one step, so that the code that
// confirmed the secret is behind the next one.
func (b *browser) enableTotp() string {
	b.t.Helper()
	begin, err := b.beginTotp()
	if err != nil {
		b.t.Fatalf("BeginTotp: %v", err)
	}
	secret := begin.Msg.GetSecret()
	if _, err := b.confirmTotp(b.env.code(secret)); err != nil {
		b.t.Fatalf("ConfirmTotp: %v", err)
	}
	b.env.clock.Advance(30 * time.Second)
	return secret
}

// raw sends a request without a client library.
func (e *env) raw(method, path string, body string, header map[string]string) (*http.Response, string) {
	e.t.Helper()
	return rawTo(e.t, e.srv, method, path, body, header)
}

func rawTo(t *testing.T, srv *httptest.Server, method, path, body string, header map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the response: %v", err)
	}
	return resp, string(out)
}

// callAs sends a procedure with the session cookie of token, as JSON.
func (e *env) callAs(token, procedure, body string) (*http.Response, string) {
	e.t.Helper()
	header := map[string]string{"Content-Type": "application/json"}
	if token != "" {
		header["Cookie"] = CookieName + "=" + token
	}
	return e.raw(http.MethodPost, procedure, body, header)
}

// setCookies parses the cookies that a response sets.
func setCookies(t *testing.T, h http.Header) []*http.Cookie {
	t.Helper()
	var out []*http.Cookie
	for _, line := range h.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			t.Fatalf("Set-Cookie %q: %v", line, err)
		}
		out = append(out, c)
	}
	return out
}

// sessionCookie returns the one cookie of the session that a response sets.
func sessionCookie(t *testing.T, h http.Header) *http.Cookie {
	t.Helper()
	var found *http.Cookie
	for _, c := range setCookies(t, h) {
		if c.Name != CookieName {
			continue
		}
		if found != nil {
			t.Fatalf("the response sets the session cookie twice: %v", h.Values("Set-Cookie"))
		}
		found = c
	}
	if found == nil {
		t.Fatalf("the response sets no session cookie: %v", h.Values("Set-Cookie"))
	}
	return found
}

func wantCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %v", want)
	}
	if got := connect.CodeOf(err); got != want {
		t.Fatalf("code = %v (%v), want %v", got, err, want)
	}
}

func wantOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// tokenHash is what the store keeps of a token.
func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// retryAfter returns the Retry-After header of an error, in seconds.
func retryAfter(t *testing.T, err error) string {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("%v is not a Connect error", err)
	}
	return ce.Meta().Get("Retry-After")
}

func connectLogin(username, password string) *connect.Request[panelv1.LoginRequest] {
	return connect.NewRequest(&panelv1.LoginRequest{Username: username, Password: password})
}

// runningOn is the number of attempts that are running on a key.
func (l *limiter) runningOn(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.buckets[key]; b != nil {
		return b.running
	}
	return 0
}
