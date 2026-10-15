package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/passwd"
)

const (
	listNodes = "/postern.panel.v1.NodeService/ListNodes"
	authPath  = "/postern.panel.v1.AuthService/"
)

func TestMiddlewareBlocksProceduresWithoutASession(t *testing.T) {
	e := newEnvAdmin(t)

	// A procedure of another service.
	resp, body := e.callAs("", listNodes, `{}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401; body %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type %q", ct)
	}
	if !strings.Contains(body, `"code":"unauthenticated"`) {
		t.Errorf("body %s is not a Connect error of code unauthenticated", body)
	}
	if n := e.protectedCallCount(); n != 0 {
		t.Errorf("the handler ran %d times", n)
	}

	// The same for the procedures of the auth service that are not public,
	// seen through a Connect client.
	b := e.browser()
	for name, call := range map[string]func() error{
		"Logout":         func() error { _, err := b.logout(); return err },
		"Me":             func() error { _, err := b.me(); return err },
		"ChangePassword": func() error { _, err := b.changePassword(testPassword, otherPassword); return err },
		"BeginTotp":      func() error { _, err := b.beginTotp(); return err },
		"ConfirmTotp":    func() error { _, err := b.confirmTotp("123456"); return err },
		"DisableTotp":    func() error { _, err := b.disableTotp(testPassword, "123456"); return err },
	} {
		err := call()
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s without a session: %v", name, err)
		}
	}

	// A browser that is not a Connect client gets an error that it can read, too.
	resp, body = e.raw(http.MethodGet, listNodes, "", nil)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "unauthenticated") {
		t.Errorf("GET: status %d, body %s", resp.StatusCode, body)
	}
}

func TestMiddlewareLetsThePublicProceduresIn(t *testing.T) {
	e := newEnv(t)
	b := e.browser()

	if !b.setupStatus() {
		t.Error("GetSetupStatus needs setup")
	}
	// Setup and Login are the services' own answers, not the middleware's:
	// their errors say what is wrong with the request.
	_, err := b.setup("wrong", "admin", testPassword)
	wantCode(t, err, connect.CodePermissionDenied)
	_, err = b.login("nobody", "whatever password", "")
	wantCode(t, err, connect.CodeUnauthenticated)
	if got := errMessage(err); got == "authentication required" {
		t.Error("Login was answered by the middleware")
	}

	resp, body := e.callAs("", "/postern.panel.v1.HealthService/Check", `{}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HealthService.Check: status %d, body %s", resp.StatusCode, body)
	}
}

func TestMiddlewarePassesTheAdminOn(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	token := b.mustLogin()

	resp, body := e.callAs(token, listNodes, `{}`)
	if resp.StatusCode != http.StatusOK || body != "admin:"+testUser {
		t.Errorf("status %d, body %q, want the admin in the context of the handler", resp.StatusCode, body)
	}
	if n := e.protectedCallCount(); n != 1 {
		t.Errorf("handler ran %d times, want 1", n)
	}
}

// Routes that are not procedures are not the middleware's to refuse: the SPA
// and its assets have to load before anybody has signed in. A route that is for
// admins only is put behind RequireAdmin, as /download is.
func TestMiddlewareLeavesOtherRoutesToTheirHandlers(t *testing.T) {
	e := newEnvAdmin(t)
	if resp, body := e.raw(http.MethodGet, "/assets/app.js", "", nil); resp.StatusCode != http.StatusOK || body != "js" {
		t.Errorf("asset: status %d, body %q", resp.StatusCode, body)
	}
	if resp, _ := e.raw(http.MethodGet, "/download", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/download without a session: status %d, want the 401 of RequireAdmin", resp.StatusCode)
	}
	token := e.browser().mustLogin()
	resp, body := e.raw(http.MethodGet, "/download", "", map[string]string{"Cookie": CookieName + "=" + token})
	if resp.StatusCode != http.StatusOK || body != "admin:"+testUser {
		t.Errorf("/download with a session: status %d, body %q", resp.StatusCode, body)
	}
	// Not a procedure, not found: still the mux's business.
	if resp, _ := e.raw(http.MethodGet, "/nothing/here", "", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown route: status %d, want 404", resp.StatusCode)
	}
}

// If the middleware is mounted outside of a prefix that is stripped later, or
// the path has a stray slash, a protected procedure is still protected.
func TestMiddlewareProtectsProceduresUnderOddPaths(t *testing.T) {
	e := newEnvAdmin(t)
	for _, path := range []string{
		"/api" + listNodes,
		"/api/v2" + listNodes,
		listNodes + "/",
		"//postern.panel.v1.NodeService/ListNodes",
		"/api" + authPath + "Me",
		authPath + "Me/",
		"/api" + authPath + "Logout",
	} {
		resp, body := e.callAs("", path, `{}`)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d (%s), want 401", path, resp.StatusCode, body)
		}
	}
	if n := e.protectedCallCount(); n != 0 {
		t.Errorf("a handler ran %d times", n)
	}

	// A public procedure is public under a prefix, too: this one gets as far as
	// the mux, which does not know the path.
	resp, _ := e.callAs("", "/api"+authPath+"Login", `{}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("/api Login: status %d, want 404 from the mux, not 401 from the middleware", resp.StatusCode)
	}
}

func TestProcedureOf(t *testing.T) {
	for path, want := range map[string]string{
		"/postern.panel.v1.AuthService/Login":       "/postern.panel.v1.AuthService/Login",
		"/postern.panel.v1.AuthService/Login/":      "/postern.panel.v1.AuthService/Login",
		"//postern.panel.v1.AuthService/Login":      "/postern.panel.v1.AuthService/Login",
		"/api/postern.panel.v1.AuthService/Login":   "/postern.panel.v1.AuthService/Login",
		"/a/b/c/postern.panel.v1.NodeService/Get_1": "/postern.panel.v1.NodeService/Get_1",
		"/grpc.health.v1.Health/Check":              "/grpc.health.v1.Health/Check",
		"/":                                         "",
		"":                                          "",
		"/index.html":                               "",
		"/assets/app.js":                            "",
		"/settings/profile":                         "",
		"/postern.panel.v1.AuthService":             "",
		"/postern.panel.v1.AuthService/":            "",
		"/postern..panel/Login":                     "",
		"/.hidden/Login":                            "",
		"/postern.panel.v1.AuthService/Lo gin":      "",
		"/postern.panel.v1.AuthService/Lo-gin":      "",
		"/postern.panel.v1.AuthService/Login.js":    "",
		"/postern.panel.v1.AuthService/1Login":      "",
	} {
		got, ok := procedureOf(path)
		if got != want || ok != (want != "") {
			t.Errorf("procedureOf(%q) = %q, %v, want %q", path, got, ok, want)
		}
	}
}

func TestSessionExpires(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	token := b.mustLogin()

	e.clock.Advance(7*24*time.Hour - time.Second)
	if _, err := b.me(); err != nil {
		t.Fatalf("Me just before the end: %v", err)
	}
	// That request slid the session on, so go a whole week from there.
	e.clock.Advance(7 * 24 * time.Hour)
	_, err := b.me()
	wantCode(t, err, connect.CodeUnauthenticated)
	if _, err := e.session(token); err == nil {
		t.Error("the expired session is still stored")
	}
}

func TestSessionSlidesAtMostOncePerHour(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	token := b.mustLogin()
	week := 7 * 24 * time.Hour
	expiry := func() time.Time {
		s, err := e.session(token)
		if err != nil {
			t.Fatal(err)
		}
		return s.ExpiresAt
	}
	start := e.clock.Now()

	// Half an hour in: not touched, and no new cookie.
	e.clock.Advance(30 * time.Minute)
	resp, err := b.me()
	wantOK(t, err)
	if got := expiry(); !got.Equal(start.Add(week)) {
		t.Errorf("expiry after 30 min = %v, want unchanged %v", got, start.Add(week))
	}
	if n := len(resp.Header().Values("Set-Cookie")); n != 0 {
		t.Errorf("a cookie was set without a touch: %v", resp.Header().Values("Set-Cookie"))
	}

	// Exactly an hour is still not past it.
	e.clock.Advance(30 * time.Minute)
	_, err = b.me()
	wantOK(t, err)
	if got := expiry(); !got.Equal(start.Add(week)) {
		t.Errorf("expiry after 60 min = %v, want unchanged", got)
	}

	// Past the hour: a week from now, and the cookie says so too.
	e.clock.Advance(time.Minute)
	resp, err = b.me()
	wantOK(t, err)
	touched := e.clock.Now()
	if got := expiry(); !got.Equal(touched.Add(week)) {
		t.Errorf("expiry after 61 min = %v, want %v", got, touched.Add(week))
	}
	c := sessionCookie(t, resp.Header())
	if c.Value != token || c.MaxAge != int(week/time.Second) || !c.Expires.Equal(touched.Add(week)) ||
		!c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("refreshed cookie %+v", c)
	}

	// And then not again for an hour.
	e.clock.Advance(59 * time.Minute)
	resp, err = b.me()
	wantOK(t, err)
	if got := expiry(); !got.Equal(touched.Add(week)) {
		t.Errorf("expiry moved again after 59 min: %v", got)
	}
	if n := len(resp.Header().Values("Set-Cookie")); n != 0 {
		t.Errorf("a cookie was set without a touch: %v", resp.Header().Values("Set-Cookie"))
	}
	e.clock.Advance(2 * time.Minute)
	if _, err := b.me(); err != nil {
		t.Fatal(err)
	}
	if got := expiry(); !got.Equal(e.clock.Now().Add(week)) {
		t.Errorf("expiry after another hour = %v, want %v", got, e.clock.Now().Add(week))
	}
}

// A session that is active stays: the week counts from the last touch.
func TestSessionOutlivesAWeekWhileItIsUsed(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	for range 20 { // 20 days, a visit every day
		e.clock.Advance(24 * time.Hour)
		if _, err := b.me(); err != nil {
			t.Fatalf("day %v: %v", e.clock.Now().Sub(t0), err)
		}
	}
}

func TestMiddlewareRejectsCookiesThatAreNotSessions(t *testing.T) {
	e := newEnvAdmin(t)
	valid := e.browser().mustLogin()
	other := base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // well formed, unknown

	flipped := []byte(valid)
	if flipped[0] == 'A' {
		flipped[0] = 'B'
	} else {
		flipped[0] = 'A'
	}
	for name, token := range map[string]string{
		"empty":                "",
		"short":                "abc",
		"long":                 valid + "A",
		"padded":               valid + "=",
		"not base64url":        strings.Repeat("!", 43),
		"standard base64":      strings.Repeat("+", 43),
		"unknown":              other,
		"one character off":    string(flipped),
		"the stored hash":      tokenHash(valid),
		"a token with a space": valid[:20] + " " + valid[21:],
	} {
		resp, body := e.callAs(token, listNodes, `{}`)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d (%s), want 401", name, resp.StatusCode, body)
		}
	}
	// And the real one is still fine.
	if resp, _ := e.callAs(valid, listNodes, `{}`); resp.StatusCode != http.StatusOK {
		t.Errorf("the valid token: status %d", resp.StatusCode)
	}
}

// Another cookie, or the right name on another path, is not the session.
func TestMiddlewareReadsOnlyTheSessionCookie(t *testing.T) {
	e := newEnvAdmin(t)
	token := e.browser().mustLogin()
	resp, _ := e.raw(http.MethodPost, listNodes, `{}`, map[string]string{
		"Content-Type": "application/json",
		"Cookie":       "other=" + token + "; " + CookieName + "x=" + token,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", resp.StatusCode)
	}
	resp, _ = e.raw(http.MethodPost, listNodes, `{}`, map[string]string{
		"Content-Type": "application/json",
		"Cookie":       "other=1; " + CookieName + "=" + token + "; more=2",
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200 with the cookie among others", resp.StatusCode)
	}
}

// If the database cannot say who the caller is, the answer is not "yes" and not
// "no, sign in again".
func TestMiddlewareFailsClosedWhenTheStoreFails(t *testing.T) {
	e := newEnvAdmin(t)
	token := e.browser().mustLogin()
	if err := e.db.Close(); err != nil {
		t.Fatal(err)
	}
	resp, body := e.callAs(token, listNodes, `{}`)
	if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(body, `"code":"internal"`) {
		t.Errorf("status %d, body %s, want a Connect error of code internal", resp.StatusCode, body)
	}
	if n := e.protectedCallCount(); n != 0 {
		t.Error("the handler ran")
	}
	if strings.Contains(body, "sql") || strings.Contains(body, "database") {
		t.Errorf("the error tells what failed inside: %s", body)
	}
	// A public route does not need the database to be served.
	if resp, _ := e.callAs(token, "/postern.panel.v1.HealthService/Check", `{}`); resp.StatusCode != http.StatusOK {
		t.Errorf("HealthService.Check: status %d", resp.StatusCode)
	}
}

// What anybody can send to the public procedures is bounded.
func TestMiddlewareBoundsTheBodiesOfPublicProcedures(t *testing.T) {
	e := newEnvAdmin(t)
	var calls atomic.Int32
	real := e.svc.verify
	e.svc.verify = func(encoded, password string) (bool, error) {
		calls.Add(1)
		return real(encoded, password)
	}
	big := `{"username":"admin","password":"` + strings.Repeat("p", 1<<20) + `"}`
	for _, procedure := range []string{"Login", "Setup"} {
		resp, body := e.callAs("", authPath+procedure, big)
		// Not the answer of the procedure to a password that is too long, which
		// is a wrong password or a bad request, but a refusal to read it.
		if !strings.Contains(body, `"code":"resource_exhausted"`) {
			t.Errorf("%s with a body of 1 MiB: status %d, body %s, want a Connect error of code resource_exhausted",
				procedure, resp.StatusCode, body)
		}
		if len(body) > 1000 {
			t.Errorf("%s: the answer is %d bytes", procedure, len(body))
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d passwords were checked", n)
	}
	// Requests of a normal size are not touched by it.
	if _, err := e.browser().login(testUser, testPassword, ""); err != nil {
		t.Errorf("Login: %v", err)
	}
}

func TestSessionToken(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		token, hash, err := newToken()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(raw) != 32 || len(token) != 43 {
			t.Fatalf("token %q: %d bytes of base64url, %v", token, len(raw), err)
		}
		if hash != tokenHash(token) || len(hash) != 64 {
			t.Fatalf("hash %q is not the hex SHA-256 of the token", hash)
		}
		if seen[token] {
			t.Fatal("a token came twice")
		}
		seen[token] = true
	}
}

func TestAdminFromWithoutTheMiddleware(t *testing.T) {
	if a, ok := AdminFrom(context.Background()); ok || a != nil {
		t.Errorf("AdminFrom(background) = %v, %v", a, ok)
	}
}

// The admin that a handler gets is its own copy.
func TestAdminFromReturnsACopy(t *testing.T) {
	e := newEnvAdmin(t)
	var seen string
	e.mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		a, _ := AdminFrom(r.Context())
		a.Username = "changed"
		a.TOTPSecretEnc = []byte("x")
		b, ok := AdminFrom(r.Context())
		if ok {
			seen = b.Username
		}
	})
	token := e.browser().mustLogin()
	e.raw(http.MethodGet, "/probe", "", map[string]string{"Cookie": CookieName + "=" + token})
	if seen != testUser {
		t.Errorf("the second AdminFrom saw %q, want the unchanged %q", seen, testUser)
	}
}

// clientIP believes an X-Forwarded-For header only from the peers that were
// configured as proxies (Ruling 15). A Service made as a literal, as here, has
// none unless the case names them.
func TestClientIP(t *testing.T) {
	proxy := netip.MustParsePrefix("198.51.100.0/24")
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
	docker := []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}
	for _, c := range []struct {
		name    string
		remote  string
		xff     []string
		trusted []netip.Prefix
		want    string
	}{
		{"direct", "203.0.113.9:4000", nil, nil, "203.0.113.9"},
		{"direct ipv6", "[2001:db8::7]:4000", nil, nil, "2001:db8::7"},
		{"a header from a stranger is ignored", "203.0.113.9:4000", []string{"192.0.2.1"}, nil, "203.0.113.9"},
		{"a header from a stranger is ignored, whoever is trusted", "203.0.113.9:4000", []string{"192.0.2.1"}, loopback, "203.0.113.9"},

		// Nothing is a proxy by being on the loopback or a private network.
		{"loopback is not a proxy unless configured", "127.0.0.1:4000", []string{"192.0.2.1"}, nil, "127.0.0.1"},
		{"ipv6 loopback is not a proxy unless configured", "[::1]:4000", []string{"192.0.2.1"}, nil, "::1"},
		{"a private peer is not a proxy", "10.1.2.3:4000", []string{"192.0.2.1"}, nil, "10.1.2.3"},
		{"a private peer is not a proxy, whoever else is trusted", "10.1.2.3:4000", []string{"192.0.2.1"}, loopback, "10.1.2.3"},
		{"a unique local ipv6 peer is not a proxy", "[fd00::5]:4000", []string{"192.0.2.1"}, nil, "fd00::5"},
		{"a link-local peer is not a proxy", "169.254.1.2:4000", []string{"192.0.2.1"}, nil, "169.254.1.2"},
		{"a link-local ipv6 peer is not a proxy", "[fe80::1]:4000", []string{"192.0.2.1"}, nil, "fe80::1"},
		{"a configured private range", "172.18.0.1:4000", []string{"203.0.113.5"}, docker, "203.0.113.5"},
		{"a private peer outside the configured private range", "10.1.2.3:4000", []string{"203.0.113.5"}, docker, "10.1.2.3"},

		{"loopback is a proxy when configured", "127.0.0.1:4000", []string{"192.0.2.1"}, loopback, "192.0.2.1"},
		{"ipv6 loopback is a proxy when configured", "[::1]:4000", []string{"192.0.2.1"}, loopback, "192.0.2.1"},
		{"mapped loopback is a proxy when configured", "[::ffff:127.0.0.1]:4000", []string{"192.0.2.1"}, loopback, "192.0.2.1"},
		{"loopback without a header", "127.0.0.1:4000", nil, loopback, "127.0.0.1"},
		{"configured proxy", "198.51.100.2:4000", []string{"203.0.113.5"}, []netip.Prefix{proxy}, "203.0.113.5"},
		{"configured proxy, not configured", "198.51.100.2:4000", []string{"203.0.113.5"}, nil, "198.51.100.2"},
		{"the chain is read from the right", "198.51.100.2:4000",
			[]string{"192.0.2.1, 203.0.113.5, 198.51.100.3"}, []netip.Prefix{proxy}, "203.0.113.5"},
		{"a client cannot put its address first", "198.51.100.2:4000",
			[]string{"192.0.2.99", "203.0.113.5"}, []netip.Prefix{proxy}, "203.0.113.5"},
		{"several header lines", "198.51.100.2:4000",
			[]string{"192.0.2.1", "203.0.113.5, 198.51.100.3"}, []netip.Prefix{proxy}, "203.0.113.5"},
		{"only proxies in the chain", "198.51.100.2:4000", []string{"198.51.100.9, 198.51.100.3"}, []netip.Prefix{proxy}, "198.51.100.9"},
		// Only the proxies that were configured are skipped on the way to the
		// client: a private address in the chain is the client, as far as the
		// panel can tell, not another proxy.
		{"a private address in the chain is not skipped", "127.0.0.1:4000", []string{"203.0.113.5, 10.0.0.9"}, loopback, "10.0.0.9"},
		{"a loopback address in the chain is not skipped", "198.51.100.2:4000", []string{"203.0.113.5, 127.0.0.1"}, []netip.Prefix{proxy}, "127.0.0.1"},
		{"a port in the header", "127.0.0.1:4000", []string{"203.0.113.5:55555"}, loopback, "203.0.113.5"},
		{"an ipv6 address with a port", "127.0.0.1:4000", []string{"[2001:db8::5]:55555"}, loopback, "2001:db8::5"},
		{"a zone is dropped", "127.0.0.1:4000", []string{"fe80::1%eth0"}, loopback, "fe80::1"},
		{"garbage in the header", "127.0.0.1:4000", []string{"not an address"}, loopback, "127.0.0.1"},
		{"garbage next to the proxy", "127.0.0.1:4000", []string{"203.0.113.5, garbage"}, loopback, "127.0.0.1"},
		{"empty header", "127.0.0.1:4000", []string{" "}, loopback, "127.0.0.1"},
		{"mapped addresses are unmapped", "[::ffff:203.0.113.9]:4000", nil, nil, "203.0.113.9"},
		{"no port", "203.0.113.9", nil, nil, "203.0.113.9"},
		{"not an address", "@", nil, nil, "unknown"},
		{"empty", "", nil, nil, "unknown"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &Service{trusted: c.trusted}
			h := http.Header{}
			for _, v := range c.xff {
				h.Add("X-Forwarded-For", v)
			}
			if got := s.clientIP(c.remote, h); got != c.want {
				t.Errorf("clientIP(%q, %q) = %q, want %q", c.remote, c.xff, got, c.want)
			}
		})
	}
}

// forwardedHTTPS believes X-Forwarded-Proto on the terms of X-Forwarded-For:
// from a proxy of the panel only, and of its values the last only (Ruling 37).
func TestForwardedHTTPS(t *testing.T) {
	s := &Service{trusted: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("::1/128")}}
	for _, c := range forwardedProtoCases {
		t.Run(c.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range c.values {
				h.Add("X-Forwarded-Proto", v)
			}
			for _, proxy := range []string{"198.51.100.7:4000", "[::1]:4000", "[::ffff:198.51.100.7]:4000", "198.51.100.7"} {
				if got := s.forwardedHTTPS(proxy, h); got != c.want {
					t.Errorf("X-Forwarded-Proto %q from the proxy %s: %v, want %v", c.values, proxy, got, c.want)
				}
			}
			for _, other := range []string{"203.0.113.9:4000", "127.0.0.1:4000", "[2001:db8::1]:4000", "", "@"} {
				if s.forwardedHTTPS(other, h) {
					t.Errorf("X-Forwarded-Proto %q from %q, which is not a proxy, is believed", c.values, other)
				}
			}
		})
	}
}

func TestIPKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":          "203.0.113.9",
		"2001:db8:1:2::1":      "2001:db8:1:2::/64",
		"2001:db8:1:2:f::ffff": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"::1":                  "::/64",
		"unknown":              "unknown",
	} {
		if got := ipKey(in); got != want {
			t.Errorf("ipKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// RequireAdmin is for the routes that are not procedures, such as a download:
// the middleware finds the admin, and this refuses the request without one.
func TestRequireAdmin(t *testing.T) {
	e := newEnvAdmin(t)

	resp, body := e.raw(http.MethodGet, "/download", "", nil)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, `"code":"unauthenticated"`) {
		t.Errorf("without a session: status %d, body %s, want 401 and a Connect error of code unauthenticated", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type %q", ct)
	}
	// A cookie that is not a session is no better.
	resp, _ = e.raw(http.MethodGet, "/download", "", map[string]string{"Cookie": CookieName + "=" + strings.Repeat("A", 43)})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("with an unknown token: status %d, want 401", resp.StatusCode)
	}
	if n := e.downloadCount(); n != 0 {
		t.Fatalf("the handler ran %d times for requests without a session", n)
	}

	token := e.browser().mustLogin()
	resp, body = e.raw(http.MethodGet, "/download", "", map[string]string{"Cookie": CookieName + "=" + token})
	if resp.StatusCode != http.StatusOK || body != "admin:"+testUser {
		t.Errorf("with a session: status %d, body %q", resp.StatusCode, body)
	}
	if n := e.downloadCount(); n != 1 {
		t.Errorf("the handler ran %d times, want 1", n)
	}
}

// It does not depend on the middleware having run, either: with none, there is
// no admin, and so no way in.
func TestRequireAdminIsClosedWithoutTheMiddleware(t *testing.T) {
	called := false
	h := RequireAdmin(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/bundle.tar", nil))
	if rec.Code != http.StatusUnauthorized || called {
		t.Errorf("status %d, handler called: %v; want 401 and not called", rec.Code, called)
	}
}

// The handler of the service is closed by itself. Mounted without the
// middleware, it still refuses everything that needs a session, also when the
// request carries a good one: it never opens, it only becomes unusable.
func TestProceduresFailClosedWithoutTheMiddleware(t *testing.T) {
	e := newEnvAdmin(t)
	mux := http.NewServeMux()
	path, h := panelv1connect.NewAuthServiceHandler(e.svc)
	mux.Handle(path, h)
	bare := httptest.NewServer(mux) // no middleware
	t.Cleanup(bare.Close)

	good := e.browser().mustLogin() // a real session, made on the proper server
	b := e.browserFor(bare)
	b.setToken(good)

	for name, call := range map[string]func() error{
		"Me":             func() error { _, err := b.me(); return err },
		"Logout":         func() error { _, err := b.logout(); return err },
		"ChangePassword": func() error { _, err := b.changePassword(testPassword, otherPassword); return err },
		"BeginTotp":      func() error { _, err := b.beginTotp(); return err },
		"ConfirmTotp":    func() error { _, err := b.confirmTotp("123456"); return err },
		"DisableTotp":    func() error { _, err := b.disableTotp(testPassword, "123456"); return err },
	} {
		if err := call(); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s without the middleware: %v, want unauthenticated", name, err)
		}
	}
	// Nothing happened: the session is there, and the password is the same.
	if _, err := e.session(good); err != nil {
		t.Errorf("the session is gone: %v", err)
	}
	if ok, _ := passwd.Verify(e.admin(testUser).PasswordHash, testPassword); !ok {
		t.Error("the password changed")
	}

	// The public procedures do not need the middleware; they just do not give
	// a session that anything else will accept.
	if b.setupStatus() {
		t.Error("GetSetupStatus says that setup is needed")
	}
	if _, err := b.login(testUser, testPassword, ""); err != nil {
		t.Fatalf("Login: %v", err)
	}
	_, err := b.me()
	wantCode(t, err, connect.CodeUnauthenticated)
}

// A request that the client has given up is not a fault of the panel: its
// session lookup is not logged as an error, and the answer says so.
func TestMiddlewareDoesNotLogACanceledLookupAsAnError(t *testing.T) {
	e := newEnvAdmin(t)
	token := e.browser().mustLogin()
	before := len(e.logs.String())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, listNodes, strings.NewReader("{}")).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", CookieName+"="+token)
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), `"code":"canceled"`) {
		t.Errorf("status %d, body %s, want a Connect error of code canceled", rec.Code, rec.Body.String())
	}
	if n := e.protectedCallCount(); n != 0 {
		t.Errorf("the handler ran %d times", n)
	}
	if logged := e.logs.String()[before:]; strings.Contains(logged, "level=ERROR") || strings.Contains(logged, "level=WARN") {
		t.Errorf("a canceled lookup was logged as a fault:\n%s", logged)
	}
}
