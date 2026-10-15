package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/passwd"
)

func TestLoginSetsTheSessionCookie(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.header("User-Agent", "postern-test/1.0")
	ctx := context.Background()

	resp, err := b.login(testUser, testPassword, "")
	wantOK(t, err)
	if resp.Msg.GetTotpRequired() {
		t.Fatal("totp_required for an admin without TOTP")
	}

	c := sessionCookie(t, resp.Header())
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Secure {
		t.Errorf("cookie attributes: HttpOnly=%v SameSite=%v Path=%q Secure=%v, want HttpOnly, Strict, /, not Secure over plain HTTP",
			c.HttpOnly, c.SameSite, c.Path, c.Secure)
	}
	if c.MaxAge != int(7*24*time.Hour/time.Second) {
		t.Errorf("Max-Age = %d, want 7 days", c.MaxAge)
	}
	if want := e.clock.Now().Add(7 * 24 * time.Hour); !c.Expires.Equal(want) {
		t.Errorf("Expires = %v, want %v", c.Expires, want)
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 32 {
		t.Fatalf("token %q is not 32 bytes of unpadded base64url: %v", c.Value, err)
	}

	// The database holds the hash of the token, not the token.
	sess, err := e.db.SessionByTokenHash(ctx, tokenHash(c.Value))
	if err != nil {
		t.Fatalf("no session under the SHA-256 of the token: %v", err)
	}
	admin := e.admin(testUser)
	if sess.AdminID != admin.ID || sess.TokenHash == c.Value {
		t.Errorf("session = %+v", sess)
	}
	if !sess.CreatedAt.Equal(e.clock.Now()) || !sess.ExpiresAt.Equal(e.clock.Now().Add(7*24*time.Hour)) {
		t.Errorf("session times = %v .. %v", sess.CreatedAt, sess.ExpiresAt)
	}
	if sess.IP != "127.0.0.1" || sess.UserAgent != "postern-test/1.0" {
		t.Errorf("session IP %q, user agent %q", sess.IP, sess.UserAgent)
	}
	if admin.LastLoginAt == nil || !admin.LastLoginAt.Equal(e.clock.Now()) {
		t.Errorf("LastLoginAt = %v, want %v", admin.LastLoginAt, e.clock.Now())
	}
	if n := e.count(`SELECT count(*) FROM sessions WHERE token_hash = ?`, c.Value); n != 0 {
		t.Error("the token itself is stored")
	}

	// And the cookie opens the API.
	me, err := b.me()
	wantOK(t, err)
	if me.Msg.GetUsername() != testUser || me.Msg.GetTotpEnabled() {
		t.Errorf("Me = %v", me.Msg)
	}
}

// What the SPA and the end-to-end test do: plain JSON over HTTP.
func TestLoginOverJSON(t *testing.T) {
	e := newEnvAdmin(t)
	resp, body := e.raw(http.MethodPost, "/postern.panel.v1.AuthService/Login",
		`{"username":"admin","password":"`+testPassword+`"}`,
		map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if strings.Contains(body, "totpRequired") && strings.Contains(body, "true") {
		t.Errorf("body %s", body)
	}
	c := sessionCookie(t, resp.Header)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie %+v", c)
	}
	// Used as a cookie header, it is the session.
	resp, body = e.callAs(c.Value, "/postern.panel.v1.AuthService/Me", `{}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"username":"admin"`) {
		t.Errorf("Me: status %d, body %s", resp.StatusCode, body)
	}
}

// forwardedProtoCases are values of X-Forwarded-Proto, one header line for each
// element, and whether a proxy of the panel says with them that its client is
// on https: it is the last value that counts, the one that the proxy wrote. The
// values before it may be the client's own.
var forwardedProtoCases = []struct {
	name   string
	values []string
	want   bool
}{
	{"none", nil, false},
	{"https", []string{"https"}, true},
	{"HTTPS", []string{"HTTPS"}, true},
	{"https with spaces", []string{" https "}, true},
	{"http", []string{"http"}, false},
	{"nonsense", []string{"wss"}, false},
	{"empty", []string{""}, false},
	{"http, then https from the proxy", []string{"http, https"}, true},
	{"https from the client, then http from the proxy", []string{"https, http"}, false},
	{"https, then nothing", []string{"https,"}, false},
	{"two lines, the last https", []string{"http", "https"}, true},
	{"two lines, the last http", []string{"https", "http"}, false},
}

// The session cookie is Secure when the client is on TLS: the connection is, or
// a proxy of the panel says so in X-Forwarded-Proto (Ruling 37).
func TestSessionCookieIsSecureWhenTheRequestIsTLS(t *testing.T) {
	login := `{"username":"admin","password":"` + testPassword + `"}`
	secure := func(t *testing.T, e *env, values []string) bool {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, e.srv.URL+authPath+"Login", strings.NewReader(login))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		for _, v := range values {
			req.Header.Add("X-Forwarded-Proto", v)
		}
		resp, err := e.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		return sessionCookie(t, resp.Header).Secure
	}

	// The loopback, where the test client is, is a proxy of the panel by default.
	for _, c := range forwardedProtoCases {
		t.Run("from a proxy, "+c.name, func(t *testing.T) {
			if got := secure(t, newEnvAdmin(t), c.values); got != c.want {
				t.Errorf("X-Forwarded-Proto %q from a proxy: Secure = %v, want %v", c.values, got, c.want)
			}
		})
	}
	// From any other peer the header says nothing.
	t.Run("from a peer that is not a proxy", func(t *testing.T) {
		e := newEnvAdminWith(t, WithTrustedProxies(prefixes(t, "198.51.100.0/24")...))
		for _, values := range [][]string{{"https"}, {"http, https"}, {"http", "https"}} {
			if secure(t, e, values) {
				t.Errorf("X-Forwarded-Proto %q from a peer that is not a proxy made the cookie Secure", values)
			}
		}
	})

	// A request that arrives over TLS, with a header or without one, from a proxy
	// or not.
	for name, opts := range map[string][]Option{"proxy": nil, "not a proxy": {WithTrustedProxies()}} {
		e := newEnvAdminWith(t, opts...)
		tlsSrv := httptest.NewTLSServer(e.handler)
		t.Cleanup(tlsSrv.Close)
		for _, header := range []map[string]string{{}, {"X-Forwarded-Proto": "http"}} {
			header["Content-Type"] = "application/json"
			resp, body := rawTo(t, tlsSrv, http.MethodPost, authPath+"Login", login, header)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("TLS, %s: status %d: %s", name, resp.StatusCode, body)
			}
			if !sessionCookie(t, resp.Header).Secure {
				t.Errorf("TLS, %s, %v: the cookie is not Secure", name, header)
			}
		}
	}
}

// A procedure that is called without the middleware takes what it knows of the
// client from the headers and the peer of the call, and believes
// X-Forwarded-Proto on the same terms: only from a proxy, and only its last
// value.
func TestSessionCookieIsSecureWithoutTheMiddleware(t *testing.T) {
	for _, c := range []struct {
		name   string
		opts   []Option
		values []string
		want   bool
	}{
		{"proxy, https", nil, []string{"https"}, true},
		{"proxy, http then https", nil, []string{"http, https"}, true},
		{"proxy, https then http", nil, []string{"https, http"}, false},
		{"proxy, two lines, the last https", nil, []string{"http", "https"}, true},
		{"proxy, no header", nil, nil, false},
		{"not a proxy, https", []Option{WithTrustedProxies(prefixes(t, "198.51.100.0/24")...)}, []string{"https"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnvAdminWith(t, c.opts...)
			mux := http.NewServeMux()
			path, h := panelv1connect.NewAuthServiceHandler(e.svc)
			mux.Handle(path, h)
			bare := httptest.NewServer(mux) // no middleware
			t.Cleanup(bare.Close)

			req := connectLogin(testUser, testPassword)
			for _, v := range c.values {
				req.Header().Add("X-Forwarded-Proto", v)
			}
			resp, err := panelv1connect.NewAuthServiceClient(bare.Client(), bare.URL).Login(context.Background(), req)
			if err != nil {
				t.Fatalf("Login: %v", err)
			}
			if got := sessionCookie(t, resp.Header()).Secure; got != c.want {
				t.Errorf("X-Forwarded-Proto %q: Secure = %v, want %v", c.values, got, c.want)
			}
		})
	}
}

func TestLoginWithWrongPassword(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	resp, err := b.login(testUser, wrongPassword, "")
	wantCode(t, err, connect.CodeUnauthenticated)
	if resp != nil {
		t.Error("a response came with the error")
	}
	if got := b.token(); got != "" || e.sessions() != 0 {
		t.Errorf("a failed login left a session (token %q, %d sessions)", got, e.sessions())
	}
	if e.admin(testUser).LastLoginAt != nil {
		t.Error("a failed login set LastLoginAt")
	}
}

// An unknown user gets the same answer as a wrong password, and costs the same:
// the password is checked against a dummy hash.
func TestLoginForUnknownUserLooksLikeWrongPassword(t *testing.T) {
	e := newEnvAdmin(t)
	var verified []string
	real := e.svc.verify
	e.svc.verify = func(encoded, password string) (bool, error) {
		verified = append(verified, encoded)
		return real(encoded, password)
	}
	b := e.browser()

	_, wrongErr := b.login(testUser, wrongPassword, "")
	wantCode(t, wrongErr, connect.CodeUnauthenticated)
	_, unknownErr := b.login("nobody", wrongPassword, "")
	wantCode(t, unknownErr, connect.CodeUnauthenticated)

	if connect.CodeOf(wrongErr) != connect.CodeOf(unknownErr) || errMessage(wrongErr) != errMessage(unknownErr) {
		t.Errorf("the answers differ: %q and %q", wrongErr, unknownErr)
	}
	if len(verified) != 2 {
		t.Fatalf("%d password checks for two logins, want 2", len(verified))
	}
	if verified[0] != e.admin(testUser).PasswordHash {
		t.Error("the known user was not checked against the stored hash")
	}
	if verified[1] != e.svc.dummy {
		t.Error("the unknown user was not checked against the dummy hash")
	}
}

// The dummy hash costs what a real one does, or the unknown user would be
// quicker to turn down.
func TestDummyHashHasTheCostOfARealHash(t *testing.T) {
	e := newEnv(t)
	svc := newService(e.db, e.key, nil, e.clock.Now)
	if !strings.HasPrefix(svc.dummy, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Errorf("dummy hash %q does not have the cost of internal/passwd", svc.dummy)
	}
	if ok, err := passwd.Verify(svc.dummy, "anything"); err != nil || ok {
		t.Errorf("Verify(dummy) = %v, %v, want false and no error", ok, err)
	}
}

func TestLoginUserNameIsNotCaseSensitive(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	if _, err := b.login("  ADMIN ", testPassword, ""); err != nil {
		t.Fatalf("Login: %v", err)
	}
}

// A password of more than 256 bytes is turned down before it is hashed.
func TestLoginRefusesLongPasswordsWithoutHashing(t *testing.T) {
	e := newEnvAdmin(t)
	var calls atomic.Int32
	real := e.svc.verify
	e.svc.verify = func(encoded, password string) (bool, error) {
		calls.Add(1)
		return real(encoded, password)
	}
	b := e.browser()

	_, err := b.login(testUser, strings.Repeat("p", 257), "")
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = b.login("nobody", strings.Repeat("p", 257), "")
	wantCode(t, err, connect.CodeUnauthenticated)
	if n := calls.Load(); n != 0 {
		t.Errorf("%d password checks for passwords of 257 bytes, want none", n)
	}

	// 256 bytes are checked.
	_, err = b.login(testUser, strings.Repeat("p", 256), "")
	wantCode(t, err, connect.CodeUnauthenticated)
	if n := calls.Load(); n != 1 {
		t.Errorf("%d password checks for a password of 256 bytes, want 1", n)
	}
}

func TestLoginReplacesTheSessionOfTheCookieItGot(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	first := b.mustLogin()
	second := b.mustLogin()
	if first == second {
		t.Fatal("two logins gave the same token")
	}
	if _, err := e.session(first); err == nil {
		t.Error("the session of the old cookie is still there")
	}
	if _, err := e.session(second); err != nil {
		t.Errorf("the new session is missing: %v", err)
	}
	if n := e.sessions(); n != 1 {
		t.Errorf("%d sessions, want 1", n)
	}
}

func TestLoginDeletesExpiredSessions(t *testing.T) {
	e := newEnvAdmin(t)
	admin := e.admin(testUser)
	stale := &store.Session{
		TokenHash: tokenHash("stale"), AdminID: admin.ID,
		CreatedAt: e.clock.Now().Add(-8 * 24 * time.Hour), ExpiresAt: e.clock.Now().Add(-24 * time.Hour),
	}
	live := &store.Session{
		TokenHash: tokenHash("live"), AdminID: admin.ID,
		CreatedAt: e.clock.Now(), ExpiresAt: e.clock.Now().Add(time.Hour),
	}
	for _, s := range []*store.Session{stale, live} {
		if err := e.db.CreateSession(context.Background(), s); err != nil {
			t.Fatal(err)
		}
	}
	e.browser().mustLogin()
	if _, err := e.db.SessionByTokenHash(context.Background(), stale.TokenHash); err == nil {
		t.Error("the expired session is still there")
	}
	if _, err := e.db.SessionByTokenHash(context.Background(), live.TokenHash); err != nil {
		t.Errorf("a session that has not expired was deleted: %v", err)
	}
}

func TestLogout(t *testing.T) {
	e := newEnvAdmin(t)
	b, other := e.browser(), e.browser()
	token := b.mustLogin()
	otherToken := other.mustLogin()

	resp, err := b.logout()
	wantOK(t, err)
	c := sessionCookie(t, resp.Header())
	if c.Value != "" || c.MaxAge >= 0 || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Errorf("Logout sets %+v, want an empty cookie that expires at once", c)
	}
	if _, err := e.session(token); err == nil {
		t.Error("the session survived Logout")
	}
	if b.token() != "" {
		t.Error("the browser still has the cookie")
	}

	// The old cookie is dead, also if a browser keeps sending it.
	b.setToken(token)
	_, err = b.me()
	wantCode(t, err, connect.CodeUnauthenticated)

	// Logout needs a session, and ends only its own.
	_, err = b.logout()
	wantCode(t, err, connect.CodeUnauthenticated)
	if _, err := other.me(); err != nil {
		t.Errorf("the other session was ended: %v", err)
	}
	if _, err := e.session(otherToken); err != nil {
		t.Errorf("the other session is gone: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	e := newEnvAdmin(t)
	a, other := e.browser(), e.browser()
	oldToken := a.mustLogin()
	otherToken := other.mustLogin()

	// Only a signed-in admin who knows the password.
	_, err := e.browser().changePassword(testPassword, otherPassword)
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = a.changePassword(wrongPassword, otherPassword)
	wantCode(t, err, connect.CodePermissionDenied)
	_, err = a.changePassword(testPassword, "elevenchars")
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = a.changePassword(testPassword, strings.Repeat("p", 257))
	wantCode(t, err, connect.CodeInvalidArgument)
	if e.sessions() != 2 {
		t.Fatal("a refused ChangePassword ended sessions")
	}
	before := e.admin(testUser).PasswordHash

	resp, err := a.changePassword(testPassword, otherPassword)
	wantOK(t, err)
	if e.admin(testUser).PasswordHash == before {
		t.Fatal("the hash did not change")
	}

	// Every session that was there is gone, the one that made the call too ...
	if _, err := e.session(oldToken); err == nil {
		t.Error("the session that made the call survived")
	}
	if _, err := e.session(otherToken); err == nil {
		t.Error("the other session survived")
	}
	other.setToken(otherToken)
	_, err = other.me()
	wantCode(t, err, connect.CodeUnauthenticated)

	// ... and the caller got a new one, so that it is not signed out.
	c := sessionCookie(t, resp.Header())
	if c.Value == "" || c.Value == oldToken || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("new cookie %+v", c)
	}
	if a.token() != c.Value {
		t.Error("the browser did not take the new cookie")
	}
	if _, err := a.me(); err != nil {
		t.Errorf("the caller is signed out: %v", err)
	}
	if n := e.sessions(); n != 1 {
		t.Errorf("%d sessions, want 1", n)
	}

	// The new password is the one that works.
	fresh := e.browser()
	_, err = fresh.login(testUser, testPassword, "")
	wantCode(t, err, connect.CodeUnauthenticated)
	if _, err := fresh.login(testUser, otherPassword, ""); err != nil {
		t.Errorf("Login with the new password: %v", err)
	}
}

// ChangePassword and DisableTotp ask for the password again, so a stolen
// session cannot be used to guess it at the speed of argon2.
func TestReauthenticationIsRateLimited(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	for range maxFailures {
		_, err := b.changePassword(wrongPassword, otherPassword)
		wantCode(t, err, connect.CodePermissionDenied)
	}
	_, err := b.changePassword(testPassword, otherPassword)
	wantCode(t, err, connect.CodeResourceExhausted)
	if retryAfter(t, err) == "" {
		t.Error("no Retry-After")
	}
	// The failures count on the limits of signing in: the address, which every
	// browser of this test shares, is locked at the door as well.
	_, err = e.browser().login(testUser, testPassword, "")
	wantCode(t, err, connect.CodeResourceExhausted)
}

// The password guessed through a stolen session locks the address of the thief,
// and not the user name: from anywhere else the admin still signs in, and is
// still asked for the password, and let through, before a change.
func TestReauthenticationFailuresDoNotLockOtherAddresses(t *testing.T) {
	e := newEnvAdmin(t)
	thief := e.browser()
	thief.header("X-Forwarded-For", "192.0.2.66")
	thief.mustLogin()
	for range maxFailures {
		_, err := thief.changePassword(wrongPassword, otherPassword)
		wantCode(t, err, connect.CodePermissionDenied)
	}
	_, err := thief.changePassword(testPassword, otherPassword)
	wantCode(t, err, connect.CodeResourceExhausted)

	owner := e.browser()
	owner.header("X-Forwarded-For", "192.0.2.11")
	if _, err := owner.login(testUser, testPassword, ""); err != nil {
		t.Fatalf("Login of the admin from another address: %v", err)
	}
	if _, err := owner.changePassword(testPassword, otherPassword); err != nil {
		t.Fatalf("ChangePassword of the admin from another address: %v", err)
	}
}

// Failures lock the address that they come from, and not the user name that
// they are for: whoever knows the name of the admin cannot lock the admin out of
// the panel (Ruling 35).
func TestLoginFailuresLockTheAddressNotTheUserName(t *testing.T) {
	e := newEnvAdmin(t)
	attacker, owner := e.browser(), e.browser()
	attacker.header("X-Forwarded-For", "192.0.2.10")
	owner.header("X-Forwarded-For", "192.0.2.11")

	for i := range maxFailures {
		_, err := attacker.login(testUser, wrongPassword, "")
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("failure %d: code = %v (%v), want unauthenticated", i+1, connect.CodeOf(err), err)
		}
	}

	// The sixth attempt from the address is refused, with the right password too,
	// and for any user name.
	for _, user := range []string{testUser, "somebody"} {
		_, err := attacker.login(user, testPassword, "")
		wantCode(t, err, connect.CodeResourceExhausted)
		if got := retryAfter(t, err); got != "900" {
			t.Errorf("%s: Retry-After = %q, want 900", user, got)
		}
	}
	if e.sessions() != 0 {
		t.Fatal("a refused login started a session")
	}

	// From another address the admin signs in as ever.
	if _, err := owner.login(testUser, testPassword, ""); err != nil {
		t.Fatalf("Login from another address: %v", err)
	}

	// A refused attempt does not lengthen the lock.
	e.clock.Advance(14*time.Minute + 59*time.Second)
	_, err := attacker.login(testUser, testPassword, "")
	wantCode(t, err, connect.CodeResourceExhausted)
	if got := retryAfter(t, err); got != "1" {
		t.Errorf("Retry-After = %q, want 1", got)
	}

	// After the lock the address gets in again.
	e.clock.Advance(time.Second)
	if _, err := attacker.login(testUser, testPassword, ""); err != nil {
		t.Fatalf("Login after the lock: %v", err)
	}
}

// Five failures for one user name from one address lock that user name for that
// address, also when a sign-in in between has cleared the count of the address:
// an account of its own is no way for an attacker to go on guessing the password
// of another. The lock grows like any other, and holds nobody else.
func TestLoginLocksAUserNameForAnAddress(t *testing.T) {
	e := newEnvAdmin(t)
	e.createAdmin("other", otherPassword)
	a, b := e.browser(), e.browser()
	a.header("X-Forwarded-For", "192.0.2.10")
	b.header("X-Forwarded-For", "192.0.2.11")

	for round, want := range []string{"900", "1800"} {
		for range maxFailures - 1 {
			_, err := a.login(testUser, wrongPassword, "")
			wantCode(t, err, connect.CodeUnauthenticated)
		}
		// A success from the address clears the count of the address ...
		if _, err := a.login("other", otherPassword, ""); err != nil {
			t.Fatalf("round %d: Login of the other admin: %v", round+1, err)
		}
		// ... and not the one of the address for the admin: this is the fifth.
		_, err := a.login(testUser, wrongPassword, "")
		wantCode(t, err, connect.CodeUnauthenticated)
		_, err = a.login(testUser, testPassword, "")
		wantCode(t, err, connect.CodeResourceExhausted)
		if got := retryAfter(t, err); got != want {
			t.Errorf("round %d: Retry-After = %q, want %s", round+1, got, want)
		}

		// The address is not locked: the other admin signs in from it. Nor is
		// the user name: the admin signs in from another address.
		if _, err := a.login("other", otherPassword, ""); err != nil {
			t.Errorf("round %d: Login of the other admin from the address: %v", round+1, err)
		}
		if _, err := b.login(testUser, testPassword, ""); err != nil {
			t.Errorf("round %d: Login of the admin from another address: %v", round+1, err)
		}
		e.clock.Advance(time.Duration(mustAtoi(t, want)) * time.Second)
	}
	if _, err := a.login(testUser, testPassword, ""); err != nil {
		t.Fatalf("Login after the lock: %v", err)
	}
}

// Every lock is twice as long as the one before, until a login gets through.
func TestLoginLockoutGrowsExponentially(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	for round, want := range []string{"900", "1800", "3600", "7200"} {
		for range maxFailures {
			_, err := b.login(testUser, wrongPassword, "")
			wantCode(t, err, connect.CodeUnauthenticated)
		}
		_, err := b.login(testUser, testPassword, "")
		wantCode(t, err, connect.CodeResourceExhausted)
		if got := retryAfter(t, err); got != want {
			t.Fatalf("lock %d: Retry-After = %q, want %s", round+1, got, want)
		}
		e.clock.Advance(time.Duration(mustAtoi(t, want)) * time.Second)
	}

	// A successful login forgets the history.
	if _, err := b.login(testUser, testPassword, ""); err != nil {
		t.Fatal(err)
	}
	for range maxFailures {
		_, err := b.login(testUser, wrongPassword, "")
		wantCode(t, err, connect.CodeUnauthenticated)
	}
	_, err := b.login(testUser, testPassword, "")
	wantCode(t, err, connect.CodeResourceExhausted)
	if got := retryAfter(t, err); got != "900" {
		t.Errorf("after a successful login the first lock is %q, want 900", got)
	}
}

func TestLoginRateLimitPerAddress(t *testing.T) {
	e := newEnvAdmin(t)
	attacker, innocent := e.browser(), e.browser()
	attacker.header("X-Forwarded-For", "192.0.2.10")
	innocent.header("X-Forwarded-For", "192.0.2.11")

	// Five failures, each against another name: no user name is locked, the
	// address is.
	for i := range maxFailures {
		_, err := attacker.login("user"+string(rune('a'+i)), wrongPassword, "")
		wantCode(t, err, connect.CodeUnauthenticated)
	}
	_, err := attacker.login(testUser, testPassword, "")
	wantCode(t, err, connect.CodeResourceExhausted)
	if retryAfter(t, err) == "" {
		t.Error("no Retry-After")
	}

	// Another address is not affected, and the user name was never locked.
	if _, err := innocent.login(testUser, testPassword, ""); err != nil {
		t.Fatalf("Login from another address: %v", err)
	}
	e.clock.Advance(failWindow)
	if _, err := attacker.login(testUser, testPassword, ""); err != nil {
		t.Fatalf("Login after the lock: %v", err)
	}
}

// IPv6 addresses count by their /64: one customer has many.
func TestLoginRateLimitCountsIPv6ByPrefix(t *testing.T) {
	e := newEnvAdmin(t)
	for i := range maxFailures {
		b := e.browser()
		b.header("X-Forwarded-For", "2001:db8:1:2::"+string(rune('1'+i)))
		_, err := b.login("user"+string(rune('a'+i)), wrongPassword, "")
		wantCode(t, err, connect.CodeUnauthenticated)
	}
	b := e.browser()
	b.header("X-Forwarded-For", "2001:db8:1:2:ffff::9")
	_, err := b.login(testUser, testPassword, "")
	wantCode(t, err, connect.CodeResourceExhausted)

	b = e.browser()
	b.header("X-Forwarded-For", "2001:db8:1:3::1")
	if _, err := b.login(testUser, testPassword, ""); err != nil {
		t.Errorf("Login from another /64: %v", err)
	}
}

func TestSuccessfulLoginClearsTheFailures(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	for range 2 {
		for range maxFailures - 1 {
			_, err := b.login(testUser, wrongPassword, "")
			wantCode(t, err, connect.CodeUnauthenticated)
		}
		if _, err := b.login(testUser, testPassword, ""); err != nil {
			t.Fatalf("Login after 4 failures: %v", err)
		}
	}
}

// Parallel guesses do not get past the limit: the attempts are counted when they
// start, not when they have been checked.
func TestLoginRateLimitHoldsAgainstParallelGuesses(t *testing.T) {
	e := newEnvAdmin(t)
	var checks atomic.Int32
	real := e.svc.verify
	e.svc.verify = func(encoded, password string) (bool, error) {
		checks.Add(1)
		return real(encoded, password)
	}

	const n = 24
	var (
		wg           sync.WaitGroup
		mu           sync.Mutex
		wrong, limit int
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.browser().login(testUser, wrongPassword, "")
			mu.Lock()
			defer mu.Unlock()
			switch connect.CodeOf(err) {
			case connect.CodeUnauthenticated:
				wrong++
			case connect.CodeResourceExhausted:
				limit++
			default:
				t.Errorf("unexpected error %v", err)
			}
		}()
	}
	wg.Wait()

	if got := checks.Load(); got != maxFailures {
		t.Errorf("%d passwords were checked, want %d", got, maxFailures)
	}
	if wrong != maxFailures || limit != n-maxFailures {
		t.Errorf("%d answers of unauthenticated and %d of resource_exhausted, want %d and %d", wrong, limit, maxFailures, n-maxFailures)
	}
}

// eventLog notes, in order, what the service did with the attempts of a test.
type eventLog struct {
	mu   sync.Mutex
	list []string
}

func (l *eventLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append(l.list, s)
}

// take returns what was noted since the last take.
func (l *eventLog) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.list
	l.list = nil
	return out
}

// watchSlowdown makes the waits of the slowdown and the password checks of the
// service note themselves, as "wait <duration>" and "check". The waits return at
// once.
func watchSlowdown(e *env) *eventLog {
	ev := &eventLog{}
	e.svc.sleep = func(_ context.Context, d time.Duration) error {
		ev.add("wait " + d.String())
		return nil
	}
	real := e.svc.verify
	e.svc.verify = func(encoded, password string) (bool, error) {
		ev.add("check")
		return real(encoded, password)
	}
	return ev
}

// failEachFromItsOwnAddress makes n sign-ins of the admin fail, each from an
// address of its own, so that none of them comes near a lock.
func failEachFromItsOwnAddress(t *testing.T, e *env, n int) {
	t.Helper()
	for i := range n {
		b := e.browser()
		b.header("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i+1))
		_, err := b.login(testUser, wrongPassword, "")
		wantCode(t, err, connect.CodeUnauthenticated)
	}
}

// More than 100 failures within a minute, from all the addresses together, slow
// every attempt down: it waits a second before it is checked. That locks nobody
// out, and it is over when the failures are a minute old (Ruling 35).
func TestSignInsAreSlowedDownWhileManyFail(t *testing.T) {
	e := newEnvAdmin(t)
	ev := watchSlowdown(e)
	b := e.browser()
	b.header("X-Forwarded-For", "198.51.100.1")
	b.mustLogin() // for the password that is asked for again, below
	ev.take()

	failEachFromItsOwnAddress(t, e, maxRecentFailures)
	if got := ev.take(); len(got) != maxRecentFailures || slices.Contains(got, "wait 1s") {
		t.Fatalf("the first %d failures were slowed down: %v", maxRecentFailures, got)
	}
	// 100 are not more than 100: this one is not slowed down. It is the 101st.
	_, err := b.login(testUser, wrongPassword, "")
	wantCode(t, err, connect.CodeUnauthenticated)
	if got := ev.take(); !slices.Equal(got, []string{"check"}) {
		t.Fatalf("the 101st failure: %v, want a check and no wait", got)
	}

	// Now every attempt waits before its check: one that fails, one that is
	// right, which gets in, and the password that a session is asked for again.
	_, err = b.login(testUser, wrongPassword, "")
	wantCode(t, err, connect.CodeUnauthenticated)
	if got := ev.take(); !slices.Equal(got, []string{"wait 1s", "check"}) {
		t.Errorf("a failure: %v, want a wait of 1s and then the check", got)
	}
	if _, err := b.login(testUser, testPassword, ""); err != nil {
		t.Fatalf("the right password while sign-ins are slowed down: %v", err)
	}
	if got := ev.take(); !slices.Equal(got, []string{"wait 1s", "check"}) {
		t.Errorf("a success: %v, want a wait of 1s and then the check", got)
	}
	_, err = b.changePassword(wrongPassword, otherPassword)
	wantCode(t, err, connect.CodePermissionDenied)
	if got := ev.take(); !slices.Equal(got, []string{"wait 1s", "check"}) {
		t.Errorf("a password asked for again: %v, want a wait of 1s and then the check", got)
	}

	// A minute after the failures nothing waits any more.
	e.clock.Advance(time.Minute)
	if _, err := b.login(testUser, testPassword, ""); err != nil {
		t.Fatalf("Login a minute later: %v", err)
	}
	if got := ev.take(); !slices.Equal(got, []string{"check"}) {
		t.Errorf("a minute later: %v, want a check and no wait", got)
	}
}

// While sign-ins are slowed down, a user name that nobody has waits, and is
// checked, exactly as one that exists, so that neither the time nor the answer
// tells which names exist.
func TestSlowedDownSignInsAreAlikeForEveryUserName(t *testing.T) {
	e := newEnvAdmin(t)
	ev := watchSlowdown(e)
	failEachFromItsOwnAddress(t, e, maxRecentFailures+1)
	ev.take()

	for _, c := range []struct {
		name     string
		password string
		want     []string
	}{
		{"a wrong password", wrongPassword, []string{"wait 1s", "check"}},
		{"a password that is too long to be checked", strings.Repeat("p", maxPasswordBytes+1), []string{"wait 1s"}},
	} {
		var answers []error
		for i, user := range []string{testUser, "nobody"} {
			b := e.browser()
			b.header("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))
			_, err := b.login(user, c.password, "")
			wantCode(t, err, connect.CodeUnauthenticated)
			answers = append(answers, err)
			if got := ev.take(); !slices.Equal(got, c.want) {
				t.Errorf("%s for %q: %v, want %v", c.name, user, got, c.want)
			}
		}
		if errMessage(answers[0]) != errMessage(answers[1]) {
			t.Errorf("%s: the answers differ: %q and %q", c.name, answers[0], answers[1])
		}
	}
}

// A sign-in whose request is gone during the wait is not a failure: it was never
// checked.
func TestSignInThatGivesUpDuringTheSlowdownIsNotAFailure(t *testing.T) {
	e := newEnvAdmin(t)
	failEachFromItsOwnAddress(t, e, maxRecentFailures+1)
	gone := 0
	e.svc.sleep = func(context.Context, time.Duration) error {
		gone++
		return context.Canceled
	}
	b := e.browser()
	b.header("X-Forwarded-For", "198.51.100.1")
	for range maxFailures {
		_, err := b.login(testUser, wrongPassword, "")
		wantCode(t, err, connect.CodeCanceled)
	}
	if gone != maxFailures {
		t.Fatalf("%d waits for %d slowed-down sign-ins", gone, maxFailures)
	}
	e.svc.sleep = func(context.Context, time.Duration) error { return nil }
	if _, err := b.login(testUser, testPassword, ""); err != nil {
		t.Fatalf("the attempts that were never checked locked the address: %v", err)
	}
}

// The wait of the slowdown is a real one, which a request that is gone cuts
// short.
func TestSleepCtxWaitsOrGivesUp(t *testing.T) {
	start := time.Now()
	if err := sleepCtx(context.Background(), 20*time.Millisecond); err != nil {
		t.Fatalf("sleepCtx: %v", err)
	}
	if d := time.Since(start); d < 20*time.Millisecond {
		t.Errorf("sleepCtx(20ms) returned after %v", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	within(t, time.Second, "sleepCtx with a request that is gone", func() {
		if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
			t.Errorf("sleepCtx with a canceled context: %v, want context.Canceled", err)
		}
	})
	// It is what a service waits with: a request that is gone ends the wait of the
	// slowdown at once, with the error of the request.
	e := newEnv(t)
	svc := newService(e.db, e.key, nil, e.clock.Now)
	for range maxRecentFailures + 1 {
		svc.recent.add(e.clock.Now())
	}
	within(t, time.Second, "the slowdown of a request that is gone", func() {
		if err := svc.slowDown(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("slowDown with a canceled context: %v, want context.Canceled", err)
		}
	})
	// And otherwise it waits the whole second.
	start = time.Now()
	within(t, 5*time.Second, "the slowdown", func() {
		if err := svc.slowDown(context.Background()); err != nil {
			t.Errorf("slowDown: %v", err)
		}
	})
	if d := time.Since(start); d < time.Second {
		t.Errorf("the slowdown waited %v, want 1s", d)
	}
}

func TestTotpEnrollmentAndLogin(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	admin := e.admin(testUser)

	me, err := b.me()
	wantOK(t, err)
	if me.Msg.GetTotpEnabled() {
		t.Fatal("TOTP is on before it was enrolled")
	}

	begin, err := b.beginTotp()
	wantOK(t, err)
	secret := begin.Msg.GetSecret()
	if len(secret) != 32 {
		t.Fatalf("secret %q is not 32 characters of base32", secret)
	}
	if want := "otpauth://totp/Postern:admin?secret=" + secret + "&issuer=Postern&algorithm=SHA1&digits=6&period=30"; begin.Msg.GetOtpauthUri() != want {
		t.Errorf("otpauth_uri = %q, want %q", begin.Msg.GetOtpauthUri(), want)
	}
	// Nothing is on yet, and nothing is stored.
	if len(e.admin(testUser).TOTPSecretEnc) != 0 {
		t.Fatal("BeginTotp stored the secret")
	}

	_, err = b.confirmTotp(e.badCode(secret))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = b.confirmTotp("")
	wantCode(t, err, connect.CodeInvalidArgument)
	if len(e.admin(testUser).TOTPSecretEnc) != 0 {
		t.Fatal("a wrong code turned TOTP on")
	}

	_, err = b.confirmTotp(" " + e.code(secret)[:3] + " " + e.code(secret)[3:] + "\t")
	wantOK(t, err)
	me, err = b.me()
	wantOK(t, err)
	if !me.Msg.GetTotpEnabled() {
		t.Error("Me says TOTP is off after ConfirmTotp")
	}

	// The secret is stored sealed, for this admin only.
	enc := e.admin(testUser).TOTPSecretEnc
	if len(enc) == 0 || strings.Contains(string(enc), secret) {
		t.Fatal("the secret is stored in the clear, or not at all")
	}
	if got := e.secretOf(admin.ID); got != secret {
		t.Errorf("the sealed secret opens to %q, want %q", got, secret)
	}
	if _, err := sealOpen(e, enc, "totp:"+e.admin(testUser).ID+"x"); err == nil {
		t.Error("the sealed secret opens for another admin")
	}

	// Signing in now needs the code.
	e.clock.Advance(30 * time.Second)
	fresh := e.browser()
	resp, err := fresh.login(testUser, testPassword, "")
	wantOK(t, err)
	if !resp.Msg.GetTotpRequired() {
		t.Fatal("totp_required is false for an admin with TOTP")
	}
	if len(resp.Header().Values("Set-Cookie")) != 0 || fresh.token() != "" {
		t.Error("a session cookie came without the code")
	}
	if e.sessions() != 1 { // the one that enrolled
		t.Errorf("%d sessions, want only the first", e.sessions())
	}

	_, err = fresh.login(testUser, testPassword, e.badCode(secret))
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = fresh.login(testUser, wrongPassword, e.code(secret))
	wantCode(t, err, connect.CodeUnauthenticated)
	if fresh.token() != "" {
		t.Fatal("a session came with a wrong code")
	}

	resp, err = fresh.login(testUser, testPassword, e.code(secret))
	wantOK(t, err)
	if resp.Msg.GetTotpRequired() || fresh.token() == "" {
		t.Fatal("the right code did not sign in")
	}
	if _, err := fresh.me(); err != nil {
		t.Errorf("Me after login with a code: %v", err)
	}
}

// A code that has been accepted is not accepted again, nor is any code of an
// earlier step, although the clock still allows it.
func TestTotpCodeCannotBeUsedTwice(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	secret := b.enableTotp()

	step := func(offset time.Duration) string {
		c, err := codeAt(secret, e.clock.Now().Add(offset))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	used := step(0)
	if _, err := e.browser().login(testUser, testPassword, used); err != nil {
		t.Fatalf("Login: %v", err)
	}
	for name, code := range map[string]string{
		"the same code":         used,
		"the code before it":    step(-30 * time.Second),
		"the same code, spaced": used[:2] + " " + used[2:],
	} {
		_, err := e.browser().login(testUser, testPassword, code)
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s: code = %v (%v), want unauthenticated", name, connect.CodeOf(err), err)
		}
	}

	// The next step is a new code, and so is one that the clock allows ahead of
	// time; but once that one is used, the current step is behind it.
	if _, err := e.browser().login(testUser, testPassword, step(30*time.Second)); err != nil {
		t.Fatalf("Login with the next code: %v", err)
	}
	_, err := e.browser().login(testUser, testPassword, step(0))
	wantCode(t, err, connect.CodeUnauthenticated)

	e.clock.Advance(60 * time.Second)
	if _, err := e.browser().login(testUser, testPassword, e.code(secret)); err != nil {
		t.Fatalf("Login with a code after both: %v", err)
	}
}

// Requests that bring the same code at once do not all get in: the check of
// the step and the note of it are one step.
func TestTotpCodeIsAcceptedOnceWhenUsedAtOnce(t *testing.T) {
	for round := range 10 {
		e := newEnvAdmin(t)
		b := e.browser()
		b.mustLogin()
		secret := b.enableTotp()
		code := e.code(secret)

		// Each from an address of its own, so that the limiter lets all of them
		// in at once.
		const n = maxFailures
		var (
			wg        sync.WaitGroup
			succeeded atomic.Int32
		)
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := e.browser()
				c.header("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i+1))
				<-start
				if resp, err := c.login(testUser, testPassword, code); err == nil && !resp.Msg.GetTotpRequired() {
					succeeded.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if got := succeeded.Load(); got != 1 {
			t.Fatalf("round %d: %d logins with the same code succeeded, want 1", round, got)
		}
	}
}

// The code that confirmed the secret is used up, too.
func TestTotpConfirmationCodeCannotLogIn(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	begin, err := b.beginTotp()
	wantOK(t, err)
	secret := begin.Msg.GetSecret()
	code := e.code(secret)
	_, err = b.confirmTotp(code)
	wantOK(t, err)

	_, err = e.browser().login(testUser, testPassword, code)
	wantCode(t, err, connect.CodeUnauthenticated)
	e.clock.Advance(30 * time.Second)
	if _, err := e.browser().login(testUser, testPassword, e.code(secret)); err != nil {
		t.Fatalf("Login with the next code: %v", err)
	}
}

func TestLoginWithTotpAcceptsTheClockSkewOfOneStep(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	secret := b.enableTotp()
	for name, offset := range map[string]time.Duration{"a step late": -30 * time.Second, "a step early": 30 * time.Second} {
		e.clock.Advance(90 * time.Second) // each case has steps of its own
		code, err := codeAt(secret, e.clock.Now().Add(offset))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.browser().login(testUser, testPassword, code); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.clock.Advance(90 * time.Second)
	code, err := codeAt(secret, e.clock.Now().Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.browser().login(testUser, testPassword, code)
	wantCode(t, err, connect.CodeUnauthenticated)
}

// The password is asked for first. An admin is not told that TOTP is on to
// someone who does not know the password.
func TestTotpRequiredIsOnlyToldForTheRightPassword(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	b.enableTotp()

	_, err := e.browser().login(testUser, wrongPassword, "")
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = e.browser().login("nobody", wrongPassword, "")
	wantCode(t, err, connect.CodeUnauthenticated)
}

// Asking for the code is a step of signing in, not a failure of it.
func TestLoginWithoutTheCodeIsNotAFailure(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	b.enableTotp()
	for i := range 3 * maxFailures {
		resp, err := e.browser().login(testUser, testPassword, "")
		if err != nil || !resp.Msg.GetTotpRequired() {
			t.Fatalf("attempt %d: %v, %v", i+1, resp, err)
		}
	}
}

func TestWrongTotpCodesAreFailures(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	secret := b.enableTotp()
	for range maxFailures {
		_, err := e.browser().login(testUser, testPassword, e.badCode(secret))
		wantCode(t, err, connect.CodeUnauthenticated)
	}
	_, err := e.browser().login(testUser, testPassword, e.code(secret))
	wantCode(t, err, connect.CodeResourceExhausted)
}

func TestBeginTotpIsRefusedWhileTotpIsOn(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	secret := b.enableTotp()
	_, err := b.beginTotp()
	wantCode(t, err, connect.CodeFailedPrecondition)
	if got := e.secretOf(e.admin(testUser).ID); got != secret {
		t.Error("the secret changed")
	}
}

func TestConfirmTotpNeedsABeginThatIsNotTooOld(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()

	_, err := b.confirmTotp("123456")
	wantCode(t, err, connect.CodeFailedPrecondition)

	begin, err := b.beginTotp()
	wantOK(t, err)
	e.clock.Advance(pendingTotpTTL + time.Second)
	_, err = b.confirmTotp(e.code(begin.Msg.GetSecret()))
	wantCode(t, err, connect.CodeFailedPrecondition)
	if len(e.admin(testUser).TOTPSecretEnc) != 0 {
		t.Fatal("TOTP is on")
	}

	// A new Begin replaces the one before.
	first, err := b.beginTotp()
	wantOK(t, err)
	second, err := b.beginTotp()
	wantOK(t, err)
	if first.Msg.GetSecret() == second.Msg.GetSecret() {
		t.Fatal("two Begin calls gave the same secret")
	}
	_, err = b.confirmTotp(e.code(first.Msg.GetSecret()))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = b.confirmTotp(e.code(second.Msg.GetSecret()))
	wantOK(t, err)
}

func TestTotpProceduresNeedASession(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	_, err := b.beginTotp()
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = b.confirmTotp("123456")
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = b.disableTotp(testPassword, "123456")
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = b.changePassword(testPassword, otherPassword)
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = b.me()
	wantCode(t, err, connect.CodeUnauthenticated)
}

func TestDisableTotp(t *testing.T) {
	e := newEnvAdmin(t)
	b, other := e.browser(), e.browser()
	oldToken := b.mustLogin()
	otherToken := other.mustLogin()

	// There is nothing to disable.
	_, err := b.disableTotp(testPassword, "123456")
	wantCode(t, err, connect.CodeFailedPrecondition)

	secret := b.enableTotp()
	_, err = b.disableTotp(wrongPassword, e.code(secret))
	wantCode(t, err, connect.CodePermissionDenied)
	_, err = b.disableTotp(testPassword, e.badCode(secret))
	wantCode(t, err, connect.CodePermissionDenied)
	_, err = b.disableTotp(testPassword, "")
	wantCode(t, err, connect.CodePermissionDenied)
	if len(e.admin(testUser).TOTPSecretEnc) == 0 || e.sessions() != 2 {
		t.Fatal("a refused DisableTotp changed something")
	}

	resp, err := b.disableTotp(testPassword, e.code(secret))
	wantOK(t, err)
	if len(e.admin(testUser).TOTPSecretEnc) != 0 {
		t.Error("the secret is still stored")
	}

	// Every session is gone, and the caller has a new one.
	if _, err := e.session(oldToken); err == nil {
		t.Error("the session that made the call survived")
	}
	other.setToken(otherToken)
	_, err = other.me()
	wantCode(t, err, connect.CodeUnauthenticated)
	c := sessionCookie(t, resp.Header())
	if c.Value == "" || c.Value == oldToken {
		t.Errorf("new cookie %+v", c)
	}
	me, err := b.me()
	wantOK(t, err)
	if me.Msg.GetTotpEnabled() {
		t.Error("Me says TOTP is still on")
	}
	if n := e.sessions(); n != 1 {
		t.Errorf("%d sessions, want 1", n)
	}

	// The code is not needed any more.
	if _, err := e.browser().login(testUser, testPassword, ""); err != nil {
		t.Errorf("Login without a code: %v", err)
	}
}

// The code that was used to sign in is used up for DisableTotp as well.
func TestDisableTotpDoesNotAcceptACodeThatWasUsed(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	secret := b.enableTotp()
	code := e.code(secret)
	if _, err := e.browser().login(testUser, testPassword, code); err != nil {
		t.Fatal(err)
	}
	_, err := b.disableTotp(testPassword, code)
	wantCode(t, err, connect.CodePermissionDenied)
	e.clock.Advance(30 * time.Second)
	_, err = b.disableTotp(testPassword, e.code(secret))
	wantOK(t, err)
}

func TestExpiredSessionsCannotChangeAnything(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	e.clock.Advance(7 * 24 * time.Hour)
	_, err := b.changePassword(testPassword, otherPassword)
	wantCode(t, err, connect.CodeUnauthenticated)
	if ok, _ := passwd.Verify(e.admin(testUser).PasswordHash, testPassword); !ok {
		t.Error("the password changed")
	}
}

// Logins that are under way while the password changes do not undo the change
// and do not leave a session that the change should have ended.
func TestPasswordChangeSurvivesConcurrentLogins(t *testing.T) {
	for round := range 8 {
		e := newEnvAdmin(t)
		b := e.browser()
		b.mustLogin()

		// The logins come from addresses of their own, and the change from the
		// one of b, so the limiter turns none of them away for running at once.
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := e.browser()
				c.header("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i+1))
				<-start
				// Some of these are checked against the old hash, some against the
				// new one; none may leave a session behind after the change.
				_, _ = c.login(testUser, testPassword, "")
			}()
		}
		close(start)
		if _, err := b.changePassword(testPassword, otherPassword); err != nil {
			t.Fatalf("round %d: ChangePassword: %v", round, err)
		}
		wg.Wait()

		admin := e.admin(testUser)
		if ok, err := passwd.Verify(admin.PasswordHash, otherPassword); err != nil || !ok {
			t.Fatalf("round %d: the new password does not work: %v, %v", round, ok, err)
		}
		// Whatever order they ran in, the sessions that were made with the old
		// password are gone: only the one of the caller of ChangePassword is left.
		if n := e.sessions(); n != 1 {
			t.Errorf("round %d: %d sessions, want 1", round, n)
		}
		if _, err := b.me(); err != nil {
			t.Errorf("round %d: the caller of ChangePassword is signed out: %v", round, err)
		}
	}
}

// holdFirstCheck makes the first password check of the service wait, after it
// has been made, until the returned gate is opened. The caller gets a signal when
// the check has been made and is being held.
func holdFirstCheck(t *testing.T, e *env) (g *gate, held <-chan struct{}) {
	t.Helper()
	g = newGate(t)
	signal := make(chan struct{}, 1)
	real := e.svc.verify
	var first atomic.Bool
	e.svc.verify = func(encoded, password string) (bool, error) {
		ok, err := real(encoded, password)
		if first.CompareAndSwap(false, true) {
			signal <- struct{}{}
			g.wait()
		}
		return ok, err
	}
	return g, signal
}

// A login that has checked the password does not get a session if the password
// has been changed since: the change has ended the sessions that it should end,
// and one that is made afterwards would be one that it missed.
func TestLoginAfterAPasswordChangeThatCameInBetweenGetsNoSession(t *testing.T) {
	e := newEnvAdmin(t)
	owner := e.browser()
	owner.mustLogin()
	g, held := holdFirstCheck(t, e)

	result := make(chan error, 1)
	go func() {
		_, err := e.browser().login(testUser, testPassword, "")
		result <- err
	}()
	waitStarted(t, held, 1) // the old password is checked, and its result is held

	if _, err := owner.changePassword(testPassword, otherPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	g.open()

	select {
	case err := <-result:
		wantCode(t, err, connect.CodeAborted)
	case <-time.After(5 * time.Second):
		t.Fatal("Login did not return")
	}
	if n := e.sessions(); n != 1 {
		t.Errorf("%d sessions, want only the new one of the caller of ChangePassword", n)
	}
}

// The session of a call can end while the call is under way, and then it does
// not change anything.
func TestChangePasswordDoesNotOutliveItsSession(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	token := b.mustLogin()
	g, held := holdFirstCheck(t, e)

	result := make(chan error, 1)
	go func() {
		_, err := b.changePassword(testPassword, otherPassword)
		result <- err
	}()
	waitStarted(t, held, 1)

	// Another tab signs out of the same session.
	other := e.browser()
	other.setToken(token)
	if _, err := other.logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	g.open()

	select {
	case err := <-result:
		wantCode(t, err, connect.CodeUnauthenticated)
	case <-time.After(5 * time.Second):
		t.Fatal("ChangePassword did not return")
	}
	if ok, _ := passwd.Verify(e.admin(testUser).PasswordHash, testPassword); !ok {
		t.Error("the password was changed by a call whose session had ended")
	}
	if n := e.sessions(); n != 0 {
		t.Errorf("%d sessions, want none", n)
	}
}

// A password that has been checked is not the one that is replaced if it has
// changed since.
func TestChangePasswordRefusesWhenThePasswordChangedMeanwhile(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	g, held := holdFirstCheck(t, e)

	result := make(chan error, 1)
	go func() {
		_, err := b.changePassword(testPassword, otherPassword)
		result <- err
	}()
	waitStarted(t, held, 1)

	admin := e.admin(testUser)
	changed, err := cheapHash("a password that somebody else set")
	if err != nil {
		t.Fatal(err)
	}
	admin.PasswordHash = changed
	if err := e.db.UpdateAdmin(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	g.open()

	select {
	case err := <-result:
		wantCode(t, err, connect.CodeAborted)
	case <-time.After(5 * time.Second):
		t.Fatal("ChangePassword did not return")
	}
	if got := e.admin(testUser).PasswordHash; got != changed {
		t.Error("the call replaced a password that it had not checked")
	}
	if n := e.sessions(); n != 1 {
		t.Errorf("%d sessions, want the one that there was", n)
	}
}

// What a client that is not a Connect library sees of a lock: HTTP 429, a
// Retry-After header, and the Connect error as JSON.
func TestLoginLockIsAnHTTP429WithRetryAfter(t *testing.T) {
	e := newEnvAdmin(t)
	body := `{"username":"admin","password":"` + wrongPassword + `"}`
	for i := range maxFailures {
		resp, out := e.callAs("", authPath+"Login", body)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d, body %s", i+1, resp.StatusCode, out)
		}
	}
	resp, out := e.callAs("", authPath+"Login", body)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429; body %s", resp.StatusCode, out)
	}
	if got := resp.Header.Get("Retry-After"); got != "900" {
		t.Errorf("Retry-After = %q, want 900", got)
	}
	if !strings.Contains(out, `"code":"resource_exhausted"`) {
		t.Errorf("body %s", out)
	}
	if len(resp.Header.Values("Set-Cookie")) != 0 {
		t.Error("a refusal set a cookie")
	}
}

// Enrolling an authenticator takes the password, so that whoever holds a session
// is not enough.
func TestConfirmTotpNeedsThePassword(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	begin, err := b.beginTotp()
	wantOK(t, err)
	code := e.code(begin.Msg.GetSecret())

	for name, password := range map[string]string{"none": "", "wrong": wrongPassword} {
		_, err := b.confirmTotpWith(code, password)
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("%s password: code = %v (%v), want permission_denied", name, connect.CodeOf(err), err)
		}
	}
	if len(e.admin(testUser).TOTPSecretEnc) != 0 {
		t.Fatal("TOTP was turned on without the password")
	}

	// The refusals used up neither the code nor the set-up that BeginTotp started.
	_, err = b.confirmTotpWith(code, testPassword)
	wantOK(t, err)
	if len(e.admin(testUser).TOTPSecretEnc) == 0 {
		t.Error("TOTP is not on after a right password and a right code")
	}
}

// The password that ConfirmTotp asks for counts on the limits of signing in, like
// the one of ChangePassword: it cannot be guessed through it.
func TestConfirmTotpPasswordIsRateLimited(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	begin, err := b.beginTotp()
	wantOK(t, err)
	code := e.code(begin.Msg.GetSecret())

	for range maxFailures {
		_, err := b.confirmTotpWith(code, wrongPassword)
		wantCode(t, err, connect.CodePermissionDenied)
	}
	_, err = b.confirmTotpWith(code, testPassword)
	wantCode(t, err, connect.CodeResourceExhausted)
	if retryAfter(t, err) == "" {
		t.Error("no Retry-After")
	}
	if len(e.admin(testUser).TOTPSecretEnc) != 0 {
		t.Error("TOTP is on")
	}
}

// A thief who has the session and not the password can start an enrolment with a
// secret of its own, which is harmless, and cannot finish it: the authenticator
// that would lock the owner out is not enrolled.
func TestStolenSessionCannotEnrolAnAuthenticator(t *testing.T) {
	e := newEnvAdmin(t)
	owner := e.browser()
	token := owner.mustLogin()
	thief := e.browser()
	thief.setToken(token)

	begin, err := thief.beginTotp()
	wantOK(t, err)
	thiefsCode := e.code(begin.Msg.GetSecret()) // from an app of its own
	for _, password := range []string{"", wrongPassword} {
		_, err = thief.confirmTotpWith(thiefsCode, password)
		wantCode(t, err, connect.CodePermissionDenied)
	}
	if len(e.admin(testUser).TOTPSecretEnc) != 0 {
		t.Fatal("the thief enrolled its authenticator")
	}
	// The owner still signs in with the password alone.
	if resp, err := e.browser().login(testUser, testPassword, ""); err != nil || resp.Msg.GetTotpRequired() {
		t.Errorf("the owner cannot sign in as before: %v, %v", resp, err)
	}
}

// With TOTP on, the password alone does not change the password.
func TestChangePasswordNeedsACodeWhenTotpIsOn(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	oldToken := b.mustLogin()
	secret := b.enableTotp()
	before := e.admin(testUser).PasswordHash

	for name, c := range map[string]struct{ current, code string }{
		"no code":                      {testPassword, ""},
		"a wrong code":                 {testPassword, e.badCode(secret)},
		"a code that is too short":     {testPassword, "12345"},
		"a right code, wrong password": {wrongPassword, e.code(secret)},
	} {
		_, err := b.changePasswordWithCode(c.current, otherPassword, c.code)
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("%s: code = %v (%v), want permission_denied", name, connect.CodeOf(err), err)
		}
	}
	if e.admin(testUser).PasswordHash != before {
		t.Fatal("a refused ChangePassword changed the password")
	}
	if _, err := e.session(oldToken); err != nil || e.sessions() != 1 {
		t.Fatalf("a refused ChangePassword ended sessions (%d left): %v", e.sessions(), err)
	}

	// Right password and right code: the code may have spaces, as the app shows it.
	code := e.code(secret)
	resp, err := b.changePasswordWithCode(testPassword, otherPassword, code[:3]+" "+code[3:])
	wantOK(t, err)
	if e.admin(testUser).PasswordHash == before {
		t.Error("the password did not change")
	}
	if c := sessionCookie(t, resp.Header()); c.Value == "" || c.Value == oldToken {
		t.Errorf("new cookie %+v", c)
	}

	// The code is used up, here as everywhere: it does not sign in the next
	// second. The one of the next step does.
	_, err = e.browser().login(testUser, otherPassword, code)
	wantCode(t, err, connect.CodeUnauthenticated)
	e.clock.Advance(30 * time.Second)
	if resp, err := e.browser().login(testUser, otherPassword, e.code(secret)); err != nil || resp.Msg.GetTotpRequired() {
		t.Errorf("Login with the new password and the next code: %v, %v", resp, err)
	}
}

func TestChangePasswordIgnoresACodeWhenTotpIsOff(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	if _, err := b.changePasswordWithCode(testPassword, otherPassword, "123456"); err != nil {
		t.Fatalf("ChangePassword with a code for an admin without TOTP: %v", err)
	}
}

func TestChangePasswordWrongCodesAreFailures(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	secret := b.enableTotp()
	for range maxFailures {
		_, err := b.changePasswordWithCode(testPassword, otherPassword, e.badCode(secret))
		wantCode(t, err, connect.CodePermissionDenied)
	}
	_, err := b.changePasswordWithCode(testPassword, otherPassword, e.code(secret))
	wantCode(t, err, connect.CodeResourceExhausted)
}

// Whether a code is needed is decided at the start of the call and checked again
// at the end. If TOTP was turned on in the meantime, the call does not go
// through without a code.
func TestChangePasswordRefusesWhenTotpWasTurnedOnMeanwhile(t *testing.T) {
	e := newEnvAdmin(t)
	a, other := e.browser(), e.browser()
	a.mustLogin()
	other.mustLogin()
	g, held := holdFirstCheck(t, e)

	result := make(chan error, 1)
	go func() {
		_, err := a.changePassword(testPassword, otherPassword)
		result <- err
	}()
	waitStarted(t, held, 1) // the password is checked, and no code was asked for

	other.enableTotp()
	g.open()

	select {
	case err := <-result:
		wantCode(t, err, connect.CodeAborted)
	case <-time.After(5 * time.Second):
		t.Fatal("ChangePassword did not return")
	}
	if ok, _ := passwd.Verify(e.admin(testUser).PasswordHash, testPassword); !ok {
		t.Error("the password was changed without a code")
	}
}

// The password that ConfirmTotp has checked is the one that is there when it
// writes.
func TestConfirmTotpRefusesWhenThePasswordChangedMeanwhile(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	b.mustLogin()
	begin, err := b.beginTotp()
	wantOK(t, err)
	code := e.code(begin.Msg.GetSecret())
	g, held := holdFirstCheck(t, e)

	result := make(chan error, 1)
	go func() {
		_, err := b.confirmTotp(code)
		result <- err
	}()
	waitStarted(t, held, 1)

	admin := e.admin(testUser)
	changed, err := cheapHash("a password that somebody else set")
	if err != nil {
		t.Fatal(err)
	}
	admin.PasswordHash = changed
	if err := e.db.UpdateAdmin(context.Background(), admin); err != nil {
		t.Fatal(err)
	}
	g.open()

	select {
	case err := <-result:
		wantCode(t, err, connect.CodeAborted)
	case <-time.After(5 * time.Second):
		t.Fatal("ConfirmTotp did not return")
	}
	if len(e.admin(testUser).TOTPSecretEnc) != 0 {
		t.Error("TOTP was turned on by a call whose password was no longer the password")
	}
}
