package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/passwd"
)

func TestSetupFlow(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	ctx := context.Background()

	if !b.setupStatus() {
		t.Fatal("a panel without an admin does not need setup")
	}
	token, ok := e.svc.SetupToken()
	if !ok || len(token) != 43 {
		t.Fatalf("SetupToken() = %q, %v, want a token of 43 characters", token, ok)
	}

	// The token is required, and a wrong one does not use up the right one.
	for name, bad := range map[string]string{
		"none":       "",
		"wrong":      strings.Repeat("a", 43),
		"too short":  token[:10],
		"with extra": token + "x",
	} {
		_, err := b.setup(bad, "admin", testPassword)
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("Setup with %s token: code = %v (%v), want permission_denied", name, connect.CodeOf(err), err)
		}
	}
	if n, _ := e.db.CountAdmins(ctx); n != 0 {
		t.Fatalf("%d admins after Setup with wrong tokens", n)
	}
	if again, ok := e.svc.SetupToken(); !ok || again != token {
		t.Fatal("a wrong token used up the setup token")
	}

	// A bad user name or password is refused before anything is stored, and
	// leaves the token alone, so that a typo does not force a restart.
	for name, c := range map[string]struct{ user, password string }{
		"empty user name":        {"", testPassword},
		"user name with a space": {"two words", testPassword},
		"user name of 65":        {strings.Repeat("a", 65), testPassword},
		"user name with control": {"ad\x00min", testPassword},
		"password of 11":         {"admin", "elevenchars"},
		"empty password":         {"admin", ""},
		"password of 257 bytes":  {"admin", strings.Repeat("p", 257)},
	} {
		_, err := b.setup(token, c.user, c.password)
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("Setup with %s: code = %v (%v), want invalid_argument", name, connect.CodeOf(err), err)
		}
	}
	if n, _ := e.db.CountAdmins(ctx); n != 0 {
		t.Fatalf("%d admins after Setup with bad values", n)
	}
	if _, ok := e.svc.SetupToken(); !ok {
		t.Fatal("a refused Setup used up the setup token")
	}

	// A password of 12 characters is enough, and so is one of 256 bytes. The
	// user name is not case-sensitive.
	if _, err := b.setup(token, "  Admin ", "twelve chars"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if b.setupStatus() {
		t.Error("the panel still needs setup after Setup")
	}
	if tok, ok := e.svc.SetupToken(); ok {
		t.Errorf("SetupToken() = %q, true after Setup, want the token cleared", tok)
	}
	a := e.admin("admin")
	if ok, err := passwd.Verify(a.PasswordHash, "twelve chars"); err != nil || !ok {
		t.Errorf("the stored hash does not verify the password: %v, %v", ok, err)
	}
	if strings.Contains(a.PasswordHash, "twelve") {
		t.Error("the stored hash contains the password")
	}
	if len(a.TOTPSecretEnc) != 0 {
		t.Error("a new admin has TOTP on")
	}
	if !a.CreatedAt.Equal(e.clock.Now()) {
		t.Errorf("CreatedAt = %v, want %v", a.CreatedAt, e.clock.Now())
	}
	// Setup does not sign anybody in.
	if b.token() != "" || e.sessions() != 0 {
		t.Error("Setup started a session")
	}

	// The token is used up: it opens nothing a second time, and neither does
	// any other.
	_, err := b.setup(token, "second", testPassword)
	wantCode(t, err, connect.CodeFailedPrecondition)
	if n, _ := e.db.CountAdmins(ctx); n != 1 {
		t.Fatalf("%d admins after the second Setup, want 1", n)
	}
}

func TestSetupAcceptsLongestPassword(t *testing.T) {
	e := newEnv(t)
	token, _ := e.svc.SetupToken()
	if _, err := e.browser().setup(token, "admin", strings.Repeat("p", 256)); err != nil {
		t.Fatalf("Setup with a password of 256 bytes: %v", err)
	}
}

// Twelve characters are twelve code points, not twelve bytes.
func TestPasswordLengthCountsCharacters(t *testing.T) {
	for name, c := range map[string]struct {
		password string
		code     connect.Code
		ok       bool
	}{
		"12 characters of 3 bytes":  {strings.Repeat("пароль", 2), 0, true}, // 24 bytes
		"11 characters of 3 bytes":  {strings.Repeat("п", 11), connect.CodeInvalidArgument, false},
		"128 characters of 2 bytes": {strings.Repeat("п", 128), 0, true}, // 256 bytes
		"129 characters of 2 bytes": {strings.Repeat("п", 129), connect.CodeInvalidArgument, false},
	} {
		e := newEnv(t)
		token, _ := e.svc.SetupToken()
		_, err := e.browser().setup(token, "admin", c.password)
		if c.ok {
			wantOK(t, err)
		} else if connect.CodeOf(err) != c.code {
			t.Errorf("%s: code = %v (%v), want %v", name, connect.CodeOf(err), err, c.code)
		}
	}
}

func TestSetupTokenExpiresAfterAnHour(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	token, ok := e.svc.SetupToken()
	if !ok {
		t.Fatal("no setup token")
	}

	e.clock.Advance(time.Hour - time.Second)
	if _, ok := e.svc.SetupToken(); !ok {
		t.Fatal("the token expired before an hour")
	}

	e.clock.Advance(time.Second)
	if tok, ok := e.svc.SetupToken(); ok {
		t.Fatalf("SetupToken() = %q, true after an hour", tok)
	}
	_, err := b.setup(token, "admin", testPassword)
	wantCode(t, err, connect.CodePermissionDenied)
	if n, _ := e.db.CountAdmins(context.Background()); n != 0 {
		t.Fatal("Setup with an expired token created an admin")
	}
	// The panel still has no admin, whatever happened to the token.
	if !b.setupStatus() {
		t.Error("needs_setup is false while there is no admin")
	}
}

func TestNoSetupTokenWhenAnAdminExists(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	if tok, ok := e.svc.SetupToken(); ok {
		t.Fatalf("SetupToken() = %q, true for a panel that has an admin", tok)
	}
	if b.setupStatus() {
		t.Error("a panel with an admin needs setup")
	}
	_, err := b.setup(strings.Repeat("a", 43), "second", testPassword)
	wantCode(t, err, connect.CodeFailedPrecondition)
	if n, _ := e.db.CountAdmins(context.Background()); n != 1 {
		t.Fatalf("%d admins, want 1", n)
	}
}

// Many requests with the right token at once make one admin, not one each.
func TestSetupIsUsedUpByOneOfManyConcurrentRequests(t *testing.T) {
	e := newEnv(t)
	token, _ := e.svc.SetupToken()

	const n = 8
	var wg sync.WaitGroup
	results := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = e.browser().setup(token, fmt.Sprintf("admin%d", i), testPassword)
		}()
	}
	wg.Wait()

	succeeded := 0
	for i, err := range results {
		switch {
		case err == nil:
			succeeded++
		case connect.CodeOf(err) != connect.CodeFailedPrecondition && connect.CodeOf(err) != connect.CodePermissionDenied:
			t.Errorf("request %d: unexpected error %v", i, err)
		}
	}
	if succeeded != 1 {
		t.Errorf("%d requests succeeded, want 1", succeeded)
	}
	if got, _ := e.db.CountAdmins(context.Background()); got != 1 {
		t.Errorf("%d admins, want 1", got)
	}
}

// The setup token is made when the service starts, from random bytes, and a
// restart makes a new one.
func TestSetupTokenIsRandomPerStart(t *testing.T) {
	seen := map[string]bool{}
	for range 5 {
		e := newEnv(t)
		tok, ok := e.svc.SetupToken()
		if !ok || seen[tok] {
			t.Fatalf("token %q (ok=%v) is empty or was seen before", tok, ok)
		}
		seen[tok] = true
	}
}

// The password of the first admin is stored with the real cost, not the
// cheap one of the other tests.
func TestSetupHashesWithArgon2id(t *testing.T) {
	e := newEnv(t)
	e.svc.hash = passwd.Hash
	token, _ := e.svc.SetupToken()
	if _, err := e.browser().setup(token, "admin", testPassword); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	a := e.admin("admin")
	if !strings.HasPrefix(a.PasswordHash, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Errorf("hash %q is not argon2id with the cost of internal/passwd", a.PasswordHash)
	}
	if ok, err := passwd.Verify(a.PasswordHash, testPassword); err != nil || !ok {
		t.Errorf("Verify = %v, %v", ok, err)
	}
}

// Whoever has the token and the right to write to the database cannot make a
// second admin through Setup, either.
func TestSetupRefusesWhenAnAdminAppearedAfterStart(t *testing.T) {
	e := newEnv(t)
	token, _ := e.svc.SetupToken()
	if err := e.db.CreateAdmin(context.Background(), &store.Admin{Username: "other", PasswordHash: "x"}); err != nil {
		t.Fatal(err)
	}
	_, err := e.browser().setup(token, "admin", testPassword)
	wantCode(t, err, connect.CodeFailedPrecondition)
	if _, ok := e.svc.SetupToken(); ok {
		t.Error("the token is still valid although the panel has an admin")
	}
}

// Anybody can send a wrong token, as often as they like: that is not a thing to
// raise a warning about, nor to fill the log with at the usual level.
func TestWrongSetupTokenIsLoggedAtDebugOnly(t *testing.T) {
	e := newEnv(t)
	_, err := e.browser().setup("not the token", "admin", testPassword)
	wantCode(t, err, connect.CodePermissionDenied)

	found := false
	for _, line := range strings.Split(e.logs.String(), "\n") {
		if !strings.Contains(line, "setup refused") {
			continue
		}
		found = true
		if !strings.Contains(line, "level=DEBUG") {
			t.Errorf("a wrong setup token is logged above debug: %s", line)
		}
	}
	if !found {
		t.Error("a wrong setup token is not logged at all, not even at debug")
	}
}
