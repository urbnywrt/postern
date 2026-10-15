package auth

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// audits returns the entries of the audit log whose action begins with "auth.",
// oldest first.
func (e *env) audits() []*store.AuditEntry {
	e.t.Helper()
	all, err := e.db.ListAudit(context.Background(), store.AuditFilter{ActionPrefix: "auth.", Limit: 1000})
	if err != nil {
		e.t.Fatalf("ListAudit: %v", err)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].TS.Before(all[j].TS) })
	return all
}

func actionsOf(entries []*store.AuditEntry) []string {
	out := make([]string, 0, len(entries))
	for _, a := range entries {
		out = append(out, a.Action)
	}
	return out
}

// wantNoSecretIn fails the test if any detail of the entries holds one of the
// secrets.
func wantNoSecretIn(t *testing.T, entries []*store.AuditEntry, secrets ...string) {
	t.Helper()
	for _, a := range entries {
		for k, v := range a.Details {
			for _, s := range secrets {
				if s != "" && (strings.Contains(v, s) || strings.Contains(k, s)) {
					t.Errorf("%s: detail %s=%q holds a secret", a.Action, k, v)
				}
			}
		}
	}
}

func TestAuthAuditsSetupSignInAndCredentialChanges(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	token, _ := e.svc.SetupToken()
	_, err := b.setup(token, testUser, testPassword)
	wantOK(t, err)
	e.clock.Advance(time.Second)
	b.mustLogin()
	e.clock.Advance(time.Second)
	secret := b.enableTotp()
	code := e.code(secret)
	_, err = b.disableTotp(testPassword, code)
	wantOK(t, err)
	e.clock.Advance(time.Second)
	_, err = b.changePassword(testPassword, otherPassword)
	wantOK(t, err)

	entries := e.audits()
	got := strings.Join(actionsOf(entries), " ")
	want := "auth.setup auth.login auth.totp_enabled auth.totp_disabled auth.password_changed"
	if got != want {
		t.Fatalf("audit actions = %q, want %q", got, want)
	}
	id := e.admin(testUser).ID
	for _, a := range entries {
		if a.AdminID != id || a.Target != "admin:"+id {
			t.Errorf("%s: admin %q target %q, want %q and admin:%s", a.Action, a.AdminID, a.Target, id, id)
		}
		if a.Details["username"] != testUser || a.Details["source"] != "127.0.0.1" {
			t.Errorf("%s: details %v, want the user name and the source", a.Action, a.Details)
		}
	}
	wantNoSecretIn(t, entries, testPassword, otherPassword, token, secret, code, b.token())
}

func TestFailedSignInsAreAuditedOncePerSourceAMinute(t *testing.T) {
	e := newEnvAdmin(t)
	b := e.browser()
	for range 3 {
		_, err := b.login(testUser, wrongPassword, "")
		if err == nil {
			t.Fatal("a wrong password signed in")
		}
	}
	// A name that nobody has may be a password typed into the wrong field: it
	// is not written down.
	_, _ = b.login(otherPassword, wrongPassword, "")
	entries := e.audits()
	if len(entries) != 1 || entries[0].Action != "auth.login_failed" {
		t.Fatalf("after four failures in a minute: %q, want one auth.login_failed", actionsOf(entries))
	}
	if d := entries[0].Details; d["username"] != testUser || d["source"] != "127.0.0.1" || d["suppressed"] != "" {
		t.Errorf("the first failure: details %v", d)
	}

	e.clock.Advance(time.Minute)
	_, _ = b.login(otherPassword, wrongPassword, "")
	entries = e.audits()
	if len(entries) != 2 {
		t.Fatalf("after a minute: %q, want a second auth.login_failed", actionsOf(entries))
	}
	d := entries[1].Details
	if _, has := d["username"]; has || d["suppressed"] != "3" {
		t.Errorf("the failure of the next minute: details %v, want no user name and suppressed=3", d)
	}
	wantNoSecretIn(t, entries, wrongPassword, otherPassword)
}

func TestFailedSignInAuditsAreBoundedAcrossSources(t *testing.T) {
	l := &auditLimiter{}
	now := t0
	written := 0
	for i := range 1000 {
		if ok, _ := l.allow("10.0."+strconv.Itoa(i/256)+"."+strconv.Itoa(i%256), now); ok {
			written++
		}
	}
	if written != maxFailedAuditsPerMinute {
		t.Fatalf("%d rows for 1000 sources in a minute, want %d", written, maxFailedAuditsPerMinute)
	}
	ok, suppressed := l.allow("10.9.9.9", now.Add(time.Minute))
	if !ok || suppressed != 1000-maxFailedAuditsPerMinute {
		t.Fatalf("next minute: allow = %v, suppressed = %d, want true, %d", ok, suppressed, 1000-maxFailedAuditsPerMinute)
	}
}
