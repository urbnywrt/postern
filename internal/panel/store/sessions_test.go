package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func newSession(adminID, hash string) *Session {
	return &Session{
		TokenHash: hash,
		AdminID:   adminID,
		IP:        "192.0.2.10",
		UserAgent: "Mozilla/5.0 (test)",
		CreatedAt: testNow,
		ExpiresAt: testNow.Add(7 * 24 * time.Hour),
	}
}

func TestSessionRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	admin := mustAdmin(t, db, "admin")
	s := newSession(admin.ID, "hash-1")
	if err := db.CreateSession(ctx, s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := db.SessionByTokenHash(ctx, "hash-1")
	if err != nil {
		t.Fatalf("SessionByTokenHash: %v", err)
	}
	if !reflect.DeepEqual(got, s) {
		t.Errorf("session = %+v, want %+v", got, s)
	}
}

func TestSessionCreatedAtDefaultsToNow(t *testing.T) {
	db := newTestDB(t)
	db.now = fixedClock(testNow)
	admin := mustAdmin(t, db, "admin")
	s := &Session{TokenHash: "h", AdminID: admin.ID, ExpiresAt: testNow.Add(time.Hour)}
	if err := db.CreateSession(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if !s.CreatedAt.Equal(testNow) {
		t.Errorf("CreatedAt = %v, want %v", s.CreatedAt, testNow)
	}
}

// A time that is not set comes back as not set, not as the 1970 epoch.
func TestZeroTimeRoundTrips(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	admin := mustAdmin(t, db, "admin")
	s := &Session{TokenHash: "h", AdminID: admin.ID} // no ExpiresAt
	if err := db.CreateSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, err := db.SessionByTokenHash(ctx, "h")
	if err != nil {
		t.Fatal(err)
	}
	if !got.ExpiresAt.IsZero() || !reflect.DeepEqual(got.ExpiresAt, time.Time{}) {
		t.Errorf("ExpiresAt = %v, want the zero time", got.ExpiresAt)
	}
	if !reflect.DeepEqual(got, s) {
		t.Errorf("session = %+v, want %+v", got, s)
	}
}

func TestSessionErrors(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	admin := mustAdmin(t, db, "admin")

	if _, err := db.SessionByTokenHash(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("SessionByTokenHash err = %v, want ErrNotFound", err)
	}
	if err := db.CreateSession(ctx, newSession("no-such-admin", "h")); !errors.Is(err, ErrNotFound) {
		t.Errorf("CreateSession for an unknown admin: err = %v, want ErrNotFound", err)
	}
	if err := db.CreateSession(ctx, newSession(admin.ID, "dup")); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession(ctx, newSession(admin.ID, "dup")); !errors.Is(err, ErrConflict) {
		t.Errorf("CreateSession twice: err = %v, want ErrConflict", err)
	}
}

func TestTouchSession(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	admin := mustAdmin(t, db, "admin")
	s := newSession(admin.ID, "h")
	if err := db.CreateSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	later := testNow.Add(30 * 24 * time.Hour)
	if err := db.TouchSession(ctx, "h", later); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	got, err := db.SessionByTokenHash(ctx, "h")
	if err != nil {
		t.Fatal(err)
	}
	want := *s
	want.ExpiresAt = later
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("after touch = %+v, want %+v", *got, want)
	}
	if err := db.TouchSession(ctx, "missing", later); !errors.Is(err, ErrNotFound) {
		t.Errorf("TouchSession on a missing session: err = %v, want ErrNotFound", err)
	}
}

func TestDeleteSession(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	admin := mustAdmin(t, db, "admin")
	for _, h := range []string{"a", "b"} {
		if err := db.CreateSession(ctx, newSession(admin.ID, h)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.DeleteSession(ctx, "a"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := db.SessionByTokenHash(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted session is still there: %v", err)
	}
	if _, err := db.SessionByTokenHash(ctx, "b"); err != nil {
		t.Errorf("another session was deleted: %v", err)
	}
	// Logging out twice is not an error.
	if err := db.DeleteSession(ctx, "a"); err != nil {
		t.Errorf("DeleteSession of a missing session: %v", err)
	}
}

func TestDeleteSessionsForAdmin(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	one := mustAdmin(t, db, "one")
	two := mustAdmin(t, db, "two")
	for _, s := range []*Session{
		newSession(one.ID, "o1"), newSession(one.ID, "o2"), newSession(two.ID, "t1"),
	} {
		if err := db.CreateSession(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.DeleteSessionsForAdmin(ctx, one.ID); err != nil {
		t.Fatalf("DeleteSessionsForAdmin: %v", err)
	}
	for _, h := range []string{"o1", "o2"} {
		if _, err := db.SessionByTokenHash(ctx, h); !errors.Is(err, ErrNotFound) {
			t.Errorf("session %s survived: %v", h, err)
		}
	}
	if _, err := db.SessionByTokenHash(ctx, "t1"); err != nil {
		t.Errorf("the session of another admin was deleted: %v", err)
	}
	// None left is not an error.
	if err := db.DeleteSessionsForAdmin(ctx, one.ID); err != nil {
		t.Errorf("second DeleteSessionsForAdmin: %v", err)
	}
}

func TestSessionsGoWithTheirAdmin(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	admin := mustAdmin(t, db, "admin")
	if err := db.CreateSession(ctx, newSession(admin.ID, "h")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM admins WHERE id = ?`, admin.ID); err != nil {
		t.Fatal(err)
	}
	if n := count(t, db, `SELECT count(*) FROM sessions`); n != 0 {
		t.Errorf("%d sessions left after the admin was deleted", n)
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	admin := mustAdmin(t, db, "admin")
	for name, expires := range map[string]time.Time{
		"expired":     testNow.Add(-time.Hour),
		"expires-now": testNow, // a session is valid until its expiry, not at it
		"valid":       testNow.Add(time.Second),
	} {
		s := newSession(admin.ID, name)
		s.ExpiresAt = expires
		if err := db.CreateSession(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	n, err := db.DeleteExpiredSessions(ctx, testNow)
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d sessions, want 2", n)
	}
	if _, err := db.SessionByTokenHash(ctx, "valid"); err != nil {
		t.Errorf("the valid session was deleted: %v", err)
	}
	for _, h := range []string{"expired", "expires-now"} {
		if _, err := db.SessionByTokenHash(ctx, h); !errors.Is(err, ErrNotFound) {
			t.Errorf("session %s was not deleted: %v", h, err)
		}
	}
}
