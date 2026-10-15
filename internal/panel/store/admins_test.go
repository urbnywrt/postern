package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// mustAdmin creates an admin with a name of its own.
func mustAdmin(t *testing.T, db *DB, username string) *Admin {
	t.Helper()
	a := &Admin{Username: username, PasswordHash: "hash-of-password"}
	if err := db.CreateAdmin(context.Background(), a); err != nil {
		t.Fatalf("CreateAdmin(%s): %v", username, err)
	}
	return a
}

func TestAdminRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	login := testNow.Add(time.Hour)
	a := &Admin{
		Username:      "admin",
		PasswordHash:  "hash-of-password",
		TOTPSecretEnc: []byte("sealed-totp"),
		CreatedAt:     testNow,
		LastLoginAt:   &login,
	}
	if err := db.CreateAdmin(ctx, a); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	if len(a.ID) != 26 {
		t.Fatalf("ID = %q, want a ULID", a.ID)
	}

	byID, err := db.AdminByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("AdminByID: %v", err)
	}
	if !reflect.DeepEqual(byID, a) {
		t.Errorf("AdminByID = %+v, want %+v", byID, a)
	}
	byName, err := db.AdminByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("AdminByUsername: %v", err)
	}
	if !reflect.DeepEqual(byName, a) {
		t.Errorf("AdminByUsername = %+v, want %+v", byName, a)
	}
}

func TestAdminDefaults(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow.Add(500 * time.Millisecond)) // the sub-second part is not kept
	a := &Admin{Username: "admin", PasswordHash: "hash-of-password"}
	if err := db.CreateAdmin(ctx, a); err != nil {
		t.Fatal(err)
	}
	if !a.CreatedAt.Equal(testNow) {
		t.Errorf("CreatedAt = %v, want the clock to the second (%v)", a.CreatedAt, testNow)
	}
	got, err := db.AdminByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TOTPSecretEnc != nil || got.LastLoginAt != nil {
		t.Errorf("TOTPSecretEnc = %v, LastLoginAt = %v, want both unset", got.TOTPSecretEnc, got.LastLoginAt)
	}
	if !reflect.DeepEqual(got, a) {
		t.Errorf("stored admin %+v differs from the record that Create filled in: %+v", got, a)
	}
}

func TestAdminKeepsID(t *testing.T) {
	db := newTestDB(t)
	a := &Admin{ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Username: "admin", PasswordHash: "h"}
	if err := db.CreateAdmin(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if a.ID != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Errorf("ID = %q, want the one that was given", a.ID)
	}
}

func TestAdminDuplicateUsername(t *testing.T) {
	db := newTestDB(t)
	mustAdmin(t, db, "admin")
	err := db.CreateAdmin(context.Background(), &Admin{Username: "admin", PasswordHash: "other"})
	if !errors.Is(err, ErrConflict) {
		t.Errorf("err = %v, want ErrConflict", err)
	}
	// Names are compared exactly; callers normalise them if they want to.
	if err := db.CreateAdmin(context.Background(), &Admin{Username: "Admin", PasswordHash: "other"}); err != nil {
		t.Errorf("a name that differs in case was refused: %v", err)
	}
}

func TestAdminNotFound(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.AdminByID(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("AdminByID err = %v, want ErrNotFound", err)
	}
	if _, err := db.AdminByUsername(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("AdminByUsername err = %v, want ErrNotFound", err)
	}
	if err := db.UpdateAdmin(ctx, &Admin{ID: "nope", Username: "x", PasswordHash: "h"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateAdmin err = %v, want ErrNotFound", err)
	}
}

func TestUpdateAdmin(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow)
	a := mustAdmin(t, db, "admin")
	other := mustAdmin(t, db, "other")

	login := testNow.Add(2 * time.Hour)
	a.Username = "root"
	a.PasswordHash = "new-hash"
	a.TOTPSecretEnc = []byte("sealed-totp")
	a.LastLoginAt = &login
	if err := db.UpdateAdmin(ctx, a); err != nil {
		t.Fatalf("UpdateAdmin: %v", err)
	}
	got, err := db.AdminByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, a) {
		t.Errorf("after update = %+v, want %+v", got, a)
	}
	if !got.CreatedAt.Equal(testNow) {
		t.Errorf("CreatedAt changed to %v", got.CreatedAt)
	}

	// Switching TOTP off stores NULL again.
	a.TOTPSecretEnc = nil
	if err := db.UpdateAdmin(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, _ = db.AdminByID(ctx, a.ID)
	if got.TOTPSecretEnc != nil {
		t.Errorf("TOTPSecretEnc = %v, want nil", got.TOTPSecretEnc)
	}

	// Another admin was not touched.
	if o, _ := db.AdminByID(ctx, other.ID); !reflect.DeepEqual(o, other) {
		t.Errorf("other admin changed: %+v", o)
	}

	// A name that is taken is a conflict.
	a.Username = "other"
	if err := db.UpdateAdmin(ctx, a); !errors.Is(err, ErrConflict) {
		t.Errorf("err = %v, want ErrConflict", err)
	}
}

func TestCountAdmins(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for want, name := range []string{"", "one", "two"} {
		if name != "" {
			mustAdmin(t, db, name)
		}
		got, err := db.CountAdmins(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("CountAdmins = %d, want %d", got, want)
		}
	}
}
