package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/urbnywrt/postern/internal/ids"
)

// An Admin is a person who can sign in to the panel.
type Admin struct {
	ID string
	// Username is compared exactly as it is stored. A caller that wants names
	// to be case-insensitive normalises them before it creates and looks up.
	Username     string
	PasswordHash string // the encoded argon2id hash, see internal/passwd
	// TOTPSecretEnc is the sealed TOTP secret, or nil when TOTP is off.
	TOTPSecretEnc []byte
	CreatedAt     time.Time
	LastLoginAt   *time.Time // nil: never signed in
}

const adminColumns = `id, username, password_hash, totp_secret_enc, created_at, last_login_at`

func scanAdmin(s scanner) (*Admin, error) {
	var (
		a       Admin
		created int64
		last    sql.NullInt64
	)
	if err := s.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.TOTPSecretEnc, &created, &last); err != nil {
		return nil, err
	}
	a.CreatedAt = timeFromDB(created)
	a.LastLoginAt = timePtrFromDB(last)
	return &a, nil
}

// CountAdmins returns the number of admins. The panel is set up when it is not
// zero.
func (db *DB) CountAdmins(ctx context.Context) (int, error) {
	var n int
	if err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM admins`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count admins: %w", err)
	}
	return n, nil
}

// CreateAdmin stores a. It gives a an ID if it has none and a creation time if
// it has none. A user name that is taken is [ErrConflict].
func (db *DB) CreateAdmin(ctx context.Context, a *Admin) error {
	id := a.ID
	if id == "" {
		id = ids.New()
	}
	created := a.CreatedAt
	if created.IsZero() {
		created = db.now()
	}
	created = normTime(created)
	last := normTimePtr(a.LastLoginAt)

	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO admins (`+adminColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
		id, a.Username, a.PasswordHash, nullBlob(a.TOTPSecretEnc), created.Unix(), nullTime(last))
	if err != nil {
		return fmt.Errorf("store: create admin: %w", mapErr(err, fkMissing))
	}
	a.ID, a.CreatedAt, a.LastLoginAt = id, created, last
	return nil
}

// AdminByUsername returns the admin with exactly this user name, or
// [ErrNotFound].
func (db *DB) AdminByUsername(ctx context.Context, username string) (*Admin, error) {
	a, err := scanAdmin(db.sql.QueryRowContext(ctx, `SELECT `+adminColumns+` FROM admins WHERE username = ?`, username))
	if err != nil {
		return nil, fmt.Errorf("store: admin by username: %w", queryNotFound(err, "admin"))
	}
	return a, nil
}

// AdminByID returns the admin with this id, or [ErrNotFound].
func (db *DB) AdminByID(ctx context.Context, id string) (*Admin, error) {
	a, err := scanAdmin(db.sql.QueryRowContext(ctx, `SELECT `+adminColumns+` FROM admins WHERE id = ?`, id))
	if err != nil {
		return nil, fmt.Errorf("store: admin by id: %w", queryNotFound(err, "admin"))
	}
	return a, nil
}

// UpdateAdmin writes the user name, the password hash, the TOTP secret and the
// time of the last sign-in of a. The id says which admin, and the creation time
// is not changed. An admin that does not exist is [ErrNotFound], a user name
// that is taken [ErrConflict].
func (db *DB) UpdateAdmin(ctx context.Context, a *Admin) error {
	last := normTimePtr(a.LastLoginAt)
	res, err := db.sql.ExecContext(ctx,
		`UPDATE admins SET username = ?, password_hash = ?, totp_secret_enc = ?, last_login_at = ? WHERE id = ?`,
		a.Username, a.PasswordHash, nullBlob(a.TOTPSecretEnc), nullTime(last), a.ID)
	if err != nil {
		return fmt.Errorf("store: update admin: %w", mapErr(err, fkMissing))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: update admin: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: update admin: %w", notFound("admin"))
	}
	a.LastLoginAt = last
	return nil
}
