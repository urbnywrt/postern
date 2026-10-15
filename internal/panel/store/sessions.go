package store

import (
	"context"
	"fmt"
	"time"
)

// A Session is a sign-in of an admin. It is found by the hash of its token: the
// token itself is only in the cookie of the browser.
type Session struct {
	TokenHash string // hex SHA-256 of the token
	AdminID   string
	IP        string
	UserAgent string
	CreatedAt time.Time
	ExpiresAt time.Time
}

const sessionColumns = `token_hash, admin_id, ip, user_agent, created_at, expires_at`

// CreateSession stores s, with the creation time of the clock if it has none. An
// admin that does not exist is [ErrNotFound], a token hash that is taken
// [ErrConflict].
func (db *DB) CreateSession(ctx context.Context, s *Session) error {
	created := s.CreatedAt
	if created.IsZero() {
		created = db.now()
	}
	created = normTime(created)
	expires := normTime(s.ExpiresAt)

	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO sessions (`+sessionColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
		s.TokenHash, s.AdminID, s.IP, s.UserAgent, created.Unix(), expires.Unix())
	if err != nil {
		return fmt.Errorf("store: create session: %w", mapErr(err, fkMissing))
	}
	s.CreatedAt, s.ExpiresAt = created, expires
	return nil
}

// SessionByTokenHash returns the session with this token hash, or
// [ErrNotFound]. It returns an expired session too: whether a session has
// expired is for the caller to decide.
func (db *DB) SessionByTokenHash(ctx context.Context, hash string) (*Session, error) {
	var (
		s                Session
		created, expires int64
	)
	err := db.sql.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE token_hash = ?`, hash).
		Scan(&s.TokenHash, &s.AdminID, &s.IP, &s.UserAgent, &created, &expires)
	if err != nil {
		return nil, fmt.Errorf("store: session by token hash: %w", queryNotFound(err, "session"))
	}
	s.CreatedAt, s.ExpiresAt = timeFromDB(created), timeFromDB(expires)
	return &s, nil
}

// TouchSession sets the expiry of a session, which is how a session slides. A
// session that does not exist is [ErrNotFound].
func (db *DB) TouchSession(ctx context.Context, hash string, expires time.Time) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE sessions SET expires_at = ? WHERE token_hash = ?`, normTime(expires).Unix(), hash)
	if err != nil {
		return fmt.Errorf("store: touch session: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: touch session: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: touch session: %w", notFound("session"))
	}
	return nil
}

// DeleteSession deletes a session. It is not an error that there is none, so
// that signing out twice works.
func (db *DB) DeleteSession(ctx context.Context, hash string) error {
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hash); err != nil {
		return fmt.Errorf("store: delete session: %w", err)
	}
	return nil
}

// DeleteSessionsForAdmin deletes every session of an admin, for example after a
// password change.
func (db *DB) DeleteSessionsForAdmin(ctx context.Context, adminID string) error {
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM sessions WHERE admin_id = ?`, adminID); err != nil {
		return fmt.Errorf("store: delete sessions of admin: %w", err)
	}
	return nil
}

// DeleteExpiredSessions deletes the sessions that have expired at now, which is
// the sessions whose expiry is not after it, and returns how many there were. A
// session that nobody looks at again is otherwise never deleted.
func (db *DB) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.Unix())
	if err != nil {
		return 0, fmt.Errorf("store: delete expired sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: delete expired sessions: %w", err)
	}
	return n, nil
}
