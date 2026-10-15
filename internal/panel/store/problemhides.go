package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// A ProblemHide hides a problem of the feed until it changes: the feed shows
// the problem again once its fingerprint is not this one.
type ProblemHide struct {
	// Key names the problem across refreshes.
	Key string
	// Fingerprint is a hash of the problem's severity and summary when it
	// was hidden.
	Fingerprint string
	HiddenAt    time.Time
	AdminID     string
}

// HideProblem stores a hide, replacing the one of the same key. The time is
// the clock's if h has none.
func (db *DB) HideProblem(ctx context.Context, h *ProblemHide) error {
	at := h.HiddenAt
	if at.IsZero() {
		at = db.now()
	}
	at = normTime(at)
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO problem_hides (key, fingerprint, hidden_at, admin_id) VALUES (?, ?, ?, ?)
		 ON CONFLICT (key) DO UPDATE SET fingerprint = excluded.fingerprint,
		   hidden_at = excluded.hidden_at, admin_id = excluded.admin_id`,
		h.Key, h.Fingerprint, at.Unix(), h.AdminID)
	if err != nil {
		return fmt.Errorf("store: hide problem: %w", err)
	}
	h.HiddenAt = at
	return nil
}

// UnhideProblem deletes the hide of a problem and reports whether there was
// one.
func (db *DB) UnhideProblem(ctx context.Context, key string) (bool, error) {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM problem_hides WHERE key = ?`, key)
	if err != nil {
		return false, fmt.Errorf("store: unhide problem: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: unhide problem: %w", err)
	}
	return n > 0, nil
}

// SettleProblemHides compares the hides with the problems there are now, the
// fingerprint of each by its key, and returns the hides that hold, by key. It
// deletes the hide of a problem whose fingerprint changed; when complete is
// set (current is the whole feed), also those of problems that are gone.
func (db *DB) SettleProblemHides(ctx context.Context, current map[string]string, complete bool) (map[string]ProblemHide, error) {
	held := map[string]ProblemHide{}
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT key, fingerprint, hidden_at, admin_id FROM problem_hides`)
		if err != nil {
			return err
		}
		var stale []string
		for rows.Next() {
			var (
				h  ProblemHide
				at int64
			)
			if err := rows.Scan(&h.Key, &h.Fingerprint, &at, &h.AdminID); err != nil {
				_ = rows.Close()
				return err
			}
			h.HiddenAt = time.Unix(at, 0).UTC()
			fp, there := current[h.Key]
			switch {
			case there && fp == h.Fingerprint:
				held[h.Key] = h
			case there || complete:
				stale = append(stale, h.Key)
			}
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, key := range stale {
			if _, err := tx.ExecContext(ctx, `DELETE FROM problem_hides WHERE key = ?`, key); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: settle problem hides: %w", err)
	}
	return held, nil
}
