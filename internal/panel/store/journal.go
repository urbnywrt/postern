package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The page sizes of the journal (ListEventsFiltered, ListAudit). The store
// returns up to maxJournalLimit+1 rows: a caller that pages at the maximum
// asks for one row more to know whether there is a next page.
const (
	defaultJournalLimit = 50
	maxJournalLimit     = 200 + 1
)

// ErrBadFilter is returned for a journal filter that names an unknown value.
var ErrBadFilter = errors.New("store: bad filter")

// SeverityRank orders the severities of events: info 0, warning (or warn) 1,
// error 2. A severity it does not know is false.
func SeverityRank(s string) (int, bool) {
	switch s {
	case "info":
		return 0, true
	case "warning", "warn":
		return 1, true
	case "error":
		return 2, true
	}
	return 0, false
}

// severityRankSQL is SeverityRank in SQL; a severity it does not know is 0.
const severityRankSQL = `CASE severity WHEN 'error' THEN 2 WHEN 'warning' THEN 1 WHEN 'warn' THEN 1 ELSE 0 END`

// A Cursor is where a page of the journal ended: its last row. The next page
// begins with the row before it, in the order (ts DESC, id DESC), so rows of
// the same second are neither repeated nor skipped.
type Cursor struct {
	TS time.Time
	ID string
}

// EventFilter selects events. Empty fields do not filter. From is inclusive
// and To exclusive, to the second. Limit is the page size: 0 or less is 50,
// and at most 200.
type EventFilter struct {
	NodeID      string
	ProxyID     string
	MinSeverity string // "", or a severity that SeverityRank knows
	Kind        string // exactly this kind
	KindPrefix  string
	From, To    time.Time
	Before      *Cursor
	Limit       int
}

// AuditFilter selects audit entries, as EventFilter does events.
type AuditFilter struct {
	AdminID      string
	ActionPrefix string
	From, To     time.Time
	Before       *Cursor
	Limit        int
}

// where builds a conjunction of conditions and their arguments.
type where struct {
	conds []string
	args  []any
}

func (w *where) add(cond string, args ...any) {
	w.conds = append(w.conds, cond)
	w.args = append(w.args, args...)
}

// prefix keeps the values of col that begin with p: compared as text, so that
// p is not a LIKE pattern.
func (w *where) prefix(col, p string) {
	if p != "" {
		w.add(`substr(`+col+`, 1, length(?)) = ?`, p, p)
	}
}

// page adds the time range and the cursor, and returns the query's end.
func (w *where) page(from, to time.Time, before *Cursor, limit int) string {
	if !from.IsZero() {
		w.add(`ts >= ?`, from.Unix())
	}
	if !to.IsZero() {
		w.add(`ts < ?`, to.Unix())
	}
	if before != nil {
		ts := before.TS.Unix()
		w.add(`(ts < ? OR (ts = ? AND id < ?))`, ts, ts, before.ID)
	}
	q := ""
	if len(w.conds) > 0 {
		q = ` WHERE ` + strings.Join(w.conds, ` AND `)
	}
	if limit <= 0 {
		limit = defaultJournalLimit
	}
	w.args = append(w.args, min(limit, maxJournalLimit))
	return q + ` ORDER BY ts DESC, id DESC LIMIT ?`
}

// eventsQuery is the query of ListEventsFiltered and its arguments.
func eventsQuery(f EventFilter) (string, []any, error) {
	var w where
	if f.NodeID != "" {
		w.add(`node_id = ?`, f.NodeID)
	}
	if f.ProxyID != "" {
		w.add(`proxy_id = ?`, f.ProxyID)
	}
	if f.Kind != "" {
		w.add(`kind = ?`, f.Kind)
	}
	if f.MinSeverity != "" {
		rank, ok := SeverityRank(f.MinSeverity)
		if !ok {
			return "", nil, fmt.Errorf("%w: severity %q", ErrBadFilter, f.MinSeverity)
		}
		w.add(severityRankSQL+` >= ?`, rank)
	}
	w.prefix("kind", f.KindPrefix)
	tail := w.page(f.From, f.To, f.Before, f.Limit)
	return `SELECT id, ts, node_id, proxy_id, kind, severity, message, details FROM events` + tail, w.args, nil
}

// ListEventsFiltered returns a page of the events that f selects, newest
// first (by time, then by id). An unknown MinSeverity is ErrBadFilter.
func (db *DB) ListEventsFiltered(ctx context.Context, f EventFilter) ([]*Event, error) {
	query, args, err := eventsQuery(f)
	if err != nil {
		return nil, err
	}
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Event
	for rows.Next() {
		var (
			e       Event
			ts      int64
			details string
		)
		if err := rows.Scan(&e.ID, &ts, &e.NodeID, &e.ProxyID, &e.Kind, &e.Severity, &e.Message, &details); err != nil {
			return nil, fmt.Errorf("store: list events: %w", err)
		}
		e.TS = timeFromDB(ts)
		if e.Details, err = decodeMap[string](details); err != nil {
			return nil, fmt.Errorf("store: list events: decode details: %w", err)
		}
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list events: %w", err)
	}
	return out, nil
}

// ListAudit returns a page of the audit entries that f selects, newest first
// (by time, then by id).
func (db *DB) ListAudit(ctx context.Context, f AuditFilter) ([]*AuditEntry, error) {
	var w where
	if f.AdminID != "" {
		w.add(`admin_id = ?`, f.AdminID)
	}
	w.prefix("action", f.ActionPrefix)
	tail := w.page(f.From, f.To, f.Before, f.Limit)
	rows, err := db.sql.QueryContext(ctx,
		`SELECT id, ts, admin_id, action, target, details FROM audit_log`+tail, w.args...)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*AuditEntry
	for rows.Next() {
		var (
			a       AuditEntry
			ts      int64
			details string
		)
		if err := rows.Scan(&a.ID, &ts, &a.AdminID, &a.Action, &a.Target, &details); err != nil {
			return nil, fmt.Errorf("store: list audit: %w", err)
		}
		a.TS = timeFromDB(ts)
		if a.Details, err = decodeMap[string](details); err != nil {
			return nil, fmt.Errorf("store: list audit: decode details: %w", err)
		}
		out = append(out, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	return out, nil
}
