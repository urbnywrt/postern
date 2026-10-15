package store

import (
	"context"
	"fmt"
	"time"

	"github.com/urbnywrt/postern/internal/ids"
)

// The limits of ListEvents.
const (
	defaultEventLimit = 100  // used when no limit is given
	maxEventLimit     = 1000 // the most that one call returns
)

// Events are kept for 30 days. PruneEvents deletes the older ones in batches
// of pruneEventsBatch, each a transaction of its own: one long delete would
// keep every other writer of the database waiting.
const (
	retentionEvents  = 30 * 24 * time.Hour
	pruneEventsBatch = 1000
)

// An Event is something that happened to a node or a proxy. Events are history:
// they keep naming a node or proxy that has been deleted since.
type Event struct {
	ID       string
	TS       time.Time
	NodeID   string // "" when the event is not about a node
	ProxyID  string // "" when the event is not about a proxy
	Kind     string
	Severity string // "info" by default
	Message  string
	Details  map[string]string
}

// AppendEvent stores e. It gives e an ID if it has none, the time of the clock
// if it has none, and the severity "info" if it has none.
func (db *DB) AppendEvent(ctx context.Context, e *Event) error {
	c := *e
	if c.ID == "" {
		c.ID = ids.New()
	}
	if c.TS.IsZero() {
		c.TS = db.now()
	}
	c.TS = normTime(c.TS)
	if c.Severity == "" {
		c.Severity = "info"
	}
	details, err := encodeMap(c.Details)
	if err != nil {
		return fmt.Errorf("store: append event: encode details: %w", err)
	}
	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO events (id, ts, node_id, proxy_id, kind, severity, message, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.TS.Unix(), c.NodeID, c.ProxyID, c.Kind, c.Severity, c.Message, details)
	if err != nil {
		return fmt.Errorf("store: append event: %w", mapErr(err, fkMissing))
	}
	*e = c
	return nil
}

// ListEvents returns the newest events first, the events of one node if nodeID
// is not empty and those of every node if it is. A limit of zero or less means
// 100, and no call returns more than 1000.
func (db *DB) ListEvents(ctx context.Context, limit int, nodeID string) ([]*Event, error) {
	if limit <= 0 {
		limit = defaultEventLimit
	}
	limit = min(limit, maxEventLimit)
	query := `SELECT id, ts, node_id, proxy_id, kind, severity, message, details FROM events`
	var args []any
	if nodeID != "" {
		query += ` WHERE node_id = ?`
		args = append(args, nodeID)
	}
	query += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

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

// PruneEvents deletes the events that are more than 30 days older than now, to
// the second, and returns how many it deleted. It deletes at most 1000 at a
// time, each batch in a transaction of its own, and leaves the write lock free
// between the batches (see stepTx), so that other writers get the database.
// The audit log is kept.
func (db *DB) PruneEvents(ctx context.Context, now time.Time) (int64, error) {
	cut := now.Add(-retentionEvents).Unix()
	var total int64
	for first := true; ; first = false {
		if !first {
			if err := db.pause(ctx); err != nil {
				return total, fmt.Errorf("store: prune events: %w", err)
			}
		}
		res, err := db.sql.ExecContext(ctx,
			`DELETE FROM events WHERE rowid IN (SELECT rowid FROM events WHERE ts < ? LIMIT ?)`, cut, pruneEventsBatch)
		if err != nil {
			return total, fmt.Errorf("store: prune events: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("store: prune events: %w", err)
		}
		total += n
		if n < pruneEventsBatch {
			return total, nil
		}
	}
}

// An AuditEntry records what an admin did.
type AuditEntry struct {
	ID      string
	TS      time.Time
	AdminID string // "" for what no admin did, such as the first setup
	Action  string // for example "proxy.create"
	Target  string // what the action was about, for example "proxy:<id>"
	Details map[string]string
}

// AppendAudit stores a. It gives a an ID if it has none and the time of the
// clock if it has none.
func (db *DB) AppendAudit(ctx context.Context, a *AuditEntry) error {
	c := *a
	if c.ID == "" {
		c.ID = ids.New()
	}
	if c.TS.IsZero() {
		c.TS = db.now()
	}
	c.TS = normTime(c.TS)
	details, err := encodeMap(c.Details)
	if err != nil {
		return fmt.Errorf("store: append audit entry: encode details: %w", err)
	}
	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO audit_log (id, ts, admin_id, action, target, details) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.TS.Unix(), c.AdminID, c.Action, c.Target, details)
	if err != nil {
		return fmt.Errorf("store: append audit entry: %w", mapErr(err, fkMissing))
	}
	*a = c
	return nil
}

// HasEvent reports whether an event of the kind is stored whose details have
// key set to value: a marker that something was recorded once.
func (db *DB) HasEvent(ctx context.Context, kind, key, value string) (bool, error) {
	var n int
	err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE kind = ?
		 AND CASE WHEN json_valid(details) THEN json_extract(details, '$.' || ?) END = ?`,
		kind, key, value).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: has event: %w", err)
	}
	return n > 0, nil
}
