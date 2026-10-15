package store

import (
	"context"
	"fmt"
	"time"

	"github.com/urbnywrt/postern/internal/ids"
)

// The values of Listener.Kind.
const (
	ListenerKindTLS          = "tls"           // a public port that takes TLS and routes by SNI
	ListenerKindHTTPUpstream = "http-upstream" // an internal port for a WEB proxy behind someone else's web server
)

// The values of Listener.StrangerAction: what a connection with an SNI that is
// not known gets.
const (
	StrangerMask   = "mask"   // it is passed to the mask target
	StrangerReject = "reject" // it gets a TLS alert, unrecognized_name
	StrangerDrop   = "drop"   // it is closed after a random delay
)

// The values of Listener.NonTLSAction: what a connection that is not TLS gets.
const (
	NonTLSDrop    = "drop"
	NonTLSHTTP400 = "http400" // an answer like that of nginx to plain HTTP on an HTTPS port
)

// A Listener is a port that a node accepts connections on. Proxies live on
// listeners.
type Listener struct {
	ID               string
	NodeID           string // fixed when the listener is created
	Kind             string // ListenerKindTLS by default
	BindIP           string
	Port             uint32
	LinkHostOverride string
	StrangerAction   string // StrangerMask by default
	MaskTarget       string
	NonTLSAction     string   // NonTLSDrop by default
	TrustedCIDRs     []string // http-upstream only
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

const listenerColumns = `id, node_id, kind, bind_ip, port, link_host_override,
	stranger_action, mask_target, non_tls_action, trusted_cidrs, created_at, updated_at`

func scanListener(s scanner) (*Listener, error) {
	var (
		l                Listener
		port             int64
		cidrs            string
		created, updated int64
	)
	if err := s.Scan(&l.ID, &l.NodeID, &l.Kind, &l.BindIP, &port, &l.LinkHostOverride,
		&l.StrangerAction, &l.MaskTarget, &l.NonTLSAction, &cidrs, &created, &updated); err != nil {
		return nil, err
	}
	l.Port = uint32Of(port)
	var err error
	if l.TrustedCIDRs, err = decodeStrings(cidrs); err != nil {
		return nil, fmt.Errorf("decode trusted_cidrs: %w", err)
	}
	l.CreatedAt, l.UpdatedAt = timeFromDB(created), timeFromDB(updated)
	return &l, nil
}

// CreateListener stores l. It gives l an ID if it has none, a creation time if
// it has none, ListenerKindTLS, StrangerMask and NonTLSDrop for the kind and
// the two actions if they are empty, and the creation time as the time of the
// last update if that is not set. A node that does not exist is [ErrNotFound].
func (db *DB) CreateListener(ctx context.Context, l *Listener) error {
	return insertListener(ctx, db.sql, db.now(), l)
}

// insertListener is [DB.CreateListener] on q, with now as the time of the clock.
func insertListener(ctx context.Context, q dbtx, now time.Time, l *Listener) error {
	c := *l
	if c.ID == "" {
		c.ID = ids.New()
	}
	if c.Kind == "" {
		c.Kind = ListenerKindTLS
	}
	if c.StrangerAction == "" {
		c.StrangerAction = StrangerMask
	}
	if c.NonTLSAction == "" {
		c.NonTLSAction = NonTLSDrop
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.CreatedAt = normTime(c.CreatedAt)
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = c.CreatedAt
	}
	c.UpdatedAt = normTime(c.UpdatedAt)
	cidrs, err := encodeStrings(c.TrustedCIDRs)
	if err != nil {
		return fmt.Errorf("store: create listener: encode trusted_cidrs: %w", err)
	}

	_, err = q.ExecContext(ctx,
		`INSERT INTO listeners (`+listenerColumns+`) VALUES (`+placeholders(12)+`)`,
		c.ID, c.NodeID, c.Kind, c.BindIP, int64(c.Port), c.LinkHostOverride,
		c.StrangerAction, c.MaskTarget, c.NonTLSAction, cidrs, c.CreatedAt.Unix(), c.UpdatedAt.Unix())
	if err != nil {
		return fmt.Errorf("store: create listener: %w", mapErr(err, fkMissing))
	}
	*l = c
	return nil
}

// ListenerByID returns the listener with this id, or [ErrNotFound].
func (db *DB) ListenerByID(ctx context.Context, id string) (*Listener, error) {
	l, err := scanListener(db.sql.QueryRowContext(ctx, `SELECT `+listenerColumns+` FROM listeners WHERE id = ?`, id))
	if err != nil {
		return nil, fmt.Errorf("store: listener by id: %w", queryNotFound(err, "listener"))
	}
	return l, nil
}

// ListListeners returns the listeners of a node, in the order they were
// created, or those of every node when nodeID is empty.
func (db *DB) ListListeners(ctx context.Context, nodeID string) ([]*Listener, error) {
	query := `SELECT ` + listenerColumns + ` FROM listeners`
	var args []any
	if nodeID != "" {
		query += ` WHERE node_id = ?`
		args = append(args, nodeID)
	}
	query += ` ORDER BY created_at, id`
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list listeners: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Listener
	for rows.Next() {
		l, err := scanListener(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list listeners: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list listeners: %w", err)
	}
	return out, nil
}

// UpdateListener writes every field of l except the id, the node and the
// creation time, and sets the time of the last update. The listener is found by
// its id and its node together: a listener of another node, whatever its id, is
// [ErrNotFound], and nothing is changed.
func (db *DB) UpdateListener(ctx context.Context, l *Listener) error {
	cidrs, err := encodeStrings(l.TrustedCIDRs)
	if err != nil {
		return fmt.Errorf("store: update listener: encode trusted_cidrs: %w", err)
	}
	updated := normTime(db.now())
	res, err := db.sql.ExecContext(ctx,
		`UPDATE listeners SET kind = ?, bind_ip = ?, port = ?, link_host_override = ?,
		 stranger_action = ?, mask_target = ?, non_tls_action = ?, trusted_cidrs = ?, updated_at = ?
		 WHERE id = ? AND node_id = ?`,
		l.Kind, l.BindIP, int64(l.Port), l.LinkHostOverride,
		l.StrangerAction, l.MaskTarget, l.NonTLSAction, cidrs, updated.Unix(),
		l.ID, l.NodeID)
	if err != nil {
		return fmt.Errorf("store: update listener: %w", mapErr(err, fkMissing))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: update listener: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: update listener: %w", notFound("listener"))
	}
	l.UpdatedAt = updated
	return nil
}

// DeleteListener deletes a listener. It is [ErrConflict] while a proxy uses it,
// and [ErrNotFound] when there is no such listener.
func (db *DB) DeleteListener(ctx context.Context, id string) error {
	res, err := db.sql.ExecContext(ctx, `DELETE FROM listeners WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete listener: %w", mapErr(err, fkInUse))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: delete listener: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: delete listener: %w", notFound("listener"))
	}
	return nil
}
