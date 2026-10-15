package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// A Probe is the result of one probe of a proxy from outside, as a client would
// connect: from the panel (Vantage "panel") or from the node itself ("node"),
// of a kind such as "l2" (an MTProto handshake through the proxy) or "web". The
// services name the vantages and kinds; the store keeps them as they are.
// Probes are kept for 7 days.
type Probe struct {
	ProxyID   string
	TS        time.Time // stored to the second
	Vantage   string
	Kind      string
	OK        bool
	LatencyMS uint32
	Error     string // why it failed, "" when it did not
}

// InsertProbe stores a probe. One of the same proxy, vantage, kind and second
// that is there already is no error, and stays as it is: a result that is
// delivered again is the same one. A proxy that does not exist is
// [ErrNotFound].
func (db *DB) InsertProbe(ctx context.Context, p Probe) error {
	if err := insertProbe(ctx, db.sql, p); err != nil {
		return fmt.Errorf("store: insert probe: %w", err)
	}
	return nil
}

func insertProbe(ctx context.Context, q dbtx, p Probe) error {
	_, err := q.ExecContext(ctx,
		`INSERT INTO probes (proxy_id, ts, vantage, kind, ok, latency_ms, error) VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (proxy_id, vantage, kind, ts) DO NOTHING`,
		p.ProxyID, p.TS.Unix(), p.Vantage, p.Kind, boolInt(p.OK), int64(p.LatencyMS), p.Error)
	return mapErr(err, fkMissing)
}

const probeCols = `proxy_id, ts, vantage, kind, ok, latency_ms, error`

func scanProbes(rows *sql.Rows) ([]Probe, error) {
	var out []Probe
	for rows.Next() {
		var p Probe
		var ts, ok, lat int64
		if err := rows.Scan(&p.ProxyID, &ts, &p.Vantage, &p.Kind, &ok, &lat, &p.Error); err != nil {
			return nil, err
		}
		p.TS, p.OK, p.LatencyMS = timeFromDB(ts), ok != 0, uint32Of(lat)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Probes returns the probes of a proxy from the vantage ("" for every vantage)
// made in [from, to), oldest first.
func (db *DB) Probes(ctx context.Context, proxyID, vantage string, from, to time.Time) ([]Probe, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+probeCols+` FROM probes WHERE proxy_id = ? AND (? = '' OR vantage = ?) AND ts >= ? AND ts < ?
		 ORDER BY ts, vantage, kind`, proxyID, vantage, vantage, from.Unix(), to.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: probes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out, err := scanProbes(rows)
	if err != nil {
		return nil, fmt.Errorf("store: probes: %w", err)
	}
	return out, nil
}

// LastProbes returns the newest n probes of every proxy that has any, from the
// vantage ("" for every vantage), by proxy id, each newest first. Only the
// probes of the 7 days that PruneStats keeps are read, by the clock of the
// store, so that the window does not grow with a prune that is late.
func (db *DB) LastProbes(ctx context.Context, vantage string, n int) (map[string][]Probe, error) {
	out := map[string][]Probe{}
	if n <= 0 {
		return out, nil
	}
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+probeCols+` FROM (
		   SELECT `+probeCols+`, ROW_NUMBER() OVER (PARTITION BY proxy_id ORDER BY ts DESC, vantage, kind) AS place
		   FROM probes WHERE (? = '' OR vantage = ?) AND ts >= ?)
		 WHERE place <= ? ORDER BY proxy_id, place`, vantage, vantage, db.now().Add(-keepProbes).Unix(), n)
	if err != nil {
		return nil, fmt.Errorf("store: last probes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	ps, err := scanProbes(rows)
	if err != nil {
		return nil, fmt.Errorf("store: last probes: %w", err)
	}
	for _, p := range ps {
		out[p.ProxyID] = append(out[p.ProxyID], p)
	}
	return out, nil
}
