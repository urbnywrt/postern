package store

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

// maxSightingBytes is the most that the bytes of an address are stored as. They
// only grow, minute by minute, for as long as the address is seen; a limit far
// above any real total keeps a wrong reading from making them overflow, which
// would fail every batch that names the address.
const maxSightingBytes = 1 << 62

// This does not compile if a minute at the limit of a counter could make the
// bytes of an address overflow.
const _ = uint64(1<<63 - 1 - maxSightingBytes - maxCounter)

// A Sighting is where a client address was seen: on which proxy, from when to
// when, with how many bytes, and in which country (a code as in CountryStat, ""
// when it is not known). They are kept only under IPPolicyFull, for
// stats.ip_days after the address was seen last, and at most 100,000 of a
// proxy, those seen last.
//
// A sighting adds to the one of the same proxy and address: the first time is
// the earliest, the last the latest, the bytes are summed, and the country is
// replaced by one that is not empty. An address is stored in its usual form,
// an IPv4 address in IPv6 as IPv4; one that is not an address is not stored.
type Sighting struct {
	ProxyID   string
	IP        string
	Country   string
	FirstSeen time.Time
	LastSeen  time.Time
	Bytes     uint64
}

// markMinute leaves the marker that the sightings of a minute of a node are
// stored, and reports whether it is the first: the sightings add up, so they
// are stored once a minute. Markers are kept for 8 days (keepMarkers), as far
// back as IngestMinute takes a minute.
func markMinute(ctx context.Context, q dbtx, nodeID string, minute int64) (bool, error) {
	n, err := execCount(ctx, q, `INSERT INTO stats_batches (node_id, minute) VALUES (?, ?) ON CONFLICT DO NOTHING`, nodeID, minute)
	return n == 1, err
}

// addSighting adds a sighting to where its address was seen on its proxy. A
// proxy that does not exist is [ErrNotFound].
func addSighting(ctx context.Context, q dbtx, s Sighting) error {
	addr, err := netip.ParseAddr(s.IP)
	if err != nil {
		return nil // not an address
	}
	_, err = q.ExecContext(ctx,
		`INSERT INTO ip_sightings (proxy_id, ip, first_seen, last_seen, bytes, country) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
		 ON CONFLICT (proxy_id, ip) DO UPDATE SET
		   first_seen = MIN(first_seen, excluded.first_seen),
		   last_seen = MAX(last_seen, excluded.last_seen),
		   bytes = MIN(bytes + excluded.bytes, ?7),
		   country = IIF(excluded.country = '', country, excluded.country)`,
		s.ProxyID, addr.WithZone("").Unmap().String(), s.FirstSeen.Unix(), s.LastSeen.Unix(),
		clampCounter(s.Bytes), countryCode(s.Country), int64(maxSightingBytes))
	return mapErr(err, fkMissing)
}

// capSightings deletes the sightings of a proxy beyond the ?1 that were seen
// last; of two seen last at the same second, the one with the greater address
// is kept.
const capSightings = `
DELETE FROM ip_sightings WHERE (proxy_id, ip) IN (
  SELECT proxy_id, ip FROM (
    SELECT proxy_id, ip, ROW_NUMBER() OVER (PARTITION BY proxy_id ORDER BY last_seen DESC, ip DESC) AS place
    FROM ip_sightings
    WHERE proxy_id IN (SELECT proxy_id FROM ip_sightings GROUP BY proxy_id HAVING count(*) > ?1)
  ) WHERE place > ?1
)`

// ListSightings returns the sightings of a proxy ("" for every proxy), only
// those of a country when country is not empty, the ones seen last first, from offset on, at most limit of
// them (all when limit is not positive), and how many there are in all that
// match.
//
// It does not look at the IP policy: the store keeps no sighting under another
// policy than full (ApplyStatsSettings deletes them, IngestMinute and
// PruneStats keep none), and a caller that serves them must refuse to while
// the policy is not full, as MetricsService.ListIpSightings does, rather than
// rely on the table being empty.
func (db *DB) ListSightings(ctx context.Context, proxyID, country string, limit, offset int) ([]Sighting, int, error) {
	const where = `WHERE (?1 = '' OR proxy_id = ?1) AND (?2 = '' OR country = ?2)`
	var total int
	if err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM ip_sightings `+where, proxyID, country).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: list sightings: %w", err)
	}
	if limit <= 0 {
		limit = -1
	}
	rows, err := db.sql.QueryContext(ctx,
		`SELECT proxy_id, ip, country, first_seen, last_seen, bytes FROM ip_sightings `+where+`
		 ORDER BY last_seen DESC, proxy_id, ip LIMIT ?3 OFFSET ?4`, proxyID, country, limit, max(offset, 0))
	if err != nil {
		return nil, 0, fmt.Errorf("store: list sightings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Sighting
	for rows.Next() {
		var s Sighting
		var first, last, bytes int64
		if err := rows.Scan(&s.ProxyID, &s.IP, &s.Country, &first, &last, &bytes); err != nil {
			return nil, 0, fmt.Errorf("store: list sightings: %w", err)
		}
		s.FirstSeen, s.LastSeen, s.Bytes = timeFromDB(first), timeFromDB(last), uint64Of(bytes)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: list sightings: %w", err)
	}
	return out, total, nil
}
