package store

import (
	"context"
	"fmt"
	"time"
)

// A MemberStat is the health of a member of an egress chain of a node in one
// minute, as the edge saw it last in the minute: its status ("up", "down" or
// "unknown"; anything else counts as unknown), its latency when it was up, and
// the address that it leaves from (ExitIP), "" when it is not known.
//
// Minutes are kept as long as the minutes of proxies (egress_health_1m), and
// make hours (egress_health), which are kept for 30 days: how many minutes
// of the hour the member was up, down and unknown, the average and the highest
// latency of the minutes that it was up and had one, and the last exit address
// of the hour that is known.
type MemberStat struct {
	ChainID   string
	MemberKey string
	Status    string
	LatencyMS uint32
	ExitIP    string
}

// upsertMemberMinute stores the minute of a member of a chain of a node,
// replacing what is there.
func upsertMemberMinute(ctx context.Context, q dbtx, nodeID string, minute int64, m MemberStat) error {
	_, err := q.ExecContext(ctx,
		`INSERT INTO egress_health_1m (node_id, chain_id, member_key, ts, status, latency_ms, exit_ip)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (node_id, chain_id, member_key, ts) DO UPDATE SET
		   status = excluded.status, latency_ms = excluded.latency_ms, exit_ip = excluded.exit_ip`,
		nodeID, m.ChainID, m.MemberKey, minute, m.Status, int64(m.LatencyMS), m.ExitIP)
	return mapErr(err, fkMissing)
}

// rollupMemberHours makes the hours of the members of chains of their minutes,
// with the parameters of the other rollups: the minutes of [?3, ?1), and whole
// hours from ?2 on (see rollupWindow). The WHERE before ON CONFLICT is SQLite's
// way to tell the upsert from a join.
const rollupMemberHours = `
INSERT INTO egress_health (node_id, chain_id, member_key, ts,
  minutes_up, minutes_down, minutes_unknown, latency_avg_ms, latency_max_ms, exit_ip)
SELECT g.node_id, g.chain_id, g.member_key, g.hour, g.up, g.down, g.unknown, g.latency_avg, g.latency_max,
       COALESCE((SELECT e.exit_ip FROM egress_health_1m e
                 WHERE e.node_id = g.node_id AND e.chain_id = g.chain_id AND e.member_key = g.member_key
                   AND e.ts >= g.hour AND e.ts < g.hour + 3600 AND e.exit_ip <> ''
                 ORDER BY e.ts DESC LIMIT 1), '')
FROM (
  SELECT node_id, chain_id, member_key, ts / 3600 * 3600 AS hour,
         SUM(status = 'up') AS up, SUM(status = 'down') AS down, SUM(status NOT IN ('up', 'down')) AS unknown,
         COALESCE(CAST(ROUND(AVG(CASE WHEN status = 'up' AND latency_ms > 0 THEN latency_ms END)) AS INTEGER), 0) AS latency_avg,
         COALESCE(MAX(CASE WHEN status = 'up' AND latency_ms > 0 THEN latency_ms END), 0) AS latency_max
  FROM egress_health_1m
  WHERE ts >= ?3 AND ts < ?1
  GROUP BY node_id, chain_id, member_key, ts / 3600
) g
WHERE true
ON CONFLICT (node_id, chain_id, member_key, ts) DO UPDATE SET
  minutes_up = excluded.minutes_up, minutes_down = excluded.minutes_down, minutes_unknown = excluded.minutes_unknown,
  latency_avg_ms = excluded.latency_avg_ms, latency_max_ms = excluded.latency_max_ms, exit_ip = excluded.exit_ip
WHERE egress_health.ts >= ?2`

// A MemberHour is the health of a member of an egress chain in one hour (UTC):
// the minutes it was up, down and unknown, its latency (average and highest of
// the minutes that it was up and had one), and the last exit address of the
// hour that is known.
type MemberHour struct {
	ChainID, MemberKey         string
	TS                         time.Time // the start of the hour
	Up, Down, Unknown          uint32    // minutes
	LatencyAvgMS, LatencyMaxMS uint32
	ExitIP                     string
}

// EgressHistory returns the hours of the members of the chains of a node that
// start in [from, to), oldest first, then by chain and member. Hours are kept
// for 30 days.
func (db *DB) EgressHistory(ctx context.Context, nodeID string, from, to time.Time) ([]MemberHour, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT chain_id, member_key, ts, minutes_up, minutes_down, minutes_unknown, latency_avg_ms, latency_max_ms, exit_ip
		 FROM egress_health WHERE node_id = ? AND ts >= ? AND ts < ? ORDER BY ts, chain_id, member_key`,
		nodeID, from.Unix(), to.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: egress history: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []MemberHour
	for rows.Next() {
		var h MemberHour
		var ts, up, down, unknown, avg, maxMS int64
		if err := rows.Scan(&h.ChainID, &h.MemberKey, &ts, &up, &down, &unknown, &avg, &maxMS, &h.ExitIP); err != nil {
			return nil, fmt.Errorf("store: egress history: %w", err)
		}
		h.TS = timeFromDB(ts)
		h.Up, h.Down, h.Unknown = uint32Of(up), uint32Of(down), uint32Of(unknown)
		h.LatencyAvgMS, h.LatencyMaxMS = uint32Of(avg), uint32Of(maxMS)
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: egress history: %w", err)
	}
	return out, nil
}
