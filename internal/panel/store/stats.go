package store

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// Statistics are kept in three resolutions, in the tables stats_proxy_*,
// stats_node_* and stats_country_* with the suffixes 1m, 1h and 1d, and the
// health of the members of egress chains as minutes (egress_health_1m) and
// hours (egress_health). A row is the minute, hour or day (UTC) that starts at
// its ts. Nodes report minutes (IngestMinute). RollupStats makes hours of
// minutes and days of hours, and PruneStats deletes what is old. How long the
// minutes, the hours and where the addresses were seen are kept is the
// Retention that both are given, from the settings (StatsSettings); the other
// tables are kept for times of their own.
// What PruneStats keeps for a time or a number of its own, whatever the
// retention.
const (
	keepMarkers          = 8 * 24 * time.Hour  // stats_batches: as far back as IngestMinute takes a minute
	keepCountryHours     = 30 * 24 * time.Hour // stats_country_1h
	keepMemberHours      = 30 * 24 * time.Hour // egress_health
	keepProbes           = 7 * 24 * time.Hour  // probes
	keepRuns             = 30 * 24 * time.Hour // diagnostic_runs, and their results with them
	maxRunsPerNode       = 100                 // the newest runs of a node
	maxSightingsPerProxy = 100_000             // the addresses of a proxy that were seen last
)

// How much of the minutes, and of the hours, one transaction of RollupStats or
// PruneStats works on at most. A transaction holds the write lock of the
// database, which every writer waits for, the ingest of the nodes too, for at
// most its busy timeout of 5 seconds: the work of a round is cut into steps
// that stay far below that, whatever the retention. Tests make them smaller.
var (
	minutesPerTx = 6 * time.Hour
	hoursPerTx   = 24 * time.Hour
)

// The tables of minutes and of hours that are rolled up and pruned in steps.
// Each has an index on ts.
var (
	minuteTables = []string{"stats_proxy_1m", "stats_node_1m", "stats_country_1m", "egress_health_1m"}
	hourTables   = []string{"stats_proxy_1h", "stats_node_1h"}
)

// ErrMinuteTooOld is what IngestMinute returns for a minute that is older than
// it takes, 8 days, of which it stores nothing. It is final: the caller counts
// the minute as dropped and takes it as delivered, and does not try again,
// which would only drop it again.
var ErrMinuteTooOld = errors.New("store: the minute is older than the 8 days that are taken")

// A ProxyStat is the traffic of a proxy in one minute, hour or day.
type ProxyStat struct {
	ProxyID   string
	TS        time.Time // the start of the period
	Up        uint64    // bytes from clients to Telegram
	Down      uint64    // bytes from Telegram to clients
	ConnsNew  uint32    // connections opened
	ConnsPeak uint32    // the most connections open at once
	Devices   uint32    // unique client IPs; over a longer period, the highest of its minutes
}

// A NodeStat is the load of a node in one minute, hour or day. Over longer
// periods CPU, memory in use, load and disk in use are averages, the totals and
// the connections are the highest of the minutes, and the traffic and the
// refusals are the sum.
type NodeStat struct {
	NodeID    string
	TS        time.Time // the start of the period
	CPU       float64   // percent
	MemUsed   uint64    // bytes
	MemTotal  uint64
	Load1     float64
	DiskUsed  uint64
	DiskTotal uint64
	NetRx     uint64 // bytes received in the period
	NetTx     uint64 // bytes sent in the period
	Conns     uint32
	// The connections of the public listeners that the edge closed in the
	// period: as they were accepted, because the connections that had not sent
	// their whole ClientHello yet were at a cap (RefusedPreHello) or because
	// the edge held as many connections as it may (RefusedTotal); and before
	// their ClientHello, to make room for a new one (EvictedPreHello).
	RefusedPreHello uint64
	RefusedTotal    uint64
	EvictedPreHello uint64
}

// floorTo rounds the Unix time sec down to a multiple of step.
func floorTo(sec, step int64) int64 {
	r := sec % step
	if r < 0 {
		r += step
	}
	return sec - r
}

// ceilTo rounds the Unix time sec up to a multiple of step.
func ceilTo(sec, step int64) int64 {
	f := floorTo(sec, step)
	if f == sec {
		return sec
	}
	return f + step
}

// UpsertProxyMinute stores the traffic of a proxy in the minute that s.TS is in.
// Stored again for the same minute it replaces what is there, rather than adding
// to it, so that a batch that is delivered twice is not counted twice. A proxy
// that does not exist is [ErrNotFound], which a caller that ingests the reports
// of a node can skip: the proxy may have been deleted while the node went on
// reporting it.
//
// A byte count above 2^50, about a petabyte, which no node comes near, is stored
// as 2^50: a wrong reading must not be able to make the sums of the rollups
// overflow, which would stop every rollup and prune.
func (db *DB) UpsertProxyMinute(ctx context.Context, s ProxyStat) error {
	if err := upsertProxyMinute(ctx, db.sql, s); err != nil {
		return fmt.Errorf("store: upsert proxy stats: %w", err)
	}
	return nil
}

// UpsertNodeMinute is UpsertProxyMinute for the load of a node. Of the sizes, the
// traffic and the refusals, the same limit of 2^50 holds, and a CPU or load
// reading that is not a number is stored as 0.
func (db *DB) UpsertNodeMinute(ctx context.Context, s NodeStat) error {
	if err := upsertNodeMinute(ctx, db.sql, s); err != nil {
		return fmt.Errorf("store: upsert node stats: %w", err)
	}
	return nil
}

// UpsertMinutes stores what a node reports of one minute, the traffic of its
// proxies and its own load (node, which may be nil), as UpsertProxyMinute and
// UpsertNodeMinute would one row at a time, but in one transaction: the
// database syncs every commit to the disk, and a batch is one commit instead
// of one for every row. A proxy that does not exist is skipped and named in
// gone, and so is the minute of a node that does not exist: they may have been
// deleted while the node went on reporting them. Any other error stores
// nothing of the batch. [DB.IngestMinute] stores the rest of a minute as well.
func (db *DB) UpsertMinutes(ctx context.Context, proxies []ProxyStat, node *NodeStat) (gone []string, err error) {
	err = db.withTx(ctx, func(tx *sql.Tx) error {
		gone = nil
		for _, s := range proxies {
			// A row that the foreign key refuses aborts only its statement,
			// and the transaction goes on.
			switch err := upsertProxyMinute(ctx, tx, s); {
			case errors.Is(err, ErrNotFound):
				gone = append(gone, s.ProxyID)
			case err != nil:
				return err
			}
		}
		if node == nil {
			return nil
		}
		if err := upsertNodeMinute(ctx, tx, *node); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: upsert minutes: %w", err)
	}
	return gone, nil
}

func upsertProxyMinute(ctx context.Context, q dbtx, s ProxyStat) error {
	_, err := q.ExecContext(ctx,
		`INSERT INTO stats_proxy_1m (proxy_id, ts, up, down, conns_new, conns_peak, devices)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (proxy_id, ts) DO UPDATE SET
		   up = excluded.up, down = excluded.down, conns_new = excluded.conns_new,
		   conns_peak = excluded.conns_peak, devices = excluded.devices`,
		s.ProxyID, floorTo(s.TS.Unix(), 60), clampCounter(s.Up), clampCounter(s.Down),
		int64(s.ConnsNew), int64(s.ConnsPeak), int64(s.Devices))
	return mapErr(err, fkMissing)
}

func upsertNodeMinute(ctx context.Context, q dbtx, s NodeStat) error {
	_, err := q.ExecContext(ctx,
		`INSERT INTO stats_node_1m (node_id, ts, cpu, mem_used, mem_total, load1, disk_used, disk_total, net_rx, net_tx, conns,
		   refused_prehello, refused_total, evicted_prehello)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (node_id, ts) DO UPDATE SET
		   cpu = excluded.cpu, mem_used = excluded.mem_used, mem_total = excluded.mem_total, load1 = excluded.load1,
		   disk_used = excluded.disk_used, disk_total = excluded.disk_total,
		   net_rx = excluded.net_rx, net_tx = excluded.net_tx, conns = excluded.conns,
		   refused_prehello = excluded.refused_prehello, refused_total = excluded.refused_total,
		   evicted_prehello = excluded.evicted_prehello`,
		s.NodeID, floorTo(s.TS.Unix(), 60), finite(s.CPU), clampCounter(s.MemUsed), clampCounter(s.MemTotal), finite(s.Load1),
		clampCounter(s.DiskUsed), clampCounter(s.DiskTotal), clampCounter(s.NetRx), clampCounter(s.NetTx), int64(s.Conns),
		clampCounter(s.RefusedPreHello), clampCounter(s.RefusedTotal), clampCounter(s.EvictedPreHello))
	return mapErr(err, fkMissing)
}

// pickResolution is the suffix of the statistics tables that a range of time is
// read from, by the retention r: minutes while the span fits the minutes that
// are kept, hours while it fits the hours, days beyond.
func pickResolution(span time.Duration, r Retention) string {
	switch {
	case span <= r.Minutes:
		return "1m"
	case span <= r.Hours:
		return "1h"
	default:
		return "1d"
	}
}

// SeriesStep is the length of a period of a series over span, by the retention
// r: a minute while the span fits the minutes that r keeps, an hour while it
// fits the hours, a day beyond. It is the resolution that ProxySeries,
// NodeSeries and NodeTraffic read.
func SeriesStep(span time.Duration, r Retention) time.Duration {
	switch pickResolution(span, r) {
	case "1m":
		return time.Minute
	case "1h":
		return time.Hour
	default:
		return 24 * time.Hour
	}
}

// proxySource is what the statistics of proxies of a resolution are read from,
// in a query whose ?1 and ?2 are the Unix times that bound the periods wanted.
// The days of a proxy are rolled up when their hours are, but after a panel
// outage of more than the 9 days that ingest and rollups wait, an hour can
// still have no day: the source adds the sums of such hours as a day. The
// day that is not over yet (today) has no day row either, so it is made of
// its hours too, and stops at the last hour that RollupStats has made: the
// minutes since then are not in it. hours is a condition on the hour rows
// (alias h) that the caller narrows them by, the same as its own WHERE, so
// that the hours of the other proxies are not summed for nothing; "true" for
// none.
//
// The conditions of the callers: the proxies of the node ?3, and those of the
// node ?3 or of every node when it is empty.
const (
	proxiesOfNode      = `h.proxy_id IN (SELECT id FROM proxies WHERE node_id = ?3)`
	proxiesOfNodeOrAll = `?3 = '' OR h.proxy_id IN (SELECT id FROM proxies WHERE node_id = ?3)`
)

func proxySource(res, hours string) string {
	if res != "1d" {
		return "stats_proxy_" + res
	}
	return `(SELECT proxy_id, ts, up, down, conns_new, conns_peak, devices FROM stats_proxy_1d
	 UNION ALL
	 SELECT h.proxy_id, h.ts / 86400 * 86400, SUM(h.up), SUM(h.down), SUM(h.conns_new), MAX(h.conns_peak), MAX(h.devices)
	 FROM stats_proxy_1h h
	 WHERE h.ts >= ?1 AND h.ts < ?2 + 86400 AND (` + hours + `)
	   AND NOT EXISTS (SELECT 1 FROM stats_proxy_1d d WHERE d.proxy_id = h.proxy_id AND d.ts = h.ts / 86400 * 86400)
	 GROUP BY h.proxy_id, h.ts / 86400)`
}

// nodeSource is proxySource for the load of nodes, summed and averaged as the
// rollup of days does, with the hour rows narrowed to the node ?3.
func nodeSource(res string) string {
	if res != "1d" {
		return "stats_node_" + res
	}
	return `(SELECT node_id, ts, cpu, mem_used, mem_total, load1, disk_used, disk_total, net_rx, net_tx, conns,
	   refused_prehello, refused_total, evicted_prehello FROM stats_node_1d
	 UNION ALL
	 SELECT h.node_id, h.ts / 86400 * 86400, AVG(h.cpu), CAST(ROUND(AVG(h.mem_used)) AS INTEGER), MAX(h.mem_total), AVG(h.load1),
	   CAST(ROUND(AVG(h.disk_used)) AS INTEGER), MAX(h.disk_total), SUM(h.net_rx), SUM(h.net_tx), MAX(h.conns),
	   SUM(h.refused_prehello), SUM(h.refused_total), SUM(h.evicted_prehello)
	 FROM stats_node_1h h
	 WHERE h.ts >= ?1 AND h.ts < ?2 + 86400 AND h.node_id = ?3
	   AND NOT EXISTS (SELECT 1 FROM stats_node_1d d WHERE d.node_id = h.node_id AND d.ts = h.ts / 86400 * 86400)
	 GROUP BY h.node_id, h.ts / 86400)`
}

// ProxySeries returns the statistics of a proxy for the periods that start in
// [from, to), oldest first. How long a period is depends on how long the range
// is and on the retention r: minutes while the span fits the minutes that r
// keeps, hours while it fits the hours, days beyond. Periods without a row are
// left out.
func (db *DB) ProxySeries(ctx context.Context, proxyID string, from, to time.Time, r Retention) ([]ProxyStat, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT proxy_id, ts, up, down, conns_new, conns_peak, devices FROM `+proxySource(pickResolution(to.Sub(from), r), "h.proxy_id = ?3")+`
		 WHERE proxy_id = ?3 AND ts >= ?1 AND ts < ?2 ORDER BY ts`,
		from.Unix(), to.Unix(), proxyID)
	if err != nil {
		return nil, fmt.Errorf("store: proxy series: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ProxyStat
	for rows.Next() {
		var (
			s                                 ProxyStat
			ts, up, down, connsNew, connsPeak int64
			devices                           int64
		)
		if err := rows.Scan(&s.ProxyID, &ts, &up, &down, &connsNew, &connsPeak, &devices); err != nil {
			return nil, fmt.Errorf("store: proxy series: %w", err)
		}
		s.TS = timeFromDB(ts)
		s.Up, s.Down = uint64Of(up), uint64Of(down)
		s.ConnsNew, s.ConnsPeak, s.Devices = uint32Of(connsNew), uint32Of(connsPeak), uint32Of(devices)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: proxy series: %w", err)
	}
	return out, nil
}

// NodeSeries is ProxySeries for the load of a node.
func (db *DB) NodeSeries(ctx context.Context, nodeID string, from, to time.Time, r Retention) ([]NodeStat, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT node_id, ts, cpu, mem_used, mem_total, load1, disk_used, disk_total, net_rx, net_tx, conns,
		   refused_prehello, refused_total, evicted_prehello FROM `+nodeSource(pickResolution(to.Sub(from), r))+`
		 WHERE node_id = ?3 AND ts >= ?1 AND ts < ?2 ORDER BY ts`,
		from.Unix(), to.Unix(), nodeID)
	if err != nil {
		return nil, fmt.Errorf("store: node series: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []NodeStat
	for rows.Next() {
		var (
			s                                                  NodeStat
			ts, memUsed, memTotal, diskUsed, diskTotal, rx, tx int64
			conns, refusedPre, refusedTotal, evictedPre        int64
		)
		if err := rows.Scan(&s.NodeID, &ts, &s.CPU, &memUsed, &memTotal, &s.Load1, &diskUsed, &diskTotal, &rx, &tx, &conns,
			&refusedPre, &refusedTotal, &evictedPre); err != nil {
			return nil, fmt.Errorf("store: node series: %w", err)
		}
		s.TS = timeFromDB(ts)
		s.MemUsed, s.MemTotal = uint64Of(memUsed), uint64Of(memTotal)
		s.DiskUsed, s.DiskTotal = uint64Of(diskUsed), uint64Of(diskTotal)
		s.NetRx, s.NetTx = uint64Of(rx), uint64Of(tx)
		s.Conns = uint32Of(conns)
		s.RefusedPreHello, s.RefusedTotal, s.EvictedPreHello = uint64Of(refusedPre), uint64Of(refusedTotal), uint64Of(evictedPre)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: node series: %w", err)
	}
	return out, nil
}

// A MinuteBatch is what a node reports of one minute: the traffic of its
// proxies, its own load, the countries of the clients of its proxies, the
// health of the members of its egress chains, where client addresses were seen,
// and the results of its probes.
type MinuteBatch struct {
	NodeID string
	// Minute is the minute of the batch. The minutes of the proxies, the node,
	// the countries and the members are stored under the minute that it is in:
	// the TS of Proxies and of Node is not used, nor the NodeID of Node.
	// Sightings and probes have times of their own.
	Minute time.Time

	Proxies   []ProxyStat
	Node      *NodeStat // nil: the node did not report its load
	Countries []CountryStat
	Members   []MemberStat
	Sightings []Sighting
	Probes    []Probe
}

// IngestMinute stores a MinuteBatch in one transaction, so that a batch that is
// delivered twice, or a minute that the node emits again, is stored once:
//
//   - the minutes of the proxies, of the node, of the countries and of the
//     members are replaced by those of the batch: a minute that comes again,
//     with the same values or with others, replaces the first. The countries of
//     a proxy are replaced as a whole, after their codes are checked and they
//     are cut to 50 (see CountryStat);
//   - probes are stored once, the first time (see InsertProbe);
//   - where addresses were seen adds up (see Sighting), so it is stored only
//     the first time that the minute of the node comes: the batch leaves a
//     marker of the node and the minute, which is kept for 8 days;
//   - a minute older than that, by the clock of the store when the transaction
//     has the write lock, is not stored at all: its marker may be gone, and its
//     addresses would be counted a second time. IngestMinute returns
//     ErrMinuteTooOld for it, which the caller acknowledges, as it would a
//     stored minute, and counts as dropped: trying it again would only drop it
//     again.
//
// What the IP policy that is stored does not keep is left out, whatever the
// caller has filtered: where addresses were seen unless the policy is full, and
// the countries when it is off (a policy that cannot be read counts as off).
// The policy is read in the transaction, which a change of the policy waits
// for (ApplyStatsSettings), so that a batch that was made under full and comes
// after the change keeps no address.
//
// A proxy that does not exist is skipped and named in gone, once: it may have
// been deleted while the node went on reporting it. A node that does not exist
// makes the call do nothing. Counters keep the limit of 2^50 a minute of
// UpsertProxyMinute. Any other error stores nothing of the batch.
func (db *DB) IngestMinute(ctx context.Context, b MinuteBatch) (gone []string, err error) {
	minute := floorTo(b.Minute.Unix(), 60)
	var tooOld bool
	err = db.withTx(ctx, func(tx *sql.Tx) error {
		gone, tooOld = nil, false
		// Under the write lock: a prune that has moved the markers on while
		// this one waited for it is behind this clock reading.
		if minute < db.now().Add(-keepMarkers).Unix() {
			tooOld = true
			return nil
		}
		var one int
		switch err := tx.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE id = ?`, b.NodeID).Scan(&one); {
		case errors.Is(err, sql.ErrNoRows):
			return nil
		case err != nil:
			return err
		}
		sightings, countries := b.Sightings, b.Countries
		switch ipPolicy(ctx, tx) {
		case IPPolicyFull:
		case IPPolicyCountries:
			sightings = nil
		default:
			sightings, countries = nil, nil
		}

		ts := timeFromDB(minute)
		var g goneProxies
		for _, s := range b.Proxies {
			s.TS = ts
			if err := g.skip(s.ProxyID, upsertProxyMinute(ctx, tx, s)); err != nil {
				return err
			}
		}
		if b.Node != nil {
			n := *b.Node
			n.NodeID, n.TS = b.NodeID, ts
			if err := upsertNodeMinute(ctx, tx, n); err != nil {
				return err
			}
		}
		for _, c := range countriesByProxy(countries) {
			if err := g.skip(c.proxyID, replaceCountryMinutes(ctx, tx, c.proxyID, minute, c.rows)); err != nil {
				return err
			}
		}
		for _, m := range b.Members {
			if err := upsertMemberMinute(ctx, tx, b.NodeID, minute, m); err != nil {
				return err
			}
		}
		if len(sightings) > 0 {
			first, err := markMinute(ctx, tx, b.NodeID, minute)
			if err != nil {
				return err
			}
			if first {
				for _, s := range sightings {
					if err := g.skip(s.ProxyID, addSighting(ctx, tx, s)); err != nil {
						return err
					}
				}
			}
		}
		for _, p := range b.Probes {
			if err := g.skip(p.ProxyID, insertProbe(ctx, tx, p)); err != nil {
				return err
			}
		}
		gone = g.ids
		return nil
	})
	switch {
	case err != nil:
		return nil, fmt.Errorf("store: ingest minute: %w", err)
	case tooOld:
		return nil, ErrMinuteTooOld
	}
	return gone, nil
}

// goneProxies collects the proxies of a batch that are not there any more.
type goneProxies struct {
	ids  []string
	seen map[string]bool
}

// skip returns err, unless it says that the proxy is not there, which skip
// notes, once, and returns nil for. A row that the foreign key refuses aborts
// only its statement, and the transaction goes on.
func (g *goneProxies) skip(proxyID string, err error) error {
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	if !g.seen[proxyID] {
		if g.seen == nil {
			g.seen = map[string]bool{}
		}
		g.seen[proxyID] = true
		g.ids = append(g.ids, proxyID)
	}
	return nil
}

// The rollups. Each one takes the rows of the finer table from lo (?3) and
// before end (?1), both whole periods, groups them by period and writes a row
// per group to the coarser table; a period from whole (?2) on is whole (see
// rollupWindow). Traffic, new connections and refusals are summed. The peaks,
// and the devices, which cannot be added up, are the highest. The load of a
// node is averaged.
const (
	rollupProxyHours = `
INSERT INTO stats_proxy_1h (proxy_id, ts, up, down, conns_new, conns_peak, devices)
SELECT proxy_id, ts / 3600 * 3600, SUM(up), SUM(down), SUM(conns_new), MAX(conns_peak), MAX(devices)
FROM stats_proxy_1m
WHERE ts >= ?3 AND ts < ?1
GROUP BY proxy_id, ts / 3600
ON CONFLICT (proxy_id, ts) DO UPDATE SET
  up = excluded.up, down = excluded.down, conns_new = excluded.conns_new,
  conns_peak = excluded.conns_peak, devices = excluded.devices
WHERE stats_proxy_1h.ts >= ?2`

	rollupProxyDays = `
INSERT INTO stats_proxy_1d (proxy_id, ts, up, down, conns_new, conns_peak, devices)
SELECT proxy_id, ts / 86400 * 86400, SUM(up), SUM(down), SUM(conns_new), MAX(conns_peak), MAX(devices)
FROM stats_proxy_1h
WHERE ts >= ?3 AND ts < ?1
GROUP BY proxy_id, ts / 86400
ON CONFLICT (proxy_id, ts) DO UPDATE SET
  up = excluded.up, down = excluded.down, conns_new = excluded.conns_new,
  conns_peak = excluded.conns_peak, devices = excluded.devices
WHERE stats_proxy_1d.ts >= ?2`

	rollupNodeHours = `
INSERT INTO stats_node_1h (node_id, ts, cpu, mem_used, mem_total, load1, disk_used, disk_total, net_rx, net_tx, conns,
  refused_prehello, refused_total, evicted_prehello)
SELECT node_id, ts / 3600 * 3600, AVG(cpu), CAST(ROUND(AVG(mem_used)) AS INTEGER), MAX(mem_total), AVG(load1),
       CAST(ROUND(AVG(disk_used)) AS INTEGER), MAX(disk_total), SUM(net_rx), SUM(net_tx), MAX(conns),
       SUM(refused_prehello), SUM(refused_total), SUM(evicted_prehello)
FROM stats_node_1m
WHERE ts >= ?3 AND ts < ?1
GROUP BY node_id, ts / 3600
ON CONFLICT (node_id, ts) DO UPDATE SET
  cpu = excluded.cpu, mem_used = excluded.mem_used, mem_total = excluded.mem_total, load1 = excluded.load1,
  disk_used = excluded.disk_used, disk_total = excluded.disk_total,
  net_rx = excluded.net_rx, net_tx = excluded.net_tx, conns = excluded.conns,
  refused_prehello = excluded.refused_prehello, refused_total = excluded.refused_total,
  evicted_prehello = excluded.evicted_prehello
WHERE stats_node_1h.ts >= ?2`

	rollupNodeDays = `
INSERT INTO stats_node_1d (node_id, ts, cpu, mem_used, mem_total, load1, disk_used, disk_total, net_rx, net_tx, conns,
  refused_prehello, refused_total, evicted_prehello)
SELECT node_id, ts / 86400 * 86400, AVG(cpu), CAST(ROUND(AVG(mem_used)) AS INTEGER), MAX(mem_total), AVG(load1),
       CAST(ROUND(AVG(disk_used)) AS INTEGER), MAX(disk_total), SUM(net_rx), SUM(net_tx), MAX(conns),
       SUM(refused_prehello), SUM(refused_total), SUM(evicted_prehello)
FROM stats_node_1h
WHERE ts >= ?3 AND ts < ?1
GROUP BY node_id, ts / 86400
ON CONFLICT (node_id, ts) DO UPDATE SET
  cpu = excluded.cpu, mem_used = excluded.mem_used, mem_total = excluded.mem_total, load1 = excluded.load1,
  disk_used = excluded.disk_used, disk_total = excluded.disk_total,
  net_rx = excluded.net_rx, net_tx = excluded.net_tx, conns = excluded.conns,
  refused_prehello = excluded.refused_prehello, refused_total = excluded.refused_total,
  evicted_prehello = excluded.evicted_prehello
WHERE stats_node_1d.ts >= ?2`
)

// runRollups runs rollups on the rows of [lo, end), with whole as the start of
// the whole periods.
func runRollups(ctx context.Context, tx *sql.Tx, lo, end, whole int64, rollups ...[2]string) error {
	for _, s := range rollups {
		if _, err := tx.ExecContext(ctx, s[1], end, whole, lo); err != nil {
			return fmt.Errorf("%s: %w", s[0], err)
		}
	}
	return nil
}

// rollupHoursIn makes the hours in [lo, end) of their minutes: of proxies, nodes,
// countries and members.
func rollupHoursIn(ctx context.Context, tx *sql.Tx, lo, end, whole int64) error {
	return runRollups(ctx, tx, lo, end, whole,
		[2]string{"proxy hours", rollupProxyHours},
		[2]string{"node hours", rollupNodeHours},
		[2]string{"country hours", clearCountryHours},
		[2]string{"country hours", rollupCountryHours},
		[2]string{"member hours", rollupMemberHours})
}

// rollupDaysIn makes the days in [lo, end) of proxies and nodes of their hours.
func rollupDaysIn(ctx context.Context, tx *sql.Tx, lo, end, whole int64) error {
	return runRollups(ctx, tx, lo, end, whole,
		[2]string{"proxy days", rollupProxyDays},
		[2]string{"node days", rollupNodeDays})
}

// rollupCountryDaysIn makes the days in [lo, end) of countries of their hours.
func rollupCountryDaysIn(ctx context.Context, tx *sql.Tx, lo, end, whole int64) error {
	return runRollups(ctx, tx, lo, end, whole,
		[2]string{"country days", clearCountryDays},
		[2]string{"country days", rollupCountryDays})
}

// The Unix times that a rollup works with. Each rollup reads the finer rows
// before end. A period from whole on is whole: none of its finer rows has been
// pruned yet, so it is made again from them, and its new row replaces what is
// there. A period before whole has lost some of its finer rows to PruneStats,
// and a row made of the rest would be too small: it is left as it is, and only
// a period that has no row yet gets one, because nothing has been deleted that
// a rollup has not seen.
type rollupWindow struct {
	hoursEnd, hoursWhole             int64 // minutes into hours: proxies, nodes, countries, members
	daysEnd, daysWhole               int64 // hours into days: proxies and nodes
	countryDaysEnd, countryDaysWhole int64 // country hours into country days
}

// settingStatsPruned keeps how far PruneStats has deleted the minutes and the
// hours, as Unix times: every row before them may be gone. The retention alone
// does not tell it once it has changed: when minutes are kept longer than
// before, those that were deleted do not come back, and the hour that the last
// prune cut in two is still cut.
const settingStatsPruned = "stats_pruned" // {"minutes":1759840200,"hours":1752323400}

type prunedBefore struct {
	Minutes int64 `json:"minutes"` // stats_proxy_1m, stats_node_1m, stats_country_1m, egress_health_1m
	Hours   int64 `json:"hours"`   // stats_proxy_1h, stats_node_1h
}

func readPruned(ctx context.Context, q dbtx) (prunedBefore, error) {
	var p prunedBefore
	if _, err := getSetting(ctx, q, settingStatsPruned, &p); err != nil {
		return prunedBefore{}, err
	}
	return p, nil
}

// earliest returns the earliest ts from from on of the tables, and false when
// they have none. Each table has an index on ts, which makes it quick.
func earliest(ctx context.Context, q dbtx, tables []string, from int64) (int64, bool, error) {
	parts := make([]string, len(tables))
	for i, t := range tables {
		parts[i] = `SELECT MIN(ts) AS ts FROM ` + t + ` WHERE ts >= ?1`
	}
	var ts sql.NullInt64
	if err := q.QueryRowContext(ctx, `SELECT MIN(ts) FROM (`+strings.Join(parts, ` UNION ALL `)+`)`, from).Scan(&ts); err != nil {
		return 0, false, err
	}
	return ts.Int64, ts.Valid, nil
}

// windowAt is the window of a rollup at now. Hours of minutes and days of hours
// are whole from where PruneStats has deleted the finer rows. Before a prune
// has said so (a database that an older version pruned, by a retention that
// this one does not know), they are whole from the oldest of the finer rows
// that are left, and never from before where the retention cuts. Days of
// country hours are whole from 30 days back, as long as country hours are
// kept, so that a day is final before any of its hours is deleted.
func windowAt(ctx context.Context, q dbtx, now time.Time, r Retention) (rollupWindow, error) {
	pruned, err := readPruned(ctx, q)
	if err != nil {
		return rollupWindow{}, err
	}
	minutes, hours := pruned.Minutes, pruned.Hours
	for _, c := range []struct {
		cut    *int64
		tables []string
		kept   time.Duration
	}{
		{&minutes, minuteTables, r.Minutes},
		{&hours, hourTables, r.Hours},
	} {
		if *c.cut != 0 {
			continue
		}
		*c.cut = now.Add(-c.kept).Unix()
		oldest, ok, err := earliest(ctx, q, c.tables, math.MinInt64)
		if err != nil {
			return rollupWindow{}, err
		}
		if ok {
			*c.cut = max(*c.cut, oldest)
		}
	}
	return rollupWindow{
		hoursEnd:         floorTo(now.Unix(), 3600),
		hoursWhole:       ceilTo(minutes, 3600),
		daysEnd:          floorTo(now.Unix(), 86400),
		daysWhole:        ceilTo(hours, 86400),
		countryDaysEnd:   floorTo(now.Unix(), 86400),
		countryDaysWhole: ceilTo(now.Add(-keepCountryHours).Unix(), 86400),
	}, nil
}

// stepTx runs fn in a transaction of its own, one step of RollupStats or
// PruneStats, and returns how long it held the write lock. Then it leaves the
// lock free for db.steps.pause, or until ctx is done. SQLite does not queue the
// writers that wait for the lock: one of them only gets it when it tries
// between two transactions, which it does every 100 ms at most, so steps back
// to back would keep the ingest of the nodes waiting until its busy timeout.
// The pause follows the last step as well, which keeps two calls in a row
// apart.
func (db *DB) stepTx(ctx context.Context, fn func(tx *sql.Tx) error) (time.Duration, error) {
	took, err := db.timedTx(ctx, fn)
	if err != nil {
		return 0, err
	}
	return took, db.pause(ctx)
}

// timedTx runs fn in a transaction and returns how long it held the write lock.
func (db *DB) timedTx(ctx context.Context, fn func(tx *sql.Tx) error) (time.Duration, error) {
	var start time.Time
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		start = time.Now()
		return fn(tx)
	})
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// pause leaves the write lock free for db.steps.pause, or until ctx is done.
func (db *DB) pause(ctx context.Context) error {
	if db.steps.onPause != nil {
		db.steps.onPause()
	}
	if db.steps.pause <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(db.steps.pause)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// inTx calls the hook of the tests, if there is one, in a transaction of a step
// with what it works on.
func (db *DB) inTx(what string, from, to int64) {
	if db.steps.inTx != nil {
		db.steps.inTx(what, from, to)
	}
}

// A stepSize is how much of the minutes or of the hours a step of RollupStats
// or PruneStats takes, in seconds, in multiples of align. Rows are not as dense
// everywhere (a proxy may have 3 countries a minute, or 50), so it starts at
// least and follows how long the steps take: it doubles after a transaction
// that held the lock less than half of db.steps.slow, up to most, and halves
// after one that held it longer than db.steps.slow, down to least.
type stepSize struct {
	size, least, most, align int64
}

func newStepSize(most, least time.Duration, align int64) *stepSize {
	m := max(floorTo(int64(most/time.Second), align), align)
	l := min(max(floorTo(int64(least/time.Second), align), align), m)
	return &stepSize{size: l, least: l, most: m, align: align}
}

func (s *stepSize) adapt(took, slow time.Duration) {
	switch {
	case took > slow:
		s.size /= 2
	case took < slow/2:
		s.size *= 2
	}
	s.size = min(max(floorTo(s.size, s.align), s.least), s.most)
}

// RollupStats makes hourly statistics of minutes and daily statistics of hours,
// of every proxy, node, country and member of a chain, for the hours and days
// that are over at now, with the retention r that PruneStats is given. It can
// be called again and again: it makes the same rows from the same minutes, and
// it picks up a minute that arrives late as long as its hour is still whole
// (and its day). It reads all the minutes there are, so about once an hour is
// often enough.
//
// It holds the write lock a step at a time, and leaves it free after each step
// (see stepTx): the hours in windows of up to minutesPerTx (6 hours), each a
// transaction of its own that reads only its own minutes, a window halved,
// down to an hour, after one that took long (see stepSize); then the days, in
// one transaction that reads only the hours that can still change, those of
// the 8 days that ingest takes minutes of and a day more. An older day is not
// made again here: PruneStats rolls up the days whose hours it deletes.
func (db *DB) RollupStats(ctx context.Context, now time.Time, r Retention) error {
	if err := r.check(); err != nil {
		return err
	}
	end := floorTo(now.Unix(), 3600)
	window := newStepSize(minutesPerTx, time.Hour, 3600)
	for lo := int64(math.MinInt64); ; {
		next, ok, err := earliest(ctx, db.sql, minuteTables, lo)
		if err != nil {
			return fmt.Errorf("store: roll up stats: %w", err)
		}
		if lo = floorTo(next, 3600); !ok || lo >= end {
			break
		}
		hi := min(lo+window.size, end)
		took, err := db.stepTx(ctx, func(tx *sql.Tx) error {
			db.inTx("rollup hours", lo, hi)
			w, err := windowAt(ctx, tx, now, r)
			if err != nil {
				return err
			}
			return rollupHoursIn(ctx, tx, lo, hi, w.hoursWhole)
		})
		if err != nil {
			return fmt.Errorf("store: roll up stats: %w", err)
		}
		window.adapt(took, db.steps.slow)
		lo = hi
	}

	_, err := db.stepTx(ctx, func(tx *sql.Tx) error {
		w, err := windowAt(ctx, tx, now, r)
		if err != nil {
			return err
		}
		lo := floorTo(now.Add(-keepMarkers-time.Hour).Unix(), 86400)
		db.inTx("rollup days", lo, w.daysEnd)
		if err := rollupDaysIn(ctx, tx, lo, w.daysEnd, w.daysWhole); err != nil {
			return err
		}
		return rollupCountryDaysIn(ctx, tx, lo, w.countryDaysEnd, w.countryDaysWhole)
	})
	if err != nil {
		return fmt.Errorf("store: roll up stats: %w", err)
	}
	return nil
}

// capRuns deletes the runs of a node beyond its newest ?1.
const capRuns = `
DELETE FROM diagnostic_runs WHERE id IN (
  SELECT id FROM (
    SELECT id, ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY started_at DESC, id DESC) AS place
    FROM diagnostic_runs
  ) WHERE place > ?1
)`

// A pruneSeries is a kind of rows that PruneStats deletes in steps: the rows of
// tables (each with an index on ts) before cut, up to most of their time a step
// and down to least after steps that took long (see stepSize). A step rolls up
// first, when rollup is set, the coarser periods (period seconds long) that it
// cuts, and those before them, and records how far it has deleted, when record
// is set.
type pruneSeries struct {
	name        string
	tables      []string
	cut         int64
	most, least time.Duration
	period      int64
	rollup      func(ctx context.Context, tx *sql.Tx, w rollupWindow, lo, end int64) error
	record      func(p *prunedBefore, cut int64)
}

// pruneInSteps deletes the rows of s before s.cut, a step at a time, each step a
// transaction of its own: it rolls up what it is about to delete, deletes it,
// and records how far it went, so that a prune that stops between two steps
// leaves the statistics as whole as one that has finished. The step that
// leaves no row before s.cut records s.cut, and is the last.
func (db *DB) pruneInSteps(ctx context.Context, now time.Time, r Retention, s pruneSeries) error {
	step := newStepSize(s.most, s.least, 1)
	for done := false; !done; {
		took, err := db.stepTx(ctx, func(tx *sql.Tx) error {
			oldest, ok, err := earliest(ctx, tx, s.tables, math.MinInt64)
			if err != nil {
				return err
			}
			cut := s.cut
			if ok && oldest < s.cut {
				cut = min(oldest+step.size, s.cut)
				db.inTx("prune "+s.name, oldest, cut)
				if s.rollup != nil {
					w, err := windowAt(ctx, tx, now, r)
					if err != nil {
						return err
					}
					if err := s.rollup(ctx, tx, w, floorTo(oldest, s.period), ceilTo(cut, s.period)); err != nil {
						return err
					}
				}
				for _, table := range s.tables {
					if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE ts < ?`, cut); err != nil {
						return err
					}
				}
				next, more, err := earliest(ctx, tx, s.tables, cut)
				if err != nil {
					return err
				}
				if !more || next >= s.cut {
					cut = s.cut // nothing is left before it
				}
			} else {
				db.inTx("prune "+s.name, s.cut, s.cut)
			}
			done = cut >= s.cut
			if s.record == nil {
				return nil
			}
			pruned, err := readPruned(ctx, tx)
			if err != nil {
				return err
			}
			s.record(&pruned, cut)
			return putSetting(ctx, tx, settingStatsPruned, pruned)
		})
		if err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
		step.adapt(took, db.steps.slow)
	}
	return nil
}

// PruneStats deletes what is older than it is kept at now, counting from the
// start of a period, to the second:
//
//   - the minutes of proxies, nodes, countries and members of chains, after
//     r.Minutes;
//   - the markers of IngestMinute after 8 days;
//   - the hours of proxies and nodes after r.Hours, those of countries and
//     members after 30 days; days are kept for good;
//   - probes after 7 days;
//   - where an address was seen, when it was seen last more than r.IPs ago, and
//     beyond the 100,000 addresses of a proxy that were seen last; under a
//     policy other than full, every one;
//   - diagnostic runs, with their results, after 30 days and beyond the newest
//     100 of a node.
//
// What it is about to delete is rolled up first if that has not been done, so
// that no total is lost whether or not RollupStats ran before, also when r is
// shorter than the last time. It works in steps, each a transaction of its
// own, and leaves the write lock free after each (see stepTx): the minutes up
// to minutesPerTx (6 hours) of them a step, down to an hour after steps that
// took long (see stepSize), the hours a day of them a step, each step rolling
// up, deleting and recording how far it went; markers, probes, runs and
// addresses in a last step. A prune that stops in between, cancelled or
// failed, leaves what it has done whole, and the next one goes on from there.
//
// After it has deleted where addresses were seen, it empties the write-ahead
// log, see ApplyStatsSettings, and it does when an earlier attempt could not;
// that it cannot is an error, after the rows are deleted.
func (db *DB) PruneStats(ctx context.Context, now time.Time, r Retention) error {
	if err := r.check(); err != nil {
		return err
	}
	ago := func(d time.Duration) int64 { return now.Add(-d).Unix() }
	const day = 24 * time.Hour
	for _, s := range []pruneSeries{
		{
			name: "minutes", tables: minuteTables, cut: ago(r.Minutes),
			most: minutesPerTx, least: time.Hour, period: 3600,
			rollup: func(ctx context.Context, tx *sql.Tx, w rollupWindow, lo, end int64) error {
				return rollupHoursIn(ctx, tx, lo, min(end, w.hoursEnd), w.hoursWhole)
			},
			record: func(p *prunedBefore, cut int64) { p.Minutes = max(p.Minutes, cut) },
		},
		{
			name: "hours", tables: hourTables, cut: ago(r.Hours), most: hoursPerTx, least: day, period: 86400,
			rollup: func(ctx context.Context, tx *sql.Tx, w rollupWindow, lo, end int64) error {
				return rollupDaysIn(ctx, tx, lo, min(end, w.daysEnd), w.daysWhole)
			},
			record: func(p *prunedBefore, cut int64) { p.Hours = max(p.Hours, cut) },
		},
		{
			name: "country hours", tables: []string{"stats_country_1h"}, cut: ago(keepCountryHours),
			most: hoursPerTx, least: day, period: 86400,
			rollup: func(ctx context.Context, tx *sql.Tx, w rollupWindow, lo, end int64) error {
				return rollupCountryDaysIn(ctx, tx, lo, min(end, w.countryDaysEnd), w.countryDaysWhole)
			},
		},
		{
			name: "member hours", tables: []string{"egress_health"}, cut: ago(keepMemberHours),
			most: hoursPerTx, least: day, period: 86400,
		},
	} {
		if err := db.pruneInSteps(ctx, now, r, s); err != nil {
			return fmt.Errorf("store: prune stats: %w", err)
		}
	}

	var addresses int64 // of where addresses were seen
	_, err := db.timedTx(ctx, func(tx *sql.Tx) error {
		db.inTx("prune the rest", 0, 0)
		addresses = 0
		type deletion struct {
			query     string
			arg       int64
			addresses bool
		}
		deletes := []deletion{
			{`DELETE FROM stats_batches WHERE minute < ?`, ago(keepMarkers), false},
			{`DELETE FROM probes WHERE ts < ?`, ago(keepProbes), false},
			{`DELETE FROM diagnostic_runs WHERE started_at < ?`, ago(keepRuns), false},
			{capRuns, maxRunsPerNode, false},
		}
		if ipPolicy(ctx, tx) == IPPolicyFull {
			deletes = append(deletes,
				deletion{`DELETE FROM ip_sightings WHERE last_seen < ?`, ago(r.IPs), true},
				deletion{capSightings, maxSightingsPerProxy, true})
		} else {
			// No address is kept under another policy, however recently it was
			// seen: one that came in before the policy changed does not stay.
			deletes = append(deletes, deletion{`DELETE FROM ip_sightings WHERE last_seen < ?`, math.MaxInt64, true})
		}
		for _, d := range deletes {
			n, err := execCount(ctx, tx, d.query, d.arg)
			if err != nil {
				return err
			}
			if d.addresses {
				addresses += n
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: prune stats: %w", err)
	}
	// The log is emptied before the pause of the last step, which a cancel may
	// cut short.
	if err := db.scrubWAL(ctx, addresses > 0); err != nil {
		return fmt.Errorf("store: prune stats: the rows are deleted, but the write-ahead log, which may still hold "+
			"client addresses, was not emptied; the next prune tries again: %w", err)
	}
	if err := db.pause(ctx); err != nil {
		return fmt.Errorf("store: prune stats: %w", err)
	}
	return nil
}

// A NodeTraffic is the traffic of the proxies of a node in one period: Up and
// Down summed over its proxies, and DevicesSum the sum of their devices (the
// highest of each proxy's minutes in a period of hours or days), which the UI
// labels "Unique IPs, sum of proxies": an address that two proxies saw counts
// twice.
type NodeTraffic struct {
	TS         time.Time // the start of the period
	Up, Down   uint64
	DevicesSum uint32
}

// NodeTraffic returns the traffic of the proxies of a node for the periods that
// start in [from, to), oldest first, in the resolution that ProxySeries picks.
func (db *DB) NodeTraffic(ctx context.Context, nodeID string, from, to time.Time, r Retention) ([]NodeTraffic, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT s.ts, SUM(s.up), SUM(s.down), SUM(s.devices) FROM `+proxySource(pickResolution(to.Sub(from), r), proxiesOfNode)+` s
		 JOIN proxies p ON p.id = s.proxy_id
		 WHERE p.node_id = ?3 AND s.ts >= ?1 AND s.ts < ?2 GROUP BY s.ts ORDER BY s.ts`,
		from.Unix(), to.Unix(), nodeID)
	if err != nil {
		return nil, fmt.Errorf("store: node traffic: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []NodeTraffic
	for rows.Next() {
		var ts, up, down, devices int64
		if err := rows.Scan(&ts, &up, &down, &devices); err != nil {
			return nil, fmt.Errorf("store: node traffic: %w", err)
		}
		out = append(out, NodeTraffic{TS: timeFromDB(ts), Up: uint64Of(up), Down: uint64Of(down), DevicesSum: uint32Of(devices)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: node traffic: %w", err)
	}
	return out, nil
}

// A ProxyTotal is what a proxy (or, from TrafficSince, a node: ProxyID is then
// empty) carried over a range of time: bytes, connections opened, and the most
// unique client IPs of one of its periods (for a node, of its proxies' sum).
type ProxyTotal struct {
	ProxyID     string
	Up, Down    uint64
	ConnsNew    uint64
	DevicesPeak uint32
}

// A span is a range [lo, hi) of Unix times that is read from the tables of one
// resolution.
type span struct {
	res    string
	lo, hi int64
}

// totalSpans cuts [from, to) into the spans that a total is read from, so that
// each moment is counted once, and by the finest rows that are certain to be
// there. The whole hours come from the hour rows, up to the last hour that
// RollupStats has made (hoursTable, whose newest row tells), and the minutes
// of the partial hours at both ends, and of the hours that are not rolled up
// yet, from the minute rows. When the range is longer than daysAfter, the
// whole days in it come from the day rows, and only the hours around them from
// the hour rows.
//
// Two limits follow. How far the hours are rolled up is read from the newest
// hour of any row of hoursTable, not of the proxies that are summed: RollupStats
// rolls every proxy (and country) up to the same hour, so they agree, but a
// series that has no row in that hour is read from its hours up to it, and
// from its minutes only after it, as the others are. And the partial hour at
// the start comes from the minutes, which are kept only for the minutes of the
// retention: a from that is older than that loses what its first partial hour
// carried (the whole hours after it are still counted).
func (db *DB) totalSpans(ctx context.Context, hoursTable string, from, to time.Time, daysAfter time.Duration) ([]span, error) {
	f, t := from.Unix(), to.Unix()
	if t <= f {
		return nil, nil
	}
	h0, h1 := ceilTo(f, 3600), floorTo(t, 3600)
	if h0 >= h1 {
		return []span{{"1m", f, t}}, nil
	}
	var newest sql.NullInt64
	if err := db.sql.QueryRowContext(ctx, `SELECT MAX(ts) FROM `+hoursTable).Scan(&newest); err != nil {
		return nil, fmt.Errorf("store: newest hour: %w", err)
	}
	hEnd := h0
	if newest.Valid {
		hEnd = min(max(newest.Int64+3600, h0), h1)
	}
	var out []span
	add := func(res string, lo, hi int64) {
		if lo < hi {
			out = append(out, span{res, lo, hi})
		}
	}
	add("1m", f, h0)
	if d0, d1 := ceilTo(h0, 86400), floorTo(hEnd, 86400); to.Sub(from) > daysAfter && d0 < d1 {
		add("1h", h0, d0)
		add("1d", d0, d1)
		add("1h", d1, hEnd)
	} else {
		add("1h", h0, hEnd)
	}
	add("1m", hEnd, t)
	return out, nil
}

// proxyTotals sums what proxies carried over [from, to), by proxy, or by node
// when byNode, of the proxies of nodeID when it is not empty.
func (db *DB) proxyTotals(ctx context.Context, nodeID string, from, to time.Time, byNode bool) (map[string]ProxyTotal, error) {
	r, err := db.retention(ctx)
	if err != nil {
		return nil, err
	}
	spans, err := db.totalSpans(ctx, "stats_proxy_1h", from, to, r.Hours)
	if err != nil {
		return nil, err
	}
	out := map[string]ProxyTotal{}
	for _, sp := range spans {
		var q string
		if byNode {
			q = `SELECT node_id, SUM(up), SUM(down), SUM(conns_new), MAX(devices) FROM (
			       SELECT p.node_id AS node_id, s.ts, SUM(s.up) AS up, SUM(s.down) AS down,
			              SUM(s.conns_new) AS conns_new, SUM(s.devices) AS devices
			       FROM ` + proxySource(sp.res, proxiesOfNodeOrAll) + ` s JOIN proxies p ON p.id = s.proxy_id
			       WHERE s.ts >= ?1 AND s.ts < ?2 AND (?3 = '' OR p.node_id = ?3) GROUP BY p.node_id, s.ts)
			     GROUP BY node_id`
		} else {
			q = `SELECT s.proxy_id, SUM(s.up), SUM(s.down), SUM(s.conns_new), MAX(s.devices)
			     FROM ` + proxySource(sp.res, proxiesOfNodeOrAll) + ` s
			     WHERE s.ts >= ?1 AND s.ts < ?2 AND (?3 = '' OR s.proxy_id IN (SELECT id FROM proxies WHERE node_id = ?3))
			     GROUP BY s.proxy_id`
		}
		rows, err := db.sql.QueryContext(ctx, q, sp.lo, sp.hi, nodeID)
		if err != nil {
			return nil, fmt.Errorf("store: totals: %w", err)
		}
		for rows.Next() {
			var key string
			var up, down, conns, devices int64
			if err := rows.Scan(&key, &up, &down, &conns, &devices); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("store: totals: %w", err)
			}
			t := out[key]
			if !byNode {
				t.ProxyID = key
			}
			t.Up += uint64Of(up)
			t.Down += uint64Of(down)
			t.ConnsNew += uint64Of(conns)
			t.DevicesPeak = max(t.DevicesPeak, uint32Of(devices))
			out[key] = t
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, fmt.Errorf("store: totals: %w", err)
		}
	}
	return out, nil
}

// retention returns the retention of the stored settings.
func (db *DB) retention(ctx context.Context) (Retention, error) {
	s, _, err := db.StatsSettings(ctx)
	if err != nil {
		return Retention{}, err
	}
	return s.Retention(), nil
}

// TopProxies returns what the proxies of a node (all proxies when nodeID is
// empty) carried over [from, to), the busiest first (by Up + Down, then by id),
// at most limit of them (all when limit is not positive). Whole hours are read
// from the hour rows (whole days beyond the hours that are kept) and the
// minutes of the partial hours at both ends are added.
func (db *DB) TopProxies(ctx context.Context, nodeID string, from, to time.Time, limit int) ([]ProxyTotal, error) {
	m, err := db.proxyTotals(ctx, nodeID, from, to, false)
	if err != nil {
		return nil, err
	}
	out := make([]ProxyTotal, 0, len(m))
	for _, t := range m {
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b ProxyTotal) int {
		if c := cmp.Compare(b.Up+b.Down, a.Up+a.Down); c != 0 {
			return c
		}
		return cmp.Compare(a.ProxyID, b.ProxyID)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// TrafficSince returns what the proxies of each node carried from since to now,
// by node id (ProxyID is empty); a node without traffic is not in it. The
// partial hours at both ends are added from the minutes, so a since that is not
// on the hour (the local midnight of UTC+03:30 is 20:30 UTC) is counted to the
// minute.
func (db *DB) TrafficSince(ctx context.Context, since, now time.Time) (map[string]ProxyTotal, error) {
	return db.proxyTotals(ctx, "", since, now, true)
}

// LatestNodeMinutes returns the newest minute of each node that has one from
// now - within on, by node id.
func (db *DB) LatestNodeMinutes(ctx context.Context, now time.Time, within time.Duration) (map[string]NodeStat, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT node_id, ts, cpu, mem_used, mem_total, load1, disk_used, disk_total, net_rx, net_tx, conns,
		   refused_prehello, refused_total, evicted_prehello FROM stats_node_1m n
		 WHERE ts >= ?1 AND ts = (SELECT MAX(ts) FROM stats_node_1m WHERE node_id = n.node_id AND ts >= ?1)`,
		now.Add(-within).Unix())
	if err != nil {
		return nil, fmt.Errorf("store: latest node minutes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]NodeStat{}
	for rows.Next() {
		var (
			s                                                  NodeStat
			ts, memUsed, memTotal, diskUsed, diskTotal, rx, tx int64
			conns, refusedPre, refusedTotal, evictedPre        int64
		)
		if err := rows.Scan(&s.NodeID, &ts, &s.CPU, &memUsed, &memTotal, &s.Load1, &diskUsed, &diskTotal, &rx, &tx, &conns,
			&refusedPre, &refusedTotal, &evictedPre); err != nil {
			return nil, fmt.Errorf("store: latest node minutes: %w", err)
		}
		s.TS = timeFromDB(ts)
		s.MemUsed, s.MemTotal = uint64Of(memUsed), uint64Of(memTotal)
		s.DiskUsed, s.DiskTotal = uint64Of(diskUsed), uint64Of(diskTotal)
		s.NetRx, s.NetTx = uint64Of(rx), uint64Of(tx)
		s.Conns = uint32Of(conns)
		s.RefusedPreHello, s.RefusedTotal, s.EvictedPreHello = uint64Of(refusedPre), uint64Of(refusedTotal), uint64Of(evictedPre)
		out[s.NodeID] = s
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: latest node minutes: %w", err)
	}
	return out, nil
}
