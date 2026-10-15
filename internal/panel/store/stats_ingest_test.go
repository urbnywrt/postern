package store

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// ingestFixture is statsFixture with the clock of the store at statsNow, which
// IngestMinute measures the age of a minute by, and the IP policy full, under
// which every kind of a batch is stored (the tests of the policy set others).
func ingestFixture(t *testing.T) (db *DB, node *Node, p, q *Proxy) {
	t.Helper()
	db, node, p, q = statsFixture(t)
	db.now = fixedClock(statsNow)
	if _, err := db.ApplyStatsSettings(context.Background(), withPolicy(IPPolicyFull)); err != nil {
		t.Fatal(err)
	}
	return db, node, p, q
}

// statsTables are the tables that IngestMinute, RollupStats and PruneStats
// write.
var statsTables = []string{
	"stats_proxy_1m", "stats_proxy_1h", "stats_proxy_1d",
	"stats_node_1m", "stats_node_1h", "stats_node_1d",
	"stats_country_1m", "stats_country_1h", "stats_country_1d",
	"egress_health_1m", "egress_health",
	"ip_sightings", "probes", "stats_batches",
}

// rowsOf runs a query and returns its rows, each as its values joined by "|".
func rowsOf(t *testing.T, db *DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.sql.QueryContext(context.Background(), query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		parts := make([]string, len(vals))
		for i, v := range vals {
			parts[i] = fmt.Sprint(v)
		}
		out = append(out, strings.Join(parts, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// snapshot returns every row of the tables, to tell whether a call changed any.
func snapshot(t *testing.T, db *DB, tables ...string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, table := range tables {
		rows := rowsOf(t, db, `SELECT * FROM `+table)
		slices.Sort(rows)
		out[table] = rows
	}
	return out
}

func sameSnapshot(t *testing.T, what string, got, want map[string][]string) {
	t.Helper()
	for table, rows := range want {
		if !slices.Equal(got[table], rows) {
			t.Errorf("%s changed %s:\n got  %q\n want %q", what, table, got[table], rows)
		}
	}
}

// fullBatch is the minute of a node with something of every kind in it.
func fullBatch(node *Node, p, q *Proxy, minute time.Time) MinuteBatch {
	return MinuteBatch{
		NodeID: node.ID,
		Minute: minute.Add(25 * time.Second), // a time inside a minute is the minute
		Proxies: []ProxyStat{
			{ProxyID: p.ID, Up: 100, Down: 200, ConnsNew: 3, ConnsPeak: 4, Devices: 2},
			{ProxyID: q.ID, Up: 1, Down: 1, ConnsNew: 1, ConnsPeak: 1, Devices: 1},
		},
		Node: &NodeStat{
			CPU: 12.5, MemUsed: 1 << 30, MemTotal: 4 << 30, Load1: 0.5, DiskUsed: 1 << 32, DiskTotal: 1 << 34,
			NetRx: 1000, NetTx: 2000, Conns: 7, RefusedPreHello: 3, RefusedTotal: 5, EvictedPreHello: 1,
		},
		Countries: []CountryStat{
			{ProxyID: p.ID, Country: "DE", IPs: 2, Bytes: 250},
			{ProxyID: p.ID, Country: "NL", IPs: 1, Bytes: 50},
		},
		Members: []MemberStat{
			{ChainID: "C1", MemberKey: "m1", Status: "up", LatencyMS: 40, ExitIP: "203.0.113.5"},
			{ChainID: "C1", MemberKey: "m2", Status: "down"},
		},
		Sightings: []Sighting{
			{ProxyID: p.ID, IP: "198.51.100.7", Country: "DE", FirstSeen: minute, LastSeen: minute.Add(30 * time.Second), Bytes: 250},
		},
		Probes: []Probe{
			{ProxyID: p.ID, TS: minute.Add(10 * time.Second), Vantage: "node", Kind: "l2", OK: true, LatencyMS: 120},
		},
	}
}

func ingest(t *testing.T, db *DB, b MinuteBatch) {
	t.Helper()
	gone, err := db.IngestMinute(context.Background(), b)
	if err != nil {
		t.Fatalf("IngestMinute: %v", err)
	}
	if len(gone) != 0 {
		t.Fatalf("IngestMinute: gone = %v, want none", gone)
	}
}

func TestIngestMinuteStoresEveryKind(t *testing.T) {
	db, node, p, q := ingestFixture(t)
	m := at(10, 12, 0)
	ingest(t, db, fullBatch(node, p, q, m))
	ts := m.Unix()

	for _, tt := range []struct {
		what  string
		query string
		args  []any
		want  []string
	}{
		{"proxy minutes", `SELECT proxy_id, ts, up, down, conns_new, conns_peak, devices FROM stats_proxy_1m ORDER BY proxy_id`, nil,
			sortedRows(fmt.Sprintf("%s|%d|100|200|3|4|2", p.ID, ts), fmt.Sprintf("%s|%d|1|1|1|1|1", q.ID, ts))},
		{"node minute", `SELECT ts, cpu, mem_used, net_rx, net_tx, conns, refused_prehello, refused_total, evicted_prehello FROM stats_node_1m WHERE node_id = ?`,
			[]any{node.ID}, []string{fmt.Sprintf("%d|12.5|%d|1000|2000|7|3|5|1", ts, 1<<30)}},
		{"country minutes", `SELECT proxy_id, ts, country, ips, bytes FROM stats_country_1m ORDER BY country`, nil,
			[]string{fmt.Sprintf("%s|%d|DE|2|250", p.ID, ts), fmt.Sprintf("%s|%d|NL|1|50", p.ID, ts)}},
		{"member minutes", `SELECT node_id, chain_id, member_key, ts, status, latency_ms, exit_ip FROM egress_health_1m ORDER BY member_key`, nil,
			[]string{fmt.Sprintf("%s|C1|m1|%d|up|40|203.0.113.5", node.ID, ts), fmt.Sprintf("%s|C1|m2|%d|down|0|", node.ID, ts)}},
		{"sightings", `SELECT proxy_id, ip, first_seen, last_seen, bytes, country FROM ip_sightings`, nil,
			[]string{fmt.Sprintf("%s|198.51.100.7|%d|%d|250|DE", p.ID, ts, ts+30)}},
		{"probes", `SELECT proxy_id, ts, vantage, kind, ok, latency_ms, error FROM probes`, nil,
			[]string{fmt.Sprintf("%s|%d|node|l2|1|120|", p.ID, ts+10)}},
		{"markers", `SELECT node_id, minute FROM stats_batches`, nil,
			[]string{fmt.Sprintf("%s|%d", node.ID, ts)}},
	} {
		if got := rowsOf(t, db, tt.query, tt.args...); !slices.Equal(got, tt.want) {
			t.Errorf("%s = %q\nwant %q", tt.what, got, tt.want)
		}
	}
}

func sortedRows(rows ...string) []string {
	slices.Sort(rows)
	return rows
}

// The same batch delivered twice is stored once: the minutes are replaced by
// themselves, the address is not seen twice, a probe is not stored twice.
func TestIngestMinuteTwiceChangesNothing(t *testing.T) {
	db, node, p, q := ingestFixture(t)
	b := fullBatch(node, p, q, at(10, 12, 0))
	ingest(t, db, b)
	once := snapshot(t, db, statsTables...)
	ingest(t, db, b)
	sameSnapshot(t, "a second delivery", snapshot(t, db, statsTables...), once)
}

// Markers are kept as long as ingest takes a minute, 8 days. A minute older
// than that is not taken at all: its marker may be gone, and its address
// would be counted a second time.
func TestIngestMinuteReplayAfterItsMarkerIsPruned(t *testing.T) {
	db, node, p, q := ingestFixture(t)
	ctx := context.Background()
	m := at(1, 12, 0)
	db.now = fixedClock(m.Add(time.Minute))
	ingest(t, db, fullBatch(node, p, q, m))

	// The address is seen again two days later, so that it is still kept when
	// the marker of the first minute goes.
	m2 := m.Add(48 * time.Hour)
	db.now = fixedClock(m2.Add(time.Minute))
	ingest(t, db, MinuteBatch{NodeID: node.ID, Minute: m2, Sightings: []Sighting{
		{ProxyID: p.ID, IP: "198.51.100.7", FirstSeen: m2, LastSeen: m2, Bytes: 100},
	}})

	now := m.Add(8*24*time.Hour + time.Hour)
	if err := db.PruneStats(ctx, now, testRetention); err != nil {
		t.Fatal(err)
	}
	if got := rowsOf(t, db, `SELECT minute FROM stats_batches`); !slices.Equal(got, []string{fmt.Sprint(m2.Unix())}) {
		t.Fatalf("markers after the prune = %v, want only that of the later minute", got)
	}
	if got := rowsOf(t, db, `SELECT bytes FROM ip_sightings`); !slices.Equal(got, []string{"350"}) {
		t.Fatalf("bytes of the address = %v, want 350", got)
	}

	before := snapshot(t, db, statsTables...)
	db.now = fixedClock(now)
	gone, err := db.IngestMinute(ctx, fullBatch(node, p, q, m))
	if !errors.Is(err, ErrMinuteTooOld) || gone != nil {
		t.Fatalf("IngestMinute of the replay = %v, %v; want nothing and ErrMinuteTooOld", gone, err)
	}
	sameSnapshot(t, "the replay of a minute without a marker", snapshot(t, db, statsTables...), before)
}

// A minute is taken up to 8 days back, to the second; an older one is refused
// as such, so that the caller can tell it from a minute that was stored.
func TestIngestMinuteAgeLimit(t *testing.T) {
	for _, tt := range []struct {
		age  time.Duration
		kept bool
	}{
		{8 * 24 * time.Hour, true},
		{8*24*time.Hour + time.Minute, false},
	} {
		db, node, p, _ := ingestFixture(t)
		m := statsNow.Add(-tt.age)
		_, err := db.IngestMinute(context.Background(), MinuteBatch{NodeID: node.ID, Minute: m, Proxies: []ProxyStat{{ProxyID: p.ID, Up: 1}}})
		switch {
		case tt.kept && err != nil:
			t.Errorf("a minute of %s ago: %v", tt.age, err)
		case !tt.kept && !errors.Is(err, ErrMinuteTooOld):
			t.Errorf("a minute of %s ago: err = %v, want ErrMinuteTooOld", tt.age, err)
		}
		if kept := proxyUp(t, db, "stats_proxy_1m", p.ID, m) == 1; kept != tt.kept {
			t.Errorf("a minute of %s ago: stored = %v, want %v", tt.age, kept, tt.kept)
		}
	}
}

// A minute that is emitted again with other values replaces the first: its
// proxy, node, country and member minutes, and the hours made of them. Where
// the addresses were seen is added up once a minute only.
func TestIngestMinuteSecondEmitReplaces(t *testing.T) {
	db, node, p, q := ingestFixture(t)
	ctx := context.Background()
	m := at(10, 9, 0)
	ingest(t, db, fullBatch(node, p, q, m))

	second := fullBatch(node, p, q, m)
	second.Proxies[0].Up, second.Proxies[0].Down = 150, 300
	second.Node.NetRx, second.Node.RefusedTotal = 1500, 9
	second.Countries = []CountryStat{ // NL is not in it any more
		{ProxyID: p.ID, Country: "DE", IPs: 3, Bytes: 400},
		{ProxyID: p.ID, Country: "FR", IPs: 1, Bytes: 30},
	}
	second.Members[0].LatencyMS = 80
	second.Sightings[0].Bytes = 999
	ingest(t, db, second)

	ts := m.Unix()
	check := func(what string, got, want []string) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Errorf("%s = %q, want %q", what, got, want)
		}
	}
	check("proxy minute", rowsOf(t, db, `SELECT up, down FROM stats_proxy_1m WHERE proxy_id = ? AND ts = ?`, p.ID, ts), []string{"150|300"})
	check("node minute", rowsOf(t, db, `SELECT net_rx, refused_total FROM stats_node_1m WHERE ts = ?`, ts), []string{"1500|9"})
	check("country minutes", rowsOf(t, db, `SELECT country, ips, bytes FROM stats_country_1m WHERE ts = ? ORDER BY country`, ts), []string{"DE|3|400", "FR|1|30"})
	check("member minute", rowsOf(t, db, `SELECT latency_ms FROM egress_health_1m WHERE member_key = 'm1'`), []string{"80"})
	check("bytes of the address", rowsOf(t, db, `SELECT bytes FROM ip_sightings`), []string{"250"})

	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatal(err)
	}
	hour := m.Unix()
	check("proxy hour", rowsOf(t, db, `SELECT up, down FROM stats_proxy_1h WHERE proxy_id = ? AND ts = ?`, p.ID, hour), []string{"150|300"})
	check("node hour", rowsOf(t, db, `SELECT net_rx, refused_total FROM stats_node_1h WHERE ts = ?`, hour), []string{"1500|9"})
	check("country hours", rowsOf(t, db, `SELECT country, ips, bytes FROM stats_country_1h WHERE ts = ? ORDER BY country`, hour), []string{"DE|3|400", "FR|1|30"})
	check("member hour", rowsOf(t, db, `SELECT latency_avg_ms, latency_max_ms FROM egress_health WHERE member_key = 'm1'`), []string{"80|80"})
}

// Proxies that are gone are skipped and named once; the rest of the batch is
// stored. A node that is gone stores nothing at all.
func TestIngestMinuteSkipsWhatIsGone(t *testing.T) {
	db, node, p, _ := ingestFixture(t)
	ctx := context.Background()
	const goneProxy = "01K6Y00000000000000000000Z"
	m := at(10, 12, 0)
	b := MinuteBatch{
		NodeID:    node.ID,
		Minute:    m,
		Proxies:   []ProxyStat{{ProxyID: goneProxy, Up: 2}, {ProxyID: p.ID, Up: 1}},
		Countries: []CountryStat{{ProxyID: goneProxy, Country: "DE", IPs: 1, Bytes: 1}, {ProxyID: p.ID, Country: "DE", IPs: 1, Bytes: 1}},
		Sightings: []Sighting{
			{ProxyID: goneProxy, IP: "198.51.100.8", FirstSeen: m, LastSeen: m, Bytes: 1},
			{ProxyID: p.ID, IP: "198.51.100.9", FirstSeen: m, LastSeen: m, Bytes: 1},
		},
		Probes: []Probe{
			{ProxyID: goneProxy, TS: m, Vantage: "node", Kind: "l2"},
			{ProxyID: p.ID, TS: m, Vantage: "node", Kind: "l2", OK: true},
		},
	}
	gone, err := db.IngestMinute(ctx, b)
	if err != nil {
		t.Fatalf("IngestMinute: %v", err)
	}
	if !reflect.DeepEqual(gone, []string{goneProxy}) {
		t.Errorf("gone = %v, want the proxy that is not there, once", gone)
	}
	for table, want := range map[string]int{"stats_proxy_1m": 1, "stats_country_1m": 1, "ip_sightings": 1, "probes": 1} {
		if n := count(t, db, `SELECT count(*) FROM `+table+` WHERE proxy_id = ?`, p.ID); n != want {
			t.Errorf("%s: %d rows of the proxy that is there, want %d", table, n, want)
		}
	}

	before := snapshot(t, db, statsTables...)
	gone, err = db.IngestMinute(ctx, MinuteBatch{
		NodeID:    "01K6Y0000000000000000000NZ",
		Minute:    m.Add(time.Minute),
		Proxies:   []ProxyStat{{ProxyID: p.ID, Up: 5}},
		Node:      &NodeStat{Conns: 1},
		Countries: []CountryStat{{ProxyID: p.ID, Country: "FR", IPs: 1, Bytes: 1}},
		Members:   []MemberStat{{ChainID: "C1", MemberKey: "m1", Status: "up"}},
		Sightings: []Sighting{{ProxyID: p.ID, IP: "198.51.100.10", FirstSeen: m, LastSeen: m, Bytes: 1}},
		Probes:    []Probe{{ProxyID: p.ID, TS: m.Add(time.Minute), Vantage: "node", Kind: "l2"}},
	})
	if err != nil || gone != nil {
		t.Errorf("IngestMinute of a node that is gone = %v, %v; want nothing and no error", gone, err)
	}
	sameSnapshot(t, "the batch of a node that is gone", snapshot(t, db, statsTables...), before)
}

// A batch that fails in the middle leaves nothing of itself behind, the
// marker included, so that it can be delivered again.
func TestIngestMinuteFailsAsAWhole(t *testing.T) {
	db, node, p, q := ingestFixture(t)
	before := snapshot(t, db, statsTables...)
	mustExec(t, db, `CREATE TRIGGER refuse_probes BEFORE INSERT ON probes BEGIN SELECT RAISE(ABORT, 'refused by the test'); END`)
	if _, err := db.IngestMinute(context.Background(), fullBatch(node, p, q, at(10, 12, 0))); err == nil {
		t.Fatal("IngestMinute: no error, although a probe was refused")
	}
	sameSnapshot(t, "a batch that failed", snapshot(t, db, statsTables...), before)

	mustExec(t, db, `DROP TRIGGER refuse_probes`)
	ingest(t, db, fullBatch(node, p, q, at(10, 12, 0)))
	if n := count(t, db, `SELECT count(*) FROM ip_sightings`); n != 1 {
		t.Errorf("after the batch is delivered again: %d sightings, want 1", n)
	}
}

// Counters keep the limit of 2^50 a minute, and a total that only grows, the
// bytes of an address, stops at 2^62 instead of overflowing.
func TestIngestMinuteClampsCounters(t *testing.T) {
	db, node, p, _ := ingestFixture(t)
	m := at(10, 12, 0)
	const huge = math.MaxUint64
	mustExec(t, db, `INSERT INTO ip_sightings (proxy_id, ip, first_seen, last_seen, bytes) VALUES (?, '198.51.100.7', 1, 1, ?)`,
		p.ID, int64(1<<62-5))
	ingest(t, db, MinuteBatch{
		NodeID:    node.ID,
		Minute:    m,
		Proxies:   []ProxyStat{{ProxyID: p.ID, Up: huge, Down: huge}},
		Node:      &NodeStat{NetRx: huge, RefusedPreHello: huge, RefusedTotal: huge, EvictedPreHello: huge},
		Countries: []CountryStat{{ProxyID: p.ID, Country: "DE", IPs: math.MaxUint32, Bytes: huge}},
		Sightings: []Sighting{{ProxyID: p.ID, IP: "198.51.100.7", FirstSeen: m, LastSeen: m, Bytes: huge}},
	})
	const c = cappedCounter
	for _, tt := range []struct {
		query string
		want  string
	}{
		{`SELECT up, down FROM stats_proxy_1m`, fmt.Sprintf("%d|%d", c, c)},
		{`SELECT net_rx, refused_prehello, refused_total, evicted_prehello FROM stats_node_1m`, fmt.Sprintf("%d|%d|%d|%d", c, c, c, c)},
		{`SELECT ips, bytes FROM stats_country_1m`, fmt.Sprintf("%d|%d", uint32(math.MaxUint32), c)},
		{`SELECT bytes FROM ip_sightings`, fmt.Sprint(int64(1 << 62))},
	} {
		if got := rowsOf(t, db, tt.query); !slices.Equal(got, []string{tt.want}) {
			t.Errorf("%s = %v, want %s", tt.query, got, tt.want)
		}
	}
}

// Three minutes of an hour make the hour: the traffic of a proxy and of a node
// with its refusals summed, a country's peak of addresses in a minute and its
// bytes summed, and of a member of a chain a minute per status, the latency of
// the minutes it was up and had one, and its last exit address.
func TestRollupThreeMinutesOfAnHour(t *testing.T) {
	db, node, p, q := ingestFixture(t)
	ctx := context.Background()
	minutes := []MinuteBatch{
		{
			Proxies:   []ProxyStat{{ProxyID: p.ID, Up: 10, Down: 1, ConnsNew: 1, ConnsPeak: 5, Devices: 2}},
			Node:      &NodeStat{CPU: 10, NetRx: 5, Conns: 4, RefusedPreHello: 1, RefusedTotal: 2, EvictedPreHello: 0},
			Countries: []CountryStat{{ProxyID: p.ID, Country: "DE", IPs: 2, Bytes: 100}, {ProxyID: p.ID, Country: "NL", IPs: 1, Bytes: 10}},
			Members: []MemberStat{
				{ChainID: "C1", MemberKey: "m1", Status: "up", LatencyMS: 40, ExitIP: "203.0.113.5"},
				{ChainID: "C1", MemberKey: "m2", Status: "unknown", ExitIP: "203.0.113.9"},
			},
		},
		{
			Proxies:   []ProxyStat{{ProxyID: p.ID, Up: 20, Down: 2, ConnsNew: 2, ConnsPeak: 9, Devices: 4}},
			Node:      &NodeStat{CPU: 30, NetRx: 6, Conns: 9, RefusedPreHello: 2, RefusedTotal: 3, EvictedPreHello: 1},
			Countries: []CountryStat{{ProxyID: p.ID, Country: "DE", IPs: 5, Bytes: 200}},
			Members: []MemberStat{
				{ChainID: "C1", MemberKey: "m1", Status: "down", ExitIP: "203.0.113.6"},
				{ChainID: "C1", MemberKey: "m2", Status: "up"}, // up, without a latency
			},
		},
		{
			Proxies: []ProxyStat{{ProxyID: p.ID, Up: 30, Down: 3, ConnsNew: 3, ConnsPeak: 7, Devices: 3}},
			Node:    &NodeStat{CPU: 20, NetRx: 7, Conns: 6, RefusedPreHello: 4, RefusedTotal: 5, EvictedPreHello: 2},
			Countries: []CountryStat{
				{ProxyID: p.ID, Country: "DE", IPs: 3, Bytes: 300},
				{ProxyID: p.ID, Country: "FR", IPs: 4, Bytes: 40},
				{ProxyID: p.ID, Country: "xx", IPs: 1, Bytes: 5}, // not a code: ""
			},
			Members: []MemberStat{
				{ChainID: "C1", MemberKey: "m1", Status: "up", LatencyMS: 61},
				{ChainID: "C1", MemberKey: "m2", Status: "degraded"}, // a status of its own: unknown
			},
		},
	}
	for i, b := range minutes {
		b.NodeID, b.Minute = node.ID, at(10, 9, i)
		ingest(t, db, b)
	}
	ingest(t, db, MinuteBatch{NodeID: node.ID, Minute: at(10, 10, 0), Proxies: []ProxyStat{{ProxyID: q.ID, Up: 1}}}) // another hour
	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}

	hour := at(10, 9, 0).Unix()
	for _, tt := range []struct {
		what  string
		query string
		id    string
		want  []string
	}{
		{"proxy hour", `SELECT up, down, conns_new, conns_peak, devices FROM stats_proxy_1h WHERE proxy_id = ? AND ts = ?`, p.ID,
			[]string{"60|6|6|9|4"}},
		{"node hour", `SELECT cpu, net_rx, conns, refused_prehello, refused_total, evicted_prehello FROM stats_node_1h WHERE node_id = ? AND ts = ?`, node.ID,
			[]string{"20|18|9|7|10|3"}},
		{"country hours", `SELECT country, ips, bytes FROM stats_country_1h WHERE proxy_id = ? AND ts = ? ORDER BY country`, p.ID,
			[]string{"|1|5", "DE|5|600", "FR|4|40", "NL|1|10"}},
		{"member hours", `SELECT member_key, minutes_up, minutes_down, minutes_unknown, latency_avg_ms, latency_max_ms, exit_ip
			FROM egress_health WHERE node_id = ? AND ts = ? ORDER BY member_key`, node.ID,
			[]string{"m1|2|1|0|51|61|203.0.113.6", "m2|1|0|2|0|0|203.0.113.9"}},
	} {
		if got := rowsOf(t, db, tt.query, tt.id, hour); !slices.Equal(got, tt.want) {
			t.Errorf("%s = %q\nwant %q", tt.what, got, tt.want)
		}
	}
}

// The edge's refusals of a node are read back with its minutes.
func TestNodeRefusalCountersRoundTrip(t *testing.T) {
	db, node, _, _ := statsFixture(t)
	ctx := context.Background()
	want := fullNodeStat(node.ID, at(10, 9, 0))
	want.RefusedPreHello, want.RefusedTotal, want.EvictedPreHello = 11, 22, 33
	if err := db.UpsertNodeMinute(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := db.NodeSeries(ctx, node.ID, at(10, 9, 0), at(10, 10, 0), testRetention)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []NodeStat{want}) {
		t.Errorf("series = %+v\nwant     %+v", got, []NodeStat{want})
	}
}
