package store

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"
)

// statsNow is the clock of the statistics tests: 12:30 on 10 October 2026.
// Everything that RollupStats and PruneStats do is relative to it.
var statsNow = time.Date(2026, 10, 10, 12, 30, 0, 0, time.UTC)

// testRetention is the retention of the statistics tests, the default one:
// minutes for 48 hours, hours for 90 days, addresses for 7 days. It is written
// out here, and not taken from the code under test.
var testRetention = Retention{Minutes: 48 * time.Hour, Hours: 90 * 24 * time.Hour, IPs: 7 * 24 * time.Hour}

// at is a time in October 2026 (UTC).
func at(day, hour, minute int) time.Time {
	return time.Date(2026, 10, day, hour, minute, 0, 0, time.UTC)
}

// statsFixture is a node with one listener and two proxies.
func statsFixture(t *testing.T) (db *DB, node *Node, p, q *Proxy) {
	t.Helper()
	db = newTestDB(t)
	node = mustNode(t, db, "n")
	l := mustListener(t, db, node.ID, 443)
	p = mustProxy(t, db, node.ID, l.ID, "p")
	q = mustProxy(t, db, node.ID, l.ID, "q")
	return db, node, p, q
}

// putProxyStat writes a row of a statistics table with SQL, to set up a state
// that the repository would not produce by itself.
func putProxyStat(t *testing.T, db *DB, table, proxyID string, ts time.Time, s ProxyStat) {
	t.Helper()
	mustExec(t, db, `INSERT INTO `+table+` (proxy_id, ts, up, down, conns_new, conns_peak, devices) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		proxyID, ts.Unix(), s.Up, s.Down, s.ConnsNew, s.ConnsPeak, s.Devices)
}

func putNodeStat(t *testing.T, db *DB, table, nodeID string, ts time.Time, s NodeStat) {
	t.Helper()
	mustExec(t, db, `INSERT INTO `+table+` (node_id, ts, cpu, mem_used, mem_total, load1, disk_used, disk_total, net_rx, net_tx, conns,
		refused_prehello, refused_total, evicted_prehello) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nodeID, ts.Unix(), s.CPU, s.MemUsed, s.MemTotal, s.Load1, s.DiskUsed, s.DiskTotal, s.NetRx, s.NetTx, s.Conns,
		s.RefusedPreHello, s.RefusedTotal, s.EvictedPreHello)
}

// proxyUp returns the up column of one row, or -1 when there is no such row.
func proxyUp(t *testing.T, db *DB, table, proxyID string, ts time.Time) int {
	t.Helper()
	var up int
	err := db.sql.QueryRow(`SELECT up FROM `+table+` WHERE proxy_id = ? AND ts = ?`, proxyID, ts.Unix()).Scan(&up)
	if err != nil {
		return -1
	}
	return up
}

func series(t *testing.T, db *DB, proxyID string, from, to time.Time) []ProxyStat {
	t.Helper()
	got, err := db.ProxySeries(context.Background(), proxyID, from, to, testRetention)
	if err != nil {
		t.Fatalf("ProxySeries: %v", err)
	}
	return got
}

func TestUpsertProxyMinute(t *testing.T) {
	db, _, p, q := statsFixture(t)
	ctx := context.Background()

	// A time inside a minute is the minute it is in.
	first := ProxyStat{ProxyID: p.ID, TS: at(10, 9, 0).Add(30 * time.Second), Up: 100, Down: 200, ConnsNew: 3, ConnsPeak: 4, Devices: 2}
	if err := db.UpsertProxyMinute(ctx, first); err != nil {
		t.Fatalf("UpsertProxyMinute: %v", err)
	}
	got := series(t, db, p.ID, at(10, 9, 0), at(10, 10, 0))
	want := []ProxyStat{{ProxyID: p.ID, TS: at(10, 9, 0), Up: 100, Down: 200, ConnsNew: 3, ConnsPeak: 4, Devices: 2}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("series = %+v, want %+v", got, want)
	}

	// The same minute again replaces the row: a batch that is delivered twice
	// is not counted twice.
	second := ProxyStat{ProxyID: p.ID, TS: at(10, 9, 0), Up: 150, Down: 250, ConnsNew: 5, ConnsPeak: 6, Devices: 3}
	if err := db.UpsertProxyMinute(ctx, second); err != nil {
		t.Fatal(err)
	}
	got = series(t, db, p.ID, at(10, 9, 0), at(10, 10, 0))
	want = []ProxyStat{{ProxyID: p.ID, TS: at(10, 9, 0), Up: 150, Down: 250, ConnsNew: 5, ConnsPeak: 6, Devices: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("after the second upsert: series = %+v, want %+v", got, want)
	}

	// Another proxy has rows of its own.
	if err := db.UpsertProxyMinute(ctx, ProxyStat{ProxyID: q.ID, TS: at(10, 9, 0), Up: 1}); err != nil {
		t.Fatal(err)
	}
	if got := series(t, db, p.ID, at(10, 9, 0), at(10, 10, 0)); len(got) != 1 || got[0].Up != 150 {
		t.Errorf("a row of another proxy changed this one: %+v", got)
	}

	// A proxy that does not exist (it was deleted while its node went on
	// reporting) is told apart, so that the caller can skip it.
	if err := db.UpsertProxyMinute(ctx, ProxyStat{ProxyID: "no-such-proxy", TS: at(10, 9, 0)}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpsertProxyMinute for an unknown proxy: err = %v, want ErrNotFound", err)
	}
}

func TestProxySeriesRange(t *testing.T) {
	db, _, p, q := statsFixture(t)
	ctx := context.Background()
	for m := range 5 {
		s := ProxyStat{ProxyID: p.ID, TS: at(10, 9, m), Up: uint64(m + 1)}
		if err := db.UpsertProxyMinute(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertProxyMinute(ctx, ProxyStat{ProxyID: q.ID, TS: at(10, 9, 2), Up: 99}); err != nil {
		t.Fatal(err)
	}

	ups := func(ss []ProxyStat) []uint64 {
		var out []uint64
		for _, s := range ss {
			out = append(out, s.Up)
		}
		return out
	}
	// From is included, to is not, and the rows come in time order.
	if got := ups(series(t, db, p.ID, at(10, 9, 1), at(10, 9, 4))); !reflect.DeepEqual(got, []uint64{2, 3, 4}) {
		t.Errorf("[09:01, 09:04) = %v, want [2 3 4]", got)
	}
	if got := ups(series(t, db, p.ID, at(10, 9, 0), at(10, 10, 0))); !reflect.DeepEqual(got, []uint64{1, 2, 3, 4, 5}) {
		t.Errorf("the whole hour = %v", got)
	}
	// A row is the minute that starts at its time, so a range that starts inside
	// a minute leaves that minute out.
	if got := ups(series(t, db, p.ID, at(10, 9, 1).Add(20*time.Second), at(10, 9, 3))); !reflect.DeepEqual(got, []uint64{3}) {
		t.Errorf("[09:01:20, 09:03) = %v, want [3]", got)
	}
	if got := series(t, db, p.ID, at(10, 9, 3), at(10, 9, 3)); len(got) != 0 {
		t.Errorf("an empty range returned %v", got)
	}
	if got := series(t, db, p.ID, at(10, 10, 0), at(10, 9, 0)); len(got) != 0 {
		t.Errorf("a backwards range returned %v", got)
	}
	if got := series(t, db, "no-such-proxy", at(10, 9, 0), at(10, 10, 0)); len(got) != 0 {
		t.Errorf("an unknown proxy returned %v", got)
	}
}

// The table that a series is read from depends on how long the range is: the
// minutes for up to 48 hours, the hours for up to 90 days, the days beyond that.
func TestProxySeriesResolution(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	end := at(10, 12, 0)
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 11, 30), ProxyStat{Up: 1})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(10, 11, 0), ProxyStat{Up: 2})
	putProxyStat(t, db, "stats_proxy_1d", p.ID, at(9, 0, 0), ProxyStat{Up: 3})

	tests := []struct {
		name string
		span time.Duration
		want uint64
	}{
		{"1 hour", time.Hour, 1},
		{"24 hours", 24 * time.Hour, 1},
		{"48 hours", 48 * time.Hour, 1},
		{"48 hours and a second", 48*time.Hour + time.Second, 2},
		{"7 days", 7 * 24 * time.Hour, 2},
		{"30 days", 30 * 24 * time.Hour, 2},
		{"90 days", 90 * 24 * time.Hour, 2},
		{"90 days and a second", 90*24*time.Hour + time.Second, 3},
		{"1 year", 365 * 24 * time.Hour, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := series(t, db, p.ID, end.Add(-tt.span), end)
			if tt.want == 3 && len(got) == 2 && got[1].Up == 2 {
				got = got[:1] // today has an hour but no day row: the series makes one up
			}
			if len(got) != 1 || got[0].Up != tt.want {
				t.Errorf("series over %s = %+v, want the one row with up = %d", tt.span, got, tt.want)
			}
		})
	}
}

func fullNodeStat(nodeID string, ts time.Time) NodeStat {
	return NodeStat{
		NodeID: nodeID, TS: ts, CPU: 12.5, MemUsed: 1 << 30, MemTotal: 4 << 30, Load1: 0.75,
		DiskUsed: 10 << 30, DiskTotal: 100 << 30, NetRx: 1000, NetTx: 2000, Conns: 42,
	}
}

func TestUpsertNodeMinuteAndSeries(t *testing.T) {
	db, node, _, _ := statsFixture(t)
	ctx := context.Background()
	other := mustNode(t, db, "other")

	s := fullNodeStat(node.ID, at(10, 9, 0).Add(15*time.Second))
	if err := db.UpsertNodeMinute(ctx, s); err != nil {
		t.Fatalf("UpsertNodeMinute: %v", err)
	}
	got, err := db.NodeSeries(ctx, node.ID, at(10, 9, 0), at(10, 10, 0), testRetention)
	if err != nil {
		t.Fatal(err)
	}
	want := []NodeStat{fullNodeStat(node.ID, at(10, 9, 0))}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("series = %+v\nwant     %+v", got, want)
	}

	// The same minute replaces the row.
	s.CPU, s.Conns = 99, 7
	if err := db.UpsertNodeMinute(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, _ = db.NodeSeries(ctx, node.ID, at(10, 9, 0), at(10, 10, 0), testRetention)
	if len(got) != 1 || got[0].CPU != 99 || got[0].Conns != 7 {
		t.Errorf("after the second upsert: %+v", got)
	}

	// Range, order and the node.
	for m := 1; m < 4; m++ {
		if err := db.UpsertNodeMinute(ctx, NodeStat{NodeID: node.ID, TS: at(10, 9, m), Conns: uint32(m)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertNodeMinute(ctx, NodeStat{NodeID: other.ID, TS: at(10, 9, 1), Conns: 500}); err != nil {
		t.Fatal(err)
	}
	got, err = db.NodeSeries(ctx, node.ID, at(10, 9, 1), at(10, 9, 3), testRetention)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Conns != 1 || got[1].Conns != 2 {
		t.Errorf("[09:01, 09:03) = %+v, want the rows of minutes 1 and 2", got)
	}

	if err := db.UpsertNodeMinute(ctx, NodeStat{NodeID: "no-such-node", TS: at(10, 9, 0)}); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpsertNodeMinute for an unknown node: err = %v, want ErrNotFound", err)
	}
}

// A reading that is not a number (a CPU load of 0 divided by 0, say) is stored as
// 0, instead of making the whole minute fail.
func TestUpsertNodeMinuteNonFiniteValues(t *testing.T) {
	db, node, _, _ := statsFixture(t)
	ctx := context.Background()
	s := fullNodeStat(node.ID, at(10, 9, 0))
	s.CPU, s.Load1 = math.NaN(), math.Inf(1)
	if err := db.UpsertNodeMinute(ctx, s); err != nil {
		t.Fatalf("UpsertNodeMinute: %v", err)
	}
	got, err := db.NodeSeries(ctx, node.ID, at(10, 9, 0), at(10, 10, 0), testRetention)
	if err != nil || len(got) != 1 {
		t.Fatalf("series = %+v, %v", got, err)
	}
	if got[0].CPU != 0 || got[0].Load1 != 0 || got[0].Conns != s.Conns {
		t.Errorf("stored cpu = %v, load1 = %v, conns = %d; want 0, 0 and the other values as they were", got[0].CPU, got[0].Load1, got[0].Conns)
	}
}

func TestNodeSeriesResolution(t *testing.T) {
	db, node, _, _ := statsFixture(t)
	end := at(10, 12, 0)
	putNodeStat(t, db, "stats_node_1m", node.ID, at(10, 11, 30), NodeStat{Conns: 1})
	putNodeStat(t, db, "stats_node_1h", node.ID, at(10, 11, 0), NodeStat{Conns: 2})
	putNodeStat(t, db, "stats_node_1d", node.ID, at(9, 0, 0), NodeStat{Conns: 3})
	for span, want := range map[time.Duration]uint32{
		time.Hour:                     1,
		48 * time.Hour:                1,
		48*time.Hour + time.Second:    2,
		7 * 24 * time.Hour:            2,
		90 * 24 * time.Hour:           2,
		90*24*time.Hour + time.Second: 3,
		365 * 24 * time.Hour:          3,
	} {
		got, err := db.NodeSeries(context.Background(), node.ID, end.Add(-span), end, testRetention)
		if err != nil {
			t.Fatal(err)
		}
		if want == 3 && len(got) == 2 && got[1].Conns == 2 {
			got = got[:1] // today has an hour but no day row: the series makes one up
		}
		if len(got) != 1 || got[0].Conns != want {
			t.Errorf("series over %s = %+v, want the row with conns = %d", span, got, want)
		}
	}
}

func TestRollupProxyStatsIntoHours(t *testing.T) {
	db, _, p, q := statsFixture(t)
	ctx := context.Background()
	put := func(proxy *Proxy, ts time.Time, up, down uint64, newConns, peak, devices uint32) {
		t.Helper()
		if err := db.UpsertProxyMinute(ctx, ProxyStat{ProxyID: proxy.ID, TS: ts, Up: up, Down: down, ConnsNew: newConns, ConnsPeak: peak, Devices: devices}); err != nil {
			t.Fatal(err)
		}
	}
	put(p, at(10, 9, 0), 10, 1, 1, 5, 2)
	put(p, at(10, 9, 1), 20, 2, 2, 9, 4)
	put(p, at(10, 9, 2), 30, 3, 3, 7, 3)
	put(p, at(10, 10, 30), 5, 5, 1, 1, 1)
	put(p, at(10, 12, 10), 100, 100, 100, 100, 100) // the hour that is not over yet
	put(q, at(10, 9, 5), 1, 1, 1, 1, 1)

	hours := func(proxy *Proxy) []ProxyStat {
		return series(t, db, proxy.ID, statsNow.Add(-7*24*time.Hour), statsNow) // 7 days: hourly rows
	}
	if got := hours(p); len(got) != 0 {
		t.Fatalf("hourly rows before the rollup: %+v", got)
	}

	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	wantP := []ProxyStat{
		{ProxyID: p.ID, TS: at(10, 9, 0), Up: 60, Down: 6, ConnsNew: 6, ConnsPeak: 9, Devices: 4}, // sums, and the highest
		{ProxyID: p.ID, TS: at(10, 10, 0), Up: 5, Down: 5, ConnsNew: 1, ConnsPeak: 1, Devices: 1},
	}
	if got := hours(p); !reflect.DeepEqual(got, wantP) {
		t.Errorf("hourly rows of p = %+v\nwant %+v", got, wantP)
	}
	wantQ := []ProxyStat{{ProxyID: q.ID, TS: at(10, 9, 0), Up: 1, Down: 1, ConnsNew: 1, ConnsPeak: 1, Devices: 1}}
	if got := hours(q); !reflect.DeepEqual(got, wantQ) {
		t.Errorf("hourly rows of q = %+v\nwant %+v", got, wantQ)
	}
	// The minutes stay for their 48 hours.
	if got := series(t, db, p.ID, at(10, 9, 0), at(10, 13, 0)); len(got) != 5 {
		t.Errorf("the rollup removed minute rows: %d left, want 5", len(got))
	}

	// Doing it again changes nothing.
	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatal(err)
	}
	if got := hours(p); !reflect.DeepEqual(got, wantP) {
		t.Errorf("hourly rows of p after a second rollup = %+v\nwant %+v", got, wantP)
	}

	// A minute that arrives late is counted by the next rollup.
	put(p, at(10, 9, 3), 40, 4, 4, 11, 6)
	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatal(err)
	}
	wantP[0] = ProxyStat{ProxyID: p.ID, TS: at(10, 9, 0), Up: 100, Down: 10, ConnsNew: 10, ConnsPeak: 11, Devices: 6}
	if got := hours(p); !reflect.DeepEqual(got, wantP) {
		t.Errorf("hourly rows of p after a late minute = %+v\nwant %+v", got, wantP)
	}

	// Once the hour is over, it is rolled up as well.
	if err := db.RollupStats(ctx, at(10, 13, 0), testRetention); err != nil {
		t.Fatal(err)
	}
	if up := proxyUp(t, db, "stats_proxy_1h", p.ID, at(10, 12, 0)); up != 100 {
		t.Errorf("hourly row of 12:00 = %d, want 100 once the hour is over", up)
	}
}

func TestRollupProxyStatsIntoDays(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(8, 0, 0), ProxyStat{Up: 10, Down: 1, ConnsNew: 2, ConnsPeak: 3, Devices: 2})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(8, 13, 0), ProxyStat{Up: 20, Down: 2, ConnsNew: 3, ConnsPeak: 8, Devices: 5})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(9, 23, 0), ProxyStat{Up: 7, Down: 7, ConnsNew: 7, ConnsPeak: 7, Devices: 7})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(10, 3, 0), ProxyStat{Up: 99}) // today, which is not over

	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	want := []ProxyStat{
		{ProxyID: p.ID, TS: at(8, 0, 0), Up: 30, Down: 3, ConnsNew: 5, ConnsPeak: 8, Devices: 5},
		{ProxyID: p.ID, TS: at(9, 0, 0), Up: 7, Down: 7, ConnsNew: 7, ConnsPeak: 7, Devices: 7},
	}
	// More than 90 days: daily rows (up to the end of yesterday: today has hours
	// but no day row yet, which a day series makes up from them).
	if got := series(t, db, p.ID, statsNow.Add(-120*24*time.Hour), at(10, 0, 0)); !reflect.DeepEqual(got, want) {
		t.Errorf("daily rows = %+v\nwant %+v", got, want)
	}

	// And again, with the same result.
	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatal(err)
	}
	if got := series(t, db, p.ID, statsNow.Add(-120*24*time.Hour), at(10, 0, 0)); !reflect.DeepEqual(got, want) {
		t.Errorf("daily rows after a second rollup = %+v\nwant %+v", got, want)
	}
}

// The daily rows are made of the hourly rows that the same call has just made.
func TestRollupMinutesToDaysInOneCall(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()
	for _, s := range []ProxyStat{
		{ProxyID: p.ID, TS: at(9, 9, 0), Up: 1, ConnsPeak: 4},
		{ProxyID: p.ID, TS: at(9, 15, 30), Up: 2, ConnsPeak: 6},
	} {
		if err := db.UpsertProxyMinute(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatal(err)
	}
	want := []ProxyStat{{ProxyID: p.ID, TS: at(9, 0, 0), Up: 3, ConnsPeak: 6}}
	if got := series(t, db, p.ID, statsNow.Add(-120*24*time.Hour), at(10, 0, 0)); !reflect.DeepEqual(got, want) {
		t.Errorf("daily rows = %+v\nwant %+v", got, want)
	}
}

// A row is replaced by a new rollup only while the rows that it was made from
// are all still there. The hour that PruneStats cuts in two, for example, has
// lost its first minutes, and rolling it up again would make its total smaller.
func TestRollupKeepsTotalsOfPartiallyPrunedPeriods(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()

	// The oldest minute that is kept is 10-08 12:30, so hours from 13:00 on are
	// whole, the hour of 12:00 is cut in two, and the hours before are gone.
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(8, 12, 0), ProxyStat{Up: 1000}) // the full total
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(8, 12, 40), ProxyStat{Up: 5})
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(8, 12, 50), ProxyStat{Up: 6})

	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(8, 11, 0), ProxyStat{Up: 7}) // never rolled up
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(8, 11, 30), ProxyStat{Up: 8})

	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(8, 13, 0), ProxyStat{Up: 1}) // stale, and whole
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(8, 13, 5), ProxyStat{Up: 50})

	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	if got := proxyUp(t, db, "stats_proxy_1h", p.ID, at(8, 12, 0)); got != 1000 {
		t.Errorf("the hour that was cut in two: up = %d, want its total of 1000 kept", got)
	}
	if got := proxyUp(t, db, "stats_proxy_1h", p.ID, at(8, 11, 0)); got != 15 {
		t.Errorf("an older hour that was never rolled up: up = %d, want 15", got)
	}
	if got := proxyUp(t, db, "stats_proxy_1h", p.ID, at(8, 13, 0)); got != 50 {
		t.Errorf("a whole hour: up = %d, want 50 (replaced)", got)
	}
}

// RollupStats makes days only of the hours that can still change, those of the
// 8 days that ingest takes minutes of and a day more (here from 2 October on),
// so the days of this test are within them: hours are kept for 7 days.
func TestRollupKeepsTotalsOfPartiallyPrunedDays(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()
	r := testRetention
	r.Hours = 7 * 24 * time.Hour

	// 7 days before statsNow is 3 October 12:30, so days from 4 October on are
	// whole, 3 October is cut in two, and the days before are gone.
	putProxyStat(t, db, "stats_proxy_1d", p.ID, at(3, 0, 0), ProxyStat{Up: 1000})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(3, 18, 0), ProxyStat{Up: 5})

	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(2, 1, 0), ProxyStat{Up: 7}) // never rolled up
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(2, 2, 0), ProxyStat{Up: 8})

	putProxyStat(t, db, "stats_proxy_1d", p.ID, at(4, 0, 0), ProxyStat{Up: 1}) // stale, and whole
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(4, 5, 0), ProxyStat{Up: 50})

	if err := db.RollupStats(ctx, statsNow, r); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	if got := proxyUp(t, db, "stats_proxy_1d", p.ID, at(3, 0, 0)); got != 1000 {
		t.Errorf("the day that was cut in two: up = %d, want its total of 1000 kept", got)
	}
	if got := proxyUp(t, db, "stats_proxy_1d", p.ID, at(2, 0, 0)); got != 15 {
		t.Errorf("an older day that was never rolled up: up = %d, want 15", got)
	}
	if got := proxyUp(t, db, "stats_proxy_1d", p.ID, at(4, 0, 0)); got != 50 {
		t.Errorf("a whole day: up = %d, want 50 (replaced)", got)
	}
}

// A day older than the hours that can still change is not made again by
// RollupStats, whole or not: ingest takes no minute of it any more. (PruneStats
// rolls up the days whose hours it deletes.)
func TestRollupLeavesTheDaysThatCannotChange(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	day := func(month, d, hour int) time.Time {
		return time.Date(2026, time.Month(month), d, hour, 0, 0, 0, time.UTC)
	}
	putProxyStat(t, db, "stats_proxy_1d", p.ID, day(9, 20, 0), ProxyStat{Up: 1}) // whole, at 90 days of hours
	putProxyStat(t, db, "stats_proxy_1h", p.ID, day(9, 20, 5), ProxyStat{Up: 50})
	putProxyStat(t, db, "stats_proxy_1d", p.ID, day(10, 5, 0), ProxyStat{Up: 1}) // within the last 8 days
	putProxyStat(t, db, "stats_proxy_1h", p.ID, day(10, 5, 5), ProxyStat{Up: 60})

	if err := db.RollupStats(context.Background(), statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	if got := proxyUp(t, db, "stats_proxy_1d", p.ID, day(9, 20, 0)); got != 1 {
		t.Errorf("a day of 20 days ago: up = %d, want it left as it was", got)
	}
	if got := proxyUp(t, db, "stats_proxy_1d", p.ID, day(10, 5, 0)); got != 60 {
		t.Errorf("a day of 5 days ago: up = %d, want 60 (made again)", got)
	}
}

// The same, for the load of a node.
func TestRollupKeepsNodeTotalsOfPartiallyPrunedPeriods(t *testing.T) {
	db, node, _, _ := statsFixture(t)
	ctx := context.Background()
	netRx := func(table string, ts time.Time) int {
		t.Helper()
		var rx int
		if err := db.sql.QueryRow(`SELECT net_rx FROM `+table+` WHERE node_id = ? AND ts = ?`, node.ID, ts.Unix()).Scan(&rx); err != nil {
			return -1
		}
		return rx
	}
	r := testRetention
	r.Hours = 7 * 24 * time.Hour // so that the days are among those that RollupStats makes

	// The hour of 12:00 on 8 October is cut by the cutoff of 12:30, and the day of
	// 3 October is cut by the cutoff for hours.
	putNodeStat(t, db, "stats_node_1h", node.ID, at(8, 12, 0), NodeStat{NetRx: 1000})
	putNodeStat(t, db, "stats_node_1m", node.ID, at(8, 12, 40), NodeStat{NetRx: 5})
	putNodeStat(t, db, "stats_node_1d", node.ID, at(3, 0, 0), NodeStat{NetRx: 1000})
	putNodeStat(t, db, "stats_node_1h", node.ID, at(3, 18, 0), NodeStat{NetRx: 5})
	// Whole periods are replaced.
	putNodeStat(t, db, "stats_node_1h", node.ID, at(8, 13, 0), NodeStat{NetRx: 1})
	putNodeStat(t, db, "stats_node_1m", node.ID, at(8, 13, 5), NodeStat{NetRx: 50})
	putNodeStat(t, db, "stats_node_1d", node.ID, at(4, 0, 0), NodeStat{NetRx: 1})
	putNodeStat(t, db, "stats_node_1h", node.ID, at(4, 5, 0), NodeStat{NetRx: 60})

	if err := db.RollupStats(ctx, statsNow, r); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	for _, tt := range []struct {
		table string
		ts    time.Time
		want  int
	}{
		{"stats_node_1h", at(8, 12, 0), 1000},
		{"stats_node_1h", at(8, 13, 0), 50},
		{"stats_node_1d", at(3, 0, 0), 1000},
		{"stats_node_1d", at(4, 0, 0), 60},
	} {
		if got := netRx(tt.table, tt.ts); got != tt.want {
			t.Errorf("%s at %s: net_rx = %d, want %d", tt.table, tt.ts.Format(time.DateTime), got, tt.want)
		}
	}
}

// RollupStats before PruneStats, with the same time, loses nothing.
func TestRollupThenPruneKeepsHourlyTotals(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()
	for _, s := range []ProxyStat{
		{ProxyID: p.ID, TS: at(8, 11, 10), Up: 1},
		{ProxyID: p.ID, TS: at(8, 12, 10), Up: 100}, // before the cutoff of 12:30
		{ProxyID: p.ID, TS: at(8, 12, 40), Up: 50},
	} {
		if err := db.UpsertProxyMinute(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 { // twice: the second time the hour of 12:00 is cut in two
		if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
			t.Fatal(err)
		}
		if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
			t.Fatal(err)
		}
		if got := proxyUp(t, db, "stats_proxy_1h", p.ID, at(8, 11, 0)); got != 1 {
			t.Errorf("round %d: hour 11:00 = %d, want 1", i, got)
		}
		if got := proxyUp(t, db, "stats_proxy_1h", p.ID, at(8, 12, 0)); got != 150 {
			t.Errorf("round %d: hour 12:00 = %d, want 150", i, got)
		}
	}
	if got := count(t, db, `SELECT count(*) FROM stats_proxy_1m`); got != 1 {
		t.Errorf("%d minute rows left, want only the one from 12:40", got)
	}
}

// PruneStats does not lose a total when RollupStats has not run before it.
func TestPruneStatsRollsUpWhatItDeletes(t *testing.T) {
	db, node, p, _ := statsFixture(t)
	ctx := context.Background()
	day := func(month, d, hour int) time.Time {
		return time.Date(2026, time.Month(month), d, hour, 0, 0, 0, time.UTC)
	}

	// Minutes: the hour of 11:00 is older than the cutoff of 12:30 (10 October
	// minus 48 hours), and the hour of 12:00 is cut by it.
	for _, s := range []ProxyStat{
		{ProxyID: p.ID, TS: at(8, 11, 10), Up: 1},
		{ProxyID: p.ID, TS: at(8, 11, 50), Up: 2},
		{ProxyID: p.ID, TS: at(8, 12, 10), Up: 100},
		{ProxyID: p.ID, TS: at(8, 12, 40), Up: 50},
	} {
		if err := db.UpsertProxyMinute(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertNodeMinute(ctx, NodeStat{NodeID: node.ID, TS: at(8, 11, 10), NetRx: 7, Conns: 3}); err != nil {
		t.Fatal(err)
	}
	// Hours: 12 July 12:30 is the cutoff; the day of 11 July is older than it, the
	// day of 12 July is cut by it.
	putProxyStat(t, db, "stats_proxy_1h", p.ID, day(7, 11, 1), ProxyStat{Up: 7})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, day(7, 11, 2), ProxyStat{Up: 8})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, day(7, 12, 9), ProxyStat{Up: 20})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, day(7, 12, 18), ProxyStat{Up: 5})

	if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}

	for _, tt := range []struct {
		table string
		ts    time.Time
		want  int
	}{
		{"stats_proxy_1h", at(8, 11, 0), 3},
		{"stats_proxy_1h", at(8, 12, 0), 150}, // the whole hour, also the minutes that were kept
		{"stats_proxy_1d", day(7, 11, 0), 15},
		{"stats_proxy_1d", day(7, 12, 0), 25},
	} {
		if got := proxyUp(t, db, tt.table, p.ID, tt.ts); got != tt.want {
			t.Errorf("%s at %s: up = %d, want %d", tt.table, tt.ts.Format(time.DateTime), got, tt.want)
		}
	}
	var rx int
	if err := db.sql.QueryRow(`SELECT net_rx FROM stats_node_1h WHERE node_id = ? AND ts = ?`, node.ID, at(8, 11, 0).Unix()).Scan(&rx); err != nil || rx != 7 {
		t.Errorf("hourly row of the node: net_rx = %d, %v; want 7", rx, err)
	}
	// What was deleted is gone.
	if got := count(t, db, `SELECT count(*) FROM stats_proxy_1m`); got != 1 {
		t.Errorf("%d minute rows left, want only the one from 12:40", got)
	}
	if got := count(t, db, `SELECT count(*) FROM stats_proxy_1h WHERE ts < ?`, day(7, 12, 0).Add(12*time.Hour).Unix()); got != 0 {
		t.Errorf("%d hourly rows from before the cutoff are left", got)
	}
}

func TestRollupNodeStats(t *testing.T) {
	db, node, _, _ := statsFixture(t)
	ctx := context.Background()
	for _, s := range []NodeStat{
		{NodeID: node.ID, TS: at(10, 9, 0), CPU: 10, MemUsed: 100, MemTotal: 1000, Load1: 0.5, DiskUsed: 10, DiskTotal: 100, NetRx: 5, NetTx: 1, Conns: 4},
		{NodeID: node.ID, TS: at(10, 9, 1), CPU: 30, MemUsed: 201, MemTotal: 2000, Load1: 1.5, DiskUsed: 20, DiskTotal: 200, NetRx: 6, NetTx: 2, Conns: 9},
	} {
		if err := db.UpsertNodeMinute(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	// Gauges are averaged, sizes and the connection peak take the highest value,
	// and traffic is summed.
	want := NodeStat{NodeID: node.ID, TS: at(10, 9, 0), CPU: 20, MemUsed: 151, MemTotal: 2000, Load1: 1, DiskUsed: 15, DiskTotal: 200, NetRx: 11, NetTx: 3, Conns: 9}

	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	hourly := func() []NodeStat {
		got, err := db.NodeSeries(ctx, node.ID, statsNow.Add(-7*24*time.Hour), statsNow, testRetention)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := hourly(); !reflect.DeepEqual(got, []NodeStat{want}) {
		t.Errorf("hourly rows = %+v\nwant %+v", got, []NodeStat{want})
	}
	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatal(err)
	}
	if got := hourly(); !reflect.DeepEqual(got, []NodeStat{want}) {
		t.Errorf("hourly rows after a second rollup = %+v", got)
	}

	// Days are made of hours in the same way.
	putNodeStat(t, db, "stats_node_1h", node.ID, at(8, 0, 0), NodeStat{CPU: 10, MemUsed: 100, MemTotal: 1000, Load1: 0.5, DiskUsed: 10, DiskTotal: 100, NetRx: 5, NetTx: 1, Conns: 4})
	putNodeStat(t, db, "stats_node_1h", node.ID, at(8, 13, 0), NodeStat{CPU: 30, MemUsed: 201, MemTotal: 2000, Load1: 1.5, DiskUsed: 20, DiskTotal: 200, NetRx: 6, NetTx: 2, Conns: 9})
	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatal(err)
	}
	wantDay := want
	wantDay.TS = at(8, 0, 0)
	daily, err := db.NodeSeries(ctx, node.ID, statsNow.Add(-120*24*time.Hour), at(10, 0, 0), testRetention)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(daily, []NodeStat{wantDay}) {
		t.Errorf("daily rows = %+v\nwant %+v", daily, []NodeStat{wantDay})
	}
}

func TestRollupOfNothing(t *testing.T) {
	db := newTestDB(t)
	if err := db.RollupStats(context.Background(), statsNow, testRetention); err != nil {
		t.Errorf("RollupStats on an empty database: %v", err)
	}
	if err := db.PruneStats(context.Background(), statsNow, testRetention); err != nil {
		t.Errorf("PruneStats on an empty database: %v", err)
	}
}

func TestPruneStats(t *testing.T) {
	db, node, p, _ := statsFixture(t)
	storePolicy(t, db, IPPolicyFull) // under which where addresses were seen is kept for its time
	ctx := context.Background()
	ago := func(d time.Duration) time.Time { return statsNow.Add(-d) }
	const day = 24 * time.Hour

	// Minutes are kept for 48 hours, hours for 90 days and days for good, counted
	// back from now to the second.
	rows := []struct {
		table string // the resolution: 1m, 1h or 1d
		age   time.Duration
		kept  bool
		what  string
	}{
		{"1m", 48*time.Hour + time.Minute, false, "a minute of more than 48 hours"},
		{"1m", 48 * time.Hour, true, "a minute of exactly 48 hours"},
		{"1m", 47 * time.Hour, true, "a minute of 47 hours"},
		{"1m", 0, true, "the minute of now"},
		{"1h", 90*day + time.Hour, false, "an hour of more than 90 days"},
		{"1h", 90*day - time.Hour, true, "an hour of a little less than 90 days"},
		{"1h", 89 * day, true, "an hour of 89 days"},
		{"1d", 3000 * day, true, "a day of 3000 days ago"},
		{"1d", 400 * day, true, "a day of 400 days ago"},
		{"1d", day, true, "yesterday"},
	}
	for _, r := range rows {
		putProxyStat(t, db, "stats_proxy_"+r.table, p.ID, ago(r.age), ProxyStat{Up: 1})
		putNodeStat(t, db, "stats_node_"+r.table, node.ID, ago(r.age), NodeStat{Conns: 1})
	}
	// Where addresses were seen: 7 days, by the last sighting.
	sightings := []struct {
		ip   string
		age  time.Duration
		kept bool
	}{
		{"192.0.2.1", 7*day + time.Second, false},
		{"192.0.2.2", 7 * day, true},
		{"192.0.2.3", day, true},
	}
	for _, s := range sightings {
		mustExec(t, db, `INSERT INTO ip_sightings (proxy_id, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)`,
			p.ID, s.ip, ago(30*day).Unix(), ago(s.age).Unix())
	}

	if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}

	for _, r := range rows {
		for _, q := range []struct{ table, idColumn, id string }{
			{"stats_proxy_" + r.table, "proxy_id", p.ID},
			{"stats_node_" + r.table, "node_id", node.ID},
		} {
			n := count(t, db, `SELECT count(*) FROM `+q.table+` WHERE `+q.idColumn+` = ? AND ts = ?`, q.id, ago(r.age).Unix())
			if kept := n == 1; kept != r.kept {
				t.Errorf("%s, %s: kept = %v, want %v", q.table, r.what, kept, r.kept)
			}
		}
	}
	for _, s := range sightings {
		n := count(t, db, `SELECT count(*) FROM ip_sightings WHERE ip = ?`, s.ip)
		if kept := n == 1; kept != s.kept {
			t.Errorf("sighting of %s last seen %s ago: kept = %v, want %v", s.ip, s.age, kept, s.kept)
		}
	}
}

// cappedCounter is the most that a counter is stored as: 2^50, about a petabyte
// per minute. It is written out here, and not taken from the code under test, so
// that a test fails if the number changes by accident.
const cappedCounter = 1 << 50

// A node that counts wrong, say a counter that went backwards and was
// subtracted as an unsigned number, can send a value that no SQLite integer
// holds. Rollups add counters up with SUM, which stops with "integer overflow"
// when a total leaves int64, and one such error would fail every rollup and
// every prune, of every proxy and node, for good. So a counter is stored as at
// most 2^50, whatever it is sent.
func TestHugeCountersDoNotBreakRollupOrPrune(t *testing.T) {
	ctx := context.Background()
	hour := at(8, 11, 0) // more than 48 hours before statsNow, so PruneStats rolls it up as well

	seed := func(t *testing.T) (*DB, *Node, *Proxy) {
		t.Helper()
		db, node, p, _ := statsFixture(t)
		for _, minute := range []int{10, 20} { // two minutes of one hour
			if err := db.UpsertProxyMinute(ctx, ProxyStat{
				ProxyID: p.ID, TS: at(8, 11, minute), Up: math.MaxUint64, Down: math.MaxUint64,
				ConnsNew: math.MaxUint32, ConnsPeak: math.MaxUint32, Devices: math.MaxUint32,
			}); err != nil {
				t.Fatalf("UpsertProxyMinute: %v", err)
			}
			if err := db.UpsertNodeMinute(ctx, NodeStat{
				NodeID: node.ID, TS: at(8, 11, minute), CPU: 100, Load1: 1,
				MemUsed: math.MaxUint64, MemTotal: math.MaxUint64, DiskUsed: math.MaxUint64, DiskTotal: math.MaxUint64,
				NetRx: math.MaxUint64, NetTx: math.MaxUint64, Conns: math.MaxUint32,
			}); err != nil {
				t.Fatalf("UpsertNodeMinute: %v", err)
			}
		}
		return db, node, p
	}
	// checkHour looks at the hourly rows, which are the series of seven days.
	checkHour := func(t *testing.T, db *DB, node *Node, p *Proxy) {
		t.Helper()
		from := statsNow.Add(-7 * 24 * time.Hour)
		ps := series(t, db, p.ID, from, statsNow)
		ns, err := db.NodeSeries(ctx, node.ID, from, statsNow, testRetention)
		if err != nil {
			t.Fatal(err)
		}
		if len(ps) != 1 || len(ns) != 1 {
			t.Fatalf("hourly rows: %d of the proxy and %d of the node, want one each", len(ps), len(ns))
		}
		if !ps[0].TS.Equal(hour) || ps[0].Up != 2*cappedCounter || ps[0].Down != 2*cappedCounter {
			t.Errorf("hourly row of the proxy = %+v, want %s with up and down of 2 * 2^50", ps[0], hour)
		}
		n := ns[0]
		if n.NetRx != 2*cappedCounter || n.NetTx != 2*cappedCounter {
			t.Errorf("hourly traffic of the node: rx = %d, tx = %d, want 2 * 2^50", n.NetRx, n.NetTx)
		}
		if n.MemUsed != cappedCounter || n.MemTotal != cappedCounter || n.DiskUsed != cappedCounter || n.DiskTotal != cappedCounter {
			t.Errorf("hourly sizes of the node = %+v, want every one 2^50", n)
		}
	}

	t.Run("stored as the cap", func(t *testing.T) {
		db, node, p := seed(t)
		for _, s := range series(t, db, p.ID, hour, hour.Add(time.Hour)) {
			if s.Up != cappedCounter || s.Down != cappedCounter || s.ConnsNew != math.MaxUint32 {
				t.Errorf("minute of the proxy = %+v, want up and down of 2^50 and the small counters as they were", s)
			}
		}
		ns, err := db.NodeSeries(ctx, node.ID, hour, hour.Add(time.Hour), testRetention)
		if err != nil || len(ns) != 2 {
			t.Fatalf("minutes of the node = %+v, %v; want two", ns, err)
		}
		for _, s := range ns {
			if s.NetRx != cappedCounter || s.NetTx != cappedCounter || s.MemUsed != cappedCounter || s.DiskTotal != cappedCounter {
				t.Errorf("minute of the node = %+v, want every counter and size at 2^50", s)
			}
		}
	})
	t.Run("RollupStats then PruneStats", func(t *testing.T) {
		db, node, p := seed(t)
		if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
			t.Fatalf("RollupStats: %v", err)
		}
		checkHour(t, db, node, p)
		if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
			t.Fatalf("PruneStats: %v", err)
		}
		checkHour(t, db, node, p)
		if n := count(t, db, `SELECT count(*) FROM stats_proxy_1m`) + count(t, db, `SELECT count(*) FROM stats_node_1m`); n != 0 {
			t.Errorf("%d minute rows are left, want the two old minutes of each pruned", n)
		}
	})
	t.Run("PruneStats alone", func(t *testing.T) {
		db, node, p := seed(t)
		if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
			t.Fatalf("PruneStats: %v", err)
		}
		checkHour(t, db, node, p) // rolled up by the prune itself
		if n := count(t, db, `SELECT count(*) FROM stats_proxy_1m`) + count(t, db, `SELECT count(*) FROM stats_node_1m`); n != 0 {
			t.Errorf("%d minute rows are left, want the two old minutes of each pruned", n)
		}
	})
}

// The most that rollups ever add up: a whole day of minutes that all hold the
// cap. That is 1440 * 2^50, which is far inside int64, and the days of the
// hours are made of the same hours.
func TestRollupOfADayAtTheCap(t *testing.T) {
	db, node, p, _ := statsFixture(t)
	ctx := context.Background()
	day := at(8, 0, 0)
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for m := range 24 * 60 {
		ts := day.Add(time.Duration(m) * time.Minute).Unix()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO stats_proxy_1m (proxy_id, ts, up, down, conns_new, conns_peak, devices) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			p.ID, ts, int64(cappedCounter), int64(cappedCounter), int64(math.MaxUint32), int64(math.MaxUint32), int64(math.MaxUint32)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO stats_node_1m (node_id, ts, net_rx, net_tx) VALUES (?, ?, ?, ?)`,
			node.ID, ts, int64(cappedCounter), int64(cappedCounter)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	const wantDay = 24 * 60 * cappedCounter
	if got := proxyUp(t, db, "stats_proxy_1d", p.ID, day); got != wantDay {
		t.Errorf("up of the day = %d, want %d", got, int64(wantDay))
	}
	var rxBytes, txBytes int64
	if err := db.sql.QueryRow(`SELECT net_rx, net_tx FROM stats_node_1d WHERE node_id = ? AND ts = ?`, node.ID, day.Unix()).Scan(&rxBytes, &txBytes); err != nil {
		t.Fatal(err)
	}
	if rxBytes != wantDay || txBytes != wantDay {
		t.Errorf("traffic of the day = %d and %d, want %d", rxBytes, txBytes, int64(wantDay))
	}
	if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
		t.Errorf("PruneStats: %v", err)
	}
}

// UpsertMinutes stores a whole batch of a node in one transaction: every proxy
// minute and the node minute, skipping what is gone, or nothing at all.
func TestUpsertMinutes(t *testing.T) {
	db, node, p, q := statsFixture(t)
	ctx := context.Background()
	m := at(10, 12, 0)
	rows := []ProxyStat{
		{ProxyID: p.ID, TS: m, Up: 1, Down: 2, ConnsNew: 3, ConnsPeak: 4, Devices: 5},
		{ProxyID: "01K6Y00000000000000000000Z", TS: m, Up: 9}, // deleted meanwhile
		{ProxyID: q.ID, TS: m.Add(30 * time.Second), Up: 10},  // stored under the start of its minute
	}
	gone, err := db.UpsertMinutes(ctx, rows, &NodeStat{NodeID: node.ID, TS: m, CPU: 1.5, Conns: 7})
	if err != nil {
		t.Fatalf("UpsertMinutes: %v", err)
	}
	if !reflect.DeepEqual(gone, []string{"01K6Y00000000000000000000Z"}) {
		t.Errorf("gone = %v, want the proxy that is not there", gone)
	}
	if up := proxyUp(t, db, "stats_proxy_1m", p.ID, m); up != 1 {
		t.Errorf("up of p = %d, want 1", up)
	}
	if up := proxyUp(t, db, "stats_proxy_1m", q.ID, m); up != 10 {
		t.Errorf("up of q = %d, want 10", up)
	}
	if c := count(t, db, `SELECT count(*) FROM stats_node_1m WHERE node_id = ? AND conns = 7`, node.ID); c != 1 {
		t.Errorf("%d node minutes, want 1", c)
	}

	// Stored again, the minutes are replaced, not added to.
	rows[0].Up = 100
	if _, err := db.UpsertMinutes(ctx, rows[:1], nil); err != nil {
		t.Fatalf("UpsertMinutes again: %v", err)
	}
	if up := proxyUp(t, db, "stats_proxy_1m", p.ID, m); up != 100 {
		t.Errorf("up of p after a second batch = %d, want 100", up)
	}

	// A node that is gone has its minute skipped, and is no error.
	if _, err := db.UpsertMinutes(ctx, nil, &NodeStat{NodeID: "01K6Y0000000000000000000NZ", TS: m}); err != nil {
		t.Errorf("UpsertMinutes for a node that is gone: %v", err)
	}

	// A batch that fails in the middle leaves nothing of it behind.
	mustExec(t, db, `CREATE TRIGGER refuse_node_minutes BEFORE INSERT ON stats_node_1m BEGIN SELECT RAISE(ABORT, 'refused by the test'); END`)
	next := m.Add(time.Minute)
	_, err = db.UpsertMinutes(ctx, []ProxyStat{{ProxyID: p.ID, TS: next, Up: 1}, {ProxyID: q.ID, TS: next, Up: 1}},
		&NodeStat{NodeID: node.ID, TS: next})
	if err == nil {
		t.Fatal("UpsertMinutes with a node minute that the database refuses: no error")
	}
	if c := count(t, db, `SELECT count(*) FROM stats_proxy_1m WHERE ts = ?`, next.Unix()); c != 0 {
		t.Errorf("%d proxy minutes of a batch that failed were stored, want none", c)
	}
}
