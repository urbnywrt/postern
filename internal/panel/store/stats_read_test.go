package store

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// twoNodes is two nodes: n with the proxies p and q, and n2 with r.
func twoNodes(t *testing.T) (db *DB, n, n2 *Node, p, q, r *Proxy) {
	t.Helper()
	db = newTestDB(t)
	n, n2 = mustNode(t, db, "n"), mustNode(t, db, "n2")
	l, l2 := mustListener(t, db, n.ID, 443), mustListener(t, db, n2.ID, 443)
	return db, n, n2, mustProxy(t, db, n.ID, l.ID, "p"), mustProxy(t, db, n.ID, l.ID, "q"), mustProxy(t, db, n2.ID, l2.ID, "r")
}

// The resolution of a series follows the retention that it is given.
func TestSeriesResolutionFollowsRetention(t *testing.T) {
	db, node, p, _ := statsFixture(t)
	end := at(10, 12, 0)
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 11, 30), ProxyStat{Up: 1})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(10, 11, 0), ProxyStat{Up: 2})
	putProxyStat(t, db, "stats_proxy_1d", p.ID, at(9, 0, 0), ProxyStat{Up: 3})
	putNodeStat(t, db, "stats_node_1m", node.ID, at(10, 11, 30), NodeStat{Conns: 1})
	putNodeStat(t, db, "stats_node_1h", node.ID, at(10, 11, 0), NodeStat{Conns: 2})
	putNodeStat(t, db, "stats_node_1d", node.ID, at(9, 0, 0), NodeStat{Conns: 3})

	short := Retention{Minutes: 6 * time.Hour, Hours: 7 * 24 * time.Hour, IPs: 24 * time.Hour}
	for _, tt := range []struct {
		span time.Duration
		want uint64
	}{
		{6 * time.Hour, 1},
		{6*time.Hour + time.Second, 2}, // 48 h would still be minutes by default
		{7 * 24 * time.Hour, 2},
		{7*24*time.Hour + time.Second, 3}, // 90 d would still be hours by default
	} {
		got, err := db.ProxySeries(context.Background(), p.ID, end.Add(-tt.span), end, short)
		if tt.want == 3 && len(got) == 2 && got[1].Up == 2 {
			got = got[:1] // Oct 10 has an hour but no day row: made up from it
		}
		if err != nil || len(got) != 1 || got[0].Up != tt.want {
			t.Errorf("ProxySeries over %s = %+v, %v; want the row with up = %d", tt.span, got, err, tt.want)
		}
		ns, err := db.NodeSeries(context.Background(), node.ID, end.Add(-tt.span), end, short)
		if tt.want == 3 && len(ns) == 2 && ns[1].Conns == 2 {
			ns = ns[:1]
		}
		if err != nil || len(ns) != 1 || uint64(ns[0].Conns) != tt.want {
			t.Errorf("NodeSeries over %s = %+v, %v; want the row with conns = %d", tt.span, ns, err, tt.want)
		}
	}
	long := Retention{Minutes: 168 * time.Hour, Hours: 730 * 24 * time.Hour}
	if got, _ := db.ProxySeries(context.Background(), p.ID, end.Add(-100*time.Hour), end, long); len(got) != 1 || got[0].Up != 1 {
		t.Errorf("a longer retention reads minutes for 100 h: %+v", got)
	}
}

// A day that has hour rows but no day row (the panel was down for longer than
// hours wait for their day) is made of its hours; a day that has a row is not
// counted twice.
func TestDaySeriesAddsDaysThatHaveOnlyHours(t *testing.T) {
	db, node, p, _ := statsFixture(t)
	ctx := context.Background()
	to := at(10, 0, 0)
	from := to.Add(-5 * 24 * time.Hour) // Oct 5, longer than the hours of testRetention below
	short := Retention{Minutes: 6 * time.Hour, Hours: 24 * time.Hour}

	// Oct 6 has its day row and also hours (which must not be added to it).
	putProxyStat(t, db, "stats_proxy_1d", p.ID, at(6, 0, 0), ProxyStat{Up: 100, ConnsPeak: 9, Devices: 3})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(6, 5, 0), ProxyStat{Up: 1000})
	// Oct 7 has hours only.
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(7, 3, 0), ProxyStat{Up: 7, Down: 1, ConnsNew: 2, ConnsPeak: 5, Devices: 4})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(7, 4, 0), ProxyStat{Up: 8, Down: 2, ConnsNew: 3, ConnsPeak: 6, Devices: 2})
	// Oct 4 is before the range: its hours stay out.
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(4, 3, 0), ProxyStat{Up: 5000})

	got, err := db.ProxySeries(ctx, p.ID, from, to, short)
	if err != nil {
		t.Fatal(err)
	}
	want := []ProxyStat{
		{ProxyID: p.ID, TS: at(6, 0, 0), Up: 100, ConnsPeak: 9, Devices: 3},
		{ProxyID: p.ID, TS: at(7, 0, 0), Up: 15, Down: 3, ConnsNew: 5, ConnsPeak: 6, Devices: 4},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ProxySeries = %+v, want %+v", got, want)
	}

	putNodeStat(t, db, "stats_node_1d", node.ID, at(6, 0, 0), NodeStat{CPU: 50, Conns: 1})
	putNodeStat(t, db, "stats_node_1h", node.ID, at(6, 5, 0), NodeStat{CPU: 99, Conns: 99})
	putNodeStat(t, db, "stats_node_1h", node.ID, at(7, 3, 0), NodeStat{CPU: 10, MemUsed: 100, NetRx: 5, Conns: 8, RefusedTotal: 1})
	putNodeStat(t, db, "stats_node_1h", node.ID, at(7, 4, 0), NodeStat{CPU: 30, MemUsed: 300, NetRx: 6, Conns: 4, RefusedTotal: 2})
	ns, err := db.NodeSeries(ctx, node.ID, from, to, short)
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 2 || ns[0].CPU != 50 || ns[0].Conns != 1 {
		t.Fatalf("NodeSeries = %+v; want the day row of Oct 6 first", ns)
	}
	if d := ns[1]; d.TS != at(7, 0, 0) || d.CPU != 20 || d.MemUsed != 200 || d.NetRx != 11 || d.Conns != 8 || d.RefusedTotal != 3 {
		t.Errorf("the day of Oct 7 made of hours = %+v", d)
	}
}

func TestNodeTraffic(t *testing.T) {
	db, n, n2, p, q, r := twoNodes(t)
	ctx := context.Background()
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 9, 0), ProxyStat{Up: 1, Down: 10, Devices: 2})
	putProxyStat(t, db, "stats_proxy_1m", q.ID, at(10, 9, 0), ProxyStat{Up: 2, Down: 20, Devices: 3})
	putProxyStat(t, db, "stats_proxy_1m", q.ID, at(10, 9, 1), ProxyStat{Up: 4, Down: 40, Devices: 1})
	putProxyStat(t, db, "stats_proxy_1m", r.ID, at(10, 9, 0), ProxyStat{Up: 1000, Down: 1000, Devices: 100})
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 10, 0), ProxyStat{Up: 99}) // out of range

	got, err := db.NodeTraffic(ctx, n.ID, at(10, 9, 0), at(10, 10, 0), testRetention)
	if err != nil {
		t.Fatal(err)
	}
	want := []NodeTraffic{
		{TS: at(10, 9, 0), Up: 3, Down: 30, DevicesSum: 5},
		{TS: at(10, 9, 1), Up: 4, Down: 40, DevicesSum: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NodeTraffic(n) = %+v, want %+v", got, want)
	}
	got, _ = db.NodeTraffic(ctx, n2.ID, at(10, 9, 0), at(10, 10, 0), testRetention)
	if len(got) != 1 || got[0].Up != 1000 || got[0].DevicesSum != 100 {
		t.Errorf("NodeTraffic(n2) = %+v", got)
	}
	// Hours: the same sums.
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(8, 5, 0), ProxyStat{Up: 6, Devices: 2})
	putProxyStat(t, db, "stats_proxy_1h", q.ID, at(8, 5, 0), ProxyStat{Up: 7, Devices: 5})
	got, _ = db.NodeTraffic(ctx, n.ID, at(3, 0, 0), at(10, 0, 0), testRetention)
	if len(got) != 1 || got[0].Up != 13 || got[0].DevicesSum != 7 {
		t.Errorf("NodeTraffic over 7 days = %+v", got)
	}
}

// Totals take whole hours from the hour rows and add the minutes of the partial
// hours at both ends, and of the hour that is not rolled up yet; the minutes of
// the hours in between are not counted again.
func TestTotalsPartialHours(t *testing.T) {
	db, n, n2, p, q, r := twoNodes(t)
	ctx := context.Background()
	since := at(9, 20, 30) // the local midnight of UTC+03:30
	now := at(10, 12, 30)

	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(9, 20, 10), ProxyStat{Up: 1000})                   // before since
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(9, 20, 40), ProxyStat{Up: 3, Down: 1, Devices: 1}) // first partial hour
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(9, 20, 0), ProxyStat{Up: 2000})                    // the hour holding since: its minutes are read
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(9, 21, 0), ProxyStat{Up: 10, Down: 2, ConnsNew: 5, Devices: 4})
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 3, 10), ProxyStat{Up: 777}) // inside a whole hour
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(10, 11, 0), ProxyStat{Up: 20, ConnsNew: 1, Devices: 6})
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 12, 10), ProxyStat{Up: 5, ConnsNew: 2, Devices: 7}) // not rolled up yet
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 12, 40), ProxyStat{Up: 5000})                       // after now
	putProxyStat(t, db, "stats_proxy_1h", q.ID, at(10, 0, 0), ProxyStat{Up: 100, Down: 100, Devices: 5})
	putProxyStat(t, db, "stats_proxy_1h", r.ID, at(10, 1, 0), ProxyStat{Up: 1, Devices: 1})

	got, err := db.TrafficSince(ctx, since, now)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]ProxyTotal{
		n.ID:  {Up: 3 + 10 + 20 + 5 + 100, Down: 1 + 2 + 100, ConnsNew: 5 + 1 + 2, DevicesPeak: 7},
		n2.ID: {Up: 1, DevicesPeak: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TrafficSince = %+v, want %+v", got, want)
	}

	top, err := db.TopProxies(ctx, "", since, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantTop := []ProxyTotal{
		{ProxyID: q.ID, Up: 100, Down: 100, DevicesPeak: 5},
		{ProxyID: p.ID, Up: 38, Down: 3, ConnsNew: 8, DevicesPeak: 7},
		{ProxyID: r.ID, Up: 1, DevicesPeak: 1},
	}
	if !reflect.DeepEqual(top, wantTop) {
		t.Errorf("TopProxies = %+v, want %+v", top, wantTop)
	}
	if top, _ = db.TopProxies(ctx, "", since, now, 2); len(top) != 2 || top[1].ProxyID != p.ID {
		t.Errorf("TopProxies(limit 2) = %+v", top)
	}
	if top, _ = db.TopProxies(ctx, n2.ID, since, now, 5); len(top) != 1 || top[0].ProxyID != r.ID {
		t.Errorf("TopProxies(n2) = %+v", top)
	}
	// A range inside one hour reads minutes only.
	if top, _ = db.TopProxies(ctx, "", at(10, 12, 0), now, 5); len(top) != 1 || top[0].Up != 5 {
		t.Errorf("TopProxies(12:00-12:30) = %+v", top)
	}
}

// Beyond the hours that are kept, whole days come from the day rows, a day
// that only has hours from its hours, and the hours and minutes at the ends.
func TestTotalsDays(t *testing.T) {
	db, n, _, p, _, _ := twoNodes(t)
	ctx := context.Background()
	s := DefaultStatsSettings()
	s.HoursDays = 7
	if _, err := db.ApplyStatsSettings(ctx, s); err != nil {
		t.Fatal(err)
	}
	from, now := at(1, 0, 30), at(10, 12, 30) // 9.5 days > 7

	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(1, 0, 30), ProxyStat{Up: 1})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(1, 5, 0), ProxyStat{Up: 10})
	for d := 2; d <= 9; d++ {
		if d == 5 {
			continue
		}
		putProxyStat(t, db, "stats_proxy_1d", p.ID, at(d, 0, 0), ProxyStat{Up: 100})
	}
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(3, 4, 0), ProxyStat{Up: 999}) // inside a day with a row
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(5, 3, 0), ProxyStat{Up: 7})   // a day without its row
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(10, 3, 0), ProxyStat{Up: 20})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(10, 11, 0), ProxyStat{Up: 30})
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 3, 10), ProxyStat{Up: 555})
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 12, 10), ProxyStat{Up: 4})

	got, err := db.TrafficSince(ctx, from, now)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(1 + 10 + 7*100 + 7 + 20 + 30 + 4); got[n.ID].Up != want {
		t.Errorf("TrafficSince over 9.5 days: up = %d, want %d", got[n.ID].Up, want)
	}
}

func TestCountryTotals(t *testing.T) {
	db, _, n2, p, q, r := twoNodes(t)
	ctx := context.Background()
	from, to := at(10, 9, 30), at(10, 12, 30)

	putCountry(t, db, "stats_country_1h", p.ID, at(10, 9, 0), "DE", 50, 1000) // the hour holding from: minutes are read
	putCountry(t, db, "stats_country_1m", p.ID, at(10, 9, 40), "DE", 3, 5)
	putCountry(t, db, "stats_country_1m", q.ID, at(10, 9, 40), "DE", 2, 5)
	putCountry(t, db, "stats_country_1m", p.ID, at(10, 9, 10), "DE", 99, 999) // before from
	putCountry(t, db, "stats_country_1h", p.ID, at(10, 10, 0), "DE", 4, 100)
	putCountry(t, db, "stats_country_1m", p.ID, at(10, 10, 15), "DE", 40, 999) // inside a whole hour
	putCountry(t, db, "stats_country_1h", p.ID, at(10, 11, 0), "FR", 1, 300)
	putCountry(t, db, "stats_country_1m", p.ID, at(10, 12, 10), "DE", 9, 7)
	putCountry(t, db, "stats_country_1m", r.ID, at(10, 12, 10), "", 1, 2)
	putCountry(t, db, "stats_country_1m", p.ID, at(10, 12, 40), "DE", 1, 1) // after to

	got, err := db.CountryTotals(ctx, CountryFilter{}, from, to)
	if err != nil {
		t.Fatal(err)
	}
	want := []CountryTotal{{"FR", 300, 1}, {"DE", 117, 9}, {"", 2, 1}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CountryTotals = %+v, want %+v", got, want)
	}
	// The peak of a minute sums the proxies: 3 + 2 at 09:40, below 9 at 12:10.
	got, _ = db.CountryTotals(ctx, CountryFilter{ProxyID: p.ID}, from, to)
	if want := []CountryTotal{{"FR", 300, 1}, {"DE", 112, 9}}; !reflect.DeepEqual(got, want) {
		t.Errorf("CountryTotals(p) = %+v, want %+v", got, want)
	}
	got, _ = db.CountryTotals(ctx, CountryFilter{NodeID: n2.ID}, from, to)
	if want := []CountryTotal{{"", 2, 1}}; !reflect.DeepEqual(got, want) {
		t.Errorf("CountryTotals(n2) = %+v, want %+v", got, want)
	}
	got, _ = db.CountryTotals(ctx, CountryFilter{ProxyID: q.ID, NodeID: n2.ID}, from, to)
	if len(got) != 0 {
		t.Errorf("a proxy that is not of the node: %+v", got)
	}
	// Peak of the sum over proxies in the same minute.
	got, _ = db.CountryTotals(ctx, CountryFilter{}, at(10, 9, 30), at(10, 9, 50))
	if len(got) != 1 || got[0].IPsPeak != 5 || got[0].Bytes != 10 {
		t.Errorf("CountryTotals(09:30-09:50) = %+v, want DE 10 bytes, peak 5", got)
	}
}

// Beyond the 30 days of country hours, whole days come from the day rows.
func TestCountryTotalsDays(t *testing.T) {
	db, _, _, p, _, _ := twoNodes(t)
	from, to := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), at(10, 12, 30) // 39.5 days
	putCountry(t, db, "stats_country_1d", p.ID, time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC), "DE", 6, 50)
	putCountry(t, db, "stats_country_1h", p.ID, time.Date(2026, 9, 3, 2, 0, 0, 0, time.UTC), "DE", 6, 9999) // inside that day
	putCountry(t, db, "stats_country_1h", p.ID, at(10, 5, 0), "DE", 2, 8)
	putCountry(t, db, "stats_country_1h", p.ID, at(10, 11, 0), "DE", 3, 100)
	putCountry(t, db, "stats_country_1m", p.ID, at(10, 5, 10), "DE", 1, 4444) // inside a whole hour
	putCountry(t, db, "stats_country_1m", p.ID, at(10, 12, 10), "DE", 9, 7)
	got, err := db.CountryTotals(context.Background(), CountryFilter{}, from, to)
	if want := []CountryTotal{{"DE", 50 + 8 + 100 + 7, 9}}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("CountryTotals over 39.5 days = %+v, %v; want %+v", got, err, want)
	}
}

func TestListSightings(t *testing.T) {
	db, _, _, p, q, _ := twoNodes(t)
	ctx := context.Background()
	put := func(proxy *Proxy, ip, country string, last int, bytes uint64) {
		t.Helper()
		mustExec(t, db, `INSERT INTO ip_sightings (proxy_id, ip, first_seen, last_seen, bytes, country) VALUES (?, ?, ?, ?, ?, ?)`,
			proxy.ID, ip, at(10, 1, 0).Unix(), at(10, 2, last).Unix(), bytes, country)
	}
	put(p, "192.0.2.1", "DE", 1, 10)
	put(p, "192.0.2.2", "FR", 5, 20)
	put(p, "192.0.2.3", "DE", 3, 30)
	put(q, "198.51.100.1", "DE", 9, 40)

	got, total, err := db.ListSightings(ctx, p.ID, "", 2, 0)
	if err != nil || total != 3 || len(got) != 2 || got[0].IP != "192.0.2.2" || got[1].IP != "192.0.2.3" {
		t.Fatalf("page 1 = %+v, total %d, %v", got, total, err)
	}
	if got[0].LastSeen != at(10, 2, 5) || got[0].FirstSeen != at(10, 1, 0) || got[0].Bytes != 20 || got[0].Country != "FR" || got[0].ProxyID != p.ID {
		t.Errorf("fields = %+v", got[0])
	}
	got, total, _ = db.ListSightings(ctx, p.ID, "", 2, 2)
	if total != 3 || len(got) != 1 || got[0].IP != "192.0.2.1" {
		t.Errorf("page 2 = %+v, total %d", got, total)
	}
	got, total, _ = db.ListSightings(ctx, p.ID, "DE", 10, 0)
	if total != 2 || len(got) != 2 || got[0].IP != "192.0.2.3" {
		t.Errorf("DE = %+v, total %d", got, total)
	}
	got, total, _ = db.ListSightings(ctx, "", "DE", 10, 0)
	if total != 3 || got[0].IP != "198.51.100.1" {
		t.Errorf("every proxy, DE = %+v, total %d", got, total)
	}
	if got, total, _ = db.ListSightings(ctx, p.ID, "", 10, 10); total != 3 || len(got) != 0 {
		t.Errorf("past the end = %+v, total %d", got, total)
	}
}

func TestEgressHistoryProbesLatestMinutesAndStorage(t *testing.T) {
	db, n, n2, p, q, _ := twoNodes(t)
	ctx := context.Background()

	insertChain(t, db, "c1", "")
	hour := func(node *Node, chain, member string, ts time.Time, up, down, unknown, avg, maxMS int, ip string) {
		mustExec(t, db, `INSERT INTO egress_health (node_id, chain_id, member_key, ts, minutes_up, minutes_down, minutes_unknown,
			latency_avg_ms, latency_max_ms, exit_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			node.ID, chain, member, ts.Unix(), up, down, unknown, avg, maxMS, ip)
	}
	hour(n, "c1", "m2", at(10, 9, 0), 50, 5, 5, 40, 90, "203.0.113.2")
	hour(n, "c1", "m1", at(10, 9, 0), 60, 0, 0, 30, 31, "203.0.113.1")
	hour(n, "c1", "m1", at(10, 8, 0), 1, 2, 3, 4, 5, "")
	hour(n, "c1", "m1", at(10, 10, 0), 9, 9, 9, 9, 9, "") // not in range
	hour(n2, "c1", "m1", at(10, 9, 0), 7, 7, 7, 7, 7, "")
	eh, err := db.EgressHistory(ctx, n.ID, at(10, 8, 0), at(10, 10, 0))
	if err != nil {
		t.Fatal(err)
	}
	wantEH := []MemberHour{
		{ChainID: "c1", MemberKey: "m1", TS: at(10, 8, 0), Up: 1, Down: 2, Unknown: 3, LatencyAvgMS: 4, LatencyMaxMS: 5},
		{ChainID: "c1", MemberKey: "m1", TS: at(10, 9, 0), Up: 60, LatencyAvgMS: 30, LatencyMaxMS: 31, ExitIP: "203.0.113.1"},
		{ChainID: "c1", MemberKey: "m2", TS: at(10, 9, 0), Up: 50, Down: 5, Unknown: 5, LatencyAvgMS: 40, LatencyMaxMS: 90, ExitIP: "203.0.113.2"},
	}
	if !reflect.DeepEqual(eh, wantEH) {
		t.Errorf("EgressHistory = %+v, want %+v", eh, wantEH)
	}

	probe := func(proxy *Proxy, vantage, kind string, ts time.Time, ok bool, ms uint32, e string) {
		if err := db.InsertProbe(ctx, Probe{ProxyID: proxy.ID, TS: ts, Vantage: vantage, Kind: kind, OK: ok, LatencyMS: ms, Error: e}); err != nil {
			t.Fatal(err)
		}
	}
	for m := range 4 {
		probe(p, "panel", "l2", at(10, 9, m), m%2 == 0, uint32(10+m), "")
	}
	probe(p, "node", "l2", at(10, 9, 10), false, 0, "refused")
	probe(q, "panel", "l2", at(10, 9, 2), true, 5, "")
	pr, err := db.Probes(ctx, p.ID, "panel", at(10, 9, 1), at(10, 9, 3))
	if err != nil || len(pr) != 2 || pr[0].TS != at(10, 9, 1) || pr[0].OK || pr[1].TS != at(10, 9, 2) || !pr[1].OK || pr[1].LatencyMS != 12 {
		t.Errorf("Probes = %+v, %v", pr, err)
	}
	if pr, _ = db.Probes(ctx, p.ID, "", at(10, 9, 0), at(10, 10, 0)); len(pr) != 5 || pr[4].Vantage != "node" || pr[4].Error != "refused" {
		t.Errorf("Probes(any vantage) = %+v", pr)
	}
	// LastProbes reads the 7 days that are kept, by the clock of the store: a
	// probe of q older than that, which a late prune left, is not its newest.
	db.now = fixedClock(at(10, 12, 30))
	probe(q, "panel", "l2", at(3, 12, 29), false, 0, "old")
	last, err := db.LastProbes(ctx, "panel", 2)
	if err != nil || len(last) != 2 || len(last[p.ID]) != 2 || last[p.ID][0].TS != at(10, 9, 3) || last[p.ID][1].TS != at(10, 9, 2) || len(last[q.ID]) != 1 {
		t.Errorf("LastProbes(panel, 2) = %+v, %v", last, err)
	}
	if last, _ = db.LastProbes(ctx, "node", 5); len(last) != 1 || len(last[p.ID]) != 1 {
		t.Errorf("LastProbes(node) = %+v", last)
	}

	now := at(10, 12, 30)
	putNodeStat(t, db, "stats_node_1m", n.ID, at(10, 12, 20), NodeStat{Conns: 1})
	putNodeStat(t, db, "stats_node_1m", n.ID, at(10, 12, 28), NodeStat{Conns: 2, CPU: 5})
	putNodeStat(t, db, "stats_node_1m", n2.ID, at(10, 12, 0), NodeStat{Conns: 3})
	lm, err := db.LatestNodeMinutes(ctx, now, 5*time.Minute)
	if err != nil || len(lm) != 1 || lm[n.ID].Conns != 2 || lm[n.ID].CPU != 5 || lm[n.ID].TS != at(10, 12, 28) {
		t.Errorf("LatestNodeMinutes(5m) = %+v, %v", lm, err)
	}
	if lm, _ = db.LatestNodeMinutes(ctx, now, 31*time.Minute); len(lm) != 2 || lm[n2.ID].Conns != 3 {
		t.Errorf("LatestNodeMinutes(31m) = %+v", lm)
	}

	// Storage counts what the tests put in.
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 9, 0), ProxyStat{Up: 1})
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 9, 1), ProxyStat{Up: 1})
	putProxyStat(t, db, "stats_proxy_1d", p.ID, at(9, 0, 0), ProxyStat{Up: 1})
	putCountry(t, db, "stats_country_1m", p.ID, at(10, 9, 0), "DE", 1, 1)
	mustExec(t, db, `INSERT INTO ip_sightings (proxy_id, ip, first_seen, last_seen) VALUES (?, '192.0.2.1', 1, 1)`, p.ID)
	mustExec(t, db, `INSERT INTO events (id, ts, kind) VALUES ('e1', 1, 'k'), ('e2', 2, 'k')`)
	mustExec(t, db, `INSERT INTO diagnostic_runs (id, node_id, scope, reason, state, started_at) VALUES ('r1', ?, 'node', 'manual', 'done', 1)`, n.ID)
	mustExec(t, db, `INSERT INTO diagnostic_results (run_id, seq, check_id, layer, checked_at) VALUES ('r1', 0, 'x', 'host', 1)`)
	info, err := db.Storage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]int64{
		"stats_proxy_1m": 2, "stats_proxy_1d": 1, "stats_node_1m": 3, "stats_country_1m": 1, "probes": 7, "ip_sightings": 1,
		"events": 2, "diagnostic_runs": 1, "diagnostic_results": 1, "egress_health": 5, "stats_proxy_1h": 0,
	} {
		if got, ok := info.Rows[table]; !ok || got != want {
			t.Errorf("Rows[%s] = %d (present %v), want %d", table, got, ok, want)
		}
	}
	var pages, size, free int64
	_ = db.sql.QueryRow(`PRAGMA page_count`).Scan(&pages)
	_ = db.sql.QueryRow(`PRAGMA page_size`).Scan(&size)
	_ = db.sql.QueryRow(`PRAGMA freelist_count`).Scan(&free)
	if info.FileBytes != pages*size || info.FreeBytes != free*size || info.FileBytes <= 0 {
		t.Errorf("sizes = %d, %d; want %d, %d", info.FileBytes, info.FreeBytes, pages*size, free*size)
	}
}

// Hours that RollupStats has not made yet are read from their minutes: the
// minute rows start where the newest hour row ends.
func TestTotalsReadMinutesOfHoursNotRolledUpYet(t *testing.T) {
	db, n, _, p, _, _ := twoNodes(t)
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(10, 9, 0), ProxyStat{Up: 10})
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 9, 15), ProxyStat{Up: 777}) // inside the hour that is rolled up
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 10, 15), ProxyStat{Up: 5})
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 11, 10), ProxyStat{Up: 6})
	got, err := db.TrafficSince(context.Background(), at(10, 9, 0), at(10, 11, 30))
	if err != nil || got[n.ID].Up != 21 {
		t.Errorf("TrafficSince = %+v, %v; want up = 10 + 5 + 6", got, err)
	}
}
