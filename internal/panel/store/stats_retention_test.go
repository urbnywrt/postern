package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

const day = 24 * time.Hour

// setSteps sets how much of the minutes and of the hours one transaction of
// RollupStats and PruneStats takes, until the test ends.
func setSteps(t *testing.T, minutes, hours time.Duration) {
	t.Helper()
	oldMinutes, oldHours := minutesPerTx, hoursPerTx
	minutesPerTx, hoursPerTx = minutes, hours
	t.Cleanup(func() { minutesPerTx, hoursPerTx = oldMinutes, oldHours })
}

// countTx counts the transactions of RollupStats and PruneStats that commit.
func countTx(db *DB) *int {
	var n int
	db.steps.onPause = func() { n++ }
	return &n
}

// The rollups and prunes come to the same rows whatever the size of their
// steps: their tests, again with steps of an hour of minutes and an hour of
// hours.
func TestRollupsAndPrunesInStepsOfAnHour(t *testing.T) {
	setSteps(t, time.Hour, time.Hour)
	for _, tt := range []struct {
		name string
		test func(*testing.T)
	}{
		{"RollupProxyStatsIntoHours", TestRollupProxyStatsIntoHours},
		{"RollupProxyStatsIntoDays", TestRollupProxyStatsIntoDays},
		{"RollupMinutesToDaysInOneCall", TestRollupMinutesToDaysInOneCall},
		{"RollupKeepsTotalsOfPartiallyPrunedPeriods", TestRollupKeepsTotalsOfPartiallyPrunedPeriods},
		{"RollupKeepsTotalsOfPartiallyPrunedDays", TestRollupKeepsTotalsOfPartiallyPrunedDays},
		{"RollupKeepsNodeTotalsOfPartiallyPrunedPeriods", TestRollupKeepsNodeTotalsOfPartiallyPrunedPeriods},
		{"RollupLeavesTheDaysThatCannotChange", TestRollupLeavesTheDaysThatCannotChange},
		{"RollupThenPruneKeepsHourlyTotals", TestRollupThenPruneKeepsHourlyTotals},
		{"PruneStatsRollsUpWhatItDeletes", TestPruneStatsRollsUpWhatItDeletes},
		{"RollupNodeStats", TestRollupNodeStats},
		{"RollupOfNothing", TestRollupOfNothing},
		{"PruneStats", TestPruneStats},
		{"HugeCountersDoNotBreakRollupOrPrune", TestHugeCountersDoNotBreakRollupOrPrune},
		{"RollupOfADayAtTheCap", TestRollupOfADayAtTheCap},
		{"IngestMinuteReplayAfterItsMarkerIsPruned", TestIngestMinuteReplayAfterItsMarkerIsPruned},
		{"IngestMinuteSecondEmitReplaces", TestIngestMinuteSecondEmitReplaces},
		{"RollupThreeMinutesOfAnHour", TestRollupThreeMinutesOfAnHour},
		{"PruneBoundariesOfEveryTable", TestPruneBoundariesOfEveryTable},
		{"PruneStatsKeepsTheNewestRunsOfANode", TestPruneStatsKeepsTheNewestRunsOfANode},
		{"PruneWithAShorterRetentionRollsUpFirst", TestPruneWithAShorterRetentionRollsUpFirst},
		{"RollupAfterALongerRetentionKeepsWhatWasCut", TestRollupAfterALongerRetentionKeepsWhatWasCut},
		{"RollupWithoutARecordOfThePruneKeepsWhatWasCut", TestRollupWithoutARecordOfThePruneKeepsWhatWasCut},
		{"CountryCapOfAnHour", TestCountryCapOfAnHour},
		{"CountryDays", TestCountryDays},
		{"CountryDayIsFinalOnceItsHoursAreCut", TestCountryDayIsFinalOnceItsHoursAreCut},
		{"PruneStatsRollsUpTheCountriesItDeletes", TestPruneStatsRollsUpTheCountriesItDeletes},
		{"CountryRollupOfADayAtTheCap", TestCountryRollupOfADayAtTheCap},
		{"MemberHoursPerChainAndNode", TestMemberHoursPerChainAndNode},
		{"MemberHoursOfPrunedMinutes", TestMemberHoursOfPrunedMinutes},
	} {
		t.Run(tt.name, tt.test)
	}
}

// RollupStats holds the write lock, which ingest waits for, a window of hours
// at a time, starting with an hour and doubling after each quick window, up to
// 6 hours: 30 hours of minutes are windows of 1, 2, 4, 6, 6, 6 and 6 hours,
// then the days.
func TestRollupStatsWorksInWindows(t *testing.T) {
	setSteps(t, 6*time.Hour, 24*time.Hour)
	db, _, p, _ := statsFixture(t)
	for h := range 30 {
		putProxyStat(t, db, "stats_proxy_1m", p.ID, at(9, 0, 5).Add(time.Duration(h)*time.Hour), ProxyStat{Up: 1})
	}
	txs := countTx(db)
	if err := db.RollupStats(context.Background(), statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	if *txs != 8 {
		t.Errorf("RollupStats took %d transactions, want 7 windows of hours and one of days", *txs)
	}
	if n := count(t, db, `SELECT count(*) FROM stats_proxy_1h WHERE up = 1`); n != 30 {
		t.Errorf("%d hours of one byte, want 30", n)
	}
	if got := rowsOf(t, db, `SELECT ts, up FROM stats_proxy_1d`); len(got) != 1 || got[0] != fmt.Sprintf("%d|24", at(9, 0, 0).Unix()) {
		t.Errorf("days = %v, want 24 bytes on the 9th, and nothing of the 10th, which is not over", got)
	}
}

// A prune moves its cut a step at a time, each step in a transaction of its
// own: one that is cancelled after two steps has deleted the minutes of those
// steps, has rolled them up into their hours first, and says how far it went;
// the next prune goes on from there.
func TestPruneStatsCancelledMidway(t *testing.T) {
	setSteps(t, 6*time.Hour, 24*time.Hour)
	db, _, p, _ := statsFixture(t)
	// 30 hours of minutes, all before the cut of 10-08 12:30: one byte every
	// 10 minutes, 6 an hour.
	start := at(7, 0, 0)
	for m := 0; m < 30*60; m += 10 {
		putProxyStat(t, db, "stats_proxy_1m", p.ID, start.Add(time.Duration(m)*time.Minute), ProxyStat{Up: 1})
	}
	hours := func(from, to time.Time) (n, wrong int) {
		t.Helper()
		for h := from; h.Before(to); h = h.Add(time.Hour) {
			n++
			if up := proxyUp(t, db, "stats_proxy_1h", p.ID, h); up != 6 {
				wrong++
			}
		}
		return n, wrong
	}

	ctx, cancel := context.WithCancel(context.Background())
	steps := 0
	db.steps.onPause = func() {
		if steps++; steps == 2 {
			cancel()
		}
	}
	if err := db.PruneStats(ctx, statsNow, testRetention); !errors.Is(err, context.Canceled) {
		t.Fatalf("PruneStats cancelled after two steps: err = %v, want context.Canceled", err)
	}
	cut := at(7, 3, 0) // two steps, of an hour and of two
	var pruned prunedBefore
	if _, err := db.GetSetting(context.Background(), settingStatsPruned, &pruned); err != nil || pruned.Minutes != cut.Unix() {
		t.Errorf("stats_pruned = %+v, %v; want the minutes cut at %s", pruned, err, cut.Format(time.DateTime))
	}
	if n := count(t, db, `SELECT count(*) FROM stats_proxy_1m WHERE ts < ?`, cut.Unix()); n != 0 {
		t.Errorf("%d minutes before the cut of the last step are left", n)
	}
	if n := count(t, db, `SELECT count(*) FROM stats_proxy_1m`); n != 27*6 {
		t.Errorf("%d minutes are left, want the 27 hours after the cut", n)
	}
	if n, wrong := hours(start, cut); wrong != 0 {
		t.Errorf("%d of the %d hours whose minutes are deleted do not have their total", wrong, n)
	}

	db.steps.onPause = nil
	if err := db.PruneStats(context.Background(), statsNow, testRetention); err != nil {
		t.Fatalf("PruneStats again: %v", err)
	}
	if n, wrong := hours(start, start.Add(30*time.Hour)); wrong != 0 {
		t.Errorf("after the second prune, %d of the %d hours do not have their total", wrong, n)
	}
	if n := count(t, db, `SELECT count(*) FROM stats_proxy_1m`); n != 0 {
		t.Errorf("%d minutes are left after the second prune, want none", n)
	}
	if _, err := db.GetSetting(context.Background(), settingStatsPruned, &pruned); err != nil || pruned.Minutes != statsNow.Add(-48*time.Hour).Unix() {
		t.Errorf("stats_pruned = %+v, %v; want the minutes cut at 48 hours", pruned, err)
	}
}

// putMinutesOfHours writes a minute of p at five past each of n hours from
// 10-09 00:00, of one byte each.
func putMinutesOfHours(t *testing.T, db *DB, p *Proxy, n int) {
	t.Helper()
	for h := range n {
		putProxyStat(t, db, "stats_proxy_1m", p.ID, at(9, 0, 5).Add(time.Duration(h)*time.Hour), ProxyStat{Up: 1})
	}
}

// SQLite does not queue writers: one that waits for the write lock only gets
// it when it tries between two transactions. So RollupStats and PruneStats
// pause after each of theirs, with the lock free: a write there gets it at
// once.
func TestStepsLeaveTheWriteLockFree(t *testing.T) {
	setSteps(t, 6*time.Hour, 24*time.Hour)
	db, _, p, _ := statsFixture(t)
	putMinutesOfHours(t, db, p, 30)
	ctx := context.Background()
	pauses := 0
	db.steps.onPause = func() {
		pauses++
		start := time.Now()
		if _, err := db.sql.ExecContext(ctx,
			`INSERT INTO settings (key, value) VALUES ('test', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
			pauses); err != nil {
			t.Errorf("a write at pause %d: %v", pauses, err)
		}
		if took := time.Since(start); took > time.Second {
			t.Errorf("a write at pause %d waited %s for the lock", pauses, took)
		}
	}
	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	if pauses != 8 { // after each of 7 windows of hours, and after the days
		t.Errorf("RollupStats paused %d times, want 8", pauses)
	}
	short := testRetention
	short.Minutes = 6 * time.Hour
	pauses = 0
	if err := db.PruneStats(ctx, statsNow, short); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}
	// 30 hours of minutes in steps of 1, 2, 4, 6, 6, 6 and what is left, one
	// step of each other series, and the last one.
	if pauses != 7+4 {
		t.Errorf("PruneStats paused %d times, want 11", pauses)
	}
}

// The pause is as long as it is set to, and ends with the context.
func TestStepsPause(t *testing.T) {
	setSteps(t, 6*time.Hour, 24*time.Hour)
	db, _, p, _ := statsFixture(t)
	putMinutesOfHours(t, db, p, 12) // windows of 1, 2, 4 and 6 hours, then the days
	db.steps.pause = 50 * time.Millisecond
	start := time.Now()
	if err := db.RollupStats(context.Background(), statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	if took := time.Since(start); took < 250*time.Millisecond {
		t.Errorf("five transactions with a pause of 50 ms after each took %s", took)
	}

	db.steps.pause = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start = time.Now()
	if err := db.RollupStats(ctx, statsNow, testRetention); !errors.Is(err, context.Canceled) {
		t.Errorf("RollupStats cancelled in a pause of an hour: err = %v, want context.Canceled", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("RollupStats cancelled in a pause of an hour returned after %s", took)
	}
}

// Rows are not as dense everywhere (a proxy may have 3 countries a minute, or
// 50), so a step starts small: an hour of minutes, doubled after each
// transaction that took less than half of db.steps.slow, up to its size; one
// that took longer than db.steps.slow halves the next, down to an hour (the
// windows of RollupStats stay whole hours).
func TestStepsAdaptToHowLongTheyTake(t *testing.T) {
	setSteps(t, 6*time.Hour, 24*time.Hour)
	db, _, p, _ := statsFixture(t)
	putMinutesOfHours(t, db, p, 24)
	db.steps.slow = 300 * time.Millisecond
	var steps []string
	db.steps.inTx = func(what string, from, to int64) {
		if what != "rollup hours" && what != "prune minutes" || from == to {
			return
		}
		steps = append(steps, (time.Duration(to-from) * time.Second).String())
		if n := len(steps); n == 4 || n == 5 { // the fourth and the fifth step are slow
			time.Sleep(350 * time.Millisecond)
		}
	}

	if err := db.RollupStats(context.Background(), statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	want := []string{"1h0m0s", "2h0m0s", "4h0m0s", "6h0m0s", "3h0m0s", "1h0m0s", "2h0m0s", "4h0m0s", "6h0m0s"}
	if !slices.Equal(steps, want) {
		t.Errorf("windows = %q, want %q", steps, want)
	}
	if n := count(t, db, `SELECT count(*) FROM stats_proxy_1h WHERE up = 1`); n != 24 {
		t.Errorf("%d hours of one byte, want 24", n)
	}

	steps = nil
	short := testRetention
	short.Minutes = 6 * time.Hour
	if err := db.PruneStats(context.Background(), statsNow, short); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}
	want = []string{"1h0m0s", "2h0m0s", "4h0m0s", "6h0m0s", "3h0m0s", "1h30m0s", "3h0m0s", "6h0m0s"}
	if !slices.Equal(steps, want) {
		t.Errorf("steps = %q, want %q", steps, want)
	}
	if n := count(t, db, `SELECT count(*) FROM stats_proxy_1m`); n != 0 {
		t.Errorf("%d minutes are left, want none", n)
	}
	if n := count(t, db, `SELECT count(*) FROM stats_proxy_1h WHERE up = 1`); n != 24 {
		t.Errorf("after the prune, %d hours of one byte, want 24", n)
	}
}

// However long the steps take, they do not get shorter than an hour of
// minutes.
func TestStepsDoNotGetShorterThanAnHour(t *testing.T) {
	setSteps(t, 6*time.Hour, 24*time.Hour)
	db, _, p, _ := statsFixture(t)
	putMinutesOfHours(t, db, p, 3)
	db.steps.slow = 10 * time.Millisecond
	var steps []string
	db.steps.inTx = func(what string, from, to int64) {
		if what != "prune minutes" || from == to {
			return
		}
		steps = append(steps, (time.Duration(to-from) * time.Second).String())
		time.Sleep(20 * time.Millisecond) // every step is slow
	}
	short := testRetention
	short.Minutes = 6 * time.Hour
	if err := db.PruneStats(context.Background(), statsNow, short); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}
	if want := []string{"1h0m0s", "1h0m0s", "1h0m0s"}; !slices.Equal(steps, want) {
		t.Errorf("steps = %q, want %q", steps, want)
	}
}

// Before any prune has said how far it went, on a database that an older
// version pruned, a period is whole only from the oldest of its finer rows on
// that are left, and never before where the retention cuts: the hour that the
// older version cut in two keeps its total although the retention is longer
// now.
func TestRollupWithoutARecordOfThePruneKeepsWhatWasCut(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	// The older version deleted the minutes before 10-08 12:30.
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(8, 12, 0), ProxyStat{Up: 1000}) // the whole hour
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(8, 12, 40), ProxyStat{Up: 5})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(8, 13, 0), ProxyStat{Up: 1}) // made before its last minute came
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(8, 13, 5), ProxyStat{Up: 7})

	longer := Retention{Minutes: 168 * time.Hour, Hours: 365 * day, IPs: 30 * day}
	if err := db.RollupStats(context.Background(), statsNow, longer); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	if got := proxyUp(t, db, "stats_proxy_1h", p.ID, at(8, 12, 0)); got != 1000 {
		t.Errorf("the hour that was cut in two: up = %d, want its total of 1000 kept", got)
	}
	if got := proxyUp(t, db, "stats_proxy_1h", p.ID, at(8, 13, 0)); got != 7 {
		t.Errorf("a whole hour: up = %d, want 7 (made again)", got)
	}
}

// putRun writes a diagnostic run of a node, with SQL.
func putRun(t *testing.T, db *DB, id, nodeID string, started time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO diagnostic_runs (id, node_id, scope, reason, state, started_at) VALUES (?, ?, 'node', 'manual', 'done', ?)`,
		id, nodeID, started.Unix())
}

// putResult writes a result of a diagnostic run, with SQL.
func putResult(t *testing.T, db *DB, runID string, seq int) {
	t.Helper()
	mustExec(t, db, `INSERT INTO diagnostic_results (run_id, seq, check_id, layer, checked_at) VALUES (?, ?, 'host.docker', 'host', 0)`, runID, seq)
}

// Every table is pruned at its own age, to the second: a row as old as the
// table keeps them is kept, one a second older is deleted. Minutes, hours and
// addresses follow the retention that PruneStats is given; markers (8 days),
// country and member hours (30 days), probes (7 days) and runs (30 days) do
// not; days are kept for good.
func TestPruneBoundariesOfEveryTable(t *testing.T) {
	short := Retention{Minutes: 6 * time.Hour, Hours: 7 * day, IPs: day}
	for _, r := range []Retention{testRetention, short} {
		t.Run(fmt.Sprintf("minutes %s, hours %s, addresses %s", r.Minutes, r.Hours, r.IPs), func(t *testing.T) {
			db, node, p, _ := statsFixture(t)
			storePolicy(t, db, IPPolicyFull) // under which where addresses were seen is kept for its time
			n := 0                           // makes the keys of the rows that need one
			tables := []struct {
				table, column string
				age           time.Duration // 0: kept for good
				put           func(ts time.Time)
			}{
				{"stats_proxy_1m", "ts", r.Minutes, func(ts time.Time) { putProxyStat(t, db, "stats_proxy_1m", p.ID, ts, ProxyStat{Up: 1}) }},
				{"stats_node_1m", "ts", r.Minutes, func(ts time.Time) { putNodeStat(t, db, "stats_node_1m", node.ID, ts, NodeStat{Conns: 1}) }},
				{"stats_country_1m", "ts", r.Minutes, func(ts time.Time) { putCountry(t, db, "stats_country_1m", p.ID, ts, "DE", 1, 1) }},
				{"egress_health_1m", "ts", r.Minutes, func(ts time.Time) { putMemberMinute(t, db, node.ID, "C1", "m1", ts, "up", 1, "") }},
				{"stats_batches", "minute", 8 * day, func(ts time.Time) {
					mustExec(t, db, `INSERT INTO stats_batches (node_id, minute) VALUES (?, ?)`, node.ID, ts.Unix())
				}},
				{"stats_proxy_1h", "ts", r.Hours, func(ts time.Time) { putProxyStat(t, db, "stats_proxy_1h", p.ID, ts, ProxyStat{Up: 1}) }},
				{"stats_node_1h", "ts", r.Hours, func(ts time.Time) { putNodeStat(t, db, "stats_node_1h", node.ID, ts, NodeStat{Conns: 1}) }},
				{"stats_country_1h", "ts", 30 * day, func(ts time.Time) { putCountry(t, db, "stats_country_1h", p.ID, ts, "DE", 1, 1) }},
				{"egress_health", "ts", 30 * day, func(ts time.Time) {
					mustExec(t, db, `INSERT INTO egress_health (node_id, chain_id, member_key, ts) VALUES (?, 'C1', 'm1', ?)`, node.ID, ts.Unix())
				}},
				{"probes", "ts", 7 * day, func(ts time.Time) {
					mustExec(t, db, `INSERT INTO probes (proxy_id, ts, vantage, kind, ok) VALUES (?, ?, 'panel', 'l2', 1)`, p.ID, ts.Unix())
				}},
				{"ip_sightings", "last_seen", r.IPs, func(ts time.Time) {
					n++
					putSighting(t, db, p.ID, fmt.Sprintf("198.51.100.%d", n), ts)
				}},
				{"diagnostic_runs", "started_at", 30 * day, func(ts time.Time) {
					n++
					putRun(t, db, fmt.Sprintf("RUN%d", n), node.ID, ts)
				}},
				{"stats_proxy_1d", "ts", 0, func(ts time.Time) { putProxyStat(t, db, "stats_proxy_1d", p.ID, ts, ProxyStat{Up: 1}) }},
				{"stats_node_1d", "ts", 0, func(ts time.Time) { putNodeStat(t, db, "stats_node_1d", node.ID, ts, NodeStat{Conns: 1}) }},
				{"stats_country_1d", "ts", 0, func(ts time.Time) { putCountry(t, db, "stats_country_1d", p.ID, ts, "DE", 1, 1) }},
			}
			ago := func(d time.Duration) time.Time { return statsNow.Add(-d) }
			for _, tt := range tables {
				if tt.age == 0 {
					tt.put(ago(3000 * day))
					continue
				}
				tt.put(ago(tt.age))
				tt.put(ago(tt.age + time.Second))
			}

			if err := db.PruneStats(context.Background(), statsNow, r); err != nil {
				t.Fatalf("PruneStats: %v", err)
			}

			kept := func(table, column string, ts time.Time) bool {
				return count(t, db, `SELECT count(*) FROM `+table+` WHERE `+column+` = ?`, ts.Unix()) > 0
			}
			for _, tt := range tables {
				if tt.age == 0 {
					if !kept(tt.table, tt.column, ago(3000*day)) {
						t.Errorf("%s: a row of 3000 days ago was deleted", tt.table)
					}
					continue
				}
				if !kept(tt.table, tt.column, ago(tt.age)) {
					t.Errorf("%s: the row of exactly %s ago was deleted", tt.table, tt.age)
				}
				if kept(tt.table, tt.column, ago(tt.age+time.Second)) {
					t.Errorf("%s: the row of a second more than %s ago was kept", tt.table, tt.age)
				}
			}
		})
	}
}

// A node keeps its newest 100 runs, of the last 30 days; the results of a run
// go with it.
func TestPruneStatsKeepsTheNewestRunsOfANode(t *testing.T) {
	db, node, _, _ := statsFixture(t)
	other := mustNode(t, db, "other")
	for i := range 102 {
		putRun(t, db, fmt.Sprintf("N%03d", i), node.ID, statsNow.Add(-time.Duration(102-i)*time.Minute))
	}
	putResult(t, db, "N000", 1)
	putResult(t, db, "N101", 1)
	for i := range 3 {
		putRun(t, db, fmt.Sprintf("O%d", i), other.ID, statsNow.Add(-time.Duration(i)*time.Hour))
	}

	if err := db.PruneStats(context.Background(), statsNow, testRetention); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}
	if n := count(t, db, `SELECT count(*) FROM diagnostic_runs WHERE node_id = ?`, node.ID); n != 100 {
		t.Errorf("%d runs of the node, want 100", n)
	}
	if n := count(t, db, `SELECT count(*) FROM diagnostic_runs WHERE id IN ('N000', 'N001')`); n != 0 {
		t.Errorf("%d of the two oldest runs are left", n)
	}
	if n := count(t, db, `SELECT count(*) FROM diagnostic_runs WHERE node_id = ?`, other.ID); n != 3 {
		t.Errorf("%d runs of the other node, want 3", n)
	}
	if got := rowsOf(t, db, `SELECT run_id FROM diagnostic_results`); len(got) != 1 || got[0] != "N101" {
		t.Errorf("results left = %v, want only those of the run that is kept", got)
	}
}

// A shorter retention deletes more at once, and what it deletes is rolled up
// first: an hour that has no row gets one, and an hour whose minutes are all
// still there is made again from them before they go, also when its row was
// made before its last minute came.
func TestPruneWithAShorterRetentionRollsUpFirst(t *testing.T) {
	db, node, p, _ := statsFixture(t)
	ctx := context.Background()
	if err := db.PruneStats(ctx, statsNow, testRetention); err != nil { // minutes before 10-08 12:30 are gone
		t.Fatal(err)
	}
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 5, 10), ProxyStat{Up: 5})
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 5, 20), ProxyStat{Up: 6})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, at(10, 4, 0), ProxyStat{Up: 1}) // made before its last minute came
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(10, 4, 10), ProxyStat{Up: 50})
	putNodeStat(t, db, "stats_node_1m", node.ID, at(10, 5, 10), NodeStat{NetRx: 7, RefusedTotal: 2})
	putCountry(t, db, "stats_country_1m", p.ID, at(10, 5, 10), "DE", 2, 9)
	putMemberMinute(t, db, node.ID, "C1", "m1", at(10, 5, 10), "up", 20, "203.0.113.4")

	short := testRetention
	short.Minutes = 6 * time.Hour // the oldest minute that is kept is 06:30 today
	if err := db.PruneStats(ctx, statsNow, short); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}
	for _, tt := range []struct {
		what, query string
		want        string
	}{
		{"proxy hour 05:00", fmt.Sprintf(`SELECT up FROM stats_proxy_1h WHERE ts = %d`, at(10, 5, 0).Unix()), "11"},
		{"proxy hour 04:00", fmt.Sprintf(`SELECT up FROM stats_proxy_1h WHERE ts = %d`, at(10, 4, 0).Unix()), "50"},
		{"node hour", fmt.Sprintf(`SELECT net_rx, refused_total FROM stats_node_1h WHERE ts = %d`, at(10, 5, 0).Unix()), "7|2"},
		{"country hour", fmt.Sprintf(`SELECT country, ips, bytes FROM stats_country_1h WHERE ts = %d`, at(10, 5, 0).Unix()), "DE|2|9"},
		{"member hour", fmt.Sprintf(`SELECT minutes_up, latency_avg_ms, exit_ip FROM egress_health WHERE ts = %d`, at(10, 5, 0).Unix()), "1|20|203.0.113.4"},
	} {
		if got := rowsOf(t, db, tt.query); len(got) != 1 || got[0] != tt.want {
			t.Errorf("%s = %q, want %s", tt.what, got, tt.want)
		}
	}
	for _, table := range []string{"stats_proxy_1m", "stats_node_1m", "stats_country_1m", "egress_health_1m"} {
		if n := count(t, db, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%s: %d minutes left, want none", table, n)
		}
	}
}

// When minutes or hours are kept longer than before, the periods that a prune
// has cut are still cut: their totals are not made again from what is left of
// them.
func TestRollupAfterALongerRetentionKeepsWhatWasCut(t *testing.T) {
	db, node, p, _ := statsFixture(t)
	ctx := context.Background()
	july := func(d, hour int) time.Time { return time.Date(2026, 7, d, hour, 0, 0, 0, time.UTC) }

	// The prune at 48 hours and 90 days cuts the hour of 10-08 12:00 and the day
	// of 12 July.
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(8, 12, 10), ProxyStat{Up: 100})
	putProxyStat(t, db, "stats_proxy_1m", p.ID, at(8, 12, 40), ProxyStat{Up: 50})
	putNodeStat(t, db, "stats_node_1m", node.ID, at(8, 12, 10), NodeStat{NetRx: 100})
	putNodeStat(t, db, "stats_node_1m", node.ID, at(8, 12, 40), NodeStat{NetRx: 50})
	putCountry(t, db, "stats_country_1m", p.ID, at(8, 12, 10), "DE", 4, 100)
	putCountry(t, db, "stats_country_1m", p.ID, at(8, 12, 40), "DE", 1, 50)
	putMemberMinute(t, db, node.ID, "C1", "m1", at(8, 12, 10), "up", 10, "203.0.113.1")
	putMemberMinute(t, db, node.ID, "C1", "m1", at(8, 12, 40), "down", 0, "")
	putProxyStat(t, db, "stats_proxy_1h", p.ID, july(12, 9), ProxyStat{Up: 20})
	putProxyStat(t, db, "stats_proxy_1h", p.ID, july(12, 18), ProxyStat{Up: 5})
	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatal(err)
	}
	if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
		t.Fatal(err)
	}

	checks := []struct {
		what, query string
		want        string
	}{
		{"proxy hour", fmt.Sprintf(`SELECT up FROM stats_proxy_1h WHERE ts = %d`, at(8, 12, 0).Unix()), "150"},
		{"node hour", fmt.Sprintf(`SELECT net_rx FROM stats_node_1h WHERE ts = %d`, at(8, 12, 0).Unix()), "150"},
		{"country hour", fmt.Sprintf(`SELECT ips, bytes FROM stats_country_1h WHERE ts = %d`, at(8, 12, 0).Unix()), "4|150"},
		{"member hour", fmt.Sprintf(`SELECT minutes_up, minutes_down FROM egress_health WHERE ts = %d`, at(8, 12, 0).Unix()), "1|1"},
		{"proxy day", fmt.Sprintf(`SELECT up FROM stats_proxy_1d WHERE ts = %d`, july(12, 0).Unix()), "25"},
	}
	run := func(when string) {
		t.Helper()
		for _, tt := range checks {
			if got := rowsOf(t, db, tt.query); len(got) != 1 || got[0] != tt.want {
				t.Errorf("%s: %s = %q, want %s", when, tt.what, got, tt.want)
			}
		}
	}
	run("after the prune")

	longer := Retention{Minutes: 168 * time.Hour, Hours: 365 * day, IPs: 30 * day}
	later := statsNow.Add(time.Hour)
	if err := db.RollupStats(ctx, later, longer); err != nil {
		t.Fatal(err)
	}
	run("after a rollup with a longer retention")
	if err := db.PruneStats(ctx, later, longer); err != nil {
		t.Fatal(err)
	}
	run("after a prune with a longer retention")
}

// A retention of nothing is a mistake of the caller, not an order to delete
// every row.
func TestRetentionMustBePositive(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()
	putProxyStat(t, db, "stats_proxy_1m", p.ID, statsNow.Add(-time.Hour), ProxyStat{Up: 1})
	for _, r := range []Retention{{}, {Minutes: time.Hour, Hours: day}, {Minutes: -time.Hour, Hours: day, IPs: day}} {
		if err := db.RollupStats(ctx, statsNow, r); err == nil {
			t.Errorf("RollupStats with %+v: no error", r)
		}
		if err := db.PruneStats(ctx, statsNow, r); err == nil {
			t.Errorf("PruneStats with %+v: no error", r)
		}
	}
	if n := count(t, db, `SELECT count(*) FROM stats_proxy_1m`); n != 1 {
		t.Errorf("%d minutes left, want the one there was", n)
	}
}
