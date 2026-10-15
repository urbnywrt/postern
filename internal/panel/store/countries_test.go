package store

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

// code is the i-th country code of two letters: AA, AB, ... AZ, BA, ... They
// sort in the order of i.
func code(i int) string {
	return string([]byte{byte('A' + i/26), byte('A' + i%26)})
}

// countryRows returns the rows of a country table of a proxy and period as
// "country|ips|bytes", by country.
func countryRows(t *testing.T, db *DB, table, proxyID string, ts time.Time) []string {
	t.Helper()
	return rowsOf(t, db, `SELECT country, ips, bytes FROM `+table+` WHERE proxy_id = ? AND ts = ? ORDER BY country`, proxyID, ts.Unix())
}

// A code is two upper-case letters A–Z; anything else is stored as "", summed
// with the others that are not codes.
func TestCountryCodes(t *testing.T) {
	db, node, p, _ := ingestFixture(t)
	m := at(10, 12, 0)
	c := func(country string, ips uint32, bytes uint64) CountryStat {
		return CountryStat{ProxyID: p.ID, Country: country, IPs: ips, Bytes: bytes}
	}
	ingest(t, db, MinuteBatch{NodeID: node.ID, Minute: m, Countries: []CountryStat{
		c("DE", 1, 1), c("de", 1, 2), c("D", 1, 4), c("DEU", 1, 8), c("Ä", 1, 16), c("1A", 1, 32), c("", 1, 64), c("FR", 2, 128),
	}})
	want := []string{"|6|126", "DE|1|1", "FR|2|128"}
	if got := countryRows(t, db, "stats_country_1m", p.ID, m); !slices.Equal(got, want) {
		t.Errorf("country minutes = %q, want %q", got, want)
	}
}

// At most 50 countries are kept of a proxy and minute, those with the most
// bytes (of two with as many, the first by its code); the others are summed
// under "", with what came as "".
func TestCountryCapOfAMinute(t *testing.T) {
	db, node, p, _ := ingestFixture(t)
	m := at(10, 12, 0)
	var cs []CountryStat
	for i := range 50 {
		cs = append(cs, CountryStat{ProxyID: p.ID, Country: code(i), IPs: 1, Bytes: uint64(1000 - i)})
	}
	cs = append(cs,
		CountryStat{ProxyID: p.ID, Country: code(50), IPs: 1, Bytes: 951}, // as many as code(49)
		CountryStat{ProxyID: p.ID, Country: code(51), IPs: 1, Bytes: 900},
		CountryStat{ProxyID: p.ID, Country: code(52), IPs: 1, Bytes: 899},
		CountryStat{ProxyID: p.ID, Country: "", IPs: 2, Bytes: 7},
	)
	ingest(t, db, MinuteBatch{NodeID: node.ID, Minute: m, Countries: cs})

	want := []string{"|5|2757"}
	for i := range 50 {
		want = append(want, fmt.Sprintf("%s|1|%d", code(i), 1000-i))
	}
	if got := countryRows(t, db, "stats_country_1m", p.ID, m); !slices.Equal(got, want) {
		t.Errorf("country minutes = %q\nwant %q", got, want)
	}
}

// At most 50 countries are kept of a proxy and hour, by their bytes in the
// hour. The others are summed under "": their bytes, and as addresses the most
// that they had together in one minute. A late minute that changes which ones
// are kept changes the hour: a country that is no longer kept leaves no row.
func TestCountryCapOfAnHour(t *testing.T) {
	db, node, p, _ := ingestFixture(t)
	ctx := context.Background()
	minute := func(m int, from, to int, ips uint32, bytes uint64) {
		t.Helper()
		var cs []CountryStat
		for i := from; i < to; i++ {
			cs = append(cs, CountryStat{ProxyID: p.ID, Country: code(i), IPs: ips, Bytes: bytes})
		}
		ingest(t, db, MinuteBatch{NodeID: node.ID, Minute: at(10, 9, m), Countries: cs})
	}
	hourRows := func() []string {
		t.Helper()
		if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
			t.Fatalf("RollupStats: %v", err)
		}
		return countryRows(t, db, "stats_country_1h", p.ID, at(10, 9, 0))
	}

	// Countries 0-24 have 100 bytes in the hour, 25-49 have 200, 50-74 have
	// 100. Kept: 25-49, and of those with 100 the first 25 by code, 0-24.
	minute(0, 0, 50, 1, 100)
	minute(1, 25, 75, 2, 100)
	want := []string{"|50|2500"} // 50-74: 2 addresses each in minute 1
	for i := range 50 {
		if i < 25 {
			want = append(want, fmt.Sprintf("%s|1|100", code(i)))
		} else {
			want = append(want, fmt.Sprintf("%s|2|200", code(i)))
		}
	}
	if got := hourRows(); !slices.Equal(got, want) {
		t.Errorf("country hours = %q\nwant %q", got, want)
	}

	// Now 50-74 have 600 bytes, and 0-24 go under "".
	minute(2, 50, 75, 3, 500)
	want = []string{"|25|2500"} // 0-24: 1 address each in minute 0
	for i := 25; i < 75; i++ {
		if i < 50 {
			want = append(want, fmt.Sprintf("%s|2|200", code(i)))
		} else {
			want = append(want, fmt.Sprintf("%s|3|600", code(i)))
		}
	}
	if got := hourRows(); !slices.Equal(got, want) {
		t.Errorf("country hours after a late minute = %q\nwant %q", got, want)
	}
}

// A day of a country is its bytes summed and its peak of addresses, of every
// hour of the day; it is made again while the day is whole, and a country that
// has left every hour of it leaves the day as well.
func TestCountryDays(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()
	putCountry(t, db, "stats_country_1h", p.ID, at(8, 1, 0), "DE", 3, 100)
	putCountry(t, db, "stats_country_1h", p.ID, at(8, 13, 0), "DE", 5, 50)
	putCountry(t, db, "stats_country_1h", p.ID, at(8, 13, 0), "", 1, 7)
	putCountry(t, db, "stats_country_1h", p.ID, at(10, 3, 0), "DE", 9, 9) // today, which is not over

	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	// The hour of 13:00 is whole, and has no minutes to be made again of: its
	// rows stay as they are.
	if got := countryRows(t, db, "stats_country_1h", p.ID, at(8, 13, 0)); !slices.Equal(got, []string{"|1|7", "DE|5|50"}) {
		t.Errorf("country hour without minutes = %q, want its rows kept", got)
	}
	if got := countryRows(t, db, "stats_country_1d", p.ID, at(8, 0, 0)); !slices.Equal(got, []string{"|1|7", "DE|5|150"}) {
		t.Errorf("country day = %q", got)
	}
	if n := count(t, db, `SELECT count(*) FROM stats_country_1d WHERE ts = ?`, at(10, 0, 0).Unix()); n != 0 {
		t.Errorf("%d rows of the day that is not over", n)
	}

	mustExec(t, db, `DELETE FROM stats_country_1h WHERE country = ''`)
	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatal(err)
	}
	if got := countryRows(t, db, "stats_country_1d", p.ID, at(8, 0, 0)); !slices.Equal(got, []string{"DE|5|150"}) {
		t.Errorf("country day after its hours changed = %q, want only DE", got)
	}
}

// Country hours are kept for 30 days, and a day of countries is final from the
// moment the prune starts to delete its hours: a rollup after the cut leaves
// it as it was.
func TestCountryDayIsFinalOnceItsHoursAreCut(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()
	day := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	putCountry(t, db, "stats_country_1h", p.ID, day.Add(time.Hour), "DE", 3, 100)
	putCountry(t, db, "stats_country_1h", p.ID, day.Add(13*time.Hour), "DE", 5, 50)

	// Two days after it, the day is made of its hours, which are all there.
	if err := db.RollupStats(ctx, day.Add(2*24*time.Hour), testRetention); err != nil {
		t.Fatal(err)
	}
	if got := countryRows(t, db, "stats_country_1d", p.ID, day); !slices.Equal(got, []string{"DE|5|150"}) {
		t.Fatalf("country day = %q, want DE|5|150", got)
	}

	// Thirty days after its noon, its hour of 01:00 is pruned.
	later := day.Add(30*24*time.Hour + 12*time.Hour)
	if err := db.PruneStats(ctx, later, testRetention); err != nil {
		t.Fatal(err)
	}
	if got := rowsOf(t, db, `SELECT ts FROM stats_country_1h`); !slices.Equal(got, []string{fmt.Sprint(day.Add(13 * time.Hour).Unix())}) {
		t.Fatalf("country hours after the prune = %v, want the one of 13:00", got)
	}
	mustExec(t, db, `UPDATE stats_country_1h SET bytes = 1, ips = 1`)
	for _, now := range []time.Time{later, later.Add(24 * time.Hour)} {
		if err := db.RollupStats(ctx, now, testRetention); err != nil {
			t.Fatal(err)
		}
		if got := countryRows(t, db, "stats_country_1d", p.ID, day); !slices.Equal(got, []string{"DE|5|150"}) {
			t.Errorf("country day after a rollup at %s = %q, want it as it was", now.Format(time.DateTime), got)
		}
	}
}

// The most that the countries ever add up: a whole day of minutes of a proxy
// with 60 countries, every one at the limit of a counter. The 10 beyond the 50
// that an hour keeps go under "", which is a counter of its own and keeps the
// limit in every minute; otherwise its day would be 14,400 times the limit,
// beyond int64, and every rollup and prune would fail from then on.
func TestCountryRollupOfADayAtTheCap(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()
	day := at(8, 0, 0)
	mustExec(t, db, `WITH RECURSIVE m(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM m WHERE i < 1439),
		c(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM c WHERE j < 59)
		INSERT INTO stats_country_1m (proxy_id, ts, country, ips, bytes)
		SELECT ?, ? + i * 60, char(65 + j / 26, 65 + j % 26), 1, ? FROM m, c`,
		p.ID, day.Unix(), int64(cappedCounter))

	if err := db.RollupStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("RollupStats: %v", err)
	}
	want := []string{fmt.Sprintf("|10|%d", int64(24*60*cappedCounter))} // 10 addresses a minute, the limit a minute
	for i := range 50 {
		want = append(want, fmt.Sprintf("%s|1|%d", code(i), int64(24*60*cappedCounter)))
	}
	if got := countryRows(t, db, "stats_country_1d", p.ID, day); !slices.Equal(got, want) {
		t.Errorf("country day = %q\nwant %q", got, want)
	}
	if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
		t.Errorf("PruneStats: %v", err)
	}
}

// What PruneStats deletes of the countries it rolls up first, into the hours
// and the days that have no rows yet.
func TestPruneStatsRollsUpTheCountriesItDeletes(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()
	putCountry(t, db, "stats_country_1m", p.ID, at(8, 11, 10), "DE", 2, 10) // more than 48 hours ago
	putCountry(t, db, "stats_country_1m", p.ID, at(8, 11, 20), "DE", 3, 20)
	day := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC) // more than 30 days ago
	putCountry(t, db, "stats_country_1h", p.ID, day.Add(5*time.Hour), "NL", 4, 40)

	if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}
	if got := countryRows(t, db, "stats_country_1h", p.ID, at(8, 11, 0)); !slices.Equal(got, []string{"DE|3|30"}) {
		t.Errorf("country hour of the pruned minutes = %q, want DE|3|30", got)
	}
	if got := countryRows(t, db, "stats_country_1d", p.ID, day); !slices.Equal(got, []string{"NL|4|40"}) {
		t.Errorf("country day of the pruned hours = %q, want NL|4|40", got)
	}
	if n := count(t, db, `SELECT count(*) FROM stats_country_1m`) + count(t, db, `SELECT count(*) FROM stats_country_1h WHERE ts < ?`, day.Add(24*time.Hour).Unix()); n != 0 {
		t.Errorf("%d pruned country rows are left", n)
	}
}
