package store

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"
)

// maxCountries is the most countries that are kept of a proxy and minute, or
// hour: those with the most bytes. The others are summed under "".
const maxCountries = 50

// countryTables are the tables of the countries, which IPPolicyOff deletes.
var countryTables = []string{"stats_country_1m", "stats_country_1h", "stats_country_1d"}

// A CountryStat is what the clients of one country did on a proxy in a minute,
// hour or day: how many addresses it had (in a minute, those that were seen;
// over a longer period, the most of its minutes) and their bytes.
//
// Country is a code of two upper-case letters A–Z (ISO 3166-1), or "" for the
// clients whose country is not known, and for the countries beyond the 50 that
// are kept of a proxy and minute or hour (those with the most bytes; of two
// with as many, the first by code), which are summed under it. A code that is
// not one is stored as "".
type CountryStat struct {
	ProxyID string
	Country string
	IPs     uint32
	Bytes   uint64
}

// countryCode returns c if it is a code of two upper-case letters A–Z, and ""
// if it is not.
func countryCode(c string) string {
	if len(c) == 2 && 'A' <= c[0] && c[0] <= 'Z' && 'A' <= c[1] && c[1] <= 'Z' {
		return c
	}
	return ""
}

// proxyCountries are the countries of one proxy in a batch.
type proxyCountries struct {
	proxyID string
	rows    []CountryStat
}

// countriesByProxy groups the countries of a batch by proxy, in the order in
// which the proxies first come.
func countriesByProxy(cs []CountryStat) []proxyCountries {
	var out []proxyCountries
	index := map[string]int{}
	for _, c := range cs {
		i, ok := index[c.ProxyID]
		if !ok {
			i = len(out)
			index[c.ProxyID] = i
			out = append(out, proxyCountries{proxyID: c.ProxyID})
		}
		out[i].rows = append(out[i].rows, c)
	}
	return out
}

// capCountries returns the countries of one proxy and minute as they are
// stored: codes checked, a country that comes more than once summed, and at
// most 50, the others summed under "". In a minute, the addresses of one
// country are not those of another, so the addresses of the countries that are
// summed add up. Counters keep the limit of 2^50.
func capCountries(rows []CountryStat) []CountryStat {
	type sum struct{ ips, bytes uint64 }
	add := func(s *sum, ips, bytes uint64) {
		s.ips = min(s.ips+ips, math.MaxUint32)
		s.bytes = min(s.bytes+bytes, maxCounter)
	}
	sums := map[string]*sum{}
	for _, r := range rows {
		c := countryCode(r.Country)
		if sums[c] == nil {
			sums[c] = &sum{}
		}
		add(sums[c], uint64(r.IPs), uint64(clampCounter(r.Bytes)))
	}

	codes := make([]string, 0, len(sums))
	for c := range sums {
		if c != "" {
			codes = append(codes, c)
		}
	}
	slices.SortFunc(codes, func(a, b string) int {
		if n := cmp.Compare(sums[b].bytes, sums[a].bytes); n != 0 {
			return n
		}
		return cmp.Compare(a, b)
	})
	rest := sums[""]
	if len(codes) > maxCountries {
		if rest == nil {
			rest = &sum{}
		}
		for _, c := range codes[maxCountries:] {
			add(rest, sums[c].ips, sums[c].bytes)
		}
		codes = codes[:maxCountries]
	}

	out := make([]CountryStat, 0, len(codes)+1)
	for _, c := range codes {
		out = append(out, CountryStat{Country: c, IPs: uint32(sums[c].ips), Bytes: sums[c].bytes})
	}
	if rest != nil {
		out = append(out, CountryStat{Country: "", IPs: uint32(rest.ips), Bytes: rest.bytes})
	}
	return out
}

// replaceCountryMinutes stores the countries of a proxy in a minute in place of
// those that are there: a minute that comes again is replaced as a whole, so
// that a country that has gone under "" since does not stay as well. A proxy
// that does not exist is [ErrNotFound].
func replaceCountryMinutes(ctx context.Context, q dbtx, proxyID string, minute int64, rows []CountryStat) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM stats_country_1m WHERE proxy_id = ? AND ts = ?`, proxyID, minute); err != nil {
		return err
	}
	for _, c := range capCountries(rows) {
		_, err := q.ExecContext(ctx, `INSERT INTO stats_country_1m (proxy_id, ts, country, ips, bytes) VALUES (?, ?, ?, ?, ?)`,
			proxyID, minute, c.Country, int64(c.IPs), int64(c.Bytes))
		if err != nil {
			return mapErr(err, fkMissing)
		}
	}
	return nil
}

// The rollups of the countries, with the parameters of the others: the rows of
// [?3, ?1), and whole periods from ?2 on (see rollupWindow). A whole period is
// made again as a whole: the rows of a whole period that has finer rows are
// cleared first, so that a country that has gone under "" since does not stay;
// one without finer rows keeps its rows, as the rollups of proxies do. A period
// that is not whole gets rows only when it has none.
//
// An hour keeps the 50 countries with the most bytes in the hour, as a minute
// does; the others go under "", whose addresses are the most that they had
// together in one minute (a minute of a country, and a minute of "", is the
// number of its own addresses). A day sums the bytes of its hours and keeps
// their peak of addresses.
const (
	clearCountryHours = `
DELETE FROM stats_country_1h
WHERE ts >= ?2 AND ts >= ?3 AND ts < ?1 AND EXISTS (
  SELECT 1 FROM stats_country_1m m
  WHERE m.proxy_id = stats_country_1h.proxy_id AND m.ts >= stats_country_1h.ts AND m.ts < stats_country_1h.ts + 3600)`

	clearCountryDays = `
DELETE FROM stats_country_1d
WHERE ts >= ?2 AND ts >= ?3 AND ts < ?1 AND EXISTS (
  SELECT 1 FROM stats_country_1h h
  WHERE h.proxy_id = stats_country_1d.proxy_id AND h.ts >= stats_country_1d.ts AND h.ts < stats_country_1d.ts + 86400)`
)

// rollupCountryHours sums the minutes of each proxy, hour and country once
// (grouped), and numbers the countries of an hour by their bytes, "" last
// (ranked). An hour of up to 50 countries keeps them all, and "" as it is. Of
// an hour of more, the first 50 are kept, and the others are summed with ""
// minute by minute, which only such an hour has to read its minutes again for.
// The "" of a minute is a counter like the others, and keeps their limit: it
// sums up to 51 rows of a minute, and a day of it must not overflow.
var rollupCountryHours = `
WITH grouped AS MATERIALIZED (
  SELECT proxy_id, ts / 3600 * 3600 AS hour, country, MAX(ips) AS ips, SUM(bytes) AS bytes
  FROM stats_country_1m
  WHERE ts >= ?3 AND ts < ?1
  GROUP BY proxy_id, ts / 3600, country
),
ranked AS MATERIALIZED (
  SELECT proxy_id, hour, country, ips, bytes,
         ROW_NUMBER() OVER (PARTITION BY proxy_id, hour ORDER BY country = '', bytes DESC, country) AS place,
         SUM(country <> '') OVER (PARTITION BY proxy_id, hour) AS countries
  FROM grouped
),
hourly AS (
  SELECT proxy_id, hour, country, ips, bytes FROM ranked
  WHERE countries <= ` + strconv.Itoa(maxCountries) + ` OR place <= ` + strconv.Itoa(maxCountries) + `
  UNION ALL
  SELECT proxy_id, hour, '', MAX(ips), SUM(bytes) FROM (
    SELECT r.proxy_id, r.hour, m.ts,
           MIN(SUM(m.ips), ` + strconv.FormatInt(math.MaxUint32, 10) + `) AS ips,
           MIN(SUM(m.bytes), ` + strconv.FormatInt(maxCounter, 10) + `) AS bytes
    FROM ranked r CROSS JOIN stats_country_1m m
      ON m.proxy_id = r.proxy_id AND m.ts >= r.hour AND m.ts < r.hour + 3600 AND m.country = r.country
    WHERE r.countries > ` + strconv.Itoa(maxCountries) + ` AND r.place > ` + strconv.Itoa(maxCountries) + `
    GROUP BY r.proxy_id, r.hour, m.ts
  )
  GROUP BY proxy_id, hour
)
INSERT INTO stats_country_1h (proxy_id, ts, country, ips, bytes)
SELECT proxy_id, hour, country, ips, bytes FROM hourly x
WHERE x.hour >= ?2 OR NOT EXISTS (SELECT 1 FROM stats_country_1h h WHERE h.proxy_id = x.proxy_id AND h.ts = x.hour)`

const rollupCountryDays = `
INSERT INTO stats_country_1d (proxy_id, ts, country, ips, bytes)
SELECT proxy_id, day, country, MAX(ips), SUM(bytes)
FROM (SELECT proxy_id, ts / 86400 * 86400 AS day, country, ips, bytes FROM stats_country_1h WHERE ts >= ?3 AND ts < ?1) h
WHERE h.day >= ?2 OR NOT EXISTS (SELECT 1 FROM stats_country_1d x WHERE x.proxy_id = h.proxy_id AND x.ts = h.day)
GROUP BY proxy_id, day, country`

// CountryFilter narrows CountryTotals to a proxy, to the proxies of a node, or
// both; with both empty it reads every proxy.
type CountryFilter struct{ ProxyID, NodeID string }

// A CountryTotal is what the clients of one country did over a range of time:
// their bytes and IPsPeak, the most unique client IPs that the country had in
// one minute (of the proxies that the filter takes, summed, as the devices of
// proxies are). Country "" holds the clients whose country is not known.
type CountryTotal struct {
	Country string
	Bytes   uint64
	IPsPeak uint32
}

// CountryTotals returns the countries of [from, to), those with the most bytes
// first (then by code). Whole hours are read from the hour rows, which are
// kept for 30 days (whole days beyond that), and the minutes of the partial
// hours at both ends are added.
func (db *DB) CountryTotals(ctx context.Context, f CountryFilter, from, to time.Time) ([]CountryTotal, error) {
	spans, err := db.totalSpans(ctx, "stats_country_1h", from, to, keepCountryHours)
	if err != nil {
		return nil, err
	}
	acc := map[string]CountryTotal{}
	for _, sp := range spans {
		rows, err := db.sql.QueryContext(ctx,
			`SELECT country, SUM(bytes), MAX(ips) FROM (
			   SELECT country, ts, SUM(ips) AS ips, SUM(bytes) AS bytes FROM stats_country_`+sp.res+`
			   WHERE ts >= ?1 AND ts < ?2 AND (?3 = '' OR proxy_id = ?3)
			     AND (?4 = '' OR proxy_id IN (SELECT id FROM proxies WHERE node_id = ?4))
			   GROUP BY country, ts)
			 GROUP BY country`, sp.lo, sp.hi, f.ProxyID, f.NodeID)
		if err != nil {
			return nil, fmt.Errorf("store: country totals: %w", err)
		}
		for rows.Next() {
			var c string
			var bytes, ips int64
			if err := rows.Scan(&c, &bytes, &ips); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("store: country totals: %w", err)
			}
			t := acc[c]
			t.Country = c
			t.Bytes += uint64Of(bytes)
			t.IPsPeak = max(t.IPsPeak, uint32Of(ips))
			acc[c] = t
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, fmt.Errorf("store: country totals: %w", err)
		}
	}
	out := make([]CountryTotal, 0, len(acc))
	for _, t := range acc {
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b CountryTotal) int {
		if c := cmp.Compare(b.Bytes, a.Bytes); c != 0 {
			return c
		}
		return cmp.Compare(a.Country, b.Country)
	})
	return out, nil
}
