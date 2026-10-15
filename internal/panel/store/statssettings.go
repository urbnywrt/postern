package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"
)

// The IP policies (spec §8.6): what the panel and its nodes keep of the
// addresses of clients.
const (
	// IPPolicyFull keeps where each address was seen (ip_sightings), and the
	// countries.
	IPPolicyFull = "full"
	// IPPolicyCountries keeps the countries of the clients only: per minute, how
	// many addresses a country had and their bytes. No address is stored.
	IPPolicyCountries = "countries"
	// IPPolicyOff keeps nothing of the addresses. The devices of a proxy, which
	// are a count, stay.
	IPPolicyOff = "off"
)

// The keys of the statistics settings in the table settings. A key that is not
// there is its default.
const (
	settingStats    = "stats"     // {"minutes_hours":48,"hours_days":90,"ip_days":7}
	settingIPPolicy = "ip_policy" // "countries"
	settingProbes   = "probes"    // {"interval_minutes":5,"extra_sources":[]}
)

// The ranges of the statistics settings.
const (
	minMinutesHours, maxMinutesHours = 6, 168 // minutes are kept for 6 hours to a week
	minHoursDays, maxHoursDays       = 7, 730 // hours for a week to two years
	minIPDays, maxIPDays             = 1, 30  // where an address was seen, a day to a month
	maxProbeIntervalMinutes          = 60     // 0 is no probes
	maxExtraProbeSources             = 16
)

// Retention is how long statistics are kept: the minutes, the hours, and where
// the addresses were seen. Days are kept for good, and the other tables for
// times of their own (see [DB.PruneStats]).
type Retention struct{ Minutes, Hours, IPs time.Duration }

// check refuses a retention that would delete every row: the zero value, which
// a caller that forgot to set one passes.
func (r Retention) check() error {
	if r.Minutes <= 0 || r.Hours <= 0 || r.IPs <= 0 {
		return fmt.Errorf("store: a retention of %s for minutes, %s for hours and %s for addresses: each has to be more than nothing",
			r.Minutes, r.Hours, r.IPs)
	}
	return nil
}

// StatsSettings are the settings of the statistics: how long they are kept,
// what is kept of the addresses of clients, and the probes of the panel.
type StatsSettings struct {
	MinutesHours uint32 // hours that minutes are kept, 6 to 168
	HoursDays    uint32 // days that hours are kept, 7 to 730
	IPDays       uint32 // days that where an address was seen is kept, 1 to 30
	IPPolicy     string // IPPolicyFull, IPPolicyCountries or IPPolicyOff
	// ProbeIntervalMinutes is how often the panel probes every proxy, 0 to 60
	// minutes; 0 is never.
	ProbeIntervalMinutes uint32
	// ExtraProbeSources are the addresses that the nodes let probe their
	// proxies besides the panel: at most 16, each a single address, never a
	// prefix, which would let a whole network through.
	ExtraProbeSources []string
}

// DefaultStatsSettings are the settings while none are stored: minutes for 48
// hours, hours for 90 days, addresses for 7 days, the policy countries, and a
// probe every 5 minutes.
func DefaultStatsSettings() StatsSettings {
	return StatsSettings{MinutesHours: 48, HoursDays: 90, IPDays: 7, IPPolicy: IPPolicyCountries, ProbeIntervalMinutes: 5}
}

// Validate reports every setting that is out of its range.
func (s StatsSettings) Validate() error {
	var errs []error
	if s.MinutesHours < minMinutesHours || s.MinutesHours > maxMinutesHours {
		errs = append(errs, fmt.Errorf("minutes are kept for %d to %d hours, not %d", minMinutesHours, maxMinutesHours, s.MinutesHours))
	}
	if s.HoursDays < minHoursDays || s.HoursDays > maxHoursDays {
		errs = append(errs, fmt.Errorf("hours are kept for %d to %d days, not %d", minHoursDays, maxHoursDays, s.HoursDays))
	}
	if s.IPDays < minIPDays || s.IPDays > maxIPDays {
		errs = append(errs, fmt.Errorf("where addresses were seen is kept for %d to %d days, not %d", minIPDays, maxIPDays, s.IPDays))
	}
	switch s.IPPolicy {
	case IPPolicyFull, IPPolicyCountries, IPPolicyOff:
	default:
		errs = append(errs, fmt.Errorf("the IP policy is %q, %q or %q, not %q", IPPolicyFull, IPPolicyCountries, IPPolicyOff, s.IPPolicy))
	}
	if s.ProbeIntervalMinutes > maxProbeIntervalMinutes {
		errs = append(errs, fmt.Errorf("probes run every 1 to %d minutes, or never (0), not every %d", maxProbeIntervalMinutes, s.ProbeIntervalMinutes))
	}
	if len(s.ExtraProbeSources) > maxExtraProbeSources {
		errs = append(errs, fmt.Errorf("at most %d extra probe sources, not %d", maxExtraProbeSources, len(s.ExtraProbeSources)))
	}
	for _, src := range s.ExtraProbeSources {
		if err := checkProbeSource(src); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// checkProbeSource refuses an extra probe source that is not one address of
// one host.
func checkProbeSource(src string) error {
	if strings.Contains(src, "/") {
		return fmt.Errorf("the extra probe source %q is a prefix: only single addresses are let through", src)
	}
	a, err := netip.ParseAddr(src)
	switch {
	case err != nil:
		return fmt.Errorf("the extra probe source %q is not an IP address", src)
	case a.Zone() != "":
		return fmt.Errorf("the extra probe source %q has a zone", src)
	case a.IsUnspecified() || a.IsMulticast():
		return fmt.Errorf("the extra probe source %q is not the address of one host", src)
	}
	return nil
}

// FallbackRetention is the retention to prune by when the stored settings
// cannot be read: the longest that a setting may keep the minutes and the
// hours, so that it deletes no statistic that a valid setting would keep, and
// the shortest that it may keep where an address was seen, so that it errs
// toward deleting addresses.
func FallbackRetention() Retention {
	return StatsSettings{MinutesHours: maxMinutesHours, HoursDays: maxHoursDays, IPDays: minIPDays}.Retention()
}

// ipPolicy returns the IP policy that is stored, the default (countries) while
// none is, and off when it cannot be read: what is not known to be allowed is
// not kept.
func ipPolicy(ctx context.Context, q dbtx) string {
	policy := DefaultStatsSettings().IPPolicy
	if _, err := getSetting(ctx, q, settingIPPolicy, &policy); err != nil {
		return IPPolicyOff
	}
	return policy
}

// Retention is how long the settings keep the statistics.
func (s StatsSettings) Retention() Retention {
	return Retention{
		Minutes: time.Duration(s.MinutesHours) * time.Hour,
		Hours:   time.Duration(s.HoursDays) * 24 * time.Hour,
		IPs:     time.Duration(s.IPDays) * 24 * time.Hour,
	}
}

// statsSetting and probesSetting are the values of the keys stats and probes.
type statsSetting struct {
	MinutesHours uint32 `json:"minutes_hours"`
	HoursDays    uint32 `json:"hours_days"`
	IPDays       uint32 `json:"ip_days"`
}

type probesSetting struct {
	IntervalMinutes uint32   `json:"interval_minutes"`
	ExtraSources    []string `json:"extra_sources"`
}

// StatsSettings returns the statistics settings. A key that is not stored, or a
// field that a key leaves out, is its default. stored reports whether the IP
// policy is stored, which it is from the first time that settings are applied;
// until then the settings are the defaults. Settings that were stored out of
// their ranges, by hand, are an error rather than a retention that deletes what
// it should keep.
func (db *DB) StatsSettings(ctx context.Context) (s StatsSettings, stored bool, err error) {
	d := DefaultStatsSettings()
	st := statsSetting{MinutesHours: d.MinutesHours, HoursDays: d.HoursDays, IPDays: d.IPDays}
	policy := d.IPPolicy
	pr := probesSetting{IntervalMinutes: d.ProbeIntervalMinutes}

	// One query, so that the keys are read as one transaction wrote them.
	rows, err := db.sql.QueryContext(ctx, `SELECT key, value FROM settings WHERE key IN (?, ?, ?)`,
		settingStats, settingIPPolicy, settingProbes)
	if err != nil {
		return StatsSettings{}, false, fmt.Errorf("store: stats settings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var key, raw string
		if err := rows.Scan(&key, &raw); err != nil {
			return StatsSettings{}, false, fmt.Errorf("store: stats settings: %w", err)
		}
		var dst any
		switch key {
		case settingStats:
			dst = &st
		case settingIPPolicy:
			dst, stored = &policy, true
		default:
			dst = &pr
		}
		if err := json.Unmarshal([]byte(raw), dst); err != nil {
			return StatsSettings{}, false, fmt.Errorf("store: stats settings: decode %q: %w", key, err)
		}
	}
	if err := rows.Err(); err != nil {
		return StatsSettings{}, false, fmt.Errorf("store: stats settings: %w", err)
	}

	s = StatsSettings{
		MinutesHours: st.MinutesHours, HoursDays: st.HoursDays, IPDays: st.IPDays,
		IPPolicy: policy, ProbeIntervalMinutes: pr.IntervalMinutes,
	}
	if len(pr.ExtraSources) > 0 {
		s.ExtraProbeSources = pr.ExtraSources
	}
	if err := s.Validate(); err != nil {
		return StatsSettings{}, false, fmt.Errorf("store: the stored stats settings are not valid: %w", err)
	}
	return s, stored, nil
}

// Deleted counts the rows that ApplyStatsSettings deleted because the new IP
// policy does not keep them.
type Deleted struct{ Sightings, CountryRows int64 }

// ApplyStatsSettings validates s, and in one transaction stores it and deletes
// what its IP policy does not keep: where the addresses were seen unless the
// policy is full, and the countries (stats_country_1m, 1h and 1d) when it is
// off. A failure leaves the settings and the data as they were.
//
// After rows are deleted, the write-ahead log is emptied into the database
// file, where secure_delete has overwritten them, so that they are gone from
// the disk as well. A reader that keeps the log from being emptied does not
// fail the call, which has applied the settings: it is logged, and the next
// PruneStats empties the log.
func (db *DB) ApplyStatsSettings(ctx context.Context, s StatsSettings) (Deleted, error) {
	if err := s.Validate(); err != nil {
		return Deleted{}, fmt.Errorf("store: apply stats settings: %w", err)
	}
	sources := s.ExtraProbeSources
	if sources == nil {
		sources = []string{} // stored as [], as the setting is documented
	}
	var d Deleted
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		d = Deleted{}
		for _, kv := range []struct {
			key   string
			value any
		}{
			{settingStats, statsSetting{MinutesHours: s.MinutesHours, HoursDays: s.HoursDays, IPDays: s.IPDays}},
			{settingIPPolicy, s.IPPolicy},
			{settingProbes, probesSetting{IntervalMinutes: s.ProbeIntervalMinutes, ExtraSources: sources}},
		} {
			if err := putSetting(ctx, tx, kv.key, kv.value); err != nil {
				return err
			}
		}
		if s.IPPolicy != IPPolicyFull {
			n, err := execCount(ctx, tx, `DELETE FROM ip_sightings`)
			if err != nil {
				return fmt.Errorf("delete the sightings: %w", err)
			}
			d.Sightings = n
		}
		if s.IPPolicy == IPPolicyOff {
			for _, table := range countryTables {
				n, err := execCount(ctx, tx, `DELETE FROM `+table)
				if err != nil {
					return fmt.Errorf("delete %s: %w", table, err)
				}
				d.CountryRows += n
			}
		}
		return nil
	})
	if err != nil {
		return Deleted{}, fmt.Errorf("store: apply stats settings: %w", err)
	}
	if err := db.scrubWAL(ctx, d != (Deleted{})); err != nil {
		slog.Warn("store: the write-ahead log still holds the rows that the statistics settings deleted, "+
			"because a reader is using it; the next prune of the statistics empties it", "err", err)
	}
	return d, nil
}

// execCount runs a statement and returns the number of rows that it changed.
func execCount(ctx context.Context, q dbtx, query string, args ...any) (int64, error) {
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
