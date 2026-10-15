package store

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// putSighting writes where an address was seen, with SQL.
func putSighting(t *testing.T, db *DB, proxyID, ip string, lastSeen time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO ip_sightings (proxy_id, ip, first_seen, last_seen, bytes) VALUES (?, ?, ?, ?, 1)`,
		proxyID, ip, lastSeen.Add(-time.Hour).Unix(), lastSeen.Unix())
}

// putCountry writes a row of one of the country tables, with SQL.
func putCountry(t *testing.T, db *DB, table, proxyID string, ts time.Time, country string, ips, bytes int) {
	t.Helper()
	mustExec(t, db, `INSERT INTO `+table+` (proxy_id, ts, country, ips, bytes) VALUES (?, ?, ?, ?, ?)`,
		proxyID, ts.Unix(), country, ips, bytes)
}

// settingJSON returns the raw JSON of a setting, "" when it is not there.
func settingJSON(t *testing.T, db *DB, key string) string {
	t.Helper()
	var v string
	if err := db.sql.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return ""
	}
	return v
}

func TestDefaultStatsSettings(t *testing.T) {
	want := StatsSettings{MinutesHours: 48, HoursDays: 90, IPDays: 7, IPPolicy: "countries", ProbeIntervalMinutes: 5}
	if got := DefaultStatsSettings(); !reflect.DeepEqual(got, want) {
		t.Errorf("DefaultStatsSettings() = %+v, want %+v", got, want)
	}
	if err := DefaultStatsSettings().Validate(); err != nil {
		t.Errorf("the defaults are not valid: %v", err)
	}
	wantR := Retention{Minutes: 48 * time.Hour, Hours: 90 * 24 * time.Hour, IPs: 7 * 24 * time.Hour}
	if got := DefaultStatsSettings().Retention(); got != wantR {
		t.Errorf("Retention() of the defaults = %+v, want %+v", got, wantR)
	}
}

func TestStatsSettingsRetention(t *testing.T) {
	s := StatsSettings{MinutesHours: 6, HoursDays: 730, IPDays: 30}
	want := Retention{Minutes: 6 * time.Hour, Hours: 730 * 24 * time.Hour, IPs: 30 * 24 * time.Hour}
	if got := s.Retention(); got != want {
		t.Errorf("Retention() = %+v, want %+v", got, want)
	}
}

// Until the settings are stored, they read as the defaults, and stored says so.
func TestStatsSettingsBeforeAnyAreStored(t *testing.T) {
	db := newTestDB(t)
	s, stored, err := db.StatsSettings(context.Background())
	if err != nil {
		t.Fatalf("StatsSettings: %v", err)
	}
	if stored {
		t.Error("stored = true in a database that has no statistics settings")
	}
	if !reflect.DeepEqual(s, DefaultStatsSettings()) {
		t.Errorf("StatsSettings = %+v, want the defaults", s)
	}
}

func TestApplyStatsSettingsStoresThem(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	want := StatsSettings{
		MinutesHours: 72, HoursDays: 365, IPDays: 14, IPPolicy: "full",
		ProbeIntervalMinutes: 0, ExtraProbeSources: []string{"192.0.2.10", "2001:db8::10"},
	}
	if _, err := db.ApplyStatsSettings(ctx, want); err != nil {
		t.Fatalf("ApplyStatsSettings: %v", err)
	}
	got, stored, err := db.StatsSettings(ctx)
	if err != nil || !stored {
		t.Fatalf("StatsSettings = %v, %v; want stored settings", stored, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("StatsSettings = %+v\nwant          %+v", got, want)
	}
	// The keys and their shapes are those of the settings table.
	for key, raw := range map[string]string{
		"stats":     `{"minutes_hours":72,"hours_days":365,"ip_days":14}`,
		"ip_policy": `"full"`,
		"probes":    `{"interval_minutes":0,"extra_sources":["192.0.2.10","2001:db8::10"]}`,
	} {
		if got := settingJSON(t, db, key); got != raw {
			t.Errorf("setting %s = %s, want %s", key, got, raw)
		}
	}

	// No extra sources are stored as an empty list, and read back as none.
	want.ExtraProbeSources = nil
	if _, err := db.ApplyStatsSettings(ctx, want); err != nil {
		t.Fatal(err)
	}
	if got := settingJSON(t, db, "probes"); got != `{"interval_minutes":0,"extra_sources":[]}` {
		t.Errorf("setting probes = %s, want an empty list of sources", got)
	}
	if got, _, _ := db.StatsSettings(ctx); got.ExtraProbeSources != nil {
		t.Errorf("ExtraProbeSources = %#v, want nil", got.ExtraProbeSources)
	}
}

// A key that is not there reads as its defaults, and so does a field that a
// key leaves out; stored is about the IP policy alone.
func TestStatsSettingsReadKeyByKey(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.PutSetting(ctx, "probes", map[string]any{"interval_minutes": 0}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutSetting(ctx, "stats", map[string]any{"ip_days": 3}); err != nil {
		t.Fatal(err)
	}
	s, stored, err := db.StatsSettings(ctx)
	if err != nil {
		t.Fatalf("StatsSettings: %v", err)
	}
	want := DefaultStatsSettings()
	want.IPDays, want.ProbeIntervalMinutes = 3, 0 // 0 is "off", not "absent"
	if stored || !reflect.DeepEqual(s, want) {
		t.Errorf("StatsSettings = %+v, stored = %v; want %+v, false", s, stored, want)
	}

	if err := db.PutSetting(ctx, "ip_policy", "off"); err != nil {
		t.Fatal(err)
	}
	s, stored, err = db.StatsSettings(ctx)
	want.IPPolicy = "off"
	if err != nil || !stored || !reflect.DeepEqual(s, want) {
		t.Errorf("StatsSettings = %+v, %v, %v; want %+v, stored", s, stored, err, want)
	}
}

// Settings that were stored by hand out of their ranges are an error rather
// than a retention that deletes what it should keep.
func TestStatsSettingsRefusesStoredValuesOutOfRange(t *testing.T) {
	for key, value := range map[string]any{
		"stats":     map[string]any{"minutes_hours": 0},
		"ip_policy": "everything",
		"probes":    map[string]any{"extra_sources": []string{"192.0.2.0/24"}},
	} {
		t.Run(key, func(t *testing.T) {
			db := newTestDB(t)
			if err := db.PutSetting(context.Background(), key, value); err != nil {
				t.Fatal(err)
			}
			if _, _, err := db.StatsSettings(context.Background()); err == nil {
				t.Errorf("StatsSettings with %s = %v: no error", key, value)
			}
		})
	}
}

func TestStatsSettingsValidate(t *testing.T) {
	sources := func(n int) []string {
		var out []string
		for i := range n {
			out = append(out, "192.0.2."+strconv.Itoa(i+1))
		}
		return out
	}
	tests := []struct {
		name    string
		change  func(*StatsSettings)
		wantErr string // "" when valid
	}{
		{"the defaults", func(*StatsSettings) {}, ""},
		{"minutes for 6 hours", func(s *StatsSettings) { s.MinutesHours = 6 }, ""},
		{"minutes for 168 hours", func(s *StatsSettings) { s.MinutesHours = 168 }, ""},
		{"minutes for 5 hours", func(s *StatsSettings) { s.MinutesHours = 5 }, "minutes"},
		{"minutes for 169 hours", func(s *StatsSettings) { s.MinutesHours = 169 }, "minutes"},
		{"hours for 7 days", func(s *StatsSettings) { s.HoursDays = 7 }, ""},
		{"hours for 730 days", func(s *StatsSettings) { s.HoursDays = 730 }, ""},
		{"hours for 6 days", func(s *StatsSettings) { s.HoursDays = 6 }, "hours"},
		{"hours for 731 days", func(s *StatsSettings) { s.HoursDays = 731 }, "hours"},
		{"addresses for 1 day", func(s *StatsSettings) { s.IPDays = 1 }, ""},
		{"addresses for 30 days", func(s *StatsSettings) { s.IPDays = 30 }, ""},
		{"addresses for 0 days", func(s *StatsSettings) { s.IPDays = 0 }, "addresses"},
		{"addresses for 31 days", func(s *StatsSettings) { s.IPDays = 31 }, "addresses"},
		{"policy full", func(s *StatsSettings) { s.IPPolicy = "full" }, ""},
		{"policy off", func(s *StatsSettings) { s.IPPolicy = "off" }, ""},
		{"no policy", func(s *StatsSettings) { s.IPPolicy = "" }, "policy"},
		{"an unknown policy", func(s *StatsSettings) { s.IPPolicy = "Full" }, "policy"},
		{"probes off", func(s *StatsSettings) { s.ProbeIntervalMinutes = 0 }, ""},
		{"probes every 60 minutes", func(s *StatsSettings) { s.ProbeIntervalMinutes = 60 }, ""},
		{"probes every 61 minutes", func(s *StatsSettings) { s.ProbeIntervalMinutes = 61 }, "probe"},
		{"16 sources", func(s *StatsSettings) { s.ExtraProbeSources = sources(16) }, ""},
		{"17 sources", func(s *StatsSettings) { s.ExtraProbeSources = sources(17) }, "16"},
		{"an IPv6 address", func(s *StatsSettings) { s.ExtraProbeSources = []string{"2001:db8::1"} }, ""},
		{"an IPv4 prefix", func(s *StatsSettings) { s.ExtraProbeSources = []string{"192.0.2.0/24"} }, "prefix"},
		{"a single-address prefix", func(s *StatsSettings) { s.ExtraProbeSources = []string{"192.0.2.1/32"} }, "prefix"},
		{"an IPv6 prefix", func(s *StatsSettings) { s.ExtraProbeSources = []string{"2001:db8::/64"} }, "prefix"},
		{"a host name", func(s *StatsSettings) { s.ExtraProbeSources = []string{"probe.example.com"} }, "probe.example.com"},
		{"an address with a zone", func(s *StatsSettings) { s.ExtraProbeSources = []string{"fe80::1%eth0"} }, "zone"},
		{"the unspecified address", func(s *StatsSettings) { s.ExtraProbeSources = []string{"0.0.0.0"} }, "0.0.0.0"},
		{"a multicast address", func(s *StatsSettings) { s.ExtraProbeSources = []string{"ff02::1"} }, "ff02::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := DefaultStatsSettings()
			tt.change(&s)
			err := s.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("Validate() = %v, want nil", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("Validate() = %v, want an error that mentions %q", err, tt.wantErr)
			}
		})
	}
}

// Settings that are not valid are refused before anything is written.
func TestApplyStatsSettingsRefusesInvalidSettings(t *testing.T) {
	db := newTestDB(t)
	s := DefaultStatsSettings()
	s.ExtraProbeSources = []string{"198.51.100.0/24"}
	if _, err := db.ApplyStatsSettings(context.Background(), s); err == nil || !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("ApplyStatsSettings with a prefix: err = %v, want it refused", err)
	}
	if n := count(t, db, `SELECT count(*) FROM settings`); n != 0 {
		t.Errorf("%d settings were written, want none", n)
	}
}

// ipFixture is statsFixture with an address seen on each proxy and a row of
// every country table of p.
func ipFixture(t *testing.T) (*DB, *Proxy, *Proxy) {
	t.Helper()
	db, _, p, q := statsFixture(t)
	putSighting(t, db, p.ID, "198.51.100.1", statsNow)
	putSighting(t, db, q.ID, "198.51.100.2", statsNow)
	putCountry(t, db, "stats_country_1m", p.ID, at(10, 12, 0), "DE", 1, 10)
	putCountry(t, db, "stats_country_1h", p.ID, at(10, 11, 0), "DE", 1, 10)
	putCountry(t, db, "stats_country_1h", p.ID, at(10, 11, 0), "NL", 1, 10)
	putCountry(t, db, "stats_country_1d", p.ID, at(9, 0, 0), "DE", 1, 10)
	return db, p, q
}

func withPolicy(policy string) StatsSettings {
	s := DefaultStatsSettings()
	s.IPPolicy = policy
	return s
}

// storePolicy stores the settings with this IP policy.
func storePolicy(t *testing.T, db *DB, policy string) {
	t.Helper()
	if _, err := db.ApplyStatsSettings(context.Background(), withPolicy(policy)); err != nil {
		t.Fatal(err)
	}
}

// Leaving full deletes where the addresses were seen; off deletes the countries
// as well; full deletes nothing.
func TestApplyStatsSettingsDeletesWhatThePolicyNoLongerKeeps(t *testing.T) {
	ctx := context.Background()
	countries := func(t *testing.T, db *DB) int {
		t.Helper()
		return count(t, db, `SELECT (SELECT count(*) FROM stats_country_1m) + (SELECT count(*) FROM stats_country_1h) + (SELECT count(*) FROM stats_country_1d)`)
	}
	tests := []struct {
		policy        string
		want          Deleted
		sightingsLeft int
		countriesLeft int
	}{
		{"full", Deleted{}, 2, 4},
		{"countries", Deleted{Sightings: 2}, 0, 4},
		{"off", Deleted{Sightings: 2, CountryRows: 4}, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.policy, func(t *testing.T) {
			db, _, _ := ipFixture(t)
			if _, err := db.ApplyStatsSettings(ctx, withPolicy("full")); err != nil {
				t.Fatal(err)
			}
			got, err := db.ApplyStatsSettings(ctx, withPolicy(tt.policy))
			if err != nil {
				t.Fatalf("ApplyStatsSettings(%s): %v", tt.policy, err)
			}
			if got != tt.want {
				t.Errorf("Deleted = %+v, want %+v", got, tt.want)
			}
			if n := count(t, db, `SELECT count(*) FROM ip_sightings`); n != tt.sightingsLeft {
				t.Errorf("%d sightings left, want %d", n, tt.sightingsLeft)
			}
			if n := countries(t, db); n != tt.countriesLeft {
				t.Errorf("%d country rows left, want %d", n, tt.countriesLeft)
			}
			if s, _, _ := db.StatsSettings(ctx); s.IPPolicy != tt.policy {
				t.Errorf("policy = %q, want %q", s.IPPolicy, tt.policy)
			}
		})
	}
}

// The policy and the data change together or not at all: a failure inside the
// transaction leaves the policy that was there and every row.
func TestApplyStatsSettingsFailsAsAWhole(t *testing.T) {
	db, _, _ := ipFixture(t)
	ctx := context.Background()
	before := DefaultStatsSettings()
	before.IPPolicy = "full"
	before.MinutesHours = 72
	if _, err := db.ApplyStatsSettings(ctx, before); err != nil {
		t.Fatal(err)
	}
	// The last delete of the transaction fails, after the settings are written
	// and the sightings deleted.
	mustExec(t, db, `CREATE TRIGGER refuse_country_days BEFORE DELETE ON stats_country_1d BEGIN SELECT RAISE(ABORT, 'refused by the test'); END`)

	after := withPolicy("off")
	if _, err := db.ApplyStatsSettings(ctx, after); err == nil {
		t.Fatal("ApplyStatsSettings: no error, although the transaction failed")
	}
	got, stored, err := db.StatsSettings(ctx)
	if err != nil || !stored || !reflect.DeepEqual(got, before) {
		t.Errorf("settings after the failure = %+v (stored %v, err %v), want %+v", got, stored, err, before)
	}
	if n := count(t, db, `SELECT count(*) FROM ip_sightings`); n != 2 {
		t.Errorf("%d sightings left, want both", n)
	}
	if n := count(t, db, `SELECT count(*) FROM stats_country_1m`) + count(t, db, `SELECT count(*) FROM stats_country_1h`); n != 3 {
		t.Errorf("%d country minutes and hours left, want 3", n)
	}
}
