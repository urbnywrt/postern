package geodb

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/geoip/geoiptest"
	"github.com/urbnywrt/postern/internal/version"
)

// Addresses that the databases of monthDB know: documentation ranges.
var (
	addrV4    = netip.MustParseAddr("198.51.100.7")
	addrV6    = netip.MustParseAddr("2001:db8::1")
	addrOther = netip.MustParseAddr("203.0.113.1")
)

func TestDefaults(t *testing.T) {
	e := newEnv(t)
	m := NewManager(e.db, e.dir, nil) // no log: it is discarded
	if m.base != DefaultBaseURL || DefaultBaseURL != "https://download.db-ip.com/free" {
		t.Errorf("the download base is %q (default %q), want https://download.db-ip.com/free", m.base, DefaultBaseURL)
	}
	if m.maxDownload != 64<<20 || m.maxUnpacked != 256<<20 || m.maxUpload != 256<<20 {
		t.Errorf("caps: download %d, unpacked %d, upload %d; want 64 MiB, 256 MiB, 256 MiB", m.maxDownload, m.maxUnpacked, m.maxUpload)
	}
	if m.timeout != 5*time.Minute || m.every != 24*time.Hour {
		t.Errorf("download timeout %v and interval %v, want 5 minutes and 24 hours", m.timeout, m.every)
	}
	if m.client.Timeout != 5*time.Minute {
		t.Errorf("the client's timeout is %v, want 5 minutes overall", m.client.Timeout)
	}
	if connectTimeout != 30*time.Second {
		t.Errorf("the connect timeout is %v, want 30 seconds", connectTimeout)
	}
	if !m.enabled.Load() {
		t.Error("the country database is not enabled by default")
	}
}

func TestBaseURL(t *testing.T) {
	e := newEnv(t)
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))

	t.Run("a base with a path, and slashes at its end", func(t *testing.T) {
		m := e.manager(WithBaseURL(e.src.srv.URL + "/mirror/free//"))
		if _, err := m.Refresh(e.ctx); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if got, want := e.src.asked(), []string{"/mirror/free/dbip-country-lite-2026-10.mmdb.gz"}; !slices.Equal(got, want) {
			t.Errorf("asked for %q, want %q", got, want)
		}
	})

	t.Run("an empty base is the default", func(t *testing.T) {
		m := NewManager(e.db, e.dir, nil, WithBaseURL(""), WithBaseURL("  "))
		if m.base != DefaultBaseURL {
			t.Errorf("base = %q, want the default", m.base)
		}
	})

	t.Run("the client that the manager makes itself", func(t *testing.T) {
		e := newEnv(t)
		e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
		log := slog.New(slog.NewTextHandler(e.logs, nil))
		m := NewManager(e.db, e.dir, log, WithBaseURL(e.src.srv.URL), WithNow(e.clock.Now))
		st, err := m.Refresh(e.ctx)
		if err != nil || st.Month != "2026-10" {
			t.Fatalf("Refresh = %+v, %v", st, err)
		}
	})
}

func TestCandidateMonths(t *testing.T) {
	zone := time.FixedZone("UTC+3", 3*3600)
	for _, c := range []struct {
		now  time.Time
		want [2]string
	}{
		{time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC), [2]string{"2026-10", "2026-09"}},
		{time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), [2]string{"2026-10", "2026-09"}},
		{time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC), [2]string{"2026-10", "2026-09"}},
		{time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC), [2]string{"2027-01", "2026-12"}},
		// A month is not taken off a day: the 31st of March has no 31st of
		// February behind it.
		{time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC), [2]string{"2026-03", "2026-02"}},
		// The month is the UTC month: this is still September there.
		{time.Date(2026, 10, 1, 1, 0, 0, 0, zone), [2]string{"2026-09", "2026-08"}},
	} {
		if got := candidates(c.now); got != c.want {
			t.Errorf("candidates(%v) = %v, want %v", c.now, got, c.want)
		}
	}
}

func TestRefreshInstallsTheDatabaseOfTheCurrentMonth(t *testing.T) {
	e := newEnv(t)
	db := monthDB(t, "2026-10", "DE")
	e.src.publish("2026-10", gzipped(t, db))

	st, err := e.m.Refresh(e.ctx)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	built := time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	checkStatus(t, st, Status{
		Enabled: true, Present: true, Month: "2026-10", Built: built,
		Size: int64(len(db)), SHA256: sumOf(db), Fetched: t0, Checked: t0,
	})

	if got, want := e.src.asked(), []string{file("2026-10")}; !slices.Equal(got, want) {
		t.Errorf("asked for %q, want %q", got, want)
	}
	if got, want := e.src.userAgents(), []string{"postern/" + version.Version}; !slices.Equal(got, want) {
		t.Errorf("User-Agent %q, want %q", got, want)
	}

	// The file: named by the month, the database unpacked, readable by everyone
	// (it is public data), and nothing else in the directory.
	const name = "dbip-country-lite-2026-10.mmdb"
	path := filepath.Join(e.dir, name)
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, db) {
		t.Errorf("the file holds %d bytes (err %v), want the %d bytes of the database", len(content), err, len(db))
	}
	if info, err := os.Stat(path); err != nil {
		t.Error(err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm() != 0o644 {
		t.Errorf("the file has the mode %v, want 0644", info.Mode().Perm())
	}
	if got := e.names(); !slices.Equal(got, []string{name}) {
		t.Errorf("the directory holds %q, want only %q", got, name)
	}

	// It is in use.
	for ip, want := range map[netip.Addr]string{addrV4: "DE", addrV6: "DE", addrOther: ""} {
		if got := e.m.Country(ip); got != want {
			t.Errorf("Country(%v) = %q, want %q", ip, got, want)
		}
	}
	cur, ok := e.m.Current()
	if want := (Current{Month: "2026-10", SHA256: sumOf(db), Path: path, Size: int64(len(db))}); !ok || cur != want {
		t.Errorf("Current = %+v, %v; want %+v", cur, ok, want)
	}

	// It is told: one event, about neither a node nor a proxy.
	updated := e.events("geoip.updated")
	if len(updated) != 1 {
		t.Fatalf("%d geoip.updated events, want 1", len(updated))
	}
	if ev := updated[0]; ev.Severity != "info" || ev.NodeID != "" || ev.ProxyID != "" ||
		ev.Details["month"] != "2026-10" || ev.Details["source"] != "download" || ev.Details["sha256"] != sumOf(db) {
		t.Errorf("event = %+v", ev)
	}
	if failed := e.events("geoip.failed"); len(failed) != 0 {
		t.Errorf("%d geoip.failed events, want none", len(failed))
	}

	// And it is kept, in the shape that the setting has.
	want := state{
		Month: "2026-10", File: name, SHA256: sumOf(db), Size: int64(len(db)),
		BuiltUnix: built.Unix(), FetchedUnix: t0.Unix(), CheckedUnix: t0.Unix(),
	}
	if got := e.state(); got != want {
		t.Errorf("geoip_state = %+v, want %+v", got, want)
	}
}

// The setting holds the fields that the plan names, under these names.
func TestStateHasTheFieldsOfThePlan(t *testing.T) {
	e := newEnv(t)
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	e.refresh()
	var raw map[string]any
	if ok, err := e.db.GetSetting(e.ctx, "geoip_state", &raw); err != nil || !ok {
		t.Fatalf("GetSetting = %v, %v", ok, err)
	}
	var keys []string
	for k := range raw {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	want := []string{"built_unix", "checked_unix", "error", "fetched_unix", "file", "month", "sha256", "size"}
	if !slices.Equal(keys, want) {
		t.Errorf("geoip_state has the keys %q, want %q", keys, want)
	}
}

func TestRefreshFallsBackToThePreviousMonthOn404(t *testing.T) {
	for _, c := range []struct {
		name     string
		now      time.Time
		previous string
		current  string
	}{
		{"the first hours of a month", time.Date(2026, 10, 1, 0, 30, 0, 0, time.UTC), "2026-09", "2026-10"},
		{"over the turn of the year", time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC), "2026-12", "2027-01"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.clock.Set(c.now)
			e.src.publish(c.previous, gzipped(t, monthDB(t, c.previous, "FR")))

			st := e.refresh()
			if want := []string{file(c.current), file(c.previous)}; !slices.Equal(e.src.asked(), want) {
				t.Errorf("asked for %q, want %q", e.src.asked(), want)
			}
			if st.Month != c.previous || !st.Present || st.Error != "" {
				t.Errorf("status = %+v, want the database of %s and no error", st, c.previous)
			}
			if got := e.m.Country(addrV4); got != "FR" {
				t.Errorf("Country = %q, want FR", got)
			}
			// A month that is not published yet is nothing to report.
			if n := len(e.events("geoip.failed")); n != 0 {
				t.Errorf("%d geoip.failed events, want none", n)
			}
		})
	}
}

func TestRefreshDoesNotDownloadAMonthThatIsInstalled(t *testing.T) {
	e := newEnv(t)
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	first := e.refresh()

	// A day later: nothing is asked of DB-IP, and the look is noted.
	later := t0.Add(26 * time.Hour)
	e.clock.Set(later)
	second := e.refresh()
	if n := len(e.src.asked()); n != 1 {
		t.Errorf("%d requests, want the one of the first refresh only: %q", n, e.src.asked())
	}
	if second.Month != first.Month || second.SHA256 != first.SHA256 || !second.Fetched.Equal(first.Fetched) || !second.Checked.Equal(later) {
		t.Errorf("after the second refresh: %+v, want the database of the first, fetched %v, checked %v", second, first.Fetched, later)
	}
	if n := len(e.events("geoip.updated")); n != 1 {
		t.Errorf("%d geoip.updated events, want 1", n)
	}
	if got := e.state().CheckedUnix; got != later.Unix() {
		t.Errorf("the state says it was checked at %d, want %d", got, later.Unix())
	}

	// The turn of the month, before DB-IP has the new file: the new month is
	// asked for once, and the month before is what is installed.
	november := time.Date(2026, 11, 1, 0, 10, 0, 0, time.UTC)
	e.clock.Set(november)
	st := e.refresh()
	if want := []string{file("2026-10"), file("2026-11")}; !slices.Equal(e.src.asked(), want) {
		t.Errorf("asked for %q, want %q", e.src.asked(), want)
	}
	if st.Month != "2026-10" || st.Error != "" || !st.Checked.Equal(november) {
		t.Errorf("status = %+v, want October, no error, checked now", st)
	}

	// DB-IP publishes it: it is downloaded, and October is kept beside it.
	e.src.publish("2026-11", gzipped(t, monthDB(t, "2026-11", "FR")))
	e.clock.Set(november.Add(24 * time.Hour))
	st = e.refresh()
	if st.Month != "2026-11" {
		t.Errorf("month = %q, want 2026-11", st.Month)
	}
	if got, want := e.names(), []string{"dbip-country-lite-2026-10.mmdb", "dbip-country-lite-2026-11.mmdb"}; !slices.Equal(got, want) {
		t.Errorf("the directory holds %q, want %q", got, want)
	}
	if got := e.m.Country(addrV4); got != "FR" {
		t.Errorf("Country = %q, want FR", got)
	}
}

func TestRefreshThatFindsNothingRecordsTheErrorOnce(t *testing.T) {
	e := newEnv(t)

	st, err := e.m.Refresh(e.ctx)
	if err == nil {
		t.Fatal("Refresh succeeded with nothing published")
	}
	if !strings.Contains(st.Error, "no country database for 2026-10 or 2026-09") || st.Error != err.Error() {
		t.Errorf("status error %q, error %q; want the same words, naming both months", st.Error, err)
	}
	if st.Present || !st.Enabled || !st.Checked.Equal(t0) {
		t.Errorf("status = %+v, want enabled, no database, checked now", st)
	}
	if want := []string{file("2026-10"), file("2026-09")}; !slices.Equal(e.src.asked(), want) {
		t.Errorf("asked for %q, want %q", e.src.asked(), want)
	}
	failed := e.events("geoip.failed")
	if len(failed) != 1 {
		t.Fatalf("%d geoip.failed events, want 1", len(failed))
	}
	if ev := failed[0]; ev.Message != st.Error || ev.Severity != "warn" || ev.NodeID != "" || ev.ProxyID != "" {
		t.Errorf("event = %+v", ev)
	}
	if got := e.state().Error; got != st.Error {
		t.Errorf("the state holds the error %q, want %q", got, st.Error)
	}

	// The same failure again is not another event, and the look is noted.
	e.clock.Set(t0.Add(time.Hour))
	st2, err := e.m.Refresh(e.ctx)
	if err == nil || st2.Error != st.Error {
		t.Fatalf("second Refresh: %v, %q", err, st2.Error)
	}
	if n := len(e.events("geoip.failed")); n != 1 {
		t.Errorf("%d geoip.failed events after the same failure twice, want 1", n)
	}
	if !st2.Checked.Equal(t0.Add(time.Hour)) {
		t.Errorf("checked = %v, want an hour later", st2.Checked)
	}

	// Another failure is another event.
	e.src.answer("2026-10", http.StatusServiceUnavailable)
	st3, err := e.m.Refresh(e.ctx)
	if err == nil || !strings.Contains(st3.Error, "503") {
		t.Fatalf("third Refresh: %v, %q; want a 503", err, st3.Error)
	}
	if n := len(e.events("geoip.failed")); n != 2 {
		t.Errorf("%d geoip.failed events after a different failure, want 2", n)
	}
	// A 503 is no reason to look at the month before: only a 404 is.
	if want := 4 + 1; len(e.src.asked()) != want {
		t.Errorf("asked %d times (%q), want %d", len(e.src.asked()), e.src.asked(), want)
	}

	// A success clears it.
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	st4 := e.refresh()
	if st4.Error != "" || !st4.Present || e.state().Error != "" {
		t.Errorf("after a success: %+v, state error %q", st4, e.state().Error)
	}
	if n := len(e.events("geoip.failed")); n != 2 {
		t.Errorf("%d geoip.failed events, want 2", n)
	}
	if n := len(e.events("geoip.updated")); n != 1 {
		t.Errorf("%d geoip.updated events, want 1", n)
	}
}

func TestRefreshKeepsTheOldDatabaseWhenTheNewOneCannotBeUsed(t *testing.T) {
	e := newEnv(t)
	old := monthDB(t, "2026-10", "DE")
	e.src.publish("2026-10", gzipped(t, old))
	e.refresh()

	e.clock.Set(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	e.src.publish("2026-11", []byte("<html>not a database</html>"))
	st, err := e.m.Refresh(e.ctx)
	if err == nil {
		t.Fatal("Refresh succeeded with a file that is not a database")
	}
	if !st.Present || st.Month != "2026-10" || st.SHA256 != sumOf(old) || st.Error == "" {
		t.Errorf("status = %+v, want the database of October still, and the error", st)
	}
	if got := e.m.Country(addrV4); got != "DE" {
		t.Errorf("Country = %q, want DE from the old database", got)
	}
	if got, want := e.names(), []string{"dbip-country-lite-2026-10.mmdb"}; !slices.Equal(got, want) {
		t.Errorf("the directory holds %q, want %q (no leftover of the failed file)", got, want)
	}
	if got := e.state(); got.File != "dbip-country-lite-2026-10.mmdb" || got.SHA256 != sumOf(old) || got.Error == "" {
		t.Errorf("state = %+v, want the old file and an error", got)
	}
	if n := len(e.events("geoip.failed")); n != 1 {
		t.Errorf("%d geoip.failed events, want 1", n)
	}
	if n := len(e.events("geoip.updated")); n != 1 {
		t.Errorf("%d geoip.updated events, want the one of October", n)
	}
}

func TestRefreshRefusesWhatIsNotACountryDatabase(t *testing.T) {
	good := monthDB(t, "2026-10", "DE")
	packed := gzipped(t, good)
	corrupt := bytes.Clone(packed)
	for i := len(corrupt) / 2; i < len(corrupt)/2+8; i++ {
		corrupt[i] ^= 0xff
	}
	asn := monthDB(t, "2026-10", "DE", geoiptest.WithType("GeoLite2-ASN"))
	v4, err := geoiptest.Bytes(map[string]string{"198.51.100.0/24": "DE"}, geoiptest.WithIPVersion(4))
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		body []byte
		want string // part of the error
	}{
		{"text", []byte("hello"), "not a MaxMind DB file"},
		{"gzipped text", gzipped(t, []byte("hello")), "not a MaxMind DB file"},
		{"an empty answer", nil, "not a MaxMind DB file"},
		{"gzip that is corrupt", corrupt, "could not unpack"},
		{"gzip that is cut in half", packed[:len(packed)/2], "could not unpack"},
		{"the start of a gzip header only", []byte{0x1f, 0x8b, 0x08}, "could not unpack"},
		{"a database of ASNs", gzipped(t, asn), "not a country database"},
		{"a database with a tree of IPv4", gzipped(t, v4), "IPv6"},
		{"a database that is gzipped twice", gzipped(t, packed), "not a MaxMind DB file"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.src.publish("2026-10", c.body)
			st, err := e.m.Refresh(e.ctx)
			if err == nil {
				t.Fatalf("Refresh succeeded: %+v", st)
			}
			if !strings.Contains(st.Error, c.want) {
				t.Errorf("the status error does not say %q: %q", c.want, st.Error)
			}
			if st.Present || e.m.Country(addrV4) != "" {
				t.Errorf("status = %+v: a database is in use", st)
			}
			if got := e.names(); len(got) != 0 {
				t.Errorf("the directory holds %q, want nothing", got)
			}
			if n := len(e.events("geoip.failed")); n != 1 {
				t.Errorf("%d geoip.failed events, want 1", n)
			}
			if n := len(e.events("geoip.updated")); n != 0 {
				t.Errorf("%d geoip.updated events, want none", n)
			}
			if got := e.state().File; got != "" {
				t.Errorf("the state names the file %q", got)
			}
		})
	}
}

func TestRefreshSizeCaps(t *testing.T) {
	db := monthDB(t, "2026-10", "DE")
	packed := gzipped(t, db)

	// refused makes a refresh that has to fail and checks that nothing is left.
	refused := func(t *testing.T, e *env, want string) {
		t.Helper()
		st, err := e.m.Refresh(e.ctx)
		if err == nil {
			t.Fatalf("Refresh succeeded: %+v", st)
		}
		if !strings.Contains(st.Error, want) {
			t.Errorf("the error does not say %q: %q", want, st.Error)
		}
		if st.Present || len(e.names()) != 0 {
			t.Errorf("status %+v, directory %q: want nothing installed and no leftover", st, e.names())
		}
	}

	t.Run("a download that says it is too long is refused", func(t *testing.T) {
		e := newEnv(t)
		e.m.maxDownload = int64(len(packed)) - 1
		e.src.publish("2026-10", packed)
		refused(t, e, "larger than")
	})
	// Said by its length alone, the body is not waited for: here it never comes.
	t.Run("a download that says it is too long is refused before its body is read", func(t *testing.T) {
		e := newEnv(t)
		e.m.maxDownload = 1000
		e.m.timeout = 3 * time.Second
		e.src.handle(func(w http.ResponseWriter, r *http.Request, month string) bool {
			w.Header().Set("Content-Length", "5000000")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return true
		})
		start := time.Now()
		refused(t, e, "larger than")
		if d := time.Since(start); d > time.Second {
			t.Errorf("it took %v: the body was waited for", d)
		}
	})
	t.Run("a download that is too long and does not say so is cut off", func(t *testing.T) {
		e := newEnv(t)
		e.m.maxDownload = 1000
		e.src.handle(func(w http.ResponseWriter, r *http.Request, month string) bool {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush() // no Content-Length from here on
			_, _ = w.Write(bytes.Repeat([]byte("x"), 5000))
			return true
		})
		refused(t, e, "larger than")
	})
	t.Run("the cap counts what is sent, packed or not", func(t *testing.T) {
		e := newEnv(t)
		e.m.maxDownload = int64(len(db)) - 1
		e.src.publish("2026-10", db)
		refused(t, e, "larger than")
	})
	t.Run("a database that is too large unpacked", func(t *testing.T) {
		e := newEnv(t)
		e.m.maxUnpacked = int64(len(db)) - 1
		e.src.publish("2026-10", packed)
		refused(t, e, "unpacked")
	})
	t.Run("a gzip that unpacks to far more than it is", func(t *testing.T) {
		e := newEnv(t)
		e.m.maxUnpacked = 64 << 10
		bomb := gzipped(t, make([]byte, 4<<20))
		if len(bomb) > 16<<10 {
			t.Fatalf("the test file is %d bytes packed; it was meant to be tiny", len(bomb))
		}
		e.src.publish("2026-10", bomb)
		refused(t, e, "unpacked")
	})
	t.Run("exactly at the caps is within them", func(t *testing.T) {
		e := newEnv(t)
		e.m.maxDownload = int64(len(packed))
		e.m.maxUnpacked = int64(len(db))
		e.src.publish("2026-10", packed)
		if st := e.refresh(); !st.Present || st.Month != "2026-10" {
			t.Errorf("status = %+v", st)
		}
	})
}

func TestRefreshWhenDisabledAsksNothing(t *testing.T) {
	e := newEnv(t)
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	old := monthDB(t, "2026-09", "FR")
	if _, err := e.m.Install(e.ctx, bytes.NewReader(old)); err != nil {
		t.Fatal(err)
	}

	st, err := e.m.SetEnabled(e.ctx, false)
	if err != nil || st.Enabled || !st.Present {
		t.Fatalf("SetEnabled(false) = %+v, %v; want disabled, the file kept", st, err)
	}
	st, err = e.m.Refresh(e.ctx)
	if err != nil {
		t.Fatalf("Refresh while disabled: %v", err)
	}
	if st.Enabled || st.Month != "2026-09" || !st.Checked.IsZero() {
		t.Errorf("status = %+v, want disabled, September still, never checked", st)
	}
	if got := e.src.asked(); len(got) != 0 {
		t.Errorf("asked for %q while disabled, want nothing", got)
	}

	// Nothing is found, and nothing is passed on.
	if got := e.m.Country(addrV4); got != "" {
		t.Errorf("Country while disabled = %q, want empty", got)
	}
	if cur, ok := e.m.Current(); ok {
		t.Errorf("Current while disabled = %+v, true", cur)
	}

	// Enabled again, the file that was kept is in use and a refresh looks.
	if _, err := e.m.SetEnabled(e.ctx, true); err != nil {
		t.Fatal(err)
	}
	if got := e.m.Country(addrV4); got != "FR" {
		t.Errorf("Country after enabling = %q, want FR from the kept file", got)
	}
	if st := e.refresh(); st.Month != "2026-10" {
		t.Errorf("month after the refresh = %q, want 2026-10", st.Month)
	}
}

func TestEnabledIsKept(t *testing.T) {
	e := newEnv(t)
	// Not set: on.
	if st, err := e.m.Status(e.ctx); err != nil || !st.Enabled {
		t.Fatalf("Status = %+v, %v; want enabled by default", st, err)
	}
	if _, err := e.m.SetEnabled(e.ctx, false); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Enabled *bool `json:"enabled"`
	}
	if ok, err := e.db.GetSetting(e.ctx, "geoip", &raw); err != nil || !ok || raw.Enabled == nil || *raw.Enabled {
		t.Errorf("the setting geoip = %+v, %v, %v; want {enabled: false}", raw, ok, err)
	}

	// A panel that starts again finds it off, and asks DB-IP for nothing.
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	m := e.manager()
	ctx, cancel := context.WithCancel(e.ctx)
	m.Start(ctx)
	if st, err := m.Status(e.ctx); err != nil || st.Enabled {
		t.Errorf("Status after Start = %+v, %v; want disabled", st, err)
	}
	cancel()
	m.Wait()
	if got := e.src.asked(); len(got) != 0 {
		t.Errorf("a disabled panel asked for %q at start", got)
	}
}

func TestInstall(t *testing.T) {
	for _, c := range []struct {
		name string
		pack func(*testing.T, []byte) []byte
	}{
		{"unpacked", func(_ *testing.T, b []byte) []byte { return b }},
		{"gzip", gzipped},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			built := time.Date(2026, 8, 17, 9, 30, 0, 0, time.UTC)
			db := monthDB(t, "2026-08", "DE", geoiptest.WithBuilt(built))

			st, err := e.m.Install(e.ctx, bytes.NewReader(c.pack(t, db)))
			if err != nil {
				t.Fatalf("Install: %v", err)
			}
			// The month is the month that it was built in, and the checksum is
			// that of the database, not of what was sent.
			checkStatus(t, st, Status{
				Enabled: true, Present: true, Month: "2026-08", Built: built,
				Size: int64(len(db)), SHA256: sumOf(db), Fetched: t0,
			})
			const name = "dbip-country-lite-2026-08.mmdb"
			if content, err := os.ReadFile(filepath.Join(e.dir, name)); err != nil || !bytes.Equal(content, db) {
				t.Errorf("the file holds %d bytes (err %v), want the %d of the database", len(content), err, len(db))
			}
			if got := e.names(); !slices.Equal(got, []string{name}) {
				t.Errorf("the directory holds %q", got)
			}
			if got := e.m.Country(addrV4); got != "DE" {
				t.Errorf("Country = %q, want DE", got)
			}
			if got := e.src.asked(); len(got) != 0 {
				t.Errorf("an upload asked DB-IP for %q", got)
			}
			updated := e.events("geoip.updated")
			if len(updated) != 1 || updated[0].Details["source"] != "upload" || updated[0].Details["month"] != "2026-08" {
				t.Errorf("events = %+v, want one geoip.updated from an upload", updated)
			}
			// The upload is no look at DB-IP.
			if got := e.state(); got.CheckedUnix != 0 || got.FetchedUnix != t0.Unix() || got.File != name {
				t.Errorf("state = %+v", got)
			}
		})
	}
}

// The month of an uploaded database is the one that it was built in, in UTC.
func TestInstallTakesTheMonthFromTheBuildTime(t *testing.T) {
	for _, c := range []struct {
		built time.Time
		want  string
	}{
		{time.Date(2026, 8, 31, 23, 59, 59, 0, time.UTC), "2026-08"},
		{time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), "2026-09"},
		{time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), "2026-11"},
		{time.Date(2026, 9, 1, 2, 0, 0, 0, time.FixedZone("UTC+3", 3*3600)), "2026-08"},
	} {
		e := newEnv(t)
		db := monthDB(t, "2026-01", "DE", geoiptest.WithBuilt(c.built))
		st, err := e.m.Install(e.ctx, bytes.NewReader(db))
		if err != nil || st.Month != c.want {
			t.Errorf("built %v: month %q, %v; want %s", c.built, st.Month, err, c.want)
		}
	}
}

func TestInstallRefusesWhatIsNotUsableAndKeepsTheOldDatabase(t *testing.T) {
	good := monthDB(t, "2026-09", "FR")
	packed := gzipped(t, good)
	corrupt := bytes.Clone(packed)
	for i := len(corrupt) / 2; i < len(corrupt)/2+8; i++ {
		corrupt[i] ^= 0xff
	}
	asn := monthDB(t, "2026-10", "DE", geoiptest.WithType("GeoLite2-ASN"))
	v4, err := geoiptest.Bytes(map[string]string{"198.51.100.0/24": "DE"}, geoiptest.WithIPVersion(4))
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		body []byte
	}{
		{"text", []byte("this is not a database")},
		{"nothing", nil},
		{"gzipped text", gzipped(t, []byte("text"))},
		{"gzip that is corrupt", corrupt},
		{"gzip that is cut in half", packed[:len(packed)/2]},
		{"a database of ASNs", asn},
		{"a database with a tree of IPv4", v4},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			if _, err := e.m.Install(e.ctx, bytes.NewReader(good)); err != nil {
				t.Fatal(err)
			}
			changes := 0
			e.m.OnChange(func() { changes++ })

			if st, err := e.m.Install(e.ctx, bytes.NewReader(c.body)); err == nil {
				t.Fatalf("Install succeeded: %+v", st)
			} else if !errors.Is(err, geoip.ErrInvalid) {
				t.Errorf("the error is not geoip.ErrInvalid: %v", err)
			}
			if got := e.m.Country(addrV4); got != "FR" {
				t.Errorf("Country = %q, want FR from the old database", got)
			}
			if got, want := e.names(), []string{"dbip-country-lite-2026-09.mmdb"}; !slices.Equal(got, want) {
				t.Errorf("the directory holds %q, want %q", got, want)
			}
			if changes != 0 {
				t.Errorf("OnChange was called %d times for an upload that failed", changes)
			}
			// The admin is told by the answer; the record of the refresh is not
			// theirs to change.
			if n := len(e.events("geoip.failed")); n != 0 {
				t.Errorf("%d geoip.failed events for an upload that failed", n)
			}
			if got := e.state(); got.Error != "" || got.SHA256 != sumOf(good) {
				t.Errorf("state = %+v", got)
			}
		})
	}

	t.Run("more than the upload may be", func(t *testing.T) {
		e := newEnv(t)
		e.m.maxUpload = int64(len(good)) - 1
		_, err := e.m.Install(e.ctx, bytes.NewReader(good))
		var tooLarge *sizeError
		if !errors.As(err, &tooLarge) || !errors.Is(err, geoip.ErrInvalid) {
			t.Fatalf("Install = %v, want a size error", err)
		}
		if !strings.Contains(err.Error(), "larger than") {
			t.Errorf("the error does not say how large: %v", err)
		}
		if got := e.names(); len(got) != 0 {
			t.Errorf("the directory holds %q", got)
		}
		// Exactly the cap is within it.
		e.m.maxUpload = int64(len(good))
		if _, err := e.m.Install(e.ctx, bytes.NewReader(good)); err != nil {
			t.Errorf("Install of exactly the cap: %v", err)
		}
	})

	t.Run("a reader that fails is a fault of the server", func(t *testing.T) {
		e := newEnv(t)
		boom := errors.New("the connection broke")
		_, err := e.m.Install(e.ctx, io.MultiReader(bytes.NewReader(good[:100]), &failingReader{err: boom}))
		if !errors.Is(err, boom) || errors.Is(err, geoip.ErrInvalid) {
			t.Errorf("Install = %v, want the error of the reader, which is not ErrInvalid", err)
		}
		if got := e.names(); len(got) != 0 {
			t.Errorf("the directory holds %q", got)
		}
	})
}

type failingReader struct{ err error }

func (f *failingReader) Read([]byte) (int, error) { return 0, f.err }

// The directory keeps the current database and the one before it.
func TestOlderDatabasesAreDeleted(t *testing.T) {
	e := newEnv(t)
	install := func(month, country string) {
		t.Helper()
		if _, err := e.m.Install(e.ctx, bytes.NewReader(monthDB(t, month, country))); err != nil {
			t.Fatalf("Install %s: %v", month, err)
		}
	}
	name := func(month string) string { return "dbip-country-lite-" + month + ".mmdb" }

	// What is not a file of the manager is none of its business.
	for _, f := range []string{"notes.txt", name("2026-07") + ".bak", "dbip-country-lite-2026-7.mmdb", "dbip-country-lite-2026-13.mmdb", "other-2026-06.mmdb"} {
		if err := os.MkdirAll(e.dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(e.dir, f), []byte("mine"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unmanaged := e.names()

	install("2026-07", "DE")
	install("2026-08", "FR")
	if got, want := e.names(), append(slices.Clone(unmanaged), name("2026-07"), name("2026-08")); !sameSet(got, want) {
		t.Errorf("after two: %q, want %q", got, want)
	}
	install("2026-09", "JP")
	if got, want := e.names(), append(slices.Clone(unmanaged), name("2026-08"), name("2026-09")); !sameSet(got, want) {
		t.Errorf("after three: the directory holds %q, want %q", got, want)
	}

	// The same month again replaces the file, and the one before is still there.
	if _, err := e.m.Install(e.ctx, bytes.NewReader(monthDB(t, "2026-09", "US"))); err != nil {
		t.Fatal(err)
	}
	if got, want := e.names(), append(slices.Clone(unmanaged), name("2026-08"), name("2026-09")); !sameSet(got, want) {
		t.Errorf("after the same month again: %q, want %q", got, want)
	}
	if got := e.m.Country(addrV4); got != "US" {
		t.Errorf("Country = %q, want US from the file that was written last", got)
	}

	// A leftover of a crash is swept with the rest.
	if err := os.WriteFile(filepath.Join(e.dir, tempPrefix+"123"), []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	install("2026-10", "DE")
	if got, want := e.names(), append(slices.Clone(unmanaged), name("2026-09"), name("2026-10")); !sameSet(got, want) {
		t.Errorf("after four: the directory holds %q, want %q", got, want)
	}
}

// sameSet reports whether two lists hold the same names.
func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func TestOnChange(t *testing.T) {
	e := newEnv(t)
	var calls, other atomic.Int32
	e.m.OnChange(func() {
		calls.Add(1)
		// A callback may ask the manager anything.
		_, _ = e.m.Status(e.ctx)
		_, _ = e.m.Current()
	})
	e.m.OnChange(func() { other.Add(1) })
	e.m.OnChange(nil) // is nothing

	expect := func(what string, want int32) {
		t.Helper()
		if got := calls.Load(); got != want {
			t.Errorf("%s: OnChange was called %d times in all, want %d", what, got, want)
		}
	}
	db := monthDB(t, "2026-10", "DE")

	if _, err := e.m.Install(e.ctx, bytes.NewReader(db)); err != nil {
		t.Fatal(err)
	}
	expect("after an install", 1)

	if _, err := e.m.SetEnabled(e.ctx, false); err != nil {
		t.Fatal(err)
	}
	expect("after disabling", 2)
	if _, err := e.m.SetEnabled(e.ctx, false); err != nil {
		t.Fatal(err)
	}
	expect("after disabling what is disabled", 2)
	if _, err := e.m.SetEnabled(e.ctx, true); err != nil {
		t.Fatal(err)
	}
	expect("after enabling", 3)

	// A refresh that finds the month installed changes nothing; one that fails
	// changes nothing.
	e.refresh()
	expect("after a refresh that found nothing new", 3)
	e.clock.Set(time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC))
	if _, err := e.m.Refresh(e.ctx); err != nil {
		t.Fatal(err) // October is installed, and November is not published: not a failure
	}
	e.src.answer("2026-11", http.StatusInternalServerError)
	if _, err := e.m.Refresh(e.ctx); err == nil {
		t.Fatal("Refresh succeeded against a 500")
	}
	expect("after a refresh that failed", 3)

	// One that installs does.
	e.src.publish("2026-11", gzipped(t, monthDB(t, "2026-11", "FR")))
	e.refresh()
	expect("after a refresh that installed", 4)
	if got := other.Load(); got != 4 {
		t.Errorf("the second callback was called %d times, want 4", got)
	}
}

func TestCurrent(t *testing.T) {
	e := newEnv(t)
	if cur, ok := e.m.Current(); ok {
		t.Fatalf("Current before any database = %+v, true", cur)
	}
	db := monthDB(t, "2026-10", "DE")
	if _, err := e.m.Install(e.ctx, bytes.NewReader(gzipped(t, db))); err != nil {
		t.Fatal(err)
	}
	want := Current{
		Month: "2026-10", SHA256: sumOf(db), Size: int64(len(db)),
		Path: filepath.Join(e.dir, "dbip-country-lite-2026-10.mmdb"),
	}
	cur, ok := e.m.Current()
	if !ok || cur != want {
		t.Fatalf("Current = %+v, %v; want %+v", cur, ok, want)
	}
	// The path is the database, which a caller can read and send.
	if content, err := os.ReadFile(cur.Path); err != nil || sumOf(content) != cur.SHA256 {
		t.Errorf("the file at Current().Path does not have the SHA256 that Current says (err %v)", err)
	}
	if opened, err := geoip.Open(cur.Path); err != nil || opened.Country(addrV4) != "DE" {
		t.Errorf("the file at Current().Path does not open as the database: %v", err)
	}

	if _, err := e.m.SetEnabled(e.ctx, false); err != nil {
		t.Fatal(err)
	}
	if cur, ok := e.m.Current(); ok {
		t.Errorf("Current while disabled = %+v, true", cur)
	}
	if _, err := e.m.SetEnabled(e.ctx, true); err != nil {
		t.Fatal(err)
	}
	if cur, ok := e.m.Current(); !ok || cur != want {
		t.Errorf("Current after enabling = %+v, %v", cur, ok)
	}
}

func TestStatusOfAManagerWithNothing(t *testing.T) {
	e := newEnv(t)
	st, err := e.m.Status(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	checkStatus(t, st, Status{Enabled: true})
	if got := e.m.Country(addrV4); got != "" {
		t.Errorf("Country with no database = %q", got)
	}
}

func TestStartLoadsTheInstalledDatabaseAtOnce(t *testing.T) {
	e := newEnv(t)
	db := monthDB(t, "2026-10", "DE")
	e.src.publish("2026-10", gzipped(t, db))
	e.refresh() // the manager of the panel that ran before

	m := e.manager()
	if got := m.Country(addrV4); got != "" {
		t.Errorf("Country before Start = %q, want empty", got)
	}
	if _, ok := m.Current(); ok {
		t.Error("Current before Start is a database")
	}
	ctx, cancel := context.WithCancel(e.ctx)
	t.Cleanup(func() { cancel(); m.Wait() })
	m.Start(ctx)

	// At once: Start has loaded it by the time that it returns.
	if got := m.Country(addrV4); got != "DE" {
		t.Errorf("Country after Start = %q, want DE", got)
	}
	cur, ok := m.Current()
	if !ok || cur.Month != "2026-10" || cur.SHA256 != sumOf(db) || cur.Size != int64(len(db)) {
		t.Errorf("Current = %+v, %v", cur, ok)
	}
	st, err := m.Status(e.ctx)
	if err != nil || !st.Present || st.Month != "2026-10" || st.SHA256 != sumOf(db) || !st.Fetched.Equal(t0) {
		t.Errorf("Status = %+v, %v", st, err)
	}

	// It had the month, so the refresh that Start begins asks for nothing.
	cancel()
	m.Wait()
	if n := len(e.src.asked()); n != 1 {
		t.Errorf("%d requests in all, want the one of the first panel: %q", n, e.src.asked())
	}
}

// What is kept in the state is what the panel made, but the file is what is
// used: one that cannot be used is no database, and the next refresh makes it
// one again.
func TestStartWithAFileThatCannotBeUsed(t *testing.T) {
	for _, c := range []struct {
		name   string
		damage func(t *testing.T, path string)
	}{
		{"damaged", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("damaged"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"deleted", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			db := monthDB(t, "2026-10", "DE")
			e.src.publish("2026-10", gzipped(t, db))
			e.refresh()
			path := filepath.Join(e.dir, "dbip-country-lite-2026-10.mmdb")
			c.damage(t, path)

			// DB-IP answers when the test lets it, so that what Start finds can
			// be looked at before the refresh mends it.
			release := make(chan struct{})
			e.src.handle(func(http.ResponseWriter, *http.Request, string) bool {
				<-release
				return false
			})
			m := e.manager()
			ctx, cancel := context.WithCancel(e.ctx)
			t.Cleanup(func() { cancel(); m.Wait() })
			m.Start(ctx)

			if got := m.Country(addrV4); got != "" {
				t.Errorf("Country = %q with a file that cannot be used", got)
			}
			if cur, ok := m.Current(); ok {
				t.Errorf("Current = %+v, true", cur)
			}
			st, err := m.Status(e.ctx)
			if err != nil || st.Present || !strings.Contains(st.Error, "cannot be used") {
				t.Errorf("Status = %+v, %v; want no database and the reason", st, err)
			}
			if strings.Contains(st.Error, e.dir) {
				t.Errorf("the error has the path of the directory: %q", st.Error)
			}
			if n := len(e.events("geoip.failed")); n != 1 {
				t.Errorf("%d geoip.failed events, want 1", n)
			}

			// Let the refresh come: the month is not installed, so it is
			// downloaded again, and the error is gone.
			close(release)
			eventually(t, "the refresh to install the database again", func() bool {
				st, err := m.Status(e.ctx)
				return err == nil && st.Present && st.Error == ""
			})
			if got := m.Country(addrV4); got != "DE" {
				t.Errorf("Country after the refresh = %q, want DE", got)
			}
			if content, err := os.ReadFile(path); err != nil || !bytes.Equal(content, db) {
				t.Errorf("the file was not made again (err %v)", err)
			}
			// The event is the last that an install does.
			eventually(t, "the event of the second install", func() bool { return len(e.events("geoip.updated")) == 2 })
		})
	}
}

// A file that was being received when the panel stopped is not a database, and
// is cleared away when the panel starts.
func TestStartClearsTheLeftoversOfACrash(t *testing.T) {
	e := newEnv(t)
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	e.refresh()
	if err := os.WriteFile(filepath.Join(e.dir, tempPrefix+"4711"), []byte("half of a file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "notes.txt"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := e.manager()
	ctx, cancel := context.WithCancel(e.ctx)
	t.Cleanup(func() { cancel(); m.Wait() })
	m.Start(ctx)
	if got, want := e.names(), []string{"dbip-country-lite-2026-10.mmdb", "notes.txt"}; !slices.Equal(got, want) {
		t.Errorf("after Start the directory holds %q, want %q", got, want)
	}
}

// A file that is a database, but not the one that the state noted, is the one
// that is used, and the state is brought into line with it: nodes are sent the
// file under its checksum.
func TestStartUsesTheFileThatIsThere(t *testing.T) {
	e := newEnv(t)
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	e.refresh()
	other := monthDB(t, "2026-10", "FR")
	path := filepath.Join(e.dir, "dbip-country-lite-2026-10.mmdb")
	if err := os.WriteFile(path, other, 0o600); err != nil {
		t.Fatal(err)
	}

	m := e.manager()
	ctx, cancel := context.WithCancel(e.ctx)
	t.Cleanup(func() { cancel(); m.Wait() })
	m.Start(ctx)

	if got := m.Country(addrV4); got != "FR" {
		t.Errorf("Country = %q, want FR from the file that is there", got)
	}
	if cur, ok := m.Current(); !ok || cur.SHA256 != sumOf(other) || cur.Size != int64(len(other)) {
		t.Errorf("Current = %+v, %v; want the checksum and the size of the file that is there", cur, ok)
	}
	if got := e.state(); got.SHA256 != sumOf(other) || got.Size != int64(len(other)) {
		t.Errorf("state = %+v, want the checksum and size of the file", got)
	}
}

// A file named in the state that is not one that the panel makes is not opened:
// a state that points somewhere else cannot make the panel read there.
func TestStartIgnoresAFileNameThatIsNotItsOwn(t *testing.T) {
	e := newEnv(t)
	outside := filepath.Join(filepath.Dir(e.dir), "outside.mmdb")
	if err := os.WriteFile(outside, monthDB(t, "2026-10", "DE"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../outside.mmdb", outside, "notes.txt", "dbip-country-lite-2026-1.mmdb"} {
		if err := e.db.PutSetting(e.ctx, "geoip_state", state{Month: "2026-10", File: name}); err != nil {
			t.Fatal(err)
		}
		m := e.manager()
		ctx, cancel := context.WithCancel(e.ctx)
		e.src.handle(func(http.ResponseWriter, *http.Request, string) bool { return true }) // answers nothing
		m.Start(ctx)
		if _, ok := m.Current(); ok {
			t.Errorf("the file name %q was opened", name)
		}
		cancel()
		m.Wait()
	}
}

func TestStartRefreshesNowAndRetriesAFailedLook(t *testing.T) {
	e := newEnv(t) // nothing is published: every refresh asks twice, and fails
	e.m.every = time.Hour
	e.m.retry = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(e.ctx)
	t.Cleanup(func() { cancel(); e.m.Wait() })
	e.m.Start(ctx)

	// Three refreshes, two requests each, the first of them now.
	eventually(t, "three refreshes", func() bool { return len(e.src.asked()) >= 6 })
	cancel()
	e.m.Wait()
	n := len(e.src.asked())
	time.Sleep(80 * time.Millisecond)
	if got := len(e.src.asked()); got != n {
		t.Errorf("the refreshes went on after the context was done: %d requests, then %d", n, got)
	}
	// The same failure, every time, is one event.
	if got := len(e.events("geoip.failed")); got != 1 {
		t.Errorf("%d geoip.failed events, want 1", got)
	}
}

func TestStartRunsOneLoop(t *testing.T) {
	e := newEnv(t)
	e.m.every = time.Hour
	ctx, cancel := context.WithCancel(e.ctx)
	t.Cleanup(func() { cancel(); e.m.Wait() })
	e.m.Start(ctx)
	e.m.Start(ctx)
	// The goroutine of the loop is there once it has begun to run. A second one
	// would begin as soon as that, so it has had its time when the wait is over.
	eventually(t, "the loop to run", func() bool { return loops() >= 1 })
	time.Sleep(50 * time.Millisecond)
	if got := loops(); got != 1 {
		t.Errorf("%d loops after two calls of Start, want 1", got)
	}
	cancel()
	e.m.Wait()
	if got := loops(); got != 0 {
		t.Errorf("%d loops after Wait, want none", got)
	}
}

// loops counts the goroutines that run the loop of a manager.
func loops() int {
	buf := make([]byte, 1<<20)
	return strings.Count(string(buf[:runtime.Stack(buf, true)]), "geodb.(*Manager).loop")
}

// The panel stopping, or the caller going away, is no verdict on DB-IP.
func TestRefreshThatIsCanceledRecordsNothing(t *testing.T) {
	e := newEnv(t)
	entered := make(chan struct{}, 4)
	e.src.handle(func(_ http.ResponseWriter, r *http.Request, _ string) bool {
		entered <- struct{}{}
		<-r.Context().Done()
		return true
	})
	ctx, cancel := context.WithCancel(e.ctx)
	done := make(chan error, 1)
	go func() {
		_, err := e.m.Refresh(ctx)
		done <- err
	}()
	<-entered
	cancel()
	err := <-done
	var failed *failure
	if !errors.Is(err, context.Canceled) || errors.As(err, &failed) {
		t.Errorf("Refresh = %v, want context.Canceled, and not the failure to get a database", err)
	}
	if st := e.state(); st.Error != "" || st.CheckedUnix != 0 {
		t.Errorf("state = %+v, want nothing recorded", st)
	}
	if n := len(e.events("geoip.failed")); n != 0 {
		t.Errorf("%d geoip.failed events for a refresh that was canceled", n)
	}
	// The lock is free again: another refresh is not left waiting.
	e.src.handle(nil)
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	if st := e.refresh(); st.Month != "2026-10" {
		t.Errorf("status = %+v", st)
	}
}

func TestRefreshThatTakesTooLongFails(t *testing.T) {
	for _, c := range []struct {
		name string
		hang func(w http.ResponseWriter, r *http.Request)
	}{
		{"nothing comes", func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }},
		{"the body stops half way", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "100000")
			_, _ = w.Write([]byte("start of a file"))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.m.timeout = 100 * time.Millisecond
			e.src.handle(func(w http.ResponseWriter, r *http.Request, _ string) bool {
				c.hang(w, r)
				return true
			})
			st, err := e.m.Refresh(e.ctx)
			if err == nil || st.Error == "" {
				t.Fatalf("Refresh = %+v, %v; want a failure", st, err)
			}
			if n := len(e.events("geoip.failed")); n != 1 {
				t.Errorf("%d geoip.failed events, want 1", n)
			}
			if got := e.names(); len(got) != 0 {
				t.Errorf("the directory holds %q", got)
			}
		})
	}
}

func TestRefreshWhenTheDirectoryCannotBeMade(t *testing.T) {
	e := newEnv(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("a file where a directory should be"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.m.dir = filepath.Join(blocker, "geoip")
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
	st, err := e.m.Refresh(e.ctx)
	if err == nil || st.Error == "" || st.Present {
		t.Fatalf("Refresh = %+v, %v; want a failure and no database", st, err)
	}
	if n := len(e.events("geoip.failed")); n != 1 {
		t.Errorf("%d geoip.failed events, want 1", n)
	}
	// The operation and the reason, and not the path of the panel's disk.
	if !strings.Contains(st.Error, "mkdir: ") || strings.Contains(st.Error, blocker) || strings.Contains(e.logs.String(), blocker) {
		t.Errorf("the error is %q: want the operation and the reason, and no path", st.Error)
	}
}

// A database that cannot be put in its place is not left behind as a file of
// its own, and the one that was there stays in use.
func TestADatabaseThatCannotBePutInItsPlaceLeavesNothing(t *testing.T) {
	// The place of the file of October is taken by a directory.
	setup := func(t *testing.T) *env {
		e := newEnv(t)
		old := monthDB(t, "2026-09", "FR")
		if _, err := e.m.Install(e.ctx, bytes.NewReader(old)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(e.dir, "dbip-country-lite-2026-10.mmdb"), 0o755); err != nil {
			t.Fatal(err)
		}
		return e
	}
	want := []string{"dbip-country-lite-2026-09.mmdb", "dbip-country-lite-2026-10.mmdb"}

	t.Run("downloaded", func(t *testing.T) {
		e := setup(t)
		e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))
		st, err := e.m.Refresh(e.ctx)
		if err == nil || !strings.Contains(st.Error, "could not put the country database in its place") {
			t.Fatalf("Refresh = %+v, %v; want a failure to put the file in its place", st, err)
		}
		if got := e.names(); !slices.Equal(got, want) {
			t.Errorf("the directory holds %q, want %q (no temporary file)", got, want)
		}
		if got := e.m.Country(addrV4); got != "FR" {
			t.Errorf("Country = %q, want FR from the database that was there", got)
		}
	})
	t.Run("uploaded", func(t *testing.T) {
		e := setup(t)
		if _, err := e.m.Install(e.ctx, bytes.NewReader(monthDB(t, "2026-10", "DE"))); err == nil {
			t.Fatal("Install succeeded")
		}
		if got := e.names(); !slices.Equal(got, want) {
			t.Errorf("the directory holds %q, want %q (no temporary file)", got, want)
		}
		if got := e.m.Country(addrV4); got != "FR" {
			t.Errorf("Country = %q, want FR from the database that was there", got)
		}
	})
}

func TestConcurrentUse(t *testing.T) {
	e := newEnv(t)
	e.src.publish("2026-10", gzipped(t, monthDB(t, "2026-10", "DE")))

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = e.m.Country(addrV4)
				_, _ = e.m.Current()
				if _, err := e.m.Status(e.ctx); err != nil {
					t.Errorf("Status: %v", err)
					return
				}
			}
		}()
	}

	// Several refreshes at once make one download.
	var refreshes sync.WaitGroup
	for range 4 {
		refreshes.Add(1)
		go func() {
			defer refreshes.Done()
			if _, err := e.m.Refresh(e.ctx); err != nil {
				t.Errorf("Refresh: %v", err)
			}
		}()
	}
	refreshes.Wait()
	if n := len(e.src.asked()); n != 1 {
		t.Errorf("%d requests for refreshes that all came at once, want 1: %q", n, e.src.asked())
	}

	// And installs while the readers read.
	for i, month := range []string{"2026-06", "2026-07", "2026-08", "2026-09"} {
		if _, err := e.m.Install(e.ctx, bytes.NewReader(monthDB(t, month, []string{"US", "FR", "JP", "DE"}[i]))); err != nil {
			t.Errorf("Install %s: %v", month, err)
		}
	}
	close(stop)
	readers.Wait()
}

// An upload waits its turn behind a refresh, but not longer than its caller does.
func TestInstallGivesUpWaitingWhenTheCallerGoesAway(t *testing.T) {
	e := newEnv(t)
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	e.src.handle(func(_ http.ResponseWriter, _ *http.Request, _ string) bool {
		entered <- struct{}{}
		<-release
		return false
	})
	refreshed := make(chan struct{})
	go func() {
		defer close(refreshed)
		_, _ = e.m.Refresh(e.ctx)
	}()
	<-entered

	ctx, cancel := context.WithTimeout(e.ctx, 50*time.Millisecond)
	defer cancel()
	_, err := e.m.Install(ctx, bytes.NewReader(monthDB(t, "2026-09", "FR")))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Install = %v, want the deadline that its caller had", err)
	}
	close(release)
	<-refreshed
}
