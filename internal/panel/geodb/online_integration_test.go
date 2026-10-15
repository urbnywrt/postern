//go:build integration

package geodb

// The one test of this package that talks to DB-IP. It downloads the file of
// the current month (about 4 MB of gzip) from download.db-ip.com, so it runs
// only when it is asked to, and not with the other tests that carry the tag:
//
//	POSTERN_GEOIP_ONLINE=1 go test -tags integration -run TestRealDBIP -v ./internal/panel/geodb/
//
// It is the check that nothing else makes: that the file that DB-IP really
// publishes is one that the panel takes (the type that its metadata gives, the
// IPv6 tree, the record that holds the country) and that the download works
// against the real site, with its redirects, its CDN and its 404 for a month
// that is not out yet. The file is written to a temporary directory and removed
// with it; nothing of it is kept.

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/panel/store"
)

func TestRealDBIP(t *testing.T) {
	if os.Getenv("POSTERN_GEOIP_ONLINE") != "1" {
		t.Skip("set POSTERN_GEOIP_ONLINE=1 to download the real database of DB-IP (about 4 MB)")
	}
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// The manager as the panel makes it: DB-IP's address, its own client, the
	// clock of the machine.
	m := NewManager(db, filepath.Join(dir, "geoip"), nil)

	st, err := m.Refresh(t.Context())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	now := time.Now().UTC()
	months := candidates(now)
	if !st.Present || (st.Month != months[0] && st.Month != months[1]) {
		t.Fatalf("status = %+v, want a database of %s or of %s", st, months[0], months[1])
	}
	t.Logf("installed the database of %s: %d bytes, built %s, sha256 %s", st.Month, st.Size, st.Built.Format(time.RFC3339), st.SHA256)

	cur, ok := m.Current()
	if !ok {
		t.Fatal("Current says there is no database")
	}
	opened, err := geoip.Open(cur.Path)
	if err != nil {
		t.Fatalf("the file that was installed does not open: %v", err)
	}
	info := opened.Info()
	t.Logf("type %q, IPv%d, built %s", info.DatabaseType, info.IPVersion, info.Built.Format(time.RFC3339))
	if !strings.Contains(strings.ToLower(info.DatabaseType), "country") || info.IPVersion != 6 {
		t.Errorf("info = %+v", info)
	}
	if st.Size < 1<<20 || st.Size > 64<<20 {
		t.Errorf("the database is %d bytes: not what a country database of DB-IP is", st.Size)
	}

	// The example of DB-IP's own page on the format: 8.8.8.8 is in the US, also
	// when it is written the IPv6 way.
	for _, ip := range []string{"8.8.8.8", "::ffff:8.8.8.8"} {
		if got := m.Country(netip.MustParseAddr(ip)); got != "US" {
			t.Errorf("Country(%s) = %q, want US", ip, got)
		}
	}
	// A second refresh the same day asks for nothing: it has the month.
	again, err := m.Refresh(t.Context())
	if err != nil || again.SHA256 != st.SHA256 {
		t.Errorf("second Refresh = %+v, %v", again, err)
	}
}
