package geoiptest_test

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/urbnywrt/postern/internal/geoip"
	"github.com/urbnywrt/postern/internal/geoip/geoiptest"
)

var networks = map[string]string{
	"198.51.100.0/24": "DE",
	"127.0.0.0/8":     "ZZ",
	"2001:db8::/32":   "JP",
}

// What Write makes is what the reader of the panel and of the nodes opens, and
// the reserved networks that tests use are in it.
func TestWriteMakesADatabaseThatOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := geoiptest.Write(path, networks); err != nil {
		t.Fatalf("Write: %v", err)
	}
	db, err := geoip.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for ip, want := range map[string]string{
		"198.51.100.1": "DE", "127.0.0.1": "ZZ", "2001:db8::1": "JP", "203.0.113.1": "",
	} {
		if got := db.Country(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Country(%s) = %q, want %q", ip, got, want)
		}
	}
	if info := db.Info(); info.DatabaseType != geoiptest.DatabaseType || info.IPVersion != 6 {
		t.Errorf("Info = %+v", info)
	}

	// Bytes is the file, and the same networks make the same file.
	data, err := geoiptest.Bytes(networks, geoiptest.WithBuilt(time.Unix(1_700_000_000, 0)))
	if err != nil {
		t.Fatal(err)
	}
	again, err := geoiptest.Bytes(networks, geoiptest.WithBuilt(time.Unix(1_700_000_000, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, again) {
		t.Error("the same networks and build time made two different files")
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk) != len(data) {
		t.Errorf("the file has %d bytes, Bytes gave %d", len(onDisk), len(data))
	}
}

func TestOptions(t *testing.T) {
	built := time.Date(2026, 9, 1, 6, 0, 0, 0, time.UTC)
	data, err := geoiptest.Bytes(networks, geoiptest.WithBuilt(built), geoiptest.WithType("Some-Type"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := maxminddb.OpenBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.Metadata.DatabaseType != "Some-Type" || !r.Metadata.BuildTime().Equal(built) || r.Metadata.IPVersion != 6 {
		t.Errorf("metadata = %+v", r.Metadata)
	}
	// The IPv4 networks are aliased into the tree of IPv6, as in the database of
	// DB-IP, so an address that is written the IPv6 way finds its country.
	if !r.Lookup(netip.MustParseAddr("::ffff:198.51.100.7")).Found() {
		t.Error("an IPv4-mapped address was not found: the aliasing is off")
	}

	// Without the options: now, the type of DB-IP, IPv6.
	before := time.Now().Add(-time.Minute)
	data, err = geoiptest.Bytes(networks)
	if err != nil {
		t.Fatal(err)
	}
	if r, err = maxminddb.OpenBytes(data); err != nil {
		t.Fatal(err)
	}
	if r.Metadata.DatabaseType != "DBIP-Country-Lite" || r.Metadata.BuildTime().Before(before) {
		t.Errorf("default metadata = %+v", r.Metadata)
	}

	// Without the aliasing, the IPv6 form of an IPv4 address is not in the tree.
	bare, err := geoiptest.Bytes(networks, geoiptest.WithoutIPv4Aliasing())
	if err != nil {
		t.Fatal(err)
	}
	if r, err = maxminddb.OpenBytes(bare); err != nil {
		t.Fatal(err)
	}
	if r.Lookup(netip.MustParseAddr("::ffff:198.51.100.7")).Found() || !r.Lookup(netip.MustParseAddr("198.51.100.7")).Found() {
		t.Error("with no aliasing, the mapped address was found or the IPv4 address was not")
	}

	v4, err := geoiptest.Bytes(map[string]string{"198.51.100.0/24": "DE"}, geoiptest.WithIPVersion(4))
	if err != nil {
		t.Fatal(err)
	}
	if r, err = maxminddb.OpenBytes(v4); err != nil {
		t.Fatal(err)
	}
	if r.Metadata.IPVersion != 4 {
		t.Errorf("IPVersion = %d, want 4", r.Metadata.IPVersion)
	}
}

func TestErrors(t *testing.T) {
	if _, err := geoiptest.Bytes(map[string]string{"198.51.100.0": "DE"}); err == nil {
		t.Error("a network that is not a prefix was taken")
	}
	if _, err := geoiptest.Bytes(map[string]string{"2001:db8::/32": "JP"}, geoiptest.WithIPVersion(4)); err == nil {
		t.Error("an IPv6 network was put in a tree of IPv4")
	}
	if _, err := geoiptest.Bytes(networks, geoiptest.WithIPVersion(5)); err == nil {
		t.Error("a tree of IPv5 was made")
	}
	if err := geoiptest.Write(filepath.Join(t.TempDir(), "no", "such", "dir.mmdb"), networks); err == nil {
		t.Error("Write to a directory that is not there succeeded")
	}
}
