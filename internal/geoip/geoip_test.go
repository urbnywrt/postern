package geoip

import (
	"bytes"
	"compress/gzip"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/urbnywrt/postern/internal/geoip/geoiptest"
)

// networks is a country database of the documentation ranges and loopback, the
// addresses that tests are allowed to use.
var networks = map[string]string{
	"198.51.100.0/24": "DE",
	"203.0.113.0/24":  "FR",
	"192.0.2.0/24":    "US",
	"127.0.0.0/8":     "ZZ",
	"2001:db8::/32":   "JP",
}

// writeDB writes a database of nets to a new file and returns its path.
func writeDB(t *testing.T, nets map[string]string, opts ...geoiptest.Option) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := geoiptest.Write(path, nets, opts...); err != nil {
		t.Fatalf("geoiptest.Write: %v", err)
	}
	return path
}

// openDB opens a database of nets.
func openDB(t *testing.T, nets map[string]string, opts ...geoiptest.Option) *DB {
	t.Helper()
	db, err := Open(writeDB(t, nets, opts...))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return db
}

func TestAttribution(t *testing.T) {
	// DB-IP's licence asks for the link, and the text is what the UI shows.
	if Attribution != "IP Geolocation by DB-IP" || AttributionURL != "https://db-ip.com" || Licence != "CC BY 4.0" {
		t.Errorf("attribution = %q, %q, %q", Attribution, AttributionURL, Licence)
	}
}

func TestCountry(t *testing.T) {
	db := openDB(t, networks)
	for _, c := range []struct{ ip, want string }{
		{"198.51.100.0", "DE"},
		{"198.51.100.7", "DE"},
		{"198.51.100.255", "DE"},
		{"203.0.113.1", "FR"},
		{"192.0.2.200", "US"},
		{"127.0.0.1", "ZZ"},
		{"127.255.255.254", "ZZ"},
		{"2001:db8::1", "JP"},
		{"2001:db8:ffff:ffff::1", "JP"},
		// An IPv4 address that an IPv6 socket reports is the IPv4 address.
		{"::ffff:198.51.100.7", "DE"},
		{"::ffff:203.0.113.9", "FR"},
		// Not in the database.
		{"198.51.99.255", ""},
		{"198.51.101.0", ""},
		{"198.18.0.1", ""},
		{"0.0.0.0", ""},
		{"2001:db9::1", ""},
		{"::1", ""},
		{"::ffff:198.18.0.1", ""},
	} {
		if got := db.Country(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("Country(%s) = %q, want %q", c.ip, got, c.want)
		}
	}

	// A zone is no part of the address.
	if got := db.Country(netip.MustParseAddr("2001:db8::1%eth0")); got != "JP" {
		t.Errorf("Country of an address with a zone = %q, want JP", got)
	}
	// The zero address is no address.
	if got := db.Country(netip.Addr{}); got != "" {
		t.Errorf("Country(zero address) = %q, want empty", got)
	}
}

// An IPv4 address that an IPv6 socket reports is the IPv4 address that it stands
// for, also in a database that has no place for the IPv6 form in its tree.
func TestCountryOfAnIPv4MappedAddressNeedsNoAliasing(t *testing.T) {
	db := openDB(t, networks, geoiptest.WithoutIPv4Aliasing())
	for _, c := range []struct{ ip, want string }{
		{"198.51.100.7", "DE"},
		{"::ffff:198.51.100.7", "DE"},
		{"::ffff:203.0.113.9", "FR"},
		{"::ffff:198.18.0.1", ""},
		{"2001:db8::1", "JP"},
	} {
		if got := db.Country(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("Country(%s) = %q, want %q", c.ip, got, c.want)
		}
	}
}

func TestCountryOfANilDatabase(t *testing.T) {
	var db *DB
	if got := db.Country(netip.MustParseAddr("198.51.100.7")); got != "" {
		t.Errorf("Country on a nil database = %q, want empty", got)
	}
	if got := db.Info(); got != (Info{}) {
		t.Errorf("Info on a nil database = %+v, want the zero value", got)
	}
}

// A record whose country is not a code of two letters says nothing that a
// caller could count under a country.
func TestCountryThatIsNotTwoLetters(t *testing.T) {
	db := openDB(t, map[string]string{
		"198.51.100.0/24": "Germany",
		"203.0.113.0/24":  "D",
		"192.0.2.0/24":    "1A",
		"127.0.0.0/8":     "",
		"2001:db8::/32":   "de",
		"2001:db9::/32":   "ÄÖ", // two letters, but four bytes
		"2001:dba::/32":   "D-",
	})
	for _, c := range []struct{ ip, want string }{
		{"198.51.100.1", ""},
		{"203.0.113.1", ""},
		{"192.0.2.1", ""},
		{"127.0.0.1", ""},
		{"2001:db8::1", "DE"}, // upper case, which is what the callers count under
		{"2001:db9::1", ""},
		{"2001:dba::1", ""},
	} {
		if got := db.Country(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("Country(%s) = %q, want %q", c.ip, got, c.want)
		}
	}
}

func TestInfo(t *testing.T) {
	built := time.Date(2026, 10, 1, 6, 29, 26, 0, time.UTC)
	db := openDB(t, networks, geoiptest.WithBuilt(built))
	info := db.Info()
	if info.DatabaseType != "DBIP-Country-Lite" || info.IPVersion != 6 || !info.Built.Equal(built) {
		t.Errorf("Info = %+v, want DBIP-Country-Lite, IPv6, built %v", info, built)
	}
	if info.Built.Location() != time.UTC {
		t.Errorf("the build time is in %v, want UTC", info.Built.Location())
	}
}

// Other databases that have the country in the same place are as good: a
// GeoLite2 or GeoIP2 country database is the same kind of file.
func TestOpenAcceptsOtherCountryDatabases(t *testing.T) {
	for _, typ := range []string{"DBIP-Country-Lite", "DBIP-Country", "GeoLite2-Country", "GeoIP2-Country", "geolite2-country"} {
		db, err := Open(writeDB(t, networks, geoiptest.WithType(typ)))
		if err != nil {
			t.Errorf("a database of type %q was refused: %v", typ, err)
			continue
		}
		if got := db.Country(netip.MustParseAddr("198.51.100.7")); got != "DE" {
			t.Errorf("%s: Country = %q, want DE", typ, got)
		}
	}
}

func TestOpenRefusesWhatIsNotACountryDatabase(t *testing.T) {
	good, err := geoiptest.Bytes(networks)
	if err != nil {
		t.Fatal(err)
	}
	var packed bytes.Buffer
	zw := gzip.NewWriter(&packed)
	_, _ = zw.Write(good)
	_ = zw.Close()

	// The tree is cut in the middle of its data.
	cut := bytes.Clone(good[:len(good)/2])
	// The marker that tells where the metadata begins is spoiled.
	spoiled := bytes.Replace(bytes.Clone(good), []byte("MaxMind.com"), []byte("MaxMint.com"), 1)

	write := func(data []byte) string {
		path := filepath.Join(t.TempDir(), "x.mmdb")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	asn, err := geoiptest.Bytes(networks, geoiptest.WithType("GeoLite2-ASN"))
	if err != nil {
		t.Fatal(err)
	}
	city, err := geoiptest.Bytes(networks, geoiptest.WithType("DBIP-City-Lite"))
	if err != nil {
		t.Fatal(err)
	}
	notTyped, err := geoiptest.Bytes(networks, geoiptest.WithType(""))
	if err != nil {
		t.Fatal(err)
	}
	v4, err := geoiptest.Bytes(map[string]string{"198.51.100.0/24": "DE"}, geoiptest.WithIPVersion(4))
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		path string
		want string // part of the error
		// invalid is whether the file was read and is no country database, which
		// is ErrInvalid, and not a file that could not be read.
		invalid bool
	}{
		{"a database of ASNs", write(asn), "not a country database", true},
		{"a database of cities", write(city), "not a country database", true},
		{"a database that has no type", write(notTyped), "not a country database", true},
		{"a tree of IPv4", write(v4), "IPv6", true},
		{"text", write([]byte("this is not a database\n")), "not a MaxMind DB file", true},
		{"an empty file", write(nil), "not a MaxMind DB file", true},
		{"a database cut in half", write(cut), "MaxMind DB", true},
		{"a spoiled marker", write(spoiled), "not a MaxMind DB file", true},
		// Open does not unpack: the caller does, and says what it unpacked.
		{"a database that is still gzipped", write(packed.Bytes()), "not a MaxMind DB file", true},
		{"a file that is not there", filepath.Join(t.TempDir(), "nope.mmdb"), "no such file", false},
		{"a directory", t.TempDir(), "not a regular file", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			db, err := Open(c.path)
			if err == nil {
				t.Fatalf("Open succeeded: %+v", db.Info())
			}
			if db != nil {
				t.Error("Open returned a database and an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the error does not say %q: %v", c.want, err)
			}
			if got := errors.Is(err, ErrInvalid); got != c.invalid {
				t.Errorf("errors.Is(err, ErrInvalid) = %v, want %v: %v", got, c.invalid, err)
			}
		})
	}
}

// A database whose tree is broken is found by Verify, not by a lookup that runs
// into it much later.
func TestOpenVerifies(t *testing.T) {
	good, err := geoiptest.Bytes(networks)
	if err != nil {
		t.Fatal(err)
	}
	// Every byte of the search tree, and of the data after it, is overwritten
	// with 0xff, so that its records point to places that are not there. The
	// metadata at the end is left alone, which is what makes this a database
	// that opens and does not verify.
	marker := bytes.LastIndex(good, []byte("\xab\xcd\xefMaxMind.com"))
	if marker < 64 {
		t.Fatalf("the marker is at %d", marker)
	}
	damaged := bytes.Clone(good)
	for i := 0; i < marker; i++ {
		damaged[i] = 0xff
	}
	path := filepath.Join(t.TempDir(), "damaged.mmdb")
	if err := os.WriteFile(path, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted a database whose search tree is damaged")
	} else if !strings.Contains(err.Error(), "the database is damaged") || !errors.Is(err, ErrInvalid) {
		t.Errorf("the error does not say that the database is damaged, or is not ErrInvalid: %v", err)
	}
}

// What is read is capped: a file of more than 256 MiB is refused without being
// read, and the cap is checked as exactly as it is said.
func TestOpenRefusesALargeFile(t *testing.T) {
	if MaxFileSize != 256<<20 {
		t.Errorf("MaxFileSize = %d, want 256 MiB", MaxFileSize)
	}
	path := filepath.Join(t.TempDir(), "big.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxFileSize + 1); err != nil { // sparse: it costs nothing
		t.Skipf("cannot make a file of 256 MiB here: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = Open(path)
	if err == nil || !strings.Contains(err.Error(), "256 MiB") || !errors.Is(err, ErrInvalid) {
		t.Errorf("Open of a file of 256 MiB + 1 byte: %v, want a refusal that names the limit", err)
	}
}

func TestReadFileLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	for _, c := range []struct {
		size  int
		limit int64
		ok    bool
	}{
		{0, 10, true},
		{9, 10, true},
		{10, 10, true},
		{11, 10, false},
		{1000, 10, false},
	} {
		if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, c.size), 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := readFile(path, c.limit)
		if (err == nil) != c.ok {
			t.Errorf("readFile of %d bytes with the limit %d: err = %v, want ok = %v", c.size, c.limit, err, c.ok)
		}
		if err == nil && len(data) != c.size {
			t.Errorf("readFile of %d bytes returned %d", c.size, len(data))
		}
	}
}

// The reader is made for lookups on many goroutines at once, and the database
// is used on those of ingest.
func TestCountryConcurrently(t *testing.T) {
	db := openDB(t, networks)
	done := make(chan struct{})
	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for range 500 {
				if got := db.Country(netip.MustParseAddr("2001:db8::7")); got != "JP" {
					t.Errorf("Country = %q, want JP", got)
					return
				}
				if got := db.Country(netip.MustParseAddr("203.0.113.7")); got != "FR" {
					t.Errorf("Country = %q, want FR", got)
					return
				}
			}
		}()
	}
	for range 8 {
		<-done
	}
}

// The reader of MaxMind DB files is somebody else's code that reads bytes that
// an admin sent: a panic in it is the file's fault and no reason to stop the
// panel, or to leave a caller that holds a lock holding it.
func TestOpenRecoversAPanicOfTheReader(t *testing.T) {
	path := writeDB(t, networks)
	oldOpen, oldVerify := openReader, verifyReader
	t.Cleanup(func() { openReader, verifyReader = oldOpen, oldVerify })

	openReader = func([]byte) (*maxminddb.Reader, error) { panic("the parser blew up") }
	db, err := Open(path)
	if err == nil || db != nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "the parser blew up") {
		t.Errorf("Open with a parser that panics = %v, %v; want a refusal that is ErrInvalid", db, err)
	}

	openReader = oldOpen
	verifyReader = func(*maxminddb.Reader) error { panic("the verifier blew up") }
	db, err = Open(path)
	if err == nil || db != nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "the verifier blew up") {
		t.Errorf("Open with a verifier that panics = %v, %v; want a refusal that is ErrInvalid", db, err)
	}

	// And with both as they are, the file opens.
	verifyReader = oldVerify
	if _, err := Open(path); err != nil {
		t.Errorf("Open: %v", err)
	}
}

func TestSizeText(t *testing.T) {
	for n, want := range map[int64]string{256 << 20: "256 MiB", 64 << 20: "64 MiB", 1 << 20: "1 MiB", 1000: "1000 bytes", 0: "0 MiB"} {
		if got := SizeText(n); got != want {
			t.Errorf("SizeText(%d) = %q, want %q", n, got, want)
		}
	}
}
