// Package geoip looks up the country of an IP address in a country database of
// the MaxMind DB format, which is what the "IP to Country Lite" database of
// DB-IP is. The panel and the nodes both use it: the panel keeps the database
// current (internal/panel/geodb) and the nodes look their clients up in the copy
// that the panel sends them, so that no client address leaves a node.
//
// A database is read into memory, about 8 MB for the one of DB-IP, and not
// mapped from its file: a file that is replaced, or deleted, while it is being
// used cannot make a lookup fault, and the owner of a [DB] that it no longer
// wants only has to let go of it. A [DB] is safe for use by many goroutines.
//
// A lookup gives the code of a country, "DE", or nothing. DB-IP gives the code
// "ZZ" to ranges that belong to no country, such as loopback and the private
// ranges; it is a code of two letters like the others, and callers that do not
// want it leave it out themselves.
//
// DB-IP's licence (CC BY 4.0) asks for a link back to DB-IP.com wherever its
// data is shown; [Attribution], [AttributionURL] and [Licence] are the words.
package geoip

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// What DB-IP asks to be shown next to its data: the text, the page it links to,
// and the licence of the database.
const (
	Attribution    = "IP Geolocation by DB-IP"
	AttributionURL = "https://db-ip.com"
	Licence        = "CC BY 4.0"
)

// MaxFileSize is the largest file that [Open] reads, 256 MiB. The database of
// DB-IP is about 8 MB; the cap is for a file that is something else.
const MaxFileSize = 256 << 20

// ErrInvalid is what the error of [Open] is when the file was read and is not a
// usable country database: it is too large, it is not in the MaxMind DB format,
// it is damaged, it is a database of another kind, or its search tree is one of
// IPv4. A file that could not be read at all is not this: that is the error of
// the file system. A caller tells the two apart with errors.Is, to answer a
// client who sent the file with a refusal and not with a fault of the server.
var ErrInvalid = errors.New("geoip: not a usable country database")

// invalidError is an error that says what is wrong with a file in its own words
// and is [ErrInvalid] for errors.Is.
type invalidError struct {
	msg   string
	cause error
}

func (e *invalidError) Error() string {
	if e.cause == nil {
		return e.msg
	}
	return e.msg + ": " + e.cause.Error()
}

func (e *invalidError) Unwrap() error { return e.cause }

func (e *invalidError) Is(target error) bool { return target == ErrInvalid }

// Info describes a database.
type Info struct {
	// DatabaseType is the type that the file says it is, "DBIP-Country-Lite".
	DatabaseType string
	// Built is when the database was built, in UTC.
	Built time.Time
	// IPVersion is the version of the search tree: always 6 for a database that
	// [Open] takes. Addresses of IPv4 are found in it, too.
	IPVersion uint
}

// A DB is a country database that has been read and verified.
type DB struct {
	reader *maxminddb.Reader
	info   Info
}

// Open reads the file at path, which is at most [MaxFileSize], and opens it as a
// database. It verifies the whole of the file, so that a database that is
// damaged is found now and not by a lookup that runs into it, and it refuses
// anything that is not a country database with a search tree of IPv6: another
// type of database (cities, ASNs), a tree of IPv4, a file that is not in the
// MaxMind DB format at all. A file that is still gzipped is one of those: the
// caller unpacks it.
func Open(path string) (*DB, error) {
	data, err := readFile(path, MaxFileSize)
	if err != nil {
		return nil, err
	}
	return parse(data)
}

// The reader of MaxMind DB files and its verification, which tests replace by
// ones that panic.
var (
	openReader   = func(data []byte) (*maxminddb.Reader, error) { return maxminddb.OpenBytes(data) }
	verifyReader = func(r *maxminddb.Reader) error { return r.Verify() }
)

// parse opens the bytes of a file as a country database. The reader is the code
// of somebody else and the bytes are not to be trusted: a panic in it is the
// fault of the file, and it is ErrInvalid, as any other.
func parse(data []byte) (db *DB, err error) {
	defer func() {
		if r := recover(); r != nil {
			db, err = nil, &invalidError{msg: "geoip: the file made the reader of MaxMind DB files fail", cause: fmt.Errorf("%v", r)}
		}
	}()
	reader, err := openReader(data)
	if err != nil {
		return nil, &invalidError{msg: "geoip: the file is not a MaxMind DB file", cause: err}
	}
	md := reader.Metadata
	// "DBIP-Country-Lite", "GeoLite2-Country", "GeoIP2-Country": the types of
	// the databases that hold the country of a network in country.iso_code.
	if !strings.Contains(strings.ToLower(md.DatabaseType), "country") {
		return nil, &invalidError{msg: fmt.Sprintf("geoip: the database is of type %q, not a country database", md.DatabaseType)}
	}
	if md.IPVersion != 6 {
		return nil, &invalidError{msg: fmt.Sprintf("geoip: the database has a search tree of IPv%d; a country database has to have one of IPv6", md.IPVersion)}
	}
	if err := verifyReader(reader); err != nil {
		return nil, &invalidError{msg: "geoip: the database is damaged", cause: err}
	}
	return &DB{
		reader: reader,
		info: Info{
			DatabaseType: md.DatabaseType,
			Built:        md.BuildTime().UTC(),
			IPVersion:    md.IPVersion,
		},
	}, nil
}

// readFile reads the whole of the regular file at path, if it is at most limit
// bytes. A file that is larger is refused without being read.
func readFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("geoip: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("geoip: %s is not a regular file", filepath.Base(path))
	}
	if st.Size() > limit {
		return nil, &invalidError{msg: fmt.Sprintf("geoip: the file is larger than %s", SizeText(limit))}
	}
	data := make([]byte, st.Size())
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, fmt.Errorf("geoip: %w", err)
	}
	return data, nil
}

// SizeText says a size as the messages of the panel do: 256 MiB, or, when it is
// not a whole number of mebibytes, 1000 bytes.
func SizeText(n int64) string {
	if n%(1<<20) == 0 {
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d bytes", n)
}

// Info describes the database. The zero Info is for a nil *DB.
func (d *DB) Info() Info {
	if d == nil {
		return Info{}
	}
	return d.info
}

// country is what a record of the database holds that Country reads.
type country struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// Country returns the code of the country of an address, "DE", in upper case.
// It returns "" for an address that the database does not have, for the zero
// address, for a nil *DB, and for a record whose code is not two letters. An
// IPv4 address that is written as an IPv6 one (::ffff:192.0.2.1) is looked up as
// the IPv4 address that it stands for, and a zone is no part of an address.
func (d *DB) Country(ip netip.Addr) string {
	if d == nil || !ip.IsValid() {
		return ""
	}
	var rec country
	if err := d.reader.Lookup(ip.Unmap()).Decode(&rec); err != nil {
		return ""
	}
	return twoLetters(rec.Country.ISOCode)
}

// twoLetters returns code in upper case if it is two letters of the alphabet,
// and "" if it is anything else.
func twoLetters(code string) string {
	if len(code) != 2 {
		return ""
	}
	var out [2]byte
	for i := range out {
		c := code[i]
		switch {
		case 'A' <= c && c <= 'Z':
		case 'a' <= c && c <= 'z':
			c -= 'a' - 'A'
		default:
			return ""
		}
		out[i] = c
	}
	return string(out[:])
}
