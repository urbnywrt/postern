// Package geoiptest writes small country databases for the tests of any package
// that looks countries up: the same kind of file that DB-IP publishes (a MaxMind
// DB with an IPv6 search tree, IPv4 networks aliased into it, and the country of
// a network in country.iso_code), with only the networks that a test names.
//
//	err := geoiptest.Write(path, map[string]string{
//		"198.51.100.0/24": "DE",
//		"2001:db8::/32":   "JP",
//	})
//
// The networks that tests use are documentation ranges and loopback, which are
// reserved: a writer leaves them out unless it is told to include them, and this
// one is. It is a package for tests; nothing but tests imports it.
package geoiptest

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"slices"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// DatabaseType is the type that Write gives a database unless [WithType] says
// otherwise: the one that DB-IP gives its country database.
const DatabaseType = "DBIP-Country-Lite"

// An Option changes the database that [Write] and [Bytes] make.
type Option func(*config)

type config struct {
	built        time.Time
	databaseType string
	ipVersion    int
	noAliasing   bool
}

// WithBuilt sets the build time of the database. Without it the database is
// built now.
func WithBuilt(t time.Time) Option { return func(c *config) { c.built = t } }

// WithType sets the type of the database: "GeoLite2-ASN" makes a database that
// is not one of countries, for a test that has to refuse one.
func WithType(databaseType string) Option { return func(c *config) { c.databaseType = databaseType } }

// WithIPVersion sets the version of the search tree, 4 or 6; it is 6 without
// this option. A tree of version 4 holds IPv4 networks only.
func WithIPVersion(version int) Option { return func(c *config) { c.ipVersion = version } }

// WithoutIPv4Aliasing leaves the IPv4 networks out of the places in the tree of
// IPv6 where an IPv4 address that is written the IPv6 way (::ffff:192.0.2.1,
// 2002:c000:201::) is found. DB-IP's database has them there, and so has every
// database that Write makes without this option; it is for a test of a reader
// that must not depend on it.
func WithoutIPv4Aliasing() Option { return func(c *config) { c.noAliasing = true } }

// Write makes a database of the networks, each a CIDR prefix such as
// "198.51.100.0/24" that maps to a country code such as "DE", and writes it to
// path. The code is stored as it is given: a test may give one that is not two
// letters, to see what the reader does with it.
func Write(path string, networks map[string]string, opts ...Option) error {
	data, err := Bytes(networks, opts...)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("geoiptest: %w", err)
	}
	return nil
}

// Bytes is [Write] without the file: the database as the bytes of the file.
func Bytes(networks map[string]string, opts ...Option) ([]byte, error) {
	c := config{databaseType: DatabaseType, ipVersion: 6}
	for _, opt := range opts {
		opt(&c)
	}
	options := mmdbwriter.Options{
		DatabaseType: c.databaseType,
		Description:  map[string]string{"en": "Postern test database"},
		Languages:    []string{"en"},
		IPVersion:    c.ipVersion,
		// The aliasing of IPv4 into the IPv6 tree stays on, as it is in the
		// database of DB-IP, unless a test asks for none; a tree of IPv4 has
		// none.
		DisableIPv4Aliasing: c.noAliasing,
		// Loopback, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and
		// 2001:db8::/32 are reserved networks, which a tree takes only when it
		// is told to.
		IncludeReservedNetworks: true,
	}
	if !c.built.IsZero() {
		options.BuildEpoch = c.built.Unix()
	}
	tree, err := mmdbwriter.New(options)
	if err != nil {
		return nil, fmt.Errorf("geoiptest: %w", err)
	}

	// In order, so that the same networks make the same file.
	prefixes := make([]string, 0, len(networks))
	for prefix := range networks {
		prefixes = append(prefixes, prefix)
	}
	slices.Sort(prefixes)
	for _, prefix := range prefixes {
		_, network, err := net.ParseCIDR(prefix)
		if err != nil {
			return nil, fmt.Errorf("geoiptest: %w", err)
		}
		// The writer takes an IPv6 network into a tree of IPv4 without a word,
		// and files it under an address that it is not.
		if c.ipVersion == 4 && network.IP.To4() == nil {
			return nil, fmt.Errorf("geoiptest: %s is not an IPv4 network, and the tree is one of IPv4", prefix)
		}
		record := mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(networks[prefix])}}
		if err := tree.Insert(network, record); err != nil {
			return nil, fmt.Errorf("geoiptest: %s: %w", prefix, err)
		}
	}

	var buf bytes.Buffer
	if _, err := tree.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("geoiptest: %w", err)
	}
	return buf.Bytes(), nil
}
