// Package webrules holds the rules of the settings of a WEB proxy
// (nodev1.WebSettings) that more than one part of the node reads: the state
// validator refuses what breaks them, and the telemt driver renders what it
// takes. The rules are telemt's (its [web] section) and the plan's.
package webrules

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

// ClockTolerance is how far ahead of the clock the notBefore of a WEB proxy's
// certificate may be and the certificate still count as valid (the panel's
// preflight, the node's import and status, the edge): a certificate minted a
// moment ago by a clock a little ahead is not refused (F5 of the real-server
// pass). CAs back-date notBefore; a scripted mint-and-import does not.
const ClockTolerance = 5 * time.Minute

// The modes of the certificate of a WEB proxy on a tls listener.
const (
	CertModeACME     = "acme-dns01"
	CertModeImported = "imported"
)

// The secret modes of a WEB profile; empty means SecretModePlain.
const (
	SecretModePlain = "plain"
	SecretModeDD    = "dd"
)

// The carriers telemt serves. Empty carrier means CarrierHTTPS; empty carriers
// means [CarrierHTTPSLanes] (spec 5.4: https for clients that do not
// negotiate, among them iOS; https-lanes for Desktop).
const (
	CarrierHTTPS      = "https"
	CarrierHTTPSLanes = "https-lanes"
)

// PublicPort is the port of public_addr: a WEB proxy is always reached on 443
// (clients ignore any other port, and telemt checks it).
const PublicPort = 443

// MaxBasePathSegment is the longest segment of a base path, in bytes.
const MaxBasePathSegment = 128

// SecretMode returns the secret mode, SecretModePlain for an empty one.
func SecretMode(s string) string {
	if s == "" {
		return SecretModePlain
	}
	return s
}

// CheckSecretMode accepts "", plain and dd.
func CheckSecretMode(s string) error {
	switch s {
	case "", SecretModePlain, SecretModeDD:
		return nil
	}
	return fmt.Errorf("secret_mode %.40q is neither %q nor %q", s, SecretModePlain, SecretModeDD)
}

// Carrier returns the carrier, CarrierHTTPS for an empty one.
func Carrier(s string) string {
	if s == "" {
		return CarrierHTTPS
	}
	return s
}

// Carriers returns the carriers offered, [CarrierHTTPSLanes] for none.
func Carriers(cs []string) []string {
	if len(cs) == 0 {
		return []string{CarrierHTTPSLanes}
	}
	return cs
}

// CheckCarrier accepts "", https and https-lanes.
func CheckCarrier(s string) error {
	switch s {
	case "", CarrierHTTPS, CarrierHTTPSLanes:
		return nil
	}
	return fmt.Errorf("carrier %.40q is neither %q nor %q", s, CarrierHTTPS, CarrierHTTPSLanes)
}

// CheckCarriers accepts a list of distinct carriers that CheckCarrier takes,
// none empty.
func CheckCarriers(cs []string) error {
	seen := map[string]bool{}
	for _, c := range cs {
		if c == "" {
			return errors.New("carriers has an empty entry")
		}
		if err := CheckCarrier(c); err != nil {
			return fmt.Errorf("carriers: %w", err)
		}
		if seen[c] {
			return fmt.Errorf("carriers names %q twice", c)
		}
		seen[c] = true
	}
	return nil
}

// CheckBasePath accepts an empty base path, or segments of
// [A-Za-z0-9][A-Za-z0-9_-]* of at most MaxBasePathSegment bytes, joined by
// single slashes, with no slash at either end: "tg", "a/b-c". telemt gets it
// as it is.
func CheckBasePath(s string) error {
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return fmt.Errorf("base_path %.70q must not start or end with a slash", s)
	}
	for seg := range strings.SplitSeq(s, "/") {
		switch {
		case seg == "":
			return fmt.Errorf("base_path %.70q has an empty segment", s)
		case len(seg) > MaxBasePathSegment:
			return fmt.Errorf("base_path %.70q has a segment longer than %d bytes", s, MaxBasePathSegment)
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
			if !alnum && (i == 0 || c != '_' && c != '-') {
				return fmt.Errorf("base_path %.70q: a segment must be letters, digits, '_' or '-' and start with a letter or digit", s)
			}
		}
	}
	return nil
}

// ParsePublicAddr reads public_addr: an IPv4 address, bare or with port 443
// ("203.0.113.10" or "203.0.113.10:443"), that is a global unicast address.
// Empty is an error: the caller decides what an unset one means.
func ParsePublicAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, errors.New("public_addr is empty")
	}
	host := s
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Port() != PublicPort {
			return netip.Addr{}, fmt.Errorf("public_addr %.70q: the port must be %d", s, PublicPort)
		}
		host = ap.Addr().String()
	}
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("public_addr %.70q is not an IPv4 address", s)
	}
	a = a.Unmap()
	if !a.Is4() {
		return netip.Addr{}, fmt.Errorf("public_addr %.70q is not an IPv4 address", s)
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return netip.Addr{}, fmt.Errorf("public_addr %s is not a public address", a)
	}
	return a, nil
}

// PublicAddr formats the public_addr of a vhost, "ip:443".
func PublicAddr(a netip.Addr) string {
	return netip.AddrPortFrom(a, PublicPort).String()
}

// CertDomain is the name of the certificate directory of a WEB domain, and the
// host of its vhost: the domain in lowercase ASCII (punycode for a name with
// other letters), without the dot a fully qualified name may end with.
func CertDomain(domain string) (string, error) {
	d := strings.TrimSuffix(domain, ".")
	if d == "" {
		return "", errors.New("the domain is empty")
	}
	ascii, err := idna.Lookup.ToASCII(d)
	if err != nil {
		return "", fmt.Errorf("the domain %.70q is not a host name: %v", domain, err)
	}
	ascii = strings.ToLower(ascii)
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("the domain %.70q has a single label", domain)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", fmt.Errorf("the domain %.70q has an empty label or one longer than 63 bytes", domain)
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", fmt.Errorf("the domain %.70q has a character that is not allowed in a host name", domain)
			}
		}
	}
	return ascii, nil
}
