// Package preflight checks a WEB proxy before the panel stores it (design
// spec 5.4): the domain has an A record that is an address of its node and is
// not proxied by Cloudflare, the base path is one that telemt takes, and an
// imported certificate is a valid pair for the domain. The node checks the
// domain again whenever it applies its state; this is the early answer that
// an admin gets while the form is still open.
package preflight

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/webrules"
)

// ErrDomain marks every finding about a domain: what an admin can mend, as
// opposed to a lookup that failed.
var ErrDomain = errors.New("the domain is not ready for a WEB proxy")

// ErrLookup marks a lookup that got no answer: the resolvers could not be
// reached, or answered with an error other than "no such name".
var ErrLookup = errors.New("the domain could not be looked up")

// A Resolver looks up the addresses of a name, as doh.Client does.
type Resolver interface {
	LookupIP(ctx context.Context, name string) ([]netip.Addr, error)
}

// lookupTimeout bounds one lookup.
const lookupTimeout = 15 * time.Second

// A Checker checks domains.
type Checker struct {
	resolver Resolver
	cf       *CloudflareRanges
}

// New returns a checker that looks up domains with r and knows the Cloudflare
// ranges cf (the embedded ones when nil).
func New(r Resolver, cf *CloudflareRanges) *Checker {
	if cf == nil {
		cf = DefaultCloudflareRanges()
	}
	return &Checker{resolver: r, cf: cf}
}

// CheckDomain checks the domain of a WEB proxy on a node whose public
// addresses are nodeIPs (as the node reported them): the domain has an A
// record, none of its addresses is in the Cloudflare ranges (an orange cloud
// terminates TLS at Cloudflare, and no WEB proxy can be behind that), and one
// A record is an address of the node. When the node has not reported its
// addresses yet, the last check is left to the node. It returns the A record
// that is the node's, or the first one when that is not known.
//
// A finding is an error that wraps ErrDomain; a lookup that failed wraps
// ErrLookup.
func (c *Checker) CheckDomain(ctx context.Context, domain string, nodeIPs []string) (netip.Addr, error) {
	ascii, err := webrules.CertDomain(domain)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %w", ErrDomain, err)
	}
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	addrs, err := c.resolver.LookupIP(ctx, ascii)
	if err != nil {
		if isNotFound(err) {
			return netip.Addr{}, fmt.Errorf("%w: %s has no A record", ErrDomain, ascii)
		}
		return netip.Addr{}, fmt.Errorf("%w: %s: %v", ErrLookup, ascii, err)
	}
	var a []netip.Addr
	for _, addr := range addrs {
		addr = addr.Unmap()
		if c.cf.Contains(addr) {
			return netip.Addr{}, fmt.Errorf("%w: %s resolves to %s, an address of Cloudflare: the record is proxied (orange cloud); make it DNS only", ErrDomain, ascii, addr)
		}
		if addr.Is4() {
			a = append(a, addr)
		}
	}
	if len(a) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s has no A record (an IPv4 address); a WEB proxy needs one", ErrDomain, ascii)
	}
	var own []netip.Addr
	for _, s := range nodeIPs {
		if ip, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			own = append(own, ip.Unmap())
		}
	}
	if len(own) == 0 {
		return a[0], nil
	}
	for _, addr := range a {
		if slices.Contains(own, addr) {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: the A record of %s is %s, which is not an address of the node (%s)",
		ErrDomain, ascii, joinAddrs(a), joinAddrs(own))
}

func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}

// isNotFound reports whether a lookup error says that the name does not exist
// or has no address (net.DNSError.IsNotFound, as doh returns it).
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// CheckBasePath checks the base path of a WEB proxy: empty, or segments of
// [A-Za-z0-9][A-Za-z0-9_-]* of at most 128 bytes each, joined by single
// slashes, with none at either end (the rule of telemt, webrules).
func CheckBasePath(s string) error {
	return webrules.CheckBasePath(s)
}

// maxPEM is the most bytes of a chain or a key that the node takes
// (PutCertificate).
const maxPEM = 64 * 1024

// A Certificate is what the panel keeps of an imported certificate.
type Certificate struct {
	// SHA256 is the lowercase hex SHA-256 of the chain as given, which the
	// node serves the route by (WebSettings.cert_sha256).
	SHA256 string
	// NotBefore and NotAfter are the validity of the leaf.
	NotBefore, NotAfter time.Time
}

// CheckCertificate checks an imported certificate: fullchain is a PEM chain,
// leaf first, key the PEM private key of the leaf, the leaf is for domain and
// valid at now. The error never holds any part of the input.
func CheckCertificate(fullchain, key []byte, domain string, now time.Time) (Certificate, error) {
	switch {
	case len(fullchain) == 0:
		return Certificate{}, errors.New("the certificate chain is empty")
	case len(key) == 0:
		return Certificate{}, errors.New("the private key is empty")
	case len(fullchain) > maxPEM:
		return Certificate{}, fmt.Errorf("the certificate chain is longer than %d bytes", maxPEM)
	case len(key) > maxPEM:
		return Certificate{}, fmt.Errorf("the private key is longer than %d bytes", maxPEM)
	}
	pair, err := tls.X509KeyPair(fullchain, key)
	if err != nil {
		// The errors of the standard library name what is wrong without
		// quoting the input.
		return Certificate{}, fmt.Errorf("the certificate and the key are not a pair: %v", err)
	}
	if len(pair.Certificate) == 0 {
		return Certificate{}, errors.New("the certificate chain has no certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return Certificate{}, fmt.Errorf("the first certificate of the chain cannot be read: %v", err)
	}
	ascii, err := webrules.CertDomain(domain)
	if err != nil {
		return Certificate{}, err
	}
	if err := leaf.VerifyHostname(ascii); err != nil {
		return Certificate{}, fmt.Errorf("the certificate is not for %s: %v", ascii, err)
	}
	switch {
	case now.Add(webrules.ClockTolerance).Before(leaf.NotBefore):
		return Certificate{}, fmt.Errorf("the certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	case !now.Before(leaf.NotAfter):
		return Certificate{}, fmt.Errorf("the certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	sum := sha256.Sum256(fullchain)
	return Certificate{SHA256: hex.EncodeToString(sum[:]), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
}
