package auth

import (
	"fmt"
	"net/netip"
	"strings"
)

// DefaultTrustedProxies is the list of proxies whose X-Forwarded-For and
// X-Forwarded-Proto headers are believed when none is configured: the loopback
// addresses, so that a reverse proxy on the same host works and nothing else
// does. It is the form that [ParseTrustedProxies] reads.
const DefaultTrustedProxies = "127.0.0.1/32,::1/128"

// An Option changes how [NewService] makes the service.
type Option func(*Service)

// WithTrustedProxies sets the proxies of the panel: the peers whose
// X-Forwarded-For header is believed when the panel works out which address a
// request comes from (the address that the limits on failed sign-ins count),
// and whose X-Forwarded-Proto is when it works out whether the client is on
// https (whether the session cookie is Secure). A request from any other peer
// says nothing with those headers, which are then ignored, so a client that
// connects to the panel directly cannot choose the address that it is counted
// under.
//
// The list replaces the default, [DefaultTrustedProxies]. It is nothing but
// what is given: a loopback, private or link-local peer is a proxy only when a
// prefix says so. Without any prefix no peer is a proxy. The service keeps its
// own copy of the list.
func WithTrustedProxies(prefixes ...netip.Prefix) Option {
	return func(s *Service) {
		s.trusted = make([]netip.Prefix, len(prefixes))
		for i, p := range prefixes {
			s.trusted[i] = p.Masked()
		}
	}
}

// defaultTrustedProxies is [DefaultTrustedProxies] as prefixes.
func defaultTrustedProxies() []netip.Prefix {
	prefixes, err := ParseTrustedProxies(DefaultTrustedProxies)
	if err != nil {
		panic("auth: " + err.Error()) // the constant is a list that can be read
	}
	return prefixes
}

// ParseTrustedProxies reads a comma-separated list of proxies, each an IP
// address (a prefix of the length of the address) or a CIDR prefix, as the
// operator writes them in POSTERN_TRUSTED_PROXIES: "127.0.0.1/32,::1/128" or
// "192.0.2.7, 198.51.100.0/24". Spaces around an entry and empty entries are
// ignored; the host bits of a prefix are cleared. An IPv4 address or network
// written in IPv6 form (::ffff:192.0.2.7) is read as the IPv4 one, because that
// is how the panel sees the peers that connect to it. An empty list gives no
// prefixes and no error.
//
// An entry that cannot be read is an error that names it, and no prefixes are
// returned: a proxy that is left out by mistake would only show up as every
// client having the address of the proxy, and one that is added by mistake
// would let clients choose their address.
func ParseTrustedProxies(list string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for entry := range strings.SplitSeq(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		p, err := parseProxy(entry)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

func parseProxy(entry string) (netip.Prefix, error) {
	unreadable := fmt.Errorf("trusted proxies: cannot read %q: write an IP address or a CIDR prefix, such as 203.0.113.7 or 203.0.113.0/24", entry)

	if !strings.Contains(entry, "/") {
		addr, err := netip.ParseAddr(entry)
		if err != nil || addr.Zone() != "" {
			return netip.Prefix{}, unreadable
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}

	p, err := netip.ParsePrefix(entry)
	if err != nil {
		return netip.Prefix{}, unreadable
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("trusted proxies: %q is an IPv4 network written in IPv6 form with a prefix shorter than 96 bits: write it as an IPv4 prefix", entry)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}
