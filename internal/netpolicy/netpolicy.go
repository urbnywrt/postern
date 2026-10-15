// Package netpolicy is the one destination policy of the node: which addresses
// something the node does not trust with its network may be connected to on
// its behalf. The edge's SOCKS ports apply it to the engines' connections and
// to the mask connections of strangers (egress.DestinationAllowed), the mtg
// driver to the fronting target that mtg dials from the node itself, and the
// state validation to a mask target override of an mtg proxy.
//
// An IPv6 address that carries an IPv4 address is judged as that IPv4 address:
// IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d, deprecated), NAT64
// under the well-known prefix (64:ff9b::a.b.c.d, RFC 6052) and 6to4
// (2002:AABB:CCDD::, RFC 3056). Otherwise a NAT64 gateway or a 6to4 relay would
// deliver a connection to 64:ff9b::7f00:1 to the node's own loopback, or one to
// 2002:0a00:0001:: to a private network, past a check of the IPv6 form alone.
//
// The local-use NAT64 prefix 64:ff9b:1::/48 (RFC 8215) is refused as a whole
// (Ruling S5-15): a network may lay the IPv4 address out under it with any of
// the RFC 6052 prefix lengths (/32 to /64, or /96), at different offsets, so no
// one check can tell which address a packet to it would reach. Local-use NAT64
// is not a supported setup for a node.
package netpolicy

import (
	"net/netip"
	"strings"
)

var (
	ipv4Compatible = netip.MustParsePrefix("::/96")
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	nat64Local     = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour      = netip.MustParsePrefix("2002::/16")

	cgnat       = netip.MustParsePrefix("100.64.0.0/10")
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8")
	broadcast   = netip.MustParseAddr("255.255.255.255")
)

// EmbeddedIPv4 returns the IPv4 address that an IPv6 address carries, and
// true, for the IPv4-mapped, IPv4-compatible, well-known NAT64 and 6to4 forms
// (see the package documentation); an IPv4 address is returned as it is. For
// any other address, the local-use NAT64 prefix among them, it returns the
// address itself and false. The zone is dropped.
func EmbeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	a = a.WithZone("")
	if !a.IsValid() {
		return a, false
	}
	if a.Is4() {
		return a, true
	}
	b := a.As16()
	switch {
	case a.Is4In6():
		return a.Unmap(), true
	case ipv4Compatible.Contains(a):
		// :: and ::1 are the unspecified and the loopback address, not
		// 0.0.0.0 and 0.0.0.1 in another form; both are refused either way.
		if a.IsUnspecified() || a.IsLoopback() {
			return a, false
		}
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case nat64WellKnown.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return a, false
}

// NonPublic says what kind of address a is when the policy refuses it, and
// returns "" for an address that may be connected to: no loopback, private
// (RFC 1918, unique local), link-local (the metadata services of the clouds
// among them), multicast, unspecified, "this network", broadcast or
// carrier-grade NAT address, nothing under the local-use NAT64 prefix, and
// nothing that is not an address at all. An IPv6 address that carries an IPv4
// address is judged as that address.
func NonPublic(a netip.Addr) string {
	if v4, ok := EmbeddedIPv4(a); ok {
		a = v4
	}
	switch {
	case !a.IsValid():
		return "not an IP address"
	case nat64Local.Contains(a):
		return "local-use NAT64"
	case a.IsUnspecified():
		return "unspecified"
	case a.IsLoopback():
		return "loopback"
	case a.IsPrivate():
		return "private"
	case a.IsLinkLocalUnicast():
		return "link-local"
	case a.IsMulticast():
		return "multicast"
	case cgnat.Contains(a):
		return "carrier-grade NAT"
	case thisNetwork.Contains(a):
		return "this network"
	case a == broadcast:
		return "broadcast"
	}
	return ""
}

// Allowed reports whether the policy lets a be connected to: NonPublic(a) == "".
func Allowed(a netip.Addr) bool { return NonPublic(a) == "" }

// AbsoluteName returns host, the name of a destination, as an absolute DNS name
// with its final dot when it has a dot in it: such a name is a name on the
// Internet, so the search list of resolv.conf must never be tried on it (a
// name that does not exist would be looked up again under the node's local
// domains, and could resolve there; the runners of GitHub have such a search
// list). An IP literal, an empty host, an absolute name and a name of one
// label, such as localhost (which /etc/hosts answers), are returned as they
// are; what any name resolves to is still checked against the policy.
func AbsoluteName(host string) string {
	if host == "" || strings.HasSuffix(host, ".") || !strings.Contains(host, ".") {
		return host
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return host
	}
	return host + "."
}
