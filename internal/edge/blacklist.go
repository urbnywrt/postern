package edge

import (
	"fmt"
	"net/netip"

	"github.com/urbnywrt/postern/internal/edge/rules"
)

// cidrSet is a set of IP prefixes: the blacklist of a node. The prefixes are
// grouped by length, so that asking for an address costs one map lookup per
// distinct length in the set, however many prefixes it holds. IPv4 addresses
// are kept apart from IPv6 ones, and an IPv4-mapped IPv6 address, in the set
// or asked for, counts as the IPv4 address it maps.
//
// The zero value is the empty set. A cidrSet is not changed after
// parseCIDRs returns it, and may be read from any number of goroutines.
type cidrSet struct {
	v4, v6 []prefixGroup
}

// prefixGroup holds the prefixes of one length, as their masked addresses.
type prefixGroup struct {
	bits  int
	addrs map[netip.Addr]struct{}
}

// parseCIDRs builds the set of the given prefixes. An entry is a prefix in
// CIDR notation, whose host bits may be set ("192.0.2.7/24" is 192.0.2.0/24),
// or a bare address, which is the prefix of that one address (see
// rules.ParsePrefix).
func parseCIDRs(list []string) (cidrSet, error) {
	var s cidrSet
	for _, item := range list {
		p, err := rules.ParsePrefix(item)
		if err != nil {
			return cidrSet{}, fmt.Errorf("edge: blacklist entry: %w", err)
		}
		s.add(p)
	}
	return s, nil
}

func (s *cidrSet) add(p netip.Prefix) {
	groups := &s.v6
	if p.Addr().Is4() {
		groups = &s.v4
	}
	for _, g := range *groups {
		if g.bits == p.Bits() {
			g.addrs[p.Addr()] = struct{}{}
			return
		}
	}
	*groups = append(*groups, prefixGroup{bits: p.Bits(), addrs: map[netip.Addr]struct{}{p.Addr(): {}}})
}

// contains reports whether a falls in a prefix of the set. The zone of an IPv6
// address does not matter, and the invalid address is in no set.
func (s cidrSet) contains(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	groups := s.v6
	if a.Is4() {
		groups = s.v4
	}
	for _, g := range groups {
		p, err := a.Prefix(g.bits)
		if err != nil {
			continue // the invalid address
		}
		if _, ok := g.addrs[p.Addr()]; ok {
			return true
		}
	}
	return false
}
