package netpolicy

import (
	"net/netip"
	"strings"
	"testing"
)

// Every IPv6 form that carries an IPv4 address is judged as that address: a
// public one embedded is allowed, a private or loopback one embedded is
// refused.
func TestEmbeddedIPv4Forms(t *testing.T) {
	tests := []struct {
		name  string
		addr  string
		want  string // the embedded IPv4 address, "" for none
		allow bool
	}{
		{"ipv4 public", "192.0.2.10", "192.0.2.10", true},
		{"ipv4 private", "10.0.0.1", "10.0.0.1", false},
		{"ipv4 loopback", "127.0.0.1", "127.0.0.1", false},
		{"mapped public", "::ffff:192.0.2.10", "192.0.2.10", true},
		{"mapped private", "::ffff:10.0.0.1", "10.0.0.1", false},
		{"mapped loopback", "::ffff:127.0.0.1", "127.0.0.1", false},
		{"compatible public", "::192.0.2.10", "192.0.2.10", true},
		{"compatible private", "::c0a8:101", "192.168.1.1", false},
		{"compatible loopback", "::7f00:1", "127.0.0.1", false},
		{"nat64 public", "64:ff9b::c000:20a", "192.0.2.10", true},
		{"nat64 private", "64:ff9b::a00:1", "10.0.0.1", false},
		{"nat64 loopback", "64:ff9b::7f00:1", "127.0.0.1", false},
		// The local-use NAT64 prefix is refused as a whole, whatever the
		// layout of the IPv4 address under it (RFC 6052 prefix lengths):
		// 127.0.0.1 and 192.0.2.10 in every layout that fits under the /48
		// (the /32 and /40 layouts put the IPv4 address where the prefix
		// is, so none of them lies inside it).
		{"nat64 local, bytes of the /40 layout", "64:ff9b:1:7f00:0:100::", "", false},
		{"nat64 local /48 layout", "64:ff9b:1:7f00:0:1::", "", false},
		{"nat64 local /56 layout", "64:ff9b:1:0:7f:0:1:0", "", false},
		{"nat64 local /64 layout", "64:ff9b:1:0:0:7f00:100:0", "", false},
		{"nat64 local /96 layout loopback", "64:ff9b:1::7f00:1", "", false},
		{"nat64 local /96 layout public", "64:ff9b:1::c000:20a", "", false},
		{"nat64 local /48 layout public", "64:ff9b:1:c000:0:20a::", "", false},
		{"nat64 local private /96", "64:ff9b:1:abcd::ac10:1", "", false},
		{"6to4 public", "2002:c000:20a::1", "192.0.2.10", true},
		{"6to4 private", "2002:a00:1::1", "10.0.0.1", false},
		{"6to4 loopback", "2002:7f00:1::1", "127.0.0.1", false},
		{"6to4 cgnat", "2002:6440:1::1", "100.64.0.1", false},
		{"ipv6 public", "2001:db8::10", "", true},
		{"ipv6 loopback", "::1", "", false},
		{"ipv6 unspecified", "::", "", false},
		{"ipv6 unique local", "fd00::1", "", false},
		{"ipv6 link-local with zone", "fe80::1%eth0", "", false},
		{"ipv6 multicast", "ff02::1", "", false},
		{"ipv4 cgnat", "100.64.0.1", "100.64.0.1", false},
		{"ipv4 this network", "0.1.2.3", "0.1.2.3", false},
		{"ipv4 broadcast", "255.255.255.255", "255.255.255.255", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := netip.MustParseAddr(tt.addr)
			v4, ok := EmbeddedIPv4(a)
			if tt.want == "" {
				if ok && a.Is6() {
					t.Errorf("EmbeddedIPv4(%s) = %s, want none", a, v4)
				}
				if strings.HasPrefix(tt.name, "nat64 local") && NonPublic(a) != "local-use NAT64" {
					t.Errorf("NonPublic(%s) = %q, want local-use NAT64", a, NonPublic(a))
				}
			} else if !ok || v4.String() != tt.want {
				t.Errorf("EmbeddedIPv4(%s) = %s, %v; want %s", a, v4, ok, tt.want)
			}
			if got := Allowed(a); got != tt.allow {
				t.Errorf("Allowed(%s) = %v (%q), want %v", a, got, NonPublic(a), tt.allow)
			}
		})
	}
	if kind := NonPublic(netip.Addr{}); kind != "not an IP address" {
		t.Errorf("NonPublic(zero) = %q", kind)
	}
}

// The names of destinations on the Internet are looked up as absolute names,
// so that the search list of resolv.conf is never tried on them; IP literals
// and names of one label stay as they are.
func TestAbsoluteName(t *testing.T) {
	for in, want := range map[string]string{
		"core.telegram.org":  "core.telegram.org.",
		"core.telegram.org.": "core.telegram.org.",
		"localhost":          "localhost",
		"192.0.2.1":          "192.0.2.1",
		"2001:db8::1":        "2001:db8::1",
		"fe80::1%eth0":       "fe80::1%eth0",
		"":                   "",
	} {
		if got := AbsoluteName(in); got != want {
			t.Errorf("AbsoluteName(%q) = %q, want %q", in, got, want)
		}
	}
}
