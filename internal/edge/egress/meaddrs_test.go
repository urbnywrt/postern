package egress

import (
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// The middle-proxy addresses of a configuration are IP addresses and ports;
// anything else refuses the configuration, and so do too many of them.
func TestParseMEAddrs(t *testing.T) {
	me, err := ParseMEAddrs([]string{"203.0.113.7:8888", "[2001:db8::d]:8888", "[::ffff:198.51.100.9]:80", "203.0.113.7:8888", "203.0.113.7:443"})
	if err != nil {
		t.Fatalf("ParseMEAddrs: %v", err)
	}
	if me.Len() != 4 {
		t.Errorf("Len = %d, want 4 (a repeated address counts once, another port of an address apart)", me.Len())
	}
	type ipPort struct {
		ip   string
		port uint16
	}
	for _, a := range []ipPort{
		{"203.0.113.7", 8888}, {"203.0.113.7", 443}, {"2001:db8::d", 8888}, {"198.51.100.9", 80},
		{"::ffff:203.0.113.7", 8888}, {"2001:DB8:0:0:0:0:0:D", 8888},
	} {
		if !me.Contains(netip.MustParseAddr(a.ip), a.port) {
			t.Errorf("%s port %d is not among the addresses", a.ip, a.port)
		}
	}
	for _, a := range []ipPort{
		{"203.0.113.7", 8889}, {"149.154.175.50", 8888}, {"2001:db8::d", 443}, {"198.51.100.9", 8888}, {"203.0.113.8", 8888},
	} {
		if me.Contains(netip.MustParseAddr(a.ip), a.port) {
			t.Errorf("%s port %d is among the addresses", a.ip, a.port)
		}
	}
	var none *MEAddrs
	if none.Len() != 0 || none.Contains(netip.MustParseAddr("203.0.113.7"), 8888) {
		t.Error("a nil set is not empty")
	}

	if me, err := ParseMEAddrs(nil); err != nil || me.Len() != 0 {
		t.Errorf("ParseMEAddrs(nil) = %v, %v; want an empty set", me, err)
	}
	for _, bad := range []string{
		"", "203.0.113.9", "203.0.113.9:0", "203.0.113.9:65536", "proxy.example.com:8888", "[fe80::1%eth0]:8888",
		"2001:db8::1:8888", "[203.0.113.9]:8888", "[2001:db8::1]", " 203.0.113.9:8888",
	} {
		_, err := ParseMEAddrs([]string{"203.0.113.7:8888", bad})
		if err == nil {
			t.Errorf("ParseMEAddrs took %q", bad)
			continue
		}
		if bad != "" && !strings.Contains(err.Error(), strings.TrimSpace(bad)) {
			t.Errorf("the error for %q does not name it: %v", bad, err)
		}
	}
	many := make([]string, MaxMEAddrs+1)
	for i := range many {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)})
		many[i] = netip.AddrPortFrom(a, 8888).String()
	}
	if _, err := ParseMEAddrs(many[:MaxMEAddrs]); err != nil {
		t.Errorf("ParseMEAddrs refused %d addresses: %v", MaxMEAddrs, err)
	}
	if _, err := ParseMEAddrs(many); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Errorf("ParseMEAddrs of %d addresses = %v, want too many", len(many), err)
	}
}

// A CONNECT without a scope to a middle proxy, by its address and port, is of
// scope "me"; a scope that the engine gives wins; a name is never taken for a
// middle proxy, and neither is a datacenter, also on the address of one.
func TestRouterScopeOf(t *testing.T) {
	r := NewRouter(quiet)
	if got := r.ScopeOf("", "203.0.113.7", 8888); got != "" {
		t.Errorf("without addresses: ScopeOf = %q, want no scope", got)
	}
	// getProxyConfig lists middle proxies on the datacenters' own addresses,
	// at port 8888.
	me, err := ParseMEAddrs([]string{"203.0.113.7:8888", "[2001:db8::d]:8888", "149.154.175.50:8888"})
	if err != nil {
		t.Fatal(err)
	}
	r.SetMEAddrs(me)
	cases := []struct {
		scope, host string
		port        uint16
		want        string
	}{
		{"", "203.0.113.7", 8888, "me"},
		{"", "2001:db8::d", 8888, "me"},
		{"", "2001:DB8:0:0:0:0:0:D", 8888, "me"}, // another spelling of the address
		{"", "::ffff:203.0.113.7", 8888, "me"},
		{"", "149.154.175.50", 8888, "me"}, // a middle proxy on the address of DC1
		{"", "149.154.175.50", 443, ""},    // DC1 itself
		{"", "149.154.175.50", 80, ""},
		{"", "203.0.113.7", 443, ""}, // another port of a middle proxy's address
		{"", "149.154.167.51", 443, ""},
		{"", "proxy.example.com", 8888, ""},
		{"", "203.0.113.5", 8888, ""},
		{"", "", 0, ""},
		{"fetch", "203.0.113.7", 8888, "fetch"}, // the engine's scope wins
		{"me", "203.0.113.5", 443, "me"},
		{"other", "2001:db8::d", 8888, "other"},
	}
	for _, tc := range cases {
		if got := r.ScopeOf(tc.scope, tc.host, tc.port); got != tc.want {
			t.Errorf("ScopeOf(%q, %q, %d) = %q, want %q", tc.scope, tc.host, tc.port, got, tc.want)
		}
	}
	r.SetMEAddrs(nil)
	if got := r.ScopeOf("", "203.0.113.7", 8888); got != "" {
		t.Errorf("after SetMEAddrs(nil): ScopeOf = %q, want no scope", got)
	}
}

// The addresses may change while connections are classified.
func TestRouterScopeOfIsRaceFree(t *testing.T) {
	r := NewRouter(quiet)
	a, _ := ParseMEAddrs([]string{"203.0.113.7:8888"})
	b, _ := ParseMEAddrs([]string{"203.0.113.8:8888"})
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			for j := range 500 {
				if (i+j)%2 == 0 {
					r.SetMEAddrs(a)
				} else {
					r.SetMEAddrs(b)
				}
				_ = r.ScopeOf("", "203.0.113.7", 8888)
			}
		})
	}
	wg.Wait()
}

// The SOCKS ports take a CONNECT without a scope to a middle proxy through the
// port's chain of scope "me", and an explicit scope through its own chain. A
// datacenter on the address of a middle proxy, at another port, takes the
// default chain.
func TestSocksPortsTellTheMiddleProxyByItsAddress(t *testing.T) {
	r, ds := bannerRouter(t)
	s := newPorts(t, r, socksOptions{allow: allowAll})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "proxy-1", "main", map[string]string{"me": "direct"})}); err != nil {
		t.Fatal(err)
	}
	me, err := ParseMEAddrs([]string{"203.0.113.7:8888", "[2001:db8::7]:8888", "149.154.175.50:8888"})
	if err != nil {
		t.Fatal(err)
	}
	r.SetMEAddrs(me)

	cases := []struct {
		scope, target, banner string
	}{
		{"", "203.0.113.7:8888", "direct-1|"},    // a middle proxy: scope me
		{"", "[2001:db8::7]:8888", "direct-1|"},  // over IPv6 too
		{"", "149.154.175.50:8888", "direct-1|"}, // a middle proxy on the address of DC1
		{"", "149.154.175.50:443", "main-1|"},    // DC1 itself: the default chain
		{"", "203.0.113.7:443", "main-1|"},       // another port of a middle proxy's address
		{"", "203.0.113.5:443", "main-1|"},       // anything else as well
		{"fetch", "203.0.113.7:8888", "main-1|"}, // the scope of the engine wins
		{"me", "203.0.113.5:443", "direct-1|"},
	}
	for _, tc := range cases {
		c := mustEngineDial(t, p, tc.scope, tc.target)
		if got := readBanner(t, c, len(tc.banner)); got != tc.banner {
			t.Errorf("scope %q, target %s: served by %q, want %q", tc.scope, tc.target, got, tc.banner)
		}
	}
	want := []string{"203.0.113.7:8888", "[2001:db8::7]:8888", "149.154.175.50:8888", "203.0.113.5:443"}
	if got := ds.get("direct-1").calls(); !slices.Equal(got, want) {
		t.Errorf("the chain of scope me was asked for %v, want %v", got, want)
	}

	// Without the addresses, a middle proxy is ordinary traffic again.
	r.SetMEAddrs(nil)
	c := mustEngineDial(t, p, "", "203.0.113.7:8888")
	if got := readBanner(t, c, 7); got != "main-1|" {
		t.Errorf("without the addresses: served by %q, want the default chain", got)
	}
}
