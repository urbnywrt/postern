package edge

import (
	"net/netip"
	"testing"
	"time"
)

func TestCIDRSet(t *testing.T) {
	set, err := parseCIDRs([]string{
		"192.0.2.0/25",            // .0 to .127
		"198.51.100.7",            // a bare address is a host prefix
		"198.51.100.77/30",        // host bits set: the prefix is .76 to .79
		"2001:db8:1::/48",         //
		"::ffff:203.0.113.64/122", // an IPv4-mapped prefix is the IPv4 prefix: .64 to .127
		"2001:db8:2::5",           //
	})
	if err != nil {
		t.Fatalf("parseCIDRs: %v", err)
	}
	tests := []struct {
		addr string
		want bool
	}{
		{"192.0.2.1", true},
		{"192.0.2.127", true},
		{"192.0.2.128", false},
		{"::ffff:192.0.2.9", true}, // IPv4-mapped client address
		{"198.51.100.7", true},
		{"198.51.100.8", false},
		{"::ffff:198.51.100.7", true},
		{"198.51.100.75", false},
		{"198.51.100.76", true},
		{"198.51.100.79", true},
		{"198.51.100.80", false},
		{"2001:db8:1:abcd::1", true},
		{"2001:db8:1::1%eth0", true}, // a zone does not matter
		{"2001:db8:2::5", true},
		{"2001:db8:2::6", false},
		{"203.0.113.77", true},
		{"::ffff:203.0.113.77", true},
		{"203.0.113.63", false},
		{"203.0.113.128", false},
		{"2001:db8:3::1", false},
		{"127.0.0.1", false},
		{"::1", false},
	}
	for _, tt := range tests {
		if got := set.contains(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("contains(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
	if set.contains(netip.Addr{}) {
		t.Error("contains(invalid address) = true")
	}

	all4, err := parseCIDRs([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("parseCIDRs: %v", err)
	}
	if !all4.contains(netip.MustParseAddr("203.0.113.1")) || !all4.contains(netip.MustParseAddr("::ffff:192.0.2.1")) {
		t.Error("0.0.0.0/0 does not hold every IPv4 address")
	}
	if all4.contains(netip.MustParseAddr("2001:db8::1")) {
		t.Error("0.0.0.0/0 holds an IPv6 address")
	}

	var empty cidrSet
	if empty.contains(netip.MustParseAddr("192.0.2.1")) {
		t.Error("the empty set holds an address")
	}
}

func TestParseCIDRsRejects(t *testing.T) {
	for _, s := range []string{"", "192.0.2.0/33", "192.0.2.256", "example.com", "2001:db8::/129", "192.0.2.0/24 ", "2001:db8::1%eth0/64"} {
		if _, err := parseCIDRs([]string{"192.0.2.0/24", s}); err == nil {
			t.Errorf("parseCIDRs accepted %q", s)
		}
	}
}

func TestBlacklistDropsBeforeRead(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	// A client that sends nothing is given up on after 3 s by default; a
	// blacklisted one is closed at once.
	e := newTestEdge(t, Options{ClientHelloTimeout: 3 * time.Second})
	cfg := oneRoute(1, port, "reject", "proxy.example.com", be.addr)
	cfg.BlacklistCidrs = []string{"127.0.0.2/32", "127.0.0.64/26"}
	mustApply(t, e, cfg)

	for _, from := range []string{"127.0.0.2", "127.0.0.100"} {
		start := time.Now()
		c := dialEdge(t, from, loopback(port))
		expectClosed(t, c, time.Second)
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("%s: closed after %v; a blacklisted client is to be closed at once", from, d)
		}

		// A blacklisted client that sends a hello does not reach the backend.
		c = dialEdge(t, from, loopback(port))
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = c.Write(helloRecord("proxy.example.com"))
		expectClosed(t, c, time.Second)
	}
	be.expectNone(t, 200*time.Millisecond)

	// Other clients are served.
	openRelay(t, "127.0.0.3", loopback(port), "proxy.example.com", be)

	// The blacklist is part of the configuration: a new one applies at once.
	cfg = oneRoute(2, port, "reject", "proxy.example.com", be.addr)
	cfg.BlacklistCidrs = []string{"127.0.0.3"}
	mustApply(t, e, cfg)
	expectClosed(t, dialEdge(t, "127.0.0.3", loopback(port)), time.Second)
	openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)

	// Blacklisted connections are not counted for any proxy.
	if p := proxyCounters(e.Snapshot(true), "p1"); p.GetConnsTotal() != 2 {
		t.Errorf("conns_total %d, want 2 (the two relays)", p.GetConnsTotal())
	}
}
