package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/netpolicy"
	"github.com/urbnywrt/postern/internal/socks5"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

func allowAll(netip.Addr) bool { return true }

// newPorts returns SocksPorts over r that are closed when the test ends.
func newPorts(t *testing.T, r *Router, o socksOptions) *SocksPorts {
	t.Helper()
	s := newSocksPorts(quiet, r, o)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sockPort(port uint32, proxy, defaultChain string, scopes map[string]string) *edgev1.SocksPort {
	return &edgev1.SocksPort{Port: port, ProxyId: proxy, DefaultChainId: defaultChain, ScopeChains: scopes}
}

// engineDial is what an engine does: it connects to the SOCKS port and asks for
// target, with scope as the user name.
func engineDial(port uint32, scope, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ioTimeout)
	defer cancel()
	return socks5.Dial(ctx, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), scope, "", target)
}

func mustEngineDial(t *testing.T, port uint32, scope, target string) net.Conn {
	t.Helper()
	c, err := engineDial(port, scope, target)
	if err != nil {
		t.Fatalf("SOCKS port %d, scope %q, target %s: %v", port, scope, target, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// refusedWith returns the code of the reply with which an engine was turned
// away, or fails the test when it was not.
func refusedWith(t *testing.T, err error) byte {
	t.Helper()
	var re *socks5.ReplyError
	if !errors.As(err, &re) {
		t.Fatalf("error %v, want a failure reply of the SOCKS server", err)
	}
	return re.Code
}

// bannerRouter returns a router with the chains "main" (default) and "direct",
// whose members answer with their own name as a banner, and the fake dialers
// behind them.
func bannerRouter(t *testing.T) (*Router, *dialers) {
	t.Helper()
	ds := newDialers("main-1", "main-2", "direct-1")
	for _, k := range []string{"main-1", "main-2", "direct-1"} {
		ds.get(k).fn = func(context.Context, string) (net.Conn, error) { return echoConn(k + "|"), nil }
	}
	r := newRouter(quiet, deps{newDialer: ds.factory(), clock: newFakeClock()})
	chains := []*edgev1.Chain{
		chainOf("main", mem("main-1", "direct"), mem("main-2", "direct")),
		chainOf("direct", mem("direct-1", "direct")),
	}
	if err := r.Apply(chains, nil); err != nil {
		t.Fatal(err)
	}
	return r, ds
}

// ---------------------------------------------------------------------------
// The destination policy
// ---------------------------------------------------------------------------

func TestDestinationAllowed(t *testing.T) {
	denied := []string{
		"127.0.0.1", "127.255.255.254", "::1",
		"10.1.2.3", "172.16.5.5", "172.31.255.254", "192.168.100.7", // RFC 1918
		"fd12:3456:789a::1", "fc00::1", // unique local
		"169.254.169.254", "169.254.0.1", "fe80::1", // link local, the metadata service of the clouds among them
		"0.0.0.0", "::", "0.1.2.3", // unspecified, and "this network"
		"100.64.0.1", "100.127.255.254", // shared address space of carrier-grade NAT
		"224.0.0.1", "239.255.255.250", "ff02::1", // multicast
		"255.255.255.255",
		"::ffff:127.0.0.1", "::ffff:10.1.2.3", "::ffff:0.0.0.0", "::ffff:169.254.169.254", // IPv4 in the form of IPv6
		"::7f00:1", "::a01:203", // IPv4-compatible (::a.b.c.d)
		"64:ff9b::7f00:1", "64:ff9b::a01:203", "64:ff9b::a9fe:a9fe", // NAT64, the well-known prefix
		"64:ff9b:1::7f00:1", "64:ff9b:1:abcd::c0a8:6407", "64:ff9b:1::cb00:7107", "64:ff9b:1:7f00:0:100::", // NAT64, the local-use prefix: refused as a whole
		"2002:7f00:1::1", "2002:a01:203::1", "2002:6440:1::", // 6to4
	}
	allowed := []string{
		"149.154.175.50", "149.154.167.51", "149.154.175.100", "149.154.167.91", "91.108.56.130", // the datacenters
		"192.0.2.1", "198.51.100.9", "203.0.113.7", "2001:db8::1", // addresses for documentation
		"::ffff:203.0.113.7", "::cb00:7107", "64:ff9b::cb00:7107", "2002:cb00:7107::1", // 203.0.113.7 embedded
	}
	for _, s := range denied {
		if destinationAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s is allowed, want it refused", s)
		}
	}
	for _, s := range allowed {
		if !destinationAllowed(netip.MustParseAddr(s)) {
			t.Errorf("%s is refused, want it allowed", s)
		}
	}
	if destinationAllowed(netip.Addr{}) {
		t.Error("the zero address is allowed")
	}
	if destinationAllowed(netip.MustParseAddr("fe80::1%eth0")) {
		t.Error("a link local address with a zone is allowed")
	}
}

// DestinationAllowed, which the edge applies to the addresses of a mask domain,
// is the policy of the ports.
func TestDestinationAllowedIsExported(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "::1", "10.0.0.1", "fd00::1", "169.254.169.254", "fe80::1", "100.64.0.1", "0.0.0.0",
		"224.0.0.1", "255.255.255.255", "::ffff:127.0.0.1", "203.0.113.7", "2001:db8::1", "::ffff:203.0.113.7",
	} {
		a := netip.MustParseAddr(s)
		if got, want := DestinationAllowed(a), destinationAllowed(a); got != want {
			t.Errorf("DestinationAllowed(%s) = %v, want %v", s, got, want)
		}
	}
	if DestinationAllowed(netip.Addr{}) {
		t.Error("the zero address is allowed")
	}
}

// TestDestinationAllowedAtTheEdgesOfTheRanges looks at the first and the last
// address of each refused range, and at the addresses next to them.
func TestDestinationAllowedAtTheEdgesOfTheRanges(t *testing.T) {
	ranges := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.168.0.0/16", "224.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	}
	var prefixes []netip.Prefix
	for _, s := range ranges {
		prefixes = append(prefixes, netip.MustParsePrefix(s))
	}
	inRanges := func(a netip.Addr) bool {
		for _, p := range prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, p := range prefixes {
		first := p.Masked().Addr()
		last := lastAddr(p)
		for _, a := range []netip.Addr{first, last} {
			if destinationAllowed(a) {
				t.Errorf("%s of %s is allowed", a, p)
			}
		}
		for _, a := range []netip.Addr{first.Prev(), last.Next()} {
			if !a.IsValid() || inRanges(a) {
				continue // the range next to another one that is refused
			}
			if v4, ok := netpolicy.EmbeddedIPv4(a); ok && a.Is6() {
				// An IPv6 address that carries an IPv4 address (::2 is
				// ::0.0.0.2) is judged as that address.
				if want := !inRanges(v4); destinationAllowed(a) != want {
					t.Errorf("%s, next to %s, carries %s: allowed = %v, want %v", a, p, v4, !want, want)
				}
				continue
			}
			if a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
				continue
			}
			if !destinationAllowed(a) {
				t.Errorf("%s, next to %s, is refused", a, p)
			}
		}
	}
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(a)*8; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	out, _ := netip.AddrFromSlice(a)
	return out
}

func TestLocalName(t *testing.T) {
	for _, name := range []string{"localhost", "LOCALHOST", "Localhost.", "foo.localhost", "a.b.LocalHost.", "x.localhost."} {
		if !localName(name) {
			t.Errorf("%q is not taken for a local name", name)
		}
	}
	for _, name := range []string{"example.com", "notlocalhost", "localhost.example", "localhostx.com", "local", "", "host"} {
		if localName(name) {
			t.Errorf("%q is taken for a local name", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Routing: the port is the proxy, the user name is the scope
// ---------------------------------------------------------------------------

func TestSocksPortsRouteByScope(t *testing.T) {
	r, ds := bannerRouter(t)
	s := newPorts(t, r, socksOptions{allow: allowAll})
	p1, p2 := freePort(t), freePort(t)
	err := s.Apply([]*edgev1.SocksPort{
		sockPort(p1, "proxy-1", "main", map[string]string{"me": "direct"}),
		sockPort(p2, "proxy-2", "direct", nil),
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		port   uint32
		scope  string
		banner string
	}{
		{p1, "me", "direct-1|"},     // an entry of the scopes
		{p1, "", "main-1|"},         // no user name: the default chain
		{p1, "fetch", "main-1|"},    // a scope that has no entry: the default chain
		{p1, "whatever", "main-1|"}, // any other user name as well
		{p2, "me", "direct-1|"},     // this port has no entry for me, and its default is direct
		{p2, "", "direct-1|"},
	}
	for _, tc := range cases {
		c := mustEngineDial(t, tc.port, tc.scope, "203.0.113.5:443")
		if got := readBanner(t, c, len(tc.banner)); got != tc.banner {
			t.Errorf("port %d scope %q: served by %q, want %q", tc.port, tc.scope, got, tc.banner)
		}
	}
	if got := ds.get("main-1").calls(); len(got) != 3 || got[0] != "203.0.113.5:443" {
		t.Errorf("main-1 was asked for %v, want the target of the engine three times", got)
	}
}

func TestSocksPortsEmptyScopeEntryFallsBackToTheDefault(t *testing.T) {
	r, _ := bannerRouter(t)
	s := newPorts(t, r, socksOptions{allow: allowAll})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "main", map[string]string{"me": ""})}); err != nil {
		t.Fatal(err)
	}
	c := mustEngineDial(t, p, "me", "203.0.113.5:443")
	if got := readBanner(t, c, 7); got != "main-1|" {
		t.Errorf("served by %q, want the default chain for an empty entry", got)
	}
}

func TestSocksPortsPassTheTargetOfTheEngineToTheChain(t *testing.T) {
	r, ds := bannerRouter(t)
	s := newPorts(t, r, socksOptions{allow: allowAll})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	targets := []string{"203.0.113.5:443", "example.com:8443", "[2001:db8::1]:443", "149.154.167.51:443"}
	for _, tg := range targets {
		c := mustEngineDial(t, p, "", tg)
		_ = readBanner(t, c, 7)
	}
	if got := ds.get("main-1").calls(); strings.Join(got, ",") != strings.Join(targets, ",") {
		t.Errorf("the chain was asked for %v, want %v", got, targets)
	}
}

func TestSocksPortsFallBackAlongTheChain(t *testing.T) {
	r, ds := bannerRouter(t)
	ds.get("main-1").fn = failing(opErr(syscall.ECONNREFUSED))
	s := newPorts(t, r, socksOptions{allow: allowAll})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	c := mustEngineDial(t, p, "", "203.0.113.5:443")
	if got := readBanner(t, c, 7); got != "main-2|" {
		t.Errorf("served by %q, want the second member", got)
	}
}

// ---------------------------------------------------------------------------
// What the engine is told when the chain fails
// ---------------------------------------------------------------------------

// attempt is the dial of one member of a chain in a test: its kind and what it
// fails with, nil for a member that is down.
type attempt struct {
	kind string
	err  error
}

func TestSocksPortsReplyToAFailedChain(t *testing.T) {
	notFound := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "nowhere.example", IsNotFound: true}}
	cases := []struct {
		name    string
		members []attempt
		want    byte
	}{
		// A SOCKS5 proxy that works and turned the target down: its reply goes on
		// to the engine as it came.
		{"general failure of the proxy", []attempt{{KindSOCKS5, &socks5.ReplyError{Code: 0x01}}}, 0x01},
		{"ruleset of the proxy", []attempt{{KindSOCKS5, &socks5.ReplyError{Code: 0x02}}}, 0x02},
		{"network unreachable through the proxy", []attempt{{KindSOCKS5, &socks5.ReplyError{Code: 0x03}}}, 0x03},
		{"host unreachable through the proxy", []attempt{{KindSOCKS5, &socks5.ReplyError{Code: 0x04}}}, 0x04},
		{"target refused through the proxy", []attempt{{KindSOCKS5, &socks5.ReplyError{Code: 0x05}}}, 0x05},
		{"ttl expired through the proxy", []attempt{{KindSOCKS5, &socks5.ReplyError{Code: 0x06}}}, 0x06},
		{"command not supported by the proxy", []attempt{{KindSOCKS5, &socks5.ReplyError{Code: 0x07}}}, 0x07},
		{"address type not supported by the proxy", []attempt{{KindSOCKS5, &socks5.ReplyError{Code: 0x08}}}, 0x08},
		{"a code that is not assigned", []attempt{{KindSOCKS5, &socks5.ReplyError{Code: 0x42}}}, 0x01},
		// A member that fails itself: the target is not to blame. A refused
		// connection to a proxy is not a refusal of the target.
		{"proxy that refuses connections", []attempt{{KindSOCKS5, opErr(syscall.ECONNREFUSED)}}, 0x01},
		{"proxy that is unreachable", []attempt{{KindSOCKS5, opErr(syscall.ENETUNREACH)}}, 0x01},
		{"proxy that does not answer in time", []attempt{{KindSOCKS5, context.DeadlineExceeded}}, 0x01},
		{"http proxy that refuses connections", []attempt{{KindHTTP, opErr(syscall.ECONNREFUSED)}}, 0x01},
		{"credentials of an http member", []attempt{{KindHTTP, &ConnectError{Status: 407}}}, 0x01},
		// An HTTP proxy that works and answered with a status.
		{"http proxy answers 502", []attempt{{KindHTTP, &ConnectError{Status: 502}}}, 0x01},
		{"http proxy answers 504", []attempt{{KindHTTP, &ConnectError{Status: 504}}}, 0x04},
		// A direct member connects to the target itself: what it meets is the
		// target's.
		{"target refused a direct member", []attempt{{KindDirect, opErr(syscall.ECONNREFUSED)}}, 0x05},
		{"target unreachable from a direct member", []attempt{{KindDirect, opErr(syscall.EHOSTUNREACH)}}, 0x04},
		{"network unreachable from a direct member", []attempt{{KindDirect, opErr(syscall.ENETUNREACH)}}, 0x04},
		{"target timed out for a direct member", []attempt{{KindDirect, context.DeadlineExceeded}}, 0x04},
		{"name of the target not found by a direct member", []attempt{{KindDirect, notFound}}, 0x04},
		{"anything else of a direct member", []attempt{{KindDirect, errors.New("boom")}}, 0x01},
		{"every member is down", []attempt{{KindDirect, nil}, {KindSOCKS5, nil}}, 0x01},
		// The first member that has something to say about the target says it.
		{"a proxy that is down, then a target that refuses", []attempt{
			{KindSOCKS5, opErr(syscall.ECONNREFUSED)}, {KindDirect, opErr(syscall.ECONNREFUSED)},
		}, 0x05},
		{"the ruleset of a proxy, then a target that refuses", []attempt{
			{KindSOCKS5, &socks5.ReplyError{Code: 0x02}}, {KindDirect, opErr(syscall.ECONNREFUSED)},
		}, 0x02},
		{"a target that refuses, then one unreachable through a proxy", []attempt{
			{KindDirect, opErr(syscall.ECONNREFUSED)}, {KindSOCKS5, &socks5.ReplyError{Code: 0x04}},
		}, 0x05},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ds := newDialers()
			sp := newScriptedProbe()
			var members []*edgev1.ChainMember
			for i, a := range tc.members {
				members = append(members, mem(fmt.Sprintf("m%d", i), a.kind))
			}
			r := newTestRouter(t, ds, sp, []*edgev1.Chain{chainOf("c", members...)}, nil)
			for i, a := range tc.members {
				key := fmt.Sprintf("m%d", i)
				if a.err == nil {
					bringDown(t, r, sp, key)
					continue
				}
				ds.get(key).fn = failing(a.err)
			}
			s := newPorts(t, r, socksOptions{allow: allowAll})
			p := freePort(t)
			if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "c", nil)}); err != nil {
				t.Fatal(err)
			}
			_, err := engineDial(p, "", "203.0.113.5:443")
			if got := refusedWith(t, err); got != tc.want {
				t.Errorf("the engine was refused with 0x%02x, want 0x%02x", got, tc.want)
			}
		})
	}
}

func TestSocksPortsReplyWhenThereIsNoChain(t *testing.T) {
	r, _ := bannerRouter(t)
	s := newPorts(t, r, socksOptions{allow: allowAll})
	p1, p2 := freePort(t), freePort(t)
	err := s.Apply([]*edgev1.SocksPort{
		sockPort(p1, "x", "", nil), // no default chain
		sockPort(p2, "y", "no-such-chain", map[string]string{"me": "main"}), // a chain that does not exist
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		port  uint32
		scope string
		ok    bool
	}{{p1, "", false}, {p1, "me", false}, {p2, "", false}, {p2, "fetch", false}, {p2, "me", true}} {
		c, err := engineDial(tc.port, tc.scope, "203.0.113.5:443")
		if tc.ok {
			if err != nil {
				t.Errorf("port %d scope %q: %v", tc.port, tc.scope, err)
			} else {
				_ = c.Close()
			}
			continue
		}
		if err == nil {
			_ = c.Close()
			t.Errorf("port %d scope %q: connected, want a refusal", tc.port, tc.scope)
			continue
		}
		if got := refusedWith(t, err); got != 0x01 {
			t.Errorf("port %d scope %q: refused with 0x%02x, want 0x01", tc.port, tc.scope, got)
		}
	}
}

func TestSocksPortsContainAPanicOfAMember(t *testing.T) {
	ds := newDialers("m")
	var calls atomic.Int32
	ds.get("m").fn = func(context.Context, string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			panic("a bug in a member")
		}
		return echoConn("ok|"), nil
	}
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("m", "direct"))}, nil)
	var lb logBuf
	s := newSocksPorts(lb.logger(), r, socksOptions{allow: allowAll})
	defer func() { _ = s.Close() }()
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "c", nil)}); err != nil {
		t.Fatal(err)
	}
	_, err := engineDial(p, "", "203.0.113.5:443")
	if got := refusedWith(t, err); got != 0x01 {
		t.Errorf("the engine was refused with 0x%02x, want 0x01", got)
	}
	c := mustEngineDial(t, p, "", "203.0.113.5:443")
	if got := readBanner(t, c, 3); got != "ok|" {
		t.Errorf("the port does not serve after the panic: %q", got)
	}
}

// panicOnMessage is a log handler that panics on the records whose message
// contains a given text. A log call is the one thing in the serving of a
// connection that the SOCKS server does not guard, so it stands for a bug there.
type panicOnMessage struct {
	slog.Handler
	text string
}

func (h panicOnMessage) Handle(ctx context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.text) {
		panic("a bug in the serving of a connection")
	}
	return h.Handler.Handle(ctx, r)
}

func (h panicOnMessage) WithAttrs(attrs []slog.Attr) slog.Handler {
	return panicOnMessage{Handler: h.Handler.WithAttrs(attrs), text: h.text}
}

func (h panicOnMessage) WithGroup(name string) slog.Handler {
	return panicOnMessage{Handler: h.Handler.WithGroup(name), text: h.text}
}

func TestSocksPortsContainAPanicInTheServingOfAConnection(t *testing.T) {
	var lb logBuf
	ds := newDialers("m")
	var fail atomic.Bool
	fail.Store(true)
	ds.get("m").fn = func(context.Context, string) (net.Conn, error) {
		if fail.Load() {
			return nil, opErr(syscall.ECONNREFUSED)
		}
		return echoConn("ok|"), nil
	}
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("m", "direct"))}, nil)
	logger := slog.New(panicOnMessage{Handler: lb.logger().Handler(), text: "cannot connect"})
	s := newSocksPorts(logger, r, socksOptions{allow: allowAll})
	defer func() { _ = s.Close() }()
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "c", nil)}); err != nil {
		t.Fatal(err)
	}

	// The log call of a failed connect panics. The connection is closed, the
	// panic is logged with its stack, and the process lives.
	if c, err := engineDial(p, "", "203.0.113.5:443"); err == nil {
		_ = c.Close()
		t.Fatal("connected through a chain that fails")
	}
	waitFor(t, func() bool { return len(find(lb.records(t), "ERROR", "panic")) == 1 }, "the log of the panic")
	rec := find(lb.records(t), "ERROR", "panic")[0]
	if !strings.Contains(fmt.Sprint(rec["stack"]), "goroutine") || !strings.Contains(fmt.Sprint(rec["panic"]), "a bug") {
		t.Errorf("the log of the panic lacks the panic or the stack: %v", rec)
	}

	// The port goes on serving.
	fail.Store(false)
	c := mustEngineDial(t, p, "", "203.0.113.5:443")
	if got := readBanner(t, c, 3); got != "ok|" {
		t.Errorf("the port does not serve after the panic: %q", got)
	}
}

// ---------------------------------------------------------------------------
// The tunnel
// ---------------------------------------------------------------------------

// startOneShot serves a TCP target that reads until the client stops sending,
// and then answers with the number of bytes it was sent and closes.
func startOneShot(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				n, _ := io.Copy(io.Discard, c)
				_, _ = fmt.Fprintf(c, "got %d bytes", n)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestSocksPortsRelayHalfClose(t *testing.T) {
	// A client that has said everything it had to say, and half-closes, still
	// gets the answer; that needs the half-close to get through the whole path,
	// which is why the connections of the relay are bare TCP connections.
	target := startOneShot(t)
	r := NewRouter(quiet)
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("d", "direct"))}, nil); err != nil {
		t.Fatal(err)
	}
	s := newPorts(t, r, socksOptions{allow: allowAll})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "c", nil)}); err != nil {
		t.Fatal(err)
	}
	c := mustEngineDial(t, p, "", target)
	tc, ok := c.(*net.TCPConn)
	if !ok {
		t.Fatalf("the connection of the engine is a %T, want *net.TCPConn", c)
	}
	if err := tc.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
	if _, err := tc.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(tc)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("got %d bytes", len(payload)); string(got) != want {
		t.Errorf("the target answered %q, want %q", got, want)
	}
}

func TestSocksPortsRelayBothWays(t *testing.T) {
	echo := startEcho(t)
	r := NewRouter(quiet)
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("d", "direct"))}, nil); err != nil {
		t.Fatal(err)
	}
	s := newPorts(t, r, socksOptions{allow: allowAll})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "c", nil)}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := engineDial(p, "me", echo)
			if err != nil {
				t.Errorf("connection %d: %v", i, err)
				return
			}
			defer func() { _ = c.Close() }()
			msg := strings.Repeat(fmt.Sprintf("%02d", i), 5000)
			_ = c.SetDeadline(time.Now().Add(ioTimeout))
			go func() { _, _ = c.Write([]byte(msg)) }()
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(c, got); err != nil || string(got) != msg {
				t.Errorf("connection %d: echo of %d bytes: %v", i, len(msg), err)
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// The destination policy at the port
// ---------------------------------------------------------------------------

func TestSocksPortsRefuseForbiddenDestinations(t *testing.T) {
	r, ds := bannerRouter(t)
	s := newPorts(t, r, socksOptions{}) // the policy that ships
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"127.0.0.1:25001", "127.1.2.3:80", "[::1]:25001",
		"10.1.2.3:443", "172.16.5.5:443", "192.168.100.7:443", "[fd12:3456:789a::1]:443",
		"169.254.169.254:80", "[fe80::1]:80",
		"0.0.0.0:80", "[::]:80",
		"100.64.0.1:443", "224.0.0.1:80",
		"[::ffff:127.0.0.1]:80", "[::ffff:10.1.2.3]:80",
		"localhost:25001", "LOCALHOST:80", "foo.localhost:80", "localhost.:80",
	} {
		for _, scope := range []string{"", "me", "fetch"} {
			_, err := engineDial(p, scope, target)
			if got := refusedWith(t, err); got != 0x02 {
				t.Errorf("%s (scope %q): refused with 0x%02x, want 0x02 (not allowed by ruleset)", target, scope, got)
			}
		}
	}
	for _, k := range []string{"main-1", "main-2", "direct-1"} {
		if got := ds.get(k).calls(); len(got) != 0 {
			t.Errorf("%s was asked for %v: a destination that is refused must not reach a member", k, got)
		}
	}
}

func TestSocksPortsLetThroughWhatThePolicyAllows(t *testing.T) {
	r, ds := bannerRouter(t)
	s := newPorts(t, r, socksOptions{})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	targets := []string{
		"149.154.175.50:443", "149.154.167.51:443", "91.108.56.130:443", // the datacenters
		"203.0.113.7:443", "198.51.100.9:80", "192.0.2.1:8443", "[2001:db8::1]:443", // addresses for documentation
		"example.com:443", "core.example:443", "a.b.c.example:8443", // names are for the member to resolve
		"notlocalhost:443", "localhost.example:443",
	}
	for _, tg := range targets {
		c := mustEngineDial(t, p, "", tg)
		if got := readBanner(t, c, 7); got != "main-1|" {
			t.Errorf("%s: served by %q", tg, got)
		}
	}
	if got := ds.get("main-1").calls(); strings.Join(got, ",") != strings.Join(targets, ",") {
		t.Errorf("the chain was asked for %v, want %v", got, targets)
	}
}

func TestSocksPortsRefusalIsOnTheWire(t *testing.T) {
	r, _ := bannerRouter(t)
	s := newPorts(t, r, socksOptions{})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(p)), ioTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(ioTimeout))
	send := func(b ...byte) {
		t.Helper()
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	expect := func(want ...byte) {
		t.Helper()
		got := make([]byte, len(want))
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("read % x (%v), want % x", got, err, want)
		}
	}
	send(0x05, 0x01, 0x02)                                // greeting: user name and password
	expect(0x05, 0x02)                                    //
	send(0x01, 0x02, 'm', 'e', 0x01, 'x')                 // user "me", password "x"
	expect(0x01, 0x00)                                    //
	send(0x05, 0x01, 0x00, 0x01, 10, 1, 2, 3, 0x01, 0xbb) // CONNECT 10.1.2.3:443
	expect(0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0)      // not allowed by ruleset
	// And that is all: the connection is closed, with nothing else sent.
	if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("after the refusal: read %d bytes, error %v, want the end of the stream", n, err)
	}
}

func TestSocksPortsPutThePolicyInTheContextOfTheDial(t *testing.T) {
	// The members check what a name resolves to against the policy that the
	// context of the dial carries. The port is what puts it there.
	probe := func(t *testing.T, o socksOptions) (loopback, public bool) {
		t.Helper()
		ds := newDialers("m")
		got := make(chan func(netip.Addr) bool, 1)
		ds.get("m").fn = func(ctx context.Context, _ string) (net.Conn, error) {
			got <- policyOf(ctx)
			return sinkConn(), nil
		}
		r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("m", "direct"))}, nil)
		s := newPorts(t, r, o)
		p := freePort(t)
		if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "c", nil)}); err != nil {
			t.Fatal(err)
		}
		c := mustEngineDial(t, p, "", "example.com:443")
		_ = c.Close()
		f := <-got
		if f == nil {
			t.Fatal("the dial has no policy in its context")
		}
		return f(netip.MustParseAddr("127.0.0.1")), f(netip.MustParseAddr("203.0.113.7"))
	}
	if loopback, public := probe(t, socksOptions{}); loopback || !public {
		t.Errorf("the policy that ships: loopback allowed %v, a public address allowed %v", loopback, public)
	}
	if loopback, public := probe(t, socksOptions{allow: allowAll}); !loopback || !public {
		t.Errorf("the policy of the test: loopback allowed %v, a public address allowed %v", loopback, public)
	}
}

func TestSocksPortsRefuseWhenAMemberFindsTheDestinationNotAllowed(t *testing.T) {
	// A name that the policy lets through, and that a direct member finds to be a
	// loopback address when it resolves it, is refused as the literal is, and the
	// members after it are not asked: the destination is the same for them.
	ds := newDialers("m", "next")
	ds.get("m").fn = failing(fmt.Errorf("dial tcp: %w", ErrDestinationNotAllowed))
	r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("m", "direct"), mem("next", "direct"))}, nil)
	s := newPorts(t, r, socksOptions{})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "c", nil)}); err != nil {
		t.Fatal(err)
	}
	_, err := engineDial(p, "", "rebinding.example:25001")
	if got := refusedWith(t, err); got != 0x02 {
		t.Errorf("refused with 0x%02x, want 0x02 (not allowed by ruleset)", got)
	}
	if got := ds.get("next").calls(); len(got) != 0 {
		t.Errorf("the next member was asked for %v after the destination was refused", got)
	}
}

// ---------------------------------------------------------------------------
// Apply and Close
// ---------------------------------------------------------------------------

// closedPort reports whether a connection to the port of the loopback interface
// is refused.
func closedPort(port uint32) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), time.Second)
	if err != nil {
		return errors.Is(err, syscall.ECONNREFUSED)
	}
	_ = c.Close()
	return false
}

func TestSocksPortsApplyAddsAndRemovesPorts(t *testing.T) {
	r, _ := bannerRouter(t)
	s := newPorts(t, r, socksOptions{allow: allowAll})
	p1, p2, p3 := freePort(t), freePort(t), freePort(t)

	if err := s.Apply([]*edgev1.SocksPort{sockPort(p1, "a", "main", nil), sockPort(p2, "b", "direct", nil)}); err != nil {
		t.Fatal(err)
	}
	for port, banner := range map[uint32]string{p1: "main-1|", p2: "direct-1|"} {
		c := mustEngineDial(t, port, "", "203.0.113.5:443")
		if got := readBanner(t, c, len(banner)); got != banner {
			t.Errorf("port %d: %q, want %q", port, got, banner)
		}
	}

	// A connection that is open on p2 while p2 goes away, and p3 comes.
	open := mustEngineDial(t, p2, "", "203.0.113.5:443")
	_ = readBanner(t, open, 9)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p1, "a", "main", nil), sockPort(p3, "c", "direct", nil)}); err != nil {
		t.Fatal(err)
	}
	if !closedPort(p2) {
		t.Errorf("port %d still accepts connections after it was removed", p2)
	}
	if got := roundTrip(t, open, "still here"); got != "still here" {
		t.Errorf("the connection that was open when its port was removed: %q", got)
	}
	for _, port := range []uint32{p1, p3} {
		c := mustEngineDial(t, port, "", "203.0.113.5:443")
		_ = readBanner(t, c, 7)
	}

	// An empty configuration closes everything, and ports can come back.
	if err := s.Apply(nil); err != nil {
		t.Fatal(err)
	}
	for _, port := range []uint32{p1, p2, p3} {
		if !closedPort(port) {
			t.Errorf("port %d still accepts connections after an empty Apply", port)
		}
	}
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p2, "b", "direct", nil)}); err != nil {
		t.Fatal(err)
	}
	c := mustEngineDial(t, p2, "", "203.0.113.5:443")
	_ = readBanner(t, c, 9)
}

func TestSocksPortsApplyKeepsTheListenerOfAPortThatStays(t *testing.T) {
	var opened atomic.Int32
	s := newSocksPorts(quiet, NewRouter(quiet), socksOptions{
		allow: allowAll,
		listen: func(addr string) (net.Listener, error) {
			opened.Add(1)
			return listenReusePort(addr)
		},
	})
	defer func() { _ = s.Close() }()
	p := freePort(t)
	for range 3 {
		if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "a", "x", nil)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := opened.Load(); got != 1 {
		t.Errorf("the port was bound %d times for 3 Apply calls with the same port, want 1", got)
	}
}

func TestSocksPortsApplyChangesAPortInPlace(t *testing.T) {
	r, _ := bannerRouter(t)
	s := newPorts(t, r, socksOptions{allow: allowAll})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "a", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	old := mustEngineDial(t, p, "me", "203.0.113.5:443")
	if got := readBanner(t, old, 7); got != "main-1|" {
		t.Fatalf("before: %q", got)
	}

	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "a", "direct", map[string]string{"me": "main"})}); err != nil {
		t.Fatal(err)
	}
	// New connections follow the new configuration, and the open one is not touched.
	for scope, want := range map[string]string{"": "direct-1|", "me": "main-1|"} {
		c := mustEngineDial(t, p, scope, "203.0.113.5:443")
		if got := readBanner(t, c, len(want)); got != want {
			t.Errorf("scope %q after the change: %q, want %q", scope, got, want)
		}
	}
	if got := roundTrip(t, old, "still the old"); got != "still the old" {
		t.Errorf("the open connection: %q", got)
	}
}

func TestSocksPortsApplyValidation(t *testing.T) {
	r, _ := bannerRouter(t)
	s := newPorts(t, r, socksOptions{allow: allowAll})
	keep := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(keep, "a", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	fresh := freePort(t)
	cases := []struct {
		name  string
		ports []*edgev1.SocksPort
	}{
		{"port 0", []*edgev1.SocksPort{sockPort(fresh, "a", "main", nil), sockPort(0, "b", "main", nil)}},
		{"port out of range", []*edgev1.SocksPort{sockPort(fresh, "a", "main", nil), sockPort(70000, "b", "main", nil)}},
		{"the same port twice", []*edgev1.SocksPort{sockPort(fresh, "a", "main", nil), sockPort(fresh, "b", "main", nil)}},
		{"nil port", []*edgev1.SocksPort{sockPort(fresh, "a", "main", nil), nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Apply(tc.ports); err == nil {
				t.Fatal("Apply succeeded")
			}
			// Nothing was opened or closed by the call that failed.
			if !closedPort(fresh) {
				t.Errorf("port %d was opened by an Apply that failed", fresh)
			}
			c := mustEngineDial(t, keep, "", "203.0.113.5:443")
			if got := readBanner(t, c, 7); got != "main-1|" {
				t.Errorf("the port that was there: %q", got)
			}
		})
	}
}

// threePorts returns two free loopback ports and a third that a socket which does
// not share its port occupies, so that SO_REUSEPORT cannot bind it. The ports of an
// Apply are bound in order, and what a failure has to undo depends on which of them
// failed, so the occupied one is the highest of the three when busyIsHighest is
// true, and the lowest when it is false.
func threePorts(t *testing.T, busyIsHighest bool) (keep, fresh uint32, blocker net.Listener, busy uint32) {
	t.Helper()
	var lns []net.Listener
	for range 3 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
	}
	slices.SortFunc(lns, func(a, b net.Listener) int {
		return a.Addr().(*net.TCPAddr).Port - b.Addr().(*net.TCPAddr).Port
	})
	i := 0
	if busyIsHighest {
		i = 2
	}
	blocker = lns[i]
	t.Cleanup(func() { _ = blocker.Close() })
	var free []uint32
	for j, ln := range lns {
		if j == i {
			continue
		}
		free = append(free, uint32(ln.Addr().(*net.TCPAddr).Port))
		_ = ln.Close()
	}
	return free[0], free[1], blocker, uint32(blocker.Addr().(*net.TCPAddr).Port)
}

func TestSocksPortsApplyBindFailureKeepsThePreviousPorts(t *testing.T) {
	for _, tc := range []struct {
		name          string
		busyIsHighest bool // the port that cannot be bound comes after the one that can
	}{
		{"the failing port is bound after the new one", true},
		{"the failing port is bound before the new one", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := bannerRouter(t)
			s := newPorts(t, r, socksOptions{allow: allowAll})
			keep, fresh, blocker, busy := threePorts(t, tc.busyIsHighest)
			if err := s.Apply([]*edgev1.SocksPort{sockPort(keep, "a", "main", nil)}); err != nil {
				t.Fatal(err)
			}

			err := s.Apply([]*edgev1.SocksPort{
				sockPort(keep, "a", "direct", nil), // a change of the port that stays
				sockPort(fresh, "b", "main", nil),  // a port that opens
				sockPort(busy, "c", "main", nil),   // a port that cannot
			})
			if err == nil {
				t.Fatal("Apply succeeded with a port that is taken")
			}
			if !strings.Contains(err.Error(), fmt.Sprint(busy)) {
				t.Errorf("error %q does not name the port", err)
			}
			if !closedPort(fresh) {
				t.Errorf("port %d was left open by an Apply that failed", fresh)
			}
			// The port that was there is as it was, and the change of its chain did not
			// happen either.
			c := mustEngineDial(t, keep, "", "203.0.113.5:443")
			if got := readBanner(t, c, 7); got != "main-1|" {
				t.Errorf("the port that was there serves %q, want main-1|", got)
			}
			// And the same Apply goes through once the way is clear.
			_ = blocker.Close()
			if err := s.Apply([]*edgev1.SocksPort{sockPort(keep, "a", "direct", nil), sockPort(fresh, "b", "main", nil)}); err != nil {
				t.Fatal(err)
			}
			c2 := mustEngineDial(t, keep, "", "203.0.113.5:443")
			if got := readBanner(t, c2, 9); got != "direct-1|" {
				t.Errorf("after the second Apply: %q", got)
			}
		})
	}
}

func TestSocksPortsListenOnTheLoopbackOnly(t *testing.T) {
	r, _ := bannerRouter(t)
	s := NewSocksPorts(quiet, r)
	defer func() { _ = s.Close() }()
	p1, p2 := freePort(t), freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p1, "a", "main", nil), sockPort(p2, "b", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	got := s.addrs()
	want := []string{fmt.Sprintf("127.0.0.1:%d", p1), fmt.Sprintf("127.0.0.1:%d", p2)}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("bound %v, want %v", got, want)
	}
}

func TestSocksPortsOfTwoGenerationsShareAPort(t *testing.T) {
	if !reusePort {
		t.Skip("SO_REUSEPORT is not available on this platform")
	}
	// The new generation of the edge takes the port of the old one over while the
	// old one still serves, and then the old one goes away.
	gen := func(name string) *SocksPorts {
		ds := newDialers("m")
		ds.get("m").fn = func(context.Context, string) (net.Conn, error) { return echoConn(name + "|"), nil }
		r := newTestRouter(t, ds, newScriptedProbe(), []*edgev1.Chain{chainOf("c", mem("m", "direct"))}, nil)
		return newPorts(t, r, socksOptions{allow: allowAll})
	}
	g1, g2 := gen("gen1"), gen("gen2")
	p := freePort(t)
	for i, s := range []*SocksPorts{g1, g2} {
		if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "c", nil)}); err != nil {
			t.Fatalf("generation %d cannot bind the port of the other: %v", i+1, err)
		}
	}
	seen := map[string]int{}
	for range 64 {
		c := mustEngineDial(t, p, "", "203.0.113.5:443")
		seen[readBanner(t, c, 5)]++
		_ = c.Close()
	}
	if seen["gen1|"] == 0 || seen["gen2|"] == 0 {
		t.Errorf("connections were served by %v: both generations must take their share", seen)
	}

	// The old generation closes its port; the new one serves on.
	if err := g1.Close(); err != nil {
		t.Fatal(err)
	}
	for range 16 {
		c := mustEngineDial(t, p, "", "203.0.113.5:443")
		if got := readBanner(t, c, 5); got != "gen2|" {
			t.Fatalf("served by %q after the old generation closed its port, want gen2|", got)
		}
		_ = c.Close()
	}
}

func TestSocksPortsCloseStopsAcceptingAndLeavesTheTunnelsAlone(t *testing.T) {
	r, _ := bannerRouter(t)
	s := newPorts(t, r, socksOptions{allow: allowAll})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "a", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	open := mustEngineDial(t, p, "", "203.0.113.5:443")
	_ = readBanner(t, open, 7)

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !closedPort(p) {
		t.Error("the port accepts connections after Close")
	}
	// A tunnel that is up when the edge drains goes on to its end.
	if got := roundTrip(t, open, "after close"); got != "after close" {
		t.Errorf("the tunnel that was open at Close: %q", got)
	}
	if err := s.Close(); err != nil {
		t.Errorf("the second Close: %v", err)
	}
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "a", "main", nil)}); !errors.Is(err, ErrClosed) {
		t.Errorf("Apply after Close: error %v, want ErrClosed", err)
	}
	if !closedPort(p) {
		t.Error("Apply after Close opened a port")
	}
}

func TestSocksPortsCloseWithoutApply(t *testing.T) {
	s := NewSocksPorts(quiet, NewRouter(quiet))
	if err := s.Close(); err != nil {
		t.Error(err)
	}
	if err := s.Close(); err != nil {
		t.Error(err)
	}
}

// fakeListener is a listener whose Accept fails with the errors it is given
// before it takes the connections of the real one.
type fakeListener struct {
	net.Listener
	mu   sync.Mutex
	errs []error
}

func (l *fakeListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

func TestSocksPortsAcceptSurvivesTransientErrors(t *testing.T) {
	r, _ := bannerRouter(t)
	s := newSocksPorts(quiet, r, socksOptions{
		allow: allowAll,
		listen: func(addr string) (net.Listener, error) {
			ln, err := listenReusePort(addr)
			if err != nil {
				return nil, err
			}
			return &fakeListener{Listener: ln, errs: []error{
				&net.OpError{Op: "accept", Err: syscall.EMFILE},
				&net.OpError{Op: "accept", Err: syscall.ECONNABORTED},
				&net.OpError{Op: "accept", Err: syscall.ENFILE},
			}}, nil
		},
	})
	defer func() { _ = s.Close() }()
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "a", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	c := mustEngineDial(t, p, "", "203.0.113.5:443")
	if got := readBanner(t, c, 7); got != "main-1|" {
		t.Errorf("served by %q after the transient errors", got)
	}
}

func TestSocksPortsAFailedPortIsOpenedAgainByTheNextApply(t *testing.T) {
	r, _ := bannerRouter(t)
	var mu sync.Mutex
	var opened []*fakeListener
	s := newSocksPorts(quiet, r, socksOptions{
		allow: allowAll,
		listen: func(addr string) (net.Listener, error) {
			ln, err := listenReusePort(addr)
			if err != nil {
				return nil, err
			}
			fl := &fakeListener{Listener: ln}
			mu.Lock()
			defer mu.Unlock()
			if len(opened) == 0 {
				fl.errs = []error{errors.New("a failure that does not pass")}
			}
			opened = append(opened, fl)
			return fl, nil
		},
	})
	defer func() { _ = s.Close() }()
	p := freePort(t)
	cfg := []*edgev1.SocksPort{sockPort(p, "a", "main", nil)}
	if err := s.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	// The accept loop gives up on a failure that does not pass, and closes the
	// listener, so that the engines are not left to hang on a port that nobody
	// serves.
	waitFor(t, func() bool { return closedPort(p) }, "the port of the failed accept loop to be closed")
	if err := s.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := len(opened)
	mu.Unlock()
	if n != 2 {
		t.Errorf("the port was bound %d times, want again after the failure", n)
	}
	c := mustEngineDial(t, p, "", "203.0.113.5:443")
	if got := readBanner(t, c, 7); got != "main-1|" {
		t.Errorf("served by %q", got)
	}
}

// ---------------------------------------------------------------------------
// Logs, leaks
// ---------------------------------------------------------------------------

func TestSocksPortsLogNothingSecret(t *testing.T) {
	var lb logBuf
	ds := newDialers("m")
	ds.get("m").fn = failing(opErr(syscall.ECONNREFUSED))
	member := &edgev1.ChainMember{Key: "m", Kind: "socks5", Addr: "127.0.0.1:1", Username: "member-user", Password: "member-secret"}
	r := newRouter(lb.logger(), deps{newDialer: ds.factory(), clock: newFakeClock()})
	if err := r.Apply([]*edgev1.Chain{chainOf("c", member)}, nil); err != nil {
		t.Fatal(err)
	}
	s := newSocksPorts(lb.logger(), r, socksOptions{})
	defer func() { _ = s.Close() }()
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "a", "c", nil)}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), ioTimeout)
	defer cancel()
	// The engine presents a password, as telemt may; the server must drop it.
	for _, target := range []string{"203.0.113.5:443", "10.1.2.3:443"} {
		_, _ = socks5.Dial(ctx, net.JoinHostPort("127.0.0.1", fmt.Sprint(p)), "me", "engine-secret", target)
	}
	time.Sleep(50 * time.Millisecond)
	for _, secret := range []string{"member-secret", "member-user", "engine-secret"} {
		if strings.Contains(lb.String(), secret) {
			t.Errorf("the log carries %q:\n%s", secret, lb.String())
		}
	}
	if lb.String() == "" {
		t.Error("nothing was logged at all: the test checks nothing")
	}
}

func TestFailedDialsAreLoggedAtDebug(t *testing.T) {
	// Every connection of an engine that fails would fill the log if it were
	// logged above debug, and a member that is down fails them all. What the
	// operator is told is that the member went down, once.
	var lb logBuf
	ds := newDialers("m")
	ds.get("m").fn = failing(opErr(syscall.ECONNREFUSED))
	r := newRouter(lb.logger(), deps{newDialer: ds.factory(), clock: newFakeClock()})
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("m", "direct"))}, nil); err != nil {
		t.Fatal(err)
	}
	s := newSocksPorts(lb.logger(), r, socksOptions{allow: allowAll})
	defer func() { _ = s.Close() }()
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "c", nil)}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_, _, _ = r.Dial(context.Background(), "c", target)
		_, _ = engineDial(p, "me", target)
	}
	time.Sleep(50 * time.Millisecond)

	var debug []string
	for _, rec := range lb.records(t) {
		switch rec["level"] {
		case "DEBUG":
			debug = append(debug, rec["msg"].(string))
		case "INFO":
			// The opening of the port.
			if !strings.Contains(rec["msg"].(string), "port") {
				t.Errorf("a message at info: %v", rec)
			}
		default:
			t.Errorf("a failed dial was logged above debug: %v", rec)
		}
	}
	var viaRouter, viaPort int
	for _, msg := range debug {
		switch {
		case strings.Contains(msg, "member"):
			viaRouter++
		case strings.Contains(msg, "cannot connect"):
			viaPort++
		}
	}
	if viaRouter < 6 || viaPort != 3 {
		t.Errorf("debug messages: %d about members, %d from the SOCKS server, want at least 6 and 3: %q", viaRouter, viaPort, debug)
	}
}

func TestPolicyRefusalsAreLoggedAtWarn(t *testing.T) {
	// A destination that is refused is not a failure of the chain: an engine that
	// asks for the loopback interface of the node is worth the attention of whoever
	// reads the log.
	var lb logBuf
	r, _ := bannerRouter(t)
	s := newSocksPorts(lb.logger(), r, socksOptions{})
	defer func() { _ = s.Close() }()
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "proxy-7", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	_, _ = engineDial(p, "fetch", "127.0.0.1:25001")
	waitFor(t, func() bool { return len(find(lb.records(t), "WARN", "refused")) == 1 }, "the warning about the refusal")
	rec := find(lb.records(t), "WARN", "refused")[0]
	if rec["proxy"] != "proxy-7" || rec["scope"] != "fetch" || rec["target"] != "127.0.0.1:25001" {
		t.Errorf("the warning: %v", rec)
	}
}

// settledGoroutines returns the number of goroutines once it has stopped
// changing: the goroutines of earlier tests take a moment to end.
func settledGoroutines() int {
	n := runtime.NumGoroutine()
	for stable, deadline := 0, time.Now().Add(2*time.Second); stable < 5 && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
		if m := runtime.NumGoroutine(); m == n {
			stable++
		} else {
			n, stable = m, 0
		}
	}
	return n
}

func TestNoGoroutineLeak(t *testing.T) {
	// The servers of the test are part of the baseline: they run until it ends.
	echo := startEcho(t)
	dc := startFakeDC(t, dcAnswers, nil)
	exit := startEchoHTTP(t, answer(200, "203.0.113.7"))
	before := settledGoroutines()

	r := NewRouter(quiet)
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("d", "direct"), mem("dead", "socks5"))}, nil); err == nil {
		t.Fatal("a socks5 member without an address was accepted")
	}
	hc := &edgev1.HealthCheck{TimeoutSeconds: 2, IntervalSeconds: 1, DcAddrs: []string{dc.Addr()}, EchoUrls: []string{exit.url()}}
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("d", "direct"))}, hc); err != nil {
		t.Fatal(err)
	}
	s := newSocksPorts(quiet, r, socksOptions{allow: allowAll})
	p1, p2 := freePort(t), freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p1, "a", "c", nil), sockPort(p2, "b", "c", nil)}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		if err := r.RunHealth(ctx); err != nil {
			t.Errorf("RunHealth: %v", err)
		}
		close(done)
	}()
	for _, p := range []uint32{p1, p2} {
		for range 5 {
			c, err := engineDial(p, "me", echo)
			if err != nil {
				t.Fatal(err)
			}
			_ = roundTrip(t, c, "ping")
			_ = c.Close()
		}
	}
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p1, "a", "c", nil)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return r.Health()[0].GetExitIp() == "203.0.113.7" }, "the health loop to learn the exit ip")
	cancel()
	<-done
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	exit.CloseClientConnections()

	waitFor(t, func() bool { return runtime.NumGoroutine() <= before }, "the goroutines to return to %d (now %d)", before, runtime.NumGoroutine())
}

// panickyListener is a listener whose Accept panics, once.
type panickyListener struct {
	net.Listener
	panicked atomic.Bool
}

func (l *panickyListener) Accept() (net.Conn, error) {
	if l.panicked.CompareAndSwap(false, true) {
		panic("a bug in Accept")
	}
	return l.Listener.Accept()
}

func TestSocksPortsContainAPanicOfTheAcceptLoop(t *testing.T) {
	var lb logBuf
	r, _ := bannerRouter(t)
	var opened atomic.Int32
	s := newSocksPorts(lb.logger(), r, socksOptions{
		allow: allowAll,
		listen: func(addr string) (net.Listener, error) {
			ln, err := listenReusePort(addr)
			if err != nil {
				return nil, err
			}
			if opened.Add(1) == 1 {
				return &panickyListener{Listener: ln}, nil
			}
			return ln, nil
		},
	})
	defer func() { _ = s.Close() }()
	p := freePort(t)
	cfg := []*edgev1.SocksPort{sockPort(p, "a", "main", nil)}
	if err := s.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	// The panic is logged with its stack, and the port is closed: an engine is
	// refused and does not wait on a port that nobody serves.
	waitFor(t, func() bool { return len(find(lb.records(t), "ERROR", "accept loop")) == 1 }, "the log of the panic")
	rec := find(lb.records(t), "ERROR", "accept loop")[0]
	if !strings.Contains(fmt.Sprint(rec["stack"]), "goroutine") || rec["port"] != float64(p) {
		t.Errorf("the log of the panic: %v", rec)
	}
	waitFor(t, func() bool { return closedPort(p) }, "the port to be closed")
	if err := s.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	c := mustEngineDial(t, p, "", "203.0.113.5:443")
	if got := readBanner(t, c, 7); got != "main-1|" {
		t.Errorf("served by %q after the port was bound again", got)
	}
}

func TestSocksPortsWithoutARouterRefuseEverything(t *testing.T) {
	s := newSocksPorts(quiet, nil, socksOptions{allow: allowAll})
	defer func() { _ = s.Close() }()
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "a", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	_, err := engineDial(p, "", "203.0.113.5:443")
	if got := refusedWith(t, err); got != 0x01 {
		t.Errorf("refused with 0x%02x, want 0x01", got)
	}
}

func TestDefaultLoggersAreUsedWhenNoneIsGiven(t *testing.T) {
	r := NewRouter(nil)
	s := NewSocksPorts(nil, r)
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("d", "direct"))}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// slowListener is a listener whose Accept does not return for a while after the
// listener is closed, and says when it has.
type slowListener struct {
	net.Listener
	exited atomic.Bool
}

func (l *slowListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		time.Sleep(50 * time.Millisecond)
		l.exited.Store(true)
	}
	return c, err
}

func TestSocksPortsCloseWaitsForTheAcceptLoops(t *testing.T) {
	r, _ := bannerRouter(t)
	var sl *slowListener
	s := newSocksPorts(quiet, r, socksOptions{
		allow: allowAll,
		listen: func(addr string) (net.Listener, error) {
			ln, err := listenReusePort(addr)
			if err != nil {
				return nil, err
			}
			sl = &slowListener{Listener: ln}
			return sl, nil
		},
	})
	if err := s.Apply([]*edgev1.SocksPort{sockPort(freePort(t), "a", "main", nil)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !sl.exited.Load() {
		t.Error("Close returned while the accept loop was still running")
	}
}
