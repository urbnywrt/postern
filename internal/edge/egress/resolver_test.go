package egress

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/socks5"
)

// fakeDNS is a DNS server on a UDP port of 127.0.0.1 that notes the names it
// is asked for. A name that set gave addresses is answered with them, A and
// AAAA records in the order given; a name that setMissing named does not
// exist; any other name has the A record 127.0.0.1 and no AAAA record.
type fakeDNS struct {
	pc      net.PacketConn
	mu      sync.Mutex
	names   []string
	answers map[string][]netip.Addr
	missing map[string]bool
}

func startFakeDNS(t *testing.T) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeDNS{pc: pc, answers: map[string][]netip.Addr{}, missing: map[string]bool{}}
	t.Cleanup(func() { _ = pc.Close() })
	go s.serve()
	return s
}

// set makes name, "host.test.", resolve to addrs.
func (s *fakeDNS) set(name string, addrs ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range addrs {
		s.answers[name] = append(s.answers[name], netip.MustParseAddr(a))
	}
}

// setMissing makes name, "host.test.", a name that does not exist.
func (s *fakeDNS) setMissing(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.missing[name] = true
}

func (s *fakeDNS) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
			continue
		}
		qq := q.Questions[0]
		name := strings.ToLower(qq.Name.String())
		s.mu.Lock()
		s.names = append(s.names, name)
		addrs, known := s.answers[name]
		missing := s.missing[name]
		s.mu.Unlock()
		if !known {
			addrs = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		}
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true},
			Questions: q.Questions,
		}
		if missing {
			resp.RCode = dnsmessage.RCodeNameError
		}
		for _, a := range addrs {
			if missing {
				break
			}
			hdr := dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 60}
			switch {
			case qq.Type == dnsmessage.TypeA && a.Is4():
				resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: a.As4()}})
			case qq.Type == dnsmessage.TypeAAAA && a.Is6():
				resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AAAAResource{AAAA: a.As16()}})
			}
		}
		b, err := resp.Pack()
		if err != nil {
			continue
		}
		_, _ = s.pc.WriteTo(b, from)
	}
}

// asked reports whether the server was asked for name.
func (s *fakeDNS) asked(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.names {
		if n == name {
			return true
		}
	}
	return false
}

// list returns the names asked for so far.
func (s *fakeDNS) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.names...)
}

func (s *fakeDNS) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.names)
}

// resolver returns a resolver whose every query goes to s, as the one of the
// edge's DNS forwarder does.
func (s *fakeDNS) resolver() *net.Resolver {
	addr := s.pc.LocalAddr().String()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
}

// acceptor accepts TCP connections on a port of 127.0.0.1 and closes them.
func acceptor(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
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
			_ = c.Close()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// A direct member resolves the name it connects to with the resolver of its
// router, and with the one the router has from then on when it changes. (Only
// fake resolvers here: nothing is asked of the system's.)
func TestDirectMembersResolveWithTheRoutersResolver(t *testing.T) {
	dns := startFakeDNS(t)
	port := acceptor(t)
	r := NewRouter(quiet)
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("d", KindDirect))}, nil); err != nil {
		t.Fatal(err)
	}
	r.SetResolver(dns.resolver())

	ctx, cancel := context.WithTimeout(context.Background(), ioTimeout)
	defer cancel()
	conn, key, err := r.Dial(ctx, "c", net.JoinHostPort("target.test", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()
	if key != "d" || !dns.asked("target.test.") {
		t.Errorf("dialed through %q; the resolver was asked for %v", key, dns.list())
	}

	// The members that are there take the change as well, without an Apply.
	other := startFakeDNS(t)
	r.SetResolver(other.resolver())
	before := dns.count()
	conn, _, err = r.Dial(ctx, "c", net.JoinHostPort("other.test", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatalf("Dial with the new resolver: %v", err)
	}
	_ = conn.Close()
	if dns.count() != before || !other.asked("other.test.") {
		t.Errorf("after the change: the old resolver was asked %d more times, the new one for %v", dns.count()-before, other.list())
	}
}

// The exit address of a direct member is asked for through the member, and the
// name of the echo service is resolved with the router's resolver too.
func TestEchoURLsResolveWithTheRoutersResolver(t *testing.T) {
	dns := startFakeDNS(t)
	echo := startEchoHTTP(t, answer(http.StatusOK, "203.0.113.7"))
	port := echo.Listener.Addr().(*net.TCPAddr).Port

	r := NewRouter(quiet)
	r.SetResolver(dns.resolver())
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("d", KindDirect))}, nil); err != nil {
		t.Fatal(err)
	}
	m := r.cur.Load().members[0]
	ctx, cancel := context.WithTimeout(context.Background(), ioTimeout)
	defer cancel()
	ip, err := fetchExitIP(ctx, m.dialer, "http://echo.test:"+strconv.Itoa(port)+"/ip", 2*time.Second, nil)
	if err != nil || ip != "203.0.113.7" {
		t.Fatalf("fetchExitIP = %q, %v", ip, err)
	}
	if !dns.asked("echo.test.") {
		t.Errorf("the router's resolver was not asked for the echo service: %v", dns.list())
	}
}

// A member that was made outside a router resolves with the system's resolver,
// and the hook is not in the way of a dial to an address.
func TestMemberDialerOutsideARouter(t *testing.T) {
	port := acceptor(t)
	d, err := NewMemberDialer(mem("d", KindDirect), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), ioTimeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port).String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

// A member made outside a router with a resolver of its own resolves with it:
// the agent goes through a member that way, with the agent's resolver.
func TestMemberDialerWithAResolver(t *testing.T) {
	dns := startFakeDNS(t)
	port := acceptor(t)
	d, err := NewMemberDialerWithResolver(mem("d", KindDirect), time.Second, dns.resolver())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), ioTimeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort("target.test", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	if !dns.asked("target.test.") {
		t.Errorf("the resolver was not asked: %v", dns.list())
	}
}

// ---------------------------------------------------------------------------
// Proxy members: the name of the proxy, and the name of the target under a
// destination policy.
// ---------------------------------------------------------------------------

var proxyKinds = []string{KindSOCKS5, KindHTTP}

// notingProxy is a proxy of one kind on 127.0.0.1 that notes the target of
// every request. It turns the targets in fail down with an answer of its own,
// the SOCKS5 reply "host unreachable" or the HTTP status 502, and connects
// every other request to an echo server, whatever the target.
type notingProxy struct {
	addr    string
	mu      sync.Mutex
	targets []string
}

func startNotingProxy(t *testing.T, kind string, fail ...string) *notingProxy {
	t.Helper()
	echo := startEcho(t)
	failing := map[string]bool{}
	for _, f := range fail {
		failing[f] = true
	}
	p := &notingProxy{}
	note := func(target string) bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.targets = append(p.targets, target)
		return !failing[target]
	}
	switch kind {
	case KindSOCKS5:
		p.addr = startSOCKS5(t, func(ctx context.Context, req socks5.Request) (net.Conn, error) {
			if !note(net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port)))) {
				return nil, &socks5.ReplyError{Code: 0x04}
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", echo)
		})
	case KindHTTP:
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		p.addr = ln.Addr().String()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go serveConnect(c, echo, note)
			}
		}()
	default:
		t.Fatalf("no proxy of kind %q", kind)
	}
	return p
}

// serveConnect serves one CONNECT of an HTTP proxy that connects to echo, or
// answers 502 when note says no.
func serveConnect(c net.Conn, echo string, note func(string) bool) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(ioTimeout))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	if !note(req.Host) {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	up, err := net.DialTimeout("tcp", echo, ioTimeout)
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	go func() { _, _ = io.Copy(up, br) }()
	_, _ = io.Copy(c, up)
}

func (p *notingProxy) list() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.targets)
}

// proxyRouter returns a router with the chain "c" of one member of kind at
// addr, which resolves with dns.
func proxyRouter(t *testing.T, dns *fakeDNS, kind, addr string) *Router {
	t.Helper()
	r := NewRouter(quiet)
	r.SetResolver(dns.resolver())
	if err := r.Apply([]*edgev1.Chain{chainOf("c", &edgev1.ChainMember{Key: "p", Kind: kind, Addr: addr})}, nil); err != nil {
		t.Fatal(err)
	}
	return r
}

// dialOnce dials target through the chain "c" of r and closes the connection.
func dialOnce(ctx context.Context, r *Router, target string) error {
	ctx, cancel := context.WithTimeout(ctx, ioTimeout)
	defer cancel()
	conn, _, err := r.Dial(ctx, "c", target)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// Under a destination policy, which the connections of the engines carry, a
// proxy member resolves the name of its target itself, with the router's
// resolver, and hands the proxy an address that the policy allows: a name that
// resolves to the node's own network does not get through a proxy either
// (Ruling 30). Without one, the name goes to the proxy as it is.
func TestProxyMembersResolveTheTargetUnderAPolicy(t *testing.T) {
	for _, kind := range proxyKinds {
		t.Run(kind, func(t *testing.T) {
			dns := startFakeDNS(t)
			dns.set("public.test.", "2001:db8::10", "192.0.2.10")
			dns.set("internal.test.", "127.0.0.1", "10.1.2.3")
			dns.set("mixed.test.", "10.1.2.3", "192.0.2.11")
			dns.setMissing("nowhere.test.")
			p := startNotingProxy(t, kind)
			r := proxyRouter(t, dns, kind, p.addr)
			policy := withDestinationPolicy(context.Background(), destinationAllowed)

			for _, target := range []string{"public.test:443", "mixed.test:443", "[2001:db8::1]:443"} {
				if err := dialOnce(policy, r, target); err != nil {
					t.Errorf("%s: %v", target, err)
				}
			}
			if err := dialOnce(policy, r, "internal.test:443"); !errors.Is(err, ErrDestinationNotAllowed) {
				t.Errorf("a name of the node's network: error %v, want ErrDestinationNotAllowed", err)
			}
			if err := dialOnce(policy, r, "nowhere.test:443"); err == nil || errors.Is(err, ErrDestinationNotAllowed) {
				t.Errorf("a name that does not exist: error %v, want the failure of the lookup", err)
			}
			// The health checks and the echo services: no policy, and the proxy
			// resolves the name where the traffic comes out.
			if err := dialOnce(context.Background(), r, "public.test:443"); err != nil {
				t.Errorf("without a policy: %v", err)
			}
			want := []string{"192.0.2.10:443", "192.0.2.11:443", "[2001:db8::1]:443", "public.test:443"}
			if got := p.list(); !slices.Equal(got, want) {
				t.Errorf("the proxy was asked for %q, want %q", got, want)
			}
		})
	}
}

// The addresses of a name are asked for in order, IPv4 first, for as long as
// the proxy answers that the target did not connect. A proxy that fails itself
// is not asked again: no other address would fare better through it.
func TestProxyMembersTryTheAddressesOfANameInOrder(t *testing.T) {
	for _, kind := range proxyKinds {
		t.Run(kind, func(t *testing.T) {
			dns := startFakeDNS(t)
			dns.set("multi.test.", "2001:db8::20", "192.0.2.20", "192.0.2.21")
			dns.set("dead.test.", "192.0.2.30", "192.0.2.31")
			p := startNotingProxy(t, kind, "192.0.2.20:443", "192.0.2.21:443", "192.0.2.30:443", "192.0.2.31:443")
			r := proxyRouter(t, dns, kind, p.addr)
			policy := withDestinationPolicy(context.Background(), destinationAllowed)

			if err := dialOnce(policy, r, "multi.test:443"); err != nil {
				t.Errorf("multi.test: %v", err)
			}
			err := dialOnce(policy, r, "dead.test:443")
			if err == nil || !answered(err) {
				t.Errorf("dead.test: error %v, want the answer of the proxy", err)
			}
			want := []string{"192.0.2.20:443", "192.0.2.21:443", "[2001:db8::20]:443", "192.0.2.30:443", "192.0.2.31:443"}
			if got := p.list(); !slices.Equal(got, want) {
				t.Errorf("the proxy was asked for %q, want %q", got, want)
			}
		})
		t.Run(kind+" that fails itself", func(t *testing.T) {
			dns := startFakeDNS(t)
			dns.set("multi.test.", "192.0.2.20", "192.0.2.21")
			cl, addr := startCounting(t) // takes the connection and closes it
			r := proxyRouter(t, dns, kind, addr)
			if err := dialOnce(withDestinationPolicy(context.Background(), destinationAllowed), r, "multi.test:443"); err == nil {
				t.Fatal("Dial through a proxy that hangs up succeeded")
			}
			if n := cl.accepted(); n != 1 {
				t.Errorf("the proxy was connected to %d times, want once", n)
			}
		})
	}
}

// startScriptedProxy serves a proxy of one kind on 127.0.0.1 that reads the
// request of each connection and then does what the script says for it, in the
// order of the connections: "refuse" answers that the target did not connect
// (the SOCKS5 reply 0x04, or the HTTP status 502), "hang up" closes the
// connection without an answer. It returns its address.
func startScriptedProxy(t *testing.T, kind string, script ...string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for i := 0; ; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			step := "hang up"
			if i < len(script) {
				step = script[i]
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(ioTimeout))
				refusal := "HTTP/1.1 502 Bad Gateway\r\n\r\n"
				if kind == KindSOCKS5 {
					if readSOCKS5Request(c) != nil {
						return
					}
					refusal = "\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00"
				} else if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				if step == "refuse" {
					_, _ = io.WriteString(c, refusal)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// readSOCKS5Request takes the greeting of a SOCKS5 client without credentials,
// answers it, and reads its request to the end.
func readSOCKS5Request(c net.Conn) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, make([]byte, head[1])); err != nil {
		return err
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return err
	}
	n := map[byte]int{0x01: 4, 0x04: 16}[req[3]]
	if req[3] == 0x03 {
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return err
		}
		n = int(l[0])
	}
	_, err := io.ReadFull(c, make([]byte, n+2))
	return err
}

// When the proxy answers for one address of a name and then fails itself on the
// next, the error of the member is its own failure: the answer before it does
// not hide a proxy that went away.
func TestProxyMembersReportTheirOwnFailureAfterAnAnswer(t *testing.T) {
	for _, kind := range proxyKinds {
		t.Run(kind, func(t *testing.T) {
			dns := startFakeDNS(t)
			dns.set("two.test.", "192.0.2.20", "192.0.2.21")
			r := proxyRouter(t, dns, kind, startScriptedProxy(t, kind, "refuse", "hang up"))
			err := dialOnce(withDestinationPolicy(context.Background(), destinationAllowed), r, "two.test:443")
			var de *DialError
			if !errors.As(err, &de) || len(de.Attempts) != 1 {
				t.Fatalf("error %v, want a DialError of one attempt", err)
			}
			if a := de.Attempts[0]; a.Answered || !errors.Is(a.Err, io.ErrUnexpectedEOF) {
				t.Errorf("the attempt: %v (answered %v), want the proxy hanging up and no answer", a.Err, a.Answered)
			}
		})
	}
}

// A proxy member reaches its proxy by name with the router's resolver too: on
// a node whose own resolver cannot get out, the edge's DNS forwarder is the
// one that works.
func TestProxyMembersReachTheirProxyWithTheRoutersResolver(t *testing.T) {
	for _, kind := range proxyKinds {
		t.Run(kind, func(t *testing.T) {
			dns := startFakeDNS(t) // every other name is 127.0.0.1
			p := startNotingProxy(t, kind)
			_, port, _ := net.SplitHostPort(p.addr)
			r := proxyRouter(t, dns, kind, net.JoinHostPort("proxy.test", port))
			if err := dialOnce(context.Background(), r, "192.0.2.10:443"); err != nil {
				t.Fatalf("Dial: %v", err)
			}
			if !dns.asked("proxy.test.") {
				t.Errorf("the router's resolver was not asked for the proxy: %v", dns.list())
			}
		})
	}
}

// The datacenters and the echo services of the health check may be given by
// name, and a direct member resolves them with the router's resolver, in the
// probes of the loop as in the dials of the engines.
func TestProbeResolvesNamesWithTheRoutersResolver(t *testing.T) {
	dns := startFakeDNS(t)
	dc := startFakeDC(t, dcAnswers, nil)
	_, dcPort, _ := net.SplitHostPort(dc.Addr())
	echo := startEchoHTTP(t, answer(http.StatusOK, "203.0.113.7"))
	echoPort := echo.Listener.Addr().(*net.TCPAddr).Port
	r := newRouter(quiet, deps{clock: newFakeClock()})
	r.SetResolver(dns.resolver())
	hc := &edgev1.HealthCheck{
		TimeoutSeconds: 2,
		DcAddrs:        []string{net.JoinHostPort("dc.test", dcPort)},
		EchoUrls:       []string{"http://echo.test:" + strconv.Itoa(echoPort) + "/ip"},
	}
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("d", KindDirect))}, hc); err != nil {
		t.Fatal(err)
	}
	r.probeRound(context.Background(), false)
	if h := r.Health()[0]; h.GetStatus() != "up" || h.GetExitIp() != "203.0.113.7" {
		t.Errorf("member %v, want up with its exit address", h)
	}
	if !dns.asked("dc.test.") || !dns.asked("echo.test.") || dc.Accepted() != 1 {
		t.Errorf("the resolver was asked for %v; the datacenter took %d connections", dns.list(), dc.Accepted())
	}
}

// onlyTenIsDenied is the destination policy of the tests of mixed names: the
// node's network is 10.0.0.0/8, and every other address is allowed, 0.0.0.0
// among them. A connection to 0.0.0.0 goes to the node itself on Linux, so on
// a closed port it is refused at once; and as its source is a loopback address,
// RFC 6724 orders it after 10.1.2.3, whose source is the node's own: the
// address that the policy refuses comes first in the answer, as it must for
// what these tests look at.
func onlyTenIsDenied(a netip.Addr) bool {
	return !netip.MustParsePrefix("10.0.0.0/8").Contains(a.Unmap())
}

// Under a destination policy a direct member dials only the addresses of a name
// that the policy allows. A name with an address of the node's network next to
// one that is allowed is the allowed one's: when that one does not connect, its
// own failure is the error, and not a refusal that would end the chain, whatever
// the order of the answer. A name with no address that is allowed is refused,
// and nothing is dialed.
func TestDirectMemberDialsTheAllowedAddressesOfAMixedName(t *testing.T) {
	dns := startFakeDNS(t)
	dns.set("mixed.test.", "10.1.2.3", "0.0.0.0")
	dns.set("internal.test.", "10.1.2.3", "10.4.5.6")
	dns.set("doc.test.", "10.1.2.3", "192.0.2.1")
	var res atomic.Pointer[net.Resolver]
	res.Store(dns.resolver())
	d, err := newMemberDialer(mem("d", KindDirect), 300*time.Millisecond, &res)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(closedAddr(t))
	policy := withDestinationPolicy(context.Background(), onlyTenIsDenied)

	_, err = d.DialContext(policy, "tcp", net.JoinHostPort("mixed.test", port))
	if !errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, ErrDestinationNotAllowed) {
		t.Errorf("mixed.test: error %v, want the refusal of the connection to 0.0.0.0 and not a refused destination", err)
	}
	if _, err := d.DialContext(policy, "tcp", net.JoinHostPort("internal.test", port)); !errors.Is(err, ErrDestinationNotAllowed) {
		t.Errorf("internal.test: error %v, want ErrDestinationNotAllowed", err)
	}
	// With the policy that ships: 192.0.2.1 is an address for documentation,
	// and whatever the network makes of it (it may even connect, through a
	// tunnel that takes every address), the destination is not refused.
	conn, err := d.DialContext(withDestinationPolicy(context.Background(), destinationAllowed), "tcp", "doc.test:443")
	if err == nil {
		_ = conn.Close()
	} else if errors.Is(err, ErrDestinationNotAllowed) {
		t.Errorf("doc.test: error %v, want the failure of 192.0.2.1 and not a refused destination", err)
	}
}

// Through the SOCKS port, the allowed address of a mixed name that refuses the
// connection is a refusal of the target (0x05), and the chain goes on to its
// next member, which a refused destination would have stopped.
func TestSocksPortsGoOnAfterTheAllowedAddressOfAMixedNameFails(t *testing.T) {
	dns := startFakeDNS(t)
	dns.set("mixed.test.", "10.1.2.3", "0.0.0.0")
	_, port, _ := net.SplitHostPort(closedAddr(t))
	var lb logBuf
	r := NewRouter(lb.logger())
	r.SetResolver(dns.resolver())
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("a", KindDirect), mem("b", KindDirect))}, nil); err != nil {
		t.Fatal(err)
	}
	s := newPorts(t, r, socksOptions{allow: onlyTenIsDenied})
	p := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(p, "x", "c", nil)}); err != nil {
		t.Fatal(err)
	}
	_, err := engineDial(p, "", net.JoinHostPort("mixed.test", port))
	if got := refusedWith(t, err); got != 0x05 {
		t.Errorf("refused with 0x%02x, want 0x05: the allowed address refused the connection", got)
	}
	if n := len(find(lb.records(t), "DEBUG", "member dial failed")); n != 2 {
		t.Errorf("%d members failed, want both: a refused connection does not end the chain", n)
	}
}

// An engine is turned away from a name of the node's network through a proxy
// member as through a direct one, with "not allowed by ruleset", and from a
// name that does not exist with "host unreachable", and the proxy hears of
// neither.
func TestSocksPortsThroughAProxyMemberRefuseNamesOfTheNodesNetwork(t *testing.T) {
	dns := startFakeDNS(t)
	dns.set("internal.test.", "10.1.2.3")
	dns.setMissing("nowhere.test.")
	p := startNotingProxy(t, KindSOCKS5)
	r := proxyRouter(t, dns, KindSOCKS5, p.addr)
	s := newPorts(t, r, socksOptions{}) // the policy that ships
	port := freePort(t)
	if err := s.Apply([]*edgev1.SocksPort{sockPort(port, "x", "c", nil)}); err != nil {
		t.Fatal(err)
	}
	_, err := engineDial(port, "", "internal.test:443")
	if got := refusedWith(t, err); got != 0x02 {
		t.Errorf("internal.test: refused with 0x%02x, want 0x02", got)
	}
	_, err = engineDial(port, "", "nowhere.test:443")
	if got := refusedWith(t, err); got != 0x04 {
		t.Errorf("nowhere.test: refused with 0x%02x, want 0x04", got)
	}
	if got := p.list(); len(got) != 0 {
		t.Errorf("the proxy was asked for %q", got)
	}
}
