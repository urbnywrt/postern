package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// wantHTTP400 is the answer of the http400 action, written out here
// independently of the package.
const wantHTTP400 = "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n" +
	"<html><head><title>400 The plain HTTP request was sent to HTTPS port</title></head><body>" +
	"<center><h1>400 Bad Request</h1></center><center>The plain HTTP request was sent to HTTPS port</center>" +
	"<hr><center>nginx</center></body></html>\r\n"

func TestUnknownSNIRejectAlert(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	cfg := oneRoute(1, port, "reject", "proxy.example.com", be.addr)
	// A web route without a certificate gets the alert as well, whatever the
	// listener does with strangers.
	cfg.Routes = append(cfg.Routes, &edgev1.Route{ListenerId: "l1", Sni: "web.example.com", ProxyId: "p2", Kind: "web", Backend: be.addr.String()})
	mustApply(t, e, cfg)

	for _, tt := range []struct{ name, sni string }{
		{"unknown name", "other.example.com"},
		{"no server name", ""},
		{"a prefix of a route", "proxy.example.co"},
		{"a route with NUL", "proxy.example.com\x00"},
		{"a route with two dots", "proxy.example.com.."},
		{"a route with a high byte", "proxy.example.com\xff"},
		{"too long", strings.Repeat("a", 300)},
		{"web route", "web.example.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := dialEdge(t, "", loopback(port))
			send(t, c, helloRecord(tt.sni))
			expectAlert(t, c)
		})
	}
	be.expectNone(t, 100*time.Millisecond)

	t.Run("crypto/tls reads the alert", func(t *testing.T) {
		c := dialEdge(t, "", loopback(port))
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		err := tls.Client(c, &tls.Config{ServerName: "other.example.com"}).Handshake()
		if err == nil || !strings.Contains(err.Error(), "unrecognized name") {
			t.Fatalf("handshake error %v, want the alert unrecognized_name", err)
		}
	})

	if p := proxyCounters(e.Snapshot(true), "p1"); p.GetConnsTotal() != 0 {
		t.Errorf("conns_total %d: strangers are counted for no proxy", p.GetConnsTotal())
	}
}

func TestMaskToPoolDomain(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	site := newBackend(t, false, echoHandler) // the site behind the mask target
	md := newMaskDialer(site.addr)
	port := freePort(t)
	res := resolverOf("pool.example.com", "203.0.113.10", "pool2.example.com", "203.0.113.11")
	e := newTestEdge(t, Options{DialMask: md.dial, Resolver: res})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", be.addr)
	cfg.MaskDomains = []string{"Pool.Example.com", "pool2.example.com."}
	mustApply(t, e, cfg)

	t.Run("a name of the pool goes to itself on 443", func(t *testing.T) {
		hello := helloRecord("POOL.example.COM.")
		c := dialEdge(t, "", loopback(port))
		send(t, c, hello)
		// The name is looked up, folded, and its address is dialed.
		if got := md.target(t); got != "203.0.113.10:443" {
			t.Fatalf("DialMask(%q), want 203.0.113.10:443, the address of pool.example.com", got)
		}
		if bc := site.next(t); !bytes.Equal(bc.hello, hello) {
			t.Fatalf("the mask target got % x, want the hello % x", bc.hello, hello)
		}
		roundTrip(t, c, "masked")
		roundTrip(t, c, string(bytes.Repeat([]byte("m"), 100000)))
	})

	t.Run("other names are rejected", func(t *testing.T) {
		for _, sni := range []string{"other.example.com", "", "pool.example.com\x00", "pool.example.com..", "xpool.example.com"} {
			c := dialEdge(t, "", loopback(port))
			send(t, c, helloRecord(sni))
			expectAlert(t, c)
		}
		md.expectNoDial(t)
	})

	t.Run("mask_target takes every stranger", func(t *testing.T) {
		cfg := oneRoute(2, port, "mask", "proxy.example.com", be.addr)
		cfg.Listeners[0].MaskTarget = "Mask.Example.com:8443"
		cfg.MaskDomains = []string{"pool.example.com"}
		mustApply(t, e, cfg)
		for _, sni := range []string{"other.example.com", "", "pool.example.com", "bad\x00name"} {
			hello := helloRecord(sni)
			c := dialEdge(t, "", loopback(port))
			send(t, c, hello)
			if got := md.target(t); got != "mask.example.com:8443" {
				t.Fatalf("DialMask(%q), want mask.example.com:8443", got)
			}
			if bc := site.next(t); !bytes.Equal(bc.hello, hello) {
				t.Fatalf("the mask target got % x, want % x", bc.hello, hello)
			}
			roundTrip(t, c, "to the mask target")
		}
	})

	t.Run("a failed dial closes without an answer", func(t *testing.T) {
		md.fail.Store(true)
		defer md.fail.Store(false)
		c := dialEdge(t, "", loopback(port))
		send(t, c, helloRecord("other.example.com"))
		md.target(t)
		expectClosed(t, c, 5*time.Second)
	})

	// Routes are served as ever.
	openRelay(t, "", loopback(port), "proxy.example.com", be)
}

func TestNonTLSHTTP400(t *testing.T) {
	checkGoroutines(t)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	cfg := oneRoute(1, port, "reject", "proxy.example.com", loopback(freePort(t)))
	cfg.Listeners[0].NonTlsAction = "http400"
	mustApply(t, e, cfg)

	for _, first := range []string{
		"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n",
		"SSH-2.0-OpenSSH_9.6\r\n",
		"\x16\x02\x00\x00\x05hello", // a handshake record of a version that is not TLS
		"G",
	} {
		c := dialEdge(t, "", loopback(port))
		send(t, c, []byte(first))
		if got := readToEOF(t, c, 5*time.Second); string(got) != wantHTTP400 {
			t.Fatalf("after %q: got %q, want the nginx answer", first, got)
		}
	}

	// A request larger than what the edge reads before it answers.
	c := dialEdge(t, "", loopback(port))
	send(t, c, []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20000\r\n\r\n"+strings.Repeat("x", 20000)))
	if got := readToEOF(t, c, 5*time.Second); string(got) != wantHTTP400 {
		t.Fatalf("after a large request: got %q, want the nginx answer", got)
	}

	cfg = oneRoute(2, port, "reject", "proxy.example.com", loopback(freePort(t)))
	cfg.Listeners[0].NonTlsAction = "drop"
	mustApply(t, e, cfg)
	c = dialEdge(t, "", loopback(port))
	send(t, c, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	expectClosed(t, c, 5*time.Second)
}

func TestStrangerDrop(t *testing.T) {
	checkGoroutines(t)
	const delay = 300 * time.Millisecond
	port := freePort(t)
	e := newTestEdge(t, Options{})
	e.dropDelay = func() time.Duration { return delay }
	mustApply(t, e, oneRoute(1, port, "drop", "proxy.example.com", loopback(freePort(t))))

	c := dialEdge(t, "", loopback(port))
	start := time.Now()
	send(t, c, helloRecord("other.example.com"))
	expectClosed(t, c, 3*time.Second)
	if d := time.Since(start); d < delay-20*time.Millisecond {
		t.Fatalf("dropped after %v, before the delay of %v", d, delay)
	}

	t.Run("default delay", func(t *testing.T) {
		seen := make(map[time.Duration]bool)
		for range 1000 {
			d := randomDropDelay()
			if d < 0 || d > 2*time.Second {
				t.Fatalf("delay %v outside 0-2 s", d)
			}
			seen[d] = true
		}
		if len(seen) < 100 {
			t.Fatalf("only %d distinct delays in 1000", len(seen))
		}
	})
}

func TestMalformedHelloTakesStrangerPath(t *testing.T) {
	checkGoroutines(t)
	wrongType := []byte{0x16, 3, 1, 0, 4, 2, 0, 0, 0} // a handshake record that is not a ClientHello

	t.Run("reject", func(t *testing.T) {
		port := freePort(t)
		e := newTestEdge(t, Options{MaxClientHello: 512})
		mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", loopback(freePort(t))))
		for _, b := range [][]byte{wrongType, helloRecord(strings.Repeat("a.", 300) + "example.com")} {
			c := dialEdge(t, "", loopback(port))
			send(t, c, b)
			expectAlert(t, c)
		}
	})

	t.Run("mask replays what was read", func(t *testing.T) {
		site := newRawServer(t)
		md := newMaskDialer(site.addr)
		port := freePort(t)
		e := newTestEdge(t, Options{DialMask: md.dial})
		cfg := oneRoute(1, port, "mask", "proxy.example.com", loopback(freePort(t)))
		cfg.Listeners[0].MaskTarget = "mask.example.com:443"
		mustApply(t, e, cfg)

		c := dialEdge(t, "", loopback(port))
		send(t, c, append(bytes.Clone(wrongType), "tail"...))
		if got := md.target(t); got != "mask.example.com:443" {
			t.Fatalf("DialMask(%q)", got)
		}
		bc := site.next(t)
		defer func() { _ = bc.conn.Close() }()
		_ = bc.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(wrongType)+len("tail"))
		if _, err := io.ReadFull(bc.r, got); err != nil {
			t.Fatal(err)
		}
		if want := append(bytes.Clone(wrongType), "tail"...); !bytes.Equal(got, want) {
			t.Fatalf("the mask target got % x, want % x", got, want)
		}
	})
}

func TestTruncatedHelloClosesSilently(t *testing.T) {
	checkGoroutines(t)
	const helloTimeout = 300 * time.Millisecond
	port := freePort(t)
	e := newTestEdge(t, Options{ClientHelloTimeout: helloTimeout})
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", loopback(freePort(t))))
	hello := helloRecord("proxy.example.com")

	t.Run("cut off", func(t *testing.T) {
		c := dialEdge(t, "", loopback(port))
		send(t, c, hello[:20])
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		expectClosed(t, c, 3*time.Second)
	})
	t.Run("silent", func(t *testing.T) {
		start := time.Now()
		c := dialEdge(t, "", loopback(port))
		expectClosed(t, c, 3*time.Second)
		if d := time.Since(start); d < helloTimeout-50*time.Millisecond {
			t.Fatalf("closed after %v, before the hello timeout of %v", d, helloTimeout)
		}
	})
	t.Run("stalls in the middle", func(t *testing.T) {
		c := dialEdge(t, "", loopback(port))
		send(t, c, hello[:20])
		expectClosed(t, c, 3*time.Second)
	})
}

func TestMaskedStrangersCapped(t *testing.T) {
	checkGoroutines(t)
	site := newBackend(t, false, nil) // the test holds the masked connections open
	md := newMaskDialer(site.addr)
	port := freePort(t)
	e := newTestEdge(t, Options{DialMask: md.dial, MaxMasked: 2})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", loopback(freePort(t)))
	cfg.Listeners[0].MaskTarget = "mask.example.com:443"
	mustApply(t, e, cfg)

	mask := func() (net.Conn, *backendConn) {
		t.Helper()
		c := dialEdge(t, "", loopback(port))
		send(t, c, helloRecord("other.example.com"))
		md.target(t)
		return c, site.next(t)
	}
	c1, s1 := mask()
	mask()

	// Over the cap a stranger is rejected, and nothing is dialed.
	c := dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("other.example.com"))
	expectAlert(t, c)
	md.expectNoDial(t)

	// A masked connection that ends gives its place back.
	_ = c1.Close()
	_ = s1.conn.Close()
	waitFor(t, "a place to free", func() bool { return e.masked.Load() == 1 })
	mask()
}

func TestMaskCapBoundsLoops(t *testing.T) {
	checkGoroutines(t)
	port := freePort(t)
	// The forwarder plays a NAT hairpin: the pool domain leads back to this
	// edge, but from an address the loop guard cannot recognise.
	hairpin := newForwarder(t, loopback(port))
	var dials atomic.Int32
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		if dials.Add(1) > 20 {
			return nil, errors.New("the loop is not bounded")
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp4", hairpin.addr.String())
	}
	e := newTestEdge(t, Options{DialMask: dial, MaxMasked: 5, Resolver: resolverOf("loop.example.com", "203.0.113.20")})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", loopback(freePort(t)))
	cfg.MaskDomains = []string{"loop.example.com"}
	mustApply(t, e, cfg)

	c := dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("loop.example.com"))
	// The sixth hop is over the cap and rejected; its alert comes back through
	// the five masked relays.
	expectAlert(t, c)
	if n := dials.Load(); n != 5 {
		t.Fatalf("DialMask called %d times, want 5", n)
	}
}

func TestMaskLoopIsCut(t *testing.T) {
	checkGoroutines(t)
	port := freePort(t)
	var calls atomic.Int32
	// The pool domain resolves to a public address of this very node, which the
	// dialer stands in for with the address of the edge.
	dialSelf := func(ctx context.Context, addr string) (net.Conn, error) {
		if calls.Add(1) > 5 {
			return nil, errors.New("mask loop not cut")
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp4", loopback(port).String())
	}
	e := newTestEdge(t, Options{DialMask: dialSelf, Resolver: resolverOf("loop.example.com", "203.0.113.20")})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", loopback(freePort(t)))
	cfg.MaskDomains = []string{"loop.example.com"}
	mustApply(t, e, cfg)

	c := dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("loop.example.com"))
	expectClosed(t, c, 5*time.Second)
	if n := calls.Load(); n != 1 {
		t.Fatalf("DialMask called %d times, want once", n)
	}
}

// A stranger that is masked to its own server name, a mask domain, goes to an
// address that the destination policy allows, and nowhere else: what the name
// resolves to is up to whoever answers for it in the DNS, which must not be able
// to point the edge at the node or its network (Ruling 36). A name with no such
// address is rejected, as a stranger without a mask target is, and nothing is
// dialed.
func TestMaskDomainObeysTheDestinationPolicy(t *testing.T) {
	checkGoroutines(t)
	site := newBackend(t, false, echoHandler)
	md := newMaskDialer(site.addr)
	port := freePort(t)
	refused := []string{ // a name and its addresses
		"loopback.example.com", "127.0.0.1",
		"private.example.com", "10.0.0.1",
		"metadata.example.com", "169.254.169.254",
		"cgnat.example.com", "100.64.0.1",
		"ula.example.com", "fd00::1",
		"mapped.example.com", "::ffff:127.0.0.1",
		"internal.example.com", "10.0.0.1,::1,0.0.0.0",
	}
	allowed := []string{ // a name, its addresses, and the target that is dialed
		"public.example.com", "203.0.113.10", "203.0.113.10:443",
		"v6.example.com", "2001:db8::10", "[2001:db8::10]:443",
		"mixed.example.com", "10.0.0.1,169.254.169.254,203.0.113.11", "203.0.113.11:443",
	}
	res := resolverOf(refused...)
	for i := 0; i < len(allowed); i += 3 {
		maps.Copy(res, resolverOf(allowed[i], allowed[i+1]))
	}
	log, logs := captureLogger(slog.LevelInfo)
	e := newTestEdgeLog(t, log, Options{DialMask: md.dial, Resolver: res})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", loopback(freePort(t)))
	cfg.MaskDomains = slices.Collect(maps.Keys(res))
	mustApply(t, e, cfg)

	for i := 0; i < len(refused); i += 2 {
		name := refused[i]
		c := dialEdge(t, "", loopback(port))
		send(t, c, helloRecord(name))
		expectAlert(t, c)
		// The place among the masked strangers was given back before the alert.
		if n := e.masked.Load(); n != 0 {
			t.Errorf("%s: %d strangers are masked after the refusal, want none", name, n)
		}
		if !strings.Contains(logs.String(), "domain="+name) {
			t.Errorf("%s: the refusal is not logged:\n%s", name, logs.String())
		}
	}
	md.expectNoDial(t)

	for i := 0; i < len(allowed); i += 3 {
		name, want := allowed[i], allowed[i+2]
		hello := helloRecord(name)
		c := dialEdge(t, "", loopback(port))
		send(t, c, hello)
		if got := md.target(t); got != want {
			t.Fatalf("%s: DialMask(%q), want %s", name, got, want)
		}
		if bc := site.next(t); !bytes.Equal(bc.hello, hello) {
			t.Fatalf("%s: the mask target got % x, want the hello % x", name, bc.hello, hello)
		}
		roundTrip(t, c, "masked")
	}
	md.expectNoDial(t)
}

// The mask target of a listener is the operator's own choice, and is dialed as it
// is, an address on the loopback or a private one too: a web server of the node
// itself may be the mask. It is not looked up by the edge either.
func TestMaskTargetIsNotFiltered(t *testing.T) {
	checkGoroutines(t)
	site := newBackend(t, false, echoHandler)
	md := newMaskDialer(site.addr)
	port := freePort(t)
	e := newTestEdge(t, Options{DialMask: md.dial, Resolver: resolverOf("pool.example.com", "127.0.0.1")})
	for gen, target := range []string{"127.0.0.1:8443", "10.0.0.1:443", "mask.example.com:443"} {
		cfg := oneRoute(uint64(gen+1), port, "mask", "proxy.example.com", loopback(freePort(t)))
		cfg.Listeners[0].MaskTarget = target
		cfg.MaskDomains = []string{"pool.example.com"}
		mustApply(t, e, cfg)
		for _, sni := range []string{"other.example.com", "pool.example.com"} {
			c := dialEdge(t, "", loopback(port))
			send(t, c, helloRecord(sni))
			if got := md.target(t); got != target {
				t.Fatalf("%s, mask target %s: DialMask(%q)", sni, target, got)
			}
			site.next(t)
			roundTrip(t, c, "to the mask target")
		}
	}
}

// maskAttempt is a dial of the mask dialer of a test: where to, when it began,
// and the deadline that it had.
type maskAttempt struct {
	target   string
	at       time.Time
	deadline time.Time
}

// attemptLog notes the dials of a mask dialer, in the order they began.
type attemptLog struct {
	mu   sync.Mutex
	list []maskAttempt
}

func (l *attemptLog) note(ctx context.Context, target string) {
	deadline, _ := ctx.Deadline()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.list = append(l.list, maskAttempt{target: target, at: time.Now(), deadline: deadline})
}

func (l *attemptLog) all() []maskAttempt {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.list)
}

// The addresses of a mask domain that are allowed are raced as RFC 8305 says
// (Happy Eyeballs): the families take turns, starting with the family of the
// first address of the answer; an attempt starts 300 ms after the one before it
// began, or as soon as that one fails; every attempt has the whole of the dial
// timeout; the first connection wins. On a node whose IPv6 is a black hole the
// IPv4 address is tried after 300 ms, not after a share of the timeout.
func TestMaskDomainTriesItsAddressesInTurn(t *testing.T) {
	checkGoroutines(t)
	site := newBackend(t, false, echoHandler)
	attempts := &attemptLog{}
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		attempts.note(ctx, addr)
		switch addr {
		case "[2001:db8::10]:443", "[2001:db8::11]:443": // black holes
			<-ctx.Done()
			return nil, ctx.Err()
		case "203.0.113.11:443": // refused, after a while
			select {
			case <-time.After(150 * time.Millisecond):
				return nil, syscall.ECONNREFUSED
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp4", site.addr.String())
	}
	port := freePort(t)
	e := newTestEdge(t, Options{DialMask: dial, DialTimeout: 3 * time.Second,
		Resolver: resolverOf("pool.example.com", "2001:db8::10,10.0.0.1,2001:db8::11,203.0.113.11,203.0.113.12")})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", loopback(freePort(t)))
	cfg.MaskDomains = []string{"pool.example.com"}
	mustApply(t, e, cfg)

	start := time.Now()
	c := dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("pool.example.com"))
	site.next(t)
	roundTrip(t, c, "masked by the fourth attempt")
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Errorf("masked after %v, want about 750 ms: two delays of 300 ms and a refusal after 150 ms", d)
	}

	got := attempts.all()
	var order []string
	for _, a := range got {
		order = append(order, a.target)
	}
	// IPv6 first, as the answer has it, then the families in turn; the private
	// address is not dialed.
	if want := []string{"[2001:db8::10]:443", "203.0.113.11:443", "[2001:db8::11]:443", "203.0.113.12:443"}; !slices.Equal(order, want) {
		t.Fatalf("dialed %v, want %v", order, want)
	}
	between := func(i, j int, least, most time.Duration, why string) {
		t.Helper()
		if d := got[j].at.Sub(got[i].at); d < least || d > most {
			t.Errorf("%s began %v after %s, want %v to %v: %s", got[j].target, d, got[i].target, least, most, why)
		}
	}
	between(0, 1, 250*time.Millisecond, 700*time.Millisecond, "the IPv4 address follows the black hole after the delay")
	between(1, 2, 100*time.Millisecond, 280*time.Millisecond, "an attempt that fails starts the next one at once, before the delay is up")
	between(2, 3, 250*time.Millisecond, 700*time.Millisecond, "and the delay counts again from there")
	// Every attempt has the deadline of the whole dial, not a share of it.
	for _, a := range got[1:] {
		if !a.deadline.Equal(got[0].deadline) || a.deadline.IsZero() {
			t.Errorf("%s had the deadline %v, want the one of the whole dial, %v", a.target, a.deadline, got[0].deadline)
		}
	}
}

// The addresses of a mask domain that are raced are 8 at most, the first ones
// in the order of the race, so that both families are among them: one answer
// of the DNS cannot fan a stranger out into many dials.
func TestMaskDomainRacesEightAddressesAtMost(t *testing.T) {
	checkGoroutines(t)
	attempts := &attemptLog{}
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		attempts.note(ctx, addr)
		return nil, syscall.ECONNREFUSED // at once: the next address is tried at once
	}
	var answer []string
	for i := range 10 {
		answer = append(answer, fmt.Sprintf("2001:db8::%d", i+1))
	}
	for i := range 10 {
		answer = append(answer, fmt.Sprintf("203.0.113.%d", i+1))
	}
	port := freePort(t)
	e := newTestEdge(t, Options{DialMask: dial, Resolver: resolverOf("many.example.com", strings.Join(answer, ","))})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", loopback(freePort(t)))
	cfg.MaskDomains = []string{"many.example.com"}
	mustApply(t, e, cfg)

	c := dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("many.example.com"))
	expectClosed(t, c, 3*time.Second)
	var got []string
	for _, a := range attempts.all() {
		got = append(got, a.target)
	}
	want := []string{
		"[2001:db8::1]:443", "203.0.113.1:443", "[2001:db8::2]:443", "203.0.113.2:443",
		"[2001:db8::3]:443", "203.0.113.3:443", "[2001:db8::4]:443", "203.0.113.4:443",
	}
	if !slices.Equal(got, want) {
		t.Errorf("dialed %v, want %v", got, want)
	}
	waitFor(t, "the place of the masked stranger", func() bool { return e.masked.Load() == 0 })
}

// noteClose is a connection that notes that it was closed.
type noteClose struct {
	net.Conn
	closed atomic.Bool
}

func (c *noteClose) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// The connections of the attempts that lose the race are closed, also one that
// is made after the race is over, and the attempts that are left are not made:
// nothing of the race stays behind.
func TestMaskDomainRaceClosesTheLosers(t *testing.T) {
	checkGoroutines(t)
	site := newBackend(t, false, echoHandler)
	sink := newRawServer(t) // where the connection that loses goes
	attempts := &attemptLog{}
	var (
		mu    sync.Mutex
		conns = map[string]*noteClose{}
	)
	// won is closed once the connection that won the race has made its round
	// trip; the attempt that loses connects only then.
	won := make(chan struct{})
	var wonOnce sync.Once
	raceWon := func() { wonOnce.Do(func() { close(won) }) }
	t.Cleanup(raceWon) // a test that fails early lets the losing dial end
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		attempts.note(ctx, addr)
		to := site.addr
		if addr == "[2001:db8::20]:443" {
			// This one connects too, after the race is won, whatever ctx says.
			<-won
			to = sink.addr
		}
		var d net.Dialer
		c, err := d.Dial("tcp4", to.String())
		if err != nil {
			return nil, err
		}
		nc := &noteClose{Conn: c}
		mu.Lock()
		conns[addr] = nc
		mu.Unlock()
		return nc, nil
	}
	conn := func(target string) *noteClose {
		mu.Lock()
		defer mu.Unlock()
		return conns[target]
	}
	port := freePort(t)
	e := newTestEdge(t, Options{DialMask: dial,
		Resolver: resolverOf("pool.example.com", "2001:db8::20,203.0.113.21,2001:db8::21")})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", loopback(freePort(t)))
	cfg.MaskDomains = []string{"pool.example.com"}
	mustApply(t, e, cfg)

	c := dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("pool.example.com"))
	site.next(t)
	roundTrip(t, c, "masked by the second attempt")
	raceWon()

	waitFor(t, "the connection that lost to be made and closed", func() bool {
		lost := conn("[2001:db8::20]:443")
		return lost != nil && lost.closed.Load()
	})
	if won := conn("203.0.113.21:443"); won == nil || won.closed.Load() {
		t.Error("the connection that won is closed, or was never made")
	}
	roundTrip(t, c, "still masked")
	var order []string
	for _, a := range attempts.all() {
		order = append(order, a.target)
	}
	if want := []string{"[2001:db8::20]:443", "203.0.113.21:443"}; !slices.Equal(order, want) {
		t.Errorf("dialed %v, want %v: nothing is dialed once the race is won", order, want)
	}
	_ = c.Close()
	waitFor(t, "the place of the masked stranger", func() bool { return e.masked.Load() == 0 })
}

// A panic in a dial of the race, which runs in a goroutine of its own, is
// stopped and logged like one in the goroutine of a connection. The dial counts
// as one that failed: the next address is tried, and the edge lives on.
func TestPanicInARaceDialIsContained(t *testing.T) {
	checkGoroutines(t)
	log, buf := captureLogger(slog.LevelInfo)
	be := newBackend(t, true, echoHandler)
	site := newBackend(t, false, echoHandler)
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		if addr == "203.0.113.66:443" {
			panic("the mask dialer exploded")
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp4", site.addr.String())
	}
	port := freePort(t)
	e := newTestEdgeLog(t, log, Options{DialMask: dial,
		Resolver: resolverOf("boom.example.com", "203.0.113.66", "half.example.com", "203.0.113.66,203.0.113.67")})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", be.addr)
	cfg.MaskDomains = []string{"boom.example.com", "half.example.com"}
	mustApply(t, e, cfg)

	// The only address panics: the stranger is closed without an answer.
	c := dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("boom.example.com"))
	expectClosed(t, c, 3*time.Second)
	waitFor(t, "the panic to be logged", func() bool { return strings.Contains(buf.String(), "panic while serving") })
	out := buf.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "the mask dialer exploded") || !strings.Contains(out, "goroutine") {
		t.Errorf("the panic is not logged as an error with its stack:\n%s", out)
	}

	// The first of two panics, and the second wins the race at once.
	c = dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("half.example.com"))
	site.next(t)
	roundTrip(t, c, "masked by the address that did not panic")
	_ = c.Close()

	// The edge lives on.
	openRelay(t, "", loopback(port), "proxy.example.com", be)
	waitFor(t, "the places of the masked strangers", func() bool { return e.masked.Load() == 0 })
}

// interleaveFamilies orders addresses for a race: the families take turns,
// starting with the family of the first address, and each keeps its order.
func TestInterleaveFamilies(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{"203.0.113.1", "203.0.113.1"},
		{"203.0.113.1,203.0.113.2", "203.0.113.1,203.0.113.2"},
		{"2001:db8::1,2001:db8::2,203.0.113.1,203.0.113.2,203.0.113.3", "2001:db8::1,203.0.113.1,2001:db8::2,203.0.113.2,203.0.113.3"},
		{"203.0.113.1,203.0.113.2,2001:db8::1", "203.0.113.1,2001:db8::1,203.0.113.2"},
		{"2001:db8::1,203.0.113.1,2001:db8::2,203.0.113.2", "2001:db8::1,203.0.113.1,2001:db8::2,203.0.113.2"},
	} {
		var in []netip.Addr
		if c.in != "" {
			in = resolverOf("x", c.in)["x"]
		}
		var got []string
		for _, a := range interleaveFamilies(in) {
			got = append(got, a.String())
		}
		if g := strings.Join(got, ","); g != c.want {
			t.Errorf("interleaveFamilies(%s) = %s, want %s", c.in, g, c.want)
		}
	}
}

// stuckResolver does not answer for the name stuck until the lookup is given up;
// for the others it is a fakeResolver.
type stuckResolver struct {
	fakeResolver
	stuck string
}

func (r stuckResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if host == r.stuck {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return r.fakeResolver.LookupNetIP(ctx, network, host)
}

// A mask domain that cannot be looked up is a mask target that cannot be
// reached: the stranger is closed without an answer, and within the dial timeout
// also when the resolver does not answer at all.
func TestMaskDomainThatCannotBeLookedUp(t *testing.T) {
	checkGoroutines(t)
	md := newMaskDialer(loopback(freePort(t)))
	port := freePort(t)
	const dialTimeout = 300 * time.Millisecond
	e := newTestEdge(t, Options{DialMask: md.dial, DialTimeout: dialTimeout,
		Resolver: stuckResolver{fakeResolver: fakeResolver{}, stuck: "stuck.example.com"}})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", loopback(freePort(t)))
	cfg.MaskDomains = []string{"nx.example.com", "stuck.example.com"}
	mustApply(t, e, cfg)

	for _, name := range []string{"nx.example.com", "stuck.example.com"} {
		start := time.Now()
		c := dialEdge(t, "", loopback(port))
		send(t, c, helloRecord(name))
		expectClosed(t, c, 3*time.Second)
		if d := time.Since(start); d > dialTimeout+time.Second {
			t.Errorf("%s: closed after %v, want it within the dial timeout of %v", name, d, dialTimeout)
		}
	}
	md.expectNoDial(t)
	waitFor(t, "the places of the masked strangers", func() bool { return e.masked.Load() == 0 })
}
