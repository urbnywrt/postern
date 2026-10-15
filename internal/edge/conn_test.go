package edge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// clientAddr is the address of the client end of c, as the edge sees it.
func clientAddr(c net.Conn) netip.AddrPort {
	ap := c.LocalAddr().(*net.TCPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func TestRoutesBySNIWithProxyHeader(t *testing.T) {
	checkGoroutines(t)
	withHeader := newBackend(t, true, echoHandler)
	plain := newBackend(t, false, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, &edgev1.EdgeConfig{
		Generation: 1,
		Listeners:  []*edgev1.EdgeListener{tlsListener("l1", port, "reject")},
		Routes: []*edgev1.Route{
			engineRoute("l1", "proxy.example.com", "p1", withHeader.addr),
			{ListenerId: "l1", Sni: "Plain.Example.COM", ProxyId: "p2", Kind: "engine", Backend: plain.addr.String()},
		},
	})

	t.Run("crypto/tls hello, PROXY v2 header", func(t *testing.T) {
		hello := realHello(t, "Proxy.Example.COM") // routes fold the case
		c := dialEdge(t, "127.0.0.5", loopback(port))
		send(t, c, hello)
		bc := withHeader.next(t)
		if bc.header == nil || bc.header.Local {
			t.Fatalf("PROXY header %+v, want the PROXY command", bc.header)
		}
		if want := clientAddr(c); bc.header.Src != want {
			t.Errorf("PROXY source %v, want the client %v", bc.header.Src, want)
		}
		if want := loopback(port); bc.header.Dst != want {
			t.Errorf("PROXY destination %v, want the listener %v", bc.header.Dst, want)
		}
		if !bytes.Equal(bc.hello, hello) {
			t.Errorf("the backend got a hello of %d bytes that differs from the %d bytes sent", len(bc.hello), len(hello))
		}
		roundTrip(t, c, "ping")
		roundTrip(t, c, string(bytes.Repeat([]byte("0123456789"), 20000))) // larger than a relay buffer
	})

	t.Run("trailing dot, no PROXY header", func(t *testing.T) {
		hello := helloRecord("plain.example.com.")
		c := dialEdge(t, "", loopback(port))
		send(t, c, hello)
		bc := plain.next(t)
		if !bytes.Equal(bc.hello, hello) {
			t.Errorf("the backend got % x, want % x", bc.hello, hello)
		}
		roundTrip(t, c, "pong")
	})

	t.Run("bytes behind the hello in the same write", func(t *testing.T) {
		hello := helloRecord("proxy.example.com")
		c := dialEdge(t, "", loopback(port))
		send(t, c, append(slices.Clone(hello), "early data"...))
		bc := withHeader.next(t)
		if !bytes.Equal(bc.hello, hello) {
			t.Errorf("the backend got % x, want % x", bc.hello, hello)
		}
		if got := readN(t, c, len("early data")); string(got) != "early data" {
			t.Errorf("echo of the early data: %q", got)
		}
	})

	t.Run("hello split across writes", func(t *testing.T) {
		hello := helloRecord("proxy.example.com")
		c := dialEdge(t, "", loopback(port))
		for _, part := range [][]byte{hello[:1], hello[1:5], hello[5:30], hello[30:]} {
			send(t, c, part)
			time.Sleep(10 * time.Millisecond)
		}
		if bc := withHeader.next(t); !bytes.Equal(bc.hello, hello) {
			t.Errorf("the backend got % x, want % x", bc.hello, hello)
		}
		roundTrip(t, c, "split")
	})
}

// A test listener whose port something else holds is left out, with a warning,
// and the configuration applies all the same: no client uses a test listener,
// the node's probes through it fail on their own, and the proxies go on (I1).
// The warning is not repeated by every Apply of the agent, and the next Apply
// tries the port again.
func TestTestListenerThatCannotBindIsLeftOut(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	// Something that is not an edge holds the port: no SO_REUSEPORT. It
	// listens first, so that the kernel cannot hand it the port of the edge.
	squatter, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = squatter.Close() }()
	testPort := uint32(squatter.Addr().(*net.TCPAddr).Port)
	port := freePort(t)

	log, logs := captureLogger(slog.LevelInfo)
	clock := newFakeClock()
	e := newTestEdgeLog(t, log, Options{Now: clock.Now})
	cfg := oneRoute(1, port, "reject", "proxy.example.com", be.addr)
	cfg.TestListeners = []*edgev1.TestListener{{Port: testPort, ListenerId: "l1"}}
	mustApply(t, e, cfg)

	if got, want := e.Bound(), []string{loopback(port).String()}; !slices.Equal(got, want) {
		t.Fatalf("bound %v, want %v: the listener without its test listener", got, want)
	}
	if g := e.Generation(); g != 1 {
		t.Fatalf("generation %d, want 1", g)
	}
	c := openRelay(t, "", loopback(port), "proxy.example.com", be)
	roundTrip(t, c, "the proxy is served")
	warnings := func() int {
		return strings.Count(logs.String(), "a test listener cannot be bound")
	}
	if n := warnings(); n != 1 || !strings.Contains(logs.String(), loopback(testPort).String()) || !strings.Contains(logs.String(), "listener=l1") {
		t.Errorf("%d warnings, want one that names the address and the listener:\n%s", n, logs.String())
	}

	// The agent sends the configuration on every pass: one warning in a while.
	mustApply(t, e, cfg)
	if n := warnings(); n != 1 {
		t.Errorf("%d warnings after the second Apply, want still 1", n)
	}
	clock.Advance(probeWarnInterval)
	mustApply(t, e, cfg)
	if n := warnings(); n != 2 {
		t.Errorf("%d warnings after the interval, want 2", n)
	}

	// The port is free again: the next Apply binds it.
	_ = squatter.Close()
	mustApply(t, e, cfg)
	want := []string{loopback(port).String(), loopback(testPort).String()}
	slices.Sort(want)
	if got := e.Bound(); !slices.Equal(got, want) {
		t.Errorf("bound %v, want %v", got, want)
	}
}

func TestTestListenerMirrorsRoutes(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port, testPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{})
	cfg := oneRoute(1, port, "reject", "proxy.example.com", be.addr)
	cfg.TestListeners = []*edgev1.TestListener{{Port: testPort, ListenerId: "l1"}}
	mustApply(t, e, cfg)

	want := []string{loopback(port).String(), loopback(testPort).String()}
	slices.Sort(want)
	if got := e.Bound(); !slices.Equal(got, want) {
		t.Fatalf("bound %v, want %v", got, want)
	}

	// A route of the listener is served on the test listener, and the PROXY
	// header names the address the client connected to.
	c := dialEdge(t, "", loopback(testPort))
	send(t, c, helloRecord("proxy.example.com"))
	bc := be.next(t)
	if bc.header.Dst != loopback(testPort) {
		t.Errorf("PROXY destination %v, want the test listener %v", bc.header.Dst, loopback(testPort))
	}
	if bc.header.Src != clientAddr(c) {
		t.Errorf("PROXY source %v, want the client %v", bc.header.Src, clientAddr(c))
	}
	roundTrip(t, c, "via the test listener")

	// A stranger gets what a stranger of the listener gets.
	s := dialEdge(t, "", loopback(testPort))
	send(t, s, helloRecord("other.example.com"))
	expectAlert(t, s)

	// The test listener is for the node's own probes: they are not held to the
	// limits of the proxy, and not counted, so that a probe neither takes the
	// place of a device nor shows up as one.
	cfg.Generation = 2
	cfg.Routes[0].Limits = &edgev1.EdgeLimits{Devices: 1, ConnsTotal: 1, ConnsPerIp: 1}
	mustApply(t, e, cfg)
	user := openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	for range 3 {
		openRelay(t, "127.0.0.3", loopback(testPort), "proxy.example.com", be)
	}
	expectRefusedAt(t, "127.0.0.3", loopback(port)) // the real listener does hold to the limits
	snap := e.Snapshot(true)
	if p := proxyCounters(snap, "p1"); p.GetConnsTotal() != 1 || p.GetConnsActive() != 1 || p.GetDevicesActive() != 1 {
		t.Errorf("counters %v: want the one connection of the user only", p)
	}
	if ip := ipCounters(snap, "p1", "127.0.0.3"); ip != nil {
		t.Errorf("the prober is counted: %v", ip)
	}
	roundTrip(t, user, "the user is still served")

	// Without the test listener the port is closed; the relay goes on.
	mustApply(t, e, oneRoute(3, port, "reject", "proxy.example.com", be.addr))
	if got, want := e.Bound(), []string{loopback(port).String()}; !slices.Equal(got, want) {
		t.Fatalf("bound %v, want %v", got, want)
	}
	if conn, err := net.DialTimeout("tcp4", loopback(testPort).String(), time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("the test listener still accepts connections")
	}
	roundTrip(t, c, "the relay outlives its listener")
}

// A probe route takes the node's probes on the test listener of its listener
// to its backend, in place of the route of the same name, and no other
// connection: the agent probes a new engine generation through it before the
// route of the proxy moves (spec 5.5). A name without a probe route is
// routed as ever, and the probes are not counted.
func TestProbeRoutesTakeTheTestListenerOnly(t *testing.T) {
	checkGoroutines(t)
	serving := newBackend(t, true, echoHandler)
	starting := newBackend(t, true, echoHandler)
	other := newBackend(t, true, echoHandler)
	port, testPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{})
	cfg := oneRoute(1, port, "reject", "proxy.example.com", serving.addr)
	cfg.Routes = append(cfg.Routes, engineRoute("l1", "other.example.com", "p2", other.addr))
	cfg.TestListeners = []*edgev1.TestListener{{Port: testPort, ListenerId: "l1"}}
	cfg.ProbeRoutes = []*edgev1.Route{
		engineRoute("l1", "Proxy.Example.com.", "p1", starting.addr), // the name as the edge folds it
		engineRoute("l1", "new.example.com", "p3", starting.addr),    // a proxy that has no route yet
	}
	mustApply(t, e, cfg)

	// The public listener: the routes, never a probe route.
	openRelay(t, "", loopback(port), "proxy.example.com", serving)
	s := dialEdge(t, "", loopback(port))
	send(t, s, helloRecord("new.example.com"))
	expectAlert(t, s)

	// The test listener: the probe route where there is one, the route where
	// there is not.
	c := dialEdge(t, "", loopback(testPort))
	send(t, c, helloRecord("proxy.example.com"))
	if bc := starting.next(t); bc.header.Dst != loopback(testPort) {
		t.Errorf("PROXY destination %v, want the test listener %v", bc.header.Dst, loopback(testPort))
	}
	roundTrip(t, c, "the new generation through the test listener")
	openRelay(t, "", loopback(testPort), "new.example.com", starting)
	openRelay(t, "", loopback(testPort), "other.example.com", other)
	serving.expectNone(t, 50*time.Millisecond)

	snap := e.Snapshot(true)
	if p := proxyCounters(snap, "p1"); p.GetConnsTotal() != 1 {
		t.Errorf("counters of p1 %v: want the one connection of the public listener", p)
	}
	if p := proxyCounters(snap, "p3"); p.GetConnsTotal() != 0 || p.GetConnsActive() != 0 {
		t.Errorf("counters of p3 %v: a probe route is counted", p)
	}

	// Without the probe routes the test listener mirrors the listener again.
	cfg.Generation = 2
	cfg.ProbeRoutes = nil
	mustApply(t, e, cfg)
	openRelay(t, "", loopback(testPort), "proxy.example.com", serving)
	starting.expectNone(t, 50*time.Millisecond)
}

func TestRelayHalfClose(t *testing.T) {
	checkGoroutines(t)

	t.Run("client ends first", func(t *testing.T) {
		port := freePort(t)
		be := newBackend(t, true, func(bc *backendConn) {
			b, _ := io.ReadAll(bc.r) // until the client's end of stream comes through
			_, _ = fmt.Fprintf(bc.conn, "got %d bytes", len(b))
		})
		e := newTestEdge(t, Options{})
		mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))
		c := dialEdge(t, "", loopback(port))
		send(t, c, append(helloRecord("proxy.example.com"), "abc"...))
		be.next(t)
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if got := readToEOF(t, c, 5*time.Second); string(got) != "got 3 bytes" {
			t.Fatalf("answer after the half-close: %q", got)
		}
	})

	t.Run("backend ends first", func(t *testing.T) {
		got := make(chan string, 1)
		be := newBackend(t, true, func(bc *backendConn) {
			_, _ = bc.conn.Write([]byte("bye"))
			_ = bc.conn.(*net.TCPConn).CloseWrite()
			b, _ := io.ReadAll(bc.r)
			got <- string(b)
		})
		e := newTestEdge(t, Options{})
		port := freePort(t)
		mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))
		c := dialEdge(t, "", loopback(port))
		send(t, c, helloRecord("proxy.example.com"))
		be.next(t)
		if b := readToEOF(t, c, 5*time.Second); string(b) != "bye" {
			t.Fatalf("got %q before the end of stream, want %q", b, "bye")
		}
		send(t, c, []byte("late"))
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		select {
		case s := <-got:
			if s != "late" {
				t.Fatalf("the backend got %q after its half-close, want %q", s, "late")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the backend did not see the end of the client's stream")
		}
	})
}

func TestRelayIdleTimeout(t *testing.T) {
	checkGoroutines(t)
	const idle = 300 * time.Millisecond
	be := newBackend(t, true, nil) // the test plays the backend
	port := freePort(t)
	e := newTestEdge(t, Options{IdleTimeout: idle})
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))

	open := func() (net.Conn, *backendConn) {
		c := dialEdge(t, "", loopback(port))
		send(t, c, helloRecord("proxy.example.com"))
		return c, be.next(t)
	}
	// expectBothClosed checks that both ends are closed within a margin of the
	// idle timeout counted from last, the time of the last byte.
	expectBothClosed := func(c net.Conn, bc *backendConn, last time.Time) {
		t.Helper()
		expectClosed(t, c, 3*time.Second)
		if d := time.Since(last); d < idle-50*time.Millisecond {
			t.Errorf("closed %v after the last byte, before the idle timeout of %v", d, idle)
		}
		_ = bc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if b, err := io.ReadAll(bc.r); err != nil || len(b) > 0 {
			t.Errorf("backend side: %q, %v; want a clean end of stream", b, err)
		}
	}

	t.Run("silent from the start", func(t *testing.T) {
		c, bc := open()
		expectBothClosed(c, bc, time.Now())
	})

	t.Run("downstream traffic keeps it open", func(t *testing.T) {
		c, bc := open()
		var last time.Time
		for range 10 { // a second in all, more than three idle timeouts
			if _, err := bc.conn.Write([]byte{'d'}); err != nil {
				t.Fatal(err)
			}
			readN(t, c, 1)
			last = time.Now()
			time.Sleep(idle / 3)
		}
		expectBothClosed(c, bc, last)
	})

	t.Run("upstream traffic keeps it open", func(t *testing.T) {
		c, bc := open()
		var last time.Time
		for range 10 {
			send(t, c, []byte{'u'})
			_ = bc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(bc.r, make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			last = time.Now()
			time.Sleep(idle / 3)
		}
		expectBothClosed(c, bc, last)
	})
}

func TestHelloReadIsBuffered(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))
	tbl := e.table.Load()
	l := tbl.listeners[loopback(port)]

	// Serve one connection by hand, through a connection that counts the reads.
	srv, cli := tcpPair(t)
	cc := &countingConn{Conn: srv}
	f := e.conns.add(cc)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer e.conns.remove(f)
		tk := &ticket{helloBy: time.Now().Add(e.opts.ClientHelloTimeout)} // one that holds no place
		e.handle(tbl, loopback(port), l, f, addrPortOf(srv.RemoteAddr()), addrPortOf(srv.LocalAddr()), tk, time.Now())
	}()

	// 10.9k records of one byte each fill the 64 KiB budget: read straight off
	// the socket that is three reads per record.
	hello := tinyRecordHello("proxy.example.com", 64<<10)
	send(t, cli, append(slices.Clone(hello), "early"...))
	bc := be.next(t)
	reads := cc.reads.Load() // the relay may have one read pending by now
	if !bytes.Equal(bc.hello, hello) {
		t.Fatalf("the backend got a hello of %d bytes, want the %d sent", len(bc.hello), len(hello))
	}
	if got := readN(t, cli, len("early")); string(got) != "early" {
		t.Fatalf("the bytes behind the hello came back as %q", got)
	}
	if reads > 40 {
		t.Errorf("%d reads of the socket for a %d-byte hello", reads, len(hello))
	}
	t.Logf("%d reads of the socket for a hello of %d one-byte records", reads, len(hello)/6)
	_ = cli.Close()
	<-done
}

func TestTinyRecordHelloRoutes(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))

	hello := tinyRecordHello("proxy.example.com", 64<<10)
	c := dialEdge(t, "", loopback(port))
	send(t, c, hello)
	if bc := be.next(t); !bytes.Equal(bc.hello, hello) {
		t.Fatalf("the backend got a hello of %d bytes, want the %d sent", len(bc.hello), len(hello))
	}
	roundTrip(t, c, "after many records")
	waitFor(t, "the bytes to be counted", func() bool {
		return proxyCounters(e.Snapshot(true), "p1").GetBytesUp() == uint64(len(hello)+len("after many records"))
	})
}

func TestPanicInHandlerIsContained(t *testing.T) {
	checkGoroutines(t)
	log, buf := captureLogger(slog.LevelInfo)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdgeLog(t, log, Options{DialMask: func(context.Context, string) (net.Conn, error) {
		panic("the mask dialer exploded")
	}})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", be.addr)
	cfg.Listeners[0].MaskTarget = "mask.example.com:443"
	mustApply(t, e, cfg)

	c := dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("other.example.com"))
	expectClosed(t, c, 5*time.Second)
	// The connection is closed on the way out of the panic, before it is logged.
	waitFor(t, "the panic to be logged", func() bool { return strings.Contains(buf.String(), "panic while serving") })
	out := buf.String()
	if !strings.Contains(out, "the mask dialer exploded") || !strings.Contains(out, "goroutine") {
		t.Errorf("the panic and its stack are not in the log:\n%s", out)
	}
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("the panic is not logged as an error:\n%s", out)
	}

	// The edge lives on, and the connection was let go of (Drain does not wait for it).
	openRelay(t, "", loopback(port), "proxy.example.com", be)
	waitFor(t, "the masked slot to be given back", func() bool { return e.masked.Load() == 0 })
}

func TestRelayPanicIsContained(t *testing.T) {
	checkGoroutines(t)
	log, buf := captureLogger(slog.LevelInfo)
	e := New(log, Options{})
	edgeSide, client := tcpPair(t)
	upstream, backendSide := tcpPair(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.relay(edgeSide, upstream, func(int) { panic("the counter exploded") }, nil)
	}()
	send(t, client, []byte("x")) // the upward copy counts it, and panics
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not end after the panic")
	}
	if got := readToEOF(t, backendSide, 5*time.Second); string(got) != "x" {
		t.Errorf("the backend got %q", got)
	}
	expectClosed(t, client, 5*time.Second)
	if out := buf.String(); !strings.Contains(out, "the counter exploded") {
		t.Errorf("the panic is not in the log:\n%s", out)
	}
}

func TestRelayOutlivesHelloTimeout(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{ClientHelloTimeout: 200 * time.Millisecond})
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))

	c := openRelay(t, "", loopback(port), "proxy.example.com", be)
	time.Sleep(500 * time.Millisecond) // silent for longer than the hello may take
	roundTrip(t, c, "the hello deadline is gone")
}

// failingListener is a net.Listener whose Accept fails, as it does when the
// process runs out of descriptors, until it is closed.
type failingListener struct {
	calls  atomic.Int32
	closed chan struct{}
	once   sync.Once
}

func (f *failingListener) Accept() (net.Conn, error) {
	select {
	case <-f.closed:
		return nil, net.ErrClosed
	default:
	}
	f.calls.Add(1)
	return nil, &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept4", syscall.EMFILE)}
}

func (f *failingListener) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *failingListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(loopback(1)) }

func TestAcceptBacksOff(t *testing.T) {
	checkGoroutines(t)
	log, buf := captureLogger(slog.LevelInfo)
	e := New(log, Options{})
	fl := &failingListener{closed: make(chan struct{})}
	l := &listener{addr: loopback(1), ln: fl, stop: make(chan struct{}), done: make(chan struct{})}
	go e.serve(l)
	time.Sleep(500 * time.Millisecond)
	l.close() // returns once serve has

	// Waits of 5, 10, 20, 40, 80, 160, 320 ms: some seven tries in half a
	// second, not thousands, and the listener is not given up.
	if n := fl.calls.Load(); n < 3 || n > 12 {
		t.Errorf("Accept tried %d times in 500 ms", n)
	}
	if n := strings.Count(buf.String(), "accept failed"); n != 1 {
		t.Errorf("%d warnings about the failures, want 1:\n%s", n, buf)
	}
}

func TestBackendUnreachable(t *testing.T) {
	checkGoroutines(t)
	port, dead := freePort(t), freePort(t) // nothing listens on dead
	e := newTestEdge(t, Options{})
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", loopback(dead)))

	c := dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("proxy.example.com"))
	expectClosed(t, c, 5*time.Second) // closed, and no alert: the name is known

	waitFor(t, "the connection to end", func() bool { return activeConns(e, "p1") == 0 })
	p := proxyCounters(e.Snapshot(true), "p1")
	if p.GetConnsTotal() != 1 || len(p.GetBackendActive()) != 0 {
		t.Fatalf("counters %v, want one connection in all and no backend active", p)
	}
}
