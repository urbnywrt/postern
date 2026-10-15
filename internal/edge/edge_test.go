package edge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

func TestDefaults(t *testing.T) {
	e := New(nil, Options{})
	if e.log == nil {
		t.Error("nil logger not replaced")
	}
	o := e.opts
	if o.ClientHelloTimeout != 10*time.Second || o.IdleTimeout != 15*time.Minute || o.DialTimeout != 4*time.Second ||
		o.MaxClientHello != 65536 || o.MaxMasked != 256 || o.Now == nil || o.DialMask == nil {
		t.Errorf("defaults %+v", o)
	}
	if o.Resolver != Resolver(net.DefaultResolver) {
		t.Errorf("the default resolver is %v, want the one of the system", o.Resolver)
	}
	if o.CertsDir != "/opt/postern/data/certs" {
		t.Errorf("the default certificate directory is %q, want the one of the edge container", o.CertsDir)
	}
	// The caps on connections come from the limits of the process.
	memory, _ := systemMemory()
	derived := deriveCaps(openFileLimit(), memory)
	preHello, conns := derived.preHello, derived.conns
	if o.MaxPreHello != preHello || o.MaxConns != conns {
		t.Errorf("caps %d before the hello and %d in all, want %d and %d", o.MaxPreHello, o.MaxConns, preHello, conns)
	}
	e = New(nil, Options{ClientHelloTimeout: -1, IdleTimeout: -1, DialTimeout: -1, MaxClientHello: -1, MaxMasked: -1,
		MaxPreHello: -1, MaxConns: -1})
	o = e.opts
	if o.ClientHelloTimeout != 10*time.Second || o.IdleTimeout != 15*time.Minute || o.DialTimeout != 4*time.Second ||
		o.MaxClientHello != 65536 || o.MaxMasked != 256 || o.MaxPreHello != preHello || o.MaxConns != conns {
		t.Errorf("negative options not replaced by the defaults: %+v", o)
	}
	if g := e.ingress; g.maxPreHello != preHello || g.maxConns != conns || g.hello != 10*time.Second || g.fastHello != 3*time.Second {
		t.Errorf("the caps in effect: %d before the hello, %d in all, %v and %v for the hello", g.maxPreHello, g.maxConns, g.hello, g.fastHello)
	}
	if e.Generation() != 0 || len(e.Bound()) != 0 {
		t.Errorf("a new edge has generation %d and is bound to %v", e.Generation(), e.Bound())
	}
	if s := e.Snapshot(true); s.GetGeneration() != 0 || len(s.GetProxies()) != 0 || len(s.GetIps()) != 0 ||
		s.GetRefusedPrehello() != 0 || s.GetRefusedTotal() != 0 || s.GetEvictedPrehello() != 0 {
		t.Errorf("snapshot of a new edge: %v", s)
	}

	// The default DialMask is a plain TCP dial.
	site := newRawServer(t)
	c, err := e.opts.DialMask(context.Background(), site.addr.String())
	if err != nil {
		t.Fatalf("default DialMask: %v", err)
	}
	_ = c.Close()
	site.next(t)
}

func TestLogLimiter(t *testing.T) {
	l := newLogLimiter(10 * time.Second)
	t0 := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for _, step := range []struct {
		key  string
		at   time.Duration
		want bool
	}{
		{"a", 0, true},
		{"a", time.Second, false},
		{"b", time.Second, true}, // keys are apart
		{"a", 9 * time.Second, false},
		{"a", 10 * time.Second, true},
		{"a", 15 * time.Second, false},
		{"a", -time.Hour, true}, // a clock that went back does not silence a key for good
	} {
		if got := l.allow(step.key, t0.Add(step.at)); got != step.want {
			t.Errorf("allow(%q, t0%+v) = %v, want %v", step.key, step.at, got, step.want)
		}
	}
}

func TestApplySwapsTableKeepsConnections(t *testing.T) {
	checkGoroutines(t)
	beA := newBackend(t, true, echoHandler)
	beB := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", beA.addr))
	old := openRelay(t, "", loopback(port), "proxy.example.com", beA)

	mustApply(t, e, oneRoute(2, port, "reject", "proxy.example.com", beB.addr))
	if g := e.Generation(); g != 2 {
		t.Fatalf("generation %d, want 2", g)
	}
	if got, want := e.Bound(), []string{loopback(port).String()}; !slices.Equal(got, want) {
		t.Fatalf("bound %v, want %v", got, want)
	}

	roundTrip(t, old, "still through the old backend")
	openRelay(t, "", loopback(port), "proxy.example.com", beB)
	beA.expectNone(t, 100*time.Millisecond)

	want := map[string]uint32{beA.addr.String(): 1, beB.addr.String(): 1}
	if got := proxyCounters(e.Snapshot(true), "p1").GetBackendActive(); !maps.Equal(got, want) {
		t.Errorf("backend_active %v, want %v", got, want)
	}
	_ = old.Close()
	waitFor(t, "the old backend to be idle", func() bool {
		_, busy := proxyCounters(e.Snapshot(true), "p1").GetBackendActive()[beA.addr.String()]
		return !busy
	})

	// A route removed (a paused proxy) makes its name a stranger at once.
	mustApply(t, e, &edgev1.EdgeConfig{Generation: 3, Listeners: []*edgev1.EdgeListener{tlsListener("l1", port, "reject")}})
	c := dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("proxy.example.com"))
	expectAlert(t, c)
}

func TestDrainWaitsForConnections(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)

	t.Run("waits for the last connection", func(t *testing.T) {
		port := freePort(t)
		e := newTestEdge(t, Options{})
		mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))
		c := openRelay(t, "", loopback(port), "proxy.example.com", be)

		errc := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			errc <- e.Drain(ctx)
		}()
		waitFor(t, "the listeners to close", func() bool { return len(e.Bound()) == 0 })
		if conn, err := net.DialTimeout("tcp4", loopback(port).String(), time.Second); err == nil {
			_ = conn.Close()
			t.Fatal("a drained edge accepts connections")
		}
		select {
		case err := <-errc:
			t.Fatalf("Drain returned %v while a connection was open", err)
		case <-time.After(200 * time.Millisecond):
		}
		roundTrip(t, c, "served while draining")

		_ = c.Close()
		select {
		case err := <-errc:
			if err != nil {
				t.Fatalf("Drain: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Drain did not return after the last connection ended")
		}
		if err := e.Apply(oneRoute(2, port, "reject", "proxy.example.com", be.addr)); err == nil {
			t.Fatal("Apply succeeded after Drain")
		}
		if len(e.Bound()) != 0 {
			t.Fatalf("bound %v after a refused Apply", e.Bound())
		}
	})

	t.Run("counts connections still reading their hello", func(t *testing.T) {
		port := freePort(t)
		e := newTestEdge(t, Options{ClientHelloTimeout: 300 * time.Millisecond})
		mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))
		c := dialEdge(t, "", loopback(port))
		time.Sleep(50 * time.Millisecond) // let the edge accept it
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := e.Drain(ctx); err != nil {
			t.Fatalf("Drain: %v", err)
		}
		if d := time.Since(start); d < 200*time.Millisecond {
			t.Errorf("Drain returned after %v, before the silent client was given up on", d)
		}
		expectClosed(t, c, time.Second)
	})

	t.Run("gives up at the deadline and closes what is left", func(t *testing.T) {
		port := freePort(t)
		e := newTestEdge(t, Options{})
		mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))
		c := openRelay(t, "", loopback(port), "proxy.example.com", be)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if err := e.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Drain: %v, want the deadline", err)
		}
		expectClosed(t, c, 2*time.Second)
		// Draining again finds nothing left.
		waitFor(t, "the connections to end", func() bool { return activeConns(e, "p1") == 0 })
		if err := e.Drain(context.Background()); err != nil {
			t.Fatalf("second Drain: %v", err)
		}
	})

	t.Run("stops a drop delay", func(t *testing.T) {
		port := freePort(t)
		e := newTestEdge(t, Options{})
		e.dropDelay = func() time.Duration { return time.Hour }
		mustApply(t, e, oneRoute(1, port, "drop", "proxy.example.com", be.addr))
		c := dialEdge(t, "", loopback(port))
		send(t, c, helloRecord("other.example.com"))
		time.Sleep(50 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if err := e.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Drain: %v, want the deadline", err)
		}
		expectClosed(t, c, 2*time.Second)
	})
}

func TestReuseportTwoEdgesSamePort(t *testing.T) {
	if !reusePort {
		t.Skip("SO_REUSEPORT is not supported on this platform")
	}
	checkGoroutines(t)
	beA := newBackend(t, true, echoHandler)
	beB := newBackend(t, true, echoHandler)
	port := freePort(t)
	eA := newTestEdge(t, Options{})
	eB := newTestEdge(t, Options{})
	mustApply(t, eA, oneRoute(1, port, "reject", "proxy.example.com", beA.addr))
	mustApply(t, eB, oneRoute(1, port, "reject", "proxy.example.com", beB.addr))
	want := []string{loopback(port).String()}
	if !slices.Equal(eA.Bound(), want) || !slices.Equal(eB.Bound(), want) {
		t.Fatalf("bound %v and %v, want %v for both", eA.Bound(), eB.Bound(), want)
	}

	// The kernel spreads the connections over both edges.
	byA, byB := 0, 0
	for range 40 {
		c := dialEdge(t, "", loopback(port))
		send(t, c, helloRecord("proxy.example.com"))
		select {
		case <-beA.accepted:
			byA++
		case <-beB.accepted:
			byB++
		case <-time.After(5 * time.Second):
			t.Fatal("no backend got the connection")
		}
		_ = c.Close()
	}
	if byA == 0 || byB == 0 {
		t.Fatalf("connections served: %d by one edge, %d by the other; want both to serve", byA, byB)
	}

	// The edge that drains leaves the port to the other: a hand-over.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := eA.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	for range 10 {
		openRelay(t, "", loopback(port), "proxy.example.com", beB)
	}
	beA.expectNone(t, 100*time.Millisecond)
}

func TestListenerFamilies(t *testing.T) {
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback here: %v", err)
	}
	_ = probe.Close()
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freeDualPort(t)
	e := newTestEdge(t, Options{})
	v4 := &edgev1.EdgeListener{Id: "v4", BindIp: "0.0.0.0", Port: port, Kind: "tls", StrangerAction: "reject", NonTlsAction: "drop"}
	mustApply(t, e, &edgev1.EdgeConfig{Generation: 1, Listeners: []*edgev1.EdgeListener{v4}})

	// 0.0.0.0 is IPv4 only: an IPv6-only socket without SO_REUSEPORT can still
	// take the port. (Go's "tcp" network would have made it dual-stack.)
	other, err := net.Listen("tcp6", net.JoinHostPort("::", fmt.Sprint(port)))
	if err != nil {
		t.Fatalf("the IPv4 listener took IPv6 too: %v", err)
	}
	_ = other.Close()

	// [::] is a listener of its own, next to 0.0.0.0, for IPv6 only.
	v6 := &edgev1.EdgeListener{Id: "v6", BindIp: "::", Port: port, Kind: "tls", StrangerAction: "reject", NonTlsAction: "drop"}
	mustApply(t, e, &edgev1.EdgeConfig{
		Generation: 2,
		Listeners:  []*edgev1.EdgeListener{v4, v6},
		Routes:     []*edgev1.Route{engineRoute("v6", "proxy.example.com", "p1", be.addr)},
	})
	want := []string{"0.0.0.0:" + fmt.Sprint(port), "[::]:" + fmt.Sprint(port)}
	if got := e.Bound(); !slices.Equal(got, want) {
		t.Fatalf("bound %v, want %v", got, want)
	}

	// An IPv6 client is relayed with an IPv6 PROXY header.
	conn, err := net.DialTimeout("tcp6", net.JoinHostPort("::1", fmt.Sprint(port)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c := conn.(*net.TCPConn)
	t.Cleanup(func() { _ = c.Close() })
	send(t, c, helloRecord("proxy.example.com"))
	bc := be.next(t)
	if bc.header.Src != clientAddr(c) || bc.header.Dst.String() != "[::1]:"+fmt.Sprint(port) {
		t.Errorf("PROXY header %v -> %v, want %v -> [::1]:%d", bc.header.Src, bc.header.Dst, clientAddr(c), port)
	}
	roundTrip(t, c, "over IPv6")

	// The IPv4 listener has no route: an IPv4 client of the same port is a stranger.
	s := dialEdge(t, "", loopback(port))
	send(t, s, helloRecord("proxy.example.com"))
	expectAlert(t, s)
}

func TestLogPrivacy(t *testing.T) {
	checkGoroutines(t)
	const client = "127.0.0.7"
	evil := "evil\x00name.example\xff"

	run := func(t *testing.T, level slog.Level) string {
		log, buf := captureLogger(level)
		be := newBackend(t, true, echoHandler)
		site := newBackend(t, false, echoHandler)
		md := newMaskDialer(site.addr)
		port, dead := freePort(t), freePort(t)
		e := newTestEdgeLog(t, log, Options{DialMask: md.dial, Resolver: resolverOf("pool.example.com", "203.0.113.10")})
		cfg := oneRoute(1, port, "mask", "proxy.example.com", be.addr)
		cfg.Routes = append(cfg.Routes, engineRoute("l1", "dead.example.com", "p2", loopback(dead)))
		cfg.MaskDomains = []string{"pool.example.com"}
		cfg.Routes[0].Limits = &edgev1.EdgeLimits{ConnsTotal: 1}
		mustApply(t, e, cfg)

		openRelay(t, client, loopback(port), "proxy.example.com", be) // relayed
		c := dialEdge(t, client, loopback(port))                      // over the limit: rejected
		send(t, c, helloRecord("proxy.example.com"))
		expectAlert(t, c)
		c = dialEdge(t, client, loopback(port)) // invalid name: rejected
		send(t, c, helloRecord(evil))
		expectAlert(t, c)
		c = dialEdge(t, client, loopback(port)) // masked
		send(t, c, helloRecord("pool.example.com"))
		md.target(t)
		site.next(t)
		c = dialEdge(t, client, loopback(port)) // backend down
		send(t, c, helloRecord("dead.example.com"))
		expectClosed(t, c, 5*time.Second)
		c = dialEdge(t, client, loopback(port)) // not TLS
		send(t, c, []byte("GET / HTTP/1.1\r\n\r\n"))
		expectClosed(t, c, 5*time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_ = e.Drain(ctx)
		return buf.String()
	}

	t.Run("info", func(t *testing.T) {
		out := run(t, slog.LevelInfo)
		if strings.Contains(out, client) {
			t.Errorf("a client address is in the log at info level:\n%s", out)
		}
		if !strings.Contains(out, loopback(0).Addr().String()) || !strings.Contains(out, "dead.example.com") {
			t.Errorf("the log lacks the listener and the unreachable backend; is it captured?\n%s", out)
		}
		if strings.Contains(out, "evil") {
			t.Errorf("an invalid server name is in the log:\n%s", out)
		}
	})
	t.Run("debug", func(t *testing.T) {
		out := run(t, slog.LevelDebug)
		if !strings.Contains(out, client) {
			t.Errorf("no client address in the debug log:\n%s", out)
		}
		if strings.Contains(out, "evil") || strings.ContainsRune(out, 0) {
			t.Errorf("an invalid server name is in the log:\n%s", out)
		}
	})
}
