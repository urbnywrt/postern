package edge

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// limitedRoute is oneRoute with limits on the route.
func limitedRoute(gen uint64, port uint32, be *backend, lim *edgev1.EdgeLimits) *edgev1.EdgeConfig {
	cfg := oneRoute(gen, port, "reject", "proxy.example.com", be.addr)
	cfg.Routes[0].Limits = lim
	return cfg
}

// expectRefused connects from the address from with a hello for the route and
// checks that the connection is treated as a stranger: the alert of reject.
func expectRefused(t *testing.T, from string, port uint32) {
	t.Helper()
	expectRefusedAt(t, from, loopback(port))
}

func expectRefusedAt(t *testing.T, from string, to netip.AddrPort) {
	t.Helper()
	c := dialEdge(t, from, to)
	send(t, c, helloRecord("proxy.example.com"))
	expectAlert(t, c)
}

func TestConnsPerIPLimit(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, limitedRoute(1, port, be, &edgev1.EdgeLimits{ConnsPerIp: 2}))

	a1 := openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	expectRefused(t, "127.0.0.2", port)
	openRelay(t, "127.0.0.3", loopback(port), "proxy.example.com", be) // another IP has its own allowance

	if got := proxyCounters(e.Snapshot(true), "p1").GetConnsTotal(); got != 3 {
		t.Errorf("conns_total %d, want 3: a refused connection is not counted", got)
	}

	_ = a1.Close()
	waitFor(t, "the first connection to end", func() bool { return activeConns(e, "p1") == 2 })
	openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	expectRefused(t, "127.0.0.2", port)
}

func TestConnsTotalLimit(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, limitedRoute(1, port, be, &edgev1.EdgeLimits{ConnsTotal: 2}))

	a := openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	openRelay(t, "127.0.0.3", loopback(port), "proxy.example.com", be)
	expectRefused(t, "127.0.0.4", port)
	expectRefused(t, "127.0.0.2", port)

	_ = a.Close()
	waitFor(t, "a connection to end", func() bool { return activeConns(e, "p1") == 1 })
	openRelay(t, "127.0.0.4", loopback(port), "proxy.example.com", be)
	expectRefused(t, "127.0.0.5", port)

	// A new limit applies to the connections that come next.
	mustApply(t, e, limitedRoute(2, port, be, &edgev1.EdgeLimits{ConnsTotal: 3}))
	openRelay(t, "127.0.0.5", loopback(port), "proxy.example.com", be)
	expectRefused(t, "127.0.0.6", port)
}

func TestLimitsSharedByRoutesOfOneProxy(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port, port2 := freePort(t), freePort(t)
	e := newTestEdge(t, Options{})
	lim := &edgev1.EdgeLimits{ConnsTotal: 1}
	mustApply(t, e, &edgev1.EdgeConfig{
		Generation: 1,
		Listeners:  []*edgev1.EdgeListener{tlsListener("l1", port, "reject"), tlsListener("l2", port2, "reject")},
		Routes: []*edgev1.Route{
			{ListenerId: "l1", Sni: "a.example.com", ProxyId: "p1", Kind: "engine", Backend: be.addr.String(), ProxyProtocol: true, Limits: lim},
			{ListenerId: "l2", Sni: "b.example.com", ProxyId: "p1", Kind: "engine", Backend: be.addr.String(), ProxyProtocol: true, Limits: lim},
			{ListenerId: "l1", Sni: "c.example.com", ProxyId: "p2", Kind: "engine", Backend: be.addr.String(), ProxyProtocol: true, Limits: lim},
		},
	})

	openRelay(t, "127.0.0.2", loopback(port), "a.example.com", be)
	c := dialEdge(t, "127.0.0.3", loopback(port2))
	send(t, c, helloRecord("b.example.com"))
	expectAlert(t, c)
	openRelay(t, "127.0.0.3", loopback(port), "c.example.com", be) // another proxy
}

func TestOverLimitTakesStrangerPath(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	site := newBackend(t, false, echoHandler)
	md := newMaskDialer(site.addr)
	port := freePort(t)
	e := newTestEdge(t, Options{DialMask: md.dial, Resolver: resolverOf("proxy.example.com", "203.0.113.30")})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", be.addr)
	cfg.Routes[0].Limits = &edgev1.EdgeLimits{ConnsTotal: 1}
	cfg.MaskDomains = []string{"proxy.example.com"} // the proxy's own domain is in the pool
	mustApply(t, e, cfg)

	openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	hello := helloRecord("proxy.example.com")
	c := dialEdge(t, "127.0.0.3", loopback(port))
	send(t, c, hello)
	if got := md.target(t); got != "203.0.113.30:443" {
		t.Fatalf("DialMask(%q), want 203.0.113.30:443, the address of proxy.example.com", got)
	}
	if bc := site.next(t); !bytes.Equal(bc.hello, hello) {
		t.Fatal("the mask target did not get the hello")
	}
	roundTrip(t, c, "masked, not relayed")
	be.expectNone(t, 100*time.Millisecond)
}

func TestDevicesLimitWithIdleWindow(t *testing.T) {
	checkGoroutines(t)
	clk := newFakeClock()
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{Now: clk.Now})
	mustApply(t, e, limitedRoute(1, port, be, &edgev1.EdgeLimits{Devices: 1})) // window: the default 120 s

	devices := func() uint32 { return proxyCounters(e.Snapshot(true), "p1").GetDevicesActive() }

	a1 := openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	expectRefused(t, "127.0.0.3", port)                                      // a second device
	a2 := openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be) // the device opens more connections
	if d := devices(); d != 1 {
		t.Fatalf("devices_active %d, want 1", d)
	}

	_ = a1.Close()
	_ = a2.Close()
	waitFor(t, "the connections to end", func() bool { return activeConns(e, "p1") == 0 })

	// 127.0.0.2 stays a device for 120 s after its last connection ended.
	clk.Advance(119 * time.Second)
	expectRefused(t, "127.0.0.3", port)
	if d := devices(); d != 1 {
		t.Fatalf("devices_active %d 119 s after the last connection, want 1", d)
	}
	clk.Advance(time.Second)
	if d := devices(); d != 0 {
		t.Fatalf("devices_active %d 120 s after the last connection, want 0", d)
	}
	b := openRelay(t, "127.0.0.3", loopback(port), "proxy.example.com", be)
	expectRefused(t, "127.0.0.2", port) // now 127.0.0.3 is the device

	// The window comes from the configuration.
	cfg := limitedRoute(2, port, be, &edgev1.EdgeLimits{Devices: 1})
	cfg.DeviceIdleSeconds = 30
	mustApply(t, e, cfg)
	_ = b.Close()
	waitFor(t, "the connection to end", func() bool { return activeConns(e, "p1") == 0 })
	clk.Advance(29 * time.Second)
	expectRefused(t, "127.0.0.2", port)
	clk.Advance(time.Second)
	openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)

	// Without a device limit any number of devices is let in, and counted.
	mustApply(t, e, limitedRoute(3, port, be, nil))
	for _, from := range []string{"127.0.0.3", "127.0.0.4", "127.0.0.5"} {
		openRelay(t, from, loopback(port), "proxy.example.com", be)
	}
	if d := devices(); d != 4 {
		t.Fatalf("devices_active %d, want 4", d)
	}
}
