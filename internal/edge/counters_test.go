package edge

import (
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"google.golang.org/protobuf/proto"
)

func TestCountersAccumulate(t *testing.T) {
	checkGoroutines(t)
	clk := newFakeClock()
	t0 := clk.Now()
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{Now: clk.Now})
	cfg := &edgev1.EdgeConfig{
		Generation: 1,
		Listeners:  []*edgev1.EdgeListener{tlsListener("l1", port, "reject")},
		Routes: []*edgev1.Route{
			engineRoute("l1", "a.example.com", "p1", be.addr),
			engineRoute("l1", "b.example.com", "p1", be.addr),
			engineRoute("l1", "c.example.com", "p2", be.addr),
		},
	}
	mustApply(t, e, cfg)

	// Every routed proxy is listed, before it has had a connection.
	s := e.Snapshot(true)
	if s.GetGeneration() != 1 || s.GetTsUnixNano() != t0.UnixNano() {
		t.Fatalf("generation %d, ts %d; want 1, %d", s.GetGeneration(), s.GetTsUnixNano(), t0.UnixNano())
	}
	for _, id := range []string{"p1", "p2"} {
		want := &edgev1.ProxyCounters{ProxyId: id}
		if got := proxyCounters(s, id); !proto.Equal(got, want) {
			t.Fatalf("counters of %s before any connection: %v, want %v", id, got, want)
		}
	}

	helloA, helloB := helloRecord("a.example.com"), helloRecord("b.example.com")
	c1 := dialEdge(t, "127.0.0.2", loopback(port))
	send(t, c1, helloA)
	be.next(t)
	roundTrip(t, c1, "hello world")
	clk.Advance(10 * time.Second)
	c2 := dialEdge(t, "127.0.0.3", loopback(port))
	send(t, c2, helloB)
	be.next(t)
	roundTrip(t, c2, "abc")

	up := uint64(len(helloA) + len("hello world") + len(helloB) + len("abc"))
	down := uint64(len("hello world") + len("abc"))
	bytesFlowed := func() bool {
		p := proxyCounters(e.Snapshot(true), "p1")
		return p.GetBytesUp() == up && p.GetBytesDown() == down
	}
	waitFor(t, "the bytes to be counted", bytesFlowed)

	s = e.Snapshot(true)
	p := proxyCounters(s, "p1")
	if p.GetConnsTotal() != 2 || p.GetConnsActive() != 2 || p.GetDevicesActive() != 2 {
		t.Errorf("p1 with two open connections: %v", p)
	}
	if want := map[string]uint32{be.addr.String(): 2}; !maps.Equal(p.GetBackendActive(), want) {
		t.Errorf("backend_active %v, want %v", p.GetBackendActive(), want)
	}
	now := clk.Now().Unix()
	for _, want := range []*edgev1.IpCounters{
		{ProxyId: "p1", Ip: "127.0.0.2", ConnsActive: 1, LastSeenUnix: now, Bytes: uint64(len(helloA) + 2*len("hello world"))},
		{ProxyId: "p1", Ip: "127.0.0.3", ConnsActive: 1, LastSeenUnix: now, Bytes: uint64(len(helloB) + 2*len("abc"))},
	} {
		if got := ipCounters(s, "p1", want.Ip); !proto.Equal(got, want) {
			t.Errorf("IP counters %v, want %v", got, want)
		}
	}
	if got := proxyCounters(s, "p2"); !proto.Equal(got, &edgev1.ProxyCounters{ProxyId: "p2"}) {
		t.Errorf("p2 had no connection: %v", got)
	}

	// The connections end; what they moved stays counted.
	_ = c1.Close()
	_ = c2.Close()
	waitFor(t, "the connections to end", func() bool { return activeConns(e, "p1") == 0 })
	closed := clk.Now()
	clk.Advance(5 * time.Second)

	check := func(when string, gen uint64, devices uint32) {
		t.Helper()
		s := e.Snapshot(true)
		if s.GetGeneration() != gen || s.GetTsUnixNano() != clk.Now().UnixNano() {
			t.Errorf("%s: generation %d, ts %d; want %d, %d", when, s.GetGeneration(), s.GetTsUnixNano(), gen, clk.Now().UnixNano())
		}
		want := &edgev1.ProxyCounters{ProxyId: "p1", BytesUp: up, BytesDown: down, ConnsTotal: 2, DevicesActive: devices}
		if got := proxyCounters(s, "p1"); !proto.Equal(got, want) {
			t.Errorf("%s: p1 %v, want %v", when, got, want)
		}
	}
	check("after the connections ended", 1, 2)
	s = e.Snapshot(true)
	if got := s.GetIps(); len(got) != 2 || got[0].GetIp() != "127.0.0.2" || got[1].GetIp() != "127.0.0.3" {
		t.Fatalf("IP counters %v, want 127.0.0.2 then 127.0.0.3", got)
	}
	for _, ip := range s.GetIps() {
		if ip.GetConnsActive() != 0 || ip.GetLastSeenUnix() != closed.Unix() {
			t.Errorf("IP counters %v, want no connection and last seen at %d", ip, closed.Unix())
		}
	}

	// Counters survive Apply, even of a configuration without the proxy.
	cfg.Generation = 2
	mustApply(t, e, cfg)
	check("after Apply", 2, 2)
	mustApply(t, e, &edgev1.EdgeConfig{Generation: 3, Listeners: cfg.Listeners})
	check("after Apply without the routes", 3, 2)

	// The devices leave with the idle window, the IPs some minutes later.
	clk.Advance(115 * time.Second) // 120 s after the end of the connections
	check("after the device window", 3, 0)
	if n := len(e.Snapshot(true).GetIps()); n != 2 {
		t.Fatalf("%d IP entries right after the device window, want 2", n)
	}
	clk.Advance(3 * time.Minute) // 5 min after the end of the connections
	check("after the IP retention", 3, 0)
	if ips := e.Snapshot(true).GetIps(); len(ips) != 0 {
		t.Fatalf("IP entries 5 min after their last connection: %v", ips)
	}
}

// The counters of the client IPs come only when they are asked for: the agent
// asks for them only when the IP policy of the node keeps client addresses, and
// they are the bulk of a snapshot (M4). The counters of the proxies come either
// way.
func TestSnapshotLeavesTheIPsOutUnlessAsked(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))
	c := openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	roundTrip(t, c, "counted")

	without := e.Snapshot(false)
	if ips := without.GetIps(); len(ips) != 0 {
		t.Errorf("IP counters without asking: %v", ips)
	}
	if p := proxyCounters(without, "p1"); p.GetConnsActive() != 1 || p.GetBytesUp() == 0 || p.GetDevicesActive() != 1 {
		t.Errorf("proxy counters without the IPs = %v, want the connection counted", p)
	}
	with := e.Snapshot(true)
	if ip := ipCounters(with, "p1", "127.0.0.2"); ip == nil || ip.GetConnsActive() != 1 || ip.GetBytes() == 0 {
		t.Errorf("IP counters when asked = %v, want those of 127.0.0.2", with.GetIps())
	}
}

// docIP returns the i-th address of 2001:db8::/32.
func docIP(i int) netip.Addr {
	b := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	b[12], b[13], b[14], b[15] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
	return netip.AddrFrom16(b)
}

func TestIPEntriesCapped(t *testing.T) {
	const window = 120 * time.Second
	t0 := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	t.Run("the oldest idle entries go first", func(t *testing.T) {
		p := newStatsRegistry().proxy("p1")
		var held []*lease
		for i := range 100 { // these keep a connection open throughout
			ls, _ := p.admit(docIP(i), "b", limits{}, t0, window)
			held = append(held, ls)
		}
		now := t0
		for i := 100; i < 6100; i++ { // 6000 clients come and go, 10 ms apart
			now = t0.Add(time.Duration(i) * 10 * time.Millisecond)
			ls, over := p.admit(docIP(i), "b", limits{}, now, window)
			if ls == nil {
				t.Fatalf("client %d refused (%s): the cap must not refuse anybody", i, over)
			}
			ls.release(now)
			if n := len(p.ips); n > maxIPsPerProxy {
				t.Fatalf("%d IP entries after client %d, more than %d", n, i, maxIPsPerProxy)
			}
		}
		for i := range 100 {
			if p.ips[docIP(i)] == nil {
				t.Fatalf("IP %d, which has a connection open, was dropped", i)
			}
		}
		if p.ips[docIP(6099)] == nil || p.ips[docIP(100)] != nil {
			t.Fatal("not the oldest idle entries were dropped")
		}
		// The snapshot of a full proxy stays small.
		pc, ips := p.snapshot(now, window, true)
		size := proto.Size(&edgev1.SnapshotResponse{Proxies: []*edgev1.ProxyCounters{pc}, Ips: ips})
		if size > 512<<10 {
			t.Errorf("the snapshot of one proxy takes %d bytes", size)
		}
		t.Logf("%d IP entries, %d bytes of snapshot", len(ips), size)
		for _, ls := range held {
			ls.release(now)
		}
	})

	t.Run("devices under a device limit are kept", func(t *testing.T) {
		p := newStatsRegistry().proxy("p1")
		for i := range maxIPsPerProxy - 3 { // old clients, no longer devices
			ls, _ := p.admit(docIP(i), "b", limits{}, t0, window)
			ls.release(t0)
		}
		t1 := t0.Add(window + time.Second)
		lim := limits{devices: 5}
		for _, i := range []int{10001, 10002, 10003} { // three devices
			ls, _ := p.admit(docIP(i), "b", lim, t1, window)
			ls.release(t1)
		}
		ls, over := p.admit(docIP(10004), "b", lim, t1, window) // the map is full
		if ls == nil {
			t.Fatalf("a fourth device of five refused: %s", over)
		}
		for _, i := range []int{10001, 10002, 10003, 10004} {
			if p.ips[docIP(i)] == nil {
				t.Fatalf("device %d was dropped", i)
			}
		}
		if n := len(p.ips); n > maxIPsPerProxy {
			t.Fatalf("%d IP entries, more than %d", n, maxIPsPerProxy)
		}
		if d := p.devicesLocked(t1, window); d != 4 {
			t.Fatalf("%d devices, want 4", d)
		}
	})

	t.Run("a device limit above the cap", func(t *testing.T) {
		// Devices are the newest idle IPs, so the oldest-first eviction reaches
		// them only when fewer than a batch of others are left: here 96.
		p := newStatsRegistry().proxy("p1")
		for i := range 96 {
			ls, _ := p.admit(docIP(i), "b", limits{}, t0, window)
			ls.release(t0)
		}
		t1 := t0.Add(window + time.Second)
		lim := limits{devices: 4500}
		for i := 1000; i < 1000+maxIPsPerProxy-96; i++ {
			ls, over := p.admit(docIP(i), "b", lim, t1, window)
			if ls == nil {
				t.Fatalf("device %d refused: %s", i, over)
			}
			ls.release(t1)
		}
		if ls, over := p.admit(docIP(9999), "b", lim, t1, window); ls == nil {
			t.Fatalf("a new device under the limit refused: %s", over)
		}
		if d, want := p.devicesLocked(t1, window), maxIPsPerProxy-96+1; d != want {
			t.Fatalf("%d devices, want %d: devices were forgotten", d, want)
		}
		for i := range 96 {
			if p.ips[docIP(i)] != nil {
				t.Fatalf("old IP %d kept while devices had to make room", i)
			}
		}
	})

	t.Run("entries that must stay are not refused", func(t *testing.T) {
		p := newStatsRegistry().proxy("p1")
		var held []*lease
		for i := range maxIPsPerProxy + 10 { // all with a connection open
			ls, over := p.admit(docIP(i), "b", limits{}, t0, window)
			if ls == nil {
				t.Fatalf("client %d refused (%s)", i, over)
			}
			held = append(held, ls)
		}
		if n := len(p.ips); n != maxIPsPerProxy+10 {
			t.Fatalf("%d IP entries, want %d: none may be dropped", n, maxIPsPerProxy+10)
		}
		// Once their connections end they may go again.
		for _, ls := range held {
			ls.release(t0)
		}
		p.admit(docIP(1<<20), "b", limits{}, t0, window)
		if n := len(p.ips); n > maxIPsPerProxy {
			t.Fatalf("%d IP entries after the connections ended, more than %d", n, maxIPsPerProxy)
		}
	})
}

func TestClamp32(t *testing.T) {
	type tc struct {
		in   int
		want uint32
	}
	cases := []tc{{-5, 0}, {0, 0}, {7, 7}, {math.MaxInt32, math.MaxInt32}}
	if strconv.IntSize == 64 { // only a 64-bit int can be too large
		maxU32, big := uint64(math.MaxUint32), uint64(1)<<32+5 // the low 32 bits of big are 5
		cases = append(cases, tc{int(maxU32), math.MaxUint32}, tc{int(big), math.MaxUint32}, tc{math.MaxInt, math.MaxUint32})
	}
	for _, c := range cases {
		if got := clamp32(c.in); got != c.want {
			t.Errorf("clamp32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSnapshotOrder(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	var routes []*edgev1.Route
	for _, id := range []string{"pc", "pa", "pb"} {
		routes = append(routes, engineRoute("l1", id+".example.com", id, be.addr))
	}
	mustApply(t, e, &edgev1.EdgeConfig{
		Generation: 1,
		Listeners:  []*edgev1.EdgeListener{tlsListener("l1", port, "reject")},
		Routes:     routes,
	})
	for _, c := range []struct{ from, sni string }{
		{"127.0.0.9", "pb.example.com"}, {"127.0.0.10", "pb.example.com"}, {"127.0.0.2", "pb.example.com"},
		{"127.0.0.3", "pa.example.com"},
	} {
		openRelay(t, c.from, loopback(port), c.sni, be)
	}
	s := e.Snapshot(true)
	var proxies, ips []string
	for _, p := range s.GetProxies() {
		proxies = append(proxies, p.GetProxyId())
	}
	for _, ip := range s.GetIps() {
		ips = append(ips, ip.GetProxyId()+"/"+ip.GetIp())
	}
	if want := []string{"pa", "pb", "pc"}; !slices.Equal(proxies, want) {
		t.Errorf("proxies %v, want %v", proxies, want)
	}
	if want := []string{"pa/127.0.0.3", "pb/127.0.0.2", "pb/127.0.0.9", "pb/127.0.0.10"}; !slices.Equal(ips, want) {
		t.Errorf("IPs %v, want %v", ips, want)
	}
}
