package edge

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// upstreamConfig is a configuration of one http-upstream listener on port that
// trusts the prefixes trusted, with a web route of the proxy "pu" for the Host
// name to backend.
func upstreamConfig(port uint32, name string, backend netip.AddrPort, trusted ...string) *edgev1.EdgeConfig {
	return &edgev1.EdgeConfig{
		Generation: 1,
		Listeners: []*edgev1.EdgeListener{{
			Id: "up", BindIp: "127.0.0.1", Port: port, Kind: "http-upstream",
			StrangerAction: "reject", NonTlsAction: "drop", TrustedCidrs: trusted,
		}},
		Routes: []*edgev1.Route{webRoute("up", name, "pu", backend)},
	}
}

// upstreamExchange connects to the http-upstream listener at to from the
// address from, sends req and reads the response.
func upstreamExchange(t *testing.T, from string, to netip.AddrPort, req string) *http.Response {
	t.Helper()
	c := dialEdge(t, from, to)
	return rawExchange(t, c, bufio.NewReader(c), req)
}

func TestHTTPUpstreamClosesPeersItDoesNotTrust(t *testing.T) {
	checkGoroutines(t)
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, upstreamConfig(port, "web.example.com", be.addr, "127.0.0.2/32", "fd00::/8"))
	if got, want := e.Bound(), []string{loopback(port).String()}; !slices.Equal(got, want) {
		t.Fatalf("bound %v, want %v: an http-upstream listener is bound", got, want)
	}

	c := dialEdge(t, "127.0.0.3", loopback(port))
	send(t, c, []byte("GET /base/ HTTP/1.1\r\nHost: web.example.com\r\n\r\n"))
	expectClosed(t, c, 5*time.Second)
	be.expectNone(t)

	resp := upstreamExchange(t, "127.0.0.2", loopback(port),
		"GET /base/ HTTP/1.1\r\nHost: web.example.com\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n")
	if got := decodeEcho(t, resp); got.URI != "/base/" {
		t.Errorf("a trusted peer: the backend saw %q", got.URI)
	}

	// No trusted prefix: nobody is served.
	mustApply(t, e, upstreamConfig(port, "web.example.com", be.addr))
	c = dialEdge(t, "127.0.0.2", loopback(port))
	send(t, c, []byte("GET /base/ HTTP/1.1\r\nHost: web.example.com\r\n\r\n"))
	expectClosed(t, c, 5*time.Second)
}

// liveConns is the number of connections that the caps of ingress.go count now.
func liveConns(e *Edge) int {
	g := e.ingress
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.conns - g.leaving
}

// The connections of an http-upstream listener count among all the
// connections of the edge, and may take half of the total cap at most
// (Ruling S3-4): a slow web server in front of the listener cannot make the
// edge refuse fake TLS at accept. One over the half is closed as it is
// accepted. They have no hello to send, and the caps on the connections before
// their hello, of the edge and of a source, do not hold for them.
func TestHTTPUpstreamConnectionsHoldHalfTheTotalCapAtMost(t *testing.T) {
	checkGoroutines(t)
	be := newWebBackend(t, nil)
	engine := newBackend(t, true, echoHandler)
	port, tlsPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{MaxConns: 36, MaxPreHello: 1})
	cfg := upstreamConfig(port, "web.example.com", be.addr, "127.0.0.1")
	cfg.Listeners = append(cfg.Listeners, tlsListener("l1", tlsPort, "reject"))
	cfg.Routes = append(cfg.Routes, engineRoute("l1", "proxy.example.com", "p1", engine.addr))
	mustApply(t, e, cfg)
	to := loopback(port)
	const get = "GET /base/ HTTP/1.1\r\nHost: web.example.com\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n"

	// Half of 36, more of one source than perSourcePreHello, and than
	// MaxPreHello.
	var open []net.Conn
	for range 18 {
		c := dialEdge(t, "", to)
		decodeEcho(t, rawExchange(t, c, bufio.NewReader(c), get))
		open = append(open, c)
	}
	if n := liveConns(e); n != 18 {
		t.Fatalf("%d connections counted, want 18: they count among all of them", n)
	}
	expectClosed(t, dialEdge(t, "", to), 5*time.Second)
	snap := e.Snapshot(false)
	if snap.GetRefusedTotal() != 1 || snap.GetRefusedPrehello() != 0 || snap.GetEvictedPrehello() != 0 {
		t.Errorf("refused_total %d, refused_prehello %d, evicted_prehello %d; want 1, 0, 0",
			snap.GetRefusedTotal(), snap.GetRefusedPrehello(), snap.GetEvictedPrehello())
	}
	// Fake TLS is still taken.
	openRelay(t, "", loopback(tlsPort), "proxy.example.com", engine)
	if n := liveConns(e); n != 19 {
		t.Errorf("%d connections counted, want 19", n)
	}

	// An http-upstream connection that ends gives its place back.
	_ = open[0].Close()
	waitFor(t, "the closed connection to give its place back", func() bool { return liveConns(e) == 18 })
	c := dialEdge(t, "", to)
	decodeEcho(t, rawExchange(t, c, bufio.NewReader(c), get))
}

// The refusal of an http-upstream connection over the half of the total cap
// that these may hold says so, apart from the total cap; and a cap so small
// that its half is no connection still lets one in.
func TestHTTPUpstreamHalfCapIsItsOwn(t *testing.T) {
	checkGoroutines(t)
	be := newWebBackend(t, nil)
	const get = "GET /base/ HTTP/1.1\r\nHost: web.example.com\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n"

	t.Run("its own warning", func(t *testing.T) {
		port := freePort(t)
		log, logs := captureLogger(slog.LevelInfo)
		e := newTestEdgeLog(t, log, Options{MaxConns: 4})
		mustApply(t, e, upstreamConfig(port, "web.example.com", be.addr, "127.0.0.1"))
		for range 2 {
			c := dialEdge(t, "", loopback(port))
			decodeEcho(t, rawExchange(t, c, bufio.NewReader(c), get))
		}
		expectClosed(t, dialEdge(t, "", loopback(port)), 5*time.Second)
		// The edge logs once it has closed the connection.
		waitFor(t, "the warning about the half cap", func() bool { return strings.Contains(logs.String(), "half of the connections") })
		if out := logs.String(); strings.Contains(out, "connections over the caps are closed") {
			t.Errorf("the refusal over the half cap is told as one over the total cap:\n%s", out)
		}
	})
	t.Run("a cap of one", func(t *testing.T) {
		port := freePort(t)
		e := newTestEdge(t, Options{MaxConns: 1})
		mustApply(t, e, upstreamConfig(port, "web.example.com", be.addr, "127.0.0.1"))
		c := dialEdge(t, "", loopback(port))
		decodeEcho(t, rawExchange(t, c, bufio.NewReader(c), get))
	})
}

// A Host with a port that is no port is refused with 400.
func TestHTTPUpstreamHostWithAPortThatIsNoPort(t *testing.T) {
	checkGoroutines(t)
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, upstreamConfig(port, "web.example.com", be.addr, "127.0.0.1"))
	for _, host := range []string{"web.example.com:junk", "web.example.com:443:443"} {
		resp := upstreamExchange(t, "", loopback(port), "GET /base/ HTTP/1.1\r\nHost: "+host+"\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n")
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusBadRequest || !resp.Close {
			t.Errorf("Host %q: %d, close %v; want 400 and the connection closed", host, resp.StatusCode, resp.Close)
		}
	}
	be.expectNone(t)
}

// The name in a Host is folded, without its port. A Host whose port is no
// port, or with a colon that is neither that of a port nor one of an IPv6
// address, is no Host at all. An IPv6 address names no host; an IPv4 address
// passes for a name, and folds to itself.
func TestHostName(t *testing.T) {
	for _, tc := range []struct {
		host string
		name string
		ok   bool
	}{
		{"web.example.com", "web.example.com", true},
		{"WEB.Example.com.", "web.example.com", true},
		{"web.example.com:443", "web.example.com", true},
		{"web.example.com:0443", "web.example.com", true},
		{"web.example.com:", "", false},
		{"web.example.com:junk", "", false},
		{"web.example.com:65536", "", false},
		{"web.example.com:+443", "", false},
		{"web.example.com:443:443", "", false},
		{"192.0.2.1", "192.0.2.1", true},
		{"192.0.2.1:443", "192.0.2.1", true},
		{"[2001:db8::1]:443", "", true},
		{"[2001:db8::1]", "", true},
		{"2001:db8::1", "", true},
		{"[2001:db8::1]:junk", "", false},
		{"[2001:db8::1]:443:443", "", false},
		{"", "", true},
	} {
		if name, ok := hostName(tc.host); name != tc.name || ok != tc.ok {
			t.Errorf("hostName(%q) = %q, %v; want %q, %v", tc.host, name, ok, tc.name, tc.ok)
		}
	}
}

// The client of a request is found in X-Forwarded-For from the right: the
// hops of the trusted web servers are passed over, and the first other address
// is the client; when every hop is trusted, the first one is. The header may
// come in several lines, in order. Anything but an address where the client
// is to be is no client.
func TestForwardedClient(t *testing.T) {
	trusted, err := parseCIDRs([]string{"127.0.0.1", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		values []string
		want   string // "" for no client
	}{
		{"appended chain", []string{"203.0.113.9, 198.51.100.7"}, "198.51.100.7"},
		{"overwritten single value", []string{"198.51.100.8"}, "198.51.100.8"},
		{"a trusted hop at the right end", []string{"198.51.100.7, 10.0.0.5"}, "198.51.100.7"},
		{"trusted hops at the right end", []string{"203.0.113.1,198.51.100.7,10.0.0.5, 127.0.0.1"}, "198.51.100.7"},
		{"all hops trusted", []string{"10.0.0.9, 10.0.0.5"}, "10.0.0.9"},
		{"one trusted hop", []string{"127.0.0.1"}, "127.0.0.1"},
		{"several header lines", []string{"203.0.113.9", "203.0.113.10, 198.51.100.9"}, "198.51.100.9"},
		{"several lines, the client in the first", []string{"198.51.100.9", "10.0.0.5"}, "198.51.100.9"},
		{"several lines, all trusted", []string{"10.0.0.7", "10.0.0.5"}, "10.0.0.7"},
		{"an IPv6 client", []string{"2001:db8::7"}, "2001:db8::7"},
		{"an IPv4-mapped client", []string{"::ffff:198.51.100.7, ::ffff:10.0.0.5"}, "198.51.100.7"},
		{"v4 with a port", []string{"198.51.100.7:5555"}, "198.51.100.7"},
		{"v6 in brackets with a port", []string{"[2001:db8::8]:5555"}, "2001:db8::8"},
		{"garbage left of the client", []string{"unknown, 198.51.100.7"}, "198.51.100.7"},
		{"missing", nil, ""},
		{"empty", []string{""}, ""},
		{"blank", []string{"  "}, ""},
		{"unknown", []string{"unknown"}, ""},
		{"garbage where the client is", []string{"198.51.100.7, unknown"}, ""},
		{"an empty hop where the client is", []string{"198.51.100.7, , 10.0.0.5"}, ""},
		{"v6 in brackets without a port", []string{"[2001:db8::8]"}, ""},
		{"v4 in brackets", []string{"[198.51.100.7]:80"}, ""},
		{"a port alone", []string{":5555"}, ""},
		{"a bad port", []string{"198.51.100.7:http"}, ""},
		{"a zone", []string{"fe80::1%eth0"}, ""},
		{"a host name", []string{"client.example.com"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := forwardedClient(tc.values, trusted)
			switch {
			case tc.want == "" && ok:
				t.Errorf("forwardedClient(%q) = %v, want no client", tc.values, got)
			case tc.want != "" && (!ok || got.String() != tc.want):
				t.Errorf("forwardedClient(%q) = %v, %v; want %s", tc.values, got, ok, tc.want)
			}
		})
	}
}

// The front server sends the whole subtree of the base path; the edge passes
// every request target on as it came, with the client that the front server
// saw in X-Forwarded-For alone.
func TestHTTPUpstreamPassesThePathAndTheClient(t *testing.T) {
	checkGoroutines(t)
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, upstreamConfig(port, "web.example.com", be.addr, "127.0.0.1", "10.0.0.0/8"))
	to := loopback(port)

	for _, tc := range []struct {
		name    string
		target  string
		headers string
		xff     string
	}{
		{"the subtree", "/base/a%2Fb/./c?x=1;y=%2f", "X-Forwarded-For: 203.0.113.9, 198.51.100.7\r\n", "198.51.100.7"},
		{"the base path without a slash", "/base", "X-Forwarded-For: 198.51.100.8\r\n", "198.51.100.8"},
		{"two header lines", "/base/x", "X-Forwarded-For: 203.0.113.9\r\nX-Forwarded-For: 203.0.113.10, 198.51.100.9\r\n", "198.51.100.9"},
		{"a trusted hop at the right end", "/base/x", "X-Forwarded-For: 198.51.100.10, 10.0.0.5\r\n", "198.51.100.10"},
		{"an IPv6 client", "/base/x", "X-Forwarded-For: 2001:db8::7\r\n", "2001:db8::7"},
		{"a client with a port", "/base/x", "X-Forwarded-For: [2001:db8::8]:5555\r\n", "2001:db8::8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := upstreamExchange(t, "", to, "GET "+tc.target+" HTTP/1.1\r\nHost: web.example.com\r\n"+tc.headers+"\r\n")
			if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusPermanentRedirect {
				t.Fatalf("redirected to %q", resp.Header.Get("Location"))
			}
			got := decodeEcho(t, resp)
			if got.URI != tc.target || got.Host != "web.example.com" {
				t.Errorf("the backend saw %q for %s, want %q for web.example.com", got.URI, got.Host, tc.target)
			}
			if xff := got.Header["X-Forwarded-For"]; !slices.Equal(xff, []string{tc.xff}) {
				t.Errorf("X-Forwarded-For %q, want %q", xff, tc.xff)
			}
		})
	}

	// A request is a connection of the proxy, counted for its client.
	snap := e.Snapshot(true)
	if n := proxyCounters(snap, "pu").GetConnsTotal(); n != 6 {
		t.Errorf("conns_total %d after 6 requests, want 6", n)
	}
	if ip := ipCounters(snap, "pu", "198.51.100.7"); ip == nil {
		t.Errorf("no counters for the client 198.51.100.7: %v", snap.GetIps())
	}

	t.Run("a Host with a port", func(t *testing.T) {
		resp := upstreamExchange(t, "", to, "GET /base/ HTTP/1.1\r\nHost: Web.Example.com:443\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n")
		if got := decodeEcho(t, resp); got.Host != "Web.Example.com:443" {
			t.Errorf("the backend saw the Host %q, want it as it was sent", got.Host)
		}
	})
	t.Run("a Host with another port", func(t *testing.T) {
		// Unlike a web route, an http-upstream listener keeps the port: its
		// backend may build redirects and cookies from Host:port.
		resp := upstreamExchange(t, "", to, "GET /base/ HTTP/1.1\r\nHost: web.example.com:8443\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n")
		if got := decodeEcho(t, resp); got.Host != "web.example.com:8443" {
			t.Errorf("the backend saw the Host %q, want it as it was sent", got.Host)
		}
	})
	t.Run("an unknown Host", func(t *testing.T) {
		for len(be.requests) > 0 {
			<-be.requests
		}
		resp := upstreamExchange(t, "", to, "GET /base/ HTTP/1.1\r\nHost: other.example.com\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n")
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusMisdirectedRequest || !resp.Close {
			t.Errorf("status %d, close %v; want 421 and the connection closed", resp.StatusCode, resp.Close)
		}
		be.expectNone(t)
	})
}

// A request whose X-Forwarded-For names no client is refused with 400, and the
// connection closed: the edge never takes the web server in front of it for
// the client, which would make every user one device and blind the blacklist.
// One warning says that the server has to set the header, and never what the
// header held.
func TestHTTPUpstreamRefusesARequestWithoutAClient(t *testing.T) {
	checkGoroutines(t)
	be := newWebBackend(t, nil)
	port := freePort(t)
	log, logs := captureLogger(slog.LevelInfo)
	e := newTestEdgeLog(t, log, Options{})
	mustApply(t, e, upstreamConfig(port, "web.example.com", be.addr, "127.0.0.1"))
	const marker = "MARKER-not-an-address"
	for _, headers := range []string{
		"",
		"X-Forwarded-For: \r\n",
		"X-Forwarded-For: unknown\r\n",
		"X-Forwarded-For: 198.51.100.7, " + marker + "\r\n",
		"X-Forwarded-For: [2001:db8::8]\r\n",
	} {
		resp := upstreamExchange(t, "", loopback(port), "GET /base/ HTTP/1.1\r\nHost: web.example.com\r\n"+headers+"\r\n")
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusBadRequest || !resp.Close {
			t.Errorf("X-Forwarded-For %q: status %d, close %v; want 400 and the connection closed", headers, resp.StatusCode, resp.Close)
		}
	}
	be.expectNone(t)
	if n := proxyCounters(e.Snapshot(true), "pu").GetConnsTotal(); n != 0 {
		t.Errorf("conns_total %d: a request without a client is no connection of the proxy", n)
	}
	out := logs.String()
	if n := strings.Count(out, "must set X-Forwarded-For"); n != 1 {
		t.Errorf("%d warnings for five requests, want 1:\n%s", n, out)
	}
	if strings.Contains(out, marker) {
		t.Errorf("the log has what the header held:\n%s", out)
	}
}

// The blacklist and the limits of the proxy hold for the client of a request,
// from X-Forwarded-For.
func TestHTTPUpstreamBlacklistAndLimitsByClient(t *testing.T) {
	checkGoroutines(t)
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	cfg := upstreamConfig(port, "web.example.com", be.addr, "127.0.0.1")
	cfg.BlacklistCidrs = []string{"203.0.113.0/24"}
	cfg.Routes[0].Limits = &edgev1.EdgeLimits{Devices: 1}
	mustApply(t, e, cfg)
	to := loopback(port)
	get := func(client string) *http.Response {
		t.Helper()
		resp := upstreamExchange(t, "", to, "GET /base/ HTTP/1.1\r\nHost: web.example.com\r\nX-Forwarded-For: "+client+"\r\n\r\n")
		t.Cleanup(func() { _, _ = io.Copy(io.Discard, resp.Body) })
		return resp
	}

	if resp := get("203.0.113.5"); resp.StatusCode != http.StatusForbidden || !resp.Close {
		t.Errorf("a blacklisted client: status %d, close %v; want 403 and the connection closed", resp.StatusCode, resp.Close)
	}
	be.expectNone(t)

	if resp := get("198.51.100.1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("the first device: status %d", resp.StatusCode)
	}
	if resp := get("198.51.100.2"); resp.StatusCode != http.StatusServiceUnavailable || !resp.Close {
		t.Errorf("a second device over the limit: status %d, close %v; want 503 and the connection closed", resp.StatusCode, resp.Close)
	}
	if resp := get("198.51.100.1"); resp.StatusCode != http.StatusOK {
		t.Errorf("the first device again: status %d", resp.StatusCode)
	}
}

// A WebSocket goes through an http-upstream listener too, and its bytes are
// counted for the client of the request.
func TestHTTPUpstreamWebSocket(t *testing.T) {
	checkGoroutines(t)
	be := newWebBackend(t, func(w http.ResponseWriter, r *http.Request) {
		c, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		if brw.Flush() != nil {
			return
		}
		_, _ = io.Copy(c, brw)
	})
	port := freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, upstreamConfig(port, "web.example.com", be.addr, "127.0.0.1"))

	c := dialEdge(t, "", loopback(port))
	br := bufio.NewReader(c)
	resp := rawExchange(t, c, br, "GET /base/ws HTTP/1.1\r\nHost: web.example.com\r\nUpgrade: websocket\r\n"+
		"Connection: Upgrade\r\nX-Forwarded-For: 198.51.100.4\r\n\r\n")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d, want 101", resp.StatusCode)
	}
	msg := strings.Repeat("x", 1000)
	send(t, c, []byte(msg))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo: %v", err)
	}
	// The bytes of the echo are counted as the relay writes them, which may be
	// just after the client has read them.
	waitFor(t, "the counters of both ways", func() bool {
		ip := ipCounters(e.Snapshot(true), "pu", "198.51.100.4")
		return ip.GetConnsActive() == 1 && ip.GetBytes() >= 2*uint64(len(msg))
	})
}
