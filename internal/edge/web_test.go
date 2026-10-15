package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// ---------------------------------------------------------------------------
// Backends, clients and configurations of the web routes
// ---------------------------------------------------------------------------

// webEcho is what the backend of a web route saw of a request.
type webEcho struct {
	Method  string              `json:"method"`
	Host    string              `json:"host"`
	URI     string              `json:"uri"` // the request target, as it came
	Proto   string              `json:"proto"`
	Header  map[string][]string `json:"header"`
	Body    string              `json:"body"`
	BodyLen int                 `json:"body_len"`
}

// echoWeb answers every request with what it saw of it.
func echoWeb(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(webEcho{
		Method: r.Method, Host: r.Host, URI: r.RequestURI, Proto: r.Proto,
		Header: r.Header, Body: string(body), BodyLen: len(body),
	})
}

// webBackend is an HTTP/1.1 server on 127.0.0.1 that stands in for the WEB
// listener of an engine. It is closed at the end of the test.
type webBackend struct {
	addr     netip.AddrPort
	requests chan string  // the request target of every request, as it came
	dialed   atomic.Int64 // the connections made to it
}

// newWebBackend starts a backend that serves h, or echoWeb when h is nil.
func newWebBackend(t *testing.T, h http.HandlerFunc) *webBackend {
	t.Helper()
	if h == nil {
		h = echoWeb
	}
	b := &webBackend{requests: make(chan string, 64)}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case b.requests <- r.RequestURI:
		default:
		}
		h(w, r)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			b.dialed.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	b.addr = netip.MustParseAddrPort(srv.Listener.Addr().String())
	return b
}

// next returns the request target of the next request that came to the
// backend.
func (b *webBackend) next(t *testing.T) string {
	t.Helper()
	select {
	case uri := <-b.requests:
		return uri
	case <-time.After(5 * time.Second):
		t.Fatal("no request came to the backend")
		return ""
	}
}

// expectNone fails the test if a request has come to the backend.
func (b *webBackend) expectNone(t *testing.T) {
	t.Helper()
	select {
	case uri := <-b.requests:
		t.Fatalf("a request for %q came to the backend, and should not have", uri)
	default:
	}
}

// webRoute routes sni of a listener to the WEB listener of an engine at backend.
func webRoute(listenerID, sni, proxyID string, backend netip.AddrPort) *edgev1.Route {
	return &edgev1.Route{ListenerId: listenerID, Sni: sni, ProxyId: proxyID, Kind: "web", Backend: backend.String()}
}

// webConfig is a configuration of one tls listener on port that rejects its
// strangers, with a web route of the proxy "pw" for name, and the certificate
// of name at generation 1.
func webConfig(gen uint64, port uint32, name string, backend netip.AddrPort) *edgev1.EdgeConfig {
	return &edgev1.EdgeConfig{
		Generation: gen,
		Listeners:  []*edgev1.EdgeListener{tlsListener("l1", port, "reject")},
		Routes:     []*edgev1.Route{webRoute("l1", name, "pw", backend)},
		Certs:      []*edgev1.CertRef{{Domain: name, Generation: 1}},
	}
}

// webClient returns an HTTP client that trusts the CA of the test alone and
// connects to the edge at to from the address from ("" for any), whatever the
// URL says. It speaks HTTP/2 when the edge offers it. Its connections are
// closed at the end of the test.
func webClient(t *testing.T, ca *testCA, from string, to netip.AddrPort) (*http.Client, *http.Transport) {
	t.Helper()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			if from != "" {
				d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
			}
			return d.DialContext(ctx, "tcp4", to.String())
		},
		TLSClientConfig:   &tls.Config{RootCAs: ca.pool},
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}, tr
}

// dialWeb makes a TLS connection to the edge at to for serverName, offering
// the protocols protos, and fails the test when the handshake does. It is
// closed at the end of the test.
func dialWeb(t *testing.T, ca *testCA, to netip.AddrPort, serverName string, protos ...string) *tls.Conn {
	t.Helper()
	c, err := tryDialWeb(ca, to, serverName, protos...)
	if err != nil {
		t.Fatalf("TLS to the edge for %s: %v", serverName, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// tryDialWeb makes a TLS connection to the edge at to for serverName, without
// a session cache: every handshake is a full one.
func tryDialWeb(ca *testCA, to netip.AddrPort, serverName string, protos ...string) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	cfg := &tls.Config{RootCAs: ca.pool, ServerName: serverName, NextProtos: protos}
	c, err := tls.DialWithDialer(d, "tcp4", to.String(), cfg)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c, nil
}

// servedCert returns the serial number of the certificate that the edge at to
// serves for serverName.
func servedCert(t *testing.T, ca *testCA, to netip.AddrPort, serverName string) *big.Int {
	t.Helper()
	c := dialWeb(t, ca, to, serverName, "h2", "http/1.1")
	defer func() { _ = c.Close() }()
	return c.ConnectionState().PeerCertificates[0].SerialNumber
}

// rawExchange writes req, a request in the form HTTP/1.1 sends it, to c, and
// reads the response through br.
func rawExchange(t *testing.T, c net.Conn, br *bufio.Reader, req string) *http.Response {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("writing the request: %v", err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// decodeEcho reads what the echo backend saw from a response.
func decodeEcho(t *testing.T, resp *http.Response) webEcho {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d (%q), want 200", resp.StatusCode, b)
	}
	var e webEcho
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("decoding what the backend saw: %v", err)
	}
	return e
}

func newRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// ---------------------------------------------------------------------------
// Termination and proxying
// ---------------------------------------------------------------------------

func TestWebTerminatesTLSAndProxiesOverHTTP2(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	serial := ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	client, _ := webClient(t, ca, "127.0.0.7", loopback(port))
	// The client says where it comes from, which the edge does not believe.
	req := newRequest(t, http.MethodPost, "https://web.example.com/base/a%2Fb/./c?x=1;y=%2f", "hello, engine")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("Forwarded", "for=203.0.113.9")
	req.Header.Set("X-Kept", "yes")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.Proto != "HTTP/2.0" || resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h2" {
		t.Errorf("protocol %s, ALPN %v: want HTTP/2", resp.Proto, resp.TLS)
	}
	if got := resp.TLS.PeerCertificates[0].SerialNumber; got.Cmp(serial) != 0 {
		t.Errorf("served the certificate %v, want %v", got, serial)
	}
	got := decodeEcho(t, resp)
	if got.Method != http.MethodPost || got.Host != "web.example.com" || got.URI != "/base/a%2Fb/./c?x=1;y=%2f" ||
		got.Proto != "HTTP/1.1" || got.Body != "hello, engine" {
		t.Errorf("the backend saw %s %s %q %s with %q; want POST web.example.com \"/base/a%%2Fb/./c?x=1;y=%%2f\" HTTP/1.1 with %q",
			got.Method, got.Host, got.URI, got.Proto, got.Body, "hello, engine")
	}
	if xff := got.Header["X-Forwarded-For"]; !slices.Equal(xff, []string{"127.0.0.7"}) {
		t.Errorf("X-Forwarded-For %q, want the address of the client alone", xff)
	}
	if fwd, ok := got.Header["Forwarded"]; ok {
		t.Errorf("Forwarded %q reached the backend", fwd)
	}
	if kept := got.Header["X-Kept"]; !slices.Equal(kept, []string{"yes"}) {
		t.Errorf("X-Kept %q, want the header as it was sent", kept)
	}

	// Another request goes over the same connection: one connection of the
	// proxy for any number of requests.
	got = decodeEcho(t, mustDo(t, client, newRequest(t, http.MethodGet, "https://web.example.com/", "")))
	if got.Method != http.MethodGet || got.URI != "/" {
		t.Errorf("second request: the backend saw %s %q", got.Method, got.URI)
	}
	snap := e.Snapshot(true)
	p := proxyCounters(snap, "pw")
	if p.GetConnsTotal() != 1 || p.GetConnsActive() != 1 || p.GetDevicesActive() != 1 {
		t.Errorf("conns_total %d, conns_active %d, devices %d; want 1, 1, 1",
			p.GetConnsTotal(), p.GetConnsActive(), p.GetDevicesActive())
	}
	if p.GetBytesUp() < uint64(len("hello, engine")) || p.GetBytesDown() == 0 {
		t.Errorf("bytes up %d, down %d", p.GetBytesUp(), p.GetBytesDown())
	}
	// The requests of a web connection keep its backend busy, the connection
	// does not: no request is in flight. A request is let go just after its
	// answer has been written, so the client can see the answer first.
	waitFor(t, "no request in flight between requests", func() bool {
		return len(proxyCounters(e.Snapshot(true), "pw").GetBackendActive()) == 0
	})
	if ip := ipCounters(snap, "pw", "127.0.0.7"); ip.GetConnsActive() != 1 || ip.GetBytes() == 0 {
		t.Errorf("counters of the client IP: %v", ip)
	}
}

func mustDo(t *testing.T, client *http.Client, req *http.Request) *http.Response {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	return resp
}

// HTTP/1.1 works as well, hop-by-hop headers stop at the edge both ways, and
// the path is the client's to the byte.
func TestWebOverHTTP1StripsHopByHopHeaders(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "X-Resp-Hop")
		w.Header().Set("X-Resp-Hop", "1")
		w.Header().Set("Keep-Alive", "timeout=9")
		w.Header().Set("X-Resp-Kept", "1")
		echoWeb(w, r)
	})
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
	if p := c.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Fatalf("ALPN %q, want http/1.1", p)
	}
	br := bufio.NewReader(c)
	resp := rawExchange(t, c, br, "GET /base/%7e/x?q=a%20b HTTP/1.1\r\n"+
		"Host: web.example.com\r\n"+
		"Connection: X-Hop, keep-alive\r\n"+
		"X-Hop: secret\r\n"+
		"Keep-Alive: timeout=5\r\n"+
		"Proxy-Connection: keep-alive\r\n"+
		"X-Forwarded-For: 203.0.113.9, 198.51.100.1\r\n"+
		"X-Kept: yes\r\n"+
		"\r\n")
	if resp.Proto != "HTTP/1.1" {
		t.Errorf("protocol %s, want HTTP/1.1", resp.Proto)
	}
	for _, h := range []string{"X-Resp-Hop", "Keep-Alive"} {
		if v, ok := resp.Header[h]; ok {
			t.Errorf("the response has the hop-by-hop header %s: %q", h, v)
		}
	}
	if resp.Header.Get("X-Resp-Kept") != "1" {
		t.Errorf("the response lost X-Resp-Kept")
	}
	got := decodeEcho(t, resp)
	if got.URI != "/base/%7e/x?q=a%20b" || got.Host != "web.example.com" {
		t.Errorf("the backend saw %q for %s, want the request target and the Host as they were sent", got.URI, got.Host)
	}
	for _, h := range []string{"X-Hop", "Keep-Alive", "Proxy-Connection"} {
		if v, ok := got.Header[h]; ok {
			t.Errorf("the hop-by-hop header %s reached the backend: %q", h, v)
		}
	}
	if !slices.Equal(got.Header["X-Kept"], []string{"yes"}) {
		t.Errorf("X-Kept %q, want yes", got.Header["X-Kept"])
	}
	if xff := got.Header["X-Forwarded-For"]; !slices.Equal(xff, []string{"127.0.0.1"}) {
		t.Errorf("X-Forwarded-For %q, want the address of the client alone", xff)
	}

	// The connection stays open for the next request.
	resp = rawExchange(t, c, br, "GET /next HTTP/1.1\r\nHost: web.example.com\r\n\r\n")
	if got := decodeEcho(t, resp); got.URI != "/next" {
		t.Errorf("second request: the backend saw %q", got.URI)
	}
	if n := proxyCounters(e.Snapshot(false), "pw").GetConnsTotal(); n != 1 {
		t.Errorf("conns_total %d after two requests on one connection, want 1", n)
	}
}

func TestWebRequestBodyLimit(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))
	client, _ := webClient(t, ca, "", loopback(port))

	const limit = 2 << 20
	// At the limit the body goes through.
	got := decodeEcho(t, mustDo(t, client, newRequest(t, http.MethodPost, "https://web.example.com/up", strings.Repeat("a", limit))))
	if got.BodyLen != limit {
		t.Errorf("the backend got %d bytes of a body of %d", got.BodyLen, limit)
	}

	// A length over it is refused before anything goes to the backend.
	for len(be.requests) > 0 {
		<-be.requests
	}
	resp := mustDo(t, client, newRequest(t, http.MethodPost, "https://web.example.com/up", strings.Repeat("a", limit+1)))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d for a body of %d bytes, want 413", resp.StatusCode, limit+1)
	}
	be.expectNone(t)

	// So is a body without a length that grows over it.
	req := newRequest(t, http.MethodPost, "https://web.example.com/up", "")
	req.Body = io.NopCloser(io.LimitReader(zeros{}, limit+1))
	req.ContentLength = -1
	resp = mustDo(t, client, req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d for a streamed body of %d bytes, want 413", resp.StatusCode, limit+1)
	}
}

// zeros reads as an endless stream of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// wsEcho is the backend of a WebSocket: it switches protocols, says in
// X-Seen-For what X-Forwarded-For it got, and echoes what comes until the
// client is gone.
func wsEcho(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	c, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = c.Close() }()
	_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"X-Seen-For: " + r.Header.Get("X-Forwarded-For") + "\r\n\r\n")
	if brw.Flush() != nil {
		return
	}
	_, _ = io.Copy(c, brw)
}

// wsUpgrade is the request that opens a WebSocket at /ws.
const wsUpgrade = "GET /ws HTTP/1.1\r\nHost: web.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
	"Sec-WebSocket-Version: 13\r\n\r\n"

func TestWebSocketGoesThrough(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, wsEcho)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
	br := bufio.NewReader(c)
	resp := rawExchange(t, c, br, wsUpgrade)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d, want 101", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Seen-For"); got != "127.0.0.1" {
		t.Errorf("the backend saw X-Forwarded-For %q, want 127.0.0.1", got)
	}
	for i := range 3 {
		msg := fmt.Sprintf("frame %d", i)
		if _, err := io.WriteString(c, msg); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(br, buf); err != nil || string(buf) != msg {
			t.Fatalf("echo %q, %v; want %q", buf, err, msg)
		}
	}
	if p := proxyCounters(e.Snapshot(false), "pw"); p.GetBytesUp() == 0 || p.GetBytesDown() == 0 || p.GetConnsActive() != 1 {
		t.Errorf("counters %v", p)
	}
}

// h2Settings returns the settings that the edge at to sends first on an
// HTTP/2 connection for serverName, by their identifiers (RFC 9113, 6.5).
func h2Settings(t *testing.T, ca *testCA, to netip.AddrPort, serverName string) map[uint16]uint32 {
	t.Helper()
	c := dialWeb(t, ca, to, serverName, "h2")
	if p := c.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("ALPN %q, want h2", p)
	}
	// The preface of the client, and its SETTINGS: empty.
	send(t, c, append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0, 0, 0, 4, 0, 0, 0, 0, 0))
	for {
		header := readN(t, c, 9) // length (24 bits), type, flags, stream
		payload := readN(t, c, int(header[0])<<16|int(header[1])<<8|int(header[2]))
		if header[3] != 4 || header[4]&1 != 0 { // not SETTINGS, or an ACK
			continue
		}
		settings := make(map[uint16]uint32)
		for i := 0; i+6 <= len(payload); i += 6 {
			settings[binary.BigEndian.Uint16(payload[i:])] = binary.BigEndian.Uint32(payload[i+2:])
		}
		return settings
	}
}

// The identifiers of the HTTP/2 settings that the tests look at.
const (
	h2MaxConcurrentStreams  = 0x3
	h2EnableConnectProtocol = 0x8 // RFC 8441
)

// WebSockets go over HTTP/1.1 upgrades, which ReverseProxy passes through: the
// edge never offers them over HTTP/2 (extended CONNECT, RFC 8441), which it
// could not pass on. Go 1.27 has no setting of a server for it; the default of
// the toolchain is off unless GODEBUG has http2xconnect=1, and this pins it.
func TestWebDoesNotOfferWebSocketsOverHTTP2(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	if v, ok := h2Settings(t, ca, loopback(port), "web.example.com")[h2EnableConnectProtocol]; ok && v != 0 {
		t.Errorf("SETTINGS_ENABLE_CONNECT_PROTOCOL %d: the edge offers WebSockets over HTTP/2", v)
	}
}

// The request target reaches the backend byte for byte, also with the bytes
// that Go would escape again in a path.
func TestWebForwardsTheRequestTargetByteForByte(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port, upstreamPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	cfg := webConfig(1, port, "web.example.com", be.addr)
	up := upstreamConfig(upstreamPort, "web.example.com", be.addr, "127.0.0.1")
	cfg.Listeners = append(cfg.Listeners, up.Listeners...)
	cfg.Routes = append(cfg.Routes, up.Routes...)
	mustApply(t, e, cfg)

	for _, target := range []string{
		"/base/a|b^c?x=1;y",
		"/base/{a}/`b`|^?q=%zz;|",
		"/base/%7e/%2F/./../x?",
		"//base//x?q",
		"/",
	} {
		t.Run(target, func(t *testing.T) {
			c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
			resp := rawExchange(t, c, bufio.NewReader(c), "GET "+target+" HTTP/1.1\r\nHost: web.example.com\r\n\r\n")
			if got := decodeEcho(t, resp); got.URI != target {
				t.Errorf("web route: the backend saw %q, want %q", got.URI, target)
			}
			resp = upstreamExchange(t, "", loopback(upstreamPort),
				"GET "+target+" HTTP/1.1\r\nHost: web.example.com\r\nX-Forwarded-For: 198.51.100.1\r\n\r\n")
			if got := decodeEcho(t, resp); got.URI != target {
				t.Errorf("http-upstream: the backend saw %q, want %q", got.URI, target)
			}
		})
	}
}

// A request of a web route asks for the server name of its connection: a Host
// of another name is answered 421, so that a client that put requests of
// another name on the connection (HTTP/2 coalescing under a certificate of
// several names) sends them on a connection of their own.
func TestWebHostMustBeTheServerName(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com", "web.example.com", "other.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
	br := bufio.NewReader(c)
	resp := rawExchange(t, c, br, "GET /a HTTP/1.1\r\nHost: WEB.Example.com.:443\r\n\r\n")
	if got := decodeEcho(t, resp); got.URI != "/a" {
		t.Errorf("the name in another case, with a dot and a port: the backend saw %q", got.URI)
	}
	for len(be.requests) > 0 {
		<-be.requests
	}
	resp = rawExchange(t, c, br, "GET /b HTTP/1.1\r\nHost: other.example.com\r\n\r\n")
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusMisdirectedRequest || !resp.Close {
		t.Errorf("another Host over HTTP/1.1: status %d, close %v; want 421 and the connection closed", resp.StatusCode, resp.Close)
	}

	client, _ := webClient(t, ca, "", loopback(port))
	req := newRequest(t, http.MethodGet, "https://web.example.com/c", "")
	req.Host = "other.example.com"
	resp = mustDo(t, client, req)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest || resp.Proto != "HTTP/2.0" {
		t.Errorf("another :authority over HTTP/2: %s %d, want 421", resp.Proto, resp.StatusCode)
	}
	be.expectNone(t)
}

// claimedHeaders are headers in which a client may claim to be another.
var claimedHeaders = []string{"X-Real-Ip", "True-Client-Ip", "Cf-Connecting-Ip", "X-Client-Ip",
	"X-Cluster-Client-Ip", "Fastly-Client-Ip", "X-Forwarded-For-Original", "Forwarded", "X-Forwarded-Host",
	"X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Prefix"}

// No header in which a client says who it is reaches the backend, but the
// X-Forwarded-For of the edge, with the client that the edge found.
func TestWebStripsWhatClientsSayAboutThemselves(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port, upstreamPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	cfg := webConfig(1, port, "web.example.com", be.addr)
	up := upstreamConfig(upstreamPort, "web.example.com", be.addr, "127.0.0.1")
	cfg.Listeners = append(cfg.Listeners, up.Listeners...)
	cfg.Routes = append(cfg.Routes, up.Routes...)
	mustApply(t, e, cfg)

	var claims strings.Builder
	for _, h := range claimedHeaders {
		claims.WriteString(h + ": 203.0.113.66\r\n")
	}
	check := func(t *testing.T, got webEcho, client string) {
		t.Helper()
		for _, h := range claimedHeaders {
			if v, ok := got.Header[h]; ok {
				t.Errorf("%s %q reached the backend", h, v)
			}
		}
		if xff := got.Header["X-Forwarded-For"]; !slices.Equal(xff, []string{client}) {
			t.Errorf("X-Forwarded-For %q, want %s alone", xff, client)
		}
	}
	t.Run("web route", func(t *testing.T) {
		c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
		resp := rawExchange(t, c, bufio.NewReader(c), "GET / HTTP/1.1\r\nHost: web.example.com\r\n"+
			"X-Forwarded-For: 203.0.113.66\r\n"+claims.String()+"\r\n")
		check(t, decodeEcho(t, resp), "127.0.0.1")
	})
	t.Run("http-upstream", func(t *testing.T) {
		resp := upstreamExchange(t, "", loopback(upstreamPort), "GET /base/ HTTP/1.1\r\nHost: web.example.com\r\n"+
			"X-Forwarded-For: 198.51.100.4\r\n"+claims.String()+"\r\n")
		check(t, decodeEcho(t, resp), "198.51.100.4")
	})
}

// A request that fails for a fault of its client is answered 400, or dropped,
// and is no sign of a backend that cannot be reached: nothing is logged as
// one.
func TestWebClientFaultsAreNotTheBackends(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	log, logs := captureLogger(slog.LevelInfo)
	e := newTestEdgeLog(t, log, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	for _, tc := range []struct{ name, req string }{
		{"a malformed chunked body", "POST /up HTTP/1.1\r\nHost: web.example.com\r\nTransfer-Encoding: chunked\r\n\r\n" +
			"zz\r\nhello\r\n0\r\n\r\n"},
		{"an upgrade to a protocol that is no name", "GET /ws HTTP/1.1\r\nHost: web.example.com\r\n" +
			"Connection: Upgrade\r\nUpgrade: \xffbad\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
			resp := rawExchange(t, c, bufio.NewReader(c), tc.req)
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusBadRequest || !resp.Close {
				t.Errorf("status %d, close %v; want 400 and the connection closed", resp.StatusCode, resp.Close)
			}
		})
	}
	if out := logs.String(); strings.Contains(out, "cannot reach the backend") {
		t.Errorf("a fault of the client is logged as a backend that cannot be reached:\n%s", out)
	}
}

// The bytes read with the ClientHello are let go once they are replayed.
func TestWebConnLetsTheReplayGo(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	wc := newWebConn(a, netip.AddrPort{}, netip.AddrPort{})
	defer wc.w.stop()
	wc.replay = []byte("hello")
	buf := make([]byte, 3)
	if n, err := wc.Read(buf); err != nil || string(buf[:n]) != "hel" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
	if n, err := wc.Read(buf); err != nil || string(buf[:n]) != "lo" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
	if wc.replay != nil {
		t.Errorf("the replay buffer is kept once replayed: %d bytes of capacity", cap(wc.replay))
	}
	go func() { _, _ = b.Write([]byte("x")) }()
	if n, err := wc.Read(buf); err != nil || string(buf[:n]) != "x" {
		t.Fatalf("Read of the connection = %q, %v", buf[:n], err)
	}
}

// One HTTP/2 connection carries as many requests at a time as nginx let real
// clients have, and no more.
func TestWebHTTP2StreamsPerConnection(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	settings := h2Settings(t, ca, loopback(port), "web.example.com")
	if got, ok := settings[h2MaxConcurrentStreams]; !ok || got != 128 {
		t.Errorf("SETTINGS_MAX_CONCURRENT_STREAMS %d (sent: %v), want 128", got, ok)
	}
}

// The requests in flight to the backends, of the web routes and of the
// http-upstream listeners together, are as many as the edge may hold
// connections at most; one more is answered 503 without going anywhere. A
// request holds its place until its response is done, the client gives up, or
// its WebSocket ends.
func TestWebRequestsInFlightAreCapped(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	held, release := make(chan struct{}, 8), make(chan struct{})
	be := newWebBackend(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hold":
			held <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			echoWeb(w, r)
		case "/ws":
			wsEcho(w, r)
		default:
			echoWeb(w, r)
		}
	})
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir, MaxConns: 3})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))
	inflight := func() int64 { return e.web.inflight.Load() }

	// Two long polls on one HTTP/2 connection...
	client, _ := webClient(t, ca, "", loopback(port))
	abortCtx, abort := context.WithCancel(context.Background())
	defer abort()
	polls := []*http.Request{
		newRequest(t, http.MethodGet, "https://web.example.com/hold", "").WithContext(abortCtx),
		newRequest(t, http.MethodGet, "https://web.example.com/hold", ""),
	}
	results := make(chan error, len(polls))
	for _, req := range polls {
		go func() {
			resp, err := client.Do(req)
			if err == nil {
				_, err = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
			results <- err
		}()
	}
	for range polls {
		select {
		case <-held:
		case <-time.After(5 * time.Second):
			t.Fatal("the long polls did not reach the backend")
		}
	}
	// ...and a WebSocket on a connection of its own: the cap of 3.
	ws := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
	if resp := rawExchange(t, ws, bufio.NewReader(ws), wsUpgrade); resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("WebSocket: status %d", resp.StatusCode)
	}
	waitFor(t, "three requests in flight", func() bool { return inflight() == 3 })
	for len(be.requests) > 0 {
		<-be.requests
	}

	resp := mustDo(t, client, newRequest(t, http.MethodGet, "https://web.example.com/over", ""))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" {
		t.Errorf("HTTP/2 over the cap: status %d, Retry-After %q; want 503 and 1", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	h1 := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
	resp = rawExchange(t, h1, bufio.NewReader(h1), "GET /over HTTP/1.1\r\nHost: web.example.com\r\n\r\n")
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" || !resp.Close {
		t.Errorf("HTTP/1.1 over the cap: status %d, Retry-After %q, close %v; want 503, 1 and the connection closed",
			resp.StatusCode, resp.Header.Get("Retry-After"), resp.Close)
	}
	be.expectNone(t)

	// The WebSocket ends: its place is free.
	_ = ws.Close()
	waitFor(t, "the WebSocket to give its place back", func() bool { return inflight() == 2 })
	decodeEcho(t, mustDo(t, client, newRequest(t, http.MethodGet, "https://web.example.com/after", "")))
	// A client that gives up gives its place back.
	abort()
	waitFor(t, "the request given up to give its place back", func() bool { return inflight() == 1 })
	// So does a response that is done.
	release <- struct{}{}
	waitFor(t, "the done request to give its place back", func() bool { return inflight() == 0 })
	var failed int
	for range polls {
		select {
		case err := <-results:
			if err != nil {
				failed++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a long poll did not end")
		}
	}
	if failed != 1 {
		t.Errorf("%d long polls failed, want the one given up", failed)
	}
}

// A response is passed on as the backend sends it, not when it ends: a long
// poll or a stream of the engine reaches the client at once.
func TestWebStreamsResponses(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	release := make(chan struct{})
	be := newWebBackend(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		// A response of a known length, which a proxy that flushes only
		// what has no length would hold back.
		w.Header().Set("Content-Length", fmt.Sprint(len("first\nsecond\n")))
		_, _ = io.WriteString(w, "first\n")
		_ = http.NewResponseController(w).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "second\n")
	})
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	expectStream := func(t *testing.T, body io.Reader) {
		t.Helper()
		br := bufio.NewReader(body)
		first := make(chan string, 1)
		go func() {
			line, _ := br.ReadString('\n')
			first <- line
		}()
		select {
		case line := <-first:
			if line != "first\n" {
				t.Fatalf("first line %q", line)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("the first part of the response did not come while the backend was still at it")
		}
		select {
		case release <- struct{}{}:
		case <-time.After(5 * time.Second):
			t.Fatal("the backend no longer waits to send the rest")
		}
		if line, err := br.ReadString('\n'); line != "second\n" {
			t.Fatalf("second line %q, %v", line, err)
		}
	}

	t.Run("HTTP/2", func(t *testing.T) {
		client, _ := webClient(t, ca, "", loopback(port))
		resp := mustDo(t, client, newRequest(t, http.MethodGet, "https://web.example.com/poll", ""))
		defer func() { _ = resp.Body.Close() }()
		if resp.Proto != "HTTP/2.0" {
			t.Errorf("protocol %s", resp.Proto)
		}
		// The request in flight keeps the backend busy.
		if got, want := proxyCounters(e.Snapshot(false), "pw").GetBackendActive(), map[string]uint32{be.addr.String(): 1}; !maps.Equal(got, want) {
			t.Errorf("backend_active %v while a request is in flight, want %v", got, want)
		}
		expectStream(t, resp.Body)
	})
	t.Run("HTTP/1.1", func(t *testing.T) {
		c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
		resp := rawExchange(t, c, bufio.NewReader(c), "GET /poll HTTP/1.1\r\nHost: web.example.com\r\n\r\n")
		expectStream(t, resp.Body)
	})
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

func TestWebCertificateHotReload(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	first := ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	cfg := webConfig(1, port, "web.example.com", be.addr)
	mustApply(t, e, cfg)
	addr := loopback(port)
	if got := servedCert(t, ca, addr, "web.example.com"); got.Cmp(first) != 0 {
		t.Fatalf("serial %v, want %v", got, first)
	}
	listenerOf := func() *listener {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.listeners[addr]
	}
	before := listenerOf()
	// A connection made before the new certificate, which goes on after it.
	old := dialWeb(t, ca, addr, "web.example.com", "http/1.1")
	oldReader := bufio.NewReader(old)
	decodeEcho(t, rawExchange(t, old, oldReader, "GET /before HTTP/1.1\r\nHost: web.example.com\r\n\r\n"))

	// New files under the generation that was read are not read again.
	second := ca.install(t, dir, "web.example.com")
	cfg.Generation = 2 // of the edge, not of the certificate
	mustApply(t, e, cfg)
	if got := servedCert(t, ca, addr, "web.example.com"); got.Cmp(first) != 0 {
		t.Fatalf("serial %v after new files under the same generation, want %v still", got, first)
	}

	cfg.Certs[0].Generation = 2
	mustApply(t, e, cfg)
	if got := servedCert(t, ca, addr, "web.example.com"); got.Cmp(second) != 0 {
		t.Fatalf("serial %v after the new generation, want %v", got, second)
	}
	if after := listenerOf(); after != before {
		t.Error("the listener was opened again for a new certificate")
	}
	if got := decodeEcho(t, rawExchange(t, old, oldReader, "GET /after HTTP/1.1\r\nHost: web.example.com\r\n\r\n")); got.URI != "/after" {
		t.Errorf("the old connection: the backend saw %q", got.URI)
	}
}

func TestWebRouteWithoutAValidCertificateGetsTheAlert(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	now := time.Now()
	const marker = "MARKER-not-a-key-0123456789"
	for _, tc := range []struct {
		name  string
		certs bool // the configuration names the certificate
		setup func(t *testing.T, dir string)
		why   string // in the warning
	}{
		{"no certificate in the configuration", false, func(t *testing.T, dir string) {
			ca.install(t, dir, "web.example.com")
		}, "no certificate"},
		{"no files", true, func(t *testing.T, dir string) {}, "no such file"},
		{"a key that is not one", true, func(t *testing.T, dir string) {
			chain, _, _ := ca.issue(t, now.Add(-time.Hour), now.Add(time.Hour), "web.example.com")
			writeCertFiles(t, dir, "web.example.com", chain, []byte(marker))
		}, "key"},
		{"a certificate of another name", true, func(t *testing.T, dir string) {
			ca.install(t, dir, "web.example.com", "other.example.com")
		}, "web.example.com"},
		{"an expired certificate", true, func(t *testing.T, dir string) {
			chain, key, _ := ca.issue(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour), "web.example.com")
			writeCertFiles(t, dir, "web.example.com", chain, key)
		}, "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			be := newWebBackend(t, nil)
			port := freePort(t)
			log, logs := captureLogger(slog.LevelInfo)
			e := newTestEdgeLog(t, log, Options{CertsDir: dir})
			cfg := webConfig(1, port, "web.example.com", be.addr)
			if !tc.certs {
				cfg.Certs = nil
			}
			mustApply(t, e, cfg)

			_, err := tryDialWeb(ca, loopback(port), "web.example.com", "h2")
			if err == nil || !strings.Contains(err.Error(), "unrecognized name") {
				t.Fatalf("handshake: %v, want the alert unrecognized_name", err)
			}
			// The alert is the one of the reject action, byte for byte.
			c := dialEdge(t, "", loopback(port))
			send(t, c, realHello(t, "web.example.com"))
			expectAlert(t, c)

			be.expectNone(t)
			if n := proxyCounters(e.Snapshot(false), "pw").GetConnsTotal(); n != 0 {
				t.Errorf("conns_total %d: a connection without a certificate is not the proxy's", n)
			}
			out := logs.String()
			if n := strings.Count(out, "has no valid certificate"); n != 1 {
				t.Errorf("%d warnings about the certificate for two connections, want 1:\n%s", n, out)
			}
			if !strings.Contains(out, "level=WARN") || !strings.Contains(out, tc.why) {
				t.Errorf("the log does not say %q:\n%s", tc.why, out)
			}
			for _, secret := range []string{marker, "PRIVATE KEY"} {
				if strings.Contains(out, secret) {
					t.Errorf("the log has %q in it:\n%s", secret, out)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Web and fake TLS, limits, failures, drain
// ---------------------------------------------------------------------------

func TestWebAndFakeTLSShareAListener(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	web := newWebBackend(t, nil)
	engine := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	cfg := webConfig(1, port, "web.example.com", web.addr)
	cfg.Routes = append(cfg.Routes, engineRoute("l1", "proxy.example.com", "p1", engine.addr))
	mustApply(t, e, cfg)

	relay := openRelay(t, "", loopback(port), "proxy.example.com", engine)
	client, _ := webClient(t, ca, "", loopback(port))
	if got := decodeEcho(t, mustDo(t, client, newRequest(t, http.MethodGet, "https://web.example.com/x", ""))); got.URI != "/x" {
		t.Errorf("the web backend saw %q", got.URI)
	}
	roundTrip(t, relay, "fake TLS still relays")

	// A stranger is still a stranger.
	c := dialEdge(t, "", loopback(port))
	send(t, c, helloRecord("other.example.com"))
	expectAlert(t, c)

	snap := e.Snapshot(false)
	if p := proxyCounters(snap, "p1"); p.GetConnsTotal() != 1 {
		t.Errorf("fake TLS: conns_total %d", p.GetConnsTotal())
	}
	if p := proxyCounters(snap, "pw"); p.GetConnsTotal() != 1 {
		t.Errorf("web: conns_total %d", p.GetConnsTotal())
	}
}

// The limits of a WEB proxy count TCP connections, not the requests or the
// HTTP/2 streams on them, and a connection over them is a stranger.
func TestWebLimitsCountConnections(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	cfg := webConfig(1, port, "web.example.com", be.addr)
	cfg.Routes[0].Limits = &edgev1.EdgeLimits{ConnsTotal: 1}
	mustApply(t, e, cfg)

	client, tr := webClient(t, ca, "", loopback(port))
	for i := range 3 {
		url := fmt.Sprintf("https://web.example.com/%d", i)
		if got := decodeEcho(t, mustDo(t, client, newRequest(t, http.MethodGet, url, ""))); got.URI != fmt.Sprintf("/%d", i) {
			t.Fatalf("request %d: the backend saw %q", i, got.URI)
		}
	}
	// A second connection is over conns_total, and the listener rejects it.
	if _, err := tryDialWeb(ca, loopback(port), "web.example.com", "h2"); err == nil || !strings.Contains(err.Error(), "unrecognized name") {
		t.Fatalf("a connection over the limit: %v, want the alert of the reject action", err)
	}
	tr.CloseIdleConnections()
	waitFor(t, "the first connection to end", func() bool { return activeConns(e, "pw") == 0 })
	c := dialWeb(t, ca, loopback(port), "web.example.com", "h2")
	_ = c.Close()
	if n := proxyCounters(e.Snapshot(false), "pw").GetConnsTotal(); n != 2 {
		t.Errorf("conns_total %d, want 2", n)
	}
}

// A backend that cannot be reached gets the client a 502, and is logged as a
// relayed one is, once in a while.
func TestWebBackendDown(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	port := freePort(t)
	log, logs := captureLogger(slog.LevelInfo)
	e := newTestEdgeLog(t, log, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", loopback(freePort(t))))

	client, _ := webClient(t, ca, "", loopback(port))
	resp := mustDo(t, client, newRequest(t, http.MethodGet, "https://web.example.com/", ""))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || resp.Proto != "HTTP/2.0" {
		t.Errorf("%s %d, want HTTP/2 502", resp.Proto, resp.StatusCode)
	}
	c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
	br := bufio.NewReader(c)
	for range 2 {
		resp := rawExchange(t, c, br, "GET / HTTP/1.1\r\nHost: web.example.com\r\n\r\n")
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("HTTP/1.1: status %d, want 502", resp.StatusCode)
		}
	}
	if n := strings.Count(logs.String(), "cannot reach the backend"); n != 1 {
		t.Errorf("%d warnings about the backend, want 1:\n%s", n, logs.String())
	}
}

// Every request of a web connection takes the route of its proxy as it is when
// the request comes: the requests of a connection that began with one
// generation of the engine go to the next once the route has moved to it, and
// one that comes when the proxy has no route any more is sent to a new
// connection.
func TestWebRequestsFollowTheRouteOfTheirProxy(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	beA, beB := newWebBackend(t, nil), newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", beA.addr))

	c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
	br := bufio.NewReader(c)
	get := func(path string) *http.Response {
		t.Helper()
		return rawExchange(t, c, br, "GET "+path+" HTTP/1.1\r\nHost: web.example.com\r\n\r\n")
	}
	decodeEcho(t, get("/1"))
	if uri := beA.next(t); uri != "/1" {
		t.Fatalf("backend A got %q", uri)
	}

	mustApply(t, e, webConfig(2, port, "web.example.com", beB.addr))
	decodeEcho(t, get("/2"))
	beA.expectNone(t)
	if uri := beB.next(t); uri != "/2" {
		t.Fatalf("backend B got %q", uri)
	}
	if n := proxyCounters(e.Snapshot(false), "pw").GetConnsTotal(); n != 1 {
		t.Errorf("conns_total %d, want 1: one connection", n)
	}

	// The proxy is paused: its route is gone.
	mustApply(t, e, &edgev1.EdgeConfig{Generation: 3, Listeners: []*edgev1.EdgeListener{tlsListener("l1", port, "reject")}})
	resp := get("/3")
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusMisdirectedRequest || !resp.Close {
		t.Errorf("status %d, close %v: want 421 and the connection closed", resp.StatusCode, resp.Close)
	}
	beA.expectNone(t)
	beB.expectNone(t)
}

// Drain lets idle web connections go at once, and waits for the requests in
// flight until it gives up.
func TestWebDrain(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	held := make(chan struct{})
	be := newWebBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			close(held)
			<-r.Context().Done()
			return
		}
		echoWeb(w, r)
	})
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	idle1, _ := webClient(t, ca, "", loopback(port))
	decodeEcho(t, mustDo(t, idle1, newRequest(t, http.MethodGet, "https://web.example.com/", "")))
	idle2 := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
	decodeEcho(t, rawExchange(t, idle2, bufio.NewReader(idle2), "GET / HTTP/1.1\r\nHost: web.example.com\r\n\r\n"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := e.Drain(ctx); err != nil {
		t.Fatalf("Drain with idle web connections: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Drain took %v with idle connections only", d)
	}

	// Another edge, with a request in flight.
	port = freePort(t)
	e = newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))
	busy, _ := webClient(t, ca, "", loopback(port))
	errc := make(chan error, 1)
	go func() {
		resp, err := busy.Get("https://web.example.com/hold")
		if err == nil {
			_, err = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		errc <- err
	}()
	<-held
	ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := e.Drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Drain with a request in flight: %v, want it to give up", err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Error("the request in flight ended well after Drain gave up")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request in flight did not end")
	}
}

// A WebSocket keeps the backend of its proxy busy while it is open, and no
// longer.
func TestWebSocketKeepsItsBackendBusy(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, wsEcho)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))
	backendActive := func() map[string]uint32 { return proxyCounters(e.Snapshot(false), "pw").GetBackendActive() }

	c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
	br := bufio.NewReader(c)
	if resp := rawExchange(t, c, br, wsUpgrade); resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d, want 101", resp.StatusCode)
	}
	send(t, c, []byte("ping"))
	echo := make([]byte, 4)
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != "ping" { // the tunnel is up
		t.Fatalf("echo %q, %v", echo, err)
	}
	if got, want := backendActive(), map[string]uint32{be.addr.String(): 1}; !maps.Equal(got, want) {
		t.Errorf("backend_active %v while the WebSocket is open, want %v", got, want)
	}
	_ = c.Close()
	waitFor(t, "the closed WebSocket to keep the backend busy no more", func() bool { return len(backendActive()) == 0 })
}

// A web route without a certificate gets the alert unrecognized_name
// whatever the listener does with strangers: it is neither masked nor
// dropped.
func TestWebRouteWithoutACertificateGetsTheAlertWhateverTheStrangerAction(t *testing.T) {
	checkGoroutines(t)
	site := newRawServer(t)
	md := newMaskDialer(site.addr)
	be := newWebBackend(t, nil)
	e := newTestEdge(t, Options{DialMask: md.dial})
	for _, action := range []string{"mask", "drop"} {
		t.Run(action, func(t *testing.T) {
			port := freePort(t)
			l := tlsListener("l1", port, action)
			l.MaskTarget = "mask.example.com"
			mustApply(t, e, &edgev1.EdgeConfig{
				Generation: 1,
				Listeners:  []*edgev1.EdgeListener{l},
				Routes:     []*edgev1.Route{webRoute("l1", "web.example.com", "pw", be.addr)},
			})
			c := dialEdge(t, "", loopback(port))
			start := time.Now()
			send(t, c, realHello(t, "web.example.com"))
			expectAlert(t, c)
			if d := time.Since(start); d > time.Second {
				t.Errorf("the alert came after %v", d)
			}
			md.expectNoDial(t)
			be.expectNone(t)
		})
	}
}

// Nothing of a request is logged, at any level, whatever becomes of it: its
// URL and its headers carry what the client authenticates with.
func TestWebLogsNothingOfARequest(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	ca.install(t, dir, "down.example.com")
	be := newWebBackend(t, nil)
	port, upstreamPort := freePort(t), freePort(t)
	log, logs := captureLogger(slog.LevelDebug)
	e := newTestEdgeLog(t, log, Options{CertsDir: dir})
	cfg := webConfig(1, port, "web.example.com", be.addr)
	cfg.Routes = append(cfg.Routes, webRoute("l1", "down.example.com", "pd", loopback(freePort(t))))
	cfg.Certs = append(cfg.Certs, &edgev1.CertRef{Domain: "down.example.com", Generation: 1})
	up := upstreamConfig(upstreamPort, "web.example.com", be.addr, "127.0.0.1")
	cfg.Listeners = append(cfg.Listeners, up.Listeners...)
	cfg.Routes = append(cfg.Routes, up.Routes...)
	mustApply(t, e, cfg)

	const query, bearer = "MARKER-in-the-query", "MARKER-in-authorization"
	headers := "Authorization: Bearer " + bearer + "\r\n"
	target := "/base/?token=" + query
	exchange := func(c net.Conn, req string) {
		t.Helper()
		resp := rawExchange(t, c, bufio.NewReader(c), req)
		_, _ = io.Copy(io.Discard, resp.Body)
	}
	// A request that goes through, over HTTP/2 and over HTTP/1.1.
	client, _ := webClient(t, ca, "", loopback(port))
	req := newRequest(t, http.MethodGet, "https://web.example.com"+target, "")
	req.Header.Set("Authorization", "Bearer "+bearer)
	decodeEcho(t, mustDo(t, client, req))
	exchange(dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1"),
		"GET "+target+" HTTP/1.1\r\nHost: web.example.com\r\n"+headers+"\r\n")
	// One whose backend cannot be reached.
	exchange(dialWeb(t, ca, loopback(port), "down.example.com", "http/1.1"),
		"GET "+target+" HTTP/1.1\r\nHost: down.example.com\r\n"+headers+"\r\n")
	// One whose body cannot be read, and one that asks for no protocol.
	exchange(dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1"),
		"POST "+target+" HTTP/1.1\r\nHost: web.example.com\r\n"+headers+"Transfer-Encoding: chunked\r\n\r\nzz\r\n")
	exchange(dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1"),
		"GET "+target+" HTTP/1.1\r\nHost: web.example.com\r\n"+headers+"Connection: Upgrade\r\nUpgrade: \xff"+query+"\r\n\r\n")
	// Of the http-upstream listener: one that names no client, and one that
	// goes through.
	exchange(dialEdge(t, "", loopback(upstreamPort)),
		"GET "+target+" HTTP/1.1\r\nHost: web.example.com\r\n"+headers+"X-Forwarded-For: "+query+"\r\n\r\n")
	exchange(dialEdge(t, "", loopback(upstreamPort)),
		"GET "+target+" HTTP/1.1\r\nHost: web.example.com\r\n"+headers+"X-Forwarded-For: 198.51.100.1\r\n\r\n")

	out := logs.String()
	if !strings.Contains(out, "cannot reach the backend") {
		t.Fatalf("the log has not even the backend that cannot be reached:\n%s", out)
	}
	for _, marker := range []string{query, bearer} {
		if strings.Contains(out, marker) {
			t.Errorf("the log has %q in it:\n%s", marker, out)
		}
	}
}

// A Host or an :authority with a port reaches the backend without it: telemt
// matches its vhost on the name alone, and a port gets the client its generic 404
// instead of the decoy. A Host without a port goes as it came.
func TestWebHostReachesTheBackendWithoutItsPort(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	client, _ := webClient(t, ca, "", loopback(port))
	for _, u := range []string{"https://web.example.com:443/x", "https://web.example.com:8443/x"} {
		resp, err := client.Do(newRequest(t, http.MethodGet, u, ""))
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		if got := decodeEcho(t, resp); got.Host != "web.example.com" || resp.Proto != "HTTP/2.0" {
			t.Errorf("HTTP/2 %s: the backend saw the Host %q over %s, want web.example.com", u, got.Host, resp.Proto)
		}
	}
	for host, want := range map[string]string{
		"web.example.com:443":  "web.example.com",
		"Web.Example.com:8443": "Web.Example.com",
		"Web.Example.com":      "Web.Example.com",
	} {
		c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
		if got := decodeEcho(t, rawExchange(t, c, bufio.NewReader(c), "GET /y HTTP/1.1\r\nHost: "+host+"\r\n\r\n")); got.Host != want {
			t.Errorf("HTTP/1.1 Host %q: the backend saw %q, want %q", host, got.Host, want)
		}
	}
}

func TestHostWithoutPort(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":       "example.com",
		"example.com:443":   "example.com",
		"example.com:8443":  "example.com",
		"192.0.2.1:80":      "192.0.2.1",
		"[2001:db8::1]:443": "[2001:db8::1]",
		"[2001:db8::1]":     "[2001:db8::1]",
		"2001:db8::1":       "2001:db8::1",
		"":                  "",
	} {
		if got := hostWithoutPort(in); got != want {
			t.Errorf("hostWithoutPort(%q) = %q, want %q", in, got, want)
		}
	}
}
