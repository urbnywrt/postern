package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/urbnywrt/postern/internal/edge/rules"
)

// WEB proxies.
//
// A route of kind web leads to the WEB listener of an engine (telemt's
// listener of transport "web", on the loopback interface), which does not
// terminate TLS itself. The edge does. For a connection whose server name has a
// web route, it feeds what it read of the connection, the ClientHello first, to
// a TLS server of its own with the certificate of the name (certs.go), serves
// HTTP/2 or HTTP/1.1 as the client asks by ALPN, and passes every request on to
// the backend of the route over HTTP/1.1 (webproxy.go). A WEB proxy placed under
// a path of another web server reaches the edge as plain HTTP on a listener of
// kind http-upstream instead (httpupstream.go). One HTTP server serves both.
//
// A web connection is a connection of its proxy as a relayed one is: it holds
// its place in the caps of ingress.go and in the limits of the proxy from before
// its TLS begins to its end, and its bytes on the wire are counted. The requests
// and the HTTP/2 streams on it are not connections of their own; they are what
// keeps the backend of the proxy busy (backend_active), as long as each of them
// lasts. Every request takes the web route of the proxy in the table in effect
// as it comes, so that the requests of a long-lived connection go to the new
// generation of the engine once the route has moved to it; when the listener
// has no web route of the proxy for the name any more (a paused proxy), the
// request is refused with 421 Misdirected Request, which sends the client to a
// new connection.
//
// The requests in flight to the backends are bounded, in all and for one
// source, and a stream whose client takes or sends nothing for
// webProgressTimeout loses its place (takeWebSlot, webResponse, webBody): one
// client cannot hold the WEB proxies of the node down. The node's own probes
// take no place.
//
// Nothing about a request is logged: its URL and its headers carry what the
// client authenticates with.

// The timeouts and bounds of web connections.
const (
	// webHandshakeTimeout bounds the TLS handshake after the ClientHello.
	webHandshakeTimeout = 10 * time.Second
	// webHeaderTimeout bounds the reading of the headers of a request, from
	// its first byte.
	webHeaderTimeout = 20 * time.Second
	// webIdleTimeout ends a connection on which nothing was read or written
	// for that long, and a connection kept alive without a request. It is above
	// the 65 s that a WebSocket of the engine may stay quiet between its pings,
	// and well above the 25 s of a long poll.
	webIdleTimeout = 90 * time.Second
	// webMaxHeaderBytes is the most bytes of the headers of a request, and of
	// a response of a backend.
	webMaxHeaderBytes = 64 << 10
	// webMaxStreams is the most requests at a time on one HTTP/2 connection:
	// the http2_max_concurrent_streams of nginx.
	webMaxStreams = 128
	// webProgressTimeout is the time that a write of a response to a client,
	// or a read of the body of a request from it, has to make progress in;
	// otherwise the stream is lost, and its place among the requests in flight
	// with it. Only a write or a read that is under way is timed: a long poll,
	// whose backend writes nothing until it answers, is not.
	webProgressTimeout = 30 * time.Second
	// One source holds max(minPerSourceSlots, Options.MaxConns /
	// perSourceSlotsDivisor) of the requests in flight at most.
	minPerSourceSlots     = 32
	perSourceSlotsDivisor = 16
)

// webConn is a connection that the HTTP server of the edge serves, as the
// server sees it: under the TLS of the edge for a web route, as it is for an
// http-upstream listener. It replays what was read before, counts the bytes
// that go through it, ends after webIdleTimeout without a read or a write, and
// tells when it is closed.
type webConn struct {
	net.Conn // the connection the edge accepted

	listener netip.AddrPort // the address of the listener that accepted it
	peer     netip.AddrPort // where it comes from: the client, or the web server in front of an http-upstream listener
	w        *watchdog
	done     chan struct{} // closed by Close
	once     sync.Once

	// Of a connection of a web route.
	replay  []byte           // read with the ClientHello; Read returns it first
	ls      *lease           // where the bytes of the connection are counted; nil to count nothing
	cert    *tls.Certificate // the certificate it is served
	sni     string           // its folded server name
	proxyID string           // the proxy of its route
	probe   bool             // one of the node's own probes, on a test listener

	// upstream is set for a connection of an http-upstream listener, whose
	// requests are routed by their Host.
	upstream bool
}

// newWebConn wraps c, which the listener at listener accepted from peer, and
// starts its idle timeout. The caller stops it.
func newWebConn(c net.Conn, listener, peer netip.AddrPort) *webConn {
	wc := &webConn{Conn: c, listener: listener, peer: peer, done: make(chan struct{})}
	wc.w = startWatchdog(webIdleTimeout, func() { _ = c.Close() })
	return wc
}

// Read returns what was read with the ClientHello first, then what comes. The
// TLS server, and then the HTTP server, read a connection from one goroutine
// at a time.
func (c *webConn) Read(p []byte) (int, error) {
	if len(c.replay) > 0 {
		n := copy(p, c.replay)
		if c.replay = c.replay[n:]; len(c.replay) == 0 {
			c.replay = nil // what is replayed is let go
		}
		return n, nil
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.w.touch()
		if c.ls != nil {
			c.ls.addUp(n)
		}
	}
	return n, err
}

func (c *webConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.w.touch()
		if c.ls != nil {
			c.ls.addDown(n)
		}
	}
	return n, err
}

// CloseWrite ends the stream to the peer and leaves the other way open: a
// WebSocket of an http-upstream listener that the backend ends is half-closed
// as a relayed connection is.
func (c *webConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *webConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

// serveWeb serves a connection of the web route r with the certificate cert,
// which the caller found: it completes the TLS handshake that the replayed
// ClientHello began, hands the connection to the HTTP server, and returns once
// the connection has ended. addr is the address of the listener that accepted
// the connection, and ls its lease, nil for a probe. The caller closes the
// connection, and gives the lease back.
func (e *Edge) serveWeb(f *flow, addr netip.AddrPort, r *route, cert *tls.Certificate, replay []byte, client netip.AddrPort, ls *lease, probe bool) {
	wc := newWebConn(f.client, addr, client)
	defer wc.w.stop()
	wc.replay, wc.ls, wc.cert = replay, ls, cert
	wc.sni, wc.proxyID, wc.probe = r.sni, r.proxyID, probe
	if ls != nil {
		ls.addUp(len(replay))
	}
	tc := tls.Server(wc, e.web.tlsConfig)
	if err := handshakeWithin(tc, webHandshakeTimeout); err != nil {
		e.log.Debug("edge: the TLS handshake of a web connection failed", "proxy", r.proxyID, "sni", r.sni,
			"client", client.Addr(), "err", err)
		return
	}
	if e.web.serve(tc) {
		<-wc.done
	}
}

// handshakeWithin makes the TLS handshake of c within d.
func handshakeWithin(c *tls.Conn, d time.Duration) error {
	if err := c.SetDeadline(time.Now().Add(d)); err != nil {
		return err
	}
	if err := c.Handshake(); err != nil {
		return err
	}
	return c.SetDeadline(time.Time{})
}

// webCert returns the certificate for a connection of the web route r, or nil
// when the name of the route has none that is valid now. Then it logs why, at
// most once per certWarnInterval for a domain, and never anything of the key.
func (e *Edge) webCert(r *route) *tls.Certificate {
	cert, err := e.certs.lookup(r.sni, time.Now())
	if err == nil {
		return cert
	}
	level := slog.LevelDebug
	if e.certWarns.allow("serve "+r.sni, e.now()) {
		level = slog.LevelWarn
	}
	e.log.Log(context.Background(), level, "edge: a WEB domain has no valid certificate; its connections get the alert unrecognized_name",
		"domain", r.sni, "proxy", r.proxyID, "err", err)
	return nil
}

// updateCerts makes refs the certificates of the web routes (see certs.go), and
// logs what it read: a certificate that cannot be read at most once per
// certWarnInterval for a domain.
func (e *Edge) updateCerts(refs []certRef) {
	for _, l := range e.certs.update(refs) {
		if l.err == nil {
			e.log.Info("edge: certificate read", "domain", l.domain, "generation", l.gen,
				"not_after", l.notAfter.UTC().Format(time.RFC3339))
			continue
		}
		msg := "edge: the certificate of a WEB domain cannot be read; its connections get the alert unrecognized_name"
		if l.kept {
			msg = "edge: the new certificate of a WEB domain cannot be read; the one before it is still served"
		}
		level := slog.LevelDebug
		if e.certWarns.allow("read "+l.domain, e.now()) {
			level = slog.LevelWarn
		}
		e.log.Log(context.Background(), level, msg, "domain", l.domain, "generation", l.gen, "err", l.err)
	}
}

// webCertificate is the GetCertificate of the TLS server of the web routes: a
// connection is served the certificate that serveWeb found for it, for its
// server name. Anything else gets the alert unrecognized_name.
func webCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if wc, ok := hi.Conn.(*webConn); ok && wc.cert != nil && rules.Fold(hi.ServerName) == wc.sni {
		return wc.cert, nil
	}
	return nil, nil // with no Certificates, crypto/tls sends unrecognized_name
}

// webRoute returns the route that a request of the web connection wc takes:
// the web route of its proxy for its server name on its listener, in the table
// in effect now; nil when there is none any more.
func (e *Edge) webRoute(wc *webConn) *route {
	t := e.table.Load()
	if t == nil {
		return nil
	}
	l := t.listeners[wc.listener]
	if l == nil || l.kind != rules.KindTLS {
		return nil
	}
	r := l.routeFor(wc.sni, wc.probe)
	if r == nil || r.kind != routeWeb || r.proxyID != wc.proxyID {
		return nil
	}
	return r
}

type webConnKey struct{}

// serveWebRequest serves a request of a web connection.
func (e *Edge) serveWebRequest(rw http.ResponseWriter, req *http.Request) {
	defer e.recoverRequest()
	wc, _ := req.Context().Value(webConnKey{}).(*webConn)
	if wc == nil { // cannot be: the server serves webConns only
		answer(rw, req, http.StatusInternalServerError, true)
		return
	}
	// The request goes to the backend over HTTP/1.1, and HTTP/2 lets through
	// what no HTTP/1.1 request may carry: a method that is no token, a path
	// with a space or a byte beyond ASCII. That is the client's fault, and
	// nothing is dialed for it.
	if !httpguts.ValidHeaderFieldName(req.Method) || !validTarget(req.RequestURI) {
		e.log.Debug("edge: a WEB request that HTTP/1.1 cannot carry refused")
		answer(rw, req, http.StatusBadRequest, true)
		return
	}
	if wc.upstream {
		e.serveUpstream(rw, req, wc)
		return
	}
	// A request asks for the name of its connection. One for another name
	// (a client that coalesced HTTP/2 connections under a certificate of
	// several names) is sent to a connection of its own. A Host with a port
	// that is no port is no Host at all.
	name, ok := hostName(req.Host)
	if !ok {
		e.log.Debug("edge: a WEB request with a Host whose port is no port refused")
		answer(rw, req, http.StatusBadRequest, true)
		return
	}
	if name != wc.sni {
		answer(rw, req, http.StatusMisdirectedRequest, true)
		return
	}
	r := e.webRoute(wc)
	if r == nil {
		answer(rw, req, http.StatusMisdirectedRequest, true)
		return
	}
	// The node's own probes take no place among the requests in flight, as
	// they take none in the caps of ingress.go.
	if !wc.probe {
		src, ok := e.takeWebSlot(rw, req, wc.peer.Addr())
		if !ok {
			return
		}
		defer e.giveWebSlot(src)
	}
	e.proxyWeb(rw, req, &webTarget{route: r, client: wc.peer.Addr(), busy: !wc.probe})
}

// validTarget reports whether target, the request target of a request, can
// stand in an HTTP/1.1 request line as it is: it is not empty, and is of
// visible ASCII alone, with no space and no control byte.
func validTarget(target string) bool {
	if target == "" {
		return false
	}
	for i := range len(target) {
		if c := target[i]; c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}

// takeWebSlot takes a place among the requests in flight to the backends for
// req, whose client is client, or answers it 503 with Retry-After when there is
// none. It reports whether it took one, and returns the source of the request,
// which the caller gives back with giveWebSlot once the request is done.
//
// A request in flight holds a connection to a backend, goroutines and
// buffers, as a relayed connection does, and one HTTP/2 connection carries
// many: the requests are bounded as the connections of the edge are
// (Options.MaxConns), whose cap was made for what they hold. One source, the
// sourceKey of the client (an IPv4 address, an IPv6 /64), holds maxPerSource
// of them at most, so that it cannot take them all. A long poll, or a
// WebSocket, holds its place for as long as it lasts; a stream that makes no
// progress loses it (see webResponse and webBody). A request whose backend
// answered early, before its HTTP/1.1 body was whole, holds its place while
// Go reads the rest of the body from a client that has stalled: until the
// activity watchdog of the connection (webIdleTimeout, 90 s) closes it.
func (e *Edge) takeWebSlot(rw http.ResponseWriter, req *http.Request, client netip.Addr) (netip.Addr, bool) {
	w := e.web
	src := sourceKey(client)
	w.slotsMu.Lock()
	full, sourceFull := w.inflight.Load() >= w.maxInflight, w.sources[src] >= w.maxPerSource
	if !full && !sourceFull {
		w.inflight.Add(1)
		w.sources[src]++
	}
	w.slotsMu.Unlock()
	switch {
	case full:
		if e.warns.allow("web requests in flight", e.now()) {
			e.log.Warn("edge: as many WEB requests are in flight as the edge may hold connections; the others are answered 503",
				"max", w.maxInflight)
		}
	case sourceFull:
		e.log.Debug("edge: a source has as many WEB requests in flight as one may", "source", src)
		if e.warns.allow("web requests of a source", e.now()) {
			e.log.Warn("edge: a source has as many WEB requests in flight as one may; its others are answered 503",
				"max_per_source", w.maxPerSource)
		}
	default:
		return src, true
	}
	rw.Header().Set("Retry-After", "1")
	answer(rw, req, http.StatusServiceUnavailable, true)
	return src, false
}

// giveWebSlot gives back the place that takeWebSlot took for src.
func (e *Edge) giveWebSlot(src netip.Addr) {
	w := e.web
	w.slotsMu.Lock()
	defer w.slotsMu.Unlock()
	w.inflight.Add(-1)
	if w.sources[src]--; w.sources[src] <= 0 {
		delete(w.sources, src)
	}
}

// recoverRequest stops a panic in the handler of a request and logs it as an
// error, but for the one with which the HTTP server aborts a response, and
// aborts the response: the server closes the connection then, and logs nothing.
// It must be the deferred function itself, for recover to see the panic.
func (e *Edge) recoverRequest() {
	r := recover()
	if r == nil {
		return
	}
	if err, ok := r.(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
		e.log.Error("edge: panic while serving a web request", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
	}
	panic(http.ErrAbortHandler)
}

// answer answers a request with status and no body. end asks an HTTP/1
// client to close the connection afterwards.
func answer(rw http.ResponseWriter, req *http.Request, status int, end bool) {
	if end && req.ProtoMajor == 1 {
		rw.Header().Set("Connection", "close")
	}
	rw.WriteHeader(status)
}

// webServer is the HTTP server of the web connections of an edge: one
// http.Server for all of them, fed through a connQueue. It starts with the
// first connection, and stops when the edge drains.
type webServer struct {
	log       *slog.Logger
	base      context.Context // of every request: it ends when the edge gives up its drain
	handler   http.Handler
	tlsConfig *tls.Config
	proxy     *httputil.ReverseProxy
	transport *http.Transport
	backends  *webBackendConns

	// inflight counts the requests being passed on to the backends, of the web
	// routes and of the http-upstream listeners together; there are
	// maxInflight at most, and maxPerSource of one source (see takeWebSlot).
	// Changes of inflight, and sources, are made under slotsMu.
	inflight     atomic.Int64
	maxInflight  int64
	maxPerSource int64
	slotsMu      sync.Mutex
	sources      map[netip.Addr]int64 // the requests in flight by source; no zero entries

	// progress is the time that a write of a response, or a read of the body
	// of a request, has to make progress in (webProgressTimeout; a field, so
	// that tests can shorten it).
	progress time.Duration

	mu       sync.Mutex
	srv      *http.Server // nil until the first connection
	queue    *connQueue
	served   chan struct{} // closed when Serve has returned
	stopping bool
	// shutdown is closed when the Shutdown that stop began has returned;
	// endShutdown makes it return.
	shutdown    chan struct{}
	endShutdown context.CancelFunc
}

func newWebServer(e *Edge) *webServer {
	w := &webServer{
		log:     e.log,
		base:    e.ctx,
		handler: http.HandlerFunc(e.serveWebRequest),
		tlsConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
			GetCertificate: webCertificate,
		},
		backends:     newWebBackendConns(e.opts.DialTimeout),
		maxInflight:  int64(e.opts.MaxConns),
		maxPerSource: int64(max(minPerSourceSlots, e.opts.MaxConns/perSourceSlotsDivisor)),
		sources:      make(map[netip.Addr]int64),
		progress:     webProgressTimeout,
	}
	w.transport = newWebTransport(w.backends)
	w.proxy = e.newWebProxy(w.transport)
	return w
}

// serve hands c to the HTTP server, which it starts with the first connection.
// It returns false when the server takes no connection any more, because the
// edge drains; c is not touched then.
func (w *webServer) serve(c net.Conn) bool {
	w.mu.Lock()
	if w.stopping {
		w.mu.Unlock()
		return false
	}
	if w.srv == nil {
		w.startLocked()
	}
	q := w.queue
	w.mu.Unlock()
	return q.push(c)
}

func (w *webServer) startLocked() {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true) // over TLS: the connections of an http-upstream listener speak HTTP/1
	srv := &http.Server{
		Handler:           w.handler,
		ReadHeaderTimeout: webHeaderTimeout,
		IdleTimeout:       webIdleTimeout,
		MaxHeaderBytes:    webMaxHeaderBytes,
		Protocols:         &protocols,
		// WebSockets go over upgrades of HTTP/1.1, which ReverseProxy passes
		// on; extended CONNECT over HTTP/2 (RFC 8441) it could not. Go 1.27
		// has no setting of a server for it: it is off unless GODEBUG has
		// http2xconnect=1, and TestWebDoesNotOfferWebSocketsOverHTTP2 pins it.
		//
		// An HTTP/2 connection is closed when one of its writes to the TLS
		// connection, a flush of its 4 KiB buffer or a frame of up to about
		// 32 KiB, does not go through within the progress timeout
		// (WriteByteTimeout): when the client takes nothing and the buffers
		// of the sockets are full, the reset of a stream could not get
		// through either. WriteByteTimeout would give a write that time again
		// for every byte that goes, but crypto/tls fails a write that times
		// out for good: the time holds for each write whole.
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: webMaxStreams, WriteByteTimeout: w.progress},
		// OPTIONS * goes to the engine as well: the server answers nothing of its own.
		DisableGeneralOptionsHandler: true,
		BaseContext:                  func(net.Listener) context.Context { return w.base },
		ConnContext:                  webConnContext,
		// What the server logs is about connections that fail, and only that.
		ErrorLog: slog.NewLogLogger(w.log.Handler(), slog.LevelDebug),
	}
	q, served := newConnQueue(), make(chan struct{})
	w.srv, w.queue, w.served = srv, q, served
	go func() {
		defer close(served)
		_ = srv.Serve(q)
	}()
}

// webConnContext puts the webConn of a connection in the context of its
// requests.
func webConnContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	if wc, ok := c.(*webConn); ok {
		return context.WithValue(ctx, webConnKey{}, wc)
	}
	return ctx
}

// stop makes the server take no more connections, closes those that wait for
// a request, and tells those of HTTP/2 to go away (GOAWAY); the requests in
// flight go on. Drain calls it when it begins.
func (w *webServer) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopping {
		return
	}
	w.stopping = true
	if w.srv == nil {
		return
	}
	ctx, cancel := context.WithCancel(w.base)
	srv, done := w.srv, make(chan struct{})
	w.shutdown, w.endShutdown = done, cancel
	go func() {
		defer close(done)
		_ = srv.Shutdown(ctx)
	}()
}

// finish closes what is left of the server and of the connections to the
// backends, and waits for the goroutines of the server. Drain calls it last,
// when every connection of the edge has ended or has been closed.
func (w *webServer) finish() {
	w.stop()
	w.mu.Lock()
	srv, served, shutdown, endShutdown := w.srv, w.served, w.shutdown, w.endShutdown
	w.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
		endShutdown()
		<-shutdown
		<-served
	}
	w.transport.CloseIdleConnections()
	w.backends.closeAll()
}

// connQueue is the listener of the HTTP server of the web connections: the
// edge hands it the connections that it accepted and read the start of.
type connQueue struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newConnQueue() *connQueue {
	return &connQueue{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case c := <-q.conns:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

func (q *connQueue) Close() error {
	q.once.Do(func() { close(q.done) })
	return nil
}

func (q *connQueue) Addr() net.Addr { return queueAddr{} }

// push hands c to Accept, and reports whether it was taken: not once the queue
// is closed.
func (q *connQueue) push(c net.Conn) bool {
	select {
	case q.conns <- c:
		return true
	case <-q.done:
		return false
	}
}

// queueAddr is the address of a connQueue, which has none.
type queueAddr struct{}

func (queueAddr) Network() string { return "edge" }
func (queueAddr) String() string  { return "web connections" }
