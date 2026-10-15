package edge

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The proxying of the requests of the web routes to their backends.
//
// Every request of a vhost goes to the backend of its route as it came: the
// request target to the byte, the Host as the client sent it (but for its port
// on a web route: hostWithoutPort), the body as it
// comes, without waiting for its end. The edge takes out the hop-by-hop headers
// (ReverseProxy does: Connection and the headers it names, Keep-Alive,
// Proxy-Connection, Proxy-Authenticate, Proxy-Authorization, Te but for
// "trailers", Trailer, Transfer-Encoding, and Upgrade but for an upgrade), and
// every header in which a client may say who it is: Forwarded, every header
// whose name begins with X-Forwarded- (X-Forwarded-For-Original among them),
// X-Real-IP, True-Client-IP, CF-Connecting-IP, X-Client-IP, X-Cluster-Client-IP
// and Fastly-Client-IP. It puts in X-Forwarded-For with the address of the
// client alone, from which the engine takes it. The response goes back as the
// backend sends it, every write flushed, so that a long poll or a stream
// reaches the client at once, and a WebSocket (an upgrade of HTTP/1.1) goes
// through both ways. A body over webMaxBody is refused with 413.
//
// A failure before the backend answers is put down to the backend only when
// the dial failed, or when a connection to the backend was had and the body of
// the request had come whole: that gets the client a 502, and is logged as for
// a relayed connection. Any other is a fault of the request, and so of the
// client: a body that cannot be read or does not come whole, an upgrade to no
// protocol, a request that the transport refuses before it connects (a
// declared trailer that is no header name, which HTTP/2 lets through) is
// answered 400 and logged at the debug level only. A backend that answers an
// upgrade wrongly gets the client a 502 too, logged at the debug level only. A
// client that went away, or an upgraded connection that fails, is dropped.

const (
	// webMaxBody is the most bytes of the body of a request: the
	// max_body_bytes of the WEB transport of telemt, 2 MiB.
	webMaxBody = 2 << 20
	// webBackendTimeout bounds the wait of a request for the headers of its
	// response, and every read and write of a connection to a backend: above
	// the 65 s that a WebSocket of the engine may stay quiet, as webIdleTimeout.
	webBackendTimeout = 90 * time.Second
	// webBackendIdle closes a connection to a backend after it has had no
	// request for that long; it is below webBackendTimeout, so that a pooled
	// connection is closed before a read of it times out.
	webBackendIdle = 60 * time.Second
	// webBackendIdleConns is the most connections kept open to one backend
	// between requests.
	webBackendIdleConns = 64
)

// webTarget is where a request goes, and for whom.
type webTarget struct {
	route  *route
	client netip.Addr // what the backend gets in X-Forwarded-For
	// keepHost passes the Host on with its port, as it came: a request of an
	// http-upstream listener, whose backend may build redirects and cookies from
	// Host:port. A web route goes to telemt, which wants the name alone.
	keepHost bool
	// ls is the lease of a request of an http-upstream listener, which is a
	// connection of the proxy of its own: its bytes are counted on it. A request
	// of a web route has none; its bytes are counted on its connection.
	ls *lease
	// busy counts the request in the backend_active of its proxy while it lasts
	// (a request of a web route; a lease counts itself).
	busy bool

	// What became of the request, for webProxyError. All of it but gotConn is
	// set in the goroutine of the handler, before ReverseProxy calls
	// webProxyError there.
	body       *webBody    // the body of the client; nil when it has none, or one of no bytes
	roundTrip  bool        // the round trip to the backend was made
	backendErr error       // the error of the round trip
	gotConn    atomic.Bool // a connection to the backend was had for the request
}

type webTargetKey struct{}

// targetOf returns the target of a request that proxyWeb passed on.
func targetOf(req *http.Request) *webTarget {
	tg, _ := req.Context().Value(webTargetKey{}).(*webTarget)
	return tg
}

// proxyWeb passes req on to the backend of the route of tg.
func (e *Edge) proxyWeb(rw http.ResponseWriter, req *http.Request, tg *webTarget) {
	if req.ContentLength > webMaxBody {
		answer(rw, req, http.StatusRequestEntityTooLarge, true)
		return
	}
	if tg.busy && tg.route.stats != nil {
		defer tg.route.stats.busy(tg.route.backendKey)()
	}
	// A body of no bytes (an HTTP/2 request that ends with its headers has
	// one) is whole from the start: ReverseProxy sends none.
	if req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0 {
		tg.body = newWebBody(req.Body, rw, e.web.progress)
		// The transport may read the body after the handler has returned,
		// when the ResponseWriter is no more.
		defer tg.body.handlerDone()
		if tg.ls != nil {
			tg.body.count = tg.ls.addUp
		}
		req.Body = http.MaxBytesReader(rw, tg.body, webMaxBody)
	}
	ctx := context.WithValue(req.Context(), webTargetKey{}, tg)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { tg.gotConn.Store(true) },
	})
	e.web.proxy.ServeHTTP(newWebResponse(rw, e.web.progress), req.WithContext(ctx))
}

// newWebProxy returns the reverse proxy of the web routes, over transport.
func (e *Edge) newWebProxy(transport *http.Transport) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite:        rewriteWeb,
		Transport:      webRoundTripper{transport},
		FlushInterval:  -1,
		ModifyResponse: countWebResponse,
		ErrorHandler:   e.webProxyError,
		ErrorLog:       slog.NewLogLogger(e.log.Handler(), slog.LevelDebug),
	}
}

// clientIPHeaders are the headers in which a client, or a proxy before the
// edge, may say who the client is, besides those of X-Forwarded-: the edge
// takes them out of every request.
var clientIPHeaders = []string{"Forwarded", "X-Real-Ip", "True-Client-Ip", "Cf-Connecting-Ip", "X-Client-Ip",
	"X-Cluster-Client-Ip", "Fastly-Client-Ip"}

// rewriteWeb makes the request to the backend; ReverseProxy has taken out the
// hop-by-hop headers already.
func rewriteWeb(pr *httputil.ProxyRequest) {
	tg := targetOf(pr.In)
	out := pr.Out
	out.URL.Scheme = "http"
	out.URL.Host = tg.route.backendKey
	out.URL.User = nil
	setRequestTarget(out.URL, pr.In)
	out.Host = pr.In.Host
	if !tg.keepHost {
		out.Host = hostWithoutPort(out.Host)
	}
	for name := range out.Header {
		if strings.HasPrefix(name, "X-Forwarded-") {
			delete(out.Header, name)
		}
	}
	for _, name := range clientIPHeaders {
		out.Header.Del(name)
	}
	out.Header["X-Forwarded-For"] = []string{tg.client.String()}
}

// hostWithoutPort returns the Host of a request, or its :authority under
// HTTP/2, without its port: the name, or the address, an IPv6 one in its
// brackets. The WEB listener of telemt matches its vhost on the name alone, and
// a Host with a port, which a client or a front server may send, gets its
// generic 404 instead of the decoy. A Host without a port is returned as it is.
func hostWithoutPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

// setRequestTarget makes u, the URL of the request to the backend, give the
// request target of in as it came, byte for byte: as Opaque, which the
// transport writes as it is, where Go would escape bytes of a path again (|,
// ^, {, } and `), and with the query as it came, whose parameters ReverseProxy
// would leave out when it cannot parse them. A path that begins with "//" is
// the exception: as Opaque it would make the request line an absolute URI, so
// it goes as Go parsed it, which only those bytes of it could change. So do
// "*" and an absolute URI.
func setRequestTarget(u *url.URL, in *http.Request) {
	uri := in.RequestURI
	if !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") {
		u.RawQuery = in.URL.RawQuery
		return
	}
	path, query, hasQuery := strings.Cut(uri, "?")
	u.Opaque, u.RawQuery, u.ForceQuery = path, query, hasQuery && query == ""
}

// webRoundTripper is the transport of ReverseProxy: it records on the target
// of a request that its round trip to the backend was made, and how it failed,
// which tells a backend that cannot be reached from a fault of the client. It
// tells the body of the request that the backend has answered, before the
// answer goes out (see webBody).
type webRoundTripper struct{ *http.Transport }

func (t webRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.Transport.RoundTrip(req)
	if tg := targetOf(req); tg != nil {
		tg.roundTrip, tg.backendErr = true, err
		if err == nil && tg.body != nil {
			tg.body.answered.Store(true)
		}
	}
	return res, err
}

// webResponse is the ResponseWriter that ReverseProxy writes to.
//
// Every write of the response, and every flush of it, has to make progress
// within the progress timeout: a client that takes no byte of it for that long
// loses the stream, and with it the place of the request among those in
// flight. Over HTTP/1.1 the deadline is that of the connection, and holds when
// the TCP window of the client is full too. Over HTTP/2 it is the deadline of
// the stream, which holds when the window of the stream is 0; when the
// connection itself cannot write (the TCP window is full), the reset of the
// stream cannot be sent either, and it is the WriteByteTimeout of the server
// (startLocked) that closes the connection, with every stream on it. The
// deadline is armed only while a write is under way, so that a long poll, whose
// backend writes nothing until it answers, is not touched; ReverseProxy
// flushes after every write, and the flush is what waits for the client under
// HTTP/2. The tunnel of an upgrade is not written through here: it has the
// deadlines of webIdleTimeout and webBackendTimeout.
//
// It also tells whether the connection of the client was hijacked for an
// upgrade, after which nothing can be answered on it.
type webResponse struct {
	http.ResponseWriter
	rc       *http.ResponseController // of the ResponseWriter of the server
	progress time.Duration
	hijacked bool
}

func newWebResponse(rw http.ResponseWriter, progress time.Duration) *webResponse {
	return &webResponse{ResponseWriter: rw, rc: http.NewResponseController(rw), progress: progress}
}

func (w *webResponse) Write(p []byte) (int, error) {
	defer w.writing()()
	return w.ResponseWriter.Write(p)
}

// FlushError flushes the response, within the progress timeout.
func (w *webResponse) FlushError() error {
	defer w.writing()()
	return w.rc.Flush()
}

// WriteHeader passes the header of the response on: an informational one
// (1xx, not 101) goes out at once, within the progress timeout.
func (w *webResponse) WriteHeader(code int) {
	if code >= 100 && code <= 199 && code != http.StatusSwitchingProtocols {
		defer w.writing()()
	}
	w.ResponseWriter.WriteHeader(code)
}

// writing arms the deadline of a write, and returns the function that
// disarms it once the write is done.
func (w *webResponse) writing() (done func()) {
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.progress))
	return func() { _ = w.rc.SetWriteDeadline(time.Time{}) }
}

// Unwrap lets http.ResponseController reach the ResponseWriter of the server.
func (w *webResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack hijacks the connection of the client for an upgrade; a hijack that
// fails (HTTP/2 has none) is no hijack, and the client is still answered.
func (w *webResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, brw, err := w.rc.Hijack()
	if err == nil {
		w.hijacked = true
	}
	return c, brw, err
}

// webBody is the body of a request as its client sends it.
//
// Every read of it has to make progress within the progress timeout: a client
// that sends no byte of its body for that long loses the request, and its
// place among those in flight. The deadline is armed only while a read is
// under way.
//
// Where the request fails, the deadline is left expired: when a read fails,
// the timeout of a stalled upload among them, and when the body was closed
// before its end while the backend has not answered (the request is answered
// 400 or 413, its backend cannot be had, or its client is gone). Such a close
// is put off until the handler returns (handlerDone): the request has been
// answered by then, by its outcome. Go's close of an HTTP/1.1 body reads the
// rest of it, and a read that failed on the expired deadline there would end
// the context of the request before webProxyError judged it, so a POST whose
// body follows its head, to a backend that cannot be dialed, would be dropped
// as one whose client went away, not answered 502. What Go would
// read of the rest of an HTTP/1.1 body from the connection to keep it (up to
// 256 KiB, with no deadline of its own) then fails at once, and does not hold
// the request until the client goes; Go closes the connection after the
// answer. The expiry is for good: no read clears it, and it is set once, since
// Go may have the rest of the body at hand, read it to its end, and go on to
// wait for the next request, a read that a second expiry would end.
//
// Once the backend has answered, the deadline is left alone. As the answer
// goes out, Go reads what is left of an HTTP/1.1 body itself, closes the body,
// and from its end reads the connection for the next request: a deadline that
// ended that read would make Go take the client for gone, cancel the context
// of the connection, and drop the next request on it. So a read of the body
// that Go has closed only clears the deadline of the read, and a close of the
// body sets none. So a client that stalls after such an early answer holds the
// connection, and the slot of its request (takeWebSlot), until the activity
// watchdog of the connection (webIdleTimeout, 90 s) closes it.
//
// It counts what is read of the body when count is set, and remembers whether
// reading it failed, or came to its end: the client's fault either way, or a
// failure of the backend that may be the client's while the body is not whole
// (see webProxyError).
type webBody struct {
	io.ReadCloser
	count    func(int)
	failed   atomic.Bool // set by the transport, read by the handler
	eof      atomic.Bool
	answered atomic.Bool // set by webRoundTripper, read by the transport

	rc       *http.ResponseController // of the ResponseWriter of the server
	progress time.Duration
	// The transport reads the body, from a goroutine of its own, and may go
	// on after the handler has returned, when the ResponseWriter is no more:
	// once done is set, the deadlines are not touched. Once expired is set,
	// the deadline is left expired (expire).
	mu      sync.Mutex
	done    bool
	expired bool
	// closed says that Close came before the end of the body while the
	// backend had not answered: handlerDone leaves the deadline expired.
	closed bool
}

func newWebBody(body io.ReadCloser, rw http.ResponseWriter, progress time.Duration) *webBody {
	return &webBody{ReadCloser: body, rc: http.NewResponseController(rw), progress: progress}
}

func (b *webBody) Read(p []byte) (int, error) {
	b.setDeadline(time.Now().Add(b.progress))
	n, err := b.ReadCloser.Read(p)
	if n > 0 && b.count != nil {
		b.count(n)
	}
	switch {
	case err == nil:
		b.setDeadline(time.Time{})
	case errors.Is(err, io.EOF):
		b.eof.Store(true)
		b.setDeadline(time.Time{})
	case errors.Is(err, http.ErrBodyReadAfterClose):
		// Closed under the transport: by Go, as the answer of the backend
		// went out, or by Close, which has seen to the deadline.
		b.setDeadline(time.Time{})
	default:
		b.failed.Store(true)
		b.expire()
	}
	return n, err
}

// Close closes the body. A body that is closed before its end while the
// backend has not answered is that of a request that fails: it is not closed
// until the handler returns, after the request was answered, and then leaves
// the deadline expired, so that what Go reads of the rest of it, as it closes
// the body after the handler, fails at once (see the type).
func (b *webBody) Close() error {
	if !b.eof.Load() && !b.answered.Load() {
		b.mu.Lock()
		putOff := !b.done
		if putOff {
			b.closed = true
		}
		b.mu.Unlock()
		if putOff {
			return nil
		}
		b.expire()
	}
	return b.ReadCloser.Close()
}

// longAgo is a deadline in the past, which makes a read fail at once.
var longAgo = time.Unix(1, 0)

// setDeadline sets the read deadline of the connection to d, unless the
// handler has returned or the deadline is left expired.
func (b *webBody) setDeadline(d time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.done && !b.expired {
		_ = b.rc.SetReadDeadline(d)
	}
}

// expire leaves the read deadline of the connection expired, for good, unless
// the handler has returned; it does so once.
func (b *webBody) expire() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.done && !b.expired {
		b.expired = true
		_ = b.rc.SetReadDeadline(longAgo)
	}
}

// handlerDone tells the body that the handler of its request returns: the
// ResponseWriter, on which its deadlines are set, is no more. A body that was
// closed before its end while the backend had not answered leaves the deadline
// expired first (see Close); Go closes it after the handler.
func (b *webBody) handlerDone() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed && !b.eof.Load() && !b.answered.Load() && !b.expired {
		b.expired = true
		_ = b.rc.SetReadDeadline(longAgo)
	}
	b.done = true
}

// countWebResponse counts the bytes of a response of a request of an
// http-upstream listener, the bytes of both ways of a WebSocket among them.
func countWebResponse(res *http.Response) error {
	tg := targetOf(res.Request)
	if tg == nil || tg.ls == nil || res.Body == nil {
		return nil
	}
	if rwc, ok := res.Body.(io.ReadWriteCloser); ok && res.StatusCode == http.StatusSwitchingProtocols {
		res.Body = &countedTunnel{ReadWriteCloser: rwc, ls: tg.ls}
		return nil
	}
	res.Body = &countedBody{ReadCloser: res.Body, count: tg.ls.addDown}
	return nil
}

// webProxyError answers a request that could not be passed on, or whose
// response could not be had, by whose fault it is (see the top of the file).
// Only a backend that cannot be dialed, or whose connection fails once a
// connection was had and the body of the request had come whole, is logged as
// one (backendDown), and gets the client a 502. A body over webMaxBody is
// answered 413; one that cannot be read, a connection that fails while the
// body is still coming, a request that the transport refuses before it
// connects, or an upgrade to no protocol, 400; a backend that answers an
// upgrade wrongly, 502 at the debug level. A client that went away, or a drain
// that gave up, aborts the request, and an upgraded connection that fails is
// left as it is. The URL and the headers of the request are never logged.
func (e *Edge) webProxyError(rw http.ResponseWriter, req *http.Request, err error) {
	tg := targetOf(req)
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		answer(rw, req, http.StatusRequestEntityTooLarge, true)
	case tg != nil && tg.body != nil && tg.body.failed.Load():
		// Before the context: over HTTP/1.1 a read that fails, the timeout of
		// a stalled upload among them, cancels the context of the request,
		// and the client may well still read its answer.
		e.log.Debug("edge: the body of a WEB request could not be read", "proxy", tg.route.proxyID, "err", err)
		answer(rw, req, http.StatusBadRequest, true)
	case req.Context().Err() != nil:
		e.log.Debug("edge: a WEB request ended without its client", "err", req.Context().Err())
		panic(http.ErrAbortHandler)
	case tg == nil: // cannot be: proxyWeb gives every request a target
		answer(rw, req, http.StatusBadGateway, true)
	case tg.backendErr != nil && (isDialError(err) || (tg.gotConn.Load() && (tg.body == nil || tg.body.eof.Load()))):
		e.backendDown(tg.route, err)
		answer(rw, req, http.StatusBadGateway, false)
	case tg.backendErr != nil:
		// Refused by the transport before it connected, or failed while the
		// body of the client was still coming: a request that cannot go, or a
		// client that holds its body back, as much as a backend that fails.
		e.log.Debug("edge: a WEB request failed before its backend had it whole", "proxy", tg.route.proxyID, "err", err)
		answer(rw, req, http.StatusBadRequest, true)
	case !tg.roundTrip:
		// Refused before the round trip: the client asked to upgrade to
		// something that is no protocol.
		e.log.Debug("edge: a WEB request asks for an upgrade to no protocol", "proxy", tg.route.proxyID)
		answer(rw, req, http.StatusBadRequest, true)
	case isHijacked(rw):
		e.log.Debug("edge: an upgraded WEB connection failed", "proxy", tg.route.proxyID)
	default:
		e.log.Debug("edge: the backend answered an upgrade wrongly", "proxy", tg.route.proxyID, "backend", tg.route.backendKey)
		answer(rw, req, http.StatusBadGateway, true)
	}
}

// isHijacked reports whether the connection of the client was hijacked under
// rw, the webResponse of a request.
func isHijacked(rw http.ResponseWriter) bool {
	w, ok := rw.(*webResponse)
	return ok && w.hijacked
}

// isDialError reports whether err is the failure of a dial.
func isDialError(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// countedBody counts what is read of a body.
type countedBody struct {
	io.ReadCloser
	count func(int)
}

func (b *countedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.count(n)
	}
	return n, err
}

// countedTunnel counts the bytes of both ways of an upgraded connection to a
// backend: what is written to it comes from the client, what is read goes to
// it.
type countedTunnel struct {
	io.ReadWriteCloser
	ls *lease
}

func (t *countedTunnel) Read(p []byte) (int, error) {
	n, err := t.ReadWriteCloser.Read(p)
	if n > 0 {
		t.ls.addDown(n)
	}
	return n, err
}

func (t *countedTunnel) Write(p []byte) (int, error) {
	n, err := t.ReadWriteCloser.Write(p)
	if n > 0 {
		t.ls.addUp(n)
	}
	return n, err
}

// newWebTransport returns the transport of the requests to the backends: HTTP/1.1
// over the connections of backends, kept alive between requests, the bytes of
// the responses passed on as they are (no compression is asked for), no proxy
// of the environment.
func newWebTransport(backends *webBackendConns) *http.Transport {
	return &http.Transport{
		DialContext:            backends.dial,
		ResponseHeaderTimeout:  webBackendTimeout,
		IdleConnTimeout:        webBackendIdle,
		MaxIdleConnsPerHost:    webBackendIdleConns,
		MaxResponseHeaderBytes: webMaxHeaderBytes,
		DisableCompression:     true,
	}
}

// webBackendConns are the connections of the edge to the backends of web routes,
// so that the end of a drain can close them all.
type webBackendConns struct {
	dialer net.Dialer

	mu     sync.Mutex
	conns  map[*webBackendConn]struct{}
	closed bool
}

func newWebBackendConns(dialTimeout time.Duration) *webBackendConns {
	return &webBackendConns{dialer: net.Dialer{Timeout: dialTimeout}, conns: make(map[*webBackendConn]struct{})}
}

// errBackendsClosed is the error of a dial to a backend once the drain is over.
var errBackendsClosed = errors.New("edge: drained, no connection to a backend is made")

func (b *webBackendConns) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := b.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	bc := &webBackendConn{Conn: c, set: b}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		_ = c.Close()
		return nil, errBackendsClosed
	}
	b.conns[bc] = struct{}{}
	return bc, nil
}

// closeAll closes every connection to a backend, and makes dial refuse any
// more.
func (b *webBackendConns) closeAll() {
	b.mu.Lock()
	b.closed = true
	conns := make([]*webBackendConn, 0, len(b.conns))
	for c := range b.conns {
		conns = append(conns, c)
	}
	b.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// webBackendConn is a connection to a backend. Every read and write of it has
// webBackendTimeout; a write gives a read in progress that long again, since
// what is written is to be answered.
type webBackendConn struct {
	net.Conn
	set *webBackendConns
}

func (c *webBackendConn) Read(p []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(webBackendTimeout))
	return c.Conn.Read(p)
}

func (c *webBackendConn) Write(p []byte) (int, error) {
	d := time.Now().Add(webBackendTimeout)
	_ = c.SetWriteDeadline(d)
	_ = c.SetReadDeadline(d)
	return c.Conn.Write(p)
}

func (c *webBackendConn) Close() error {
	c.set.mu.Lock()
	delete(c.set.conns, c)
	c.set.mu.Unlock()
	return c.Conn.Close()
}
