package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urbnywrt/postern/internal/edge/rules"
	"github.com/urbnywrt/postern/internal/proxyproto"
	"github.com/urbnywrt/postern/internal/tlsx"
)

// listener is a socket the edge listens on, and the goroutine that accepts on
// it.
type listener struct {
	addr netip.AddrPort
	ln   net.Listener
	stop chan struct{} // closed by close; ends a wait after a failed Accept
	done chan struct{} // closed when serve returns
}

// listen binds addr with the options of listenConfig. An IPv4 address is bound
// for IPv4 only and an IPv6 address for IPv6 only, the unspecified "::"
// included (nginx does the same by default), so that 0.0.0.0:443 and [::]:443
// are two listeners of their own.
func listen(addr netip.AddrPort) (*listener, error) {
	network := "tcp4"
	if addr.Addr().Is6() {
		network = "tcp6"
	}
	lc := listenConfig()
	ln, err := lc.Listen(context.Background(), network, addr.String())
	if err != nil {
		return nil, err
	}
	return &listener{addr: addr, ln: ln, stop: make(chan struct{}), done: make(chan struct{})}, nil
}

// close closes the socket and waits for serve to return. The connections it
// accepted are not touched.
func (l *listener) close() {
	close(l.stop)
	_ = l.ln.Close()
	<-l.done
}

// serve accepts connections on l until it is closed. An error of Accept other
// than that, such as running out of descriptors, makes it wait a moment, longer
// each time up to a second, and try again: the edge never gives a port up on
// its own.
func (e *Edge) serve(l *listener) {
	defer close(l.done)
	var delay time.Duration
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			if e.warns.allow("accept "+l.addr.String(), e.now()) {
				e.log.Warn("edge: accept failed, trying again", "addr", l.addr.String(), "err", err, "delay", delay)
			}
			select {
			case <-time.After(delay):
			case <-l.stop:
				return
			}
			continue
		}
		delay = 0
		e.accept(l.addr, c)
	}
}

// accept takes a connection the listener at addr accepted. A client of the
// blacklist is closed at once, before anything is read from it, and so is a
// connection over the caps of ingress.go, which is counted; one that comes when
// the cap on connections before their hello is full takes the place of the
// oldest of them. Any other connection is handled in a goroutine of its own,
// under the table in effect now. A listener of kind http-upstream takes its
// connections as httpupstream.go says.
func (e *Edge) accept(addr netip.AddrPort, c net.Conn) {
	client, local := addrPortOf(c.RemoteAddr()), addrPortOf(c.LocalAddr())
	t := e.table.Load()
	var l *listenerEntry
	if t != nil {
		l = t.listeners[addr]
	}
	// A listener the table no longer has is being closed. Without both
	// addresses there is no blacklist to check and no PROXY header to write.
	if l == nil || !client.IsValid() || !local.IsValid() {
		_ = c.Close()
		return
	}
	if l.kind == rules.KindHTTPUpstream {
		e.acceptUpstream(addr, l, c, client)
		return
	}
	if t.blacklist.contains(client.Addr()) {
		_ = c.Close()
		e.log.Debug("edge: blacklisted client closed", "listener", l.id, "client", client.Addr())
		return
	}
	// A probe of the node comes to a test listener from the loopback
	// interface. The deadline of the hello runs from now, on the real clock,
	// and so does the lifetime of a probe of the panel.
	probe := t.probes[addr] && client.Addr().IsLoopback()
	at := time.Now()
	tk, over, evicted := e.ingress.admit(c, client.Addr(), probe, at)
	if tk == nil {
		_ = c.Close()
		e.log.Debug("edge: connection over the caps closed", "listener", l.id, "client", client.Addr(), "cap", over)
		e.warnCaps()
		return
	}
	if evicted {
		e.log.Debug("edge: the oldest connection before its hello closed for a new one", "listener", l.id, "client", client.Addr())
		e.warnCaps()
	}
	f := e.conns.add(c)
	if f == nil { // Drain has begun
		tk.release()
		_ = c.Close()
		return
	}
	go func() {
		defer e.conns.remove(f)
		defer tk.release()
		defer e.recoverConn("connection", f.close)
		e.handle(t, addr, l, f, client, local, tk, at)
	}()
}

// recoverConn stops a panic in a goroutine that serves a connection: it logs
// the panic and its stack as an error and calls closeConns. A connection that
// trips a bug must not take every other session of the node down with it. It
// must be the deferred function itself, for recover to see the panic.
func (e *Edge) recoverConn(where string, closeConns func()) {
	if r := recover(); r != nil {
		e.log.Error("edge: panic while serving a connection", "in", where,
			"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
		closeConns()
	}
}

// helloBufSize is the size of the buffer the ClientHello is read through.
const helloBufSize = 4 << 10

var helloReaders = sync.Pool{New: func() any { return bufio.NewReaderSize(nil, helloBufSize) }}

// readHello reads the ClientHello from c through a pooled buffered reader, so
// that a hello cut into many tiny records costs a few reads of the socket, not
// three for every record: 64 KiB of one-byte records would be some 33 thousand.
//
// It returns the hello and the bytes to replay to whoever the connection goes
// to: hello.Raw, then what the reader took from c beyond it, which the client
// sent behind its hello. Together they are exactly the bytes read from c, in
// order, so replaying them and then relaying c from where it stands reproduces
// the stream of the client. That holds when err is not nil too.
func readHello(c io.Reader, maxBytes int) (hello *tlsx.ClientHello, replay []byte, err error) {
	br := helloReaders.Get().(*bufio.Reader)
	br.Reset(c)
	defer func() {
		br.Reset(nil)
		helloReaders.Put(br)
	}()
	hello, err = tlsx.ReadClientHello(br, maxBytes)
	replay = hello.Raw
	if n := br.Buffered(); n > 0 {
		rest, _ := br.Peek(n) // cannot fail: the bytes are in the buffer
		replay = append(replay, rest...)
	}
	return hello, replay, err
}

// handle serves a connection to its end and closes it: it reads the
// ClientHello by the deadline of the ticket, and relays the connection to the
// route of its server name, or treats it as a stranger. The connection of a
// web route is served by the edge itself (web.go), with the certificate of its
// name, or answered with the alert unrecognized_name when the name has none. A
// probe of the node (a connection to a test listener from the loopback
// interface) takes the probe route of its name when there is one, and is held
// to no limit and not counted. A probe of the panel (a connection of a public
// listener from one of the probe sources of the table) is held to no limit of
// its proxy while the proxy has fewer than maxExemptPerProxy of them, and is
// closed exemptLifetime after at, its accept (see admitExempt). addr is the
// address of the listener that accepted the connection. The caller releases
// the ticket once handle returns.
func (e *Edge) handle(t *table, addr netip.AddrPort, l *listenerEntry, f *flow, client, local netip.AddrPort, tk *ticket, at time.Time) {
	c := f.client
	defer func() { _ = c.Close() }()

	if c.SetReadDeadline(tk.helloBy) != nil {
		return
	}
	hello, replay, err := readHello(c, e.opts.MaxClientHello)
	// Whatever becomes of the connection now, relayed, masked, rejected or
	// closed, it is no longer one before its hello.
	tk.helloRead()
	if e.isMaskLoop(client) {
		if e.warns.allow("mask loop", e.now()) {
			e.log.Warn("edge: a mask target leads back to this edge, the connection is closed; check the mask targets and the mask domains",
				"listener", l.id)
		}
		return
	}
	if c.SetReadDeadline(time.Time{}) != nil {
		return
	}
	switch {
	case err == nil:
	case errors.Is(err, tlsx.ErrNotTLS):
		e.log.Debug("edge: not TLS", "listener", l.id, "client", client.Addr(), "action", l.nonTLS)
		e.answerNonTLS(l, c)
		return
	case errors.Is(err, tlsx.ErrMalformed), errors.Is(err, tlsx.ErrTooLarge):
		e.stranger(t, l, f, client, "", replay, err.Error())
		return
	default:
		// The client went away, or was too slow, before its hello was
		// complete: there is nobody to answer and nothing to mask.
		e.log.Debug("edge: no ClientHello", "listener", l.id, "client", client.Addr(), "err", err)
		return
	}

	sni, _ := rules.FoldName(hello.SNI) // "" for a name that is not one, which no route has
	r := l.routeFor(sni, tk.probe)
	if r == nil {
		e.stranger(t, l, f, client, sni, replay, "no route")
		return
	}
	var cert *tls.Certificate
	backend := r.backendKey
	if r.kind == routeWeb {
		// Without a certificate there is no vhost to serve: the alert, as
		// nginx answers a name it has no certificate for, whatever the
		// listener does with strangers.
		if cert = e.webCert(r); cert == nil {
			e.reject(c)
			return
		}
		backend = "" // its requests count in backend_active, not the connection
	}
	var ls *lease
	if r.stats != nil && !tk.probe {
		if !t.probes[addr] && t.probeSources[client.Addr()] {
			ls = r.stats.admitExempt(backend)
		}
		if ls != nil {
			stop := e.afterFunc(exemptLifetime-time.Since(at), f.close)
			defer stop()
			e.log.Debug("edge: a probe of the panel", "listener", l.id, "proxy", r.proxyID)
		} else {
			var over string
			ls, over = r.stats.admit(client.Addr(), backend, r.limits, e.now(), t.deviceIdle)
			if ls == nil {
				e.stranger(t, l, f, client, sni, replay, "over the "+over+" limit of proxy "+r.proxyID)
				return
			}
		}
		defer func() { ls.release(e.now()) }()
	}
	if r.kind == routeWeb {
		e.serveWeb(f, addr, r, cert, replay, client, ls, tk.probe)
		return
	}
	e.forward(f, r, replay, client, local, ls)
}

// forward relays an admitted connection to the backend of its route: first the
// PROXY v2 header, if the route wants one, then raw, the bytes read from the
// client so far (the ClientHello as it came, and what came behind it), then
// whatever either side sends. The bytes of the client, raw among them, are
// counted on ls, if there is one.
func (e *Edge) forward(f *flow, r *route, raw []byte, client, local netip.AddrPort, ls *lease) {
	ctx, cancel := context.WithTimeout(e.ctx, e.opts.DialTimeout)
	up, err := e.dialer.DialContext(ctx, "tcp", r.backendKey)
	cancel()
	if err != nil {
		e.backendDown(r, err)
		return
	}
	defer func() { _ = up.Close() }()
	if !f.attach(up) {
		return // Drain closed the connection meanwhile
	}
	first := raw
	if r.proxyProtocol {
		first = append(proxyproto.HeaderV2(client, local), raw...)
	}
	if err := writeWithin(up, first, e.opts.DialTimeout); err != nil {
		e.backendDown(r, err)
		return
	}
	var upCount, downCount func(int)
	if ls != nil {
		ls.addUp(len(raw))
		upCount, downCount = ls.addUp, ls.addDown
	}
	e.log.Debug("edge: relaying", "proxy", r.proxyID, "sni", r.sni, "backend", r.backendKey, "client", client.Addr())
	e.relay(f.client, up, upCount, downCount)
}

// backendDown logs that the backend of a route cannot be reached, at most once
// per warnInterval and backend at warning level.
func (e *Edge) backendDown(r *route, err error) {
	if e.warns.allow("backend "+r.backendKey, e.now()) {
		e.log.Warn("edge: cannot reach the backend", "proxy", r.proxyID, "sni", r.sni, "backend", r.backendKey, "err", err)
		return
	}
	e.log.Debug("edge: cannot reach the backend", "proxy", r.proxyID, "sni", r.sni, "backend", r.backendKey, "err", err)
}

// relayBufSize is the size of the buffer of each direction of a relay.
const relayBufSize = 32 << 10

var relayBufs = sync.Pool{New: func() any {
	b := make([]byte, relayBufSize)
	return &b
}}

// closeWriter is a connection that can tell its peer that nothing more will be
// sent and still receive, as *net.TCPConn can.
type closeWriter interface {
	CloseWrite() error
}

// relay copies data between the client and the upstream connection in both
// directions until each direction has come to its end. The caller closes both
// connections afterwards.
//
// When one side ends its stream, relay passes the end on to the other with
// CloseWrite and the opposite direction goes on: a half-close goes through. A
// failure in either direction, or a side that cannot half-close, ends both
// directions. So does the idle timeout: when nothing has been read from either
// side for Options.IdleTimeout, both connections are closed. up and down, when
// not nil, are told of every chunk of bytes written to the upstream and to the
// client, as it is written.
//
// A panic in the goroutine of the upward copy is stopped there, and closes both
// connections; one in the downward copy, which runs in the caller's goroutine,
// is the caller's to stop.
func (e *Edge) relay(client, upstream net.Conn, up, down func(int)) {
	closeBoth := func() {
		_ = client.Close()
		_ = upstream.Close()
	}
	w := startWatchdog(e.opts.IdleTimeout, closeBoth)
	defer w.stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer e.recoverConn("relay", closeBoth)
		pipe(upstream, client, w, up, closeBoth)
	}()
	pipe(client, upstream, w, down, closeBoth)
	<-done
}

// pipe copies from src to dst until src ends or something fails; see relay.
func pipe(dst, src net.Conn, w *watchdog, count func(int), closeBoth func()) {
	bp := relayBufs.Get().(*[]byte)
	defer relayBufs.Put(bp)
	buf := *bp
	for {
		n, err := src.Read(buf)
		if n > 0 {
			w.touch()
			m, werr := dst.Write(buf[:n])
			if m > 0 && count != nil {
				count(m)
			}
			if werr != nil {
				closeBoth()
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
					return
				}
			}
			closeBoth()
			return
		}
	}
}

// watchdog calls fire once nothing has been read in a relay for idle. A read
// only records the time; the timer is re-armed when it goes off, so that a busy
// relay costs no timer operation per read.
type watchdog struct {
	idle  time.Duration
	start time.Time    // the base of last, on the monotonic clock
	last  atomic.Int64 // the time of the last read, as a duration since start
	fire  func()

	mu      sync.Mutex
	timer   *time.Timer
	stopped bool
}

func startWatchdog(idle time.Duration, fire func()) *watchdog {
	w := &watchdog{idle: idle, start: time.Now(), fire: fire}
	w.mu.Lock()
	w.timer = time.AfterFunc(idle, w.check)
	w.mu.Unlock()
	return w
}

// touch records activity.
func (w *watchdog) touch() { w.last.Store(int64(time.Since(w.start))) }

func (w *watchdog) check() {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	if quiet := time.Since(w.start) - time.Duration(w.last.Load()); quiet < w.idle {
		w.timer.Reset(w.idle - quiet)
		w.mu.Unlock()
		return
	}
	w.stopped = true
	w.mu.Unlock()
	w.fire()
}

// stop disarms the watchdog for good.
func (w *watchdog) stop() {
	w.mu.Lock()
	w.stopped = true
	w.timer.Stop()
	w.mu.Unlock()
}

// flow is a connection being handled: the client's, and the connection to the
// backend or the mask target once there is one.
type flow struct {
	client net.Conn

	mu       sync.Mutex
	upstream net.Conn
	closed   bool
}

// attach records the upstream connection, so that close closes it too. It
// returns false when the flow is closed already; the caller closes up then.
func (f *flow) attach(up net.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.upstream = up
	return true
}

// close closes both connections of the flow, which makes every goroutine that
// serves it return soon.
func (f *flow) close() {
	f.mu.Lock()
	f.closed = true
	up := f.upstream
	f.mu.Unlock()
	_ = f.client.Close()
	if up != nil {
		_ = up.Close()
	}
}

// connSet is the set of the connections being handled, for Drain.
type connSet struct {
	mu         sync.Mutex
	flows      map[*flow]struct{}
	draining   bool
	idle       chan struct{} // made by drain, closed once the set is empty
	idleClosed bool
}

func newConnSet() *connSet {
	return &connSet{flows: make(map[*flow]struct{})}
}

// add registers a new connection. It returns nil, and registers nothing, once
// drain has been called.
func (s *connSet) add(c net.Conn) *flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.draining {
		return nil
	}
	f := &flow{client: c}
	s.flows[f] = struct{}{}
	return f
}

// remove unregisters a connection that has been handled.
func (s *connSet) remove(f *flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.flows, f)
	s.signalLocked()
}

func (s *connSet) signalLocked() {
	if s.draining && len(s.flows) == 0 && !s.idleClosed {
		close(s.idle)
		s.idleClosed = true
	}
}

// drain makes add refuse new connections and returns a channel that is closed
// once no connection is left.
func (s *connSet) drain() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.draining {
		s.draining = true
		s.idle = make(chan struct{})
		s.signalLocked()
	}
	return s.idle
}

func (s *connSet) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.flows)
}

// closeAll closes every connection being handled and returns their number.
func (s *connSet) closeAll() int {
	s.mu.Lock()
	flows := slices.Collect(maps.Keys(s.flows))
	s.mu.Unlock()
	for _, f := range flows {
		f.close()
	}
	return len(flows)
}

// addrPortOf returns the address of a TCP endpoint with an IPv4-mapped address
// unmapped and without zone; the zero value for anything else.
func addrPortOf(a net.Addr) netip.AddrPort {
	ta, ok := a.(*net.TCPAddr)
	if !ok || ta == nil {
		return netip.AddrPort{}
	}
	ap := ta.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

// writeWithin writes b to c within d, and lifts the deadline afterwards.
func writeWithin(c net.Conn, b []byte, d time.Duration) error {
	if err := c.SetWriteDeadline(time.Now().Add(d)); err != nil {
		return err
	}
	if _, err := c.Write(b); err != nil {
		return err
	}
	return c.SetWriteDeadline(time.Time{})
}
