package agent

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/urbnywrt/postern/internal/proxyproto"
)

// proxyHeaderTimeout is how long the hidden management listener waits for
// the PROXY v2 header of a connection.
const proxyHeaderTimeout = 10 * time.Second

// The backoff of run after a temporary Accept error: it starts at acceptBackoffMin
// and doubles up to acceptBackoffMax, so that a burst of them (a descriptor
// limit reached, a connection reset before it was accepted) does not spin the
// loop and does not end it either.
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

// newProxyV2Listener wraps ln for the hidden management listener of spec 5.3:
// the edge routes mgmt_sni there and tells it the client's address with a
// PROXY v2 header before the TLS bytes. Every accepted connection has its
// header read first (proxyproto.ReadV2, within timeout, through a
// bufio.Reader the connection keeps reading from); a connection without one
// is closed and never handed out; one with a header has the header's source
// as its RemoteAddr, so that the HTTP server, and GetInfo's peer_addr, see
// the panel's address and not the edge's loopback. A LOCAL header names no
// client: the connection keeps its own address.
//
// The headers are read beside Accept, one goroutine per connection, so that
// a peer that sends nothing holds nobody else up. No slice plan wires the
// hidden listener yet; when one does, it must use this wrapper.
func newProxyV2Listener(ln net.Listener, timeout time.Duration) net.Listener {
	if timeout <= 0 {
		timeout = proxyHeaderTimeout
	}
	pl := &proxyListener{ln: ln, timeout: timeout, ready: make(chan net.Conn), done: make(chan struct{}), stopped: make(chan struct{})}
	go pl.run()
	return pl
}

type proxyListener struct {
	ln      net.Listener
	timeout time.Duration
	ready   chan net.Conn // connections whose header is in
	done    chan struct{} // closed by Close
	stopped chan struct{} // closed by run when it ends (closeErr is then set)

	mu       sync.Mutex
	closeErr error // the error that ended run, once; net.ErrClosed after Close
	closed   bool
}

// run accepts connections and reads their headers. A temporary Accept error
// (a connection aborted before it was accepted, the descriptor limit reached)
// does not end the loop: run waits a little, with a backoff that doubles from
// 5 ms to 1 s, and accepts again. Only a lasting error, or Close, ends it.
func (p *proxyListener) run() {
	backoff := acceptBackoffMin
	for {
		c, err := p.ln.Accept()
		if err != nil {
			if isTemporaryAccept(err) {
				select {
				case <-p.done:
					// Close ended it; fall through to report net.ErrClosed.
				case <-time.After(backoff):
					backoff = min(2*backoff, acceptBackoffMax)
					continue
				}
			}
			p.mu.Lock()
			if p.closed {
				err = net.ErrClosed
			}
			p.closeErr = err
			p.mu.Unlock()
			// stopped, not ready: a prepare goroutine may still be selecting to
			// send on ready, and closing ready under it is a race. Closing
			// stopped wakes Accept instead.
			close(p.stopped)
			return
		}
		backoff = acceptBackoffMin
		go p.prepare(c)
	}
}

// isTemporaryAccept reports whether an Accept error is one to retry rather than
// end the loop over: a connection aborted before it was accepted
// (ECONNABORTED), the per-process or system descriptor limit reached (EMFILE,
// ENFILE), or any net.Error that calls itself temporary or a timeout.
func isTemporaryAccept(err error) bool {
	if errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout() || isTemporaryErr(ne)
	}
	return false
}

// isTemporaryErr reports whether err implements the deprecated Temporary() bool
// and says yes; some listeners still return such errors from Accept.
func isTemporaryErr(err error) bool {
	t, ok := err.(interface{ Temporary() bool })
	return ok && t.Temporary()
}

// prepare reads the header of c and hands c out, or closes it.
func (p *proxyListener) prepare(c net.Conn) {
	pc, ok := p.readHeader(c)
	if !ok {
		_ = c.Close()
		return
	}
	select {
	case p.ready <- pc:
	case <-p.done:
		_ = c.Close()
	case <-p.stopped:
		_ = c.Close()
	}
}

// readHeader reads the PROXY v2 header of c within the timeout.
func (p *proxyListener) readHeader(c net.Conn) (*proxyConn, bool) {
	if err := c.SetReadDeadline(time.Now().Add(p.timeout)); err != nil {
		return nil, false
	}
	br := bufio.NewReader(c)
	h, err := proxyproto.ReadV2(br)
	if err != nil {
		return nil, false
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		return nil, false
	}
	pc := &proxyConn{Conn: c, r: br, remote: c.RemoteAddr()}
	if !h.Local {
		pc.remote = tcpAddr(h.Src)
	}
	return pc, true
}

// Accept returns the next connection whose header is in. It prefers done to a
// ready connection: once Close has run, a closed listener never hands out a
// connection, even one whose header was already read.
func (p *proxyListener) Accept() (net.Conn, error) {
	select {
	case <-p.done:
		return p.acceptErr()
	default:
	}
	select {
	case c := <-p.ready:
		return c, nil
	case <-p.done:
	case <-p.stopped:
	}
	return p.acceptErr()
}

// acceptErr is the error Accept returns once the listener is closed or run has
// ended: net.ErrClosed after Close, otherwise the error that ended run.
func (p *proxyListener) acceptErr() (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.closeErr == nil {
		return nil, net.ErrClosed
	}
	return nil, p.closeErr
}

// Close closes the listener underneath; connections waiting with their
// header read are closed, and Accept returns net.ErrClosed.
func (p *proxyListener) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.done)
	p.mu.Unlock()
	err := p.ln.Close()
	if errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return err
}

func (p *proxyListener) Addr() net.Addr { return p.ln.Addr() }

// proxyConn is a connection behind a PROXY v2 header: reads go through the
// buffered reader the header was read with, and the remote address is the
// header's source.
type proxyConn struct {
	net.Conn
	r      *bufio.Reader
	remote net.Addr
}

func (c *proxyConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *proxyConn) RemoteAddr() net.Addr       { return c.remote }

// tcpAddr is the net.TCPAddr of an address and port.
func tcpAddr(ap netip.AddrPort) *net.TCPAddr {
	return net.TCPAddrFromAddrPort(ap)
}
