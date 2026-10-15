package egress

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Passive detection of a dead member (Ruling S2-24).
//
// The SOCKS inbound of Xray acknowledges a CONNECT before its way out is up, so a
// member whose way out is dead takes the connections of the engines and hangs
// them up at once: an acknowledgement, then the end of the stream or a reset,
// and not a byte from upstream. The health rounds find that out in
// fail_threshold intervals; the connections of the clients find it out at once.
//
// The router watches the connections that it makes through a proxy member. One
// that the upstream ends, by EOF or reset, within passiveWindow of the
// acknowledgement and before a byte came from it is an early end. passiveThreshold
// early ends in a row ask the health loop for a round of that member at once,
// without waiting for the interval, at most one per passiveInterval; while the
// ends stay in a row, the next early end after that asks again. A connection
// through which the upstream sent anything ends the row.
//
// The early ends never take a member down themselves: the round does, by the
// same hysteresis as any other. A client that hangs up first ends nothing: the
// end of a connection that was closed or half-closed on the near side is not
// counted.
const (
	passiveWindow    = 2 * time.Second
	passiveThreshold = 3
	passiveInterval  = 5 * time.Second
	// passiveQueue bounds the members that wait for a passive round. A request
	// that does not fit is dropped; the member asks again once its interval is
	// over.
	passiveQueue = 64
)

// watch wraps conn, made through m, to watch for early ends. Only the
// connections of a proxy member are watched, and only a bare *net.TCPConn
// (which is what a member dialer returns): the wrapper embeds it, so that
// CloseWrite and the splice of the relay towards the upstream are kept.
func (r *Router) watch(m *member, conn net.Conn) net.Conn {
	if m.spec.kind != KindSOCKS5 && m.spec.kind != KindHTTP {
		return conn
	}
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return conn
	}
	return &watchedConn{TCPConn: tc, r: r, m: m, start: r.d.clock.Now()}
}

// watchedConn is a connection through a proxy member that is watched until its
// first verdict: bytes from upstream, an end, or a close on the near side.
type watchedConn struct {
	*net.TCPConn
	r       *Router
	m       *member
	start   time.Time
	settled atomic.Bool
}

func (c *watchedConn) Read(p []byte) (int, error) {
	n, err := c.TCPConn.Read(p)
	if !c.settled.Load() {
		c.observe(n, err)
	}
	return n, err
}

func (c *watchedConn) observe(n int, err error) {
	switch {
	case n > 0:
		if c.settled.CompareAndSwap(false, true) {
			c.m.noteGoodConn()
		}
	case err != nil:
		if c.settled.CompareAndSwap(false, true) && hungUp(err) && c.r.d.clock.Now().Sub(c.start) < passiveWindow {
			c.r.noteEarlyEnd(c.m)
		}
	}
}

// WriteTo is what io.Copy takes from the connection: it reads through Read until
// the verdict is in, and then hands the rest to the bare connection.
func (c *watchedConn) WriteTo(w io.Writer) (int64, error) {
	var total int64
	if !c.settled.Load() {
		buf := make([]byte, 32<<10)
		for !c.settled.Load() {
			n, err := c.Read(buf)
			if n > 0 {
				wn, werr := w.Write(buf[:n])
				total += int64(wn)
				if werr != nil {
					return total, werr
				}
				if wn < n {
					return total, io.ErrShortWrite
				}
			}
			if err == io.EOF {
				return total, nil
			}
			if err != nil {
				return total, err
			}
		}
	}
	n, err := io.Copy(w, c.TCPConn)
	return total + n, err
}

// CloseWrite and Close on the near side settle the connection: whatever the
// upstream does after them is no verdict on the member.
func (c *watchedConn) CloseWrite() error {
	c.settled.Store(true)
	return c.TCPConn.CloseWrite()
}

func (c *watchedConn) Close() error {
	c.settled.Store(true)
	return c.TCPConn.Close()
}

// noteGoodConn ends the row of early ends.
func (m *member) noteGoodConn() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.earlyEnds = 0
}

// noteEarlyEnd counts an early end, and reports whether a passive round of m is
// due now; when it is, the interval starts again.
func (m *member) noteEarlyEnd(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.earlyEnds++
	if m.earlyEnds < passiveThreshold {
		return false
	}
	if !m.lastPassive.IsZero() && now.Sub(m.lastPassive) < passiveInterval {
		return false
	}
	m.lastPassive = now
	return true
}

func (r *Router) noteEarlyEnd(m *member) {
	if !m.noteEarlyEnd(r.d.clock.Now()) {
		return
	}
	select {
	case r.passive <- m:
	default:
	}
}

// startPassive probes m on its own, beside the loop, if it is still a member of
// the configuration and is not being probed passively already.
func (r *Router) startPassive(ctx context.Context, wg *sync.WaitGroup, m *member) {
	cfg := r.cur.Load()
	if cfg.index[memberID{key: m.key, spec: m.spec}] != m {
		return
	}
	if !m.passiveBusy.CompareAndSwap(false, true) {
		return
	}
	r.log.Info("egress: connections through a member end early, checking it now", "member", m.key,
		"chains", cfg.chainsOf(m))
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer m.passiveBusy.Store(false)
		r.probeOne(ctx, cfg, m)
	}()
}
