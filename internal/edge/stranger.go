package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/urbnywrt/postern/internal/edge/egress"
	"github.com/urbnywrt/postern/internal/edge/rules"
	"github.com/urbnywrt/postern/internal/netpolicy"
)

// alertUnrecognizedName is the TLS record of a fatal unrecognized_name alert,
// which is what nginx sends with ssl_reject_handshake.
var alertUnrecognizedName = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70}

// http400 is what nginx answers when plain HTTP comes to an HTTPS port.
const http400 = "HTTP/1.1 400 Bad Request\r\n" +
	"Server: nginx\r\n" +
	"Content-Type: text/html\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"<html><head><title>400 The plain HTTP request was sent to HTTPS port</title></head><body>" +
	"<center><h1>400 Bad Request</h1></center>" +
	"<center>The plain HTTP request was sent to HTTPS port</center>" +
	"<hr><center>nginx</center></body></html>\r\n"

const (
	// answerTimeout bounds the write of an answer of the edge's own, the alert
	// or the 400, and then the wait for the client to end its side.
	answerTimeout = 2 * time.Second
	// maxDiscard is the most bytes read and thrown away after such an answer.
	maxDiscard = 64 << 10
	// maskAttemptDelay is how long the dial to one address of a mask domain
	// has to itself before the dial to the next one starts as well: the
	// Connection Attempt Delay of Happy Eyeballs (RFC 8305), which is what the
	// net package waits before it falls back to the other family.
	maskAttemptDelay = 300 * time.Millisecond
	// maxMaskAddrs is the most addresses of a mask domain that are raced: the
	// first ones in the order of the race, so that both families are among
	// them. One answer of the DNS cannot fan a stranger out into more dials.
	maxMaskAddrs = 8
)

// stranger handles a connection the listener has no route for: an unknown
// server name, none, one that is not a host name, a hello the edge cannot
// read, a web route, or a proxy over its limits. sni is the folded server name,
// or "" when there is none that is valid; raw is everything read from the
// client so far.
//
// The listener's stranger action decides. mask relays the connection, raw
// first, to the listener's mask target, or else to the server name itself on
// port 443 when the name is one of the mask domains, at an address of the name
// that the destination policy allows (see mask); with neither, with a mask
// domain that has no such address, or when Options.MaxMasked strangers are
// being masked already, it rejects. reject answers with the TLS alert
// unrecognized_name. drop closes the connection after a random delay of up to
// 2 s.
func (e *Edge) stranger(t *table, l *listenerEntry, f *flow, client netip.AddrPort, sni string, raw []byte, reason string) {
	action, target, domain := l.stranger, "", ""
	if action == rules.StrangerMask {
		target = l.maskTarget
		if target == "" && sni != "" && t.maskDomains[sni] {
			domain, target = sni, net.JoinHostPort(sni, rules.MaskPort)
		}
		switch {
		case target == "":
			action = rules.StrangerReject
		case !e.takeMaskPlace():
			action = rules.StrangerReject
			if e.warns.allow("mask cap", e.now()) {
				e.log.Warn("edge: too many strangers masked at once, the others are rejected", "max", e.opts.MaxMasked)
			}
		}
	}
	e.log.Debug("edge: stranger", "listener", l.id, "client", client.Addr(), "sni", sni, "reason", reason, "action", action)
	switch action {
	case rules.StrangerMask:
		if refused := e.mask(f, target, domain, raw); refused {
			e.reject(f.client) // as a stranger without a mask target
		}
	case rules.StrangerReject:
		e.reject(f.client)
	default: // rules.StrangerDrop
		e.drop()
	}
}

var (
	// errMaskRefused is the error of a dial to a mask domain that has
	// addresses, and none that the destination policy allows.
	errMaskRefused = errors.New("edge: the mask domain has no address that the edge may connect to")
	// errMaskDialPanicked is the error of a dial to an address of a mask
	// domain in which DialMask panicked; the panic is logged.
	errMaskDialPanicked = errors.New("edge: the dial panicked")
)

// mask relays a stranger to target: what was read from it first, then whatever
// either side sends. Nothing is counted for any proxy. A target that cannot be
// reached closes the connection without an answer. mask gives back the place
// of Options.MaxMasked that the caller took for the stranger.
//
// The mask target of a listener (domain is "") is dialed as it is, whatever it
// is: it is the operator's own choice, and may well be a web server on the node
// itself. A mask domain, the server name of the stranger, is not: what the name
// resolves to is up to whoever answers for it in the DNS, who must not be able
// to point the edge at the node or its network and have it relay the Internet
// there. The name is resolved, and only an address that the destination policy
// allows is dialed (see dialMaskDomain). When the name has addresses and none
// that is allowed, nothing is dialed, and mask returns refused: the caller
// rejects the stranger, as one without a mask target.
func (e *Edge) mask(f *flow, target, domain string, raw []byte) (refused bool) {
	defer e.masked.Add(-1)
	ctx, cancel := context.WithTimeout(e.ctx, e.opts.DialTimeout)
	var (
		up  net.Conn
		err error
	)
	if domain != "" {
		up, err = e.dialMaskDomain(ctx, domain)
	} else {
		up, err = e.opts.DialMask(ctx, target)
	}
	cancel()
	if errors.Is(err, errMaskRefused) {
		msg := "edge: a mask domain has no address that the edge may connect to, its strangers are rejected"
		if e.warns.allow("mask policy "+domain, e.now()) {
			e.log.Warn(msg, "domain", domain, "err", err)
		} else {
			e.log.Debug(msg, "domain", domain, "err", err)
		}
		return true
	}
	if err != nil || up == nil {
		if up != nil {
			_ = up.Close()
		}
		if e.warns.allow("mask "+target, e.now()) {
			e.log.Warn("edge: cannot reach the mask target", "target", target, "err", err)
		} else {
			e.log.Debug("edge: cannot reach the mask target", "target", target, "err", err)
		}
		return false
	}
	defer func() { _ = up.Close() }()
	if la := addrPortOf(up.LocalAddr()); la.IsValid() {
		e.maskLocal.Store(la, struct{}{})
		defer e.maskLocal.Delete(la)
	}
	if !f.attach(up) {
		return false // Drain closed the connection meanwhile
	}
	if writeWithin(up, raw, e.opts.DialTimeout) != nil {
		return false
	}
	e.relay(f.client, up, nil, nil)
	return false
}

// dialMaskDomain connects to a mask domain on port 443. It looks the name up
// with the resolver of the edge, Options.Resolver, and keeps the addresses that
// the destination policy allows: the one of the SOCKS ports of the engines,
// egress.DestinationAllowed, which refuses the loopback, private, link-local
// (the metadata services of the clouds), carrier-grade NAT, unspecified and
// multicast addresses. It races maxMaskAddrs of those at most, as IP literals
// (see raceMaskDial). A name that has addresses and none that is allowed is
// errMaskRefused.
func (e *Edge) dialMaskDomain(ctx context.Context, name string) (net.Conn, error) {
	addrs, err := e.opts.Resolver.LookupNetIP(ctx, "ip", netpolicy.AbsoluteName(name))
	if err != nil {
		return nil, err
	}
	allowed := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if egress.DestinationAllowed(a) {
			allowed = append(allowed, a.Unmap().WithZone("")) // what was checked
		}
	}
	if len(allowed) == 0 {
		if len(addrs) == 0 {
			return nil, fmt.Errorf("edge: %s has no address", name)
		}
		return nil, fmt.Errorf("%w: it resolves to %v", errMaskRefused, addrs)
	}
	race := interleaveFamilies(allowed)
	return e.raceMaskDial(ctx, race[:min(len(race), maxMaskAddrs)])
}

// raceMaskDial connects to one of addrs on port 443 as Happy Eyeballs does
// (RFC 8305), in the order given: it dials the first, and the next one when
// maskAttemptDelay has passed since the last dial began, or at once when a
// dial fails, so that an address that never answers holds the others up for
// the delay and no longer. Every dial has the whole of ctx. The first
// connection is the one that is returned. The dials that are still under way
// then are cancelled, and a connection that one of them makes all the same is
// closed: nothing of the race is left behind. When every dial fails, the error
// is the one of the first that failed. A dial in which DialMask panics is one
// that fails, after the panic is logged: the dials run in goroutines of their
// own, which the recovery of the goroutine of the connection does not cover.
func (e *Edge) raceMaskDial(ctx context.Context, addrs []netip.Addr) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	over := make(chan struct{}) // closed when the race is decided
	defer close(over)
	next, running := 0, 0
	dial := func() {
		target := net.JoinHostPort(addrs[next].String(), rules.MaskPort)
		next++
		running++
		go func() {
			var conn net.Conn
			err := errMaskDialPanicked // unless the dial returns
			func() {
				// The dial does not run in the goroutine of the connection,
				// whose recoverConn would stop a panic in it.
				defer e.recoverConn("mask dial", func() {})
				conn, err = e.opts.DialMask(ctx, target)
			}()
			select {
			case results <- result{conn, err}:
			case <-over:
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}

	dial()
	delay := time.NewTimer(maskAttemptDelay)
	defer delay.Stop()
	var first error
	for running > 0 {
		var due <-chan time.Time // nil, never ready, when no address is left
		if next < len(addrs) {
			due = delay.C
		}
		select {
		case r := <-results:
			running--
			if r.err == nil && r.conn != nil {
				return r.conn, nil
			}
			if r.conn != nil {
				_ = r.conn.Close()
			}
			if first == nil {
				first = r.err
			}
			if next < len(addrs) {
				dial()
				delay.Reset(maskAttemptDelay)
			}
		case <-due:
			dial()
			delay.Reset(maskAttemptDelay)
		case <-ctx.Done():
			// The dials see it too; this is for one that does not.
			if first == nil {
				first = ctx.Err()
			}
			return nil, first
		}
	}
	return nil, first
}

// interleaveFamilies orders addresses for raceMaskDial as RFC 8305 says: the
// address families take turns, starting with the family of the first address,
// and the addresses of each family keep their order.
func interleaveFamilies(addrs []netip.Addr) []netip.Addr {
	if len(addrs) == 0 {
		return addrs
	}
	var same, other []netip.Addr
	for _, a := range addrs {
		if a.Is4() == addrs[0].Is4() {
			same = append(same, a)
		} else {
			other = append(other, a)
		}
	}
	out := make([]netip.Addr, 0, len(addrs))
	for i := 0; i < len(same) || i < len(other); i++ {
		if i < len(same) {
			out = append(out, same[i])
		}
		if i < len(other) {
			out = append(out, other[i])
		}
	}
	return out
}

// takeMaskPlace takes one of the Options.MaxMasked places of the strangers
// being masked, if one is free. The caller gives it back with
// e.masked.Add(-1).
func (e *Edge) takeMaskPlace() bool {
	if e.masked.Add(1) > int64(e.opts.MaxMasked) {
		e.masked.Add(-1)
		return false
	}
	return true
}

// isMaskLoop reports whether a connection comes from this very edge, through a
// mask target: a mask target, or a mask domain, that leads to the node itself.
// Masking that connection again would dial the edge again, and so on without
// end, all from one connection of a client.
//
// The local address of every open connection to a mask target is recorded
// before the ClientHello is replayed to it, so once a looped connection has
// read that hello, its client address is found among them.
func (e *Edge) isMaskLoop(client netip.AddrPort) bool {
	_, ok := e.maskLocal.Load(client)
	return ok
}

// reject answers with the alert unrecognized_name.
func (e *Edge) reject(c net.Conn) {
	if writeWithin(c, alertUnrecognizedName, answerTimeout) == nil {
		finish(c)
	}
}

// drop waits for the delay of the drop action; the caller closes the
// connection afterwards. Drain cuts the wait short when it gives up.
func (e *Edge) drop() {
	t := time.NewTimer(e.dropDelay())
	defer t.Stop()
	select {
	case <-t.C:
	case <-e.ctx.Done():
	}
}

// answerNonTLS handles a client that did not open with a TLS handshake: the
// listener's non-TLS action answers like nginx does (http400), or closes at
// once (drop, by the caller).
func (e *Edge) answerNonTLS(l *listenerEntry, c net.Conn) {
	if l.nonTLS == rules.NonTLSHTTP400 && writeWithin(c, []byte(http400), answerTimeout) == nil {
		finish(c)
	}
}

// finish ends an answer of the edge's own: it sends the end of the stream, then
// reads and throws away what the client still sends, until the client ends its
// side too, for answerTimeout and maxDiscard bytes at most. Closing a socket
// with unread data in it makes the kernel reset the connection, and the reset
// can destroy the answer before the client has read it. The caller closes c.
func finish(c net.Conn) {
	cw, ok := c.(closeWriter)
	if !ok || cw.CloseWrite() != nil {
		return
	}
	if c.SetReadDeadline(time.Now().Add(answerTimeout)) != nil {
		return
	}
	_, _ = io.CopyN(io.Discard, c, maxDiscard)
}
