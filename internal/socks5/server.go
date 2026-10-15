// Package socks5 is a small SOCKS5 server and client. Both speak RFC 1928 with
// the CONNECT command only, and the user name and password authentication of
// RFC 1929.
//
// The server is the way out for the MTProto engines. An engine sends all of its
// outbound traffic, to Telegram and to the sites its fake-TLS front imitates, to
// a SOCKS5 port that the edge opens on the loopback interface of the node. It
// says what a connection is for in the user name of the authentication: the
// scope, "me", "fetch" or nothing. The server does not authenticate anybody. It
// takes any credentials, drops the password and passes the user name on with the
// target address, and the edge picks the egress chain by the scope. Because of
// that the server belongs on the loopback interface, and only there: on any other
// it would be an open proxy.
//
// The client dials through an upstream SOCKS5 proxy, which is how an egress
// member that is a SOCKS5 proxy, or a proxy process of the node, is reached.
// Relay joins two connections, and is what the server does with a tunnel once
// the target has been dialed.
//
// Both ends read a message in exact pieces and never beyond it, so that the bytes
// that follow a handshake stay with the connection and nothing in this package
// has to hand them back. Every length that the protocol carries is one byte, and
// the buffers have the size of the largest.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"
)

const (
	version5    = 0x05 // the version of the protocol
	authVersion = 0x01 // the version of the user name and password sub-negotiation

	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNone     = 0xff // in the answer of the server: no method is acceptable

	authSuccess = 0x00
	authFailure = 0x01

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded        = 0x00
	repGeneralFailure   = 0x01
	repNotAllowed       = 0x02
	repNetUnreachable   = 0x03
	repHostUnreachable  = 0x04
	repRefused          = 0x05
	repTTLExpired       = 0x06
	repCmdNotSupported  = 0x07
	repAddrNotSupported = 0x08

	// maxField is the longest field of the protocol: every length in it is one
	// byte. It bounds the user name, the password, the methods and the name of a
	// domain, and with it every buffer that is read into.
	maxField = 255

	// defaultTimeout is the time a handshake may take on the server when
	// Server.HandshakeTimeout is not set, and the time Dial allows itself when its
	// context has no deadline.
	defaultTimeout = 10 * time.Second
)

// Request is what a client asked the server to connect to.
type Request struct {
	// Username is the user name of the client's authentication, "" when the
	// client used none or sent an empty one. For an engine it is the scope of the
	// connection: "me", "fetch" or "". It is whatever the client sent, up to 255
	// bytes, and is not checked.
	Username string
	// Host is the IP address of the target, in the form of netip.Addr.String and
	// without brackets, or its domain name as the client sent it. A domain name
	// is never empty and has no space or control character in it, but is not
	// checked beyond that. An IPv4-mapped IPv6 address stays an IPv6 address.
	Host string
	// Port is the TCP port of the target. It may be 0; the server does not look
	// at it.
	Port uint16
}

// DialFunc connects to the target of a request. The server owns the connection
// it returns and closes it. On failure it answers the client by the kind of the
// error: see Server.
//
// The server applies no policy to the targets. Which of them a DialFunc takes
// is up to it.
type DialFunc func(ctx context.Context, req Request) (net.Conn, error)

// Server is a SOCKS5 server that takes CONNECT requests.
//
// A Server serves any number of connections at once. Its fields must not change
// while it serves.
//
// A client may offer the methods "no authentication" and "user name and
// password", and the server takes the second whenever it is offered, so that the
// user name is there to be seen. Any user name and password are accepted. Of the
// commands only CONNECT is served, and the request must carry an IPv4 address, an
// IPv6 address or a domain name.
//
// A request that Dial fails is answered by the kind of the error. A *ReplyError
// in it, which is what Dial returns when an upstream proxy turns a request down,
// is answered with its code as it came, when that is a failure code of RFC 1928
// (0x01 to 0x08): a server in front of a proxy passes its refusals on, "not
// allowed by ruleset" among them, and a DialFunc picks the code of its own
// refusals by returning one. Otherwise a refused connection (ECONNREFUSED) is
// answered with 0x05; a network or a host that cannot be reached, a timeout of
// any kind, a name that is not found, with 0x04; everything else with 0x01. The
// answer to a request that succeeded carries the local address of the
// connection to the target.
type Server struct {
	// Dial connects to the targets. It is required.
	Dial DialFunc

	// HandshakeTimeout is the time a client has for the handshake: from the moment
	// ServeConn takes the connection to the end of the request. It is one limit
	// for all of it, and a peer that sends a byte now and then does not get more
	// time. The answers of the handshake are written within it as well. The reply
	// to the request is written once the dial is over, and is given as much time
	// again, for a client that does not read it must not keep the connection. The
	// limit does not apply to the dial, nor to the tunnel that follows. Zero or
	// less means 10 seconds.
	HandshakeTimeout time.Duration

	// Logger receives the log of the server. nil means slog.Default(). The
	// password of a client never reaches it.
	Logger *slog.Logger
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) timeout() time.Duration {
	if s.HandshakeTimeout > 0 {
		return s.HandshakeTimeout
	}
	return defaultTimeout
}

// Serve accepts connections on ln and serves each of them with ServeConn in a
// goroutine of its own. It returns nil when ln is closed. A connection that is
// being served at that time is not touched and goes on to its end.
//
// An error of Accept that is likely to pass, such as running out of file
// descriptors, makes Serve wait a moment, longer each time up to a second, and try
// again. Any other error ends it and is returned. Serve does not close ln.
func (s *Server) Serve(ln net.Listener) error {
	if s.Dial == nil {
		return errors.New("socks5: Server.Dial is nil")
	}
	var delay time.Duration // the wait after a transient error of Accept, 0 when there was none
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if !transientAcceptError(err) {
				return err
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			s.logger().Warn("socks5: accept failed, trying again", "err", err, "delay", delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		go s.ServeConn(context.Background(), c)
	}
}

// transientAcceptError reports whether err of Accept is one that a later call may
// not meet again: a shortage of descriptors or memory, a connection that a
// firewall or the peer took away before it was accepted, a timeout. Giving up on
// the listener for any of them would leave the engines of the node without a way
// out until the edge is restarted.
func transientAcceptError(err error) bool {
	for _, errno := range []syscall.Errno{
		syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.ECONNABORTED, syscall.ECONNRESET, syscall.EPERM, syscall.EINTR, syscall.EAGAIN,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ServeConn serves one client connection: the handshake, the request, the dial
// and then the tunnel. It returns when the connection is done, and closes it, and
// the connection to the target, before it does.
//
// The handshake is bounded by Server.HandshakeTimeout. Cancelling ctx closes the
// connection of the client and stops a dial that is under way, wherever the
// connection is: its handshake, its dial or its tunnel. A DialFunc is passed a
// context that is cancelled when ServeConn returns.
//
// The client's bytes are read in exact pieces. A client that does not wait for
// the reply, and sends the first bytes for the target behind its request, finds
// them at the target.
func (s *Server) ServeConn(ctx context.Context, c net.Conn) {
	if ctx == nil {
		ctx = context.Background()
	}
	log := s.logger()
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Closing c is what wakes a goroutine that is blocked on it, in the
	// handshake as much as in the tunnel; a dial is stopped by ctx itself. The
	// function is withdrawn before cancel runs, so that ServeConn's own return is
	// not taken for a cancellation.
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()

	timeout := s.timeout()
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		log.Debug("socks5: cannot bound the handshake", "err", err)
		return
	}
	user, err := negotiate(c)
	if err != nil {
		log.Debug("socks5: handshake failed", "remote", addrString(c.RemoteAddr()), "err", err)
		return
	}
	host, port, reply, err := readRequest(c)
	if err != nil {
		if reply != 0 {
			_ = writeReply(c, reply, netip.AddrPort{})
		}
		log.Debug("socks5: bad request", "remote", addrString(c.RemoteAddr()), "err", err)
		return
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return
	}

	req := Request{Username: user, Host: host, Port: port}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	up, err := s.dial(ctx, req)
	if err != nil {
		code := replyCode(err)
		log.Warn("socks5: cannot connect", "scope", user, "target", target, "reply", code, "err", err)
		_ = replyWithin(c, timeout, code, netip.AddrPort{})
		return
	}
	if err := replyWithin(c, timeout, repSucceeded, bindAddr(up)); err != nil {
		log.Debug("socks5: cannot answer the client", "scope", user, "target", target, "err", err)
		_ = up.Close()
		return
	}

	started := time.Now()
	sent, received := Relay(c, up)
	log.Debug("socks5: connection ended", "scope", user, "target", target,
		"sent", sent, "received", received, "duration", time.Since(started).Round(time.Millisecond))
}

// dial calls the DialFunc. It leaves nothing to chance that the rest of the
// server relies on: without a function, or when it panics, or when it returns no
// connection without an error, the result is an error. A connection that comes
// with an error is closed. The panic of a DialFunc is logged with its stack and
// answered as a failure; it does not take the process down with it.
func (s *Server) dial(ctx context.Context, req Request) (conn net.Conn, err error) {
	if s.Dial == nil {
		return nil, errors.New("socks5: the server has no Dial function")
	}
	defer func() {
		if r := recover(); r != nil {
			s.logger().Error("socks5: the Dial function panicked", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			conn, err = nil, fmt.Errorf("socks5: the Dial function panicked: %v", r)
		}
	}()
	conn, err = s.Dial(ctx, req)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("socks5: the Dial function returned no connection")
	}
	return conn, nil
}

// replyCode maps the error of a dial to the reply code that tells the client the
// most about it: the code of a *ReplyError in it as it is, if that is a failure
// code, or else the code of the condition.
func replyCode(err error) byte {
	var re *ReplyError
	if errors.As(err, &re) && re.Code >= repGeneralFailure && re.Code <= repAddrNotSupported {
		return re.Code
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return repRefused
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ETIMEDOUT), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, os.ErrDeadlineExceeded):
		return repHostUnreachable
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) { // not found, or no answer from the resolver
		return repHostUnreachable
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return repHostUnreachable
	}
	return repGeneralFailure
}

// negotiate runs the greeting, and the authentication when the method calls for
// it, and returns the user name, which is empty without one.
func negotiate(c net.Conn) (user string, err error) {
	var head [2]byte // version, number of methods
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", err // an EOF at once is a peer that came and went
	}
	if head[0] != version5 {
		return "", fmt.Errorf("socks5: greeting of version %#02x", head[0])
	}
	var methods [maxField]byte
	n := int(head[1])
	if _, err := io.ReadFull(c, methods[:n]); err != nil {
		return "", noEOF(err)
	}

	var haveNoAuth, haveUserPass bool
	for _, m := range methods[:n] {
		switch m {
		case methodNoAuth:
			haveNoAuth = true
		case methodUserPass:
			haveUserPass = true
		}
	}
	method := byte(methodNone)
	switch {
	case haveUserPass: // preferred: the user name is the scope of the connection
		method = methodUserPass
	case haveNoAuth:
		method = methodNoAuth
	}
	if _, err := c.Write([]byte{version5, method}); err != nil {
		return "", err
	}
	switch method {
	case methodNone:
		return "", errors.New("socks5: the client offers no method that is acceptable")
	case methodUserPass:
		return readCredentials(c)
	}
	return "", nil
}

// readCredentials runs the user name and password sub-negotiation of RFC 1929. It
// takes any user name and any password, reads the password without keeping it,
// and returns the user name.
func readCredentials(c net.Conn) (string, error) {
	var head [2]byte // version, length of the user name
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", noEOF(err)
	}
	if head[0] != authVersion {
		_, _ = c.Write([]byte{authVersion, authFailure})
		return "", fmt.Errorf("socks5: authentication of version %#02x", head[0])
	}
	var name [maxField]byte
	if _, err := io.ReadFull(c, name[:head[1]]); err != nil {
		return "", noEOF(err)
	}
	var plen [1]byte
	if _, err := io.ReadFull(c, plen[:]); err != nil {
		return "", noEOF(err)
	}
	if _, err := io.CopyN(io.Discard, c, int64(plen[0])); err != nil {
		return "", noEOF(err)
	}
	if _, err := c.Write([]byte{authVersion, authSuccess}); err != nil {
		return "", err
	}
	return string(name[:head[1]]), nil
}

// readRequest reads the request that follows the handshake and returns the host
// and the port of the target. When it fails and the client is owed an answer,
// reply is the failure code to send. When the error is one of the connection, or
// the client is not speaking SOCKS5, reply is 0 and there is nobody to answer.
//
// A request of a known address type is read to its end before it is judged, so
// that the connection is closed with nothing unread in it. An address of a type
// that is not known has no length, and is judged at once.
func readRequest(c net.Conn) (host string, port uint16, reply byte, err error) {
	var head [4]byte // version, command, reserved, address type
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", 0, 0, noEOF(err)
	}
	if head[0] != version5 {
		return "", 0, 0, fmt.Errorf("socks5: request of version %#02x", head[0])
	}
	cmd, reserved, atyp := head[1], head[2], head[3]

	switch atyp {
	case atypIPv4, atypIPv6, atypDomain:
	default:
		return "", 0, repAddrNotSupported, fmt.Errorf("socks5: address type %#02x is not supported", atyp)
	}
	host, port, err = readAddress(c, atyp)
	if err != nil {
		return "", 0, 0, err
	}

	switch {
	case reserved != 0:
		return "", 0, repGeneralFailure, fmt.Errorf("socks5: reserved byte of the request is %#02x", reserved)
	case atyp == atypDomain && !validName(host):
		return "", 0, repGeneralFailure, errors.New("socks5: malformed domain name in the request")
	case cmd != cmdConnect:
		return "", 0, repCmdNotSupported, fmt.Errorf("socks5: command %#02x is not supported", cmd)
	}
	return host, port, 0, nil
}

// readAddress reads an address of type atyp and the port behind it. An address is
// returned as netip.Addr.String has it; a domain name is returned as it came.
func readAddress(r io.Reader, atyp byte) (host string, port uint16, err error) {
	var buf [maxField]byte
	switch atyp {
	case atypIPv4:
		if _, err := io.ReadFull(r, buf[:4]); err != nil {
			return "", 0, noEOF(err)
		}
		host = netip.AddrFrom4([4]byte(buf[:4])).String()
	case atypIPv6:
		if _, err := io.ReadFull(r, buf[:16]); err != nil {
			return "", 0, noEOF(err)
		}
		host = netip.AddrFrom16([16]byte(buf[:16])).String()
	case atypDomain:
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return "", 0, noEOF(err)
		}
		n := int(buf[0])
		if _, err := io.ReadFull(r, buf[:n]); err != nil {
			return "", 0, noEOF(err)
		}
		host = string(buf[:n])
	default:
		return "", 0, fmt.Errorf("socks5: address type %#02x is not supported", atyp)
	}
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return "", 0, noEOF(err)
	}
	return host, binary.BigEndian.Uint16(buf[:2]), nil
}

// validName reports whether s is fit to pass on as the name of a host: it is not
// empty and has no space or control character. Those are the bytes with which a
// name could end the line, and start another, in a request that has it in text,
// such as the CONNECT line to an HTTP proxy. What is a name beyond that is for
// the resolver to say.
func validName(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if c := s[i]; c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

// replyWithin writes a reply within d. The write of an answer is bounded for the
// same reason as the reading of the request is: a client that does not read it
// must not keep the connection for ever. The bound is lifted once the reply is
// out.
func replyWithin(c net.Conn, d time.Duration, code byte, bnd netip.AddrPort) error {
	if err := c.SetWriteDeadline(time.Now().Add(d)); err != nil {
		return err
	}
	if err := writeReply(c, code, bnd); err != nil {
		return err
	}
	return c.SetWriteDeadline(time.Time{})
}

// writeReply writes the reply with the given code and bound address in a single
// Write. An address that is not an IP address goes out as the unspecified IPv4
// address, the answer of a server that has no address to report.
func writeReply(w io.Writer, code byte, bnd netip.AddrPort) error {
	b := make([]byte, 0, 4+16+2)
	b = append(b, version5, code, 0)
	addr := bnd.Addr().Unmap()
	switch {
	case addr.Is4():
		a := addr.As4()
		b = append(append(b, atypIPv4), a[:]...)
	case addr.Is6():
		a := addr.As16()
		b = append(append(b, atypIPv6), a[:]...)
	default:
		b = append(b, atypIPv4, 0, 0, 0, 0)
	}
	b = binary.BigEndian.AppendUint16(b, bnd.Port())
	_, err := w.Write(b)
	return err
}

// bindAddr is the address of the reply to a request that succeeded: the local
// address of the connection to the target. It is the zero value when there is
// none that can be told, as with the connections of a net.Pipe.
func bindAddr(c net.Conn) netip.AddrPort {
	switch a := c.LocalAddr().(type) {
	case nil:
		return netip.AddrPort{}
	case *net.TCPAddr:
		return a.AddrPort()
	default:
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.AddrPort{}
		}
		return ap
	}
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// noEOF reports a message that ends inside itself as io.ErrUnexpectedEOF. Other
// errors are left as they are.
func noEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
