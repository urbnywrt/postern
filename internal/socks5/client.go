package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// dialTimeout is the time Dial allows itself when its context has no deadline.
// It is a variable only so that a test can shorten it, see export_test.go.
var dialTimeout = defaultTimeout

// ReplyError is the error of Dial when the proxy answers the CONNECT with a failure
// reply. Code is the reply code of RFC 1928, from 0x01 to 0x08 in the standard.
//
// The codes for an unreachable network or host, a refused connection and an
// expired TTL stand for what the operating system reports for the same
// conditions, and the error answers to errors.Is for the matching errno:
// ENETUNREACH, EHOSTUNREACH, ECONNREFUSED and ETIMEDOUT. This lets code that
// sorts the errors of dials do so alike for a direct connection and for one that
// went through a proxy. A Server whose DialFunc fails with a ReplyError answers
// its own client with the same code (see Server).
type ReplyError struct {
	Code byte
}

func (e *ReplyError) Error() string {
	return fmt.Sprintf("socks5: the proxy refused the connection: %s (0x%02x)", replyText(e.Code), e.Code)
}

// Unwrap returns the errno that stands for the code, or nil when none does.
func (e *ReplyError) Unwrap() error {
	switch e.Code {
	case repNetUnreachable:
		return syscall.ENETUNREACH
	case repHostUnreachable:
		return syscall.EHOSTUNREACH
	case repRefused:
		return syscall.ECONNREFUSED
	case repTTLExpired:
		return syscall.ETIMEDOUT
	}
	return nil
}

func replyText(code byte) string {
	switch code {
	case repGeneralFailure:
		return "general SOCKS server failure"
	case repNotAllowed:
		return "connection not allowed by ruleset"
	case repNetUnreachable:
		return "network unreachable"
	case repHostUnreachable:
		return "host unreachable"
	case repRefused:
		return "connection refused"
	case repTTLExpired:
		return "TTL expired"
	case repCmdNotSupported:
		return "command not supported"
	case repAddrNotSupported:
		return "address type not supported"
	}
	return "unassigned reply code"
}

// Dial connects to target, a "host:port" whose host is an IP address or a domain
// name, through the SOCKS5 proxy at proxyAddr, and returns the connection to the
// target, ready for use.
//
// With no user name and no password the client offers the method "no
// authentication". Otherwise it offers that and the method "user name and
// password" and uses whichever the proxy takes. Neither may be longer than 255
// bytes. An IP address goes out as one, IPv4 or IPv6; a domain name, which must
// be 1 to 255 bytes long without a space or a control character, is sent for the
// proxy to resolve.
//
// ctx bounds the whole of it, the connection to the proxy and the handshake. When
// it has no deadline, Dial gives itself ten seconds. Once Dial has returned, ctx
// has nothing more to do with the connection: it may be cancelled, and its
// deadline may pass, and the connection is not affected.
//
// If the proxy turns the request down, the error is a *ReplyError. If the proxy
// closes the connection in the middle of the handshake, it is
// io.ErrUnexpectedEOF. A context that is done is reported as its error, wrapped.
// No error contains the password.
func Dial(ctx context.Context, proxyAddr, username, password, target string) (net.Conn, error) {
	req, err := checkRequest(username, password, target)
	if err != nil {
		return nil, err
	}
	ctx, cancel := withDialTimeout(ctx)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: connecting to the proxy: %w", err)
	}
	if err := handshake(ctx, conn, username, password, req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Handshake asks the SOCKS5 proxy at the other end of conn for a connection to
// target, as Dial does once it has connected to the proxy, and leaves conn
// ready for use as the connection to the target. It is for a connection to the
// proxy that the caller makes itself: from a given source address, or through
// a given interface.
//
// ctx bounds the handshake, and when it has no deadline Handshake gives itself
// ten seconds. Handshake never closes conn, and never leaves a deadline on it;
// after a failure conn is of no use, and the caller closes it. The arguments
// and the errors are those of Dial.
func Handshake(ctx context.Context, conn net.Conn, username, password, target string) error {
	req, err := checkRequest(username, password, target)
	if err != nil {
		return err
	}
	ctx, cancel := withDialTimeout(ctx)
	defer cancel()
	return handshake(ctx, conn, username, password, req)
}

// checkRequest checks the credentials and returns the CONNECT request for
// target.
func checkRequest(username, password, target string) ([]byte, error) {
	if len(username) > maxField || len(password) > maxField {
		return nil, errors.New("socks5: user name or password of more than 255 bytes")
	}
	return encodeRequest(target)
}

// withDialTimeout gives ctx the time of a dial when it has no deadline.
func withDialTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, dialTimeout)
}

// handshake runs the exchange with the proxy on conn for as long as ctx is not
// done. It never leaves a deadline on conn.
//
// The only thing that ends a wait for the proxy is ctx. When it is done it moves
// the deadline of conn into the past, which makes a read or a write that is
// blocked return, and the error that Dial reports is the one of ctx. A deadline
// on conn of its own, set from the one of ctx, would fall due at the very moment
// when ctx does and race with it for the error.
func handshake(ctx context.Context, conn net.Conn, user, pass string, req []byte) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	err := converse(conn, user, pass, req)
	if !stop() {
		// ctx was done while the exchange was under way, and the deadline of conn
		// is spoilt. conn is of no use, whatever came of the exchange.
		return fmt.Errorf("socks5: %w", ctx.Err())
	}
	return err
}

// converse is the handshake itself: the greeting, the authentication if the proxy
// wants one, the request, and the reply. Every message is read in exact pieces and
// not a byte beyond it, so what the target sends right after its reply stays in
// the connection.
func converse(conn net.Conn, user, pass string, req []byte) error {
	hasCredentials := user != "" || pass != ""
	greeting := []byte{version5, 1, methodNoAuth}
	if hasCredentials {
		greeting = []byte{version5, 2, methodNoAuth, methodUserPass}
	}
	if _, err := conn.Write(greeting); err != nil {
		return err
	}

	var chosen [2]byte // version, method
	if _, err := io.ReadFull(conn, chosen[:]); err != nil {
		return noEOF(err)
	}
	if chosen[0] != version5 {
		return fmt.Errorf("socks5: the proxy answered with version %#02x", chosen[0])
	}
	switch chosen[1] {
	case methodNoAuth:
	case methodUserPass:
		if !hasCredentials {
			return errors.New("socks5: the proxy wants a user name and a password, and there are none")
		}
		if err := authenticate(conn, user, pass); err != nil {
			return err
		}
	case methodNone:
		return errors.New("socks5: the proxy takes none of the methods offered (no acceptable method)")
	default:
		return fmt.Errorf("socks5: the proxy chose method %#02x, which was not offered", chosen[1])
	}

	if _, err := conn.Write(req); err != nil {
		return err
	}
	return readReply(conn)
}

// authenticate runs the user name and password sub-negotiation of RFC 1929.
func authenticate(conn net.Conn, user, pass string) error {
	b := make([]byte, 0, 3+len(user)+len(pass))
	b = append(b, authVersion, byte(len(user)))
	b = append(b, user...)
	b = append(b, byte(len(pass)))
	b = append(b, pass...)
	if _, err := conn.Write(b); err != nil {
		return err
	}

	var status [2]byte // version, status
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		return noEOF(err)
	}
	if status[0] != authVersion {
		return fmt.Errorf("socks5: the proxy answered the credentials with version %#02x", status[0])
	}
	if status[1] != authSuccess {
		return errors.New("socks5: the proxy rejected the credentials")
	}
	return nil
}

// readReply reads the reply to the request. A failure reply is a *ReplyError, and
// the two bytes that tell it are all that is taken: some proxies send no more. A
// reply that succeeded is read to its end, with the address it names, which is not
// used. The reserved byte is not checked.
func readReply(conn net.Conn) error {
	var head [2]byte // version, reply code
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return noEOF(err)
	}
	if head[0] != version5 {
		return fmt.Errorf("socks5: the proxy replied with version %#02x", head[0])
	}
	if head[1] != repSucceeded {
		return &ReplyError{Code: head[1]}
	}
	var rest [2]byte // reserved byte, address type
	if _, err := io.ReadFull(conn, rest[:]); err != nil {
		return noEOF(err)
	}
	if _, _, err := readAddress(conn, rest[1]); err != nil {
		return err
	}
	return nil
}

// encodeRequest builds the CONNECT request for target, "host:port".
func encodeRequest(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("socks5: bad target: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("socks5: bad port %q in the target", portText)
	}

	b := make([]byte, 0, 4+1+maxField+2)
	b = append(b, version5, cmdConnect, 0)
	if addr, err := netip.ParseAddr(host); err == nil {
		switch {
		case addr.Zone() != "":
			return nil, fmt.Errorf("socks5: the target address %q has a zone, which a request cannot carry", host)
		case addr.Is4():
			a := addr.As4()
			b = append(append(b, atypIPv4), a[:]...)
		default: // IPv6, an IPv4-mapped address among them: it stays one
			a := addr.As16()
			b = append(append(b, atypIPv6), a[:]...)
		}
	} else {
		if len(host) > maxField {
			return nil, fmt.Errorf("socks5: the domain name of the target is %d bytes long, at most %d are allowed", len(host), maxField)
		}
		if !validName(host) {
			return nil, errors.New("socks5: the domain name of the target is empty or has a space or a control character")
		}
		b = append(append(b, atypDomain, byte(len(host))), host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}
