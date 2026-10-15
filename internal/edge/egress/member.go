package egress

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/edge/rules"
	"github.com/urbnywrt/postern/internal/netpolicy"
	"github.com/urbnywrt/postern/internal/socks5"
)

// The kinds of a member of a chain, as edgev1.ChainMember.Kind spells them.
const (
	KindDirect = "direct"
	KindSOCKS5 = "socks5"
	KindHTTP   = "http"
)

// DefaultDialTimeout is the time a member has to make a connection, the
// handshake with its proxy included, when the health check does not say.
const DefaultDialTimeout = 4 * time.Second

// Dialer opens outbound TCP connections. The members of a chain are Dialers, and
// so is anything that stands in for one in a test.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewMemberDialer returns the Dialer of a member of a chain.
//
//   - A direct member connects from the node itself.
//   - A socks5 member connects through the SOCKS5 proxy at addr, with the user
//     name and password if there are any.
//   - An http member connects through the HTTP proxy at addr, with CONNECT, and
//     with basic authentication if there are a user name or a password.
//
// Any member may be tied to an interface that Postern did not bring up
// (bind_device, SO_BINDTODEVICE: wg0, tun0 and the like) and to a source address
// (bind_ip). They apply to the connection that the member makes: to the target
// for a direct member, and to the proxy for the others. SO_BINDTODEVICE needs
// CAP_NET_RAW on a kernel older than 5.7.
//
// timeout bounds a dial: the connection and the handshake with the proxy, for
// every address that is tried. Zero or less means DefaultDialTimeout.
//
// Names are resolved with the resolver of the system; the members of a router
// resolve with the router's (Router.SetResolver), which is the DNS forwarder of
// the edge while it runs. A direct member resolves the name of its target, and
// a proxy member the name of its proxy. The name of the target of a proxy
// member goes to the proxy as it is, so that the proxy resolves it where the
// traffic comes out.
//
// A dial under a destination policy (the connections of the engines, see
// SocksPorts) is made to the addresses that the policy allows and to no other.
// An address is checked as it is. A name is resolved by the member, and only
// the addresses of the answer that the policy allows are used: a direct member
// races them as Happy Eyeballs does (raceDial), and a proxy member asks its
// proxy for them in order, IPv4 first, for as long as the proxy answers that
// the target did not connect. A name that resolves to no address that the
// policy allows fails with ErrDestinationNotAllowed and nothing is dialed: a
// proxy does not take the engines where they may not go directly (Ruling 30).
// One that has such an address fails, if it fails, with the failure of that
// address, whatever else the name resolves to and in whatever order.
//
// Every connection that a Dialer returns is the bare *net.TCPConn that the
// connection to the target is, or the one to the proxy after its handshake: no
// wrapper, so that CloseWrite (half-close) and the splice of the relay work. The
// timeout and the context bound the dial and leave nothing behind on the
// connection.
//
// Errors never contain the user name or the password.
func NewMemberDialer(m *edgev1.ChainMember, timeout time.Duration) (Dialer, error) {
	return newMemberDialer(m, timeout, nil)
}

// NewMemberDialerWithResolver is NewMemberDialer whose member resolves names
// with res (nil: the resolver of the system), as the members of a router do
// with the router's (Router.SetResolver). The agent goes through the members of
// a chain this way, with its own resolver, when it cannot reach something by
// itself.
func NewMemberDialerWithResolver(m *edgev1.ChainMember, timeout time.Duration, res *net.Resolver) (Dialer, error) {
	var p atomic.Pointer[net.Resolver]
	p.Store(res)
	return newMemberDialer(m, timeout, &p)
}

// newMemberDialer is NewMemberDialer for a member of a router: res is the
// resolver of the router, which the member looks up at every dial; nil, or nil
// in it, is the resolver of the system.
func newMemberDialer(m *edgev1.ChainMember, timeout time.Duration, res *atomic.Pointer[net.Resolver]) (Dialer, error) {
	if m == nil {
		return nil, errors.New("egress: nil chain member")
	}
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	kind := m.GetKind()
	switch kind {
	case KindDirect, KindSOCKS5, KindHTTP:
	default:
		return nil, fmt.Errorf("egress: unknown member kind %q", kind)
	}
	sock, err := newSocket(kind, m, timeout, res)
	if err != nil {
		return nil, err
	}
	switch kind {
	case KindSOCKS5:
		return newSOCKS5Dialer(m, timeout, sock)
	case KindHTTP:
		return newHTTPDialer(m, timeout, sock)
	}
	return &directDialer{sock: sock}, nil
}

var errUnsupportedNetwork = errors.New("egress: unsupported network")

// ---------------------------------------------------------------------------
// The destination policy of a dial
// ---------------------------------------------------------------------------

type policyKey struct{}

// withDestinationPolicy returns a context that makes the members check the
// address they are about to connect to, or to ask their proxy for, with allow.
// A member resolves a name itself to check what it resolves to, and uses only
// the addresses that allow lets through; an address that is given as one is
// checked as well. Without it in the context a member connects to anything, as
// the health checks need.
func withDestinationPolicy(ctx context.Context, allow func(netip.Addr) bool) context.Context {
	return context.WithValue(ctx, policyKey{}, allow)
}

// policyOf returns the policy that ctx carries, nil when it has none.
func policyOf(ctx context.Context) func(netip.Addr) bool {
	allow, _ := ctx.Value(policyKey{}).(func(netip.Addr) bool)
	return allow
}

// ---------------------------------------------------------------------------
// The connections of a member
// ---------------------------------------------------------------------------

// socket makes the TCP connections of a member: from the source address of
// bind_ip and through the interface of bind_device when they are set, with names
// resolved by the router's resolver.
type socket struct {
	nd     net.Dialer                    // the timeout and the source address; the rest is set at each dial
	device string                        // bind_device, "" for none
	res    *atomic.Pointer[net.Resolver] // the router's resolver; nil, or nil in it: the system's
}

func newSocket(kind string, m *edgev1.ChainMember, timeout time.Duration, res *atomic.Pointer[net.Resolver]) (*socket, error) {
	s := &socket{device: m.GetBindDevice(), res: res}
	s.nd.Timeout = timeout
	if v := m.GetBindIp(); v != "" {
		ip, err := netip.ParseAddr(v)
		if err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("egress: %s member: bind_ip is not an IP address", kind)
		}
		s.nd.LocalAddr = &net.TCPAddr{IP: ip.Unmap().AsSlice()}
	}
	if s.device != "" {
		if err := checkDeviceName(s.device); err != nil {
			return nil, fmt.Errorf("egress: %s member: %w", kind, err)
		}
		if !bindDeviceSupported {
			return nil, fmt.Errorf("egress: %s member: bind_device is supported on Linux only", kind)
		}
	}
	return s, nil
}

// resolver is the resolver of the moment: the router's, or nil for the
// system's.
func (s *socket) resolver() *net.Resolver {
	if s.res == nil {
		return nil
	}
	return s.res.Load()
}

// dial connects to addr. With allow, every address that the dial is about to
// connect to is checked with it first, and one that it refuses fails with
// ErrDestinationNotAllowed.
func (s *socket) dial(ctx context.Context, network, addr string, allow func(netip.Addr) bool) (net.Conn, error) {
	nd := s.nd // a copy, to take the resolver of the moment
	nd.Resolver = s.resolver()
	nd.ControlContext = func(_ context.Context, _, address string, c syscall.RawConn) error {
		if allow != nil {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("egress: cannot check the destination: %w", err)
			}
			if !allow(ap.Addr()) {
				return ErrDestinationNotAllowed
			}
		}
		if s.device != "" {
			return bindToDevice(c, s.device)
		}
		return nil
	}
	return nd.DialContext(ctx, network, addr)
}

// checkDeviceName accepts what the kernel accepts as the name of an interface: at
// most 15 bytes, and no slash, colon, space or control character.
func checkDeviceName(dev string) error {
	bad := len(dev) > 15 || dev == "." || dev == ".."
	for i := 0; i < len(dev) && !bad; i++ {
		c := dev[i]
		bad = c <= ' ' || c == 0x7f || c == '/' || c == ':'
	}
	if bad {
		return errors.New("bind_device is not the name of an interface")
	}
	return nil
}

// ---------------------------------------------------------------------------
// direct
// ---------------------------------------------------------------------------

type directDialer struct {
	sock *socket
}

// DialContext connects to addr. Under a destination policy a name is resolved
// here, and the addresses that the policy allows are raced (raceDial); an
// address, and any dial without a policy, goes to the net package as it is, and
// a policy checks the address there just before the connection is made.
func (d *directDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var lookup string // the network of the lookup of a name
	switch network {
	case "tcp":
		lookup = "ip"
	case "tcp4":
		lookup = "ip4"
	case "tcp6":
		lookup = "ip6"
	default:
		return nil, fmt.Errorf("%w %q", errUnsupportedNetwork, network)
	}
	allow := policyOf(ctx)
	host, port, err := net.SplitHostPort(addr)
	if allow == nil || err != nil {
		return d.sock.dial(ctx, network, addr, allow)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return d.sock.dial(ctx, network, addr, allow)
	}
	ctx, cancel := context.WithTimeout(ctx, d.sock.nd.Timeout) // the lookup and the dials, as the net package bounds them
	defer cancel()
	ips, err := allowedAddrs(ctx, d.sock.resolver(), lookup, host, allow)
	if err != nil {
		return nil, err
	}
	return raceDial(ctx, interleaveFamilies(ips), func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
		return d.sock.dial(ctx, network, net.JoinHostPort(ip.String(), port), allow)
	})
}

// ---------------------------------------------------------------------------
// The names of the targets under a destination policy
// ---------------------------------------------------------------------------

// targetLookupError is the failure of a member to resolve the name of its
// target, which it does under a destination policy. It is about the target, and
// not about the member.
type targetLookupError struct {
	err error
}

func (e *targetLookupError) Error() string { return "egress: the name of the target: " + e.err.Error() }
func (e *targetLookupError) Unwrap() error { return e.err }

// allowedAddrs resolves the name host with res (nil: the resolver of the
// system), for network ("ip", "ip4" or "ip6"), and returns the addresses of the
// answer that allow lets through, in the order of the answer. A name that does
// not resolve is a *targetLookupError, and one that resolves to no address that
// is allowed is ErrDestinationNotAllowed.
func allowedAddrs(ctx context.Context, res *net.Resolver, network, host string, allow func(netip.Addr) bool) ([]netip.Addr, error) {
	if res == nil {
		res = net.DefaultResolver
	}
	ips, err := res.LookupNetIP(ctx, network, netpolicy.AbsoluteName(host))
	if err == nil && len(ips) == 0 {
		err = &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	if err != nil {
		return nil, &targetLookupError{err: err}
	}
	var out []netip.Addr
	for _, ip := range ips {
		if ip = ip.Unmap(); allow(ip) {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s resolves to no address that is allowed", ErrDestinationNotAllowed, host)
	}
	return out, nil
}

// connectionAttemptDelay is how long the dial to one address of a name has to
// itself before the dial to the next one starts as well: the Connection Attempt
// Delay of Happy Eyeballs (RFC 8305), which is also what the net package waits
// before it falls back to the other family.
const connectionAttemptDelay = 300 * time.Millisecond

// errDialPanicked is the error of a dial of raceDial that panicked.
var errDialPanicked = errors.New("egress: the dial panicked")

// raceDial connects to one of addrs as Happy Eyeballs does (RFC 8305), in the
// order given (see interleaveFamilies): it dials the first, and the next one
// when connectionAttemptDelay has passed since the last dial began, or at once
// when a dial fails, so that an address that never answers holds the others up
// for the delay and no longer. Every dial has the whole of ctx. The first
// connection wins; the dials still under way are cancelled, and a connection
// that one of them makes all the same is closed: nothing of the race is left
// behind. When every dial fails, the error is the one of the first that failed.
// The dials run in goroutines of their own, and a panic in one of them is the
// failure of that dial: the edge does not go down with it.
func raceDial(ctx context.Context, addrs []netip.Addr, dial func(context.Context, netip.Addr) (net.Conn, error)) (net.Conn, error) {
	if len(addrs) == 1 {
		return dial(ctx, addrs[0])
	}
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
	start := func() {
		addr := addrs[next]
		next++
		running++
		go func() {
			var r result
			func() {
				defer func() {
					if p := recover(); p != nil {
						r = result{err: fmt.Errorf("%w: %v", errDialPanicked, p)}
					}
				}()
				r.conn, r.err = dial(ctx, addr)
			}()
			select {
			case results <- r:
			case <-over:
				if r.conn != nil {
					_ = r.conn.Close()
				}
			}
		}()
	}

	start()
	delay := time.NewTimer(connectionAttemptDelay)
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
				if first == nil {
					first = errors.New("egress: the dial returned neither a connection nor an error")
				}
			}
			if next < len(addrs) {
				start()
				delay.Reset(connectionAttemptDelay)
			}
		case <-due:
			start()
			delay.Reset(connectionAttemptDelay)
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

// interleaveFamilies orders addresses for raceDial as RFC 8305 says: the
// address families take turns, starting with the family of the first address,
// the one that the resolver prefers, and the addresses of each family keep their
// order.
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

// ---------------------------------------------------------------------------
// What the proxy members share
// ---------------------------------------------------------------------------

// proxyTargets returns what a proxy member asks its proxy for to reach addr,
// "host:port", in order: addr itself without a destination policy in ctx, and
// under one the addresses of addr that the policy allows (see NewMemberDialer),
// resolved with res (nil: the system's) when addr is a name.
//
// IPv4 comes first: the far end of a proxy (an Xray server, WARP) often has no
// IPv6, and a proxy such as Xray acknowledges a connection before it makes it,
// so that an address it cannot reach is not found out in time to try the next.
func proxyTargets(ctx context.Context, res *net.Resolver, addr string) ([]string, error) {
	allow := policyOf(ctx)
	if allow == nil {
		return []string{addr}, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("egress: bad target: %w", err)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !allow(ip) {
			return nil, fmt.Errorf("%w: %s", ErrDestinationNotAllowed, host)
		}
		return []string{addr}, nil
	}
	ips, err := allowedAddrs(ctx, res, "ip", host, allow)
	if err != nil {
		return nil, err
	}
	var v4, v6 []string
	for _, ip := range ips {
		if t := net.JoinHostPort(ip.String(), port); ip.Is4() {
			v4 = append(v4, t)
		} else {
			v6 = append(v6, t)
		}
	}
	return append(v4, v6...), nil
}

// dialThroughProxy asks a proxy, with ask, for a connection to the targets of
// addr (proxyTargets) in order, and ctx bounds them all. The next is asked for
// only while the proxy answers that the target did not connect. A proxy that
// fails itself ends the dial with its own failure, also after it answered for an
// address before: what the member did must not hide behind an answer about the
// target. When the proxy answered for every address, the error is the answer
// for the first.
func dialThroughProxy(ctx context.Context, sock *socket, addr string, ask func(context.Context, string) (net.Conn, error)) (net.Conn, error) {
	targets, err := proxyTargets(ctx, sock.resolver(), addr)
	if err != nil {
		return nil, err
	}
	var first error
	for _, target := range targets {
		conn, err := ask(ctx, target)
		if err == nil {
			return conn, nil
		}
		if !answered(err) {
			return nil, err
		}
		if first == nil {
			first = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, first
}

// ---------------------------------------------------------------------------
// socks5
// ---------------------------------------------------------------------------

type socks5Dialer struct {
	addr, username, password string
	timeout                  time.Duration
	sock                     *socket
}

func newSOCKS5Dialer(m *edgev1.ChainMember, timeout time.Duration, sock *socket) (*socks5Dialer, error) {
	if _, _, err := rules.ParseHostPort(m.GetAddr()); err != nil {
		return nil, fmt.Errorf("egress: socks5 member: addr must be host:port: %w", err)
	}
	if err := rules.CheckSOCKS5Credentials(m.GetUsername(), m.GetPassword()); err != nil {
		return nil, fmt.Errorf("egress: socks5 member: %w", err)
	}
	return &socks5Dialer{addr: m.GetAddr(), username: m.GetUsername(), password: m.GetPassword(), timeout: timeout, sock: sock}, nil
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("%w %q", errUnsupportedNetwork, network)
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return dialThroughProxy(ctx, d.sock, addr, d.ask)
}

// ask connects to the proxy and asks it for target.
func (d *socks5Dialer) ask(ctx context.Context, target string) (net.Conn, error) {
	conn, err := d.sock.dial(ctx, "tcp", d.addr, nil)
	if err != nil {
		return nil, fmt.Errorf("socks5: connecting to the proxy: %w", err)
	}
	if err := socks5.Handshake(ctx, conn, d.username, d.password, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// ---------------------------------------------------------------------------
// http
// ---------------------------------------------------------------------------

// ConnectError is the error of an HTTP member whose proxy answered the CONNECT
// with a status other than 2xx. Like a *socks5.ReplyError, it shows that the
// proxy was reached and spoke; MemberError.Answered says what that is taken to
// mean.
type ConnectError struct {
	Status int
}

func (e *ConnectError) Error() string {
	return strings.TrimSpace(fmt.Sprintf("egress: the http proxy refused the CONNECT: %d %s", e.Status, http.StatusText(e.Status)))
}

// maxConnectAnswer bounds what an HTTP member reads of the answer of its proxy.
const maxConnectAnswer = 16 << 10

type httpDialer struct {
	addr    string
	auth    string // the Proxy-Authorization header, "" without credentials
	timeout time.Duration
	sock    *socket
}

func newHTTPDialer(m *edgev1.ChainMember, timeout time.Duration, sock *socket) (*httpDialer, error) {
	if _, _, err := rules.ParseHostPort(m.GetAddr()); err != nil {
		return nil, fmt.Errorf("egress: http member: addr must be host:port: %w", err)
	}
	d := &httpDialer{addr: m.GetAddr(), timeout: timeout, sock: sock}
	if m.GetUsername() != "" || m.GetPassword() != "" {
		if err := rules.CheckHTTPCredentials(m.GetUsername(), m.GetPassword()); err != nil {
			return nil, fmt.Errorf("egress: http member: %w", err)
		}
		d.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(m.GetUsername()+":"+m.GetPassword()))
	}
	return d, nil
}

func (d *httpDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("%w %q", errUnsupportedNetwork, network)
	}
	if _, _, err := rules.ParseHostPort(addr); err != nil {
		return nil, fmt.Errorf("egress: http member: bad target: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return dialThroughProxy(ctx, d.sock, addr, d.ask)
}

// ask connects to the proxy and asks it for a tunnel to target.
func (d *httpDialer) ask(ctx context.Context, target string) (net.Conn, error) {
	host, port, err := rules.ParseHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("egress: http member: bad target: %w", err)
	}
	authority := net.JoinHostPort(host, strconv.Itoa(int(port)))
	conn, err := d.sock.dial(ctx, "tcp", d.addr, nil)
	if err != nil {
		return nil, fmt.Errorf("egress: http member: connecting to the proxy: %w", err)
	}
	if err := d.connect(ctx, conn, authority); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// connect asks the proxy on conn for a tunnel to authority, for as long as ctx is
// not done, and never leaves a deadline on conn.
//
// The only thing that ends a wait for the proxy is ctx. When it is done it moves
// the deadline of conn into the past, which makes a read or a write that is
// blocked return, and the error is the one of ctx. A deadline on conn of its own,
// set from the one of ctx, would fall due at the very moment when ctx does and
// race with it for the error.
func (d *httpDialer) connect(ctx context.Context, conn net.Conn, authority string) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	err := d.exchange(conn, authority)
	if !stop() {
		// ctx was done while the exchange was under way, and the deadline of conn
		// is spoilt. conn is of no use, whatever came of the exchange.
		return fmt.Errorf("egress: http member: %w", ctx.Err())
	}
	return err
}

func (d *httpDialer) exchange(conn net.Conn, authority string) error {
	var req strings.Builder
	req.WriteString("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n")
	if d.auth != "" {
		req.WriteString("Proxy-Authorization: " + d.auth + "\r\n")
	}
	req.WriteString("\r\n")
	if _, err := io.WriteString(conn, req.String()); err != nil {
		return fmt.Errorf("egress: http member: sending the CONNECT: %w", err)
	}
	status, err := readConnectAnswer(conn)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return &ConnectError{Status: status}
	}
	return nil
}

// readConnectAnswer reads the head of the answer to a CONNECT and returns its
// status. It reads a byte at a time and not one beyond the blank line that ends
// the head, so that what the target sends right after it stays in the connection.
// The head of an answer that is only informational (1xx) is followed by the next.
func readConnectAnswer(conn net.Conn) (int, error) {
	var (
		head      []byte // the head that is being read
		lineStart int    // where its last line begins
		total     int    // the bytes read in all, over every head
		b         [1]byte
	)
	for total < maxConnectAnswer {
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return 0, fmt.Errorf("egress: http member: reading the answer: %w", err)
		}
		total++
		head = append(head, b[0])
		if b[0] != '\n' {
			continue
		}
		line := strings.TrimSuffix(string(head[lineStart:len(head)-1]), "\r")
		if line != "" {
			lineStart = len(head)
			continue
		}
		// The blank line: the head is complete.
		status, err := parseStatusLine(head)
		if err != nil {
			return 0, err
		}
		if status/100 == 1 {
			head, lineStart = head[:0], 0
			continue
		}
		return status, nil
	}
	return 0, errors.New("egress: http member: the answer of the proxy is longer than 16 KiB")
}

// parseStatusLine returns the status code of the first line of an HTTP/1.x
// response head.
func parseStatusLine(head []byte) (int, error) {
	line, _, _ := strings.Cut(string(head), "\n")
	line = strings.TrimSuffix(line, "\r")
	malformed := fmt.Errorf("egress: http member: the answer of the proxy is not an HTTP/1.x response")
	if !strings.HasPrefix(line, "HTTP/1.") || len(line) < len("HTTP/1.x 200") || line[len("HTTP/1.x")] != ' ' {
		return 0, malformed
	}
	rest := line[len("HTTP/1.x "):]
	if len(rest) > 3 && rest[3] != ' ' {
		return 0, malformed
	}
	code := rest[:min(3, len(rest))]
	if len(code) != 3 {
		return 0, malformed
	}
	status, err := strconv.Atoi(code)
	if err != nil || status < 100 || status > 999 || code[0] == '+' || code[0] == '-' {
		return 0, malformed
	}
	return status, nil
}
