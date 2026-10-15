package egress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/netpolicy"
	"github.com/urbnywrt/postern/internal/socks5"
)

// SocksPorts are the SOCKS5 ports on the loopback interface that the engines send
// their outbound traffic to, and that lead into the chains of a Router.
//
// There is one port for each instance of an engine, and the port is how the
// instance is told apart. The user name that an engine presents is the scope of
// the connection: telemt sends "fetch" for what it downloads, and nothing for the
// ordinary traffic to the datacenters, nor for its connections to the middle
// proxies (finding F3), which the router tells by their address and port and
// gives the scope "me" (Router.ScopeOf); a scope that the engine gives wins. The chain of a
// connection is the one that the port gives for its scope, or else the default
// chain of the port. The engine's password is of no use and is dropped.
//
// The ports are bound with SO_REUSEPORT, on 127.0.0.1 and nowhere else: the
// server does not authenticate anybody, and on any other address it would be an
// open proxy. The ports have stable numbers, and the next generation of the edge
// binds the same ones while the old generation still serves, so that the engines
// do not lose their way out when the edge is handed over.
//
// An engine is not trusted with the node. It is turned away, with the reply "not
// allowed by ruleset", from every address that is the node's own or its
// network's: loopback, private (RFC 1918 and unique local), link local,
// unspecified, multicast, and the shared address space of carrier-grade NAT.
// Those are the engine APIs, the management ports, the egress processes and the
// metadata services of the clouds, which an engine has no business with. A name is
// let through the port: the member resolves it and uses only the addresses that
// the same rule allows, so that no member takes an engine where it may not go
// (see NewMemberDialer), and a name with no such address is turned away. The
// names "localhost" and "*.localhost", which are loopback by definition, are
// turned away at the port. A refusal ends the dial at once: the next member of
// the chain would be asked for the same destination.
//
// When the chain fails, the engine is told why with the code of the reply: the
// reply of a SOCKS5 proxy that turned the target down as it came; for a target
// that a direct member found to refuse the connection "connection refused"
// (0x05); for one that cannot be reached, does not answer in time, or whose name
// does not resolve "host unreachable" (0x04), as for an HTTP proxy that answers
// 504; and a general failure (0x01) for anything else, a member that fails itself
// among it: a refused connection to a proxy that is down must not reach the
// engine as a refusal of the target. Of the members that were tried, the first
// that has something to say about the target says it.
type SocksPorts struct {
	log    *slog.Logger
	srvLog *slog.Logger // the log of the SOCKS server: see routineHandler
	router *Router
	listen func(addr string) (net.Listener, error)
	allow  func(netip.Addr) bool

	mu     sync.Mutex
	closed bool
	ports  map[uint16]*socksPort
}

// socksOptions are what SocksPorts take from outside, for a test to replace.
type socksOptions struct {
	listen func(addr string) (net.Listener, error) // the default binds with SO_REUSEPORT
	allow  func(netip.Addr) bool                   // the default is destinationAllowed
}

type socksPort struct {
	port uint16
	ln   net.Listener
	cfg  atomic.Pointer[portConfig]
	dead atomic.Bool   // the accept loop ended on its own, and the listener is closed
	stop chan struct{} // closed when the port is closed
	once sync.Once
	done chan struct{} // closed when the accept loop has returned
}

func (p *socksPort) close() error {
	var err error
	p.once.Do(func() {
		close(p.stop)
		err = p.ln.Close()
	})
	return err
}

// portConfig is the configuration of a port, which an Apply can change without the
// port being bound again.
type portConfig struct {
	proxyID      string
	defaultChain string
	scopeChains  map[string]string
}

// chainFor returns the chain of a scope: its entry, or else the default chain. An
// entry that is empty is no entry.
func (c *portConfig) chainFor(scope string) string {
	if id := c.scopeChains[scope]; id != "" {
		return id
	}
	return c.defaultChain
}

// NewSocksPorts returns SocksPorts that dial through r. They have no ports until
// Apply gives them some.
func NewSocksPorts(log *slog.Logger, r *Router) *SocksPorts {
	return newSocksPorts(log, r, socksOptions{})
}

func newSocksPorts(log *slog.Logger, r *Router, o socksOptions) *SocksPorts {
	if log == nil {
		log = slog.Default()
	}
	if o.listen == nil {
		o.listen = listenReusePort
	}
	if o.allow == nil {
		o.allow = destinationAllowed
	}
	return &SocksPorts{
		log:    log,
		srvLog: slog.New(routineHandler{log.Handler()}),
		router: r,
		listen: o.listen,
		allow:  o.allow,
		ports:  make(map[uint16]*socksPort),
	}
}

// Apply makes the ports of s the ones given: it binds 127.0.0.1:<port> for each
// that is new, closes those that are no longer listed, and gives the others the new
// default chain and scope chains for the connections that follow. A port that
// stays keeps its listener.
//
// Nothing is changed when anything is wrong: a port that is not from 1 to 65535 or
// is listed twice is an error, and so is a port that cannot be bound, in which case
// the ports that this call opened are closed again and the configuration that was
// there stays in effect. A port whose accept loop ended on a failure that does not
// pass is bound again.
//
// Connections that are open are not touched by any of it, not even those of a port
// that is closed: they go on to their end.
func (s *SocksPorts) Apply(ports []*edgev1.SocksPort) error {
	want := make(map[uint16]*portConfig, len(ports))
	for _, sp := range ports {
		n := sp.GetPort()
		if n == 0 || n > 65535 {
			return fmt.Errorf("egress: SOCKS port %d is not a TCP port", n)
		}
		port := uint16(n)
		if _, dup := want[port]; dup {
			return fmt.Errorf("egress: SOCKS port %d is listed twice", port)
		}
		want[port] = &portConfig{
			proxyID:      sp.GetProxyId(),
			defaultChain: sp.GetDefaultChainId(),
			scopeChains:  maps.Clone(sp.GetScopeChains()),
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for port, p := range s.ports {
		if p.dead.Load() {
			delete(s.ports, port)
		}
	}

	var opened []*socksPort
	for _, port := range slices.Sorted(maps.Keys(want)) {
		if _, ok := s.ports[port]; ok {
			continue
		}
		ln, err := s.listen(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		if err != nil {
			for _, o := range opened {
				_ = o.close()
			}
			return fmt.Errorf("egress: SOCKS port %d: %w", port, err)
		}
		opened = append(opened, &socksPort{port: port, ln: ln, stop: make(chan struct{}), done: make(chan struct{})})
	}

	// Everything is bound: from here on nothing can fail.
	for port, cfg := range want {
		if p, ok := s.ports[port]; ok {
			p.cfg.Store(cfg)
		}
	}
	for _, p := range opened {
		p.cfg.Store(want[p.port])
		s.ports[p.port] = p
		go s.accept(p)
		s.log.Info("egress: SOCKS port opened", "port", p.port, "proxy", want[p.port].proxyID)
	}
	for port, p := range s.ports {
		if _, keep := want[port]; !keep {
			delete(s.ports, port)
			_ = p.close()
			s.log.Info("egress: SOCKS port closed", "port", port)
		}
	}
	return nil
}

// Close closes every port: no connection is accepted after it returns, and Apply
// is an error. The connections that are open are not touched, and go on to their
// end. That is what a drain of the edge needs, and the process ending is what ends
// the rest. Close may be called again.
func (s *SocksPorts) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ports := s.ports
	s.ports = nil
	s.mu.Unlock()

	var errs []error
	for _, p := range ports {
		if err := p.close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	for _, p := range ports {
		<-p.done
	}
	return errors.Join(errs...)
}

// addrs returns the addresses that the ports are bound to, sorted.
func (s *SocksPorts) addrs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, p := range s.ports {
		out = append(out, p.ln.Addr().String())
	}
	slices.Sort(out)
	return out
}

// accept serves the connections of a port, each in a goroutine of its own, until
// the port is closed.
//
// A failure of Accept that is likely to pass, such as running out of file
// descriptors, makes it wait a moment, longer each time up to a second, and try
// again: giving the port up would leave the engine without a way out until the
// edge is restarted. Any other failure ends the loop and closes the listener, so
// that the engine is refused and does not hang on a port that nobody serves, and
// the next Apply binds the port again.
func (s *SocksPorts) accept(p *socksPort) {
	defer close(p.done)
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("egress: the accept loop of a SOCKS port panicked", "port", p.port,
				"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			p.dead.Store(true)
			_ = p.close()
		}
	}()
	var delay time.Duration
	for {
		c, err := p.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if retryableAcceptError(err) {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				s.log.Warn("egress: accept failed on a SOCKS port, trying again", "port", p.port, "err", err, "delay", delay)
				select {
				case <-time.After(delay):
					continue
				case <-p.stop:
					return
				}
			}
			s.log.Error("egress: accept failed on a SOCKS port, closing it", "port", p.port, "err", err)
			p.dead.Store(true)
			_ = p.close()
			return
		}
		delay = 0
		go s.serveConn(p, c)
	}
}

// retryableAcceptError reports whether err of Accept is one that a later call may
// not meet again: a shortage of descriptors or memory, a connection that was
// taken away before it was accepted, a timeout.
func retryableAcceptError(err error) bool {
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

// serveConn serves one engine connection. A panic in it is logged with its stack
// and closes the connection: the edge carries the public ingress as well and does
// not go down with one connection of an engine.
func (s *SocksPorts) serveConn(p *socksPort, c net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("egress: panic while serving a SOCKS connection", "port", p.port,
				"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			_ = c.Close()
		}
	}()
	cfg := p.cfg.Load()
	attrs := []any{"port", p.port, "proxy", cfg.proxyID}
	log := s.log.With(attrs...)
	srv := &socks5.Server{
		Dial:   func(ctx context.Context, req socks5.Request) (net.Conn, error) { return s.dial(ctx, cfg, req, log) },
		Logger: s.srvLog.With(attrs...),
	}
	srv.ServeConn(context.Background(), c)
}

// dial is the DialFunc of the SOCKS server of a port. Its errors carry the code
// of the reply that the server answers the engine with (engineFailure).
func (s *SocksPorts) dial(ctx context.Context, cfg *portConfig, req socks5.Request, log *slog.Logger) (net.Conn, error) {
	target := net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port)))
	if !s.permitted(req.Host) {
		return nil, s.refused(log, req, target, ErrDestinationNotAllowed)
	}
	if s.router == nil {
		return nil, engineError(errors.New("egress: the SOCKS ports have no router"))
	}
	scope := s.router.ScopeOf(req.Username, req.Host, req.Port)
	chainID := cfg.chainFor(scope)
	conn, key, err := s.router.Dial(withDestinationPolicy(ctx, s.allow), chainID, target)
	if err != nil {
		if errors.Is(err, ErrDestinationNotAllowed) {
			return nil, s.refused(log, req, target, err)
		}
		log.Debug("egress: connection failed", "scope", scope, "chain", chainID, "target", target, "err", err)
		return nil, engineError(err)
	}
	log.Debug("egress: connected", "scope", scope, "chain", chainID, "member", key, "target", target)
	return conn, nil
}

// permitted reports whether an engine may ask for host, an address or a name.
func (s *SocksPorts) permitted(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return s.allow(ip)
	}
	return !localName(host)
}

// The codes of the replies that the ports pick themselves (RFC 1928).
const (
	replyGeneralFailure  = 0x01
	replyNotAllowed      = 0x02
	replyHostUnreachable = 0x04
	replyRefused         = 0x05
	replyLastFailure     = 0x08 // the last failure code that RFC 1928 assigns
)

// refused logs that the destination of an engine is not allowed, and returns the
// error with which the SOCKS server tells the engine so: "not allowed by
// ruleset".
func (s *SocksPorts) refused(log *slog.Logger, req socks5.Request, target string, err error) error {
	log.Warn("egress: destination refused", "scope", req.Username, "target", target)
	return &engineFailure{err: err, reply: socks5.ReplyError{Code: replyNotAllowed}}
}

// engineFailure is an error with which the SOCKS server of a port answers an
// engine: it has the text of what went wrong, and unwraps to nothing but the
// *socks5.ReplyError of the code that the engine is to get, which the server
// answers with as it is. Nothing else in it is taken for a refused connection
// or a timeout.
type engineFailure struct {
	err   error
	reply socks5.ReplyError
}

func (e *engineFailure) Error() string { return e.err.Error() }
func (e *engineFailure) Unwrap() error { return &e.reply }

// engineError turns the error of a dial through the chain into the one that the
// SOCKS server answers the engine with: the code of the first member that was
// tried and has something to say about the target (targetReply), or a general
// failure when none has (see SocksPorts).
func engineError(err error) error {
	code := byte(replyGeneralFailure)
	var de *DialError
	if errors.As(err, &de) {
		for _, a := range de.Attempts {
			if c, ok := targetReply(a); ok {
				code = c
				break
			}
		}
	}
	return &engineFailure{err: err, reply: socks5.ReplyError{Code: code}}
}

// targetReply returns the code of the reply for the failure of a member that is
// about the target, and false for one that is about the member.
//
// What a proxy answered is about the target: the reply of a SOCKS5 proxy is
// passed on as it came (a code that RFC 1928 does not assign as a general
// failure), and an HTTP status other than 407, which is about the credentials
// of the member, is a general failure, or "host unreachable" for a timeout of
// the gateway (504). A name of the target that does not resolve is "host
// unreachable" as well. A direct member connects to the target itself, so what
// it meets is the target's: a refusal, or a network or a host that cannot be
// reached, or no answer in time.
func targetReply(a *MemberError) (byte, bool) {
	var re *socks5.ReplyError
	if errors.As(a.Err, &re) {
		if re.Code >= replyGeneralFailure && re.Code <= replyLastFailure {
			return re.Code, true
		}
		return replyGeneralFailure, true
	}
	var ce *ConnectError
	if errors.As(a.Err, &ce) {
		switch ce.Status {
		case http.StatusProxyAuthRequired:
			return 0, false
		case http.StatusGatewayTimeout:
			return replyHostUnreachable, true
		}
		return replyGeneralFailure, true
	}
	var tle *targetLookupError
	if errors.As(a.Err, &tle) {
		return replyHostUnreachable, true
	}
	if a.Kind != KindDirect {
		return 0, false
	}
	var dnsErr *net.DNSError
	var netErr net.Error
	switch {
	case errors.Is(a.Err, syscall.ECONNREFUSED):
		return replyRefused, true
	case errors.Is(a.Err, syscall.ENETUNREACH), errors.Is(a.Err, syscall.EHOSTUNREACH),
		errors.Is(a.Err, syscall.ETIMEDOUT), errors.Is(a.Err, context.DeadlineExceeded),
		errors.Is(a.Err, os.ErrDeadlineExceeded), errors.As(a.Err, &dnsErr),
		errors.As(a.Err, &netErr) && netErr.Timeout():
		return replyHostUnreachable, true
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// The destination policy
// ---------------------------------------------------------------------------

// DestinationAllowed reports whether the edge may connect to ip on behalf of
// somebody that it does not trust with the node and its network: an engine,
// through the SOCKS ports, or a stranger that the edge masks to the stranger's
// own server name, a mask domain, and so to whatever the DNS says that the name
// is. It is the policy of SocksPorts, netpolicy.Allowed: no loopback, private,
// link-local (the metadata services of the clouds among them), unspecified,
// multicast or carrier-grade NAT address. An IPv6 address that carries an IPv4
// address (IPv4-mapped, IPv4-compatible, NAT64, 6to4) is that IPv4 address.
func DestinationAllowed(ip netip.Addr) bool { return destinationAllowed(ip) }

// destinationAllowed reports whether an engine may connect to ip. See SocksPorts
// for what it may not.
func destinationAllowed(ip netip.Addr) bool { return netpolicy.Allowed(ip) }

// localName reports whether host is "localhost" or a name under it, which are
// loopback addresses by definition (RFC 6761).
func localName(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// ---------------------------------------------------------------------------
// The log of the SOCKS server
// ---------------------------------------------------------------------------

// routineHandler wraps the handler of the log that the SOCKS server gets. The
// server logs every connection that it could not make at warn. For the edge a
// connection that cannot be made is routine, with a target that is down or a member
// that is, and an engine makes them all day, so it is a debug message here; what is
// worth a warning is a member going down, which the router says once, and a
// destination that is refused, which the port says.
type routineHandler struct{ slog.Handler }

func (h routineHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level == slog.LevelWarn && strings.HasPrefix(r.Message, "socks5: cannot connect") {
		r.Level = slog.LevelDebug
	}
	if !h.Enabled(ctx, r.Level) {
		return nil
	}
	return h.Handler.Handle(ctx, r)
}

func (h routineHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return routineHandler{h.Handler.WithAttrs(attrs)}
}

func (h routineHandler) WithGroup(name string) slog.Handler {
	return routineHandler{h.Handler.WithGroup(name)}
}

// listenReusePort listens on addr, where the address of another listener that was
// bound with SO_REUSEPORT may be shared.
func listenReusePort(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: reusePortControl}
	return lc.Listen(context.Background(), "tcp", addr)
}
