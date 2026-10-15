// Package dns is the DNS forwarder of the node.
//
// Production nodes may block UDP port 53, and the containers of the node need
// names all the same: telemt resolves its TLS front and its mask host with the
// resolver of its container, Xray resolves the servers it connects to, and the
// agent fetches subscriptions and lists. The edge runs a forwarder for all of
// them on 127.0.0.2:53, UDP and TCP; their containers get a resolv.conf that
// names it, and the edge and the agent resolve their own names through it
// (Switch).
//
// The forwarder never resolves anything itself. It asks DNS-over-HTTPS
// endpoints (package doh), and the nameservers of the host, over UDP and then
// TCP, when those fail or have not answered within 1.5 s (a hedge: the
// DNS-over-HTTPS client may take 2 x 3 s, longer than a client waits); the
// first good answer wins, and when nothing answers the answer is SERVFAIL,
// which is kept for a second (RFC 9520).
//
// Answers are cached in wire form: 4096 of them and 16 MiB in all at the most,
// the least recently used going first; an answer of more than 8 KiB is served
// and not kept. A positive answer is kept for its TTL but no longer than 300 s;
// a negative one (NXDOMAIN, no record of the type) for the TTL or the minimum
// of its SOA, 30 s at the most, and not at all without an SOA (RFC 2308).
// Identical questions in flight at the same time make one upstream query, and
// no more than 256 questions are in flight: one more is answered SERVFAIL at
// once.
//
// What it takes is a well-formed query with exactly one question (FORMERR
// otherwise) and the opcode QUERY (NOTIMP otherwise). A message that is not even
// a header, and a response, are not answered at all. Over UDP an answer is cut
// down to the size the client announces with EDNS(0), or to 512 bytes without
// it: records are dropped from the end, and TC is set when an answer or an
// authority record had to go, so that the client asks again over TCP. TCP takes
// 16 connections at a time and closes one that is idle for 10 s.
package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/doh"
)

// ListenAddr is the address of the forwarder, for UDP and TCP. The containers of
// the node name it in their resolv.conf.
const ListenAddr = "127.0.0.2:53"

// forwarderAddr is ListenAddr: a nameserver that the forwarder must never ask.
var forwarderAddr = netip.MustParseAddrPort(ListenAddr)

const (
	// maxTTL is the longest an answer is cached, in seconds; the TTLs of the
	// answers are cut to it.
	maxTTL = 300
	// negativeTTL is the longest a negative answer is cached, in seconds; its
	// SOA may say less.
	negativeTTL = 30
	// failTTL is how long the failure of every upstream is kept for a question,
	// in seconds (RFC 9520).
	failTTL = 1
	// maxCachedAnswer is the longest answer the cache keeps, in wire form;
	// longer ones are served and not kept.
	maxCachedAnswer = 8 << 10
	// maxUDPSize is the largest answer over UDP, and the size that the forwarder
	// announces with EDNS(0). The clients are on the loopback interface, where
	// nothing is fragmented.
	maxUDPSize = 4096
	// minUDPSize is the size of an answer over UDP without EDNS(0) (RFC 1035).
	minUDPSize = 512
	// headerLen is the length of the header of a DNS message.
	headerLen = 12
	// maxListed bounds the endpoints and the nameservers of a configuration.
	maxListed = 16
)

// limits are the bounds of a forwarder. A zero field means its default.
type limits struct {
	tcpConns        int           // TCP connections at a time
	tcpIdle         time.Duration // how long a TCP connection may say nothing
	inFlight        int           // questions in flight upstream at a time, and DNS-over-HTTPS attempts
	udpHandlers     int           // UDP queries handled at a time
	cacheEntries    int           // answers in the cache
	cacheBytes      int           // bytes in the cache, the answers in wire form, their keys and an overhead
	exchangeTimeout time.Duration // one query to a nameserver of the host, over UDP or TCP
	hedgeDelay      time.Duration // how long DNS-over-HTTPS has before the nameservers of the host are asked too
	resolveTimeout  time.Duration // all the upstream work for one question
}

func defaultLimits() limits {
	return limits{
		tcpConns:        16,
		tcpIdle:         10 * time.Second,
		inFlight:        256,
		udpHandlers:     1024,
		cacheEntries:    4096,
		cacheBytes:      16 << 20,
		exchangeTimeout: 2 * time.Second,
		hedgeDelay:      1500 * time.Millisecond,
		resolveTimeout:  10 * time.Second,
	}
}

func (l limits) withDefaults() limits {
	d := defaultLimits()
	if l.tcpConns <= 0 {
		l.tcpConns = d.tcpConns
	}
	if l.tcpIdle <= 0 {
		l.tcpIdle = d.tcpIdle
	}
	if l.inFlight <= 0 {
		l.inFlight = d.inFlight
	}
	if l.udpHandlers <= 0 {
		l.udpHandlers = d.udpHandlers
	}
	if l.cacheEntries <= 0 {
		l.cacheEntries = d.cacheEntries
	}
	if l.cacheBytes <= 0 {
		l.cacheBytes = d.cacheBytes
	}
	if l.hedgeDelay <= 0 {
		l.hedgeDelay = d.hedgeDelay
	}
	if l.exchangeTimeout <= 0 {
		l.exchangeTimeout = d.exchangeTimeout
	}
	if l.resolveTimeout <= 0 {
		l.resolveTimeout = d.resolveTimeout
	}
	return l
}

// Upstream is the DNS-over-HTTPS side of the forwarder: Exchange takes a query
// in wire format and returns the answer, as doh.Client does.
type Upstream interface {
	Exchange(ctx context.Context, query []byte) ([]byte, error)
}

// defaultUpstream is the DNS-over-HTTPS client of the endpoints.
func defaultUpstream(urls []string) Upstream { return doh.New(urls) }

// Options are the settings of a forwarder that the configuration does not
// give. The zero value is what the edge runs with.
type Options struct {
	// Addr is the address to listen on, UDP and TCP; empty means ListenAddr. A
	// port of 0 takes a port that is free for both.
	Addr string
	// Now is the clock of the cache; nil means time.Now.
	Now func() time.Time
	// NewUpstream makes the DNS-over-HTTPS side for the endpoints of a
	// configuration; nil means a doh.Client.
	NewUpstream func(urls []string) Upstream

	limits limits // the tests change them
}

var errClosed = errors.New("dns: the forwarder is closed")

// Forwarder is the DNS forwarder of the edge. It does nothing until Apply
// enables it. Its methods may be called from any goroutine.
type Forwarder struct {
	log   *slog.Logger
	opts  Options
	lim   limits
	sw    *Switch
	cache *cache
	warns rateLimit

	mu      sync.Mutex // serializes Apply and Close
	srv     *server    // nil while the forwarder does not run
	urlsKey string     // the endpoints of the upstream in effect
	closed  bool

	ups     atomic.Pointer[upstreams]
	running atomic.Bool
}

// upstreams are what the forwarder asks: one configuration of them.
type upstreams struct {
	doh      Upstream
	fallback []netip.AddrPort
}

// New returns a forwarder that does not run yet. A nil log means
// slog.Default().
func New(log *slog.Logger, opts Options) *Forwarder {
	if log == nil {
		log = slog.Default()
	}
	if opts.Addr == "" {
		opts.Addr = ListenAddr
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewUpstream == nil {
		opts.NewUpstream = defaultUpstream
	}
	lim := opts.limits.withDefaults()
	f := &Forwarder{
		log:   log,
		opts:  opts,
		lim:   lim,
		sw:    NewSwitch(),
		cache: newCache(lim.cacheEntries, lim.cacheBytes),
		warns: rateLimit{every: 30 * time.Second},
	}
	f.ups.Store(&upstreams{})
	return f
}

func (f *Forwarder) now() time.Time { return f.opts.Now() }

// Apply makes cfg the configuration of the forwarder; nil, or a configuration
// that is not enabled, stops it. A configuration that CheckConfig refuses is
// refused here, and nothing changes.
//
// An enabled forwarder that does not run yet binds its address now, UDP and TCP.
// When that fails, Apply returns the error and the forwarder does not run; the
// next Apply tries again. One that runs keeps its sockets and what it has cached:
// it only takes the new endpoints and nameservers, for the questions that come
// after.
//
// While the forwarder runs, the resolver of Resolver asks it.
func (f *Forwarder) Apply(cfg *edgev1.Dns) error {
	if err := CheckConfig(cfg); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errClosed
	}
	if !cfg.GetEnabled() {
		f.stopLocked()
		return nil
	}

	urls := cfg.GetDohUrls()
	if len(urls) == 0 {
		urls = doh.DefaultEndpoints
	}
	fallback := make([]netip.AddrPort, 0, len(cfg.GetFallback()))
	for _, s := range cfg.GetFallback() {
		ns, _ := parseNameserver(s) // checked above
		fallback = append(fallback, ns)
	}
	old := f.ups.Load()
	next := &upstreams{doh: old.doh, fallback: fallback}
	if key := strings.Join(urls, "\n"); key != f.urlsKey || next.doh == nil {
		next.doh = f.opts.NewUpstream(slices.Clone(urls))
		f.urlsKey = key
	}
	f.ups.Store(next)
	if old.doh != nil && old.doh != next.doh {
		closeIdle(old.doh)
	}

	if f.srv != nil {
		return nil
	}
	srv, err := f.listen()
	if err != nil {
		return err
	}
	f.srv = srv
	f.running.Store(true)
	f.sw.Use(srv.addr.String())
	f.log.Info("dns: forwarder listening", "addr", srv.addr.String(), "doh_endpoints", len(urls), "fallback", len(fallback))
	return nil
}

// stopLocked closes the sockets and waits for the queries that are being
// answered; those that wait for an upstream are cut short.
func (f *Forwarder) stopLocked() {
	if f.srv == nil {
		return
	}
	f.sw.Use("")
	f.running.Store(false)
	f.srv.close()
	f.srv = nil
	f.cache.clear()
	if u := f.ups.Load(); u.doh != nil {
		closeIdle(u.doh)
	}
	f.log.Info("dns: forwarder stopped")
}

// Close stops the forwarder for good: Apply fails after it. It may be called
// more than once.
func (f *Forwarder) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	f.stopLocked()
	if u := f.ups.Load(); u.doh != nil {
		closeIdle(u.doh)
	}
}

// Running reports whether the forwarder runs: it is enabled and bound.
func (f *Forwarder) Running() bool { return f.running.Load() }

// Addr returns the address the forwarder is bound to, the zero value while it
// does not run.
func (f *Forwarder) Addr() netip.AddrPort {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.srv == nil {
		return netip.AddrPort{}
	}
	return f.srv.addr
}

// Resolver returns a resolver that asks the forwarder while it runs, and the
// nameservers of /etc/resolv.conf while it does not. The edge resolves the
// names it connects to itself with it.
func (f *Forwarder) Resolver() *net.Resolver { return f.sw.Resolver() }

// closeIdle closes the idle connections of an upstream that has them, the
// connections of a doh.Client to its endpoints.
func closeIdle(u Upstream) {
	if c, ok := u.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// ---------------------------------------------------------------------------
// The configuration
// ---------------------------------------------------------------------------

// CheckConfig checks the DNS part of an edge configuration. A configuration
// that is not enabled is not looked at. The endpoints are https URLs whose host
// is an IP address, without credentials; the nameservers are "ip" (port 53) or
// "ip:port", not the forwarder itself; 16 of each at the most.
func CheckConfig(c *edgev1.Dns) error {
	if !c.GetEnabled() {
		return nil
	}
	if len(c.GetDohUrls()) > maxListed || len(c.GetFallback()) > maxListed {
		return fmt.Errorf("dns: more than %d endpoints or nameservers", maxListed)
	}
	for i, raw := range c.GetDohUrls() {
		if err := checkDoHURL(raw); err != nil {
			return fmt.Errorf("dns: doh_urls[%d]: %w", i, err)
		}
	}
	for i, raw := range c.GetFallback() {
		if _, err := parseNameserver(raw); err != nil {
			return fmt.Errorf("dns: fallback[%d] %.64q: %w", i, raw, err)
		}
	}
	return nil
}

// checkDoHURL checks an endpoint. Its error does not repeat the URL, which may
// carry credentials.
func checkDoHURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil || raw == "":
		return errors.New("not a URL")
	case u.User != nil:
		return errors.New("the URL carries credentials")
	case u.Scheme != "https":
		return errors.New("not an https URL")
	}
	if _, err := netip.ParseAddr(u.Hostname()); err != nil {
		return errors.New("the host of the URL is not an IP address: no name is looked up to reach an endpoint")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.ParseUint(p, 10, 16); err != nil || n == 0 {
			return errors.New("the port of the URL is not from 1 to 65535")
		}
	}
	return nil
}

// parseNameserver reads a nameserver of the host: "ip", which means port 53, or
// "ip:port".
func parseNameserver(s string) (netip.AddrPort, error) {
	var ap netip.AddrPort
	if a, err := netip.ParseAddr(s); err == nil {
		ap = netip.AddrPortFrom(a, 53)
	} else if ap, err = netip.ParseAddrPort(s); err != nil {
		return netip.AddrPort{}, errors.New("neither an IP address nor ip:port")
	}
	a := ap.Addr().Unmap()
	switch {
	case ap.Port() == 0:
		return netip.AddrPort{}, errors.New("the port is 0")
	case a.IsUnspecified() || a.IsMulticast():
		return netip.AddrPort{}, errors.New("not the address of a nameserver")
	case netip.AddrPortFrom(a.WithZone(""), ap.Port()) == forwarderAddr:
		return netip.AddrPort{}, errors.New("it is the forwarder itself")
	}
	return netip.AddrPortFrom(a, ap.Port()), nil
}

// ---------------------------------------------------------------------------
// The sockets
// ---------------------------------------------------------------------------

// listen binds the address of the forwarder, TCP and UDP on one port, with
// SO_REUSEPORT, so that the edge generation that takes over can bind it while
// this one still holds it.
func (f *Forwarder) listen() (*server, error) {
	want, err := netip.ParseAddrPort(f.opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("dns: the address %q: %w", f.opts.Addr, err)
	}
	v := "4"
	if want.Addr().Unmap().Is6() {
		v = "6"
	}
	lc := listenConfig()
	ctx := context.Background()
	for attempt := 1; ; attempt++ {
		ln, err := lc.Listen(ctx, "tcp"+v, want.String())
		if err != nil {
			return nil, fmt.Errorf("dns: listening on %s over TCP: %w", want, err)
		}
		tcpAddr := ln.Addr().(*net.TCPAddr).AddrPort()
		bound := netip.AddrPortFrom(tcpAddr.Addr().Unmap(), tcpAddr.Port())
		pc, err := lc.ListenPacket(ctx, "udp"+v, bound.String())
		if err != nil {
			_ = ln.Close()
			if want.Port() == 0 && attempt < 10 {
				continue // the UDP side of the free TCP port is taken: another port
			}
			return nil, fmt.Errorf("dns: listening on %s over UDP: %w", bound, err)
		}
		return newServer(f, bound, pc.(*net.UDPConn), ln.(*net.TCPListener)), nil
	}
}

// server is the forwarder while it runs: its sockets, the queries being
// answered and the questions in flight.
type server struct {
	f      *Forwarder
	addr   netip.AddrPort
	udp    *net.UDPConn
	tcp    *net.TCPListener
	ctx    context.Context // done when the server closes: ends every wait
	cancel context.CancelFunc
	wg     sync.WaitGroup
	udpSem chan struct{}
	tcpSem chan struct{}

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closed  bool
	flights map[cacheKey]*flight
	joins   atomic.Int64 // clients that waited for a question in flight

	// dohSlots bounds the DNS-over-HTTPS attempts, also those that run on
	// after their question has its answer (see lookup).
	dohSlots chan struct{}
}

// flight is a question that is being asked upstream. The first client asks;
// the others with the same question wait for its answer.
type flight struct {
	done chan struct{}
	e    *entry
	err  error
}

func newServer(f *Forwarder, addr netip.AddrPort, udp *net.UDPConn, tcp *net.TCPListener) *server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &server{
		f: f, addr: addr, udp: udp, tcp: tcp, ctx: ctx, cancel: cancel,
		udpSem:   make(chan struct{}, f.lim.udpHandlers),
		tcpSem:   make(chan struct{}, f.lim.tcpConns),
		dohSlots: make(chan struct{}, f.lim.inFlight),
		conns:    map[net.Conn]struct{}{},
		flights:  map[cacheKey]*flight{},
	}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return s
}

// close closes the sockets and the TCP connections, cuts short the questions in
// flight, and waits until every goroutine of the server has returned.
func (s *server) close() {
	s.cancel()
	_ = s.udp.Close()
	_ = s.tcp.Close()
	s.mu.Lock()
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	var delay time.Duration
	for {
		n, from, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			delay = s.pause(delay, "udp read", err)
			continue
		}
		delay = 0
		if n < headerLen {
			continue // not even a header: nothing to answer
		}
		select {
		case s.udpSem <- struct{}{}:
		default:
			continue // too many at once: the client asks again
		}
		query := slices.Clone(buf[:n])
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.udpSem }()
			defer s.recovered("udp")
			if resp := s.answer(query, true); resp != nil {
				_, _ = s.udp.WriteToUDPAddrPort(resp, from)
			}
		}()
	}
}

func (s *server) serveTCP() {
	defer s.wg.Done()
	var delay time.Duration
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			delay = s.pause(delay, "tcp accept", err)
			continue
		}
		delay = 0
		select {
		case s.tcpSem <- struct{}{}:
		default:
			_ = c.Close() // 16 at a time: the client goes elsewhere or asks again
			continue
		}
		if !s.track(c) {
			<-s.tcpSem
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go s.serveConn(c)
	}
}

// pause waits after a failed read or accept, longer each time up to a second,
// or until the server closes; it returns the next delay.
func (s *server) pause(delay time.Duration, what string, err error) time.Duration {
	delay = min(max(2*delay, 5*time.Millisecond), time.Second)
	if s.f.warns.allow() {
		s.f.log.Warn("dns: "+what+" failed, trying again", "err", err, "delay", delay)
	}
	select {
	case <-time.After(delay):
	case <-s.ctx.Done():
	}
	return delay
}

func (s *server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

// serveConn answers the queries of one TCP connection, one after the other,
// until it ends, says something that is not a query, or is idle for too long.
func (s *server) serveConn(c net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		_ = c.Close()
		<-s.tcpSem
	}()
	defer s.recovered("tcp")
	idle := s.f.lim.tcpIdle
	for {
		_ = c.SetReadDeadline(time.Now().Add(idle))
		query, err := readMessage(c)
		if err != nil || len(query) < headerLen {
			return
		}
		resp := s.answer(query, false)
		if resp == nil {
			return
		}
		_ = c.SetWriteDeadline(time.Now().Add(idle))
		if err := writeMessage(c, resp); err != nil {
			return
		}
	}
}

// recovered logs a panic in the answer to a query; it ends that answer, and
// not the edge.
func (s *server) recovered(transport string) {
	if p := recover(); p != nil {
		s.f.log.Error("dns: panic while answering a query", "transport", transport, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
	}
}

// ---------------------------------------------------------------------------
// Answers
// ---------------------------------------------------------------------------

// errBusy is the failure of a question over the cap of questions in flight.
var errBusy = errors.New("too many questions in flight")

// errInternal is the result of a flight whose lookup did not return.
var errInternal = errors.New("internal error")

// answer returns the answer to query, nil when there is none to give. udp says
// whether the answer goes back over UDP, and is cut to the client's size.
func (s *server) answer(query []byte, udp bool) []byte {
	in, ok := parseQuery(query)
	if !ok {
		return nil
	}
	if in.rcode != 0 {
		return in.reply(in.rcode)
	}
	limit := 0
	if udp {
		limit = in.udpSize()
	}
	k := keyOf(in.q)
	now := s.f.now()
	if e := s.f.cache.get(k, now); e != nil {
		return in.answer(e, now, limit)
	}
	e, err := s.resolve(k, in.q)
	if err != nil {
		if s.ctx.Err() == nil && s.f.warns.allow() {
			s.f.log.Warn("dns: no answer for a question", "name", in.q.Name.String(), "type", in.q.Type.String(), "err", err)
		}
		return in.reply(dnsmessage.RCodeServerFailure)
	}
	return in.answer(e, s.f.now(), limit)
}

// resolve asks upstream for the answer to q, or waits for the answer of the
// client that asks it already. A new question over the cap of questions in
// flight fails at once.
func (s *server) resolve(k cacheKey, q dnsmessage.Question) (*entry, error) {
	s.mu.Lock()
	if fl, ok := s.flights[k]; ok {
		s.mu.Unlock()
		s.joins.Add(1)
		select {
		case <-fl.done:
			return fl.e, fl.err
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		}
	}
	if len(s.flights) >= s.f.lim.inFlight {
		s.mu.Unlock()
		return nil, errBusy
	}
	fl := &flight{done: make(chan struct{}), err: errInternal}
	s.flights[k] = fl
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.flights, k)
		s.mu.Unlock()
		close(fl.done)
	}()
	e, err := s.lookup(q)
	switch {
	case err == nil:
		s.f.cache.put(k, e)
	case s.ctx.Err() == nil:
		s.f.cache.put(k, failure(s.f.now())) // RFC 9520: not asked again for a second
	}
	fl.e, fl.err = e, err
	return e, err
}

// rateLimit allows one thing per interval.
type rateLimit struct {
	every time.Duration
	last  atomic.Int64 // unix nanoseconds of the last one allowed
}

func (r *rateLimit) allow() bool {
	now := time.Now().UnixNano()
	last := r.last.Load()
	if last != 0 && now-last < int64(r.every) {
		return false
	}
	return r.last.CompareAndSwap(last, now)
}
