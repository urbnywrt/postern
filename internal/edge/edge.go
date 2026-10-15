// Package edge is the data plane of a node: it owns the proxy ports.
//
// For every connection the edge reads the TLS ClientHello, picks the route of
// the listener by the server name the client asks for, and relays the
// connection to the backend of the route, an MTProto engine on the loopback
// interface, behind a PROXY v2 header that names the client. The ClientHello is
// replayed to the backend byte for byte. A connection for a name the listener
// has no route for, a "stranger", is masked (relayed as it is to another
// server), rejected with a TLS alert or dropped, as the listener says. Before
// any of that, a connection is held to the caps of ingress.go, which bound the
// connections that have not sent their hello yet and all the connections of
// the public listeners: one over a cap is closed as it is accepted, or, when
// the connections before their hello are at their cap, the oldest of them
// makes way for it. The edge also enforces the limits of every proxy and
// keeps its traffic counters.
// None of this depends on the engine behind a route: the edge knows a backend
// by its address only.
//
// A route of kind web is not relayed: the edge terminates its TLS with the
// certificate of its name and proxies its HTTP requests to the WEB listener of
// the engine (web.go, webproxy.go, certs.go). A listener of kind http-upstream
// takes such requests as plain HTTP from a web server in front of it
// (httpupstream.go).
//
// The configuration is one edgev1.EdgeConfig, applied whole by Apply. It is
// turned into an immutable route table that replaces the previous one
// atomically, so that a connection is handled by one table from its start to
// its end, and Apply never disturbs a connection in flight. (A web connection
// is admitted by one table too; each of its requests then takes the route of
// its proxy in the table in effect as the request comes.)
package edge

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// The defaults of Options.
const (
	defaultClientHelloTimeout = 10 * time.Second
	defaultIdleTimeout        = 15 * time.Minute
	defaultDialTimeout        = 4 * time.Second
	defaultMaxClientHello     = 64 << 10
	defaultMaxMasked          = 256
	defaultCertsDir           = "/opt/postern/data/certs"
)

// Options are the tunables of an Edge. The zero value of every field, or a
// negative one, means its default.
type Options struct {
	// ClientHelloTimeout is the time a client has, from the moment its
	// connection is accepted, to send its whole ClientHello. A client that is
	// slower is closed without an answer. While more than half of MaxPreHello
	// is taken, a new connection has 3 s at most. Default 10 s.
	ClientHelloTimeout time.Duration
	// IdleTimeout ends a relayed connection when nothing has come from either
	// side for that long. Default 15 min.
	IdleTimeout time.Duration
	// DialTimeout bounds the dial of a backend or of a mask target, and the
	// write of the first bytes to it. Default 4 s.
	DialTimeout time.Duration
	// MaxClientHello is the most bytes read for a ClientHello, record headers
	// included. A larger hello makes the connection a stranger. Default 65536.
	MaxClientHello int
	// Now is the clock of the device idle window and of the counters. Default
	// time.Now. The deadlines of connections always follow the real clock.
	Now func() time.Time
	// DialMask connects to the target of a masked stranger: the listener's mask
	// target as it is, or "<address>:443", an address of the server name that
	// the destination policy allows. The addresses of a name are raced, so
	// several of these dials may be under way at once (see raceMaskDial).
	// Default: a net.Dialer over TCP.
	DialMask func(ctx context.Context, addr string) (net.Conn, error)
	// MaxMasked is the most strangers masked at a time by the whole edge;
	// the ones over it are rejected, as the reject action does. A masked
	// stranger costs a connection to its target, and a lookup of its server
	// name when that is a mask domain; and a mask target that leads back to
	// the node in a way the edge cannot see, through a NAT hairpin or another
	// node, would otherwise make it dial itself without end. Default 256.
	MaxMasked int
	// MaxPreHello is the most connections of the public listeners that may be
	// between their accept and the end of their ClientHello at a time, in the
	// whole edge. When there are as many, the oldest of them is closed to make
	// room for a new one. There may be 16 at most of one source as well, and a
	// connection over that is closed as it is accepted. Default min(4096, 25 %
	// of the soft limit of open files of the process, half the default of
	// MaxConns). See ingress.go.
	MaxPreHello int
	// MaxConns is the most connections the edge holds for its public listeners
	// at a time: before their hello, relayed, masked or being answered. A
	// connection over it is closed as it is accepted. Default min(max(1024,
	// 20 % of the soft limit of open files of the process), max(1024, 50 % of
	// its memory limit / 100 KiB)); the memory limit is the memory.max of its
	// cgroup when it has one, else the memory of the machine.
	MaxConns int
	// Resolver looks up the addresses of a mask domain, before a stranger is
	// masked to its own server name (see stranger). Default: the resolver of
	// the system, net.DefaultResolver. A resolver of the edge's own, such as a
	// DNS forwarder, goes here.
	Resolver Resolver
	// CertsDir is the certificate directory of the node: the certificate of a
	// WEB domain is <CertsDir>/<domain>/fullchain.pem, with its key in
	// privkey.pem (see certs.go). Default /opt/postern/data/certs, where the
	// edge container has the directory, read-only.
	CertsDir string
}

// Resolver looks up the IP addresses of a host name. *net.Resolver is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// withDefaults fills in the defaults; c are the caps derived from the limits
// of the process.
func (o Options) withDefaults(c caps) Options {
	if o.MaxPreHello <= 0 {
		o.MaxPreHello = c.preHello
	}
	if o.MaxConns <= 0 {
		o.MaxConns = c.conns
	}
	if o.ClientHelloTimeout <= 0 {
		o.ClientHelloTimeout = defaultClientHelloTimeout
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = defaultDialTimeout
	}
	if o.MaxClientHello <= 0 {
		o.MaxClientHello = defaultMaxClientHello
	}
	if o.MaxMasked <= 0 {
		o.MaxMasked = defaultMaxMasked
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.DialMask == nil {
		var d net.Dialer
		o.DialMask = func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.CertsDir == "" {
		o.CertsDir = defaultCertsDir
	}
	return o
}

// maxDropDelay is the longest the drop action waits before it closes.
const maxDropDelay = 2 * time.Second

// randomDropDelay is the wait of the drop action: random, so that the
// moment a dropped connection closes tells a prober nothing.
func randomDropDelay() time.Duration {
	return rand.N(maxDropDelay + 1)
}

// errDrained is the error of Apply once Drain has begun.
var errDrained = errors.New("edge: drained, no new configuration is taken")

// Edge is the data plane of a node. It does nothing until the first Apply.
// Its methods may be called from any goroutine.
type Edge struct {
	log  *slog.Logger
	opts Options

	// dropDelay returns the wait of the drop action; a field so that tests can
	// set it. It is randomDropDelay otherwise.
	dropDelay func() time.Duration
	// afterFunc starts the timer that closes an exempt connection of the
	// panel's probes, and returns the function that stops it; a field so
	// that tests can run the timer on a clock of their own. It is
	// time.AfterFunc otherwise.
	afterFunc func(d time.Duration, f func()) (stop func() bool)

	dialer net.Dialer // to the backends; the timeout comes with the context

	table   atomic.Pointer[table] // the table in effect; nil before the first Apply
	stats   *statsRegistry        // per proxy; outlives every table
	conns   *connSet              // the connections being handled
	ingress *ingress              // the caps on the connections of the public listeners
	warns   *logLimiter
	// capWarns limits the warning about the connections refused at accept to
	// one per refusalWarnInterval.
	capWarns *logLimiter
	// probeWarns limits the warning about a test listener that cannot be
	// bound to one per probeWarnInterval and address.
	probeWarns *logLimiter
	// certWarns limits the warnings about a certificate of a WEB domain that
	// cannot be read or served to one per certWarnInterval and domain.
	certWarns *logLimiter

	certs *certStore // the certificates of the web routes; outlives every table
	web   *webServer // the HTTP server of the web connections

	// maskLocal holds the local addresses of the connections to mask targets
	// that are open, to tell a mask target that is this very edge (see
	// isMaskLoop).
	maskLocal sync.Map     // netip.AddrPort -> struct{}
	masked    atomic.Int64 // strangers being masked, see Options.MaxMasked

	// ctx is cancelled when Drain gives up waiting: it stops dials and the
	// waits of the drop action of the connections that are left.
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex // serializes Apply, Drain and the retries of the binds
	listeners map[netip.AddrPort]*listener
	// failed holds the listeners of the table in effect that are not bound:
	// their bind failed, and is tried again (see retryDue). A test listener
	// is never among them.
	failed     map[netip.AddrPort]*bindFailure
	retryTimer *time.Timer // runs retryBinds when the earliest retry is due; nil when nothing failed
	// retryMin is the first wait before a failed bind is tried again, and
	// retryMax the longest, as the wait doubles: fields so that tests can
	// shorten them.
	retryMin, retryMax time.Duration
	drained            bool
	// ignoredLogged holds the probe sources that are no address and have
	// been logged, so that each is logged once and not by every Apply.
	ignoredLogged map[string]bool
}

// maxIgnoredLogged bounds Edge.ignoredLogged: once it holds that many, it is
// emptied, and an entry may be logged again.
const maxIgnoredLogged = 64

// The waits between the retries of a bind that failed: the first one, and the
// longest one, as the wait doubles after each failure.
const (
	bindRetryMin = 30 * time.Second
	bindRetryMax = 5 * time.Minute
)

// bindFailure is a listener of the table in effect that could not be bound.
type bindFailure struct {
	id   string
	err  error
	wait time.Duration // the wait before the next retry, after a failure
	next time.Time     // when the next retry is due, on the real clock
}

// New returns an Edge with the given options. A nil log means slog.Default().
func New(log *slog.Logger, opts Options) *Edge {
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	// The limits of the process are read once, here: the caps derived from
	// them do not change while the edge runs.
	nofile := openFileLimit()
	memory, memoryFrom := systemMemory()
	c := deriveCaps(nofile, memory)
	opts = opts.withDefaults(c)
	var openFiles any = nofile
	if nofile == 0 {
		openFiles = "unknown"
	}
	log.Info("edge: connection caps", "open_files", openFiles, "memory", memory, "memory_from", memoryFrom,
		"max_conns_by_open_files", c.byFiles, "max_conns_by_memory", c.byMemory, "max_conns", opts.MaxConns,
		"max_prehello", opts.MaxPreHello, "max_prehello_per_source", perSourcePreHello)
	e := &Edge{
		log:       log,
		opts:      opts,
		dropDelay: randomDropDelay,
		afterFunc: func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		},
		stats:      newStatsRegistry(),
		conns:      newConnSet(),
		ingress:    newIngress(opts),
		warns:      newLogLimiter(warnInterval),
		capWarns:   newLogLimiter(refusalWarnInterval),
		probeWarns: newLogLimiter(probeWarnInterval),
		certWarns:  newLogLimiter(certWarnInterval),
		certs:      newCertStore(opts.CertsDir),
		ctx:        ctx,
		cancel:     cancel,
		listeners:  make(map[netip.AddrPort]*listener),
		failed:     make(map[netip.AddrPort]*bindFailure),
		retryMin:   bindRetryMin,
		retryMax:   bindRetryMax,
	}
	e.web = newWebServer(e)
	return e
}

func (e *Edge) now() time.Time { return e.opts.Now() }

// Apply makes cfg the configuration in effect.
//
// The configuration is checked as a whole first; if anything is wrong with it,
// Apply returns an error and nothing changes. Then the listeners that cfg has
// and the edge has not are bound, with SO_REUSEPORT, each on its own: one that
// cannot be bound, because its port is held by a process that does not share
// it or its address is not on the host, fails nothing but itself. The new
// route table replaces the previous one at once, the listeners that were bound
// start accepting, and the listeners cfg no longer has are closed. The
// listeners that failed are reported by Failures, and tried again after
// retryMin, then after twice the wait each time up to retryMax, and by every
// Apply; one that binds later starts serving at once and leaves Failures.
//
// A test listener of cfg binds 127.0.0.1 and routes like the listener it
// names, but that a probe route of cfg for the listener and a server name
// takes that name to its own backend; its connections, the node's own probes,
// are held to no limit and counted for no proxy. The probe routes serve no
// other connection. A test listener that cannot be bound is not reported by
// Failures and not retried on its own: no client uses it, so it is left out,
// with a warning (at most one per probeWarnInterval), the configuration
// applies without it, and the next Apply tries it again; the probes through
// it fail meanwhile.
//
// The probe sources of cfg, the panel's addresses, take effect with the
// table: a connection that a public listener accepts from one of them after
// that is exempt from the limits of its proxy, bounded (see handle). An entry
// that is no single address is ignored, and logged once.
//
// The certificates of cfg are read before the new table takes effect, those
// of the domains that are new or have a new generation only (see certs.go). A
// certificate that cannot be read fails nothing: it is logged, and the
// connections of its name get the alert unrecognized_name until a later Apply
// reads it.
//
// A listener is identified by its address: one that cfg keeps, even under
// another id, keeps its socket and is never closed. Connections in flight are
// not touched by Apply: they go on under the table they were accepted with, and
// a connection accepted by a listener that Apply closes goes on as well; but
// every request of a web connection takes the route of its proxy as it is when
// the request comes (web.go). The counters and the limit state of the proxies
// survive Apply.
//
// The parts of cfg that are not the edge's own (socks, chains, health) are not
// looked at. Once Drain has begun Apply fails.
func (e *Edge) Apply(cfg *edgev1.EdgeConfig) error {
	t, err := buildTable(cfg)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.drained {
		return errDrained
	}

	// The failures of listeners cfg no longer has go; the others are tried
	// again below, and keep their wait if they fail again.
	for addr := range e.failed {
		if _, keep := t.listeners[addr]; !keep {
			delete(e.failed, addr)
		}
	}
	var opened []*listener
	now := time.Now()
	for _, addr := range slices.SortedFunc(maps.Keys(t.listeners), netip.AddrPort.Compare) {
		if _, ok := e.listeners[addr]; ok {
			continue
		}
		id := t.listeners[addr].id
		l, err := listen(addr)
		switch {
		case err != nil && t.probes[addr]:
			// Only the node's own probes use a test listener: the table goes
			// on without it (I1), and is tried again by the next Apply.
			e.warnProbeBind(id, addr, err)
			delete(t.listeners, addr)
			delete(t.probes, addr)
		case err != nil:
			e.noteBindFailure(id, addr, err, now)
		default:
			delete(e.failed, addr)
			opened = append(opened, l)
		}
	}
	e.scheduleRetryLocked(now)

	// Each route gets the state of its proxy now, not per connection; this
	// also lists the proxy in Snapshot before its first connection.
	for _, r := range t.routes {
		if r.proxyID != "" {
			r.stats = e.stats.proxy(r.proxyID)
		}
	}
	// Nothing fails from here on: the certificates of the table are read for
	// it before its web routes are served.
	e.updateCerts(t.certs)
	e.logIgnoredSources(t.ignoredSources)
	e.table.Store(t)

	for _, l := range opened {
		e.listeners[l.addr] = l
		go e.serve(l)
		e.log.Info("edge: listening", "addr", l.addr.String(), "listener", t.listeners[l.addr].id)
	}
	for addr, l := range e.listeners {
		if _, keep := t.listeners[addr]; !keep {
			l.close()
			delete(e.listeners, addr)
			e.log.Info("edge: listener closed", "addr", addr.String())
		}
	}
	e.log.Info("edge: configuration applied", "generation", t.generation,
		"listeners", len(e.listeners), "failed_listeners", len(e.failed), "routes", len(t.routes),
		"probe_sources", len(t.probeSources))
	return nil
}

// logIgnoredSources warns of the probe sources of a configuration that are no
// single IP address, each once. e.mu must be held.
func (e *Edge) logIgnoredSources(ignored []string) {
	for _, s := range ignored {
		if e.ignoredLogged[s] {
			continue
		}
		if e.ignoredLogged == nil || len(e.ignoredLogged) >= maxIgnoredLogged {
			e.ignoredLogged = make(map[string]bool)
		}
		e.ignoredLogged[s] = true
		e.log.Warn("edge: a probe source is not a single IP address and is ignored; the panel's probes from it count as clients",
			"probe_source", fmt.Sprintf("%.70q", s))
	}
}

// noteBindFailure records that the listener id at addr could not be bound at
// now (err). A failure that is new, or whose error has changed, is logged as a
// warning; one that goes on keeps its wait, and the retry is due after it.
func (e *Edge) noteBindFailure(id string, addr netip.AddrPort, err error, now time.Time) {
	f, ok := e.failed[addr]
	if !ok {
		f = &bindFailure{wait: e.retryMin}
		e.failed[addr] = f
	}
	if !ok || f.err.Error() != err.Error() {
		e.log.Warn("edge: a listener cannot be bound; the others serve, and it is tried again until it binds",
			"listener", id, "addr", addr.String(), "err", err, "retry_in", f.wait.String())
	}
	f.id, f.err, f.next = id, err, now.Add(f.wait)
}

// scheduleRetryLocked arms the timer of the retries for the earliest failure
// that is due, or stops it when nothing failed. The caller holds mu.
func (e *Edge) scheduleRetryLocked(now time.Time) {
	if e.retryTimer != nil {
		e.retryTimer.Stop()
		e.retryTimer = nil
	}
	if len(e.failed) == 0 || e.drained {
		return
	}
	var earliest time.Time
	for _, f := range e.failed {
		if earliest.IsZero() || f.next.Before(earliest) {
			earliest = f.next
		}
	}
	e.retryTimer = time.AfterFunc(max(earliest.Sub(now), 0), e.retryBinds)
}

// retryBinds tries the failed listeners whose retry is due now again.
func (e *Edge) retryBinds() { e.retryDue(time.Now()) }

// retryDue tries every failed listener whose retry is due at now again. One
// that binds starts serving at once, under the table in effect, and leaves the
// failures; one that fails again waits twice as long, up to retryMax.
func (e *Edge) retryDue(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.drained {
		return
	}
	t := e.table.Load()
	for _, addr := range slices.SortedFunc(maps.Keys(e.failed), netip.AddrPort.Compare) {
		f := e.failed[addr]
		if now.Before(f.next) {
			continue
		}
		if t == nil || t.listeners[addr] == nil {
			delete(e.failed, addr) // not in the table any more: nothing to bind
			continue
		}
		l, err := listen(addr)
		if err != nil {
			f.wait = min(2*f.wait, e.retryMax)
			if f.err.Error() != err.Error() {
				e.log.Warn("edge: a listener still cannot be bound", "listener", f.id, "addr", addr.String(), "err", err, "retry_in", f.wait.String())
			}
			f.err, f.next = err, now.Add(f.wait)
			continue
		}
		delete(e.failed, addr)
		e.listeners[addr] = l
		go e.serve(l)
		e.log.Info("edge: listening, after a bind that had failed", "addr", addr.String(), "listener", f.id)
	}
	e.scheduleRetryLocked(now)
}

// Failures returns the listeners of the configuration in effect that are not
// bound, by listener id, with the error of their last bind: the address and
// port and what the OS said, and no secret. Empty when every listener is
// bound, and after Drain. Test listeners are never among them.
func (e *Edge) Failures() []*edgev1.ListenerFailure {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*edgev1.ListenerFailure, 0, len(e.failed))
	for _, f := range e.failed {
		out = append(out, &edgev1.ListenerFailure{ListenerId: f.id, Reason: f.err.Error()})
	}
	slices.SortFunc(out, func(a, b *edgev1.ListenerFailure) int {
		return cmp.Compare(a.GetListenerId(), b.GetListenerId())
	})
	return out
}

// warnProbeBind logs that the test listener of listener id cannot be bound at
// addr, at most once per probeWarnInterval for an address.
func (e *Edge) warnProbeBind(id string, addr netip.AddrPort, err error) {
	level := slog.LevelDebug
	if e.probeWarns.allow(addr.String(), e.now()) {
		level = slog.LevelWarn
	}
	e.log.Log(context.Background(), level, "edge: a test listener cannot be bound; it is left out, and the node's probes through it fail",
		"listener", id, "addr", addr.String(), "err", err)
}

// Generation returns the generation of the configuration in effect, 0 before
// the first Apply.
func (e *Edge) Generation() uint64 {
	if t := e.table.Load(); t != nil {
		return t.generation
	}
	return 0
}

// Bound returns the addresses the edge listens on, as "ip:port" ("[ip]:port"
// for IPv6), sorted. Test listeners are among them.
func (e *Edge) Bound() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.listeners))
	for addr := range e.listeners {
		out = append(out, addr.String())
	}
	slices.Sort(out)
	return out
}

// Snapshot returns the counters of every proxy the edge has had a route for
// since it started, ordered by proxy id, and of their client IPs, ordered by
// proxy id and address, and the counts of the connections refused at accept
// over the caps, or evicted, since it started. The counters are cumulative and
// survive Apply; the counters of an IP are dropped some minutes after its last
// connection ended, and start from zero if it comes back. Connections of test
// listeners, the node's own probes, are not counted. The health of the egress
// is not the edge's, and is left empty. The counters of the IPs are there only
// when ips is set; otherwise they are not even gathered.
func (e *Edge) Snapshot(ips bool) *edgev1.SnapshotResponse {
	now := e.now()
	window := defaultDeviceIdle
	resp := &edgev1.SnapshotResponse{
		TsUnixNano:      now.UnixNano(),
		RefusedPrehello: e.ingress.refusedPreHello.Load(),
		RefusedTotal:    e.ingress.refusedTotal.Load(),
		EvictedPrehello: e.ingress.evictedPreHello.Load(),
	}
	if t := e.table.Load(); t != nil {
		resp.Generation, window = t.generation, t.deviceIdle
	}
	for _, p := range e.stats.all() {
		pc, ipc := p.snapshot(now, window, ips)
		resp.Proxies = append(resp.Proxies, pc)
		resp.Ips = append(resp.Ips, ipc...)
	}
	return resp
}

// Drain stops accepting: it closes every listener at once, and the web
// connections that wait for a request (those of HTTP/2 are told to go away).
// Then it waits until the connections being handled have all ended, and
// returns nil, or until ctx is done. In that case it closes the connections
// that are left and returns the error of ctx; their goroutines end shortly
// after.
//
// After Drain the edge takes no configuration any more. Drain may be called
// more than once.
func (e *Edge) Drain(ctx context.Context) error {
	e.mu.Lock()
	e.drained = true
	for addr, l := range e.listeners {
		l.close()
		delete(e.listeners, addr)
	}
	clear(e.failed) // no bind is tried any more
	e.scheduleRetryLocked(time.Now())
	e.mu.Unlock()

	e.web.stop()
	defer e.web.finish()
	idle := e.conns.drain()
	select {
	case <-idle:
		return nil
	default:
	}
	e.log.Info("edge: draining", "connections", e.conns.len())
	select {
	case <-idle:
		e.log.Info("edge: drained")
		return nil
	case <-ctx.Done():
	}
	select {
	case <-idle:
		return nil
	default:
	}
	e.cancel()
	n := e.conns.closeAll()
	e.log.Info("edge: drain cut short, connections closed", "connections", n)
	return ctx.Err()
}

// warnInterval is how often, at most, a warning about one thing is logged.
const warnInterval = 10 * time.Second

// probeWarnInterval is how often, at most, a test listener that cannot be
// bound is logged: the agent applies its configuration every 30 s.
const probeWarnInterval = 10 * time.Minute

// logLimiter tells whether a warning about a thing may be logged now. A
// backend that is down makes every connection to it fail, and every client of
// an MTProto proxy retries at once; one warning per thing per interval is
// enough.
type logLimiter struct {
	every time.Duration
	mu    sync.Mutex
	last  map[string]time.Time
}

func newLogLimiter(every time.Duration) *logLimiter {
	return &logLimiter{every: every, last: make(map[string]time.Time)}
}

// allow reports whether a warning about key may be logged at now, and if so
// counts it as logged. The keys are addresses from the configuration, so their
// number is bounded.
func (l *logLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if last, ok := l.last[key]; ok && now.Sub(last) < l.every && !now.Before(last) {
		return false
	}
	l.last[key] = now
	return true
}
