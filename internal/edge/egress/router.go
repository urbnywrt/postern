// Package egress is the way out of the edge.
//
// An MTProto engine sends all of its outbound traffic, to Telegram and to the
// sites its fake-TLS front imitates, to a SOCKS5 port that the edge opens for it
// on the loopback interface (SocksPorts). The port is the proxy, and the user
// name of the engine is the scope of the connection: "me", "fetch" or nothing;
// a connection without one to the address and port of one of Telegram's
// middle proxies is of scope "me" (Router.ScopeOf), since telemt does not say
// so itself.
// The scope and the port pick an egress chain, and a chain is a list of members
// that the connection is tried on in order (Router). A member is a way out: the
// node itself, perhaps through an interface that was brought up outside Postern,
// an upstream SOCKS5 or HTTP proxy, or the loopback port of a process that
// Postern runs (Xray, Psiphon), which is a SOCKS5 proxy as well.
//
// The router dials through the first member of the chain that is not down, and
// goes on to the next when that fails, within twice the timeout of a member in
// all. Which members are down is found out by checks that exchange the first
// message of MTProto with Telegram datacenters through every member, with
// hysteresis (RunHealth): a proxy that says yes to a connection it has not made
// does not pass for that. A member that was never checked is taken to work.
//
// Everything here runs in the process of the edge, which carries the public
// ingress as well. Nothing may take it down: a panic in the serving of a
// connection or in a probe is logged with its stack and ends that connection or
// that probe, not the process.
package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/socks5"
)

var (
	// ErrUnknownChain is the error of a dial through a chain that the router does
	// not have.
	ErrUnknownChain = errors.New("egress: unknown chain")
	// ErrNoMembers is the error of a dial through a chain without members.
	ErrNoMembers = errors.New("egress: the chain has no members")
	// ErrNoUsableMember is the error of a dial through a chain whose members are
	// all down. None of them was tried.
	ErrNoUsableMember = errors.New("egress: every member of the chain is down")
	// ErrDestinationNotAllowed is the error of a dial to a destination that the
	// policy of the engines does not allow.
	ErrDestinationNotAllowed = errors.New("egress: destination not allowed")
	// ErrClosed is the error of an Apply of SocksPorts that was closed.
	ErrClosed = errors.New("egress: closed")
	// ErrHealthRunning is the error of RunHealth while another call of it runs:
	// one loop of checks per router.
	ErrHealthRunning = errors.New("egress: the health checks of the router run already")
)

// MemberError is the failure of a dial through one member of a chain.
type MemberError struct {
	Key  string // the key of the member
	Kind string // the kind of the member: KindDirect, KindSOCKS5 or KindHTTP
	Err  error
	// Answered is true when the member was reached and what it said is about the
	// target: a failure reply of a SOCKS5 proxy (*socks5.ReplyError), an HTTP status
	// of an HTTP proxy other than 407 (*ConnectError). The member itself works, and
	// the target is what did not connect. It is the question to ask before the
	// error of a dial is taken for the failure of a member: errors.Is on an errno
	// cannot tell the two apart.
	Answered bool
}

func (e *MemberError) Error() string { return "member " + e.Key + ": " + e.Err.Error() }
func (e *MemberError) Unwrap() error { return e.Err }

// DialError is the error of Router.Dial when members of the chain were tried and
// none of them connected.
//
// Unwrap exposes the error of every attempt, in the order of the chain. What kind
// of failure each is can be told by its type, and not by errors.Is on an errno:
// a refused connection (ECONNREFUSED) is the answer of a proxy that works and
// reports that the target refused, a *socks5.ReplyError, and it is as well the
// error of a member whose proxy is not there. MemberError.Answered tells them
// apart.
type DialError struct {
	ChainID  string
	Attempts []*MemberError
	Skipped  int // the members that are down, which were not tried
	// Untried are the members that were not tried because the time of the dial
	// was up: twice the timeout of a member, for the whole chain.
	Untried int
}

func (e *DialError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "egress: chain %q: no member connected", e.ChainID)
	for i, a := range e.Attempts {
		if i == 0 {
			b.WriteString(": ")
		} else {
			b.WriteString("; ")
		}
		b.WriteString(a.Error())
	}
	if e.Skipped > 0 {
		fmt.Fprintf(&b, " (%d down, not tried)", e.Skipped)
	}
	if e.Untried > 0 {
		fmt.Fprintf(&b, " (%d not tried: the time of the dial was up)", e.Untried)
	}
	return b.String()
}

// Failed returns the number of attempts that failed because of the member, those
// that were not answers about the target. A member that refuses connections, or
// times out, or whose handshake is cut short counts; a proxy that works and says
// that the target refused does not.
func (e *DialError) Failed() int {
	n := 0
	for _, a := range e.Attempts {
		if !a.Answered {
			n++
		}
	}
	return n
}

func (e *DialError) Unwrap() []error {
	errs := make([]error, len(e.Attempts))
	for i, a := range e.Attempts {
		errs[i] = a
	}
	return errs
}

// answered reports whether err shows that the member itself was reached and
// spoke, and what it said is about the target: a failure reply of a SOCKS5 proxy,
// or an HTTP status of a proxy other than 407. Such a member is not down. It
// works and the target did not connect, or the proxy would not.
//
// An error that is not of that kind, a refused or a timed out connection to the
// member, a handshake that was cut short, the rejection of the credentials of the
// member, says something about the member.
//
// This is the question to ask first. errors.Is(err, syscall.ECONNREFUSED) cannot
// answer it: it holds for both.
func answered(err error) bool {
	var re *socks5.ReplyError
	if errors.As(err, &re) {
		return true
	}
	var ce *ConnectError
	return errors.As(err, &ce) && ce.Status != http.StatusProxyAuthRequired
}

// ---------------------------------------------------------------------------
// The state of a member
// ---------------------------------------------------------------------------

type status uint8

const (
	statusUnknown status = iota // not checked yet, and treated as usable
	statusUp
	statusDown
)

func (s status) String() string {
	switch s {
	case statusUp:
		return "up"
	case statusDown:
		return "down"
	}
	return "unknown"
}

// memberSpec is what a member is made of. A member whose spec changes is another
// member, which has not been checked; one whose spec does not change keeps what is
// known of it.
type memberSpec struct {
	kind, addr, username, password, bindDevice, bindIP string
	timeout                                            time.Duration
}

type memberID struct {
	key  string
	spec memberSpec
}

// member is a member of one chain or of several: the same key and the same spec
// is the same member, with one dialer and one state, however many chains list it.
type member struct {
	key    string
	spec   memberSpec
	dialer Dialer

	down atomic.Bool // status == statusDown, for Dial to read without the lock

	mu          sync.Mutex
	status      status
	okStreak    int // successes in a row
	failStreak  int // failures in a row
	latency     time.Duration
	exitIP      string
	exitFailing bool // the last probe that asked for the exit address got none
	checked     time.Time
	probed      bool
	earlyEnds   int       // early ends in a row of the connections through it (passive.go)
	lastPassive time.Time // when the last passive round was asked for

	passiveBusy atomic.Bool // a passive round of it runs
}

func (m *member) isDown() bool { return m.down.Load() }

func (m *member) wasProbed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.probed
}

func (m *member) report(chainID string) *edgev1.MemberHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := &edgev1.MemberHealth{
		ChainId:   chainID,
		MemberKey: m.key,
		Status:    m.status.String(),
		LatencyMs: latencyMs(m.latency),
		ExitIp:    m.exitIP,
	}
	if !m.checked.IsZero() {
		h.CheckedUnix = m.checked.Unix()
	}
	return h
}

// recorded is what the record of the check of the datacenters changed, for the
// log.
type recorded struct {
	from, to status
	failures int // the failures in a row
}

// exitRecorded is what the record of the answer of the echo services changed,
// for the log.
type exitRecorded struct {
	lost   bool   // no echo service answered, and the one before did, or none was asked before
	first  bool   // the first exit address that is known
	back   bool   // the exit address is known again after the echo services failed to give it
	change bool   // the exit address is another one
	prev   string // the exit address that was known before
	ip     string // the exit address that is known now
}

// record takes the result of the check of the datacenters into account.
//
// A member that was never checked becomes up with its first success: that is
// evidence that it works, which "unknown" lacks. After that the hysteresis is
// symmetric: fail_threshold failures in a row take a member down, and
// recover_threshold successes in a row bring it back up. A success interrupts the
// failures and a failure interrupts the successes.
func (m *member) record(res probeResult, c checkConfig, now time.Time) recorded {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := recorded{from: m.status}
	m.probed = true
	m.checked = now

	if res.ok {
		m.failStreak = 0
		m.okStreak++
		m.latency = res.latency
		switch m.status {
		case statusUnknown:
			m.status = statusUp
		case statusDown:
			if m.okStreak >= c.recoverThreshold {
				m.status = statusUp
			}
		}
	} else {
		m.okStreak = 0
		m.failStreak++
		if m.status != statusDown && m.failStreak >= c.failThreshold {
			m.status = statusDown
			m.latency = 0
		}
	}
	m.down.Store(m.status == statusDown)
	rec.to = m.status
	rec.failures = m.failStreak
	return rec
}

// recordExit takes the answer of the echo services into account. A failure to
// learn the exit address is not a failure of the member, and the address that
// was known is kept.
func (m *member) recordExit(ex exitResult) exitRecorded {
	m.mu.Lock()
	defer m.mu.Unlock()
	var rec exitRecorded
	if ex.ip == "" {
		if !m.exitFailing {
			m.exitFailing = true
			rec.lost = true
		}
	} else {
		prev := m.exitIP
		switch {
		case m.exitFailing:
			rec.back = true
		case prev == "":
			rec.first = true
		}
		m.exitFailing = false
		rec.change = prev != "" && prev != ex.ip
		rec.prev = prev
		m.exitIP = ex.ip
	}
	rec.ip = m.exitIP
	return rec
}

// latencyMs converts a latency to the milliseconds of a MemberHealth, rounded to
// the nearest. A connection that is quicker than a millisecond is reported as one,
// and not as none.
func latencyMs(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	ms := int64((d + 500*time.Microsecond) / time.Millisecond)
	return uint32(min(max(ms, 1), math.MaxUint32))
}

// ---------------------------------------------------------------------------
// The configuration of the router
// ---------------------------------------------------------------------------

type chain struct {
	id      string
	members []*member
}

// config is one configuration of the router, immutable once it is published.
type config struct {
	check   checkConfig
	chains  []*chain // in the order of the configuration
	byID    map[string]*chain
	members []*member // every member once, in the order of first appearance
	index   map[memberID]*member
}

func (c *config) chainsOf(m *member) []string {
	var ids []string
	for _, ch := range c.chains {
		for _, x := range ch.members {
			if x == m {
				ids = append(ids, ch.id)
				break
			}
		}
	}
	return ids
}

// clock is the time of the health checks. The timers and the time are the
// router's own; a test moves them by hand.
type clock interface {
	Now() time.Time
	NewTimer(d time.Duration) timer
}

type timer interface {
	C() <-chan time.Time
	Stop() bool
}

type realClock struct{}

func (realClock) Now() time.Time                 { return time.Now() }
func (realClock) NewTimer(d time.Duration) timer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (t realTimer) C() <-chan time.Time { return t.t.C }
func (t realTimer) Stop() bool          { return t.t.Stop() }

// deps are what a router takes from outside, for a test to replace.
type deps struct {
	clock     clock
	newDialer func(m *edgev1.ChainMember, timeout time.Duration) (Dialer, error)
	probe     probeFunc   // the check of the datacenters through a member
	exit      exitFunc    // the question of the exit address of a member
	echoTLS   *tls.Config // the TLS configuration of the requests to the echo services; nil is the default
}

// Router holds the egress chains of the node and the health of their members,
// and dials through them. It is safe for concurrent use.
type Router struct {
	log *slog.Logger
	d   deps

	mu   sync.Mutex // serializes Apply
	cur  atomic.Pointer[config]
	wake chan struct{} // tells the health loop that there are members to probe now
	// retime tells the health loop that the interval changed, so that the wait
	// under way follows it.
	retime chan struct{}
	// passive are the members whose connections end early, for a round of their
	// own (passive.go).
	passive chan *member

	// res is the resolver of the members, nil for the system's: the dialers that
	// the router makes read it at every dial.
	res atomic.Pointer[net.Resolver]

	// me are the addresses of the middle proxies (SetMEAddrs), nil for none.
	me atomic.Pointer[MEAddrs]

	healthRuns atomic.Bool // a call of RunHealth runs
}

// NewRouter returns a router without chains. Apply gives it some, and RunHealth
// checks their members.
func NewRouter(log *slog.Logger) *Router {
	return newRouter(log, deps{})
}

func newRouter(log *slog.Logger, d deps) *Router {
	if log == nil {
		log = slog.Default()
	}
	r := &Router{log: log, d: d, wake: make(chan struct{}, 1), retime: make(chan struct{}, 1), passive: make(chan *member, passiveQueue)}
	if r.d.clock == nil {
		r.d.clock = realClock{}
	}
	if r.d.newDialer == nil {
		r.d.newDialer = func(m *edgev1.ChainMember, timeout time.Duration) (Dialer, error) {
			return newMemberDialer(m, timeout, &r.res)
		}
	}
	if r.d.probe == nil {
		r.d.probe = r.probeMember
	}
	if r.d.exit == nil {
		r.d.exit = r.probeExit
	}
	check, _ := newCheckConfig(nil)
	r.cur.Store(&config{check: check, byID: map[string]*chain{}, index: map[memberID]*member{}})
	return r
}

// SetResolver makes the members of the router resolve the names they connect
// to with res: a direct member the targets of its dials, the datacenters and the
// echo services of the checks among them, and a proxy member the name of its
// proxy, and the name of its target under a destination policy (see
// NewMemberDialer). nil, which is what a new router has, is the resolver of the
// system. The edge gives it the resolver of its DNS forwarder
// (dns.Forwarder.Resolver), which asks the forwarder while it runs. The members
// that the router has take the change too, from their next dial on.
func (r *Router) SetResolver(res *net.Resolver) { r.res.Store(res) }

// Apply replaces the chains, and the parameters of the checks, with the ones
// given; hc may be nil, and every field that is zero or empty means its default
// (see DefaultHealthCheck). It checks them first, and when anything is wrong it
// returns an error and leaves the router as it was.
//
// A member that is the same as one of the previous configuration, the same key
// and the same kind, address, credentials, interface and source address, and a
// health check with the same timeout, keeps its dialer and what is known of its
// health. A member that is not is new and has not been checked: the process behind
// its address may have been replaced. Members that are new are probed without
// waiting for the next round of the checks.
//
// Connections that are open are not touched, and dials that are under way go on
// with the configuration that they began with.
func (r *Router) Apply(chains []*edgev1.Chain, hc *edgev1.HealthCheck) error {
	check, err := newCheckConfig(hc)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.cur.Load()
	next := &config{
		check: check,
		byID:  make(map[string]*chain, len(chains)),
		index: make(map[memberID]*member),
	}
	added := false
	for _, pc := range chains {
		id := pc.GetId()
		if id == "" {
			return errors.New("egress: a chain has an empty id")
		}
		if _, dup := next.byID[id]; dup {
			return fmt.Errorf("egress: duplicate chain id %q", id)
		}
		ch := &chain{id: id}
		seen := make(map[string]struct{}, len(pc.GetMembers()))
		for _, pm := range pc.GetMembers() {
			key := pm.GetKey()
			if key == "" {
				return fmt.Errorf("egress: chain %q has a member with an empty key", id)
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("egress: chain %q has a duplicate member key %q", id, key)
			}
			seen[key] = struct{}{}

			mid := memberID{key: key, spec: memberSpec{
				kind: pm.GetKind(), addr: pm.GetAddr(), username: pm.GetUsername(), password: pm.GetPassword(),
				bindDevice: pm.GetBindDevice(), bindIP: pm.GetBindIp(), timeout: check.timeout,
			}}
			m := next.index[mid]
			if m == nil {
				m = old.index[mid]
				if m == nil {
					dialer, err := r.d.newDialer(pm, check.timeout)
					if err != nil {
						return fmt.Errorf("egress: chain %q, member %q: %w", id, key, err)
					}
					m = &member{key: key, spec: mid.spec, dialer: dialer}
					added = true
				}
				next.index[mid] = m
				next.members = append(next.members, m)
			}
			ch.members = append(ch.members, m)
		}
		next.chains = append(next.chains, ch)
		next.byID[id] = ch
	}

	r.cur.Store(next)
	if check.interval != old.check.interval {
		select {
		case r.retime <- struct{}{}:
		default:
		}
	}
	if added {
		select {
		case r.wake <- struct{}{}:
		default:
		}
	}
	r.log.Debug("egress: chains applied", "chains", len(next.chains), "members", len(next.members))
	return nil
}

// Dial connects to addr, "host:port", through the chain chainID, and returns the
// connection with the key of the member that made it.
//
// The members are tried in the order of the chain. A member that is down is
// skipped, one that is not known yet is tried. Each is given the timeout of the
// health check for its dial, the handshake with its proxy included, and the dial
// as a whole has twice that: a member is given what is left of it when that is
// less, and the members after the one that used it up are not tried
// (DialError.Untried). An engine waits for that long at most, whatever the
// chain is like.
//
// When a member fails, the next is tried. A failure that comes with an answer of
// the proxy, a failure reply of a SOCKS5 proxy or an HTTP status of an HTTP proxy,
// is one of the target and the member is not to blame for it (MemberError.Answered);
// the next member is tried all the same, since it comes out somewhere else. A dial
// that fails is not held against a member: only the checks of the datacenters take
// a member down, for a target that is not there fails dials through a member that
// is perfectly well. The connection of a proxy member is watched for early ends,
// which ask for a check of the member at once (see passive.go); the check decides.
//
// A destination that the policy of the dial does not allow (see
// withDestinationPolicy) ends the dial with an error that wraps
// ErrDestinationNotAllowed, and no further member is tried: it would be asked for
// the same destination. When the caller's ctx is done, Dial stops at once and
// returns its error, and no further member is tried either.
//
// If every member is down the error is ErrNoUsableMember, and if the members that
// were tried all failed it is a *DialError. A chain that is not known is
// ErrUnknownChain, and one without members ErrNoMembers.
func (r *Router) Dial(ctx context.Context, chainID, addr string) (net.Conn, string, error) {
	cfg := r.cur.Load()
	ch := cfg.byID[chainID]
	if ch == nil {
		return nil, "", fmt.Errorf("%w: %q", ErrUnknownChain, chainID)
	}
	if len(ch.members) == 0 {
		return nil, "", fmt.Errorf("%w: %q", ErrNoMembers, chainID)
	}
	timeout := cfg.check.timeout
	budget, cancel := context.WithTimeout(ctx, 2*timeout)
	defer cancel()
	// The time is up at the deadline itself, also when the timer of budget has
	// not yet done its work: a member whose own timeout ends with it returns at
	// that very moment, and the next one must not be dialed with no time left.
	end, _ := budget.Deadline()
	var attempts []*MemberError
	skipped, untried := 0, 0
	for _, m := range ch.members {
		if m.isDown() {
			skipped++
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, "", fmt.Errorf("egress: chain %q: %w", chainID, err)
		}
		if !time.Now().Before(end) {
			untried++
			continue
		}
		conn, err := dialMember(budget, timeout, m, addr)
		if err == nil {
			return r.watch(m, conn), m.key, nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return nil, "", fmt.Errorf("egress: chain %q: %w", chainID, cerr)
		}
		if errors.Is(err, ErrDestinationNotAllowed) {
			return nil, "", fmt.Errorf("egress: chain %q, member %s: %w", chainID, m.key, err)
		}
		r.log.Debug("egress: member dial failed", "chain", chainID, "member", m.key, "target", addr,
			"answered", answered(err), "err", err)
		attempts = append(attempts, &MemberError{Key: m.key, Kind: m.spec.kind, Err: err, Answered: answered(err)})
	}
	if len(attempts) == 0 {
		return nil, "", fmt.Errorf("%w: %q (%d down)", ErrNoUsableMember, chainID, skipped)
	}
	return nil, "", &DialError{ChainID: chainID, Attempts: attempts, Skipped: skipped, Untried: untried}
}

// dialMember makes one dial through m. It does not trust the dialer to keep to
// its contract: a connection that comes with an error is closed, and neither a
// connection nor an error is an error.
func dialMember(ctx context.Context, timeout time.Duration, m *member, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := m.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("egress: the dialer returned neither a connection nor an error")
	}
	return conn, nil
}

// ---------------------------------------------------------------------------
// The scope of the middle proxies
// ---------------------------------------------------------------------------

// ScopeME is the scope of the connections of an engine to Telegram's middle
// proxies.
const ScopeME = "me"

// MaxMEAddrs is the most middle-proxy addresses a configuration may have. Telegram
// lists a few dozen.
const MaxMEAddrs = 4096

// MEAddrs are the addresses of Telegram's middle proxies (EdgeConfig.me_addrs):
// IP addresses and ports. A middle proxy may share its IP address with a
// datacenter on another port (getProxyConfig lists some on the datacenters' own
// addresses, at port 8888), so an address alone is not enough. A set is not
// changed once it is made; nil is the empty set.
type MEAddrs struct {
	set map[netip.AddrPort]struct{}
}

// ParseMEAddrs reads the middle-proxy addresses of a configuration: "ip:port"
// (an IPv6 address in brackets), without a zone, a port from 1 to 65535, at
// most MaxMEAddrs of them; an IPv4-mapped IPv6 address is the IPv4 address.
// Anything else is an error that names the entry (an address of a middle
// proxy is no secret).
func ParseMEAddrs(list []string) (*MEAddrs, error) {
	if len(list) > MaxMEAddrs {
		return nil, fmt.Errorf("egress: too many middle-proxy addresses: %d, at most %d", len(list), MaxMEAddrs)
	}
	me := &MEAddrs{set: make(map[netip.AddrPort]struct{}, len(list))}
	for _, s := range list {
		ap, err := netip.ParseAddrPort(s)
		if err != nil || ap.Addr().Zone() != "" || ap.Port() == 0 {
			return nil, fmt.Errorf("egress: middle-proxy address %.64q is not an IP address and a port", s)
		}
		me.set[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())] = struct{}{}
	}
	return me, nil
}

// Len is the number of addresses.
func (m *MEAddrs) Len() int {
	if m == nil {
		return 0
	}
	return len(m.set)
}

// Contains reports whether ip (or the IPv4 address it maps) and port are the
// address of a middle proxy.
func (m *MEAddrs) Contains(ip netip.Addr, port uint16) bool {
	if m == nil {
		return false
	}
	_, ok := m.set[netip.AddrPortFrom(ip.WithZone("").Unmap(), port)]
	return ok
}

// SetMEAddrs makes me the addresses of the middle proxies (see ScopeOf); nil is
// none. The connections that follow take it.
func (r *Router) SetMEAddrs(me *MEAddrs) { r.me.Store(me) }

// ScopeOf returns the scope of a CONNECT of an engine to host, an IP address or
// a name, and port, for which the engine gave scope, its user name: that scope
// when it gave one, ScopeME when it gave none and host and port are the
// address of a middle proxy (SetMEAddrs), and "" otherwise. telemt gives its
// connections to the middle proxies no scope (finding F3), so the edge tells
// them by their address; a name is never resolved for it, and a datacenter on
// the address of a middle proxy, at another port, is not one.
func (r *Router) ScopeOf(scope, host string, port uint16) string {
	if scope != "" {
		return scope
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !r.me.Load().Contains(ip, port) {
		return ""
	}
	return ScopeME
}

// Health returns the health of every member of every chain, in the order of the
// configuration: a message for each pair of a chain and a member, so that a member
// that is in two chains is in the report twice, with the same state. The messages
// are the caller's.
func (r *Router) Health() []*edgev1.MemberHealth {
	cfg := r.cur.Load()
	var out []*edgev1.MemberHealth
	for _, ch := range cfg.chains {
		for _, m := range ch.members {
			out = append(out, m.report(ch.id))
		}
	}
	return out
}
