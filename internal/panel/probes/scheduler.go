package probes

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

const (
	// maxConcurrent is the most probes that run at a time.
	maxConcurrent = 8
	// jitterDivisor makes the jitter of a round ±1/5 (20 %) of the interval.
	jitterDivisor = 5
	// tickEvery is how often the scheduler reads the settings and the proxies
	// and starts the probes that are due.
	tickEvery = 5 * time.Second
	// readTimeout bounds the reads of a round.
	readTimeout = 10 * time.Second
	// writeTimeout bounds the writes of a result.
	writeTimeout = 10 * time.Second
	// downIntervals is how many intervals old the newer of the two failed
	// probes of a proxy that is down may be.
	downIntervals = 3
	// failedStreak is the failure in a row that makes event probe.failed.
	failedStreak = 2
)

// ErrNotProbeable is the error of Probe for a proxy that the panel does not
// probe: one without a link host or listener, or whose domain is the
// management name of its node. The text after it says which.
var ErrNotProbeable = errors.New("the proxy cannot be probed from the panel")

// An Option changes how NewScheduler makes the scheduler.
type Option func(*Scheduler)

// WithProbe replaces the probe (RealProbe by default).
func WithProbe(f ProbeFunc) Option { return func(s *Scheduler) { s.probe = f } }

// WithWebProbe replaces the probe of the WEB proxies (RealWebProbe by
// default).
func WithWebProbe(f ProbeFunc) Option { return func(s *Scheduler) { s.webProbe = f } }

// withWebTransport replaces the transport of CheckBasePath (tests).
func withWebTransport(tr webTransport) Option { return func(s *Scheduler) { s.webTr = tr } }

// WithNow replaces the clock (time.Now by default).
func WithNow(now func() time.Time) Option { return func(s *Scheduler) { s.now = now } }

// WithRand replaces the random source of the jitter.
func WithRand(r *rand.Rand) Option { return func(s *Scheduler) { s.rnd = r } }

// Scheduler probes every enabled proxy of an online node, a fake-TLS one
// through its link host (kind l2) and a WEB one at its URL (kind web), every probes.interval_minutes (read at every round; 0 is off).
// A proxy's rounds are at its own offset in the interval, FNV-32a of its id,
// each moved by a random ±20 % of the interval, so that the probes of a fleet
// spread over the interval and do not line up. At most 8 probes run at a time.
type Scheduler struct {
	db       *store.DB
	key      seal.Key
	log      *slog.Logger
	probe    ProbeFunc
	webProbe ProbeFunc
	webTr    webTransport
	now      func() time.Time
	tick     time.Duration
	sem      chan struct{}

	mu       sync.Mutex
	rnd      *rand.Rand
	interval time.Duration       // as the last round read it
	plans    map[string]*plan    // the next round of every proxy that is probed, by id
	inflight map[string]bool     // the proxies whose scheduled probe runs
	last     map[string][]result // the newest two panel probes of a proxy, newest first
	fails    map[string]int      // the failures in a row of a proxy
	onResult []func(store.Probe)

	wg sync.WaitGroup
}

// plan is the next round of a proxy: the round's number (its start is
// slot × interval + offset after the Unix epoch) and when it is due, jitter
// included.
type plan struct {
	slot int64
	due  time.Time
}

type result struct {
	ts time.Time
	ok bool
}

// candidate is a proxy that the scheduler can probe.
type candidate struct {
	proxy *store.Proxy
	addr  string
}

// NewScheduler returns a scheduler on the database; key opens the proxy
// secrets. A nil log discards the log.
func NewScheduler(db *store.DB, key seal.Key, log *slog.Logger, opts ...Option) *Scheduler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Scheduler{
		db: db, key: key, log: log,
		probe:    RealProbe(),
		webProbe: RealWebProbe(),
		webTr:    systemTransport,
		now:      time.Now,
		tick:     tickEvery,
		sem:      make(chan struct{}, maxConcurrent),
		rnd:      rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())), //nolint:gosec // the jitter of a schedule, no secret
		plans:    map[string]*plan{},
		inflight: map[string]bool{},
		last:     map[string][]result{},
		fails:    map[string]int{},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// OnResult adds a function that is called with every result, after it is
// stored. It must not block.
func (s *Scheduler) OnResult(fn func(p store.Probe)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onResult = append(s.onResult, fn)
}

// Start loads the newest panel probes of every proxy (for Down and the
// streaks) and the interval, and then runs the schedule until ctx is done.
// Wait waits for it to stop.
func (s *Scheduler) Start(ctx context.Context) {
	s.load(ctx)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(s.tick)
		defer t.Stop()
		for {
			s.round(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// Wait waits for the schedule and its probes to stop, after the context of
// Start is done.
func (s *Scheduler) Wait() { s.wg.Wait() }

// load reads what Down and the streaks start from.
func (s *Scheduler) load(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	if set, _, err := s.db.StatsSettings(ctx); err != nil {
		s.log.Warn("probes: could not read the settings", "err", err)
	} else {
		s.mu.Lock()
		s.interval = time.Duration(set.ProbeIntervalMinutes) * time.Minute
		s.mu.Unlock()
	}
	last, err := s.db.LastProbes(ctx, VantagePanel, 2)
	if err != nil {
		s.log.Warn("probes: could not read the last probes", "err", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ps := range last {
		rs := make([]result, 0, len(ps))
		fails := 0
		for i, p := range ps {
			rs = append(rs, result{ts: p.TS, ok: p.OK})
			if !p.OK && fails == i {
				fails++
			}
		}
		s.last[id], s.fails[id] = rs, fails
	}
}

// round reads the interval and the proxies, and starts the probes that are
// due. An interval that changed makes a new plan for every proxy: the next
// round follows the new interval.
func (s *Scheduler) round(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	set, _, err := s.db.StatsSettings(rctx)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("probes: could not read the settings", "err", err)
		}
		return
	}
	interval := time.Duration(set.ProbeIntervalMinutes) * time.Minute
	s.mu.Lock()
	if interval != s.interval {
		s.interval, s.plans = interval, map[string]*plan{}
	}
	s.mu.Unlock()
	if interval <= 0 {
		return
	}
	cands, err := s.candidates(rctx)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("probes: could not read the proxies", "err", err)
		}
		return
	}

	now := s.now()
	var due []candidate
	s.mu.Lock()
	seen := make(map[string]bool, len(cands))
	for _, c := range cands {
		id := c.proxy.ID
		seen[id] = true
		p := s.plans[id]
		if p == nil {
			p = &plan{slot: slotAfter(now, offset(id, interval), interval)}
			p.due = s.dueOf(id, p.slot, interval)
			s.plans[id] = p
		}
		if now.Before(p.due) || s.inflight[id] {
			continue
		}
		s.inflight[id] = true
		due = append(due, c)
		// The next round; one that is over already, after a long stop, is
		// left out.
		next := p.slot + 1
		if slotStart(next, offset(id, interval), interval).Add(interval / jitterDivisor).Before(now) {
			next = slotAfter(now, offset(id, interval), interval)
		}
		p.slot, p.due = next, s.dueOf(id, next, interval)
	}
	for id := range s.plans {
		if !seen[id] {
			delete(s.plans, id)
		}
	}
	s.mu.Unlock()

	for _, c := range due {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.inflight, c.proxy.ID)
				s.mu.Unlock()
			}()
			if _, _, err := s.run(ctx, c); err != nil && ctx.Err() == nil {
				s.log.Warn("probes: a proxy could not be probed", "proxy", c.proxy.ID, "err", err)
			}
		}()
	}
}

// offset is where in the interval the rounds of a proxy start: FNV-32a of its
// id modulo the interval, in whole seconds.
func offset(proxyID string, interval time.Duration) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(proxyID))
	secs := uint32(interval / time.Second)
	if secs == 0 {
		return 0
	}
	return time.Duration(h.Sum32()%secs) * time.Second
}

// slotStart is when round slot starts, before its jitter.
func slotStart(slot int64, off, interval time.Duration) time.Time {
	return time.Unix(0, 0).Add(time.Duration(slot)*interval + off)
}

// slotAfter is the first round that starts after now.
func slotAfter(now time.Time, off, interval time.Duration) int64 {
	d := now.Sub(time.Unix(0, 0)) - off
	k := int64(d / interval)
	if d < 0 && d%interval != 0 {
		k-- // floor
	}
	return k + 1
}

// dueOf is when round slot of a proxy is due: its start moved by a random
// ±20 % of the interval. The caller holds mu.
func (s *Scheduler) dueOf(proxyID string, slot int64, interval time.Duration) time.Time {
	j := int64(interval / jitterDivisor)
	jitter := time.Duration(s.rnd.Int64N(2*j+1) - j)
	return slotStart(slot, offset(proxyID, interval), interval).Add(jitter)
}

// candidates are the proxies that are probed: enabled proxies of online
// nodes, fake-TLS ones with a link host.
func (s *Scheduler) candidates(ctx context.Context) ([]candidate, error) {
	nodes, err := s.db.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	byNode := make(map[string]*store.Node, len(nodes))
	for _, n := range nodes {
		if n.Status == store.NodeStatusOnline {
			byNode[n.ID] = n
		}
	}
	listeners, err := s.db.ListListeners(ctx, "")
	if err != nil {
		return nil, err
	}
	byListener := make(map[string]*store.Listener, len(listeners))
	for _, l := range listeners {
		byListener[l.ID] = l
	}
	ps, err := s.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return nil, err
	}
	var out []candidate
	for _, p := range ps {
		n := byNode[p.NodeID]
		if !p.Enabled || n == nil {
			continue
		}
		if addr, err := addrOf(p, n, byListener[p.ListenerID]); err == nil {
			out = append(out, candidate{proxy: p, addr: addr})
		}
	}
	return out, nil
}

// addrOf is the address the panel probes a proxy at: its link host and its
// listener's port; for a WEB proxy, its URL (webURL), whatever the link host.
// One without a listener, a fake-TLS one without a link host, and one whose
// domain is the management SNI of its node, which a probe must never send,
// are ErrNotProbeable.
func addrOf(p *store.Proxy, n *store.Node, l *store.Listener) (string, error) {
	switch {
	case l == nil:
		return "", fmt.Errorf("%w: its listener is gone", ErrNotProbeable)
	case n.MgmtSNI != "" && strings.EqualFold(strings.TrimSuffix(p.Domain, "."), strings.TrimSuffix(n.MgmtSNI, ".")):
		return "", fmt.Errorf("%w: its domain is the management name of its node", ErrNotProbeable)
	case p.Type == store.ProxyTypeWeb:
		return webURL(p, l)
	}
	host := cmp.Or(l.LinkHostOverride, n.LinkHost)
	if host == "" {
		return "", fmt.Errorf("%w: no link host", ErrNotProbeable)
	}
	return net.JoinHostPort(host, strconv.FormatUint(uint64(l.Port), 10)), nil
}

// Probe probes a proxy now, whatever the schedule says, stores the result and
// returns it with whether L1 passed. A proxy that does not exist is
// store.ErrNotFound; one that the panel does not probe (paused, on a node that
// is not online, without a link host) is ErrNotProbeable, and nothing is
// probed or stored. It
// has no rate limit and writes no audit entry: its callers do.
func (s *Scheduler) Probe(ctx context.Context, proxyID string) (store.Probe, bool, error) {
	p, err := s.db.ProxyByID(ctx, proxyID)
	if err != nil {
		return store.Probe{}, false, err
	}
	n, err := s.db.NodeByID(ctx, p.NodeID)
	if err != nil {
		return store.Probe{}, false, err
	}
	l, err := s.db.ListenerByID(ctx, p.ListenerID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.Probe{}, false, err
	}
	switch {
	case !p.Enabled:
		return store.Probe{}, false, fmt.Errorf("%w: it is paused", ErrNotProbeable)
	case n.Status != store.NodeStatusOnline:
		return store.Probe{}, false, fmt.Errorf("%w: its node is not online", ErrNotProbeable)
	}
	addr, err := addrOf(p, n, l)
	if err != nil {
		return store.Probe{}, false, err
	}
	return s.run(ctx, candidate{proxy: p, addr: addr})
}

// run probes a candidate, at most maxConcurrent at a time, and records the
// result. A probe that ctx stopped is not recorded.
func (s *Scheduler) run(ctx context.Context, c candidate) (store.Probe, bool, error) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return store.Probe{}, false, ctx.Err()
	}
	defer func() { <-s.sem }()

	t := Target{ProxyID: c.proxy.ID, Type: c.proxy.Type, Addr: c.addr, SNI: c.proxy.Domain}
	probe, kind := s.probe, KindL2
	if c.proxy.Type == store.ProxyTypeWeb {
		probe, kind = s.webProbe, KindWeb // no secret: the probe is at the HTTP level
	} else {
		secret, err := s.openSecret(c.proxy)
		if err != nil {
			return store.Probe{}, false, err
		}
		defer clear(secret)
		t.Secret = secret
	}
	ts := s.now()
	p, l1 := probe(ctx, t)
	if err := ctx.Err(); err != nil {
		return store.Probe{}, false, err
	}
	p.ProxyID, p.TS, p.Vantage, p.Kind = c.proxy.ID, ts, VantagePanel, kind
	if p.OK {
		p.Error = ""
	}
	s.record(context.WithoutCancel(ctx), c.proxy.NodeID, p)
	return p, l1, nil
}

// openSecret opens the sealed secret of a proxy into its 16 bytes.
func (s *Scheduler) openSecret(p *store.Proxy) ([]byte, error) {
	plain, err := proxies.OpenSecret(s.key, p)
	if err != nil {
		return nil, fmt.Errorf("the secret of proxy %s does not open: %w", p.ID, err)
	}
	secret, err := hex.DecodeString(plain)
	if err != nil {
		return nil, fmt.Errorf("the secret of proxy %s is not hex", p.ID)
	}
	return secret, nil
}

// record stores a result, notes it for Down and the streak, writes the events
// of the streak and calls the OnResult functions.
func (s *Scheduler) record(ctx context.Context, nodeID string, p store.Probe) {
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	if err := s.db.InsertProbe(ctx, p); err != nil {
		s.log.Warn("probes: could not store a probe", "proxy", p.ProxyID, "err", err)
	}

	s.mu.Lock()
	rs := append([]result{{ts: p.TS, ok: p.OK}}, s.last[p.ProxyID]...)
	s.last[p.ProxyID] = rs[:min(len(rs), 2)]
	var ev *store.Event
	if p.OK {
		if s.fails[p.ProxyID] >= failedStreak {
			ev = &store.Event{Kind: "probe.recovered", Severity: "info", Message: "the panel's probes of the proxy pass again"}
		}
		s.fails[p.ProxyID] = 0
	} else {
		s.fails[p.ProxyID]++
		if s.fails[p.ProxyID] == failedStreak {
			ev = &store.Event{Kind: "probe.failed", Severity: "warn", Message: "the panel's probes of the proxy fail: " + p.Error,
				Details: map[string]string{"error": p.Error}}
		}
	}
	fns := slices.Clone(s.onResult)
	s.mu.Unlock()

	if ev != nil {
		ev.TS, ev.NodeID, ev.ProxyID = p.TS, nodeID, p.ProxyID
		if err := s.db.AppendEvent(ctx, ev); err != nil {
			s.log.Warn("probes: could not store an event", "kind", ev.Kind, "proxy", p.ProxyID, "err", err)
		}
		level := slog.LevelWarn
		if p.OK {
			level = slog.LevelInfo
		}
		s.log.Log(ctx, level, ev.Message, "proxy", p.ProxyID)
	}
	for _, fn := range fns {
		fn(p)
	}
}
