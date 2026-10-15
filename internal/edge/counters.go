package edge

import (
	"maps"
	"math"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

const (
	// minIPRetention is the least time the counters of an IP are kept after its
	// last connection ended; they are kept for the device idle window at least.
	// The agent takes a snapshot every 10 s, so it sees the final counters of
	// every IP many times over before they go.
	minIPRetention = 5 * time.Minute

	// pruneInterval is how often admit looks for IPs to forget, at most. Snapshot
	// does it every time.
	pruneInterval = 30 * time.Second

	// maxIPsPerProxy is the most client IPs a proxy keeps the state of, not
	// counting the ones it may not forget (see makeRoomLocked). It bounds the
	// memory of a proxy, the size of its part of a snapshot (some 60 bytes an
	// IP) and the work that admit and Snapshot do over the IPs.
	maxIPsPerProxy = 4096
	// ipEvictBatch is how many IPs go at once when the proxy is full, so that
	// the search for them is not made for every new IP.
	ipEvictBatch = maxIPsPerProxy / 8
)

// statsRegistry holds the counters and the limit state of every proxy the edge
// has had a route for, by proxy id. It belongs to the Edge and not to a table,
// so it outlives Apply: the counters of a proxy only ever grow while the edge
// runs, which is what the agent computes its deltas from.
type statsRegistry struct {
	mu      sync.Mutex
	proxies map[string]*proxyStats
}

func newStatsRegistry() *statsRegistry {
	return &statsRegistry{proxies: make(map[string]*proxyStats)}
}

// proxy returns the state of the proxy with the given id, created on first use.
func (r *statsRegistry) proxy(id string) *proxyStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.proxies[id]
	if !ok {
		p = &proxyStats{id: id, ips: make(map[netip.Addr]*ipStats), backends: make(map[string]int)}
		r.proxies[id] = p
	}
	return p
}

// all returns every proxy, ordered by id.
func (r *statsRegistry) all() []*proxyStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := slices.Sorted(maps.Keys(r.proxies))
	out := make([]*proxyStats, len(ids))
	for i, id := range ids {
		out[i] = r.proxies[id]
	}
	return out
}

// proxyStats is the state of one proxy: its traffic counters, and its
// connections and client IPs, against which its limits are checked.
type proxyStats struct {
	id string

	bytesUp    atomic.Uint64 // client to backend, the replayed ClientHello included
	bytesDown  atomic.Uint64 // backend to client
	connsTotal atomic.Uint64 // connections admitted since the edge started

	mu        sync.Mutex
	active    int                     // connections admitted and not yet ended, the exempt ones aside
	exempt    int                     // connections of the panel's probes open (admitExempt); not in active
	ips       map[netip.Addr]*ipStats // client IPs, see pruneLocked and makeRoomLocked for how long
	backends  map[string]int          // active connections by backend address; no zero entries
	nextPrune time.Time               // when admit looks for IPs to forget next
	// evictable is false after makeRoomLocked found no IP that may go, until a
	// connection ends, so that a proxy full of IPs that must stay is not
	// searched again for every new IP.
	evictable bool
}

// ipStats is the state of one client IP of a proxy.
type ipStats struct {
	bytes atomic.Uint64 // both directions

	// Guarded by the mutex of the proxyStats.
	active   int       // connections open
	lastSeen time.Time // when a connection of the IP was last admitted or ended
}

// pruneLocked forgets the IPs that have had no connection for the retention
// time: the device idle window, but at least minIPRetention. An IP that comes
// back later starts from zero. p.mu must be held.
func (p *proxyStats) pruneLocked(now time.Time, window time.Duration) {
	keep := max(window, minIPRetention)
	for ip, st := range p.ips {
		if st.active == 0 && now.Sub(st.lastSeen) >= keep {
			delete(p.ips, ip)
		}
	}
}

// makeRoomLocked makes room for one more IP when the proxy holds
// maxIPsPerProxy of them: it forgets the IPs past retention, and then, if that
// was not enough, the ipEvictBatch IPs idle the longest among those that may
// go. An IP may not go while it has a connection open, nor, when deviceLimit
// is set, while it is a device: forgetting it would let a new device in over
// the limit. When no IP may go, nothing goes and the proxy holds more than
// maxIPsPerProxy: those IPs are bounded by the open connections and the device
// limit. p.mu must be held.
func (p *proxyStats) makeRoomLocked(now time.Time, window time.Duration, deviceLimit bool) {
	if len(p.ips) < maxIPsPerProxy || !p.evictable && len(p.ips) > maxIPsPerProxy {
		return
	}
	p.pruneLocked(now, window)
	if len(p.ips) < maxIPsPerProxy {
		return
	}
	type idleIP struct {
		ip   netip.Addr
		seen time.Time
	}
	var idle []idleIP
	for ip, st := range p.ips {
		if st.active > 0 || deviceLimit && st.isDevice(now, window) {
			continue
		}
		idle = append(idle, idleIP{ip, st.lastSeen})
	}
	p.evictable = len(idle) > 0
	slices.SortFunc(idle, func(a, b idleIP) int { return a.seen.Compare(b.seen) })
	for _, c := range idle[:min(len(idle), ipEvictBatch)] {
		delete(p.ips, c.ip)
	}
}

// snapshot returns the counters of the proxy at now, and, when withIPs is set,
// those of its IPs in the order of their addresses.
//
// The last_seen of an IP with a connection open is now: it is being seen. For
// an IP without one it is when its last connection ended.
func (p *proxyStats) snapshot(now time.Time, window time.Duration, withIPs bool) (*edgev1.ProxyCounters, []*edgev1.IpCounters) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked(now, window)

	pc := &edgev1.ProxyCounters{
		ProxyId:       p.id,
		BytesUp:       p.bytesUp.Load(),
		BytesDown:     p.bytesDown.Load(),
		ConnsTotal:    p.connsTotal.Load(),
		ConnsActive:   clamp32(p.active),
		DevicesActive: clamp32(p.devicesLocked(now, window)),
	}
	if len(p.backends) > 0 {
		pc.BackendActive = make(map[string]uint32, len(p.backends))
		for b, n := range p.backends {
			pc.BackendActive[b] = clamp32(n)
		}
	}
	if !withIPs {
		return pc, nil
	}

	addrs := slices.SortedFunc(maps.Keys(p.ips), netip.Addr.Compare)
	ips := make([]*edgev1.IpCounters, 0, len(addrs))
	for _, a := range addrs {
		st := p.ips[a]
		seen := st.lastSeen
		if st.active > 0 {
			seen = now
		}
		ips = append(ips, &edgev1.IpCounters{
			ProxyId:      p.id,
			Ip:           a.String(),
			ConnsActive:  clamp32(st.active),
			LastSeenUnix: seen.Unix(),
			Bytes:        st.bytes.Load(),
		})
	}
	return pc, ips
}

// clamp32 converts a count to the uint32 of the protocol, saturating.
func clamp32(n int) uint32 {
	switch {
	case n <= 0:
		return 0
	case uint64(n) > math.MaxUint32:
		return math.MaxUint32
	}
	return uint32(n)
}
