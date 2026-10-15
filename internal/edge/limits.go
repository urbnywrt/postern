package edge

import (
	"net/netip"
	"time"
)

// limits are the limits of a route, as edgev1.EdgeLimits has them; 0 is no
// limit.
//
// The limits are the proxy's, not the route's: the state they are checked
// against is kept by proxy id (see proxyStats), so that two routes of one proxy,
// on two listeners say, share one allowance.
type limits struct {
	devices    int // distinct client IPs, see proxyStats.isDevice
	connsTotal int // connections of the proxy at a time
	connsPerIP int // connections of one IP to the proxy at a time
}

// The reasons admit gives for a refusal, for the log.
const (
	overConnsTotal = "conns_total"
	overConnsPerIP = "conns_per_ip"
	overDevices    = "devices"
)

// The bounds of the panel's probes (EdgeConfig.probe_sources, Ruling R6-1).
const (
	// maxExemptPerProxy is the most connections from the panel's probe
	// sources that a proxy holds exempt from its limits at a time; one more
	// is an ordinary client.
	maxExemptPerProxy = 4
	// exemptLifetime is how long an exempt connection lasts from its accept:
	// a probe takes a few seconds, and an address of the panel that someone
	// else shares (a NAT) gets no lasting unlimited session out of it.
	exemptLifetime = 30 * time.Second
)

// lease is a connection admitted for a proxy. It holds the place of the
// connection in the limits until release, and is where the bytes of the
// connection are counted.
type lease struct {
	p       *proxyStats
	ip      *ipStats // nil for an exempt connection: it has no IP state
	backend string   // "" for a web connection: see busy
}

// admitExempt lets in a connection from one of the panel's probe sources,
// relayed to backend ("" for a web route, as for admit), outside the limits:
// it takes no device slot and holds no place in conns_total or conns_per_ip,
// and its IP gets no state, so no counters; it counts in conns_total and its
// bytes in the totals of the proxy, and in backend_active. It returns nil when
// the proxy has maxExemptPerProxy exempt connections open already: the
// connection is then an ordinary client.
func (p *proxyStats) admitExempt(backend string) *lease {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exempt >= maxExemptPerProxy {
		return nil
	}
	p.exempt++
	if backend != "" {
		p.backends[backend]++
	}
	p.connsTotal.Add(1)
	return &lease{p: p, backend: backend}
}

// admit lets a connection from ip, relayed to backend, in under lim, or tells
// which limit it is over. now is the time of the edge's clock; window is the
// device idle window of the configuration in effect. The connection counts in
// backend_active for backend, but for a backend of ""; that of a web route
// is given "", since its requests are what keeps a backend busy (see busy).
//
// A connection is over the device limit only when it comes from an IP that is
// not a device already: a device may open as many connections as the other
// limits allow.
func (p *proxyStats) admit(ip netip.Addr, backend string, lim limits, now time.Time, window time.Duration) (*lease, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !now.Before(p.nextPrune) {
		p.pruneLocked(now, window)
		p.nextPrune = now.Add(pruneInterval)
	}
	st := p.ips[ip]
	switch {
	case lim.connsTotal > 0 && p.active >= lim.connsTotal:
		return nil, overConnsTotal
	case lim.connsPerIP > 0 && st != nil && st.active >= lim.connsPerIP:
		return nil, overConnsPerIP
	case lim.devices > 0 && !st.isDevice(now, window) && p.devicesLocked(now, window) >= lim.devices:
		return nil, overDevices
	}
	if st == nil {
		p.makeRoomLocked(now, window, lim.devices > 0)
		st = &ipStats{}
		p.ips[ip] = st
	}
	st.active++
	st.lastSeen = now
	p.active++
	if backend != "" {
		p.backends[backend]++
	}
	p.connsTotal.Add(1)
	return &lease{p: p, ip: st, backend: backend}, ""
}

// release gives the place of the connection back. now is the time it ended:
// its IP stays a device for the idle window from then on.
func (l *lease) release(now time.Time) {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if l.ip == nil {
		p.exempt--
	} else {
		l.ip.active--
		l.ip.lastSeen = now
		p.evictable = true // the IP may be one that can go now
		p.active--
	}
	if l.backend != "" {
		p.leaveLocked(l.backend)
	}
}

// busy counts a request of a web connection in backend_active for backend, and
// returns the function that ends it. The requests of a web connection go to
// whichever backend the route of its proxy has as each of them comes, so they,
// not the connection, are what keeps a backend busy: the agent sees a
// generation of an engine idle once its last request has ended.
func (p *proxyStats) busy(backend string) (done func()) {
	p.mu.Lock()
	p.backends[backend]++
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.leaveLocked(backend)
	}
}

// leaveLocked counts one connection or request fewer for backend. p.mu must be
// held.
func (p *proxyStats) leaveLocked(backend string) {
	if p.backends[backend]--; p.backends[backend] <= 0 {
		delete(p.backends, backend)
	}
}

// addUp counts n bytes from the client to the backend.
func (l *lease) addUp(n int) {
	l.p.bytesUp.Add(uint64(n))
	if l.ip != nil {
		l.ip.bytes.Add(uint64(n))
	}
}

// addDown counts n bytes from the backend to the client.
func (l *lease) addDown(n int) {
	l.p.bytesDown.Add(uint64(n))
	if l.ip != nil {
		l.ip.bytes.Add(uint64(n))
	}
}

// isDevice reports whether the IP of st is a device at now: it has a
// connection open, or had one that ended less than window ago. st may be nil,
// for an IP never seen or forgotten.
func (st *ipStats) isDevice(now time.Time, window time.Duration) bool {
	return st != nil && (st.active > 0 || now.Sub(st.lastSeen) < window)
}

// devicesLocked counts the devices of the proxy at now. p.mu must be held.
func (p *proxyStats) devicesLocked(now time.Time, window time.Duration) int {
	n := 0
	for _, st := range p.ips {
		if st.isDevice(now, window) {
			n++
		}
	}
	return n
}
