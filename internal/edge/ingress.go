package edge

import (
	"io"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// The caps on the connections of the public listeners.
//
// A client that sends its ClientHello a byte every few seconds holds its
// connection for the whole ClientHelloTimeout, and many of them, from many
// addresses, would take the descriptors, the goroutines and the memory of the
// process that carries every proxy of the node. So the connections that have
// not finished their hello are capped, in the whole edge and per source, and
// so are all the connections of the public listeners together.
//
// A connection over the cap of its source, or over the total cap, is closed as
// soon as it is accepted, before anything is read from it or written to it,
// and is counted. When the cap of the whole edge on connections before their
// hello is full, the oldest of them is closed instead and the newcomer takes
// its place: a flood of silent clients cannot keep a real one out. While more
// than half of that cap is taken, a new connection has a shorter time for its
// hello.
//
// The node's own probes, which come from the loopback interface to the test
// listeners, are not held to the caps. The SOCKS ports of the engines and the
// control socket are not listeners of the edge at all, and know nothing of them.
const (
	// The connections between their accept and the end of their hello may be
	// preHelloPercent of the soft limit of open files at most, no more than
	// maxPreHelloCap, and no more than preHelloOfConnsPercent of the total cap:
	// min(4096, 25 % of RLIMIT_NOFILE, 50 % of the total cap). The last term
	// keeps them below the total cap, so that a flood of them fills their own
	// cap, and has its oldest evicted, before the total cap refuses anybody;
	// the other half is for the connections past their hello.
	preHelloPercent        = 25
	maxPreHelloCap         = 4096
	preHelloOfConnsPercent = 50
	// perSourcePreHello is the most of them from one source: an IPv4 address,
	// or an IPv6 /64 (sourceV6Bits), which one client often has whole.
	perSourcePreHello = 16
	sourceV6Bits      = 64
	// All the connections of the public listeners may be connsFilesPercent of
	// the soft limit of open files, and as many as connsMemoryPercent of the
	// memory limit holds at connMemory each, at most; each bound is
	// minConnsCap at least: min(max(1024, 20 % of RLIMIT_NOFILE), max(1024,
	// 50 % of the memory limit / 100 KiB)). A relayed connection holds two
	// descriptors, and the SOCKS ports of the engines take theirs from the same
	// limit.
	connsFilesPercent  = 20
	connsMemoryPercent = 50
	connMemory         = 100 << 10
	minConnsCap        = 1024
	// unknownOpenFiles is taken for a limit of open files that cannot be read.
	// A memory limit that cannot be read leaves the memory bound at its floor.
	unknownOpenFiles = 4096
	// maxMemory bounds the memory limit that is taken: no product overflows.
	maxMemory = 1 << 50
	// fastHelloTimeout is the time a new connection has for its hello while
	// more than half of the pre-hello cap is taken, if ClientHelloTimeout is
	// longer.
	fastHelloTimeout = 3 * time.Second
	// refusalWarnInterval is how often, at most, the refusals and evictions
	// are logged.
	refusalWarnInterval = time.Minute
)

// caps are the caps on connections, with the two bounds the total cap is the
// smaller of, for the log.
type caps struct {
	preHello int // connections before the end of their hello
	conns    int // all the connections of the public listeners
	byFiles  int // the bound of conns by the limit of open files
	byMemory int // the bound of conns by the memory limit
}

// deriveCaps derives the caps from nofile, the soft limit of open files of the
// process, and memory, its memory limit in bytes; 0 is a limit that is not
// known.
func deriveCaps(nofile, memory uint64) caps {
	if nofile == 0 {
		nofile = unknownOpenFiles
	}
	// Linux allows some 2^31 open files at most, and RLIM_INFINITY is the
	// largest uint64: the bounds keep the products from overflowing, and the
	// caps an int on every platform.
	n := min(nofile, math.MaxInt32)
	m := min(memory, maxMemory)
	var c caps
	c.byFiles = int(max(n*connsFilesPercent/100, minConnsCap))
	c.byMemory = minConnsCap
	if m > 0 {
		c.byMemory = int(min(max(m*connsMemoryPercent/100/connMemory, minConnsCap), math.MaxInt32))
	}
	c.conns = min(c.byFiles, c.byMemory)
	c.preHello = int(max(1, min(n*preHelloPercent/100, maxPreHelloCap, uint64(c.conns)*preHelloOfConnsPercent/100)))
	return c
}

// sourceKey is what the connections of a client are counted under for
// perSourcePreHello: its IPv4 address (an IPv4-mapped IPv6 address is the IPv4
// address it maps), or the /64 prefix of its IPv6 address, without zone.
func sourceKey(a netip.Addr) netip.Addr {
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a
	}
	p, err := a.Prefix(sourceV6Bits)
	if err != nil {
		return netip.Addr{}
	}
	return p.Addr()
}

// ingress holds the counts the caps are checked against, and the refusals. Its
// methods may be called from any goroutine; the caps do not change after
// newIngress.
//
// An evicted connection is closed by the goroutine that evicts it, and gives
// its places back itself, once the goroutine that serves it sees the
// connection closed and ends: until then it is counted in preHello, sources
// and conns, and among the leaving, but no longer among the pending, which are
// what the cap of the edge on connections before their hello is checked
// against. The live connections are conns - leaving.
type ingress struct {
	maxPreHello int           // Options.MaxPreHello
	maxConns    int           // Options.MaxConns
	hello       time.Duration // the time a connection has for its hello: Options.ClientHelloTimeout
	fastHello   time.Duration // the same while more than half of maxPreHello is taken

	mu       sync.Mutex
	preHello int                // connections before the end of their hello
	sources  map[netip.Addr]int // the same by sourceKey; no zero entries
	conns    int                // every connection, before its hello or after
	// oldest and newest are the ends of the list of the connections before
	// their hello that have not been evicted, in the order they came, and
	// pending is how many there are.
	oldest, newest *ticket
	pending        int
	leaving        int // evicted connections that have not ended yet
	upstream       int // connections of http-upstream listeners, among conns: maxUpstream at most

	refusedPreHello atomic.Uint64 // since the start: see edgev1.SnapshotResponse
	refusedTotal    atomic.Uint64
	evictedPreHello atomic.Uint64
}

func newIngress(o Options) *ingress {
	return &ingress{
		maxPreHello: o.MaxPreHello,
		maxConns:    o.MaxConns,
		hello:       o.ClientHelloTimeout,
		fastHello:   min(fastHelloTimeout, o.ClientHelloTimeout),
		sources:     make(map[netip.Addr]int),
	}
}

// The caps that a connection is refused over, as the counters of Snapshot
// name them.
const (
	capPreHello = "prehello"
	capTotal    = "total"
	// capUpstream is the share of the http-upstream listeners in the total
	// cap, whose refusals are counted among those of the total cap.
	capUpstream = "upstream"
)

// admit takes a new connection c from the client address a, accepted at now.
// It returns the ticket of the connection, and whether the oldest connection
// before its hello was evicted for it; or nil and the cap the connection is
// over, which it counts. A probe is held to no cap and not counted.
//
// The total cap is checked first, then the cap of the source. When the edge
// has maxPreHello connections before their hello, the oldest of them is
// closed and makes way, unless as many evicted ones are still on their way
// out: the newcomer is refused then.
//
// A connection has fastHello for its hello when more than half of maxPreHello
// is taken by others as it comes, and the full time otherwise. It keeps the
// deadline it gets, whatever comes later.
func (g *ingress) admit(c io.Closer, a netip.Addr, probe bool, now time.Time) (tk *ticket, over string, evicted bool) {
	if probe {
		return &ticket{probe: true, helloBy: now.Add(g.hello)}, "", false
	}
	key := sourceKey(a)
	g.mu.Lock()
	evict := g.pending >= g.maxPreHello
	live := g.conns - g.leaving
	if evict {
		live-- // the oldest makes way, here as well
	}
	switch {
	case live >= g.maxConns:
		g.mu.Unlock()
		g.refusedTotal.Add(1)
		return nil, capTotal, false
	case g.sources[key] >= perSourcePreHello, evict && g.leaving >= g.maxPreHello:
		g.mu.Unlock()
		g.refusedPreHello.Add(1)
		return nil, capPreHello, false
	}
	var victim *ticket
	if evict {
		victim = g.oldest
		g.unlinkLocked(victim)
		victim.evicted = true
		g.leaving++
	}
	hello := g.hello
	if g.pending > g.maxPreHello/2 {
		hello = g.fastHello
	}
	tk = &ticket{g: g, conn: c, src: key, helloBy: now.Add(hello), preHello: true, held: true}
	g.conns++
	g.preHello++
	g.sources[key]++
	g.pushLocked(tk)
	g.mu.Unlock()

	if victim == nil {
		return tk, "", false
	}
	g.evictedPreHello.Add(1)
	// Closing makes the read of the hello fail in the goroutine of the
	// victim, which gives the places back as it ends.
	_ = victim.conn.Close()
	return tk, "", true
}

// admitHeld takes a new connection c that has no hello to send, one of an
// http-upstream listener: it holds a place among all the connections of the
// edge, and none among those before their hello. It returns the ticket of the
// connection; or nil, and the cap that the connection is over, when the edge
// holds as many connections as it may (capTotal), or the http-upstream
// listeners as many as maxUpstream (capUpstream), which it counts among the
// refusals of the total cap.
func (g *ingress) admitHeld(c io.Closer) (*ticket, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case g.conns-g.leaving >= g.maxConns:
		g.refusedTotal.Add(1)
		return nil, capTotal
	case g.upstream >= g.maxUpstream():
		g.refusedTotal.Add(1)
		return nil, capUpstream
	}
	g.conns++
	g.upstream++
	return &ticket{g: g, conn: c, held: true, upstream: true}, ""
}

// maxUpstream is the most connections that the http-upstream listeners may
// hold together: half of the total cap, so that a slow web server in front of
// them cannot make the edge refuse fake TLS at accept (Ruling S3-4), and one at
// least.
func (g *ingress) maxUpstream() int { return max(1, g.maxConns/2) }

// pushLocked puts k at the end of the list of the pending connections. g.mu
// must be held.
func (g *ingress) pushLocked(k *ticket) {
	k.prev, k.next, k.listed = g.newest, nil, true
	if g.newest != nil {
		g.newest.next = k
	} else {
		g.oldest = k
	}
	g.newest = k
	g.pending++
}

// unlinkLocked takes k out of the list of the pending connections, if it is in
// it. g.mu must be held.
func (g *ingress) unlinkLocked(k *ticket) {
	if !k.listed {
		return
	}
	if k.prev != nil {
		k.prev.next = k.next
	} else {
		g.oldest = k.next
	}
	if k.next != nil {
		k.next.prev = k.prev
	} else {
		g.newest = k.prev
	}
	k.prev, k.next, k.listed = nil, nil, false
	g.pending--
}

// leave gives back the places of the connection of k: the one among the
// connections before their hello, the one among all of them, or both.
func (g *ingress) leave(k *ticket, preHello, held bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if preHello {
		g.unlinkLocked(k)
		g.preHello--
		if g.sources[k.src]--; g.sources[k.src] <= 0 {
			delete(g.sources, k.src)
		}
	}
	if held {
		g.conns--
		if k.upstream {
			g.upstream--
		}
		if k.evicted {
			g.leaving--
		}
	}
}

// ticket is what admit made of a connection: when its hello has to be
// complete, and the places it holds in the counts until it gives them back.
// The goroutine that serves the connection owns it, and it alone gives the
// places back, also when the connection was evicted. The ticket of a probe
// holds no place.
type ticket struct {
	g       *ingress   // nil when the ticket holds no place
	conn    io.Closer  // the connection, closed when it is evicted
	src     netip.Addr // the sourceKey of the client
	probe   bool       // one of the node's own probes, on a test listener
	helloBy time.Time  // the deadline of the hello, on the real clock

	// Of the owner alone.
	preHello bool // holds a place among the connections before their hello
	held     bool // holds a place among all the connections

	upstream bool // a connection of an http-upstream listener (admitHeld); set at the start, read under the mutex of g

	// Guarded by the mutex of g.
	evicted    bool    // closed to make room for a newcomer
	listed     bool    // in the list of the pending connections of g
	prev, next *ticket // its neighbours there, the older and the newer
}

// helloRead gives back the place among the connections before their hello:
// the hello has been read, or never will be. The place among all the
// connections is kept.
func (k *ticket) helloRead() {
	if k.g == nil || !k.preHello {
		return
	}
	k.preHello = false
	k.g.leave(k, true, false)
}

// release gives back every place the ticket still holds, when the connection
// has ended.
func (k *ticket) release() {
	if k.g == nil || !k.preHello && !k.held {
		return
	}
	preHello, held := k.preHello, k.held
	k.preHello, k.held = false, false
	k.g.leave(k, preHello, held)
}

// warnCaps logs that connections are refused at accept or evicted, with the
// counts since the start and never an address, at most once per
// refusalWarnInterval of the edge's clock.
func (e *Edge) warnCaps() {
	if !e.capWarns.allow("caps", e.now()) {
		return
	}
	g := e.ingress
	e.log.Warn("edge: connections over the caps are closed (counts since the start)",
		"refused_prehello", g.refusedPreHello.Load(), "refused_total", g.refusedTotal.Load(),
		"evicted_prehello", g.evictedPreHello.Load(),
		"max_prehello", g.maxPreHello, "max_prehello_per_source", perSourcePreHello, "max_conns", g.maxConns)
}
