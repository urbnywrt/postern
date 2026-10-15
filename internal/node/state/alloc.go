package state

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// Port ranges on 127.0.0.1, by name (Global Constraints, spec 5.1).
const (
	RangeEngine      = "engine"       // engine listeners, 20000-24999
	RangeEngineAPI   = "engine-api"   // engine APIs and metrics, 25000-29999
	RangeEdgeSocks   = "edge-socks"   // the edge's SOCKS ports for engines, 30000-34999
	RangeEgressSocks = "egress-socks" // SOCKS ports of egress providers, 35000-39999
	RangeService     = "service"      // test listeners, mgmt, http-upstream, 40000-40999
)

// PortRange is an inclusive range of ports.
type PortRange struct {
	First, Last uint16
}

var defaultRanges = map[string]PortRange{
	RangeEngine:      {20000, 24999},
	RangeEngineAPI:   {25000, 29999},
	RangeEdgeSocks:   {30000, 34999},
	RangeEgressSocks: {35000, 39999},
	RangeService:     {40000, 40999},
}

// DefaultRange returns the range of the given name.
func DefaultRange(name string) (PortRange, bool) {
	r, ok := defaultRanges[name]
	return r, ok
}

// Allocator hands out loopback ports from the named ranges and records them in
// the runtime. A port is taken only when no key of the runtime holds it and it
// can be bound on 127.0.0.1 at that moment (something outside Postern may sit
// on it). The search for a free port goes on after the previous allocation of
// the range, so a port that was just released is not handed out again at once.
//
// The zero value is ready to use. It is safe for concurrent use, but the
// runtime passed in must not be changed by others meanwhile.
type Allocator struct {
	// Ranges replaces the default ranges (tests); nil means the defaults.
	Ranges map[string]PortRange
	// IsFree reports whether a port can be used; nil probe-binds
	// 127.0.0.1:<port> over TCP.
	IsFree func(port uint16) bool

	mu       sync.Mutex
	next     map[string]uint16 // where the next search of a range starts
	reserved map[uint16]bool   // never handed out (Reserve)
}

// Reserve keeps ports from ever being allocated: the ports of the listeners
// of the desired state, which a test listener must not land on even if the
// validator let one into the service range. Reservations accumulate.
func (a *Allocator) Reserve(ports ...uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reserved == nil {
		a.reserved = map[uint16]bool{}
	}
	for _, p := range ports {
		a.reserved[p] = true
	}
}

// Alloc returns the port recorded under key, or allocates a free one from the
// named range and records it.
func (a *Allocator) Alloc(rt *Runtime, key, rangeName string) (uint16, error) {
	if rt == nil {
		return 0, errors.New("state: no runtime record to allocate in")
	}
	if p, ok := rt.Ports[key]; ok {
		return p, nil
	}
	r, ok := a.Ranges[rangeName]
	if a.Ranges == nil {
		r, ok = defaultRanges[rangeName]
	}
	if !ok || r.First == 0 || r.First > r.Last {
		return 0, fmt.Errorf("state: unknown port range %q", rangeName)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	used := make(map[uint16]bool, len(rt.Ports))
	for _, p := range rt.Ports {
		used[p] = true
	}
	free := a.IsFree
	if free == nil {
		free = canBind
	}
	size := int(r.Last) - int(r.First) + 1
	start := a.next[rangeName]
	if start < r.First || start > r.Last {
		start = r.First
	}
	for i := 0; i < size; i++ {
		p := uint16(int(r.First) + (int(start)-int(r.First)+i)%size)
		if used[p] || a.reserved[p] || !free(p) {
			continue
		}
		if rt.Ports == nil {
			rt.Ports = map[string]uint16{}
		}
		rt.Ports[key] = p
		if a.next == nil {
			a.next = map[string]uint16{}
		}
		a.next[rangeName] = p + 1 // past Last, the next search wraps around
		return p, nil
	}
	return 0, fmt.Errorf("state: no free port in range %s (%d-%d)", rangeName, r.First, r.Last)
}

// Release forgets the port recorded under key.
func (a *Allocator) Release(rt *Runtime, key string) {
	if rt != nil {
		delete(rt.Ports, key)
	}
}

// canBind reports whether 127.0.0.1:port can be listened on right now.
func canBind(port uint16) bool {
	ln, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}
