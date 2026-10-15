package edge

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/edge/rules"
)

// The kinds of a route, as edgev1.Route.Kind spells them. The values of a
// listener are those of the package rules, which the node checks a desired
// state with as well.
const (
	routeEngine = "engine"
	routeWeb    = "web"
	routeMgmt   = "mgmt"
)

// defaultDeviceIdle is how long an IP stays a device after its last connection
// ended, when the configuration does not say.
const defaultDeviceIdle = 120 * time.Second

// maxIgnoredSources is the most probe sources that are no address a table
// keeps for the log.
const maxIgnoredSources = 8

// testListenerIP is the address every test listener binds.
var testListenerIP = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// table is the routing state built from one EdgeConfig. Nothing in it changes
// once Apply has put it in effect (Apply sets route.stats just before): Apply
// replaces the table whole, and a connection is handled by the table it was
// accepted under from its start to its end.
type table struct {
	generation uint64

	// listeners holds the listeners to bind, by address. A test listener maps
	// to the entry of the listener it mirrors, so that it routes the same.
	listeners map[netip.AddrPort]*listenerEntry
	// probes holds the addresses of the test listeners. Their connections are
	// the node's own probes: they are routed like any other, but are not held
	// to the limits of a proxy and not counted for it.
	probes map[netip.AddrPort]bool
	// probeSources are the addresses of the panel's probes (unmapped, without
	// zone): a connection of a public listener from one of them is exempt from
	// the limits of its proxy, bounded (see admitExempt). ignoredSources are
	// the entries of the configuration that are no single address, for Apply
	// to log.
	probeSources   map[netip.Addr]bool
	ignoredSources []string

	blacklist   cidrSet
	maskDomains map[string]bool // folded names, see rules.FoldName
	deviceIdle  time.Duration
	routes      []*route  // every route, of every listener
	certs       []certRef // the certificates of the web routes, by folded domain
}

// listenerEntry is what a listener does with a connection: the routes by
// server name, and what becomes of strangers and of traffic that is not TLS.
// A listener of kind http-upstream routes the requests of its connections by
// their Host instead (httpupstream.go): only its routes of kind web and its
// trusted prefixes matter to it.
type listenerEntry struct {
	id         string
	kind       string
	stranger   string            // rules.StrangerMask, rules.StrangerReject or rules.StrangerDrop
	maskTarget string            // host:port, or "" for the stranger's own name
	nonTLS     string            // rules.NonTLSDrop or rules.NonTLSHTTP400
	trusted    cidrSet           // http-upstream: the peers that are served, whose X-Forwarded-For is believed
	routes     map[string]*route // by folded server name
	// probeRoutes are the routes of the node's own probes, by folded server
	// name: a probe on a test listener of the listener takes one in place of
	// the route of its name (EdgeConfig.probe_routes). They have no stats.
	probeRoutes map[string]*route
}

// routeFor returns the route of a connection for the folded server name sni:
// for a probe of the node, the probe route of the name when there is one, and
// else the route of the name; nil when there is none.
func (l *listenerEntry) routeFor(sni string, probe bool) *route {
	if probe {
		if r := l.probeRoutes[sni]; r != nil {
			return r
		}
	}
	return l.routes[sni]
}

// route is where the connections for one server name of one listener go.
type route struct {
	sni     string // folded
	proxyID string // "" for a management route: such a route has no limits and no counters
	kind    string
	// backend is the address to relay to, or for a web route the one of the
	// WEB listener of the engine that its requests go to.
	backend       netip.AddrPort
	backendKey    string // backend.String(), the key of backend_active
	proxyProtocol bool
	limits        limits
	// stats is the state of the proxy, against which its limits are checked
	// and where its traffic is counted. Apply sets it before the table is in
	// effect; nil for a route without a proxy.
	stats *proxyStats
}

// CheckConfig checks a configuration as Apply does before it binds anything,
// and returns the error that Apply would return for it, or nil. It opens no
// socket and reads no file, and needs no Edge: the node and the panel check
// with it that the edge takes what they would send.
func CheckConfig(cfg *edgev1.EdgeConfig) error {
	_, err := buildTable(cfg)
	return err
}

// buildTable checks a configuration as a whole and builds the table for it.
// The error says what is wrong with the first fault found.
func buildTable(cfg *edgev1.EdgeConfig) (*table, error) {
	if cfg == nil {
		return nil, errors.New("edge: no configuration")
	}
	t := &table{
		generation:  cfg.GetGeneration(),
		listeners:   make(map[netip.AddrPort]*listenerEntry),
		probes:      make(map[netip.AddrPort]bool),
		maskDomains: make(map[string]bool),
		deviceIdle:  defaultDeviceIdle,
	}
	if s := cfg.GetDeviceIdleSeconds(); s > 0 {
		t.deviceIdle = time.Duration(s) * time.Second
	}

	byID := make(map[string]*listenerEntry)
	taken := make(map[netip.AddrPort]string) // address -> who takes it, for the error
	for _, l := range cfg.GetListeners() {
		entry, addr, err := parseListener(l)
		if err != nil {
			return nil, err
		}
		if _, dup := byID[entry.id]; dup {
			return nil, fmt.Errorf("edge: listener %q is defined twice", entry.id)
		}
		if who, dup := taken[addr]; dup {
			return nil, fmt.Errorf("edge: listener %q takes %s, which %s takes already", entry.id, addr, who)
		}
		byID[entry.id] = entry
		taken[addr] = fmt.Sprintf("listener %q", entry.id)
		t.listeners[addr] = entry
	}

	for _, tl := range cfg.GetTestListeners() {
		entry, ok := byID[tl.GetListenerId()]
		if !ok {
			return nil, fmt.Errorf("edge: test listener on port %d: no listener %q", tl.GetPort(), tl.GetListenerId())
		}
		port, err := rules.ParsePort(tl.GetPort())
		if err != nil {
			return nil, fmt.Errorf("edge: test listener of %q: %w", entry.id, err)
		}
		addr := netip.AddrPortFrom(testListenerIP, port)
		if who, dup := taken[addr]; dup {
			return nil, fmt.Errorf("edge: test listener of %q takes %s, which %s takes already", entry.id, addr, who)
		}
		taken[addr] = fmt.Sprintf("the test listener of %q", entry.id)
		// The node's probes speak TLS: a test listener of an http-upstream
		// listener would have nothing to serve them, and is not bound.
		if entry.kind == rules.KindTLS {
			t.listeners[addr] = entry
			t.probes[addr] = true
		}
	}

	for _, r := range cfg.GetRoutes() {
		entry, ok := byID[r.GetListenerId()]
		if !ok {
			return nil, fmt.Errorf("edge: route %q: no listener %q", r.GetSni(), r.GetListenerId())
		}
		rt, err := parseRoute(r)
		if err != nil {
			return nil, fmt.Errorf("edge: route %q of listener %q: %w", r.GetSni(), entry.id, err)
		}
		if _, dup := entry.routes[rt.sni]; dup {
			return nil, fmt.Errorf("edge: listener %q routes %q twice", entry.id, rt.sni)
		}
		entry.routes[rt.sni] = rt
		t.routes = append(t.routes, rt)
	}
	// The probe routes: checked like the routes, kept apart from them, and not
	// in t.routes, whose stats are the proxies'.
	for _, r := range cfg.GetProbeRoutes() {
		entry, ok := byID[r.GetListenerId()]
		if !ok {
			return nil, fmt.Errorf("edge: probe route %q: no listener %q", r.GetSni(), r.GetListenerId())
		}
		rt, err := parseRoute(r)
		if err != nil {
			return nil, fmt.Errorf("edge: probe route %q of listener %q: %w", r.GetSni(), entry.id, err)
		}
		if _, dup := entry.probeRoutes[rt.sni]; dup {
			return nil, fmt.Errorf("edge: listener %q has two probe routes for %q", entry.id, rt.sni)
		}
		entry.probeRoutes[rt.sni] = rt
	}

	// A probe source that is not one address fails nothing: the panel's
	// probes from it are counted as clients, which is what an edge without
	// the field does too.
	for _, s := range cfg.GetProbeSources() {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			if len(t.ignoredSources) < maxIgnoredSources {
				t.ignoredSources = append(t.ignoredSources, s)
			}
			continue
		}
		if t.probeSources == nil {
			t.probeSources = make(map[netip.Addr]bool)
		}
		t.probeSources[a.Unmap()] = true
	}

	var err error
	if t.blacklist, err = parseCIDRs(cfg.GetBlacklistCidrs()); err != nil {
		return nil, err
	}
	for _, d := range cfg.GetMaskDomains() {
		name, ok := rules.FoldName(d)
		if !ok {
			return nil, fmt.Errorf("edge: mask domain %q is not a host name", d)
		}
		t.maskDomains[name] = true
	}
	// The domain of a certificate names its directory: a host name, which has
	// no slash and no empty label, cannot lead out of the certificate
	// directory.
	certs := make(map[string]bool)
	for _, c := range cfg.GetCerts() {
		name, ok := rules.FoldName(c.GetDomain())
		if !ok {
			return nil, fmt.Errorf("edge: the domain of a certificate, %.70q, is not a host name", c.GetDomain())
		}
		if certs[name] {
			return nil, fmt.Errorf("edge: the certificate of %q is named twice", name)
		}
		certs[name] = true
		t.certs = append(t.certs, certRef{domain: name, gen: c.GetGeneration()})
	}
	return t, nil
}

func parseListener(l *edgev1.EdgeListener) (*listenerEntry, netip.AddrPort, error) {
	id := l.GetId()
	if id == "" {
		return nil, netip.AddrPort{}, errors.New("edge: a listener has no id")
	}
	fail := func(format string, args ...any) (*listenerEntry, netip.AddrPort, error) {
		return nil, netip.AddrPort{}, fmt.Errorf("edge: listener %q: "+format, append([]any{id}, args...)...)
	}
	// An IPv4-mapped address is the IPv4 address: the listener binds IPv4.
	ip, err := rules.ParseBindIP(l.GetBindIp())
	if err != nil {
		return fail("%v", err)
	}
	port, err := rules.ParsePort(l.GetPort())
	if err != nil {
		return fail("%v", err)
	}
	if !rules.ValidListenerKind(l.GetKind()) {
		return fail("unknown kind %q", l.GetKind())
	}
	if !rules.ValidStrangerAction(l.GetStrangerAction()) {
		return fail("unknown stranger action %q", l.GetStrangerAction())
	}
	if !rules.ValidNonTLSAction(l.GetNonTlsAction()) {
		return fail("unknown non-TLS action %q", l.GetNonTlsAction())
	}
	target, err := rules.ParseMaskTarget(l.GetMaskTarget())
	if err != nil {
		return fail("%v", err)
	}
	upstream := l.GetKind() == rules.KindHTTPUpstream
	if upstream {
		if err := rules.CheckUpstreamBind(ip); err != nil {
			return fail("%v", err)
		}
	}
	var trusted cidrSet
	for _, c := range l.GetTrustedCidrs() {
		p, err := rules.ParsePrefix(c)
		if err != nil {
			return fail("trusted CIDR: %v", err)
		}
		if upstream {
			if err := rules.CheckUpstreamTrusted(p); err != nil {
				return fail("%v", err)
			}
		}
		trusted.add(p)
	}
	entry := &listenerEntry{
		id:          id,
		kind:        l.GetKind(),
		stranger:    l.GetStrangerAction(),
		maskTarget:  target,
		nonTLS:      l.GetNonTlsAction(),
		trusted:     trusted,
		routes:      make(map[string]*route),
		probeRoutes: make(map[string]*route),
	}
	return entry, netip.AddrPortFrom(ip, port), nil
}

func parseRoute(r *edgev1.Route) (*route, error) {
	sni, ok := rules.FoldName(r.GetSni())
	if !ok {
		return nil, errors.New("the server name is not a host name")
	}
	rt := &route{
		sni:           sni,
		proxyID:       r.GetProxyId(),
		kind:          r.GetKind(),
		proxyProtocol: r.GetProxyProtocol(),
		limits:        limitsOf(r.GetLimits()),
	}
	switch rt.kind {
	case routeEngine, routeWeb:
		if rt.proxyID == "" {
			return nil, fmt.Errorf("a route of kind %s needs a proxy id", rt.kind)
		}
	case routeMgmt:
	default:
		return nil, fmt.Errorf("unknown kind %q", rt.kind)
	}
	b := r.GetBackend()
	if b == "" {
		return nil, errors.New("no backend")
	}
	// The backend is an engine or the agent on this node: an address, never a
	// name, so that no connection waits for a resolver.
	ap, err := netip.ParseAddrPort(b)
	if err != nil || ap.Port() == 0 {
		return nil, fmt.Errorf("backend %q is not an IP address and a port", b)
	}
	rt.backend = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	rt.backendKey = rt.backend.String()
	return rt, nil
}

func limitsOf(l *edgev1.EdgeLimits) limits {
	n := func(v uint32) int { return int(min(v, math.MaxInt32)) }
	return limits{devices: n(l.GetDevices()), connsTotal: n(l.GetConnsTotal()), connsPerIP: n(l.GetConnsPerIp())}
}
