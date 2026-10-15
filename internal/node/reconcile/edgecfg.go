package reconcile

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge/rules"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/webrules"
)

// deviceIdleSeconds is how long an IP counts as a device after its last
// connection closed (Global Constraints).
const deviceIdleSeconds = 120

// startingInstance is an engine generation that is being started in this pass:
// the edge must already offer its SOCKS port when the engine comes up, but
// routes no client to it yet. While its way out is checked (probe set), a
// probe route of the edge leads the node's probes of its proxy's domain on the
// test listener to its port, listen.
type startingInstance struct {
	gen    uint64
	socks  uint16
	listen uint16
	probe  bool
}

// buildEdgeConfig computes the edge's whole configuration from the desired
// state and the runtime record. It is a pure function: the same input gives the
// same config, every list in a fixed order. gen is the edge generation, the
// value the edge reports back from Health and Snapshot.
//
//   - listeners: every listener, with a test listener on its service port;
//   - routes: an enabled proxy whose engine instance serves goes to that
//     instance (PROXY protocol v2, the proxy's limits), under the listener and
//     domain the instance was rendered for, as it is written (the edge folds it:
//     a domain with a dot at its end routes for the SNI without it) and keyed
//     as the edge folds names (state.FoldDomain), so that two keys that are one
//     name to the edge are one key here; a paused or deleted proxy has no
//     route, so its SNI is a stranger's;
//   - probe routes: for a starting instance whose way out is checked, its
//     proxy's listener and domain to its port (see startingInstance);
//   - SOCKS ports: one per serving, draining and starting engine instance,
//     with the proxy's chain (or the node's default) and scope chains; a
//     deleted proxy's instances use the default chain while they drain;
//   - chains: every chain, its members built from the egresses: one for an
//     egress the edge dials itself, one per member of its serving instance for
//     an egress of a provider (none while it has none), in the order of the
//     chain;
//   - mask domains: the domain pool and every proxy's domain, folded as the edge
//     folds names (ASCII lower case, one dot at the end dropped);
//   - WEB proxies (web.go): the route of a WEB proxy is of kind web, without
//     PROXY protocol, to the web listener of its instance (its ListenPort, as
//     every route: the idle check of a draining generation counts on it); on
//     a tls listener it is there only while webCerts says the edge may serve
//     its domain, and the domain is then among certs (CertRef) with the
//     generation webCerts gives; on an http-upstream listener it is always
//     there, and no certificate is named.
//
// buildEdgeConfig is buildEdgeConfigWith without certificates: no web route of
// a tls listener.
func buildEdgeConfig(st *nodev1.NodeState, rt *state.Runtime, gen uint64, starting map[string]startingInstance) *edgev1.EdgeConfig {
	return buildEdgeConfigWith(st, rt, gen, starting, nil)
}

func buildEdgeConfigWith(st *nodev1.NodeState, rt *state.Runtime, gen uint64, starting map[string]startingInstance, webCerts map[string]webCert) *edgev1.EdgeConfig {
	cfg := &edgev1.EdgeConfig{Generation: gen, DeviceIdleSeconds: deviceIdleSeconds}
	if st == nil {
		return cfg
	}

	listeners := slices.Clone(st.GetListeners())
	slices.SortFunc(listeners, func(a, b *nodev1.Listener) int { return strings.Compare(a.GetId(), b.GetId()) })
	upstream := map[string]bool{}
	for _, l := range listeners {
		upstream[l.GetId()] = l.GetKind() == nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM
		cfg.Listeners = append(cfg.Listeners, &edgev1.EdgeListener{
			Id:             l.GetId(),
			BindIp:         l.GetBindIp(),
			Port:           l.GetPort(),
			Kind:           listenerKind(l.GetKind()),
			StrangerAction: strangerAction(l.GetStrangerAction()),
			MaskTarget:     l.GetMaskTarget(),
			NonTlsAction:   nonTLSAction(l.GetNonTlsAction()),
			TrustedCidrs:   slices.Clone(l.GetTrustedCidrs()),
		})
		if port := rt.Ports[state.TestListenerPortKey(l.GetId())]; port != 0 {
			cfg.TestListeners = append(cfg.TestListeners, &edgev1.TestListener{Port: uint32(port), ListenerId: l.GetId()})
		}
	}

	proxies := map[string]*nodev1.Proxy{}
	for _, p := range st.GetProxies() {
		proxies[p.GetId()] = p
	}
	chains := map[string]*nodev1.EgressChain{}
	for _, c := range st.GetChains() {
		chains[c.GetId()] = c
	}
	defaultChain := st.GetSettings().GetDefaultChainId()

	// Routes: the serving instance of every enabled proxy, under the key it
	// was rendered for (the record's listener and domain). During a blue-green
	// the old domain thus keeps reaching the old generation; the key moves when
	// the new generation takes over. When two keys collide (a domain swap),
	// the instance whose key is also its proxy's desired one wins; between two
	// stale keys, the instance that took over last.
	listenerIDs := map[string]bool{}
	for _, l := range listeners {
		listenerIDs[l.GetId()] = true
	}
	type candidate struct {
		route   *edgev1.Route
		current bool      // the key is the proxy's desired one
		since   time.Time // when the instance took over
	}
	wins := func(a, b candidate) bool {
		if a.current != b.current {
			return a.current
		}
		return a.since.After(b.since) // on a tie the earlier proxy id stays
	}
	byKey := map[string]candidate{}
	certs := map[string]uint64{}
	for _, id := range slices.Sorted(maps.Keys(proxies)) {
		p := proxies[id]
		rec, ok := rt.Instances[id]
		if !p.GetEnabled() || !ok || rec.Generation == 0 || rec.ListenPort == 0 {
			continue
		}
		listener, sni := routeKey(p, rec)
		if !listenerIDs[listener] {
			continue // the listener it serves is gone; the edge must not hear of it
		}
		kind, proxyProto := "engine", true
		if isWeb(p) {
			kind, proxyProto = "web", false
			if !upstream[listener] {
				domain, err := webrules.CertDomain(sni)
				if err != nil {
					continue
				}
				c, ok := webCerts[domain]
				if !ok || !c.ok {
					// No certificate to serve the route with (yet). webCerts is
					// built from the desired listener of each proxy: a draining
					// generation whose old route is on a tls listener while the
					// proxy moved to an http-upstream listener loses its route at
					// once rather than draining. Accepted: the move is rare and
					// the new placement serves.
					continue
				}
				certs[domain] = c.gen
			}
		}
		c := candidate{
			route: &edgev1.Route{
				ListenerId:    listener,
				Sni:           sni,
				ProxyId:       id,
				Kind:          kind,
				Backend:       loopback(rec.ListenPort),
				ProxyProtocol: proxyProto,
				Limits: &edgev1.EdgeLimits{
					Devices:    p.GetLimits().GetDevices(),
					ConnsTotal: p.GetLimits().GetConnsTotal(),
					ConnsPerIp: p.GetLimits().GetConnsPerIp(),
				},
			},
			current: listener == p.GetListenerId() && state.FoldDomain(sni) == state.FoldDomain(p.GetDomain()),
			since:   rec.ServingSince,
		}
		key := listener + "\x00" + state.FoldDomain(sni)
		if prev, taken := byKey[key]; taken && !wins(c, prev) {
			continue
		}
		byKey[key] = c
	}
	for _, c := range byKey {
		cfg.Routes = append(cfg.Routes, c.route)
	}
	// The hidden management listener (spec 5.3): when mgmt_sni is set and the
	// agent has allocated the hidden port, a route of kind mgmt on every public
	// tls listener forwards mgmt_sni, with PROXY v2, to the agent's hidden
	// listener on the loopback. state.Validate refuses a mgmt_sni that collides
	// (after folding) with a proxy domain or a pool domain, so the edge never
	// gets two routes of one name on a listener.
	if sni := st.GetSettings().GetMgmtSni(); sni != "" {
		if port := rt.Ports[state.MgmtHiddenPortKey]; port != 0 {
			for _, l := range listeners {
				if l.GetKind() != nodev1.ListenerKind_LISTENER_KIND_TLS {
					continue
				}
				cfg.Routes = append(cfg.Routes, &edgev1.Route{
					ListenerId:    l.GetId(),
					Sni:           sni,
					Kind:          "mgmt",
					Backend:       loopback(port),
					ProxyProtocol: true,
				})
			}
		}
	}
	slices.SortStableFunc(cfg.Routes, func(a, b *edgev1.Route) int {
		return cmp.Or(strings.Compare(a.GetListenerId(), b.GetListenerId()),
			strings.Compare(state.FoldDomain(a.GetSni()), state.FoldDomain(b.GetSni())))
	})
	for _, domain := range slices.Sorted(maps.Keys(certs)) {
		cfg.Certs = append(cfg.Certs, &edgev1.CertRef{Domain: domain, Generation: certs[domain]})
	}

	// Probe routes: the node's probes of a starting instance whose way out is
	// checked, under its proxy's desired listener and domain.
	probeKeys := map[string]bool{}
	for _, id := range slices.Sorted(maps.Keys(starting)) {
		s, p := starting[id], proxies[id]
		if !s.probe || s.listen == 0 || p == nil || !listenerIDs[p.GetListenerId()] || isWeb(p) {
			continue
		}
		key := p.GetListenerId() + "\x00" + state.FoldDomain(p.GetDomain())
		if probeKeys[key] {
			continue
		}
		probeKeys[key] = true
		cfg.ProbeRoutes = append(cfg.ProbeRoutes, &edgev1.Route{
			ListenerId: p.GetListenerId(), Sni: p.GetDomain(), ProxyId: id, Kind: "engine",
			Backend: loopback(s.listen), ProxyProtocol: true,
		})
	}

	// SOCKS ports: whatever runs needs its way out.
	seen := map[uint16]bool{}
	addSocks := func(proxyID string, port uint16) {
		if port == 0 || seen[port] {
			return
		}
		chain, scopes := defaultChain, map[string]string(nil)
		if p, ok := proxies[proxyID]; ok {
			chain = cmp.Or(p.GetEgressChainId(), defaultChain)
			for scope, c := range p.GetEgressScopeChains() {
				if _, ok := chains[c]; ok && scope != "" {
					if scopes == nil {
						scopes = map[string]string{}
					}
					scopes[scope] = c
				}
			}
		}
		if _, ok := chains[chain]; !ok {
			return // no way out to offer
		}
		seen[port] = true
		cfg.Socks = append(cfg.Socks, &edgev1.SocksPort{
			Port: uint32(port), ProxyId: proxyID, DefaultChainId: chain, ScopeChains: scopes,
		})
	}
	for _, id := range slices.Sorted(maps.Keys(rt.Instances)) {
		rec := rt.Instances[id]
		if rec.Generation > 0 {
			addSocks(id, rec.SocksPort)
		}
		for _, d := range rec.Draining {
			addSocks(id, rt.Ports[state.EnginePortKey(id, d.Generation, state.PortSocks)])
		}
	}
	for _, id := range slices.Sorted(maps.Keys(starting)) {
		addSocks(id, starting[id].socks)
	}
	slices.SortFunc(cfg.Socks, func(a, b *edgev1.SocksPort) int { return cmp.Compare(a.GetPort(), b.GetPort()) })

	// Chains.
	egresses := map[string]*nodev1.Egress{}
	for _, e := range st.GetEgresses() {
		egresses[e.GetId()] = e
	}
	for _, id := range slices.Sorted(maps.Keys(chains)) {
		c := &edgev1.Chain{Id: id}
		for _, m := range chains[id].GetMemberEgressIds() {
			if e := egresses[m]; e != nil && isProviderKind(e.GetKind()) {
				c.Members = append(c.Members, providerMembers(m, rt.Egresses[m])...)
				continue
			}
			if member := chainMember(egresses[m]); member != nil {
				c.Members = append(c.Members, member)
			}
		}
		cfg.Chains = append(cfg.Chains, c)
	}
	cfg.Health = healthCheck(chains, defaultChain)

	for _, entry := range st.GetSettings().GetBlacklistCidrs() {
		if p, err := state.ParseBlacklistEntry(entry); err == nil {
			cfg.BlacklistCidrs = append(cfg.BlacklistCidrs, p.String())
		}
	}

	// The panel's probe sources (R6-1), as the panel sends them, each once,
	// written as the edge compares them: unmapped, in canonical form. An
	// entry that is no single address cannot be in a state that validated.
	for _, entry := range st.GetSettings().GetProbeSources() {
		if a, err := state.ProbeSource(entry); err == nil && !slices.Contains(cfg.ProbeSources, a.String()) {
			cfg.ProbeSources = append(cfg.ProbeSources, a.String())
		}
	}

	domains := map[string]bool{}
	for _, d := range st.GetSettings().GetDomainPool() {
		domains[state.FoldDomain(d)] = true
	}
	for _, p := range st.GetProxies() {
		domains[state.FoldDomain(p.GetDomain())] = true
	}
	delete(domains, "")
	cfg.MaskDomains = slices.Sorted(maps.Keys(domains))
	return cfg
}

// routeKey is the (listener, SNI) the serving instance of a proxy was rendered
// for; a record without one (written before keys were kept) uses the desired
// proxy's.
func routeKey(p *nodev1.Proxy, rec state.InstanceRecord) (listener, sni string) {
	if rec.ListenerID == "" || rec.Domain == "" {
		return p.GetListenerId(), p.GetDomain()
	}
	return rec.ListenerID, rec.Domain
}

// chainMember turns an egress the edge dials itself into a member of a chain;
// nil for an egress that does not exist or that the edge cannot dial itself
// (one of a provider: see providerMembers).
func chainMember(e *nodev1.Egress) *edgev1.ChainMember {
	if e == nil {
		return nil
	}
	switch e.GetKind() {
	case nodev1.EgressKind_EGRESS_KIND_DIRECT:
		p, err := state.ParseDirectParams(e.GetParamsJson())
		if err != nil {
			return nil
		}
		return &edgev1.ChainMember{Key: e.GetId(), Kind: "direct", BindDevice: p.Interface, BindIp: p.BindIP}
	case nodev1.EgressKind_EGRESS_KIND_SOCKS5, nodev1.EgressKind_EGRESS_KIND_HTTP:
		p, err := state.ParseProxyParams(e.GetParamsJson())
		if err != nil {
			return nil
		}
		kind := "socks5"
		if e.GetKind() == nodev1.EgressKind_EGRESS_KIND_HTTP {
			kind = "http"
		}
		return &edgev1.ChainMember{Key: e.GetId(), Kind: kind, Addr: p.Addr, Username: p.Username, Password: p.Password}
	}
	return nil
}

// edgeNeedsNetRaw reports whether a member of a chain of st, as the edge gets
// it (chainMember), is tied to an interface (bind_device). The edge then needs
// CAP_NET_RAW: SO_BINDTODEVICE takes it on a kernel older than 5.7.
func edgeNeedsNetRaw(st *nodev1.NodeState) bool {
	egresses := map[string]*nodev1.Egress{}
	for _, e := range st.GetEgresses() {
		egresses[e.GetId()] = e
	}
	for _, c := range st.GetChains() {
		for _, id := range c.GetMemberEgressIds() {
			if m := chainMember(egresses[id]); m.GetBindDevice() != "" {
				return true
			}
		}
	}
	return false
}

// healthCheck is the check of the node's default chain, or else of the first
// chain (by id) that has one; nil leaves the edge's defaults. The edge runs one
// check for all of its chains.
func healthCheck(chains map[string]*nodev1.EgressChain, defaultChain string) *edgev1.HealthCheck {
	hc := chains[defaultChain].GetCheck()
	if hc == nil {
		for _, id := range slices.Sorted(maps.Keys(chains)) {
			if hc = chains[id].GetCheck(); hc != nil {
				break
			}
		}
	}
	if hc == nil {
		return nil
	}
	return &edgev1.HealthCheck{
		IntervalSeconds:  hc.GetIntervalSeconds(),
		TimeoutSeconds:   hc.GetTimeoutSeconds(),
		FailThreshold:    hc.GetFailThreshold(),
		RecoverThreshold: hc.GetRecoverThreshold(),
		DcAddrs:          slices.Clone(hc.GetDcAddrs()),
	}
}

// listenerKind maps the listener's kind to the edge's; every value maps to one
// that the edge reads (state.Validate refuses the values it does not know).
func listenerKind(k nodev1.ListenerKind) string {
	if k == nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM {
		return rules.KindHTTPUpstream
	}
	return rules.KindTLS
}

// strangerAction maps the listener's action; not set means mask (which turns
// into reject for a server name that is neither a pool nor a proxy domain).
func strangerAction(a nodev1.StrangerAction) string {
	switch a {
	case nodev1.StrangerAction_STRANGER_ACTION_REJECT:
		return rules.StrangerReject
	case nodev1.StrangerAction_STRANGER_ACTION_DROP:
		return rules.StrangerDrop
	}
	return rules.StrangerMask
}

// nonTLSAction maps the listener's action for non-TLS traffic; not set means
// drop.
func nonTLSAction(a nodev1.NonTlsAction) string {
	if a == nodev1.NonTlsAction_NON_TLS_ACTION_HTTP400 {
		return rules.NonTLSHTTP400
	}
	return rules.NonTLSDrop
}

// loopback is "127.0.0.1:<port>".
func loopback(port uint16) string {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port).String()
}
