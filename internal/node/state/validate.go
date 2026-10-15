package state

import (
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge/rules"
	"github.com/urbnywrt/postern/internal/engines/telemt/overrides"
	"github.com/urbnywrt/postern/internal/netpolicy"
	"github.com/urbnywrt/postern/internal/webrules"
)

// ValidationError lists every problem Validate found. Its text never contains
// a secret, an ad tag or egress parameters.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "invalid node state: " + strings.Join(e.Problems, "; ")
}

// Validate checks a desired state as a whole before it is applied:
//
//   - ids of listeners, proxies, egresses and chains are well formed (they end up
//     in container names, labels and paths) and unique per kind, ignoring case;
//   - listeners: kind tls or http-upstream, an IPv4 bind address, port 1-65535
//     and, on 0.0.0.0 or 127.0.0.1, outside the node's internal loopback
//     ranges (20000-40999, an http-upstream listener too: the service range
//     holds the node's test listeners), no two on one address, and on one
//     port either 0.0.0.0 alone or specific addresses only; a stranger action
//     and a non-TLS action that the node knows (not set is mask and drop), a
//     mask target and trusted CIDRs that the edge reads (the rules of
//     internal/edge/rules, which the edge parses its configuration with: it
//     refuses its whole table, with every proxy on the node, for one it cannot
//     read), and a mask target that is not on the node's internal loopback
//     ports, which would relay strangers to an engine, its API or a SOCKS port
//     of the edge; an http-upstream listener binds a loopback or private
//     address and trusts at least one loopback or private prefix (the edge's
//     placement rules);
//   - proxies: fake TLS or WEB (see web), an existing listener, a
//     domain that the edge can route by (see checkDomain: ASCII letters, digits,
//     hyphens and dots, in labels of 1 to 63 bytes, with one dot at the end at
//     most, as a proxy may keep it; the edge refuses its whole table for
//     any other) and that is unique on its listener (compared as the edge
//     compares names: ASCII letter case and the dot at the end aside, see
//     FoldDomain), a secret of exactly
//     32 hex digits, an ad_tag that is empty or 32 hex digits, an engine and
//     version, an engine that supports the type (driverSupports), telemt or
//     mtg (mtg for fake TLS only, never with an ad_tag, the middle proxy, a
//     nat_ip or engine overrides, and with a mask target override that is a
//     public IP address: see mtg), engine overrides that are on the whitelist
//     of internal/engines/telemt/overrides with values in their ranges (and
//     none of the keys that Postern owns), a usable nat_ip, and an egress
//     chain (its own or the node's default);
//   - egresses: direct (through an interface or not), socks5 or http, with
//     parameters that parse as the edge reads them; xray-uri with a share link
//     that egressuri reads, xray-subscription with an http or https URL and a
//     selection of its servers, warp without parameters, psiphon with an exit
//     country of Psiphon and partner ids both or neither (egressparams.go);
//     chains: existing members, each
//     once, at least one;
//   - settings: dns_mode is "", "doh" or "system"; in DNS mode doh no listener
//     takes 127.0.0.2:53, the address of the edge's DNS forwarder;
//     artifact_source is "", "panel" or "direct".
//
// It returns nil or a *ValidationError with every problem found. It does not
// change st.
func Validate(st *nodev1.NodeState, driverSupports func(nodev1.Engine, nodev1.ProxyType) bool) error {
	if st == nil {
		return &ValidationError{Problems: []string{"the state is empty"}}
	}
	v := &validator{supports: driverSupports}
	v.run(st)
	if len(v.problems) > 0 {
		return &ValidationError{Problems: v.problems}
	}
	return nil
}

type validator struct {
	supports func(nodev1.Engine, nodev1.ProxyType) bool
	problems []string
}

func (v *validator) addf(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

func (v *validator) run(st *nodev1.NodeState) {
	listeners := v.listeners(st.GetListeners())
	egresses := v.egresses(st.GetEgresses())
	chains := v.chains(st.GetChains(), egresses)
	defaultChain := v.settings(st.GetSettings(), chains)
	v.dns(st.GetSettings(), st.GetListeners())
	v.artifactSource(st.GetSettings())
	v.proxies(st.GetProxies(), listeners, chains, defaultChain)
	v.mgmtSNI(st.GetSettings(), st.GetProxies(), listeners)
}

// mgmtSNI checks the management SNI of spec 5.3: when it is set it is a host
// name that the edge can route by, and it must not collide (after folding) with
// a domain of the pool or with the domain of a proxy on a tls listener. The
// reconciler puts a mgmt route of it on every public tls listener, and the edge
// refuses its whole table for two routes of one name on a listener. The panel
// checks it with this same validator (validateState), so both refuse it.
func (v *validator) mgmtSNI(s *nodev1.NodeSettings, ps []*nodev1.Proxy, listeners map[string]*nodev1.Listener) {
	sni := s.GetMgmtSni()
	if sni == "" {
		return
	}
	if err := checkDomain(sni); err != nil {
		v.addf("mgmt_sni: %v", err)
		return
	}
	folded := FoldDomain(sni)
	for _, d := range s.GetDomainPool() {
		if FoldDomain(d) == folded {
			v.addf("mgmt_sni %.70q is a domain of the pool: the hidden-management route would clash with the mask of %.70q", sni, d)
			return
		}
	}
	for _, p := range ps {
		l, ok := listeners[p.GetListenerId()]
		if !ok || l.GetKind() != nodev1.ListenerKind_LISTENER_KIND_TLS {
			continue
		}
		if p.GetDomain() != "" && FoldDomain(p.GetDomain()) == folded {
			v.addf("mgmt_sni %.70q is the domain of proxy %.70q on tls listener %.70q: the edge cannot route two names alike", sni, p.GetId(), p.GetListenerId())
			return
		}
	}
}

// The DNS modes of a node (NodeSettings.dns_mode).
const (
	// DNSModeDoH: the edge runs a DNS forwarder on 127.0.0.2:53 that asks
	// DNS-over-HTTPS endpoints, and the containers of the node use it. The
	// default.
	DNSModeDoH = "doh"
	// DNSModeSystem: no forwarder; the containers keep the host's resolver.
	DNSModeSystem = "system"
)

// forwarderAddr is the address of the edge's DNS forwarder (dns.ListenAddr).
var forwarderAddr = netip.MustParseAddrPort("127.0.0.2:53")

// DNSModeOf returns the DNS mode of the settings: DNSModeDoH when it is not set.
func DNSModeOf(s *nodev1.NodeSettings) string {
	if s.GetDnsMode() == "" {
		return DNSModeDoH
	}
	return s.GetDnsMode()
}

// dns checks the DNS mode, and that no listener takes the address of the
// forwarder when it runs.
func (v *validator) dns(s *nodev1.NodeSettings, ls []*nodev1.Listener) {
	switch s.GetDnsMode() {
	case "", DNSModeDoH, DNSModeSystem:
	default:
		v.addf("dns_mode %.70q is neither %q nor %q", s.GetDnsMode(), DNSModeDoH, DNSModeSystem)
		return
	}
	if DNSModeOf(s) != DNSModeDoH {
		return
	}
	for _, l := range ls {
		ip, err := netip.ParseAddr(l.GetBindIp())
		if err == nil && l.GetPort() == uint32(forwarderAddr.Port()) && ip.Unmap() == forwarderAddr.Addr() {
			v.addf("listener %.70q: %s is the address of the DNS forwarder of the node (dns_mode doh)", l.GetId(), forwarderAddr)
		}
	}
}

// ids checks one id and its uniqueness among seen (lower case → original).
func (v *validator) id(kind, id string, seen map[string]string) bool {
	if !validID(id) {
		v.addf("%s id %.70q is not valid (1 to 64 letters, digits, '.', '_' or '-', starting with a letter or digit)", kind, id)
		return false
	}
	key := strings.ToLower(id)
	if other, dup := seen[key]; dup {
		v.addf("duplicate %s id %q (also %q)", kind, id, other)
		return false
	}
	seen[key] = id
	return true
}

func (v *validator) listeners(ls []*nodev1.Listener) map[string]*nodev1.Listener {
	byID := map[string]*nodev1.Listener{}
	seen := map[string]string{}
	type addr struct {
		ip   string
		port uint32
	}
	byAddr := map[addr]string{}
	ports := map[uint32][]*nodev1.Listener{}
	for _, l := range ls {
		if l == nil {
			v.addf("a listener is empty")
			continue
		}
		ok := v.id("listener", l.GetId(), seen)
		if ok {
			byID[l.GetId()] = l
		}
		name := fmt.Sprintf("listener %.70q", l.GetId())
		upstream := false
		switch l.GetKind() {
		case nodev1.ListenerKind_LISTENER_KIND_TLS:
		case nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM:
			upstream = true
		default:
			v.addf("%s: kind is not set", name)
		}
		v.listenerActions(name, l)
		v.maskTarget(name, l.GetMaskTarget())
		if upstream && len(l.GetTrustedCidrs()) == 0 {
			v.addf("%s: an http-upstream listener needs trusted_cidrs, the addresses of the web servers in front of it", name)
		}
		for _, c := range l.GetTrustedCidrs() {
			p, err := rules.ParsePrefix(c)
			if err != nil {
				v.addf("%s: trusted CIDR %.70q is neither a CIDR prefix nor an IP address", name, c)
				continue
			}
			if upstream {
				if err := rules.CheckUpstreamTrusted(p); err != nil {
					v.addf("%s: %v", name, err)
				}
			}
		}
		if _, err := rules.ParsePort(l.GetPort()); err != nil {
			v.addf("%s: port %d is outside 1-65535", name, l.GetPort())
			continue
		}
		// An IPv4-mapped address is the IPv4 address it maps, as the edge
		// binds it.
		ip, err := rules.ParseBindIP(l.GetBindIp())
		switch {
		case err != nil:
			v.addf("%s: bind_ip %.70q is not an IP address", name, l.GetBindIp())
			continue
		case !ip.Is4():
			v.addf("%s: bind_ip %s: IPv6 listeners are not supported", name, ip)
			continue
		case !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsGlobalUnicast():
			v.addf("%s: bind_ip %s cannot be listened on", name, ip)
			continue
		}
		if upstream {
			if err := rules.CheckUpstreamBind(ip); err != nil {
				v.addf("%s: %v", name, err)
				continue
			}
		}
		// An http-upstream listener too: the service range holds the test
		// listeners, which the node allocates there as it pleases.
		if lo, hi := internalPorts(); (ip.IsUnspecified() || ip == netip.AddrFrom4([4]byte{127, 0, 0, 1})) &&
			l.GetPort() >= uint32(lo) && l.GetPort() <= uint32(hi) {
			v.addf("%s: port %d on %s is in the node's internal loopback range %d-%d (engines, SOCKS and test listeners); an http-upstream listener takes a port outside it",
				name, l.GetPort(), ip, lo, hi)
			continue
		}
		a := addr{ip.String(), l.GetPort()}
		if other, dup := byAddr[a]; dup {
			v.addf("%s and listener %.70q have the same address %s:%d", name, other, a.ip, a.port)
			continue
		}
		byAddr[a] = l.GetId()
		ports[l.GetPort()] = append(ports[l.GetPort()], l)
	}
	for _, port := range slices.Sorted(maps.Keys(ports)) {
		group := ports[port]
		if len(group) < 2 {
			continue
		}
		for _, l := range group {
			if a, _ := rules.ParseBindIP(l.GetBindIp()); a.IsUnspecified() {
				v.addf("port %d: listener %.70q on 0.0.0.0 and listeners on specific addresses cannot share a port", port, l.GetId())
				break
			}
		}
	}
	return byID
}

// listenerActions checks that the actions of a listener are ones the node
// knows; not set is the default, mask and drop (the reconciler turns every
// value into one the edge reads, but an unknown one was never asked for).
func (v *validator) listenerActions(name string, l *nodev1.Listener) {
	switch l.GetStrangerAction() {
	case nodev1.StrangerAction_STRANGER_ACTION_UNSPECIFIED, nodev1.StrangerAction_STRANGER_ACTION_MASK,
		nodev1.StrangerAction_STRANGER_ACTION_REJECT, nodev1.StrangerAction_STRANGER_ACTION_DROP:
	default:
		v.addf("%s: stranger_action %d is not mask, reject or drop", name, int32(l.GetStrangerAction()))
	}
	switch l.GetNonTlsAction() {
	case nodev1.NonTlsAction_NON_TLS_ACTION_UNSPECIFIED, nodev1.NonTlsAction_NON_TLS_ACTION_DROP,
		nodev1.NonTlsAction_NON_TLS_ACTION_HTTP400:
	default:
		v.addf("%s: non_tls_action %d is not drop or http400", name, int32(l.GetNonTlsAction()))
	}
}

// maskTarget checks the mask target of a listener: one that the edge reads
// (rules.ParseMaskTarget), and not on the node's internal loopback ports.
func (v *validator) maskTarget(name, target string) {
	if target == "" {
		return
	}
	t, err := rules.ParseMaskTarget(target)
	if err != nil {
		v.addf("%s: %v", name, err)
		return
	}
	if internalTarget(t) {
		lo, hi := internalPorts()
		v.addf("%s: mask target %.70q is an internal port of the node (%d-%d on the loopback): strangers would reach an engine, its API or a SOCKS port of the edge",
			name, target, lo, hi)
	}
}

// internalTarget reports whether a mask target, host:port as
// rules.ParseMaskTarget returns it, is a port of the node's own loopback
// services: localhost, a loopback address or an unspecified one (which Linux
// dials as the host itself), on 20000-40999.
func internalTarget(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	lo, hi := internalPorts()
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n < uint64(lo) || n > uint64(hi) {
		return false
	}
	if host == "localhost" { // folded
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// mtg checks what mtg cannot do (spec 5.5, the mtg driver): it serves fake
// TLS only, has no ad tag and no middle proxy (so no NAT address), takes no
// telemt overrides, and fronts to an IP address only, which it dials directly
// from the node, so that the address has to be one the node's destination
// policy allows (F6, Ruling S5-10): not loopback, private, link-local,
// carrier-grade NAT, unspecified, multicast or broadcast, also when an IPv6
// form carries it.
func (v *validator) mtg(name string, p *nodev1.Proxy) {
	if p.GetType() == nodev1.ProxyType_PROXY_TYPE_WEB {
		v.addf("%s: mtg serves fake TLS only; WEB proxies stay on telemt", name)
	}
	if p.GetAdTag() != "" {
		v.addf("%s: mtg has no ad_tag support; remove the ad_tag or keep telemt", name)
	}
	if p.GetUseMiddleProxy() {
		v.addf("%s: mtg has no middle proxy; turn use_middle_proxy off or keep telemt", name)
	}
	if p.GetNatIp() != "" {
		v.addf("%s: nat_ip is a setting of the middle proxy, which mtg does not have; remove it or keep telemt", name)
	}
	if raw := strings.TrimSpace(p.GetEngineOverridesJson()); raw != "" {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &m); err == nil && len(m) > 0 {
			v.addf("%s: telemt overrides do not apply to mtg; remove engine_overrides_json or keep telemt", name)
		}
	}
	if mask := p.GetMaskTargetOverride(); mask != "" {
		if err := CheckMTGMaskTarget(mask); err != nil {
			v.addf("%s: mask_target_override: %v", name, err)
		}
	}
}

// CheckMTGMaskTarget checks a mask target override of an mtg proxy: an IP
// address, with or without a port (192.0.2.10, 192.0.2.10:8443,
// [2001:db8::10]:8443), that the node's destination policy allows
// (netpolicy.NonPublic). mtg v2.2.8 fronts to an IP address only, and dials it
// from the node itself. The error does not quote more than 70 bytes of s.
func CheckMTGMaskTarget(s string) error {
	host := s
	if _, err := netip.ParseAddr(s); err != nil {
		h, port, serr := net.SplitHostPort(s)
		if serr != nil {
			return fmt.Errorf("%.70q is not an IP address: mtg v2.2.8 fronts to an IP address only", s)
		}
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return fmt.Errorf("%.70q has no valid port (1-65535)", s)
		}
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%.70q is not an IP address: mtg v2.2.8 fronts to an IP address only", s)
	}
	if a.Zone() != "" {
		return fmt.Errorf("%.70q has an IPv6 zone", s)
	}
	if kind := netpolicy.NonPublic(a); kind != "" {
		return fmt.Errorf("%s is not a public address (%s): mtg would connect to it directly from the node", a, kind)
	}
	return nil
}

func (v *validator) egresses(es []*nodev1.Egress) map[string]*nodev1.Egress {
	byID := map[string]*nodev1.Egress{}
	seen := map[string]string{}
	for _, e := range es {
		if e == nil {
			v.addf("an egress is empty")
			continue
		}
		if v.id("egress", e.GetId(), seen) {
			byID[e.GetId()] = e
		}
		name := fmt.Sprintf("egress %.70q", e.GetId())
		switch e.GetKind() {
		case nodev1.EgressKind_EGRESS_KIND_DIRECT:
			if _, err := ParseDirectParams(e.GetParamsJson()); err != nil {
				v.addf("%s: %v", name, err)
			}
		case nodev1.EgressKind_EGRESS_KIND_SOCKS5, nodev1.EgressKind_EGRESS_KIND_HTTP:
			p, err := ParseProxyParams(e.GetParamsJson())
			if err == nil {
				// The edge's rules for the credentials; never quoted.
				if e.GetKind() == nodev1.EgressKind_EGRESS_KIND_SOCKS5 {
					err = rules.CheckSOCKS5Credentials(p.Username, p.Password)
				} else {
					err = rules.CheckHTTPCredentials(p.Username, p.Password)
				}
			}
			if err != nil {
				v.addf("%s: %v", name, err)
			}
		case nodev1.EgressKind_EGRESS_KIND_XRAY_URI:
			if _, err := ParseXrayURIParams(e.GetParamsJson()); err != nil {
				v.addf("%s: %v", name, err)
			}
		case nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION:
			if _, err := ParseSubscriptionParams(e.GetParamsJson()); err != nil {
				v.addf("%s: %v", name, err)
			}
		case nodev1.EgressKind_EGRESS_KIND_WARP:
			if err := ParseWARPParams(e.GetParamsJson()); err != nil {
				v.addf("%s: %v", name, err)
			}
		case nodev1.EgressKind_EGRESS_KIND_PSIPHON:
			if _, err := ParsePsiphonParams(e.GetParamsJson()); err != nil {
				v.addf("%s: %v", name, err)
			}
		case nodev1.EgressKind_EGRESS_KIND_UNSPECIFIED:
			v.addf("%s: kind is not set", name)
		default:
			v.addf("%s: unknown kind %d", name, int32(e.GetKind()))
		}
	}
	return byID
}

func (v *validator) chains(cs []*nodev1.EgressChain, egresses map[string]*nodev1.Egress) map[string]*nodev1.EgressChain {
	byID := map[string]*nodev1.EgressChain{}
	seen := map[string]string{}
	for _, c := range cs {
		if c == nil {
			v.addf("a chain is empty")
			continue
		}
		if v.id("chain", c.GetId(), seen) {
			byID[c.GetId()] = c
		}
		name := fmt.Sprintf("chain %.70q", c.GetId())
		if len(c.GetMemberEgressIds()) == 0 {
			v.addf("%s has no members", name)
		}
		members := map[string]bool{}
		for _, m := range c.GetMemberEgressIds() {
			if _, ok := egresses[m]; !ok {
				v.addf("%s: member egress %.70q does not exist", name, m)
				continue
			}
			if members[m] {
				v.addf("%s: egress %.70q is a member twice", name, m)
			}
			members[m] = true
		}
		for _, dc := range c.GetCheck().GetDcAddrs() {
			if err := CheckHostPort(dc); err != nil {
				v.addf("%s: health check dc_addrs: %.70q: %v", name, dc, err)
			}
		}
	}
	return byID
}

func (v *validator) settings(s *nodev1.NodeSettings, chains map[string]*nodev1.EgressChain) string {
	def := s.GetDefaultChainId()
	if def != "" {
		if _, ok := chains[def]; !ok {
			v.addf("the default chain %.70q does not exist", def)
		}
	}
	for _, c := range s.GetBlacklistCidrs() {
		if _, err := ParseBlacklistEntry(c); err != nil {
			v.addf("blacklist entry %.70q is neither a CIDR nor an IP address", c)
		}
	}
	for _, d := range s.GetDomainPool() {
		if err := checkDomain(d); err != nil {
			v.addf("domain pool: %v", err)
		}
	}
	v.insights(s)
	return def
}

// The bounds of the settings of slice 6.
const (
	// MaxIPRetentionHours bounds NodeSettings.ip_retention_hours;
	// DefaultIPRetentionHours stands for 0.
	MaxIPRetentionHours     = 720
	DefaultIPRetentionHours = 168
	// MaxProbeSources bounds NodeSettings.probe_sources.
	MaxProbeSources = 32
)

// insights checks the statistics settings: the IP policy is one the node
// knows (unspecified is off), ip_retention_hours is 0 or 1-720, a country
// database is named only under a policy that uses countries, with a month
// YYYY-MM and a sha256 of 64 hex digits, and probe_sources are at most 32
// single addresses (ProbeSource). The nonces are free.
func (v *validator) insights(s *nodev1.NodeSettings) {
	policy := s.GetIpPolicy()
	switch policy {
	case nodev1.IpPolicy_IP_POLICY_UNSPECIFIED, nodev1.IpPolicy_IP_POLICY_FULL,
		nodev1.IpPolicy_IP_POLICY_COUNTRIES, nodev1.IpPolicy_IP_POLICY_OFF:
	default:
		v.addf("ip_policy %d is not full, countries or off", int32(policy))
	}
	if h := s.GetIpRetentionHours(); h > MaxIPRetentionHours {
		v.addf("ip_retention_hours %d is outside 1-%d (0 means %d)", h, MaxIPRetentionHours, DefaultIPRetentionHours)
	}
	if g := s.GetGeoip(); g != nil {
		if policy != nodev1.IpPolicy_IP_POLICY_FULL && policy != nodev1.IpPolicy_IP_POLICY_COUNTRIES {
			v.addf("geoip is set while the ip_policy does not use countries (it is off)")
		}
		if !validMonth(g.GetMonth()) {
			v.addf("geoip: month %.70q is not of the form YYYY-MM", g.GetMonth())
		}
		if !isHex(g.GetSha256(), 64) {
			v.addf("geoip: sha256 must be exactly 64 hex characters")
		}
	}
	if n := len(s.GetProbeSources()); n > MaxProbeSources {
		v.addf("probe_sources has %d entries, at most %d are taken", n, MaxProbeSources)
	}
	for _, src := range s.GetProbeSources() {
		if _, err := ProbeSource(src); err != nil {
			v.addf("probe_sources: %v", err)
		}
	}
}

// validMonth accepts YYYY-MM, with a month of 01-12.
func validMonth(s string) bool {
	if len(s) != 7 || s[4] != '-' {
		return false
	}
	for i, c := range []byte(s) {
		if i != 4 && (c < '0' || c > '9') {
			return false
		}
	}
	m := int(s[5]-'0')*10 + int(s[6]-'0')
	return m >= 1 && m <= 12
}

// ProbeSource reads one entry of NodeSettings.probe_sources, a single IPv4 or
// IPv6 address (R6-1: exact addresses only, so a prefix is refused, and so is
// a zone); an IPv4-mapped address is the IPv4 address it maps. The panel
// checks its extra probe sources with it.
func ProbeSource(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		if strings.Contains(s, "/") {
			return netip.Addr{}, fmt.Errorf("%.70q is a prefix; a probe source is a single IP address", s)
		}
		return netip.Addr{}, fmt.Errorf("%.70q is not a single IP address", s)
	}
	return a.Unmap(), nil
}

func (v *validator) proxies(ps []*nodev1.Proxy, listeners map[string]*nodev1.Listener, chains map[string]*nodev1.EgressChain, defaultChain string) {
	seen := map[string]string{}
	type domainKey struct{ listener, domain string }
	domains := map[domainKey]string{}
	for _, p := range ps {
		if p == nil {
			v.addf("a proxy is empty")
			continue
		}
		v.id("proxy", p.GetId(), seen)
		name := fmt.Sprintf("proxy %.70q", p.GetId())

		listener, listenerOK := listeners[p.GetListenerId()]
		upstream := listenerOK && listener.GetKind() == nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM
		typeOK := false
		switch p.GetType() {
		case nodev1.ProxyType_PROXY_TYPE_FAKETLS:
			typeOK = true
			if upstream {
				v.addf("%s: a fake-TLS proxy cannot be on http-upstream listener %.70q, which takes plain HTTP for WEB proxies", name, p.GetListenerId())
			}
		case nodev1.ProxyType_PROXY_TYPE_WEB:
			typeOK = true
			v.web(name, p, upstream)
		default:
			v.addf("%s: type is not set", name)
		}

		engineOK := false
		switch p.GetEngine() {
		case nodev1.Engine_ENGINE_TELEMT:
			engineOK = true
		case nodev1.Engine_ENGINE_MTG:
			engineOK = true
			v.mtg(name, p)
		case nodev1.Engine_ENGINE_UNSPECIFIED:
			v.addf("%s: engine is not set", name)
		default:
			v.addf("%s: unknown engine %s", name, p.GetEngine())
		}
		if typeOK && engineOK && (v.supports == nil || !v.supports(p.GetEngine(), p.GetType())) {
			v.addf("%s: engine %s does not support %s proxies", name, p.GetEngine(), p.GetType())
		}
		if !validVersion(p.GetEngineVersion()) {
			v.addf("%s: engine version %.70q is not valid", name, p.GetEngineVersion())
		}

		if !isHex(p.GetSecret(), 32) {
			v.addf("%s: the secret must be exactly 32 hex characters", name)
		}
		if tag := p.GetAdTag(); tag != "" && !isHex(tag, 32) {
			v.addf("%s: the ad_tag must be empty or exactly 32 hex characters", name)
		}
		// The whitelist is the one that the panel checks against, and the telemt
		// driver renders from (internal/engines/telemt/overrides).
		if _, problems := overrides.Parse(p.GetEngineOverridesJson()); len(problems) > 0 {
			for _, problem := range problems {
				v.addf("%s: %s", name, problem.Msg)
			}
		}
		if nat := p.GetNatIp(); nat != "" {
			a, err := netip.ParseAddr(nat)
			if err != nil || a.Zone() != "" || !a.Unmap().IsGlobalUnicast() {
				v.addf("%s: nat_ip %.70q is not a usable unicast IP address", name, nat)
			}
		}

		if err := checkDomain(p.GetDomain()); err != nil {
			v.addf("%s: %v", name, err)
		}
		if !listenerOK {
			v.addf("%s: listener %.70q does not exist", name, p.GetListenerId())
		} else if p.GetDomain() != "" {
			k := domainKey{p.GetListenerId(), FoldDomain(p.GetDomain())}
			if other, dup := domains[k]; dup {
				v.addf("%s: domain %.70q is already used by proxy %.70q on listener %.70q", name, p.GetDomain(), other, p.GetListenerId())
			} else {
				domains[k] = p.GetId()
			}
		}

		if c := p.GetEgressChainId(); c != "" {
			if _, ok := chains[c]; !ok {
				v.addf("%s: egress chain %.70q does not exist", name, c)
			}
		} else if defaultChain == "" {
			v.addf("%s: no egress chain (set egress_chain_id or the node's default chain)", name)
		}
		for _, scope := range slices.Sorted(maps.Keys(p.GetEgressScopeChains())) {
			c := p.GetEgressScopeChains()[scope]
			if scope == "" {
				v.addf("%s: a scope chain has an empty scope", name)
			}
			if _, ok := chains[c]; !ok {
				v.addf("%s: egress chain %.70q of scope %.70q does not exist", name, c, scope)
			}
		}
	}
}

// web checks the settings of a WEB proxy (webrules): web settings present; a
// domain of at least two labels that names a certificate directory and a
// vhost (webrules.CertDomain; only when checkDomain took it, so that a bad
// domain is reported once); base_path, secret_mode, carrier and carriers as
// telemt takes them; public_addr, when the panel names it, a public IPv4
// address with port 443 at most. On an http-upstream listener base_path is
// required and cert_mode is not looked at (the web server in front owns the
// certificate); on a tls listener cert_mode is acme-dns01, with a
// dns_credential, or imported, with the cert_sha256 of the chain that
// PutCertificate stored (Ruling S3-1). reissue_nonce is for acme-dns01 only. Nothing of dns_credential is quoted.
func (v *validator) web(name string, p *nodev1.Proxy, upstream bool) {
	w := p.GetWeb()
	if w == nil {
		v.addf("%s: a web proxy needs web settings", name)
		return
	}
	if checkDomain(p.GetDomain()) == nil {
		if _, err := webrules.CertDomain(p.GetDomain()); err != nil {
			v.addf("%s: %v", name, err)
		}
	}
	for _, err := range []error{
		webrules.CheckBasePath(w.GetBasePath()), webrules.CheckSecretMode(w.GetSecretMode()),
		webrules.CheckCarrier(w.GetCarrier()), webrules.CheckCarriers(w.GetCarriers()),
	} {
		if err != nil {
			v.addf("%s: %v", name, err)
		}
	}
	if w.GetPublicAddr() != "" {
		if _, err := webrules.ParsePublicAddr(w.GetPublicAddr()); err != nil {
			v.addf("%s: %v", name, err)
		}
	}
	if upstream {
		if w.GetBasePath() == "" {
			v.addf("%s: base_path is required for a web proxy on an http-upstream listener (it lives under a path of the site in front)", name)
		}
		if w.GetReissueNonce() != 0 {
			v.addf("%s: reissue_nonce is for cert_mode %s only: on an http-upstream listener the web server in front owns the certificate", name, webrules.CertModeACME)
		}
		return
	}
	switch w.GetCertMode() {
	case webrules.CertModeACME:
		if w.GetDnsCredential() == "" {
			v.addf("%s: cert_mode %s needs a dns_credential", name, webrules.CertModeACME)
		}
	case webrules.CertModeImported:
		if !isHex(w.GetCertSha256(), 64) {
			v.addf("%s: cert_mode %s needs cert_sha256, the SHA-256 of the stored fullchain.pem as 64 hex digits", name, webrules.CertModeImported)
		}
		if w.GetReissueNonce() != 0 {
			v.addf("%s: reissue_nonce is for cert_mode %s only: an imported certificate is not issued by the node", name, webrules.CertModeACME)
		}
	default:
		v.addf("%s: cert_mode %.40q is neither %q nor %q", name, w.GetCertMode(), webrules.CertModeACME, webrules.CertModeImported)
	}
}

// ---- egress parameters ----------------------------------------------------------

// DirectParams are the parameters of a DIRECT egress: an optional interface
// to bind to (SO_BINDTODEVICE) and an optional source address.
type DirectParams struct {
	Interface string `json:"interface"`
	BindIP    string `json:"bind_ip"`
}

// ProxyParams are the parameters of a SOCKS5 or HTTP egress. Password is a
// credential: never log it.
type ProxyParams struct {
	Addr     string `json:"addr"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ParseDirectParams reads the params_json of a DIRECT egress; empty means no
// parameters. Errors never quote the input.
func ParseDirectParams(raw string) (DirectParams, error) {
	var p DirectParams
	if err := decodeParams(raw, &p); err != nil {
		return DirectParams{}, err
	}
	if p.Interface != "" && !validInterface(p.Interface) {
		return DirectParams{}, fmt.Errorf("interface %.70q is not a valid interface name", p.Interface)
	}
	if p.BindIP != "" {
		if a, err := netip.ParseAddr(p.BindIP); err != nil || a.Zone() != "" {
			return DirectParams{}, fmt.Errorf("bind_ip %.70q is not an IP address", p.BindIP)
		}
	}
	return p, nil
}

// ParseProxyParams reads the params_json of a SOCKS5 or HTTP egress: addr
// (host:port) is required. Errors never quote the input.
func ParseProxyParams(raw string) (ProxyParams, error) {
	var p ProxyParams
	if err := decodeParams(raw, &p); err != nil {
		return ProxyParams{}, err
	}
	if p.Addr == "" {
		return ProxyParams{}, fmt.Errorf("params_json has no addr")
	}
	if err := CheckHostPort(p.Addr); err != nil {
		return ProxyParams{}, fmt.Errorf("addr: %v", err)
	}
	return p, nil
}

// decodeParams decodes a JSON object; the error says nothing about the content,
// which may hold credentials.
func decodeParams(raw string, into any) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(raw), into); err != nil {
		return fmt.Errorf("params_json is not a valid JSON object of the expected fields")
	}
	return nil
}

// ParseBlacklistEntry reads a blacklist entry, a CIDR or a single address, as
// the edge reads it (rules.ParsePrefix): a single address becomes a /32 or a
// /128, the host bits of a prefix are cleared, and a prefix of IPv4-mapped
// addresses is the IPv4 prefix.
func ParseBlacklistEntry(s string) (netip.Prefix, error) {
	return rules.ParsePrefix(s)
}

// internalPorts is the span of the loopback port ranges the node's own
// services use (20000-40999). A listener on 0.0.0.0 or 127.0.0.1 there would
// collide with an engine, the edge's SOCKS ports or a test listener.
func internalPorts() (lo, hi uint16) {
	lo, hi = 65535, 0
	for _, r := range defaultRanges {
		lo, hi = min(lo, r.First), max(hi, r.Last)
	}
	return lo, hi
}

// ---- syntax -----------------------------------------------------------------

// validID accepts 1 to 64 characters of [A-Za-z0-9._-], starting with a letter
// or digit: safe in a container name, a label and a path element.
func validID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// validVersion accepts an engine version that can name a directory of the
// artifact store: 1 to 64 characters of [A-Za-z0-9._+-], starting with a letter
// or digit.
func validVersion(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-' || c == '+'):
		default:
			return false
		}
	}
	return true
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// checkDomain is the policy for a proxy domain and a domain of the pool. A domain
// is the SNI that the edge routes by, the name that it masks for strangers (the
// domain of every proxy and of the pool is a mask domain, paused proxies
// included), and the TLS domain of the engine. The edge takes a name of ASCII
// letters, digits, hyphens and dots only, in labels of 1 to 63 bytes, with one dot
// at the end at most, and refuses its whole table, with every proxy on the node,
// for a route or a mask domain that it cannot take. So the node takes exactly what
// the edge takes, by the edge's own rule (rules.CheckName): at most 253 bytes, the
// dot at the end counted, of [A-Za-z0-9.-], in labels of 1 to 63 bytes.
//
// One dot at the end is the same name to the edge, which folds it away, and a
// domain that a proxy keeps with its link, byte for byte, may have one:
// it is taken, kept as it is, and compared by its folded form (FoldDomain). Two
// dots at the end are not a name. Letter case is kept too.
func checkDomain(s string) error {
	switch rules.CheckName(s) {
	case rules.NameOK:
		return nil
	case rules.NameEmpty:
		return fmt.Errorf("the domain is empty")
	case rules.NameTooLong:
		return fmt.Errorf("the domain is longer than %d bytes", rules.MaxNameLen)
	case rules.NameLongLabel:
		return fmt.Errorf("the domain %.70q has a label longer than %d bytes", s, rules.MaxLabelLen)
	case rules.NameEmptyLabel:
		return fmt.Errorf("the domain %.70q has an empty label (a dot at its start, or two dots in a row)", s)
	default:
		return fmt.Errorf("the domain %.70q has a character that is not allowed in a name: only ASCII letters, digits, hyphens and dots are", s)
	}
}

// FoldDomain is the form in which the edge compares server names, rules.Fold:
// ASCII letters in lower case, and without the one dot that a fully qualified
// name may end with. Domains that fold to the same form are one name: two
// proxies of a listener with such domains are two routes of one name, for which
// the edge refuses its whole table, so a route is keyed by its folded domain
// and uniqueness is judged on it. Only ASCII letters are folded, as the edge
// does: strings.ToLower would also fold the Kelvin sign (U+212A) into a k, and
// any other byte stays as it is, so that two different invalid names are not
// taken for one.
func FoldDomain(s string) string { return rules.Fold(s) }

// validInterface accepts a Linux interface name: 1 to 15 bytes, no slash, no
// space or control character, not "." or "..".
func validInterface(s string) bool {
	if s == "" || len(s) > 15 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if r == '/' || r == ':' || unicode.IsSpace(r) || unicode.IsControl(r) || r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// CheckHostPort is how the node reads "host:port", the address of a proxy and
// of a datacenter of a health check: as the edge does (rules.ParseHostPort: a
// host that is an IP address or a name and can stand in a request, a port
// 1-65535, brackets for an IPv6 address only), and it refuses a host with a
// space or a control character beyond ASCII as well. The panel checks such
// addresses with it. The errors do not quote s.
func CheckHostPort(s string) error {
	host, _, err := rules.ParseHostPort(s)
	if err != nil {
		return err
	}
	if strings.ContainsFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return fmt.Errorf("the host has a space or a control character")
	}
	return nil
}

// The artifact sources of a node (NodeSettings.artifact_source).
const (
	// ArtifactSourcePanel: the panel uploads the artifacts. The default.
	ArtifactSourcePanel = "panel"
	// ArtifactSourceDirect: the node downloads the artifacts from their url
	// itself; the panel uploads what it still lacks at its next resync.
	ArtifactSourceDirect = "direct"
)

// ArtifactSourceOf returns the artifact source of the settings:
// ArtifactSourcePanel when it is not set.
func ArtifactSourceOf(s *nodev1.NodeSettings) string {
	if s.GetArtifactSource() == "" {
		return ArtifactSourcePanel
	}
	return s.GetArtifactSource()
}

// artifactSource checks the artifact source.
func (v *validator) artifactSource(s *nodev1.NodeSettings) {
	switch s.GetArtifactSource() {
	case "", ArtifactSourcePanel, ArtifactSourceDirect:
	default:
		v.addf("artifact_source %.70q is neither %q nor %q", s.GetArtifactSource(), ArtifactSourcePanel, ArtifactSourceDirect)
	}
}
