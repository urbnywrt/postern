package proxies

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/webrules"
)

// The egress and the chain that every node has while it has no default chain
// of its own: the edge dials Telegram directly.
const (
	ImplicitEgressID = "direct"
	ImplicitChainID  = "default"
)

// defaultArch is the architecture of a node that has not said which it has.
const defaultArch = "amd64"

// DefaultDomainPool is the pool of domains that a new proxy gets one of when
// its request names none: well-known sites, so that the fake TLS of a proxy
// looks like a visit to one of them. A node also relays strangers that ask for
// a domain of the pool to the real site (stranger action mask).
var DefaultDomainPool = []string{
	"www.microsoft.com",
	"www.apple.com",
	"www.cloudflare.com",
	"www.wikipedia.org",
	"www.mozilla.org",
	"www.github.com",
	"www.amazon.com",
	"www.bing.com",
}

// nodeDataMu makes what the state of a node is made of change all at once:
// the mutations of the services hold it for writing from reading the data of
// the node to raising its generation, and the state builder holds it for
// reading while it reads, so that it never sees half of a change (a proxy on
// a listener that it has not read yet).
var nodeDataMu sync.RWMutex

// errSecret marks a secret that cannot be opened: a fault of the panel (another
// master key), not of the data.
var errSecret = errors.New("a proxy secret cannot be opened")

// nodeData is what the desired state of a node is made of.
type nodeData struct {
	node      *store.Node
	listeners []*store.Listener
	proxies   []*store.Proxy
	secrets   map[string]string // proxy id → secret
	bad       map[string]error  // proxy id → why its secret cannot be opened
	// tokens are the DNS tokens of the credentials that the proxies of the
	// node use, by credential id; badTokens says why one cannot be had.
	tokens    map[string]string
	badTokens map[string]error
	// eg is every egress and chain of the panel: the state takes those that
	// the node uses.
	eg *egressData
	// ch is the versions of the channels and the default channel: what the
	// proxies and the providers of the node run (versions.go).
	ch *channelData
	// held are the providers that the state builder holds at the version
	// their instance runs, by component (holdBack); nil when none.
	held map[string]string
	// pool is the own domain pool of the node, nil for the default one, and
	// blacklist its blacklist (the entries for every node and its own).
	pool, blacklist []string
}

// loadNodeData reads the data of a node and opens the secrets of its proxies.
// A secret that cannot be opened is noted rather than an error, so that the
// proxy can still be deleted. The node is read last: a node that is deleted
// meanwhile is store.ErrNotFound, never an empty node.
func loadNodeData(ctx context.Context, db *store.DB, key seal.Key, nodeID string) (*nodeData, error) {
	if nodeID == "" {
		// The lists below would be those of every node.
		return nil, fmt.Errorf("%w: no node id", store.ErrNotFound)
	}
	eg, err := loadEgressData(ctx, db, key)
	if err != nil {
		return nil, err
	}
	ch, err := loadChannelData(ctx, db)
	if err != nil {
		return nil, err
	}
	ls, err := db.ListListeners(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	ps, err := db.ListProxies(ctx, store.ProxyFilter{NodeID: nodeID})
	if err != nil {
		return nil, err
	}
	n, err := db.NodeByID(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	nd := &nodeData{node: n, listeners: ls, proxies: ps, secrets: make(map[string]string, len(ps)), bad: map[string]error{},
		tokens: map[string]string{}, badTokens: map[string]error{}, eg: eg, ch: ch}
	if nd.pool, err = db.NodeDomainPool(ctx, nodeID); err != nil {
		return nil, err
	}
	if nd.blacklist, err = db.NodeBlacklist(ctx, nodeID); err != nil {
		return nil, err
	}
	for _, p := range ps {
		s, err := openSecret(key, p)
		if err != nil {
			nd.bad[p.ID] = err
			continue
		}
		nd.secrets[p.ID] = s
	}
	for _, p := range ps {
		id := p.DNSCredentialID
		if id == "" || p.Type != store.ProxyTypeWeb {
			continue
		}
		if _, seen := nd.tokens[id]; seen {
			continue
		}
		if _, seen := nd.badTokens[id]; seen {
			continue
		}
		c, err := db.DNSCredentialByID(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				nd.badTokens[id] = fmt.Errorf("%w: credential %s: %w", errDNSCredential, id, err)
				continue
			}
			return nil, err
		}
		token, err := OpenDNSToken(key, c)
		if err != nil {
			nd.badTokens[id] = err
			continue
		}
		nd.tokens[id] = token
	}
	return nd, nil
}

// token returns the DNS token of a credential that a proxy of the node uses.
func (nd *nodeData) token(id string) (string, error) {
	if err := nd.badTokens[id]; err != nil {
		return "", err
	}
	t, ok := nd.tokens[id]
	if !ok {
		return "", fmt.Errorf("%w: credential %s is not loaded", errDNSCredential, id)
	}
	return t, nil
}

// SecretAAD is the additional data that a proxy secret is sealed with: it
// opens for its own proxy only.
func SecretAAD(proxyID string) []byte {
	return []byte("proxy:" + proxyID)
}

// openSecret opens the sealed secret of a proxy.
func openSecret(key seal.Key, p *store.Proxy) (string, error) {
	plain, err := seal.Open(key, p.SecretEnc, SecretAAD(p.ID))
	if err != nil {
		return "", fmt.Errorf("%w: proxy %s: %w", errSecret, p.ID, err)
	}
	defer clear(plain)
	return string(plain), nil
}

func (nd *nodeData) listener(id string) *store.Listener {
	for _, l := range nd.listeners {
		if l.ID == id {
			return l
		}
	}
	return nil
}

func (nd *nodeData) proxy(id string) *store.Proxy {
	for _, p := range nd.proxies {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// secret returns the secret of a proxy.
func (nd *nodeData) secret(id string) (string, error) {
	if err := nd.bad[id]; err != nil {
		return "", err
	}
	s, ok := nd.secrets[id]
	if !ok {
		return "", fmt.Errorf("%w: proxy %s has no secret", errSecret, id)
	}
	return s, nil
}

// StateBuilder builds the desired state of a node from the data of the panel.
// It is the StateBuilder of the node manager.
type StateBuilder struct {
	db      *store.DB
	key     seal.Key
	catalog *Catalog
	reports *Ingestor // what the nodes run; nil until SetReports
	geo     GeoIP     // the country database; none until SetGeoIP
	log     *slog.Logger
	pool    []string
}

// capStatsV2 is the capability of a node that takes a country database
// (NodeSettings.geoip, UploadGeoIP).
const capStatsV2 = "stats-v2"

// GeoIP is what the proxies use of the country database of the panel, as
// functions that the server sets at wiring: the country of an address ("" for
// none), and the database that the nodes are to look addresses up in (nil for
// none). A nil function is no database.
type GeoIP struct {
	Country func(netip.Addr) string
	Ref     func() *nodev1.GeoIPRef
}

// country is the country of an address, "" without a database.
func (g GeoIP) country(a netip.Addr) string {
	if g.Country == nil {
		return ""
	}
	return g.Country(a)
}

// ref is the database that the nodes are to use, nil for none.
func (g GeoIP) ref() *nodev1.GeoIPRef {
	if g.Ref == nil {
		return nil
	}
	return g.Ref()
}

// SetGeoIP gives the builder the country database, whose reference goes to the
// nodes that take one. It is set before the node manager starts.
func (b *StateBuilder) SetGeoIP(g GeoIP) { b.geo = g }

// SetReports gives the builder the ingestor, so that it can hold a proxy or a
// provider at the version its node runs while the version it is to run is not
// ready, or is unusable (holdBack). Without one every state names the
// effective versions.
func (b *StateBuilder) SetReports(in *Ingestor) { b.reports = in }

// NewStateBuilder returns the state builder on the database. key opens the
// proxy secrets, and catalog gives the engine versions and their artifacts. A
// nil log discards the log.
func NewStateBuilder(db *store.DB, key seal.Key, catalog *Catalog, log *slog.Logger) *StateBuilder {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &StateBuilder{db: db, key: key, catalog: catalog, log: log, pool: DefaultDomainPool}
}

// Build returns the desired state of a node, stamped with generation:
//
//   - settings: the default chain of the node, or the implicit one, the domain
//     pool, the management SNI, the DNS mode and the edge roll nonce of the
//     node, and the statistics settings (statsSettings: the IP policy, the
//     retention of addresses, the country database, the probe sources);
//   - the chains that the node uses (its default chain, the chains and the
//     scope chains of its proxies) with the egresses that they have and their
//     decrypted parameters, and the implicit egress "direct" and the chain
//     "default" made of it while the node has no default chain of its own;
//   - every listener, and every proxy with its enabled flag, its decrypted
//     secret and its chains, on its engine at its effective version (pinned,
//     held by a rollout, or the version of the engine on the channel of the
//     node; EffectiveVersion), with the middle proxies of Telegram as its
//     setting says (auto is when it has an ad tag), and with its engine
//     overrides, and its restart nonce;
//   - one artifact per (engine, version) that the proxies use, and one of
//     each provider that the egresses need (Xray, psiphon-core) at the version
//     of the node (ProviderVersion), for the architecture of the node (amd64
//     until the node has said): named whenever the catalog pins a SHA-256 for
//     it, ready or not (F10).
//
// It never returns a state that the node would refuse: data that would make
// one (rows that the services do not write, such as an IPv6 listener or two
// proxies with one domain on a listener) is an error, by the node's own rules
// (validateState). So is a stored value that this version does not know (see
// listenerKind and useMiddleProxy), a secret or egress parameters that cannot
// be opened, and a chain or an egress that is missing or belongs to another
// node.
func (b *StateBuilder) Build(ctx context.Context, nodeID string, generation uint64) (*nodev1.NodeState, error) {
	nodeDataMu.RLock()
	nd, err := loadNodeData(ctx, b.db, b.key, nodeID)
	nodeDataMu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("proxies: build the state of node %s: %w", nodeID, err)
	}
	return b.build(ctx, nd, generation)
}

// build makes the state of a node of the data that was read.
func (b *StateBuilder) build(ctx context.Context, nd *nodeData, generation uint64) (*nodev1.NodeState, error) {
	st, err := assemble(nd, b.pool)
	if err == nil {
		b.statsSettings(ctx, st, nd.node)
		err = validateState(st)
	}
	if err != nil {
		return nil, fmt.Errorf("proxies: build the state of node %s: %w", nd.node.ID, err)
	}
	st.Generation = generation
	arch := cmp.Or(nd.node.Arch, defaultArch)
	if err := b.holdBack(ctx, st, nd, arch); err != nil {
		return nil, fmt.Errorf("proxies: build the state of node %s: %w", nd.node.ID, err)
	}
	var missing []string
	st.Artifacts, missing, err = artifactsFor(ctx, st, nd, arch, b.catalog)
	if err != nil {
		return nil, fmt.Errorf("proxies: build the state of node %s: %w", nd.node.ID, err)
	}
	if st.GetSettings().GetArtifactSource() != store.ArtifactSourceDirect {
		// Only a node that downloads for itself gets the urls (R5-1).
		for _, a := range st.Artifacts {
			a.Url = ""
		}
	}
	for _, m := range missing {
		// The node reports the proxies of this engine version as failed,
		// with the reason; the rest of the state is good.
		b.log.Warn("the catalog has no artifact for the architecture of the node", "node", nd.node.ID, "artifact", m, "arch", arch)
	}
	return st, nil
}

// statsSettings puts the statistics settings into the settings of a state:
//
//   - ip_policy, the policy of the panel;
//   - ip_retention_hours, the days that addresses are kept, in hours;
//   - geoip, the country database of the panel, only for a node that takes one
//     (capability stats-v2) and while the policy uses countries;
//   - probe_sources, the addresses that the node saw the panel come from and
//     the extra probe sources, each once.
//
// Settings that cannot be read are the policy off, with addresses kept for a
// day, and only the addresses of the panel as probe sources: what is not known
// to be allowed is not kept.
func (b *StateBuilder) statsSettings(ctx context.Context, st *nodev1.NodeState, n *store.Node) {
	s, _, err := b.db.StatsSettings(ctx)
	if err != nil {
		b.log.Error("could not read the statistics settings; the node is told the IP policy off", "node", n.ID, "err", err)
		s = store.StatsSettings{IPPolicy: store.IPPolicyOff, IPDays: 1}
	}
	set := st.GetSettings()
	set.IpPolicy = ipPolicyOf(s.IPPolicy)
	set.IpRetentionHours = s.IPDays * 24
	set.Geoip = nil
	if (s.IPPolicy == store.IPPolicyFull || s.IPPolicy == store.IPPolicyCountries) && slices.Contains(n.HostInfo.Capabilities, capStatsV2) {
		if ref := b.geo.ref(); ref != nil {
			set.Geoip = &nodev1.GeoIPRef{Month: ref.GetMonth(), Sha256: ref.GetSha256()}
		}
	}
	set.ProbeSources = nil
	for _, a := range slices.Concat(n.PanelAddrs, s.ExtraProbeSources) {
		if !slices.Contains(set.ProbeSources, a) {
			set.ProbeSources = append(set.ProbeSources, a)
		}
	}
}

// ipPolicyOf is the IP policy of the panel as the node has it; one that the
// panel does not know is off.
func ipPolicyOf(p string) nodev1.IpPolicy {
	switch p {
	case store.IPPolicyFull:
		return nodev1.IpPolicy_IP_POLICY_FULL
	case store.IPPolicyCountries:
		return nodev1.IpPolicy_IP_POLICY_COUNTRIES
	}
	return nodev1.IpPolicy_IP_POLICY_OFF
}

// holdBack keeps a proxy, or a provider, at the version that the node reports
// it running while the version it is to run is not ready, or is recorded
// unusable, for the architecture of the node: a desired state never moves a
// running instance to a version that the catalog cannot give the node. A
// proxy or a provider that the node does not report running, or reports at
// the version it is to run already, keeps that version: it is named ready or
// not (F10), so that the upload follows. The held providers go into nd.held,
// for artifactsFor.
func (b *StateBuilder) holdBack(ctx context.Context, st *nodev1.NodeState, nd *nodeData, arch string) error {
	if b.reports == nil || b.catalog == nil || b.catalog.rel == nil {
		return nil
	}
	usable := func(component, version string) (bool, error) {
		err := b.catalog.Ready(ctx, component, version, arch)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, releases.ErrNotReady), errors.Is(err, releases.ErrUnusable), errors.Is(err, releases.ErrUnknown), errors.Is(err, releases.ErrNoPin):
			return false, nil
		}
		return false, err
	}
	for _, p := range st.GetProxies() {
		rep, ok := b.reports.ProxyReport(nd.node.ID, p.GetId())
		if !ok || rep.RunningVersion == "" || rep.RunningVersion == p.GetEngineVersion() || rep.RunningEngine != p.GetEngine() {
			continue
		}
		ok, err := usable(engineName(p.GetEngine()), p.GetEngineVersion())
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		b.log.Warn("a proxy is held at the version it runs: the version it is to run is not ready for the node",
			"node", nd.node.ID, "proxy", p.GetId(), "engine", engineName(p.GetEngine()), "runs", rep.RunningVersion, "wanted", p.GetEngineVersion())
		p.EngineVersion = rep.RunningVersion
	}
	running := map[string]string{} // provider → the version its instance runs
	for _, eg := range b.reports.EgressReports(nd.node.ID) {
		if eg.Version != "" {
			running[eg.Provider] = eg.Version
		}
	}
	for _, e := range st.GetEgresses() {
		provider := providerOf(e.GetKind())
		if provider == "" || nd.held[provider] != "" {
			continue
		}
		runs, wanted := running[provider], nd.ch.provider(nd.node, provider)
		if runs == "" || runs == wanted {
			continue
		}
		ok, err := usable(provider, wanted)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		b.log.Warn("a provider is held at the version it runs: the version it is to run is not ready for the node",
			"node", nd.node.ID, "provider", provider, "runs", runs, "wanted", wanted)
		if nd.held == nil {
			nd.held = map[string]string{}
		}
		nd.held[provider] = runs
	}
	return nil
}

// assemble makes the state of a node without its generation and artifacts. It
// shares nothing with nd that a change of nd could change.
func assemble(nd *nodeData, pool []string) (*nodev1.NodeState, error) {
	st := &nodev1.NodeState{
		Settings: &nodev1.NodeSettings{
			DefaultChainId: cmp.Or(nd.node.DefaultChainID, ImplicitChainID),
			DomainPool:     slices.Clone(pool),
			BlacklistCidrs: slices.Clone(nd.blacklist),
			IpPolicy:       nodev1.IpPolicy_IP_POLICY_OFF,
			MgmtSni:        nd.node.MgmtSNI,
			MgmtHiddenOnly: nd.node.MgmtMode == store.MgmtModeHidden,
			DnsMode:        nd.node.DNSMode,
			ArtifactSource: directOrEmpty(nd.node.ArtifactSource),
			EdgeRollNonce:  nd.node.EdgeRollNonce,
		},
	}
	if len(nd.pool) > 0 {
		st.Settings.DomainPool = slices.Clone(nd.pool)
	}
	if err := nd.addEgresses(st); err != nil {
		return nil, err
	}
	for _, l := range nd.listeners {
		kind, err := listenerKind(l.Kind)
		if err != nil {
			return nil, fmt.Errorf("listener %s: %w", l.ID, err)
		}
		stranger, err := strangerAction(l.StrangerAction)
		if err != nil {
			return nil, fmt.Errorf("listener %s: %w", l.ID, err)
		}
		nonTLS, err := nonTLSAction(l.NonTLSAction)
		if err != nil {
			return nil, fmt.Errorf("listener %s: %w", l.ID, err)
		}
		st.Listeners = append(st.Listeners, &nodev1.Listener{
			Id:             l.ID,
			Kind:           kind,
			BindIp:         l.BindIP,
			Port:           l.Port,
			StrangerAction: stranger,
			MaskTarget:     l.MaskTarget,
			NonTlsAction:   nonTLS,
			TrustedCidrs:   slices.Clone(l.TrustedCIDRs),
		})
	}
	for _, p := range nd.proxies {
		typ, err := proxyType(p.Type)
		if err != nil {
			return nil, fmt.Errorf("proxy %s: %w", p.ID, err)
		}
		engine, err := engineOf(p.Engine)
		if err != nil {
			return nil, fmt.Errorf("proxy %s: %w", p.ID, err)
		}
		secret, err := nd.secret(p.ID)
		if err != nil {
			return nil, err
		}
		overrides := ""
		if len(p.EngineOverrides) > 0 {
			raw, err := json.Marshal(p.EngineOverrides) // keys in order: the same overrides are the same text
			if err != nil {
				return nil, fmt.Errorf("proxy %s: engine overrides: %w", p.ID, err)
			}
			overrides = string(raw) // checked against the whitelist by validateState
		}
		middleProxy, err := useMiddleProxy(p)
		if err != nil {
			return nil, err
		}
		web, err := nd.webSettings(p)
		if err != nil {
			return nil, err
		}
		st.Proxies = append(st.Proxies, &nodev1.Proxy{
			Id:            p.ID,
			ListenerId:    p.ListenerID,
			Type:          typ,
			Enabled:       p.Enabled,
			Secret:        secret,
			Domain:        p.Domain,
			Engine:        engine,
			EngineVersion: nd.ch.effective(nd.node, p).Version,
			Limits: &nodev1.Limits{
				Devices:    p.LimitDevices,
				ConnsTotal: p.LimitConnsTotal,
				ConnsPerIp: p.LimitConnsPerIP,
			},
			AdTag:               p.AdTag,
			MaskTargetOverride:  p.MaskTargetOverride,
			NatIp:               p.NATIP,
			UseMiddleProxy:      middleProxy,
			EngineOverridesJson: overrides,
			EgressChainId:       p.EgressChainID,
			EgressScopeChains:   scopeChainsOf(p),
			Web:                 web,
			RestartNonce:        p.RestartNonce,
		})
	}
	return st, nil
}

// webSettings are the WEB settings of a proxy as the node has them: nil for
// a fake-TLS proxy. On a tls listener the certificate mode goes with its DNS
// token (opened) or the digest of the imported chain (Ruling S3-1); on an
// http-upstream listener the web server in front owns the certificate, and
// none of that is sent. The carriers offered are left to the node (its
// default, https-lanes). public_addr is left to the node, which resolves the
// domain when it applies the state.
func (nd *nodeData) webSettings(p *store.Proxy) (*nodev1.WebSettings, error) {
	if p.Type != store.ProxyTypeWeb {
		return nil, nil
	}
	w := &nodev1.WebSettings{
		BasePath:   p.WebBasePath,
		SecretMode: p.WebSecretMode,
		Carrier:    p.WebCarrier,
	}
	if l := nd.listener(p.ListenerID); l != nil && l.Kind == store.ListenerKindHTTPUpstream {
		return w, nil
	}
	w.CertMode, w.AcmeEmail, w.CertSha256 = p.CertMode, p.ACMEEmail, p.CertSHA256
	w.PublicAddr = p.WebPublicAddr
	if p.CertMode == webrules.CertModeACME {
		w.ReissueNonce = p.CertReissueNonce // the fix reissue_cert; the node refuses it otherwise
	}
	if p.DNSCredentialID != "" {
		token, err := nd.token(p.DNSCredentialID)
		if err != nil {
			return nil, err
		}
		w.DnsCredential = token
	}
	return w, nil
}

// useMiddleProxy is whether the node is told to start the engine of a proxy with
// the middle proxies of Telegram: as the setting of the proxy says, and, for auto
// (which an empty setting is), when it has an ad tag. A setting that the panel
// does not know is an error, since the node must not be told a guess.
func useMiddleProxy(p *store.Proxy) (bool, error) {
	switch p.UseMiddleProxy {
	case store.MiddleProxyOn:
		return true, nil
	case store.MiddleProxyOff:
		return false, nil
	case store.MiddleProxyAuto, "":
		return p.AdTag != "", nil
	}
	return false, fmt.Errorf("proxy %s: the middle-proxy setting %.20q is not one that the panel knows", p.ID, p.UseMiddleProxy)
}

// scopeChainsOf returns the scope chains of a proxy as the node has them: a
// copy, without the scopes that have no chain; nil for none.
func scopeChainsOf(p *store.Proxy) map[string]string {
	var out map[string]string
	for scope, chain := range p.EgressScopeChains {
		if chain == "" {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[scope] = chain
	}
	return out
}

// artifactsFor returns the artifacts of the engine versions that the proxies
// of a state use, and of the providers that its egresses need (Xray for
// xray-uri, xray-subscription and warp, psiphon-core for psiphon, at the
// versions of the node), for arch, ordered by engine and version: every one
// that the catalog pins a SHA-256 for, ready or not. missing names those that
// the catalog does not have, or has not pinned for the architecture. An error
// is one of reading the catalog.
func artifactsFor(ctx context.Context, st *nodev1.NodeState, nd *nodeData, arch string, cat *Catalog) (refs []*nodev1.ArtifactRef, missing []string, err error) {
	type engineVersion struct{ engine, version string }
	var used []engineVersion
	add := func(ev engineVersion) {
		if !slices.Contains(used, ev) {
			used = append(used, ev)
		}
	}
	for _, p := range st.GetProxies() {
		add(engineVersion{engineName(p.GetEngine()), p.GetEngineVersion()})
	}
	for _, e := range st.GetEgresses() {
		if provider := providerOf(e.GetKind()); provider != "" {
			add(engineVersion{provider, cmp.Or(nd.held[provider], nd.ch.provider(nd.node, provider))})
		}
	}
	slices.SortFunc(used, func(a, b engineVersion) int {
		return cmp.Or(strings.Compare(a.engine, b.engine), strings.Compare(a.version, b.version))
	})
	for _, ev := range used {
		ref, err := cat.Ref(ctx, ev.engine, ev.version, arch)
		switch {
		case errors.Is(err, releases.ErrUnknown), errors.Is(err, releases.ErrNoPin):
			missing = append(missing, ev.engine+" "+ev.version)
			continue
		case err != nil:
			return nil, nil, err
		}
		refs = append(refs, ref)
	}
	return refs, missing, nil
}

// The values of the store as the enums of the node. A value that this version
// does not know, the empty one included, is an error that names it: the API
// writes only values that it knows, so such a row was written by a hand or by
// another version, and what it means is not known. It is never sent as a value
// that is not set, which the node would take for the default: a stranger
// action that is not set is mask to it, and a non-TLS action drop, which the
// row never said. (A kind, a type or an engine that is not set the node
// refuses as well; the error here says which row and value it is.)

func listenerKind(k string) (nodev1.ListenerKind, error) {
	switch k {
	case store.ListenerKindTLS:
		return nodev1.ListenerKind_LISTENER_KIND_TLS, nil
	case store.ListenerKindHTTPUpstream:
		return nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM, nil
	}
	return 0, unknownValue("kind", k)
}

func strangerAction(a string) (nodev1.StrangerAction, error) {
	switch a {
	case store.StrangerMask:
		return nodev1.StrangerAction_STRANGER_ACTION_MASK, nil
	case store.StrangerReject:
		return nodev1.StrangerAction_STRANGER_ACTION_REJECT, nil
	case store.StrangerDrop:
		return nodev1.StrangerAction_STRANGER_ACTION_DROP, nil
	}
	return 0, unknownValue("stranger action", a)
}

func nonTLSAction(a string) (nodev1.NonTlsAction, error) {
	switch a {
	case store.NonTLSDrop:
		return nodev1.NonTlsAction_NON_TLS_ACTION_DROP, nil
	case store.NonTLSHTTP400:
		return nodev1.NonTlsAction_NON_TLS_ACTION_HTTP400, nil
	}
	return 0, unknownValue("non-TLS action", a)
}

func proxyType(t string) (nodev1.ProxyType, error) {
	switch t {
	case store.ProxyTypeFakeTLS:
		return nodev1.ProxyType_PROXY_TYPE_FAKETLS, nil
	case store.ProxyTypeWeb:
		return nodev1.ProxyType_PROXY_TYPE_WEB, nil
	}
	return 0, unknownValue("type", t)
}

func engineOf(e string) (nodev1.Engine, error) {
	switch e {
	case store.EngineTelemt:
		return nodev1.Engine_ENGINE_TELEMT, nil
	case store.EngineMtg:
		return nodev1.Engine_ENGINE_MTG, nil
	}
	return 0, unknownValue("engine", e)
}

// unknownValue is the error for a stored value that this version does not know.
func unknownValue(what, value string) error {
	return fmt.Errorf("the stored %s %.32q is not one that this version of the panel knows", what, value)
}

// providerOf is the provider that runs egresses of kind k on a node, by the
// name of its binary, which is its name in the catalog; "" for the kinds that
// the edge serves itself.
func providerOf(k nodev1.EgressKind) string {
	switch k {
	case nodev1.EgressKind_EGRESS_KIND_XRAY_URI, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, nodev1.EgressKind_EGRESS_KIND_WARP:
		return EngineXray
	case nodev1.EgressKind_EGRESS_KIND_PSIPHON:
		return EnginePsiphonCore
	}
	return ""
}

// engineName is the name of an engine in the catalog and in artifacts.
func engineName(e nodev1.Engine) string {
	switch e {
	case nodev1.Engine_ENGINE_TELEMT:
		return store.EngineTelemt
	case nodev1.Engine_ENGINE_MTG:
		return store.EngineMtg
	}
	return ""
}

// directOrEmpty is the artifact source of a node as its state carries it:
// "direct", or "" for the default, panel.
func directOrEmpty(source string) string {
	if source == store.ArtifactSourceDirect {
		return source
	}
	return ""
}
