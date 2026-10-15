package diagnostics

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/diag"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// texts cleans the text that the feed and the journal show, which nodes and
// probes wrote: every proxy secret (in each form the node's scrubber knows),
// ad tag, DNS credential token and egress parameter (xray URIs, subscription
// URLs, passwords, WARP tokens) goes, and every address but a node's own and
// the service, DC and DoH ones becomes <ip>. It is made for one request: the
// secrets are read once.
type texts struct {
	db  *store.DB
	key *seal.Key // nil: no secrets are known, only addresses are redacted
	log *slog.Logger

	secrets *nodev1.NodeState // the secrets, once read
	// blind: a secret could not be opened, so the scrubbers also take out
	// whatever may be a secret (diag.Scrubber.Strict).
	blind  bool
	byNode map[string]*diag.Scrubber
	ips    map[string][]string // the public IPs of nodes, by id
}

func newTexts(db *store.DB, key *seal.Key, log *slog.Logger) *texts {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &texts{db: db, key: key, log: log, byNode: map[string]*diag.Scrubber{}, ips: map[string][]string{}}
}

// load reads the secrets of every proxy, DNS credential and egress, opened
// as the nodes get them (proxies.OpenSecret and its kin). One that does not
// open is left out and logged by its id, and the text is then cleaned blind.
func (t *texts) load(ctx context.Context) error {
	if t.secrets != nil {
		return nil
	}
	st := &nodev1.NodeState{}
	if t.key != nil {
		for _, load := range []func(context.Context, *nodev1.NodeState) error{t.loadProxies, t.loadDNSTokens, t.loadEgresses} {
			if err := load(ctx, st); err != nil {
				return err
			}
		}
	}
	t.secrets = st
	return nil
}

// unreadable notes a secret that does not open.
func (t *texts) unreadable(what, id string, err error) {
	t.blind = true
	t.log.Warn("diagnostics: a secret does not open; the text is cleaned blind", what, id, "err", err)
}

func (t *texts) loadProxies(ctx context.Context, st *nodev1.NodeState) error {
	ps, err := t.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return err
	}
	for _, p := range ps {
		x := &nodev1.Proxy{Domain: p.Domain, AdTag: p.AdTag}
		if len(p.SecretEnc) > 0 {
			secret, err := proxies.OpenSecret(*t.key, p)
			if err != nil {
				t.unreadable("proxy", p.ID, err)
				continue
			}
			x.Secret = secret
		}
		st.Proxies = append(st.Proxies, x)
	}
	return nil
}

// loadDNSTokens puts the DNS credential tokens where the node's scrubber
// reads them: the WEB settings of a proxy.
func (t *texts) loadDNSTokens(ctx context.Context, st *nodev1.NodeState) error {
	cs, err := t.db.ListDNSCredentials(ctx)
	if err != nil {
		return err
	}
	for _, c := range cs {
		token, err := proxies.OpenDNSToken(*t.key, c)
		if err != nil {
			t.unreadable("dns_credential", c.ID, err)
			continue
		}
		st.Proxies = append(st.Proxies, &nodev1.Proxy{Web: &nodev1.WebSettings{DnsCredential: token}})
	}
	return nil
}

// loadEgresses puts the parameters of the egresses where the node's scrubber
// reads them: every string of their JSON is a secret, but a member's address.
func (t *texts) loadEgresses(ctx context.Context, st *nodev1.NodeState) error {
	es, err := t.db.ListEgresses(ctx)
	if err != nil {
		return err
	}
	for _, e := range es {
		params, err := proxies.OpenEgressParams(*t.key, e)
		if err != nil {
			t.unreadable("egress", e.ID, err)
			continue
		}
		st.Egresses = append(st.Egresses, &nodev1.Egress{Id: e.ID, ParamsJson: params})
	}
	return nil
}

// scrubber is the scrubber of the text of a node whose public IPs are known
// ("" for text of no node).
func (t *texts) scrubber(ctx context.Context, nodeID string, publicIPs []string) (*diag.Scrubber, error) {
	if s, ok := t.byNode[nodeID]; ok {
		return s, nil
	}
	if err := t.load(ctx); err != nil {
		return nil, err
	}
	var keep []netip.Addr
	for _, ip := range publicIPs {
		if a, err := netip.ParseAddr(ip); err == nil {
			keep = append(keep, a)
		}
	}
	s := diag.NewScrubber(t.secrets, nil, keep)
	if t.blind {
		s = s.Strict()
	}
	t.byNode[nodeID] = s
	return s, nil
}

// ofNode is the scrubber of a node's text, by the node's id; a node that is
// gone keeps no address.
func (t *texts) ofNode(ctx context.Context, nodeID string) (*diag.Scrubber, error) {
	ips, ok := t.ips[nodeID]
	if !ok && nodeID != "" {
		n, err := t.db.NodeByID(ctx, nodeID)
		switch {
		case err == nil:
			ips = n.PublicIPs
		case !errors.Is(err, store.ErrNotFound):
			return nil, err
		}
		t.ips[nodeID] = ips
	}
	return t.scrubber(ctx, nodeID, ips)
}

// cleanMap cleans the values of a map.
func cleanMap(s *diag.Scrubber, m map[string]string) map[string]string {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = s.Clean(v)
	}
	return out
}
