package publicpage

import (
	"cmp"
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// countryOf returns the code that the page shows for an item of proxy p, on
// node n, that has no code of its own: the country of the server by the GeoIP
// database. The server is the address of the link, host, when that is an IP
// address (a fake-TLS proxy whose link host is one), and else the public IPs
// that the panel knows for the node, the first that the database has. "" when
// there is no database or it has no answer.
func (s *Service) countryOf(p *store.Proxy, n *store.Node, host string) string {
	if s.country == nil {
		return ""
	}
	if p.Type != store.ProxyTypeWeb {
		if ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")); err == nil {
			return s.country(ip.Unmap())
		}
	}
	if n == nil {
		return ""
	}
	for _, raw := range n.PublicIPs {
		if ip, err := netip.ParseAddr(raw); err == nil {
			if c := s.country(ip.Unmap()); c != "" {
				return c
			}
		}
	}
	return ""
}

// linkHost returns the host that the links of a fake-TLS proxy carry, as
// proxies.LinksOf finds it, without opening the secret: the link host override
// of its listener, or else the link host of its node. "" for a WEB proxy and
// when there is none.
func (s *Service) linkHost(ctx context.Context, p *store.Proxy, n *store.Node) (string, error) {
	if p.Type == store.ProxyTypeWeb {
		return "", nil
	}
	l, err := s.db.ListenerByID(ctx, p.ListenerID)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var nodeHost string
	if n != nil {
		nodeHost = n.LinkHost
	}
	return cmp.Or(l.LinkHostOverride, nodeHost), nil
}

// countries returns the country that the page shows for each item of p while
// the item has no code, by proxy id: what the form offers as the placeholder
// of the code. Nil when there is no GeoIP database to ask.
func (s *Service) countries(ctx context.Context, p *store.PublicPage) (map[string]string, error) {
	if s.country == nil || len(p.Items) == 0 {
		return nil, nil
	}
	all, err := s.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*store.Proxy, len(all))
	for _, x := range all {
		byID[x.ID] = x
	}
	nodes, err := s.db.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	nodeByID := make(map[string]*store.Node, len(nodes))
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}
	out := make(map[string]string, len(p.Items))
	for _, it := range p.Items {
		x := byID[it.ProxyID]
		if x == nil {
			continue
		}
		n := nodeByID[x.NodeID]
		host, err := s.linkHost(ctx, x, n)
		if err != nil {
			return nil, err
		}
		if c := s.countryOf(x, n, host); c != "" {
			out[it.ProxyID] = c
		}
	}
	return out, nil
}
