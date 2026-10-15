package reconcile

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/idna"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/engines/mtg"
	"github.com/urbnywrt/postern/internal/netpolicy"
)

// The fronting address of an mtg proxy (Ruling S5-10).
//
// mtg v2.2.8 dials its fronting target, where it passes every connection that
// is not a client's, directly from the node, not through the edge's SOCKS port
// (F6); only Telegram traffic goes through the edge. So the agent, not mtg,
// chooses the target, and holds it to the node's destination policy
// (netpolicy, the one the edge applies to telemt's mask connections): the mask
// target override of the proxy when it has one, which validation already
// requires to be a public IP address; else an address of the proxy domain,
// resolved through the node's resolver (the edge's DNS forwarder in DNS mode
// doh), on port 443. The punycode form of the domain is looked up (Go's
// resolver refuses a name that is not ASCII).
//
// A resolved address is kept for frontingTTL and looked up again at the first
// pass after that; a pass is every 30 s and at every change, so a domain is
// resolved at most every five minutes and a little. Of the answers that the
// policy allows the address in use stays while the answer still names it, so
// that a domain whose answers rotate does not roll the engine at every lookup;
// otherwise the first IPv4 address is taken, or the first IPv6 one. A new
// address is a new instance hash (the config names it), so the proxy gets a
// new generation by the usual blue-green. A lookup that fails (the resolver
// answers nothing) keeps the address in use, when there is one, for another
// frontingTTL: a resolver hiccup rolls nothing. A domain that cannot be
// resolved while no address is in use, or that resolves to no address the
// policy allows, fails the plan of the proxy: that is reported once
// (render_failed) and the serving generation keeps serving; the lookup is
// tried again after frontingTTL.
const (
	frontingTTL     = 5 * time.Minute
	frontingTimeout = 10 * time.Second
)

// frontingEntry is what a lookup of a host gave: the address chosen, or why
// none could be, and when.
type frontingEntry struct {
	addr netip.Addr
	err  error
	at   time.Time
}

// frontsDirectly reports whether an engine dials its fronting target from the
// node itself and needs Instance.FrontingAddr: mtg does, telemt fronts through
// the edge.
func frontsDirectly(e nodev1.Engine) bool { return e == nodev1.Engine_ENGINE_MTG }

// frontingAddr is the fronting address of a proxy whose engine fronts
// directly (see above): the mask target override, or an address of the
// domain. The error, which fails the plan of the proxy, says what is wrong
// and names no secret.
func (p *pass) frontingAddr(pr *nodev1.Proxy) (netip.AddrPort, error) {
	if mask := pr.GetMaskTargetOverride(); mask != "" {
		return mtg.ParseMaskTarget(mask)
	}
	host, err := frontingHost(pr.GetDomain())
	if err != nil {
		return netip.AddrPort{}, err
	}
	addr, err := p.r.resolveFronting(p.ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, mtg.FrontingPort), nil
}

// frontingHost is the name to look up for a proxy domain: its punycode form
// (idna.Lookup), without the one dot a fully qualified name may end with.
func frontingHost(domain string) (string, error) {
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", fmt.Errorf("the proxy has no domain to front to")
	}
	host, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("the proxy domain %.70q cannot be looked up: %v", domain, err)
	}
	return host, nil
}

// resolveFronting returns the fronting address of a host: the cached one while
// it is younger than frontingTTL, else a fresh lookup (see above). A failed
// lookup is cached as well, so that it is not repeated at every pass; one
// that failed in the resolver keeps the address in use.
func (r *Reconciler) resolveFronting(ctx context.Context, host string) (netip.Addr, error) {
	now := r.now()
	prev, ok := r.fronting[host]
	if ok && now.Sub(prev.at) < frontingTTL {
		return prev.addr, prev.err
	}
	addr, err := r.lookupFronting(ctx, host, prev.addr)
	if err != nil && ctx.Err() != nil {
		return netip.Addr{}, err // the agent is stopping: nothing to remember
	}
	var lookupErr *lookupError
	if errors.As(err, &lookupErr) && prev.addr.IsValid() {
		r.log().Warn("the fronting address of a proxy domain could not be looked up again; keeping the one in use", "host", host, "addr", prev.addr, "err", lookupErr.err)
		addr, err = prev.addr, nil
	}
	r.fronting[host] = frontingEntry{addr: addr, err: err, at: now}
	return addr, err
}

// lookupError is a lookup that the resolver could not answer, as opposed to
// an answer without a usable address.
type lookupError struct {
	host string
	err  error
}

func (e *lookupError) Error() string {
	return fmt.Sprintf("cannot resolve the proxy domain %s for the fronting address: %v", e.host, e.err)
}

func (e *lookupError) Unwrap() error { return e.err }

// lookupFronting looks the host up and picks the address: current when the
// answer still names it, else the first IPv4 address the policy allows, else
// the first IPv6 one.
func (r *Reconciler) lookupFronting(ctx context.Context, host string, current netip.Addr) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, frontingTimeout)
	defer cancel()
	lookup := r.frontingLookup
	if lookup == nil {
		res := r.Resolver
		if res == nil {
			res = net.DefaultResolver
		}
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return res.LookupNetIP(ctx, "ip", netpolicy.AbsoluteName(host))
		}
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return netip.Addr{}, &lookupError{host: host, err: err}
	}
	var allowed []netip.Addr
	var refused []string
	for _, a := range addrs {
		a = a.WithZone("").Unmap()
		if kind := netpolicy.NonPublic(a); kind != "" {
			refused = append(refused, a.String()+" ("+kind+")")
			continue
		}
		allowed = append(allowed, a)
	}
	if len(allowed) == 0 {
		if len(refused) == 0 {
			return netip.Addr{}, fmt.Errorf("the proxy domain %s resolves to no address", host)
		}
		return netip.Addr{}, fmt.Errorf("the proxy domain %s resolves to no address that the node may front to from itself: %s", host, strings.Join(refused, ", "))
	}
	for _, a := range allowed {
		if a == current {
			return a, nil
		}
	}
	for _, a := range allowed {
		if a.Is4() {
			return a, nil
		}
	}
	return allowed[0], nil
}
