package reconcile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/doh"
	"github.com/urbnywrt/postern/internal/node/state"
)

// The DNS of the node (F2: production nodes may block UDP port 53). In DNS mode
// doh, the default, the edge runs a forwarder on 127.0.0.2:53 that asks
// DNS-over-HTTPS endpoints and the host's nameservers, and the containers of
// the node mount a resolv.conf that names it while the edge reports that the
// forwarder runs (ruling S2-8); otherwise, and in mode system, where there is no
// forwarder, they keep the host's resolver.
const (
	// resolvConfContent is the resolv.conf of the containers in mode doh: the
	// forwarder, two seconds for an answer, two tries.
	resolvConfContent = "nameserver 127.0.0.2\noptions timeout:2 attempts:2\n"
	// resolvConfMode lets the engines, which run as 65534, read it.
	resolvConfMode = 0o644
	// resolvConfMount is where a container sees it.
	resolvConfMount = "/etc/resolv.conf"
	// maxNameservers is the most nameservers of the host that go to the edge:
	// as many as it takes (dns.CheckConfig refuses more).
	maxNameservers = 16
)

// forwarderAddr is the address of the edge's DNS forwarder (dns.ListenAddr),
// which is never a nameserver of the host for it.
var forwarderAddr = netip.MustParseAddr("127.0.0.2")

// evDNSUnavailable is the event of a forwarder that should run and does not.
const evDNSUnavailable = "dns_unavailable"

// edgeDNSHold is how long the edge must answer a new state of its forwarder, in
// every answer, before the engines follow it (ruling S2-11): a forwarder that
// comes and goes does not roll every engine each time.
const edgeDNSHold = 60 * time.Second

// dnsEventEvery is the least time between two dns_unavailable events of one
// edge (ruling S2-12): a forwarder that comes and goes is reported once in that
// time, not every time a pass finds it down.
const dnsEventEvery = 10 * time.Minute

// edgeEvent is an event about an edge generation, and when it was sent.
type edgeEvent struct {
	gen uint64
	at  time.Time
}

// dohMode reports whether the desired state of the pass is in DNS mode doh.
func (p *pass) dohMode() bool { return state.DNSModeOf(p.st.GetSettings()) == state.DNSModeDoH }

// edgeDNSUp is the known state of the edge's DNS forwarder, the one the engines
// follow: what the edge answers (Health dns), the first answer at once and a
// change once the edge has answered it for edgeDNSHold in a row. It is kept in
// the runtime record across passes and restarts of the agent, with the time a
// change began. An edge that does not answer leaves both as they are. After
// another DNS mode than doh it is false until the edge answers that the
// forwarder runs (see takeEdgeDNS).
func (p *pass) edgeDNSUp() bool { return p.rt.EdgeDNS }

// resolvConf returns the host path of the resolv.conf that the containers of
// the node mount at /etc/resolv.conf: the one that names the edge's DNS
// forwarder, in DNS mode doh while the forwarder is known to run (edgeDNSUp);
// "" otherwise, and they keep the host's resolver. Engine containers mount it,
// and it is the providers.Instance.ResolvConf of the egress containers.
func (p *pass) resolvConf() string {
	if !p.dohMode() || !p.edgeDNSUp() {
		return ""
	}
	return p.r.Store.Paths.ResolvConfPath()
}

// withResolvConf returns spec with the host's resolv.conf at path mounted read
// only at /etc/resolv.conf; an empty path leaves spec as it is. Docker honours
// such a mount for containers on the host network, which take no --dns.
func withResolvConf(spec dockerapi.ContainerSpec, path string) dockerapi.ContainerSpec {
	if path == "" {
		return spec
	}
	spec.Binds = append(slices.Clone(spec.Binds), path+":"+resolvConfMount+":ro")
	return spec
}

// prepareDNS makes the pass ready for the DNS of the desired state: in mode doh
// it takes the host's nameservers for the forwarder, and writes the resolv.conf
// of the containers, whether the forwarder runs yet or not, before any
// container that mounts it is started (Docker would make a missing source an
// empty directory). In another mode there is nothing to prepare; the state the
// engines followed is dropped once the edge has the configuration without the
// forwarder (checkEdgeDNS).
func (p *pass) prepareDNS() error {
	if !p.dohMode() {
		return nil
	}
	p.dnsFallback = sanitizeNameservers(p.r.hostNameservers())
	path := p.r.Store.Paths.ResolvConfPath()
	if err := checkBindSource(path); err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().IsRegular() && fi.Mode().Perm() == resolvConfMode {
			if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, []byte(resolvConfContent)) {
				return nil
			}
		}
		if fi.IsDir() {
			// What Docker makes of a missing bind source: empty, or it is not
			// Docker's, and then it stays and the write below fails.
			_ = os.Remove(path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("dns: %w", err)
	}
	if err := os.MkdirAll(p.r.Store.Paths.RunDir(), 0o700); err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	if err := state.WriteFileAtomic(path, []byte(resolvConfContent), resolvConfMode); err != nil {
		return fmt.Errorf("dns: writing %s: %w", path, err)
	}
	return nil
}

func (r *Reconciler) hostNameservers() []string {
	if r.HostNameservers == nil {
		return nil
	}
	return r.HostNameservers()
}

// sanitizeNameservers keeps the IP addresses, each once, never the forwarder,
// and maxNameservers at the most: the edge refuses a whole configuration with
// anything else in it.
func sanitizeNameservers(in []string) []string {
	var out []string
	for _, s := range in {
		if len(out) == maxNameservers {
			break
		}
		a, err := netip.ParseAddr(s)
		if err != nil || a.Unmap() == forwarderAddr || a.IsUnspecified() || a.IsMulticast() {
			continue
		}
		if s = a.Unmap().String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// edgeDNS is the DNS part of the edge configuration: the forwarder with the
// default DNS-over-HTTPS endpoints and the host's nameservers in mode doh,
// nothing in mode system.
func edgeDNS(s *nodev1.NodeSettings, fallback []string) *edgev1.Dns {
	if state.DNSModeOf(s) != state.DNSModeDoH {
		return nil
	}
	return &edgev1.Dns{Enabled: true, DohUrls: slices.Clone(doh.DefaultEndpoints), Fallback: slices.Clone(fallback)}
}

// edgeConfig is the whole configuration of edge generation gen in this pass:
// the table (buildEdgeConfig), the DNS forwarder, and the addresses of the
// middle proxies (meaddrs.go).
func (p *pass) edgeConfig(gen uint64) *edgev1.EdgeConfig {
	cfg := buildEdgeConfigWith(p.st, p.rt, gen, p.starting, p.webCerts)
	cfg.Dns = edgeDNS(p.st.GetSettings(), p.dnsFallback)
	cfg.MeAddrs = p.r.meAddrs()
	return cfg
}

// observeEdgeDNS asks the current edge whether its DNS forwarder runs, and
// tells the agent what it answers (OnEdgeDNS): its own lookups go through the
// forwarder while it runs, at once. In mode doh the engines follow the known
// state, which takes the answer (see takeEdgeDNS); in another mode there is no
// forwarder to follow. An edge that does not answer tells nothing of its
// forwarder: neither the known state nor the agent's resolver change (ruling
// S2-8). It returns the answer, whether there was one, and whether the known
// state changed.
func (p *pass) observeEdgeDNS() (up, answered, changed bool) {
	ctx, cancel := context.WithTimeout(p.ctx, edgeCallTimeout)
	h, err := p.edge.Health(ctx)
	cancel()
	if err != nil {
		return false, false, false
	}
	up = h.GetDns()
	if p.r.OnEdgeDNS != nil {
		p.r.OnEdgeDNS(up)
	}
	if !p.dohMode() {
		// A forwarder that runs on until the edge has the configuration of
		// this pass must not count for the next time the mode is doh.
		return up, true, false
	}
	return up, true, takeEdgeDNS(p.rt, up, p.r.now())
}

// takeEdgeDNS takes an answer of the edge, up at now, into the known state of
// rt (ruling S2-11) and reports whether that changed. The first answer ever is
// the known state at once. After that, an answer of the known state ends a
// change that had begun; the other state begins one, or, when it has been
// answered in every answer for edgeDNSHold since the change began, becomes the
// known state. While rt awaits the forwarder after another DNS mode, only an
// answer that it runs counts, and at once.
func takeEdgeDNS(rt *state.Runtime, up bool, now time.Time) (changed bool) {
	switch {
	case rt.EdgeDNSAwaitUp:
		if up {
			changed = !rt.EdgeDNS
			rt.EdgeDNS, rt.EdgeDNSKnown, rt.EdgeDNSChangeSince, rt.EdgeDNSAwaitUp = true, true, time.Time{}, false
		}
	case !rt.EdgeDNSKnown:
		changed = up != rt.EdgeDNS
		rt.EdgeDNS, rt.EdgeDNSKnown, rt.EdgeDNSChangeSince = up, true, time.Time{}
	case up == rt.EdgeDNS:
		rt.EdgeDNSChangeSince = time.Time{}
	case rt.EdgeDNSChangeSince.IsZero():
		rt.EdgeDNSChangeSince = now
	case now.Sub(rt.EdgeDNSChangeSince) >= edgeDNSHold:
		rt.EdgeDNS, rt.EdgeDNSChangeSince = up, time.Time{}
		changed = true
	}
	return changed
}

// settleEdgeDNS follows the forwarder of the edge that runs now, before any
// engine is started: when the known state has changed, the plans are made
// again, so that the engines of this pass mount the resolv.conf exactly while
// the forwarder is known to run. (On a new node the first answer of the edge
// applies at once, in the pass that starts the first engines, which thus need
// no second generation.)
func (p *pass) settleEdgeDNS() error {
	if _, _, changed := p.observeEdgeDNS(); changed {
		return p.plan()
	}
	return nil
}

// checkEdgeDNS asks the edge again once it has the table of the pass, which may
// have turned its forwarder on or off; a change of the known state shows in the
// plans of the next pass. In another mode than doh the edge now has the
// configuration without the forwarder, and the state the engines followed is
// dropped: when the mode becomes doh again, they wait until the edge answers
// that the forwarder runs (EdgeDNSAwaitUp). Not before: a pass that a quick
// change back to doh cuts short leaves the state of a forwarder that still
// runs as it was. In mode doh a forwarder that the edge says does not run is
// reported, once until it runs again, and not within dnsEventEvery of the last
// report about the same edge (ruling S2-12); a forwarder that is still down
// when that time is over is reported then. The containers of the node cannot
// resolve through it, and keep the host's resolver once that has held.
func (p *pass) checkEdgeDNS() {
	if !p.dohMode() {
		p.rt.EdgeDNS, p.rt.EdgeDNSChangeSince, p.rt.EdgeDNSAwaitUp = false, time.Time{}, true
	}
	up, answered, _ := p.observeEdgeDNS()
	if !answered {
		return
	}
	if up || !p.dohMode() {
		p.r.clearProblem("dns")
		return
	}
	reason := fmt.Sprintf("the DNS forwarder of edge generation %d does not run: the containers of the node cannot resolve names through it (see the log of the edge)", p.edgeGen)
	now := p.r.now()
	switch last := p.r.lastDNSEvent; {
	case p.r.problems["dns"] == reason:
		// Reported, and it has not run since.
	case last.gen == p.edgeGen && now.Sub(last.at) < dnsEventEvery:
		// Reported a moment ago: a forwarder that comes and goes.
	default:
		p.r.problem("dns", reason)
		p.r.lastDNSEvent = edgeEvent{gen: p.edgeGen, at: now}
		p.r.event(evDNSUnavailable, sevWarning, "", reason, map[string]string{"generation": genString(p.edgeGen)})
	}
}
