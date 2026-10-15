package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/urbnywrt/postern/internal/node/diag"
	"github.com/urbnywrt/postern/internal/panel/geodb"
	"github.com/urbnywrt/postern/internal/panel/probes"
	"github.com/urbnywrt/postern/internal/panel/store"
)

const (
	behindAfter    = 5 * time.Minute     // panel.state: behind for this long is a warning
	geoipFreshness = 62 * 24 * time.Hour // panel.geoip: a database older than this is a warning
	resolveTimeout = 5 * time.Second     // panel.link_host
	fixRollEdge    = "roll_edge"         // the fix of panel.versions
	layerPanel     = "panel"             // the layer of the panel's checks
	layerIngress   = "ingress"           // the layer of ingress.external
	layerWeb       = "web"               // the layer of web.base_path
	checkBasePath  = "web.base_path"     // a WEB proxy behind a web server: no redirect at its base path
)

// BasePathChecker asks the site in front of a WEB proxy for its base path
// without the slash (probes.Scheduler.CheckBasePath); the Prober of the
// config may be one.
type BasePathChecker interface {
	CheckBasePath(ctx context.Context, proxyID string) (probes.BasePath, error)
}

// netResolver is the system resolver.
type netResolver struct{}

func (netResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// panelChecks runs the panel's own checks of a scope, in order, and stores
// each as it ends. why says why the node's checks will not run, "" when they
// will. An error is one of the database or the end of ctx.
func (r *Runner) panelChecks(ctx context.Context, sc scopeOf, why string, w *recorder) error {
	n := sc.node
	results := []store.DiagnosticResult{r.connection(n, why)}
	results = append(results, r.state(ctx, n), versions(n))
	for _, x := range results {
		if err := w.add(ctx, x); err != nil {
			return err
		}
	}
	hosts, err := r.linkHosts(ctx, sc)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if err := w.add(ctx, r.linkHost(ctx, n, h.target, h.host)); err != nil {
			return err
		}
	}
	if err := w.add(ctx, r.geoip(ctx)); err != nil {
		return err
	}
	ingress, err := r.external(ctx, sc)
	if err != nil {
		return err
	}
	for _, x := range ingress {
		if err := w.add(ctx, x); err != nil {
			return err
		}
	}
	paths, err := r.basePaths(ctx, sc)
	if err != nil {
		return err
	}
	for _, x := range paths {
		if err := w.add(ctx, x); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// basePaths is web.base_path of every enabled WEB proxy of the scope that
// lives under a base path behind a web server: GET
// https://<domain>/<base_path> without the slash must not be a redirect,
// which the clients of the proxy do not follow (fail). The proxies that are
// not such are left out.
func (r *Runner) basePaths(ctx context.Context, sc scopeOf) ([]store.DiagnosticResult, error) {
	bp, ok := r.cfg.Probes.(BasePathChecker)
	if !ok {
		return nil, nil
	}
	ps := []*store.Proxy{sc.proxy}
	if sc.proxy == nil {
		var err error
		if ps, err = r.cfg.DB.ListProxies(ctx, store.ProxyFilter{NodeID: sc.node.ID}); err != nil {
			return nil, err
		}
	}
	var out []store.DiagnosticResult
	for _, p := range ps {
		if p.Type != store.ProxyTypeWeb || !p.Enabled || strings.Trim(p.WebBasePath, "/") == "" {
			continue
		}
		res, err := bp.CheckBasePath(ctx, p.ID)
		if errors.Is(err, probes.ErrNotProbeable) {
			continue
		}
		base := "/" + strings.Trim(p.WebBasePath, "/")
		x := store.DiagnosticResult{CheckID: checkBasePath, Layer: layerWeb, Target: "proxy:" + p.ID, Vantage: VantagePanel, CheckedAt: r.cfg.Now()}
		switch {
		case err != nil:
			x.Status, x.Summary = StatusSkip, clip("not checked: "+redact(sc.node.PublicIPs, err.Error()), maxSummary)
		case res.Redirect():
			x.Status = StatusFail
			x.Summary = clip(fmt.Sprintf("the web server in front answers %s without the slash with a redirect (%d)", base, res.Status), maxSummary)
			x.Evidence = clip(redact(sc.node.PublicIPs, fmt.Sprintf("GET %s: %d, Location: %s", base, res.Status, res.Location)), maxEvidence)
			x.Hint = "the clients of the proxy do not follow a redirect: give the web server an exact location for " + base +
				" that goes to the node too (the snippet of the proxy's page has it)"
		default:
			x.Status, x.Summary = StatusOK, clip(fmt.Sprintf("the web server in front answers %s without the slash with %d, not a redirect", base, res.Status), maxSummary)
		}
		out = append(out, x)
	}
	return out, ctx.Err()
}

func panelResult(id, target, status, summary string) store.DiagnosticResult {
	return store.DiagnosticResult{CheckID: id, Layer: layerPanel, Target: target, Status: status, Summary: summary, Vantage: VantagePanel}
}

// connection is panel.connection: online; a state rejection or the last
// reconcile error (warn); offline (fail). When the node's checks will not run,
// it says why: as its summary when the node cannot be reached, as a skip when
// an online node lacks the capability, as the hint otherwise.
func (r *Runner) connection(n *store.Node, why string) store.DiagnosticResult {
	var x store.DiagnosticResult
	switch {
	case n.Status != store.NodeStatusOnline:
		x = panelResult("panel.connection", "", StatusFail, "the node is "+n.Status+": its checks did not run")
		x.Hint = "look at the node's host: the agent's container, its network, the management port"
	case n.StateRejection != "":
		x = panelResult("panel.connection", "", StatusWarn, "the node refused its desired state")
		x.Evidence = redact(n.PublicIPs, n.StateRejection)
	case n.LastError != "":
		x = panelResult("panel.connection", "", StatusWarn, "the node's last reconcile pass failed")
		x.Evidence = redact(n.PublicIPs, n.LastError)
	default:
		x = panelResult("panel.connection", "", StatusOK, "online")
	}
	x.CheckedAt = r.cfg.Now()
	if why == "" || n.Status != store.NodeStatusOnline {
		return x
	}
	if x.Status == StatusOK {
		x.Status, x.Summary = StatusSkip, why
		return x
	}
	x.Hint = why
	return x
}

// state is panel.state: applied = desired, or behind for less than 5 min
// (ok); behind for 5 min or more (warn).
func (r *Runner) state(ctx context.Context, n *store.Node) store.DiagnosticResult {
	now := r.cfg.Now()
	since, behind, err := r.cfg.DB.NodeBehindSince(ctx, n.ID)
	var x store.DiagnosticResult
	switch {
	case err != nil:
		x = panelResult("panel.state", "", StatusSkip, "could not read the node's generations")
	case !behind:
		x = panelResult("panel.state", "", StatusOK, fmt.Sprintf("the node applied its desired state (generation %d)", n.DesiredGeneration))
	case now.Sub(since) < behindAfter:
		x = panelResult("panel.state", "", StatusOK, fmt.Sprintf("the node is applying generation %d", n.DesiredGeneration))
	default:
		x = panelResult("panel.state", "", StatusWarn, fmt.Sprintf("the node is behind its desired state for %s (applied %d, desired %d)",
			now.Sub(since).Round(time.Minute), n.AppliedGeneration, n.DesiredGeneration))
		x.Hint = "see panel.connection and the node's last error"
	}
	x.CheckedAt = now
	return x
}

// checkVersions is the id of the check versions.
const checkVersions = "panel.versions"

// versions is panel.versions: the edge runs the agent's version (ok), or
// another (warn, fix roll_edge).
func versions(n *store.Node) store.DiagnosticResult {
	switch {
	case n.EdgeVersion == "" || n.AgentVersion == "":
		return panelResult(checkVersions, "", StatusSkip, "the node has not reported its versions")
	case n.EdgeVersion == n.AgentVersion:
		return panelResult(checkVersions, "", StatusOK, "the edge runs the agent's version "+n.AgentVersion)
	}
	x := panelResult(checkVersions, "", StatusWarn, clip(fmt.Sprintf("the edge runs %s, the agent %s", n.EdgeVersion, n.AgentVersion), maxSummary))
	x.Fix = fixRollEdge
	x.Hint = "roll the edge to the agent's version"
	return x
}

// hostOf is a link host to check and the target it is checked for.
type hostOf struct{ target, host string }

// linkHosts are the link hosts of a scope: the node's, and those of its
// listeners that have their own; for a proxy, the one of its links only.
func (r *Runner) linkHosts(ctx context.Context, sc scopeOf) ([]hostOf, error) {
	ls, err := r.cfg.DB.ListListeners(ctx, sc.node.ID)
	if err != nil {
		return nil, err
	}
	if sc.proxy != nil {
		for _, l := range ls {
			if l.ID == sc.proxy.ListenerID && l.LinkHostOverride != "" {
				return []hostOf{{"listener:" + l.ID, l.LinkHostOverride}}, nil
			}
		}
		return []hostOf{{"", sc.node.LinkHost}}, nil
	}
	out := []hostOf{{"", sc.node.LinkHost}}
	for _, l := range ls {
		if l.LinkHostOverride != "" {
			out = append(out, hostOf{"listener:" + l.ID, l.LinkHostOverride})
		}
	}
	return out, nil
}

// linkHost is panel.link_host: the link host resolves to a public IP of the
// node (ok); to none of them (warn); to nothing (fail).
func (r *Runner) linkHost(ctx context.Context, n *store.Node, target, host string) store.DiagnosticResult {
	x := r.linkHostStatus(ctx, n, host)
	x.Target, x.CheckedAt = target, r.cfg.Now()
	return x
}

func (r *Runner) linkHostStatus(ctx context.Context, n *store.Node, host string) store.DiagnosticResult {
	const id = "panel.link_host"
	if host == "" {
		x := panelResult(id, "", StatusFail, "no link host is set: the proxies have no links")
		x.Hint = "set the node's link host"
		return x
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		addrs, err = r.cfg.Resolver.LookupNetIP(rctx, "ip", host)
		cancel()
		if err != nil || len(addrs) == 0 {
			x := panelResult(id, "", StatusFail, clip("the link host "+host+" does not resolve", maxSummary))
			if err != nil {
				x.Evidence = redact(n.PublicIPs, err.Error())
			}
			x.Hint = "add an A or AAAA record of the link host that points to the node"
			return x
		}
	}
	public := map[netip.Addr]bool{}
	for _, s := range n.PublicIPs {
		if a, err := netip.ParseAddr(s); err == nil {
			public[a.Unmap()] = true
		}
	}
	got := make([]string, 0, len(addrs))
	for _, a := range addrs {
		got = append(got, a.Unmap().String())
		if public[a.Unmap()] {
			return panelResult(id, "", StatusOK, clip("the link host "+host+" resolves to "+a.Unmap().String()+", a public IP of the node", maxSummary))
		}
	}
	if len(public) == 0 {
		return panelResult(id, "", StatusSkip, "the node has not reported its public IPs")
	}
	x := panelResult(id, "", StatusWarn, clip("the link host "+host+" does not resolve to a public IP of the node", maxSummary))
	x.Evidence = "resolves to: " + strings.Join(got, ", ") + "\npublic IPs of the node: " + strings.Join(n.PublicIPs, ", ")
	x.Hint = "point the link host at the node, or set the node's link host to one that does"
	return x
}

// geoip is panel.geoip: the country database is fresh (62 days) or not
// needed (ok); older (warn); missing while the IP policy uses countries
// (fail).
func (r *Runner) geoip(ctx context.Context) store.DiagnosticResult {
	const id = "panel.geoip"
	x := r.geoipStatus(ctx, id)
	x.CheckedAt = r.cfg.Now()
	return x
}

func (r *Runner) geoipStatus(ctx context.Context, id string) store.DiagnosticResult {
	return geoipStatus(ctx, r.cfg.DB, r.cfg.GeoIP, r.cfg.Now(), id)
}

// geoipStatus is panel.geoip without its time; the problem feed shares it.
func geoipStatus(ctx context.Context, db *store.DB, geo func(context.Context) (geodb.Status, error), now time.Time, id string) store.DiagnosticResult {
	if geo == nil {
		return panelResult(id, "", StatusSkip, "the panel has no country database manager")
	}
	settings, _, err := db.StatsSettings(ctx)
	if err != nil {
		return panelResult(id, "", StatusSkip, "could not read the IP policy")
	}
	if settings.IPPolicy == store.IPPolicyOff {
		return panelResult(id, "", StatusOK, "not needed: the IP policy is off")
	}
	st, err := geo(ctx)
	switch {
	case err != nil:
		return panelResult(id, "", StatusSkip, "could not read the state of the country database")
	case !st.Enabled:
		return panelResult(id, "", StatusOK, "not needed: country lookups are off")
	case !st.Present:
		x := panelResult(id, "", StatusFail, "no country database while the IP policy uses countries")
		x.Evidence = redact(nil, st.Error)
		x.Hint = "refresh the country database in Settings, or upload one"
		return x
	case !st.Built.IsZero() && now.Sub(st.Built) > geoipFreshness:
		x := panelResult(id, "", StatusWarn, "the country database of "+st.Month+" is older than 62 days")
		x.Evidence = redact(nil, st.Error)
		x.Hint = "refresh the country database in Settings"
		return x
	}
	return panelResult(id, "", StatusOK, "the country database of "+st.Month+" is fresh")
}

// external is ingress.external of every proxy of the scope: a probe from the
// panel through the link host that a datacenter answers (ok), that only
// proves the secret (L1, warn), or that fails (fail). The probes run at once,
// bounded by the scheduler; their results are in the order of the proxies.
func (r *Runner) external(ctx context.Context, sc scopeOf) ([]store.DiagnosticResult, error) {
	ps := []*store.Proxy{sc.proxy}
	if sc.proxy == nil {
		var err error
		if ps, err = r.cfg.DB.ListProxies(ctx, store.ProxyFilter{NodeID: sc.node.ID}); err != nil {
			return nil, err
		}
	}
	out := make([]store.DiagnosticResult, len(ps))
	var wg sync.WaitGroup
	for i, p := range ps {
		wg.Go(func() {
			x := r.probe(ctx, sc.node, p)
			x.CheckID, x.Layer, x.Target, x.Vantage = "ingress.external", layerIngress, "proxy:"+p.ID, VantagePanel
			x.CheckedAt = r.cfg.Now()
			out[i] = x
		})
	}
	wg.Wait()
	return out, ctx.Err()
}

func (r *Runner) probe(ctx context.Context, n *store.Node, p *store.Proxy) store.DiagnosticResult {
	switch {
	case !p.Enabled:
		return store.DiagnosticResult{Status: StatusSkip, Summary: "the proxy is paused"}
	case r.cfg.Probes == nil:
		return store.DiagnosticResult{Status: StatusSkip, Summary: "the panel does not probe"}
	}
	res, l1, err := r.cfg.Probes.Probe(ctx, p.ID)
	res.Error = redact(n.PublicIPs, res.Error)
	switch {
	case errors.Is(err, probes.ErrNotProbeable):
		return store.DiagnosticResult{Status: StatusSkip, Summary: clip("not probed: "+err.Error(), maxSummary)}
	case err != nil:
		return store.DiagnosticResult{Status: StatusSkip, Summary: "the probe did not finish"}
	case p.Type == store.ProxyTypeWeb:
		return webExternal(res, l1)
	case res.OK:
		return store.DiagnosticResult{Status: StatusOK, Summary: fmt.Sprintf("a datacenter answered through the proxy from the panel in %d ms", res.LatencyMS)}
	case l1:
		return store.DiagnosticResult{Status: StatusWarn, Summary: "the proxy knows its secret, but no datacenter answered through it (L1 only)",
			Evidence: res.Error, Hint: "look at engine.dcs and the egress checks"}
	}
	return store.DiagnosticResult{Status: StatusFail, Summary: clip("the proxy failed from the panel: "+res.Error, maxSummary),
		Evidence: res.Error, Hint: "look at the link host, ingress.bound and the node's firewall"}
}

// webExternal is ingress.external of a WEB proxy, from the panel's web probe
// (HTTP/2 and the decoy site, not MTProto: a recorded deviation): 200 over
// HTTP/2 (ok), another answer over TLS (warn), no answer or a certificate
// that is not trusted (fail).
func webExternal(res store.Probe, answered bool) store.DiagnosticResult {
	switch {
	case res.OK:
		return store.DiagnosticResult{Status: StatusOK, Summary: fmt.Sprintf("the site of the proxy answered 200 over HTTP/2 from the panel in %d ms", res.LatencyMS)}
	case answered:
		return store.DiagnosticResult{Status: StatusWarn, Summary: clip("the site of the proxy answered from the panel, but: "+res.Error, maxSummary),
			Evidence: res.Error, Hint: "look at web.http2, web.decoy and the web server in front, if there is one"}
	}
	return store.DiagnosticResult{Status: StatusFail, Summary: clip("the site of the proxy failed from the panel: "+res.Error, maxSummary),
		Evidence: res.Error, Hint: "look at web.dns, web.cert, ingress.bound and the node's firewall"}
}

// redact passes panel-side text through the IP redactor of the node's
// diagnostics (spec 5.7): every address but the node's public IPs (public),
// the datacenter and DoH addresses, the service addresses and keep becomes
// <ip>.
func redact(public []string, text string, keep ...netip.Addr) string {
	if text == "" {
		return ""
	}
	for _, s := range public {
		if a, err := netip.ParseAddr(s); err == nil {
			keep = append(keep, a)
		}
	}
	return diag.NewScrubber(nil, nil, keep).Clean(text)
}
