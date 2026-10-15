package diagnostics

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/geodb"
	"github.com/urbnywrt/postern/internal/panel/probes"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// panelRun runs the panel's checks of a node (with no agent) and returns its
// results by "id target".
func panelRun(t *testing.T, e *env, n *store.Node, scope string) map[string]store.DiagnosticResult {
	t.Helper()
	r := e.runner(0)
	run := e.wait(r, must(r.Run(e.ctx, n.ID, scope, store.RunManual, "", "")))
	out := map[string]store.DiagnosticResult{}
	for _, x := range run.Results {
		out[x.CheckID+" "+x.Target] = x
	}
	return out
}

func TestPanelConnection(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(*store.Node)
		status string
		text   string
	}{
		{"offline", func(n *store.Node) { n.Status = store.NodeStatusOffline }, StatusFail, "offline"},
		{"rejection", func(n *store.Node) { n.StateRejection = "the listener 0.0.0.0:443 is taken" }, StatusWarn, "taken"},
		{"last error", func(n *store.Node) { n.LastError = "pull failed" }, StatusWarn, "pull failed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			n := e.node(c.change)
			e.agent(n.ID, &fakeNode{})
			x := panelRun(t, e, n, ScopeNode)["panel.connection "]
			if x.Status != c.status || !strings.Contains(x.Summary+x.Evidence, c.text) || x.Layer != "panel" || x.Vantage != VantagePanel {
				t.Fatalf("%+v", x)
			}
		})
	}
}

func TestPanelStateBehind(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	e.agent(n.ID, &fakeNode{})
	if _, err := e.db.NextNodeGeneration(e.ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	if x := panelRun(t, e, n, ScopeNode)["panel.state "]; x.Status != StatusOK {
		t.Fatalf("behind for a moment: %+v", x)
	}
	e.now = time.Now().Add(6 * time.Minute)
	if x := panelRun(t, e, n, ScopeNode)["panel.state "]; x.Status != StatusWarn || !strings.Contains(x.Summary, "behind") {
		t.Fatalf("behind for 6 min: %+v", x)
	}
}

func TestPanelVersionsOutdated(t *testing.T) {
	e := newEnv(t)
	n := e.node(func(n *store.Node) { n.EdgeVersion = "1.1.0" })
	e.agent(n.ID, &fakeNode{})
	x := panelRun(t, e, n, ScopeNode)["panel.versions "]
	if x.Status != StatusWarn || x.Fix != "roll_edge" || !strings.Contains(x.Summary, "1.1.0") {
		t.Fatalf("%+v", x)
	}
}

func TestPanelLinkHost(t *testing.T) {
	e := newEnv(t)
	n := e.node(func(n *store.Node) { n.LinkHost = "proxy.example.com" })
	e.res["proxy.example.com"] = []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	e.res["good.example.com"] = []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("198.51.100.5")}
	good := e.listener(n.ID, 443, "good.example.com")
	bad := e.listener(n.ID, 8443, "nx.example.com")
	e.listener(n.ID, 9443, "")
	e.agent(n.ID, &fakeNode{})
	got := panelRun(t, e, n, ScopeNode)
	if x := got["panel.link_host "]; x.Status != StatusWarn || !strings.Contains(x.Evidence, "203.0.113.9") || !strings.Contains(x.Evidence, "198.51.100.5") {
		t.Fatalf("not a node address: %+v", x)
	}
	if x := got["panel.link_host listener:"+good.ID]; x.Status != StatusOK {
		t.Fatalf("a public IP of the node: %+v", x)
	}
	if x := got["panel.link_host listener:"+bad.ID]; x.Status != StatusFail || !strings.Contains(x.Summary, "does not resolve") {
		t.Fatalf("does not resolve: %+v", x)
	}
	// A proxy's scope checks the host of its links only.
	p := e.proxy(good, nil)
	got = panelRun(t, e, n, "proxy:"+p.ID)
	if _, ok := got["panel.link_host "]; ok {
		t.Fatal("the node's link host in the scope of a proxy with a host of its own")
	}
	if x := got["panel.link_host listener:"+good.ID]; x.Status != StatusOK {
		t.Fatalf("%+v", x)
	}
	// No link host at all.
	n2 := e.node(func(n *store.Node) { n.LinkHost = "" })
	e.agent(n2.ID, &fakeNode{})
	if x := panelRun(t, e, n2, ScopeNode)["panel.link_host "]; x.Status != StatusFail {
		t.Fatalf("no link host: %+v", x)
	}
}

func TestPanelGeoIP(t *testing.T) {
	old := time.Now().Add(-70 * 24 * time.Hour)
	for _, c := range []struct {
		name   string
		policy string
		st     geodb.Status
		status string
	}{
		{"fresh", store.IPPolicyCountries, geodb.Status{Enabled: true, Present: true, Month: "2026-10", Built: time.Now()}, StatusOK},
		{"stale", store.IPPolicyCountries, geodb.Status{Enabled: true, Present: true, Month: "2026-07", Built: old}, StatusWarn},
		{"missing", store.IPPolicyFull, geodb.Status{Enabled: true}, StatusFail},
		{"not needed", store.IPPolicyOff, geodb.Status{Enabled: true}, StatusOK},
		{"lookups off", store.IPPolicyCountries, geodb.Status{}, StatusOK},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			s, _, err := e.db.StatsSettings(e.ctx)
			if err != nil {
				t.Fatal(err)
			}
			s.IPPolicy = c.policy
			if _, err := e.db.ApplyStatsSettings(e.ctx, s); err != nil {
				t.Fatal(err)
			}
			e.geo = c.st
			n := e.node(nil)
			e.agent(n.ID, &fakeNode{})
			if x := panelRun(t, e, n, ScopeNode)["panel.geoip "]; x.Status != c.status {
				t.Fatalf("%+v", x)
			}
		})
	}
}

func TestIngressExternal(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	l := e.listener(n.ID, 443, "")
	okP, l1P, failP := e.proxy(l, nil), e.proxy(l, nil), e.proxy(l, nil)
	paused := e.proxy(l, func(p *store.Proxy) { p.Enabled = false })
	web := e.proxy(l, func(p *store.Proxy) {
		p.Type, p.WebSecretMode, p.CertMode, p.Domain = store.ProxyTypeWeb, "plain", "external", "web.example.com"
	})
	unprobeable := e.proxy(l, nil)
	stopped := e.proxy(l, nil)
	e.prober.by[okP.ID] = proberAnswer{p: store.Probe{OK: true, LatencyMS: 12}}
	e.prober.by[l1P.ID] = proberAnswer{p: store.Probe{Error: "no datacenter answered through the proxy (L1 ok)"}, l1: true}
	e.prober.by[failP.ID] = proberAnswer{p: store.Probe{Error: "unreachable"}}
	e.prober.by[stopped.ID] = proberAnswer{err: context.Canceled}
	e.prober.by[web.ID] = proberAnswer{p: store.Probe{Error: probes.ErrWebNoHTTP}, l1: true}
	webOK := e.proxy(l, func(p *store.Proxy) {
		p.Type, p.WebSecretMode, p.CertMode, p.Domain = store.ProxyTypeWeb, "plain", "acme-dns01", "ok.example.com"
	})
	e.prober.by[webOK.ID] = proberAnswer{p: store.Probe{OK: true, LatencyMS: 30}, l1: true}
	webDown := e.proxy(l, func(p *store.Proxy) {
		p.Type, p.WebSecretMode, p.CertMode, p.Domain = store.ProxyTypeWeb, "plain", "acme-dns01", "down.example.com"
	})
	e.prober.by[webDown.ID] = proberAnswer{p: store.Probe{Error: probes.ErrWebCert}}
	e.agent(n.ID, &fakeNode{})
	got := panelRun(t, e, n, ScopeNode)
	for p, want := range map[*store.Proxy]string{
		okP: StatusOK, l1P: StatusWarn, failP: StatusFail, paused: StatusSkip, web: StatusWarn, unprobeable: StatusSkip, stopped: StatusSkip,
		webOK: StatusOK, webDown: StatusFail,
	} {
		x := got["ingress.external proxy:"+p.ID]
		if x.Status != want || x.Layer != "ingress" || x.Vantage != VantagePanel {
			t.Errorf("proxy %s: %+v, want %s", p.ID, x, want)
		}
	}
	if x := got["ingress.external proxy:"+failP.ID]; x.Evidence != "unreachable" {
		t.Errorf("fail evidence %q", x.Evidence)
	}
	if e.prober.calls != 8 {
		t.Errorf("probes %d: the paused proxy is not probed, the WEB ones are", e.prober.calls)
	}
	if x := got["ingress.external proxy:"+webOK.ID]; !strings.Contains(x.Summary, "HTTP/2") {
		t.Errorf("WEB ok: %+v", x)
	}
}

// web.base_path: a WEB proxy under a base path behind a web server must not
// get a redirect without the slash.
func TestWebBasePath(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	l := e.listener(n.ID, 443, "")
	web := func(base string) *store.Proxy {
		return e.proxy(l, func(p *store.Proxy) {
			p.Type, p.WebSecretMode, p.Domain, p.WebBasePath = store.ProxyTypeWeb, "plain", "site.example.com", base
		})
	}
	good, redirect, unreachable, other, noBase := web("tg"), web("a/b"), web("c"), web("d"), web("")
	e.prober.paths = map[string]basePathAnswer{
		good.ID:        {bp: probes.BasePath{Status: 200}},
		redirect.ID:    {bp: probes.BasePath{Status: 301, Location: "https://site.example.com/a/b/"}},
		unreachable.ID: {err: errors.New("the site did not answer: unreachable")},
		noBase.ID:      {bp: probes.BasePath{Status: 301}}, // never asked: no base path
	}
	e.agent(n.ID, &fakeNode{})
	got := panelRun(t, e, n, ScopeNode)
	if x := got["web.base_path proxy:"+good.ID]; x.Status != StatusOK || x.Layer != "web" || x.Vantage != VantagePanel {
		t.Errorf("good: %+v", x)
	}
	if x := got["web.base_path proxy:"+redirect.ID]; x.Status != StatusFail || !strings.Contains(x.Summary, "redirect (301)") || !strings.Contains(x.Evidence, "/a/b/") {
		t.Errorf("redirect: %+v", x)
	}
	if x := got["web.base_path proxy:"+unreachable.ID]; x.Status != StatusSkip {
		t.Errorf("unreachable: %+v", x)
	}
	for _, p := range []*store.Proxy{other, noBase} {
		if x, ok := got["web.base_path proxy:"+p.ID]; ok {
			t.Errorf("a result for a proxy that is not under a base path behind a web server: %+v", x)
		}
	}
}

func TestNetResolverIsUsedByDefault(t *testing.T) {
	r := NewRunner(Config{})
	if _, ok := r.cfg.Resolver.(netResolver); !ok {
		t.Fatal("not the system resolver")
	}
	if _, err := (netResolver{}).LookupNetIP(context.Background(), "ip", "localhost"); err != nil && !errors.Is(err, context.Canceled) {
		t.Logf("localhost: %v", err) // a host without localhost is no failure
	}
}
