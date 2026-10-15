package diagnostics

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/geodb"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// feedFixture is a fleet with something wrong everywhere.
type feedFixture struct {
	e                *env
	feed             *Feed
	alpha            *store.Node
	p1, p2, p3, pOff *store.Proxy
}

func newFeedFixture(t *testing.T) *feedFixture {
	e := newEnv(t)
	now := e.now.Truncate(time.Second)
	e.now = now
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	e.geo = geodb.Status{Enabled: true, Present: false, Error: "download failed from 192.0.2.9"}

	alpha := e.node(func(n *store.Node) {
		n.Name = "alpha"
		n.EdgeVersion = "1.1.0"
		n.StateRejection = "unknown field from 192.0.2.7"
		n.LastError = "docker does not answer"
		n.HostInfo.Capabilities = []string{"diagnostics", "dns-forwarder", "restart-nonce"}
	})
	lastSeen := ago(time.Hour)
	bravo := e.node(func(n *store.Node) { n.Name = "bravo"; n.Status = store.NodeStatusOffline; n.LastSeenAt = &lastSeen })
	e.node(func(n *store.Node) {
		n.Name = "charlie"
		n.Status = store.NodeStatusProvisioning
		n.LastError = "never seen"
	})
	delta := e.node(func(n *store.Node) { n.Name = "delta"; n.Status = store.NodeStatusError })
	if err := e.db.AppendEvent(e.ctx, &store.Event{NodeID: delta.ID, TS: ago(5 * time.Minute), Kind: KindNodeError, Severity: "error",
		Message: "the node's certificate is not trusted"}); err != nil {
		t.Fatal(err)
	}

	l := e.listener(alpha.ID, 443, "")
	p1 := e.proxy(l, func(p *store.Proxy) { p.Name = "p1" })
	p2 := e.proxy(l, func(p *store.Proxy) { p.Name = "p2" })
	p3 := e.proxy(l, func(p *store.Proxy) { p.Name = "p3" })
	pOff := e.proxy(l, func(p *store.Proxy) { p.Name = "paused"; p.Enabled = false })
	lb := e.listener(bravo.ID, 443, "")
	pb := e.proxy(lb, func(p *store.Proxy) { p.Name = "pb" })

	// The light checks of alpha: host.dns fails since 30 min, engine.container
	// of p1 warns since 10 min; ok and skip are no problems.
	checks := func(engine string) []store.NodeCheck {
		return []store.NodeCheck{
			{CheckID: "host.dns", Layer: "host", Status: StatusFail, Summary: "the resolver forges answers", Hint: "use DoH", Fix: "set_dns_mode_doh"},
			{CheckID: "engine.container", Layer: "engine", Target: "proxy:" + p1.ID, Status: engine, Summary: "the container restarted", Fix: "recreate_instance"},
			{CheckID: "host.disk", Layer: "host", Status: StatusOK, Summary: "fine"},
			{CheckID: "host.clock", Layer: "host", Status: StatusSkip, Summary: "skipped"},
		}
	}
	if _, err := e.db.ReplaceNodeChecks(e.ctx, alpha.ID, checks(StatusOK), ago(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.ReplaceNodeChecks(e.ctx, alpha.ID, checks(StatusWarn), ago(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// bravo is offline: what it reported last is not listed.
	if _, err := e.db.ReplaceNodeChecks(e.ctx, bravo.ID, []store.NodeCheck{{CheckID: "host.dns", Layer: "host", Status: StatusFail}}, ago(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// p1 failed 2 min ago (its newest proxy.failed event); its node reports
	// it failed again and again, which does not move the since.
	for _, at := range []time.Duration{40 * time.Minute, 2 * time.Minute} {
		if err := e.db.AppendEvent(e.ctx, &store.Event{NodeID: alpha.ID, ProxyID: p1.ID, TS: ago(at), Kind: KindProxyFailed, Severity: "error"}); err != nil {
			t.Fatal(err)
		}
	}
	reports := map[string]proxies.ProxyReport{
		p1.ID:   {Phase: nodev1.ProxyPhase_PROXY_PHASE_FAILED, Reason: "the engine exited", Reported: now},
		p3.ID:   {Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Reported: ago(time.Minute)},
		pOff.ID: {Phase: nodev1.ProxyPhase_PROXY_PHASE_FAILED, Reported: ago(time.Minute)},
		pb.ID:   {Phase: nodev1.ProxyPhase_PROXY_PHASE_FAILED, Reported: ago(time.Minute)},
	}
	down := map[string]bool{p2.ID: true, pOff.ID: true}
	feed := NewFeed(FeedConfig{DB: e.db,
		ProxyReport: func(_, id string) (proxies.ProxyReport, bool) { r, ok := reports[id]; return r, ok },
		Down:        func(id string) bool { return down[id] },
		GeoIP:       func(context.Context) (geodb.Status, error) { return e.geo, nil },
		Now:         func() time.Time { return e.now }})
	// p2's probes: ok, then failing since 20 min.
	feed.OnProbe(store.Probe{ProxyID: p2.ID, Vantage: VantagePanel, OK: true, TS: ago(25 * time.Minute)})
	feed.OnProbe(store.Probe{ProxyID: p2.ID, Vantage: VantagePanel, Error: "refused", TS: ago(20 * time.Minute)})
	feed.OnProbe(store.Probe{ProxyID: p2.ID, Vantage: "node", OK: true, TS: ago(18 * time.Minute)}) // not the panel's
	feed.OnProbe(store.Probe{ProxyID: p2.ID, Vantage: VantagePanel, Error: "unreachable from 192.0.2.8", TS: ago(15 * time.Minute)})
	return &feedFixture{e: e, feed: feed, alpha: alpha, p1: p1, p2: p2, p3: p3, pOff: pOff}
}

// line is a problem as "severity kind node proxy check since-minutes-ago".
func line(now time.Time, p *panelv1.Problem) string {
	ago := "-"
	if p.SinceUnix != 0 {
		ago = now.Sub(time.Unix(p.SinceUnix, 0)).Round(time.Minute).String()
	}
	return strings.Join([]string{p.Severity, p.Kind, p.NodeName, p.ProxyName, p.CheckId, ago}, " ")
}

func TestProblemFeedCompositionAndOrder(t *testing.T) {
	f := newFeedFixture(t)
	got, err := f.feed.List(f.e.ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, p := range got {
		lines = append(lines, line(f.e.now, p))
	}
	want := []string{
		"error proxy.failed alpha p1  2m0s",
		"error node.error delta   5m0s",
		"error proxy.down alpha p2  20m0s",
		"error check alpha  host.dns 30m0s",
		"error node.offline bravo   1h0m0s",
		"error geoip.missing   panel.geoip -",
		"error node.state_rejected alpha   -",
		"warning check alpha p1 engine.container 10m0s",
		"warning edge.outdated alpha  panel.versions -",
		"warning node.last_error alpha   -",
	}
	if !slices.Equal(lines, want) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	by := map[string]*panelv1.Problem{}
	for _, p := range got {
		by[p.Kind+" "+p.CheckId] = p
	}
	if p := by["check engine.container"]; p.Fix != "recreate_instance" || !p.FixAvailable || p.Target != "proxy:"+f.p1.ID || p.ProxyId != f.p1.ID {
		t.Errorf("engine.container = %+v, want its fix available on the proxy", p)
	}
	if p := by["check host.dns"]; p.Fix != "set_dns_mode_doh" || !p.FixAvailable || p.Hint != "use DoH" {
		t.Errorf("host.dns = %+v", p)
	}
	if p := by["edge.outdated panel.versions"]; p.Fix != "roll_edge" || p.FixAvailable || !strings.Contains(p.FixUnavailableReason, "edge-roll-nonce") || p.Target != "" {
		t.Errorf("edge.outdated = %+v, want roll_edge unavailable without the capability", p)
	}
	for _, k := range []string{"node.state_rejected ", "proxy.down ", "node.error ", "geoip.missing panel.geoip"} {
		if p := by[k]; strings.Contains(p.Summary, "192.0.2.") {
			t.Errorf("%s: a client address in %q", k, p.Summary)
		}
	}
	if s := by["proxy.down "].Summary; !strings.Contains(s, "unreachable from <ip>") {
		t.Errorf("proxy.down summary = %q, want the newest error", s)
	}
	if s := by["node.error "].Summary; !strings.Contains(s, "certificate is not trusted") {
		t.Errorf("node.error summary = %q, want the event's message", s)
	}
}

func TestProblemFeedFilters(t *testing.T) {
	f := newFeedFixture(t)
	got, err := f.feed.List(f.e.ctx, "", f.p1.ID)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, p := range got {
		lines = append(lines, line(f.e.now, p))
	}
	want := []string{"error proxy.failed alpha p1  2m0s", "warning check alpha p1 engine.container 10m0s"}
	if !slices.Equal(lines, want) {
		t.Errorf("proxy p1: %v, want %v", lines, want)
	}
	got, err = f.feed.List(f.e.ctx, f.alpha.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 {
		t.Errorf("node alpha: %d problems, want 7", len(got))
	}
	for _, p := range got {
		if p.NodeId != f.alpha.ID {
			t.Errorf("node alpha: %s of node %q", p.Kind, p.NodeName)
		}
	}
}

// A proxy that the panel found down before it started has the start of its
// failing probes from the stored probes; a probe that passes ends it.
func TestProblemFeedDownSinceFromStore(t *testing.T) {
	e := newEnv(t)
	now := e.now.Truncate(time.Second)
	e.now = now
	n := e.node(nil)
	p := e.proxy(e.listener(n.ID, 443, ""), nil)
	for _, x := range []store.Probe{
		{TS: now.Add(-40 * time.Minute), OK: false, Error: "old"},
		{TS: now.Add(-30 * time.Minute), OK: true},
		{TS: now.Add(-20 * time.Minute), OK: false, Error: "first"},
		{TS: now.Add(-10 * time.Minute), OK: false, Error: "second"},
	} {
		x.ProxyID, x.Vantage, x.Kind = p.ID, VantagePanel, "l2"
		if err := e.db.InsertProbe(e.ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	down := true
	feed := NewFeed(FeedConfig{DB: e.db, Down: func(string) bool { return down }, Now: func() time.Time { return e.now }})
	got, err := feed.List(e.ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != KindProxyDown || got[0].SinceUnix != now.Add(-20*time.Minute).Unix() || !strings.HasSuffix(got[0].Summary, ": second") {
		t.Fatalf("problems = %v, want proxy.down since 20 min with the newest error", got)
	}
	feed.OnProbe(store.Probe{ProxyID: p.ID, Vantage: VantagePanel, OK: true, TS: now})
	feed.OnProbe(store.Probe{ProxyID: p.ID, Vantage: VantagePanel, Error: "again", TS: now.Add(time.Minute)})
	e.now = now.Add(time.Minute)
	got, err = feed.List(e.ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SinceUnix != now.Add(time.Minute).Unix() {
		t.Fatalf("problems = %v, want a new streak", got)
	}
	down = false
	if got, err = feed.List(e.ctx, "", ""); err != nil || len(got) != 0 {
		t.Fatalf("problems = %v, %v, want none once the proxy is up", got, err)
	}
}

// GeoIP: stale is a warning, fresh or not needed is no problem.
func TestProblemFeedGeoIP(t *testing.T) {
	e := newEnv(t)
	feed := NewFeed(FeedConfig{DB: e.db, GeoIP: func(context.Context) (geodb.Status, error) { return e.geo, nil }, Now: func() time.Time { return e.now }})
	kinds := func() []string {
		t.Helper()
		got, err := feed.List(e.ctx, "", "")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, p := range got {
			out = append(out, p.Severity+" "+p.Kind)
		}
		return out
	}
	if k := kinds(); len(k) != 0 {
		t.Errorf("fresh: %v", k)
	}
	e.geo.Built = e.now.Add(-70 * 24 * time.Hour)
	if k := kinds(); !slices.Equal(k, []string{"warning geoip.stale"}) {
		t.Errorf("stale: %v", k)
	}
	s, _, err := e.db.StatsSettings(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.IPPolicy = store.IPPolicyOff
	e.geo.Present = false
	if _, err := e.db.ApplyStatsSettings(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	if k := kinds(); len(k) != 0 {
		t.Errorf("policy off: %v", k)
	}
}

func TestListProblemsAPI(t *testing.T) {
	f := newFeedFixture(t)
	a := newAPIFor(t, f.e, NewService(f.e.db, nil, nil, WithFeed(f.feed)))
	if _, err := a.anon.ListProblems(f.e.ctx, connect.NewRequest(&panelv1.ListProblemsRequest{})); codeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("anonymous: %v", err)
	}
	res, err := a.admin.ListProblems(f.e.ctx, connect.NewRequest(&panelv1.ListProblemsRequest{ProxyId: f.p2.ID}))
	if err != nil {
		t.Fatal(err)
	}
	if ps := res.Msg.GetProblems(); len(ps) != 1 || ps[0].GetKind() != KindProxyDown || ps[0].GetProxyName() != "p2" {
		t.Errorf("problems of p2 = %v", ps)
	}
	if _, err := a.admin.ListProblems(f.e.ctx, connect.NewRequest(&panelv1.ListProblemsRequest{NodeId: "x", ProxyId: "y"})); codeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("both filters: %v", err)
	}
}
