package proxies

import (
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// mtgNode stores a node that has connected with the capabilities given, with
// a listener whose mask target is a public IP and one whose mask target is a
// name (which the node resolves for mtg).
func (e *env) mtgNode(capabilities ...string) (n *store.Node, ipListener, nameListener *panelv1.Listener) {
	e.t.Helper()
	n = e.addNode("n1", "203.0.113.10")
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error {
		seen := time.Now().Add(-time.Minute)
		n.HostInfo.Capabilities, n.LastSeenAt, n.Arch = capabilities, &seen, "amd64"
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	ipListener = e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, MaskTarget: "203.0.113.9:443"})
	nameListener = e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443, MaskTarget: "mask.example.com:443"})
	return n, ipListener, nameListener
}

func wantRefused(t *testing.T, err error, code connect.Code, mention string) {
	t.Helper()
	wantCode(t, err, code)
	if err != nil && !strings.Contains(err.Error(), mention) {
		t.Errorf("error %q does not mention %q", err, mention)
	}
}

func TestCreateProxyMtg(t *testing.T) {
	e := newEnv(t)
	n, ip, _ := e.mtgNode("faketls", CapEngineMtg)

	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Engine: "mtg", Name: "m"})
	if p.GetEngine() != "mtg" || p.GetEngineVersion() != DefaultMtgVersion || p.GetVersionSource() != "channel" || p.GetChannel() != "stable" {
		t.Errorf("mtg proxy = %v, want engine mtg at %s from the stable channel", p, DefaultMtgVersion)
	}
	st, err := e.builder.Build(e.ctx, n.ID, 1)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(st.GetProxies()) != 1 || st.GetProxies()[0].GetEngine() != nodev1.Engine_ENGINE_MTG || len(st.GetArtifacts()) != 1 || st.GetArtifacts()[0].GetEngine() != "mtg" {
		t.Errorf("the state of the node = %v, want the mtg proxy and the mtg artifact", st)
	}

	for _, tc := range []struct {
		name    string
		req     *panelv1.CreateProxyRequest
		code    connect.Code
		mention string
	}{
		{"an ad tag", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Engine: "mtg", AdTag: adTag1}, connect.CodeFailedPrecondition, "ad_tag"},
		{"the middle proxies on", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Engine: "mtg", UseMiddleProxy: "on"}, connect.CodeFailedPrecondition, "mtg has no middle proxy"},
		{"an engine the panel does not know", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Engine: "shadowsocks"}, connect.CodeInvalidArgument, "engine"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(tc.req))
			wantRefused(t, err, tc.code, tc.mention)
		})
	}
	// Only the one proxy was made.
	ps, err := e.db.ListProxies(e.ctx, store.ProxyFilter{NodeID: n.ID})
	if err != nil || len(ps) != 1 {
		t.Errorf("proxies = %v, %v; want the one mtg proxy", ps, err)
	}
	e.assertNoSecretsLogged()
}

func TestCreateProxyMtgNeedsTheCapability(t *testing.T) {
	e := newEnv(t)
	n, ip, _ := e.mtgNode("faketls")
	_, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Engine: "mtg"}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "upgrade node n1 to use the mtg engine (engine-mtg)")
	// telemt is still fine on it.
	e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId()})
}

func TestUpdateProxyRefusesWhatMakesAnMtgProxyInvalid(t *testing.T) {
	e := newEnv(t)
	n, ip, name := e.mtgNode("faketls", CapEngineMtg)
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Engine: "mtg"})

	tag := adTag1
	_, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), AdTag: &tag}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "mtg has no ad_tag support")
	on := "on"
	_, err = e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), UseMiddleProxy: &on}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "mtg has no middle proxy")
	move := name.GetId()
	// A listener whose mask target is a name is fine: the node resolves it to the
	// address mtg fronts to (internal/node/reconcile/fronting.go).
	if _, err = e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), ListenerId: &move})); err != nil {
		t.Errorf("UpdateProxy(listener with a mask name) = %v, want it taken", err)
	}
	// A harmless edit goes through, and the engine stays.
	newName := "renamed"
	resp, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), Name: &newName}))
	if err != nil || resp.Msg.GetProxy().GetEngine() != "mtg" || resp.Msg.GetProxy().GetName() != "renamed" {
		t.Errorf("UpdateProxy(name) = %v, %v; want the mtg proxy renamed", resp, err)
	}
	if got := e.storedProxy(p.GetId()); got.Engine != "mtg" || got.AdTag != "" {
		t.Errorf("stored proxy = %+v, want mtg without an ad tag", got)
	}
}

func TestPinNeedsAPinnedVersion(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	// Known, but without a SHA-256 for any architecture yet.
	rel := &store.Release{Engine: EngineTelemt, Version: "3.5.14", Tag: "3.5.14", Source: store.SourceUpstream,
		Assets: map[string]store.ReleaseAsset{"amd64": {File: "telemt-x86_64-linux-musl.tar.gz", URL: "https://example.invalid/t"}}}
	if err := e.db.UpsertRelease(e.ctx, rel); err != nil {
		t.Fatal(err)
	}
	_, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), EngineVersion: "3.5.14"}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "not pinned yet")
	if !strings.Contains(e.prepared.String(), "telemt 3.5.14 amd64") {
		t.Errorf("the refused pin did not start a Prepare; prepared:\n%s", e.prepared.String())
	}
	_, err = e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), EngineVersion: "9.9.9"}))
	wantRefused(t, err, connect.CodeInvalidArgument, "not a version of telemt")

	// Once pinned, the version can be pinned to, on create and on update.
	e.pinRelease(EngineTelemt, "3.5.14", false)
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), EngineVersion: "3.5.14"})
	if p.GetEngineVersion() != "3.5.14" || !p.GetEngineVersionPinned() || p.GetVersionSource() != "pinned" {
		t.Errorf("pinned proxy = %v, want 3.5.14 pinned", p)
	}
	none := ""
	resp, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), EngineVersion: &none}))
	if err != nil || resp.Msg.GetProxy().GetVersionSource() != "channel" || resp.Msg.GetProxy().GetEngineVersion() != DefaultTelemtVersion {
		t.Errorf("unpinned proxy = %v, %v; want the channel version", resp, err)
	}
	// A pin of a version without an asset for the node's architecture is
	// refused the same way.
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error { n.Arch = "arm64"; return nil }); err != nil {
		t.Fatal(err)
	}
	v := "3.5.14"
	_, err = e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), EngineVersion: &v}))
	wantRefused(t, err, connect.CodeFailedPrecondition, "not pinned yet for arm64")
}

func TestListProxiesFiltersByEngineAndOutdated(t *testing.T) {
	e := newEnv(t)
	n, ip, _ := e.mtgNode("faketls", CapEngineMtg)
	follows := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Name: "follows"})
	mtg := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Name: "mtg", Engine: "mtg", Domain: "m.example.com"})
	e.pinRelease(EngineTelemt, "3.5.14", true) // stable, newer than the channel version
	pinned := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Name: "pinned", EngineVersion: "3.5.14", Domain: "p.example.com"})

	list := func(req *panelv1.ListProxiesRequest) []string {
		t.Helper()
		resp, err := e.proxies.ListProxies(e.ctx, connect.NewRequest(req))
		if err != nil {
			t.Fatalf("ListProxies(%v): %v", req, err)
		}
		var names []string
		for _, p := range resp.Msg.GetProxies() {
			names = append(names, p.GetName())
		}
		return names
	}
	// marked are the proxies of the whole list that carry the outdated mark:
	// those of the outdated filter, in the list's order.
	marked := func() []string {
		t.Helper()
		resp, err := e.proxies.ListProxies(e.ctx, connect.NewRequest(&panelv1.ListProxiesRequest{}))
		if err != nil {
			t.Fatalf("ListProxies: %v", err)
		}
		var names []string
		for _, p := range resp.Msg.GetProxies() {
			if p.GetOutdated() {
				names = append(names, p.GetName())
			}
		}
		return names
	}
	if got := list(&panelv1.ListProxiesRequest{Engine: "mtg"}); len(got) != 1 || got[0] != "mtg" {
		t.Errorf("engine=mtg lists %v, want [mtg]", got)
	}
	if got := list(&panelv1.ListProxiesRequest{Engine: "telemt"}); len(got) != 2 {
		t.Errorf("engine=telemt lists %v, want follows and pinned", got)
	}
	// The channel version 3.5.13 is older than the newest stable release:
	// the proxy that follows the channel is outdated, the one pinned at
	// 3.5.14 is not, and mtg has nothing newer.
	if got := list(&panelv1.ListProxiesRequest{Outdated: true}); len(got) != 1 || got[0] != "follows" {
		t.Errorf("outdated lists %v, want [follows]", got)
	}
	if got := marked(); !slices.Equal(got, []string{"follows"}) {
		t.Errorf("marked outdated %v, want [follows]", got)
	}
	// A node that serves the pinned proxy with another version makes it
	// outdated too; one that serves it with the effective one does not.
	now := time.Now()
	e.ingestRec(n.ID, stateRec(1, now,
		&nodev1.ProxyStatus{ProxyId: pinned.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_TELEMT, RunningVersion: "3.5.13"},
		&nodev1.ProxyStatus{ProxyId: follows.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_TELEMT, RunningVersion: "3.5.13"},
		&nodev1.ProxyStatus{ProxyId: mtg.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_TELEMT, RunningVersion: "3.5.13"},
	))
	if got := list(&panelv1.ListProxiesRequest{Outdated: true}); len(got) != 3 {
		t.Errorf("outdated after the report lists %v, want all three (follows: newer stable; pinned: runs 3.5.13; mtg: served by telemt)", got)
	}
	if got, want := marked(), list(&panelv1.ListProxiesRequest{Outdated: true}); !slices.Equal(got, want) {
		t.Errorf("marked outdated %v, want those of the filter %v", got, want)
	}
	if got := list(&panelv1.ListProxiesRequest{Outdated: true, Engine: "mtg"}); len(got) != 1 || got[0] != "mtg" {
		t.Errorf("outdated mtg lists %v, want [mtg]", got)
	}
	e.ingestRec(n.ID, stateRec(2, now.Add(time.Second),
		&nodev1.ProxyStatus{ProxyId: pinned.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_TELEMT, RunningVersion: "3.5.14"},
		&nodev1.ProxyStatus{ProxyId: mtg.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_MTG, RunningVersion: DefaultMtgVersion},
	))
	if got := list(&panelv1.ListProxiesRequest{Outdated: true}); len(got) != 1 || got[0] != "follows" {
		t.Errorf("outdated after the second report lists %v, want [follows]", got)
	}
	// A proxy pinned above the newest release of its channel (a prerelease
	// that is not stable) is ahead, not outdated.
	e.pinRelease(EngineTelemt, "3.5.15", false)
	e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Name: "ahead", EngineVersion: "3.5.15", Domain: "a.example.com"})
	if got := list(&panelv1.ListProxiesRequest{Outdated: true}); len(got) != 1 || got[0] != "follows" {
		t.Errorf("outdated with a proxy ahead of the channel lists %v, want [follows]", got)
	}
}

func TestRunningEngineAfterAFailedSwitch(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
	now := time.Now()
	rec := stateRec(3, now, &nodev1.ProxyStatus{
		ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Reason: "mtg did not come up",
		Engine: nodev1.Engine_ENGINE_TELEMT, RunningVersion: "3.5.13", InstanceGeneration: 4,
		FailedEngine: nodev1.Engine_ENGINE_MTG, FailedVersion: "v2.2.8",
	})
	rec.GetState().AppliedGeneration = 9
	rec.GetState().EgressInstances = []*nodev1.EgressInstanceStatus{
		{EgressId: "e1", Provider: "xray", Version: "v26.3.27", Phase: "serving", Generation: 2},
		{EgressId: "e2", Provider: "warp-plus", Version: "v1.2.6", Phase: "failed", Reason: "exit 1", FailedVersion: "v1.2.7", Generation: 3},
	}
	e.ingestRec(n.ID, rec)

	resp, err := e.proxies.GetProxy(e.ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: p.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	st := resp.Msg.GetProxy().GetStatus()
	if st.GetRunningEngine() != "telemt" || st.GetRunningVersion() != "3.5.13" || st.GetFailedVersion() != "v2.2.8" || st.GetPhase() != "serving" {
		t.Errorf("status = %v, want telemt 3.5.13 serving with v2.2.8 failed", st)
	}
	rep, ok := e.ingest.ProxyReport(n.ID, p.GetId())
	if !ok || rep.FailedEngine != nodev1.Engine_ENGINE_MTG || rep.RunningEngine != nodev1.Engine_ENGINE_TELEMT || rep.ReportGeneration != 9 || rep.InstanceGeneration != 4 {
		t.Errorf("ProxyReport = %+v, %v", rep, ok)
	}
	egs := e.ingest.EgressReports(n.ID)
	if len(egs) != 2 || egs[1] != (EgressReport{EgressID: "e2", Provider: "warp-plus", Version: "v1.2.6", Phase: "failed", Reason: "exit 1", FailedVersion: "v1.2.7", Generation: 3, ReportGeneration: 9}) {
		t.Errorf("EgressReports = %+v", egs)
	}
	if e.ingest.EgressReports("01K6Y00000000000000000000Z") != nil {
		t.Error("EgressReports of an unknown node is not nil")
	}
	e.ingest.ForgetNode(n.ID)
	if e.ingest.EgressReports(n.ID) != nil {
		t.Error("EgressReports after ForgetNode is not nil")
	}
}
