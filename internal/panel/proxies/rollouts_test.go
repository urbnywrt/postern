package proxies

import (
	"slices"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// A switch to mtg is checked as CreateProxy checks an mtg proxy, and the
// links of a proxy do not change when its engine does.
func TestCheckEngineSwitch(t *testing.T) {
	e := newEnv(t)
	n, ip, name := e.mtgNode("faketls", CapEngineMtg)
	plain := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Name: "plain"})
	tagged := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Name: "tagged", AdTag: adTag1})
	named := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: name.GetId(), Name: "named"})

	if err := e.svc.CheckEngineSwitch(e.ctx, n.ID, []string{plain.GetId()}, store.EngineMtg, ""); err != nil {
		t.Errorf("a plain proxy to mtg: %v", err)
	}
	if err := e.svc.CheckEngineSwitch(e.ctx, n.ID, []string{plain.GetId()}, store.EngineMtg, DefaultMtgVersion); err != nil {
		t.Errorf("a plain proxy to mtg, pinned: %v", err)
	}
	wantRefused(t, e.svc.CheckEngineSwitch(e.ctx, n.ID, []string{plain.GetId(), tagged.GetId()}, store.EngineMtg, ""),
		connect.CodeFailedPrecondition, "ad_tag")
	// A proxy without an override fronts to the address of its own domain,
	// which the agent resolves (spec 5.5): a named listener is fine; an
	// override has to be a public IP address.
	if err := e.svc.CheckEngineSwitch(e.ctx, n.ID, []string{named.GetId()}, store.EngineMtg, ""); err != nil {
		t.Errorf("a proxy on a named listener to mtg: %v", err)
	}
	hostMask := e.storedProxy(named.GetId())
	hostMask.MaskTargetOverride = "cdn.example.com:443"
	if err := e.db.UpdateProxy(e.ctx, hostMask); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, e.svc.CheckEngineSwitch(e.ctx, n.ID, []string{named.GetId()}, store.EngineMtg, ""),
		connect.CodeFailedPrecondition, "IP address only")
	wantRefused(t, e.svc.CheckEngineSwitch(e.ctx, n.ID, []string{"nope"}, store.EngineMtg, ""), connect.CodeNotFound, "not on the node")
	// Nothing was written.
	if p := e.storedProxy(tagged.GetId()); p.Engine != store.EngineTelemt {
		t.Errorf("the check wrote engine %s", p.Engine)
	}

	before, err := LinksOf(e.ctx, e.db, e.key, e.storedProxy(plain.GetId()))
	if err != nil {
		t.Fatal(err)
	}
	p := e.storedProxy(plain.GetId())
	p.Engine = store.EngineMtg
	if err := e.db.UpdateProxy(e.ctx, p); err != nil {
		t.Fatal(err)
	}
	after, err := LinksOf(e.ctx, e.db, e.key, e.storedProxy(plain.GetId()))
	if err != nil || after != before {
		t.Errorf("links after the switch %v (%v), before %v", after, err, before)
	}
}

func TestCheckEngineSwitchNeedsTheCapability(t *testing.T) {
	e := newEnv(t)
	n, ip, _ := e.mtgNode("faketls")
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId()})
	wantRefused(t, e.svc.CheckEngineSwitch(e.ctx, n.ID, []string{p.GetId()}, store.EngineMtg, ""),
		connect.CodeFailedPrecondition, "upgrade node n1 to use the mtg engine (engine-mtg)")
}

func TestNodeProviders(t *testing.T) {
	e := newEnv(t)
	n := e.goldenEgressNode("amd64")
	got, err := e.svc.NodeProviders(e.ctx, n.ID)
	if err != nil || !slices.Equal(got, []string{EnginePsiphonCore, EngineXray}) {
		t.Errorf("NodeProviders = %v, %v", got, err)
	}
}

// The other refusals of mtg: the middle proxies, overrides of telemt, a NAT
// IP. Each is checked on a proxy of its own.
func TestCheckEngineSwitchMtgRefusals(t *testing.T) {
	e := newEnv(t)
	n, ip, _ := e.mtgNode("faketls", CapEngineMtg)
	for _, tc := range []struct {
		name    string
		set     func(p *store.Proxy)
		mention string
	}{
		{"middle proxy", func(p *store.Proxy) { p.UseMiddleProxy = "on" }, "no middle proxy"},
		{"overrides", func(p *store.Proxy) { p.EngineOverrides = map[string]any{"tg_connect": float64(10)} }, "telemt overrides do not apply to mtg"},
		{"nat ip", func(p *store.Proxy) { p.NATIP = "203.0.113.20" }, "nat_ip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			created := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: ip.GetId(), Name: tc.name})
			p := e.storedProxy(created.GetId())
			tc.set(p)
			if err := e.db.UpdateProxy(e.ctx, p); err != nil {
				t.Fatal(err)
			}
			wantRefused(t, e.svc.CheckEngineSwitch(e.ctx, n.ID, []string{p.ID}, store.EngineMtg, ""), connect.CodeFailedPrecondition, tc.mention)
			// As telemt it is fine; the next case does not see it.
			if err := e.svc.CheckEngineSwitch(e.ctx, n.ID, []string{p.ID}, store.EngineTelemt, ""); err != nil {
				t.Errorf("the same proxy on telemt: %v", err)
			}
			if err := e.db.DeleteProxy(e.ctx, p.ID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
