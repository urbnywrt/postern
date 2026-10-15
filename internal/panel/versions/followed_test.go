package versions

import (
	"context"
	"slices"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

func (a *api) addProxy(n *store.Node, name string, edit func(p *store.Proxy)) {
	a.t.Helper()
	ctx := context.Background()
	ps, err := a.db.ListProxies(ctx, store.ProxyFilter{})
	if err != nil {
		a.t.Fatal(err)
	}
	l := &store.Listener{NodeID: n.ID, Port: 1000 + uint32(len(ps))}
	if err := a.db.CreateListener(ctx, l); err != nil {
		a.t.Fatal(err)
	}
	p := &store.Proxy{NodeID: n.ID, ListenerID: l.ID, Name: name, SecretEnc: []byte("sealed"), Enabled: true}
	if edit != nil {
		edit(p)
	}
	if err := a.db.CreateProxy(ctx, p); err != nil {
		a.t.Fatal(err)
	}
}

func (a *api) followed() map[string][]string {
	a.t.Helper()
	resp, err := a.client().ListComponents(context.Background(), connect.NewRequest(&panelv1.ListComponentsRequest{}))
	if err != nil {
		a.t.Fatalf("ListComponents: %v", err)
	}
	out := map[string][]string{}
	for _, c := range resp.Msg.Components {
		out[c.Name] = c.FollowedChannels
	}
	return out
}

// TestFollowedChannels: engines only; a provider has no followed channels.
func TestFollowedChannels(t *testing.T) {
	a := newAPI(t, true)

	if got := a.followed(); len(got["telemt"]) != 0 || len(got["mtg"]) != 0 || len(got["xray"]) != 0 {
		t.Errorf("without proxies: %v", got)
	}

	def := a.addNode("n1", "")          // the default channel: stable
	latest := a.addNode("n2", "latest") // only pinned and mtg proxies
	a.addProxy(def, "follows", nil)
	a.addProxy(latest, "pinned", func(p *store.Proxy) {
		p.EngineVersionPolicy, p.EngineVersion = store.EnginePolicyPinned, "3.5.13"
	})
	a.addProxy(latest, "mtg", func(p *store.Proxy) { p.Engine = store.EngineMtg })

	got := a.followed()
	for comp, want := range map[string][]string{
		"telemt":       {store.ChannelStable},
		"mtg":          {store.ChannelLatest},
		"xray":         nil, // providers are not counted
		"psiphon-core": nil,
	} {
		if !slices.Equal(got[comp], want) {
			t.Errorf("%s follows %v, want %v", comp, got[comp], want)
		}
	}

	// The default channel moves: the node without one follows latest.
	if err := a.db.PutSetting(context.Background(), store.SettingDefaultChannel, store.ChannelLatest); err != nil {
		t.Fatal(err)
	}
	if got := a.followed(); !slices.Equal(got["telemt"], []string{store.ChannelLatest}) {
		t.Errorf("telemt follows %v after the default moved, want [latest]", got["telemt"])
	}
}
