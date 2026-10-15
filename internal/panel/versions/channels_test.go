package versions

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// fakeProxies answers AffectedByChannel from a table by node and channel, and
// records what WriteVersions was asked to bump.
type fakeProxies struct {
	mu       sync.Mutex
	affected map[string][]*panelv1.AffectedProxy // node id + "/" + channel
	bumped   [][]string
	writes   int
}

func (f *fakeProxies) AffectedByChannel(_ context.Context, nodeID, channel string) ([]*panelv1.AffectedProxy, error) {
	if nodeID == "gone" {
		return nil, store.ErrNotFound
	}
	return f.affected[nodeID+"/"+channel], nil
}

func (f *fakeProxies) WriteVersions(ctx context.Context, write func(ctx context.Context) ([]string, error)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	nodeIDs, err := write(ctx)
	if err != nil {
		return err
	}
	f.writes++
	f.bumped = append(f.bumped, slices.Clone(nodeIDs))
	return nil
}

// moveChannel moves the version of a channel, as a completed rollout does.
func (a *api) moveChannel(engine, channel, version string) {
	a.t.Helper()
	if err := a.db.SetChannelVersion(context.Background(), engine, channel, version); err != nil {
		a.t.Fatal(err)
	}
}

func (a *api) addNode(name, channel string) *store.Node {
	a.t.Helper()
	n := &store.Node{Name: name, MgmtHost: "198.51.100.1", MgmtPort: 61000, LinkHost: "203.0.113.10", EngineChannel: channel}
	if err := a.db.CreateNode(context.Background(), n); err != nil {
		a.t.Fatal(err)
	}
	return n
}

func (a *api) node(id string) *store.Node {
	a.t.Helper()
	n, err := a.db.NodeByID(context.Background(), id)
	if err != nil {
		a.t.Fatal(err)
	}
	return n
}

func TestSetNodeChannel(t *testing.T) {
	a := newAPI(t, true)
	n := a.addNode("n1", "")
	other := a.addNode("n2", "latest")
	affected := &panelv1.AffectedProxy{ProxyId: "p1", Name: "one", NodeId: n.ID, FromVersion: "3.5.13", ToVersion: "3.5.14"}
	fake := &fakeProxies{affected: map[string][]*panelv1.AffectedProxy{n.ID + "/latest": {affected}}}
	a.svc.SetProxies(fake)
	a.moveChannel("xray", "latest", "v26.3.28") // latest differs from stable for a provider only
	ctx := context.Background()
	client := a.client()

	// Without confirm: the list, nothing applied, nothing written.
	resp, err := client.SetNodeChannel(ctx, connect.NewRequest(&panelv1.SetNodeChannelRequest{NodeId: n.ID, Channel: "latest"}))
	if err != nil {
		t.Fatalf("SetNodeChannel: %v", err)
	}
	if resp.Msg.GetApplied() || len(resp.Msg.GetAffectedProxies()) != 1 || resp.Msg.GetAffectedProxies()[0].GetProxyId() != "p1" {
		t.Errorf("without confirm: %v, want applied=false with the affected proxy", resp.Msg)
	}
	if a.node(n.ID).EngineChannel != "" || fake.writes != 0 || len(fake.bumped) != 0 {
		t.Errorf("without confirm the node changed: channel %q, writes %d, bumps %v", a.node(n.ID).EngineChannel, fake.writes, fake.bumped)
	}

	// With confirm: applied, the node on the channel, its generation bumped.
	resp, err = client.SetNodeChannel(ctx, connect.NewRequest(&panelv1.SetNodeChannelRequest{NodeId: n.ID, Channel: "latest", Confirm: true}))
	if err != nil {
		t.Fatalf("SetNodeChannel(confirm): %v", err)
	}
	if !resp.Msg.GetApplied() || len(resp.Msg.GetAffectedProxies()) != 1 {
		t.Errorf("with confirm: %v, want applied=true with the affected proxy", resp.Msg)
	}
	if a.node(n.ID).EngineChannel != "latest" || fake.writes != 1 || len(fake.bumped) != 1 || !slices.Equal(fake.bumped[0], []string{n.ID}) {
		t.Errorf("with confirm: channel %q, writes %d, bumps %v; want latest, 1, [[%s]]", a.node(n.ID).EngineChannel, fake.writes, fake.bumped, n.ID)
	}
	// A node without an affected proxy is bumped all the same when the
	// channels differ for any component: its providers move (I1).
	resp, err = client.SetNodeChannel(ctx, connect.NewRequest(&panelv1.SetNodeChannelRequest{NodeId: other.ID, Channel: "", Confirm: true}))
	if err != nil || !resp.Msg.GetApplied() || len(resp.Msg.GetAffectedProxies()) != 0 {
		t.Errorf("back to the default: %v, %v; want applied with no affected proxy", resp, err)
	}
	if a.node(other.ID).EngineChannel != "" || len(fake.bumped) != 2 || !slices.Equal(fake.bumped[1], []string{other.ID}) {
		t.Errorf("back to the default: channel %q, bumps %v; want \"\" and the node bumped (xray differs)", a.node(other.ID).EngineChannel, fake.bumped)
	}
	// A move between channels that give the same versions bumps nothing.
	a.moveChannel("xray", "latest", "v26.3.27")
	resp, err = client.SetNodeChannel(ctx, connect.NewRequest(&panelv1.SetNodeChannelRequest{NodeId: other.ID, Channel: "latest", Confirm: true}))
	if err != nil || !resp.Msg.GetApplied() || len(fake.bumped) != 3 || len(fake.bumped[2]) != 0 {
		t.Errorf("to a channel with the same versions: %v, %v, bumps %v; want applied and no bump", resp, err, fake.bumped)
	}
	// The same channel again changes nothing either.
	resp, err = client.SetNodeChannel(ctx, connect.NewRequest(&panelv1.SetNodeChannelRequest{NodeId: other.ID, Channel: "latest", Confirm: true}))
	if err != nil || !resp.Msg.GetApplied() || len(fake.bumped) != 4 || len(fake.bumped[3]) != 0 {
		t.Errorf("the same channel again: %v, %v, bumps %v; want applied and no bump", resp, err, fake.bumped)
	}

	_, err = client.SetNodeChannel(ctx, connect.NewRequest(&panelv1.SetNodeChannelRequest{NodeId: n.ID, Channel: "nightly"}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("an unknown channel: %v, want invalid argument", err)
	}
	_, err = client.SetNodeChannel(ctx, connect.NewRequest(&panelv1.SetNodeChannelRequest{NodeId: "01K6Y00000000000000000000Z", Channel: "latest"}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an unknown node: %v, want not found", err)
	}
	if log := strings.Join(a.auditLog(), "\n"); !strings.Contains(log, "versions.node_channel") {
		t.Errorf("audit log has no versions.node_channel entry:\n%s", log)
	}
}

func TestSetDefaultChannel(t *testing.T) {
	a := newAPI(t, true)
	onDefault := a.addNode("d1", "")
	onDefault2 := a.addNode("d2", "")
	own := a.addNode("own", "stable")
	fake := &fakeProxies{affected: map[string][]*panelv1.AffectedProxy{
		onDefault.ID + "/latest": {{ProxyId: "p1", NodeId: onDefault.ID, FromVersion: "3.5.13", ToVersion: "3.5.14"}},
		own.ID + "/latest":       {{ProxyId: "px", NodeId: own.ID, FromVersion: "3.5.13", ToVersion: "3.5.14"}}, // never asked
	}}
	a.svc.SetProxies(fake)
	a.moveChannel("warp-plus", "latest", "v1.2.7") // latest differs from stable for a provider only
	ctx := context.Background()
	client := a.client()
	setting := func() string {
		t.Helper()
		def := ""
		if _, err := a.db.GetSetting(ctx, store.SettingDefaultChannel, &def); err != nil {
			t.Fatal(err)
		}
		return def
	}

	resp, err := client.SetDefaultChannel(ctx, connect.NewRequest(&panelv1.SetDefaultChannelRequest{Channel: "latest"}))
	if err != nil {
		t.Fatalf("SetDefaultChannel: %v", err)
	}
	if resp.Msg.GetApplied() || len(resp.Msg.GetAffectedProxies()) != 1 || resp.Msg.GetAffectedProxies()[0].GetProxyId() != "p1" {
		t.Errorf("without confirm: %v, want applied=false with p1 (the node on its own channel is not asked)", resp.Msg)
	}
	if setting() != "" || fake.writes != 0 {
		t.Errorf("without confirm the setting changed: %q, writes %d", setting(), fake.writes)
	}

	resp, err = client.SetDefaultChannel(ctx, connect.NewRequest(&panelv1.SetDefaultChannelRequest{Channel: "latest", Confirm: true}))
	if err != nil {
		t.Fatalf("SetDefaultChannel(confirm): %v", err)
	}
	if !resp.Msg.GetApplied() || len(resp.Msg.GetAffectedProxies()) != 1 {
		t.Errorf("with confirm: %v, want applied=true with p1", resp.Msg)
	}
	if setting() != "latest" || fake.writes != 1 || len(fake.bumped) != 1 || !slices.Equal(fake.bumped[0], []string{onDefault.ID, onDefault2.ID}) {
		t.Errorf("with confirm: setting %q, writes %d, bumps %v; want latest, 1, [[%s %s]] (every node on the default, the one on its own channel not)",
			setting(), fake.writes, fake.bumped, onDefault.ID, onDefault2.ID)
	}
	// Back to a channel with the same versions: written, no bump.
	a.moveChannel("warp-plus", "latest", "v1.2.6")
	resp, err = client.SetDefaultChannel(ctx, connect.NewRequest(&panelv1.SetDefaultChannelRequest{Channel: "stable", Confirm: true}))
	if err != nil || !resp.Msg.GetApplied() || setting() != "stable" || len(fake.bumped) != 2 || len(fake.bumped[1]) != 0 {
		t.Errorf("back to stable with the same versions: %v, %v, setting %q, bumps %v; want applied, stable, no bump", resp, err, setting(), fake.bumped)
	}
	_, err = client.SetDefaultChannel(ctx, connect.NewRequest(&panelv1.SetDefaultChannelRequest{Channel: ""}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("an empty default channel: %v, want invalid argument", err)
	}
	if log := strings.Join(a.auditLog(), "\n"); !strings.Contains(log, "versions.default_channel") {
		t.Errorf("audit log has no versions.default_channel entry:\n%s", log)
	}
}

func TestChannelsWithoutTheProxiesService(t *testing.T) {
	a := newAPI(t, true)
	_, err := a.client().SetDefaultChannel(context.Background(), connect.NewRequest(&panelv1.SetDefaultChannelRequest{Channel: "latest"}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Errorf("without the proxies service: %v, want unimplemented", err)
	}
	var cerr *connect.Error
	if !errors.As(err, &cerr) {
		t.Errorf("not a connect error: %v", err)
	}
}
