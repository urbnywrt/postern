package proxies

import (
	"context"
	"testing"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// testChannels is a channel table: telemt and xray on both channels, mtg on
// stable only.
var testChannels = map[string]map[string]string{
	"telemt": {"stable": "3.5.13", "latest": "3.5.14"},
	"xray":   {"stable": "v26.3.27", "latest": "v26.3.28"},
	"mtg":    {"stable": "v2.2.8"},
}

func TestEffectiveVersion(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		p                           *store.Proxy
		nodeChannel, defaultChannel string
		want                        Effective
	}{
		{"pinned", &store.Proxy{EngineVersionPolicy: store.EnginePolicyPinned, EngineVersion: "3.5.12"}, "latest", "stable",
			Effective{"telemt", "3.5.12", SourcePinned}},
		{"rollout", &store.Proxy{Engine: "telemt", EngineVersionPolicy: store.EnginePolicyRollout, EngineVersion: "3.5.14"}, "", "stable",
			Effective{"telemt", "3.5.14", SourceRollout}},
		{"the channel of the node", &store.Proxy{EngineVersionPolicy: store.EnginePolicyChannel}, "latest", "stable",
			Effective{"telemt", "3.5.14", SourceChannel}},
		{"the default channel", &store.Proxy{EngineVersionPolicy: store.EnginePolicyChannel}, "", "latest",
			Effective{"telemt", "3.5.14", SourceChannel}},
		{"no default set is stable", &store.Proxy{}, "", "",
			Effective{"telemt", "3.5.13", SourceChannel}},
		{"a channel the table lacks takes the default", &store.Proxy{Engine: "mtg"}, "latest", "stable",
			Effective{"mtg", "v2.2.8", SourceChannel}},
		{"an unknown channel takes the default", &store.Proxy{}, "nightly", "latest",
			Effective{"telemt", "3.5.14", SourceChannel}},
		{"pinned without a version follows the channel", &store.Proxy{EngineVersionPolicy: store.EnginePolicyPinned}, "stable", "stable",
			Effective{"telemt", "3.5.13", SourceChannel}},
		{"an unknown engine has no version", &store.Proxy{Engine: "nope"}, "stable", "stable",
			Effective{"nope", "", SourceChannel}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EffectiveVersion(tc.p, tc.nodeChannel, tc.defaultChannel, testChannels); got != tc.want {
				t.Errorf("EffectiveVersion = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestProviderVersion(t *testing.T) {
	n := &store.Node{EngineChannel: "latest", ProviderVersions: map[string]string{"xray": "v26.3.29"}}
	if got := ProviderVersion(n, "xray", "stable", testChannels); got != "v26.3.29" {
		t.Errorf("the override of the node = %q, want v26.3.29", got)
	}
	n.ProviderVersions = nil
	if got := ProviderVersion(n, "xray", "stable", testChannels); got != "v26.3.28" {
		t.Errorf("the channel of the node = %q, want v26.3.28", got)
	}
	n.EngineChannel = ""
	if got := ProviderVersion(n, "xray", "stable", testChannels); got != "v26.3.27" {
		t.Errorf("the default channel = %q, want v26.3.27", got)
	}
}

func TestAffectedByChannel(t *testing.T) {
	e := newEnv(t)
	e.setChannel("telemt", "latest", "3.5.14")
	n, l := e.nodeWithListener()
	follows := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Name: "Follows"})
	pinned := e.storedProxy(e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Name: "Pinned"}).GetId())
	pinned.EngineVersionPolicy, pinned.EngineVersion = store.EnginePolicyPinned, "3.5.13"
	if err := e.db.UpdateProxy(e.ctx, pinned); err != nil {
		t.Fatal(err)
	}

	list, err := e.svc.AffectedByChannel(e.ctx, n.ID, "latest")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].GetProxyId() != follows.GetId() || list[0].GetFromVersion() != "3.5.13" || list[0].GetToVersion() != "3.5.14" ||
		list[0].GetName() != "Follows" || list[0].GetNodeId() != n.ID {
		t.Errorf("affected by latest = %v, want the proxy that follows its channel, 3.5.13 → 3.5.14", list)
	}
	// The channel it is on already, by the default, changes nothing; and the
	// default itself ("") is stable here.
	for _, ch := range []string{"stable", ""} {
		if list, err := e.svc.AffectedByChannel(e.ctx, n.ID, ch); err != nil || len(list) != 0 {
			t.Errorf("affected by %q = %v, %v; want none", ch, list, err)
		}
	}
	if _, err := e.svc.AffectedByChannel(e.ctx, "01K6Y00000000000000000000Z", "latest"); err == nil {
		t.Error("an unknown node: no error")
	}
}

func TestNotifyChannelBumpsTheNodesOnIt(t *testing.T) {
	e := newEnv(t)
	onDefault := e.addNode("default", "203.0.113.10")
	onLatest := e.addNode("latest", "203.0.113.11")
	if _, err := e.db.ModifyNode(e.ctx, onLatest.ID, func(n *store.Node) error { n.EngineChannel = "latest"; return nil }); err != nil {
		t.Fatal(err)
	}
	before := e.notes.count()
	if err := e.svc.NotifyChannel(e.ctx, "telemt", "latest"); err != nil {
		t.Fatal(err)
	}
	if e.generation(onLatest.ID) != 1 || e.generation(onDefault.ID) != 0 || e.notes.count() != before+1 {
		t.Errorf("generations = %d (latest), %d (default), notifications %d; want 1, 0, %d",
			e.generation(onLatest.ID), e.generation(onDefault.ID), e.notes.count(), before+1)
	}
	// "" is the default channel: stable here.
	if err := e.svc.NotifyChannel(e.ctx, "telemt", ""); err != nil {
		t.Fatal(err)
	}
	if e.generation(onDefault.ID) != 1 || e.generation(onLatest.ID) != 1 {
		t.Errorf("after the default channel moved: generations = %d (default), %d (latest); want 1, 1",
			e.generation(onDefault.ID), e.generation(onLatest.ID))
	}
}

func TestWriteVersionsWritesThenBumps(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	var genAtWrite uint64
	err := e.svc.WriteVersions(e.ctx, func(ctx context.Context) ([]string, error) {
		genAtWrite = e.generation(n.ID)
		return []string{n.ID, n.ID, "01K6Y00000000000000000000Z"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if genAtWrite != 0 || e.generation(n.ID) != 1 {
		t.Errorf("generation at the write %d, after %d; want 0 and 1 (a node named twice is bumped once, a gone node skipped)", genAtWrite, e.generation(n.ID))
	}
	if err := e.svc.WriteVersions(e.ctx, func(context.Context) ([]string, error) { return []string{n.ID}, store.ErrConflict }); err == nil {
		t.Error("a failed write: no error")
	}
	if e.generation(n.ID) != 1 {
		t.Error("a failed write bumped the node")
	}
}
