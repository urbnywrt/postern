package proxies

import (
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// setArtifactSource stores the artifact source of a node, without the
// capability check of WriteArtifactSource.
func (e *env) setArtifactSource(nodeID, source string) {
	e.t.Helper()
	if _, err := e.db.ModifyNode(e.ctx, nodeID, func(n *store.Node) error {
		n.ArtifactSource = source
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
}

func TestStateBuilderURLOnlyForDirectNodes(t *testing.T) {
	e := newEnv(t)
	n := e.goldenNode("amd64")
	const url = "https://github.com/telemt/telemt/releases/download/3.5.13/telemt-x86_64-linux-musl.tar.gz"
	for _, tc := range []struct {
		source, wantSetting, wantURL string
	}{
		{store.ArtifactSourcePanel, "", ""},
		{store.ArtifactSourceDirect, store.ArtifactSourceDirect, url},
		{"", "", ""},
	} {
		e.setArtifactSource(n.ID, tc.source)
		st, err := e.builder.Build(e.ctx, n.ID, 1)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if got := st.GetSettings().GetArtifactSource(); got != tc.wantSetting {
			t.Errorf("source %q: settings.artifact_source = %q, want %q", tc.source, got, tc.wantSetting)
		}
		if len(st.GetArtifacts()) != 1 || st.GetArtifacts()[0].GetUrl() != tc.wantURL {
			t.Errorf("source %q: artifacts = %v, want one with url %q", tc.source, st.GetArtifacts(), tc.wantURL)
		}
	}
}

func TestEnsureArtifactsDirectNodeSkipsThePushAndUploadsAtRecheck(t *testing.T) {
	e := newEnv(t)
	e.catalog.chunkSize = 1000
	ready := e.readyRelease(store.AssetReady)
	node := &uploadNode{}
	client := serveUploadNode(t, node)
	st := stateWith(ready)
	st.Generation = 2
	st.Settings = &nodev1.NodeSettings{ArtifactSource: store.ArtifactSourceDirect}

	// The push of generation 2 to a node that has 1: it downloads for itself.
	info := infoWith([]string{CapArtifactDirect, CapArtifactTrial})
	info.DesiredGeneration = 1
	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", info, st, client); err != nil {
		t.Fatalf("EnsureArtifacts at push: %v", err)
	}
	if len(node.got()) != 0 {
		t.Fatalf("%d uploads at push to a direct node, want none", len(node.got()))
	}

	// The resync after: the node has the state and still lacks the artifact.
	info.DesiredGeneration = 2
	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", info, st, client); err != nil {
		t.Fatalf("EnsureArtifacts at recheck: %v", err)
	}
	if len(node.got()) != 1 {
		t.Fatalf("%d uploads at recheck, want 1", len(node.got()))
	}

	// A node without the capability gets it at push, whatever the state says.
	node2 := &uploadNode{}
	old := infoWith([]string{CapArtifactTrial})
	old.DesiredGeneration = 1
	if err := e.catalog.EnsureArtifacts(e.ctx, "n1", old, st, serveUploadNode(t, node2)); err != nil {
		t.Fatalf("EnsureArtifacts without the capability: %v", err)
	}
	if len(node2.got()) != 1 {
		t.Errorf("%d uploads at push to a node without %s, want 1", len(node2.got()), CapArtifactDirect)
	}
}

func TestWriteArtifactSourceNeedsTheCapability(t *testing.T) {
	e := newEnv(t)
	n := e.goldenNode("amd64")
	node := func() *store.Node {
		got, err := e.db.NodeByID(e.ctx, n.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	before := node().DesiredGeneration

	err := e.svc.WriteArtifactSource(e.ctx, n.ID, store.ArtifactSourceDirect)
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("direct without the capability: %v, want FailedPrecondition", err)
	}
	if got := node(); got.DesiredGeneration != before || got.ArtifactSource != "" {
		t.Errorf("a refused change: source %q, generation %d; want panel and %d", got.ArtifactSource, got.DesiredGeneration, before)
	}

	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error {
		n.HostInfo.Capabilities = []string{CapArtifactDirect}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.WriteArtifactSource(e.ctx, n.ID, store.ArtifactSourceDirect); err != nil {
		t.Fatalf("direct with the capability: %v", err)
	}
	if got := node(); got.ArtifactSource != store.ArtifactSourceDirect || got.DesiredGeneration != before+1 {
		t.Errorf("source %q, generation %d; want direct and %d", got.ArtifactSource, got.DesiredGeneration, before+1)
	}
	// The same value again changes nothing.
	if err := e.svc.WriteArtifactSource(e.ctx, n.ID, store.ArtifactSourceDirect); err != nil || node().DesiredGeneration != before+1 {
		t.Errorf("an unchanged source: %v, generation %d; want nil and %d", err, node().DesiredGeneration, before+1)
	}
	if err := e.svc.WriteArtifactSource(e.ctx, n.ID, "torrent"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("artifact_source torrent: %v, want InvalidArgument", err)
	}
	if err := e.svc.WriteArtifactSource(e.ctx, "nope", store.ArtifactSourceDirect); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an unknown node: %v, want NotFound", err)
	}
}
