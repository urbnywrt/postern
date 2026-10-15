package proxies

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// readyFile puts the file of a pinned release (pinRelease) into the directory
// of the catalog with the pinned SHA-256 and marks the asset ready.
func (e *env) readyFile(comp, version string) {
	e.t.Helper()
	file := comp + "-" + version + "-amd64.tar.gz"
	dir := filepath.Join(e.relDir, comp, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte(comp+version), 0o644); err != nil {
		e.t.Fatal(err)
	}
	if err := e.db.SetAssetState(e.ctx, comp, version, "amd64", store.AssetReady, "", ""); err != nil {
		e.t.Fatal(err)
	}
}

// TestStateBuilderHoldsWhatIsNotReady: a proxy, or a provider, that its node
// reports running stays at that version while the version it is to run is not
// ready, or is unusable, for the node; one the node does not report, or that
// runs the wanted version already, is named ready or not (F10).
func TestStateBuilderHoldsWhatIsNotReady(t *testing.T) {
	e := newEnv(t)
	n := e.goldenEgressNode("amd64")
	now := time.Now()
	report := func(seq uint64, proxies []*nodev1.ProxyStatus, egress []*nodev1.EgressInstanceStatus) {
		t.Helper()
		rec := stateRec(seq, now.Add(time.Duration(seq)*time.Second), proxies...)
		rec.GetState().EgressInstances = egress
		e.ingestRec(n.ID, rec)
	}
	versionOf := func(st *nodev1.NodeState, id string) string {
		for _, p := range st.GetProxies() {
			if p.GetId() == id {
				return p.GetEngineVersion()
			}
		}
		return "?"
	}
	artifactOf := func(st *nodev1.NodeState, engine string) string {
		var got []string
		for _, a := range st.GetArtifacts() {
			if a.GetEngine() == engine {
				got = append(got, a.GetVersion())
			}
		}
		return strings.Join(got, " ")
	}

	// P1 follows stable, which moves to 3.5.14: pinned but not prepared.
	e.pinRelease(EngineTelemt, "3.5.14", true)
	e.setChannel(EngineTelemt, store.ChannelStable, "3.5.14")
	// Without a report the new version is named.
	st, err := e.builder.Build(e.ctx, n.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if v := versionOf(st, goldenP1); v != "3.5.14" {
		t.Errorf("P1 without a report runs %q, want 3.5.14 (named ready or not)", v)
	}
	// Running 3.5.13: held there while 3.5.14 is not ready.
	report(1, []*nodev1.ProxyStatus{{ProxyId: goldenP1, Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_TELEMT, RunningVersion: "3.5.13"}},
		[]*nodev1.EgressInstanceStatus{{EgressId: goldenE1, Provider: EngineXray, Version: "v26.3.27", Phase: "serving"}})
	st, err = e.builder.Build(e.ctx, n.ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if v := versionOf(st, goldenP1); v != "3.5.13" {
		t.Errorf("P1 running 3.5.13 with 3.5.14 unprepared runs %q, want 3.5.13", v)
	}
	if v := artifactOf(st, EngineTelemt); v != "3.5.13" {
		t.Errorf("telemt artifact = %q, want 3.5.13 (the held version)", v)
	}
	// Unusable too.
	if err := e.db.SetAssetState(e.ctx, EngineTelemt, "3.5.14", "amd64", store.AssetUnusable, "trial failed", n.ID); err != nil {
		t.Fatal(err)
	}
	if st, err = e.builder.Build(e.ctx, n.ID, 3); err != nil || versionOf(st, goldenP1) != "3.5.13" {
		t.Errorf("P1 with 3.5.14 unusable runs %q, %v; want 3.5.13", versionOf(st, goldenP1), err)
	}
	// Ready: it moves.
	e.readyFile(EngineTelemt, "3.5.14")
	if st, err = e.builder.Build(e.ctx, n.ID, 4); err != nil || versionOf(st, goldenP1) != "3.5.14" || artifactOf(st, EngineTelemt) != "3.5.13 3.5.14" {
		t.Errorf("P1 with 3.5.14 ready runs %q (artifact %q), %v; want 3.5.14", versionOf(st, goldenP1), artifactOf(st, EngineTelemt), err)
	}
	// A proxy that runs another engine than it is to run is not held by it.
	report(2, []*nodev1.ProxyStatus{{ProxyId: goldenP1, Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_MTG, RunningVersion: "v2.2.8"}}, nil)
	e.setChannel(EngineTelemt, store.ChannelStable, "3.5.15")
	e.pinRelease(EngineTelemt, "3.5.15", true)
	if st, err = e.builder.Build(e.ctx, n.ID, 5); err != nil || versionOf(st, goldenP1) != "3.5.15" {
		t.Errorf("P1 served by mtg runs %q, %v; want 3.5.15", versionOf(st, goldenP1), err)
	}

	// A provider: the node's override v26.3.28 is not prepared, Xray runs
	// v26.3.27: the artifact stays at v26.3.27.
	e.pinRelease(EngineXray, "v26.3.28", false)
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error {
		n.ProviderVersions = map[string]string{EngineXray: "v26.3.28"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	report(3, nil, []*nodev1.EgressInstanceStatus{{EgressId: goldenE1, Provider: EngineXray, Version: "v26.3.27", Phase: "serving"}})
	if st, err = e.builder.Build(e.ctx, n.ID, 6); err != nil || artifactOf(st, EngineXray) != "v26.3.27" {
		t.Errorf("xray artifact with v26.3.28 unprepared = %q, %v; want v26.3.27", artifactOf(st, EngineXray), err)
	}
	e.readyFile(EngineXray, "v26.3.28")
	if st, err = e.builder.Build(e.ctx, n.ID, 7); err != nil || artifactOf(st, EngineXray) != "v26.3.28" {
		t.Errorf("xray artifact with v26.3.28 ready = %q, %v; want v26.3.28", artifactOf(st, EngineXray), err)
	}
	// psiphon-core (psiphon egress) is not reported: named as it is.
	if v := artifactOf(st, EnginePsiphonCore); v != DefaultPsiphonCoreVersion {
		t.Errorf("psiphon-core artifact = %q, want %s", v, DefaultPsiphonCoreVersion)
	}
}
