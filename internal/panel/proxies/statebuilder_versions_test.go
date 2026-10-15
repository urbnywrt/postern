package proxies

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

const (
	goldenL3 = "01K6Y0000000000000000000A3"       // a listener whose mask target is a public IP, for mtg
	goldenP3 = "01K6Y0000000000000000000B3"       // an mtg proxy pinned at the built-in version
	goldenP4 = "01K6Y0000000000000000000B4"       // a telemt proxy held by a rollout
	secret3  = "0123456789abcdef0123456789abcdef" // gitleaks:allow (a made-up test value)
	secret4  = "fedcba9876543210fedcba9876543210" // gitleaks:allow (a made-up test value)
)

// setChannel moves the version of a channel, as a completed rollout does.
func (e *env) setChannel(engine, channel, version string) {
	e.t.Helper()
	if err := e.db.SetChannelVersion(e.ctx, engine, channel, version); err != nil {
		e.t.Fatal(err)
	}
}

// pinRelease stores an upstream release of comp with an asset for amd64
// pinned with a made-up SHA-256, state unchecked (not prepared), so that a
// state names it and nothing uploads it.
func (e *env) pinRelease(comp, version string, stable bool) {
	e.t.Helper()
	rel := &store.Release{Engine: comp, Version: version, Tag: version, Source: store.SourceUpstream, Stable: stable,
		Assets: map[string]store.ReleaseAsset{"amd64": {File: comp + "-" + version + "-amd64.tar.gz",
			URL: "https://example.invalid/" + comp + "/" + version, SHA256: sha256Hex([]byte(comp + version)), SHASource: store.SHASourceSums}}}
	if err := e.db.UpsertRelease(e.ctx, rel); err != nil {
		e.t.Fatal(err)
	}
}

// goldenVersionsNode is the golden node with egresses on latest, with a
// telemt proxy that follows the channel (P1), a telemt proxy pinned at the
// built-in version (P2), an mtg proxy pinned at the built-in version (P3), a
// telemt proxy held by a rollout (P4), and Xray at the node's own version.
func (e *env) goldenVersionsNode() *store.Node {
	e.t.Helper()
	n := e.goldenEgressNode("amd64")
	e.setChannel(EngineTelemt, store.ChannelLatest, "3.5.14")
	e.pinRelease(EngineTelemt, "3.5.14", false)
	e.pinRelease(EngineTelemt, "3.5.15", false)
	e.pinRelease(EngineXray, "v26.3.28", false)
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error {
		n.EngineChannel = store.ChannelLatest
		n.ProviderVersions = map[string]string{EngineXray: "v26.3.28"}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	e.addListener(&store.Listener{ID: goldenL3, NodeID: n.ID, BindIP: "198.51.100.8", Port: 9443, MaskTarget: "203.0.113.9:443"})
	for _, p := range []*store.Proxy{
		{ID: goldenP3, NodeID: n.ID, ListenerID: goldenL3, Name: "three", Enabled: true, Engine: store.EngineMtg,
			SecretEnc: e.sealSecret(goldenP3, secret3), Domain: "mtg.example.com",
			EngineVersionPolicy: store.EnginePolicyPinned, EngineVersion: DefaultMtgVersion},
		{ID: goldenP4, NodeID: n.ID, ListenerID: goldenL1, Name: "four", Enabled: true,
			SecretEnc: e.sealSecret(goldenP4, secret4), Domain: "roll.example.com",
			EngineVersionPolicy: store.EnginePolicyRollout, EngineVersion: "3.5.15"},
	} {
		if err := e.db.CreateProxy(e.ctx, p); err != nil {
			e.t.Fatal(err)
		}
	}
	return e.node(n.ID)
}

func TestStateBuilderGoldenVersions(t *testing.T) {
	e := newEnv(t)
	n := e.goldenVersionsNode()

	st, err := e.builder.Build(e.ctx, n.ID, 11)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	versions := map[string][2]string{}
	for _, p := range st.GetProxies() {
		versions[p.GetId()] = [2]string{p.GetEngine().String(), p.GetEngineVersion()}
	}
	want := map[string][2]string{
		goldenP1: {"ENGINE_TELEMT", "3.5.14"}, // follows latest
		goldenP2: {"ENGINE_TELEMT", "3.5.13"}, // pinned
		goldenP3: {"ENGINE_MTG", "v2.2.8"},    // pinned mtg
		goldenP4: {"ENGINE_TELEMT", "3.5.15"}, // held by a rollout
	}
	for id, w := range want {
		if versions[id] != w {
			t.Errorf("proxy %s runs %v, want %v", id, versions[id], w)
		}
	}
	var artifacts []string
	for _, a := range st.GetArtifacts() {
		artifacts = append(artifacts, a.GetEngine()+" "+a.GetVersion())
	}
	wantArtifacts := []string{"mtg v2.2.8", "psiphon-core 20261005-c4a09096ab", "telemt 3.5.13", "telemt 3.5.14", "telemt 3.5.15", "xray v26.3.28"}
	if len(artifacts) != len(wantArtifacts) {
		t.Errorf("artifacts = %v, want %v", artifacts, wantArtifacts)
	} else {
		for i := range artifacts {
			if artifacts[i] != wantArtifacts[i] {
				t.Errorf("artifact %d = %q, want %q", i, artifacts[i], wantArtifacts[i])
			}
		}
	}
	// None of them is prepared: a pinned SHA-256 is enough to name them (F10).
	for _, a := range st.GetArtifacts() {
		if a.GetSha256() == "" {
			t.Errorf("artifact %s %s is named without a SHA-256", a.GetEngine(), a.GetVersion())
		}
	}

	redacted := proto.Clone(st).(*nodev1.NodeState)
	for _, p := range redacted.GetProxies() {
		p.Secret = "<secret of " + p.GetId() + ">"
	}
	for _, eg := range redacted.GetEgresses() {
		eg.ParamsJson = "<params of " + eg.GetId() + ">"
	}
	got := goldenJSON(t, redacted)
	path := filepath.Join("testdata", "state_versions.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wantJSON, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the golden file (run with -update to write it): %v", err)
	}
	if !bytes.Equal(got, wantJSON) {
		t.Errorf("the state differs from %s (run with -update to accept a change):\ngot:\n%s", path, got)
	}
	back := &nodev1.NodeState{}
	if err := protojson.Unmarshal(wantJSON, back); err != nil {
		t.Fatalf("the golden file does not read back: %v", err)
	}
	if !proto.Equal(back, redacted) {
		t.Error("the golden file does not read back as the built state")
	}
	if err := validateState(st); err != nil {
		t.Errorf("validateState of the built state: %v", err)
	}
	e.assertNoSecretsLogged()
}
