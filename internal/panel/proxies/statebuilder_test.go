package proxies

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/mtg"
	"github.com/urbnywrt/postern/internal/engines/telemt"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// update rewrites the golden files in testdata:
//
//	go test ./internal/panel/proxies -run TestStateBuilderGolden -update
var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// The fixed ids of the golden node.
const (
	goldenNodeID = "01K6Y0000000000000000000N1"
	goldenL1     = "01K6Y0000000000000000000A1"
	goldenL2     = "01K6Y0000000000000000000A2"
	goldenP1     = "01K6Y0000000000000000000B1"
	goldenP2     = "01K6Y0000000000000000000B2"
)

// sealSecret seals a proxy secret the way the panel stores it.
func (e *env) sealSecret(proxyID, secret string) []byte {
	e.t.Helper()
	b, err := seal.Seal(e.key, []byte(secret), []byte("proxy:"+proxyID))
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

// exec runs a statement on the database through a connection of its own, for
// rows that no repository writes (egress chains).
func (e *env) exec(query string, args ...any) {
	e.t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(e.dbPath)+"?_pragma=foreign_keys(1)")
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(query, args...); err != nil {
		e.t.Fatalf("exec %q: %v", query, err)
	}
}

// goldenNode stores a node with two listeners and a proxy on each, with fixed
// ids: P1 enabled with limits and the recommended version, P2 paused with an
// ad tag and a pinned version.
func (e *env) goldenNode(arch string) *store.Node {
	e.t.Helper()
	n := &store.Node{ID: goldenNodeID, Name: "golden", MgmtHost: "198.51.100.1", MgmtPort: 61000, LinkHost: "203.0.113.10", Arch: arch}
	if err := e.db.CreateNode(e.ctx, n); err != nil {
		e.t.Fatal(err)
	}
	for _, l := range []*store.Listener{
		{ID: goldenL1, NodeID: n.ID, BindIP: "0.0.0.0", Port: 443},
		{
			ID: goldenL2, NodeID: n.ID, BindIP: "198.51.100.7", Port: 8443, LinkHostOverride: "edge.example.com",
			StrangerAction: store.StrangerReject, MaskTarget: "mask.example.com:443", NonTLSAction: store.NonTLSHTTP400,
		},
	} {
		if err := e.db.CreateListener(e.ctx, l); err != nil {
			e.t.Fatal(err)
		}
	}
	for _, p := range []*store.Proxy{
		{
			ID: goldenP1, NodeID: n.ID, ListenerID: goldenL1, Name: "one", Enabled: true,
			SecretEnc: e.sealSecret(goldenP1, secret1), Domain: "cdn.example.com",
			LimitDevices: 3, LimitConnsTotal: 100, LimitConnsPerIP: 10,
		},
		{
			ID: goldenP2, NodeID: n.ID, ListenerID: goldenL2, Name: "two", Enabled: false,
			SecretEnc: e.sealSecret(goldenP2, secret2), Domain: "WWW.Example.COM", AdTag: adTag1,
			EngineVersionPolicy: store.EnginePolicyPinned, EngineVersion: DefaultTelemtVersion,
		},
	} {
		if err := e.db.CreateProxy(e.ctx, p); err != nil {
			e.t.Fatal(err)
		}
	}
	return n
}

// goldenJSON is protojson with stable whitespace (protojson randomizes it).
func goldenJSON(t *testing.T, m proto.Message) []byte {
	t.Helper()
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var compact, out bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Indent(&out, compact.Bytes(), "", "  "); err != nil {
		t.Fatal(err)
	}
	out.WriteByte('\n')
	return out.Bytes()
}

func TestStateBuilderGolden(t *testing.T) {
	e := newEnv(t)
	n := e.goldenNode("arm64")

	st, err := e.builder.Build(e.ctx, n.ID, 7)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if st.GetGeneration() != 7 {
		t.Errorf("generation = %d, want 7", st.GetGeneration())
	}
	// The secrets are the decrypted ones; the golden file does not hold them.
	if len(st.GetProxies()) != 2 || st.GetProxies()[0].GetSecret() != secret1 || st.GetProxies()[1].GetSecret() != secret2 {
		t.Fatalf("the proxies do not carry their decrypted secrets")
	}
	redacted := proto.Clone(st).(*nodev1.NodeState)
	for _, p := range redacted.GetProxies() {
		p.Secret = "<secret of " + p.GetId() + ">"
	}
	got := goldenJSON(t, redacted)

	path := filepath.Join("testdata", "state_two_proxies.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the golden file (run with -update to write it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the state differs from %s (run with -update to accept a change):\ngot:\n%s", path, got)
	}
	// The golden file reads back as the same state.
	back := &nodev1.NodeState{}
	if err := protojson.Unmarshal(want, back); err != nil {
		t.Fatalf("the golden file does not read back: %v", err)
	}
	if !proto.Equal(back, redacted) {
		t.Error("the golden file does not read back as the built state")
	}
	// And the real state is one that the node accepts.
	if err := validateState(st); err != nil {
		t.Errorf("validateState of the built state: %v", err)
	}
	e.assertNoSecretsLogged()
}

func TestStateBuilderArtifactsFollowTheArchOfTheNode(t *testing.T) {
	for _, tc := range []struct {
		arch, file, sha string
	}{
		{"", "telemt-x86_64-linux-musl.tar.gz", "7124a854310d4c91a502aeebfd29f7fc6ddef1dcd44eb0cb72e9f9c176582b43"},
		{"amd64", "telemt-x86_64-linux-musl.tar.gz", "7124a854310d4c91a502aeebfd29f7fc6ddef1dcd44eb0cb72e9f9c176582b43"},
		{"arm64", "telemt-aarch64-linux-musl.tar.gz", "f7b5181f1160e9ec73eb28705040bf159782055ec71f54a20214e2c9a6d997cd"},
	} {
		t.Run("arch "+tc.arch, func(t *testing.T) {
			e := newEnv(t)
			n := e.goldenNode(tc.arch)
			st, err := e.builder.Build(e.ctx, n.ID, 1)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			wantArch := tc.arch
			if wantArch == "" {
				wantArch = "amd64"
			}
			want := []*nodev1.ArtifactRef{{
				Engine:   "telemt",
				Version:  DefaultTelemtVersion,
				Arch:     wantArch,
				Sha256:   tc.sha,
				FileName: tc.file,
				// no Url: the node gets its artifacts from the panel
				Binary: "telemt",
			}}
			if len(st.GetArtifacts()) != 1 || !proto.Equal(st.GetArtifacts()[0], want[0]) {
				t.Errorf("artifacts = %v, want %v", st.GetArtifacts(), want)
			}
		})
	}

	// An architecture that has no build names no artifact: the node reports
	// the proxies as failed with the reason, instead of getting no state.
	e := newEnv(t)
	n := e.goldenNode("riscv64")
	st, err := e.builder.Build(e.ctx, n.ID, 1)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(st.GetArtifacts()) != 0 {
		t.Errorf("artifacts for riscv64 = %v, want none", st.GetArtifacts())
	}
	if len(st.GetProxies()) != 2 {
		t.Errorf("%d proxies, want 2", len(st.GetProxies()))
	}
}

func TestStateBuilderForANodeWithoutProxies(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("empty", "203.0.113.10")
	st, err := e.builder.Build(e.ctx, n.ID, 3)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := &nodev1.NodeState{
		Generation: 3,
		Settings: &nodev1.NodeSettings{
			DefaultChainId: "default",
			DomainPool:     testPool,
			// The defaults of the statistics settings: countries, 7 days.
			IpPolicy:         nodev1.IpPolicy_IP_POLICY_COUNTRIES,
			IpRetentionHours: 168,
		},
		Egresses: []*nodev1.Egress{{Id: "direct", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT}},
		Chains:   []*nodev1.EgressChain{{Id: "default", MemberEgressIds: []string{"direct"}}},
	}
	if !proto.Equal(st, want) {
		t.Errorf("state = %v\nwant %v", st, want)
	}
	if err := validateState(st); err != nil {
		t.Errorf("validateState: %v", err)
	}

	_, err = e.builder.Build(e.ctx, "01K6Y00000000000000000000Z", 1)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Build of an unknown node: %v, want store.ErrNotFound", err)
	}
}

// TestStateBuilderNeverEmitsWhatTheNodeRefuses: rows that the API never
// writes, but a hand or an older or newer panel could, make Build fail rather
// than send a state that the node would refuse as a whole.
func TestStateBuilderNeverEmitsWhatTheNodeRefuses(t *testing.T) {
	tests := []struct {
		name string
		mod  func(e *env)
	}{
		{"IPv6 listener", func(e *env) {
			e.addListener(&store.Listener{NodeID: goldenNodeID, BindIP: "2001:db8::1", Port: 9443})
		}},
		{"http-upstream listener", func(e *env) {
			e.addListener(&store.Listener{NodeID: goldenNodeID, Kind: store.ListenerKindHTTPUpstream, BindIP: "127.0.0.1", Port: 40001})
		}},
		{"listeners that overlap", func(e *env) {
			e.addListener(&store.Listener{NodeID: goldenNodeID, BindIP: "198.51.100.9", Port: 443})
		}},
		{"a listener with a stranger action that the panel does not know", func(e *env) {
			e.addListener(&store.Listener{NodeID: goldenNodeID, BindIP: "198.51.100.9", Port: 9443, StrangerAction: "banish"})
		}},
		{"a listener with a non-TLS action that the panel does not know", func(e *env) {
			e.addListener(&store.Listener{NodeID: goldenNodeID, BindIP: "198.51.100.9", Port: 9443, NonTLSAction: "http500"})
		}},
		{"a listener with a trusted CIDR that the edge cannot read", func(e *env) {
			e.addListener(&store.Listener{NodeID: goldenNodeID, BindIP: "198.51.100.9", Port: 9443, TrustedCIDRs: []string{"192.0.2.0/33"}})
		}},
		{"two proxies with one domain on a listener", func(e *env) {
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "CDN.example.com"}, secret2)
		}},
		{"two proxies on a listener whose domains differ by a dot at the end", func(e *env) {
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "cdn.example.com."}, secret2)
		}},
		{"a secret that is not 32 hex digits", func(e *env) {
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x.example.com"}, "not-a-secret")
		}},
		{"a bad ad tag", func(e *env) {
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x.example.com", AdTag: "123"}, secret2)
		}},
		{"a WEB proxy", func(e *env) {
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x.example.com", Type: store.ProxyTypeWeb}, secret2)
		}},
		{"an mtg proxy with an ad tag", func(e *env) {
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x.example.com", Engine: store.EngineMtg, AdTag: adTag1}, secret2)
		}},
		{"engine overrides", func(e *env) {
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x.example.com", EngineOverrides: map[string]any{"workers": 4}}, secret2)
		}},
		{"a bad pinned version", func(e *env) {
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x.example.com", EngineVersionPolicy: store.EnginePolicyPinned, EngineVersion: "../3"}, secret2)
		}},
		{"a domain with a space", func(e *env) {
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x example.com"}, secret2)
		}},
		{"a domain that the edge does not route", func(e *env) {
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x_y.example.com"}, secret2)
		}},
		{"a paused proxy with a domain that the edge does not route", func(e *env) {
			// Its domain is a mask domain all the same.
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "пример.example"}, secret2)
			p := e.storedProxy("01K6Y0000000000000000000B9")
			p.Enabled = false
			if err := e.db.UpdateProxy(e.ctx, p); err != nil {
				e.t.Fatal(err)
			}
		}},
		{"a proxy with an egress chain that has no members", func(e *env) {
			e.exec(`INSERT INTO egress_chains (id, name) VALUES ('CHAIN1', 'chain')`)
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x.example.com", EgressChainID: "CHAIN1"}, secret2)
		}},
		{"a proxy with a scope chain that does not exist", func(e *env) {
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x.example.com", EgressScopeChains: map[string]string{"me": "CHAIN1"}}, secret2)
		}},
		{"a node with a default chain that has no members", func(e *env) {
			e.exec(`INSERT INTO egress_chains (id, name) VALUES ('CHAIN1', 'chain')`)
			if _, err := e.db.ModifyNode(e.ctx, goldenNodeID, func(n *store.Node) error { n.DefaultChainID = "CHAIN1"; return nil }); err != nil {
				e.t.Fatal(err)
			}
		}},
		{"a secret sealed for another proxy", func(e *env) {
			p := &store.Proxy{
				NodeID: goldenNodeID, ListenerID: goldenL1, Domain: "x.example.com", Enabled: true,
				SecretEnc: e.sealSecret(goldenP1, secret2),
			}
			if err := e.db.CreateProxy(e.ctx, p); err != nil {
				e.t.Fatal(err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.goldenNode("amd64")
			if _, err := e.builder.Build(e.ctx, goldenNodeID, 1); err != nil {
				t.Fatalf("Build before the change: %v", err)
			}
			tc.mod(e)
			st, err := e.builder.Build(e.ctx, goldenNodeID, 2)
			if err == nil {
				// The state is not printed: it has the secrets.
				t.Fatalf("Build made a state of %d proxies, want an error", len(st.GetProxies()))
			}
			if st != nil {
				t.Errorf("Build returned a state with its error")
			}
			if strings.Contains(err.Error(), secret2) || strings.Contains(err.Error(), secret1) {
				t.Errorf("the error has a secret in it")
			}
		})
	}
}

// addListener stores a listener as it is, past the checks of the service.
func (e *env) addListener(l *store.Listener) {
	e.t.Helper()
	if err := e.db.CreateListener(e.ctx, l); err != nil {
		e.t.Fatalf("CreateListener: %v", err)
	}
}

// addProxy stores an enabled proxy of the golden node as it is, past the
// checks of the service, with secret sealed as the panel seals it.
func (e *env) addProxy(p *store.Proxy, secret string) {
	e.t.Helper()
	p.NodeID = goldenNodeID
	p.Enabled = true
	p.ID = "01K6Y0000000000000000000B9"
	p.SecretEnc = e.sealSecret(p.ID, secret)
	if err := e.db.CreateProxy(e.ctx, p); err != nil {
		e.t.Fatalf("CreateProxy: %v", err)
	}
}

// validState is a state that the node accepts: two listeners, a proxy on
// each (with the same domain, which is fine on two listeners), and the
// implicit direct chain.
func validState() *nodev1.NodeState {
	return &nodev1.NodeState{
		Generation: 1,
		Settings: &nodev1.NodeSettings{
			DefaultChainId: "default",
			DomainPool:     []string{"a.example"},
			IpPolicy:       nodev1.IpPolicy_IP_POLICY_OFF,
		},
		Listeners: []*nodev1.Listener{
			{
				Id: "L1", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "0.0.0.0", Port: 443,
				StrangerAction: nodev1.StrangerAction_STRANGER_ACTION_MASK, NonTlsAction: nodev1.NonTlsAction_NON_TLS_ACTION_DROP,
			},
			{
				Id: "L2", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "198.51.100.7", Port: 8443,
				StrangerAction: nodev1.StrangerAction_STRANGER_ACTION_REJECT, NonTlsAction: nodev1.NonTlsAction_NON_TLS_ACTION_HTTP400,
			},
		},
		Proxies: []*nodev1.Proxy{
			{
				Id: "P1", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Enabled: true,
				Secret: secret1, Domain: "a.example.com", Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
			},
			{
				Id: "P2", ListenerId: "L2", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS,
				Secret: secret2, Domain: "A.Example.com", Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
				AdTag: adTag1, UseMiddleProxy: true, EngineOverridesJson: "{}",
			},
		},
		Egresses: []*nodev1.Egress{{Id: "direct", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT}},
		Chains:   []*nodev1.EgressChain{{Id: "default", MemberEgressIds: []string{"direct"}}},
	}
}

// TestValidateStateKeepsStoredDomains: a stored domain is used as it is, in its
// letter case and with a dot at its end, which the edge folds away; only new
// values (checkDomain) are held to the stricter rule.
func TestValidateStateKeepsStoredDomains(t *testing.T) {
	for _, d := range []string{"A.Example.COM", "a.example.com.", "x--y.example", "-a.example", "203.0.113.5", "localhost"} {
		st := validState()
		st.Proxies[0].Domain = d
		if err := validateState(st); err != nil {
			t.Errorf("domain %q: %v", d, err)
		}
	}
}

// nodeSupports is what the engine drivers of a node serve, asked as the agent
// asks them (agent.Service.supports) when it validates a state: the drivers of
// internal/engines that a node of this version runs.
func nodeSupports(e nodev1.Engine, t nodev1.ProxyType) bool {
	drivers := map[nodev1.Engine]engines.Driver{nodev1.Engine_ENGINE_TELEMT: telemt.New(), nodev1.Engine_ENGINE_MTG: mtg.New()}
	d, ok := drivers[e]
	return ok && d != nil && d.Supports(t)
}

// TestPanelRefusesExactlyWhatTheNodeRefuses: the panel judges a whole state by
// the node's own rules (state.Validate, with the engines of this version), so
// over a corpus of states it refuses exactly the states that the node refuses,
// in the node's words, and takes the others. The corpus has states of both
// kinds: the rules of the edge that the node keeps to (mask targets, trusted
// CIDRs, the members of egress chains), what the node takes as it is (an action
// that is not set, an IPv4-mapped bind address), and what neither takes.
func TestPanelRefusesExactlyWhatTheNodeRefuses(t *testing.T) {
	long := strings.Repeat("u", 256)
	tests := []struct {
		name    string
		mod     func(st *nodev1.NodeState)
		refused string // a part of the error of a state that is refused; "" for one that is taken
	}{
		{"a valid state", func(*nodev1.NodeState) {}, ""},
		// The node takes these.
		{"stranger action not set, which the node reads as mask", func(st *nodev1.NodeState) { st.Listeners[1].StrangerAction = 0 }, ""},
		{"non-TLS action not set, which the node reads as drop", func(st *nodev1.NodeState) { st.Listeners[1].NonTlsAction = 0 }, ""},
		{"an IPv4-mapped bind address, which the edge binds as IPv4", func(st *nodev1.NodeState) { st.Listeners[1].BindIp = "::ffff:198.51.100.7" }, ""},
		{"trusted CIDRs that the edge reads", func(st *nodev1.NodeState) {
			st.Listeners[0].TrustedCidrs = []string{"192.0.2.0/24", "198.51.100.7", "2001:db8::/32", "::ffff:192.0.2.0/120"}
		}, ""},
		{"a mask target on the loopback outside the internal ports", func(st *nodev1.NodeState) { st.Listeners[0].MaskTarget = "127.0.0.1:8443" }, ""},
		{"a socks5 egress with an address and credentials", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "s5", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5,
				ParamsJson: `{"addr": "198.51.100.9:1080", "username": "u", "password": "p"}`})
		}, ""},
		{"a health check of the default chain", func(st *nodev1.NodeState) {
			st.Chains[0].Check = &nodev1.HealthCheck{DcAddrs: []string{"149.154.175.50:443"}}
		}, ""},
		// The egresses of slice 2.
		{"an xray-uri egress with a share link", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "xu", Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_URI, ParamsJson: `{"uri": "` + fakeVLESS + `"}`})
		}, ""},
		{"an xray-subscription egress of every server", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "xs", Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
				ParamsJson: `{"url": "https://sub.example.com/s", "select": "all"}`})
		}, ""},
		{"an xray-subscription egress of the first server", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "xs", Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
				ParamsJson: `{"url": "https://sub.example.com/s", "select": "first"}`})
		}, ""},
		{"an xray-subscription egress by name", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "xs", Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
				ParamsJson: `{"url": "http://sub.example.com/s", "select": "name:Germany"}`})
		}, ""},
		{"an xray-subscription egress without a selection, which is every server", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "xs", Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
				ParamsJson: `{"url": "https://sub.example.com/s"}`})
		}, ""},
		{"a refresh nonce", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "xs", Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
				ParamsJson: `{"url": "https://sub.example.com/s"}`, RefreshNonce: 7})
		}, ""},
		{"a warp egress", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "w", Kind: nodev1.EgressKind_EGRESS_KIND_WARP, ParamsJson: `{}`})
		}, ""},
		{"a warp egress without parameters", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "w", Kind: nodev1.EgressKind_EGRESS_KIND_WARP})
		}, ""},
		{"a psiphon egress, its country in any case", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "ps", Kind: nodev1.EgressKind_EGRESS_KIND_PSIPHON, ParamsJson: `{"country": "de"}`})
		}, ""},
		{"a scope chain for downloads", func(st *nodev1.NodeState) { st.Proxies[0].EgressScopeChains = map[string]string{"fetch": "default"} }, ""},
		{"a scope chain for the middle proxies", func(st *nodev1.NodeState) { st.Proxies[1].EgressScopeChains = map[string]string{"me": "default"} }, ""},
		{"an interface egress from an address", func(st *nodev1.NodeState) {
			st.Egresses[0].ParamsJson = `{"interface": "wg0", "bind_ip": "198.51.100.7"}`
		}, ""},
		{"an http egress with credentials of 1 KiB each", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "h1", Kind: nodev1.EgressKind_EGRESS_KIND_HTTP,
				ParamsJson: `{"addr": "198.51.100.9:3128", "username": "` + strings.Repeat("u", 1024) + `", "password": "` + strings.Repeat("p", 1024) + `"}`})
		}, ""},

		// Neither takes these.
		{"listener id with a space", func(st *nodev1.NodeState) { st.Listeners[0].Id = "L 1"; st.Proxies[0].ListenerId = "L 1" }, "not valid"},
		{"duplicate listener id", func(st *nodev1.NodeState) { st.Listeners[1].Id = "l1" }, "duplicate listener id"},
		{"http-upstream listener", func(st *nodev1.NodeState) {
			st.Listeners[1].Kind = nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM
		}, "http-upstream"},
		{"listener kind not set", func(st *nodev1.NodeState) { st.Listeners[1].Kind = 0 }, "kind"},
		{"stranger action out of range", func(st *nodev1.NodeState) { st.Listeners[1].StrangerAction = 99 }, "stranger_action"},
		{"non-TLS action out of range", func(st *nodev1.NodeState) { st.Listeners[1].NonTlsAction = 99 }, "non_tls_action"},
		{"neither action set, on a listener that has a bad port", func(st *nodev1.NodeState) {
			st.Listeners[1].StrangerAction, st.Listeners[1].NonTlsAction, st.Listeners[1].Port = 0, 0, 0
		}, "port"},
		// What the edge cannot read as a trusted CIDR makes it refuse its table.
		{"trusted CIDR with too long a prefix", func(st *nodev1.NodeState) { st.Listeners[1].TrustedCidrs = []string{"192.0.2.0/33"} }, "trusted CIDR"},
		{"trusted CIDR that is no address", func(st *nodev1.NodeState) { st.Listeners[1].TrustedCidrs = []string{"not-an-ip"} }, "trusted CIDR"},
		{"trusted CIDR that is a host name", func(st *nodev1.NodeState) { st.Listeners[1].TrustedCidrs = []string{"proxy.example.com"} }, "trusted CIDR"},
		{"trusted CIDR that is empty", func(st *nodev1.NodeState) { st.Listeners[1].TrustedCidrs = []string{""} }, "trusted CIDR"},
		{"trusted CIDR with a zone", func(st *nodev1.NodeState) { st.Listeners[1].TrustedCidrs = []string{"fe80::1%eth0"} }, "trusted CIDR"},
		{"trusted CIDR with a zone and a length", func(st *nodev1.NodeState) { st.Listeners[1].TrustedCidrs = []string{"fe80::1%eth0/64"} }, "trusted CIDR"},
		{"a bad trusted CIDR among good ones", func(st *nodev1.NodeState) {
			st.Listeners[0].TrustedCidrs = []string{"192.0.2.0/24", "198.51.100.7", "2001:db8::/129"}
		}, "trusted CIDR"},
		{"port 0", func(st *nodev1.NodeState) { st.Listeners[1].Port = 0 }, "port"},
		{"port above 65535", func(st *nodev1.NodeState) { st.Listeners[1].Port = 70000 }, "port"},
		{"IPv6 listener", func(st *nodev1.NodeState) { st.Listeners[1].BindIp = "2001:db8::1" }, "IPv6"},
		{"bind address not an IP", func(st *nodev1.NodeState) { st.Listeners[1].BindIp = "" }, "bind_ip"},
		{"multicast bind address", func(st *nodev1.NodeState) { st.Listeners[1].BindIp = "224.0.0.1" }, "bind_ip"},
		{"two listeners on one address", func(st *nodev1.NodeState) { st.Listeners[1].BindIp, st.Listeners[1].Port = "0.0.0.0", 443 }, "same address"},
		{"internal port on 0.0.0.0", func(st *nodev1.NodeState) { st.Listeners[0].Port = 20000 }, "internal loopback range"},
		{"internal port on 127.0.0.1", func(st *nodev1.NodeState) { st.Listeners[1].BindIp, st.Listeners[1].Port = "127.0.0.1", 40999 }, "internal loopback range"},
		{"0.0.0.0 next to an address", func(st *nodev1.NodeState) { st.Listeners[1].Port = 443 }, "cannot share a port"},
		{"mask target the edge cannot read", func(st *nodev1.NodeState) { st.Listeners[0].MaskTarget = "[2001:db8::1]" }, "mask target"},
		{"mask target with spaces", func(st *nodev1.NodeState) { st.Listeners[0].MaskTarget = " mask.example.com" }, "mask target"},
		{"mask target on an internal port", func(st *nodev1.NodeState) { st.Listeners[0].MaskTarget = "127.0.0.1:30000" }, "internal port"},
		{"mask target on an internal port of localhost", func(st *nodev1.NodeState) { st.Listeners[0].MaskTarget = "LocalHost.:25000" }, "internal port"},
		{"mask target on an internal port of an IPv4-mapped loopback", func(st *nodev1.NodeState) {
			st.Listeners[0].MaskTarget = "[::ffff:127.0.0.1]:20000"
		}, "internal port"},
		{"duplicate proxy id", func(st *nodev1.NodeState) { st.Proxies[1].Id = "p1" }, "duplicate proxy id"},
		{"WEB proxy", func(st *nodev1.NodeState) { st.Proxies[0].Type = nodev1.ProxyType_PROXY_TYPE_WEB }, "web"},
		{"proxy type not set", func(st *nodev1.NodeState) { st.Proxies[0].Type = 0 }, "type"},
		{"mtg", func(st *nodev1.NodeState) { st.Proxies[0].Engine = nodev1.Engine_ENGINE_MTG }, ""},
		{"mtg with an ad tag", func(st *nodev1.NodeState) {
			st.Proxies[0].Engine, st.Proxies[0].AdTag = nodev1.Engine_ENGINE_MTG, "0123456789abcdef0123456789abcdef"
		}, "mtg has no ad_tag"},
		{"mtg with a mask name", func(st *nodev1.NodeState) {
			st.Proxies[0].Engine, st.Proxies[0].MaskTargetOverride = nodev1.Engine_ENGINE_MTG, "mask.example.com"
		}, "IP address only"},
		{"engine not set", func(st *nodev1.NodeState) { st.Proxies[0].Engine = 0 }, "engine"},
		{"bad version", func(st *nodev1.NodeState) { st.Proxies[0].EngineVersion = "3.5/13" }, "version"},
		{"no version", func(st *nodev1.NodeState) { st.Proxies[0].EngineVersion = "" }, "version"},
		{"short secret", func(st *nodev1.NodeState) { st.Proxies[0].Secret = secret1[:30] }, "secret"},
		{"secret not hex", func(st *nodev1.NodeState) { st.Proxies[0].Secret = "x" + secret1[1:] }, "secret"},
		{"bad ad tag", func(st *nodev1.NodeState) { st.Proxies[1].AdTag = "x" + adTag1[1:] }, "ad_tag"},
		{"engine override that is not supported", func(st *nodev1.NodeState) { st.Proxies[1].EngineOverridesJson = `{"workers": 4}` }, "not supported"},
		{"engine override that Postern owns", func(st *nodev1.NodeState) { st.Proxies[1].EngineOverridesJson = `{"log_level": "debug"}` }, "owned by Postern"},
		{"engine override of a listener", func(st *nodev1.NodeState) { st.Proxies[1].EngineOverridesJson = `{"listeners": []}` }, "owned by Postern"},
		{"engine override of the NAT address", func(st *nodev1.NodeState) {
			st.Proxies[1].EngineOverridesJson = `{"middle_proxy_nat_ip": "203.0.113.9"}`
		}, "owned by Postern"},
		{"engine overrides as tables", func(st *nodev1.NodeState) { st.Proxies[1].EngineOverridesJson = `{"general": {"fast_mode": false}}` }, "flat keys"},
		{"engine override of the wrong type", func(st *nodev1.NodeState) { st.Proxies[1].EngineOverridesJson = `{"fast_mode": "yes"}` }, "true or false"},
		{"engine override out of its range", func(st *nodev1.NodeState) { st.Proxies[1].EngineOverridesJson = `{"tg_connect": 601}` }, "from 1 to 600"},
		{"engine override that is not one of the choices", func(st *nodev1.NodeState) { st.Proxies[1].EngineOverridesJson = `{"rst_on_close": "sometimes"}` }, `"errors"`},
		{"engine override of a directory that climbs", func(st *nodev1.NodeState) { st.Proxies[1].EngineOverridesJson = `{"tls_front_dir": "../x"}` }, `".."`},
		{"engine override twice", func(st *nodev1.NodeState) {
			st.Proxies[1].EngineOverridesJson = `{"fast_mode": true, "fast_mode": false}`
		}, "more than once"},
		{"engine overrides not JSON", func(st *nodev1.NodeState) { st.Proxies[1].EngineOverridesJson = `[1]` }, "not a JSON object"},
		{"engine overrides cut short", func(st *nodev1.NodeState) { st.Proxies[1].EngineOverridesJson = `{"fast_mode":` }, "not a JSON object"},
		{"loopback nat_ip", func(st *nodev1.NodeState) { st.Proxies[1].NatIp = "127.0.0.1" }, "nat_ip"},
		{"empty domain", func(st *nodev1.NodeState) { st.Proxies[0].Domain = "" }, "domain"},
		{"domain with a slash", func(st *nodev1.NodeState) { st.Proxies[0].Domain = "a.example.com/x" }, "not allowed in a name"},
		// The edge does not route these and refuses its whole table.
		{"domain with an underscore", func(st *nodev1.NodeState) { st.Proxies[0].Domain = "a_b.example.com" }, "not allowed in a name"},
		{"domain not ASCII", func(st *nodev1.NodeState) { st.Proxies[0].Domain = "пример.example" }, "not allowed in a name"},
		{"domain with an empty label", func(st *nodev1.NodeState) { st.Proxies[0].Domain = "a..example.com" }, "empty label"},
		{"domain of two dots at the end", func(st *nodev1.NodeState) { st.Proxies[0].Domain = "a.example.com.." }, "empty label"},
		{"domain that is a dot", func(st *nodev1.NodeState) { st.Proxies[0].Domain = "." }, "empty label"},
		{"domain with a label of 64", func(st *nodev1.NodeState) { st.Proxies[0].Domain = strings.Repeat("a", 64) + ".example" }, "label longer"},
		{"pool domain with an underscore", func(st *nodev1.NodeState) { st.Settings.DomainPool = []string{"a_b.example"} }, "domain pool"},
		{"duplicate domain on a listener", func(st *nodev1.NodeState) { st.Proxies[1].ListenerId = "L1" }, "already used"},
		{"domains on a listener that differ by a dot at the end", func(st *nodev1.NodeState) {
			st.Proxies[1].ListenerId, st.Proxies[1].Domain = "L1", "a.example.com."
		}, "already used"},
		{"unknown listener", func(st *nodev1.NodeState) { st.Proxies[1].ListenerId = "L9" }, "listener"},
		{"unknown chain", func(st *nodev1.NodeState) { st.Proxies[1].EgressChainId = "C9" }, "chain"},
		{"unknown scope chain", func(st *nodev1.NodeState) { st.Proxies[1].EgressScopeChains = map[string]string{"me": "C9"} }, "chain"},
		{"unknown scope chain for downloads", func(st *nodev1.NodeState) { st.Proxies[0].EgressScopeChains = map[string]string{"fetch": "C9"} }, "chain"},
		{"no chain at all", func(st *nodev1.NodeState) { st.Settings.DefaultChainId = "" }, "no egress chain"},
		{"unknown default chain", func(st *nodev1.NodeState) { st.Settings.DefaultChainId = "C9" }, "default chain"},
		{"an xray-uri egress without a share link", func(st *nodev1.NodeState) { st.Egresses[0].Kind = nodev1.EgressKind_EGRESS_KIND_XRAY_URI }, "no uri"},
		{"an xray-uri egress whose link cannot be read", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "xu", Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_URI, ParamsJson: `{"uri": "vless://` + fakeUUID + `@"}`})
		}, "uri"},
		{"an xray-subscription egress of an ftp URL", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "xs", Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, ParamsJson: `{"url": "ftp://sub.example.com/s"}`})
		}, "url"},
		{"an xray-subscription egress with a selection that does not exist", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "xs", Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
				ParamsJson: `{"url": "https://sub.example.com/s", "select": "best"}`})
		}, "select"},
		{"an xray-subscription egress selecting by an empty name", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "xs", Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
				ParamsJson: `{"url": "https://sub.example.com/s", "select": "name:"}`})
		}, "select"},
		{"a warp egress with parameters that are not an object", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "w", Kind: nodev1.EgressKind_EGRESS_KIND_WARP, ParamsJson: `[1]`})
		}, "params_json"},
		{"a psiphon egress without a country", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "ps", Kind: nodev1.EgressKind_EGRESS_KIND_PSIPHON, ParamsJson: `{}`})
		}, "country"},
		{"a psiphon egress out of a country that Psiphon does not serve", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "ps", Kind: nodev1.EgressKind_EGRESS_KIND_PSIPHON, ParamsJson: `{"country": "ZZ"}`})
		}, "country"},
		{"a scope chain of no scope", func(st *nodev1.NodeState) { st.Proxies[0].EgressScopeChains = map[string]string{"": "default"} }, "empty scope"},
		{"egress kind not set", func(st *nodev1.NodeState) { st.Egresses[0].Kind = 0 }, "egress"},
		// Slice 2 lets a direct egress go out through an interface: the node takes it, so the panel does too.
		{"interface egress", func(st *nodev1.NodeState) { st.Egresses[0].ParamsJson = `{"interface": "wg0"}` }, ""},
		{"interface egress through a name with a slash", func(st *nodev1.NodeState) { st.Egresses[0].ParamsJson = `{"interface": "a/b"}` }, "interface"},
		{"direct params not an object", func(st *nodev1.NodeState) { st.Egresses[0].ParamsJson = `[1]` }, "params_json"},
		{"direct bind_ip not an address", func(st *nodev1.NodeState) { st.Egresses[0].ParamsJson = `{"bind_ip": "x"}` }, "bind_ip"},
		{"socks5 egress without an address", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "s5", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{}`})
		}, "addr"},
		// The rules by which the edge dials the members of a chain.
		{"socks5 egress with brackets around an IPv4 address", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "s5", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr": "[192.0.2.1]:1080"}`})
		}, "brackets"},
		{"socks5 egress with a user name of 256 bytes", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "s5", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5,
				ParamsJson: `{"addr": "198.51.100.9:1080", "username": "` + long + `"}`})
		}, "username"},
		{"socks5 egress with a password of 256 bytes", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "s5", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5,
				ParamsJson: `{"addr": "198.51.100.9:1080", "password": "` + long + `"}`})
		}, "password"},
		{"http egress with a colon in the user name", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "h1", Kind: nodev1.EgressKind_EGRESS_KIND_HTTP,
				ParamsJson: `{"addr": "198.51.100.9:3128", "username": "a:b"}`})
		}, "colon"},
		{"http egress with a user name of more than 1 KiB", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "h1", Kind: nodev1.EgressKind_EGRESS_KIND_HTTP,
				ParamsJson: `{"addr": "198.51.100.9:3128", "username": "` + strings.Repeat("u", 1025) + `"}`})
		}, "username"},
		{"http egress with a password of more than 1 KiB", func(st *nodev1.NodeState) {
			st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "h1", Kind: nodev1.EgressKind_EGRESS_KIND_HTTP,
				ParamsJson: `{"addr": "198.51.100.9:3128", "username": "u", "password": "` + strings.Repeat("p", 1025) + `"}`})
		}, "password"},
		{"a health check of a DC whose host cannot stand in a request", func(st *nodev1.NodeState) {
			st.Chains[0].Check = &nodev1.HealthCheck{DcAddrs: []string{"dc@example.com:443"}}
		}, "dc_addrs"},
		{"chain without members", func(st *nodev1.NodeState) { st.Chains[0].MemberEgressIds = nil }, "no members"},
		{"chain with an unknown member", func(st *nodev1.NodeState) { st.Chains[0].MemberEgressIds = []string{"nope"} }, "does not exist"},
		{"chain with a member twice", func(st *nodev1.NodeState) { st.Chains[0].MemberEgressIds = []string{"direct", "direct"} }, "twice"},
		{"bad pool domain", func(st *nodev1.NodeState) { st.Settings.DomainPool = []string{"a b"} }, "domain pool"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := validState()
			tc.mod(st)
			nodeErr := state.Validate(proto.Clone(st).(*nodev1.NodeState), nodeSupports)
			panelErr := validateState(st)
			if (panelErr == nil) != (nodeErr == nil) {
				t.Fatalf("the panel says %v, the node says %v", panelErr, nodeErr)
			}
			if tc.refused == "" {
				if panelErr != nil {
					t.Fatalf("refused: %v; want the state taken", panelErr)
				}
				return
			}
			if panelErr == nil {
				t.Fatalf("taken; want it refused for %q", tc.refused)
			}
			if !strings.Contains(panelErr.Error(), tc.refused) {
				t.Errorf("error %q does not mention %q", panelErr, tc.refused)
			}
			// The reasons are the node's own.
			var ve *state.ValidationError
			if !errors.As(nodeErr, &ve) {
				t.Fatalf("the node's error %v is not a *state.ValidationError", nodeErr)
			}
			for _, p := range ve.Problems {
				if !strings.Contains(panelErr.Error(), p) {
					t.Errorf("the panel's error %q leaves out the node's reason %q", panelErr, p)
				}
			}
			if !errors.Is(panelErr, errStateRefused) {
				t.Errorf("error %v is not errStateRefused", panelErr)
			}
			for _, s := range []string{secret1, secret2, adTag1, long} {
				if strings.Contains(panelErr.Error(), s) {
					t.Errorf("the error has a secret, an ad tag or a credential in it: %q", panelErr)
				}
			}
		})
	}
	if err := validateState(nil); err == nil {
		t.Error("validateState(nil): no error")
	}
}

// TestStateBuilderRefusesStoredValuesItDoesNotKnow: a stored kind, action, type
// or engine that this version does not know makes the state an error that names
// the row and the value, never a state with the value left unset. The node
// would read an action that is not set as the default (mask, drop), which the
// row never said. The services refuse a change of such a node in the same words.
func TestStateBuilderRefusesStoredValuesItDoesNotKnow(t *testing.T) {
	tests := []struct {
		name  string
		query string
		id    string
		want  string
	}{
		{"a stranger action", `UPDATE listeners SET stranger_action = 'banish' WHERE id = ?`, goldenL2, `"banish"`},
		{"a stranger action that is not set", `UPDATE listeners SET stranger_action = '' WHERE id = ?`, goldenL2, `stranger action ""`},
		{"a non-TLS action", `UPDATE listeners SET non_tls_action = 'http500' WHERE id = ?`, goldenL1, `"http500"`},
		{"a non-TLS action that is not set", `UPDATE listeners SET non_tls_action = '' WHERE id = ?`, goldenL1, `non-TLS action ""`},
		{"a listener kind", `UPDATE listeners SET kind = 'udp' WHERE id = ?`, goldenL1, `"udp"`},
		{"a proxy type", `UPDATE proxies SET type = 'mtproto' WHERE id = ?`, goldenP1, `"mtproto"`},
		{"an engine", `UPDATE proxies SET engine = 'other' WHERE id = ?`, goldenP2, `"other"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.goldenNode("amd64")
			e.exec(tc.query, tc.id)

			st, err := e.builder.Build(e.ctx, goldenNodeID, 2)
			if err == nil {
				t.Fatalf("Build made a state of %d proxies, want an error", len(st.GetProxies()))
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.id) {
				t.Errorf("Build error %q does not name the row %s and the value %s", err, tc.id, tc.want)
			}

			_, err = e.listeners.CreateListener(e.ctx, connect.NewRequest(&panelv1.CreateListenerRequest{NodeId: goldenNodeID, Port: 9443}))
			wantCode(t, err, connect.CodeFailedPrecondition)
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("CreateListener error %q does not name the value %s", err, tc.want)
			}
		})
	}
}

// The engine overrides that are on the whitelist of
// internal/engines/telemt/overrides are what the node takes, and the panel lets
// them through to it.
func TestValidateStateAcceptsEngineOverrides(t *testing.T) {
	for name, raw := range map[string]string{
		"none":                 "",
		"an empty object":      "{}",
		"null":                 "null",
		"one key":              `{"fast_mode": false}`,
		"tls_emulation":        `{"tls_emulation": false}`,
		"a directory":          `{"tls_front_dir": "tlsfront/cache"}`,
		"a few, in any order":  `{"update_every": 30, "tg_connect": 10, "rst_on_close": "errors", "me_writer_pick_mode": "sorted_rr"}`,
		"the smallest numbers": `{"me_keepalive_interval_secs": 1, "me_keepalive_jitter_secs": 0, "upstream_connect_retry_attempts": 1, "tg_connect": 1}`,
		"the largest numbers":  `{"me_keepalive_interval_secs": 3600, "me_reconnect_backoff_cap_ms": 600000, "update_every": 86400, "tg_connect": 600}`,
	} {
		t.Run(name, func(t *testing.T) {
			st := validState()
			st.Proxies[1].EngineOverridesJson = raw
			if err := validateState(st); err != nil {
				t.Errorf("validateState = %v, want the overrides taken", err)
			}
		})
	}
}

// What is stored as the overrides of a proxy goes to its node as JSON, with the
// keys in order, so that the same overrides are always the same state; and a state
// that has them is one that the panel sends.
func TestStateBuilderCarriesEngineOverrides(t *testing.T) {
	e := newEnv(t)
	e.goldenNode("amd64")
	e.addProxy(&store.Proxy{
		ListenerID: goldenL1, Domain: "x.example.com",
		EngineOverrides: map[string]any{"tg_connect": float64(10), "rst_on_close": "errors", "fast_mode": false, "tls_emulation": true, "tls_front_dir": "tlsfront/cache"},
	}, secret2)

	st, err := e.builder.Build(e.ctx, goldenNodeID, 3)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var got []string
	for _, p := range st.GetProxies() {
		got = append(got, p.GetId()+" "+p.GetEngineOverridesJson())
	}
	want := []string{
		goldenP1 + " ",
		goldenP2 + " ",
		"01K6Y0000000000000000000B9 " + `{"fast_mode":false,"rst_on_close":"errors","tg_connect":10,"tls_emulation":true,"tls_front_dir":"tlsfront/cache"}`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("engine overrides of the proxies:\n got %q\nwant %q", got, want)
	}
}

// A proxy whose stored overrides are not on the whitelist stops the state of its
// node, with the reason and the proxy that it is about.
func TestStateBuilderRefusesEngineOverridesThatAreNotOnTheWhitelist(t *testing.T) {
	for name, tc := range map[string]struct {
		overrides map[string]any
		want      string
	}{
		"a key that is not supported": {map[string]any{"workers": float64(4)}, "not supported"},
		"a key that Postern owns":     {map[string]any{"log_level": "debug"}, "owned by Postern"},
		"a value of the wrong type":   {map[string]any{"fast_mode": "yes"}, "true or false"},
		"a value out of its range":    {map[string]any{"tg_connect": float64(0)}, "from 1 to 600"},
		"a number that is not whole":  {map[string]any{"tg_connect": 10.5}, "integer"},
		"a table":                     {map[string]any{"general": map[string]any{"fast_mode": false}}, "flat keys"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.goldenNode("amd64")
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x.example.com", EngineOverrides: tc.overrides}, secret2)
			st, err := e.builder.Build(e.ctx, goldenNodeID, 2)
			if err == nil {
				t.Fatalf("Build made a state of %d proxies, want an error", len(st.GetProxies()))
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "01K6Y0000000000000000000B9") {
				t.Errorf("the error %q does not name the proxy and say %q", err, tc.want)
			}
			if strings.Contains(err.Error(), secret2) || strings.Contains(err.Error(), secret1) {
				t.Error("the error has a secret in it")
			}
		})
	}
}

// The middle-proxy setting of a proxy decides what the node is told: "on" and
// "off" are as they say, and "auto" is on when the proxy has an ad tag.
func TestStateBuilderMiddleProxySetting(t *testing.T) {
	tests := []struct {
		setting, adTag string
		want           bool
	}{
		{store.MiddleProxyAuto, "", false},
		{store.MiddleProxyAuto, adTag1, true},
		{store.MiddleProxyOn, "", true},
		{store.MiddleProxyOn, adTag1, true},
		{store.MiddleProxyOff, "", false},
		{store.MiddleProxyOff, adTag1, false},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%q with ad tag %q", tc.setting, tc.adTag), func(t *testing.T) {
			e := newEnv(t)
			e.goldenNode("amd64")
			e.addProxy(&store.Proxy{ListenerID: goldenL1, Domain: "x.example.com", UseMiddleProxy: tc.setting, AdTag: tc.adTag}, secret2)
			st, err := e.builder.Build(e.ctx, goldenNodeID, 2)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			for _, p := range st.GetProxies() {
				if p.GetId() != "01K6Y0000000000000000000B9" {
					continue
				}
				if p.GetUseMiddleProxy() != tc.want {
					t.Errorf("use_middle_proxy = %v, want %v", p.GetUseMiddleProxy(), tc.want)
				}
				if p.GetAdTag() != tc.adTag {
					t.Errorf("ad_tag = %q, want %q: the setting must not touch the tag", p.GetAdTag(), tc.adTag)
				}
				return
			}
			t.Fatal("the state has no such proxy")
		})
	}
}
