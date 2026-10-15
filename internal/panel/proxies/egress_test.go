package proxies

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// Made-up egress parameters: documentation names, a UUID and a password that
// are obviously fake. None of them may ever show up in a log or an error.
const (
	fakeUUID     = "00000000-0000-4000-8000-000000000001"
	fakePassword = "pass-word-not-real"   // gitleaks:allow (a made-up test value)
	fakeSubToken = "sub-token-not-real-0" // gitleaks:allow (a made-up test value)
	fakeVLESS    = "vless://" + fakeUUID + "@vless.example.com:443?security=reality&sni=www.example.com&fp=chrome" +
		"&pbk=fake-public-key-for-tests-0000000000000&sid=0123456789abcdef&type=tcp#exit"
	fakeSubURL = "https://sub.example.com/" + fakeSubToken
)

// The fixed ids of the egresses and chains of the golden node.
const (
	goldenE1 = "01K6Y0000000000000000000E1" // xray-uri
	goldenE2 = "01K6Y0000000000000000000E2" // socks5
	goldenE3 = "01K6Y0000000000000000000E3" // warp, of the node
	goldenE4 = "01K6Y0000000000000000000E4" // psiphon
	goldenE5 = "01K6Y0000000000000000000E5" // xray-subscription
	goldenE6 = "01K6Y0000000000000000000E6" // http, in no chain that the node uses
	goldenC1 = "01K6Y0000000000000000000C1" // the default chain of the node: E1, E2
	goldenC2 = "01K6Y0000000000000000000C2" // of the node: E3, the chain of P1
	goldenC3 = "01K6Y0000000000000000000C3" // E4, the chain of P1 for scope me
	goldenC4 = "01K6Y0000000000000000000C4" // E5, the chain of P2 for scope fetch
	goldenC5 = "01K6Y0000000000000000000C5" // E6, used by no one
)

// addEgress stores an egress with its parameters sealed as the panel seals
// them.
func (e *env) addEgress(id, kind, nodeID, params string, nonce uint64) *store.Egress {
	e.t.Helper()
	eg := &store.Egress{ID: id, Name: "egress " + id[len(id)-2:], Kind: kind, NodeID: nodeID, RefreshNonce: nonce}
	if params != "" {
		sealed, err := SealEgressParams(e.key, id, params)
		if err != nil {
			e.t.Fatal(err)
		}
		eg.ParamsEnc = sealed
	}
	if err := e.db.CreateEgress(e.ctx, eg); err != nil {
		e.t.Fatalf("CreateEgress: %v", err)
	}
	return eg
}

// addChain stores a chain.
func (e *env) addChain(id, nodeID string, check store.ChainCheck, members ...string) *store.EgressChain {
	e.t.Helper()
	c := &store.EgressChain{ID: id, Name: "chain " + id[len(id)-2:], NodeID: nodeID, Members: members, Check: check}
	if err := e.db.CreateChain(e.ctx, c); err != nil {
		e.t.Fatalf("CreateChain: %v", err)
	}
	return c
}

// goldenEgressNode stores the golden node (goldenNode) with egresses and
// chains: its default chain, its own WARP chain for P1 and scope chains for
// both proxies, and DNS mode system.
func (e *env) goldenEgressNode(arch string) *store.Node {
	e.t.Helper()
	n := e.goldenNode(arch)
	e.addEgress(goldenE1, store.EgressKindXrayURI, "", `{"uri":"`+fakeVLESS+`"}`, 0)
	e.addEgress(goldenE2, store.EgressKindSOCKS5, "", `{"addr":"198.51.100.9:1080","username":"user","password":"`+fakePassword+`"}`, 0)
	e.addEgress(goldenE3, store.EgressKindWARP, n.ID, `{}`, 0)
	e.addEgress(goldenE4, store.EgressKindPsiphon, "", `{"country":"DE"}`, 0)
	e.addEgress(goldenE5, store.EgressKindXraySubscription, "", `{"url":"`+fakeSubURL+`","select":"first"}`, 2)
	e.addEgress(goldenE6, store.EgressKindHTTP, "", `{"addr":"proxy.example.com:3128"}`, 0)
	e.addChain(goldenC1, "", store.ChainCheck{IntervalSeconds: 5, DCAddrs: []string{"149.154.167.51:443"}}, goldenE1, goldenE2)
	e.addChain(goldenC2, n.ID, store.ChainCheck{}, goldenE3)
	e.addChain(goldenC3, "", store.ChainCheck{}, goldenE4)
	e.addChain(goldenC4, "", store.ChainCheck{}, goldenE5)
	e.addChain(goldenC5, "", store.ChainCheck{}, goldenE6)

	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error {
		n.DefaultChainID, n.DNSMode = goldenC1, "system"
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	p1, p2 := e.storedProxy(goldenP1), e.storedProxy(goldenP2)
	p1.EgressChainID, p1.EgressScopeChains = goldenC2, map[string]string{"me": goldenC3}
	p2.EgressScopeChains = map[string]string{"fetch": goldenC4}
	for _, p := range []*store.Proxy{p1, p2} {
		if err := e.db.UpdateProxy(e.ctx, p); err != nil {
			e.t.Fatal(err)
		}
	}
	return e.node(n.ID)
}

func TestStateBuilderGoldenWithEgresses(t *testing.T) {
	e := newEnv(t)
	n := e.goldenEgressNode("amd64")

	st, err := e.builder.Build(e.ctx, n.ID, 9)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	redacted := proto.Clone(st).(*nodev1.NodeState)
	for _, p := range redacted.GetProxies() {
		p.Secret = "<secret of " + p.GetId() + ">"
	}
	got := goldenJSON(t, redacted)

	path := filepath.Join("testdata", "state_egress.json")
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
	back := &nodev1.NodeState{}
	if err := protojson.Unmarshal(want, back); err != nil {
		t.Fatalf("the golden file does not read back: %v", err)
	}
	if !proto.Equal(back, redacted) {
		t.Error("the golden file does not read back as the built state")
	}
	// The node takes it.
	if err := validateState(st); err != nil {
		t.Errorf("validateState of the built state: %v", err)
	}
	// What the state holds of the egresses is the node's: an egress that no
	// chain in the state has (E6) is not in it, and the implicit direct chain
	// is not either, since the node has a default chain of its own.
	for _, eg := range st.GetEgresses() {
		if eg.GetId() == goldenE6 || eg.GetId() == ImplicitEgressID {
			t.Errorf("the state has egress %s", eg.GetId())
		}
	}
	e.assertNoSecretsLogged()
	e.assertNoEgressSecretsLogged()
}

// assertNoEgressSecretsLogged fails the test if a credential of an egress is in
// the log.
func (e *env) assertNoEgressSecretsLogged() {
	e.t.Helper()
	logs := e.logs.String()
	for _, s := range []string{fakeUUID, fakePassword, fakeSubToken} {
		if strings.Contains(logs, s) {
			e.t.Errorf("the log contains a credential of an egress")
		}
	}
}

// The provider artifacts follow the kinds of the egresses in the state and the
// architecture of the node: Xray for xray-uri, xray-subscription and warp,
// psiphon-core for psiphon.
func TestStateBuilderArtifactsOfTheProviders(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			e := newEnv(t)
			n := e.goldenEgressNode(arch)
			st, err := e.builder.Build(e.ctx, n.ID, 1)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			var got []string
			for _, a := range st.GetArtifacts() {
				got = append(got, a.GetEngine()+" "+a.GetVersion()+" "+a.GetArch()+" "+a.GetFileName()+" "+a.GetBinary())
			}
			xrayFile := map[string]string{"amd64": "Xray-linux-64.zip", "arm64": "Xray-linux-arm64-v8a.zip"}[arch]
			telemt := map[string]string{"amd64": "telemt-x86_64-linux-musl.tar.gz", "arm64": "telemt-aarch64-linux-musl.tar.gz"}[arch]
			want := []string{
				"telemt 3.5.13 " + arch + " " + telemt + " telemt",
				"xray v26.3.27 " + arch + " " + xrayFile + " xray",
			}
			want = append([]string{"psiphon-core 20261005-c4a09096ab " + arch + " psiphon-core-linux-" + arch + " psiphon-core"}, want...)
			if !slices.Equal(got, want) {
				t.Errorf("artifacts = %q\nwant %q", got, want)
			}
		})
	}

	// Without egresses of a provider, no provider.
	e := newEnv(t)
	n := e.goldenNode("amd64")
	e.addEgress(goldenE2, store.EgressKindSOCKS5, "", `{"addr":"198.51.100.9:1080"}`, 0)
	e.addChain(goldenC1, "", store.ChainCheck{}, goldenE2)
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error { n.DefaultChainID = goldenC1; return nil }); err != nil {
		t.Fatal(err)
	}
	st, err := e.builder.Build(e.ctx, n.ID, 1)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(st.GetArtifacts()) != 1 || st.GetArtifacts()[0].GetEngine() != "telemt" {
		t.Errorf("artifacts of a node without providers = %v, want telemt alone", st.GetArtifacts())
	}
}

// TestStateBuilderRefusesEgressRowsItCannotSend: rows that the services never
// write, but a hand could, make Build fail with an error that names the row,
// never with a credential in it.
func TestStateBuilderRefusesEgressRowsItCannotSend(t *testing.T) {
	const other = "01K6Y0000000000000000000N2"
	tests := []struct {
		name string
		mod  func(e *env)
		want string
	}{
		{"the chain of a proxy belongs to another node", func(e *env) {
			e.exec(`UPDATE egress_chains SET node_id = ? WHERE id = ?`, other, goldenC2)
		}, "another node"},
		{"a member of a chain belongs to another node", func(e *env) {
			e.exec(`UPDATE egresses SET node_id = ? WHERE id = ?`, other, goldenE3)
		}, "another node"},
		{"an egress of a kind that this version does not know", func(e *env) {
			e.exec(`UPDATE egresses SET kind = 'tor' WHERE id = ?`, goldenE2)
		}, `"tor"`},
		{"a member that does not exist", func(e *env) {
			e.exec(`UPDATE egress_chains SET members = '["01K6Y0000000000000000000E9"]' WHERE id = ?`, goldenC1)
		}, "does not exist"},
		{"a scope chain that does not exist", func(e *env) {
			e.exec(`UPDATE proxies SET egress_scope_chains = '{"me": "01K6Y0000000000000000000C9"}' WHERE id = ?`, goldenP1)
		}, "does not exist"},
		{"parameters sealed for another egress", func(e *env) {
			sealed, err := SealEgressParams(e.key, goldenE1, `{"addr":"198.51.100.9:1080","password":"`+fakePassword+`"}`)
			if err != nil {
				e.t.Fatal(err)
			}
			e.exec(`UPDATE egresses SET params_enc = ? WHERE id = ?`, sealed, goldenE2)
		}, "cannot be opened"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.addNode("other", "203.0.113.20")
			e.exec(`UPDATE nodes SET id = ? WHERE name = 'other'`, other)
			e.goldenEgressNode("amd64")
			if _, err := e.builder.Build(e.ctx, goldenNodeID, 1); err != nil {
				t.Fatalf("Build before the change: %v", err)
			}
			tc.mod(e)
			st, err := e.builder.Build(e.ctx, goldenNodeID, 2)
			if err == nil {
				t.Fatalf("Build made a state of %d egresses, want an error", len(st.GetEgresses()))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Build error %q does not say %q", err, tc.want)
			}
			for _, s := range []string{fakeUUID, fakePassword, fakeSubToken} {
				if strings.Contains(err.Error(), s) {
					t.Errorf("the error has a credential in it")
				}
			}
		})
	}
}

// The features of a state are what it asks of its node beyond the slice-1
// baseline (Ruling 43); a change is refused for a feature that it adds and the
// node does not report.
func TestCapabilities(t *testing.T) {
	base := validState()
	withEgress := func(kind nodev1.EgressKind) *nodev1.NodeState {
		st := validState()
		st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "x", Kind: kind})
		return st
	}
	withDNS := func(mode string) *nodev1.NodeState {
		st := validState()
		st.Settings.DnsMode = mode
		return st
	}
	withScope := func(scope string) *nodev1.NodeState {
		st := validState()
		st.Proxies[0].EgressScopeChains = map[string]string{scope: "default"}
		return st
	}
	withDirect := func(params string) *nodev1.NodeState {
		st := validState()
		st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "x", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT, ParamsJson: params})
		return st
	}
	for _, tc := range []struct {
		name string
		st   *nodev1.NodeState
		want []string
	}{
		{"the baseline", base, nil},
		{"a direct egress", withEgress(nodev1.EgressKind_EGRESS_KIND_DIRECT), nil},
		// Slice 1 refuses a direct egress through an interface, not one from an
		// address (Ruling S2-19).
		{"a direct egress through an interface", withDirect(`{"interface":"wg0"}`), []string{CapEgressInterface}},
		{"a direct egress through an interface from an address", withDirect(`{"interface":"wg0","bind_ip":"198.51.100.7"}`), []string{CapEgressInterface}},
		{"a direct egress from an address", withDirect(`{"bind_ip":"198.51.100.7"}`), nil},
		{"a direct egress of empty parameters", withDirect(`{}`), nil},
		{"a socks5 egress", withEgress(nodev1.EgressKind_EGRESS_KIND_SOCKS5), nil},
		{"an http egress", withEgress(nodev1.EgressKind_EGRESS_KIND_HTTP), nil},
		{"an xray-uri egress", withEgress(nodev1.EgressKind_EGRESS_KIND_XRAY_URI), []string{CapEgressXray}},
		{"an xray-subscription egress", withEgress(nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION), []string{CapEgressXray}},
		{"a warp egress", withEgress(nodev1.EgressKind_EGRESS_KIND_WARP), []string{CapEgressWARP}},
		{"a psiphon egress", withEgress(nodev1.EgressKind_EGRESS_KIND_PSIPHON), []string{CapEgressPsiphon}},
		{"dns mode doh", withDNS("doh"), []string{CapDNSForwarder}},
		{"dns mode system", withDNS("system"), nil},
		{"dns mode of the node's default", withDNS(""), nil},
		{"a scope chain me", withScope("me"), []string{CapMERouting}},
		{"a scope chain fetch", withScope("fetch"), nil},
		{"nothing", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := slices.Sorted(func(yield func(string) bool) {
				for c := range features(tc.st) {
					if !yield(c) {
						return
					}
				}
			})
			if !slices.Equal(got, tc.want) {
				t.Errorf("features = %v, want %v", got, tc.want)
			}
		})
	}

	seen := time.Now().Add(-time.Minute)
	node := &store.Node{Name: "edge-1", LastSeenAt: &seen}
	xray := withEgress(nodev1.EgressKind_EGRESS_KIND_XRAY_URI)
	// A node that has connected and reports nothing has the baseline.
	err := checkCapabilities(node, base, xray)
	if err == nil || err.Error() != "upgrade node edge-1 to use Xray egresses (egress-xray)" {
		t.Errorf("checkCapabilities of an xray egress on a node of the baseline = %v", err)
	}
	// One that has never connected has not said what it is.
	fresh := &store.Node{Name: "edge-2"}
	err = checkCapabilities(fresh, base, xray)
	if err == nil || err.Error() != "node edge-2 has not reported its capabilities yet: connect it before it uses Xray egresses (egress-xray)" {
		t.Errorf("checkCapabilities on a node that has never connected = %v", err)
	}
	// One that reports it takes it.
	node.HostInfo.Capabilities = []string{"faketls", CapEgressXray}
	if err := checkCapabilities(node, base, xray); err != nil {
		t.Errorf("checkCapabilities on a node that has egress-xray: %v", err)
	}
	// What the state asked of the node before is not asked again: a change that
	// keeps it goes through on a node that no longer reports it.
	node.HostInfo.Capabilities = nil
	if err := checkCapabilities(node, xray, xray); err != nil {
		t.Errorf("checkCapabilities of a change that adds nothing: %v", err)
	}
	// A state that was not there before asks everything anew.
	if err := checkCapabilities(node, nil, xray); err == nil {
		t.Error("checkCapabilities without a state before: no error")
	}
	for _, tc := range []struct {
		st   *nodev1.NodeState
		want string
	}{
		{withEgress(nodev1.EgressKind_EGRESS_KIND_WARP), "upgrade node edge-1 to use WARP egresses (egress-warp)"},
		{withEgress(nodev1.EgressKind_EGRESS_KIND_PSIPHON), "upgrade node edge-1 to use Psiphon egresses (egress-psiphon-core)"},
		{withDNS("doh"), "upgrade node edge-1 to use the DNS forwarder of the edge (dns-forwarder)"},
		{withScope("me"), "upgrade node edge-1 to use a chain for the middle proxies (me-routing)"},
		{withDirect(`{"interface":"wg0"}`), "upgrade node edge-1 to use egresses through an interface of the node (egress-interface)"},
	} {
		if err := checkCapabilities(node, base, tc.st); err == nil || err.Error() != tc.want {
			t.Errorf("checkCapabilities = %v, want %q", err, tc.want)
		}
	}

	// A release of Postern builds the Psiphon client for arm64 too: an arm64
	// node that reports the capability takes a Psiphon egress.
	psiphon := withEgress(nodev1.EgressKind_EGRESS_KIND_PSIPHON)
	node.HostInfo.Capabilities = []string{CapEgressPsiphon}
	for _, arch := range []string{"amd64", "arm64"} {
		node.Arch = arch
		if err := checkCapabilities(node, base, psiphon); err != nil {
			t.Errorf("checkCapabilities of a psiphon egress on an %s node: %v", arch, err)
		}
	}
}

// mustEgressNode stores a node that has connected and reports the
// capabilities, with a listener and a proxy, which goes out through the
// default chain of the node.
func (e *env) mustEgressNode(name string, capabilities ...string) *store.Node {
	e.t.Helper()
	n := e.addNode(name, "203.0.113.10")
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error {
		seen := time.Now().Add(-time.Minute)
		n.HostInfo.Capabilities, n.LastSeenAt = capabilities, &seen
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "cdn.example.com"})
	return e.node(n.ID)
}

// MutateEgresses raises the generation of every node whose state the change
// changes, and of no other, and tells the notifier about each.
func TestMutateEgressesRaisesTheNodesWhoseStateChanges(t *testing.T) {
	e := newEnv(t)
	a := e.mustEgressNode("a", CapEgressXray)
	b := e.mustEgressNode("b", CapEgressXray)
	eg := e.addEgress(goldenE2, store.EgressKindSOCKS5, "", `{"addr":"198.51.100.9:1080"}`, 0)
	e.addChain(goldenC1, "", store.ChainCheck{}, eg.ID)
	setDefault := func(w *World) (func(context.Context) error, error) {
		w.Node(a.ID).DefaultChainID = goldenC1
		return func(ctx context.Context) error {
			_, err := e.db.ModifyNode(ctx, a.ID, func(n *store.Node) error { n.DefaultChainID = goldenC1; return nil })
			return err
		}, nil
	}
	genA, genB := e.generation(a.ID), e.generation(b.ID)
	changed, err := e.svc.MutateEgresses(e.ctx, setDefault)
	if err != nil {
		t.Fatalf("MutateEgresses: %v", err)
	}
	if !slices.Equal(changed, []string{a.ID}) || e.generation(a.ID) != genA+1 || e.generation(b.ID) != genB {
		t.Errorf("changed %v, generations %d→%d and %d→%d; want a alone raised", changed, genA, e.generation(a.ID), genB, e.generation(b.ID))
	}
	if got := e.notes.got(); len(got) == 0 || got[len(got)-1] != a.ID {
		t.Errorf("notified %v, want a", got)
	}

	// A change that changes no state (a name) raises nothing.
	notes := e.notes.count()
	changed, err = e.svc.MutateEgresses(e.ctx, func(w *World) (func(context.Context) error, error) {
		w.Egress(eg.ID).Name = "renamed"
		return func(ctx context.Context) error {
			eg.Name = "renamed"
			return e.db.UpdateEgress(ctx, eg)
		}, nil
	})
	if err != nil || len(changed) != 0 || e.generation(a.ID) != genA+1 || e.notes.count() != notes {
		t.Errorf("a rename: changed %v, err %v, notified %d more", changed, err, e.notes.count()-notes)
	}

	// A change of the parameters of the egress changes the state of a only.
	changed, err = e.svc.MutateEgresses(e.ctx, func(w *World) (func(context.Context) error, error) {
		w.SetEgressParams(eg.ID, `{"addr":"198.51.100.10:1080"}`)
		return func(context.Context) error { return nil }, nil
	})
	if err != nil || !slices.Equal(changed, []string{a.ID}) || e.generation(a.ID) != genA+2 || e.generation(b.ID) != genB {
		t.Errorf("new parameters: changed %v, err %v", changed, err)
	}

	// A nil write is no change, whatever the plan did to the world.
	changed, err = e.svc.MutateEgresses(e.ctx, func(w *World) (func(context.Context) error, error) {
		w.Node(b.ID).DefaultChainID = goldenC1
		return nil, nil
	})
	if err != nil || len(changed) != 0 || e.generation(b.ID) != genB {
		t.Errorf("a nil write: changed %v, err %v", changed, err)
	}
}

// A change after which a node would refuse its state, or that needs what the
// node does not report, is refused, and nothing is written.
func TestMutateEgressesRefusesWhatANodeCannotTake(t *testing.T) {
	e := newEnv(t)
	old := e.mustEgressNode("old one")
	eg := e.addEgress(goldenE1, store.EgressKindXrayURI, "", `{"uri":"`+fakeVLESS+`"}`, 0)
	e.addChain(goldenC1, "", store.ChainCheck{}, eg.ID)
	gen := e.generation(old.ID)
	wrote := false
	write := func(context.Context) error { wrote = true; return nil }

	_, err := e.svc.MutateEgresses(e.ctx, func(w *World) (func(context.Context) error, error) {
		w.Node(old.ID).DefaultChainID = goldenC1
		return write, nil
	})
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "upgrade node old one to use Xray egresses (egress-xray)") {
		t.Errorf("error %q does not ask to upgrade the node", err)
	}

	// A state that the node refuses: an egress whose share link it cannot read.
	cur := e.mustEgressNode("current", CapEgressXray)
	_, err = e.svc.MutateEgresses(e.ctx, func(w *World) (func(context.Context) error, error) {
		w.Node(cur.ID).DefaultChainID = goldenC1
		w.SetEgressParams(eg.ID, `{"uri":"vless://`+fakeUUID+`@"}`)
		return write, nil
	})
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "current") || !strings.Contains(err.Error(), "uri") {
		t.Errorf("error %q does not name the node and the problem", err)
	}
	if strings.Contains(err.Error(), fakeUUID) {
		t.Errorf("the error has the share link in it")
	}
	if wrote || e.generation(old.ID) != gen {
		t.Errorf("a refused change was written (%v) or raised a generation", wrote)
	}
	e.assertNoEgressSecretsLogged()
}

// The chains of a proxy are checked like the rest of a change of it: a chain
// that the node cannot use, a scope that the node does not know, and a scope
// chain for the middle proxies on a node that cannot route them, are refused.
func TestProxyChains(t *testing.T) {
	e := newEnv(t)
	n := e.mustEgressNode("n", CapEgressXray)
	other := e.mustEgressNode("other", CapEgressXray, CapMERouting)
	eg := e.addEgress(goldenE2, store.EgressKindSOCKS5, "", `{"addr":"198.51.100.9:1080"}`, 0)
	own := e.addEgress(goldenE3, store.EgressKindDirect, other.ID, `{}`, 0)
	e.addChain(goldenC1, "", store.ChainCheck{}, eg.ID)
	e.addChain(goldenC2, other.ID, store.ChainCheck{}, own.ID)
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 8443})

	p := e.createProxy(&panelv1.CreateProxyRequest{
		NodeId: n.ID, ListenerId: l.GetId(), Domain: "chain.example.com",
		EgressChainId: goldenC1, EgressScopeChains: map[string]string{"fetch": goldenC1, "me": ""},
	})
	if p.GetEgressChainId() != goldenC1 || len(p.GetEgressScopeChains()) != 1 || p.GetEgressScopeChains()["fetch"] != goldenC1 {
		t.Errorf("the proxy has chain %q and scope chains %v", p.GetEgressChainId(), p.GetEgressScopeChains())
	}
	if got := e.storedProxy(p.GetId()); got.EgressChainID != goldenC1 || got.EgressScopeChains["fetch"] != goldenC1 {
		t.Errorf("stored chain %q, scope chains %v", got.EgressChainID, got.EgressScopeChains)
	}
	st, err := e.builder.Build(e.ctx, n.ID, 1)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !slices.ContainsFunc(st.GetChains(), func(c *nodev1.EgressChain) bool { return c.GetId() == goldenC1 }) {
		t.Errorf("the state of the node has no chain %s", goldenC1)
	}

	for _, tc := range []struct {
		name string
		req  *panelv1.UpdateProxyRequest
		code connect.Code
		want string
	}{
		{"a chain that does not exist", &panelv1.UpdateProxyRequest{EgressChainId: proto.String("01K6Y0000000000000000000C9")}, connect.CodeNotFound, "chain"},
		{"a chain of another node", &panelv1.UpdateProxyRequest{EgressChainId: proto.String(goldenC2)}, connect.CodeInvalidArgument, "another node"},
		{"a scope that does not exist", &panelv1.UpdateProxyRequest{EgressScopeChains: &panelv1.ScopeChains{Chains: map[string]string{"web": goldenC1}}}, connect.CodeInvalidArgument, "scope"},
		{"a scope chain of another node", &panelv1.UpdateProxyRequest{EgressScopeChains: &panelv1.ScopeChains{Chains: map[string]string{"me": goldenC2}}}, connect.CodeInvalidArgument, "another node"},
		{"a chain for the middle proxies on a node that cannot route them", &panelv1.UpdateProxyRequest{EgressScopeChains: &panelv1.ScopeChains{Chains: map[string]string{"me": goldenC1}}}, connect.CodeFailedPrecondition, "upgrade node n to use a chain for the middle proxies (me-routing)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gen := e.generation(n.ID)
			tc.req.Id = p.GetId()
			_, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(tc.req))
			wantCode(t, err, tc.code)
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
			if e.generation(n.ID) != gen {
				t.Error("a refused change raised the generation")
			}
		})
	}

	// Back to the default chain of the node and no scope chains.
	gen := e.generation(n.ID)
	resp, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{
		Id: p.GetId(), EgressChainId: proto.String(""), EgressScopeChains: &panelv1.ScopeChains{},
	}))
	if err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}
	if resp.Msg.GetProxy().GetEgressChainId() != "" || len(resp.Msg.GetProxy().GetEgressScopeChains()) != 0 || e.generation(n.ID) != gen+1 {
		t.Errorf("after the change: chain %q, scope chains %v, generation %d → %d",
			resp.Msg.GetProxy().GetEgressChainId(), resp.Msg.GetProxy().GetEgressScopeChains(), gen, e.generation(n.ID))
	}
	// A change of the chains alone is a change.
	if _, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{
		Id: p.GetId(), EgressScopeChains: &panelv1.ScopeChains{Chains: map[string]string{"fetch": goldenC1}},
	})); err != nil || e.generation(n.ID) != gen+2 {
		t.Errorf("a change of the scope chains alone: %v, generation %d", err, e.generation(n.ID))
	}

	// The proxy of a node that routes the middle proxies takes a chain for them.
	lo := e.createListener(&panelv1.CreateListenerRequest{NodeId: other.ID, Port: 8443})
	po := e.createProxy(&panelv1.CreateProxyRequest{
		NodeId: other.ID, ListenerId: lo.GetId(), Domain: "me.example.com", EgressScopeChains: map[string]string{"me": goldenC2},
	})
	if po.GetEgressScopeChains()["me"] != goldenC2 {
		t.Errorf("scope chains = %v", po.GetEgressScopeChains())
	}
}

// The ingestor keeps the health of the egress members of a node, as its last
// state report has it, clipped, with the time of the report.
func TestIngestorKeepsTheEgressHealth(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n", "203.0.113.10")
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	report := &nodev1.StateReport{Egress: []*nodev1.EgressMemberHealth{
		{ChainId: "default", MemberKey: "direct", Status: "up", LatencyMs: 42, ExitIp: "203.0.113.9", CheckedUnix: at.Unix() - 5},
		{ChainId: goldenC1, MemberKey: goldenE5 + "/0123456789ab", Status: "down", ExitIp: strings.Repeat("x", 300)},
	}}
	if err := e.ingest.OnWatch(e.ctx, n.ID, &nodev1.WatchResponse{Seq: 3, TsUnix: at.Unix(), Payload: &nodev1.WatchResponse_State{State: report}}); err != nil {
		t.Fatalf("OnWatch: %v", err)
	}
	got, reported, ok := e.ingest.EgressHealth(n.ID)
	if !ok || !reported.Equal(at) || len(got) != 2 {
		t.Fatalf("EgressHealth = %v, %v, %v", got, reported, ok)
	}
	if !proto.Equal(got[0], report.GetEgress()[0]) {
		t.Errorf("member 0 = %v, want %v", got[0], report.GetEgress()[0])
	}
	if len(got[1].GetExitIp()) > 64 {
		t.Errorf("an exit IP of %d bytes was kept", len(got[1].GetExitIp()))
	}
	// The opening report of an agent that has had no pass yet says nothing.
	if err := e.ingest.OnWatch(e.ctx, n.ID, &nodev1.WatchResponse{Payload: &nodev1.WatchResponse_State{State: &nodev1.StateReport{}}}); err != nil {
		t.Fatal(err)
	}
	// It replaces nothing only while the panel knows proxies of the node; the
	// node has none, so the empty report is the health now.
	if got, _, ok := e.ingest.EgressHealth(n.ID); !ok || len(got) != 0 {
		t.Errorf("after an empty report: %v, %v", got, ok)
	}
	if _, _, ok := e.ingest.EgressHealth("01K6Y00000000000000000000Z"); ok {
		t.Error("health of a node that never reported")
	}

	// A time of a check ahead of the clock of the panel is taken as at most a
	// minute ahead: the clocks differ a little, and no more is believed.
	now := time.Now().Truncate(time.Second)
	e.ingest.now = func() time.Time { return now }
	ahead := &nodev1.StateReport{Egress: []*nodev1.EgressMemberHealth{
		{ChainId: "default", MemberKey: "direct", Status: "up", CheckedUnix: now.Unix() + 3600},
		{ChainId: "default", MemberKey: "other", Status: "up", CheckedUnix: now.Unix() + 30},
	}}
	if err := e.ingest.OnWatch(e.ctx, n.ID, &nodev1.WatchResponse{Seq: 4, TsUnix: now.Unix(), Payload: &nodev1.WatchResponse_State{State: ahead}}); err != nil {
		t.Fatal(err)
	}
	got, _, _ = e.ingest.EgressHealth(n.ID)
	if len(got) != 2 || got[0].GetCheckedUnix() != now.Unix()+60 || got[1].GetCheckedUnix() != now.Unix()+30 {
		t.Errorf("checked times = %v, want the first clamped to a minute ahead", got)
	}
}

// What the ingestor keeps of a node goes when the node is deleted.
func TestIngestorForgetsADeletedNode(t *testing.T) {
	e := newEnv(t)
	n, l := e.nodeWithListener()
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "x.example.com"})
	report := &nodev1.StateReport{
		Proxies: []*nodev1.ProxyStatus{{ProxyId: p.GetId(), Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING}},
		Egress:  []*nodev1.EgressMemberHealth{{ChainId: "default", MemberKey: "direct", Status: "up"}},
	}
	if err := e.ingest.OnWatch(e.ctx, n.ID, &nodev1.WatchResponse{Seq: 1, TsUnix: time.Now().Unix(), Payload: &nodev1.WatchResponse_State{State: report}}); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := e.ingest.EgressHealth(n.ID); !ok {
		t.Fatal("no health after a report")
	}
	if _, ok := e.ingest.ProxyReport(n.ID, p.GetId()); !ok {
		t.Fatal("no status after a report")
	}
	e.ingest.ForgetNode(n.ID)
	if _, _, ok := e.ingest.EgressHealth(n.ID); ok {
		t.Error("the health of a forgotten node is kept")
	}
	if _, ok := e.ingest.ProxyReport(n.ID, p.GetId()); ok {
		t.Error("the status of a proxy of a forgotten node is kept")
	}
}

// The parameters of an egress open with its own id only.
func TestEgressParamsAreSealedForTheirEgress(t *testing.T) {
	e := newEnv(t)
	params := `{"addr":"198.51.100.9:1080","password":"` + fakePassword + `"}`
	sealed, err := SealEgressParams(e.key, goldenE1, params)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(fakePassword)) {
		t.Fatal("the sealed parameters hold the password")
	}
	got, err := OpenEgressParams(e.key, &store.Egress{ID: goldenE1, ParamsEnc: sealed})
	if err != nil || got != params {
		t.Errorf("OpenEgressParams = %q, %v", got, err)
	}
	if _, err := OpenEgressParams(e.key, &store.Egress{ID: goldenE2, ParamsEnc: sealed}); !errors.Is(err, errParams) {
		t.Errorf("OpenEgressParams for another egress = %v, want errParams", err)
	}
	if got, err := OpenEgressParams(e.key, &store.Egress{ID: goldenE1}); err != nil || got != "" {
		t.Errorf("OpenEgressParams of none = %q, %v", got, err)
	}
}
