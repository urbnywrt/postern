package reconcile

import (
	"bytes"
	"encoding/json"
	"flag"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/state"
)

// update rewrites the golden files in testdata:
//
//	go test ./internal/node/reconcile -run TestEdgeConfigGolden -update
//
// Read the diff afterwards.
var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// goldenState has two proxies on two listeners: P1 enabled, P2 paused; four
// egresses (two direct, socks5, http) in two chains.
func goldenState() *nodev1.NodeState {
	return &nodev1.NodeState{
		Generation: 12,
		Settings: &nodev1.NodeSettings{
			DefaultChainId: "default",
			DomainPool:     []string{"pool.example.com", "A.example.com"},
			BlacklistCidrs: []string{"192.0.2.0/24", "198.51.100.7"},
			ProbeSources:   []string{"203.0.113.50", "::ffff:198.51.100.30", "2001:DB8::30", "203.0.113.50"},
		},
		Listeners: []*nodev1.Listener{
			{
				Id: "L2", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "203.0.113.10", Port: 8443,
				StrangerAction: nodev1.StrangerAction_STRANGER_ACTION_REJECT, MaskTarget: "mask.example.com:443",
				NonTlsAction: nodev1.NonTlsAction_NON_TLS_ACTION_HTTP400,
			},
			{Id: "L1", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "0.0.0.0", Port: 443},
		},
		Proxies: []*nodev1.Proxy{
			{
				Id: "P2", ListenerId: "L2", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS,
				Secret: secret2, Domain: "b.example.com",
				Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
				EgressChainId: "via-socks",
			},
			{
				Id: "P1", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Enabled: true,
				Secret: secret1, Domain: "a.example.com",
				Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
				Limits:            &nodev1.Limits{Devices: 3, ConnsTotal: 100, ConnsPerIp: 10},
				EgressScopeChains: map[string]string{"me": "via-socks"},
			},
		},
		Egresses: []*nodev1.Egress{
			{Id: "direct", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT},
			{Id: "eth", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT, ParamsJson: `{"bind_ip":"198.51.100.2"}`},
			{Id: "sock", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"198.51.100.9:1080","username":"user","password":"pw"}`},
			{Id: "web", Kind: nodev1.EgressKind_EGRESS_KIND_HTTP, ParamsJson: `{"addr":"proxy.example.com:3128"}`},
		},
		Chains: []*nodev1.EgressChain{
			{
				Id: "via-socks", MemberEgressIds: []string{"sock", "web", "eth"},
				Check: &nodev1.HealthCheck{
					IntervalSeconds: 15, TimeoutSeconds: 3, FailThreshold: 4, RecoverThreshold: 1,
					DcAddrs: []string{"149.154.175.50:443", "149.154.167.51:443"},
				},
			},
			{Id: "default", MemberEgressIds: []string{"direct"}},
		},
	}
}

// goldenRuntime: P1 is served by g3 while g2 drains; P2 (paused) by g1.
func goldenRuntime() *state.Runtime {
	since := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	rt := state.NewRuntime()
	for _, p := range []struct {
		id                 string
		gen                uint64
		listen, api, socks uint16
	}{
		{"P1", 3, 20003, 25003, 30003},
		{"P1", 2, 20002, 25002, 30002},
		{"P2", 1, 20001, 25001, 30001},
	} {
		rt.Ports[state.EnginePortKey(p.id, p.gen, state.PortListen)] = p.listen
		rt.Ports[state.EnginePortKey(p.id, p.gen, state.PortAPI)] = p.api
		rt.Ports[state.EnginePortKey(p.id, p.gen, state.PortSocks)] = p.socks
	}
	rt.Ports[state.TestListenerPortKey("L1")] = 40000
	rt.Ports[state.TestListenerPortKey("L2")] = 40001
	rt.Instances["P1"] = state.InstanceRecord{
		Generation: 3, Hash: "h3", ListenerID: "L1", Domain: "a.example.com", ListenPort: 20003, APIPort: 25003, SocksPort: 30003, ServingSince: since,
		Draining: []state.DrainingInstance{{Generation: 2, ContainerName: "postern-eng-p1-g2", Since: since, ListenPort: 20002}},
	}
	rt.Instances["P2"] = state.InstanceRecord{
		Generation: 1, Hash: "h1", ListenerID: "L2", Domain: "b.example.com", ListenPort: 20001, APIPort: 25001, SocksPort: 30001, ServingSince: since,
	}
	rt.EdgeGeneration = 5
	return rt
}

// The reconciler renders a mgmt route (spec 5.3) on every public tls listener,
// and only when mgmt_sni is set and the agent has allocated the hidden port.
func TestEdgeConfigMgmtRoute(t *testing.T) {
	st := &nodev1.NodeState{
		Generation: 1,
		Settings:   &nodev1.NodeSettings{MgmtSni: "mgmt.example.com"},
		Listeners: []*nodev1.Listener{
			{Id: "L1", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "0.0.0.0", Port: 443},
			{Id: "L2", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "203.0.113.10", Port: 8443},
			{Id: "U1", Kind: nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM, BindIp: "127.0.0.1", Port: 8080,
				TrustedCidrs: []string{"127.0.0.1/32"}},
		},
	}

	// No hidden port yet: no mgmt route.
	if got := mgmtRoutes(buildEdgeConfig(st, state.NewRuntime(), 1, nil)); len(got) != 0 {
		t.Errorf("mgmt routes without the hidden port = %v, want none", got)
	}

	rt := state.NewRuntime()
	rt.Ports[state.MgmtHiddenPortKey] = 40042
	routes := mgmtRoutes(buildEdgeConfig(st, rt, 1, nil))
	if len(routes) != 2 {
		t.Fatalf("mgmt routes = %d, want 2 (the tls listeners, not the http-upstream one)", len(routes))
	}
	listeners := map[string]bool{}
	for _, r := range routes {
		listeners[r.GetListenerId()] = true
		if r.GetSni() != "mgmt.example.com" || !r.GetProxyProtocol() || r.GetBackend() != "127.0.0.1:40042" || r.GetProxyId() != "" {
			t.Errorf("mgmt route = %v, want sni mgmt.example.com, proxy_protocol, backend 127.0.0.1:40042, no proxy id", r)
		}
	}
	if !listeners["L1"] || !listeners["L2"] || listeners["U1"] {
		t.Errorf("mgmt routes on %v, want L1 and L2 only", listeners)
	}

	// No mgmt_sni: no mgmt route even with the hidden port.
	st.Settings.MgmtSni = ""
	if got := mgmtRoutes(buildEdgeConfig(st, rt, 1, nil)); len(got) != 0 {
		t.Errorf("mgmt routes without mgmt_sni = %v, want none", got)
	}
}

// mgmtRoutes is the routes of kind mgmt of a config.
func mgmtRoutes(cfg *edgev1.EdgeConfig) []*edgev1.Route {
	var out []*edgev1.Route
	for _, r := range cfg.GetRoutes() {
		if r.GetKind() == "mgmt" {
			out = append(out, r)
		}
	}
	return out
}

func TestEdgeConfigGolden(t *testing.T) {
	st, rt := goldenState(), goldenRuntime()
	stBefore, rtBefore := proto.Clone(st), *rt
	cfg := buildEdgeConfig(st, rt, 5, nil)
	if !proto.Equal(st, stBefore) || len(rt.Ports) != len(rtBefore.Ports) {
		t.Fatal("buildEdgeConfig changed its input")
	}

	got := goldenJSON(t, cfg)
	path := filepath.Join("testdata", "edgecfg_two_proxies.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the edge config differs from %s (run with -update to accept a change):\ngot:\n%s", path, got)
	}
	// The golden file reads back as the same config (the edge loads it with
	// protojson).
	back := &edgev1.EdgeConfig{}
	if err := protojson.Unmarshal(want, back); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(back, cfg) {
		t.Error("the golden file does not read back as the built config")
	}
	// Determinism: the same input gives the same bytes.
	if again := goldenJSON(t, buildEdgeConfig(goldenState(), goldenRuntime(), 5, nil)); !bytes.Equal(again, got) {
		t.Error("buildEdgeConfig is not deterministic")
	}
}

// goldenJSON is protojson with stable whitespace (protojson randomizes it).
func goldenJSON(t *testing.T, cfg *edgev1.EdgeConfig) []byte {
	t.Helper()
	raw, err := protojson.Marshal(cfg)
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

// An instance that is being started has its SOCKS port in the edge before it
// serves; it has no route yet.
func TestEdgeConfigStartingInstance(t *testing.T) {
	st, rt := goldenState(), goldenRuntime()
	rt.Ports[state.EnginePortKey("P1", 4, state.PortSocks)] = 30004
	cfg := buildEdgeConfig(st, rt, 5, map[string]startingInstance{"P1": {gen: 4, socks: 30004}})
	var found *edgev1.SocksPort
	for _, s := range cfg.GetSocks() {
		if s.GetPort() == 30004 {
			found = s
		}
	}
	want := &edgev1.SocksPort{Port: 30004, ProxyId: "P1", DefaultChainId: "default", ScopeChains: map[string]string{"me": "via-socks"}}
	if !proto.Equal(found, want) {
		t.Errorf("socks port of the starting instance = %v, want %v", found, want)
	}
	if got := routeBackends(cfg); !slices.Equal(got, []string{"P1->127.0.0.1:20003"}) {
		t.Errorf("routes = %v, want only the serving instance", got)
	}
}

// A deleted proxy has no route; its draining instance keeps a SOCKS port on the
// node's default chain while it lives, and none when there is no default chain.
func TestEdgeConfigDeletedProxy(t *testing.T) {
	st, rt := goldenState(), goldenRuntime()
	st.Proxies = st.Proxies[:1] // P1 deleted
	rt.Instances["P1"] = state.InstanceRecord{Draining: rt.Instances["P1"].Draining}
	cfg := buildEdgeConfig(st, rt, 5, nil)
	if len(cfg.GetRoutes()) != 0 {
		t.Errorf("routes = %v, want none", cfg.GetRoutes())
	}
	if got := socksPorts(cfg); !slices.Equal(got, []uint32{30001, 30002}) {
		t.Errorf("socks ports = %v, want [30001 30002]", got)
	}
	for _, s := range cfg.GetSocks() {
		if s.GetPort() == 30002 && (s.GetDefaultChainId() != "default" || len(s.GetScopeChains()) != 0) {
			t.Errorf("socks of the deleted proxy = %v, want the default chain only", s)
		}
	}

	st.Settings.DefaultChainId = ""
	st.Proxies = nil
	cfg = buildEdgeConfig(st, rt, 5, nil)
	if got := socksPorts(cfg); !slices.Equal(got, []uint32{}) && len(got) != 0 {
		t.Errorf("socks ports without a default chain = %v, want none", got)
	}
}

// Routes are keyed by what the serving generation was rendered for. When two
// keys collide, the instance whose key is also its proxy's desired one wins;
// between two stale keys, the generation that took over last.
func TestEdgeConfigRouteKeyCollisions(t *testing.T) {
	since := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	st := &nodev1.NodeState{
		Settings:  &nodev1.NodeSettings{DefaultChainId: "default"},
		Listeners: []*nodev1.Listener{{Id: "L1", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "0.0.0.0", Port: 443}},
		Proxies: []*nodev1.Proxy{
			{Id: "A", ListenerId: "L1", Enabled: true, Domain: "y.example.com"},
			{Id: "B", ListenerId: "L1", Enabled: true, Domain: "x.example.com"},
			{Id: "C", ListenerId: "L1", Enabled: true, Domain: "z.example.com"},
		},
		Egresses: []*nodev1.Egress{{Id: "direct", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT}},
		Chains:   []*nodev1.EgressChain{{Id: "default", MemberEgressIds: []string{"direct"}}},
	}
	rt := state.NewRuntime()
	// A still serves x (its change to y is pending; SNIs collide ignoring
	// case); B serves x as desired, and took over earlier.
	rt.Instances["A"] = state.InstanceRecord{Generation: 1, ListenPort: 20001, ListenerID: "L1", Domain: "X.example.com", ServingSince: since.Add(time.Hour)}
	rt.Instances["B"] = state.InstanceRecord{Generation: 1, ListenPort: 20002, ListenerID: "L1", Domain: "x.example.com", ServingSince: since}
	cfg := buildEdgeConfig(st, rt, 1, nil)
	if got, want := routeMap(cfg), map[string]string{"L1/x.example.com": "B->127.0.0.1:20002"}; !maps.Equal(got, want) {
		t.Errorf("routes = %v, want %v", got, want)
	}

	// Two stale keys: the later switch wins.
	rt.Instances["B"] = state.InstanceRecord{Generation: 1, ListenPort: 20002, ListenerID: "L1", Domain: "w.example.com", ServingSince: since}
	rt.Instances["C"] = state.InstanceRecord{Generation: 1, ListenPort: 20003, ListenerID: "L1", Domain: "x.example.com", ServingSince: since.Add(2 * time.Hour)}
	cfg = buildEdgeConfig(st, rt, 1, nil)
	if got, want := routeMap(cfg), map[string]string{
		"L1/x.example.com": "C->127.0.0.1:20003",
		"L1/w.example.com": "B->127.0.0.1:20002",
	}; !maps.Equal(got, want) {
		t.Errorf("routes = %v, want %v", got, want)
	}
}

// A direct egress through an interface maps to bind_device.
func TestChainMemberDirectInterface(t *testing.T) {
	m := chainMember(&nodev1.Egress{Id: "wg", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT, ParamsJson: `{"interface":"wg0","bind_ip":"198.51.100.2"}`})
	want := &edgev1.ChainMember{Key: "wg", Kind: "direct", BindDevice: "wg0", BindIp: "198.51.100.2"}
	if !proto.Equal(m, want) {
		t.Errorf("member = %v, want %v", m, want)
	}
}

// The edge needs CAP_NET_RAW when, and only when, a member of one of its chains
// is tied to an interface.
func TestEdgeNeedsNetRaw(t *testing.T) {
	wg := &nodev1.Egress{Id: "wg", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT, ParamsJson: `{"interface":"wg0"}`}
	src := &nodev1.Egress{Id: "src", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT, ParamsJson: `{"bind_ip":"198.51.100.2"}`}
	sock := &nodev1.Egress{Id: "sock", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"198.51.100.9:1080"}`}
	bad := &nodev1.Egress{Id: "bad", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT, ParamsJson: `{"interface":"../wg0"}`}
	chain := func(members ...string) *nodev1.EgressChain {
		return &nodev1.EgressChain{Id: "c", MemberEgressIds: members}
	}
	for _, tc := range []struct {
		name string
		st   *nodev1.NodeState
		want bool
	}{
		{"no state", nil, false},
		{"a member through an interface", &nodev1.NodeState{Egresses: []*nodev1.Egress{sock, wg}, Chains: []*nodev1.EgressChain{chain("sock", "wg")}}, true},
		{"an interface that no chain uses", &nodev1.NodeState{Egresses: []*nodev1.Egress{sock, wg}, Chains: []*nodev1.EgressChain{chain("sock")}}, false},
		{"a source address only", &nodev1.NodeState{Egresses: []*nodev1.Egress{src}, Chains: []*nodev1.EgressChain{chain("src")}}, false},
		{"parameters that do not parse", &nodev1.NodeState{Egresses: []*nodev1.Egress{bad}, Chains: []*nodev1.EgressChain{chain("bad")}}, false},
		{"a member that does not exist", &nodev1.NodeState{Chains: []*nodev1.EgressChain{chain("wg")}}, false},
	} {
		if got := edgeNeedsNetRaw(tc.st); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Listener actions that are not set get the defaults (mask, drop).
func TestEdgeConfigListenerDefaults(t *testing.T) {
	st := goldenState()
	cfg := buildEdgeConfig(st, goldenRuntime(), 5, nil)
	for _, l := range cfg.GetListeners() {
		if l.GetId() == "L1" && (l.GetStrangerAction() != "mask" || l.GetNonTlsAction() != "drop" || l.GetKind() != "tls") {
			t.Errorf("L1 = %v, want tls, mask, drop", l)
		}
	}
}
