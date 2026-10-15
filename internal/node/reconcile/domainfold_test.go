package reconcile

import (
	"context"
	"crypto/tls"
	"log/slog"
	"maps"
	"net"
	"slices"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge"
	"github.com/urbnywrt/postern/internal/node/state"
)

// The edge folds a server name before it uses it: ASCII lower case, and without the
// one dot at its end. The node keys its routes, and tells the winner of two keys
// that collide, in the same form (state.FoldDomain); otherwise it would send the
// edge two routes of one name, for which the edge refuses its whole table, or take
// the route of a proxy away from it for a key that is its own.

// foldState is a state with one listener and the given proxies. The listener is of
// kind http-upstream on the loopback interface, unless the caller changes
// it: a table with it is for edge.CheckConfig, which binds nothing.
func foldState(proxies ...*nodev1.Proxy) *nodev1.NodeState {
	return &nodev1.NodeState{
		Settings: &nodev1.NodeSettings{DefaultChainId: "default"},
		Listeners: []*nodev1.Listener{{
			Id: "L1", Kind: nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM, BindIp: "127.0.0.1", Port: 443,
		}},
		Proxies:  proxies,
		Egresses: []*nodev1.Egress{{Id: "direct", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT}},
		Chains:   []*nodev1.EgressChain{{Id: "default", MemberEgressIds: []string{"direct"}}},
	}
}

// newTestEdge is a real edge, stopped with the test.
func newTestEdge(t *testing.T) *edge.Edge {
	t.Helper()
	e := edge.New(slog.New(slog.DiscardHandler), edge.Options{})
	t.Cleanup(func() { _ = e.Drain(context.Background()) })
	return e
}

// A route is keyed by what its instance was rendered for. When two keys are one
// name to the edge, whatever their letter case and their dot at the end, one route
// is sent: the instance whose key is also its proxy's desired one, or else the one
// that took over last. The table that comes out is one that the real edge takes.
func TestEdgeConfigKeysRoutesAsTheEdgeFoldsNames(t *testing.T) {
	type serving struct {
		desired string        // the domain of the proxy in the state
		key     string        // the domain its instance was rendered for
		since   time.Duration // when it took over, after the start of the test
	}
	start := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		a, b serving
		want map[string]string // proxy id -> the SNI of its route as it is written
	}{
		{
			"a key with a dot at the end and one without, the first is the desired one",
			serving{"example.com.", "example.com.", 0}, serving{"b.example.com", "example.com", time.Hour},
			map[string]string{"A": "example.com."},
		},
		{
			"a key without a dot and one with it, the first is the desired one",
			serving{"example.com", "example.com", 0}, serving{"b.example.com", "example.com.", time.Hour},
			map[string]string{"A": "example.com"},
		},
		{
			// The key of A is not its domain as it is written, but it is the same
			// name: it is the desired key, and the later key of B does not win.
			"a desired key that differs from the domain in letter case and a dot",
			serving{"example.com.", "EXAMPLE.com", 0}, serving{"b.example.com", "example.com", time.Hour},
			map[string]string{"A": "EXAMPLE.com"},
		},
		{
			"two stale keys, the later one wins",
			serving{"a.example.com", "Example.com.", 0}, serving{"b.example.com", "example.com", time.Hour},
			map[string]string{"B": "example.com"},
		},
		{
			"two stale keys, the later one wins, the other way round",
			serving{"a.example.com", "example.com", 2 * time.Hour}, serving{"b.example.com", "EXAMPLE.COM.", time.Hour},
			map[string]string{"A": "example.com"},
		},
		{
			"names that are not one stay two routes",
			serving{"a.example.", "a.example.", 0}, serving{"a.example.com", "a.example.com", 0},
			map[string]string{"A": "a.example.", "B": "a.example.com"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := foldState(
				&nodev1.Proxy{Id: "A", ListenerId: "L1", Enabled: true, Domain: tc.a.desired},
				&nodev1.Proxy{Id: "B", ListenerId: "L1", Enabled: true, Domain: tc.b.desired},
			)
			rt := state.NewRuntime()
			rt.Instances["A"] = state.InstanceRecord{Generation: 1, ListenPort: 20001, ListenerID: "L1", Domain: tc.a.key, ServingSince: start.Add(tc.a.since)}
			rt.Instances["B"] = state.InstanceRecord{Generation: 1, ListenPort: 20002, ListenerID: "L1", Domain: tc.b.key, ServingSince: start.Add(tc.b.since)}
			cfg := buildEdgeConfig(st, rt, 1, nil)

			got := map[string]string{}
			for _, r := range cfg.GetRoutes() {
				got[r.GetProxyId()] = r.GetSni()
			}
			if !maps.Equal(got, tc.want) {
				t.Errorf("routes (proxy -> SNI) = %v, want %v", got, tc.want)
			}
			if err := edge.CheckConfig(cfg); err != nil {
				t.Errorf("the edge refuses the table: %v", err)
			}
		})
	}
}

// Routes come in a fixed order, that of the folded names: the dot at the end does
// not count. ("a.b." folds to "a.b", which sorts before "a.b-c"; by its own bytes
// the dot sorts after the hyphen.)
func TestEdgeConfigSortsRoutesByTheFoldedName(t *testing.T) {
	st := foldState(
		&nodev1.Proxy{Id: "A", ListenerId: "L1", Enabled: true, Domain: "a.b-c"},
		&nodev1.Proxy{Id: "B", ListenerId: "L1", Enabled: true, Domain: "A.B."},
		&nodev1.Proxy{Id: "C", ListenerId: "L1", Enabled: true, Domain: "a.b.c"},
	)
	rt := state.NewRuntime()
	for i, id := range []string{"A", "B", "C"} {
		rt.Instances[id] = state.InstanceRecord{Generation: 1, ListenPort: uint16(20001 + i)}
	}
	var got []string
	for _, r := range buildEdgeConfig(st, rt, 1, nil).GetRoutes() {
		got = append(got, r.GetSni())
	}
	if want := []string{"A.B.", "a.b-c", "a.b.c"}; !slices.Equal(got, want) {
		t.Errorf("SNIs in order = %q, want %q", got, want)
	}
}

// The mask domains are folded as the edge folds names, so that a name that the pool
// and a proxy have in two forms is one.
func TestEdgeConfigFoldsMaskDomains(t *testing.T) {
	st := foldState(
		&nodev1.Proxy{Id: "A", ListenerId: "L1", Domain: "pool.example.com"},
		&nodev1.Proxy{Id: "B", ListenerId: "L1", Domain: "X.example.com."}, // paused, still a mask domain
	)
	st.Settings.DomainPool = []string{"Pool.example.com.", "other.example.com"}
	got := buildEdgeConfig(st, state.NewRuntime(), 1, nil).GetMaskDomains()
	if want := []string{"other.example.com", "pool.example.com", "x.example.com"}; !slices.Equal(got, want) {
		t.Errorf("mask domains = %q, want %q", got, want)
	}
}

// The first of a connection to the edge that the engine of a stored domain answers:
// a domain that a proxy keeps with a dot at the end, and with the letter
// case of its link, routes for the SNI that a client sends without them. The table
// comes from buildEdgeConfig and goes to a real edge, which a client of the node
// reaches with a TLS hello; the engine is a plain listener that notes who comes.
func TestStoredDomainWithADotRoutesForTheSNIWithout(t *testing.T) {
	engine, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	arrivals := make(chan struct{}, 16)
	go func() {
		for {
			c, err := engine.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				// The edge sends the PROXY header and the hello it has read;
				// reading it is all that is asked of an engine here.
				buf := make([]byte, 1)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(buf)
				arrivals <- struct{}{}
			}()
		}
	}()
	enginePort := uint16(engine.Addr().(*net.TCPAddr).Port)

	// A port that the edge can bind on the loopback.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	edgeAddr := probe.Addr().String()
	edgePort := uint32(probe.Addr().(*net.TCPAddr).Port)
	_ = probe.Close()

	st := foldState(&nodev1.Proxy{Id: "A", ListenerId: "L1", Enabled: true, Domain: "Example.COM."})
	st.Listeners[0].Kind = nodev1.ListenerKind_LISTENER_KIND_TLS
	st.Listeners[0].BindIp, st.Listeners[0].Port = "127.0.0.1", edgePort
	rt := state.NewRuntime()
	rt.Instances["A"] = state.InstanceRecord{
		Generation: 1, ListenPort: enginePort, ListenerID: "L1", Domain: "Example.COM.", ServingSince: time.Now(),
	}
	cfg := buildEdgeConfig(st, rt, 1, nil)
	if got := routeMap(cfg); !maps.Equal(got, map[string]string{"L1/Example.COM.": "A->" + addr(enginePort)}) {
		t.Fatalf("routes = %v: the domain is sent as it is stored", got)
	}
	if err := newTestEdge(t).Apply(cfg); err != nil {
		t.Fatalf("the edge refuses the table: %v", err)
	}

	hello := func(sni string) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", edgeAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("connecting to the edge: %v", err)
		}
		defer func() { _ = conn.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// Nothing answers as a real server would, so the handshake ends in an
		// error either way; what matters is where the hello went.
		_ = tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}).HandshakeContext(ctx)
	}
	for _, sni := range []string{"example.com", "EXAMPLE.com", "Example.COM"} {
		hello(sni)
		select {
		case <-arrivals:
		case <-time.After(5 * time.Second):
			t.Errorf("a client of %q did not reach the engine of the proxy whose domain is stored as \"Example.COM.\"", sni)
		}
	}
	// A name that is not its name does not reach it.
	hello("elsewhere.example")
	select {
	case <-arrivals:
		t.Error("a client of another name reached the engine")
	default:
	}
}
