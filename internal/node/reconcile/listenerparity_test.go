package reconcile

import (
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge"
	"github.com/urbnywrt/postern/internal/node/state"
)

// The node takes no listener that its edge refuses (I2): the edge refuses its
// whole configuration for one value it cannot take, with every proxy of the
// node in it. So for every value of a listener below, when state.Validate takes
// the state, the real edge takes the configuration that the reconciler makes of
// it. The node may be stricter (IPv4 listeners only, no mask target on its own
// loopback ports), never looser. The edge checks the configurations with
// edge.CheckConfig, which binds nothing, so that no socket is opened.
func TestNodeTakesNoListenerItsEdgeRefuses(t *testing.T) {
	type tally struct{ both, nodeOnlyRefuses, bothRefuse int }
	var got tally
	check := func(what string, mutate func(l *nodev1.Listener)) {
		t.Helper()
		l := &nodev1.Listener{Id: "L1", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "192.0.2.1", Port: 443}
		mutate(l)
		st := &nodev1.NodeState{Generation: 1, Listeners: []*nodev1.Listener{l}}
		nodeErr := state.Validate(st, nil)
		cfg := buildEdgeConfig(st, state.NewRuntime(), 1, nil)
		edgeErr := edge.CheckConfig(cfg)
		switch {
		case nodeErr == nil && edgeErr != nil:
			t.Errorf("%s: the node takes the listener, but the edge refuses its configuration: %v", what, edgeErr)
		case nodeErr == nil:
			got.both++
		case edgeErr == nil:
			got.nodeOnlyRefuses++
		default:
			got.bothRefuse++
		}
	}

	for _, target := range []string{
		"", "mask.example.com", "Mask.Example.COM.:8443", "192.0.2.10", "192.0.2.10:8443", "[2001:db8::1]:443",
		"2001:db8::1", "[::ffff:192.0.2.10]:443", "127.0.0.1:8443", "localhost:443", "mask.example.com:0443",
		"127.0.0.1:30000", "localhost:25000", // the node's own ports: the node alone refuses them
		"mask.example.com:https", "mask.example.com:0", "mask.example.com:65536", "mask.example.com:", ":443",
		"bad_name.example.com", "bad name.example.com", " mask.example.com", "mask.example.com ", "[2001:db8::1]",
		"mask.example.com:443:1", "mask.example.com\x00:443", "a..example.com", ".", strings.Repeat("a", 64) + ".example.com",
		"http://mask.example.com/", "mask.example.com/x", "user@mask.example.com", "\xff",
	} {
		check("mask target "+target, func(l *nodev1.Listener) { l.MaskTarget = target })
	}
	for _, c := range []string{
		"192.0.2.0/24", "192.0.2.5/24", "192.0.2.1/32", "198.51.100.7", "0.0.0.0/0", "::/0", "2001:db8::/32",
		"2001:db8::1", "::ffff:192.0.2.1", "::ffff:192.0.2.0/120",
		"", " ", "192.0.2.0/33", "192.0.2.0/-1", "192.0.2.0/", "/24", "192.0.2.0/24 ", " 192.0.2.0/24", "192.0.2.256",
		"192.0.2", "0x7f.0.0.1", "2001:db8::/129", "[2001:db8::1]", "fe80::1%eth0", "fe80::1%eth0/64",
		"proxy.example.com", "192.0.2.0/24,198.51.100.0/24", "192.0.2.0/024",
	} {
		check("trusted CIDR "+c, func(l *nodev1.Listener) { l.TrustedCidrs = []string{c} })
	}
	for _, ip := range []string{
		"192.0.2.1", "0.0.0.0", "127.0.0.1", "127.0.0.2", "::ffff:192.0.2.1", "2001:db8::1", "::", "fe80::1%eth0",
		"", "localhost", "192.0.2.256", "192.0.2.1:443", " 192.0.2.1",
	} {
		check("bind address "+ip, func(l *nodev1.Listener) { l.BindIp = ip })
	}
	for _, port := range []uint32{1, 443, 65535, 0, 65536, 1 << 31} {
		check("port", func(l *nodev1.Listener) { l.Port = port })
	}
	for _, a := range []nodev1.StrangerAction{0, 1, 2, 3, 4, 9} {
		for _, n := range []nodev1.NonTlsAction{0, 1, 2, 3, 9} {
			check("actions "+a.String()+", "+n.String(), func(l *nodev1.Listener) { l.StrangerAction, l.NonTlsAction = a, n })
		}
	}
	for _, k := range []nodev1.ListenerKind{0, 1, 2, 7} {
		check("kind "+k.String(), func(l *nodev1.Listener) { l.Kind = k })
	}
	for _, id := range []string{"L1", "", "a/b", strings.Repeat("L", 65)} {
		check("id "+id, func(l *nodev1.Listener) { l.Id = id })
	}

	// Both sides were put to work: the lists hold values that both take,
	// values that both refuse, and values that only the node refuses.
	if got.both < 40 || got.bothRefuse < 40 || got.nodeOnlyRefuses < 5 {
		t.Errorf("taken by both %d, refused by both %d, by the node only %d: the test shows little", got.both, got.bothRefuse, got.nodeOnlyRefuses)
	}
}

// What the reconciler sends for a listener's kind and actions is always a value
// the edge reads, also for an enum value it does not know: the node refuses
// those itself (state.Validate), and the edge must never see one.
func TestListenerEnumsMapToValuesTheEdgeTakes(t *testing.T) {
	kinds := []string{listenerKind(0), listenerKind(1), listenerKind(2), listenerKind(99)}
	if !slices.Equal(kinds, []string{"tls", "tls", "http-upstream", "tls"}) {
		t.Errorf("kinds = %q", kinds)
	}
	actions := []string{strangerAction(0), strangerAction(1), strangerAction(2), strangerAction(3), strangerAction(99)}
	if !slices.Equal(actions, []string{"mask", "mask", "reject", "drop", "mask"}) {
		t.Errorf("stranger actions = %q", actions)
	}
	nonTLS := []string{nonTLSAction(0), nonTLSAction(1), nonTLSAction(2), nonTLSAction(99)}
	if !slices.Equal(nonTLS, []string{"drop", "drop", "http400", "drop"}) {
		t.Errorf("non-TLS actions = %q", nonTLS)
	}
}
