package reconcile

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

// natState is the base state with a middle-proxy proxy whose default chain has
// two direct members, the second with a public source address, and a chain
// "via-me" of one.
func (h *harness) natState(gen uint64) *nodev1.NodeState {
	st := h.baseState(gen)
	st.Proxies[0].UseMiddleProxy = true
	st.Proxies[0].AdTag = adTag
	st.Egresses = append(st.Egresses,
		&nodev1.Egress{Id: "eth", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT, ParamsJson: `{"bind_ip":"198.51.100.2"}`},
		&nodev1.Egress{Id: "eth2", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT, ParamsJson: `{"bind_ip":"198.51.100.3"}`},
		&nodev1.Egress{Id: "wg", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT, ParamsJson: `{"interface":"wg0"}`},
		&nodev1.Egress{Id: "sock", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"198.51.100.9:1080"}`},
	)
	st.Chains[0].MemberEgressIds = []string{"direct", "eth"}
	st.Chains = append(st.Chains, &nodev1.EgressChain{Id: "via-me", MemberEgressIds: []string{"eth2"}})
	return st
}

func health(chain, member, status, exit string) *edgev1.MemberHealth {
	return &edgev1.MemberHealth{ChainId: chain, MemberKey: member, Status: status, ExitIp: exit}
}

// engineConfig is the config.toml of a generation of the proxy.
func (h *harness) engineConfig(gen uint64) string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.paths.InstancesDir(), "eng-01j9zzproxy0000000000000p1-g"+strconv.FormatUint(gen, 10), "config.toml"))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

// natLine is the NAT line of a config.toml for an address.
func natLine(ip string) string { return `middle_proxy_nat_ip = "` + ip + `"` }

// A proxy that uses the middle proxy and names no NAT address presents the
// exit address of the first member that is up of the chain its middle-proxy
// traffic takes: its scope chain "me" when it has one, its own chain
// otherwise. An explicit nat_ip wins. Without a known exit address, a chain of
// direct members goes out from the node's own address (Ruling S2-15): the
// public source address of its first member, or the node's public IPv4
// address; any other chain has no NAT line until its exit address is known.
func TestMiddleProxyNATIsTheExitAddressOfItsChain(t *testing.T) {
	const nodeIP = "203.0.113.77"
	cases := []struct {
		name   string
		nodeIP string // the node's public IPv4 address; nodeIP when empty, none when "-"
		mutate func(st *nodev1.NodeState)
		health []*edgev1.MemberHealth
		want   string // the NAT address, "" for no NAT line
	}{
		{
			name:   "the first member that is up",
			health: []*edgev1.MemberHealth{health("default", "direct", "down", "203.0.113.5"), health("default", "eth", "up", "203.0.113.9")},
			want:   "203.0.113.9",
		},
		{
			name:   "a member not checked yet does not count",
			health: []*edgev1.MemberHealth{health("default", "direct", "unknown", ""), health("default", "eth", "up", "203.0.113.9")},
			want:   "203.0.113.9",
		},
		{
			name:   "the scope chain me",
			mutate: func(st *nodev1.NodeState) { st.Proxies[0].EgressScopeChains = map[string]string{"me": "via-me"} },
			health: []*edgev1.MemberHealth{
				health("default", "direct", "up", "203.0.113.5"),
				health("via-me", "eth2", "up", "203.0.113.11"),
			},
			want: "203.0.113.11",
		},
		{
			name:   "an explicit nat_ip",
			mutate: func(st *nodev1.NodeState) { st.Proxies[0].NatIp = "198.51.100.5" },
			health: []*edgev1.MemberHealth{health("default", "direct", "up", "203.0.113.5")},
			want:   "198.51.100.5",
		},
		{
			name:   "no member up: the node's public address",
			health: []*edgev1.MemberHealth{health("default", "direct", "down", "203.0.113.5"), health("default", "eth", "down", "203.0.113.9")},
			want:   nodeIP,
		},
		{
			name:   "the member up has no known exit address: the node's public address",
			health: []*edgev1.MemberHealth{health("default", "direct", "up", ""), health("default", "eth", "up", "203.0.113.9")},
			want:   nodeIP,
		},
		{
			name:   "an IPv6 exit address: the node's public address",
			health: []*edgev1.MemberHealth{health("default", "direct", "up", "2001:db8::9")},
			want:   nodeIP,
		},
		{
			name: "no health at all: the node's public address",
			want: nodeIP,
		},
		{
			name:   "no health and no public address",
			nodeIP: "-",
		},
		{
			name:   "the public source address of the first member",
			mutate: func(st *nodev1.NodeState) { st.Proxies[0].EgressScopeChains = map[string]string{"me": "via-me"} },
			want:   "198.51.100.3",
		},
		{
			name: "a source address that is no public IPv4 address: the node's public address",
			mutate: func(st *nodev1.NodeState) {
				st.Egresses = append(st.Egresses, &nodev1.Egress{Id: "v6", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT, ParamsJson: `{"bind_ip":"2001:db8::5"}`})
				st.Chains = append(st.Chains, &nodev1.EgressChain{Id: "six", MemberEgressIds: []string{"v6", "eth2"}})
				st.Proxies[0].EgressChainId = "six"
			},
			want: nodeIP,
		},
		{
			name: "a chain with a proxy member waits for its exit address",
			mutate: func(st *nodev1.NodeState) {
				st.Chains = append(st.Chains, &nodev1.EgressChain{Id: "mixed", MemberEgressIds: []string{"direct", "sock"}})
				st.Proxies[0].EgressChainId = "mixed"
			},
		},
		{
			name: "a direct member tied to an interface goes out through a tunnel",
			mutate: func(st *nodev1.NodeState) {
				st.Chains = append(st.Chains, &nodev1.EgressChain{Id: "tunnel", MemberEgressIds: []string{"wg"}})
				st.Proxies[0].EgressChainId = "tunnel"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			switch tc.nodeIP {
			case "":
				h.r.NodePublicIPv4 = nodeIP
			case "-":
			default:
				h.r.NodePublicIPv4 = tc.nodeIP
			}
			h.fakeEdge(1).setHealth(tc.health...)
			st := h.natState(1)
			if tc.mutate != nil {
				tc.mutate(st)
			}
			h.apply(st)
			h.pass()
			cfg := h.engineConfig(1)
			if tc.want == "" {
				if strings.Contains(cfg, "middle_proxy_nat_ip") {
					t.Errorf("config has a NAT address:\n%s", cfg)
				}
				return
			}
			if !strings.Contains(cfg, natLine(tc.want)) {
				t.Errorf("config lacks %s:\n%s", natLine(tc.want), cfg)
			}
		})
	}
}

// A new exit address rolls the engine (a new generation with the new NAT
// address) once two observations in a row have it, and the NAT address rolls
// an engine once in ten minutes at the most. An exit address that is not known
// for a while does not roll it: the engine keeps the address it has, before
// the node's public address.
func TestExitAddressChangeRollsTheEngine(t *testing.T) {
	h := newHarness(t)
	h.r.NodePublicIPv4 = "203.0.113.77"
	e := h.fakeEdge(1)
	e.setHealth(health("default", "direct", "up", "203.0.113.9"))
	h.apply(h.natState(1))
	h.pass()
	if g := h.generation(); g != 1 || !strings.Contains(h.engineConfig(1), natLine("203.0.113.9")) {
		t.Fatalf("g%d, config:\n%s", g, h.engineConfig(1))
	}

	e.setHealth(health("default", "direct", "up", "203.0.113.10"))
	h.pass()
	if g := h.generation(); g != 1 {
		t.Fatalf("after one observation of the new address: g%d, want g1", g)
	}
	h.pass()
	if g := h.generation(); g != 2 || !strings.Contains(h.engineConfig(2), natLine("203.0.113.10")) {
		t.Fatalf("after two observations: g%d, want g2 with the new address", g)
	}

	// Another address at once: observed twice, but within ten minutes of the
	// last roll for the NAT address.
	e.setHealth(health("default", "direct", "up", "203.0.113.11"))
	h.pass()
	h.pass()
	h.clock.Advance(natRollEvery - time.Second)
	h.pass()
	if g := h.generation(); g != 2 {
		t.Fatalf("within ten minutes of the last roll: g%d, want g2", g)
	}
	h.clock.Advance(time.Second)
	h.pass()
	if g := h.generation(); g != 3 || !strings.Contains(h.engineConfig(3), natLine("203.0.113.11")) {
		t.Fatalf("ten minutes after the last roll: g%d, want g3 with the newest address", g)
	}

	// An address that comes and goes is never observed twice in a row.
	for _, ip := range []string{"203.0.113.12", "203.0.113.11", "203.0.113.12", "203.0.113.11"} {
		h.clock.Advance(natRollEvery)
		e.setHealth(health("default", "direct", "up", ip))
		h.pass()
	}
	if g := h.generation(); g != 3 {
		t.Errorf("an address that comes and goes: g%d, want g3", g)
	}

	// The members go down, or are checked anew: no address is known, and the
	// engine keeps its own, not the node's public address.
	e.setHealth(health("default", "direct", "down", ""), health("default", "eth", "unknown", ""))
	h.clock.Advance(natRollEvery)
	h.pass()
	h.pass()
	if g := h.generation(); g != 3 {
		t.Errorf("without a known exit address: g%d, want g3 still", g)
	}
	if rec := h.runtime().Instances[proxyID]; rec.NatIP != "203.0.113.11" {
		t.Errorf("recorded NAT address = %q", rec.NatIP)
	}

	// A proxy that does not use the middle proxy is not rolled by any of it.
	h2 := newHarness(t)
	h2.fakeEdge(1).setHealth(health("default", "direct", "up", "203.0.113.9"))
	st := h2.natState(1)
	st.Proxies[0].UseMiddleProxy = false
	h2.apply(st)
	h2.pass()
	h2.fakeEdge(1).setHealth(health("default", "direct", "up", "203.0.113.10"))
	h2.pass()
	h2.pass()
	if g := h2.generation(); g != 1 {
		t.Errorf("a proxy without the middle proxy: g%d, want g1", g)
	}
	if bytes.Contains([]byte(h2.engineConfig(1)), []byte("middle_proxy_nat_ip")) {
		t.Error("a proxy without the middle proxy has a NAT address")
	}
}

// The agent tells the transitions of the members from the health the edge
// reports (Ruling 40): a member that goes down or comes back up, and a chain
// whose first usable member changes. The first report is the baseline.
func TestEgressMemberEvents(t *testing.T) {
	h := newHarness(t)
	e := h.fakeEdge(1)
	st := h.natState(1)
	st.Proxies[0].UseMiddleProxy = false
	h.apply(st)

	e.setHealth(health("default", "direct", "up", ""), health("default", "eth", "up", ""))
	h.pass()
	for _, kind := range []string{"egress_member_down", "egress_member_up", "egress_failover"} {
		if n := len(h.eventsOf(kind)); n != 0 {
			t.Fatalf("%d %s events from the first report", n, kind)
		}
	}

	e.setHealth(health("default", "direct", "down", ""), health("default", "eth", "up", ""))
	h.pass()
	down := h.eventsOf("egress_member_down")
	if len(down) != 1 || down[0].GetDetails()["member"] != "direct" || down[0].GetSeverity() != "warning" {
		t.Errorf("egress_member_down events = %v", down)
	}
	fo := h.eventsOf("egress_failover")
	if len(fo) != 1 || fo[0].GetDetails()["chain"] != "default" || fo[0].GetDetails()["from"] != "direct" || fo[0].GetDetails()["to"] != "eth" {
		t.Errorf("egress_failover events = %v", fo)
	}

	h.pass() // the same health: nothing new
	if n := len(h.eventsOf("egress_member_down")) + len(h.eventsOf("egress_failover")); n != 2 {
		t.Errorf("%d events, want still 2", n)
	}

	e.setHealth(health("default", "direct", "down", ""), health("default", "eth", "down", ""))
	h.pass()
	fo = h.eventsOf("egress_failover")
	if len(fo) != 2 || fo[1].GetDetails()["from"] != "eth" || fo[1].GetDetails()["to"] != "" || fo[1].GetSeverity() != "error" {
		t.Errorf("egress_failover events = %v, want one to no member", fo)
	}

	e.setHealth(health("default", "direct", "up", ""), health("default", "eth", "down", ""))
	h.pass()
	up := h.eventsOf("egress_member_up")
	if len(up) != 1 || up[0].GetDetails()["member"] != "direct" {
		t.Errorf("egress_member_up events = %v", up)
	}
	if fo := h.eventsOf("egress_failover"); len(fo) != 3 || fo[2].GetDetails()["to"] != "direct" {
		t.Errorf("egress_failover events = %v", fo)
	}
}

// Two passes that read the same check of the edge are one observation: the
// new exit address rolls the engine at the next check that reports it.
func TestTheSameCheckOfTheEdgeIsOneObservation(t *testing.T) {
	h := newHarness(t)
	e := h.fakeEdge(1)
	at := h.clock.Now().Unix()
	up := func(ip string, checked int64) *edgev1.MemberHealth {
		m := health("default", "direct", "up", ip)
		m.CheckedUnix = checked
		return m
	}
	e.setHealth(up("203.0.113.9", at))
	h.apply(h.natState(1))
	h.pass()
	e.setHealth(up("203.0.113.10", at+30))
	for range 3 {
		h.pass()
	}
	if g := h.generation(); g != 1 {
		t.Fatalf("passes that read one check of the edge: g%d, want g1", g)
	}
	e.setHealth(up("203.0.113.10", at+60))
	h.pass()
	if g := h.generation(); g != 2 || !strings.Contains(h.engineConfig(2), natLine("203.0.113.10")) {
		t.Errorf("the next check: g%d, want g2 with the new address", g)
	}
}

// Damping never holds back a missing NAT address: an engine rendered without
// one takes the exit address as soon as it is known.
func TestAMissingNATAddressIsNotHeldBack(t *testing.T) {
	t.Run("the middle proxy off and on again within ten minutes", func(t *testing.T) {
		h := newHarness(t)
		e := h.fakeEdge(1)
		e.setHealth(health("default", "direct", "up", "203.0.113.9"))
		h.apply(h.natState(1))
		h.pass()
		// A roll from one NAT address to another.
		e.setHealth(health("default", "direct", "up", "203.0.113.10"))
		h.pass()
		h.pass()
		if g := h.generation(); g != 2 || !strings.Contains(h.engineConfig(2), natLine("203.0.113.10")) {
			t.Fatalf("g%d, want g2 with the new address", g)
		}
		off := h.natState(2)
		off.Proxies[0].UseMiddleProxy = false
		h.apply(off)
		h.pass()
		if g := h.generation(); g != 3 || strings.Contains(h.engineConfig(3), "middle_proxy_nat_ip") {
			t.Fatalf("without the middle proxy: g%d, want g3 without a NAT address", g)
		}
		h.clock.Advance(time.Minute)
		h.apply(h.natState(3))
		h.pass()
		if g := h.generation(); g != 4 || !strings.Contains(h.engineConfig(4), natLine("203.0.113.10")) {
			t.Fatalf("the middle proxy on again within ten minutes: g%d, want g4 with the exit address", g)
		}
		// Neither the address going nor coming back counts as a roll from one
		// address to another: ten minutes after g2, a new one rolls the engine.
		h.clock.Advance(natRollEvery - time.Minute)
		e.setHealth(health("default", "direct", "up", "203.0.113.11"))
		h.pass()
		h.pass()
		if g := h.generation(); g != 5 || !strings.Contains(h.engineConfig(5), natLine("203.0.113.11")) {
			t.Errorf("ten minutes after the last roll between two addresses: g%d, want g5 with the new address", g)
		}
	})
	t.Run("the middle proxy turned on while the exit address was seen once", func(t *testing.T) {
		h := newHarness(t)
		m := health("default", "direct", "up", "203.0.113.9")
		m.CheckedUnix = h.clock.Now().Unix()
		h.fakeEdge(1).setHealth(m)
		st := h.natState(1)
		st.Proxies[0].UseMiddleProxy = false
		h.apply(st)
		h.pass()
		h.apply(h.natState(2))
		h.pass() // the same check of the edge: the address is seen once still
		if g := h.generation(); g != 2 || !strings.Contains(h.engineConfig(2), natLine("203.0.113.9")) {
			t.Errorf("g%d, want g2 with the exit address", g)
		}
	})
}
