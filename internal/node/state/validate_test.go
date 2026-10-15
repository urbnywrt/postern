package state

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/edge"
	"github.com/urbnywrt/postern/internal/engines/telemt/overrides"
)

// The longest label of a name, and the longest name, which has labels of 63 bytes
// and one of 61 (253 bytes in all).
var (
	label63 = strings.Repeat("a", 63)
	name253 = label63 + "." + label63 + "." + label63 + "." + strings.Repeat("a", 61)
)

const (
	testSecret  = "00112233445566778899aabbccddeeff" // gitleaks:allow (a fake secret)
	testSecret2 = "ffeeddccbbaa99887766554433221100" // gitleaks:allow (a fake secret)
	testAdTag   = "0123456789abcdef0123456789abcdef"
	// testPassword is an egress credential; it must never show up in an error.
	testPassword = "hunter2-egress-password" // gitleaks:allow (a fake credential)
)

// telemtOnly is the driver table of the node: telemt serves fake TLS and WEB. mtg is
// listed as supporting fake TLS too, so that the tests see the slice rules and
// not a missing driver.
func telemtOnly(e nodev1.Engine, t nodev1.ProxyType) bool {
	switch e {
	case nodev1.Engine_ENGINE_TELEMT, nodev1.Engine_ENGINE_MTG:
		return t == nodev1.ProxyType_PROXY_TYPE_FAKETLS || (e == nodev1.Engine_ENGINE_TELEMT && t == nodev1.ProxyType_PROXY_TYPE_WEB)
	}
	return false
}

// validState passes Validate; every case below breaks one rule of it.
func validState() *nodev1.NodeState {
	return &nodev1.NodeState{
		Generation: 7,
		Settings: &nodev1.NodeSettings{
			DefaultChainId: "default",
			DomainPool:     []string{"pool.example.com"},
			BlacklistCidrs: []string{"192.0.2.0/24", "198.51.100.7", "2001:db8::/32"},
		},
		Listeners: []*nodev1.Listener{
			{Id: "L1", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "0.0.0.0", Port: 443, StrangerAction: nodev1.StrangerAction_STRANGER_ACTION_MASK},
			{Id: "L2", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "203.0.113.10", Port: 8443},
			{Id: "L3", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "203.0.113.11", Port: 8443},
		},
		Proxies: []*nodev1.Proxy{
			{
				Id: "P1", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Enabled: true,
				Secret: testSecret, Domain: "a.example.com",
				Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
			},
			{
				Id: "P2", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS,
				Secret: testSecret2, Domain: "b.example.com",
				Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
				AdTag: testAdTag, UseMiddleProxy: true, NatIp: "203.0.113.50",
				EgressChainId:       "via-socks",
				EgressScopeChains:   map[string]string{"me": "default"},
				EngineOverridesJson: "{}",
			},
			{
				// The same domain on another listener is fine.
				Id: "P3", ListenerId: "L2", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Enabled: true,
				Secret: testSecret, Domain: "a.example.com",
				Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
			},
		},
		Egresses: []*nodev1.Egress{
			{Id: "direct", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT},
			{Id: "eth", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT, ParamsJson: `{"interface":"","bind_ip":"198.51.100.2"}`},
			{Id: "sock", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"198.51.100.9:1080","username":"u","password":"` + testPassword + `"}`},
			{Id: "web", Kind: nodev1.EgressKind_EGRESS_KIND_HTTP, ParamsJson: `{"addr":"proxy.example.com:3128"}`},
		},
		Chains: []*nodev1.EgressChain{
			{Id: "default", MemberEgressIds: []string{"direct"}},
			{
				Id: "via-socks", MemberEgressIds: []string{"sock", "web", "eth"},
				Check: &nodev1.HealthCheck{IntervalSeconds: 30, DcAddrs: []string{"149.154.175.50:443"}},
			},
		},
		Artifacts: []*nodev1.ArtifactRef{{
			Engine: "telemt", Version: "3.5.13", Arch: "amd64",
			Sha256:   "7124a854310d4c91a502aeebfd29f7fc6ddef1dcd44eb0cb72e9f9c176582b43",
			FileName: "telemt-x86_64-linux-musl.tar.gz", Binary: "telemt",
		}},
	}
}

func TestValidateAcceptsValidState(t *testing.T) {
	st := validState()
	before := proto.Clone(st)
	if err := Validate(st, telemtOnly); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !proto.Equal(st, before) {
		t.Error("Validate changed its input")
	}
}

// A direct egress may go out through an interface that Postern did not bring
// up: the edge ties its connections to it (SO_BINDTODEVICE), and the agent
// gives the edge CAP_NET_RAW for it.
func TestValidateAcceptsAnInterfaceEgress(t *testing.T) {
	st := validState()
	for _, e := range st.Egresses {
		if e.Id == "eth" {
			e.ParamsJson = `{"interface":"wg0","bind_ip":"198.51.100.2"}`
		}
	}
	if err := Validate(st, telemtOnly); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// mtg serves a fake-TLS proxy without an ad tag, the middle proxy, a NAT
// address or engine overrides, whatever its mask target override is, as long as
// that is a public IP address, with or without a port.
func TestValidateAcceptsMTGProxies(t *testing.T) {
	for _, mask := range []string{"", "192.0.2.10", "192.0.2.10:8443", "2001:db8::10", "[2001:db8::10]:8443", "::ffff:192.0.2.10"} {
		t.Run("mask "+mask, func(t *testing.T) {
			st := validState()
			for _, p := range st.Proxies {
				if p.Id == "P1" || p.Id == "P3" {
					p.Engine, p.EngineVersion, p.MaskTargetOverride = nodev1.Engine_ENGINE_MTG, "v2.2.8", mask
				}
			}
			if err := Validate(st, telemtOnly); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

// A management SNI that is a plausible domain, not of the pool and not a
// proxy's, is accepted (spec 5.3).
func TestValidateAcceptsAMgmtSNI(t *testing.T) {
	st := validState()
	st.Settings.MgmtSni = "cdn.example.com"
	if err := Validate(st, telemtOnly); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateAcceptsEmptyState(t *testing.T) {
	if err := Validate(&nodev1.NodeState{Generation: 1}, telemtOnly); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejectsNil(t *testing.T) {
	if err := Validate(nil, telemtOnly); err == nil {
		t.Fatal("Validate(nil) = nil, want an error")
	}
}

func TestValidateRules(t *testing.T) {
	proxy := func(st *nodev1.NodeState, id string) *nodev1.Proxy {
		for _, p := range st.Proxies {
			if p.Id == id {
				return p
			}
		}
		t.Fatalf("no proxy %s", id)
		return nil
	}
	egress := func(st *nodev1.NodeState, id string) *nodev1.Egress {
		for _, e := range st.Egresses {
			if e.Id == id {
				return e
			}
		}
		t.Fatalf("no egress %s", id)
		return nil
	}

	cases := []struct {
		name     string
		mutate   func(st *nodev1.NodeState)
		supports func(nodev1.Engine, nodev1.ProxyType) bool
		want     string // a substring of the error
	}{
		// unique and well-formed ids
		{name: "duplicate listener id", want: "duplicate listener id", mutate: func(st *nodev1.NodeState) {
			st.Listeners[2].Id = "L2"
		}},
		{name: "duplicate proxy id, other case", want: "duplicate proxy id", mutate: func(st *nodev1.NodeState) {
			st.Proxies[1].Id = "p1"
		}},
		{name: "duplicate egress id", want: "duplicate egress id", mutate: func(st *nodev1.NodeState) {
			st.Egresses[1].Id = "direct"
		}},
		{name: "duplicate chain id", want: "duplicate chain id", mutate: func(st *nodev1.NodeState) {
			st.Chains[1].Id = "default"
		}},
		{name: "empty listener id", want: "listener id", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].Id = ""
		}},
		{name: "proxy id with a slash", want: "proxy id", mutate: func(st *nodev1.NodeState) {
			st.Proxies[0].Id = "../P1"
		}},
		{name: "egress id too long", want: "egress id", mutate: func(st *nodev1.NodeState) {
			st.Egresses[0].Id = strings.Repeat("e", 65)
			st.Chains[0].MemberEgressIds = []string{strings.Repeat("e", 65)}
		}},

		// listeners
		{name: "port 0", want: "port", mutate: func(st *nodev1.NodeState) {
			st.Listeners[1].Port = 0
		}},
		{name: "port above 65535", want: "port", mutate: func(st *nodev1.NodeState) {
			st.Listeners[1].Port = 65536
		}},
		{name: "wildcard and a specific address on one port", want: "0.0.0.0", mutate: func(st *nodev1.NodeState) {
			st.Listeners[1].Port = 443
		}},
		{name: "two listeners on the same address", want: "same address", mutate: func(st *nodev1.NodeState) {
			st.Listeners[2].BindIp = "203.0.113.10"
		}},
		{name: "two wildcard listeners on one port", want: "same address", mutate: func(st *nodev1.NodeState) {
			st.Listeners = append(st.Listeners, &nodev1.Listener{Id: "L4", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "0.0.0.0", Port: 443})
		}},
		{name: "bind_ip not an address", want: "bind_ip", mutate: func(st *nodev1.NodeState) {
			st.Listeners[1].BindIp = "example.com"
		}},
		{name: "IPv6 listener", want: "IPv6", mutate: func(st *nodev1.NodeState) {
			st.Listeners[1].BindIp = "2001:db8::1"
		}},
		{name: "listener kind not set", want: "kind", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].Kind = nodev1.ListenerKind_LISTENER_KIND_UNSPECIFIED
		}},
		{name: "http-upstream listener on a public address", want: "http-upstream", mutate: func(st *nodev1.NodeState) {
			st.Listeners[2].Kind = nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM
		}},
		// What the edge refuses its whole configuration for (I2).
		{name: "mask target with a bad port", want: "mask target", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].MaskTarget = "mask.example.com:https"
		}},
		{name: "mask target with port 0", want: "mask target", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].MaskTarget = "mask.example.com:0"
		}},
		{name: "mask target that is not a name", want: "mask target", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].MaskTarget = "bad_name.example.com"
		}},
		{name: "mask target with a space", want: "mask target", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].MaskTarget = " mask.example.com"
		}},
		{name: "IPv6 mask target without brackets and with a port", want: "mask target", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].MaskTarget = "[2001:db8::1]"
		}},
		{name: "trusted CIDR with a prefix too long", want: "trusted CIDR", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].TrustedCidrs = []string{"192.0.2.0/24", "192.0.2.0/40"}
		}},
		{name: "trusted CIDR with a zone", want: "trusted CIDR", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].TrustedCidrs = []string{"fe80::1%eth0"}
		}},
		{name: "trusted CIDR that is a name", want: "trusted CIDR", mutate: func(st *nodev1.NodeState) {
			st.Listeners[1].TrustedCidrs = []string{"proxy.example.com"}
		}},
		{name: "stranger action the node does not know", want: "stranger_action", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].StrangerAction = nodev1.StrangerAction(9)
		}},
		{name: "non-TLS action the node does not know", want: "non_tls_action", mutate: func(st *nodev1.NodeState) {
			st.Listeners[1].NonTlsAction = nodev1.NonTlsAction(9)
		}},
		// A mask target on the node's own loopback ports would relay strangers
		// to an engine, its API or a SOCKS port of the edge.
		{name: "mask target on an internal port", want: "internal", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].MaskTarget = "127.0.0.1:30000"
		}},
		{name: "mask target localhost on an internal port", want: "internal", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].MaskTarget = "LocalHost.:25001"
		}},
		{name: "mask target on an internal port of all addresses", want: "internal", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].MaskTarget = "[::]:40000"
		}},
		{name: "mask target on an internal port of a mapped loopback", want: "internal", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].MaskTarget = "[::ffff:127.0.0.1]:20000"
		}},

		// domains
		{name: "domain twice on a listener, other case", want: "already used", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P2").Domain = "A.Example.COM"
		}},
		// The edge folds the dot at the end away, and refuses its whole table for two
		// routes of one name.
		{name: "domain twice on a listener, with a dot at the end", want: "already used", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P2").Domain = "a.example.com."
		}},
		{name: "domain twice on a listener, other case and a dot at the end", want: "already used", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P2").Domain = "A.EXAMPLE.com."
		}},
		{name: "domain twice on a listener, once with a dot at the end", want: "already used", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "b.example.com." // P2 has b.example.com, on the same listener
		}},
		{name: "empty domain", want: "domain", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = ""
		}},
		{name: "domain with a space", want: "not allowed in a name", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a .example.com"
		}},
		// What the edge does not route, and refuses its whole table for. One dot at
		// the end is a name to it (see TestValidateAcceptsTheDomainsTheEdgeRoutes);
		// two are not, nor is a dot alone.
		{name: "domain with two dots at the end", want: "empty label", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a.example.com.."
		}},
		{name: "domain with three dots at the end", want: "empty label", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a.example.com..."
		}},
		{name: "domain that is a dot", want: "empty label", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "."
		}},
		{name: "domain that is two dots", want: "empty label", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = ".."
		}},
		{name: "domain with a dot at the start and one at the end", want: "empty label", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = ".a.example.com."
		}},
		{name: "domain with a bad byte and a dot at the end", want: "not allowed in a name", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a_b.example.com."
		}},
		{name: "domain with a label of 64 bytes and a dot at the end", want: "label longer than 63", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = strings.Repeat("a", 64) + ".example.com."
		}},
		{name: "domain with an underscore", want: "not allowed in a name", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a_b.example.com"
		}},
		{name: "domain that is not ASCII", want: "not allowed in a name", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "пример.example"
		}},
		{name: "domain that is not UTF-8", want: "not allowed in a name", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a.example.com\xff"
		}},
		{name: "domain with a NUL", want: "not allowed in a name", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a\x00.example.com"
		}},
		{name: "domain with a control character", want: "not allowed in a name", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a\r\n.example.com"
		}},
		{name: "domain with a slash", want: "not allowed in a name", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a.example.com/x"
		}},
		{name: "domain with a quote", want: "not allowed in a name", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = `a".example.com`
		}},
		{name: "domain with a port", want: "not allowed in a name", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a.example.com:443"
		}},
		{name: "domain with a bidirectional control", want: "not allowed in a name", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a.example.com\u202e"
		}},
		{name: "domain with an empty label", want: "empty label", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = "a..example.com"
		}},
		{name: "domain with a dot at the start", want: "empty label", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = ".example.com"
		}},
		{name: "domain with a label of 64 bytes", want: "label longer than 63", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = strings.Repeat("a", 64) + ".example.com"
		}},
		{name: "domain of 254 bytes", want: "longer than 253", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = name253 + "a"
		}},
		// The edge counts the dot at the end in the 253 bytes.
		{name: "domain of 253 bytes and a dot at the end", want: "longer than 253", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Domain = name253 + "."
		}},
		{name: "pool domain with two dots at the end", want: "domain pool", mutate: func(st *nodev1.NodeState) {
			st.Settings.DomainPool = []string{"pool.example.com.."}
		}},
		{name: "pool domain with an underscore", want: "domain pool", mutate: func(st *nodev1.NodeState) {
			st.Settings.DomainPool = []string{"pool_1.example.com"}
		}},
		{name: "pool domain that is not ASCII", want: "domain pool", mutate: func(st *nodev1.NodeState) {
			st.Settings.DomainPool = []string{"пример.example"}
		}},

		// secrets and tags
		{name: "secret of 31 hex digits", want: "secret", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Secret = testSecret[:31]
		}},
		{name: "secret of 33 hex digits", want: "secret", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Secret = testSecret + "0"
		}},
		{name: "secret not hex", want: "secret", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Secret = "zz" + testSecret[2:]
		}},
		{name: "ad_tag of the wrong length", want: "ad_tag", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P2").AdTag = testAdTag[:30]
		}},
		{name: "ad_tag not hex", want: "ad_tag", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P2").AdTag = "g" + testAdTag[1:]
		}},

		// references
		{name: "unknown listener", want: "listener", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").ListenerId = "L9"
		}},
		{name: "unknown chain", want: "chain", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P2").EgressChainId = "nope"
		}},
		{name: "unknown scope chain", want: "chain", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P2").EgressScopeChains["fetch"] = "nope"
		}},
		{name: "unknown default chain", want: "default chain", mutate: func(st *nodev1.NodeState) {
			st.Settings.DefaultChainId = "nope"
		}},
		{name: "no chain at all for a proxy", want: "chain", mutate: func(st *nodev1.NodeState) {
			st.Settings.DefaultChainId = ""
		}},
		{name: "unknown chain member", want: "egress", mutate: func(st *nodev1.NodeState) {
			st.Chains[1].MemberEgressIds = append(st.Chains[1].MemberEgressIds, "nope")
		}},
		{name: "chain without members", want: "no members", mutate: func(st *nodev1.NodeState) {
			st.Chains[0].MemberEgressIds = nil
		}},
		{name: "chain member twice", want: "twice", mutate: func(st *nodev1.NodeState) {
			st.Chains[1].MemberEgressIds = []string{"sock", "sock"}
		}},
		{name: "health check DC address without a port", want: "dc_addrs", mutate: func(st *nodev1.NodeState) {
			st.Chains[1].Check.DcAddrs = []string{"149.154.175.50"}
		}},

		// engines and types
		{name: "engine does not support the type", want: "does not support", supports: func(nodev1.Engine, nodev1.ProxyType) bool { return false }},
		{name: "mtg with ad_tag", want: "mtg has no ad_tag support", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P2").Engine = nodev1.Engine_ENGINE_MTG
		}},
		{name: "mtg with the middle proxy", want: "mtg has no middle proxy", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P2").Engine = nodev1.Engine_ENGINE_MTG
		}},
		{name: "mtg with a nat_ip", want: "nat_ip", mutate: func(st *nodev1.NodeState) {
			p := proxy(st, "P1")
			p.Engine, p.NatIp = nodev1.Engine_ENGINE_MTG, "203.0.113.50"
		}},
		{name: "mtg with engine overrides", want: "telemt overrides do not apply to mtg", mutate: func(st *nodev1.NodeState) {
			p := proxy(st, "P1")
			p.Engine, p.EngineOverridesJson = nodev1.Engine_ENGINE_MTG, `{"general":{"max_connections":1}}`
		}},
		{name: "mtg with a web proxy", want: "mtg serves fake TLS only", mutate: func(st *nodev1.NodeState) {
			p := proxy(st, "P1")
			p.Engine, p.Type = nodev1.Engine_ENGINE_MTG, nodev1.ProxyType_PROXY_TYPE_WEB
		}},
		{name: "mtg with a mask name", want: "mtg v2.2.8 fronts to an IP address only", mutate: func(st *nodev1.NodeState) {
			p := proxy(st, "P1")
			p.Engine, p.MaskTargetOverride = nodev1.Engine_ENGINE_MTG, "mask.example.com:443"
		}},
		{name: "mtg with a private mask", want: "not a public address (private)", mutate: func(st *nodev1.NodeState) {
			p := proxy(st, "P1")
			p.Engine, p.MaskTargetOverride = nodev1.Engine_ENGINE_MTG, "10.0.0.5"
		}},
		{name: "mtg with a loopback mask", want: "not a public address (loopback)", mutate: func(st *nodev1.NodeState) {
			p := proxy(st, "P1")
			p.Engine, p.MaskTargetOverride = nodev1.Engine_ENGINE_MTG, "127.0.0.1:8443"
		}},
		{name: "mtg with a link-local mask", want: "not a public address (link-local)", mutate: func(st *nodev1.NodeState) {
			p := proxy(st, "P1")
			p.Engine, p.MaskTargetOverride = nodev1.Engine_ENGINE_MTG, "[fe80::1]:443"
		}},
		{name: "mtg with a CGNAT mask", want: "not a public address (carrier-grade NAT)", mutate: func(st *nodev1.NodeState) {
			p := proxy(st, "P1")
			p.Engine, p.MaskTargetOverride = nodev1.Engine_ENGINE_MTG, "100.64.0.1"
		}},
		{name: "mtg with an unspecified mask", want: "not a public address (unspecified)", mutate: func(st *nodev1.NodeState) {
			p := proxy(st, "P1")
			p.Engine, p.MaskTargetOverride = nodev1.Engine_ENGINE_MTG, "0.0.0.0:443"
		}},
		{name: "mtg with a NAT64 mask of the loopback", want: "not a public address (loopback)", mutate: func(st *nodev1.NodeState) {
			p := proxy(st, "P1")
			p.Engine, p.MaskTargetOverride = nodev1.Engine_ENGINE_MTG, "[64:ff9b::7f00:1]:443"
		}},
		{name: "mtg with a bad mask port", want: "port", mutate: func(st *nodev1.NodeState) {
			p := proxy(st, "P1")
			p.Engine, p.MaskTargetOverride = nodev1.Engine_ENGINE_MTG, "192.0.2.10:70000"
		}},
		{name: "engine not set", want: "engine", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Engine = nodev1.Engine_ENGINE_UNSPECIFIED
		}},
		{name: "web proxy without web settings", want: "web settings", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Type = nodev1.ProxyType_PROXY_TYPE_WEB
		}},
		{name: "proxy type not set", want: "type", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").Type = nodev1.ProxyType_PROXY_TYPE_UNSPECIFIED
		}},
		{name: "engine version not set", want: "engine version", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineVersion = ""
		}},
		{name: "engine version with a slash", want: "engine version", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineVersion = "../3.5.13"
		}},
		{name: "engine override that Postern owns", want: "owned by Postern", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineOverridesJson = `{"log_level":"debug"}`
		}},
		{name: "engine override of the listeners", want: "owned by Postern", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineOverridesJson = `{"listeners":[]}`
		}},
		{name: "engine override that is not supported", want: "not supported", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineOverridesJson = `{"workers":4}`
		}},
		{name: "engine overrides as tables", want: "flat keys", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineOverridesJson = `{"general":{"fast_mode":false}}`
		}},
		{name: "engine override of the wrong type", want: "true or false", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineOverridesJson = `{"fast_mode":"yes"}`
		}},
		{name: "engine override out of its range", want: "integer from 1 to 600", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineOverridesJson = `{"tg_connect":0}`
		}},
		{name: "engine override of a value that is not one of the choices", want: `"sorted_rr"`, mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineOverridesJson = `{"me_writer_pick_mode":"fast"}`
		}},
		{name: "engine override of a directory that climbs", want: "relative", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineOverridesJson = `{"tls_front_dir":"/etc"}`
		}},
		{name: "engine override twice", want: "more than once", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineOverridesJson = `{"fast_mode":true,"fast_mode":false}`
		}},
		{name: "engine overrides not an object", want: "not a JSON object", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineOverridesJson = `[1]`
		}},
		{name: "engine overrides not JSON", want: "not a JSON object", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P1").EngineOverridesJson = `{"fast_mode":`
		}},
		{name: "nat_ip not an address", want: "nat_ip", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P2").NatIp = "nat.example.com"
		}},
		{name: "nat_ip loopback", want: "nat_ip", mutate: func(st *nodev1.NodeState) {
			proxy(st, "P2").NatIp = "127.0.0.1"
		}},

		// egresses
		{name: "xray uri without a uri", want: "uri", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_XRAY_URI, `{}`)
		}},
		{name: "xray uri that is not a share link", want: "uri", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_XRAY_URI, `{"uri":"https://`+testPassword+`@vpn.example.com/"}`)
		}},
		{name: "xray uri with a bad id", want: "uri", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_XRAY_URI, `{"uri":"vless://@vpn.example.com:443?x=`+testPassword+`"}`)
		}},
		{name: "xray uri params not JSON", want: "params", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_XRAY_URI, `{"uri":"vless://`+testUUID+`@vpn.example.com:443?x=`+testPassword)
		}},
		{name: "xray subscription without a url", want: "url", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, `{"select":"all"}`)
		}},
		{name: "xray subscription url of another scheme", want: "url", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, `{"url":"ftp://sub.example.com/`+testPassword+`"}`)
		}},
		{name: "xray subscription url without a host", want: "url", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, `{"url":"https:///`+testPassword+`"}`)
		}},
		{name: "xray subscription url that does not parse", want: "url", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, `{"url":"https://sub.example.com/%zz`+testPassword+`"}`)
		}},
		{name: "xray subscription url with a space", want: "url", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, `{"url":"https://sub.example.com/a b`+testPassword+`"}`)
		}},
		{name: "xray subscription select of no kind", want: "select", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, `{"url":"https://sub.example.com/s","select":"some"}`)
		}},
		{name: "xray subscription select of an empty name", want: "select", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, `{"url":"https://sub.example.com/s","select":"name:"}`)
		}},
		{name: "warp params not an object", want: "params", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_WARP, `[1]`)
		}},
		{name: "psiphon without a country", want: "country", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_PSIPHON, `{}`)
		}},
		{name: "psiphon country Psiphon does not serve", want: "country", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_PSIPHON, `{"country":"XX"}`)
		}},
		{name: "psiphon with one partner id", want: "sponsor_id", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_PSIPHON, `{"country":"DE","propagation_channel_id":"0123456789ABCDEF"}`)
		}},
		{name: "psiphon partner id not hex", want: "propagation_channel_id", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_PSIPHON, `{"country":"DE","propagation_channel_id":"0123456789ABCDEZ","sponsor_id":"0123456789ABCDEF"}`)
		}},
		{name: "psiphon params not JSON", want: "params", mutate: func(st *nodev1.NodeState) {
			kindParams(st, nodev1.EgressKind_EGRESS_KIND_PSIPHON, `{"country":`)
		}},
		{name: "egress kind not set", want: "kind", mutate: func(st *nodev1.NodeState) {
			egress(st, "web").Kind = nodev1.EgressKind_EGRESS_KIND_UNSPECIFIED
		}},
		{name: "socks5 params not JSON", want: "params", mutate: func(st *nodev1.NodeState) {
			egress(st, "sock").ParamsJson = `{"addr":"198.51.100.9:1080","password":"` + testPassword + `"`
		}},
		{name: "socks5 without addr", want: "addr", mutate: func(st *nodev1.NodeState) {
			egress(st, "sock").ParamsJson = `{"username":"u","password":"` + testPassword + `"}`
		}},
		{name: "http addr without port", want: "addr", mutate: func(st *nodev1.NodeState) {
			egress(st, "web").ParamsJson = `{"addr":"proxy.example.com"}`
		}},
		// What the edge's router refuses its whole configuration for (I2).
		{name: "socks5 addr with a slash in the host", want: "addr", mutate: func(st *nodev1.NodeState) {
			egress(st, "sock").ParamsJson = `{"addr":"proxy.example.com/x:1080"}`
		}},
		{name: "socks5 addr with an IPv4 address in brackets", want: "addr", mutate: func(st *nodev1.NodeState) {
			egress(st, "sock").ParamsJson = `{"addr":"[198.51.100.9]:1080"}`
		}},
		{name: "http addr with a signed port", want: "addr", mutate: func(st *nodev1.NodeState) {
			egress(st, "web").ParamsJson = `{"addr":"proxy.example.com:+3128"}`
		}},
		{name: "socks5 username longer than 255 bytes", want: "username", mutate: func(st *nodev1.NodeState) {
			egress(st, "sock").ParamsJson = `{"addr":"198.51.100.9:1080","username":"` + strings.Repeat("u", 256) + `","password":"` + testPassword + `"}`
		}},
		{name: "socks5 password longer than 255 bytes", want: "password", mutate: func(st *nodev1.NodeState) {
			egress(st, "sock").ParamsJson = `{"addr":"198.51.100.9:1080","username":"u","password":"` + testPassword + strings.Repeat("p", 256) + `"}`
		}},
		{name: "http username with a colon", want: "username", mutate: func(st *nodev1.NodeState) {
			egress(st, "web").ParamsJson = `{"addr":"proxy.example.com:3128","username":"a:b","password":"` + testPassword + `"}`
		}},
		{name: "http username longer than 1 KiB", want: "username", mutate: func(st *nodev1.NodeState) {
			egress(st, "web").ParamsJson = `{"addr":"proxy.example.com:3128","username":"` + strings.Repeat("u", 1025) + `","password":"` + testPassword + `"}`
		}},
		{name: "http password longer than 1 KiB", want: "password", mutate: func(st *nodev1.NodeState) {
			egress(st, "web").ParamsJson = `{"addr":"proxy.example.com:3128","username":"u","password":"` + strings.Repeat("p", 1025) + `"}`
		}},
		{name: "health check DC address with a bad host", want: "dc_addrs", mutate: func(st *nodev1.NodeState) {
			st.Chains[1].Check.DcAddrs = []string{"[149.154.175.50]:443"}
		}},
		{name: "direct bind_ip not an address", want: "bind_ip", mutate: func(st *nodev1.NodeState) {
			egress(st, "eth").ParamsJson = `{"interface":"eth1","bind_ip":"nope"}`
		}},
		{name: "direct interface name with a slash", want: "interface", mutate: func(st *nodev1.NodeState) {
			egress(st, "eth").ParamsJson = `{"interface":"../eth1"}`
		}},
		{name: "listener on 0.0.0.0 in the internal port range", want: "internal", mutate: func(st *nodev1.NodeState) {
			st.Listeners[0].Port = 20000
		}},
		{name: "listener on 127.0.0.1 in the internal port range", want: "internal", mutate: func(st *nodev1.NodeState) {
			st.Listeners[1].BindIp, st.Listeners[1].Port = "127.0.0.1", 40999
		}},

		// settings
		{name: "blacklist entry not a CIDR", want: "blacklist", mutate: func(st *nodev1.NodeState) {
			st.Settings.BlacklistCidrs = append(st.Settings.BlacklistCidrs, "192.0.2.0/33")
		}},

		// mgmt_sni (spec 5.3)
		{name: "mgmt_sni collides with a pool domain", want: "mgmt_sni", mutate: func(st *nodev1.NodeState) {
			st.Settings.MgmtSni = "Pool.example.com." // folds to the pool entry
		}},
		{name: "mgmt_sni collides with a proxy domain on a tls listener", want: "mgmt_sni", mutate: func(st *nodev1.NodeState) {
			st.Settings.MgmtSni = "A.example.com" // P1 on tls listener L1 has a.example.com
		}},
		{name: "mgmt_sni is not a host name", want: "mgmt_sni", mutate: func(st *nodev1.NodeState) {
			st.Settings.MgmtSni = "not a host"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := validState()
			if tc.mutate != nil {
				tc.mutate(st)
			}
			supports := telemtOnly
			if tc.supports != nil {
				supports = tc.supports
			}
			err := Validate(st, supports)
			if err == nil {
				t.Fatalf("Validate = nil, want an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate = %q, want it to contain %q", err, tc.want)
			}
			var verr *ValidationError
			if !errors.As(err, &verr) || len(verr.Problems) == 0 {
				t.Errorf("Validate returned %T, want a *ValidationError with problems", err)
			}
			for _, secret := range []string{testSecret, testSecret2, testSecret[:31], testAdTag, testPassword} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the error reveals a secret: %q", err)
				}
			}
		})
	}
}

// everyOverride is a document of every key of the whitelist, each at an end of its
// range: the smallest, or the largest.
func everyOverride(t *testing.T, largest bool) string {
	t.Helper()
	var parts []string
	for _, s := range overrides.Specs() {
		var v string
		switch s.Kind {
		case overrides.Bool:
			v = strconv.FormatBool(largest)
		case overrides.Int:
			v = strconv.FormatInt(map[bool]int64{false: s.Min, true: s.Max}[largest], 10)
		case overrides.Enum:
			v = strconv.Quote(map[bool]string{false: s.Values[0], true: s.Values[len(s.Values)-1]}[largest])
		case overrides.Dir:
			v = strconv.Quote(map[bool]string{false: "a", true: strings.Repeat("a", 128)}[largest])
		default:
			t.Fatalf("%s: a kind that the test does not know", s.Key)
		}
		parts = append(parts, strconv.Quote(s.Key)+":"+v)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// The engine overrides that are on the whitelist, with values in their ranges, are
// what the node takes; the whitelist is the one that the telemt driver renders
// from.
func TestValidateAcceptsEngineOverrides(t *testing.T) {
	for name, raw := range map[string]string{
		"none":                      "",
		"an empty object":           "{}",
		"null":                      "null",
		"one key":                   `{"fast_mode":false}`,
		"tls_emulation":             `{"tls_emulation":false}`,
		"every key at its smallest": everyOverride(t, false),
		"every key at its largest":  everyOverride(t, true),
	} {
		t.Run(name, func(t *testing.T) {
			st := validState()
			proxy := st.Proxies[0]
			proxy.EngineOverridesJson = raw
			if err := Validate(st, telemtOnly); err != nil {
				t.Errorf("Validate = %v, want it to take the overrides", err)
			}
		})
	}
}

// Every problem of the overrides of a proxy is told, each with the proxy and the
// key, and never with a value.
func TestValidateTellsEveryEngineOverrideProblem(t *testing.T) {
	st := validState()
	st.Proxies[1].EngineOverridesJson = `{"workers":"HUNTER2-NOT-FOR-LOGS","tg_connect":0,"log_level":"debug"}`
	err := Validate(st, telemtOnly)
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("Validate = %v, want a *ValidationError", err)
	}
	if len(verr.Problems) != 3 {
		t.Fatalf("problems = %q, want three", verr.Problems)
	}
	for i, key := range []string{"log_level", "tg_connect", "workers"} {
		want := `proxy "P2": engine override ` + strconv.Quote(key) + " "
		if !strings.HasPrefix(verr.Problems[i], want) {
			t.Errorf("problem %d = %q, want it to begin with %q", i, verr.Problems[i], want)
		}
	}
	if strings.Contains(err.Error(), "HUNTER2") {
		t.Errorf("the error repeats a value: %q", err)
	}
}

// The node's internal services listen on 127.0.0.1:20000-40999; a listener on
// 0.0.0.0 or 127.0.0.1 there would collide with them, one on another address
// would not.
func TestValidateInternalPortRange(t *testing.T) {
	for _, tc := range []struct {
		bind string
		port uint32
		ok   bool
	}{
		{"0.0.0.0", 19999, true},
		{"0.0.0.0", 20000, false},
		{"0.0.0.0", 30000, false},
		{"0.0.0.0", 40999, false},
		{"0.0.0.0", 41000, true},
		{"127.0.0.1", 25000, false},
		{"127.0.0.1", 41000, true},
		{"127.0.0.2", 25000, true},
		{"203.0.113.10", 30000, true},
	} {
		st := validState()
		st.Listeners[1].BindIp, st.Listeners[1].Port = tc.bind, tc.port
		st.Listeners[2].Port = 8444 // keep L3 off L2's port
		err := Validate(st, telemtOnly)
		if tc.ok && err != nil {
			t.Errorf("%s:%d: Validate = %v, want nil", tc.bind, tc.port, err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "internal")) {
			t.Errorf("%s:%d: Validate = %v, want an internal range error", tc.bind, tc.port, err)
		}
	}
}

// The values of a listener that the edge takes, the node takes too: mask
// targets with and without a port, as names in any case, with a dot at the end,
// as addresses, on the loopback outside the internal ports (a web server of the
// node itself); trusted CIDRs as prefixes and as
// addresses; every action, and none (the default: mask, drop).
func TestValidateAcceptsTheListenerValuesTheEdgeTakes(t *testing.T) {
	for _, target := range []string{
		"", "mask.example.com", "Mask.Example.COM.:8443", "192.0.2.10", "192.0.2.10:8443",
		"[2001:db8::1]:443", "2001:db8::1", "127.0.0.1:8443", "localhost:443", "127.0.0.1:19999", "127.0.0.1:41000",
	} {
		st := validState()
		st.Listeners[0].MaskTarget = target
		if err := Validate(st, telemtOnly); err != nil {
			t.Errorf("mask target %q: Validate = %v, want nil", target, err)
		}
	}
	st := validState()
	st.Listeners[0].TrustedCidrs = []string{"192.0.2.0/24", "192.0.2.7/24", "198.51.100.7", "2001:db8::/32", "2001:db8::1", "::ffff:192.0.2.0/120", "0.0.0.0/0"}
	if err := Validate(st, telemtOnly); err != nil {
		t.Errorf("trusted CIDRs: Validate = %v, want nil", err)
	}
	for _, a := range []nodev1.StrangerAction{
		nodev1.StrangerAction_STRANGER_ACTION_UNSPECIFIED, nodev1.StrangerAction_STRANGER_ACTION_MASK,
		nodev1.StrangerAction_STRANGER_ACTION_REJECT, nodev1.StrangerAction_STRANGER_ACTION_DROP,
	} {
		for _, n := range []nodev1.NonTlsAction{
			nodev1.NonTlsAction_NON_TLS_ACTION_UNSPECIFIED, nodev1.NonTlsAction_NON_TLS_ACTION_DROP, nodev1.NonTlsAction_NON_TLS_ACTION_HTTP400,
		} {
			st := validState()
			st.Listeners[0].StrangerAction, st.Listeners[0].NonTlsAction = a, n
			if err := Validate(st, telemtOnly); err != nil {
				t.Errorf("actions %v and %v: Validate = %v, want nil", a, n, err)
			}
		}
	}
}

// The parameters of an egress that the edge takes, the node takes too: the
// longest credentials of a socks5 proxy, an http proxy without a password, an
// IPv6 address in brackets.
func TestValidateAcceptsTheEgressParametersTheEdgeTakes(t *testing.T) {
	for kind, params := range map[nodev1.EgressKind][]string{
		nodev1.EgressKind_EGRESS_KIND_SOCKS5: {
			`{"addr":"198.51.100.9:1080"}`,
			`{"addr":"[2001:db8::9]:1080","username":"` + strings.Repeat("u", 255) + `","password":"` + strings.Repeat("p", 255) + `"}`,
			`{"addr":"proxy.example.com:1080","username":"a:b","password":""}`,
		},
		nodev1.EgressKind_EGRESS_KIND_HTTP: {
			`{"addr":"proxy.example.com:3128","username":"user"}`,
			`{"addr":"[2001:db8::9]:3128","username":"` + strings.Repeat("u", 300) + `","password":"` + testPassword + `"}`,
		},
	} {
		for _, p := range params {
			st := validState()
			st.Egresses[3].Kind, st.Egresses[3].ParamsJson = kind, p
			if err := Validate(st, telemtOnly); err != nil {
				t.Errorf("%v %.60s: Validate = %v, want nil", kind, p, err)
			}
		}
	}
}

// A problem of a listener quotes at most 70 bytes of what it is about: the
// reason goes back to the panel and into the log.
func TestValidateQuotesListenerValuesShortly(t *testing.T) {
	long := strings.Repeat("x", 500)
	st := validState()
	st.Listeners[0].MaskTarget = long + "_"
	st.Listeners[0].TrustedCidrs = []string{long}
	err := Validate(st, telemtOnly)
	if err == nil {
		t.Fatal("Validate = nil, want problems")
	}
	if strings.Contains(err.Error(), strings.Repeat("x", 71)) {
		t.Errorf("Validate quotes more than 70 bytes: %.200q...", err)
	}
}

// Every problem is reported, not only the first one.
func TestValidateReportsAllProblems(t *testing.T) {
	st := validState()
	st.Listeners[1].Port = 0
	st.Proxies[0].Secret = "short"
	st.Egresses[3].Kind = nodev1.EgressKind_EGRESS_KIND_PSIPHON
	err := Validate(st, telemtOnly)
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("Validate = %v, want a *ValidationError", err)
	}
	if len(verr.Problems) != 3 {
		t.Errorf("got %d problems, want 3: %q", len(verr.Problems), verr.Problems)
	}
}

// What the edge takes, and the node must therefore take: names in any letter
// case, with digits and hyphens anywhere (the edge does not mind a hyphen at the
// start of a label), a single label, an IP literal, the limits, and one dot at the
// end, which a domain that a proxy keeps with its link may have.
func TestValidateAcceptsTheDomainsTheEdgeRoutes(t *testing.T) {
	for _, d := range []string{
		"a.example.com", "A.Example.COM", "x--y.example", "-a.example", "xn--e1afmkfd.example",
		"203.0.113.5", "localhost", "a", "0", label63 + ".example", name253,
		// One dot at the end: the same name, kept as written.
		"a.example.com.", "A.Example.COM.", "localhost.", "a.", "203.0.113.5.", label63 + ".", name253[:252] + ".",
	} {
		st := validState()
		st.Proxies[0].Domain = d
		st.Settings.DomainPool = []string{d}
		if err := Validate(st, telemtOnly); err != nil {
			t.Errorf("domain %.70q: Validate = %v, want nil", d, err)
		}
	}
}

// A domain with a dot at the end is kept as it is, and is the same name as the one
// without: on one listener two proxies cannot have the two, in whatever letter case
// (see the rules above), and on two listeners they can, as any domain can.
func TestValidateTakesADomainWithADotAtTheEndAsTheNameWithout(t *testing.T) {
	st := validState()
	st.Proxies[0].Domain = "Example.COM." // P1, on L1
	st.Proxies[1].Domain = "other.example.com"
	st.Proxies[2].Domain = "example.com" // P3, on L2: the same name on another listener
	if err := Validate(st, telemtOnly); err != nil {
		t.Fatalf("Validate = %v, want nil: the same name on two listeners is fine", err)
	}
	if got := st.Proxies[0].Domain; got != "Example.COM." {
		t.Errorf("Validate changed the domain to %q", got)
	}
	st.Proxies[1].Domain = "example.com" // P2, on L1 like P1
	err := Validate(st, telemtOnly)
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("Validate = %v, want an error that the domain is already used", err)
	}
}

func TestFoldDomain(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"a.example.com", "a.example.com"},
		{"A.Example.COM", "a.example.com"},
		{"a.example.com.", "a.example.com"},
		{"A.EXAMPLE.com.", "a.example.com"},
		{"a.example.com..", "a.example.com."}, // one dot only, as the edge takes one
		{"", ""},
		{".", ""},
		{"203.0.113.5", "203.0.113.5"},
		// Only ASCII letters fold. strings.ToLower makes a k of the Kelvin sign.
		{"\u212a.example", "\u212a.example"},
		{"\u0130.example", "\u0130.example"},
		{"\u00c9.example", "\u00c9.example"},
		// A byte that is not a letter stays what it is, valid UTF-8 or not.
		{"a\xffB", "a\xffb"},
		{"Z\x00Y", "z\x00y"},
	} {
		if got := FoldDomain(tc.in); got != tc.want {
			t.Errorf("FoldDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Two different names are never one, whatever they hold.
	if FoldDomain("a\xffb") == FoldDomain("a\xfeb") {
		t.Error("two names that differ in an invalid byte fold to one")
	}
	if FoldDomain("\u212a.example") == FoldDomain("k.example") {
		t.Error("the Kelvin sign is folded into a k")
	}
}

// The node takes exactly the domains that the edge takes. The edge refuses its
// whole table, with every proxy of the node in it, for a route or a mask domain
// that it cannot fold, and the domain of every proxy and of the pool is both; a
// domain that the node took and the edge refused would stop the node, and one that
// the node refused and the edge took would be a proxy that cannot be had (a
// domain with a dot at its end, for one). So this goes through every short string
// made of letters, digits, hyphens, dots and what should not be in a name, and
// through the limits, and requires the node and the edge to agree on each: the
// real edge checks a table for it (edge.CheckConfig, which binds nothing).
func TestAcceptedDomainsAreExactlyTheNamesTheEdgeTakes(t *testing.T) {
	apply := func(d string) error {
		return edge.CheckConfig(&edgev1.EdgeConfig{
			Listeners: []*edgev1.EdgeListener{{
				Id: "L1", BindIp: "127.0.0.1", Port: 443, Kind: "http-upstream", StrangerAction: "mask", NonTlsAction: "drop",
			}},
			Routes:      []*edgev1.Route{{ListenerId: "L1", Sni: d, ProxyId: "P1", Kind: "web", Backend: "127.0.0.1:20001"}},
			MaskDomains: []string{d},
		})
	}
	// The oracle works: the edge does refuse names that it cannot take, and takes
	// one dot at the end.
	for _, bad := range []string{"a_b.example", "a..example", ".example", "a.example..", ".", label63 + "\xff", label63 + "a.example", "\xff"} {
		if apply(bad) == nil {
			t.Fatalf("the edge takes %q: this test has no oracle", bad)
		}
	}
	for _, good := range []string{"a.example.", "A.Example.COM.", name253[:252] + "."} {
		if err := apply(good); err != nil {
			t.Fatalf("the edge refuses %q: %v", good, err)
		}
	}

	pieces := []string{"a", "Z", "0", "-", ".", "_", " ", "\x00", "\u00e9", "/", ":", "\u212a", "\xff"}
	candidates := []string{
		label63, label63 + "a", name253, name253 + "a", name253 + ".", name253[:252] + ".", name253[:252] + "..",
		label63 + ".b", "a." + label63, label63 + ".", label63 + "a.",
	}
	var grow func(prefix string, depth int)
	grow = func(prefix string, depth int) {
		if depth == 0 {
			return
		}
		for _, p := range pieces {
			candidates = append(candidates, prefix+p)
			grow(prefix+p, depth-1)
		}
	}
	grow("", 3)

	accepted, withADot := 0, 0
	for _, d := range candidates {
		nodeErr, edgeErr := checkDomain(d), apply(d)
		switch {
		case nodeErr == nil && edgeErr != nil:
			t.Errorf("the node accepts the domain %.70q, but the edge refuses a table with it: %v", d, edgeErr)
		case nodeErr != nil && edgeErr == nil:
			t.Errorf("the node refuses the domain %.70q (%v), but the edge takes it", d, nodeErr)
		}
		if nodeErr == nil {
			accepted++
			if strings.HasSuffix(d, ".") {
				withADot++
			}
		}
	}
	if accepted < 100 || withADot < 10 {
		t.Errorf("the node accepted %d of %d candidates, %d with a dot at the end: the test shows little", accepted, len(candidates), withADot)
	}
}

// artifact_source is "panel" (the default, also when empty) or "direct".
func TestValidateArtifactSource(t *testing.T) {
	for _, tc := range []struct {
		source string
		ok     bool
	}{
		{"", true}, {"panel", true}, {"direct", true},
		{"Direct", false}, {"https", false}, {"panel ", false},
	} {
		st := validState()
		st.Settings.ArtifactSource = tc.source
		err := Validate(st, telemtOnly)
		if tc.ok && err != nil {
			t.Errorf("artifact_source %q: Validate = %v, want nil", tc.source, err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "artifact_source")) {
			t.Errorf("artifact_source %q: Validate = %v, want an error about artifact_source", tc.source, err)
		}
	}
	if got := ArtifactSourceOf(&nodev1.NodeSettings{}); got != ArtifactSourcePanel {
		t.Errorf("ArtifactSourceOf(empty) = %q, want %q", got, ArtifactSourcePanel)
	}
}

// dns_mode is "doh" (the default, also when empty) or "system".
func TestValidateDNSMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		ok   bool
	}{
		{"", true}, {"doh", true}, {"system", true},
		{"DOH", false}, {"udp", false}, {"doh ", false}, {"tcp", false},
	} {
		st := validState()
		st.Settings.DnsMode = tc.mode
		err := Validate(st, telemtOnly)
		if tc.ok && err != nil {
			t.Errorf("dns_mode %q: Validate = %v, want nil", tc.mode, err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "dns_mode")) {
			t.Errorf("dns_mode %q: Validate = %v, want an error about dns_mode", tc.mode, err)
		}
	}
}

// With the forwarder of the node on 127.0.0.2:53, no listener may take that
// address; without it, one may.
func TestValidateKeepsTheForwardersAddressFree(t *testing.T) {
	for _, tc := range []struct {
		mode, bind string
		port       uint32
		ok         bool
	}{
		{"", "127.0.0.2", 53, false},
		{"doh", "127.0.0.2", 53, false},
		{"system", "127.0.0.2", 53, true},
		{"doh", "127.0.0.2", 853, true},
		{"doh", "203.0.113.10", 53, true},
	} {
		st := validState()
		st.Settings.DnsMode = tc.mode
		st.Listeners[1].BindIp, st.Listeners[1].Port = tc.bind, tc.port
		err := Validate(st, telemtOnly)
		if tc.ok && err != nil {
			t.Errorf("%s %s:%d: Validate = %v, want nil", tc.mode, tc.bind, tc.port, err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "DNS forwarder")) {
			t.Errorf("%s %s:%d: Validate = %v, want an error about the DNS forwarder", tc.mode, tc.bind, tc.port, err)
		}
	}
}

func TestDNSModeOf(t *testing.T) {
	for _, tc := range []struct {
		s    *nodev1.NodeSettings
		want string
	}{
		{nil, DNSModeDoH},
		{&nodev1.NodeSettings{}, DNSModeDoH},
		{&nodev1.NodeSettings{DnsMode: "doh"}, DNSModeDoH},
		{&nodev1.NodeSettings{DnsMode: "system"}, DNSModeSystem},
	} {
		if got := DNSModeOf(tc.s); got != tc.want {
			t.Errorf("DNSModeOf(%v) = %q, want %q", tc.s, got, tc.want)
		}
	}
}
