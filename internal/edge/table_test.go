package edge

import (
	"slices"
	"testing"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"google.golang.org/protobuf/proto"
)

// validConfig uses every feature of the configuration once.
func validConfig(port, testPort uint32) *edgev1.EdgeConfig {
	return &edgev1.EdgeConfig{
		Generation: 1,
		Listeners: []*edgev1.EdgeListener{{
			Id:             "l1",
			BindIp:         "127.0.0.1",
			Port:           port,
			Kind:           "tls",
			StrangerAction: "mask",
			MaskTarget:     "mask.example.com:443",
			NonTlsAction:   "http400",
		}},
		Routes: []*edgev1.Route{
			{ListenerId: "l1", Sni: "a.example.com", ProxyId: "p1", Kind: "engine", Backend: "127.0.0.1:20001",
				ProxyProtocol: true, Limits: &edgev1.EdgeLimits{Devices: 3, ConnsTotal: 10, ConnsPerIp: 2}},
			{ListenerId: "l1", Sni: "mgmt.example.com", Kind: "mgmt", Backend: "127.0.0.1:40001", ProxyProtocol: true},
			{ListenerId: "l1", Sni: "web.example.com", ProxyId: "p2", Kind: "web", Backend: "127.0.0.1:20003"},
		},
		BlacklistCidrs:    []string{"192.0.2.0/24", "2001:db8::1"},
		MaskDomains:       []string{"pool.example.com"},
		DeviceIdleSeconds: 60,
		TestListeners:     []*edgev1.TestListener{{Port: testPort, ListenerId: "l1"}},
		Certs:             []*edgev1.CertRef{{Domain: "web.example.com", Generation: 1}},
		// A probe route of a name that has a route of its own: the new generation
		// of the proxy, which the node probes before the route moves to it.
		ProbeRoutes: []*edgev1.Route{
			{ListenerId: "l1", Sni: "a.example.com", ProxyId: "p1", Kind: "engine", Backend: "127.0.0.1:20002", ProxyProtocol: true},
		},
	}
}

// upstreamListener is an http-upstream listener on port 40999 of bindIP that
// trusts the prefixes trusted.
func upstreamListener(bindIP string, trusted ...string) *edgev1.EdgeListener {
	return &edgev1.EdgeListener{Id: "up", BindIp: bindIP, Port: 40999, Kind: "http-upstream",
		StrangerAction: "drop", NonTlsAction: "drop", TrustedCidrs: trusted}
}

func TestApplyRejectsInvalidConfig(t *testing.T) {
	checkGoroutines(t)
	port, testPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{})
	mustApply(t, e, validConfig(port, testPort))
	bound := e.Bound()

	tests := []struct {
		name   string
		mutate func(c *edgev1.EdgeConfig)
	}{
		{"listener without id", func(c *edgev1.EdgeConfig) { c.Listeners[0].Id = "" }},
		{"listener id twice", func(c *edgev1.EdgeConfig) {
			l := proto.Clone(c.Listeners[0]).(*edgev1.EdgeListener)
			l.Port++
			c.Listeners = append(c.Listeners, l)
		}},
		{"bind address is a name", func(c *edgev1.EdgeConfig) { c.Listeners[0].BindIp = "localhost" }},
		{"no bind address", func(c *edgev1.EdgeConfig) { c.Listeners[0].BindIp = "" }},
		{"port 0", func(c *edgev1.EdgeConfig) { c.Listeners[0].Port = 0 }},
		{"port 65536", func(c *edgev1.EdgeConfig) { c.Listeners[0].Port = 65536 }},
		{"unknown listener kind", func(c *edgev1.EdgeConfig) { c.Listeners[0].Kind = "udp" }},
		{"no listener kind", func(c *edgev1.EdgeConfig) { c.Listeners[0].Kind = "" }},
		{"unknown stranger action", func(c *edgev1.EdgeConfig) { c.Listeners[0].StrangerAction = "ignore" }},
		{"no stranger action", func(c *edgev1.EdgeConfig) { c.Listeners[0].StrangerAction = "" }},
		{"unknown non-TLS action", func(c *edgev1.EdgeConfig) { c.Listeners[0].NonTlsAction = "http500" }},
		{"no non-TLS action", func(c *edgev1.EdgeConfig) { c.Listeners[0].NonTlsAction = "" }},
		{"mask target with a bad port", func(c *edgev1.EdgeConfig) { c.Listeners[0].MaskTarget = "mask.example.com:https" }},
		{"mask target with a bad name", func(c *edgev1.EdgeConfig) { c.Listeners[0].MaskTarget = "bad_name.example.com" }},
		{"bad trusted CIDR", func(c *edgev1.EdgeConfig) { c.Listeners[0].TrustedCidrs = []string{"192.0.2.0/40"} }},
		{"two listeners on one address", func(c *edgev1.EdgeConfig) {
			l := proto.Clone(c.Listeners[0]).(*edgev1.EdgeListener)
			l.Id = "l2"
			c.Listeners = append(c.Listeners, l)
		}},
		{"one address spelled two ways", func(c *edgev1.EdgeConfig) {
			l := proto.Clone(c.Listeners[0]).(*edgev1.EdgeListener)
			l.Id, l.BindIp = "l2", "::ffff:127.0.0.1"
			c.Listeners = append(c.Listeners, l)
		}},
		{"route of an unknown listener", func(c *edgev1.EdgeConfig) { c.Routes[0].ListenerId = "nope" }},
		{"route without server name", func(c *edgev1.EdgeConfig) { c.Routes[0].Sni = "" }},
		{"route with a bad server name", func(c *edgev1.EdgeConfig) { c.Routes[0].Sni = "a_b.example.com" }},
		{"route name with NUL", func(c *edgev1.EdgeConfig) { c.Routes[0].Sni = "a.example.com\x00" }},
		{"route names that differ in case only", func(c *edgev1.EdgeConfig) {
			r := proto.Clone(c.Routes[0]).(*edgev1.Route)
			r.Sni, r.ProxyId = "A.EXAMPLE.com.", "p9"
			c.Routes = append(c.Routes, r)
		}},
		{"unknown route kind", func(c *edgev1.EdgeConfig) { c.Routes[0].Kind = "tcp" }},
		{"no route kind", func(c *edgev1.EdgeConfig) { c.Routes[0].Kind = "" }},
		{"engine route without proxy", func(c *edgev1.EdgeConfig) { c.Routes[0].ProxyId = "" }},
		{"web route without proxy", func(c *edgev1.EdgeConfig) { c.Routes[2].ProxyId = "" }},
		{"engine route without backend", func(c *edgev1.EdgeConfig) { c.Routes[0].Backend = "" }},
		{"mgmt route without backend", func(c *edgev1.EdgeConfig) { c.Routes[1].Backend = "" }},
		{"web route without backend", func(c *edgev1.EdgeConfig) { c.Routes[2].Backend = "" }},
		{"backend is a host name", func(c *edgev1.EdgeConfig) { c.Routes[0].Backend = "localhost:20001" }},
		{"backend without port", func(c *edgev1.EdgeConfig) { c.Routes[0].Backend = "127.0.0.1" }},
		{"backend port 0", func(c *edgev1.EdgeConfig) { c.Routes[0].Backend = "127.0.0.1:0" }},
		{"malformed web backend", func(c *edgev1.EdgeConfig) { c.Routes[2].Backend = "127.0.0.1" }},
		{"blacklist prefix too long", func(c *edgev1.EdgeConfig) { c.BlacklistCidrs = []string{"192.0.2.0/33"} }},
		{"blacklist entry is a name", func(c *edgev1.EdgeConfig) { c.BlacklistCidrs = []string{"example.com"} }},
		{"blacklist entry with a space", func(c *edgev1.EdgeConfig) { c.BlacklistCidrs = []string{"192.0.2.0/24 "} }},
		{"bad mask domain", func(c *edgev1.EdgeConfig) { c.MaskDomains = []string{"bad_domain.example"} }},
		{"empty mask domain", func(c *edgev1.EdgeConfig) { c.MaskDomains = []string{""} }},
		{"test listener of an unknown listener", func(c *edgev1.EdgeConfig) { c.TestListeners[0].ListenerId = "nope" }},
		{"test listener on port 0", func(c *edgev1.EdgeConfig) { c.TestListeners[0].Port = 0 }},
		{"test listener on the address of a listener", func(c *edgev1.EdgeConfig) { c.TestListeners[0].Port = port }},
		{"two test listeners on one port", func(c *edgev1.EdgeConfig) {
			c.TestListeners = append(c.TestListeners, &edgev1.TestListener{Port: testPort, ListenerId: "l1"})
		}},
		{"probe route of an unknown listener", func(c *edgev1.EdgeConfig) { c.ProbeRoutes[0].ListenerId = "nope" }},
		{"probe route with a bad server name", func(c *edgev1.EdgeConfig) { c.ProbeRoutes[0].Sni = "a_b.example.com" }},
		{"probe route without backend", func(c *edgev1.EdgeConfig) { c.ProbeRoutes[0].Backend = "" }},
		{"probe route of an unknown kind", func(c *edgev1.EdgeConfig) { c.ProbeRoutes[0].Kind = "tcp" }},
		{"two probe routes of one name", func(c *edgev1.EdgeConfig) {
			r := proto.Clone(c.ProbeRoutes[0]).(*edgev1.Route)
			r.Sni = "A.example.com."
			c.ProbeRoutes = append(c.ProbeRoutes, r)
		}},
		{"certificate without domain", func(c *edgev1.EdgeConfig) { c.Certs[0].Domain = "" }},
		{"certificate of a bad domain", func(c *edgev1.EdgeConfig) { c.Certs[0].Domain = "a_b.example.com" }},
		{"certificate of a path", func(c *edgev1.EdgeConfig) { c.Certs[0].Domain = "../web.example.com" }},
		{"certificate of a name with a slash", func(c *edgev1.EdgeConfig) { c.Certs[0].Domain = "web.example.com/x" }},
		{"two certificates of one domain", func(c *edgev1.EdgeConfig) {
			c.Certs = append(c.Certs, &edgev1.CertRef{Domain: "WEB.example.com.", Generation: 2})
		}},
		{"http-upstream listener on a public address", func(c *edgev1.EdgeConfig) {
			c.Listeners = append(c.Listeners, upstreamListener("192.0.2.1", "127.0.0.1"))
		}},
		{"http-upstream listener on every address", func(c *edgev1.EdgeConfig) {
			c.Listeners = append(c.Listeners, upstreamListener("0.0.0.0", "127.0.0.1"))
		}},
		{"http-upstream listener that trusts everyone", func(c *edgev1.EdgeConfig) {
			c.Listeners = append(c.Listeners, upstreamListener("127.0.0.1", "127.0.0.1", "0.0.0.0/0"))
		}},
		{"http-upstream listener that trusts a public prefix", func(c *edgev1.EdgeConfig) {
			c.Listeners = append(c.Listeners, upstreamListener("127.0.0.1", "198.51.100.0/24"))
		}},
		{"http-upstream listener that trusts beyond a private range", func(c *edgev1.EdgeConfig) {
			c.Listeners = append(c.Listeners, upstreamListener("10.0.0.1", "172.0.0.0/8"))
		}},
	}
	if err := CheckConfig(validConfig(port, testPort)); err != nil {
		t.Fatalf("CheckConfig refuses the valid configuration: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mustApply(t, e, validConfig(port, testPort)) // in case a case before was taken
			cfg := validConfig(port, testPort)
			cfg.Generation = 2
			tt.mutate(cfg)
			if err := CheckConfig(cfg); err == nil {
				t.Error("CheckConfig accepted the configuration")
			}
			if err := e.Apply(cfg); err == nil {
				t.Fatal("Apply accepted the configuration")
			}
			if g := e.Generation(); g != 1 {
				t.Fatalf("generation %d after a failed Apply, want 1", g)
			}
			if got := e.Bound(); !slices.Equal(got, bound) {
				t.Fatalf("bound %v after a failed Apply, want %v", got, bound)
			}
		})
	}

	t.Run("nil configuration", func(t *testing.T) {
		if err := e.Apply(nil); err == nil {
			t.Fatal("Apply accepted nil")
		}
		if g := e.Generation(); g != 1 {
			t.Fatalf("generation %d after a failed Apply, want 1", g)
		}
	})
}

func TestApplyAcceptsLenientForms(t *testing.T) {
	checkGoroutines(t)
	port, upstreamPort, testPort := freePort(t), freePort(t), freePort(t)
	e := newTestEdge(t, Options{})
	cfg := &edgev1.EdgeConfig{
		Generation: 7,
		Listeners: []*edgev1.EdgeListener{
			// An IPv4-mapped bind address is the IPv4 address. A tls listener
			// does not look at trusted prefixes, whatever they are.
			{Id: "l1", BindIp: "::ffff:127.0.0.1", Port: port, Kind: "tls", StrangerAction: "mask",
				MaskTarget: "Mask.Example.com", NonTlsAction: "drop", TrustedCidrs: []string{"0.0.0.0/0"}},
			{Id: "up", BindIp: "127.0.0.1", Port: upstreamPort, Kind: "http-upstream", StrangerAction: "reject",
				NonTlsAction: "drop", TrustedCidrs: []string{"127.0.0.1", "10.0.0.0/8", "::ffff:192.168.0.0/112", "fd00::/8"}},
		},
		Routes: []*edgev1.Route{
			{ListenerId: "l1", Sni: "Proxy.Example.com.", ProxyId: "p1", Kind: "engine", Backend: "[::ffff:127.0.0.1]:20001"},
			{ListenerId: "l1", Sni: "mgmt.example.com", Kind: "mgmt", Backend: "127.0.0.1:40001", ProxyProtocol: true},
			{ListenerId: "l1", Sni: "web.example.com", ProxyId: "p2", Kind: "web", Backend: "127.0.0.1:20003"},
			{ListenerId: "up", Sni: "web2.example.com", ProxyId: "p3", Kind: "web", Backend: "127.0.0.1:20002"},
			// A route that is not a web route can never be taken on an
			// http-upstream listener, which knows no TLS; it is not a fault.
			{ListenerId: "up", Sni: "proxy2.example.com", ProxyId: "p4", Kind: "engine", Backend: "127.0.0.1:20004"},
		},
		BlacklistCidrs: []string{"192.0.2.7", "::ffff:198.51.100.0/120", "2001:db8::/32"},
		MaskDomains:    []string{"POOL.example.com."},
		// The node's probes speak TLS: an http-upstream listener has no test
		// listener, and one given for it is not bound.
		TestListeners: []*edgev1.TestListener{{Port: testPort, ListenerId: "up"}},
		// A domain is the domain however it is written.
		Certs: []*edgev1.CertRef{{Domain: "Web.Example.com.", Generation: 3}, {Domain: "web2.example.com"}},
	}
	mustApply(t, e, cfg)
	if g := e.Generation(); g != 7 {
		t.Fatalf("generation %d, want 7", g)
	}
	want := slices.Sorted(slices.Values([]string{loopback(port).String(), loopback(upstreamPort).String()}))
	if got := e.Bound(); !slices.Equal(got, want) {
		t.Fatalf("bound %v, want %v: both listeners", got, want)
	}
}
