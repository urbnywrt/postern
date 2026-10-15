package state

import (
	"strings"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

const testCertSHA = "7124a854310d4c91a502aeebfd29f7fc6ddef1dcd44eb0cb72e9f9c176582b43"

// webState is validState with an http-upstream listener and three WEB proxies:
// one with an ACME certificate on the shared tls listener, one imported on the
// dedicated listener, one under a base path behind the web server in front.
func webState() *nodev1.NodeState {
	st := validState()
	st.Listeners = append(st.Listeners, &nodev1.Listener{
		Id: "U1", Kind: nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM, BindIp: "127.0.0.1", Port: 18080,
		TrustedCidrs: []string{"127.0.0.1/32", "172.17.0.0/16"},
	})
	st.Proxies = append(st.Proxies,
		&nodev1.Proxy{
			Id: "W1", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_WEB, Enabled: true,
			Secret: testSecret, Domain: "web.example.com", Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
			Web: &nodev1.WebSettings{CertMode: "acme-dns01", DnsCredential: "cf-token", AcmeEmail: "ops@example.com"},
		},
		&nodev1.Proxy{
			Id: "W2", ListenerId: "L2", Type: nodev1.ProxyType_PROXY_TYPE_WEB, Enabled: true,
			Secret: testSecret2, Domain: "Imported.Example.com.", Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
			Web: &nodev1.WebSettings{CertMode: "imported", CertSha256: testCertSHA, SecretMode: "dd", Carrier: "https", Carriers: []string{"https-lanes"}, PublicAddr: "203.0.113.10"},
		},
		&nodev1.Proxy{
			Id: "W3", ListenerId: "U1", Type: nodev1.ProxyType_PROXY_TYPE_WEB, Enabled: true,
			Secret: testSecret, Domain: "site.example.com", Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
			Web: &nodev1.WebSettings{BasePath: "tg/proxy-1"},
		},
	)
	return st
}

func TestValidateAcceptsWebProxies(t *testing.T) {
	if err := Validate(webState(), telemtOnly); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
	st := webState()
	st.Proxies[len(st.Proxies)-3].Web.ReissueNonce = 7 // W1, cert_mode acme-dns01
	if err := Validate(st, telemtOnly); err != nil {
		t.Fatalf("Validate with a reissue nonce on ACME = %v, want nil", err)
	}
}

func TestValidateWebRules(t *testing.T) {
	proxy := func(st *nodev1.NodeState, id string) *nodev1.Proxy {
		for _, p := range st.Proxies {
			if p.Id == id {
				return p
			}
		}
		t.Fatalf("no proxy %s", id)
		return nil
	}
	upstream := func(st *nodev1.NodeState) *nodev1.Listener { return st.Listeners[3] }
	cases := []struct {
		name   string
		mutate func(st *nodev1.NodeState)
		want   string
	}{
		{"no web settings", func(st *nodev1.NodeState) { proxy(st, "W1").Web = nil }, "web settings"},
		{"no cert mode on tls", func(st *nodev1.NodeState) { proxy(st, "W1").Web.CertMode = "" }, "cert_mode"},
		{"unknown cert mode", func(st *nodev1.NodeState) { proxy(st, "W1").Web.CertMode = "tls-alpn-01" }, "cert_mode"},
		{"acme without credential", func(st *nodev1.NodeState) { proxy(st, "W1").Web.DnsCredential = "" }, "dns_credential"},
		{"imported without digest", func(st *nodev1.NodeState) { proxy(st, "W2").Web.CertSha256 = "" }, "cert_sha256"},
		{"imported with a short digest", func(st *nodev1.NodeState) { proxy(st, "W2").Web.CertSha256 = "abc" }, "cert_sha256"},
		{"bad secret mode", func(st *nodev1.NodeState) { proxy(st, "W2").Web.SecretMode = "ee" }, "secret_mode"},
		{"bad carrier", func(st *nodev1.NodeState) { proxy(st, "W2").Web.Carrier = "wss" }, "carrier"},
		{"bad carriers", func(st *nodev1.NodeState) { proxy(st, "W2").Web.Carriers = []string{"https", "https"} }, "carriers"},
		{"bad base path", func(st *nodev1.NodeState) { proxy(st, "W3").Web.BasePath = "/tg/" }, "base_path"},
		{"no base path behind a web server", func(st *nodev1.NodeState) { proxy(st, "W3").Web.BasePath = "" }, "base_path"},
		{"private public_addr", func(st *nodev1.NodeState) { proxy(st, "W2").Web.PublicAddr = "10.0.0.1" }, "public_addr"},
		{"public_addr with another port", func(st *nodev1.NodeState) { proxy(st, "W2").Web.PublicAddr = "203.0.113.10:8443" }, "public_addr"},
		{"single-label domain", func(st *nodev1.NodeState) { proxy(st, "W1").Domain = "intranet" }, "label"},
		{"fake TLS behind a web server", func(st *nodev1.NodeState) { proxy(st, "P1").ListenerId = "U1" }, "http-upstream"},
		{"web proxy without a secret", func(st *nodev1.NodeState) { proxy(st, "W1").Secret = "" }, "secret"},
		{"two web proxies of one domain on a listener", func(st *nodev1.NodeState) { proxy(st, "W1").Domain = "a.example.com" }, "already used"},
		{"reissue of an imported certificate", func(st *nodev1.NodeState) { proxy(st, "W2").Web.ReissueNonce = 1 }, "reissue_nonce"},
		{"reissue behind a web server", func(st *nodev1.NodeState) { proxy(st, "W3").Web.ReissueNonce = 1 }, "reissue_nonce"},

		{"upstream on every interface", func(st *nodev1.NodeState) { upstream(st).BindIp = "0.0.0.0" }, "http-upstream"},
		{"upstream on a public address", func(st *nodev1.NodeState) { upstream(st).BindIp = "203.0.113.12" }, "http-upstream"},
		{"upstream trusting the world", func(st *nodev1.NodeState) { upstream(st).TrustedCidrs = []string{"0.0.0.0/0"} }, "trust"},
		{"upstream trusting nobody", func(st *nodev1.NodeState) { upstream(st).TrustedCidrs = nil }, "trusted_cidrs"},
		{"upstream on an engine port", func(st *nodev1.NodeState) { upstream(st).Port = 20100 }, "internal"},
		{"upstream on a SOCKS port", func(st *nodev1.NodeState) { upstream(st).Port = 35000 }, "internal"},
		{"upstream on a service port (the test listeners)", func(st *nodev1.NodeState) { upstream(st).Port = 40000 }, "internal"},
		{"upstream on the top of the service range", func(st *nodev1.NodeState) { upstream(st).Port = 40999 }, "internal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := webState()
			c.mutate(st)
			err := Validate(st, telemtOnly)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Validate = %v, want %q", err, c.want)
			}
			if err != nil && (strings.Contains(err.Error(), "cf-token") || strings.Contains(err.Error(), testSecret)) {
				t.Error("the error holds a credential")
			}
		})
	}
}

// What an http-upstream listener may take: the loopback or a private address,
// a port outside the node's internal ranges (the service range included: the
// test listeners are allocated there), and
// private trusted prefixes.
func TestValidateUpstreamListenerAccepts(t *testing.T) {
	for _, tc := range []struct {
		bind    string
		port    uint32
		trusted []string
	}{
		{"127.0.0.1", 18080, []string{"127.0.0.1/32"}},
		{"127.0.0.1", 8080, []string{"127.0.0.1"}},
		{"127.0.0.1", 8081, []string{"127.0.0.0/8", "10.0.0.0/8"}},
		{"10.0.0.5", 41000, []string{"192.168.1.0/24"}},
		{"172.17.0.1", 18080, []string{"172.17.0.0/16"}},
	} {
		st := webState()
		st.Listeners[3].BindIp, st.Listeners[3].Port, st.Listeners[3].TrustedCidrs = tc.bind, tc.port, tc.trusted
		if err := Validate(st, telemtOnly); err != nil {
			t.Errorf("%s:%d %v: Validate = %v, want nil", tc.bind, tc.port, tc.trusted, err)
		}
	}
}

// The validator refuses WEB proxies for an engine that does not serve them.
func TestValidateWebNeedsASupportingEngine(t *testing.T) {
	fakeTLSOnly := func(e nodev1.Engine, t nodev1.ProxyType) bool { return t == nodev1.ProxyType_PROXY_TYPE_FAKETLS }
	err := Validate(webState(), fakeTLSOnly)
	if err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Errorf("Validate = %v, want an unsupported type", err)
	}
}
