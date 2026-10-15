package mtg

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/edge/egress"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/links"
)

// update rewrites the golden files in testdata:
//
//	go test ./internal/engines/mtg -run TestRenderGolden -update
//
// Name the package before the flag: go test would take the package for the
// value of an unknown flag that comes first. Read the diff afterwards.
var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// runnerImage is the image every node container runs (Global Constraints).
const runnerImage = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

const (
	testSecret = "00112233445566778899aabbccddeeff" // gitleaks:allow (a fake secret)
	testToken  = "api-token-api-token"
	testAdTag  = "0123456789abcdef0123456789abcdef"
)

func goldenProxy() *nodev1.Proxy {
	return &nodev1.Proxy{
		Id:            "01J9ZZ0000000000000000TEST",
		ListenerId:    "listener-1",
		Type:          nodev1.ProxyType_PROXY_TYPE_FAKETLS,
		Enabled:       true,
		Secret:        testSecret,
		Domain:        "www.example.com",
		Engine:        nodev1.Engine_ENGINE_MTG,
		EngineVersion: "v2.2.8",
	}
}

func goldenInstance() engines.Instance {
	return engines.Instance{
		Proxy:       goldenProxy(),
		InstanceID:  "01J9ZZ0000000000000000TEST-g3",
		Generation:  3,
		ListenPort:  20123,
		APIPort:     25123,
		SocksPort:   30123,
		APIToken:    testToken,
		InstanceDir: "/opt/postern/data/instances/01J9ZZ0000000000000000TEST-g3",
		BinaryPath:  "/opt/postern/data/artifacts/mtg/v2.2.8/amd64/mtg",
		RunnerImage: runnerImage,
		// The proxy has no mask target override: this is an address of its
		// domain, which the agent resolved and checked.
		FrontingAddr: netip.MustParseAddrPort("203.0.113.80:443"),
	}
}

// withMask gives the instance a mask target override, and the fronting address
// the agent passes for it: the override's own address and port.
func withMask(t *testing.T, in *engines.Instance, override string) {
	t.Helper()
	addr, err := ParseMaskTarget(override)
	if err != nil {
		t.Fatalf("ParseMaskTarget(%q): %v", override, err)
	}
	in.Proxy.MaskTargetOverride = override
	in.FrontingAddr = addr
}

func render(t *testing.T, in engines.Instance) string {
	t.Helper()
	files, err := Driver{}.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("Render returned %d files, want only config.toml: %v", len(files), slices.Sorted(maps.Keys(files)))
	}
	content, ok := files["config.toml"]
	if !ok {
		t.Fatalf("Render returned %v, want config.toml", slices.Sorted(maps.Keys(files)))
	}
	return string(content)
}

// ---- golden -------------------------------------------------------------------

func TestRenderGolden(t *testing.T) {
	got := render(t, goldenInstance())
	path := filepath.Join("testdata", "faketls.toml")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("the rendered config differs from %s (run the test with -update to accept a change):\n%s", path, lineDiff(string(want), got))
	}
}

// lineDiff is a small line-by-line diff for failure messages.
func lineDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	for i := 0; i < max(len(w), len(g)); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			fmt.Fprintf(&b, "  line %d:\n    want %q\n    got  %q\n", i+1, wl, gl)
		}
	}
	return b.String()
}

func TestRenderIsDeterministic(t *testing.T) {
	in := goldenInstance()
	withMask(t, &in, "192.0.2.10:8443")
	first := render(t, in)
	for range 5 {
		if again := render(t, in); again != first {
			t.Fatalf("two renders differ:\n%s", lineDiff(first, again))
		}
	}
}

// TestRenderDoesNotTouchItsInput: the reconciler hashes what it renders and keeps
// the instance around, so Render must not change it.
func TestRenderDoesNotTouchItsInput(t *testing.T) {
	in := goldenInstance()
	in.Proxy.MaskTargetOverride = "::ffff:192.0.2.10"
	in.FrontingAddr = netip.MustParseAddrPort("[::ffff:192.0.2.10]:443") // unmapped in the config, not here
	in.Proxy.Domain = "Пример.Example."
	before := fmt.Sprintf("%+v", in)
	proxyBefore := in.Proxy.String()
	render(t, in)
	if after := fmt.Sprintf("%+v", in); after != before {
		t.Errorf("Render changed the instance:\n before %s\n after  %s", before, after)
	}
	if after := in.Proxy.String(); after != proxyBefore {
		t.Errorf("Render changed the proxy:\n before %s\n after  %s", proxyBefore, after)
	}
}

// ---- structure of the config --------------------------------------------------

// baseTables is the config of goldenInstance, table by table ("" is the top
// level, before the first table).
func baseTables() map[string]map[string]any {
	return map[string]map[string]any{
		"": {
			"debug":                        false,
			"secret":                       "ee" + testSecret + "7777772e6578616d706c652e636f6d", // "www.example.com"
			"bind-to":                      "127.0.0.1:20123",
			"proxy-protocol-listener":      true,
			"concurrency":                  8192,
			"prefer-ip":                    "prefer-ipv4",
			"auto-update":                  false,
			"tolerate-time-skewness":       "2m",
			"allow-fallback-on-unknown-dc": false,
		},
		// Always the fronting address of the instance: mtg never resolves or
		// picks its fronting target itself.
		"domain-fronting": {"ip": "203.0.113.80", "port": 443},
		"network": {
			"dns":     "",
			"proxies": []string{"socks5://127.0.0.1:30123"},
		},
		"network.timeout": {"tcp": "5s", "http": "10s", "idle": "5m", "handshake": "10s"},
		// mtg keeps a cache of the session ids it has seen, against replayed
		// handshakes.
		"defense.anti-replay": {"enabled": true},
		// Without this mtg downloads the FireHOL block list at every start (F7).
		"defense.blocklist": {"enabled": false},
		"defense.allowlist": {"enabled": false},
		// No URLs: mtg crawls nothing to learn the timing of a web site.
		"defense.doppelganger": {"urls": []string{}},
		"stats.statsd":         {"enabled": false},
		"stats.prometheus": {
			"enabled":       true,
			"bind-to":       "127.0.0.1:25123",
			"http-path":     "/",
			"metric-prefix": "mtg",
		},
	}
}

func TestRenderFakeTLSStructure(t *testing.T) {
	doc := parseTOML(t, render(t, goldenInstance()))
	want := baseTables()
	if !reflect.DeepEqual(slices.Sorted(maps.Keys(doc.tables)), slices.Sorted(maps.Keys(want))) {
		t.Errorf("tables = %q, want %q", slices.Sorted(maps.Keys(doc.tables)), slices.Sorted(maps.Keys(want)))
	}
	for name, w := range want {
		if got := doc.tables[name]; !reflect.DeepEqual(got, w) {
			t.Errorf("[%s] = %v\nwant %v", name, got, w)
		}
	}
}

// mtgKeys are the keys of mtg v2.2.8's config file, with the kind of value
// each takes: the toml tags of tomlConfig in internal/config/parse.go
// (https://github.com/9seconds/mtg/blob/v2.2.8/internal/config/parse.go). mtg
// decodes the file without DisallowUnknownFields, so a key it does not know is
// dropped without a word: a misspelt proxy-protocol-listener would leave the
// PROXY protocol off and start all the same.
var mtgKeys = map[string]string{
	"debug":                          "bool",
	"allow-fallback-on-unknown-dc":   "bool",
	"secret":                         "string",
	"bind-to":                        "string",
	"proxy-protocol-listener":        "bool",
	"prefer-ip":                      "string",
	"auto-update":                    "bool",
	"domain-fronting-port":           "int",
	"domain-fronting-ip":             "string",
	"domain-fronting-proxy-protocol": "bool",
	"tolerate-time-skewness":         "string",
	"concurrency":                    "int",
	"public-ipv4":                    "string",
	"public-ipv6":                    "string",

	"domain-fronting.ip":             "string",
	"domain-fronting.port":           "int",
	"domain-fronting.proxy-protocol": "bool",

	"defense.anti-replay.enabled":    "bool",
	"defense.anti-replay.max-size":   "string",
	"defense.anti-replay.error-rate": "float",

	"defense.blocklist.enabled":              "bool",
	"defense.blocklist.download-concurrency": "int",
	"defense.blocklist.urls":                 "strings",
	"defense.blocklist.update-each":          "string",

	"defense.allowlist.enabled":              "bool",
	"defense.allowlist.download-concurrency": "int",
	"defense.allowlist.urls":                 "strings",
	"defense.allowlist.update-each":          "string",

	"defense.doppelganger.urls":             "strings",
	"defense.doppelganger.repeats-per-raid": "int",
	"defense.doppelganger.raid-each":        "string",
	"defense.doppelganger.drs":              "bool",

	"network.timeout.tcp":       "string",
	"network.timeout.http":      "string",
	"network.timeout.idle":      "string",
	"network.timeout.handshake": "string",

	"network.keep-alive.disabled": "bool",
	"network.keep-alive.idle":     "string",
	"network.keep-alive.interval": "string",
	"network.keep-alive.count":    "int",

	"network.doh-ip":  "string",
	"network.dns":     "string",
	"network.proxies": "strings",

	"stats.statsd.enabled":       "bool",
	"stats.statsd.address":       "string",
	"stats.statsd.metric-prefix": "string",
	"stats.statsd.tag-format":    "string",

	"stats.prometheus.enabled":       "bool",
	"stats.prometheus.bind-to":       "string",
	"stats.prometheus.http-path":     "string",
	"stats.prometheus.metric-prefix": "string",
}

func kindOf(v any) string {
	switch v.(type) {
	case bool:
		return "bool"
	case int:
		return "int"
	case string:
		return "string"
	case []string:
		return "strings"
	}
	return fmt.Sprintf("%T", v)
}

// TestRenderWritesOnlyKeysMtgReads: every key of the config is one that mtg
// v2.2.8 reads, with a value of the kind it takes.
func TestRenderWritesOnlyKeysMtgReads(t *testing.T) {
	variants := map[string]func(in *engines.Instance){
		"plain":            func(in *engines.Instance) {},
		"mask ip and port": func(in *engines.Instance) { withMask(t, in, "[2001:db8::10]:8443") },
	}
	for name, edit := range variants {
		t.Run(name, func(t *testing.T) {
			in := goldenInstance()
			edit(&in)
			doc := parseTOML(t, render(t, in))
			for table, keys := range doc.tables {
				for key, value := range keys {
					path := key
					if table != "" {
						path = table + "." + key
					}
					kind, ok := mtgKeys[path]
					switch {
					case !ok:
						t.Errorf("%s is not a key of mtg v2.2.8: mtg would ignore it", path)
					case kind != kindOf(value):
						t.Errorf("%s = %v is a %s, mtg v2.2.8 takes a %s", path, value, kindOf(value), kind)
					}
				}
			}
			if len(doc.arrays) != 0 {
				t.Errorf("arrays of tables %v: mtg's config has none", slices.Sorted(maps.Keys(doc.arrays)))
			}
		})
	}
}

// TestRenderSecretIsTheLinkSecret: mtg is given the secret of the proxy's link,
// byte for byte, so a proxy that moves between telemt and mtg keeps its link.
// And mtg reads it the way it has to: its first byte 0xee, then the 16 bytes of
// the proxy secret, then the domain, whose bytes it wants to see as the
// server name of a client.
func TestRenderSecretIsTheLinkSecret(t *testing.T) {
	tests := []struct {
		name, secret, domain string
	}{
		{"ascii", testSecret, "www.example.com"},
		{"upper case domain", testSecret, "WWW.EXAMPLE.COM"},
		{"trailing dot", testSecret, "www.example.com."},
		{"internationalised domain in utf-8", testSecret, "пример.example"},
		{"upper case secret", strings.ToUpper(testSecret), "www.example.com"},
		{"everything at once", strings.ToUpper(testSecret), "Пример.Example."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := goldenInstance()
			in.Proxy.Secret, in.Proxy.Domain = tt.secret, tt.domain
			got := parseTOML(t, render(t, in)).tables[""]["secret"]
			want := links.FakeTLSSecret(tt.secret, tt.domain)
			if got != want {
				t.Fatalf("secret = %v, want the link's %q", got, want)
			}

			// As mtg reads it (mtglib.Secret.Set: hex first, then base64).
			raw, err := hex.DecodeString(got.(string))
			if err != nil {
				t.Fatalf("the secret is not hex: %v", err)
			}
			key, _ := hex.DecodeString(tt.secret)
			switch {
			case len(raw) < 1+16 || raw[0] != 0xee:
				t.Errorf("the secret does not start with 0xee and 16 bytes")
			case !slices.Equal(raw[1:17], key):
				t.Errorf("the key in the secret is not the proxy secret")
			case string(raw[17:]) != tt.domain:
				t.Errorf("the host in the secret is %q, want %q", raw[17:], tt.domain)
			}
		})
	}
}

// ---- the fronting target ------------------------------------------------------

// TestRenderMaskTarget: with a mask target override, the fronting address the
// agent passes is the override's address and port (443 when it names none),
// and the config names exactly that.
func TestRenderMaskTarget(t *testing.T) {
	base := parseTOML(t, render(t, goldenInstance()))
	tests := []struct {
		override string
		want     map[string]any // [domain-fronting]
	}{
		{"192.0.2.10", map[string]any{"ip": "192.0.2.10", "port": 443}},
		{"192.0.2.10:8443", map[string]any{"ip": "192.0.2.10", "port": 8443}},
		{"203.0.113.5:443", map[string]any{"ip": "203.0.113.5", "port": 443}},
		{"2001:db8::10", map[string]any{"ip": "2001:db8::10", "port": 443}},
		{"[2001:db8::10]:8443", map[string]any{"ip": "2001:db8::10", "port": 8443}},
		{"2001:DB8:0::10", map[string]any{"ip": "2001:db8::10", "port": 443}},
		// An IPv4 address in the form of IPv6 is the IPv4 address.
		{"::ffff:192.0.2.10", map[string]any{"ip": "192.0.2.10", "port": 443}},
		{"[::ffff:192.0.2.10]:8443", map[string]any{"ip": "192.0.2.10", "port": 8443}},
	}
	for _, tt := range tests {
		t.Run(strconv.Quote(tt.override), func(t *testing.T) {
			in := goldenInstance()
			withMask(t, &in, tt.override)
			doc := parseTOML(t, render(t, in))
			if got := doc.tables["domain-fronting"]; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("[domain-fronting] = %v, want %v", got, tt.want)
			}
			// Nothing else changes.
			for name, table := range base.tables {
				if name != "domain-fronting" && !reflect.DeepEqual(doc.tables[name], table) {
					t.Errorf("[%s] = %v, want what the base render has: %v", name, doc.tables[name], table)
				}
			}
		})
	}
}

// specialUseMasks are mask targets mtg must not be sent to: the test-only
// special-use addresses of Ruling 24, each with and without a port.
var specialUseMasks = []string{
	"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "::1", "fd00::1",
	"172.16.0.1", "fe80::1", "224.0.0.1", "255.255.255.255", "0.0.0.0", "::",
	"127.0.0.1:443", "10.0.0.1:8443", "[::1]:443", "[fd00::1]:8443", "[fe80::1]:443",
	"::ffff:10.0.0.1", "::ffff:127.0.0.1", "[::ffff:169.254.1.1]:443",
}

// TestRenderRefusesMasksThatAreNotPublic: mtg v2.2.8 connects to its fronting
// target from the node itself, not through its SOCKS proxies, so a mask target
// on the node's loopback or in its networks would reach them from outside.
func TestRenderRefusesMasksThatAreNotPublic(t *testing.T) {
	for _, mask := range specialUseMasks {
		t.Run(mask, func(t *testing.T) {
			in := goldenInstance()
			in.Proxy.MaskTargetOverride = mask
			files, err := Driver{}.Render(in)
			if err == nil {
				t.Fatalf("Render accepted the mask target %s:\n%s", mask, files["config.toml"])
			}
			if !strings.Contains(err.Error(), "not a public address") {
				t.Errorf("error %q does not say that the address is not public", err)
			}
		})
	}
}

// TestRenderMaskPolicyIsTheEdgesPolicy keeps the addresses mtg may front to in
// step with the ones the edge lets an engine connect to through its SOCKS
// ports (egress.DestinationAllowed): an address that the edge refuses for
// telemt's mask connections is refused for mtg's as well, and the other way
// round, whether it is a mask target override or an address of the proxy
// domain.
func TestRenderMaskPolicyIsTheEdgesPolicy(t *testing.T) {
	addrs := []string{
		"192.0.2.10", "198.51.100.7", "203.0.113.5", "2001:db8::10", "149.154.175.50",
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "100.64.0.1",
		"::1", "fd00::1", "fe80::1", "224.0.0.1", "255.255.255.255", "0.0.0.0", "::",
		"::ffff:10.0.0.1", "::ffff:192.0.2.10",
	}
	for _, a := range addrs {
		ip := netip.MustParseAddr(a)
		edge := egress.DestinationAllowed(ip)

		in := goldenInstance()
		in.Proxy.MaskTargetOverride = a
		in.FrontingAddr = netip.AddrPortFrom(ip, 443)
		if _, err := (Driver{}).Render(in); (err == nil) != edge {
			t.Errorf("mask target %s: Render error %v, but the edge's SOCKS ports allow it: %v", a, err, edge)
		}

		in = goldenInstance()
		in.FrontingAddr = netip.AddrPortFrom(ip, 443)
		if _, err := (Driver{}).Render(in); (err == nil) != edge {
			t.Errorf("proxy domain at %s: Render error %v, but the edge's SOCKS ports allow it: %v", a, err, edge)
		}
	}
}

func TestRenderRefusesMaskHostNames(t *testing.T) {
	for _, mask := range []string{"example.com", "example.com:8443", "mask.example.com:443", "localhost", "xn--e1afmkfd.example"} {
		t.Run(mask, func(t *testing.T) {
			in := goldenInstance()
			in.Proxy.MaskTargetOverride = mask
			_, err := Driver{}.Render(in)
			if err == nil || !strings.Contains(err.Error(), "mtg v2.2.8 fronts to an IP address only") {
				t.Errorf("Render = %v, want a refusal that says mtg v2.2.8 fronts to an IP address only", err)
			}
		})
	}
}

// TestRenderAlwaysNamesTheFrontingAddress: whatever the proxy, the config names
// the fronting address, ip and port and nothing else, so mtg never resolves or
// picks its fronting target itself (Ruling S5-10).
func TestRenderAlwaysNamesTheFrontingAddress(t *testing.T) {
	variants := map[string]func(in *engines.Instance){
		"proxy domain":             func(in *engines.Instance) {},
		"proxy domain over ipv6":   func(in *engines.Instance) { in.FrontingAddr = netip.MustParseAddrPort("[2001:db8::80]:443") },
		"mask ipv4":                func(in *engines.Instance) { withMask(t, in, "192.0.2.10") },
		"mask ipv6 with a port":    func(in *engines.Instance) { withMask(t, in, "[2001:db8::10]:8443") },
		"internationalised domain": func(in *engines.Instance) { in.Proxy.Domain = "пример.example" },
	}
	for name, edit := range variants {
		t.Run(name, func(t *testing.T) {
			in := goldenInstance()
			edit(&in)
			got := parseTOML(t, render(t, in)).tables["domain-fronting"]
			want := map[string]any{"ip": in.FrontingAddr.Addr().Unmap().String(), "port": int(in.FrontingAddr.Port())}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("[domain-fronting] = %v, want %v", got, want)
			}
		})
	}
}

// TestRenderNeedsAFrontingAddress: without a fronting address from the agent,
// mtg would resolve the proxy domain itself and connect to whatever the answer
// is, from the node; Render refuses instead.
func TestRenderNeedsAFrontingAddress(t *testing.T) {
	tests := []struct {
		name string
		addr netip.AddrPort
		want string // part of the error
	}{
		{"none", netip.AddrPort{}, "no fronting address"},
		{"a port, no address", netip.AddrPortFrom(netip.Addr{}, 443), "no fronting address"},
		{"no port", netip.AddrPortFrom(netip.MustParseAddr("203.0.113.80"), 0), "has no port"},
		{"ipv6 zone", netip.AddrPortFrom(netip.MustParseAddr("2001:db8::80%eth0"), 443), "zone"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, mask := range []string{"", "192.0.2.10"} {
				in := goldenInstance()
				in.Proxy.MaskTargetOverride = mask
				in.FrontingAddr = tt.addr
				files, err := Driver{}.Render(in)
				if err == nil {
					t.Fatalf("Render accepted the fronting address %v (mask target %q):\n%s", tt.addr, mask, files["config.toml"])
				}
				if files != nil || !strings.Contains(err.Error(), "fronting address") || !strings.Contains(err.Error(), tt.want) {
					t.Errorf("Render = %v, %v; want only an error about the fronting address that says %q", slices.Sorted(maps.Keys(files)), err, tt.want)
				}
			}
		})
	}
}

// TestNonPublicIsTheEdgesPolicy: nonPublic, which both a mask target override
// and the fronting address are held to, is egress.DestinationAllowed, also for
// what is not an address at all.
func TestNonPublicIsTheEdgesPolicy(t *testing.T) {
	addrs := []netip.Addr{{}}
	for _, a := range []string{
		"192.0.2.10", "2001:db8::10", "149.154.175.50", "127.0.0.1", "::1", "10.0.0.1", "fd00::1",
		"169.254.1.1", "fe80::1", "100.64.0.1", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255",
		"0.1.2.3", "::ffff:10.0.0.1", "::ffff:192.0.2.10",
	} {
		addrs = append(addrs, netip.MustParseAddr(a))
	}
	for _, a := range addrs {
		if kind, edge := nonPublic(a), egress.DestinationAllowed(a); (kind == "") != edge {
			t.Errorf("nonPublic(%v) = %q, but the edge allows it: %v", a, kind, edge)
		}
	}
}

// TestRenderRefusesFrontingAddressesThePolicyRefuses: an address of the proxy
// domain that the agent passes is held to the edge's destination policy like a
// mask target override: a domain that resolves to the node's loopback or the
// networks around it does not make mtg connect there.
func TestRenderRefusesFrontingAddressesThePolicyRefuses(t *testing.T) {
	for _, a := range []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.1", "192.168.1.1", "172.16.0.1", "fd00::1", // private
		"169.254.1.1", "fe80::1", // link-local
		"100.64.0.1",                                    // carrier-grade NAT
		"0.0.0.0", "::", "224.0.0.1", "255.255.255.255", // unspecified, multicast, broadcast
		"::ffff:10.0.0.1", // an IPv4 address in the form of IPv6
	} {
		t.Run(a, func(t *testing.T) {
			in := goldenInstance()
			in.FrontingAddr = netip.AddrPortFrom(netip.MustParseAddr(a), 443)
			files, err := Driver{}.Render(in)
			if err == nil {
				t.Fatalf("Render accepted the fronting address %v:\n%s", in.FrontingAddr, files["config.toml"])
			}
			if !strings.Contains(err.Error(), "not a public address") {
				t.Errorf("error %q does not say that the address is not public", err)
			}
		})
	}
}

// TestRenderFrontingAddressFollowsTheOverride: the fronting address is the mask
// target override's when there is one, and an address of the proxy domain on
// port 443 when there is none. Anything else is a mistake of the caller, and
// Render refuses it rather than front somewhere else.
func TestRenderFrontingAddressFollowsTheOverride(t *testing.T) {
	tests := []struct {
		name, mask, addr string
		ok               bool
	}{
		{"the override", "192.0.2.10:8443", "192.0.2.10:8443", true},
		{"the override in the form of ipv6", "192.0.2.10:8443", "[::ffff:192.0.2.10]:8443", true},
		{"the override without a port", "192.0.2.10", "192.0.2.10:443", true},
		{"another port than the override's", "192.0.2.10:8443", "192.0.2.10:443", false},
		{"another address than the override's", "192.0.2.10:8443", "192.0.2.11:8443", false},
		{"an address of the domain despite an override", "192.0.2.10", "203.0.113.80:443", false},
		{"the proxy domain on 443", "", "203.0.113.80:443", true},
		{"the proxy domain on another port", "", "203.0.113.80:8443", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := goldenInstance()
			in.Proxy.MaskTargetOverride = tt.mask
			in.FrontingAddr = netip.MustParseAddrPort(tt.addr)
			_, err := Driver{}.Render(in)
			if (err == nil) != tt.ok {
				t.Errorf("mask target %q, fronting address %s: Render = %v, want ok=%v", tt.mask, tt.addr, err, tt.ok)
			}
			if err != nil && !strings.Contains(err.Error(), "fronting address") {
				t.Errorf("error %q does not name the fronting address", err)
			}
		})
	}
}

// TestParseMaskTarget is the reading of a mask target override that the agent
// uses for the fronting address, and Render checks the address against.
func TestParseMaskTarget(t *testing.T) {
	for s, want := range map[string]string{
		"192.0.2.10":               "192.0.2.10:443",
		"192.0.2.10:8443":          "192.0.2.10:8443",
		"2001:DB8::10":             "[2001:db8::10]:443",
		"[2001:db8::10]:8443":      "[2001:db8::10]:8443",
		"::ffff:192.0.2.10":        "192.0.2.10:443",
		"[::ffff:192.0.2.10]:8443": "192.0.2.10:8443",
	} {
		got, err := ParseMaskTarget(s)
		if err != nil || got.String() != want {
			t.Errorf("ParseMaskTarget(%q) = %v, %v; want %s", s, got, err, want)
		}
	}
	if FrontingPort != 443 {
		t.Errorf("FrontingPort = %d, want 443", FrontingPort)
	}
	// An empty override is not one: the agent resolves the proxy domain then.
	if _, err := ParseMaskTarget(""); err == nil || !strings.Contains(err.Error(), "no mask target") {
		t.Errorf("ParseMaskTarget(\"\") = %v, want an error that says there is no mask target", err)
	}
	for _, s := range append([]string{"", "example.com", "example.com:443", "192.0.2.10:0", "192.0.2.10:x", "fe80::1%eth0", "[2001:db8::10]"}, specialUseMasks...) {
		if got, err := ParseMaskTarget(s); err == nil {
			t.Errorf("ParseMaskTarget(%q) = %v, want an error", s, got)
		}
	}
}

// ---- engine overrides ---------------------------------------------------------

func TestRenderOverrides(t *testing.T) {
	for _, raw := range []string{"", "{}", " {} ", "{ }", "\n{\n}\n", "null"} {
		t.Run("allowed "+strconv.Quote(raw), func(t *testing.T) {
			in := goldenInstance()
			in.Proxy.EngineOverridesJson = raw
			if _, err := (Driver{}).Render(in); err != nil {
				t.Errorf("Render = %v, want success for %q", err, raw)
			}
		})
	}
	for _, raw := range []string{`{"general":{"fast_mode":false}}`, `{"a":1}`, `{"a":null}`, `{"":""}`} {
		t.Run("refused "+strconv.Quote(raw), func(t *testing.T) {
			in := goldenInstance()
			in.Proxy.EngineOverridesJson = raw
			_, err := Driver{}.Render(in)
			if !errors.Is(err, ErrOverridesUnsupported) {
				t.Errorf("Render = %v, want ErrOverridesUnsupported", err)
			}
		})
	}
	// What is not a JSON object is a different error.
	for _, raw := range []string{"[]", `"x"`, "5", "true", "{", `{"a":}`, "garbage", "{} {}"} {
		t.Run("malformed "+strconv.Quote(raw), func(t *testing.T) {
			in := goldenInstance()
			in.Proxy.EngineOverridesJson = raw
			_, err := Driver{}.Render(in)
			if err == nil {
				t.Fatalf("Render accepted %q", raw)
			}
			if errors.Is(err, ErrOverridesUnsupported) {
				t.Errorf("Render = %v: malformed JSON is not the same thing as overrides", err)
			}
		})
	}
}

// ---- refusing what mtg cannot serve -------------------------------------------

func TestRenderRefuses(t *testing.T) {
	tests := []struct {
		name string
		edit func(in *engines.Instance)
		want string // part of the error; "" when any error will do
	}{
		{"nil proxy", func(in *engines.Instance) { in.Proxy = nil }, ""},
		{"web proxy", func(in *engines.Instance) { in.Proxy.Type = nodev1.ProxyType_PROXY_TYPE_WEB }, "fake TLS"},
		{"unspecified type", func(in *engines.Instance) { in.Proxy.Type = nodev1.ProxyType_PROXY_TYPE_UNSPECIFIED }, "fake TLS"},
		{"bound to telemt", func(in *engines.Instance) { in.Proxy.Engine = nodev1.Engine_ENGINE_TELEMT }, "ENGINE_TELEMT"},

		// spec 5.5: mtg has no promo tag and no middle proxy.
		{"ad tag", func(in *engines.Instance) { in.Proxy.AdTag = testAdTag }, "ad tag"},
		{"malformed ad tag", func(in *engines.Instance) { in.Proxy.AdTag = "not a tag" }, "ad tag"},
		{"middle proxy", func(in *engines.Instance) { in.Proxy.UseMiddleProxy = true }, "middle proxy"},
		{"nat ip", func(in *engines.Instance) { in.Proxy.NatIp = "203.0.113.10" }, "NAT"},
		{"nat ip with middle proxy", func(in *engines.Instance) { in.Proxy.UseMiddleProxy = true; in.Proxy.NatIp = "203.0.113.10" }, ""},

		{"empty secret", func(in *engines.Instance) { in.Proxy.Secret = "" }, "32 hex"},
		{"short secret", func(in *engines.Instance) { in.Proxy.Secret = testSecret[:31] }, "32 hex"},
		{"long secret", func(in *engines.Instance) { in.Proxy.Secret = testSecret + "0" }, "32 hex"},
		{"non hex secret", func(in *engines.Instance) { in.Proxy.Secret = strings.Repeat("g", 32) }, "32 hex"},
		{"secret with quote", func(in *engines.Instance) { in.Proxy.Secret = testSecret[:30] + `"x` }, "32 hex"},
		{"secret with ee prefix", func(in *engines.Instance) { in.Proxy.Secret = "ee" + testSecret }, "32 hex"},
		// mtg refuses a key of zeros (mtglib.Secret.Valid) and prints the whole
		// secret while it does.
		{"secret of zeros", func(in *engines.Instance) { in.Proxy.Secret = strings.Repeat("0", 32) }, "zeros"},

		{"empty domain", func(in *engines.Instance) { in.Proxy.Domain = "" }, "domain"},
		{"domain with space", func(in *engines.Instance) { in.Proxy.Domain = "www example.com" }, "domain"},
		{"domain with tab", func(in *engines.Instance) { in.Proxy.Domain = "www\texample.com" }, "domain"},
		{"domain with slash", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com/x" }, "domain"},
		{"domain with backslash", func(in *engines.Instance) { in.Proxy.Domain = `www.example.com\x` }, "domain"},
		{"domain with quote", func(in *engines.Instance) { in.Proxy.Domain = `www.example.com"` }, "domain"},
		{"domain with newline", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\n[evil]" }, "domain"},
		{"domain with nul", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\x00" }, "domain"},
		{"domain with c1 control", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\u0085" }, "domain"},
		{"domain with line separator", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\u2028" }, "domain"},
		{"domain with bidi override", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\u202e" }, "domain"},
		{"domain with bidi isolate", func(in *engines.Instance) { in.Proxy.Domain = "www.\u2066example.com" }, "domain"},
		{"domain with left-to-right mark", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\u200e" }, "domain"},
		{"domain is invalid utf-8", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\xff" }, "domain"},
		{"domain too long", func(in *engines.Instance) { in.Proxy.Domain = strings.Repeat("a", 254) }, "domain"},

		{"mask host name", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "example.com" }, "fronts to an IP address only"},
		{"mask with zone", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "fe80::1%eth0" }, ""},
		{"mask with zone and port", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "[2001:db8::10%eth0]:443" }, ""},
		{"mask port zero", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "192.0.2.10:0" }, "port"},
		{"mask port too big", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "192.0.2.10:65536" }, "port"},
		{"mask port not a number", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "192.0.2.10:https" }, "port"},
		{"mask port signed", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "192.0.2.10:+443" }, "port"},
		{"mask empty port", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "192.0.2.10:" }, "port"},
		{"mask empty host", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = ":443" }, ""},
		{"mask two ports", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "192.0.2.10:1:2" }, ""},
		{"mask bracketed without port", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "[2001:db8::10]" }, ""},
		{"mask url", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "https://192.0.2.10" }, ""},
		{"mask with space", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "192.0.2.10 " }, ""},

		// Ruling S5-10: the agent names the fronting address, and only a public one.
		{"no fronting address", func(in *engines.Instance) { in.FrontingAddr = netip.AddrPort{} }, "fronting address"},
		{"loopback fronting address", func(in *engines.Instance) { in.FrontingAddr = netip.MustParseAddrPort("127.0.0.1:443") }, "not a public address"},
		{"private fronting address", func(in *engines.Instance) { in.FrontingAddr = netip.MustParseAddrPort("[fd00::1]:443") }, "not a public address"},
		{"fronting address not the override's", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "192.0.2.10" }, "fronting address"},

		{"no listen port", func(in *engines.Instance) { in.ListenPort = 0 }, "port"},
		{"no api port", func(in *engines.Instance) { in.APIPort = 0 }, "port"},
		{"no socks port", func(in *engines.Instance) { in.SocksPort = 0 }, "port"},
		{"listen and api share a port", func(in *engines.Instance) { in.APIPort = in.ListenPort }, "port"},
		{"listen and socks share a port", func(in *engines.Instance) { in.SocksPort = in.ListenPort }, "port"},
		{"api and socks share a port", func(in *engines.Instance) { in.SocksPort = in.APIPort }, "port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := goldenInstance()
			tt.edit(&in)
			files, err := Driver{}.Render(in)
			if err == nil {
				t.Fatalf("Render accepted it and produced:\n%s", files["config.toml"])
			}
			if files != nil {
				t.Errorf("Render returned files %v together with an error", slices.Sorted(maps.Keys(files)))
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
			// The error says what is wrong, never what the secrets are.
			for _, secret := range []string{testSecret, strings.ToUpper(testSecret), testAdTag, testToken} {
				if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(secret)) {
					t.Errorf("the error %q contains a secret", err)
				}
			}
		})
	}
}

// TestRenderErrorsNeverHoldSecrets feeds secrets that are wrong in each possible
// way and checks that the offending value is not repeated in the error.
func TestRenderErrorsNeverHoldSecrets(t *testing.T) {
	for _, wrong := range []string{"NOT-HEX-SECRET-VALUE-0123456789", strings.Repeat("0", 32), testSecret + "ff", "ee" + testSecret} {
		in := goldenInstance()
		in.Proxy.Secret = wrong
		if _, err := (Driver{}).Render(in); err == nil || strings.Contains(err.Error(), wrong) {
			t.Errorf("Render = %v: the rejected secret must not be echoed", err)
		}
	}
	in := goldenInstance()
	in.Proxy.AdTag = "NOT-AN-AD-TAG-0123456789"
	if _, err := (Driver{}).Render(in); err == nil || strings.Contains(err.Error(), in.Proxy.AdTag) {
		t.Errorf("Render = %v: the rejected ad tag must not be echoed", err)
	}
}

// TestRenderHostileInputCannotInjectConfig: whatever reaches the file is
// escaped or encoded, and whatever cannot be is refused. The check is
// structural: an accepted config parses and has the tables and keys of the
// base render.
func TestRenderHostileInputCannotInjectConfig(t *testing.T) {
	base := parseTOML(t, render(t, goldenInstance()))
	hostile := []string{
		"x\"\n[network]\nproxies = []\n#",
		"x\\\"; [evil]",
		"a\r\nb",
		"\"\"\"",
		"'''",
		"x # y",
		"192.0.2.10\"\nip = \"10.0.0.1",
		"\u202e",
		"ok\u0000",
	}
	for _, h := range hostile {
		for field, set := range map[string]func(in *engines.Instance){
			"domain":    func(in *engines.Instance) { in.Proxy.Domain = h },
			"mask":      func(in *engines.Instance) { in.Proxy.MaskTargetOverride = h },
			"secret":    func(in *engines.Instance) { in.Proxy.Secret = h },
			"overrides": func(in *engines.Instance) { in.Proxy.EngineOverridesJson = h },
			"token":     func(in *engines.Instance) { in.APIToken = h },
		} {
			in := goldenInstance()
			set(&in)
			files, err := Driver{}.Render(in)
			if err != nil {
				continue // refused: fine
			}
			doc := parseTOML(t, string(files["config.toml"]))
			for name, table := range base.tables {
				if !reflect.DeepEqual(slices.Sorted(maps.Keys(doc.tables[name])), slices.Sorted(maps.Keys(table))) {
					t.Errorf("%s=%q was accepted and changed the shape of [%s]:\n%s", field, h, name, files["config.toml"])
				}
			}
			if len(doc.tables) != len(base.tables) {
				t.Errorf("%s=%q was accepted and changed the tables:\n%s", field, h, files["config.toml"])
			}
		}
	}
}

func TestRenderUsesThePortsOfTheInstance(t *testing.T) {
	in := goldenInstance()
	in.ListenPort, in.APIPort, in.SocksPort = 22001, 27002, 33003
	doc := parseTOML(t, render(t, in))
	if got := doc.tables[""]["bind-to"]; got != "127.0.0.1:22001" {
		t.Errorf("bind-to = %v, want 127.0.0.1:22001", got)
	}
	if got := doc.tables["stats.prometheus"]["bind-to"]; got != "127.0.0.1:27002" {
		t.Errorf("[stats.prometheus] bind-to = %v, want 127.0.0.1:27002", got)
	}
	if got := doc.tables["network"]["proxies"]; !reflect.DeepEqual(got, []string{"socks5://127.0.0.1:33003"}) {
		t.Errorf("proxies = %v, want only socks5://127.0.0.1:33003", got)
	}
}

// mtg's statistics endpoint takes no token: the API token of the instance is
// not written anywhere.
func TestRenderLeavesTheAPITokenOut(t *testing.T) {
	if got := render(t, goldenInstance()); strings.Contains(got, testToken) {
		t.Errorf("the config holds the API token:\n%s", got)
	}
	in := goldenInstance()
	in.APIToken = ""
	render(t, in) // and none is needed
}

// ---- quoting ------------------------------------------------------------------

func TestQuote(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"plain", `"plain"`},
		{"", `""`},
		{`with "quotes"`, `"with \"quotes\""`},
		{`back\slash`, `"back\\slash"`},
		{"tab\there", `"tab\there"`},
		{"line\nbreak", `"line\nbreak"`},
		{"carriage\rreturn", `"carriage\rreturn"`},
		{"nul\x00byte", `"nul\u0000byte"`},
		{"del\x7f", `"del\u007F"`},
		{"unicode пример", `"unicode пример"`},
	}
	for _, tt := range tests {
		t.Run(strconv.Quote(tt.in), func(t *testing.T) {
			got := quote(tt.in)
			if got != tt.want {
				t.Errorf("quote(%q) = %s, want %s", tt.in, got, tt.want)
			}
			back, err := parseString(got)
			if err != nil {
				t.Fatalf("quote(%q) = %s does not read back: %v", tt.in, got, err)
			}
			if back != tt.in {
				t.Errorf("quote(%q) reads back as %q", tt.in, back)
			}
		})
	}
}

// ---- the driver ---------------------------------------------------------------

func TestDriverBasics(t *testing.T) {
	var d engines.Driver = New()
	if got := d.Engine(); got != nodev1.Engine_ENGINE_MTG {
		t.Errorf("Engine = %v, want ENGINE_MTG", got)
	}
	if got := d.BinaryName(); got != "mtg" {
		t.Errorf("BinaryName = %q, want mtg", got)
	}
	for typ, want := range map[nodev1.ProxyType]bool{
		nodev1.ProxyType_PROXY_TYPE_FAKETLS:     true,
		nodev1.ProxyType_PROXY_TYPE_WEB:         false,
		nodev1.ProxyType_PROXY_TYPE_UNSPECIFIED: false,
	} {
		if got := d.Supports(typ); got != want {
			t.Errorf("Supports(%v) = %v, want %v", typ, got, want)
		}
	}
	if _, ok := d.(engines.Trialer); !ok {
		t.Error("the driver is not an engines.Trialer")
	}
	if DefaultVersion != "v2.2.8" {
		t.Errorf("DefaultVersion = %q, want v2.2.8", DefaultVersion)
	}
}

func TestAssetName(t *testing.T) {
	tests := []struct {
		version, arch, want string
	}{
		{"v2.2.8", "amd64", "mtg-2.2.8-linux-amd64.tar.gz"},
		{"v2.2.8", "arm64", "mtg-2.2.8-linux-arm64.tar.gz"},
		{"2.2.8", "amd64", "mtg-2.2.8-linux-amd64.tar.gz"},
		{"v2.3.0-rc.1", "arm64", "mtg-2.3.0-rc.1-linux-arm64.tar.gz"},
		{"v10.20.30+build.5", "amd64", "mtg-10.20.30+build.5-linux-amd64.tar.gz"},
	}
	for _, tt := range tests {
		got, err := AssetName(tt.version, tt.arch)
		if err != nil || got != tt.want {
			t.Errorf("AssetName(%q, %q) = %q, %v; want %q", tt.version, tt.arch, got, err, tt.want)
		}
	}
	for _, arch := range []string{"", "386", "riscv64", "x86_64", "aarch64", "AMD64", "amd64 ", "armv7"} {
		if got, err := AssetName(DefaultVersion, arch); err == nil {
			t.Errorf("AssetName(%q, %q) = %q, want an error", DefaultVersion, arch, got)
		}
	}
	for _, version := range []string{"", "v", "vv2.2.8", "v2.2.8/../x", "../2.2.8", "v2.2.8 ", " v2.2.8", "v.2.2.8", "v2.2.8\n", "v-2.2.8", strings.Repeat("1", 65)} {
		if got, err := AssetName(version, "amd64"); err == nil {
			t.Errorf("AssetName(%q, amd64) = %q, want an error", version, got)
		}
	}
}

func TestArtifactFile(t *testing.T) {
	d := New()
	for _, arch := range []string{"amd64", "arm64"} {
		got, err := d.ArtifactFile(arch)
		want, _ := AssetName(DefaultVersion, arch)
		if err != nil || got != want {
			t.Errorf("ArtifactFile(%q) = %q, %v; want %q", arch, got, err, want)
		}
	}
	for _, arch := range []string{"", "386", "x86_64", "aarch64"} {
		if got, err := d.ArtifactFile(arch); err == nil {
			t.Errorf("ArtifactFile(%q) = %q, want an error", arch, got)
		}
	}
}

// versionOutput is what the release binary of mtg v2.2.8 prints for --version,
// on stdout, before it exits with 0 (seen 2026-10-05; the format is getVersion
// in buildinfo.go: the version that goreleaser sets, without the v, and the
// build information of the Go toolchain).
const versionOutput = "2.2.8 (go1.26.1: 2026-04-07T16:10:41Z on 83a31e04585aa7d9249cf5118a7a418c809ada5f, modules checksum V78O7LjjkrD2eGuOpV9a+l+FQ15TVXK1paxVNMivm6g=)\n" // gitleaks:allow (a public build checksum)

func TestTrial(t *testing.T) {
	for _, version := range []string{"v2.2.8", "2.2.8"} {
		tr := New().Trial(version)
		if !slices.Equal(tr.Args, []string{"--version"}) || tr.ExitCode != 0 || tr.Output == nil {
			t.Fatalf("Trial(%q) = %+v, want --version, exit 0 and an output pattern", version, tr)
		}
		if !tr.Output.MatchString(versionOutput) {
			t.Errorf("Trial(%q) does not accept the output of mtg v2.2.8: %q", version, versionOutput)
		}
		for _, other := range []string{
			"", "dev (go1.26.1: ...)", "2.2.9 (go1.26.1: ...)", "2.2.80 (go1.26.1: ...)", "12.2.8 (go1.26.1: ...)",
			"2.2.8.1 (go...)", "2x2x8 (go...)", "v2.2.8-rc.1 (go...)", "2.2.8-rc.1 (go...)",
			"vv2.2.8 (go...)", "xv2.2.8 (go...)", "v12.2.8 (go...)", "V2.2.8 (go...)",
		} {
			if tr.Output.MatchString(other) {
				t.Errorf("Trial(%q) accepts the output %q of another version", version, other)
			}
		}
	}
	if tr := New().Trial("v2.3.0-rc.1"); !tr.Output.MatchString("2.3.0-rc.1 (go1.27.1: ...)\n") || tr.Output.MatchString("2.3.0 (go1.27.1: ...)\n") {
		t.Errorf("the trial of a release candidate does not tell it from the release")
	}
	// A release that prints its tag rather than the version, as goreleaser does
	// with .Tag: the v in front is not a part of another word.
	for _, out := range []string{"v2.2.9 (go1.27.1: ...)\n", "2.2.9 (go1.27.1: ...)\n", "mtg v2.2.9\n"} {
		if !New().Trial("v2.2.9").Output.MatchString(out) {
			t.Errorf("Trial(\"v2.2.9\") does not accept %q", out)
		}
	}
	// No version, no pass: an empty one would otherwise match anything. A
	// version that is not one (not even valid UTF-8, which regexp refuses to
	// compile) passes nothing either, and does not panic.
	for _, version := range []string{"", "v", "v2.2.8\xff", "\xff", "2.2.8 ", " 2.2.8", "2.2.8/..", "v2.2.8\n", strings.Repeat("1", 65)} {
		t.Run("invalid "+strconv.Quote(version), func(t *testing.T) {
			var tr engines.Trial
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Trial(%q) panics: %v", version, r)
					}
				}()
				tr = New().Trial(version)
			}()
			if tr.Output == nil {
				t.Fatalf("Trial(%q) has no output pattern, which means any output", version)
			}
			for _, out := range []string{"", versionOutput, version, version + " (go1.26.1: ...)"} {
				if tr.Output.MatchString(out) {
					t.Errorf("Trial(%q) passes the output %q", version, out)
				}
			}
		})
	}
}

func TestContainer(t *testing.T) {
	got := New().Container(goldenInstance())
	want := dockerapi.ContainerSpec{
		Name:          "postern-eng-01j9zz0000000000000000test-g3",
		Image:         runnerImage,
		User:          "65534:65534",
		NetworkMode:   "host",
		RestartPolicy: "unless-stopped",
		Entrypoint:    []string{"/opt/engine/mtg", "run", "/etc/mtg/config.toml"},
		Binds: []string{
			"/opt/postern/data/artifacts/mtg/v2.2.8/amd64/mtg:/opt/engine/mtg:ro",
			// mtg keeps nothing on disk: the config is all there is.
			"/opt/postern/data/instances/01J9ZZ0000000000000000TEST-g3:/etc/mtg:ro",
		},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Labels: map[string]string{
			"postern.managed":    "true",
			"postern.role":       "engine",
			"postern.id":         "01J9ZZ0000000000000000TEST",
			"postern.generation": "3",
		},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=16m"},
		ReadOnly:    true,
		MemoryBytes: 256 << 20,
		PidsLimit:   256,
		LogMaxSize:  "5m",
		LogMaxFile:  2,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Container differs:\n%s", specDiff(got, want))
	}
}

func specDiff(got, want dockerapi.ContainerSpec) string {
	var b strings.Builder
	gv, wv := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := range gv.NumField() {
		if !reflect.DeepEqual(gv.Field(i).Interface(), wv.Field(i).Interface()) {
			fmt.Fprintf(&b, "  %s:\n    got  %#v\n    want %#v\n", gv.Type().Field(i).Name, gv.Field(i).Interface(), wv.Field(i).Interface())
		}
	}
	return b.String()
}

func TestContainerNameAndLabels(t *testing.T) {
	tests := []struct {
		name       string
		proxyID    string
		instanceID string
		generation uint64
		wantName   string
		wantID     string
	}{
		{"ulid is lower-cased in the name only", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "x", 1, "postern-eng-01arz3ndektsv4rrffq69g5fav-g1", "01ARZ3NDEKTSV4RRFFQ69G5FAV"},
		{"big generation", "abc", "x", 18446744073709551615, "postern-eng-abc-g18446744073709551615", "abc"},
		{"generation zero", "abc", "x", 0, "postern-eng-abc-g0", "abc"},
		{"falls back to the instance id", "", "inst-1", 7, "postern-eng-inst-1-g7", "inst-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := goldenInstance()
			in.Proxy.Id = tt.proxyID
			in.InstanceID = tt.instanceID
			in.Generation = tt.generation
			spec := New().Container(in)
			if spec.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", spec.Name, tt.wantName)
			}
			if spec.Labels["postern.id"] != tt.wantID {
				t.Errorf("postern.id = %q, want %q", spec.Labels["postern.id"], tt.wantID)
			}
			if got, want := spec.Labels["postern.generation"], strconv.FormatUint(tt.generation, 10); got != want {
				t.Errorf("postern.generation = %q, want %q", got, want)
			}
		})
	}
}

func TestContainerWithoutProxyDoesNotPanic(t *testing.T) {
	in := goldenInstance()
	in.Proxy = nil
	spec := New().Container(in)
	if spec.Name == "" || spec.Image != runnerImage {
		t.Errorf("Container(nil proxy) = %+v", spec)
	}
}

// Every call returns its own slices and maps: the reconciler may adjust a spec
// (for example the restart policy of a draining instance) without touching the
// next one.
func TestContainerSpecsAreIndependent(t *testing.T) {
	in := goldenInstance()
	a := New().Container(in)
	a.Labels["postern.id"] = "changed"
	a.Binds[0] = "changed"
	a.Entrypoint[0] = "changed"
	a.CapDrop[0] = "changed"
	a.SecurityOpt[0] = "changed"
	a.Tmpfs["/tmp"] = "changed"
	b := New().Container(in)
	want := New().Container(goldenInstance())
	if !reflect.DeepEqual(b, want) {
		t.Errorf("a second Container call was affected by changes to the first:\n%s", specDiff(b, want))
	}
}

// ---- Ready --------------------------------------------------------------------

// fakeEngine starts stand-ins for the two ports of an mtg instance on loopback:
// the proxy port, which accepts connections and closes them, and the
// statistics endpoint, served by h. It returns an instance that points at them,
// and a counter of the connections the proxy port took.
func fakeEngine(t *testing.T, h http.HandlerFunc) (engines.Instance, *atomic.Int64) {
	t.Helper()
	in := goldenInstance()

	var accepted atomic.Int64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	in.ListenPort = portOf(t, ln.Addr().String())

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	in.APIPort = portOf(t, u.Host)
	return in, &accepted
}

func portOf(t *testing.T, hostport string) uint16 {
	t.Helper()
	ap, err := netip.ParseAddrPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	if !ap.Addr().IsLoopback() {
		t.Fatalf("%s is not on loopback", hostport)
	}
	return ap.Port()
}

// closedPort returns a loopback port that was just free: nothing listens there.
func closedPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portOf(t, ln.Addr().String())
	_ = ln.Close()
	return port
}

const metricsBody = "# HELP mtg_domain_fronting A number of routings to front domain.\n# TYPE mtg_domain_fronting counter\nmtg_domain_fronting 0\n"

func TestReady(t *testing.T) {
	var gotMethod, gotPath string
	var gotHeaders http.Header
	in, accepted := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotHeaders = r.Method, r.URL.Path, r.Header.Clone()
		_, _ = w.Write([]byte(metricsBody))
	})
	if err := New().Ready(t.Context(), in); err != nil {
		t.Fatalf("Ready = %v, want nil", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/" {
		t.Errorf("request = %s %s, want GET /", gotMethod, gotPath)
	}
	// The kernel completes the connection before the fake's Accept sees it.
	for deadline := time.Now().Add(2 * time.Second); accepted.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if accepted.Load() != 1 {
		t.Errorf("the proxy port took %d connections, want 1", accepted.Load())
	}
	for _, h := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		if gotHeaders.Get(h) != "" {
			t.Errorf("Ready sent %s: %q", h, gotHeaders.Get(h))
		}
	}
}

// The statistics endpoint is up before the proxy port is (mtg opens it first),
// so it alone does not say that mtg is ready.
func TestReadyWantsTheProxyPort(t *testing.T) {
	var hits atomic.Int64
	in, _ := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(metricsBody))
	})
	in.ListenPort = closedPort(t)
	err := New().Ready(t.Context(), in)
	if err == nil || !strings.Contains(err.Error(), "proxy port") {
		t.Fatalf("Ready = %v, want an error about the proxy port", err)
	}
	if hits.Load() != 0 {
		t.Errorf("the statistics endpoint was asked %d times before the proxy port answered", hits.Load())
	}
}

func TestReadyWantsTheStatisticsEndpoint(t *testing.T) {
	in, _ := fakeEngine(t, http.NotFound)
	in.APIPort = closedPort(t)
	if err := New().Ready(t.Context(), in); err == nil {
		t.Fatal("Ready = nil with nothing on the statistics port")
	}
}

func TestReadyNotOK(t *testing.T) {
	for _, status := range []int{201, 204, 301, 401, 403, 404, 500, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			in, _ := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			})
			err := New().Ready(t.Context(), in)
			if err == nil || !strings.Contains(err.Error(), strconv.Itoa(status)) {
				t.Errorf("Ready = %v, want an error that names HTTP %d", err, status)
			}
		})
	}
}

func TestReadyDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int64
	in, _ := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(metricsBody)) // would be ready, were the redirect followed
	})
	if err := New().Ready(t.Context(), in); err == nil {
		t.Error("Ready followed a redirect")
	}
	if hits.Load() != 1 {
		t.Errorf("the server was hit %d times, want 1", hits.Load())
	}
}

// Ready reads at most 1 MiB of the answer: a hostile or broken server cannot
// make it read more, and an answer over the limit is not mtg's.
func TestReadyBodyLimit(t *testing.T) {
	for _, tt := range []struct {
		size int
		ok   bool
	}{{0, true}, {1 << 20, true}, {1<<20 + 1, false}, {10 << 20, false}} {
		t.Run(strconv.Itoa(tt.size), func(t *testing.T) {
			in, _ := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(strings.Repeat("x", tt.size)))
			})
			err := New().Ready(t.Context(), in)
			if (err == nil) != tt.ok {
				t.Errorf("Ready with a %d-byte answer = %v, want ok=%v", tt.size, err, tt.ok)
			}
		})
	}
}

func TestReadyHonoursTheContext(t *testing.T) {
	block := make(chan struct{})
	in, _ := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) { <-block })
	t.Cleanup(func() { close(block) })

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- New().Ready(ctx, in) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Ready = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ready did not return after the context was cancelled")
	}
}

func TestReadyGivesUpOnASilentServer(t *testing.T) {
	old := readyRequestTimeout
	readyRequestTimeout = 150 * time.Millisecond
	t.Cleanup(func() { readyRequestTimeout = old })

	block := make(chan struct{})
	in, _ := fakeEngine(t, func(w http.ResponseWriter, r *http.Request) { <-block })
	t.Cleanup(func() { close(block) })

	start := time.Now()
	err := New().Ready(t.Context(), in) // the context has no deadline of its own
	if err == nil {
		t.Fatal("Ready = nil for a server that never answers")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("Ready took %v, want it to give up after about %v", took, readyRequestTimeout)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Ready = %v, want it to wrap context.DeadlineExceeded", err)
	}
}

func TestReadyPreconditions(t *testing.T) {
	in := goldenInstance()
	in.ListenPort = 0
	if err := New().Ready(t.Context(), in); err == nil {
		t.Error("Ready = nil without a listen port")
	}
	in = goldenInstance()
	in.APIPort = 0
	if err := New().Ready(t.Context(), in); err == nil {
		t.Error("Ready = nil without a statistics port")
	}
}

// ---- a very small TOML reader for the tests -----------------------------------

// tomlDoc is what parseTOML makes of the config: just enough TOML for the file
// Render writes (keys at the top, tables, one-line key = value pairs with
// strings, booleans, integers and arrays of strings). Anything else is a test
// failure, which is the point: it fails when the output gets a shape that a
// stricter reader might not take. The keys before the first table are the
// table "".
type tomlDoc struct {
	tables map[string]map[string]any
	arrays map[string][]map[string]any
}

func parseTOML(t *testing.T, text string) tomlDoc {
	t.Helper()
	if !strings.HasSuffix(text, "\n") {
		t.Fatalf("the config does not end with a newline")
	}
	doc := tomlDoc{tables: map[string]map[string]any{"": {}}, arrays: map[string][]map[string]any{}}
	cur := doc.tables[""]
	for n, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		fail := func(format string, args ...any) {
			t.Helper()
			t.Fatalf("config line %d %q: %s", n+1, line, fmt.Sprintf(format, args...))
		}
		if line != strings.TrimSpace(line) {
			fail("leading or trailing white space")
		}
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "[["):
			name, ok := strings.CutSuffix(strings.TrimPrefix(line, "[["), "]]")
			if !ok || !validTableName(name) {
				fail("bad array of tables header")
			}
			cur = map[string]any{}
			doc.arrays[name] = append(doc.arrays[name], cur)
		case strings.HasPrefix(line, "["):
			name, ok := strings.CutSuffix(strings.TrimPrefix(line, "["), "]")
			if !ok || !validTableName(name) {
				fail("bad table header")
			}
			if _, dup := doc.tables[name]; dup {
				fail("table defined twice")
			}
			cur = map[string]any{}
			doc.tables[name] = cur
		default:
			key, value, ok := strings.Cut(line, " = ")
			if !ok || !validBareKey(key) {
				fail("not a key = value pair")
			}
			if _, dup := cur[key]; dup {
				fail("key defined twice")
			}
			v, err := parseValue(value)
			if err != nil {
				fail("%v", err)
			}
			cur[key] = v
		}
	}
	return doc
}

func validBareKey(k string) bool {
	if k == "" {
		return false
	}
	for _, c := range k {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func validTableName(name string) bool {
	for part := range strings.SplitSeq(name, ".") {
		if !validBareKey(part) {
			return false
		}
	}
	return true
}

func parseValue(s string) (any, error) {
	switch {
	case s == "true":
		return true, nil
	case s == "false":
		return false, nil
	case strings.HasPrefix(s, `"`):
		return parseString(s)
	case strings.HasPrefix(s, "["):
		return parseStringArray(s)
	}
	n, err := strconv.Atoi(s)
	if err != nil || strconv.Itoa(n) != s {
		return nil, fmt.Errorf("unsupported value %s", s)
	}
	return n, nil
}

func parseStringArray(s string) ([]string, error) {
	inner, ok := strings.CutSuffix(strings.TrimPrefix(s, "["), "]")
	if !ok {
		return nil, fmt.Errorf("unterminated array")
	}
	out := []string{}
	for inner != "" {
		if !strings.HasPrefix(inner, `"`) {
			return nil, fmt.Errorf("array element is not a string: %s", inner)
		}
		end, err := stringEnd(inner)
		if err != nil {
			return nil, err
		}
		v, err := parseString(inner[:end])
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		inner = inner[end:]
		if inner == "" {
			break
		}
		rest, ok := strings.CutPrefix(inner, ", ")
		if !ok || rest == "" {
			return nil, fmt.Errorf("bad separator in array")
		}
		inner = rest
	}
	return out, nil
}

// stringEnd returns the index just past the closing quote of the basic string
// that starts s.
func stringEnd(s string) (int, error) {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i + 1, nil
		}
	}
	return 0, fmt.Errorf("unterminated string")
}

// parseString reads one TOML basic string (the whole of s) and returns its value.
func parseString(s string) (string, error) {
	end, err := stringEnd(s)
	if err != nil {
		return "", err
	}
	if end != len(s) {
		return "", fmt.Errorf("garbage after the string: %q", s[end:])
	}
	body := s[1 : len(s)-1]
	if !utf8.ValidString(body) {
		return "", fmt.Errorf("invalid UTF-8")
	}
	var b strings.Builder
	for i := 0; i < len(body); {
		r, size := utf8.DecodeRuneInString(body[i:])
		if r != '\\' {
			// Raw control characters other than tab are not allowed in a basic string.
			if (r < 0x20 && r != '\t') || r == 0x7f {
				return "", fmt.Errorf("raw control character %U", r)
			}
			b.WriteRune(r)
			i += size
			continue
		}
		i++
		if i >= len(body) {
			return "", fmt.Errorf("dangling backslash")
		}
		switch c := body[i]; c {
		case 'b':
			b.WriteByte('\b')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'f':
			b.WriteByte('\f')
		case 'r':
			b.WriteByte('\r')
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		case 'u', 'U':
			digits := 4
			if c == 'U' {
				digits = 8
			}
			if i+1+digits > len(body) {
				return "", fmt.Errorf("short unicode escape")
			}
			v, err := strconv.ParseUint(body[i+1:i+1+digits], 16, 32)
			if err != nil {
				return "", fmt.Errorf("bad unicode escape: %v", err)
			}
			b.WriteRune(rune(v))
			i += digits
		default:
			return "", fmt.Errorf("unknown escape \\%c", c)
		}
		i++
	}
	return b.String(), nil
}
