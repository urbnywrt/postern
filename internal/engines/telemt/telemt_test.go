package telemt

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/telemt/overrides"
)

// update rewrites the golden files in testdata:
//
//	go test ./internal/engines/telemt -run TestRenderGolden -update
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
		Engine:        nodev1.Engine_ENGINE_TELEMT,
		EngineVersion: "3.5.13",
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
		BinaryPath:  "/opt/postern/data/artifacts/telemt/3.5.13/amd64/telemt",
		RunnerImage: runnerImage,
	}
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
	assertGolden(t, "faketls.toml", render(t, goldenInstance()))
}

// assertGolden compares a rendered config with a file of testdata, and rewrites
// the file when the test runs with -update.
func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
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
	for _, raw := range []string{"", allOverrides} {
		in := goldenInstance()
		in.Proxy.EngineOverridesJson = raw
		first := render(t, in)
		for range 5 {
			if again := render(t, in); again != first {
				t.Fatalf("two renders differ:\n%s", lineDiff(first, again))
			}
		}
	}
}

// TestRenderDoesNotTouchItsInput: the reconciler hashes what it renders and keeps
// the instance around, so Render must not change it.
func TestRenderDoesNotTouchItsInput(t *testing.T) {
	in := goldenInstance()
	in.Proxy.AdTag = testAdTag
	in.Proxy.UseMiddleProxy = true
	in.Proxy.EngineOverridesJson = allOverrides
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

func TestRenderFakeTLSStructure(t *testing.T) {
	in := goldenInstance()
	doc := parseTOML(t, render(t, in))

	wantTables := map[string]map[string]any{
		"general": {
			"use_middle_proxy": false,
			"log_level":        "silent",
			"data_path":        "/etc/telemt/data",
		},
		"general.modes": {"classic": false, "secure": false, "tls": true},
		// Without this telemt prints the tg:// link, secret included, at start-up,
		// whatever log_level says; it ends up in the container log.
		"general.links": {"show": []string{}},
		// Without the first key telemt probes its public address with STUN at
		// every start: UDP to 13 public servers, around the SOCKS port, and it
		// holds back its listeners for 5 to 6 s while it does. Without the second
		// it falls back to asking a public lookup service over HTTPS, also around
		// the SOCKS port. The address that matters, the NAT address of the middle
		// proxy, is the agent's to supply.
		"network": {"stun_use": false, "http_ip_detect_urls": []string{}},
		"server":  {"proxy_protocol_trusted_cidrs": []string{"127.0.0.1/32"}},
		"server.api": {
			"enabled":     true,
			"listen":      "127.0.0.1:25123",
			"whitelist":   []string{"127.0.0.1/32"},
			"auth_header": testToken,
		},
		"censorship": {
			"tls_domain":      "www.example.com",
			"mask":            true,
			"tls_emulation":   true,
			"mask_host":       "www.example.com",
			"tls_fetch_scope": "fetch",
		},
		"access.users": {"p": testSecret},
	}
	if len(doc.tables) != len(wantTables) {
		t.Errorf("tables = %v, want %v", slices.Sorted(maps.Keys(doc.tables)), slices.Sorted(maps.Keys(wantTables)))
	}
	for name, want := range wantTables {
		if got := doc.tables[name]; !reflect.DeepEqual(got, want) {
			t.Errorf("[%s] = %v, want %v", name, got, want)
		}
	}

	wantListeners := []map[string]any{{"ip": "127.0.0.1", "port": 20123, "proxy_protocol": true}}
	if got := doc.arrays["server.listeners"]; !reflect.DeepEqual(got, wantListeners) {
		t.Errorf("[[server.listeners]] = %v, want %v", got, wantListeners)
	}

	// Everything leaves through the edge's SOCKS port: two upstreams, no other
	// kind, the second one for the requests telemt tags with a scope.
	wantUpstreams := []map[string]any{
		{"type": "socks5", "address": "127.0.0.1:30123"},
		{"type": "socks5", "address": "127.0.0.1:30123", "scopes": "me, fetch"},
	}
	if got := doc.arrays["upstreams"]; !reflect.DeepEqual(got, wantUpstreams) {
		t.Errorf("[[upstreams]] = %v, want %v", got, wantUpstreams)
	}
	if len(doc.arrays) != 2 {
		t.Errorf("arrays of tables = %v, want only server.listeners and upstreams", slices.Sorted(maps.Keys(doc.arrays)))
	}
}

// TestRenderNeverOpensAnythingButTheTwoLoopbackPorts: every address in the
// config is on 127.0.0.1 and is one of the ports of the instance.
func TestRenderNeverOpensAnythingButTheTwoLoopbackPorts(t *testing.T) {
	in := goldenInstance()
	doc := parseTOML(t, render(t, in))

	if _, ok := doc.tables["server"]["port"]; ok {
		t.Error("[server] port is set: telemt would listen there as well")
	}
	for _, key := range []string{"listen_addr_ipv4", "listen_addr_ipv6", "listen_unix_sock", "metrics_port", "metrics_listen"} {
		if v, ok := doc.tables["server"][key]; ok {
			t.Errorf("[server] %s = %v: a listener nobody asked for", key, v)
		}
	}
	if len(doc.arrays["server.listeners"]) != 1 {
		t.Fatalf("listeners = %v, want exactly one", doc.arrays["server.listeners"])
	}
	if l := doc.arrays["server.listeners"][0]; l["ip"] != "127.0.0.1" {
		t.Errorf("the listener is on %v, want 127.0.0.1", l["ip"])
	}
	if got := doc.tables["server.api"]["listen"]; got != "127.0.0.1:25123" {
		t.Errorf("the API listens on %v, want 127.0.0.1:25123", got)
	}
	for _, u := range doc.arrays["upstreams"] {
		if u["type"] == "direct" {
			t.Error("a direct upstream: all traffic must go through the edge")
		}
	}
}

func TestRenderVariants(t *testing.T) {
	base := goldenInstance()
	baseDoc := parseTOML(t, render(t, base))

	tests := []struct {
		name    string
		edit    func(p *nodev1.Proxy)
		general map[string]any // expected [general]
		censor  map[string]any // expected changes to [censorship]
	}{
		{
			name: "direct mode, no ad tag",
			edit: func(p *nodev1.Proxy) {},
			general: map[string]any{
				"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data",
			},
		},
		{
			name: "middle proxy with ad tag",
			edit: func(p *nodev1.Proxy) { p.UseMiddleProxy = true; p.AdTag = testAdTag },
			general: map[string]any{
				"use_middle_proxy": true, "log_level": "silent", "data_path": "/etc/telemt/data",
				"ad_tag": testAdTag,
			},
		},
		{
			name: "ad tag without middle proxy is still written",
			edit: func(p *nodev1.Proxy) { p.AdTag = testAdTag },
			general: map[string]any{
				"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data",
				"ad_tag": testAdTag,
			},
		},
		{
			name: "upper case ad tag is kept as it is",
			edit: func(p *nodev1.Proxy) { p.UseMiddleProxy = true; p.AdTag = strings.ToUpper(testAdTag) },
			general: map[string]any{
				"use_middle_proxy": true, "log_level": "silent", "data_path": "/etc/telemt/data",
				"ad_tag": strings.ToUpper(testAdTag),
			},
		},
		{
			name: "nat ip with middle proxy turns the probe off",
			edit: func(p *nodev1.Proxy) { p.UseMiddleProxy = true; p.NatIp = "203.0.113.10" },
			general: map[string]any{
				"use_middle_proxy": true, "log_level": "silent", "data_path": "/etc/telemt/data",
				"middle_proxy_nat_ip": "203.0.113.10", "middle_proxy_nat_probe": false,
			},
		},
		{
			name: "nat ip and ad tag",
			edit: func(p *nodev1.Proxy) { p.UseMiddleProxy = true; p.NatIp = "198.51.100.7"; p.AdTag = testAdTag },
			general: map[string]any{
				"use_middle_proxy": true, "log_level": "silent", "data_path": "/etc/telemt/data",
				"ad_tag": testAdTag, "middle_proxy_nat_ip": "198.51.100.7", "middle_proxy_nat_probe": false,
			},
		},
		{
			name: "ipv6 nat ip",
			edit: func(p *nodev1.Proxy) { p.UseMiddleProxy = true; p.NatIp = "2001:db8::10" },
			general: map[string]any{
				"use_middle_proxy": true, "log_level": "silent", "data_path": "/etc/telemt/data",
				"middle_proxy_nat_ip": "2001:db8::10", "middle_proxy_nat_probe": false,
			},
		},
		{
			name: "nat ip is ignored without middle proxy",
			edit: func(p *nodev1.Proxy) { p.UseMiddleProxy = false; p.NatIp = "203.0.113.10" },
			general: map[string]any{
				"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data",
			},
		},
		{
			// With STUN off telemt has no probe to run either: the agent has to
			// supply the NAT address, and without one nothing is written.
			name: "middle proxy without nat ip writes no nat keys",
			edit: func(p *nodev1.Proxy) { p.UseMiddleProxy = true },
			general: map[string]any{
				"use_middle_proxy": true, "log_level": "silent", "data_path": "/etc/telemt/data",
			},
		},
		{
			name: "mask host override",
			edit: func(p *nodev1.Proxy) { p.MaskTargetOverride = "mask.example.com" },
			general: map[string]any{
				"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data",
			},
			censor: map[string]any{"mask_host": "mask.example.com"},
		},
		{
			name: "mask host override with a port",
			edit: func(p *nodev1.Proxy) { p.MaskTargetOverride = "mask.example.com:8443" },
			general: map[string]any{
				"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data",
			},
			censor: map[string]any{"mask_host": "mask.example.com", "mask_port": 8443},
		},
		{
			name: "mask host override that is an ipv4 address",
			edit: func(p *nodev1.Proxy) { p.MaskTargetOverride = "192.0.2.7" },
			general: map[string]any{
				"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data",
			},
			censor: map[string]any{"mask_host": "192.0.2.7"},
		},
		{
			name: "mask host override that is an ipv4 address with a port",
			edit: func(p *nodev1.Proxy) { p.MaskTargetOverride = "192.0.2.7:8443" },
			general: map[string]any{
				"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data",
			},
			censor: map[string]any{"mask_host": "192.0.2.7", "mask_port": 8443},
		},
		{
			name: "mask host override that is an ipv6 address",
			edit: func(p *nodev1.Proxy) { p.MaskTargetOverride = "2001:db8::7" },
			general: map[string]any{
				"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data",
			},
			censor: map[string]any{"mask_host": "2001:db8::7"},
		},
		{
			name: "mask host override that is a bracketed ipv6 address with a port",
			edit: func(p *nodev1.Proxy) { p.MaskTargetOverride = "[2001:db8::7]:8443" },
			general: map[string]any{
				"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data",
			},
			censor: map[string]any{"mask_host": "2001:db8::7", "mask_port": 8443},
		},
		{
			name: "internationalised domain is written as it is",
			edit: func(p *nodev1.Proxy) { p.Domain = "пример.example" },
			general: map[string]any{
				"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data",
			},
			censor: map[string]any{"tls_domain": "пример.example", "mask_host": "пример.example"},
		},
		{
			name: "upper case secret is written as it is",
			edit: func(p *nodev1.Proxy) { p.Secret = strings.ToUpper(testSecret) },
			general: map[string]any{
				"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := goldenInstance()
			tt.edit(in.Proxy)
			doc := parseTOML(t, render(t, in))

			if got := doc.tables["general"]; !reflect.DeepEqual(got, tt.general) {
				t.Errorf("[general] = %v\nwant       %v", got, tt.general)
			}

			// Whatever the variant, everything outside [general] and the changed
			// censorship keys is what the base render has.
			wantCensor := maps.Clone(baseDoc.tables["censorship"])
			for k, v := range tt.censor {
				wantCensor[k] = v
			}
			if got := doc.tables["censorship"]; !reflect.DeepEqual(got, wantCensor) {
				t.Errorf("[censorship] = %v\nwant           %v", got, wantCensor)
			}
			wantUsers := map[string]any{"p": in.Proxy.Secret}
			if got := doc.tables["access.users"]; !reflect.DeepEqual(got, wantUsers) {
				t.Errorf("[access.users] = %v, want %v", got, wantUsers)
			}
			for _, name := range []string{"general.modes", "general.links", "network", "server", "server.api"} {
				if !reflect.DeepEqual(doc.tables[name], baseDoc.tables[name]) {
					t.Errorf("[%s] = %v, want what the base render has: %v", name, doc.tables[name], baseDoc.tables[name])
				}
			}
			for _, name := range []string{"server.listeners", "upstreams"} {
				if !reflect.DeepEqual(doc.arrays[name], baseDoc.arrays[name]) {
					t.Errorf("[[%s]] = %v, want what the base render has: %v", name, doc.arrays[name], baseDoc.arrays[name])
				}
			}
		})
	}
}

func TestRenderUsesThePortsOfTheInstance(t *testing.T) {
	in := goldenInstance()
	in.ListenPort, in.APIPort, in.SocksPort = 22001, 27002, 33003
	doc := parseTOML(t, render(t, in))
	if got := doc.arrays["server.listeners"][0]["port"]; got != 22001 {
		t.Errorf("listener port = %v, want 22001", got)
	}
	if got := doc.tables["server.api"]["listen"]; got != "127.0.0.1:27002" {
		t.Errorf("api listen = %v, want 127.0.0.1:27002", got)
	}
	for i, u := range doc.arrays["upstreams"] {
		if u["address"] != "127.0.0.1:33003" {
			t.Errorf("upstream %d address = %v, want 127.0.0.1:33003", i, u["address"])
		}
	}
}

// TestRenderDisablesAddressDiscovery: whatever the proxy looks like, telemt is
// told neither to probe its public address with STUN nor to look it up over
// HTTP, and nothing else is set in [network]. Both go out directly, around the
// edge's SOCKS port, at every start (the STUN probe also holds the listeners
// back for 5 to 6 s). The NAT address of the middle proxy is the agent's to
// supply (middle_proxy_nat_ip), not telemt's to find out.
//
// http_ip_detect_urls is the key of [network], not of [general]: telemt takes
// the empty list as "do not look".
func TestRenderDisablesAddressDiscovery(t *testing.T) {
	variants := map[string]func(p *nodev1.Proxy){
		"direct mode":            func(p *nodev1.Proxy) {},
		"middle proxy":           func(p *nodev1.Proxy) { p.UseMiddleProxy = true },
		"middle proxy, nat ip":   func(p *nodev1.Proxy) { p.UseMiddleProxy = true; p.NatIp = "203.0.113.10" },
		"middle proxy, ad tag":   func(p *nodev1.Proxy) { p.UseMiddleProxy = true; p.AdTag = testAdTag },
		"nat ip without ME":      func(p *nodev1.Proxy) { p.NatIp = "203.0.113.10" },
		"mask override":          func(p *nodev1.Proxy) { p.MaskTargetOverride = "mask.example.com:8443" },
		"empty overrides object": func(p *nodev1.Proxy) { p.EngineOverridesJson = "{}" },
	}
	for name, edit := range variants {
		t.Run(name, func(t *testing.T) {
			in := goldenInstance()
			edit(in.Proxy)
			doc := parseTOML(t, render(t, in))
			want := map[string]any{"stun_use": false, "http_ip_detect_urls": []string{}}
			if got := doc.tables["network"]; !reflect.DeepEqual(got, want) {
				t.Errorf("[network] = %v, want %v", got, want)
			}
			if _, ok := doc.tables["general"]["http_ip_detect_urls"]; ok {
				t.Error("http_ip_detect_urls is in [general], where telemt does not look for it")
			}
		})
	}
}

// ---- engine overrides ---------------------------------------------------------

// allOverrides has every key of the whitelist, with values that are not
// telemt's own, and in an order that is not the order of the table: the config
// has them in the order of the table, whatever order the JSON had.
const allOverrides = `{
	"tls_front_dir": "tlsfront/cache",
	"me_init_retry_attempts": 5,
	"update_every": 30,
	"rst_on_close": "errors",
	"tg_connect": 10,
	"upstream_connect_retry_backoff_ms": 500,
	"upstream_connect_retry_attempts": 5,
	"me_warmup_step_jitter_ms": 5,
	"me_warmup_step_delay_ms": 30,
	"me_warmup_stagger_enabled": false,
	"me_writer_pick_mode": "sorted_rr",
	"desync_all_full": true,
	"me_reconnect_fast_retry_count": 12,
	"me_reconnect_backoff_cap_ms": 1000,
	"me_reconnect_backoff_base_ms": 200,
	"me_keepalive_payload_random": false,
	"me_keepalive_jitter_secs": 1,
	"me_keepalive_interval_secs": 5,
	"me_keepalive_enabled": false,
	"me2dc_fast": true,
	"me2dc_fallback": false,
	"fast_mode": false,
	"tls_emulation": false
}`

// The tests that use allOverrides mean every key of the table, so a key that is
// added to it has to be added here.
func TestAllOverridesHasEveryKey(t *testing.T) {
	set, problems := overrides.Parse(allOverrides)
	if len(problems) != 0 {
		t.Fatalf("allOverrides is not valid: %v", problems)
	}
	if len(set) != len(overrides.Specs()) {
		var missing []string
		for _, s := range overrides.Specs() {
			if _, ok := set.Get(s.Key); !ok {
				missing = append(missing, s.Key)
			}
		}
		t.Errorf("allOverrides lacks %v", missing)
	}
}

// withOverride is a copy of a document of engine overrides in which one key has
// another JSON value, or is added. The integration test uses it for a case that
// is allOverrides but for one value.
func withOverride(t *testing.T, doc, key, value string) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	m[key] = json.RawMessage(value)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestWithOverride(t *testing.T) {
	original, problems := overrides.Parse(allOverrides)
	if len(problems) != 0 {
		t.Fatalf("allOverrides is not valid: %v", problems)
	}
	if v, _ := original.Get("me2dc_fallback"); v.Bool {
		t.Fatal("the test starts from a me2dc_fallback that is not false")
	}

	changed, problems := overrides.Parse(withOverride(t, allOverrides, "me2dc_fallback", "true"))
	if len(problems) != 0 {
		t.Fatalf("the copy is not valid: %v", problems)
	}
	if len(changed) != len(original) {
		t.Fatalf("the copy has %d keys, want %d", len(changed), len(original))
	}
	for i, v := range changed {
		w := original[i]
		switch {
		case v.Key == "me2dc_fallback":
			if !v.Bool {
				t.Error("me2dc_fallback is not true in the copy")
			}
		case v.Key != w.Key || v.Bool != w.Bool || v.Int != w.Int || v.Str != w.Str:
			t.Errorf("%s changed: %+v, want %+v", w.Key, v, w)
		}
	}
	if v, _ := mustOverrides(t, allOverrides).Get("me2dc_fallback"); v.Bool {
		t.Error("allOverrides itself changed")
	}

	// A key that the document does not have is added.
	added := mustOverrides(t, withOverride(t, `{"fast_mode":true}`, "tg_connect", "7"))
	if v, ok := added.Get("tg_connect"); !ok || v.Int != 7 || len(added) != 2 {
		t.Errorf("added = %v", added)
	}
}

func mustOverrides(t *testing.T, doc string) overrides.Set {
	t.Helper()
	set, problems := overrides.Parse(doc)
	if len(problems) != 0 {
		t.Fatalf("%s is not valid: %v", doc, problems)
	}
	return set
}

// strictConfig is a copy of a rendered config with config_strict = true as the
// first line of [general]. telemt ignores a key that it does not know, so a key
// that is misspelt or in the wrong table would go through without a word; with
// config_strict it refuses the config at start-up. The integration test runs the
// strict copy. The config of a node is not strict.
func strictConfig(t *testing.T, config []byte) []byte {
	t.Helper()
	const header = "[general]\n"
	rest, ok := strings.CutPrefix(string(config), header)
	if !ok {
		t.Fatalf("the config does not begin with %q", header)
	}
	if strings.Contains(rest, "config_strict") {
		t.Fatal("the rendered config has config_strict already")
	}
	return []byte(header + "config_strict = true\n" + rest)
}

func TestStrictConfig(t *testing.T) {
	in := goldenInstance()
	in.Proxy.EngineOverridesJson = allOverrides
	rendered := render(t, in)
	if strings.Contains(rendered, "config_strict") {
		t.Fatal("the config of a node is strict: telemt would refuse a key of a newer version of itself")
	}

	got := parseTOML(t, string(strictConfig(t, []byte(rendered))))
	want := parseTOML(t, rendered)
	want.tables["general"]["config_strict"] = true
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the strict copy differs by more than config_strict:\n%s", docDiff(want, got))
	}
}

// writeOverrides has a line for every kind of the table. A kind that it does not
// know is an error, and never a line that is missing from the config without a
// word.
func TestWriteOverridesHasALineForEveryKindOfTheTable(t *testing.T) {
	for _, spec := range overrides.Specs() {
		var w tomlWriter
		if err := w.writeOverrides([]overrides.Value{{Spec: spec, Str: "a"}}); err != nil {
			t.Errorf("%s: %v", spec.Key, err)
			continue
		}
		if !strings.HasPrefix(w.String(), spec.Key+" = ") || strings.Count(w.String(), "\n") != 1 {
			t.Errorf("%s: wrote %q, want one line for the key", spec.Key, w.String())
		}
	}
}

func TestWriteOverridesRefusesAKindItDoesNotKnow(t *testing.T) {
	for _, kind := range []overrides.Kind{0, 99, -1} {
		var w tomlWriter
		err := w.writeOverrides([]overrides.Value{
			{Spec: overrides.Spec{Key: "fast_mode", Kind: overrides.Bool}, Bool: true},
			{Spec: overrides.Spec{Key: "mystery", Kind: kind}},
		})
		if err == nil || !strings.Contains(err.Error(), `"mystery"`) {
			t.Errorf("kind %d: writeOverrides = %v, want an error that names the key", kind, err)
		}
	}
}

func TestWriteOverridesLeavesOutTheKeysThatItIsTold(t *testing.T) {
	var w tomlWriter
	err := w.writeOverrides([]overrides.Value{
		{Spec: overrides.Spec{Key: "tls_emulation", Kind: overrides.Bool}},
		{Spec: overrides.Spec{Key: "tls_front_dir", Kind: overrides.Dir}, Str: "front"},
	}, "tls_emulation")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := w.String(), "tls_front_dir = \"front\"\n"; got != want {
		t.Errorf("wrote %q, want %q", got, want)
	}
}

func TestRenderGoldenWithOverrides(t *testing.T) {
	tests := []struct {
		name string
		file string
		edit func(p *nodev1.Proxy)
	}{
		{
			name: "every override",
			file: "faketls_overrides.toml",
			edit: func(p *nodev1.Proxy) { p.EngineOverridesJson = allOverrides },
		},
		{
			name: "middle proxy with a NAT address, an ad tag, a mask target and a few overrides",
			file: "faketls_me_overrides.toml",
			edit: func(p *nodev1.Proxy) {
				p.UseMiddleProxy = true
				p.AdTag = testAdTag
				p.NatIp = "203.0.113.10"
				p.MaskTargetOverride = "mask.example.com:8443"
				p.EngineOverridesJson = `{"update_every":30,"tg_connect":10,"me_writer_pick_mode":"p2c","fast_mode":true,"rst_on_close":"off","tls_emulation":true}`
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := goldenInstance()
			tt.edit(in.Proxy)
			got := render(t, in)
			parseTOML(t, got) // well formed, and no key twice
			assertGolden(t, tt.file, got)
		})
	}
}

// No overrides, in any of the ways to say it, is the config of a proxy that never
// had any.
func TestRenderOfNoOverridesIsTheBaseConfig(t *testing.T) {
	want := render(t, goldenInstance())
	for _, raw := range []string{"", " ", "\n", "{}", " {} ", "{ }", "\n{\n}\n", "null", " null "} {
		in := goldenInstance()
		in.Proxy.EngineOverridesJson = raw
		if got := render(t, in); got != want {
			t.Errorf("overrides %q: the config differs from the base config:\n%s", raw, lineDiff(want, got))
		}
	}
}

// An override is one more line in its table, or, for tls_emulation, which Postern
// writes as true itself, the new value of that line: nothing else in the config
// changes.
func TestRenderWritesEveryOverrideToItsTable(t *testing.T) {
	base := parseTOML(t, render(t, goldenInstance()))
	for _, spec := range overrides.Specs() {
		for _, c := range overrideCases(spec) {
			t.Run(spec.Key+"="+c.json, func(t *testing.T) {
				in := goldenInstance()
				in.Proxy.EngineOverridesJson = `{"` + spec.Key + `":` + c.json + `}`
				got := parseTOML(t, render(t, in))

				want := tomlDoc{tables: map[string]map[string]any{}, arrays: base.arrays}
				for name, table := range base.tables {
					want.tables[name] = maps.Clone(table)
				}
				want.tables[string(spec.Section)][spec.Key] = c.value
				if !reflect.DeepEqual(got, want) {
					t.Errorf("the config is not the base config with %s = %v in [%s]:\n%s", spec.Key, c.value, spec.Section, docDiff(want, got))
				}
			})
		}
	}
}

type overrideCase struct {
	json  string // the value as JSON
	value any    // the value as the config has it
}

// overrideCases are values of a spec: both of a bool, the ends of a range, every
// string of an enum, some directories.
func overrideCases(s overrides.Spec) []overrideCase {
	switch s.Kind {
	case overrides.Bool:
		return []overrideCase{{"true", true}, {"false", false}}
	case overrides.Int:
		return []overrideCase{{strconv.FormatInt(s.Min, 10), int(s.Min)}, {strconv.FormatInt(s.Max, 10), int(s.Max)}}
	case overrides.Enum:
		var out []overrideCase
		for _, v := range s.Values {
			out = append(out, overrideCase{strconv.Quote(v), v})
		}
		return out
	case overrides.Dir:
		return []overrideCase{{`"tlsfront"`, "tlsfront"}, {`"a/b-c_d.e"`, "a/b-c_d.e"}}
	}
	panic(fmt.Sprintf("the kind of %s is not one that the test knows", s.Key))
}

// docDiff names the tables and arrays of two parsed configs that differ.
func docDiff(want, got tomlDoc) string {
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(want.tables)) {
		if !reflect.DeepEqual(want.tables[name], got.tables[name]) {
			fmt.Fprintf(&b, "  [%s]\n    want %v\n    got  %v\n", name, want.tables[name], got.tables[name])
		}
	}
	for _, name := range slices.Sorted(maps.Keys(got.tables)) {
		if _, ok := want.tables[name]; !ok {
			fmt.Fprintf(&b, "  [%s] is not wanted: %v\n", name, got.tables[name])
		}
	}
	for _, name := range slices.Sorted(maps.Keys(want.arrays)) {
		if !reflect.DeepEqual(want.arrays[name], got.arrays[name]) {
			fmt.Fprintf(&b, "  [[%s]]\n    want %v\n    got  %v\n", name, want.arrays[name], got.arrays[name])
		}
	}
	return b.String()
}

// tls_emulation is a line that Postern writes: an override gives it its value and
// does not write a second line (TOML would refuse the file, and telemt with it).
func TestRenderWritesTLSEmulationOnce(t *testing.T) {
	for raw, want := range map[string]bool{"": true, `{"tls_emulation":true}`: true, `{"tls_emulation":false}`: false} {
		in := goldenInstance()
		in.Proxy.EngineOverridesJson = raw
		text := render(t, in)
		if n := strings.Count(text, "tls_emulation"); n != 1 {
			t.Errorf("overrides %q: tls_emulation is written %d times, want once:\n%s", raw, n, text)
		}
		if got := parseTOML(t, text).tables["censorship"]["tls_emulation"]; got != want {
			t.Errorf("overrides %q: tls_emulation = %v, want %v", raw, got, want)
		}
	}
}

// The overrides are written in the order of the table, whatever order the JSON has:
// the same overrides make the same file, so that a proxy is not renewed for the
// order of its keys.
func TestRenderIgnoresTheOrderOfTheJSON(t *testing.T) {
	var given map[string]json.RawMessage
	if err := json.Unmarshal([]byte(allOverrides), &given); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, s := range overrides.Specs() {
		keys = append(keys, s.Key)
	}
	document := func(order []string) string {
		parts := make([]string, len(order))
		for i, k := range order {
			parts[i] = strconv.Quote(k) + ":" + string(given[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	renderOf := func(raw string) string {
		in := goldenInstance()
		in.Proxy.EngineOverridesJson = raw
		return render(t, in)
	}
	want := renderOf(allOverrides)
	if got := renderOf(document(keys)); got != want {
		t.Errorf("the keys in the order of the table make another config:\n%s", lineDiff(want, got))
	}
	reversed := slices.Clone(keys)
	slices.Reverse(reversed)
	if got := renderOf(document(reversed)); got != want {
		t.Errorf("the keys in reverse make another config:\n%s", lineDiff(want, got))
	}
}

// What Postern writes stays as Postern writes it, with every override at once and
// whatever else the proxy has: the overrides add to [general] and [censorship]
// and change nothing else.
func TestRenderOverridesLeaveWhatPosternWritesAlone(t *testing.T) {
	proxies := map[string]func(p *nodev1.Proxy){
		"plain": func(p *nodev1.Proxy) {},
		"middle proxy, ad tag, NAT address and mask target": func(p *nodev1.Proxy) {
			p.UseMiddleProxy = true
			p.AdTag = testAdTag
			p.NatIp = "198.51.100.7"
			p.MaskTargetOverride = "[2001:db8::7]:8443"
		},
	}
	for name, edit := range proxies {
		t.Run(name, func(t *testing.T) {
			in := goldenInstance()
			edit(in.Proxy)
			base := parseTOML(t, render(t, in))
			in.Proxy.EngineOverridesJson = allOverrides
			got := parseTOML(t, render(t, in))

			for table, keys := range base.tables {
				for key, want := range keys {
					if table == "censorship" && key == "tls_emulation" {
						continue // its value is the override's
					}
					if g, ok := got.tables[table][key]; !ok || !reflect.DeepEqual(g, want) {
						t.Errorf("[%s] %s = %v, want what Postern writes: %v", table, key, g, want)
					}
				}
				if table != "general" && table != "censorship" && !reflect.DeepEqual(got.tables[table], keys) {
					t.Errorf("[%s] is not what it is without overrides:\n%s", table, docDiff(base, got))
				}
			}
			for table := range got.tables {
				if _, ok := base.tables[table]; !ok {
					t.Errorf("the overrides made a table of their own: [%s]", table)
				}
			}
			if !reflect.DeepEqual(got.arrays, base.arrays) {
				t.Errorf("the arrays of tables changed:\n%s", docDiff(base, got))
			}
			// [general] and [censorship] have the overrides on top of what they had.
			if n, want := len(got.tables["general"]), len(base.tables["general"])+21; n != want {
				t.Errorf("[general] has %d keys, want %d", n, want)
			}
			if n, want := len(got.tables["censorship"]), len(base.tables["censorship"])+1; n != want {
				t.Errorf("[censorship] has %d keys, want %d (tls_front_dir)", n, want)
			}
		})
	}
}

// Postern's lines come first in a table, and the overrides after them.
func TestRenderPutsTheOverridesAfterPosternsLines(t *testing.T) {
	in := goldenInstance()
	in.Proxy.UseMiddleProxy = true
	in.Proxy.AdTag = testAdTag
	in.Proxy.NatIp = "198.51.100.7"
	in.Proxy.EngineOverridesJson = allOverrides
	lines := tableLines(render(t, in), "general")
	posterns := []string{"use_middle_proxy", "log_level", "data_path", "ad_tag", "middle_proxy_nat_ip", "middle_proxy_nat_probe"}
	if len(lines) <= len(posterns) {
		t.Fatalf("[general] has %d lines: %v", len(lines), lines)
	}
	for i, key := range posterns {
		if !strings.HasPrefix(lines[i], key+" = ") {
			t.Errorf("line %d of [general] is %q, want %s first", i+1, lines[i], key)
		}
	}
	if !strings.HasPrefix(lines[len(posterns)], "fast_mode = ") {
		t.Errorf("the first override is %q, want fast_mode", lines[len(posterns)])
	}
	if c := tableLines(render(t, in), "censorship"); !strings.HasPrefix(c[len(c)-1], "tls_front_dir = ") {
		t.Errorf("the last line of [censorship] is %q, want tls_front_dir", c[len(c)-1])
	}
}

// tableLines returns the lines under one table header of a config, up to the
// blank line that ends it.
func tableLines(config, table string) []string {
	var out []string
	in := false
	for line := range strings.SplitSeq(config, "\n") {
		switch {
		case line == "["+table+"]":
			in = true
		case in && line == "":
			return out
		case in:
			out = append(out, line)
		}
	}
	return out
}

// ---- overrides that are refused ----------------------------------------------------

// The keys that Postern owns are refused with a message that says so, and nothing
// is rendered, whatever else the document has.
func TestRenderRefusesWhatPosternOwns(t *testing.T) {
	for _, key := range []string{
		// telemt prints links at higher levels; there is no STUN; no files in a
		// read-only container
		"log_level", "stun_servers", "stun_use", "beobachten", "beobachten_minutes", "beobachten_flush_secs",
		"beobachten_file", "unknown_dc_file_log_enabled",
		// listeners, upstreams, users, the ad tag and the NAT address
		"listeners", "server", "port", "listen_addr_ipv4", "proxy_protocol", "upstreams", "access", "users",
		"ad_tag", "middle_proxy_nat_ip",
		// the rest of what Postern writes
		"use_middle_proxy", "data_path", "tls_domain", "mask_host", "middle_proxy_nat_probe", "http_ip_detect_urls",
	} {
		for _, raw := range []string{`{"` + key + `":1}`, `{"fast_mode":false,"` + key + `":1}`} {
			t.Run(raw, func(t *testing.T) {
				in := goldenInstance()
				in.Proxy.EngineOverridesJson = raw
				files, err := Driver{}.Render(in)
				if err == nil {
					t.Fatalf("Render accepted it and produced:\n%s", files["config.toml"])
				}
				if files != nil {
					t.Errorf("Render returned files %v together with an error", slices.Sorted(maps.Keys(files)))
				}
				for _, want := range []string{strconv.Quote(key), "owned by Postern"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("the error %q does not contain %q", err, want)
					}
				}
			})
		}
	}
}

func TestRenderRefusesOverridesThatAreNotValid(t *testing.T) {
	tests := []struct {
		raw  string
		want []string // parts of the error
	}{
		{`{"fast_mode":"yes"}`, []string{`"fast_mode"`, "true or false"}},
		{`{"fast_mode":1}`, []string{`"fast_mode"`, "true or false"}},
		{`{"tg_connect":0}`, []string{`"tg_connect"`, "from 1 to 600"}},
		{`{"tg_connect":601}`, []string{`"tg_connect"`, "from 1 to 600"}},
		{`{"tg_connect":"10"}`, []string{`"tg_connect"`, "integer"}},
		{`{"tg_connect":10.5}`, []string{`"tg_connect"`, "integer"}},
		{`{"upstream_connect_retry_attempts":0}`, []string{`"upstream_connect_retry_attempts"`, "from 1 to 100"}},
		{`{"me_keepalive_jitter_secs":-1}`, []string{`"me_keepalive_jitter_secs"`, "from 0 to 600"}},
		{`{"update_every":86401}`, []string{`"update_every"`, "from 1 to 86400"}},
		{`{"me_writer_pick_mode":"fast"}`, []string{`"me_writer_pick_mode"`, `"p2c"`, `"sorted_rr"`}},
		{`{"rst_on_close":true}`, []string{`"rst_on_close"`, `"off"`, `"errors"`, `"always"`}},
		{`{"tls_emulation":"tls"}`, []string{`"tls_emulation"`, "true or false"}},
		{`{"tls_front_dir":"/tmp/front"}`, []string{`"tls_front_dir"`, "relative"}},
		{`{"tls_front_dir":"../front"}`, []string{`"tls_front_dir"`, `".."`}},
		{`{"tls_front_dir":"front\ndir"}`, []string{`"tls_front_dir"`, "letters"}},
		{`{"workers":4}`, []string{`"workers"`, "not supported"}},
		{`{"general":{"fast_mode":false}}`, []string{`"general"`, "flat"}},
		{`{"network_prefer":"system"}`, []string{`"network_prefer"`, "not supported"}},
		{`{"server_client_mss":1360}`, []string{`"server_client_mss"`, "not supported"}},
		{`{"fast_mode":true,"fast_mode":false}`, []string{`"fast_mode"`, "more than once"}},
		// Every problem is told at once.
		{`{"tg_connect":0,"workers":1,"log_level":"debug"}`, []string{`"tg_connect"`, `"workers"`, `"log_level"`}},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			in := goldenInstance()
			in.Proxy.EngineOverridesJson = tt.raw
			files, err := Driver{}.Render(in)
			if err == nil {
				t.Fatalf("Render accepted it and produced:\n%s", files["config.toml"])
			}
			if files != nil {
				t.Errorf("Render returned files together with an error")
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error %q does not contain %q", err, want)
				}
			}
			if !strings.HasPrefix(err.Error(), "telemt: ") {
				t.Errorf("the error %q does not say whose it is", err)
			}
		})
	}
}

// What is not a JSON object is another error: not one about a key.
func TestRenderRefusesAnOverridesDocumentThatIsNotAnObject(t *testing.T) {
	for _, raw := range []string{"[]", `"x"`, "5", "true", "{", `{"a":}`, "garbage", "{} {}", `{"fast_mode":true} x`} {
		t.Run(strconv.Quote(raw), func(t *testing.T) {
			in := goldenInstance()
			in.Proxy.EngineOverridesJson = raw
			_, err := Driver{}.Render(in)
			if err == nil {
				t.Fatalf("Render accepted %q", raw)
			}
			if !strings.Contains(err.Error(), "engine_overrides_json is not a JSON object") {
				t.Errorf("Render = %v, want the error of a document that is not an object", err)
			}
		})
	}
}

// ---- refusing bad input -------------------------------------------------------

func TestRenderRejects(t *testing.T) {
	tests := []struct {
		name string
		edit func(in *engines.Instance)
	}{
		{"nil proxy", func(in *engines.Instance) { in.Proxy = nil }},
		{"web proxy", func(in *engines.Instance) { in.Proxy.Type = nodev1.ProxyType_PROXY_TYPE_WEB }},
		{"unspecified type", func(in *engines.Instance) { in.Proxy.Type = nodev1.ProxyType_PROXY_TYPE_UNSPECIFIED }},
		{"another engine", func(in *engines.Instance) { in.Proxy.Engine = nodev1.Engine_ENGINE_MTG }},

		{"empty secret", func(in *engines.Instance) { in.Proxy.Secret = "" }},
		{"short secret", func(in *engines.Instance) { in.Proxy.Secret = testSecret[:31] }},
		{"long secret", func(in *engines.Instance) { in.Proxy.Secret = testSecret + "0" }},
		{"non hex secret", func(in *engines.Instance) { in.Proxy.Secret = strings.Repeat("g", 32) }},
		{"secret with quote", func(in *engines.Instance) { in.Proxy.Secret = testSecret[:30] + `"x` }},
		{"secret with ee prefix", func(in *engines.Instance) { in.Proxy.Secret = "ee" + testSecret }},

		{"short ad tag", func(in *engines.Instance) { in.Proxy.AdTag = testAdTag[:31] }},
		{"long ad tag", func(in *engines.Instance) { in.Proxy.AdTag = testAdTag + "0" }},
		{"non hex ad tag", func(in *engines.Instance) { in.Proxy.AdTag = strings.Repeat("z", 32) }},
		{"ad tag with newline", func(in *engines.Instance) { in.Proxy.AdTag = testAdTag[:30] + "\n[" }},

		{"empty domain", func(in *engines.Instance) { in.Proxy.Domain = "" }},
		{"domain with space", func(in *engines.Instance) { in.Proxy.Domain = "www example.com" }},
		{"domain with tab", func(in *engines.Instance) { in.Proxy.Domain = "www\texample.com" }},
		{"domain with slash", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com/x" }},
		{"domain with backslash", func(in *engines.Instance) { in.Proxy.Domain = `www.example.com\x` }},
		{"domain with quote", func(in *engines.Instance) { in.Proxy.Domain = `www.example.com"` }},
		{"domain with newline", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\n[evil]" }},
		{"domain with nul", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\x00" }},
		{"domain with c1 control", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\u0085" }},
		{"domain with line separator", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\u2028" }},
		{"domain with bidi override", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\u202e" }},
		{"domain with bidi isolate", func(in *engines.Instance) { in.Proxy.Domain = "www.\u2066example.com" }},
		{"domain with left-to-right mark", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\u200e" }},
		{"domain is invalid utf-8", func(in *engines.Instance) { in.Proxy.Domain = "www.example.com\xff" }},
		{"domain too long", func(in *engines.Instance) { in.Proxy.Domain = strings.Repeat("a", 254) }},

		{"bad nat ip", func(in *engines.Instance) { in.Proxy.UseMiddleProxy = true; in.Proxy.NatIp = "203.0.113.999" }},
		{"nat ip is a host name", func(in *engines.Instance) { in.Proxy.UseMiddleProxy = true; in.Proxy.NatIp = "example.com" }},
		{"nat ip unspecified", func(in *engines.Instance) { in.Proxy.UseMiddleProxy = true; in.Proxy.NatIp = "0.0.0.0" }},
		{"nat ip loopback", func(in *engines.Instance) { in.Proxy.UseMiddleProxy = true; in.Proxy.NatIp = "127.0.0.1" }},
		{"nat ip with zone", func(in *engines.Instance) { in.Proxy.UseMiddleProxy = true; in.Proxy.NatIp = "fe80::1%eth0" }},
		{"nat ip with newline", func(in *engines.Instance) { in.Proxy.UseMiddleProxy = true; in.Proxy.NatIp = "203.0.113.10\n" }},

		{"mask override with space", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "a b.example.com" }},
		{"mask override with quote", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = `a".example.com` }},
		{"mask override with slash", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "a.example.com/x" }},
		{"mask override with url", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "https://a.example.com" }},
		{"mask override with newline", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "a.example.com\n[x]" }},
		{"mask override with bidi override", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "a.example.com\u202e" }},
		{"mask override port zero", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "a.example.com:0" }},
		{"mask override port too big", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "a.example.com:65536" }},
		{"mask override port not a number", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "a.example.com:https" }},
		{"mask override empty host", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = ":443" }},
		{"mask override empty port", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "a.example.com:" }},
		{"mask override two ports", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "a.example.com:1:2" }},
		{"mask override unbracketed ipv6 with port", func(in *engines.Instance) { in.Proxy.MaskTargetOverride = "2001:db8::7:443x" }},

		{"no listen port", func(in *engines.Instance) { in.ListenPort = 0 }},
		{"no api port", func(in *engines.Instance) { in.APIPort = 0 }},
		{"no socks port", func(in *engines.Instance) { in.SocksPort = 0 }},
		{"listen and api share a port", func(in *engines.Instance) { in.APIPort = in.ListenPort }},
		{"listen and socks share a port", func(in *engines.Instance) { in.SocksPort = in.ListenPort }},
		{"api and socks share a port", func(in *engines.Instance) { in.SocksPort = in.APIPort }},

		{"empty api token", func(in *engines.Instance) { in.APIToken = "" }},
		{"api token with newline", func(in *engines.Instance) { in.APIToken = "abc\n[evil]" }},
		{"api token with quote", func(in *engines.Instance) { in.APIToken = `abc"def` }},
		{"api token with nul", func(in *engines.Instance) { in.APIToken = "abc\x00def" }},
		{"api token with space", func(in *engines.Instance) { in.APIToken = "abc def" }},
		{"api token not ascii", func(in *engines.Instance) { in.APIToken = "abcdéf" }},
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
			// The error says what is wrong, never what the secrets are.
			for _, secret := range []string{testSecret, strings.ToUpper(testSecret), testToken, testAdTag} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the error %q contains a secret", err)
				}
			}
		})
	}
}

// TestRenderErrorsNeverHoldSecrets feeds secrets that are wrong in each possible
// way and checks that the offending value is not repeated in the error.
func TestRenderErrorsNeverHoldSecrets(t *testing.T) {
	const wrong = "NOT-HEX-SECRET-VALUE-0123456789"
	in := goldenInstance()
	in.Proxy.Secret = wrong
	if _, err := (Driver{}).Render(in); err == nil || strings.Contains(err.Error(), wrong) {
		t.Errorf("Render = %v: the rejected secret must not be echoed", err)
	}
	in = goldenInstance()
	in.Proxy.AdTag = "NOT-AN-AD-TAG-0123456789"
	if _, err := (Driver{}).Render(in); err == nil || strings.Contains(err.Error(), in.Proxy.AdTag) {
		t.Errorf("Render = %v: the rejected ad tag must not be echoed", err)
	}
	in = goldenInstance()
	in.APIToken = "bad token\nwith newline"
	if _, err := (Driver{}).Render(in); err == nil || strings.Contains(err.Error(), "bad token") {
		t.Errorf("Render = %v: the rejected token must not be echoed", err)
	}
}

// TestRenderHostileInputCannotInjectConfig: whatever the validation lets through
// is escaped, and nothing that is rejected can reach the file. The check is
// structural: the rendered text parses, and holds exactly the tables it should.
func TestRenderHostileInputCannotInjectConfig(t *testing.T) {
	hostile := []string{
		"x\"\n[general]\nuse_middle_proxy = true\n#",
		"x\\\"; [evil]",
		"a\r\nb",
		"\"\"\"",
		"'''",
		"x # y",
		"[[upstreams]]\ntype = \"direct\"",
		"\u202e",
		"ok\u0000",
	}
	for _, h := range hostile {
		for field, set := range map[string]func(in *engines.Instance){
			"domain":       func(in *engines.Instance) { in.Proxy.Domain = h },
			"mask":         func(in *engines.Instance) { in.Proxy.MaskTargetOverride = h },
			"token":        func(in *engines.Instance) { in.APIToken = h },
			"secret":       func(in *engines.Instance) { in.Proxy.Secret = h },
			"ad tag":       func(in *engines.Instance) { in.Proxy.AdTag = h },
			"nat ip":       func(in *engines.Instance) { in.Proxy.UseMiddleProxy = true; in.Proxy.NatIp = h },
			"overrides":    func(in *engines.Instance) { in.Proxy.EngineOverridesJson = h },
			"instance dir": func(in *engines.Instance) { in.InstanceDir = h },
			// Inside a document that is valid, as the value of an override or as its key.
			"override dir":  func(in *engines.Instance) { in.Proxy.EngineOverridesJson = `{"tls_front_dir":` + jsonText(t, h) + `}` },
			"override enum": func(in *engines.Instance) { in.Proxy.EngineOverridesJson = `{"rst_on_close":` + jsonText(t, h) + `}` },
			"override key":  func(in *engines.Instance) { in.Proxy.EngineOverridesJson = `{` + jsonText(t, h) + `:true}` },
		} {
			in := goldenInstance()
			set(&in)
			files, err := Driver{}.Render(in)
			if err != nil {
				continue // refused: fine
			}
			// Accepted: it must still be a well-formed document of the same shape.
			doc := parseTOML(t, string(files["config.toml"]))
			if len(doc.tables) != 8 || len(doc.arrays) != 2 || len(doc.arrays["upstreams"]) != 2 {
				t.Errorf("%s=%q was accepted and changed the shape of the config:\n%s", field, h, files["config.toml"])
			}
			for _, u := range doc.arrays["upstreams"] {
				if u["type"] != "socks5" {
					t.Errorf("%s=%q slipped in an upstream %v", field, h, u)
				}
			}
		}
	}
}

// jsonText is a string as a JSON string.
func jsonText(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
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
		{"form\ffeed", `"form\ffeed"`},
		{"back\bspace", `"back\bspace"`},
		{"nul\x00byte", `"nul\u0000byte"`},
		{"bell\x07", `"bell\u0007"`},
		{"del\x7f", `"del\u007F"`},
		{"unicode пример ✓", `"unicode пример ✓"`},
		{"hash # not a comment", `"hash # not a comment"`},
		{"[table]", `"[table]"`},
	}
	for _, tt := range tests {
		t.Run(strconv.Quote(tt.in), func(t *testing.T) {
			if got := quote(tt.in); got != tt.want {
				t.Errorf("quote(%q) = %s, want %s", tt.in, got, tt.want)
			}
			// The output is one line, and reading it back gives the input.
			got := quote(tt.in)
			if strings.ContainsAny(got, "\n\r") {
				t.Errorf("quote(%q) = %s spans lines", tt.in, got)
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

func TestQuoteRoundTripsEveryByteValue(t *testing.T) {
	var b strings.Builder
	for r := rune(0); r < 0x250; r++ {
		b.WriteRune(r)
	}
	in := b.String()
	back, err := parseString(quote(in))
	if err != nil {
		t.Fatal(err)
	}
	if back != in {
		t.Error("the characters U+0000..U+024F do not survive quote and read-back")
	}
}

// ---- the driver ---------------------------------------------------------------

func TestDriverBasics(t *testing.T) {
	var d engines.Driver = New()
	if got := d.Engine(); got != nodev1.Engine_ENGINE_TELEMT {
		t.Errorf("Engine = %v, want ENGINE_TELEMT", got)
	}
	if got := d.BinaryName(); got != "telemt" {
		t.Errorf("BinaryName = %q, want telemt", got)
	}
	for typ, want := range map[nodev1.ProxyType]bool{
		nodev1.ProxyType_PROXY_TYPE_FAKETLS:     true,
		nodev1.ProxyType_PROXY_TYPE_WEB:         true,
		nodev1.ProxyType_PROXY_TYPE_UNSPECIFIED: false,
	} {
		if got := d.Supports(typ); got != want {
			t.Errorf("Supports(%v) = %v, want %v", typ, got, want)
		}
	}
}

func TestArtifactFile(t *testing.T) {
	d := New()
	for arch, want := range map[string]string{
		"amd64": "telemt-x86_64-linux-musl.tar.gz",
		"arm64": "telemt-aarch64-linux-musl.tar.gz",
	} {
		got, err := d.ArtifactFile(arch)
		if err != nil {
			t.Errorf("ArtifactFile(%q): %v", arch, err)
		}
		if got != want {
			t.Errorf("ArtifactFile(%q) = %q, want %q", arch, got, want)
		}
	}
	for _, arch := range []string{"", "386", "riscv64", "x86_64", "aarch64", "AMD64", "amd64 "} {
		if got, err := d.ArtifactFile(arch); err == nil {
			t.Errorf("ArtifactFile(%q) = %q, want an error", arch, got)
		}
	}
}

func TestContainer(t *testing.T) {
	in := goldenInstance()
	got := New().Container(in)
	want := dockerapi.ContainerSpec{
		Name:          "postern-eng-01j9zz0000000000000000test-g3",
		Image:         runnerImage,
		User:          "65534:65534",
		NetworkMode:   "host",
		RestartPolicy: "unless-stopped",
		Entrypoint:    []string{"/opt/engine/telemt", "/etc/telemt/config.toml"},
		// The log level, outside the instance hash (the integration test TestLogLevel
		// proves the filter free of secrets and client addresses).
		Env: []string{"RUST_LOG=info,telemt::proxy=off,telemt::maestro::listeners::accept=off,telemt::ip_tracker=off,telemt::links=off,telemt::config::hot_reload=off"},
		Binds: []string{
			"/opt/postern/data/artifacts/telemt/3.5.13/amd64/telemt:/opt/engine/telemt:ro",
			"/opt/postern/data/instances/01J9ZZ0000000000000000TEST-g3:/etc/telemt",
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

// fakeAPI starts a stand-in for telemt's API on loopback and returns an instance
// that points at it.
func fakeAPI(t *testing.T, h http.HandlerFunc) engines.Instance {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Hostname() != "127.0.0.1" {
		t.Fatalf("test server on %s, want 127.0.0.1", u.Hostname())
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	in := goldenInstance()
	in.APIPort = uint16(port)
	return in
}

const readyBody = `{"ok":true,"data":{"ready":true,"status":"ready","admission_open":true,"healthy_upstreams":2,"total_upstreams":2},"revision":"abc"}`

func TestReady(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	var gotHeaders http.Header
	in := fakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth, gotHeaders = r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Clone()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(readyBody))
	})
	if err := New().Ready(t.Context(), in); err != nil {
		t.Fatalf("Ready = %v, want nil", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/health/ready" {
		t.Errorf("request = %s %s, want GET /v1/health/ready", gotMethod, gotPath)
	}
	// The token goes in as it is: no "Bearer " in front, telemt compares the
	// whole header value.
	if gotAuth != testToken {
		t.Errorf("Authorization = %q, want %q", gotAuth, testToken)
	}
	if gotHeaders.Get("Cookie") != "" || gotHeaders.Get("Proxy-Authorization") != "" {
		t.Errorf("unexpected headers sent: %v", gotHeaders)
	}
}

func TestReadyNotReady(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string // part of the message
	}{
		{"503 no healthy upstreams", 503,
			`{"ok":true,"data":{"ready":false,"status":"not_ready","reason":"no_healthy_upstreams","admission_open":true,"healthy_upstreams":0,"total_upstreams":2}}`,
			"no_healthy_upstreams"},
		{"503 admission closed", 503,
			`{"ok":true,"data":{"ready":false,"status":"not_ready","reason":"admission_closed","admission_open":false,"healthy_upstreams":2,"total_upstreams":2}}`,
			"admission_closed"},
		{"503 without a body", 503, ``, "503"},
		{"503 not json", 503, `<html>bad gateway</html>`, "503"},
		{"200 but not ready", 200,
			`{"ok":true,"data":{"ready":false,"status":"not_ready","reason":"admission_closed"}}`,
			"admission_closed"},
		{"200 but no data", 200, `{"ok":true}`, "not ready"},
		{"200 not telemt", 200, `<html>hello</html>`, "unexpected"},
		{"200 empty", 200, ``, "unexpected"},
		{"200 ok false", 200, `{"ok":false,"data":{"ready":true}}`, "not ready"},
		{"401", 401, `{"ok":false,"error":{"code":"unauthorized","message":"Unauthorized"},"request_id":1}`, "401"},
		{"403", 403, `{"ok":false,"error":{"code":"forbidden","message":"Forbidden"}}`, "403"},
		{"404", 404, `{"ok":false,"error":{"code":"not_found","message":"Not found"}}`, "404"},
		{"500", 500, `oops`, "500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := fakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			err := New().Ready(t.Context(), in)
			if err == nil {
				t.Fatalf("Ready = nil for HTTP %d %q", tt.status, tt.body)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Ready = %q, want it to mention %q", err, tt.wantErr)
			}
			if strings.Contains(err.Error(), testToken) {
				t.Errorf("the error %q contains the API token", err)
			}
		})
	}
}

func TestReadyDoesNotFollowRedirects(t *testing.T) {
	var hits int
	in := fakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/v1/health/ready" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(readyBody)) // would be ready, were the redirect followed
	})
	if err := New().Ready(t.Context(), in); err == nil {
		t.Error("Ready followed a redirect")
	}
	if hits != 1 {
		t.Errorf("the server was hit %d times, want 1", hits)
	}
}

func TestReadyConnectionRefused(t *testing.T) {
	// A port that was just free: nothing listens there.
	srv := httptest.NewServer(http.NotFoundHandler())
	u, _ := url.Parse(srv.URL)
	srv.Close()
	port, _ := strconv.Atoi(u.Port())

	in := goldenInstance()
	in.APIPort = uint16(port)
	err := New().Ready(t.Context(), in)
	if err == nil {
		t.Fatal("Ready = nil with nothing listening")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Errorf("the error %q contains the API token", err)
	}
}

func TestReadyHonoursTheContext(t *testing.T) {
	block := make(chan struct{})
	in := fakeAPI(t, func(w http.ResponseWriter, r *http.Request) { <-block })
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
	in := fakeAPI(t, func(w http.ResponseWriter, r *http.Request) { <-block })
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

func TestReadyBigResponseIsNotRead(t *testing.T) {
	in := fakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"data":{"ready":true,"status":"` + strings.Repeat("x", 10<<20) + `"}}`))
	})
	// A hostile or broken server cannot make Ready read ten megabytes into a
	// JSON document; whether it then counts as ready is beside the point.
	err := New().Ready(t.Context(), in)
	if err == nil {
		t.Error("Ready accepted a response far over the size limit")
	}
}

func TestReadyPreconditions(t *testing.T) {
	in := goldenInstance()
	in.APIToken = ""
	if err := New().Ready(t.Context(), in); err == nil {
		t.Error("Ready = nil without an API token: telemt would not check it, and the config never allows that")
	}
	in = goldenInstance()
	in.APIPort = 0
	if err := New().Ready(t.Context(), in); err == nil {
		t.Error("Ready = nil without an API port")
	}
}

// ---- a very small TOML reader for the tests -----------------------------------

// tomlDoc is what parseTOML makes of the config: just enough TOML for the files
// Render writes (tables, arrays of tables, one-line key = value pairs with
// strings, booleans, integers and arrays of strings). Anything else is a test
// failure, which is the point: it fails when the output gets a shape that a
// stricter reader might not take.
type tomlDoc struct {
	tables map[string]map[string]any
	arrays map[string][]map[string]any
}

func parseTOML(t *testing.T, text string) tomlDoc {
	t.Helper()
	if !strings.HasSuffix(text, "\n") {
		t.Fatalf("the config does not end with a newline")
	}
	doc := tomlDoc{tables: map[string]map[string]any{}, arrays: map[string][]map[string]any{}}
	var cur map[string]any
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
			if !ok || cur == nil || !validBareKey(key) {
				fail("not a key = value pair inside a table")
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
