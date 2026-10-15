package telemt

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/telemt/site"
)

func webProxy() *nodev1.Proxy {
	return &nodev1.Proxy{
		Id: "01J9ZZ0000000000000000WEB", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_WEB, Enabled: true,
		Secret: testSecret, Domain: "web.example.com", Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
		Web: &nodev1.WebSettings{CertMode: "acme-dns01", PublicAddr: "203.0.113.10"},
	}
}

func webInstance() engines.Instance {
	in := goldenInstance()
	in.Proxy = webProxy()
	return in
}

// renderWeb returns the files of a WEB instance: config.toml and the decoy
// site under public/.
func renderWebFiles(t *testing.T, in engines.Instance) (string, map[string][]byte) {
	t.Helper()
	files, err := (Driver{}).Render(in)
	if err != nil {
		t.Fatal(err)
	}
	cfg, ok := files[configFile]
	if !ok {
		t.Fatalf("Render returned %v, want config.toml", slices.Sorted(maps.Keys(files)))
	}
	return string(cfg), files
}

func TestSupportsWeb(t *testing.T) {
	d := Driver{}
	if !d.Supports(nodev1.ProxyType_PROXY_TYPE_WEB) || !d.Supports(nodev1.ProxyType_PROXY_TYPE_FAKETLS) {
		t.Error("telemt must support fake TLS and WEB")
	}
}

// The WEB config follows the Global Constraints of the slice: a web listener
// on the instance's loopback port behind the edge (XFF from 127.0.0.1 only),
// one vhost with the decoy site, one profile, the secret under access.users,
// and the upstreams of a fake-TLS instance.
func TestRenderWebStructure(t *testing.T) {
	in := webInstance()
	cfg, files := renderWebFiles(t, in)
	doc := parseTOML(t, cfg)

	wantTables := map[string]map[string]any{
		"general":       {"use_middle_proxy": false, "log_level": "silent", "data_path": "/etc/telemt/data"},
		"general.links": {"show": []string{}},
		"network":       {"stun_use": false, "http_ip_detect_urls": []string{}},
		"server.api": {
			"enabled": true, "listen": "127.0.0.1:25123", "whitelist": []string{"127.0.0.1/32"}, "auth_header": testToken,
		},
		"web":              {"enabled": true, "carrier": "https", "carriers": []string{"https-lanes"}},
		"web.vhosts.decoy": {"mode": "static_directory", "directory": "/etc/telemt/public", "index": "index.html"},
		"access.users":     {"p": testSecret},
	}
	if len(doc.tables) != len(wantTables) {
		t.Errorf("tables = %v, want %v", slices.Sorted(maps.Keys(doc.tables)), slices.Sorted(maps.Keys(wantTables)))
	}
	for name, want := range wantTables {
		if got := doc.tables[name]; !reflect.DeepEqual(got, want) {
			t.Errorf("[%s] = %v, want %v", name, got, want)
		}
	}
	wantArrays := map[string][]map[string]any{
		"server.listeners": {{
			"ip": "127.0.0.1", "port": 20123, "transport": "web", "proxy_protocol": false, "reuse_allow": false,
			"web_client_ip_source": "x_forwarded_for", "web_trusted_proxy_cidrs": []string{"127.0.0.1/32"},
		}},
		"web.vhosts":          {{"host": "web.example.com", "public_addr": "203.0.113.10:443"}},
		"web.vhosts.profiles": {{"user": "p", "secret_mode": "plain"}},
		"upstreams": {
			{"type": "socks5", "address": "127.0.0.1:30123"},
			{"type": "socks5", "address": "127.0.0.1:30123", "scopes": "me, fetch"},
		},
	}
	if len(doc.arrays) != len(wantArrays) {
		t.Errorf("arrays = %v, want %v", slices.Sorted(maps.Keys(doc.arrays)), slices.Sorted(maps.Keys(wantArrays)))
	}
	for name, want := range wantArrays {
		if got := doc.arrays[name]; !reflect.DeepEqual(got, want) {
			t.Errorf("[[%s]] = %v, want %v", name, got, want)
		}
	}
	// The sub-tables of the vhost follow its header, so TOML attaches them to it.
	iv, id, ip := strings.Index(cfg, "[[web.vhosts]]"), strings.Index(cfg, "[web.vhosts.decoy]"), strings.Index(cfg, "[[web.vhosts.profiles]]")
	if iv >= id || id >= ip {
		t.Errorf("vhost tables out of order: vhosts %d, decoy %d, profiles %d", iv, id, ip)
	}

	// The decoy site is in public/, as site.Generate makes it for the proxy id.
	want := site.Generate(in.Proxy.GetId())
	for name, data := range want {
		if got, ok := files["public/"+name]; !ok || string(got) != string(data) {
			t.Errorf("public/%s missing or different", name)
		}
	}
	if len(files) != len(want)+1 {
		t.Errorf("files = %v, want config.toml and the %d files of the site", slices.Sorted(maps.Keys(files)), len(want))
	}
}

func TestRenderWebVariants(t *testing.T) {
	cases := []struct {
		name  string
		tweak func(p *nodev1.Proxy)
		check func(t *testing.T, doc tomlDoc)
	}{
		{"base path, dd, carriers", func(p *nodev1.Proxy) {
			p.Web.BasePath = "tg/one"
			p.Web.SecretMode = "dd"
			p.Web.Carrier = "https-lanes"
			p.Web.Carriers = []string{"https", "https-lanes"}
		}, func(t *testing.T, doc tomlDoc) {
			if got := doc.arrays["web.vhosts"][0]["base_path"]; got != "tg/one" {
				t.Errorf("base_path = %v", got)
			}
			if got := doc.arrays["web.vhosts.profiles"][0]["secret_mode"]; got != "dd" {
				t.Errorf("secret_mode = %v", got)
			}
			if got := doc.tables["web"]; got["carrier"] != "https-lanes" || !reflect.DeepEqual(got["carriers"], []string{"https", "https-lanes"}) {
				t.Errorf("[web] = %v", got)
			}
		}},
		{"public_addr with port, upper-case domain", func(p *nodev1.Proxy) {
			p.Web.PublicAddr = "203.0.113.10:443"
			p.Domain = "Web.Example.COM."
		}, func(t *testing.T, doc tomlDoc) {
			v := doc.arrays["web.vhosts"][0]
			if v["public_addr"] != "203.0.113.10:443" || v["host"] != "web.example.com" {
				t.Errorf("vhost = %v", v)
			}
		}},
		{"middle proxy with NAT and ad tag", func(p *nodev1.Proxy) {
			p.UseMiddleProxy = true
			p.NatIp = "203.0.113.10"
			p.AdTag = strings.Repeat("ab", 16)
		}, func(t *testing.T, doc tomlDoc) {
			g := doc.tables["general"]
			if g["use_middle_proxy"] != true || g["middle_proxy_nat_ip"] != "203.0.113.10" || g["middle_proxy_nat_probe"] != false || g["ad_tag"] != strings.Repeat("ab", 16) {
				t.Errorf("[general] = %v", g)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := webInstance()
			c.tweak(in.Proxy)
			cfg, _ := renderWebFiles(t, in)
			c.check(t, parseTOML(t, cfg))
		})
	}
}

func TestRenderWebRejects(t *testing.T) {
	cases := []struct {
		name  string
		tweak func(in *engines.Instance)
		want  string
	}{
		{"no web settings", func(in *engines.Instance) { in.Proxy.Web = nil }, "web settings"},
		{"no public address", func(in *engines.Instance) { in.Proxy.Web.PublicAddr = "" }, "public_addr"},
		{"private public address", func(in *engines.Instance) { in.Proxy.Web.PublicAddr = "10.0.0.1" }, "public_addr"},
		{"bad base path", func(in *engines.Instance) { in.Proxy.Web.BasePath = "/tg" }, "base_path"},
		{"bad secret mode", func(in *engines.Instance) { in.Proxy.Web.SecretMode = "ee" }, "secret_mode"},
		{"bad carrier", func(in *engines.Instance) { in.Proxy.Web.Carriers = []string{"wss"} }, "carrier"},
		{"bad secret", func(in *engines.Instance) { in.Proxy.Secret = "xyz" }, "secret"},
		{"single-label domain", func(in *engines.Instance) { in.Proxy.Domain = "localhost" }, "domain"},
		{"overrides", func(in *engines.Instance) { in.Proxy.EngineOverridesJson = `{"a":1}` }, "override"},
		{"mtg engine", func(in *engines.Instance) { in.Proxy.Engine = nodev1.Engine_ENGINE_MTG }, "engine"},
		{"no API token", func(in *engines.Instance) { in.APIToken = "" }, "token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := webInstance()
			c.tweak(&in)
			_, err := (Driver{}).Render(in)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
			if err != nil && (strings.Contains(err.Error(), testSecret) || strings.Contains(err.Error(), testToken)) {
				t.Error("the error holds a secret")
			}
		})
	}
}

func TestRenderWebDoesNotTouchItsInput(t *testing.T) {
	in := webInstance()
	before := proto.Clone(in.Proxy)
	if _, err := (Driver{}).Render(in); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(before, in.Proxy) {
		t.Error("Render changed the proxy")
	}
}
