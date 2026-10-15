package xray

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/egressuri"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/warp"
)

// update rewrites the golden files in testdata:
//
//	go test ./internal/providers/xray -run TestRenderGolden -update
//
// Read the diff afterwards; the integration test checks every golden case with
// the real Xray (xray run -test).
var update = flag.Bool("update", false, "rewrite the golden files in testdata")

const runnerImage = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

// Fake credentials, low in entropy on purpose. None of them is real.
const (
	testUUID     = "11111111-2222-3333-4444-555555555555"
	testPassword = "pass-pass-pass"
)

var (
	realityKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	ss2022Key  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 16))
	wgPrivate  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	wgPeer     = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
)

// ---- the servers of the golden cases ------------------------------------------

func vlessRealityVision() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "vless", Name: "reality vision", Address: "reality.example.com", Port: 443, ID: testUUID,
		Flow: "xtls-rprx-vision", Network: "tcp", Security: "reality",
		SNI: "www.example.com", Fingerprint: "chrome", PublicKey: realityKey, ShortID: "0123abcd", SpiderX: "/",
	}
}

func vlessWSTLS() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "vless", Name: "ws tls", Address: "cdn.example.com", Port: 443, ID: testUUID,
		Network: "ws", Security: "tls", SNI: "cdn.example.com", Fingerprint: "firefox", ALPN: "http/1.1",
		Path: "/ws?ed=2048", Host: "cdn.example.com",
	}
}

func trojanTLS() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "trojan", Name: "trojan", Address: "198.51.100.7", Port: 8443, Password: testPassword,
		Network: "tcp", Security: "tls", SNI: "trojan.example.com",
	}
}

func vmessGRPC() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "vmess", Name: "vmess grpc", Address: "2001:db8::7", Port: 443, ID: testUUID,
		Network: "grpc", Security: "tls", SNI: "grpc.example.com", Fingerprint: "safari", ALPN: "h2",
		ServiceName: "grpc-service", Mode: "multi",
	}
}

func shadowsocks() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "shadowsocks", Name: "ss", Address: "ss.example.com", Port: 8388,
		Method: "chacha20-ietf-poly1305", Password: testPassword, Network: "tcp", Security: "none",
	}
}

func shadowsocks2022() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "shadowsocks", Name: "ss 2022", Address: "203.0.113.20", Port: 8389,
		Method: "2022-blake3-aes-128-gcm", Password: ss2022Key, Network: "tcp", Security: "none",
	}
}

func vlessXHTTP() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "vless", Name: "xhttp", Address: "xhttp.example.com", Port: 443, ID: testUUID,
		Network: "xhttp", Security: "tls", SNI: "xhttp.example.com", Fingerprint: "chrome",
		Path: "/xh", Host: "xhttp.example.com", Mode: "packet-up",
		Extra: `{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32","cMaxReuseTimes":"64-128"},"noGRPCHeader":false}`,
	}
}

func vlessHTTPUpgrade() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "vless", Name: "httpupgrade", Address: "hu.example.com", Port: 80, ID: "short-id-text",
		Network: "httpupgrade", Security: "none", Path: "/hu", Host: "hu.example.com",
	}
}

func warpAccount() *warp.Account {
	return &warp.Account{
		PrivateKey: wgPrivate, PeerPublicKey: wgPeer, Endpoint: "warp.example.com:2408",
		AddrV4: "198.51.100.2", AddrV6: "2001:db8:110::2", Reserved: [3]byte{171, 1, 254},
		ID: "device-id", Token: "device-token",
	}
}

func instance(kind nodev1.EgressKind, members ...providers.Member) providers.Instance {
	return providers.Instance{
		EgressID:    "01J9ZZ0000000000000000EGRS",
		Generation:  3,
		Kind:        kind,
		Members:     members,
		InstanceDir: "/opt/postern/data/instances/egr-01J9ZZ0000000000000000EGRS-g3",
		BinaryPath:  "/opt/postern/data/artifacts/xray/v26.3.27/amd64/xray",
		RunnerImage: runnerImage,
	}
}

func uri(s *egressuri.Server) providers.Instance {
	return instance(nodev1.EgressKind_EGRESS_KIND_XRAY_URI, providers.Member{Key: "0123456789ab", Port: 35001, Server: s}) // gitleaks:allow (a member key, not a secret)
}

// goldenCases are the instances of the golden files, by file name.
func goldenCases() map[string]providers.Instance {
	return map[string]providers.Instance{
		"vless-reality-vision.json": uri(vlessRealityVision()),
		"vless-ws-tls.json":         uri(vlessWSTLS()),
		"trojan.json":               uri(trojanTLS()),
		"vmess-grpc.json":           uri(vmessGRPC()),
		"ss.json":                   uri(shadowsocks()),
		"warp-wireguard.json": instance(nodev1.EgressKind_EGRESS_KIND_WARP,
			providers.Member{Key: "warp", Port: 35002, WARP: warpAccount()}),
		"subscription.json": instance(nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
			providers.Member{Key: "aaaaaaaaaaaa", Port: 35010, Server: vlessXHTTP()},
			providers.Member{Key: "bbbbbbbbbbbb", Port: 35011, Server: vlessHTTPUpgrade()},
			providers.Member{Key: "cccccccccccc", Port: 35012, Server: shadowsocks2022()},
		),
	}
}

func render(t *testing.T, in providers.Instance) []byte {
	t.Helper()
	files, err := Driver{}.Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files["config.json"] == nil {
		t.Fatalf("Render returned %v, want config.json only", slices.Sorted(maps.Keys(files)))
	}
	return files["config.json"]
}

// ---- golden -------------------------------------------------------------------

func TestRenderGolden(t *testing.T) {
	for name, in := range goldenCases() {
		t.Run(name, func(t *testing.T) {
			got := render(t, in)
			path := filepath.Join("testdata", name)
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("the rendered config differs from %s (run with -update to accept a change):\ngot:\n%s", path, got)
			}
		})
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	for name, in := range goldenCases() {
		if a, b := render(t, in), render(t, in); !bytes.Equal(a, b) {
			t.Errorf("%s: two renders differ", name)
		}
	}
}

// decoded is a rendered config as plain JSON values.
func decoded(t *testing.T, cfg []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(cfg, &m); err != nil {
		t.Fatalf("the config is not JSON: %v", err)
	}
	return m
}

// The frame of every config: quiet logs, one loopback SOCKS inbound per member
// routed to its own outbound, a blackhole as the default outbound, no rule that
// needs data files.
func TestRenderFrame(t *testing.T) {
	in := goldenCases()["subscription.json"]
	m := decoded(t, render(t, in))
	if got := fmt.Sprint(m["log"]); got != "map[access:none loglevel:warning]" {
		t.Errorf("log = %s", got)
	}
	inbounds := m["inbounds"].([]any)
	outbounds := m["outbounds"].([]any)
	rules := m["routing"].(map[string]any)["rules"].([]any)
	if len(inbounds) != 3 || len(outbounds) != 4 || len(rules) != 3 {
		t.Fatalf("%d inbounds, %d outbounds, %d rules, want 3, 4 (with the default), 3", len(inbounds), len(outbounds), len(rules))
	}
	if first := outbounds[0].(map[string]any); first["protocol"] != "blackhole" || first["tag"] != "block" {
		t.Errorf("the first (default) outbound is %v, want the blackhole", first)
	}
	for i, mem := range in.Members {
		ib := inbounds[i].(map[string]any)
		want := map[string]any{
			"tag": "in-" + mem.Key, "listen": "127.0.0.1", "port": float64(mem.Port), "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": false},
		}
		if !reflect.DeepEqual(ib, want) {
			t.Errorf("inbound %d = %v, want %v", i, ib, want)
		}
		if tag := outbounds[i+1].(map[string]any)["tag"]; tag != "out-"+mem.Key {
			t.Errorf("outbound %d has tag %v, want out-%s", i+1, tag, mem.Key)
		}
		rule := rules[i].(map[string]any)
		wantRule := map[string]any{"inboundTag": []any{"in-" + mem.Key}, "outboundTag": "out-" + mem.Key}
		if !reflect.DeepEqual(rule, wantRule) {
			t.Errorf("rule %d = %v, want %v", i, rule, wantRule)
		}
	}
	if s := string(render(t, in)); strings.Contains(s, "geoip") || strings.Contains(s, "geosite") {
		t.Error("the config refers to geo data files")
	}
}

// ---- refused members ----------------------------------------------------------

// secretsOf are the credentials a server or an account holds, which no error may
// repeat.
func secretsOf(s *egressuri.Server) []string {
	var out []string
	for _, v := range []string{s.ID, s.Password, s.PublicKey, s.ShortID} {
		if len(v) >= 4 {
			out = append(out, v)
		}
	}
	return out
}

func TestRenderRefusesBadMembers(t *testing.T) {
	type mutate func(s *egressuri.Server)
	extra := func(e string) mutate { return func(s *egressuri.Server) { s.Extra = e } }
	tests := []struct {
		name  string
		base  func() *egressuri.Server
		edit  mutate
		field string
	}{
		// The address of the server (the ruling on member addresses).
		{"loopback v4", vlessRealityVision, func(s *egressuri.Server) { s.Address = "127.0.0.1" }, "address"},
		{"loopback v6", trojanTLS, func(s *egressuri.Server) { s.Address = "::1" }, "address"},
		{"unspecified", shadowsocks, func(s *egressuri.Server) { s.Address = "0.0.0.0" }, "address"},
		{"metadata", vmessGRPC, func(s *egressuri.Server) { s.Address = "169.254.169.254" }, "address"},
		{"link-local v6", vmessGRPC, func(s *egressuri.Server) { s.Address = "fe80::1" }, "address"},
		{"multicast", shadowsocks, func(s *egressuri.Server) { s.Address = "224.0.0.251" }, "address"},
		{"mapped loopback", vlessWSTLS, func(s *egressuri.Server) { s.Address = "::ffff:127.0.0.1" }, "address"},
		{"localhost", vlessWSTLS, func(s *egressuri.Server) { s.Address = "localhost" }, "address"},
		{"no port", trojanTLS, func(s *egressuri.Server) { s.Port = 0 }, "port"},

		// The protocol and its credentials.
		{"unknown protocol", vlessWSTLS, func(s *egressuri.Server) { s.Protocol = "hysteria2" }, "protocol"},
		{"vless id of 31 bytes", vlessWSTLS, func(s *egressuri.Server) { s.ID = strings.Repeat("a", 31) }, "id"},
		{"vless id of 37 bytes", vlessWSTLS, func(s *egressuri.Server) { s.ID = testUUID + "0" }, "id"},
		{"vless id not hex", vlessWSTLS, func(s *egressuri.Server) { s.ID = "zzzzzzzz-2222-3333-4444-555555555555" }, "id"},
		{"vless id empty", vlessWSTLS, func(s *egressuri.Server) { s.ID = "" }, "id"},
		{"vmess id bad", vmessGRPC, func(s *egressuri.Server) { s.ID = "11111111-2222-3333-4444-55555555555" + "x" }, "id"},
		{"flow of old xtls", vlessRealityVision, func(s *egressuri.Server) { s.Flow = "xtls-rprx-direct" }, "flow"},
		{"flow in caps", vlessRealityVision, func(s *egressuri.Server) { s.Flow = "XTLS-RPRX-VISION" }, "flow"},
		{"flow on trojan", trojanTLS, func(s *egressuri.Server) { s.Flow = "xtls-rprx-vision" }, "flow"},
		{"trojan without password", trojanTLS, func(s *egressuri.Server) { s.Password = "" }, "password"},
		{"ss method unknown", shadowsocks, func(s *egressuri.Server) { s.Method = "aes-256-cfb" }, "method"},
		{"ss method empty", shadowsocks, func(s *egressuri.Server) { s.Method = "" }, "method"},
		{"ss without password", shadowsocks, func(s *egressuri.Server) { s.Password = "" }, "password"},
		{"ss 2022 key not base64", shadowsocks2022, func(s *egressuri.Server) { s.Password = "not base64!" }, "password"},
		{"ss 2022 key short", shadowsocks2022, func(s *egressuri.Server) { s.Password = b64(15) }, "password"},
		{"ss 2022 256 key of 16 bytes", shadowsocks2022, func(s *egressuri.Server) { s.Method = "2022-blake3-aes-256-gcm" }, "password"},
		{"ss 2022 key unpadded", shadowsocks2022, func(s *egressuri.Server) { s.Password = strings.TrimRight(b64(16), "=") }, "password"},
		{"ss 2022 empty second key", shadowsocks2022, func(s *egressuri.Server) { s.Password = b64(16) + ":" }, "password"},
		{"ss 2022 chacha with two keys", shadowsocks2022, func(s *egressuri.Server) {
			s.Method = "2022-blake3-chacha20-poly1305"
			s.Password = b64(32) + ":" + b64(32)
		}, "password"},

		// Transport and security.
		{"unknown network", vlessWSTLS, func(s *egressuri.Server) { s.Network = "kcp" }, "type"},
		{"unknown security", vlessWSTLS, func(s *egressuri.Server) { s.Security = "xtls" }, "security"},
		{"reality over ws", vlessRealityVision, func(s *egressuri.Server) { s.Network = "ws" }, "security"},
		{"reality over httpupgrade", vlessRealityVision, func(s *egressuri.Server) { s.Network = "httpupgrade" }, "security"},
		{"tls fingerprint unknown", vlessWSTLS, func(s *egressuri.Server) { s.Fingerprint = "chrome_999" }, "fp"},
		{"reality fingerprint unsafe", vlessRealityVision, func(s *egressuri.Server) { s.Fingerprint = "unsafe" }, "fp"},
		{"reality fingerprint golang", vlessRealityVision, func(s *egressuri.Server) { s.Fingerprint = "hellogolang" }, "fp"},
		{"reality key missing", vlessRealityVision, func(s *egressuri.Server) { s.PublicKey = "" }, "pbk"},
		{"reality key std base64", vlessRealityVision, func(s *egressuri.Server) {
			s.PublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))
		}, "pbk"},
		{"reality key short", vlessRealityVision, func(s *egressuri.Server) {
			s.PublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 31))
		}, "pbk"},
		{"short id too long", vlessRealityVision, func(s *egressuri.Server) { s.ShortID = "0123456789abcdef01" }, "sid"},
		{"short id odd", vlessRealityVision, func(s *egressuri.Server) { s.ShortID = "abc" }, "sid"},
		{"short id not hex", vlessRealityVision, func(s *egressuri.Server) { s.ShortID = "zz" }, "sid"},
		{"spider x without a slash", vlessRealityVision, func(s *egressuri.Server) { s.SpiderX = "index.html" }, "spx"},
		// url.Parse refuses these, and Xray panics on them (u.Query() of a nil URL).
		{"spider x with a bad escape", vlessRealityVision, func(s *egressuri.Server) { s.SpiderX = "/%zz" }, "spx"},
		{"spider x with a bad port", vlessRealityVision, func(s *egressuri.Server) { s.SpiderX = "//x:y/" }, "spx"},
		{"alpn with an empty entry", vlessWSTLS, func(s *egressuri.Server) { s.ALPN = "h2,,http/1.1" }, "alpn"},
		{"alpn too long", vlessWSTLS, func(s *egressuri.Server) { s.ALPN = strings.Repeat("a", 256) }, "alpn"},
		{"grpc mode unknown", vmessGRPC, func(s *egressuri.Server) { s.Mode = "guna" }, "mode"},
		{"xhttp mode unknown", vlessXHTTP, func(s *egressuri.Server) { s.Mode = "stream-two" }, "mode"},

		// The xhttp extra, which Xray decodes on its own.
		{"extra not an object", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `[1,2]` }, "extra"},
		{"extra of a wrong type", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"noGRPCHeader":"yes"}` }, "extra"},
		{"extra range not a range", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"xPaddingBytes":"a-b"}` }, "extra"},
		{"extra range of a bool", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"xmux":{"maxConcurrency":true}}` }, "extra"},
		{"extra header host", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"headers":{"Host":"x.example.com"}}` }, "extra"},
		{"extra headers not strings", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"headers":{"X-A":1}}` }, "extra"},
		{"extra padding off", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"xPaddingBytes":"0-100"}` }, "extra"},
		{"extra xmux both limits", vlessXHTTP, func(s *egressuri.Server) {
			s.Extra = `{"xmux":{"maxConcurrency":"4","maxConnections":"2"}}`
		}, "extra"},
		{"extra max header bytes negative", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"serverMaxHeaderBytes":-1}` }, "extra"},
		{"extra padding placement", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"xPaddingPlacement":"body"}` }, "extra"},
		{"extra padding method", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"xPaddingMethod":"zeros"}` }, "extra"},
		{"extra session placement", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"sessionPlacement":"body"}` }, "extra"},
		{"extra seq placement", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"seqPlacement":"body"}` }, "extra"},
		{"extra GET uplink outside packet-up", vlessXHTTP, func(s *egressuri.Server) {
			s.Mode, s.Extra = "stream-up", `{"uplinkHTTPMethod":"GET"}`
		}, "extra"},
		{"extra download in stream-one", vlessXHTTP, func(s *egressuri.Server) {
			s.Mode, s.Extra = "stream-one", `{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp"}}`
		}, "extra"},
		{"extra download to the loopback", vlessXHTTP, func(s *egressuri.Server) {
			s.Extra = `{"downloadSettings":{"address":"127.0.0.1","port":8080,"network":"xhttp"}}`
		}, "extra"},
		{"extra download to localhost", vlessXHTTP, func(s *egressuri.Server) {
			s.Extra = `{"downloadSettings":{"address":"localhost","port":8080,"network":"xhttp"}}`
		}, "extra"},
		{"extra download insecure", vlessXHTTP, func(s *egressuri.Server) {
			s.Extra = `{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"allowInsecure":true}}}`
		}, "extra"},
		{"extra download reality without key", vlessXHTTP, func(s *egressuri.Server) {
			s.Extra = `{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"reality","realitySettings":{"serverName":"a.example.com"}}}`
		}, "extra"},
		{"extra download unknown network", vlessXHTTP, func(s *egressuri.Server) {
			s.Extra = `{"downloadSettings":{"address":"dl.example.com","port":443,"network":"quic"}}`
		}, "extra"},
		{"extra download port of a string", vlessXHTTP, func(s *egressuri.Server) {
			s.Extra = `{"downloadSettings":{"address":"dl.example.com","port":"443","network":"xhttp"}}`
		}, "extra"},
		{"extra download not an object", vlessXHTTP, func(s *egressuri.Server) { s.Extra = `{"downloadSettings":"dl.example.com"}` }, "extra"},

		// Xray takes these at load and panics at the first dial through the
		// member: the download needs an address, and XHTTP.
		{"extra download without an address", vlessXHTTP, extra(`{"downloadSettings":{"port":443,"network":"xhttp"}}`), "extra"},
		{"extra download with an empty address", vlessXHTTP, extra(`{"downloadSettings":{"address":"","port":443,"network":"xhttp"}}`), "extra"},
		{"extra download without a network", vlessXHTTP, extra(`{"downloadSettings":{"address":"dl.example.com","port":443}}`), "extra"},
		{"extra download over ws", vlessXHTTP, extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"ws"}}`), "extra"},
		{"extra download over raw", vlessXHTTP, extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"raw"}}`), "extra"},
		{"extra download without a port", vlessXHTTP, extra(`{"downloadSettings":{"address":"dl.example.com","network":"xhttp"}}`), "extra"},

		// The download is an allowlist: what it does not check is refused.
		{"extra download with sockopt", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","sockopt":{"dialerProxy":"out-x"}}}`), "extra"},
		{"extra download with a finalmask", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","finalmask":{"udp":[{"type":"noise"}]}}}`), "extra"},
		{"extra download with a sockopt of another type", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","sockopt":[]}}`), "extra"},
		{"extra download with ws settings", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","wsSettings":{"path":"/"}}}`), "extra"},
		{"extra download tls with a key log", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"masterKeyLog":"/tmp/k"}}}`), "extra"},
		{"extra download tls with an empty alpn", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"alpn":["h2",""]}}}`), "extra"},
		{"extra download reality with mldsa65", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"reality","realitySettings":{"publicKey":"` + realityKey + `","mldsa65Verify":"AAAA"}}}`), "extra"},
		{"extra download reality spider unparseable", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"reality","realitySettings":{"publicKey":"` + realityKey + `","spiderX":"/%zz"}}}`), "extra"},
		{"extra download xhttp with its own extra", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","xhttpSettings":{"extra":{"noGRPCHeader":true}}}}`), "extra"},
		{"extra download xhttp with its own download", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","xhttpSettings":{"downloadSettings":{}}}}`), "extra"},
		{"extra download xhttp mode unknown", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","xhttpSettings":{"mode":"Auto"}}}`), "extra"},
		{"extra download xhttp header host", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","xhttpSettings":{"headers":{"HOST":"a.example.com"}}}}`), "extra"},
		{"extra download xhttp of a wrong type", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","xhttpSettings":{"noSSEHeader":1}}}`), "extra"},
		{"extra download xhttp GET outside packet-up", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","xhttpSettings":{"uplinkHTTPMethod":"GET"}}}`), "extra"},
		{"extra download from an environment variable", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"env:HOSTNAME","port":443,"network":"xhttp"}}`), "extra"},
		{"extra download to a bracketed loopback with spaces", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"[ 127.0.0.1 ]","port":443,"network":"xhttp"}}`), "extra"},
		{"extra download to the Alibaba metadata", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"100.100.100.200","port":80,"network":"xhttp"}}`), "extra"},
		{"extra download to the Azure wire server", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"168.63.129.16","port":80,"network":"xhttp"}}`), "extra"},
		// Names to Xray, dialed as "<name>:<port>", and Go's dialer takes the
		// brackets off.
		{"extra download to a spaced, bracketed loopback", vlessXHTTP,
			extra(`{"downloadSettings":{"address":" [127.0.0.1]","port":443,"network":"xhttp"}}`), "extra"},
		{"extra download to a doubly bracketed loopback", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"[[::1]]","port":443,"network":"xhttp"}}`), "extra"},
		{"extra download to a bracketed metadata address", vlessXHTTP,
			extra(`{"downloadSettings":{"address":" [169.254.169.254]","port":80,"network":"xhttp"}}`), "extra"},

		// A key twice, in any case: Xray merges what each brings, a check of one
		// would not see the other.
		{"extra download twice", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","sockopt":{"dialerProxy":"out-x"}},` +
				`"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp"}}`), "extra"},
		{"extra download in another case", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","sockopt":{"dialerProxy":"out-x"}},` +
				`"DownloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp"}}`), "extra"},
		{"extra download with a long s", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","sockopt":{"dialerProxy":"out-x"}},` +
				`"downloadſettings":{"address":"dl.example.com","port":443,"network":"xhttp"}}`), "extra"},
		{"extra download address twice", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp","ADDRESS":"dl.example.com"}}`), "extra"},
		{"extra header names in two cases", vlessXHTTP, extra(`{"headers":{"X-A":"1","x-a":"2"}}`), "extra"},
		{"extra xmux key twice", vlessXHTTP, extra(`{"xmux":{"maxConcurrency":"4","maxconcurrency":"8"}}`), "extra"},

		// Xray decodes the extra's own host, path and mode, and refuses the whole
		// config when one is not a string.
		{"extra host of a wrong type", vlessXHTTP, extra(`{"host":1}`), "extra"},
		{"extra path of a wrong type", vlessXHTTP, extra(`{"path":["/a"]}`), "extra"},
		{"extra mode of a wrong type", vlessXHTTP, extra(`{"mode":true}`), "extra"},
		{"extra uplink data placement unknown", vlessXHTTP, extra(`{"uplinkDataPlacement":"query"}`), "extra"},
		{"extra download splithttp mode unknown", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"splithttp","splithttpSettings":{"mode":"bogus"}}}`), "extra"},
		{"extra download splithttp with its own extra", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"splithttp","splithttpSettings":{"extra":{}}}}`), "extra"},
		{"extra download reality show of a wrong type", vlessXHTTP,
			extra(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"reality","realitySettings":{"show":"yes","publicKey":"` + realityKey + `"}}}`), "extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.base()
			tt.edit(s)
			in := instance(nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
				providers.Member{Key: "good00000000", Port: 35001, Server: trojanTLS()},
				providers.Member{Key: "bad000000000", Port: 35002, Server: s},
			)
			files, err := Driver{}.Render(in)
			if err == nil {
				t.Fatalf("Render accepted it:\n%s", files["config.json"])
			}
			mes := providers.MemberErrors(err)
			if len(mes) != 1 {
				t.Fatalf("Render = %v, want one member error", err)
			}
			if mes[0].Key != "bad000000000" || mes[0].Field != tt.field {
				t.Errorf("member error for %s, field %s, want bad000000000, %s (%v)", mes[0].Key, mes[0].Field, tt.field, err)
			}
			for _, secret := range secretsOf(s) {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the error repeats a credential: %v", err)
				}
			}
		})
	}
}

func b64(n int) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, n)) }

// Every bad member is reported, not only the first.
func TestRenderReportsEveryBadMember(t *testing.T) {
	bad1, bad2 := vlessWSTLS(), shadowsocks()
	bad1.Fingerprint = "nope"
	bad2.Method = "rc4-md5"
	in := instance(nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION,
		providers.Member{Key: "one", Port: 35001, Server: bad1},
		providers.Member{Key: "two", Port: 35002, Server: trojanTLS()},
		providers.Member{Key: "three", Port: 35003, Server: bad2},
	)
	_, err := Driver{}.Render(in)
	var keys []string
	for _, me := range providers.MemberErrors(err) {
		keys = append(keys, me.Key+"/"+me.Field)
	}
	if fmt.Sprint(keys) != "[one/fp three/method]" {
		t.Errorf("member errors %v (%v), want one/fp and three/method", keys, err)
	}
}

// A WARP account the driver cannot use.
func TestRenderRefusesBadWARPAccounts(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(a *warp.Account)
		field string
	}{
		{"endpoint on the loopback", func(a *warp.Account) { a.Endpoint = "127.0.0.1:2408" }, "endpoint"},
		{"endpoint on localhost", func(a *warp.Account) { a.Endpoint = "localhost:2408" }, "endpoint"},
		{"endpoint link-local v6", func(a *warp.Account) { a.Endpoint = "[fe80::1]:2408" }, "endpoint"},
		{"private key missing", func(a *warp.Account) { a.PrivateKey = "" }, "account"},
		{"peer key short", func(a *warp.Account) { a.PeerPublicKey = b64(16) }, "account"},
		{"v4 address bad", func(a *warp.Account) { a.AddrV4 = "nope" }, "account"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := warpAccount()
			tt.edit(a)
			in := instance(nodev1.EgressKind_EGRESS_KIND_WARP, providers.Member{Key: "warp", Port: 35002, WARP: a})
			_, err := Driver{}.Render(in)
			mes := providers.MemberErrors(err)
			if len(mes) != 1 || mes[0].Key != "warp" || mes[0].Field != tt.field {
				t.Fatalf("Render = %v, want a member error on %s", err, tt.field)
			}
			for _, secret := range []string{a.PrivateKey, a.Token} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Errorf("the error repeats a credential: %v", err)
				}
			}
		})
	}
}

// An instance that does not fit its kind is the agent's mistake: a plain error.
func TestRenderRefusesBadInstances(t *testing.T) {
	m := func(key string, port uint16, s *egressuri.Server) providers.Member {
		return providers.Member{Key: key, Port: port, Server: s}
	}
	w := providers.Member{Key: "warp", Port: 35002, WARP: warpAccount()}
	both := providers.Member{Key: "both", Port: 35003, Server: trojanTLS(), WARP: warpAccount()}
	tests := map[string]providers.Instance{
		"psiphon":                instance(nodev1.EgressKind_EGRESS_KIND_PSIPHON, m("a", 35001, trojanTLS())),
		"socks5":                 instance(nodev1.EgressKind_EGRESS_KIND_SOCKS5, m("a", 35001, trojanTLS())),
		"unspecified":            instance(nodev1.EgressKind_EGRESS_KIND_UNSPECIFIED, m("a", 35001, trojanTLS())),
		"uri with two members":   instance(nodev1.EgressKind_EGRESS_KIND_XRAY_URI, m("a", 35001, trojanTLS()), m("b", 35002, trojanTLS())),
		"uri without a server":   instance(nodev1.EgressKind_EGRESS_KIND_XRAY_URI, providers.Member{Key: "a", Port: 35001}),
		"uri with an account":    instance(nodev1.EgressKind_EGRESS_KIND_XRAY_URI, w),
		"uri with both":          instance(nodev1.EgressKind_EGRESS_KIND_XRAY_URI, both),
		"subscription with warp": instance(nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, m("a", 35001, trojanTLS()), w),
		"warp with a server":     instance(nodev1.EgressKind_EGRESS_KIND_WARP, m("a", 35001, trojanTLS())),
		"warp with both":         instance(nodev1.EgressKind_EGRESS_KIND_WARP, both),
		"warp twice":             instance(nodev1.EgressKind_EGRESS_KIND_WARP, w, providers.Member{Key: "warp2", Port: 35003, WARP: warpAccount()}),
		"no members":             instance(nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION),
		"port out of range":      instance(nodev1.EgressKind_EGRESS_KIND_XRAY_URI, m("a", 20001, trojanTLS())),
		"duplicate keys":         instance(nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, m("a", 35001, trojanTLS()), m("a", 35002, trojanTLS())),
		"bad key":                instance(nodev1.EgressKind_EGRESS_KIND_XRAY_URI, m("a b", 35001, trojanTLS())),
	}
	badID := uri(trojanTLS())
	badID.EgressID = "../x"
	tests["bad egress id"] = badID
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Driver{}.Render(in)
			if err == nil {
				t.Fatal("Render accepted it")
			}
			if mes := providers.MemberErrors(err); len(mes) != 0 {
				t.Errorf("Render = %v: a member error for a mistake of the instance", err)
			}
		})
	}
}

// ---- accepted values ------------------------------------------------------------

// outboundOf renders a one-member instance and returns its outbound.
func outboundOf(t *testing.T, s *egressuri.Server) map[string]any {
	t.Helper()
	m := decoded(t, render(t, uri(s)))
	return m["outbounds"].([]any)[1].(map[string]any)
}

func streamOf(t *testing.T, s *egressuri.Server) map[string]any {
	t.Helper()
	return outboundOf(t, s)["streamSettings"].(map[string]any)
}

func TestRenderAcceptsWhatXrayAccepts(t *testing.T) {
	t.Run("tls fingerprints", func(t *testing.T) {
		for _, fp := range append(slices.Clone(Fingerprints()), "unsafe", "Chrome", "HelloChrome_Auto") {
			s := vlessWSTLS()
			s.Fingerprint = fp
			if got := streamOf(t, s)["tlsSettings"].(map[string]any)["fingerprint"]; got != strings.ToLower(fp) {
				t.Errorf("fp %q: rendered %v", fp, got)
			}
		}
	})
	t.Run("reality fingerprints", func(t *testing.T) {
		for _, fp := range Fingerprints() {
			if fp == "hellogolang" {
				continue
			}
			s := vlessRealityVision()
			s.Fingerprint = fp
			if got := streamOf(t, s)["realitySettings"].(map[string]any)["fingerprint"]; got != fp {
				t.Errorf("fp %q: rendered %v", fp, got)
			}
		}
	})
	t.Run("no fingerprint is chrome", func(t *testing.T) {
		s := vlessRealityVision()
		s.Fingerprint = ""
		if got := streamOf(t, s)["realitySettings"].(map[string]any)["fingerprint"]; got != "chrome" {
			t.Errorf("reality: %v", got)
		}
		s = vlessWSTLS()
		s.Fingerprint = ""
		if got := streamOf(t, s)["tlsSettings"].(map[string]any)["fingerprint"]; got != "chrome" {
			t.Errorf("tls: %v", got)
		}
	})
	t.Run("flows", func(t *testing.T) {
		for _, flow := range []string{"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"} {
			s := vlessRealityVision()
			s.Flow = flow
			user := outboundOf(t, s)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
			if got, _ := user["flow"].(string); got != flow {
				t.Errorf("flow %q rendered as %q", flow, got)
			}
			if user["encryption"] != "none" {
				t.Errorf("encryption %v", user["encryption"])
			}
		}
	})
	t.Run("ids", func(t *testing.T) {
		for _, id := range []string{
			testUUID, strings.ToUpper(testUUID), strings.ReplaceAll(testUUID, "-", ""),
			"11111111-22223333-4444-555555555555", "a", strings.Repeat("x", 30), "пароль",
			strings.ReplaceAll(testUUID, "-", "") + "zzzz", // Xray reads five groups and ignores what follows
		} {
			s := vlessWSTLS()
			s.ID = id
			user := outboundOf(t, s)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
			if user["id"] != id {
				t.Errorf("id %q rendered as %v", id, user["id"])
			}
		}
	})
	t.Run("shadowsocks methods", func(t *testing.T) {
		for in, want := range map[string]string{
			"aes-128-gcm": "aes-128-gcm", "AEAD_AES_128_GCM": "aead_aes_128_gcm", "aes-256-gcm": "aes-256-gcm",
			"aead_aes_256_gcm": "aead_aes_256_gcm", "chacha20-poly1305": "chacha20-poly1305",
			"aead_chacha20_poly1305": "aead_chacha20_poly1305", "chacha20-ietf-poly1305": "chacha20-ietf-poly1305",
			"xchacha20-poly1305": "xchacha20-poly1305", "aead_xchacha20_poly1305": "aead_xchacha20_poly1305",
			"xchacha20-ietf-poly1305": "xchacha20-ietf-poly1305", "none": "none", "plain": "plain",
		} {
			s := shadowsocks()
			s.Method = in
			srv := outboundOf(t, s)["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if srv["method"] != want {
				t.Errorf("method %q rendered as %v, want %q", in, srv["method"], want)
			}
		}
		for method, key := range map[string]string{
			"2022-blake3-aes-128-gcm":       b64(16),
			"2022-BLAKE3-AES-256-GCM":       b64(32),
			"2022-blake3-chacha20-poly1305": b64(32),
		} {
			s := shadowsocks2022()
			s.Method, s.Password = method, key
			srv := outboundOf(t, s)["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if srv["method"] != strings.ToLower(method) {
				t.Errorf("method %q rendered as %v", method, srv["method"])
			}
		}
		// Longer keys are derived, several keys are an identity chain.
		for _, key := range []string{b64(17), b64(16) + ":" + b64(16), b64(32) + ":" + b64(16) + ":" + b64(64)} {
			s := shadowsocks2022()
			s.Password = key
			outboundOf(t, s)
		}
	})
	t.Run("vmess security", func(t *testing.T) {
		for in, want := range map[string]string{
			"": "auto", "auto": "auto", "AES-128-GCM": "aes-128-gcm", "chacha20-poly1305": "chacha20-poly1305",
			"none": "none", "zero": "zero", "aes-256-cfb": "auto", // Xray takes anything else for auto
		} {
			s := vmessGRPC()
			s.Method = in
			user := outboundOf(t, s)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
			if user["security"] != want {
				t.Errorf("scy %q rendered as %v, want %s", in, user["security"], want)
			}
		}
	})
	t.Run("transports", func(t *testing.T) {
		for in, want := range map[string]string{"tcp": "raw", "ws": "ws", "grpc": "grpc", "xhttp": "xhttp", "httpupgrade": "httpupgrade"} {
			s := vlessWSTLS()
			s.Network = in
			if s.Network != "ws" {
				s.Path, s.Host = "", ""
			}
			if got := streamOf(t, s)["network"]; got != want {
				t.Errorf("network %q rendered as %v", in, got)
			}
		}
		for _, mode := range []string{"", "gun", "GUN"} {
			s := vmessGRPC()
			s.Mode = mode
			if _, set := streamOf(t, s)["grpcSettings"].(map[string]any)["multiMode"]; set {
				t.Errorf("grpc mode %q sets multiMode", mode)
			}
		}
		if streamOf(t, vmessGRPC())["grpcSettings"].(map[string]any)["multiMode"] != true {
			t.Error("grpc mode multi is not multiMode")
		}
		for _, mode := range []string{"", "auto", "packet-up", "stream-up", "stream-one", "Stream-Up"} {
			s := vlessXHTTP()
			s.Mode, s.Extra = mode, ""
			got, _ := streamOf(t, s)["xhttpSettings"].(map[string]any)["mode"].(string)
			if got != strings.ToLower(mode) {
				t.Errorf("xhttp mode %q rendered as %q", mode, got)
			}
		}
		for _, net := range []string{"tcp", "grpc", "xhttp"} {
			s := vlessRealityVision()
			s.Network = net
			streamOf(t, s) // reality over each of them is fine
		}
	})
	t.Run("reality short ids and spider", func(t *testing.T) {
		for _, sid := range []string{"", "ab", "0123456789abcdef", "ABCDEF"} {
			s := vlessRealityVision()
			s.ShortID = sid
			got, _ := streamOf(t, s)["realitySettings"].(map[string]any)["shortId"].(string)
			if got != sid {
				t.Errorf("sid %q rendered as %q", sid, got)
			}
		}
		for _, spx := range []string{"", "/", "/a/b?c=d&e=f"} {
			s := vlessRealityVision()
			s.SpiderX = spx
			got, _ := streamOf(t, s)["realitySettings"].(map[string]any)["spiderX"].(string)
			if got != spx {
				t.Errorf("spx %q rendered as %q", spx, got)
			}
		}
	})
	t.Run("alpn", func(t *testing.T) {
		for in, want := range map[string]string{"h2": "[h2]", "h2,http/1.1": "[h2 http/1.1]", " h2 , http/1.1 ": "[h2 http/1.1]", "": "<nil>"} {
			s := vlessWSTLS()
			s.ALPN = in
			if got := fmt.Sprint(streamOf(t, s)["tlsSettings"].(map[string]any)["alpn"]); got != want {
				t.Errorf("alpn %q rendered as %s, want %s", in, got, want)
			}
		}
	})
	t.Run("extra", func(t *testing.T) {
		for _, extra := range []string{
			`{}`,
			`{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32","hKeepAlivePeriod":30}}`,
			`{"xPaddingBytes":200,"noSSEHeader":true,"scMaxEachPostBytes":"1000000","scMinPostsIntervalMs":"10-50"}`,
			`{"xmux":{"maxConnections":"4-8","cMaxReuseTimes":0}}`,
			`{"headers":{"X-Forwarded-For":"192.0.2.1"},"xPaddingPlacement":"header","xPaddingMethod":"tokenish"}`,
			`{"sessionPlacement":"cookie","seqPlacement":"query","uplinkHTTPMethod":"PUT"}`,
			`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"dl.example.com","fingerprint":"chrome","alpn":["h2"]},"xhttpSettings":{"path":"/dl"}}}`,
			`{"downloadSettings":{"address":"203.0.113.5","port":443,"network":"xhttp","security":"reality","realitySettings":{"serverName":"a.example.com","fingerprint":"firefox","password":"` + realityKey + `","shortId":"01"}}}`,
			`{"unknownFutureField":{"a":1},"extra":{"ignored":"by xray"}}`,
			`{"downloadSettings":null}`, // null is "not set", for Xray too
			`{"downloadSettings":{"address":"[2001:db8::5]","port":8443,"network":"SplitHTTP","security":"none","xhttpSettings":{"path":"/dl","mode":"stream-up","xmux":{"maxConnections":"2"}}}}`,
			`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","sockopt":{},"finalmask":null}}`,
			`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","sockopt":null,"finalmask":{ }}}`,
			`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"splithttp","splithttpSettings":{"path":"/dl","mode":"packet-up"}}}`,
			`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"dl.example.com","show":false}}}`,
			`{"downloadSettings":{"address":"203.0.113.5","port":443,"network":"xhttp","security":"reality","realitySettings":{"show":true,"serverName":"a.example.com","publicKey":"` + realityKey + `"}}}`,
			`{"uplinkDataPlacement":"body"}`,
			`{"uplinkDataPlacement":"auto","uplinkDataKey":"x"}`,
			`{"uplinkDataPlacement":"cookie"}`, // the link's mode is packet-up
			`{"host":"other.example.com","path":"/other","mode":"stream-one"}`,
		} {
			s := vlessXHTTP()
			s.Extra = extra
			got, err := json.Marshal(streamOf(t, s)["xhttpSettings"].(map[string]any)["extra"])
			if err != nil {
				t.Fatal(err)
			}
			var want any
			_ = json.Unmarshal([]byte(extra), &want)
			wantJSON, _ := json.Marshal(want)
			if !bytes.Equal(got, wantJSON) {
				t.Errorf("extra %s rendered as %s", extra, got)
			}
		}
		s := vlessXHTTP()
		s.Mode, s.Extra = "packet-up", `{"uplinkHTTPMethod":"GET"}`
		streamOf(t, s) // GET is fine in packet-up
	})
}

// A link that asks to skip the certificate check is rendered with the check:
// Xray v26.3.27 refuses a config with allowInsecure after 2026-06-01, and the
// member then works if its server's certificate verifies.
func TestAllowInsecureIsNotRendered(t *testing.T) {
	s := vlessWSTLS()
	s.AllowInsecure = true
	cfg := string(render(t, uri(s)))
	if strings.Contains(strings.ToLower(cfg), "insecure") {
		t.Errorf("the config asks for an insecure connection:\n%s", cfg)
	}
}

// Settings of other transports and of no security are left out.
func TestRenderLeavesOutWhatDoesNotApply(t *testing.T) {
	s := vlessHTTPUpgrade()
	s.SNI, s.Fingerprint, s.ALPN, s.PublicKey, s.ServiceName, s.Mode = "x.example.com", "chrome", "h2", realityKey, "svc", "multi"
	st := streamOf(t, s)
	keys := slices.Sorted(maps.Keys(st))
	if fmt.Sprint(keys) != "[httpupgradeSettings network security]" {
		t.Errorf("stream settings %v", st)
	}
}

// ---- container, artifact, readiness -------------------------------------------------

func TestContainer(t *testing.T) {
	in := uri(vlessWSTLS())
	got := Driver{}.Container(in)
	want := providers.ContainerSpec(in, providers.ContainerOptions{
		Binary: "xray", Args: []string{"run", "-c", "/etc/egress/config.json"}, MemoryBytes: 512 << 20,
	})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Container =\n%#v\nwant\n%#v", got, want)
	}
	// Spelled out, the parts that make the container what it is.
	if fmt.Sprint(got.Entrypoint) != "[/opt/engine/xray run -c /etc/egress/config.json]" {
		t.Errorf("Entrypoint %q", got.Entrypoint)
	}
	wantBinds := []string{
		"/opt/postern/data/artifacts/xray/v26.3.27/amd64/xray:/opt/engine/xray:ro",
		"/opt/postern/data/instances/egr-01J9ZZ0000000000000000EGRS-g3:/etc/egress:ro",
	}
	if !reflect.DeepEqual(got.Binds, wantBinds) {
		t.Errorf("Binds %q, want %q", got.Binds, wantBinds)
	}
	if got.User != "65534:65534" || !got.ReadOnly || fmt.Sprint(got.CapDrop) != "[ALL]" || got.NetworkMode != "host" {
		t.Errorf("not locked down: %#v", got)
	}
	if got.Name != "postern-egr-01j9zz0000000000000000egrs-g3" || got.Labels["postern.role"] != "egress" {
		t.Errorf("name %q, labels %v", got.Name, got.Labels)
	}

	in.ResolvConf = "/opt/postern/data/run/resolv.conf"
	got = Driver{}.Container(in)
	if last := got.Binds[len(got.Binds)-1]; last != "/opt/postern/data/run/resolv.conf:/etc/resolv.conf:ro" {
		t.Errorf("resolv.conf bind %q", last)
	}
}

func TestArtifactAndKinds(t *testing.T) {
	d := New()
	for arch, want := range map[string]string{"amd64": "Xray-linux-64.zip", "arm64": "Xray-linux-arm64-v8a.zip"} {
		if got, err := d.ArtifactFile(arch); err != nil || got != want {
			t.Errorf("ArtifactFile(%s) = %q, %v, want %q", arch, got, err, want)
		}
	}
	if _, err := d.ArtifactFile("riscv64"); err == nil {
		t.Error("ArtifactFile(riscv64) = nil error")
	}
	if d.BinaryName() != "xray" {
		t.Errorf("BinaryName = %q", d.BinaryName())
	}
	want := []nodev1.EgressKind{
		nodev1.EgressKind_EGRESS_KIND_XRAY_URI, nodev1.EgressKind_EGRESS_KIND_XRAY_SUBSCRIPTION, nodev1.EgressKind_EGRESS_KIND_WARP,
	}
	if !reflect.DeepEqual(d.Kinds(), want) {
		t.Errorf("Kinds = %v", d.Kinds())
	}
	var _ providers.Driver = d
}

func TestReady(t *testing.T) {
	// Ready is providers.CheckSOCKS; the failure modes are tested there. Here:
	// nothing listens, so it fails and names the member.
	in := uri(trojanTLS())
	in.Members[0].Port = closedPort(t)
	err := Driver{}.Ready(t.Context(), in)
	if err == nil || !strings.Contains(err.Error(), "0123456789ab") {
		t.Errorf("Ready = %v, want an error naming the member", err)
	}
}

// closedPort is a loopback port that nothing listens on: port 1, which no
// test can take (a port below 1024 needs root), so connecting is refused.
// (Ready does not care for the egress range.)
func closedPort(*testing.T) uint16 { return 1 }

// No reason of a member error repeats text of the link: a decode error's path
// holds the keys of the input, and an unknown field's error quotes it.
func TestExtraErrorsHoldNoLinkText(t *testing.T) {
	const marker = "Zq9\nInjected"
	for _, extra := range []string{
		`{"headers":{"` + "Zq9\\nInjected" + `":1}}`,
		`{"HEADERS":{"` + "Zq9\\nInjected" + `":true}}`,
		`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","` + "Zq9\\nInjected" + `":1}}`,
		`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","xhttpSettings":{"headers":{"` + "Zq9\\nInjected" + `":[1]}}}}`,
		`{"xmux":{"` + "Zq9\\nInjected" + `":1},"noGRPCHeader":"` + "Zq9\\nInjected" + `"}`,
	} {
		s := vlessXHTTP()
		s.Extra = extra
		_, err := Driver{}.Render(uri(s))
		mes := providers.MemberErrors(err)
		if len(mes) != 1 || mes[0].Field != "extra" {
			t.Fatalf("Render = %v, want a member error on extra", err)
		}
		for _, bad := range []string{"Zq9", "Injected", "\n"} {
			if strings.Contains(err.Error(), bad) {
				t.Errorf("extra %s: the error %q repeats %q", extra, err, bad)
			}
		}
		t.Logf("%s -> %s", strings.ReplaceAll(extra, marker, "…"), mes[0].Reason)
	}
}

func TestDuplicateKey(t *testing.T) {
	for text, want := range map[string]bool{
		`{}`: false,
		`{"a":1,"b":{"a":2},"c":[{"a":1},{"a":2}]}`: false, // the same key in other objects
		`{"a":{"x":1},"b":{"x":2}}`:                 false,
		`{"a":[1,{"b":2},[3]],"c":4}`:               false,
		`[{"a":1},{"a":1}]`:                         false, // two objects in an array
		`{"a":1,"a":2}`:                             true,
		`{"a":1,"A":2}`:                             true,
		`{"sockopt":1,"ſockopt":2}`:                 true, // ſ folds to S, as encoding/json takes it
		`{"k":1,"K":2}`:                             true, // the Kelvin sign folds to K
		`{"x":{"y":{"z":1,"Z":2}}}`:                 true,
		`{"x":[{"y":1,"y":2}]}`:                     true,
		`{"a":`:                                     true, // not JSON
		`{"a":1}{"b":2}`:                            false,
		`{"a":"b","b":"a"}`:                         false, // a value is not a key
		`{"a":{},"b":[],"a2":null}`:                 false,
	} {
		if got := duplicateKey([]byte(text)); got != want {
			t.Errorf("duplicateKey(%s) = %v, want %v", text, got, want)
		}
	}
	if foldKey("downloadſettings") != foldKey("DOWNLOADSETTINGS") {
		t.Error("foldKey does not fold the long s")
	}
}

func TestSafeFieldPath(t *testing.T) {
	for in, want := range map[string]string{
		"headers.X-A\nB":                    "headers",
		"HEADERS.k":                         "headers",
		"xmux.maxConcurrency":               "xmux.maxConcurrency",
		"XMUX.MAXCONNECTIONS":               "xmux.maxConnections",
		"noGRPCHeader":                      "noGRPCHeader",
		"tlsSettings.alpn":                  "tlsSettings.alpn",
		"xhttpSettings.headers.Evil.Deeper": "xhttpSettings.headers",
		"evil.headers":                      "",
		"port":                              "port",
		"list.1":                            "",
		"":                                  "",
	} {
		if got := safeFieldPath(in); got != want {
			t.Errorf("safeFieldPath(%q) = %q, want %q", in, got, want)
		}
	}
}
