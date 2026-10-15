//go:build integration

package providers_test

// TestIntegrationXray/configs: Xray v26.3.27 takes what the driver renders and
// refuses what the driver refuses (see integration_test.go).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/egressuri"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/xray"
)

// cfgCase is one config for `xray run -test`.
type cfgCase struct {
	name string
	data []byte
	ok   bool // Xray must take it
}

// Fake credentials, low in entropy on purpose. None of them is real.
const testUUID = "11111111-2222-3333-4444-555555555555"

// realityKey is 32 bytes of 0x11 in unpadded URL-safe base64.
const realityKey = "ERERERERERERERERERERERERERERERERERERERERERE"

func b64(n int) string { return stdB64(bytes.Repeat([]byte{0x5a}, n)) }

func stdB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func vlessWS() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "vless", Address: "cdn.example.com", Port: 443, ID: testUUID, Network: "ws", Security: "tls",
		SNI: "cdn.example.com", Fingerprint: "chrome", Path: "/ws", Host: "cdn.example.com",
	}
}

func vlessReality() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "vless", Address: "reality.example.com", Port: 443, ID: testUUID, Flow: "xtls-rprx-vision",
		Network: "tcp", Security: "reality", SNI: "www.example.com", Fingerprint: "chrome",
		PublicKey: realityKey, ShortID: "0123abcd", SpiderX: "/",
	}
}

func vlessXHTTP() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "vless", Address: "xhttp.example.com", Port: 443, ID: testUUID, Network: "xhttp", Security: "tls",
		SNI: "xhttp.example.com", Fingerprint: "chrome", Path: "/xh", Host: "xhttp.example.com", Mode: "packet-up",
	}
}

func trojan() *egressuri.Server {
	return &egressuri.Server{
		Protocol: "trojan", Address: "198.51.100.7", Port: 8443, Password: "pass-pass-pass", Network: "tcp", Security: "tls",
		SNI: "trojan.example.com",
	}
}

func ss(method, password string) *egressuri.Server {
	return &egressuri.Server{
		Protocol: "shadowsocks", Address: "ss.example.com", Port: 8388, Method: method, Password: password,
		Network: "tcp", Security: "none",
	}
}

func vmess(scy string) *egressuri.Server {
	return &egressuri.Server{
		Protocol: "vmess", Address: "vmess.example.com", Port: 443, ID: testUUID, Method: scy,
		Network: "grpc", Security: "tls", SNI: "vmess.example.com", ServiceName: "svc",
	}
}

func uriInstance(s *egressuri.Server) providers.Instance {
	return providers.Instance{
		EgressID: "ITEST", Generation: 1, Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_URI,
		Members: []providers.Member{{Key: "member", Port: 35001, Server: s}},
	}
}

// render renders s; the driver must take it.
func render(t *testing.T, s *egressuri.Server) []byte {
	t.Helper()
	files, err := xray.New().Render(uriInstance(s))
	if err != nil {
		t.Fatalf("the driver refuses a config the test means to be good: %v", err)
	}
	return files["config.json"]
}

// patch renders the good server base, and edits its outbound as plain JSON.
func patch(t *testing.T, base *egressuri.Server, edit func(out map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(render(t, base), &m); err != nil {
		t.Fatal(err)
	}
	edit(m["outbounds"].([]any)[1].(map[string]any))
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// obj walks into an object, taking the first element of an array and making
// the objects that are not there.
func obj(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		switch v := m[k].(type) {
		case map[string]any:
			m = v
		case []any:
			m = v[0].(map[string]any)
		default:
			nm := map[string]any{}
			m[k] = nm
			m = nm
		}
	}
	return m
}

func user(out map[string]any) map[string]any   { return obj(out, "settings", "vnext", "users") }
func server(out map[string]any) map[string]any { return obj(out, "settings", "servers") }
func stream(out map[string]any) map[string]any { return obj(out, "streamSettings") }

// refusal is a value the driver refuses (edit, on the server, and field, the
// field of its member error) and the same value put into a config by hand
// (raw), which Xray must refuse too, for that reason: why is a part of what Xray
// says.
type refusal struct {
	name  string
	base  func() *egressuri.Server
	edit  func(s *egressuri.Server)
	field string
	raw   func(out map[string]any)
	why   string
}

// panics is what Xray's output holds when it panicked on a config.
const panics = "nil pointer dereference"

// spiderXPanic is the frame of the panic over a spiderX that url.Parse refuses.
const spiderXPanic = "infra/conf.(*REALITYConfig).Build"

func refusals() []refusal {
	extra := func(e string) func(s *egressuri.Server) { return func(s *egressuri.Server) { s.Extra = e } }
	rawExtra := func(e string) func(out map[string]any) {
		return func(out map[string]any) { obj(out, "streamSettings", "xhttpSettings")["extra"] = json.RawMessage(e) }
	}
	reality := func(key, value string) func(out map[string]any) {
		return func(out map[string]any) { obj(out, "streamSettings", "realitySettings")[key] = value }
	}
	ext := func(name, e, why string) refusal {
		return refusal{name, vlessXHTTP, extra(e), "extra", rawExtra(e), why}
	}
	return []refusal{
		{"vless flow of old xtls", vlessReality, func(s *egressuri.Server) { s.Flow = "xtls-rprx-direct" }, "flow",
			func(out map[string]any) { user(out)["flow"] = "xtls-rprx-direct" }, `"flow" doesn't support "xtls-rprx-direct"`},
		{"vless id of 31 bytes", vlessWS, func(s *egressuri.Server) { s.ID = strings.Repeat("a", 31) }, "id",
			func(out map[string]any) { user(out)["id"] = strings.Repeat("a", 31) }, "invalid UUID"},
		{"vless id not hex", vlessWS, func(s *egressuri.Server) { s.ID = "zzzzzzzz-2222-3333-4444-555555555555" }, "id",
			func(out map[string]any) { user(out)["id"] = "zzzzzzzz-2222-3333-4444-555555555555" }, "encoding/hex: invalid byte"},
		{"vmess id of 31 bytes", func() *egressuri.Server { return vmess("") }, func(s *egressuri.Server) { s.ID = strings.Repeat("b", 31) }, "id",
			func(out map[string]any) { user(out)["id"] = strings.Repeat("b", 31) }, "invalid UUID"},
		{"trojan flow", trojan, func(s *egressuri.Server) { s.Flow = "xtls-rprx-vision" }, "flow",
			func(out map[string]any) { server(out)["flow"] = "xtls-rprx-vision" }, "Flow for Trojan has been removed"},
		{"trojan no password", trojan, func(s *egressuri.Server) { s.Password = "" }, "password",
			func(out map[string]any) { server(out)["password"] = "" }, "Trojan password is not specified"},
		{"ss unknown method", func() *egressuri.Server { return ss("aes-256-gcm", "pass-pass-pass") },
			func(s *egressuri.Server) { s.Method = "aes-256-cfb" }, "method",
			func(out map[string]any) { server(out)["method"] = "aes-256-cfb" }, "unknown cipher method"},
		{"ss 2022 short key", func() *egressuri.Server { return ss("2022-blake3-aes-128-gcm", b64(16)) },
			func(s *egressuri.Server) { s.Password = b64(15) }, "password",
			func(out map[string]any) { server(out)["password"] = b64(15) }, "bad key"},
		{"ss 2022 unpadded key", func() *egressuri.Server { return ss("2022-blake3-aes-128-gcm", b64(16)) },
			func(s *egressuri.Server) { s.Password = strings.TrimRight(b64(16), "=") }, "password",
			func(out map[string]any) { server(out)["password"] = strings.TrimRight(b64(16), "=") }, "decode key"},
		{"ss 2022 chacha with two keys", func() *egressuri.Server { return ss("2022-blake3-chacha20-poly1305", b64(32)) },
			func(s *egressuri.Server) { s.Password = b64(32) + ":" + b64(32) }, "password",
			func(out map[string]any) { server(out)["password"] = b64(32) + ":" + b64(32) }, "create method > invalid argument"},
		{"ss 2022 256 with a 16-byte key", func() *egressuri.Server { return ss("2022-blake3-aes-256-gcm", b64(32)) },
			func(s *egressuri.Server) { s.Password = b64(16) }, "password",
			func(out map[string]any) { server(out)["password"] = b64(16) }, "bad key"},
		{"reality over ws", vlessReality, func(s *egressuri.Server) { s.Network = "ws"; s.Flow = "" }, "security",
			func(out map[string]any) { stream(out)["network"] = "ws"; user(out)["flow"] = "" }, "REALITY only supports RAW, XHTTP and gRPC"},
		{"reality over httpupgrade", vlessReality, func(s *egressuri.Server) { s.Network = "httpupgrade"; s.Flow = "" }, "security",
			func(out map[string]any) { stream(out)["network"] = "httpupgrade"; user(out)["flow"] = "" }, "REALITY only supports RAW, XHTTP and gRPC"},
		{"reality fingerprint unsafe", vlessReality, func(s *egressuri.Server) { s.Fingerprint = "unsafe" }, "fp",
			reality("fingerprint", "unsafe"), `invalid "fingerprint": unsafe`},
		{"reality fingerprint hellogolang", vlessReality, func(s *egressuri.Server) { s.Fingerprint = "hellogolang" }, "fp",
			reality("fingerprint", "hellogolang"), `invalid "fingerprint": hellogolang`},
		{"tls fingerprint unknown", vlessWS, func(s *egressuri.Server) { s.Fingerprint = "chrome_999" }, "fp",
			func(out map[string]any) { obj(out, "streamSettings", "tlsSettings")["fingerprint"] = "chrome_999" }, `unknown "fingerprint": chrome_999`},
		{"reality key padded std base64", vlessReality,
			func(s *egressuri.Server) { s.PublicKey = stdB64(bytes.Repeat([]byte{0xfb}, 32)) }, "pbk",
			reality("publicKey", stdB64(bytes.Repeat([]byte{0xfb}, 32))), `invalid "password"`},
		{"reality key short", vlessReality, func(s *egressuri.Server) { s.PublicKey = realityKey[:41] }, "pbk",
			reality("publicKey", realityKey[:41]), `invalid "password"`},
		{"reality short id too long", vlessReality, func(s *egressuri.Server) { s.ShortID = "0123456789abcdef01" }, "sid",
			reality("shortId", "0123456789abcdef01"), `too long "shortId"`},
		{"reality short id odd", vlessReality, func(s *egressuri.Server) { s.ShortID = "abc" }, "sid", reality("shortId", "abc"), `invalid "shortId": abc`},
		{"reality short id not hex", vlessReality, func(s *egressuri.Server) { s.ShortID = "zz" }, "sid", reality("shortId", "zz"), `invalid "shortId": zz`},
		{"reality spider without a slash", vlessReality, func(s *egressuri.Server) { s.SpiderX = "index.html" }, "spx",
			reality("spiderX", "index.html"), `invalid "spiderX"`},
		// url.Parse refuses it, and REALITYConfig.Build dereferences the nil URL.
		{"reality spider unparseable", vlessReality, func(s *egressuri.Server) { s.SpiderX = "/%zz" }, "spx",
			reality("spiderX", "/%zz"), spiderXPanic},
		{"xhttp mode unknown", vlessXHTTP, func(s *egressuri.Server) { s.Mode = "stream-two" }, "mode",
			func(out map[string]any) { obj(out, "streamSettings", "xhttpSettings")["mode"] = "stream-two" }, "unsupported mode: stream-two"},
		ext("extra of a wrong type", `{"noGRPCHeader":"yes"}`, "SplitHTTPConfig.noGRPCHeader of type bool"),
		ext("extra range not a range", `{"xPaddingBytes":"a-b"}`, "Invalid integer range"),
		ext("extra range of a bool", `{"xmux":{"maxConcurrency":true}}`, "Invalid integer range"),
		ext("extra headers not strings", `{"headers":{"X-A":1}}`, "SplitHTTPConfig.headers"),
		ext("extra header host", `{"headers":{"Host":"x.example.com"}}`, `"headers" can't contain "host"`),
		ext("extra padding off", `{"xPaddingBytes":"0-100"}`, "xPaddingBytes cannot be disabled"),
		ext("extra padding placement", `{"xPaddingPlacement":"body"}`, "unsupported padding placement: body"),
		ext("extra padding method", `{"xPaddingMethod":"zeros"}`, "unsupported padding method: zeros"),
		ext("extra session placement", `{"sessionPlacement":"body"}`, "unsupported session placement: body"),
		ext("extra seq placement", `{"seqPlacement":"body"}`, "unsupported seq placement: body"),
		ext("extra max header bytes negative", `{"serverMaxHeaderBytes":-1}`, "invalid negative value of maxHeaderBytes"),
		ext("extra xmux both limits", `{"xmux":{"maxConcurrency":"4","maxConnections":"2"}}`,
			"maxConnections cannot be specified together with maxConcurrency"),
		{"extra GET outside packet-up", vlessXHTTP,
			func(s *egressuri.Server) { s.Mode, s.Extra = "stream-up", `{"uplinkHTTPMethod":"GET"}` }, "extra",
			func(out map[string]any) {
				x := obj(out, "streamSettings", "xhttpSettings")
				x["mode"], x["extra"] = "stream-up", json.RawMessage(`{"uplinkHTTPMethod":"GET"}`)
			}, "uplinkHTTPMethod can be GET only in packet-up mode"},
		{"extra download in stream-one", vlessXHTTP,
			func(s *egressuri.Server) {
				s.Mode, s.Extra = "stream-one", `{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp"}}`
			}, "extra",
			func(out map[string]any) {
				x := obj(out, "streamSettings", "xhttpSettings")
				x["mode"], x["extra"] = "stream-one", json.RawMessage(`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp"}}`)
			}, `Can not use "downloadSettings" in "stream-one" mode`},
		ext("extra download port of a string", `{"downloadSettings":{"address":"dl.example.com","port":"443","network":"xhttp"}}`,
			"downloadSettings.port of type uint16"),
		ext("extra download over quic", `{"downloadSettings":{"address":"dl.example.com","port":443,"network":"quic"}}`,
			"QUIC transport (without web service, etc.) has been removed"),
		ext("extra download insecure",
			`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"allowInsecure":true}}}`,
			`"allowInsecure" has been removed`),
		ext("extra download reality without a key",
			`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"reality","realitySettings":{"serverName":"a.example.com"}}}`,
			`empty "password"`),
		ext("extra download reality spider unparseable",
			`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"reality","realitySettings":{"publicKey":"`+realityKey+`","spiderX":"/%zz"}}}`,
			spiderXPanic),
		// A key twice: Xray reads the first downloadSettings too (it merges them),
		// so a check of the last alone would not see this sockopt.
		ext("extra download twice, the first broken",
			`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","sockopt":{"mark":"x"}},`+
				`"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp"}}`,
			"sockopt.mark of type int32"),
		ext("extra download in another case, the first broken",
			`{"DownloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","sockopt":{"mark":"x"}},`+
				`"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp"}}`,
			"sockopt.mark of type int32"),
		ext("extra host of a wrong type", `{"host":1}`, "SplitHTTPConfig.host of type string"),
		ext("extra path of a wrong type", `{"path":["/a"]}`, "SplitHTTPConfig.path of type string"),
		ext("extra mode of a wrong type", `{"mode":true}`, "SplitHTTPConfig.mode of type string"),
		ext("extra uplink data placement unknown", `{"uplinkDataPlacement":"query"}`, "unsupported uplink data placement"),
		ext("extra download splithttp mode unknown",
			`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"splithttp","splithttpSettings":{"mode":"bogus"}}}`,
			"unsupported mode: bogus"),
		ext("extra download reality show of a wrong type",
			`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"reality","realitySettings":{"show":"yes","publicKey":"`+realityKey+`"}}}`,
			"realitySettings.show of type bool"),
	}
}

// crasher is a downloadSettings that Xray v26.3.27 takes (xray run -test, and
// the instance starts and answers the SOCKS5 greeting) and that makes it panic
// at the first dial through the member: the splithttp dialer dereferences the
// download's destination and asserts its settings are XHTTP's. The driver
// refuses each (a member error on extra).
type crasher struct {
	name, extra, why string
}

func crashers() []crasher {
	return []crasher{
		{"download without an address", `{"downloadSettings":{"port":443,"network":"xhttp"}}`, panics},
		{"download without a network", `{"downloadSettings":{"address":"dl.example.com","port":443}}`, "interface conversion"},
		{"download over ws", `{"downloadSettings":{"address":"dl.example.com","port":443,"network":"ws"}}`, "interface conversion"},
	}
}

// accepted are configs the driver renders that Xray must take: every value of
// the driver's lists, and the odd forms the driver lets through.
func accepted(t *testing.T) []cfgCase {
	var cases []cfgCase
	add := func(name string, s *egressuri.Server) {
		cases = append(cases, cfgCase{name: name, data: render(t, s), ok: true})
	}
	for _, fp := range append(xray.Fingerprints(), "unsafe") {
		s := vlessWS()
		s.Fingerprint = fp
		add("tls fp "+fp, s)
		if fp != "hellogolang" && fp != "unsafe" {
			r := vlessReality()
			r.Fingerprint = fp
			add("reality fp "+fp, r)
		}
	}
	for _, fp := range []string{"", "Chrome", "HelloFirefox_Auto"} {
		s := vlessWS()
		s.Fingerprint = fp
		add("tls fp of case "+fp, s)
		r := vlessReality()
		r.Fingerprint = fp
		add("reality fp of case "+fp, r)
	}
	for _, flow := range []string{"", "xtls-rprx-vision", "xtls-rprx-vision-udp443"} {
		s := vlessReality()
		s.Flow = flow
		add("flow "+flow, s)
	}
	for _, id := range []string{
		strings.ToUpper(testUUID), strings.ReplaceAll(testUUID, "-", ""), "11111111-22223333-4444-555555555555",
		"a", strings.Repeat("x", 30), "пароль", strings.ReplaceAll(testUUID, "-", "") + "zzzz",
	} {
		s := vlessWS()
		s.ID = id
		add("vless id "+id, s)
		v := vmess("")
		v.ID = id
		add("vmess id "+id, v)
	}
	for _, m := range []string{
		"aes-128-gcm", "AEAD_AES_128_GCM", "aes-256-gcm", "aead_aes_256_gcm", "chacha20-poly1305", "aead_chacha20_poly1305",
		"chacha20-ietf-poly1305", "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305", "none", "plain",
	} {
		add("ss "+m, ss(m, "pass-pass-pass"))
	}
	for m, key := range map[string]string{
		"2022-blake3-aes-128-gcm": b64(16), "2022-BLAKE3-AES-256-GCM": b64(32), "2022-blake3-chacha20-poly1305": b64(32),
	} {
		add("ss "+m, ss(m, key))
	}
	add("ss 2022 longer key", ss("2022-blake3-aes-128-gcm", b64(17)))
	add("ss 2022 two keys", ss("2022-blake3-aes-256-gcm", b64(32)+":"+b64(32)))
	for _, scy := range []string{"", "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero", "aes-256-cfb"} {
		add("vmess scy "+scy, vmess(scy))
	}
	for _, network := range []string{"tcp", "ws", "grpc", "xhttp", "httpupgrade"} {
		s := vlessWS()
		s.Network = network
		add("network "+network, s)
	}
	for _, network := range []string{"tcp", "grpc", "xhttp"} {
		s := vlessReality()
		s.Network, s.Flow = network, ""
		add("reality over "+network, s)
	}
	g := vmess("")
	g.Mode = "multi"
	add("grpc multi", g)
	for _, mode := range []string{"", "auto", "packet-up", "stream-up", "stream-one"} {
		s := vlessXHTTP()
		s.Mode = mode
		add("xhttp mode "+mode, s)
	}
	for _, sid := range []string{"", "ab", "0123456789abcdef", "ABCDEF"} {
		s := vlessReality()
		s.ShortID = sid
		add("sid "+sid, s)
	}
	for i, extra := range []string{
		`{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32","hKeepAlivePeriod":30}}`,
		`{"xPaddingBytes":200,"noSSEHeader":true,"scMaxEachPostBytes":"1000000","scMinPostsIntervalMs":"10-50"}`,
		`{"xmux":{"maxConnections":"4-8","cMaxReuseTimes":0}}`,
		`{"headers":{"X-Forwarded-For":"192.0.2.1"},"xPaddingPlacement":"header","xPaddingMethod":"tokenish"}`,
		`{"xPaddingPlacement":"cookie","xPaddingMethod":"repeat-x"}`,
		`{"xPaddingPlacement":"query"}`,
		`{"xPaddingPlacement":"queryInHeader"}`,
		`{"sessionPlacement":"cookie","seqPlacement":"query","uplinkHTTPMethod":"PUT"}`,
		`{"sessionPlacement":"path","seqPlacement":"header"}`,
		`{"uplinkHTTPMethod":"GET"}`,
		`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"dl.example.com","fingerprint":"chrome","alpn":["h2"]},"xhttpSettings":{"path":"/dl"}}}`,
		`{"downloadSettings":{"address":"203.0.113.5","port":443,"network":"xhttp","security":"reality","realitySettings":{"serverName":"a.example.com","fingerprint":"firefox","password":"` + realityKey + `","shortId":"01"}}}`,
		`{"unknownFutureField":{"a":1},"extra":{"ignored":"by xray"}}`,
		`{"downloadSettings":null}`,
		`{"downloadSettings":{"address":"dl.example.com","port":443,"network":"SplitHTTP"}}`,
		`{"downloadSettings":{"address":"[2001:db8::5]","port":8443,"network":"xhttp","xhttpSettings":{"path":"/dl","mode":"stream-up","xmux":{"maxConnections":"2"}}}}`,
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
		add("extra "+strconv.Itoa(i), s)
	}
	alpn := vlessWS()
	alpn.ALPN = "h2,http/1.1"
	add("alpn", alpn)
	insecure := vlessWS()
	insecure.AllowInsecure = true // not rendered: see "refused allowInsecure"
	add("allowInsecure dropped", insecure)
	return cases
}

func (e *itest) testConfigs(t *testing.T) {
	cases := accepted(t)

	golden, err := fs.Glob(goldenFiles, "xray/testdata/*.json")
	if err != nil || len(golden) < 6 {
		t.Fatalf("golden files: %v, %v", golden, err)
	}
	for _, p := range golden {
		data, err := goldenFiles.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, cfgCase{name: "golden " + path.Base(p), data: data, ok: true})
	}

	why := map[string]string{} // case name -> part of Xray's reason
	for _, r := range refusals() {
		s := r.base()
		r.edit(s)
		_, err := xray.New().Render(uriInstance(s))
		mes := providers.MemberErrors(err)
		if len(mes) != 1 || mes[0].Field != r.field {
			t.Errorf("%s: the driver gives %v, want a member error on %s", r.name, err, r.field)
		}
		name := "refused " + r.name
		why[name] = r.why
		cases = append(cases, cfgCase{name: name, data: patch(t, r.base(), r.raw), ok: false})
	}
	// The driver drops a link's allowInsecure (TestAllowInsecureIsNotRendered in
	// package xray): this is why. Xray v26.3.27 refuses the option after
	// 2026-06-01.
	why["refused allowInsecure"] = `"allowInsecure" has been removed`
	cases = append(cases, cfgCase{name: "refused allowInsecure", ok: false, data: patch(t, vlessWS(), func(out map[string]any) {
		obj(out, "streamSettings", "tlsSettings")["allowInsecure"] = true
	})})
	// What xray run -test cannot see: these load (and Xray panics at the first
	// dial, see testCrashers). The driver refuses them all the same.
	for _, c := range crashers() {
		s := vlessXHTTP()
		s.Extra = c.extra
		if _, err := xray.New().Render(uriInstance(s)); len(providers.MemberErrors(err)) != 1 {
			t.Errorf("%s: the driver gives %v, want a member error", c.name, err)
		}
		cases = append(cases, cfgCase{name: "loads, then panics: " + c.name, ok: true, data: crasherConfig(t, c, 35001)})
	}

	got := e.xrayTest(t, cases)
	var bad, reasons []string
	nOK, nRefused := 0, 0
	for i, c := range cases {
		r, ok := got[fileName(i)]
		switch {
		case !ok:
			bad = append(bad, c.name+": no result")
		case r.ok != c.ok:
			bad = append(bad, fmt.Sprintf("%s: xray says ok=%v, want ok=%v\n%s", c.name, r.ok, c.ok, r.out))
		case c.ok:
			nOK++
		case why[c.name] == "":
			bad = append(bad, c.name+": the case does not say what Xray's reason must hold")
		case !strings.Contains(r.out, why[c.name]):
			bad = append(bad, fmt.Sprintf("%s: Xray refuses it, but not for the value under test (want %q):\n%s", c.name, why[c.name], r.out))
		default:
			nRefused++
			reasons = append(reasons, fmt.Sprintf("%s:\n%s", c.name, xrayReason(r.out)))
		}
	}
	t.Logf("Xray's reasons:\n%s", strings.Join(reasons, "\n"))
	if len(bad) > 0 {
		t.Errorf("%d of %d configs: Xray does not agree with the driver:\n%s", len(bad), len(cases), strings.Join(bad, "\n"))
	}
	t.Logf("xray run -test: %d configs taken, %d refused for the value under test, as the driver expects", nOK, nRefused)
}

// crasherConfig is the config of an XHTTP member with the extra of c, made by
// hand (the driver refuses it), with its SOCKS5 inbound on port.
func crasherConfig(t *testing.T, c crasher, port uint16) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(render(t, vlessXHTTP()), &m); err != nil {
		t.Fatal(err)
	}
	obj(m["outbounds"].([]any)[1].(map[string]any), "streamSettings", "xhttpSettings")["extra"] = json.RawMessage(c.extra)
	m["inbounds"].([]any)[0].(map[string]any)["port"] = port
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// testCrashers runs each crasher as the agent would run a member, and dials once
// through it: Xray must panic (and with the restart policy of the agent,
// unless-stopped, it would do so again at every dial, for every member of the
// egress). This is why the driver refuses them; the test checks that it does.
func (e *itest) testCrashers(t *testing.T) {
	for _, c := range crashers() {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			s := vlessXHTTP()
			s.Extra = c.extra
			if _, err := xray.New().Render(uriInstance(s)); len(providers.MemberErrors(err)) != 1 {
				t.Fatalf("the driver gives %v, want a member error", err)
			}

			port := pickPort(t, providers.MinPort, providers.MaxPort+1)
			dir := e.newDir(t, "crash")
			writeFile(t, filepath.Join(dir, "config.json"), crasherConfig(t, c, port))
			in := providers.Instance{
				EgressID: "ITESTCRASH" + strings.ToUpper(e.run), Generation: 1, Kind: nodev1.EgressKind_EGRESS_KIND_XRAY_URI,
				Members:     []providers.Member{{Key: "member", Port: port, Server: s}},
				InstanceDir: dir, BinaryPath: e.xray, RunnerImage: runnerImage,
			}
			id := e.startContainer(t, ctx, "crash", xray.New().Container(in))

			exit, out := e.runProbe(t, ctx, "probe-crash", time.Minute,
				"-ports", strconv.Itoa(int(port)), "-wait", "30s", "-poke", "192.0.2.1:443")
			if exit != 0 {
				t.Fatalf("the probe could not reach the member (exit %d):\n%s", exit, out)
			}
			var d *dockerapi.ContainerDetails
			for range 40 {
				var err error
				if d, err = e.docker.Inspect(ctx, id); err != nil {
					t.Fatal(err)
				}
				if d.State != "running" {
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
			log := e.logs(t, id)
			if d.State == "running" || !strings.Contains(log, "panic:") || !strings.Contains(log, c.why) ||
				!strings.Contains(log, "transport/internet/splithttp.Dial") {
				t.Fatalf("Xray is %s (exit %d) after a dial through the member; want it gone with a panic (%q):\n%s\nprobe: %s",
					d.State, d.ExitCode, c.why, tail(log, 15), out)
			}
			t.Logf("one dial through the member, and Xray exits %d: %s", d.ExitCode, firstLine(log, "panic:"))
		})
	}
}

// tail returns the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// firstLine returns the first line of s that holds sub.
func firstLine(s, sub string) string {
	for line := range strings.SplitSeq(s, "\n") {
		if strings.Contains(line, sub) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func fileName(i int) string { return fmt.Sprintf("case%03d.json", i) }

// xrayReason keeps the lines of Xray's output that say why it failed.
func xrayReason(out string) string {
	var keep []string
	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, "Failed") || strings.Contains(line, "rror") || strings.Contains(line, "invalid") ||
			strings.Contains(line, "panic") {
			keep = append(keep, "    "+strings.TrimSpace(strings.TrimPrefix(line, "  | ")))
		}
	}
	if len(keep) == 0 {
		return "    " + strings.TrimSpace(out)
	}
	return strings.Join(keep, "\n")
}

type testResult struct {
	ok  bool
	out string
}

// xrayTest runs `xray run -test` on every case in one container, without a
// network, and returns the result of each file.
func (e *itest) xrayTest(t *testing.T, cases []cfgCase) map[string]testResult {
	t.Helper()
	dir := e.newDir(t, "configs")
	for i, c := range cases {
		writeFile(t, filepath.Join(dir, fileName(i)), c.data)
	}
	const script = `
cd /cfg
for f in case*.json; do
  if /opt/engine/xray run -test -c "$f" > /tmp/out 2>&1; then
    echo "RESULT OK $f"
  else
    echo "RESULT FAIL $f"
  fi
  sed -n '1,25p' /tmp/out | sed 's/^/  | /'
done
`
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	exit, out := e.runHelper(t, ctx, "xraytest", dockerapi.ContainerSpec{
		Image:       runnerImage,
		User:        "65534:65534",
		NetworkMode: "none",
		Entrypoint:  []string{"/bin/sh", "-c", script},
		Binds:       []string{e.xray + ":/opt/engine/xray:ro", dir + ":/cfg:ro"},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=8m"},
	}, 5*time.Minute)
	if exit != 0 {
		t.Fatalf("the test container failed (exit %d):\n%s", exit, out)
	}
	results := map[string]testResult{}
	var current string
	for line := range strings.SplitSeq(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "RESULT "); ok {
			verdict, file, _ := strings.Cut(rest, " ")
			current = file
			results[file] = testResult{ok: verdict == "OK"}
			continue
		}
		if r, ok := results[current]; ok && strings.HasPrefix(line, "  | ") {
			r.out += line + "\n"
			results[current] = r
		}
	}
	return results
}
