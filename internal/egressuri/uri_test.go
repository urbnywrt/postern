package egressuri

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Every credential here is obviously fake, every address comes from a
// documentation range (RFC 5737, RFC 3849) and every name is under example.com,
// .example or .test.
const (
	testUUID     = "00000000-0000-4000-8000-000000000001"
	testUUID2    = "00000000-0000-4000-8000-000000000002"
	testPassword = "pa55w0rd-not-real"
	testPubKey   = "fake-public-key-for-tests-0000000000000"
	testShortID  = "0123456789abcdef"

	// Userinfo of ss:// links, base64url without padding. The first one is the
	// example of SIP002 (https://shadowsocks.org/doc/sip002.html): method
	// aes-128-gcm, password "test".
	ssUserSIP002 = "YWVzLTEyOC1nY206dGVzdA"
	ssUserAES256 = "YWVzLTI1Ni1nY206cGE1NXcwcmQtbm90LXJlYWw"                                        // aes-256-gcm:pa55w0rd-not-real
	ssUserChaCha = "Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYTU1dzByZC1ub3QtcmVhbA"                         // chacha20-ietf-poly1305:pa55w0rd-not-real
	ssUserRC4    = "cmM0LW1kNTpwYXNzd2Q"                                                            // rc4-md5:passwd, the plugin example of SIP002
	ssUser2022   = "2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D" // SIP002's plain AEAD-2022 form
)

var keyPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

// ---- helpers ---------------------------------------------------------------

// vmessLink builds a vmess:// link from a JSON object. UUID in the object stands
// for testUUID.
func vmessLink(obj string) string {
	return vmessLinkWith(base64.StdEncoding, obj)
}

func vmessLinkWith(enc *base64.Encoding, obj string) string {
	return "vmess://" + enc.EncodeToString([]byte(strings.ReplaceAll(obj, "UUID", testUUID)))
}

// diffServer lists the fields in which got and want differ.
func diffServer(got, want Server) string {
	var b strings.Builder
	gv, wv := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := range gv.NumField() {
		if !gv.Field(i).Equal(wv.Field(i)) {
			fmt.Fprintf(&b, "\n  %s: got %#v, want %#v", gv.Type().Field(i).Name, gv.Field(i).Interface(), wv.Field(i).Interface())
		}
	}
	return b.String()
}

// independentFold is the folding of an address that Key documents, written out
// on its own: ASCII upper case becomes lower case, an IP address is written as
// netip writes it.
func independentFold(a string) string {
	if ip, err := netip.ParseAddr(a); err == nil {
		return ip.String()
	}
	var b strings.Builder
	for i := range len(a) {
		c := a[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// independentKey is the documented Key formula written out on its own: the
// password is not in it.
func independentKey(s *Server) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s|%s|%d|%s", s.Protocol, independentFold(s.Address), s.Port, s.ID))
	return hex.EncodeToString(sum[:])[:12]
}

// validAddress is what a parsed Address may look like, checked without the
// parser's own helpers.
func validAddress(a string) bool {
	if ip, err := netip.ParseAddr(a); err == nil {
		return ip.Is4() || ip.Is6() && ip.Zone() == ""
	}
	return a != "" && !strings.ContainsAny(a, " \t\r\n/\\?#@[]:%")
}

// checkServer verifies what every successfully parsed Server must satisfy.
func checkServer(t testing.TB, s *Server) {
	t.Helper()
	switch s.Protocol {
	case "vless", "vmess":
		if s.ID == "" {
			t.Errorf("%s server without an ID", s.Protocol)
		}
	case "trojan", "shadowsocks":
		if s.Password == "" {
			t.Errorf("%s server without a password", s.Protocol)
		}
		if s.Protocol == "shadowsocks" && s.Method == "" {
			t.Errorf("shadowsocks server without a method")
		}
	default:
		t.Errorf("Protocol = %q", s.Protocol)
	}
	if s.Port == 0 {
		t.Errorf("Port = 0")
	}
	if !validAddress(s.Address) {
		t.Errorf("Address = %q", s.Address)
	}
	switch s.Network {
	case "tcp", "ws", "grpc", "xhttp", "httpupgrade":
	default:
		t.Errorf("Network = %q", s.Network)
	}
	switch s.Security {
	case "none", "tls", "reality":
	default:
		t.Errorf("Security = %q", s.Security)
	}
	if s.Security == "reality" && s.PublicKey == "" {
		t.Errorf("reality server without a public key")
	}
	if s.Extra != "" && !json.Valid([]byte(s.Extra)) {
		t.Errorf("Extra is not JSON: %q", s.Extra)
	}
	rv := reflect.ValueOf(*s)
	for i := range rv.NumField() {
		if f := rv.Field(i); f.Kind() == reflect.String {
			if !utf8.ValidString(f.String()) {
				t.Errorf("%s is not valid UTF-8: %q", rv.Type().Field(i).Name, f.String())
			}
			if strings.ContainsFunc(f.String(), unicode.IsControl) {
				t.Errorf("%s has a control character: %q", rv.Type().Field(i).Name, f.String())
			}
		}
	}
	if k := s.Key(); !keyPattern.MatchString(k) {
		t.Errorf("Key() = %q, want 12 lower-case hex digits", k)
	} else if want := independentKey(s); k != want {
		t.Errorf("Key() = %q, want %q", k, want)
	}
}

type parseCase struct {
	name string
	uri  string
	want Server
}

func runParseCases(t *testing.T, cases []parseCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.uri)
			if err != nil {
				t.Fatalf("Parse: unexpected error: %v", err)
			}
			if *got != tc.want {
				t.Errorf("Parse differs from the expectation:%s", diffServer(*got, tc.want))
			}
			checkServer(t, got)
		})
	}
}

type errCase struct {
	name string
	uri  string
	want string // a substring of the error
}

// runErrorCases checks that every URI fails with the wanted message, that the
// message starts with scheme (when given) and that it echoes nothing of the URI.
func runErrorCases(t *testing.T, scheme string, cases []errCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.uri)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded as %v, want an error containing %q", tc.uri, got, tc.want)
			}
			if got != nil {
				t.Errorf("Parse returned a Server together with the error %q", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.want) {
				t.Errorf("error %q does not contain %q", msg, tc.want)
			}
			if scheme != "" && !strings.HasPrefix(msg, scheme+": ") {
				t.Errorf("error %q does not start with %q", msg, scheme+": ")
			}
			assertNoEcho(t, tc.uri, msg)
		})
	}
}

// echoWindow is how many bytes of a link must not come back in an error.
const echoWindow = 12

// assertNoEcho fails when msg holds a credential used by these tests, the whole
// of uri, or any run of echoWindow bytes of it (of its base64 payload too, for
// vmess).
func assertNoEcho(t testing.TB, uri, msg string) {
	t.Helper()
	for _, secret := range []string{testUUID, testUUID2, testPassword} {
		if strings.Contains(msg, secret) {
			t.Errorf("error %q holds the credential %q", msg, secret)
		}
	}
	uri = strings.TrimSpace(uri)
	texts := []string{uri}
	if len(uri) >= len("vmess://") && strings.EqualFold(uri[:len("vmess://")], "vmess://") {
		payload, _, _ := strings.Cut(uri[len("vmess://"):], "#")
		payload, _, _ = strings.Cut(payload, "?")
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if raw, err := enc.DecodeString(payload); err == nil {
				texts = append(texts, string(raw))
				break
			}
		}
	}
	for _, text := range texts {
		if text != "" && strings.Contains(msg, text) {
			t.Errorf("error %q echoes the input %q", msg, text)
		}
		for i := 0; i+echoWindow <= len(text); i++ {
			if w := text[i : i+echoWindow]; strings.Contains(msg, w) {
				t.Errorf("error %q echoes %q of the input", msg, w)
				break
			}
		}
	}
}

// ---- vless -----------------------------------------------------------------

var vlessCases = []parseCase{
	{
		name: "plain tcp",
		uri:  "vless://" + testUUID + "@203.0.113.10:8443?type=tcp&security=none#plain",
		want: Server{Protocol: "vless", Name: "plain", Address: "203.0.113.10", Port: 8443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "port 443, tcp and no security by default",
		uri:  "vless://" + testUUID + "@vpn.example.com",
		want: Server{Protocol: "vless", Address: "vpn.example.com", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "reality with vision",
		uri: "vless://" + testUUID + "@198.51.100.7:443?encryption=none&flow=xtls-rprx-vision&security=reality" +
			"&sni=www.example.com&fp=chrome&pbk=" + testPubKey + "&sid=" + testShortID + "&spx=%2F&type=tcp&headerType=none#reality%20vision",
		want: Server{
			Protocol: "vless", Name: "reality vision", Address: "198.51.100.7", Port: 443, ID: testUUID,
			Flow: "xtls-rprx-vision", Network: "tcp", Security: "reality",
			SNI: "www.example.com", Fingerprint: "chrome", PublicKey: testPubKey, ShortID: testShortID, SpiderX: "/",
		},
	},
	{
		name: "ws over tls with a host and a path that has a query",
		uri: "vless://" + testUUID + "@203.0.113.20:2053?type=ws&security=tls&sni=cdn.example.com&host=ws.example.com" +
			"&path=%2Fws%3Fed%3D2048&fp=firefox&alpn=h2%2Chttp%2F1.1&allowInsecure=1#ws%20tls",
		want: Server{
			Protocol: "vless", Name: "ws tls", Address: "203.0.113.20", Port: 2053, ID: testUUID,
			Network: "ws", Security: "tls", SNI: "cdn.example.com", Host: "ws.example.com", Path: "/ws?ed=2048",
			Fingerprint: "firefox", ALPN: "h2,http/1.1", AllowInsecure: true,
		},
	},
	{
		name: "grpc with a service name and a mode",
		uri:  "vless://" + testUUID + "@203.0.113.21:443?type=grpc&security=tls&sni=g.example.com&serviceName=grpc-tunnel&mode=multi#grpc",
		want: Server{
			Protocol: "vless", Name: "grpc", Address: "203.0.113.21", Port: 443, ID: testUUID,
			Network: "grpc", Security: "tls", SNI: "g.example.com", ServiceName: "grpc-tunnel", Mode: "multi",
		},
	},
	{
		name: "grpc service name is percent-decoded",
		uri:  "vless://" + testUUID + "@203.0.113.21:443?type=grpc&security=none&serviceName=my%2Fsvc",
		want: Server{Protocol: "vless", Address: "203.0.113.21", Port: 443, ID: testUUID, Network: "grpc", Security: "none", ServiceName: "my/svc"},
	},
	{
		name: "xhttp with extra",
		uri: "vless://" + testUUID + "@203.0.113.22:443?type=xhttp&security=tls&sni=x.example.com&host=h.example.com&path=%2Fxh" +
			"&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%2C%22noSSEHeader%22%3Atrue%7D#xhttp",
		want: Server{
			Protocol: "vless", Name: "xhttp", Address: "203.0.113.22", Port: 443, ID: testUUID,
			Network: "xhttp", Security: "tls", SNI: "x.example.com", Host: "h.example.com", Path: "/xh", Mode: "packet-up",
			Extra: `{"xPaddingBytes":"100-1000","noSSEHeader":true}`,
		},
	},
	{
		name: "extra spread over lines is compacted",
		uri: "vless://" + testUUID + "@203.0.113.22:443?type=xhttp" +
			"&extra=%7B%0A%20%20%22xPaddingBytes%22%3A%20%22100-1000%22%2C%0A%20%20%22noSSEHeader%22%3A%20true%0A%7D",
		want: Server{
			Protocol: "vless", Address: "203.0.113.22", Port: 443, ID: testUUID, Network: "xhttp", Security: "none",
			Extra: `{"xPaddingBytes":"100-1000","noSSEHeader":true}`,
		},
	},
	{
		name: "httpupgrade",
		uri:  "vless://" + testUUID + "@203.0.113.23:80?type=httpupgrade&security=none&host=h.example.com&path=%2Fhu",
		want: Server{Protocol: "vless", Address: "203.0.113.23", Port: 80, ID: testUUID, Network: "httpupgrade", Security: "none", Host: "h.example.com", Path: "/hu"},
	},
	{
		name: "ipv6 literal with a port",
		uri:  "vless://" + testUUID + "@[2001:db8::1]:8443?type=tcp#v6",
		want: Server{Protocol: "vless", Name: "v6", Address: "2001:db8::1", Port: 8443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "ipv6 literal without a port",
		uri:  "vless://" + testUUID + "@[2001:db8::2]?type=tcp",
		want: Server{Protocol: "vless", Address: "2001:db8::2", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "the address is kept as it was written",
		uri:  "vless://" + testUUID + "@[2001:DB8:0:0::A]:443",
		want: Server{Protocol: "vless", Address: "2001:DB8:0:0::A", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "peer is an alias of sni",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?security=tls&peer=peer.example.com",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "tls", SNI: "peer.example.com"},
	},
	{
		name: "servername is an alias of sni",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?security=tls&servername=sn.example.com",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "tls", SNI: "sn.example.com"},
	},
	{
		name: "sni wins over peer, which wins over servername",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?security=tls&servername=sn.example.com&peer=peer.example.com&sni=sni.example.com",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "tls", SNI: "sni.example.com"},
	},
	{
		name: "peer wins over servername",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?security=tls&servername=sn.example.com&peer=peer.example.com",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "tls", SNI: "peer.example.com"},
	},
	{
		name: "type raw is tcp",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?type=raw",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "type splithttp is xhttp",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?type=splithttp&path=%2Fs",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "xhttp", Security: "none", Path: "/s"},
	},
	{
		name: "scheme, parameter names and the values of type and security are case-insensitive",
		uri:  "VLESS://" + testUUID + "@203.0.113.10:443?Type=WS&Security=TLS&SNI=a.example.com&ServiceName=x&AllowInsecure=TRUE",
		want: Server{
			Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "ws", Security: "tls",
			SNI: "a.example.com", ServiceName: "x", AllowInsecure: true,
		},
	},
	{
		name: "a path before the query is ignored",
		uri:  "vless://" + testUUID + "@203.0.113.10:443/?type=tcp#slash",
		want: Server{Protocol: "vless", Name: "slash", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "the name is percent-decoded",
		uri:  "vless://" + testUUID + "@203.0.113.10:443#%F0%9F%87%A9%F0%9F%87%AA%20Berlin%20%231",
		want: Server{Protocol: "vless", Name: "\U0001F1E9\U0001F1EA Berlin #1", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "a bare percent sign in the name stays",
		uri:  "vless://" + testUUID + "@203.0.113.10:443#100% fast",
		want: Server{Protocol: "vless", Name: "100% fast", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "control characters in the name become spaces",
		uri:  "vless://" + testUUID + "@203.0.113.10:443#a%0Ab%09c",
		want: Server{Protocol: "vless", Name: "a b c", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "invalid UTF-8 in the name is replaced",
		uri:  "vless://" + testUUID + "@203.0.113.10:443#bad%FFname",
		want: Server{Protocol: "vless", Name: "bad" + string(utf8.RuneError) + "name", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "surrounding whitespace is trimmed",
		uri:  "  \t vless://" + testUUID + "@203.0.113.10:443#ws \r\n",
		want: Server{Protocol: "vless", Name: "ws", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "the id is percent-decoded",
		uri:  "vless://my%2Dcustom%2Did@203.0.113.10:443",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: "my-custom-id", Network: "tcp", Security: "none"},
	},
	{
		name: "unknown parameters and headerType are ignored",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?foo=bar&type=tcp&headerType=http&authority=a.example.com&unknown",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "the first of repeated parameters wins",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?type=ws&type=grpc",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "ws", Security: "none"},
	},
	{
		name: "empty parameters are absent",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?type=&security=&sni=&flow=&path=",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "insecure=1 is allowInsecure",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?security=tls&insecure=1",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "tls", AllowInsecure: true},
	},
	{
		name: "allowInsecure=0 is off",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?security=tls&allowInsecure=0",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "tls"},
	},
	{
		name: "encryption none is accepted in any case",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?encryption=None",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "an empty value does not hide a later one",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?type=&type=ws",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "ws", Security: "none"},
	},
	{
		name: "the name may hold a slash, an at sign and a question mark",
		uri:  "vless://" + testUUID + "@203.0.113.10:443#a/b@c?d",
		want: Server{Protocol: "vless", Name: "a/b@c?d", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "a host name of 253 bytes",
		uri:  vless(strings.Repeat("a", 241) + ".example.com:443"),
		want: Server{Protocol: "vless", Address: strings.Repeat("a", 241) + ".example.com", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "a plus in a value is a space, %2B is a plus",
		uri:  "vless://" + testUUID + "@203.0.113.10:443?type=ws&path=/a+b&host=h%2Bx.example.com",
		want: Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Network: "ws", Security: "none", Path: "/a b", Host: "h+x.example.com"},
	},
}

func vless(rest string) string { return "vless://" + testUUID + "@" + rest }

var vlessErrors = []errCase{
	{"no userinfo", "vless://203.0.113.10:443?type=tcp", "vless: missing id"},
	{"empty userinfo", "vless://@203.0.113.10:443", "vless: missing id"},
	{"bad escape in the id", "vless://%zz" + testUUID + "@203.0.113.10:443", "vless: invalid id"},
	{"id that is not UTF-8", "vless://%FF%FE@203.0.113.10:443", "vless: invalid id"},
	{"no host", vless(":443"), "vless: missing address"},
	{"nothing after the at sign", vless(""), "vless: missing address"},
	{"space in the host", vless("exa mple.com:443"), "vless: invalid address"},
	{"host name of 254 bytes", vless(strings.Repeat("a", 242) + ".example.com:443"), "vless: invalid address"},
	{"zero-width space in the host", vless("exa" + string(rune(0x200B)) + "mple.com:443"), "vless: invalid address"},
	{"bidi override in the host", vless("exa" + string(rune(0x202E)) + "mple.com:443"), "vless: invalid address"},
	{"percent sign in the host", vless("exa%6Dple.com:443"), "vless: invalid address"},
	{"host that is not UTF-8", vless("exa\xFFmple.com:443"), "vless: invalid address"},
	{"ipv6 without brackets", vless("2001:db8::1:443"), "vless: invalid address"},
	{"unclosed bracket", vless("[2001:db8::1:443"), "vless: invalid address"},
	{"text after the bracket", vless("[2001:db8::1]x"), "vless: invalid address"},
	{"ipv4 in brackets", vless("[192.0.2.1]:443"), "vless: invalid address"},
	{"name in brackets", vless("[vpn.example.com]:443"), "vless: invalid address"},
	{"ipv6 zone", vless("[2001:db8::1%25eth0]:443"), "vless: invalid address"},
	{"port 0", vless("203.0.113.10:0"), "vless: invalid port"},
	{"port 65536", vless("203.0.113.10:65536"), "vless: invalid port"},
	{"port that is not a number", vless("203.0.113.10:https"), "vless: invalid port"},
	{"empty port", vless("203.0.113.10:"), "vless: invalid port"},
	{"signed port", vless("203.0.113.10:+443"), "vless: invalid port"},
	{"negative port", vless("203.0.113.10:-1"), "vless: invalid port"},
	{"unsupported network kcp", vless("203.0.113.10:443?type=kcp"), "vless: unsupported network"},
	{"unsupported network quic", vless("203.0.113.10:443?type=quic"), "vless: unsupported network"},
	{"unsupported network h2", vless("203.0.113.10:443?type=h2"), "vless: unsupported network"},
	{"unsupported network http", vless("203.0.113.10:443?type=http"), "vless: unsupported network"},
	{"unsupported security", vless("203.0.113.10:443?security=xtls"), "vless: unsupported security"},
	{"reality without a public key", vless("203.0.113.10:443?security=reality&sni=www.example.com&sid=" + testShortID), "vless: missing pbk"},
	{"vless encryption", vless("203.0.113.10:443?encryption=mlkem768x25519plus.native.0rtt.AAAA"), "vless: encryption not supported"},
	{"extra that is not JSON", vless("203.0.113.10:443?type=xhttp&extra=%7Bnot-json"), "vless: invalid extra"},
	{"extra that is not an object", vless("203.0.113.10:443?type=xhttp&extra=%5B1%5D"), "vless: invalid extra"},
	{"extra with a line break inside a JSON string", vless("203.0.113.10:443?type=xhttp&extra=%7B%22a%22%3A%22x%0Ay%22%7D"), "vless: invalid extra"},
	{"extra with a control character in a JSON string", vless("203.0.113.10:443?type=xhttp&extra=%7B%22a%22%3A%22%C2%85%22%7D"), "vless: invalid extra"},
	{"extra that is not UTF-8", vless("203.0.113.10:443?type=xhttp&extra=%7B%22a%22%3A%22%FF%22%7D"), "vless: invalid extra"},
	{"extra with text after the object", vless("203.0.113.10:443?type=xhttp&extra=%7B%7D%20x"), "vless: invalid extra"},
	{"bad escape in a parameter", vless("203.0.113.10:443?path=%zz"), "vless: invalid path"},
	{"parameter that is not UTF-8", vless("203.0.113.10:443?sni=%FF"), "vless: invalid sni"},
	{"control character in a parameter", vless("203.0.113.10:443?host=a%00b"), "vless: invalid host"},
}

func TestParseVLESS(t *testing.T)       { runParseCases(t, vlessCases) }
func TestParseVLESSErrors(t *testing.T) { runErrorCases(t, "vless", vlessErrors) }

// ---- vmess -----------------------------------------------------------------

// websafeVMess returns a vmess object whose standard base64 holds '+', '/' and
// '=', so that all four base64 alphabets and paddings give different text, and
// the ps (the name) it carries.
func websafeVMess() (obj, ps string) {
	for lead := range 6 {
		for tail := range 3 {
			ps = strings.Repeat("a", lead) + "???>>>"
			obj = `{"ps":"` + ps + `","add":"203.0.113.33","port":443,"id":"UUID","z":"` + strings.Repeat("z", tail) + `"}`
			std := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(obj, "UUID", testUUID)))
			if strings.Contains(std, "+") && strings.Contains(std, "/") && strings.Contains(std, "=") {
				return obj, ps
			}
		}
	}
	panic("no vmess object encodes to base64 with '+', '/' and '='")
}

var vmessCases = []parseCase{
	{
		name: "tcp with a numeric port and alterId 0",
		uri:  vmessLink(`{"v":"2","ps":"vm basic","add":"203.0.113.30","port":443,"id":"UUID","aid":0,"scy":"auto","net":"tcp","type":"none","host":"","path":"","tls":""}`),
		want: Server{Protocol: "vmess", Name: "vm basic", Address: "203.0.113.30", Port: 443, ID: testUUID, Method: "auto", Network: "tcp", Security: "none"},
	},
	{
		name: "string port, string alterId and a numeric version",
		uri:  vmessLink(`{"v":2,"ps":"strings","add":"vmess.example.com","port":"8443","id":"UUID","aid":"0","scy":"chacha20-poly1305","net":"tcp","tls":"none"}`),
		want: Server{Protocol: "vmess", Name: "strings", Address: "vmess.example.com", Port: 8443, ID: testUUID, Method: "chacha20-poly1305", Network: "tcp", Security: "none"},
	},
	{
		name: "only the required fields",
		uri:  vmessLink(`{"add":"vmess.example.com","port":"8443","id":"UUID"}`),
		want: Server{Protocol: "vmess", Address: "vmess.example.com", Port: 8443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "null and empty fields are absent",
		uri:  vmessLink(`{"add":"vmess.example.com","port":8443,"id":"UUID","aid":null,"scy":null,"net":"","tls":null,"host":null,"sni":""}`),
		want: Server{Protocol: "vmess", Address: "vmess.example.com", Port: 8443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "ws over tls",
		uri:  vmessLink(`{"v":"2","ps":"ws tls","add":"203.0.113.31","port":"443","id":"UUID","aid":"0","scy":"aes-128-gcm","net":"ws","type":"none","host":"ws.example.com","path":"/ws","tls":"tls","sni":"sni.example.com","alpn":"h2,http/1.1","fp":"chrome"}`),
		want: Server{
			Protocol: "vmess", Name: "ws tls", Address: "203.0.113.31", Port: 443, ID: testUUID, Method: "aes-128-gcm",
			Network: "ws", Security: "tls", Host: "ws.example.com", Path: "/ws", SNI: "sni.example.com", ALPN: "h2,http/1.1", Fingerprint: "chrome",
		},
	},
	{
		name: "grpc carries its service name in path",
		uri:  vmessLink(`{"ps":"grpc","add":"203.0.113.32","port":"443","id":"UUID","net":"grpc","type":"multi","path":"grpc-tunnel","tls":"tls","sni":"g.example.com"}`),
		want: Server{
			Protocol: "vmess", Name: "grpc", Address: "203.0.113.32", Port: 443, ID: testUUID,
			Network: "grpc", Security: "tls", ServiceName: "grpc-tunnel", SNI: "g.example.com",
		},
	},
	{
		name: "xhttp and httpupgrade",
		uri:  vmessLink(`{"add":"203.0.113.34","port":443,"id":"UUID","net":"xhttp","host":"h.example.com","path":"/x"}`),
		want: Server{Protocol: "vmess", Address: "203.0.113.34", Port: 443, ID: testUUID, Network: "xhttp", Security: "none", Host: "h.example.com", Path: "/x"},
	},
	{
		name: "httpupgrade",
		uri:  vmessLink(`{"add":"203.0.113.35","port":443,"id":"UUID","net":"httpupgrade","host":"h.example.com","path":"/u"}`),
		want: Server{Protocol: "vmess", Address: "203.0.113.35", Port: 443, ID: testUUID, Network: "httpupgrade", Security: "none", Host: "h.example.com", Path: "/u"},
	},
	{
		name: "net splithttp is xhttp and raw is tcp",
		uri:  vmessLink(`{"add":"203.0.113.36","port":443,"id":"UUID","net":"splithttp"}`),
		want: Server{Protocol: "vmess", Address: "203.0.113.36", Port: 443, ID: testUUID, Network: "xhttp", Security: "none"},
	},
	{
		name: "net raw",
		uri:  vmessLink(`{"add":"203.0.113.36","port":443,"id":"UUID","net":"raw"}`),
		want: Server{Protocol: "vmess", Address: "203.0.113.36", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "net and tls are case-insensitive",
		uri:  vmessLink(`{"add":"203.0.113.37","port":443,"id":"UUID","net":"WS","tls":"TLS"}`),
		want: Server{Protocol: "vmess", Address: "203.0.113.37", Port: 443, ID: testUUID, Network: "ws", Security: "tls"},
	},
	{
		name: "tls none",
		uri:  vmessLink(`{"add":"203.0.113.37","port":443,"id":"UUID","tls":"none"}`),
		want: Server{Protocol: "vmess", Address: "203.0.113.37", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "ipv6 address",
		uri:  vmessLink(`{"add":"2001:db8::3","port":443,"id":"UUID"}`),
		want: Server{Protocol: "vmess", Address: "2001:db8::3", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "ipv6 address in brackets",
		uri:  vmessLink(`{"add":"[2001:db8::4]","port":443,"id":"UUID"}`),
		want: Server{Protocol: "vmess", Address: "2001:db8::4", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "allowInsecure as a boolean",
		uri:  vmessLink(`{"add":"203.0.113.38","port":443,"id":"UUID","tls":"tls","allowInsecure":true}`),
		want: Server{Protocol: "vmess", Address: "203.0.113.38", Port: 443, ID: testUUID, Network: "tcp", Security: "tls", AllowInsecure: true},
	},
	{
		name: "insecure as a string",
		uri:  vmessLink(`{"add":"203.0.113.38","port":443,"id":"UUID","tls":"tls","insecure":"1"}`),
		want: Server{Protocol: "vmess", Address: "203.0.113.38", Port: 443, ID: testUUID, Network: "tcp", Security: "tls", AllowInsecure: true},
	},
	{
		name: "insecure 0 is off",
		uri:  vmessLink(`{"add":"203.0.113.38","port":443,"id":"UUID","tls":"tls","insecure":0}`),
		want: Server{Protocol: "vmess", Address: "203.0.113.38", Port: 443, ID: testUUID, Network: "tcp", Security: "tls"},
	},
	{
		name: "the fragment names the server when ps is missing",
		uri:  vmessLink(`{"add":"203.0.113.39","port":443,"id":"UUID"}`) + "#frag%20name",
		want: Server{Protocol: "vmess", Name: "frag name", Address: "203.0.113.39", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "a ps that is not text counts as none",
		uri:  vmessLink(`{"ps":{"x":1},"add":"203.0.113.39","port":443,"id":"UUID"}`) + "#frag",
		want: Server{Protocol: "vmess", Name: "frag", Address: "203.0.113.39", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "ps wins over the fragment",
		uri:  vmessLink(`{"ps":"from ps","add":"203.0.113.39","port":443,"id":"UUID"}`) + "#frag",
		want: Server{Protocol: "vmess", Name: "from ps", Address: "203.0.113.39", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "ps is cleaned like a name",
		uri:  vmessLink(`{"ps":"  a\nb\u0000c  ","add":"203.0.113.39","port":443,"id":"UUID"}`),
		want: Server{Protocol: "vmess", Name: "a b c", Address: "203.0.113.39", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "unknown and nested fields are ignored",
		uri:  vmessLink(`{"add":"203.0.113.40","port":443,"id":"UUID","x":{"y":[1,2,{"z":null}]},"type":"http","v":"2"}`),
		want: Server{Protocol: "vmess", Address: "203.0.113.40", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
	{
		name: "scheme in capitals and a UTF-8 byte order mark before the object",
		uri:  "VMESS://" + base64.StdEncoding.EncodeToString([]byte("\xEF\xBB\xBF"+`{"add":"203.0.113.41","port":443,"id":"`+testUUID+`"}`)),
		want: Server{Protocol: "vmess", Address: "203.0.113.41", Port: 443, ID: testUUID, Network: "tcp", Security: "none"},
	},
}

func TestParseVMess(t *testing.T) { runParseCases(t, vmessCases) }

// TestParseVMessBase64Alphabets feeds one object through every base64 alphabet
// and padding that share links come in.
func TestParseVMessBase64Alphabets(t *testing.T) {
	obj, ps := websafeVMess()
	want := Server{Protocol: "vmess", Name: ps, Address: "203.0.113.33", Port: 443, ID: testUUID, Network: "tcp", Security: "none"}

	std := vmessLinkWith(base64.StdEncoding, obj)
	payload := strings.TrimPrefix(std, "vmess://")
	for _, c := range "+/=" {
		if !strings.ContainsRune(payload, c) {
			t.Fatalf("the fixture does not exercise the alphabets, %q is missing from %s", c, payload)
		}
	}
	cases := []parseCase{
		{"standard, padded", std, want},
		{"standard, unpadded", vmessLinkWith(base64.RawStdEncoding, obj), want},
		{"url-safe, padded", vmessLinkWith(base64.URLEncoding, obj), want},
		{"url-safe, unpadded", vmessLinkWith(base64.RawURLEncoding, obj), want},
		{"padding percent-encoded", "vmess://" + strings.ReplaceAll(payload, "=", "%3D"), want},
		{"slash and plus percent-encoded", "vmess://" + strings.NewReplacer("/", "%2F", "+", "%2B").Replace(payload), want},
		{"query after the payload is ignored", std + "?remarks=x", want},
	}
	runParseCases(t, cases)
}

var vmessErrors = []errCase{
	{"alterId as a number", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","aid":64}`), "vmess: alterId not supported"},
	{"alterId 1", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","aid":1}`), "vmess: alterId not supported"},
	{"alterId as a string", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","aid":"16"}`), "vmess: alterId not supported"},
	{"alterId that is not a number", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","aid":"many"}`), "vmess: alterId not supported"},
	{"alterId that is an object", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","aid":{}}`), "vmess: invalid aid"},
	{"empty payload", "vmess://", "vmess: missing payload"},
	{"payload that is not base64", "vmess://!!!not-base64!!!", "vmess: invalid base64"},
	{"bad percent escape in the payload", "vmess://%zz", "vmess: invalid base64"},
	{"payload that is not JSON", "vmess://" + base64.StdEncoding.EncodeToString([]byte("auto:"+testUUID+"@203.0.113.30:443")), "vmess: invalid json"},
	{"JSON array", vmessLink(`["UUID"]`), "vmess: invalid json"},
	{"JSON null", vmessLink(`null`), "vmess: invalid json"},
	{"JSON string", vmessLink(`"UUID"`), "vmess: invalid json"},
	{"truncated JSON", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID"`), "vmess: invalid json"},
	{"JSON with trailing text", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID"} x`), "vmess: invalid json"},
	{"no add", vmessLink(`{"port":443,"id":"UUID"}`), "vmess: missing add"},
	{"no id", vmessLink(`{"add":"203.0.113.30","port":443}`), "vmess: missing id"},
	{"no port", vmessLink(`{"add":"203.0.113.30","id":"UUID"}`), "vmess: missing port"},
	{"port 0", vmessLink(`{"add":"203.0.113.30","port":0,"id":"UUID"}`), "vmess: invalid port"},
	{"port 65536", vmessLink(`{"add":"203.0.113.30","port":"65536","id":"UUID"}`), "vmess: invalid port"},
	{"port that is not a number", vmessLink(`{"add":"203.0.113.30","port":"https","id":"UUID"}`), "vmess: invalid port"},
	{"fractional port", vmessLink(`{"add":"203.0.113.30","port":443.5,"id":"UUID"}`), "vmess: invalid port"},
	{"address with a space", vmessLink(`{"add":"exa mple.com","port":443,"id":"UUID"}`), "vmess: invalid add"},
	{"address with a port", vmessLink(`{"add":"203.0.113.30:443","port":443,"id":"UUID"}`), "vmess: invalid add"},
	{"ipv4 in brackets", vmessLink(`{"add":"[192.0.2.1]","port":443,"id":"UUID"}`), "vmess: invalid add"},
	{"unclosed bracket", vmessLink(`{"add":"[2001:db8::4","port":443,"id":"UUID"}`), "vmess: invalid add"},
	{"unsupported network kcp", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","net":"kcp"}`), "vmess: unsupported network"},
	{"unsupported network h2", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","net":"h2"}`), "vmess: unsupported network"},
	{"unsupported network quic", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","net":"quic"}`), "vmess: unsupported network"},
	{"unsupported security", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","tls":"xtls"}`), "vmess: unsupported security"},
	{"reality is not a vmess security", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","tls":"reality"}`), "vmess: unsupported security"},
	{"object where a string belongs", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","host":{"a":1}}`), "vmess: invalid host"},
	{"array where a string belongs", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","path":["/x"]}`), "vmess: invalid path"},
	{"control character in a string", vmessLink(`{"add":"203.0.113.30","port":443,"id":"UUID","sni":"a\u0000b"}`), "vmess: invalid sni"},
}

func TestParseVMessErrors(t *testing.T) { runErrorCases(t, "vmess", vmessErrors) }

// ---- trojan ----------------------------------------------------------------

var trojanCases = []parseCase{
	{
		name: "tls is the default",
		uri:  "trojan://" + testPassword + "@203.0.113.40:443?sni=t.example.com#trojan",
		want: Server{Protocol: "trojan", Name: "trojan", Address: "203.0.113.40", Port: 443, Password: testPassword, Network: "tcp", Security: "tls", SNI: "t.example.com"},
	},
	{
		name: "port 443 by default",
		uri:  "trojan://" + testPassword + "@t.example.com",
		want: Server{Protocol: "trojan", Address: "t.example.com", Port: 443, Password: testPassword, Network: "tcp", Security: "tls"},
	},
	{
		name: "ws with a host and a path",
		uri: "trojan://" + testPassword + "@203.0.113.41:8443?type=ws&host=h.example.com&path=%2Ftr&sni=t.example.com" +
			"&alpn=http%2F1.1&fp=chrome#ws",
		want: Server{
			Protocol: "trojan", Name: "ws", Address: "203.0.113.41", Port: 8443, Password: testPassword,
			Network: "ws", Security: "tls", Host: "h.example.com", Path: "/tr", SNI: "t.example.com", ALPN: "http/1.1", Fingerprint: "chrome",
		},
	},
	{
		name: "grpc with a service name",
		uri:  "trojan://" + testPassword + "@203.0.113.42:443?type=grpc&serviceName=tr-grpc&sni=g.example.com",
		want: Server{
			Protocol: "trojan", Address: "203.0.113.42", Port: 443, Password: testPassword,
			Network: "grpc", Security: "tls", ServiceName: "tr-grpc", SNI: "g.example.com",
		},
	},
	{
		name: "security none",
		uri:  "trojan://" + testPassword + "@203.0.113.43:80?security=none",
		want: Server{Protocol: "trojan", Address: "203.0.113.43", Port: 80, Password: testPassword, Network: "tcp", Security: "none"},
	},
	{
		name: "the password is percent-decoded",
		uri:  "trojan://p%40ss%3Aw%2Frd%25%23%3F@203.0.113.44:443",
		want: Server{Protocol: "trojan", Address: "203.0.113.44", Port: 443, Password: "p@ss:w/rd%#?", Network: "tcp", Security: "tls"},
	},
	{
		name: "a plus in the password stays a plus",
		uri:  "trojan://a+b@203.0.113.44:443",
		want: Server{Protocol: "trojan", Address: "203.0.113.44", Port: 443, Password: "a+b", Network: "tcp", Security: "tls"},
	},
	{
		name: "an at sign in the password belongs to the password",
		uri:  "trojan://p@ss@203.0.113.44:443",
		want: Server{Protocol: "trojan", Address: "203.0.113.44", Port: 443, Password: "p@ss", Network: "tcp", Security: "tls"},
	},
	{
		name: "ipv6 literal",
		uri:  "trojan://" + testPassword + "@[2001:db8::1]:8443#v6",
		want: Server{Protocol: "trojan", Name: "v6", Address: "2001:db8::1", Port: 8443, Password: testPassword, Network: "tcp", Security: "tls"},
	},
	{
		name: "peer is an alias of sni and allowInsecure accepts true",
		uri:  "trojan://" + testPassword + "@203.0.113.45:443?peer=peer.example.com&allowInsecure=true",
		want: Server{Protocol: "trojan", Address: "203.0.113.45", Port: 443, Password: testPassword, Network: "tcp", Security: "tls", SNI: "peer.example.com", AllowInsecure: true},
	},
	{
		name: "reality",
		uri:  "trojan://" + testPassword + "@203.0.113.46:443?security=reality&sni=www.example.com&fp=chrome&pbk=" + testPubKey + "&sid=" + testShortID,
		want: Server{
			Protocol: "trojan", Address: "203.0.113.46", Port: 443, Password: testPassword, Network: "tcp", Security: "reality",
			SNI: "www.example.com", Fingerprint: "chrome", PublicKey: testPubKey, ShortID: testShortID,
		},
	},
}

func trojan(rest string) string { return "trojan://" + testPassword + "@" + rest }

var trojanErrors = []errCase{
	{"no userinfo", "trojan://203.0.113.40:443", "trojan: missing password"},
	{"empty password", "trojan://@203.0.113.40:443", "trojan: missing password"},
	{"bad escape in the password", "trojan://%zz" + testPassword + "@203.0.113.40:443", "trojan: invalid password"},
	{"password that is not UTF-8", "trojan://%FF@203.0.113.40:443", "trojan: invalid password"},
	{"control character in the password", "trojan://a%00b@203.0.113.40:443", "trojan: invalid password"},
	{"no host", trojan(":443"), "trojan: missing address"},
	{"port 0", trojan("203.0.113.40:0"), "trojan: invalid port"},
	{"port 70000", trojan("203.0.113.40:70000"), "trojan: invalid port"},
	{"unsupported security", trojan("203.0.113.40:443?security=xtls"), "trojan: unsupported security"},
	{"unsupported network", trojan("203.0.113.40:443?type=kcp"), "trojan: unsupported network"},
	{"reality without a public key", trojan("203.0.113.40:443?security=reality&sni=www.example.com"), "trojan: missing pbk"},
	{"ipv6 without brackets", trojan("2001:db8::1:443"), "trojan: invalid address"},
}

func TestParseTrojan(t *testing.T)       { runParseCases(t, trojanCases) }
func TestParseTrojanErrors(t *testing.T) { runErrorCases(t, "trojan", trojanErrors) }

// ---- shadowsocks -----------------------------------------------------------

var ssCases = []parseCase{
	{
		name: "SIP002, base64url without padding",
		uri:  "ss://" + ssUserSIP002 + "@192.0.2.1:8888#Example1",
		want: Server{Protocol: "shadowsocks", Name: "Example1", Address: "192.0.2.1", Port: 8888, Method: "aes-128-gcm", Password: "test", Network: "tcp", Security: "none"},
	},
	{
		name: "base64 with padding",
		uri:  "ss://" + ssUserSIP002 + "==@192.0.2.1:8888",
		want: Server{Protocol: "shadowsocks", Address: "192.0.2.1", Port: 8888, Method: "aes-128-gcm", Password: "test", Network: "tcp", Security: "none"},
	},
	{
		name: "padding percent-encoded",
		uri:  "ss://" + ssUserSIP002 + "%3D%3D@192.0.2.1:8888",
		want: Server{Protocol: "shadowsocks", Address: "192.0.2.1", Port: 8888, Method: "aes-128-gcm", Password: "test", Network: "tcp", Security: "none"},
	},
	{
		name: "standard alphabet with a slash in the userinfo",
		uri:  "ss://YWVzLTI1Ni1nY206Pz8/@192.0.2.1:8388",
		want: Server{Protocol: "shadowsocks", Address: "192.0.2.1", Port: 8388, Method: "aes-256-gcm", Password: "???", Network: "tcp", Security: "none"},
	},
	{
		name: "url alphabet with an underscore",
		uri:  "ss://YWVzLTI1Ni1nY206Pz8_@192.0.2.1:8388",
		want: Server{Protocol: "shadowsocks", Address: "192.0.2.1", Port: 8388, Method: "aes-256-gcm", Password: "???", Network: "tcp", Security: "none"},
	},
	{
		name: "standard alphabet with a plus",
		uri:  "ss://YWVzLTI1Ni1nY206Pj4+@192.0.2.1:8388",
		want: Server{Protocol: "shadowsocks", Address: "192.0.2.1", Port: 8388, Method: "aes-256-gcm", Password: ">>>", Network: "tcp", Security: "none"},
	},
	{
		name: "plain method:password",
		uri:  "ss://aes-256-gcm:" + testPassword + "@192.0.2.2:8388#plain",
		want: Server{Protocol: "shadowsocks", Name: "plain", Address: "192.0.2.2", Port: 8388, Method: "aes-256-gcm", Password: testPassword, Network: "tcp", Security: "none"},
	},
	{
		name: "plain AEAD-2022 with a percent-encoded key (SIP002 example)",
		uri:  "ss://" + ssUser2022 + "@192.0.2.1:8888#Example3",
		want: Server{
			Protocol: "shadowsocks", Name: "Example3", Address: "192.0.2.1", Port: 8888,
			Method: "2022-blake3-aes-256-gcm", Password: "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=", Network: "tcp", Security: "none", // gitleaks:allow (the example key of SIP002, not a secret)
		},
	},
	{
		name: "a colon in the password",
		uri:  "ss://aes-256-gcm:pa:ss@192.0.2.1:8388",
		want: Server{Protocol: "shadowsocks", Address: "192.0.2.1", Port: 8388, Method: "aes-256-gcm", Password: "pa:ss", Network: "tcp", Security: "none"},
	},
	{
		name: "ipv6 literal",
		uri:  "ss://" + ssUserChaCha + "@[2001:db8::5]:8388#v6",
		want: Server{Protocol: "shadowsocks", Name: "v6", Address: "2001:db8::5", Port: 8388, Method: "chacha20-ietf-poly1305", Password: testPassword, Network: "tcp", Security: "none"},
	},
	{
		name: "a slash and an empty query after the port",
		uri:  "ss://" + ssUserAES256 + "@192.0.2.1:8388/?#slash",
		want: Server{Protocol: "shadowsocks", Name: "slash", Address: "192.0.2.1", Port: 8388, Method: "aes-256-gcm", Password: testPassword, Network: "tcp", Security: "none"},
	},
	{
		name: "an empty plugin is no plugin",
		uri:  "ss://" + ssUserAES256 + "@192.0.2.1:8388/?plugin=",
		want: Server{Protocol: "shadowsocks", Address: "192.0.2.1", Port: 8388, Method: "aes-256-gcm", Password: testPassword, Network: "tcp", Security: "none"},
	},
	{
		name: "the name is percent-decoded",
		uri:  "ss://" + ssUserAES256 + "@192.0.2.1:8388#%E2%9C%93%20ok",
		want: Server{Protocol: "shadowsocks", Name: string(rune(0x2713)) + " ok", Address: "192.0.2.1", Port: 8388, Method: "aes-256-gcm", Password: testPassword, Network: "tcp", Security: "none"},
	},
	{
		name: "scheme in capitals",
		uri:  "SS://" + ssUserAES256 + "@192.0.2.1:8388",
		want: Server{Protocol: "shadowsocks", Address: "192.0.2.1", Port: 8388, Method: "aes-256-gcm", Password: testPassword, Network: "tcp", Security: "none"},
	},
}

var ssErrors = []errCase{
	{"plugin (SIP002 example)", "ss://" + ssUserRC4 + "@192.0.2.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2", "ss: plugins not supported"},
	{"plugin on the plain form", "ss://aes-256-gcm:" + testPassword + "@192.0.2.1:8388?plugin=v2ray-plugin", "ss: plugins not supported"},
	{"plugin that cannot be decoded", "ss://" + ssUserAES256 + "@192.0.2.1:8388/?plugin=%zz", "ss: plugins not supported"},
	{"no port after base64 userinfo", "ss://" + ssUserAES256 + "@192.0.2.1#n", "ss: missing port"},
	{"no port after plain userinfo", "ss://aes-256-gcm:" + testPassword + "@192.0.2.1", "ss: missing port"},
	{"no port after an ipv6 address", "ss://" + ssUserAES256 + "@[2001:db8::5]", "ss: missing port"},
	{"port 0", "ss://" + ssUserAES256 + "@192.0.2.1:0", "ss: invalid port"},
	{"port 65536", "ss://" + ssUserAES256 + "@192.0.2.1:65536", "ss: invalid port"},
	{"no host", "ss://" + ssUserAES256 + "@:8388", "ss: missing address"},
	{"no userinfo", "ss://192.0.2.1:8388", "ss: missing userinfo"},
	{"empty userinfo", "ss://@192.0.2.1:8388", "ss: missing userinfo"},
	{"bad escape in the userinfo", "ss://%zz" + testPassword + "@192.0.2.1:8388", "ss: invalid userinfo"},
	{"userinfo that is neither base64 nor method:password", "ss://not*base64@192.0.2.1:8388", "ss: invalid userinfo"},
	{"base64 of a text without a colon", "ss://YWVzLTI1Ni1nY20@192.0.2.1:8388", "ss: invalid userinfo"},
	{"base64 of text that is not UTF-8", "ss://YWVzOv/+@192.0.2.1:8388", "ss: invalid userinfo"},
	{"base64 of text with a control character", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:a\x00b")) + "@192.0.2.1:8388", "ss: invalid userinfo"},
	{"plain userinfo with a control character", "ss://aes-256-gcm:a%00b@192.0.2.1:8388", "ss: invalid userinfo"},
	{"empty method", "ss://:" + testPassword + "@192.0.2.1:8388", "ss: missing method"},
	{"empty password in the plain form", "ss://aes-256-gcm:@192.0.2.1:8388", "ss: missing password"},
	{"empty password in base64", "ss://YWVzLTI1Ni1nY206@192.0.2.1:8388", "ss: missing password"},
	// The pre-SIP002 form base64(method:password@host:port) is not supported, and
	// says so instead of "missing userinfo" or a port or address error.
	{"legacy form", "ss://" + ssLegacy + "=#legacy", "ss: legacy form not supported"},
	{"legacy form without padding", "ss://" + ssLegacy + "#legacy", "ss: legacy form not supported"},
	{"legacy form with percent-encoded padding", "ss://" + ssLegacy + "%3D#legacy", "ss: legacy form not supported"},
	{"legacy form in the URL alphabet", "ss://" + strings.NewReplacer("+", "-", "/", "_").Replace(ssLegacySlash) + "#legacy", "ss: legacy form not supported"},
	{"legacy form with a slash in the payload", "ss://" + ssLegacySlash + "#legacy", "ss: legacy form not supported"},
	{"legacy form with a slash after the payload", "ss://" + ssLegacy + "=/#legacy", "ss: legacy form not supported"},
	{"legacy form with an empty query", "ss://" + ssLegacy + "=/?#legacy", "ss: legacy form not supported"},
	{"no @ in the decoded text is not the legacy form", "ss://YWVzLTI1Ni1nY206cHc#n", "ss: missing userinfo"},
	{"a host that is not base64 is not the legacy form", "ss://203.0.113.10:8388#n", "ss: missing userinfo"},
	{"with a userinfo it is not the legacy form", "ss://" + ssUserAES256 + "@" + ssLegacy, "ss: missing port"},
	{"a bad escape is not the legacy form", "ss://%zz" + ssLegacy + "#n", "ss: missing userinfo"},
}

// ssLegacy is base64 (no padding, "=" is added where a test needs it) of the old
// form, aes-256-gcm:pa55w0rd-not-real@192.0.2.1:8388. ssLegacySlash is the same
// with a password that puts a "/" into the standard alphabet.
const ssLegacy = "YWVzLTI1Ni1nY206cGE1NXcwcmQtbm90LXJlYWxAMTkyLjAuMi4xOjgzODg"

var ssLegacySlash = base64.RawStdEncoding.EncodeToString([]byte("aes-256-gcm:???@192.0.2.1:8388"))

func TestParseSS(t *testing.T)       { runParseCases(t, ssCases) }
func TestParseSSErrors(t *testing.T) { runErrorCases(t, "ss", ssErrors) }

// ---- anything else ---------------------------------------------------------

var genericErrors = []errCase{
	{"empty", "", "invalid URI: missing scheme"},
	{"blank", " \t\n", "invalid URI: missing scheme"},
	{"no scheme", "203.0.113.10:443", "invalid URI: missing scheme"},
	{"a credential and no scheme", testUUID + "@203.0.113.10:443", "invalid URI: missing scheme"},
	{"empty scheme", "://" + testPassword + "@203.0.113.10:443", "unsupported scheme"},
	{"hysteria2", "hysteria2://" + testPassword + "@203.0.113.10:443#nope", `unsupported scheme "hysteria2"`},
	{"http", "http://example.com/", `unsupported scheme "http"`},
	{"ssr", "ssr://" + ssUserAES256, `unsupported scheme "ssr"`},
	{"scheme folded to lower case", "TUIC://" + testUUID + ":" + testPassword + "@203.0.113.10:443", `unsupported scheme "tuic"`},
	{"scheme too long to be named", strings.Repeat("a", 40) + "://" + testPassword + "@203.0.113.10", "unsupported scheme"},
	{"scheme that is not one", "ab cd://" + testPassword, "unsupported scheme"},
	{"nul in the name", vless("203.0.113.10:443#a\x00b"), "invalid URI: control character"},
	{"line break inside", vless("203.0.113.10:443\n") + vless("203.0.113.11:443"), "invalid URI: control character"},
	{"tab inside", vless("203.0.113.10:443?type=\ttcp"), "invalid URI: control character"},
}

func TestParseGenericErrors(t *testing.T) { runErrorCases(t, "", genericErrors) }

// TestErrorsNeverEchoSecrets plants SENTINEL text in the credentials and in the
// very value that makes each link fail, and requires that no error repeats it.
func TestErrorsNeverEchoSecrets(t *testing.T) {
	const (
		id   = "SENTINEL-ID-4f1d7c2a"
		pw   = "SENTINEL-PW-81e3b6d0"
		junk = "SENTINEL-VALUE-9a5e"
	)
	vmess := func(obj string) string {
		obj = strings.NewReplacer("@ID@", id, "@JUNK@", junk).Replace(obj)
		return "vmess://" + base64.StdEncoding.EncodeToString([]byte(obj))
	}
	ssUser := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:" + pw))
	const host = "203.0.113.10"

	uris := []string{
		// vless
		"vless://" + id + "@" + host + ":" + junk + "?type=tcp",
		"vless://" + id + "@" + junk + " x:443",
		"vless://" + id + "@[" + junk + "]:443",
		"vless://" + id + "@" + host + ":443?type=" + junk,
		"vless://" + id + "@" + host + ":443?security=" + junk,
		"vless://" + id + "@" + host + ":443?encryption=" + junk,
		"vless://" + id + "@" + host + ":443?type=xhttp&extra=" + junk,
		"vless://" + id + "@" + host + ":443?security=reality&sid=" + junk + "&spx=" + junk,
		"vless://" + id + "@" + host + ":443?path=%zz" + junk,
		"vless://" + id + "@" + host + ":443?sni=%FF" + junk,
		"vless://%zz" + id + "@" + host + ":443",
		"vless://@" + host + ":443?path=" + junk,
		// trojan
		"trojan://" + pw + "@" + host + ":" + junk,
		"trojan://" + pw + "@" + host + ":443?security=" + junk,
		"trojan://" + pw + "@" + host + ":443?type=" + junk,
		"trojan://%zz" + pw + "@" + host + ":443",
		"trojan://@" + host + ":443?sni=" + junk,
		// shadowsocks
		"ss://" + ssUser + "@" + host + ":" + junk,
		"ss://" + ssUser + "@" + host,
		"ss://" + ssUser + "@" + host + ":8388/?plugin=" + junk,
		"ss://" + junk + "@" + host + ":8388",
		"ss://aes-256-gcm:" + pw + "@" + host,
		"ss://:" + pw + "@" + host + ":8388",
		"ss://aes-256-gcm:@" + host + ":8388#" + junk,
		"ss://" + base64.RawStdEncoding.EncodeToString([]byte("aes-256-gcm:"+pw+"@"+host+":8388")) + "#" + junk,
		// vmess
		vmess(`{"add":"` + host + `","port":"@JUNK@","id":"@ID@"}`),
		vmess(`{"add":"` + host + `","port":443,"id":"@ID@","aid":"@JUNK@"}`),
		vmess(`{"add":"` + host + `","port":443,"id":"@ID@","aid":64,"ps":"@JUNK@"}`),
		vmess(`{"add":"` + host + `","port":443,"id":"@ID@","net":"@JUNK@"}`),
		vmess(`{"add":"` + host + `","port":443,"id":"@ID@","tls":"@JUNK@"}`),
		vmess(`{"add":"@JUNK@ x","port":443,"id":"@ID@"}`),
		vmess(`{"add":"` + host + `","port":443,"id":"@ID@","host":{"a":"@JUNK@"}}`),
		vmess(`{"add":"` + host + `","port":443,"id":"@ID@","path":["@JUNK@"]}`),
		vmess(`{"add":"` + host + `","id":"@ID@","ps":"@JUNK@"}`),
		vmess(`{"port":443,"id":"@ID@","ps":"@JUNK@"}`),
		vmess(`{"add":"` + host + `","port":443,"id":"@ID@"`),
		vmess(`not json @ID@ @JUNK@`),
		"vmess://" + id + "!!!",
		"vmess://%zz" + id,
		// anything else
		junk + "://" + id + "@" + host,
		id + "@" + host + ":443",
		"hysteria2://" + pw + "@" + host + ":443#" + junk,
	}

	check := func(t *testing.T, err error, input string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%q was accepted", input)
		}
		if lower := strings.ToLower(err.Error()); strings.Contains(lower, "sentinel") {
			t.Errorf("error %q repeats a value of the input", err)
		}
		if strings.Contains(err.Error(), strings.TrimSpace(input)) {
			t.Errorf("error %q holds the whole input", err)
		}
	}
	for _, uri := range uris {
		_, err := Parse(uri)
		check(t, err, uri)
	}

	// The same lines in a subscription.
	servers, errs := ParseSubscription([]byte(strings.Join(uris, "\n")))
	if len(servers) != 0 {
		t.Errorf("ParseSubscription accepted %d of the broken links", len(servers))
	}
	if len(errs) != len(uris) {
		t.Fatalf("ParseSubscription returned %d errors for %d links", len(errs), len(uris))
	}
	for i, err := range errs {
		check(t, err, uris[i])
	}
}

// ---- Key -------------------------------------------------------------------

func TestKeyKnownAnswers(t *testing.T) {
	// The wants were made with sha256sum over the documented input,
	// protocol|address|port|id with the address folded. A trojan or shadowsocks
	// server has no id, and its password is not in the input: the passwords below
	// are there to show that.
	cases := []struct {
		name string
		s    Server
		want string
	}{
		{"vless", Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID}, "21f04a761977"},
		{"trojan on ipv6", Server{Protocol: "trojan", Address: "2001:db8::1", Port: 8443, Password: testPassword}, "c17ba9cbb262"},
		{"vmess", Server{Protocol: "vmess", Address: "vmess.example.com", Port: 8443, ID: testUUID2}, "0ea21bbfb43b"},
		{"shadowsocks", Server{Protocol: "shadowsocks", Address: "192.0.2.1", Port: 8388, Method: "aes-256-gcm", Password: "test"}, "7a543e515140"},

		// The address is folded before it is hashed, so each spelling here has the
		// key of the folded one: host.example.com, 2001:db8::1, 2001:db8::a and
		// ::ffff:192.0.2.1.
		{"name in lower case", Server{Protocol: "vless", Address: "host.example.com", Port: 443, ID: testUUID}, "b329768238ca"},
		{"name in upper case", Server{Protocol: "vless", Address: "HOST.EXAMPLE.COM", Port: 443, ID: testUUID}, "b329768238ca"},
		{"name in mixed case", Server{Protocol: "vless", Address: "Host.Example.com", Port: 443, ID: testUUID}, "b329768238ca"},
		{"ipv6 in lower case", Server{Protocol: "vless", Address: "2001:db8::1", Port: 443, ID: testUUID}, "1ad99fc07973"},
		{"ipv6 in upper case", Server{Protocol: "vless", Address: "2001:DB8::1", Port: 443, ID: testUUID}, "1ad99fc07973"},
		{"ipv6 written out in full", Server{Protocol: "vless", Address: "2001:0DB8:0000:0000:0000:0000:0000:0001", Port: 443, ID: testUUID}, "1ad99fc07973"},
		{"ipv6 with a run of zeros", Server{Protocol: "vless", Address: "2001:DB8:0:0::A", Port: 443, ID: testUUID}, "cc4d0b047242"},
		{"ipv4 in ipv6", Server{Protocol: "vless", Address: "::FFFF:192.0.2.1", Port: 443, ID: testUUID}, "616ca73c5ff3"},
		// The ends of the ASCII fold: every letter from A to Z, a name that ends
		// in Z's, and names whose only upper-case letter is the last or the first.
		{"every letter, A to Z", Server{Protocol: "vless", Address: "ABCDEFGHIJKLMNOPQRSTUVWXYZ.example.com", Port: 443, ID: testUUID}, "ac71fa15a6b5"},
		{"a name with Z in it", Server{Protocol: "vless", Address: "ZEBRA.EXAMPLE.COM", Port: 443, ID: testUUID}, "b01c3dc0abd2"},
		{"Z is the only upper-case letter", Server{Protocol: "vless", Address: "Z.example.com", Port: 443, ID: testUUID}, "65c52a28ab65"},
		{"A is the only upper-case letter", Server{Protocol: "vless", Address: "A.example.com", Port: 443, ID: testUUID}, "9441de6a17fc"},
		// Only ASCII is folded: U+00C4 stays upper case, and U+00E4 is another name.
		{"non-ASCII upper case stays", Server{Protocol: "vless", Address: string(rune(0xC4)) + ".EXAMPLE.COM", Port: 443, ID: testUUID}, "35a01f59d39e"},
		{"non-ASCII lower case is another name", Server{Protocol: "vless", Address: string(rune(0xE4)) + ".example.com", Port: 443, ID: testUUID}, "727b2c29b0ca"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.Key(); got != tc.want {
				t.Errorf("Key() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestKeyFoldsTheAddress: spellings of one address are one server, and Address
// itself stays as it was written.
func TestKeyFoldsTheAddress(t *testing.T) {
	groups := [][]string{
		{"HOST.EXAMPLE.COM", "host.example.com", "Host.Example.com"},
		{"2001:DB8::1", "2001:db8::1", "2001:db8:0::1", "2001:0DB8:0:0:0:0:0:1"},
		{"203.0.113.10"},
		{"203.0.113.11"},
	}
	seen := map[string]int{}
	for i, group := range groups {
		var first string
		for _, address := range group {
			s := Server{Protocol: "vless", Address: address, Port: 443, ID: testUUID}
			key := s.Key()
			if s.Address != address {
				t.Errorf("Key() changed the Address %q to %q", address, s.Address)
			}
			if first == "" {
				first = key
			} else if key != first {
				t.Errorf("%q has the key %q, but %q has %q", address, key, group[0], first)
			}
		}
		if other, dup := seen[first]; dup {
			t.Errorf("group %d has the key of group %d: %q", i, other, first)
		}
		seen[first] = i
	}

	// The same through Parse, and through a refreshed subscription.
	cases := [][2]string{
		{vless("HOST.EXAMPLE.COM:443"), vless("host.example.com")},
		{vless("[2001:DB8::1]:443"), vless("[2001:db8::1]")},
		{trojan("Host.Example.com:8443"), trojan("host.example.COM:8443")},
	}
	for _, c := range cases {
		a, errA := Parse(c[0])
		b, errB := Parse(c[1])
		if errA != nil || errB != nil {
			t.Fatalf("Parse: %v, %v", errA, errB)
		}
		if a.Key() != b.Key() {
			t.Errorf("%q and %q: keys %q and %q", a.Address, b.Address, a.Key(), b.Key())
		}
		if a.Address == b.Address {
			t.Errorf("Parse folded the address %q: it must keep what the link wrote", a.Address)
		}
	}
	servers, _ := ParseSubscription([]byte(vless("HOST.EXAMPLE.COM:443") + "\n" + vless("host.example.com:443") + "\n" + vless("other.example.com:443")))
	if len(servers) != 3 || servers[0].Key() != servers[1].Key() || servers[0].Key() == servers[2].Key() {
		t.Errorf("keys of a subscription: %d servers", len(servers))
	}
}

func TestKeyDependsOnTheIdentityOnly(t *testing.T) {
	base := Server{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID, Password: testPassword}
	key := base.Key()

	// These do not make another member.
	same := base
	same.Name = "renamed"
	same.Password = "another-password"
	same.Method = "aes-256-gcm"
	same.Flow = "xtls-rprx-vision"
	same.Network = "ws"
	same.Security = "reality"
	same.SNI, same.Fingerprint, same.PublicKey, same.ShortID, same.SpiderX = "a", "b", "c", "d", "e"
	same.Path, same.Host, same.ServiceName, same.Mode, same.ALPN, same.Extra = "f", "g", "h", "i", "j", "{}"
	same.AllowInsecure = true
	if got := same.Key(); got != key {
		t.Errorf("Key() changed to %q when only the settings changed, want %q", got, key)
	}

	// Each of these does.
	for name, mutate := range map[string]func(*Server){
		"protocol": func(s *Server) { s.Protocol = "trojan" },
		"address":  func(s *Server) { s.Address = "203.0.113.11" },
		"port":     func(s *Server) { s.Port = 444 },
		"id":       func(s *Server) { s.ID = testUUID2 },
	} {
		other := base
		mutate(&other)
		if got := other.Key(); got == key {
			t.Errorf("Key() did not change with the %s", name)
		}
	}
}

// TestKeyIgnoresThePassword: keys are logged everywhere, and an unsalted hash of a
// password would let anyone who reads a log guess a weak one offline.
func TestKeyIgnoresThePassword(t *testing.T) {
	// Two links that differ only by the password are one member.
	pairs := [][2]string{
		{"trojan://" + testPassword + "@203.0.113.40:443?sni=t.example.com#a", "trojan://another-password@203.0.113.40:443?sni=t.example.com#b"},
		{"trojan://" + testPassword + "@203.0.113.40:443", "trojan://p%40ss%3Aw%2Frd@203.0.113.40"},
		{"ss://aes-256-gcm:" + testPassword + "@192.0.2.1:8388", "ss://chacha20-ietf-poly1305:another-password@192.0.2.1:8388"},
		{"ss://" + ssUserSIP002 + "@192.0.2.1:8388", "ss://" + ssUserAES256 + "@192.0.2.1:8388#renamed"},
	}
	for _, pair := range pairs {
		a, errA := Parse(pair[0])
		b, errB := Parse(pair[1])
		if errA != nil || errB != nil {
			t.Fatalf("Parse: %v, %v", errA, errB)
		}
		if a.Password == b.Password {
			t.Fatalf("the links have the same password %q: the test proves nothing", a.Password)
		}
		if a.Key() != b.Key() {
			t.Errorf("%s servers that differ by the password only have the keys %q and %q", a.Protocol, a.Key(), b.Key())
		}
	}

	// No key changes when only the password does, whatever the protocol.
	for _, base := range []Server{
		{Protocol: "trojan", Address: "203.0.113.40", Port: 443},
		{Protocol: "shadowsocks", Address: "192.0.2.1", Port: 8388, Method: "aes-256-gcm"},
		{Protocol: "vless", Address: "203.0.113.10", Port: 443, ID: testUUID},
		{Protocol: "vmess", Address: "vmess.example.com", Port: 8443, ID: testUUID2},
	} {
		want := base.Key()
		for _, password := range []string{"", testPassword, "another-password", strings.Repeat("x", 1000)} {
			s := base
			s.Password = password
			if got := s.Key(); got != want {
				t.Errorf("%s: a password of %d bytes changed the key from %q to %q", base.Protocol, len(password), want, got)
			}
		}
	}
}

// TestAsciiLower checks the fold at the ends of the ASCII upper-case range, the
// characters next to them, and bytes that are not ASCII.
func TestAsciiLower(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"host.example.com", "host.example.com"},
		{"HOST.EXAMPLE.COM", "host.example.com"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"},
		{"abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"},
		{"A", "a"},
		{"Z", "z"},
		{"a", "a"},
		{"z", "z"},
		{"A.example.com", "a.example.com"},
		{"Z.example.com", "z.example.com"},
		{"example.com.A", "example.com.a"},
		{"example.com.Z", "example.com.z"},
		// The characters just below A and just above Z, and just around a and z.
		{"@AZ[`az{", "@az[`az{"},
		{"0123456789-_.", "0123456789-_."},
		// Bytes of UTF-8 sequences, and of invalid ones, are not letters.
		{"\xC3\x84B", "\xC3\x84b"},
		{"a\xC3\x84B\xE2\x82\xACZ", "a\xC3\x84b\xE2\x82\xACz"},
		{"\xFFABC", "\xFFabc"},
		{"\xC3\x84\xC3\x96", "\xC3\x84\xC3\x96"},
	}
	for _, tc := range cases {
		if got := asciiLower(tc.in); got != tc.want {
			t.Errorf("asciiLower(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestKeyOfParsedLinks(t *testing.T) {
	a, err := Parse("vless://" + testUUID + "@203.0.113.10:443?type=ws&path=%2Fa#first")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse("vless://" + testUUID + "@203.0.113.10?type=grpc&serviceName=b#second")
	if err != nil {
		t.Fatal(err)
	}
	if a.Key() != b.Key() {
		t.Errorf("the same server got the keys %q and %q", a.Key(), b.Key())
	}
	if want := "21f04a761977"; a.Key() != want {
		t.Errorf("Key() = %q, want %q", a.Key(), want)
	}
	v6, err := Parse("trojan://" + testPassword + "@[2001:db8::1]:8443")
	if err != nil {
		t.Fatal(err)
	}
	if want := "c17ba9cbb262"; v6.Key() != want {
		t.Errorf("Key() of an ipv6 server = %q, want %q (the address has no brackets in it)", v6.Key(), want)
	}
}

// ---- logging ---------------------------------------------------------------

// shownFields are the fields that a Server prints: everything else is secret or
// identifies the server.
var shownFields = map[string]bool{"Protocol": true, "Name": true}

// sentinelServer has its own SENTINEL text in every string field, the port 61234
// and AllowInsecure on.
func sentinelServer(t *testing.T) Server {
	t.Helper()
	s := Server{Port: 61234, AllowInsecure: true}
	rv := reflect.ValueOf(&s).Elem()
	for i := range rv.NumField() {
		if rv.Field(i).Kind() == reflect.String {
			rv.Field(i).SetString("SENTINEL-" + rv.Type().Field(i).Name)
		}
	}
	if strings.Contains(s.Key(), "61234") {
		t.Fatal("the key holds the digits of the port: pick another port for the sentinel")
	}
	return s
}

// requireRedacted fails when out holds the sentinel of a field that must stay out
// of it, the name of such a field, the port or AllowInsecure, or when it lacks
// the sentinels of the fields that are shown.
func requireRedacted(t *testing.T, label, out string) {
	t.Helper()
	rt := reflect.TypeOf(Server{})
	for i := range rt.NumField() {
		f := rt.Field(i)
		sentinel := "SENTINEL-" + f.Name
		switch {
		case shownFields[f.Name]:
			if !strings.Contains(out, sentinel) {
				t.Errorf("%s: %q lacks the %s", label, out, f.Name)
			}
		case strings.Contains(out, sentinel):
			t.Errorf("%s: %q holds the %s", label, out, f.Name)
		case strings.Contains(out, f.Name+":"), strings.Contains(out, `"`+f.Name+`"`):
			t.Errorf("%s: %q looks like a dump of the fields", label, out)
		}
	}
	for _, leak := range []string{"61234", "AllowInsecure", "SENTINEL-Address", "SENTINEL-Password"} {
		if strings.Contains(out, leak) {
			t.Errorf("%s: %q holds %q", label, out, leak)
		}
	}
}

// withoutTime drops the time of a log line, whose digits could be any.
func withoutTime(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

// formatEverywhere prints v with every verb and logger that a Server may reach.
// slog's JSON handler is left out unless withJSON is set.
func formatEverywhere(v any, withJSON bool) map[string]string {
	out := map[string]string{
		"Sprint":   fmt.Sprint(v),
		"Sprintln": fmt.Sprintln(v),
		"%v":       fmt.Sprintf("%v", v),
		"%+v":      fmt.Sprintf("%+v", v),
		"%#v":      fmt.Sprintf("%#v", v),
		"%s":       fmt.Sprintf("%s", v),
		"%q":       fmt.Sprintf("%q", v),
		"error":    fmt.Errorf("bad server %v: %w", v, errors.New("cause")).Error(),
	}
	opts := &slog.HandlerOptions{ReplaceAttr: withoutTime}
	var text, structured bytes.Buffer
	slog.New(slog.NewTextHandler(&text, opts)).Info("member", "server", v)
	slog.New(slog.NewTextHandler(&text, opts)).Info("member", slog.Any("server", v))
	out["slog text"] = text.String()
	if withJSON {
		slog.New(slog.NewJSONHandler(&structured, opts)).Info("member", "server", v)
		out["slog json"] = structured.String()
	}
	return out
}

func TestServerIsRedactedInLogs(t *testing.T) {
	s := sentinelServer(t)
	values := []struct {
		name     string
		v        any
		withJSON bool // false where slog's JSON handler marshals the value with encoding/json, see Server
	}{
		{"Server", s, true},
		{"*Server", &s, true},
		{"[]*Server", []*Server{&s, &s}, false},
		{"[]Server", []Server{s, s}, false},
		{"map of *Server", map[string]*Server{"a": &s}, false},
		{"Server in an exported field", struct{ Member Server }{s}, false},
		{"*Server in an exported field", struct{ Member *Server }{&s}, false},
	}
	for _, tc := range values {
		t.Run(tc.name, func(t *testing.T) {
			for label, out := range formatEverywhere(tc.v, tc.withJSON) {
				requireRedacted(t, label, out)
			}
		})
	}
}

func TestServerRedactedForms(t *testing.T) {
	// The key of this server, from vless|203.0.113.10|443|<testUUID>, was made with sha256sum.
	s := Server{
		Protocol: "vless", Name: "plain", Address: "203.0.113.10", Port: 443, ID: testUUID,
		PublicKey: testPubKey, Path: "/secret-path",
	}
	const want = `egressuri.Server{key=21f04a761977, protocol=vless, name="plain"}`
	for label, got := range map[string]string{
		"String":    s.String(),
		"GoString":  s.GoString(),
		"Sprint":    fmt.Sprint(s),
		"Sprint *":  fmt.Sprint(&s),
		"%v":        fmt.Sprintf("%v", &s),
		"%+v":       fmt.Sprintf("%+v", s),
		"%#v":       fmt.Sprintf("%#v", &s),
		"in a list": strings.TrimSuffix(strings.TrimPrefix(fmt.Sprint([]*Server{&s}), "["), "]"),
	} {
		if got != want {
			t.Errorf("%s: %q, want %q", label, got, want)
		}
	}

	// A name that looks like the rest of the line stays inside its quotes.
	odd := Server{Protocol: "trojan", Name: `a "b", c}`, Address: "203.0.113.10", Port: 443, Password: testPassword}
	if got, want := odd.String(), `egressuri.Server{key=`+odd.Key()+`, protocol=trojan, name="a \"b\", c}"}`; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	// slog: a group of exactly key, protocol and name.
	v := s.LogValue()
	if v.Kind() != slog.KindGroup {
		t.Fatalf("LogValue() is a %v, want a group", v.Kind())
	}
	var got []string
	for _, a := range v.Group() {
		got = append(got, a.Key+"="+a.Value.String())
	}
	if want := []string{"key=21f04a761977", "protocol=vless", "name=plain"}; !reflect.DeepEqual(got, want) {
		t.Errorf("LogValue() = %v, want %v", got, want)
	}
	opts := &slog.HandlerOptions{ReplaceAttr: withoutTime}
	var text, structured bytes.Buffer
	slog.New(slog.NewTextHandler(&text, opts)).Info("member", "server", &s)
	if want := "level=INFO msg=member server.key=21f04a761977 server.protocol=vless server.name=plain\n"; text.String() != want {
		t.Errorf("text handler: %q, want %q", text.String(), want)
	}
	slog.New(slog.NewJSONHandler(&structured, opts)).Info("member", "server", s)
	if want := `{"level":"INFO","msg":"member","server":{"key":"21f04a761977","protocol":"vless","name":"plain"}}` + "\n"; structured.String() != want {
		t.Errorf("JSON handler: %q, want %q", structured.String(), want)
	}

	// A nil *Server prints as nil, and logging one does not panic.
	var none *Server
	if got := fmt.Sprint(none); got != "<nil>" {
		t.Errorf("Sprint(nil *Server) = %q", got)
	}
	slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)).Info("member", "server", none)
}

// TestServerStillMarshalsInFull: the members of an egress are saved as JSON, which
// needs the credentials, so redaction is only for printing and logging.
func TestServerStillMarshalsInFull(t *testing.T) {
	s := sentinelServer(t)
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"SENTINEL-ID", "SENTINEL-Password", "SENTINEL-PublicKey", "SENTINEL-Address"} {
		if !strings.Contains(string(data), field) {
			t.Errorf("the JSON of a Server lacks %s: %s", field, data)
		}
	}
	var back Server
	if err := json.Unmarshal(data, &back); err != nil || back != s {
		t.Errorf("a Server did not survive JSON: %v%s", err, diffServer(back, s))
	}
}

// ---- subscriptions ---------------------------------------------------------

var subscriptionLines = []string{
	"vless://" + testUUID + "@203.0.113.10:443?type=tcp&security=none#one",
	"trojan://" + testPassword + "@203.0.113.11:443?sni=t.example.com#two",
	"ss://" + ssUserSIP002 + "@203.0.113.12:8388#three",
	vmessLink(`{"ps":"four","add":"203.0.113.13","port":"443","id":"UUID","aid":"0","net":"ws","path":"/four","tls":"tls"}`),
}

// subscriptionWant is what the lines above parse to: names and addresses.
var subscriptionWant = [][2]string{
	{"one", "203.0.113.10"},
	{"two", "203.0.113.11"},
	{"three", "203.0.113.12"},
	{"four", "203.0.113.13"},
}

// subscriptionBanner is a comment made to put '+' and '/' into the base64 of a
// body that holds it, wherever it falls in the text: runs of 18 bytes of '?'
// and of '>' cover every alignment.
var subscriptionBanner = "# profile " + strings.Repeat("?", 18) + strings.Repeat(">", 18)

// subscriptionPlain is a plain list of the links above, under the banner.
func subscriptionPlain() string {
	return subscriptionBanner + "\n" + strings.Join(subscriptionLines, "\n")
}

// requireAlphabetsDiffer fails the test when text encodes to the same base64 in
// the standard and the URL alphabet. The cases that feed a body in the URL
// alphabet would prove nothing then.
func requireAlphabetsDiffer(t *testing.T, text string) {
	t.Helper()
	if base64.StdEncoding.EncodeToString([]byte(text)) == base64.URLEncoding.EncodeToString([]byte(text)) {
		t.Fatal("the fixture encodes the same in the standard and the URL alphabet")
	}
}

func nameAndAddress(servers []*Server) [][2]string {
	var out [][2]string
	for _, s := range servers {
		out = append(out, [2]string{s.Name, s.Address})
	}
	return out
}

func wrap(s string, width int) string {
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width] + "\n")
		s = s[width:]
	}
	b.WriteString(s + "\n")
	return b.String()
}

func TestParseSubscription(t *testing.T) {
	plain := subscriptionPlain()
	requireAlphabetsDiffer(t, plain)
	messy := "\r\n# profile-title: example\r\n  " + subscriptionLines[0] + "  \r\n\r\n\t" + subscriptionLines[1] +
		"\r\n   # a comment in the middle\r\n" + subscriptionLines[2] + "\r\n\r\n" + subscriptionLines[3] + "\r\n\r\n"
	cases := []struct {
		name string
		body string
	}{
		{"plain list", plain},
		{"plain list with a trailing newline", plain + "\n"},
		{"crlf, blank lines, comments and padding", messy},
		{"utf-8 byte order mark", "\xEF\xBB\xBF" + plain},
		{"base64, standard and padded", base64.StdEncoding.EncodeToString([]byte(plain))},
		{"base64, standard and unpadded", base64.RawStdEncoding.EncodeToString([]byte(plain))},
		{"base64, url-safe and padded", base64.URLEncoding.EncodeToString([]byte(plain))},
		{"base64, url-safe and unpadded", base64.RawURLEncoding.EncodeToString([]byte(plain))},
		{"base64 wrapped at 76 columns", wrap(base64.StdEncoding.EncodeToString([]byte(plain)), 76)},
		{"base64 wrapped with CRLF", strings.ReplaceAll(wrap(base64.StdEncoding.EncodeToString([]byte(plain)), 64), "\n", "\r\n")},
		{"base64 with whitespace around it", "\n  " + base64.StdEncoding.EncodeToString([]byte(plain)) + "  \n\n"},
		{"base64 of a messy list", base64.StdEncoding.EncodeToString([]byte(messy))},
		{"base64 with a byte order mark inside", base64.StdEncoding.EncodeToString([]byte("\xEF\xBB\xBF" + plain))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			servers, errs := ParseSubscription([]byte(tc.body))
			if len(errs) != 0 {
				t.Errorf("errors: %v", errs)
			}
			if got := nameAndAddress(servers); !reflect.DeepEqual(got, subscriptionWant) {
				t.Errorf("servers = %v, want %v", got, subscriptionWant)
			}
			for _, s := range servers {
				checkServer(t, s)
			}
		})
	}
}

func TestParseSubscriptionKeepsValidLinesAmongInvalidOnes(t *testing.T) {
	lines := []string{
		subscriptionBanner,          // 1
		subscriptionLines[0],        // 2 ok
		vless("203.0.113.10:99999"), // 3 bad port
		"",                          // 4
		"hysteria2://" + testPassword + "@203.0.113.14:443#nope", // 5 unsupported scheme
		subscriptionLines[1], // 6 ok
		"not a link at all",  // 7
		vmessLink(`{"add":"203.0.113.15","port":443,"id":"UUID","aid":64}`), // 8 alterId
		subscriptionLines[2],     // 9 ok
		trojan("203.0.113.16:0"), // 10 bad port
		subscriptionLines[3],     // 11 ok
	}
	wantServers := subscriptionWant
	wantErrors := []string{
		"line 3: vless: invalid port",
		`line 5: unsupported scheme "hysteria2"`,
		"line 7: invalid URI: missing scheme",
		"line 8: vmess: alterId not supported",
		"line 10: trojan: invalid port",
	}
	text := strings.Join(lines, "\n")
	requireAlphabetsDiffer(t, text)
	bodies := map[string]string{
		"plain":    text,
		"base64":   base64.StdEncoding.EncodeToString([]byte(text)),
		"wrapped":  wrap(base64.RawURLEncoding.EncodeToString([]byte(text)), 50),
		"crlf":     strings.ReplaceAll(text, "\n", "\r\n"),
		"b64 crlf": base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(text, "\n", "\r\n"))),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			servers, errs := ParseSubscription([]byte(body))
			if got := nameAndAddress(servers); !reflect.DeepEqual(got, wantServers) {
				t.Errorf("servers = %v, want %v", got, wantServers)
			}
			var got []string
			for _, err := range errs {
				got = append(got, err.Error())
			}
			if !reflect.DeepEqual(got, wantErrors) {
				t.Errorf("errors = %q, want %q", got, wantErrors)
			}
			for _, err := range errs {
				assertNoEcho(t, text, err.Error())
			}
		})
	}
}

func TestParseSubscriptionWhatIsNotALinkList(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantErrors []string
	}{
		{"empty", "", nil},
		{"whitespace", " \r\n\t\n", nil},
		{"only comments and blank lines", "# one\n\n   # two\r\n", nil},
		{"only a byte order mark", "\xEF\xBB\xBF", nil},
		{
			// The decoded text has three lines, the base64 text only one.
			"base64 without any link is read as a list",
			base64.StdEncoding.EncodeToString([]byte("line one\nline two\nline three")),
			[]string{"line 1: invalid URI: missing scheme"},
		},
		{
			// The decoded text is not UTF-8, but it holds "://", so it is the list.
			"base64 of text that is not UTF-8 is still the list",
			base64.StdEncoding.EncodeToString([]byte("\xFF\xFE\xFD://x")),
			[]string{"line 1: unsupported scheme"},
		},
		{
			"a web page",
			"<!doctype html>\n<html>\n<body>\n\n<p>Access denied</p>\n</body>\n</html>\n",
			[]string{
				"line 1: invalid URI: missing scheme", "line 2: invalid URI: missing scheme", "line 3: invalid URI: missing scheme",
				"line 5: invalid URI: missing scheme", "line 6: invalid URI: missing scheme", "line 7: invalid URI: missing scheme",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			servers, errs := ParseSubscription([]byte(tc.body))
			if len(servers) != 0 {
				t.Errorf("servers = %v, want none", nameAndAddress(servers))
			}
			var got []string
			for _, err := range errs {
				got = append(got, err.Error())
			}
			if !reflect.DeepEqual(got, tc.wantErrors) {
				t.Errorf("errors = %q, want %q", got, tc.wantErrors)
			}
		})
	}
}

// TestParseSubscriptionToleratesInvalidUTF8: one bad byte in a name must not make
// a base64 subscription read as one line of base64, and one in a host costs only
// that link.
func TestParseSubscriptionToleratesInvalidUTF8(t *testing.T) {
	lines := []string{
		subscriptionLines[0], // 1 one
		"vless://" + testUUID + "@203.0.113.50:443#bad\xFFname", // 2 a bad byte in the name: a server
		"vless://" + testUUID + "@exa\xFFmple.com:443#bad host", // 3 a bad byte in the host: an error
		subscriptionLines[1], // 4 two
		"trojan://" + testPassword + "@203.0.113.51:443?sni=s\xFF.example.com#sn", // 5 a bad byte in a parameter that is read: an error
		subscriptionLines[2], // 6 three
	}
	text := strings.Join(lines, "\n")
	want := [][2]string{
		{"one", "203.0.113.10"},
		{"bad" + string(utf8.RuneError) + "name", "203.0.113.50"},
		{"two", "203.0.113.11"},
		{"three", "203.0.113.12"},
	}
	wantErrors := []string{"line 3: vless: invalid address", "line 5: trojan: invalid sni"}
	bodies := map[string]string{
		"plain":   text,
		"base64":  base64.StdEncoding.EncodeToString([]byte(text)),
		"wrapped": wrap(base64.RawURLEncoding.EncodeToString([]byte(text)), 60),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			servers, errs := ParseSubscription([]byte(body))
			if got := nameAndAddress(servers); !reflect.DeepEqual(got, want) {
				t.Errorf("servers = %q, want %q", got, want)
			}
			var got []string
			for _, err := range errs {
				got = append(got, err.Error())
			}
			if !reflect.DeepEqual(got, wantErrors) {
				t.Errorf("errors = %q, want %q", got, wantErrors)
			}
			for _, s := range servers {
				checkServer(t, s)
			}
		})
	}
}

func TestParseSubscriptionKeepsDuplicatesAndOrder(t *testing.T) {
	body := subscriptionLines[1] + "\n" + subscriptionLines[0] + "\n" + subscriptionLines[1]
	servers, errs := ParseSubscription([]byte(body))
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	want := [][2]string{{"two", "203.0.113.11"}, {"one", "203.0.113.10"}, {"two", "203.0.113.11"}}
	if got := nameAndAddress(servers); !reflect.DeepEqual(got, want) {
		t.Errorf("servers = %v, want %v", got, want)
	}
	if servers[0].Key() != servers[2].Key() || servers[0].Key() == servers[1].Key() {
		t.Errorf("keys %q %q %q", servers[0].Key(), servers[1].Key(), servers[2].Key())
	}
}

func TestParseSubscriptionKeysAreStable(t *testing.T) {
	plain := subscriptionPlain()
	first, _ := ParseSubscription([]byte(plain))
	second, _ := ParseSubscription([]byte(base64.StdEncoding.EncodeToString([]byte("# refreshed\n" + plain))))
	if len(first) != len(subscriptionLines) || len(second) != len(first) {
		t.Fatalf("parsed %d and %d servers", len(first), len(second))
	}
	for i := range first {
		if first[i].Key() != second[i].Key() {
			t.Errorf("server %d: key %q became %q", i, first[i].Key(), second[i].Key())
		}
	}
}

func TestParseSubscriptionBoundsItsErrors(t *testing.T) {
	const junkLines = maxLineErrors + 50
	var b strings.Builder
	for i := range junkLines {
		fmt.Fprintf(&b, "junk %d\n", i)
	}
	b.WriteString(subscriptionLines[0] + "\n")
	servers, errs := ParseSubscription([]byte(b.String()))
	if len(servers) != 1 || servers[0].Name != "one" {
		t.Errorf("the valid line after the junk was lost: %v", nameAndAddress(servers))
	}
	if len(errs) != maxLineErrors+1 {
		t.Fatalf("got %d errors, want %d and a summary", len(errs), maxLineErrors)
	}
	if got, want := errs[0].Error(), "line 1: invalid URI: missing scheme"; got != want {
		t.Errorf("first error = %q, want %q", got, want)
	}
	if got, want := errs[len(errs)-1].Error(), "50 more lines failed to parse"; got != want {
		t.Errorf("last error = %q, want %q", got, want)
	}
}

func TestParseSubscriptionLargeBody(t *testing.T) {
	// 1 MiB of short junk lines and 1 MiB of one line: both must simply return.
	servers, errs := ParseSubscription([]byte(strings.Repeat("x\n", 512*1024)))
	if len(servers) != 0 || len(errs) != maxLineErrors+1 {
		t.Errorf("junk lines: %d servers, %d errors", len(servers), len(errs))
	}
	servers, errs = ParseSubscription([]byte("vless://" + strings.Repeat("a", 1<<20)))
	if len(servers) != 0 || len(errs) != 1 {
		t.Errorf("one long line: %d servers, %d errors", len(servers), len(errs))
	}
}
