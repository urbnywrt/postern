package links_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/links"
)

// Made-up secrets, never real ones, in the shapes a stored secret can take:
// lowercase, UPPERCASE and mixed-case hex, with distinct bytes so a swapped or
// dropped byte shows up.
const (
	hexDoc   = "000102030405060708090a0b0c0d0e0f" // the telemt docs example: bytes 00..0f
	hexUpper = "ABCDEF0123456789ABCDEF0123456789"
	hexLower = "abcdef0123456789abcdef0123456789" // same bytes as hexUpper
	hexMixed = "aBcDeF0123456789AbCdEf0123456789" // same bytes as hexUpper
	hexDesc  = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0" // high bytes: base64 sextets 62 and 63
	hexAsc   = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
)

// base64url_nopad(0x70 || secret) and base64url_nopad(0x70 || 0xdd || secret)
// for the secrets above, computed with Node's Buffer (not with this package).
// b64Doc is the value from the telemt docs.
const (
	b64Doc     = "cAABAgMEBQYHCAkKCwwNDg8"
	b64DocDD   = "cN0AAQIDBAUGBwgJCgsMDQ4P"
	b64Upper   = "cKvN7wEjRWeJq83vASNFZ4k"
	b64UpperDD = "cN2rze8BI0VniavN7wEjRWeJ"
	b64Desc    = "cP_-_fz7-vn49_b19PPy8fA"
	b64DescDD  = "cN3__v38-_r5-Pf29fTz8vHw"
	b64Asc     = "cPDx8vP09fb3-Pn6-_z9_v8"
	b64AscDD   = "cN3w8fLz9PX29_j5-vv8_f7_"
)

// Lowercase hex of the UTF-8 bytes of a domain, from Node's
// Buffer.from(domain, 'utf-8').toString('hex').
const (
	hexWWW      = "7777772e6578616d706c652e636f6d"           // www.example.com
	hexWWWUpper = "5757572e4578616d706c652e434f4d"           // WWW.Example.COM
	hexRU       = "d0bfd180d0b8d0bcd0b5d1802e6578616d706c65" // пример.example
	hexEmoji    = "f09f98802e6578616d706c65"                 // 😀.example
)

// ---------------------------------------------------------------------------
// EncodeURIComponent

// asciiAll returns every ASCII byte, 0x00 to 0x7f.
func asciiAll() string {
	b := make([]byte, 128)
	for i := range b {
		b[i] = byte(i)
	}
	return string(b)
}

// asciiAllEncoded is encodeURIComponent(asciiAll()) as computed by Node.
const asciiAllEncoded = "%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F" + // 0x00-0x0f
	"%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F" + // 0x10-0x1f
	"%20!%22%23%24%25%26'()*%2B%2C-.%2F" + // 0x20-0x2f
	"0123456789%3A%3B%3C%3D%3E%3F" + // 0x30-0x3f
	"%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5C%5D%5E_" + // 0x40-0x5f
	"%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~%7F" // 0x60-0x7f

func TestEncodeURIComponent(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"unreserved characters are left alone", "ABCXYZabcxyz0189-_.!~*'()", "ABCXYZabcxyz0189-_.!~*'()"},
		{"space is %20, not plus", "a b", "a%20b"},
		{"plus is escaped", "a+b", "a%2Bb"},
		{"percent is escaped, never decoded", "100%", "100%25"},
		{"encoded input is encoded again", "%41", "%2541"},
		{"slash", "a/b", "a%2Fb"},
		{"colon and port", "host:8443", "host%3A8443"},
		{"IPv6", "2001:db8::10", "2001%3Adb8%3A%3A10"},
		{"IPv6 in brackets", "[2001:db8::10]", "%5B2001%3Adb8%3A%3A10%5D"},
		{"mixed-case host keeps its case", "Node-1.Example.COM", "Node-1.Example.COM"},
		{"every ASCII byte", asciiAll(), asciiAllEncoded},
		{"2-byte UTF-8", "é", "%C3%A9"},
		{"Cyrillic", "пример", "%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80"},
		{"3-byte UTF-8", "€", "%E2%82%AC"},
		{"CJK", "中文", "%E4%B8%AD%E6%96%87"},
		{"4-byte UTF-8", "😀", "%F0%9F%98%80"},
		// A JS string cannot hold invalid UTF-8 (a lone surrogate makes
		// encodeURIComponent throw), so there is no reference output to match.
		// The bytes are escaped as they are instead of failing or being replaced.
		{"invalid UTF-8 is escaped byte for byte", "\xff\xfe", "%FF%FE"},
		{"truncated UTF-8 sequence", "\xe2\x82", "%E2%82"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := links.EncodeURIComponent(tt.in); got != tt.want {
				t.Errorf("EncodeURIComponent(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestEncodeURIComponentCodePointEdges covers the code points where the length
// of the UTF-8 form changes, and those on both sides of the surrogate block
// (a JavaScript string can hold a lone surrogate, which makes encodeURIComponent
// throw; UTF-8 cannot hold one). The code points are numbers, not characters
// in the source, because several of them cannot be seen in an editor.
func TestEncodeURIComponentCodePointEdges(t *testing.T) {
	tests := []struct {
		cp   rune
		want string // encodeURIComponent(String.fromCodePoint(cp)) in Node
	}{
		{0x007f, "%7F"},
		{0x0080, "%C2%80"},
		{0x07ff, "%DF%BF"},
		{0x0800, "%E0%A0%80"},
		{0xd7ff, "%ED%9F%BF"}, // just below the surrogates
		{0xe000, "%EE%80%80"}, // just above the surrogates
		{0xfffd, "%EF%BF%BD"},
		{0xffff, "%EF%BF%BF"},
		{0x10000, "%F0%90%80%80"},
		{0x10ffff, "%F4%8F%BF%BF"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("U+%04X", tt.cp), func(t *testing.T) {
			if got := links.EncodeURIComponent(string(tt.cp)); got != tt.want {
				t.Errorf("EncodeURIComponent(U+%04X) = %q, want %q", tt.cp, got, tt.want)
			}
		})
	}
}

// TestEncodeURIComponentEveryByte restates the spec rule for each single byte:
// A-Z a-z 0-9 - _ . ! ~ * ' ( ) stay, everything else becomes %XX in capitals.
func TestEncodeURIComponentEveryByte(t *testing.T) {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	for b := range 256 {
		in := string([]byte{byte(b)})
		want := fmt.Sprintf("%%%02X", b)
		if b < 0x80 && strings.IndexByte(unreserved, byte(b)) >= 0 {
			want = in
		}
		if got := links.EncodeURIComponent(in); got != want {
			t.Errorf("EncodeURIComponent(byte 0x%02x) = %q, want %q", b, got, want)
		}
	}
}

// encodedForm is what EncodeURIComponent may produce: unreserved characters
// and %XX with capital hex digits.
var encodedForm = regexp.MustCompile(`^(?:[A-Za-z0-9\-_.!~*'()]|%[0-9A-F]{2})*$`)

func FuzzEncodeURIComponent(f *testing.F) {
	for _, seed := range []string{
		"", "203.0.113.10", "2001:db8::10", "Node-1.Example.COM", "пример.example",
		"x!'()*~y", "a b+c&d=e#f/g?h@i$j,k;l:m%n", "😀", "\xff\xfe", "%41",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := links.EncodeURIComponent(s)
		if !encodedForm.MatchString(got) {
			t.Fatalf("EncodeURIComponent(%q) = %q: not made of unreserved characters and %%XX", s, got)
		}
		// PathUnescape does not turn + into a space, so it inverts the encoding.
		back, err := url.PathUnescape(got)
		if err != nil || back != s {
			t.Fatalf("PathUnescape(EncodeURIComponent(%q)) = %q, %v; want the input back", s, back, err)
		}
	})
}

// ---------------------------------------------------------------------------
// Fake TLS

func TestFakeTLSSecret(t *testing.T) {
	tests := []struct {
		name      string
		secretHex string
		domain    string
		want      string
	}{
		{"lowercase secret", hexDoc, "www.example.com", "ee" + hexDoc + hexWWW},
		{"UPPERCASE secret keeps its case", hexUpper, "www.example.com", "ee" + hexUpper + hexWWW},
		{"mixed-case secret keeps its case", hexMixed, "www.example.com", "ee" + hexMixed + hexWWW},
		{"domain case is kept in the encoded bytes", hexDoc, "WWW.Example.COM", "ee" + hexDoc + hexWWWUpper},
		{"unicode domain", hexDoc, "пример.example", "ee" + hexDoc + hexRU},
		{"4-byte unicode domain", hexDoc, "😀.example", "ee" + hexDoc + hexEmoji},
		{"empty domain", hexDoc, "", "ee" + hexDoc},
		{"empty secret", "", "www.example.com", "ee" + hexWWW},
		{"hex digits of the domain are lowercase", "", "ê", "eec3aa"},
		{"invalid UTF-8 domain is encoded byte for byte", hexDoc, "\xff", "ee" + hexDoc + "ff"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := links.FakeTLSSecret(tt.secretHex, tt.domain); got != tt.want {
				t.Errorf("FakeTLSSecret(%q, %q) = %q, want %q", tt.secretHex, tt.domain, got, tt.want)
			}
		})
	}
}

// TestFakeTLSDocumentedExample spells one link out in full, so the format can
// be read without decoding the composed expectations of the tables below.
func TestFakeTLSDocumentedExample(t *testing.T) {
	f := links.FakeTLS{Host: "203.0.113.10", Port: 443, SecretHex: hexDoc, Domain: "www.example.com"}

	wantTG := "tg://proxy?server=203.0.113.10&port=443&secret=ee000102030405060708090a0b0c0d0e0f7777772e6578616d706c652e636f6d"
	if got := f.TG(); got != wantTG {
		t.Errorf("TG() = %q, want %q", got, wantTG)
	}
	wantHTTPS := "https://t.me/proxy?server=203.0.113.10&port=443&secret=ee000102030405060708090a0b0c0d0e0f7777772e6578616d706c652e636f6d"
	if got := f.HTTPS(); got != wantHTTPS {
		t.Errorf("HTTPS() = %q, want %q", got, wantHTTPS)
	}
}

func TestFakeTLSLinks(t *testing.T) {
	tests := []struct {
		name      string
		link      links.FakeTLS
		wantQuery string // what follows "?", the same for tg:// and https://t.me/
	}{
		{
			"IPv4 host",
			links.FakeTLS{Host: "203.0.113.10", Port: 443, SecretHex: hexDoc, Domain: "www.example.com"},
			"server=203.0.113.10&port=443&secret=ee" + hexDoc + hexWWW,
		},
		{
			"IPv6 host: colons are escaped, no brackets are added",
			links.FakeTLS{Host: "2001:db8::10", Port: 443, SecretHex: hexDoc, Domain: "www.example.com"},
			"server=2001%3Adb8%3A%3A10&port=443&secret=ee" + hexDoc + hexWWW,
		},
		{
			"domain host on another port",
			links.FakeTLS{Host: "proxy.example.com", Port: 8443, SecretHex: hexDoc, Domain: "www.example.com"},
			"server=proxy.example.com&port=8443&secret=ee" + hexDoc + hexWWW,
		},
		{
			"mixed-case host, UPPERCASE secret and mixed-case domain are kept as stored",
			links.FakeTLS{Host: "Node-1.Example.COM", Port: 8443, SecretHex: hexUpper, Domain: "WWW.Example.COM"},
			"server=Node-1.Example.COM&port=8443&secret=ee" + hexUpper + hexWWWUpper,
		},
		{
			"unicode host and domain: no punycode",
			links.FakeTLS{Host: "пример.example", Port: 443, SecretHex: hexDoc, Domain: "пример.example"},
			"server=%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.example&port=443&secret=ee" + hexDoc + hexRU,
		},
		{
			"host with the characters encodeURIComponent leaves alone",
			links.FakeTLS{Host: "x!'()*~y.example", Port: 443, SecretHex: hexDoc, Domain: "www.example.com"},
			"server=x!'()*~y.example&port=443&secret=ee" + hexDoc + hexWWW,
		},
		{
			"host with reserved characters",
			links.FakeTLS{Host: "a b+c&d=e#f/g?h@i$j,k;l:m%n.example", Port: 443, SecretHex: hexDoc, Domain: "www.example.com"},
			"server=a%20b%2Bc%26d%3De%23f%2Fg%3Fh%40i%24j%2Ck%3Bl%3Am%25n.example&port=443&secret=ee" + hexDoc + hexWWW,
		},
		{
			"lowest port",
			links.FakeTLS{Host: "203.0.113.10", Port: 1, SecretHex: hexDoc, Domain: "www.example.com"},
			"server=203.0.113.10&port=1&secret=ee" + hexDoc + hexWWW,
		},
		{
			"highest port",
			links.FakeTLS{Host: "203.0.113.10", Port: 65535, SecretHex: hexDoc, Domain: "www.example.com"},
			"server=203.0.113.10&port=65535&secret=ee" + hexDoc + hexWWW,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := tt.link.TG(), "tg://proxy?"+tt.wantQuery; got != want {
				t.Errorf("TG() = %q, want %q", got, want)
			}
			if got, want := tt.link.HTTPS(), "https://t.me/proxy?"+tt.wantQuery; got != want {
				t.Errorf("HTTPS() = %q, want %q", got, want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// WEB

// checkWebLinks verifies Server, Secret, HTTPS and TG of a Web link.
func checkWebLinks(t *testing.T, w links.Web, wantServer, wantSecret string) {
	t.Helper()
	if got := w.Server(); got != wantServer {
		t.Errorf("Server() = %q, want %q", got, wantServer)
	}
	gotSecret, err := w.Secret()
	if err != nil {
		t.Fatalf("Secret() error: %v", err)
	}
	if gotSecret != wantSecret {
		t.Errorf("Secret() = %q, want %q", gotSecret, wantSecret)
	}
	gotHTTPS, err := w.HTTPS()
	if err != nil {
		t.Fatalf("HTTPS() error: %v", err)
	}
	if want := "https://t.me/webproxy?server=" + wantServer + "&secret=" + wantSecret; gotHTTPS != want {
		t.Errorf("HTTPS() = %q, want %q", gotHTTPS, want)
	}
	gotTG, err := w.TG()
	if err != nil {
		t.Fatalf("TG() error: %v", err)
	}
	if want := "tg://webproxy?server=" + wantServer + "&secret=" + wantSecret; gotTG != want {
		t.Errorf("TG() = %q, want %q", gotTG, want)
	}
}

func TestWebRoot(t *testing.T) {
	tests := []struct {
		name       string
		web        links.Web
		wantServer string
		wantSecret string
	}{
		{
			"plain: the secret as it is",
			links.Web{Domain: "proxy.example.com", SecretHex: hexDoc, Mode: links.ModePlain},
			"proxy.example.com", hexDoc,
		},
		{
			"dd: the secret behind a dd prefix",
			links.Web{Domain: "proxy.example.com", SecretHex: hexDoc, Mode: links.ModeDD},
			"proxy.example.com", "dd" + hexDoc,
		},
		{
			"plain, UPPERCASE secret keeps its case",
			links.Web{Domain: "proxy.example.com", SecretHex: hexUpper, Mode: links.ModePlain},
			"proxy.example.com", hexUpper,
		},
		{
			"dd, UPPERCASE secret keeps its case, the prefix stays lowercase",
			links.Web{Domain: "proxy.example.com", SecretHex: hexUpper, Mode: links.ModeDD},
			"proxy.example.com", "dd" + hexUpper,
		},
		{
			"mixed-case domain keeps its case",
			links.Web{Domain: "WWW.Example.COM", SecretHex: hexDoc, Mode: links.ModePlain},
			"WWW.Example.COM", hexDoc,
		},
		{
			"unicode domain: no punycode",
			links.Web{Domain: "пример.example", SecretHex: hexDoc, Mode: links.ModeDD},
			"%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.example", "dd" + hexDoc,
		},
		{
			"domain with characters encodeURIComponent leaves alone",
			links.Web{Domain: "x!'()*~y.example", SecretHex: hexDoc, Mode: links.ModePlain},
			"x!'()*~y.example", hexDoc,
		},
		{
			"domain with reserved characters",
			links.Web{Domain: "a b+c&d=e#f/g?h@i$j,k;l:m%n.example", SecretHex: hexDoc, Mode: links.ModePlain},
			"a%20b%2Bc%26d%3De%23f%2Fg%3Fh%40i%24j%2Ck%3Bl%3Am%25n.example", hexDoc,
		},
		// Only the base-path form has to decode the secret. The root form is
		// plain concatenation as before, so an imported secret of any shape
		// keeps the link it had.
		{
			"root form uses the secret as stored, even a short one",
			links.Web{Domain: "proxy.example.com", SecretHex: "12345", Mode: links.ModeDD},
			"proxy.example.com", "dd12345",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkWebLinks(t, tt.web, tt.wantServer, tt.wantSecret)
		})
	}
}

// TestWebBasePathDocumentedExample spells out the vector from the telemt docs.
// Its secret is made up. gitleaks takes the links for a leaked key, so the two
// lines that hold them carry its per-line marker.
func TestWebBasePathDocumentedExample(t *testing.T) {
	w := links.Web{Domain: "proxy.example.com", BasePath: "telegram/web", SecretHex: hexDoc, Mode: links.ModePlain}

	if got, want := w.Server(), "proxy.example.com%2Ftelegram%2Fweb"; got != want {
		t.Errorf("Server() = %q, want %q", got, want)
	}
	if got, err := w.Secret(); err != nil || got != "cAABAgMEBQYHCAkKCwwNDg8" {
		t.Errorf("Secret() = %q, %v; want %q", got, err, "cAABAgMEBQYHCAkKCwwNDg8")
	}
	wantHTTPS := "https://t.me/webproxy?server=proxy.example.com%2Ftelegram%2Fweb&secret=cAABAgMEBQYHCAkKCwwNDg8" // gitleaks:allow
	if got, err := w.HTTPS(); err != nil || got != wantHTTPS {
		t.Errorf("HTTPS() = %q, %v; want %q", got, err, wantHTTPS)
	}
	wantTG := "tg://webproxy?server=proxy.example.com%2Ftelegram%2Fweb&secret=cAABAgMEBQYHCAkKCwwNDg8" // gitleaks:allow
	if got, err := w.TG(); err != nil || got != wantTG {
		t.Errorf("TG() = %q, %v; want %q", got, err, wantTG)
	}
}

func TestWebBasePath(t *testing.T) {
	tests := []struct {
		name       string
		web        links.Web
		wantServer string
		wantSecret string
	}{
		{
			"plain",
			links.Web{Domain: "proxy.example.com", BasePath: "telegram/web", SecretHex: hexDoc, Mode: links.ModePlain},
			"proxy.example.com%2Ftelegram%2Fweb", b64Doc,
		},
		{
			"dd: the 0xdd byte goes between 0x70 and the secret",
			links.Web{Domain: "proxy.example.com", BasePath: "telegram/web", SecretHex: hexDoc, Mode: links.ModeDD},
			"proxy.example.com%2Ftelegram%2Fweb", b64DocDD,
		},
		{
			"plain, UPPERCASE hex decodes to the same bytes",
			links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexUpper, Mode: links.ModePlain},
			"proxy.example.com%2Fw", b64Upper,
		},
		{
			"plain, lowercase hex of the same bytes",
			links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexLower, Mode: links.ModePlain},
			"proxy.example.com%2Fw", b64Upper,
		},
		{
			"plain, mixed-case hex of the same bytes",
			links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexMixed, Mode: links.ModePlain},
			"proxy.example.com%2Fw", b64Upper,
		},
		{
			"dd, UPPERCASE hex",
			links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexUpper, Mode: links.ModeDD},
			"proxy.example.com%2Fw", b64UpperDD,
		},
		{
			"plain, the URL-safe alphabet: - and _, never + or /",
			links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexDesc, Mode: links.ModePlain},
			"proxy.example.com%2Fw", b64Desc,
		},
		{
			"dd, the URL-safe alphabet",
			links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexDesc, Mode: links.ModeDD},
			"proxy.example.com%2Fw", b64DescDD,
		},
		{
			"plain, ascending high bytes",
			links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexAsc, Mode: links.ModePlain},
			"proxy.example.com%2Fw", b64Asc,
		},
		{
			"dd, ascending high bytes",
			links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexAsc, Mode: links.ModeDD},
			"proxy.example.com%2Fw", b64AscDD,
		},
		{
			"nested base path",
			links.Web{Domain: "proxy.example.com", BasePath: "a/b/c", SecretHex: hexDoc, Mode: links.ModePlain},
			"proxy.example.com%2Fa%2Fb%2Fc", b64Doc,
		},
		{
			"domain and base path keep their case",
			links.Web{Domain: "WWW.Example.COM", BasePath: "Telegram/Web", SecretHex: hexDoc, Mode: links.ModePlain},
			"WWW.Example.COM%2FTelegram%2FWeb", b64Doc,
		},
		{
			"unicode domain and base path",
			links.Web{Domain: "пример.example", BasePath: "путь/web", SecretHex: hexDoc, Mode: links.ModePlain},
			"%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.example%2F%D0%BF%D1%83%D1%82%D1%8C%2Fweb", b64Doc,
		},
		{
			"base path with the characters encodeURIComponent leaves alone",
			links.Web{Domain: "proxy.example.com", BasePath: "we!'()*~b", SecretHex: hexDoc, Mode: links.ModePlain},
			"proxy.example.com%2Fwe!'()*~b", b64Doc,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkWebLinks(t, tt.web, tt.wantServer, tt.wantSecret)
		})
	}
}

// TestWebBasePathSecretShape checks what the golden values above only imply:
// URL-safe alphabet, no padding, and a length that follows from 17 or 18 bytes.
func TestWebBasePathSecretShape(t *testing.T) {
	urlSafe := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	for _, hex := range []string{hexDoc, hexUpper, hexDesc, hexAsc} {
		for _, tt := range []struct {
			mode    string
			wantLen int
		}{
			{links.ModePlain, 23}, // 17 bytes: 5 groups of 3 + 2, so 20 + 3 characters
			{links.ModeDD, 24},    // 18 bytes: 6 groups of 3, so 24 characters
		} {
			w := links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hex, Mode: tt.mode}
			got, err := w.Secret()
			if err != nil {
				t.Fatalf("%s %s: Secret() error: %v", hex, tt.mode, err)
			}
			if !urlSafe.MatchString(got) || len(got) != tt.wantLen {
				t.Errorf("%s %s: Secret() = %q, want %d URL-safe characters without padding", hex, tt.mode, got, tt.wantLen)
			}
		}
	}
}

func TestWebErrors(t *testing.T) {
	tests := []struct {
		name string
		web  links.Web
	}{
		{"root: empty mode", links.Web{Domain: "proxy.example.com", SecretHex: hexDoc, Mode: ""}},
		{"root: unknown mode", links.Web{Domain: "proxy.example.com", SecretHex: hexDoc, Mode: "classic"}},
		{"root: mode is case-sensitive", links.Web{Domain: "proxy.example.com", SecretHex: hexDoc, Mode: "DD"}},
		{"root: mode is not trimmed", links.Web{Domain: "proxy.example.com", SecretHex: hexDoc, Mode: "plain "}},
		{"base path: empty mode", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexDoc, Mode: ""}},
		{"base path: unknown mode", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexDoc, Mode: "classic"}},
		{"base path: empty secret", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: "", Mode: links.ModePlain}},
		{"base path: odd number of digits", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexDoc[:31], Mode: links.ModePlain}},
		{"base path: 15 bytes", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexDoc[:30], Mode: links.ModePlain}},
		{"base path: 17 bytes", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexDoc + "10", Mode: links.ModeDD}},
		{"base path: 32 bytes", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexDoc + hexDoc, Mode: links.ModePlain}},
		{"base path: not hex", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: "zz0102030405060708090a0b0c0d0e0f", Mode: links.ModePlain}},
		{"base path: 0x prefix", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: "0x" + hexDoc[:30], Mode: links.ModePlain}},
		{"base path: surrounding whitespace", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: " " + hexDoc[:30] + " ", Mode: links.ModePlain}},
		{"base path: multi-byte characters", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: hexDoc[:28] + "éé", Mode: links.ModePlain}},
		{"base path: dd with a short secret", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: "dd" + hexDoc, Mode: links.ModeDD}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := tt.web.Secret(); err == nil || got != "" {
				t.Errorf("Secret() = %q, %v; want an empty string and an error", got, err)
			}
			if got, err := tt.web.HTTPS(); err == nil || got != "" {
				t.Errorf("HTTPS() = %q, %v; want an empty string and an error", got, err)
			}
			if got, err := tt.web.TG(); err == nil || got != "" {
				t.Errorf("TG() = %q, %v; want an empty string and an error", got, err)
			}
		})
	}
}

// TestWebErrorsDoNotQuoteTheSecret covers every way Secret can fail while it
// holds a secret. Callers log these errors, and a secret must never reach a
// log, not even one character of it (the hex decoder's own error quotes the
// offending byte). 'Q' is not a hex digit and is in none of the messages.
func TestWebErrorsDoNotQuoteTheSecret(t *testing.T) {
	for _, tt := range []struct {
		name string
		web  links.Web
	}{
		{"fails in the hex decoder", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: strings.Repeat("Q", 32), Mode: links.ModePlain}},
		{"fails the length check", links.Web{Domain: "proxy.example.com", BasePath: "w", SecretHex: "QQQQ", Mode: links.ModePlain}},
		{"fails on the mode", links.Web{Domain: "proxy.example.com", SecretHex: strings.Repeat("Q", 32), Mode: "bogus"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.web.Secret()
			if err == nil {
				t.Fatal("Secret() returned no error")
			}
			if strings.Contains(err.Error(), "Q") {
				t.Errorf("error %q quotes part of the secret", err)
			}
		})
	}
}

func TestWebServerIgnoresMode(t *testing.T) {
	// Server depends on the domain and the base path only, so it can be shown
	// even for a proxy whose secret cannot be turned into a link.
	w := links.Web{Domain: "proxy.example.com", BasePath: "telegram/web", SecretHex: "bad", Mode: "bad"}
	if got, want := w.Server(), "proxy.example.com%2Ftelegram%2Fweb"; got != want {
		t.Errorf("Server() = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Vectors of the reference formulas

// refVector is one entry of testdata/reference_vectors.json, written by
// testdata/gen_vectors.mjs from the reference formulas.
type refVector struct {
	Host       string `json:"host"`
	Port       uint16 `json:"port"`
	Secret     string `json:"secret"`
	Domain     string `json:"domain"`
	TG         string `json:"tg"`
	WebHTTPS   string `json:"web_https"`
	WebHTTPSDD string `json:"web_https_dd"`
}

func loadReferenceVectors(t *testing.T) []refVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "reference_vectors.json"))
	if err != nil {
		t.Fatalf("read reference vectors: %v", err)
	}
	var vectors []refVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse reference vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("reference_vectors.json has no vectors")
	}
	return vectors
}

// TestReferenceVectors reproduces every reference link byte for byte. The
// https://t.me/proxy and tg://webproxy forms have no reference generator; they must carry the query
// of the form that has one.
func TestReferenceVectors(t *testing.T) {
	for i, v := range loadReferenceVectors(t) {
		t.Run(fmt.Sprintf("%03d", i), func(t *testing.T) {
			where := fmt.Sprintf("host=%q port=%d secret=%q domain=%q", v.Host, v.Port, v.Secret, v.Domain)

			fake := links.FakeTLS{Host: v.Host, Port: v.Port, SecretHex: v.Secret, Domain: v.Domain}
			if got := fake.TG(); got != v.TG {
				t.Errorf("FakeTLS.TG() for %s\n got %q\nwant %q", where, got, v.TG)
			}
			tgQuery, ok := strings.CutPrefix(v.TG, "tg://proxy?")
			if !ok {
				t.Fatalf("vector tg %q does not start with tg://proxy?", v.TG)
			}
			if got, want := fake.HTTPS(), "https://t.me/proxy?"+tgQuery; got != want {
				t.Errorf("FakeTLS.HTTPS() for %s\n got %q\nwant %q", where, got, want)
			}

			for _, c := range []struct {
				mode      string
				wantHTTPS string
			}{
				{links.ModePlain, v.WebHTTPS},
				{links.ModeDD, v.WebHTTPSDD},
			} {
				web := links.Web{Domain: v.Domain, SecretHex: v.Secret, Mode: c.mode}
				gotHTTPS, err := web.HTTPS()
				if err != nil {
					t.Fatalf("Web.HTTPS() %s for %s: %v", c.mode, where, err)
				}
				if gotHTTPS != c.wantHTTPS {
					t.Errorf("Web.HTTPS() %s for %s\n got %q\nwant %q", c.mode, where, gotHTTPS, c.wantHTTPS)
				}
				webQuery, ok := strings.CutPrefix(c.wantHTTPS, "https://t.me/webproxy?")
				if !ok {
					t.Fatalf("vector web link %q does not start with https://t.me/webproxy?", c.wantHTTPS)
				}
				gotTG, err := web.TG()
				if err != nil {
					t.Fatalf("Web.TG() %s for %s: %v", c.mode, where, err)
				}
				if want := "tg://webproxy?" + webQuery; gotTG != want {
					t.Errorf("Web.TG() %s for %s\n got %q\nwant %q", c.mode, where, gotTG, want)
				}
			}
		})
	}
}

// TestReferenceVectorsCoverRequiredInputs keeps the vector file from quietly
// losing the cases it exists for.
func TestReferenceVectorsCoverRequiredInputs(t *testing.T) {
	hasAll := func(s, chars string) bool {
		for _, r := range chars {
			if !strings.ContainsRune(s, r) {
				return false
			}
		}
		return true
	}
	hosts := map[string]bool{}
	domains := map[string]bool{}
	ports := map[uint16]bool{}
	var lowerSecret, upperSecret, specialsHost bool
	for _, v := range loadReferenceVectors(t) {
		hosts[v.Host] = true
		domains[v.Domain] = true
		ports[v.Port] = true
		// A secret counts as lowercase (UPPERCASE) when it has letters and none of the other case.
		lowerSecret = lowerSecret || (v.Secret == strings.ToLower(v.Secret) && v.Secret != strings.ToUpper(v.Secret))
		upperSecret = upperSecret || (v.Secret == strings.ToUpper(v.Secret) && v.Secret != strings.ToLower(v.Secret))
		specialsHost = specialsHost || hasAll(v.Host, "!'()*~")
	}
	for _, host := range []string{
		"203.0.113.10",       // IPv4
		"2001:db8::10",       // IPv6
		"proxy.example.com",  // domain
		"Node-1.Example.COM", // mixed case
		"пример.example",     // unicode
	} {
		if !hosts[host] {
			t.Errorf("no vector with host %q", host)
		}
	}
	for _, domain := range []string{"www.example.com", "WWW.Example.COM", "пример.example"} {
		if !domains[domain] {
			t.Errorf("no vector with domain %q", domain)
		}
	}
	for _, port := range []uint16{443, 8443} {
		if !ports[port] {
			t.Errorf("no vector with port %d", port)
		}
	}
	if !specialsHost {
		t.Error("no vector with a host that contains all of !'()*~")
	}
	if !lowerSecret {
		t.Error("no vector with a lowercase hex secret")
	}
	if !upperSecret {
		t.Error("no vector with an UPPERCASE hex secret")
	}
}
