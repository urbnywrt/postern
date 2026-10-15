package diag

import (
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/links"
	"github.com/urbnywrt/postern/internal/node/state"
)

func TestScrubberSecrets(t *testing.T) {
	const (
		adTag     = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
		apiToken  = "tok_9f8e7d6c5b4a39281706" // gitleaks:allow (made-up test value)
		password  = "hunter2-correct-horse"
		warpToken = "warp-token-0f1e2d3c4b5a"
		dnsCred   = "cf-api-token-zyxwvutsrq"
		domain    = "example.com"
	)
	st := &nodev1.NodeState{
		Proxies: []*nodev1.Proxy{
			{Id: "p1", Secret: testSecret, Domain: domain, AdTag: adTag},
			{Id: "w1", Secret: testSecret, Type: nodev1.ProxyType_PROXY_TYPE_WEB, Web: &nodev1.WebSettings{DnsCredential: `{"api_token":"` + dnsCred + `"}`}},
		},
		Egresses: []*nodev1.Egress{
			{Id: "e1", Kind: nodev1.EgressKind_EGRESS_KIND_SOCKS5, ParamsJson: `{"addr":"192.0.2.44:1080","user":"bob","password":"` + password + `"}`},
		},
	}
	rt := state.NewRuntime()
	rt.Instances["p1"] = state.InstanceRecord{APIToken: apiToken}
	s := NewScrubber(st, rt, nil).WithSecrets(warpToken)

	raw, _ := hex.DecodeString(testSecret)
	ee := links.FakeTLSSecret(testSecret, domain)
	eeRaw, _ := hex.DecodeString(ee)
	web := func(prefix ...byte) string { return base64.RawURLEncoding.EncodeToString(append(prefix, raw...)) }
	forms := map[string]string{
		"hex":             testSecret,
		"hex upper":       strings.ToUpper(testSecret),
		"ee":              ee,
		"ee base64":       base64.StdEncoding.EncodeToString(eeRaw),
		"ee base64url":    base64.RawURLEncoding.EncodeToString(eeRaw),
		"base64 std":      base64.StdEncoding.EncodeToString(raw),
		"base64 std raw":  base64.RawStdEncoding.EncodeToString(raw),
		"base64 url":      base64.URLEncoding.EncodeToString(raw),
		"base64 url raw":  base64.RawURLEncoding.EncodeToString(raw),
		"dd":              "dd" + testSecret,
		"0x70":            web(0x70),
		"0x70 dd":         web(0x70, 0xdd),
		"ad tag":          adTag,
		"api token":       apiToken,
		"egress password": password,
		"warp token":      warpToken,
		"dns credential":  dnsCred,
	}
	for name, v := range forms {
		text := "before " + v + " after"
		got := s.Clean(text)
		if got != "before *** after" {
			t.Errorf("%s: Clean(%q) = %q", name, text, got)
		}
	}
	// A link carries it too.
	link := links.FakeTLS{Host: "203.0.113.10", Port: 443, SecretHex: testSecret, Domain: domain}.TG()
	if got := s.Clean(link); strings.Contains(got, testSecret) || strings.Contains(got, "ee"+testSecret) {
		t.Errorf("a link kept the secret: %q", got)
	}
	// The member's address is kept, short values are not taken out.
	if got := s.Clean("dial 192.0.2.44:1080 as bob"); got != "dial 192.0.2.44:1080 as bob" {
		t.Errorf("member address or short value changed: %q", got)
	}
}

func TestScrubberIPs(t *testing.T) {
	st := &nodev1.NodeState{Chains: []*nodev1.EgressChain{{Id: "c", Check: &nodev1.HealthCheck{DcAddrs: []string{"192.0.2.200:443"}}}}}
	s := NewScrubber(st, nil, []netip.Addr{netip.MustParseAddr("203.0.113.10")})
	cases := map[string]string{
		"client 198.51.100.7 refused":     "client <ip> refused",
		"from 198.51.100.7:51234":         "from <ip>:51234",
		"client=2001:db8::77 gone":        "client=<ip> gone",
		"[2001:db8::77]:443 closed":       "[<ip>]:443 closed",
		"mapped ::ffff:198.51.100.8 too":  "mapped <ip> too",
		"loopback 127.0.0.3 is not ours":  "loopback <ip> is not ours",
		"engine at 127.0.0.1:20001":       "engine at 127.0.0.1:20001",
		"dns at 127.0.0.2:53, ::1 too":    "dns at 127.0.0.2:53, ::1 too",
		"DC 149.154.167.51:443 answered":  "DC 149.154.167.51:443 answered",
		"DC6 2001:b28:f23d:f001::a ok":    "DC6 2001:b28:f23d:f001::a ok",
		"public 203.0.113.10:443 bound":   "public 203.0.113.10:443 bound",
		"check dc 192.0.2.200:443":        "check dc 192.0.2.200:443",
		"doh 1.1.1.1 and 8.8.4.4":         "doh 1.1.1.1 and 8.8.4.4",
		"bind 0.0.0.0:443 and [::]:443":   "bind 0.0.0.0:443 and [::]:443",
		"version 1.2.3.4.5 and v10.0.0.1": "version 1.2.3.4.5 and v10.0.0.1",
		"at 12:30:45 std::string":         "at 12:30:45 std::string",
		"zone fe80::1%eth0 here":          "zone <ip> here",
		"end of sentence 198.51.100.9.":   "end of sentence <ip>.",
		"from:2001:db8::1 dropped":        "from:<ip> dropped",
		"addr:2001:db8:1:2:3:4:5:6":       "addr:<ip>",
		"ip6:2001:db8::1":                 "ip6:<ip>",
		"peer [2001:db8::1]:443":          "peer [<ip>]:443",
		"from:fe80::1%eth0":               "from:<ip>",
		"src:::ffff:198.51.100.7":         "src:<ip>",
		"via:2001:b28:f23d:f001::a kept":  "via:2001:b28:f23d:f001::a kept",
		"lo:127.0.0.1 kept":               "lo:127.0.0.1 kept",
	}
	for in, want := range cases {
		if got := s.Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	// A nil scrubber still redacts.
	var none *Scrubber
	if got := none.Clean("x 198.51.100.7"); got != "x <ip>" {
		t.Errorf("nil scrubber: %q", got)
	}
}

// No address that is not kept survives, whatever label and colon come
// before it.
func FuzzRedactAfterLabel(f *testing.F) {
	f.Add("from", []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, false)
	f.Add("ip6", []byte{198, 51, 100, 7}, true)
	f.Add("fe", []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, false)
	s := NewScrubber(nil, nil, []netip.Addr{netip.MustParseAddr("203.0.113.10")})
	f.Fuzz(func(t *testing.T, label string, raw []byte, mapped bool) {
		var a netip.Addr
		switch len(raw) {
		case 4:
			a = netip.AddrFrom4([4]byte(raw))
		case 16:
			a = netip.AddrFrom16([16]byte(raw))
		default:
			return
		}
		if s.classifyAddr(a) != redactAddr {
			return
		}
		lit := a.String()
		if mapped && a.Is4() {
			lit = "::ffff:" + lit
		}
		in := label + ":" + lit
		if strings.Contains(label, lit) || strings.Contains(label, a.Unmap().String()) {
			return
		}
		// A label of hex digits and colons may make one longer address of the
		// whole, which is judged as one (and redacted unless kept).
		for k := range len(in) {
			if _, err := netip.ParseAddr(in[k:]); err == nil && k < len(label) {
				return
			}
		}
		out := s.Clean(in)
		if strings.Contains(out, lit) || strings.Contains(out, a.Unmap().String()) {
			t.Fatalf("Clean(%q) = %q", in, out)
		}
	})
}
