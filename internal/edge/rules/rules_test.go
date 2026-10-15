package rules

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestFoldName(t *testing.T) {
	name253 := strings.Repeat("a.", 126) + "a"
	if len(name253) != 253 {
		t.Fatalf("bad fixture: %d bytes", len(name253))
	}
	label63 := strings.Repeat("x", 63)

	tests := []struct {
		name string
		in   string
		want string // "" when the name is to be refused
	}{
		{"plain", "proxy.example.com", "proxy.example.com"},
		{"mixed case", "Proxy.EXAMPLE.Com", "proxy.example.com"},
		{"one trailing dot", "proxy.example.com.", "proxy.example.com"},
		{"two trailing dots", "proxy.example.com..", ""},
		{"single label", "localhost", "localhost"},
		{"digits and hyphens", "a-1.b-2.example", "a-1.b-2.example"},
		{"hyphen at the edges", "-a-.example", "-a-.example"},
		{"punycode", "XN--E1AFMKFD.example", "xn--e1afmkfd.example"},
		{"ip literal", "192.0.2.1", "192.0.2.1"},
		{"253 bytes", name253, name253},
		{"254 bytes", name253 + "a", ""},
		{"253 bytes and a trailing dot", name253 + ".", ""},
		{"64 KiB", strings.Repeat("A", 65536), ""},
		{"63-byte label", label63 + ".example", label63 + ".example"},
		{"64-byte label", label63 + "x.example", ""},
		{"empty", "", ""},
		{"only a dot", ".", ""},
		{"two dots", "..", ""},
		{"leading dot", ".example.com", ""},
		{"empty label", "proxy..example.com", ""},
		{"underscore", "a_b.example.com", ""},
		{"space", "a b.example.com", ""},
		{"NUL at the end", "proxy.example.com\x00", ""},
		{"NUL inside", "proxy\x00.example.com", ""},
		{"only NUL", "\x00", ""},
		{"non-ASCII", "\xd0\xbf\xd1\x80.example", ""},
		{"high byte", "proxy.example.com\xff", ""},
		{"control byte", "proxy\r\n.example.com", ""},
		{"colon", "proxy.example.com:443", ""},
		{"slash", "proxy.example.com/x", ""},
		{"percent", "proxy%2e.example.com", ""},
		{"Kelvin sign", "K.example", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FoldName(tt.in)
			if ok != (tt.want != "") || got != tt.want {
				t.Fatalf("FoldName(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.want != "")
			}
		})
	}
}

// CheckName says what makes a string no name: the first problem from its start.
func TestCheckName(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want NameProblem
	}{
		{"a.example.com", NameOK},
		{"A.Example.COM.", NameOK},
		{"", NameEmpty},
		{strings.Repeat("a", 254), NameTooLong},
		{strings.Repeat("a.", 126) + "a.", NameTooLong}, // 253 bytes and the dot at the end
		{strings.Repeat("a", 64) + ".example", NameLongLabel},
		{".", NameEmptyLabel},
		{"..", NameEmptyLabel},
		{".example", NameEmptyLabel},
		{"a..example", NameEmptyLabel},
		{"a.example..", NameEmptyLabel},
		{"a_b.example", NameBadByte},
		{"a.example\xff", NameBadByte},
		{"a_..example", NameBadByte},    // the bad byte comes first
		{"a.._example", NameEmptyLabel}, // the empty label comes first
	} {
		if got := CheckName(tc.in); got != tc.want {
			t.Errorf("CheckName(%.40q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestFold(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"a.example.com", "a.example.com"},
		{"A.Example.COM", "a.example.com"},
		{"a.example.com.", "a.example.com"},
		{"A.EXAMPLE.com.", "a.example.com"},
		{"a.example.com..", "a.example.com."}, // one dot only, as the edge takes one
		{"", ""},
		{".", ""},
		{"203.0.113.5", "203.0.113.5"},
		// Only ASCII letters fold. strings.ToLower makes a k of the Kelvin sign.
		{"K.example", "K.example"},
		{"İ.example", "İ.example"},
		{"É.example", "É.example"},
		// A byte that is not a letter stays what it is, valid UTF-8 or not.
		{"a\xffB", "a\xffb"},
		{"Z\x00Y", "z\x00y"},
	} {
		if got := Fold(tc.in); got != tc.want {
			t.Errorf("Fold(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Two different strings are never one, whatever they hold.
	if Fold("a\xffb") == Fold("a\xfeb") {
		t.Error("two strings that differ in an invalid byte fold to one")
	}
	if Fold("K.example") == Fold("k.example") {
		t.Error("the Kelvin sign is folded into a k")
	}
}

func TestParseMaskTarget(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: ""},
		{in: "mask.example.com:8443", want: "mask.example.com:8443"},
		{in: "Mask.EXAMPLE.com.:443", want: "mask.example.com:443"},
		{in: "mask.example.com", want: "mask.example.com:443"},
		{in: "192.0.2.10", want: "192.0.2.10:443"},
		{in: "192.0.2.10:8443", want: "192.0.2.10:8443"},
		{in: "[2001:db8::1]:8443", want: "[2001:db8::1]:8443"},
		{in: "2001:db8::1", want: "[2001:db8::1]:443"},
		{in: "[::ffff:192.0.2.10]:443", want: "192.0.2.10:443"},
		{in: "mask.example.com:0443", want: "mask.example.com:443"},
		{in: "mask.example.com:0", wantErr: true},
		{in: "mask.example.com:65536", wantErr: true},
		{in: "mask.example.com:https", wantErr: true},
		{in: "mask.example.com:", wantErr: true},
		{in: ":443", wantErr: true},
		{in: "bad_name.example.com:443", wantErr: true},
		{in: "bad name.example.com", wantErr: true},
		{in: "[2001:db8::1]", wantErr: true},
		{in: "mask.example.com:443:1", wantErr: true},
		{in: "mask.example.com\x00:443", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseMaskTarget(tt.in)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("ParseMaskTarget(%q) = %q, %v; want %q, error %v", tt.in, got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestParsePrefix(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"192.0.2.0/24", "192.0.2.0/24"},
		{"192.0.2.7/24", "192.0.2.0/24"},
		{"198.51.100.7", "198.51.100.7/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"::ffff:192.0.2.1", "192.0.2.1/32"},
		{"::ffff:192.0.2.0/120", "192.0.2.0/24"},
		{"::ffff:0:0/64", "::/64"}, // shorter than the mapped space: stays IPv6
		{"0.0.0.0/0", "0.0.0.0/0"},
	} {
		p, err := ParsePrefix(tc.in)
		if err != nil || p.String() != tc.want {
			t.Errorf("ParsePrefix(%q) = %v, %v; want %s", tc.in, p, err, tc.want)
		}
	}
	for _, in := range []string{"", " ", "192.0.2.0/33", "192.0.2.0/", "/24", " 192.0.2.0/24", "192.0.2.256",
		"fe80::1%eth0", "fe80::1%eth0/64", "proxy.example.com", "192.0.2.0/024", "[2001:db8::1]"} {
		if p, err := ParsePrefix(in); err == nil {
			t.Errorf("ParsePrefix(%q) = %v, want an error", in, p)
		}
	}
}

func TestParseBindIPAndPort(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.1": "192.0.2.1", "::ffff:192.0.2.1": "192.0.2.1", "2001:db8::1": "2001:db8::1", "0.0.0.0": "0.0.0.0"} {
		if ip, err := ParseBindIP(in); err != nil || ip.String() != want {
			t.Errorf("ParseBindIP(%q) = %v, %v; want %s", in, ip, err, want)
		}
	}
	for _, in := range []string{"", "localhost", "192.0.2.256", "192.0.2.1:443"} {
		if _, err := ParseBindIP(in); err == nil {
			t.Errorf("ParseBindIP(%q) = nil error", in)
		}
	}
	for _, p := range []uint32{1, 443, 65535} {
		if got, err := ParsePort(p); err != nil || uint32(got) != p {
			t.Errorf("ParsePort(%d) = %d, %v", p, got, err)
		}
	}
	for _, p := range []uint32{0, 65536, 1 << 31} {
		if _, err := ParsePort(p); err == nil {
			t.Errorf("ParsePort(%d) = nil error", p)
		}
	}
}

// An http-upstream listener binds a loopback or private address, and trusts
// prefixes that lie inside those ranges whole.
func TestUpstreamPlacement(t *testing.T) {
	for _, in := range []string{"127.0.0.1", "127.1.2.3", "::1", "10.1.2.3", "172.16.0.1", "172.31.255.254",
		"192.168.1.10", "fd00::1", "fc00::1", "::ffff:127.0.0.1"} {
		ip, err := ParseBindIP(in)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckUpstreamBind(ip); err != nil {
			t.Errorf("CheckUpstreamBind(%s) = %v, want nil", in, err)
		}
	}
	for _, in := range []string{"0.0.0.0", "::", "192.0.2.1", "198.51.100.7", "2001:db8::1", "172.32.0.1",
		"169.254.1.1", "fe80::1", "100.64.0.1", "224.0.0.1"} {
		ip, err := ParseBindIP(in)
		if err != nil {
			t.Fatal(err)
		}
		err = CheckUpstreamBind(ip)
		if err == nil {
			t.Errorf("CheckUpstreamBind(%s) = nil, want an error", in)
			continue
		}
		for _, want := range []string{"http-upstream", "loopback or private", ip.String()} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("CheckUpstreamBind(%s) = %q: it does not say %q", in, err, want)
			}
		}
	}

	for _, in := range []string{"127.0.0.1", "127.0.0.0/8", "127.4.0.0/16", "::1", "10.0.0.0/8", "10.20.0.0/16",
		"172.16.0.0/12", "172.17.0.0/16", "192.168.0.0/16", "192.168.5.7", "fc00::/7", "fd00::/8", "fd12:3456::/32",
		"::ffff:10.0.0.0/104"} {
		p, err := ParsePrefix(in)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckUpstreamTrusted(p); err != nil {
			t.Errorf("CheckUpstreamTrusted(%s) = %v, want nil", in, err)
		}
	}
	for _, in := range []string{"0.0.0.0/0", "::/0", "192.0.2.0/24", "198.51.100.7", "2001:db8::/32",
		"127.0.0.0/7", "10.0.0.0/7", "172.0.0.0/8", "172.16.0.0/11", "192.168.0.0/15", "fc00::/6", "::/127",
		"169.254.0.0/16", "fe80::/10", "100.64.0.0/10"} {
		p, err := ParsePrefix(in)
		if err != nil {
			t.Fatal(err)
		}
		err = CheckUpstreamTrusted(p)
		if err == nil {
			t.Errorf("CheckUpstreamTrusted(%s) = nil, want an error", in)
			continue
		}
		for _, want := range []string{"http-upstream", "loopback or private", p.String()} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("CheckUpstreamTrusted(%s) = %q: it does not say %q", in, err, want)
			}
		}
	}
}

func TestListenerValues(t *testing.T) {
	for s, want := range map[string]bool{"tls": true, "http-upstream": true, "": false, "TLS": false, "udp": false} {
		if ValidListenerKind(s) != want {
			t.Errorf("ValidListenerKind(%q) = %v", s, !want)
		}
	}
	for s, want := range map[string]bool{"mask": true, "reject": true, "drop": true, "": false, "ignore": false} {
		if ValidStrangerAction(s) != want {
			t.Errorf("ValidStrangerAction(%q) = %v", s, !want)
		}
	}
	for s, want := range map[string]bool{"drop": true, "http400": true, "": false, "http500": false} {
		if ValidNonTLSAction(s) != want {
			t.Errorf("ValidNonTLSAction(%q) = %v", s, !want)
		}
	}
}

func TestParseHostPort(t *testing.T) {
	for in, want := range map[string]string{
		"198.51.100.9:1080":       "198.51.100.9 1080",
		"[2001:db8::9]:1080":      "2001:db8::9 1080",
		"proxy.example.com:65535": "proxy.example.com 65535",
		"proxy.example.com:080":   "proxy.example.com 80",
	} {
		host, port, err := ParseHostPort(in)
		if err != nil || host+" "+strconv.Itoa(int(port)) != want {
			t.Errorf("ParseHostPort(%q) = %q, %d, %v; want %s", in, host, port, err, want)
		}
	}
	for _, in := range []string{
		"", "proxy.example.com", "proxy.example.com:0", "proxy.example.com:65536", "proxy.example.com:+80", ":1080",
		"[198.51.100.9]:1080", "2001:db8::9:1080", "[proxy.example.com]:1080", "proxy.example.com/x:1080",
		"user@proxy.example.com:1080", "proxy example.com:1080", "proxy\r\n.example.com:1080", "proxy%2e.example.com:1080",
		"proxy#.example.com:1080", "proxy?.example.com:1080", `proxy\.example.com:1080`, "proxy\x7f.example.com:1080",
	} {
		if _, _, err := ParseHostPort(in); err == nil {
			t.Errorf("ParseHostPort(%q) = nil error", in)
		} else if strings.Contains(err.Error(), "proxy") {
			t.Errorf("ParseHostPort(%q) = %v: it quotes the address", in, err)
		}
	}
}

func TestCredentials(t *testing.T) {
	long := strings.Repeat("s", 256)
	if err := CheckSOCKS5Credentials(long[:255], long[:255]); err != nil {
		t.Errorf("255 bytes each: %v", err)
	}
	for _, c := range [][2]string{{long, ""}, {"", long}} {
		err := CheckSOCKS5Credentials(c[0], c[1])
		if err == nil || strings.Contains(err.Error(), "sss") {
			t.Errorf("CheckSOCKS5Credentials(%d bytes, %d bytes) = %v, want an error that quotes nothing", len(c[0]), len(c[1]), err)
		}
	}
	if err := CheckHTTPCredentials("user", "p:ss"); err != nil {
		t.Errorf("CheckHTTPCredentials(user, p:ss) = %v", err)
	}
	if err := CheckHTTPCredentials("us:er", ""); err == nil || strings.Contains(err.Error(), "us:er") {
		t.Errorf("CheckHTTPCredentials(us:er) = %v, want an error that quotes nothing", err)
	}
	// The credentials of an HTTP proxy go in a header of every CONNECT: 1 KiB each.
	kib := strings.Repeat("h", MaxHTTPCredential+1)
	if MaxHTTPCredential != 1024 {
		t.Errorf("MaxHTTPCredential = %d, want 1024", MaxHTTPCredential)
	}
	if err := CheckHTTPCredentials(kib[:MaxHTTPCredential], kib[:MaxHTTPCredential]); err != nil {
		t.Errorf("1 KiB each: %v", err)
	}
	for _, c := range []struct{ username, password, want string }{{kib, "", "username"}, {"", kib, "password"}} {
		err := CheckHTTPCredentials(c.username, c.password)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "hhh") {
			t.Errorf("CheckHTTPCredentials(%d bytes, %d bytes) = %v, want an error about the %s that quotes nothing",
				len(c.username), len(c.password), err, c.want)
		}
	}
}

// An error quotes at most 70 bytes of what it is about, as valid text.
func TestErrorsQuoteShortly(t *testing.T) {
	long := strings.Repeat("x", 300)
	for _, err := range []error{
		func() error { _, err := ParseMaskTarget(long + "_"); return err }(),
		func() error { _, err := ParseMaskTarget(long + ":0"); return err }(),
		func() error { _, err := ParsePrefix(long); return err }(),
		func() error { _, err := ParseBindIP(long); return err }(),
	} {
		if err == nil {
			t.Fatal("no error")
		}
		if strings.Contains(err.Error(), strings.Repeat("x", 71)) || !utf8.ValidString(err.Error()) {
			t.Errorf("error = %.120q...: it quotes more than 70 bytes", err)
		}
	}
}
