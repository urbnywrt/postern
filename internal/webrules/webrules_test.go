package webrules

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCheckBasePath(t *testing.T) {
	long := strings.Repeat("a", MaxBasePathSegment)
	for _, c := range []struct {
		in string
		ok bool
	}{
		{"", true}, {"tg", true}, {"a/b-c", true}, {"A1/b_2/C-3", true}, {long, true}, {long + "/" + long, true},
		{"/tg", false}, {"tg/", false}, {"a//b", false}, {"-a", false}, {"_a", false}, {"a.b", false},
		{"a b", false}, {"a/b?c", false}, {long + "a", false}, {"ü", false}, {"a%2Fb", false},
	} {
		if err := CheckBasePath(c.in); (err == nil) != c.ok {
			t.Errorf("CheckBasePath(%q) = %v, want ok=%v", c.in, err, c.ok)
		}
	}
}

func TestParsePublicAddr(t *testing.T) {
	for _, c := range []struct {
		in, want string
	}{
		{"203.0.113.10", "203.0.113.10"}, {"203.0.113.10:443", "203.0.113.10"}, {"::ffff:203.0.113.10", "203.0.113.10"},
		{"", ""}, {"203.0.113.10:8443", ""}, {"10.0.0.1", ""}, {"127.0.0.1", ""}, {"0.0.0.0", ""}, {"2001:db8::1", ""},
		{"example.com", ""}, {"203.0.113.10:", ""},
	} {
		a, err := ParsePublicAddr(c.in)
		switch {
		case c.want == "" && err == nil:
			t.Errorf("ParsePublicAddr(%q) = %s, want an error", c.in, a)
		case c.want != "" && (err != nil || a.String() != c.want):
			t.Errorf("ParsePublicAddr(%q) = %s, %v; want %s", c.in, a, err, c.want)
		}
	}
	if got := PublicAddr(mustAddr(t, "203.0.113.10")); got != "203.0.113.10:443" {
		t.Errorf("PublicAddr = %q", got)
	}
}

func TestCertDomain(t *testing.T) {
	for _, c := range []struct {
		in, want string
	}{
		{"Web.Example.COM", "web.example.com"}, {"web.example.com.", "web.example.com"},
		{"bücher.example", "xn--bcher-kva.example"}, {"", ""}, {"localhost", ""}, {"a b.example", ""}, {"..", ""},
	} {
		got, err := CertDomain(c.in)
		if (c.want == "") != (err != nil) || got != c.want {
			t.Errorf("CertDomain(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestModesAndCarriers(t *testing.T) {
	if SecretMode("") != SecretModePlain || SecretMode("dd") != "dd" || Carrier("") != CarrierHTTPS {
		t.Error("defaults")
	}
	if got := Carriers(nil); len(got) != 1 || got[0] != CarrierHTTPSLanes {
		t.Errorf("Carriers(nil) = %v", got)
	}
	for _, bad := range []string{"ee", "PLAIN", "dd "} {
		if CheckSecretMode(bad) == nil {
			t.Errorf("secret mode %q accepted", bad)
		}
	}
	for _, bad := range [][]string{{""}, {"wss"}, {"https", "https"}} {
		if CheckCarriers(bad) == nil {
			t.Errorf("carriers %q accepted", bad)
		}
	}
	if CheckCarriers([]string{"https", "https-lanes"}) != nil || CheckCarrier("") != nil {
		t.Error("good carriers refused")
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
