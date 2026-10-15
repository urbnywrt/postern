package auth

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
)

func prefixes(t *testing.T, list ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func TestParseTrustedProxies(t *testing.T) {
	for _, c := range []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"blank", "  \t ", nil},
		{"the default", DefaultTrustedProxies, []string{"127.0.0.1/32", "::1/128"}},
		{"a bare ipv4 address", "192.0.2.7", []string{"192.0.2.7/32"}},
		{"a bare ipv6 address", "2001:db8::7", []string{"2001:db8::7/128"}},
		{"cidrs", "198.51.100.0/24,2001:db8::/32", []string{"198.51.100.0/24", "2001:db8::/32"}},
		{"spaces around the entries", " 198.51.100.0/24 ,\t192.0.2.1 ", []string{"198.51.100.0/24", "192.0.2.1/32"}},
		{"empty entries are skipped", "192.0.2.1,, ,198.51.100.1,", []string{"192.0.2.1/32", "198.51.100.1/32"}},
		{"host bits are cleared", "198.51.100.77/24", []string{"198.51.100.0/24"}},
		{"host bits of an ipv6 prefix are cleared", "2001:db8::7/32", []string{"2001:db8::/32"}},
		{"an ipv4 address written as ipv6", "::ffff:192.0.2.7", []string{"192.0.2.7/32"}},
		{"an ipv4 network written as ipv6", "::ffff:192.0.2.0/120", []string{"192.0.2.0/24"}},
		{"everybody, when it is asked for", "0.0.0.0/0", []string{"0.0.0.0/0"}},
		{"upper case ipv6", "2001:DB8::/32", []string{"2001:db8::/32"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseTrustedProxies(c.in)
			if err != nil {
				t.Fatalf("ParseTrustedProxies(%q): %v", c.in, err)
			}
			want := prefixes(t, c.want...)
			if !slices.Equal(got, want) {
				t.Errorf("ParseTrustedProxies(%q) = %v, want %v", c.in, got, want)
			}
		})
	}
}

func TestParseTrustedProxiesRefusesWhatItCannotRead(t *testing.T) {
	for _, c := range []struct{ name, in, mention string }{
		{"a word", "nonsense", "nonsense"},
		{"a host name", "proxy.example", "proxy.example"},
		{"a bad length", "192.0.2.1/33", "192.0.2.1/33"},
		{"a bad ipv6 length", "2001:db8::/129", "2001:db8::/129"},
		{"a missing length", "192.0.2.0/", "192.0.2.0/"},
		{"a length that is not a number", "192.0.2.0/x", "192.0.2.0/x"},
		{"an address with a port", "192.0.2.1:8080", "192.0.2.1:8080"},
		{"an address with a zone", "fe80::1%eth0", "fe80::1%eth0"},
		{"a prefix with a zone", "fe80::%eth0/64", "fe80::%eth0/64"},
		{"a range", "192.0.2.1-192.0.2.9", "192.0.2.1-192.0.2.9"},
		{"two lengths", "192.0.2.0/24/8", "192.0.2.0/24/8"},
		{"a mapped network that is wider than ipv4", "::ffff:192.0.2.0/64", "::ffff:192.0.2.0/64"},
		{"one bad entry among good ones", "192.0.2.1,oops,198.51.100.1", "oops"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseTrustedProxies(c.in)
			if err == nil {
				t.Fatalf("ParseTrustedProxies(%q) = %v, want an error", c.in, got)
			}
			if got != nil {
				t.Errorf("ParseTrustedProxies(%q) returned %v with its error", c.in, got)
			}
			if !strings.Contains(err.Error(), c.mention) {
				t.Errorf("error %q does not name the entry %q", err, c.mention)
			}
		})
	}
}

// The default is the loopback and nothing else: a private address is not
// trusted just for being one.
func TestDefaultTrustedProxiesAreTheLoopback(t *testing.T) {
	got, err := ParseTrustedProxies(DefaultTrustedProxies)
	if err != nil {
		t.Fatal(err)
	}
	want := prefixes(t, "127.0.0.1/32", "::1/128")
	if !slices.Equal(got, want) {
		t.Fatalf("DefaultTrustedProxies = %q, which reads as %v, want %v", DefaultTrustedProxies, got, want)
	}

	e := newEnv(t)
	s := newService(e.db, e.key, nil, e.clock.Now) // no option
	for _, c := range []struct{ remote, want string }{
		{"127.0.0.1:4000", "192.0.2.1"},
		{"[::1]:4000", "192.0.2.1"},
		{"127.0.0.2:4000", "127.0.0.2"},
		{"10.1.2.3:4000", "10.1.2.3"},
		{"172.18.0.1:4000", "172.18.0.1"},
		{"169.254.1.2:4000", "169.254.1.2"},
		{"203.0.113.9:4000", "203.0.113.9"},
	} {
		h := http.Header{"X-Forwarded-For": {"192.0.2.1"}}
		if got := s.clientIP(c.remote, h); got != c.want {
			t.Errorf("by default clientIP(%q, 192.0.2.1) = %q, want %q", c.remote, got, c.want)
		}
	}
}

func TestWithTrustedProxiesReplacesTheDefault(t *testing.T) {
	e := newEnv(t)
	proxy := prefixes(t, "198.51.100.0/24")
	s := newService(e.db, e.key, nil, e.clock.Now, WithTrustedProxies(proxy...))
	xff := http.Header{"X-Forwarded-For": {"192.0.2.1"}}
	if got := s.clientIP("198.51.100.9:4000", xff); got != "192.0.2.1" {
		t.Errorf("a configured proxy: clientIP = %q, want 192.0.2.1", got)
	}
	if got := s.clientIP("127.0.0.1:4000", xff); got != "127.0.0.1" {
		t.Errorf("the loopback is not trusted once other proxies are configured: clientIP = %q, want 127.0.0.1", got)
	}

	// The service keeps its own copy of the list.
	proxy[0] = netip.MustParsePrefix("203.0.113.0/24")
	if got := s.clientIP("198.51.100.9:4000", xff); got != "192.0.2.1" {
		t.Errorf("after the caller changed its slice: clientIP = %q, want 192.0.2.1", got)
	}
	if got := s.clientIP("203.0.113.9:4000", xff); got != "203.0.113.9" {
		t.Errorf("after the caller changed its slice, its new entry is trusted: clientIP = %q", got)
	}
}

// An option without proxies trusts nobody, not even the loopback.
func TestWithTrustedProxiesWithoutAnyTrustsNobody(t *testing.T) {
	e := newEnv(t)
	s := newService(e.db, e.key, nil, e.clock.Now, WithTrustedProxies())
	xff := http.Header{"X-Forwarded-For": {"192.0.2.1"}}
	for _, remote := range []string{"127.0.0.1:4000", "[::1]:4000", "10.1.2.3:4000"} {
		if got := s.clientIP(remote, xff); got == "192.0.2.1" {
			t.Errorf("clientIP(%q) believed the header", remote)
		}
	}
}

// Through the real middleware: the peer of the test server is the loopback. When
// it is not a configured proxy, what it says in X-Forwarded-For is ignored, so
// failures from "different" clients are all counted against the one address
// that the connection comes from, and cannot be used to spread guesses.
func TestLoginRateLimitIgnoresForwardedForFromAnUntrustedPeer(t *testing.T) {
	e := newEnvAdminWith(t, WithTrustedProxies(prefixes(t, "198.51.100.0/24")...))
	for i := range maxFailures {
		b := e.browser()
		b.header("X-Forwarded-For", "192.0.2."+string(rune('1'+i)))
		_, err := b.login("user"+string(rune('a'+i)), wrongPassword, "")
		wantCode(t, err, connect.CodeUnauthenticated)
	}
	b := e.browser()
	b.header("X-Forwarded-For", "192.0.2.200") // yet another address, says the header
	_, err := b.login(testUser, testPassword, "")
	wantCode(t, err, connect.CodeResourceExhausted)
}

// And the session that is started records the address that was used.
func TestSessionRecordsTheClientAddress(t *testing.T) {
	for _, c := range []struct {
		name string
		opts []Option
		want string
	}{
		{"trusted peer", nil, "192.0.2.77"},
		{"untrusted peer", []Option{WithTrustedProxies(prefixes(t, "198.51.100.0/24")...)}, "127.0.0.1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnvAdminWith(t, c.opts...)
			b := e.browser()
			b.header("X-Forwarded-For", "192.0.2.77")
			token := b.mustLogin()
			sess, err := e.session(token)
			if err != nil {
				t.Fatal(err)
			}
			if sess.IP != c.want {
				t.Errorf("session address = %q, want %q", sess.IP, c.want)
			}
		})
	}
}
