package preflight

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fakeResolver answers by name; a name it does not know is not found, and
// "down." fails.
type fakeResolver struct {
	addrs map[string][]netip.Addr
	asked []string
}

func (f *fakeResolver) LookupIP(_ context.Context, name string) ([]netip.Addr, error) {
	f.asked = append(f.asked, name)
	if name == "down.example.com" {
		return nil, errors.New("connection refused")
	}
	a, ok := f.addrs[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return a, nil
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func TestCheckDomain(t *testing.T) {
	r := &fakeResolver{addrs: map[string][]netip.Addr{
		"web.example.com":     addrs("203.0.113.7", "2001:db8::7"),
		"two.example.com":     addrs("198.51.100.5", "203.0.113.7"),
		"cf.example.com":      addrs("104.16.1.1"),
		"cf6.example.com":     addrs("203.0.113.7", "2606:4700::1"),
		"v6only.example.com":  addrs("2001:db8::7"),
		"xn--80adxhks.com":    addrs("203.0.113.7"),
		"mapped.example.com":  []netip.Addr{netip.MustParseAddr("::ffff:203.0.113.7")},
		"private.example.com": addrs("192.0.2.9"),
	}}
	c := New(r, nil)
	node := []string{"203.0.113.7", "203.0.113.8"}
	for _, tc := range []struct {
		name, domain string
		nodeIPs      []string
		want         string // the address, or "" for an error
		wantErr      error
		errHas       string
	}{
		{"A record is the node's", "web.example.com", node, "203.0.113.7", nil, ""},
		{"one of two A records is the node's", "two.example.com", node, "203.0.113.7", nil, ""},
		{"the node has not reported its addresses", "web.example.com", nil, "203.0.113.7", nil, ""},
		{"the node reported nothing readable", "web.example.com", []string{"", "not-an-ip"}, "203.0.113.7", nil, ""},
		{"A record is not the node's", "private.example.com", node, "", ErrDomain, "not an address of the node"},
		{"proxied by Cloudflare", "cf.example.com", node, "", ErrDomain, "Cloudflare"},
		{"proxied by Cloudflare over IPv6", "cf6.example.com", node, "", ErrDomain, "Cloudflare"},
		{"no A record", "v6only.example.com", node, "", ErrDomain, "no A record"},
		{"no such name", "none.example.com", node, "", ErrDomain, "no A record"},
		{"resolver down", "down.example.com", node, "", ErrLookup, "could not be looked up"},
		{"IPv4-mapped answer", "mapped.example.com", node, "203.0.113.7", nil, ""},
		{"uppercase domain with a dot", "WEB.example.com.", node, "203.0.113.7", nil, ""},
		{"IDN is looked up as punycode", "москва.com", node, "203.0.113.7", nil, ""},
		{"single label", "localhost", node, "", ErrDomain, "single label"},
		{"empty", "", node, "", ErrDomain, "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.CheckDomain(context.Background(), tc.domain, tc.nodeIPs)
			if tc.want == "" {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.errHas) {
					t.Errorf("err = %q, want it to say %q", err, tc.errHas)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckDomain: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("addr = %s, want %s", got, tc.want)
			}
		})
	}
	for _, asked := range r.asked {
		if asked != strings.ToLower(asked) || strings.HasSuffix(asked, ".") || strings.ContainsFunc(asked, func(r rune) bool { return r > 127 }) {
			t.Errorf("looked up %q, want lowercase ASCII without a trailing dot", asked)
		}
	}
}

func TestCloudflareRanges(t *testing.T) {
	cf := DefaultCloudflareRanges()
	for _, a := range []string{"104.16.1.1", "172.64.0.1", "2606:4700::1", "::ffff:104.16.1.1"} {
		if !cf.Contains(netip.MustParseAddr(a)) {
			t.Errorf("%s not in the embedded ranges", a)
		}
	}
	for _, a := range []string{"203.0.113.7", "192.0.2.1", "2001:db8::1", "172.63.255.255"} {
		if cf.Contains(netip.MustParseAddr(a)) {
			t.Errorf("%s in the embedded ranges", a)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v4":
			_, _ = w.Write([]byte("198.51.100.0/24\n\n203.0.113.0/25\n198.51.101.0/24\n198.51.102.0/24\n"))
		case "/v6":
			_, _ = w.Write([]byte("2001:db8:1::/48\n"))
		case "/bad":
			_, _ = w.Write([]byte("not a prefix\n"))
		case "/empty":
			_, _ = w.Write([]byte("\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	if err := cf.Refresh(ctx, srv.Client(), srv.URL+"/v4", srv.URL+"/v6"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if cf.Len() != 5 || !cf.Contains(netip.MustParseAddr("203.0.113.7")) || cf.Contains(netip.MustParseAddr("104.16.1.1")) {
		t.Errorf("after refresh: len %d, 203.0.113.7 %v, 104.16.1.1 %v", cf.Len(),
			cf.Contains(netip.MustParseAddr("203.0.113.7")), cf.Contains(netip.MustParseAddr("104.16.1.1")))
	}
	for _, bad := range []string{"/bad", "/empty", "/missing"} {
		if err := cf.Refresh(ctx, srv.Client(), srv.URL+bad); err == nil {
			t.Errorf("Refresh(%s): no error", bad)
		}
		if cf.Len() != 5 {
			t.Errorf("Refresh(%s) changed the ranges", bad)
		}
	}
}

func TestCheckBasePath(t *testing.T) {
	for _, s := range []string{"", "tg", "a/b-c_d", "A1/b2", strings.Repeat("x", 128)} {
		if err := CheckBasePath(s); err != nil {
			t.Errorf("CheckBasePath(%q) = %v", s, err)
		}
	}
	for _, s := range []string{"/tg", "tg/", "a//b", "-a", "_a", "a.b", "a b", "a/", strings.Repeat("x", 129), "é"} {
		if err := CheckBasePath(s); err == nil {
			t.Errorf("CheckBasePath(%q) = nil", s)
		}
	}
}

// selfSigned makes a certificate for the names, valid in [notBefore, notAfter),
// as PEM, and the PEM of its key.
func selfSigned(t *testing.T, names []string, notBefore, notAfter time.Time) (chain, key []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestCheckCertificate(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	chain, key := selfSigned(t, []string{"web.example.com", "*.wild.example"}, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	_, otherKey := selfSigned(t, []string{"web.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	expired, expiredKey := selfSigned(t, []string{"web.example.com"}, now.Add(-2*time.Hour), now.Add(-time.Hour))
	future, futureKey := selfSigned(t, []string{"web.example.com"}, now.Add(time.Hour), now.Add(2*time.Hour))

	got, err := CheckCertificate(chain, key, "WEB.example.com.", now)
	if err != nil {
		t.Fatalf("CheckCertificate: %v", err)
	}
	sum := sha256.Sum256(chain)
	if got.SHA256 != hex.EncodeToString(sum[:]) || !got.NotAfter.Equal(now.Add(30*24*time.Hour)) {
		t.Errorf("got %+v", got)
	}
	if _, err := CheckCertificate(chain, key, "a.wild.example", now); err != nil {
		t.Errorf("wildcard: %v", err)
	}
	// F5 of the real-server pass: a certificate minted a moment ago on a clock
	// a little ahead is taken (webrules.ClockTolerance).
	soon, soonKey := selfSigned(t, []string{"web.example.com"}, now.Add(2*time.Minute), now.Add(30*24*time.Hour))
	if _, err := CheckCertificate(soon, soonKey, "web.example.com", now); err != nil {
		t.Errorf("notBefore 2 minutes ahead: %v", err)
	}

	for _, tc := range []struct {
		name       string
		chain, key []byte
		domain     string
		errHas     string
	}{
		{"other domain", chain, key, "other.example.com", "not for other.example.com"},
		{"key of another certificate", chain, otherKey, "web.example.com", "not a pair"},
		{"expired", expired, expiredKey, "web.example.com", "expired"},
		{"not yet valid", future, futureKey, "web.example.com", "not valid before"},
		{"empty chain", nil, key, "web.example.com", "chain is empty"},
		{"empty key", chain, nil, "web.example.com", "key is empty"},
		{"not PEM", []byte("junk"), key, "web.example.com", "not a pair"},
		{"too long", append(chain, make([]byte, maxPEM)...), key, "web.example.com", "longer than"},
		{"single-label domain", chain, key, "localhost", "single label"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CheckCertificate(tc.chain, tc.key, tc.domain, now)
			if err == nil {
				t.Fatal("no error")
			}
			if !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("err = %q, want it to say %q", err, tc.errHas)
			}
			// The error never carries the key, nor the certificate.
			for _, secret := range []string{string(tc.key), "PRIVATE KEY", "BEGIN CERTIFICATE"} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Errorf("err quotes the input")
				}
			}
		})
	}
}

// A list of n documentation-range prefixes, one per line.
func fakeList(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "198.51.%d.0/24\n", i)
	}
	return b.String()
}

type memSettings struct {
	m   map[string][]byte
	err error
}

func (s *memSettings) GetSetting(_ context.Context, key string, dst any) (bool, error) {
	b, ok := s.m[key]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, dst)
}

func (s *memSettings) PutSetting(_ context.Context, key string, v any) error {
	if s.err != nil {
		return s.err
	}
	b, err := json.Marshal(v)
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[key] = b
	return err
}

func TestRefresherGoodBadAndSlowAnswers(t *testing.T) {
	var v4, v6 string
	var slow bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slow {
			<-r.Context().Done()
			return
		}
		switch r.URL.Path {
		case "/v4":
			_, _ = w.Write([]byte(v4))
		case "/v6":
			_, _ = w.Write([]byte(v6))
		}
	}))
	defer srv.Close()
	store := &memSettings{}
	cf := DefaultCloudflareRanges()
	embedded := cf.Len()
	f := &Refresher{Ranges: cf, Client: srv.Client(), Store: store, URLs: []string{srv.URL + "/v4", srv.URL + "/v6"}}
	ctx := context.Background()
	inList := netip.MustParseAddr("198.51.2.9")

	// A good answer replaces the list and is stored.
	v4, v6 = fakeList(4), "2001:db8:1::/48\n"
	if err := f.RefreshOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if cf.Len() != 5 || !cf.Contains(inList) || cf.Contains(netip.MustParseAddr("104.16.1.1")) {
		t.Fatalf("after a good answer: len %d", cf.Len())
	}
	if _, ok := store.m[SettingCloudflareRanges]; !ok {
		t.Fatal("the good list is not stored")
	}

	// Bad answers keep the old list, and the stored one: a line that is no
	// range, too few ranges, an answer over 64 KiB.
	for name, body := range map[string]string{
		"junk line": fakeList(6) + "<html>\n",
		"too few":   fakeList(2),
		"too large": fakeList(5) + strings.Repeat("\n", maxList),
	} {
		v4, v6 = body, "2001:db8:2::/48\n"
		before := string(store.m[SettingCloudflareRanges])
		if err := f.RefreshOnce(ctx); err == nil {
			t.Errorf("%s: no error", name)
		}
		if cf.Len() != 5 || !cf.Contains(inList) || string(store.m[SettingCloudflareRanges]) != before {
			t.Errorf("%s: the list or the stored list changed", name)
		}
	}

	// A timeout keeps it too.
	slow = true
	tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := f.RefreshOnce(tctx); err == nil {
		t.Error("a timeout: no error")
	}
	if cf.Len() != 5 || !cf.Contains(inList) {
		t.Error("a timeout changed the list")
	}

	// A new process starts from the stored list; with nothing stored, or junk,
	// from the embedded one.
	fresh := &Refresher{Ranges: DefaultCloudflareRanges(), Store: store}
	if at := fresh.Load(ctx); at.IsZero() || fresh.Ranges.Len() != 5 {
		t.Errorf("Load: %v, %d ranges", at, fresh.Ranges.Len())
	}
	junk := &memSettings{m: map[string][]byte{SettingCloudflareRanges: []byte(`{"ranges":["x","y","z","a","b"]}`)}}
	fresh = &Refresher{Ranges: DefaultCloudflareRanges(), Store: junk}
	if at := fresh.Load(ctx); !at.IsZero() || fresh.Ranges.Len() != embedded {
		t.Errorf("Load of junk: %v, %d ranges", at, fresh.Ranges.Len())
	}
}

func TestRefreshRefusesWidePrefixesAndForeignRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fakeList(6)))
	}))
	defer other.Close()
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, other.URL+"/v4", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	cf := DefaultCloudflareRanges()
	embedded := cf.Len()
	ctx := context.Background()
	for name, b := range map[string]string{
		"v4 /0":  fakeList(6) + "0.0.0.0/0\n",
		"v4 /7":  fakeList(6) + "10.0.0.0/7\n",
		"v6 /0":  fakeList(6) + "::/0\n",
		"v6 /15": fakeList(6) + "2000::/15\n",
	} {
		body = b
		if err := cf.Refresh(ctx, srv.Client(), srv.URL+"/x"); err == nil || cf.Len() != embedded {
			t.Errorf("%s: err %v, len %d", name, err, cf.Len())
		}
	}
	body = fakeList(5) + "0.0.0.0/8\n::/16\n"
	if err := cf.Refresh(ctx, srv.Client(), srv.URL+"/x"); err != nil {
		t.Errorf("/8 and /16 are the limits that pass: %v", err)
	}
	cf = DefaultCloudflareRanges()
	if err := cf.Refresh(ctx, srv.Client(), srv.URL+"/redirect"); err == nil || cf.Len() != embedded {
		t.Errorf("a redirect to another host: err %v, len %d", err, cf.Len())
	}
}
