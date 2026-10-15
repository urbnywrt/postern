package diag

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/acme"
	"github.com/urbnywrt/postern/internal/node/state"
)

var webNow = time.Unix(1_790_000_000, 0)

// webEnv: W1 (acme-dns01) and W2 (imported) on the tls listener L1, whose
// test listener is on port; W3 behind a web server (U1); W4 paused; P1 fake
// TLS. Every enabled proxy is serving in generation 2.
func webEnv(t *testing.T, port uint16) *Env {
	t.Helper()
	st := &nodev1.NodeState{
		Listeners: []*nodev1.Listener{
			{Id: "L1", BindIp: "0.0.0.0", Port: 443},
			{Id: "U1", BindIp: "127.0.0.1", Port: 18080, Kind: nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM},
		},
		Proxies: []*nodev1.Proxy{
			{Id: "W1", ListenerId: "L1", Enabled: true, Type: nodev1.ProxyType_PROXY_TYPE_WEB, Secret: testSecret, Domain: "web.example.com",
				Web: &nodev1.WebSettings{CertMode: "acme-dns01", DnsCredential: "cf-token"}},
			{Id: "W2", ListenerId: "L1", Enabled: true, Type: nodev1.ProxyType_PROXY_TYPE_WEB, Secret: testSecret, Domain: "imported.example.com",
				Web: &nodev1.WebSettings{CertMode: "imported", CertSha256: strings.Repeat("ab", 32), PublicAddr: "203.0.113.20"}},
			{Id: "W3", ListenerId: "U1", Enabled: true, Type: nodev1.ProxyType_PROXY_TYPE_WEB, Secret: testSecret, Domain: "site.example.com",
				Web: &nodev1.WebSettings{BasePath: "tg"}},
			{Id: "W4", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_WEB, Secret: testSecret, Domain: "paused.example.com",
				Web: &nodev1.WebSettings{CertMode: "acme-dns01", DnsCredential: "cf-token"}},
			{Id: "P1", ListenerId: "L1", Enabled: true, Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Secret: testSecret, Domain: "example.com"},
		},
	}
	rt := state.NewRuntime()
	rt.Ports[state.TestListenerPortKey("L1")] = port
	for _, id := range []string{"W1", "W2", "W3", "P1"} {
		rt.Instances[id] = state.InstanceRecord{Generation: 2, ListenPort: 20001}
	}
	return &Env{Store: &state.Store{Paths: state.Paths{Home: t.TempDir()}}, Desired: st, Runtime: rt,
		Scrub: NewScrubber(st, rt, nil), Now: func() time.Time { return webNow }}
}

func TestWebTargets(t *testing.T) {
	env := webEnv(t, 0)
	if got := strings.Join(webTLSTargets(env), ","); got != "proxy:W1,proxy:W2" {
		t.Errorf("tls targets = %s", got)
	}
	units := env.webUnits(false)
	if len(units) != 3 || units[2].target != "proxy:W3" || !units[2].upstream {
		t.Errorf("all units = %+v", units)
	}
}

func TestWebCert(t *testing.T) {
	importedSHA := strings.Repeat("ab", 32)
	days := func(n int) time.Time { return webNow.Add(time.Duration(n)*24*time.Hour + time.Hour) }
	cases := []struct {
		name   string
		proxy  string
		st     acme.Status
		status nodev1.CheckStatus
		fix    string
		want   string
	}{
		{"30 days", "W1", acme.Status{Valid: true, NotAfter: days(30), FullchainSHA256: "aa", Issuer: "Test CA"}, OK, "", "30 days left"},
		{"14 days", "W1", acme.Status{Valid: true, NotAfter: days(14), FullchainSHA256: "aa"}, OK, "", "14 days left"},
		{"10 days", "W1", acme.Status{Valid: true, NotAfter: days(10), FullchainSHA256: "aa", Issuer: "Test CA", LastError: "the CA said no"}, Warn, FixReissueCert, "10 days"},
		{"2 days", "W1", acme.Status{Valid: true, NotAfter: days(2), FullchainSHA256: "aa"}, Fail, FixReissueCert, "2 days"},
		{"expired", "W1", acme.Status{NotAfter: days(-1), FullchainSHA256: "aa", Problem: "the certificate expired at x"}, Fail, FixReissueCert, "expired"},
		{"missing", "W1", acme.Status{Problem: acme.ProblemNoCertificate, LastError: "no DNS credential"}, Fail, FixReissueCert, "no certificate"},
		{"not for the domain", "W1", acme.Status{FullchainSHA256: "aa", Problem: "the certificate is not for web.example.com"}, Fail, FixReissueCert, "not for"},
		{"imported ok", "W2", acme.Status{Valid: true, NotAfter: days(60), FullchainSHA256: importedSHA}, OK, "", "valid until"},
		{"imported soon, no fix", "W2", acme.Status{Valid: true, NotAfter: days(5), FullchainSHA256: importedSHA}, Warn, "", "5 days"},
		{"imported other chain", "W2", acme.Status{Valid: true, NotAfter: days(60), FullchainSHA256: "cd"}, Fail, "", "not the one the panel named"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := webEnv(t, 0)
			env.CertStatus = func(domain string) acme.Status {
				st := c.st
				st.Domain = domain
				return st
			}
			r := byTarget(checkWebCert(t.Context(), env))["proxy:"+c.proxy]
			if r.Status != c.status || r.Fix != c.fix || !strings.Contains(r.Summary, c.want) {
				t.Fatalf("result = %+v, want %v fix %q summary ~%q", r, c.status, c.fix, c.want)
			}
			if c.status != OK && c.proxy == "W1" && !strings.Contains(r.Evidence, "last ACME error: ") {
				t.Errorf("evidence lacks the last ACME error: %q", r.Evidence)
			}
			if c.name == "10 days" && (!strings.Contains(r.Evidence, "issuer: Test CA") || !strings.Contains(r.Evidence, "expires: ") || !strings.Contains(r.Evidence, "the CA said no")) {
				t.Errorf("evidence = %q", r.Evidence)
			}
		})
	}
	env := webEnv(t, 0)
	if rs := checkWebCert(t.Context(), env); len(rs) != 2 || rs[0].Status != Skip {
		t.Errorf("without CertStatus: %+v", rs)
	}

	// F6 of the real-server pass: a chain that is not publicly trusted (a
	// private CA) warns, with a hint; a trusted one stays ok.
	env.CertStatus = func(domain string) acme.Status {
		return acme.Status{Domain: domain, Valid: true, NotAfter: days(60), FullchainSHA256: importedSHA}
	}
	env.CertTrusted = func(string) error { return errors.New("x509: certificate signed by unknown authority") }
	r := byTarget(checkWebCert(t.Context(), env))["proxy:W2"]
	if r.Status != Warn || !strings.Contains(r.Summary, "not publicly trusted") || !strings.Contains(r.Summary, "unknown authority") ||
		!strings.Contains(r.Hint, "public CA") {
		t.Errorf("a private CA: %+v", r)
	}
	env.CertTrusted = func(string) error { return nil }
	if r := byTarget(checkWebCert(t.Context(), env))["proxy:W2"]; r.Status != OK {
		t.Errorf("a trusted chain: %+v", r)
	}
	// Roots that cannot be loaded say nothing about the chain.
	env.CertTrusted = func(string) error { return acme.ErrNoRoots }
	if r := byTarget(checkWebCert(t.Context(), env))["proxy:W2"]; r.Status != OK {
		t.Errorf("no roots: %+v", r)
	}
}

func TestWebDNS(t *testing.T) {
	nodeIPs := []netip.Addr{netip.MustParseAddr("203.0.113.10")}
	cases := []struct {
		name    string
		records map[string][]string
		err     error
		w1, w2  nodev1.CheckStatus
		want    string
	}{
		{"matching", map[string][]string{"web.example.com": {"203.0.113.10"}, "imported.example.com": {"203.0.113.20", "2001:db8::1"}}, nil, OK, OK, "listener's public address"},
		{"cloudflare", map[string][]string{"web.example.com": {"104.16.0.1"}, "imported.example.com": {"203.0.113.20"}}, nil, Fail, OK, "Cloudflare"},
		{"elsewhere", map[string][]string{"web.example.com": {"203.0.113.10", "198.51.100.9"}, "imported.example.com": {"203.0.113.10"}}, nil, Fail, Fail, "not the listener's public address"},
		{"no record", map[string][]string{}, nil, Fail, Fail, "no A record"},
		{"lookup fails", nil, errors.New("doh: every endpoint failed"), Fail, Fail, "cannot be resolved"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := webEnv(t, 0)
			env.PublicIPs = func(context.Context) []netip.Addr { return nodeIPs }
			env.LookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
				if c.err != nil {
					return nil, c.err
				}
				var out []netip.Addr
				for _, s := range c.records[host] {
					out = append(out, netip.MustParseAddr(s))
				}
				return out, nil
			}
			rs := byTarget(checkWebDNS(t.Context(), env))
			if len(rs) != 2 {
				t.Fatalf("results = %+v", rs)
			}
			w1, w2 := rs["proxy:W1"], rs["proxy:W2"]
			if w1.Status != c.w1 || w2.Status != c.w2 || !strings.Contains(w1.Summary, c.want) {
				t.Fatalf("W1 %+v, W2 %+v", w1, w2)
			}
		})
	}
	env := webEnv(t, 0)
	if rs := checkWebDNS(t.Context(), env); len(rs) != 2 || rs[0].Status != Skip {
		t.Errorf("without LookupIP: %+v", rs)
	}
}

// h2Server is a TLS server on the loopback, standing in for the edge's test
// listener; its chain is written as the stored fullchain.pem of domain.
func h2Server(t *testing.T, env *Env, http2 bool, status int, domain string) (uint16, *httptest.Server) {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Host != domain || r.URL.Path != "/" || r.TLS.ServerName != domain {
			http.Error(w, "wrong request", http.StatusTeapot)
			return
		}
		w.WriteHeader(status)
	}))
	srv.EnableHTTP2 = http2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	writeChain(t, env, domain, srv.TLS.Certificates[0].Certificate)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	return uint16(port), srv
}

func writeChain(t *testing.T, env *Env, domain string, ders [][]byte) {
	t.Helper()
	dir := filepath.Join(env.Store.Paths.CertsDir(), domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var b []byte
	for _, d := range ders {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWebHTTP2(t *testing.T) {
	cases := []struct {
		name   string
		http2  bool
		status int
		other  bool // the stored chain is not the served one
		want   nodev1.CheckStatus
		sum    string
	}{
		{"ok", true, 200, false, OK, "HTTP/2, GET / 200"},
		{"http/1.1 only", false, 200, false, Fail, "does not speak HTTP/2"},
		{"another certificate", true, 200, true, Fail, "another certificate"},
		{"not 200", true, 503, false, Fail, "answers 503"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := webEnv(t, 0)
			port, _ := h2Server(t, env, c.http2, c.status, "web.example.com")
			env.Runtime.Ports[state.TestListenerPortKey("L1")] = port
			if c.other {
				writeChain(t, env, "web.example.com", [][]byte{[]byte("not the served certificate")})
			}
			var probes []*nodev1.ProbeResult
			var mu sync.Mutex
			env.AddProbe = func(p *nodev1.ProbeResult) { mu.Lock(); probes = append(probes, p); mu.Unlock() }
			env.Only = "proxy:W1"
			rs := checkWebHTTP2(t.Context(), env)
			if len(rs) != 1 || rs[0].Target != "proxy:W1" {
				t.Fatalf("results = %+v", rs)
			}
			if r := rs[0]; r.Status != c.want || !strings.Contains(r.Summary, c.sum) {
				t.Fatalf("result = %+v, want %v ~%q", r, c.want, c.sum)
			}
			if len(probes) != 1 || probes[0].GetKind() != ProbeKindWeb || probes[0].GetOk() != (c.want == OK) || probes[0].GetProxyId() != "W1" {
				t.Errorf("probes = %v", probes)
			}
		})
	}

	// W2 has no stored certificate; W1 is not serving.
	env := webEnv(t, 0)
	port, _ := h2Server(t, env, true, 200, "web.example.com")
	env.Runtime.Ports[state.TestListenerPortKey("L1")] = port
	delete(env.Runtime.Instances, "W1")
	rs := byTarget(checkWebHTTP2(t.Context(), env))
	if rs["proxy:W1"].Status != Skip || rs["proxy:W2"].Status != Skip || !strings.Contains(rs["proxy:W2"].Summary, IDWebCert) {
		t.Errorf("results = %+v", rs)
	}
	// No test listener.
	env = webEnv(t, 0)
	if rs := checkWebHTTP2(t.Context(), env); len(rs) != 2 || rs[0].Status != Skip {
		t.Errorf("without a test listener: %+v", rs)
	}
}

func TestWebDecoy(t *testing.T) {
	env := webEnv(t, 0)
	dir := filepath.Join(env.Store.Paths.InstancesDir(), "eng-w1-g2", "public")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(env.Store.Paths.InstancesDir(), "eng-w2-g2", "public", "index.html"), 0o755); err != nil {
		t.Fatal(err)
	}
	rs := byTarget(checkWebDecoy(t.Context(), env))
	if len(rs) != 3 {
		t.Fatalf("results = %+v", rs)
	}
	if r := rs["proxy:W1"]; r.Status != OK {
		t.Errorf("W1 = %+v", r)
	}
	if r := rs["proxy:W2"]; r.Status != Fail || r.Fix != FixRecreateInstance {
		t.Errorf("W2 (a directory for an index) = %+v", r)
	}
	if r := rs["proxy:W3"]; r.Status != Fail || r.Fix != FixRecreateInstance || !strings.Contains(r.Evidence, "public/index.html") {
		t.Errorf("W3 (no index) = %+v", r)
	}
	if strings.Contains(rs["proxy:W3"].Evidence, env.Store.Paths.Home) {
		t.Error("the evidence names the node's home")
	}
}
