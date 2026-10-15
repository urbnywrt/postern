package reconcile

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/acme"
	"github.com/urbnywrt/postern/internal/node/state"
)

const (
	webID    = "01J9ZZPROXY0000000000000W1"
	webDir1  = "eng-01j9zzproxy0000000000000w1-g1"
	nodeIPv4 = "203.0.113.10"
)

// webHarness is the harness with the node's addresses and lookups faked: the
// node holds nodeIPv4, every WEB domain resolves to the addresses set in
// records, web listeners answer their probe, and no ACME runs unless a test
// sets one up (acmeStub).
type webHarness struct {
	*harness
	mu      sync.Mutex
	records map[string][]netip.Addr
	lookups []string
}

func newWebHarness(t *testing.T) *webHarness {
	t.Helper()
	w := &webHarness{harness: newHarness(t), records: map[string][]netip.Addr{}}
	w.r.InterfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP(nodeIPv4), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("10.0.0.7"), Mask: net.CIDRMask(8, 32)},
		}, nil
	}
	w.r.LookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.lookups = append(w.lookups, host)
		if rs, ok := w.records[host]; ok {
			return rs, nil
		}
		return nil, errors.New("no such host")
	}
	w.r.webProbe = func(context.Context, string, string) error { return nil }
	w.resolve("web.example.com", nodeIPv4)
	return w
}

func (w *webHarness) resolve(domain string, ips ...string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var as []netip.Addr
	for _, ip := range ips {
		as = append(as, netip.MustParseAddr(ip))
	}
	w.records[domain] = as
}

// webState is baseState with a WEB proxy of cert_mode imported on L1 next to
// the fake-TLS one.
func (w *webHarness) webState(gen uint64, certSHA string) *nodev1.NodeState {
	st := w.baseState(gen)
	st.Proxies = append(st.Proxies, &nodev1.Proxy{
		Id: webID, ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_WEB, Enabled: true,
		Secret: secret2, Domain: "Web.Example.COM",
		Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
		Limits: &nodev1.Limits{Devices: 5},
		Web:    &nodev1.WebSettings{CertMode: "imported", CertSha256: certSHA},
	})
	return st
}

// cert returns a self-signed certificate for domain, PEM, and the digest of
// its chain.
func cert(t *testing.T, domain string, now time.Time) (chain, key []byte, sha string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	chain = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	key = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	sum := sha256.Sum256(chain)
	return chain, key, hex.EncodeToString(sum[:])
}

func webRoute(t *testing.T, h *harness) *edgev1.Route {
	t.Helper()
	for _, r := range h.lastSetConfig().GetRoutes() {
		if r.GetProxyId() == webID {
			return r
		}
	}
	return nil
}

// An imported certificate gates the route: the instance runs from the first
// pass, but the edge gets the route (kind web, no PROXY protocol, the
// instance's listen port, with the certificate named) only once the stored
// chain is the one the panel named, and loses it when it is not.
func TestWebProxyImportedCertificateGatesTheRoute(t *testing.T) {
	w := newWebHarness(t)
	h := w.harness
	chain, key, sha := cert(t, "web.example.com", h.clock.Now())
	h.apply(w.webState(1, sha))
	h.pass()

	if h.container("postern-eng-01j9zzproxy0000000000000w1-g1") == nil {
		t.Fatal("the WEB engine was not started")
	}
	cfg, err := os.ReadFile(filepath.Join(h.paths.InstancesDir(), webDir1, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`transport = "web"`, `public_addr = "203.0.113.10:443"`, `host = "web.example.com"`, `directory = "/etc/telemt/public"`} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("config.toml lacks %s", want)
		}
	}
	if _, err := os.Stat(filepath.Join(h.paths.InstancesDir(), webDir1, "public", "index.html")); err != nil {
		t.Errorf("decoy site: %v", err)
	}
	if r := webRoute(t, h); r != nil {
		t.Errorf("route before the certificate: %v", r)
	}
	if ps := h.proxyStatus(webID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_PENDING || !strings.Contains(ps.GetReason(), "waiting for the imported certificate") {
		t.Errorf("status = %v", ps)
	}
	if got := routeMap(h.lastSetConfig()); len(got) != 1 {
		t.Errorf("routes = %v, want the fake-TLS one only", got)
	}

	if _, err := h.r.certManager().Put(context.Background(), "web.example.com", chain, key); err != nil {
		t.Fatal(err)
	}
	h.pass()
	r := webRoute(t, h)
	rec := h.runtime().Instances[webID]
	if r == nil || r.GetKind() != "web" || r.GetProxyProtocol() || r.GetBackend() != addr(rec.ListenPort) || r.GetListenerId() != "L1" || r.GetSni() != "Web.Example.COM" || r.GetLimits().GetDevices() != 5 {
		t.Fatalf("route = %v (listen port %d)", r, rec.ListenPort)
	}
	certs := h.lastSetConfig().GetCerts()
	if len(certs) != 1 || certs[0].GetDomain() != "web.example.com" || certs[0].GetGeneration() == 0 {
		t.Errorf("certs = %v", certs)
	}
	if ps := h.proxyStatus(webID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING || ps.GetReason() != "" {
		t.Errorf("status = %v", ps)
	}
	if n := len(h.creates("engine")); n != 2 {
		t.Errorf("%d engine containers created, want 2 (one per proxy): the certificate must not roll the engine", n)
	}

	// The panel names another chain: the route goes until it arrives.
	_, _, other := cert(t, "web.example.com", h.clock.Now())
	h.apply(w.webState(2, other))
	h.pass()
	if r := webRoute(t, h); r != nil {
		t.Errorf("route with a mismatched certificate: %v", r)
	}
	if ps := h.proxyStatus(webID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_PENDING || !strings.Contains(ps.GetReason(), "not the one the panel named") {
		t.Errorf("status = %v", ps)
	}
	if certs := h.lastSetConfig().GetCerts(); len(certs) != 0 {
		t.Errorf("certs = %v, want none", certs)
	}
}

// A WEB proxy whose domain does not point to the node is not started, with a
// reason that names both sides; it starts once the record does.
func TestWebProxyNeedsItsARecordOnTheNode(t *testing.T) {
	w := newWebHarness(t)
	h := w.harness
	w.resolve("web.example.com", "198.51.100.5")
	h.apply(w.webState(1, strings.Repeat("ab", 32)))
	h.pass()
	if h.container("postern-eng-01j9zzproxy0000000000000w1-g1") != nil {
		t.Fatal("the WEB engine was started without a public address")
	}
	ps := h.proxyStatus(webID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || !strings.Contains(ps.GetReason(), "198.51.100.5") || !strings.Contains(ps.GetReason(), nodeIPv4) {
		t.Errorf("status = %v", ps)
	}
	if h.proxyStatus(proxyID).GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
		t.Error("the fake-TLS proxy must serve regardless")
	}

	// The record changes (the cache is fresh for a while: move the clock).
	w.resolve("web.example.com", "198.51.100.5", nodeIPv4)
	h.clock.Advance(webLookupTTL + time.Second)
	h.pass()
	if h.container("postern-eng-01j9zzproxy0000000000000w1-g1") == nil {
		t.Fatal("the WEB engine was not started once the record pointed here")
	}
	cfg, _ := os.ReadFile(filepath.Join(h.paths.InstancesDir(), webDir1, "config.toml"))
	if !strings.Contains(string(cfg), `public_addr = "203.0.113.10:443"`) {
		t.Errorf("public_addr not the node's address:\n%s", cfg)
	}
	// A lookup failure keeps the last answer: no roll, no failure.
	w.mu.Lock()
	delete(w.records, "web.example.com")
	w.mu.Unlock()
	h.clock.Advance(webLookupTTL + time.Second)
	h.pass()
	if ps := h.proxyStatus(webID); ps.GetPhase() == nodev1.ProxyPhase_PROXY_PHASE_FAILED {
		t.Errorf("status after a failed lookup = %v, want the last answer kept", ps)
	}
}

// Behind a web server (an http-upstream listener) the route is served as soon
// as the instance is: the web server in front owns the certificate.
func TestWebProxyBehindAWebServer(t *testing.T) {
	w := newWebHarness(t)
	h := w.harness
	st := w.webState(1, "")
	st.Listeners = append(st.Listeners, &nodev1.Listener{
		Id: "U1", Kind: nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM, BindIp: "127.0.0.1", Port: 18080,
		TrustedCidrs: []string{"127.0.0.1/32", "172.17.0.0/16"},
	})
	st.Proxies[1].ListenerId = "U1"
	st.Proxies[1].Web = &nodev1.WebSettings{BasePath: "tg/one"}
	h.apply(st)
	h.pass()

	r := webRoute(t, h)
	rec := h.runtime().Instances[webID]
	if r == nil || r.GetKind() != "web" || r.GetListenerId() != "U1" || r.GetBackend() != addr(rec.ListenPort) || r.GetProxyProtocol() {
		t.Fatalf("route = %v", r)
	}
	if certs := h.lastSetConfig().GetCerts(); len(certs) != 0 {
		t.Errorf("certs = %v, want none behind a web server", certs)
	}
	var upstream *edgev1.EdgeListener
	for _, l := range h.lastSetConfig().GetListeners() {
		if l.GetId() == "U1" {
			upstream = l
		}
	}
	if upstream == nil || upstream.GetKind() != "http-upstream" || len(upstream.GetTrustedCidrs()) != 2 {
		t.Errorf("edge listener U1 = %v", upstream)
	}
	if ps := h.proxyStatus(webID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
		t.Errorf("status = %v", ps)
	}
	cfg, _ := os.ReadFile(filepath.Join(h.paths.InstancesDir(), webDir1, "config.toml"))
	if !strings.Contains(string(cfg), `base_path = "tg/one"`) {
		t.Errorf("base_path not rendered:\n%s", cfg)
	}
}

// acmeStub stands in for the ACME manager's Issue: it records the calls and
// writes a certificate for the domain, as an issuance would.
type acmeStub struct {
	t     *testing.T
	h     *harness
	mu    sync.Mutex
	calls []string
	done  chan struct{}
	fail  error
}

func (s *acmeStub) issue(_ context.Context, domain, email string, _ acme.Credential) error {
	s.mu.Lock()
	s.calls = append(s.calls, domain+" "+email)
	fail := s.fail
	s.mu.Unlock()
	defer func() { s.done <- struct{}{} }()
	if fail != nil {
		return fail
	}
	chain, key, _ := cert(s.t, domain, s.h.clock.Now())
	_, err := s.h.r.certManager().Put(context.Background(), domain, chain, key)
	return err
}

// With cert_mode acme-dns01 the pass asks the manager for the certificate in
// the background (the domain in lowercase), the route waits with the
// manager's reason, and follows once the certificate is on disk. Issue is
// asked once per agent run while the certificate is good; a proxy that goes
// is forgotten.
func TestWebProxyACMEIssuesInTheBackground(t *testing.T) {
	w := newWebHarness(t)
	h := w.harness
	stub := &acmeStub{t: t, h: h, done: make(chan struct{}, 10)}
	h.r.Certs = &acme.Manager{Paths: h.paths, Now: h.clock.Now}
	h.r.issue = stub.issue

	st := w.webState(1, "")
	st.Proxies[1].Web = &nodev1.WebSettings{CertMode: "acme-dns01", DnsCredential: "cf-token", AcmeEmail: "ops@example.com"}
	h.apply(st)
	h.pass()
	select {
	case <-stub.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Issue was not called")
	}
	stub.mu.Lock()
	calls := append([]string(nil), stub.calls...)
	stub.mu.Unlock()
	if len(calls) != 1 || calls[0] != "web.example.com ops@example.com" {
		t.Fatalf("Issue calls = %q", calls)
	}
	if r := webRoute(t, h); r != nil {
		t.Errorf("route before the certificate: %v", r)
	}
	if ps := h.proxyStatus(webID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_PENDING || !strings.Contains(ps.GetReason(), "certificate") {
		t.Errorf("status = %v", ps)
	}

	h.pass()
	if r := webRoute(t, h); r == nil || r.GetKind() != "web" {
		t.Fatalf("route after the issuance = %v", r)
	}
	if certs := h.lastSetConfig().GetCerts(); len(certs) != 1 || certs[0].GetDomain() != "web.example.com" {
		t.Errorf("certs = %v", certs)
	}
	if ps := h.proxyStatus(webID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
		t.Errorf("status = %v", ps)
	}
	h.pass()
	stub.mu.Lock()
	n := len(stub.calls)
	stub.mu.Unlock()
	if n != 1 {
		t.Errorf("Issue called %d times, want once while the certificate is good", n)
	}
	h.r.mu.Lock()
	tracked := len(h.r.certDomains)
	h.r.mu.Unlock()
	if tracked != 1 {
		t.Errorf("%d domains tracked for renewal, want 1", tracked)
	}

	// The proxy goes: the domain is forgotten.
	h.apply(h.baseState(2))
	h.pass()
	h.r.mu.Lock()
	tracked = len(h.r.certDomains)
	h.r.mu.Unlock()
	if tracked != 0 {
		t.Errorf("%d domains tracked after the proxy went, want 0", tracked)
	}
}

// Without an ACME manager a proxy of cert_mode acme-dns01 waits with a reason
// that says so; its route is served when a certificate is on disk anyway.
func TestWebProxyACMEWithoutAManager(t *testing.T) {
	w := newWebHarness(t)
	h := w.harness
	st := w.webState(1, "")
	st.Proxies[1].Web = &nodev1.WebSettings{CertMode: "acme-dns01", DnsCredential: "cf-token"}
	h.apply(st)
	h.pass()
	if ps := h.proxyStatus(webID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_PENDING || !strings.Contains(ps.GetReason(), "ACME is not available") {
		t.Errorf("status = %v", ps)
	}
	chain, key, _ := cert(t, "web.example.com", h.clock.Now())
	if _, err := h.r.certManager().Put(context.Background(), "web.example.com", chain, key); err != nil {
		t.Fatal(err)
	}
	h.pass()
	if r := webRoute(t, h); r == nil {
		t.Error("no route with a certificate on disk")
	}
}

// A failed WEB probe aborts the generation like a failed fake-TLS probe.
func TestWebProxyProbeFailureAbortsTheGeneration(t *testing.T) {
	w := newWebHarness(t)
	h := w.harness
	h.r.webProbe = func(context.Context, string, string) error { return errors.New("connection refused") }
	h.r.probeAttempts = 2
	h.apply(w.webState(1, strings.Repeat("ab", 32)))
	h.pass()
	if h.container("postern-eng-01j9zzproxy0000000000000w1-g1") != nil {
		t.Error("the failed generation was kept")
	}
	ps := h.proxyStatus(webID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || !strings.Contains(ps.GetReason(), "web listener") {
		t.Errorf("status = %v", ps)
	}
	if calls := h.prober.callList(); len(calls) != 1 {
		t.Errorf("fake-TLS probes = %d, want 1 (the fake-TLS proxy only)", len(calls))
	}
}

// The ports of the listeners of the desired state are never handed out by
// the allocator (defence in depth: the validator refuses a listener in the
// internal ranges, but a test listener must not land on a listener's port
// either way).
func TestPlanReservesTheListenerPorts(t *testing.T) {
	w := newWebHarness(t)
	h := w.harness
	st := w.webState(1, "")
	st.Listeners = append(st.Listeners, &nodev1.Listener{
		Id: "U1", Kind: nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM, BindIp: "127.0.0.1", Port: 40000,
		TrustedCidrs: []string{"127.0.0.1/32"},
	})
	st.Proxies[1].ListenerId = "U1"
	st.Proxies[1].Web = &nodev1.WebSettings{BasePath: "tg"}
	if err := state.Validate(st, h.r.supports); err == nil || !strings.Contains(err.Error(), "internal") {
		t.Fatalf("Validate = %v, want the internal range refused", err)
	}
	// Validation bypassed: the reservation alone keeps the port.
	p := &pass{r: h.r, ctx: context.Background(), st: st, rt: state.NewRuntime()}
	p.reserveListenerPorts()
	for i := range 50 {
		port, err := h.r.alloc().Alloc(p.rt, "k"+strconv.Itoa(i), state.RangeService)
		if err != nil {
			t.Fatal(err)
		}
		if port == 40000 || port == 443 {
			t.Fatalf("the allocator handed out a listener's port %d", port)
		}
	}
}

// A paused WEB proxy keeps its certificate renewed: the domain is forgotten
// only when the proxy goes.
func TestWebProxyPausedKeepsRenewing(t *testing.T) {
	w := newWebHarness(t)
	h := w.harness
	stub := &acmeStub{t: t, h: h, done: make(chan struct{}, 10)}
	h.r.Certs = &acme.Manager{Paths: h.paths, Now: h.clock.Now}
	h.r.issue = stub.issue
	st := w.webState(1, "")
	st.Proxies[1].Web = &nodev1.WebSettings{CertMode: "acme-dns01", DnsCredential: "cf-token"}
	h.apply(st)
	h.pass()
	<-stub.done
	st = w.webState(2, "")
	st.Proxies[1].Enabled = false
	st.Proxies[1].Web = &nodev1.WebSettings{CertMode: "acme-dns01", DnsCredential: "cf-token"}
	h.apply(st)
	h.pass()
	h.r.mu.Lock()
	tracked := len(h.r.certDomains)
	h.r.mu.Unlock()
	if tracked != 1 {
		t.Errorf("%d domains tracked while paused, want 1", tracked)
	}
	if r := webRoute(t, h); r != nil {
		t.Errorf("a paused proxy has a route: %v", r)
	}
	if ps := h.proxyStatus(webID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_PAUSED {
		t.Errorf("status = %v", ps)
	}
}

// A raised reissue_nonce makes the pass ask the manager again for a domain
// whose certificate is good: the manager is told the nonce first, so the
// certificate is due.
func TestWebProxyReissueNonceAsksAgain(t *testing.T) {
	w := newWebHarness(t)
	h := w.harness
	stub := &acmeStub{t: t, h: h, done: make(chan struct{}, 10)}
	h.r.Certs = &acme.Manager{Paths: h.paths, Now: h.clock.Now}
	h.r.issue = stub.issue
	st := w.webState(1, "")
	st.Proxies[1].Web = &nodev1.WebSettings{CertMode: "acme-dns01", DnsCredential: "cf-token"}
	h.apply(st)
	h.pass()
	<-stub.done
	h.pass()
	if st := h.r.Certs.Status("web.example.com"); !st.Valid || st.Due {
		t.Fatalf("before the reissue: %+v", st)
	}
	st = w.webState(2, "")
	st.Proxies[1].Web = &nodev1.WebSettings{CertMode: "acme-dns01", DnsCredential: "cf-token", ReissueNonce: 1}
	h.apply(st)
	h.pass()
	select {
	case <-stub.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Issue was not called again after the nonce changed")
	}
	stub.mu.Lock()
	n := len(stub.calls)
	stub.mu.Unlock()
	if n != 2 {
		t.Fatalf("Issue calls = %d, want 2", n)
	}
	if r := webRoute(t, h); r == nil {
		t.Error("the route went while the certificate is reissued")
	}
}

// F4 of the real-server pass: deleting a WEB proxy removes its certificate and
// private key from the node (and with them what ACME keeps of the domain),
// once no WEB proxy has used the domain for certRemoveAfter. A domain another
// proxy uses stays; so does a certificate put just now, before the desired
// state that names its proxy arrives.
func TestWebProxyDeletedRemovesItsCertificate(t *testing.T) {
	w := newWebHarness(t)
	h := w.harness
	ctx := context.Background()
	mgr := h.r.certManager()
	chain, key, sha := cert(t, "web.example.com", h.clock.Now())
	keptChain, keptKey, _ := cert(t, "kept.example.com", h.clock.Now())
	for _, c := range []struct {
		domain     string
		chain, key []byte
	}{{"web.example.com", chain, key}, {"kept.example.com", keptChain, keptKey}} {
		if _, err := mgr.Put(ctx, c.domain, c.chain, c.key); err != nil {
			t.Fatal(err)
		}
	}
	other := &nodev1.Proxy{
		Id: "01J9ZZPROXY0000000000000W2", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_WEB, Enabled: false,
		Secret: secret2, Domain: "kept.example.com", Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
		Web: &nodev1.WebSettings{CertMode: "imported", CertSha256: strings.Repeat("ab", 32)},
	}
	st := w.webState(1, sha)
	st.Proxies = append(st.Proxies, other)
	h.apply(st)
	h.pass()
	if ps := h.proxyStatus(webID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
		t.Fatalf("status = %v", ps)
	}
	dir := filepath.Join(h.paths.CertsDir(), "web.example.com")
	kept := filepath.Join(h.paths.CertsDir(), "kept.example.com")

	// The WEB proxy is deleted.
	st = h.baseState(2)
	st.Proxies = append(st.Proxies, other)
	h.apply(st)
	h.pass()
	if _, err := os.Stat(filepath.Join(dir, "privkey.pem")); err != nil {
		t.Errorf("the key went at once, within the grace: %v", err)
	}
	h.clock.Advance(certRemoveAfter + time.Second)
	// A certificate put just now, for a proxy the panel is about to send.
	freshChain, freshKey, _ := cert(t, "fresh.example.com", h.clock.Now())
	if _, err := mgr.Put(ctx, "fresh.example.com", freshChain, freshKey); err != nil {
		t.Fatal(err)
	}
	h.pass()
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the deleted proxy's certificate and key are still there: %v", err)
	}
	if st := mgr.Status("web.example.com"); st.Valid || st.FullchainSHA256 != "" {
		t.Errorf("status after the removal = %+v", st)
	}
	if _, err := os.Stat(filepath.Join(kept, "privkey.pem")); err != nil {
		t.Errorf("the certificate of a domain another proxy uses went: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.paths.CertsDir(), "fresh.example.com", "privkey.pem")); err != nil {
		t.Errorf("a certificate put just now went: %v", err)
	}
	if len(h.eventsOf("certificate_removed")) != 1 {
		t.Error("no certificate_removed event")
	}
}

// A certificate put for a domain no proxy uses resets that domain's unused
// clock: one put 10 s before the window ends is not removed at the next pass
// after it, only certRemoveAfter after the put.
func TestCertificatePutResetsTheUnusedClock(t *testing.T) {
	w := newWebHarness(t)
	h := w.harness
	ctx := context.Background()
	mgr := h.r.certManager()
	chain, key, _ := cert(t, "late.example.com", h.clock.Now())
	if _, err := mgr.Put(ctx, "late.example.com", chain, key); err != nil {
		t.Fatal(err)
	}
	h.apply(h.baseState(1))
	h.pass() // the domain is first seen unused
	h.clock.Advance(certRemoveAfter - 10*time.Second)
	chain2, key2, _ := cert(t, "late.example.com", h.clock.Now())
	if _, err := mgr.Put(ctx, "late.example.com", chain2, key2); err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(20 * time.Second) // past the first window, within the put's
	h.pass()
	dir := filepath.Join(h.paths.CertsDir(), "late.example.com")
	if _, err := os.Stat(filepath.Join(dir, "privkey.pem")); err != nil {
		t.Fatalf("a certificate put 20 s ago was removed: %v", err)
	}
	h.clock.Advance(certRemoveAfter)
	h.pass()
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the certificate is still there after its own window: %v", err)
	}
}
