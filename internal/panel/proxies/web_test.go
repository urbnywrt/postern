package proxies

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
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/preflight"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
	"github.com/urbnywrt/postern/internal/webrules"
)

// The reference vector of a WEB link (design spec, section 4).
const (
	refSecret  = "0123456789abcdef0123456789abcdef"                                                         // gitleaks:allow (a made-up test value)
	refWebLink = "https://t.me/webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef" // gitleaks:allow (the reference vector)
	// A made-up Cloudflare token. It must never show up in a log.
	testToken = "cf-token-" + "QmFzZTY0LXRva2Vu" // gitleaks:allow (a made-up test value)
)

// fakeDomains is a DomainChecker that refuses the domains in bad and notes
// what it was asked.
type fakeDomains struct {
	bad   map[string]error
	asked []string
	ips   [][]string
}

func (f *fakeDomains) CheckDomain(_ context.Context, domain string, nodeIPs []string) (netip.Addr, error) {
	f.asked = append(f.asked, domain)
	f.ips = append(f.ips, nodeIPs)
	if err := f.bad[domain]; err != nil {
		return netip.Addr{}, err
	}
	return netip.MustParseAddr("203.0.113.10"), nil
}

// testCert makes a self-signed certificate for domain, valid now, as PEM.
func testCert(t *testing.T, domain string) (chain, key []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
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

// createCredential stores a DNS credential with testToken.
func (e *env) createCredential(name string) *panelv1.DnsCredential {
	e.t.Helper()
	resp, err := e.dns.CreateDnsCredential(e.ctx, connect.NewRequest(&panelv1.CreateDnsCredentialRequest{Name: name, Token: testToken}))
	if err != nil {
		e.t.Fatalf("CreateDnsCredential: %v", err)
	}
	return resp.Msg.GetCredential()
}

// build builds the state of a node.
func (e *env) build(nodeID string) *nodev1.NodeState {
	e.t.Helper()
	st, err := e.builder.Build(e.ctx, nodeID, 1)
	if err != nil {
		e.t.Fatalf("Build: %v", err)
	}
	return st
}

func TestCreateHTTPUpstreamListener(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	for _, tc := range []struct {
		name string
		req  *panelv1.CreateListenerRequest
		code connect.Code
	}{
		{"loopback with trusted loopback", &panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", Port: 8089, TrustedCidrs: []string{"127.0.0.1/32"}}, 0},
		{"empty bind is 127.0.0.1, docker bridge trusted", &panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", Port: 8090, TrustedCidrs: []string{"172.17.0.0/16", "127.0.0.1"}}, 0},
		{"no trusted CIDRs", &panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", Port: 8091}, connect.CodeInvalidArgument},
		{"public trusted CIDR", &panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", Port: 8091, TrustedCidrs: []string{"203.0.113.0/24"}}, connect.CodeInvalidArgument},
		{"everything trusted", &panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", Port: 8091, TrustedCidrs: []string{"0.0.0.0/0"}}, connect.CodeInvalidArgument},
		{"unreadable trusted CIDR", &panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", Port: 8091, TrustedCidrs: []string{"127.0.0.1/33"}}, connect.CodeInvalidArgument},
		{"bind on every address", &panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", BindIp: "0.0.0.0", Port: 8091, TrustedCidrs: []string{"127.0.0.1"}}, connect.CodeInvalidArgument},
		{"bind on a public address", &panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", BindIp: "203.0.113.10", Port: 8091, TrustedCidrs: []string{"127.0.0.1"}}, connect.CodeInvalidArgument},
		{"internal loopback port", &panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", Port: 40001, TrustedCidrs: []string{"127.0.0.1"}}, connect.CodeInvalidArgument},
		{"internal port on another loopback address is the node's business", &panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", BindIp: "127.0.0.2", Port: 25000, TrustedCidrs: []string{"127.0.0.1"}}, 0},
		{"trusted CIDRs on a tls listener", &panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443, TrustedCidrs: []string{"127.0.0.1"}}, connect.CodeInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := e.listeners.CreateListener(e.ctx, connect.NewRequest(tc.req))
			if tc.code != 0 {
				wantCode(t, err, tc.code)
				return
			}
			if err != nil {
				t.Fatalf("CreateListener: %v", err)
			}
			l := resp.Msg.GetListener()
			if l.GetKind() != "http-upstream" || (l.GetBindIp() != "127.0.0.1" && l.GetBindIp() != "127.0.0.2") || len(l.GetTrustedCidrs()) == 0 {
				t.Errorf("listener = %v", l)
			}
		})
	}
	// The second listener kept its CIDRs in masked form, the duplicate aside.
	resp, err := e.listeners.ListListeners(e.ctx, connect.NewRequest(&panelv1.ListListenersRequest{NodeId: n.ID}))
	if err != nil {
		t.Fatal(err)
	}
	var second *panelv1.Listener
	for _, l := range resp.Msg.GetListeners() {
		if l.GetPort() == 8090 {
			second = l
		}
	}
	if second == nil || !slices.Equal(second.GetTrustedCidrs(), []string{"172.17.0.0/16", "127.0.0.1/32"}) {
		t.Errorf("trusted CIDRs = %v, want masked prefixes", second.GetTrustedCidrs())
	}
	// Updated as a whole; a bad list changes nothing.
	up, err := e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: second.GetId(), TrustedCidrs: &panelv1.TrustedCidrs{Cidrs: []string{"10.0.0.0/8"}}}))
	if err != nil {
		t.Fatalf("UpdateListener: %v", err)
	}
	if !slices.Equal(up.Msg.GetListener().GetTrustedCidrs(), []string{"10.0.0.0/8"}) {
		t.Errorf("after update: %v", up.Msg.GetListener().GetTrustedCidrs())
	}
	_, err = e.listeners.UpdateListener(e.ctx, connect.NewRequest(&panelv1.UpdateListenerRequest{Id: second.GetId(), TrustedCidrs: &panelv1.TrustedCidrs{}}))
	wantCode(t, err, connect.CodeInvalidArgument)
	// The state of the node carries them, and the node takes it.
	st := e.build(n.ID)
	for _, l := range st.GetListeners() {
		if l.GetId() == second.GetId() && !slices.Equal(l.GetTrustedCidrs(), []string{"10.0.0.0/8"}) {
			t.Errorf("state trusted CIDRs = %v", l.GetTrustedCidrs())
		}
	}
}

func TestCreateWebProxyWithACME(t *testing.T) {
	e := newEnv(t)
	domains := &fakeDomains{bad: map[string]error{"blocked.example.com": errors.New("the A record of blocked.example.com is 192.0.2.1, which is not an address of the node")}}
	e.svc.SetDomainChecker(domains)
	n := e.addNode("n1", "203.0.113.10")
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error { n.PublicIPs = []string{"203.0.113.10"}; return nil }); err != nil {
		t.Fatal(err)
	}
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	cred := e.createCredential("cf")

	web := &panelv1.WebSettingsInput{SecretMode: "dd", DnsCredentialId: cred.GetId(), AcmeEmail: "admin@example.com"}
	for _, tc := range []struct {
		name string
		req  *panelv1.CreateProxyRequest
		code connect.Code
	}{
		{"no domain", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Web: web}, connect.CodeInvalidArgument},
		{"single-label domain", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "localhost", Web: web}, connect.CodeInvalidArgument},
		{"no web settings", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com"}, connect.CodeInvalidArgument},
		{"web settings on a fake-TLS proxy", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "web.example.com", Web: web}, connect.CodeInvalidArgument},
		{"unknown type", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "socks", Domain: "web.example.com", Web: web}, connect.CodeInvalidArgument},
		{"bad base path", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com", Web: &panelv1.WebSettingsInput{BasePath: "/tg", DnsCredentialId: cred.GetId()}}, connect.CodeInvalidArgument},
		{"bad secret mode", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com", Web: &panelv1.WebSettingsInput{SecretMode: "ee", DnsCredentialId: cred.GetId()}}, connect.CodeInvalidArgument},
		{"bad carrier", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com", Web: &panelv1.WebSettingsInput{Carrier: "http", DnsCredentialId: cred.GetId()}}, connect.CodeInvalidArgument},
		{"acme without a credential", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com", Web: &panelv1.WebSettingsInput{}}, connect.CodeInvalidArgument},
		{"acme with a credential that is not there", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com", Web: &panelv1.WebSettingsInput{DnsCredentialId: "01NOSUCHCREDENTIAL"}}, connect.CodeNotFound},
		{"bad email", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com", Web: &panelv1.WebSettingsInput{DnsCredentialId: cred.GetId(), AcmeEmail: "not an email"}}, connect.CodeInvalidArgument},
		{"preflight finding", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "blocked.example.com", Web: web}, connect.CodeFailedPrecondition},
		{"ok", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "proxy.example.com", Secret: refSecret, Web: web}, 0},
		{"domain taken by a web proxy of the panel", &panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "PROXY.example.com", Web: web}, connect.CodeAlreadyExists},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(tc.req))
			if tc.code != 0 {
				wantCode(t, err, tc.code)
			} else if err != nil {
				t.Fatalf("CreateProxy: %v", err)
			}
		})
	}
	// Nothing of a refused proxy was stored.
	list, err := e.db.ListProxies(e.ctx, store.ProxyFilter{})
	if err != nil || len(list) != 1 {
		t.Fatalf("proxies = %v, %v; want the one that was taken", list, err)
	}
	p := list[0]
	if p.Type != store.ProxyTypeWeb || p.Domain != "proxy.example.com" || p.WebSecretMode != "dd" || p.WebCarrier != "https" ||
		p.CertMode != webrules.CertModeACME || p.DNSCredentialID != cred.GetId() || p.ACMEEmail != "admin@example.com" || p.CertChainEnc != nil {
		t.Errorf("stored proxy = %+v", p)
	}
	// The preflight was asked with the addresses of the node, for the domains
	// that got that far.
	if !slices.Contains(domains.asked, "proxy.example.com") || !slices.Contains(domains.asked, "blocked.example.com") {
		t.Errorf("preflight asked %v", domains.asked)
	}
	for _, ips := range domains.ips {
		if !slices.Equal(ips, []string{"203.0.113.10"}) {
			t.Errorf("preflight got node addresses %v", ips)
		}
	}

	// The API shows the settings, never the token.
	got, err := e.proxies.GetProxy(e.ctx, connect.NewRequest(&panelv1.GetProxyRequest{Id: p.ID}))
	if err != nil {
		t.Fatal(err)
	}
	w := got.Msg.GetProxy().GetWeb()
	if got.Msg.GetProxy().GetType() != "web" || w.GetSecretMode() != "dd" || w.GetCarrier() != "https" || w.GetCertMode() != "acme-dns01" ||
		w.GetDnsCredentialId() != cred.GetId() || w.GetAcmeEmail() != "admin@example.com" || w.GetCertSha256() != "" {
		t.Errorf("proxy = %v", got.Msg.GetProxy())
	}

	// The links are the reference ones; dd before the secret, no port.
	links, err := e.proxies.GetProxyLinks(e.ctx, connect.NewRequest(&panelv1.GetProxyLinksRequest{Id: p.ID}))
	if err != nil {
		t.Fatal(err)
	}
	if links.Msg.GetHttps() != refWebLink || links.Msg.GetTg() != strings.Replace(refWebLink, "https://t.me/", "tg://", 1) {
		t.Errorf("links = %q, %q", links.Msg.GetTg(), links.Msg.GetHttps())
	}

	// The state carries the token, opened, and the node takes the state.
	st := e.build(n.ID)
	if len(st.GetProxies()) != 1 {
		t.Fatalf("state proxies = %v", st.GetProxies())
	}
	sw := st.GetProxies()[0].GetWeb()
	if st.GetProxies()[0].GetType() != nodev1.ProxyType_PROXY_TYPE_WEB || sw.GetCertMode() != "acme-dns01" || sw.GetDnsCredential() != testToken ||
		sw.GetSecretMode() != "dd" || sw.GetAcmeEmail() != "admin@example.com" || sw.GetPublicAddr() != "" {
		t.Errorf("state web settings = %v", sw)
	}
	if got := e.pushes.got(); len(got) != 0 {
		t.Errorf("certificates pushed for an ACME proxy: %v", got)
	}

	// A new domain is checked again; a fake-TLS proxy cannot be given web settings.
	_, err = e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.ID, Domain: ptr("blocked.example.com")}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	_, err = e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.ID, Domain: ptr("")}))
	wantCode(t, err, connect.CodeInvalidArgument)
	ft := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})
	_, err = e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: ft.GetId(), Web: web}))
	wantCode(t, err, connect.CodeInvalidArgument)

	if strings.Contains(e.logs.String(), testToken) {
		t.Error("the log holds the dns token")
	}
	e.assertNoSecretsLogged()
}

func ptr[T any](v T) *T { return &v }

func TestCreateWebProxyWithImportedCertificate(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	chain, key := testCert(t, "web.example.com")
	otherChain, otherKey := testCert(t, "other.example.com")

	imported := func(c, k []byte) *panelv1.WebSettingsInput {
		return &panelv1.WebSettingsInput{CertMode: "imported", CertFullchainPem: c, CertKeyPem: k}
	}
	_, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com", Web: imported(nil, nil)}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com", Web: imported(otherChain, otherKey)}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com", Web: imported(chain, otherKey)}))
	wantCode(t, err, connect.CodeInvalidArgument)
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com", Web: imported(chain, key)})

	sum := sha256.Sum256(chain)
	wantSHA := hex.EncodeToString(sum[:])
	if p.GetWeb().GetCertMode() != "imported" || p.GetWeb().GetCertSha256() != wantSHA || p.GetWeb().GetCertNotAfterUnix() == 0 {
		t.Errorf("proxy web = %v", p.GetWeb())
	}
	// Stored sealed for the proxy (Ruling S3-1): the chain and the key open
	// with cert:<id> and nothing else.
	stored := e.storedProxy(p.GetId())
	for _, blob := range [][]byte{stored.CertChainEnc, stored.CertKeyEnc} {
		if _, err := seal.Open(e.key, blob, []byte("cert:"+p.GetId())); err != nil {
			t.Errorf("open with cert:<id>: %v", err)
		}
		if _, err := seal.Open(e.key, blob, []byte("proxy:"+p.GetId())); err == nil {
			t.Error("the certificate opens with the AAD of the secret")
		}
	}
	if string(stored.CertChainEnc) == string(chain) || strings.Contains(string(stored.CertKeyEnc), "PRIVATE KEY") {
		t.Error("the certificate is stored in the clear")
	}
	if got := e.pushes.got(); !slices.Equal(got, []string{n.ID}) {
		t.Errorf("pushes = %v, want the node once", got)
	}
	st := e.build(n.ID)
	if w := st.GetProxies()[0].GetWeb(); w.GetCertMode() != "imported" || w.GetCertSha256() != wantSHA || w.GetDnsCredential() != "" {
		t.Errorf("state web = %v", w)
	}

	// Settings without a certificate keep the stored one; a new pair replaces it and is pushed.
	up, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), Web: &panelv1.WebSettingsInput{CertMode: "imported", SecretMode: "dd"}}))
	if err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}
	if up.Msg.GetProxy().GetWeb().GetCertSha256() != wantSHA || up.Msg.GetProxy().GetWeb().GetSecretMode() != "dd" {
		t.Errorf("after update: %v", up.Msg.GetProxy().GetWeb())
	}
	if got := e.pushes.got(); len(got) != 1 {
		t.Errorf("pushes after a settings change = %v, want no new push", got)
	}
	chain2, key2 := testCert(t, "web.example.com")
	up, err = e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), Web: imported(chain2, key2)}))
	if err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}
	sum2 := sha256.Sum256(chain2)
	if up.Msg.GetProxy().GetWeb().GetCertSha256() != hex.EncodeToString(sum2[:]) {
		t.Errorf("after a new certificate: %v", up.Msg.GetProxy().GetWeb())
	}
	if got := e.pushes.got(); !slices.Equal(got, []string{n.ID, n.ID}) {
		t.Errorf("pushes = %v, want the node twice", got)
	}
	// A new domain the certificate is not for is refused.
	_, err = e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), Domain: ptr("other.example.com")}))
	wantCode(t, err, connect.CodeInvalidArgument)
	// Back to ACME: the certificate goes.
	cred := e.createCredential("cf")
	up, err = e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), Web: &panelv1.WebSettingsInput{DnsCredentialId: cred.GetId()}}))
	if err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}
	if up.Msg.GetProxy().GetWeb().GetCertMode() != "acme-dns01" || up.Msg.GetProxy().GetWeb().GetCertSha256() != "" || e.storedProxy(p.GetId()).CertChainEnc != nil {
		t.Errorf("after going back to ACME: %v", up.Msg.GetProxy().GetWeb())
	}
	if strings.Contains(e.logs.String(), "PRIVATE KEY") {
		t.Error("the log holds a private key")
	}
}

func TestWebProxyOnHTTPUpstreamListener(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	up := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", Port: 8089, TrustedCidrs: []string{"127.0.0.1/32"}})
	tlsL := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})

	_, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: up.GetId(), Type: "web", Domain: "site.example.com", Web: &panelv1.WebSettingsInput{}}))
	wantCode(t, err, connect.CodeInvalidArgument) // base_path required
	_, err = e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: up.GetId()}))
	wantCode(t, err, connect.CodeInvalidArgument) // fake TLS needs tls
	// cert_mode and credentials are ignored here: the site in front has the certificate.
	p := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: up.GetId(), Type: "web", Domain: "site.example.com", Secret: refSecret,
		Web: &panelv1.WebSettingsInput{BasePath: "tg/web", CertMode: "acme-dns01", DnsCredentialId: "01NOSUCHCREDENTIAL"}})
	if p.GetWeb().GetBasePath() != "tg/web" || p.GetWeb().GetCertMode() != "" || p.GetWeb().GetDnsCredentialId() != "" {
		t.Errorf("proxy web = %v", p.GetWeb())
	}
	st := e.build(n.ID)
	if w := st.GetProxies()[0].GetWeb(); w.GetBasePath() != "tg/web" || w.GetCertMode() != "" || w.GetDnsCredential() != "" {
		t.Errorf("state web = %v", w)
	}

	// The link has the base-path form of the secret.
	links, err := e.proxies.GetProxyLinks(e.ctx, connect.NewRequest(&panelv1.GetProxyLinksRequest{Id: p.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://t.me/webproxy?server=site.example.com%2Ftg%2Fweb&secret=cAEjRWeJq83vASNFZ4mrze8"; links.Msg.GetHttps() != want { // gitleaks:allow (a made-up test value)
		t.Errorf("https link = %q, want %q", links.Msg.GetHttps(), want)
	}

	// The snippets for the server in front: the subtree and the path without a slash.
	sn, err := e.proxies.GetWebSnippets(e.ctx, connect.NewRequest(&panelv1.GetWebSnippetsRequest{Id: p.GetId()}))
	if err != nil {
		t.Fatalf("GetWebSnippets: %v", err)
	}
	caddy, nginx := sn.Msg.GetCaddy(), sn.Msg.GetNginx()
	for _, want := range []string{"handle /tg/web/* {", "handle /tg/web {", "reverse_proxy 127.0.0.1:8089 {", "header_up X-Forwarded-For {remote_host}"} {
		if !strings.Contains(caddy, want) {
			t.Errorf("caddy snippet lacks %q:\n%s", want, caddy)
		}
	}
	if strings.Contains(caddy, "handle_path") {
		t.Error("caddy snippet uses handle_path, which strips the prefix")
	}
	for _, want := range []string{"location ^~ /tg/web/ {", "location = /tg/web {", "proxy_pass http://127.0.0.1:8089;",
		"proxy_set_header Host $host;", "proxy_set_header X-Forwarded-For $remote_addr;", "proxy_read_timeout 90s;"} {
		if !strings.Contains(nginx, want) {
			t.Errorf("nginx snippet lacks %q:\n%s", want, nginx)
		}
	}
	if strings.Contains(nginx, "rewrite") || strings.Contains(nginx, "proxy_pass http://127.0.0.1:8089/") {
		t.Error("nginx snippet rewrites the path")
	}

	// Moving to the tls listener needs a certificate mode; no snippets there.
	_, err = e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), ListenerId: ptr(tlsL.GetId())}))
	wantCode(t, err, connect.CodeInvalidArgument)
	cred := e.createCredential("cf")
	if _, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: p.GetId(), ListenerId: ptr(tlsL.GetId()),
		Web: &panelv1.WebSettingsInput{BasePath: "tg/web", DnsCredentialId: cred.GetId()}})); err != nil {
		t.Fatalf("UpdateProxy to the tls listener: %v", err)
	}
	_, err = e.proxies.GetWebSnippets(e.ctx, connect.NewRequest(&panelv1.GetWebSnippetsRequest{Id: p.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	e.assertNoSecretsLogged()
}

func TestDnsCredentialService(t *testing.T) {
	e := newEnv(t)
	_, err := e.anonDNS.ListDnsCredentials(e.ctx, connect.NewRequest(&panelv1.ListDnsCredentialsRequest{}))
	wantCode(t, err, connect.CodeUnauthenticated)
	for _, req := range []*panelv1.CreateDnsCredentialRequest{
		{Name: "", Token: testToken},
		{Name: "cf", Token: " "},
		{Name: "cf", Token: testToken, Provider: "route53"},
		{Name: "cf", Token: strings.Repeat("t", 1025)},
		{Name: "cf", Token: "a\x00b"},
	} {
		_, err := e.dns.CreateDnsCredential(e.ctx, connect.NewRequest(req))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
	cred := e.createCredential("cf")
	if cred.GetProvider() != "cloudflare" || cred.GetName() != "cf" || cred.GetUsedBy() != 0 {
		t.Errorf("credential = %v", cred)
	}
	// Sealed for the credential; the API never returns it.
	stored, err := e.db.DNSCredentialByID(e.ctx, cred.GetId())
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := seal.Open(e.key, stored.TokenEnc, []byte("dnscred:"+cred.GetId())); err != nil || string(plain) != testToken {
		t.Errorf("open the token: %q, %v", plain, err)
	}

	n := e.addNode("n1", "203.0.113.10")
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com", Web: &panelv1.WebSettingsInput{DnsCredentialId: cred.GetId()}})
	gen := e.generation(n.ID)
	calls := e.notes.count()

	list, err := e.dns.ListDnsCredentials(e.ctx, connect.NewRequest(&panelv1.ListDnsCredentialsRequest{}))
	if err != nil || len(list.Msg.GetCredentials()) != 1 || list.Msg.GetCredentials()[0].GetUsedBy() != 1 {
		t.Errorf("list = %v, %v", list.Msg.GetCredentials(), err)
	}
	// In use: not deletable.
	_, err = e.dns.DeleteDnsCredential(e.ctx, connect.NewRequest(&panelv1.DeleteDnsCredentialRequest{Id: cred.GetId()}))
	wantCode(t, err, connect.CodeFailedPrecondition)
	// A new name raises nothing; a new token reaches the node.
	if _, err := e.dns.UpdateDnsCredential(e.ctx, connect.NewRequest(&panelv1.UpdateDnsCredentialRequest{Id: cred.GetId(), Name: ptr("cloudflare")})); err != nil {
		t.Fatal(err)
	}
	if e.generation(n.ID) != gen {
		t.Error("a rename raised the generation")
	}
	newToken := "cf-token-" + "bmV3LXRva2Vu" // gitleaks:allow (a made-up test value)
	if _, err := e.dns.UpdateDnsCredential(e.ctx, connect.NewRequest(&panelv1.UpdateDnsCredentialRequest{Id: cred.GetId(), Token: ptr(newToken)})); err != nil {
		t.Fatal(err)
	}
	if e.generation(n.ID) != gen+1 || e.notes.count() != calls+1 {
		t.Errorf("after a new token: generation %d (was %d), notifications %d (were %d)", e.generation(n.ID), gen, e.notes.count(), calls)
	}
	if w := e.build(n.ID).GetProxies()[0].GetWeb(); w.GetDnsCredential() != newToken {
		t.Errorf("the state has the old token")
	}
	_, err = e.dns.UpdateDnsCredential(e.ctx, connect.NewRequest(&panelv1.UpdateDnsCredentialRequest{Id: cred.GetId(), Token: ptr("")}))
	wantCode(t, err, connect.CodeInvalidArgument)
	_, err = e.dns.UpdateDnsCredential(e.ctx, connect.NewRequest(&panelv1.UpdateDnsCredentialRequest{Id: "01NOSUCHCREDENTIAL", Name: ptr("x")}))
	wantCode(t, err, connect.CodeNotFound)

	logs := e.logs.String()
	for _, secret := range []string{testToken, newToken} {
		if strings.Contains(logs, secret) {
			t.Error("the log holds a dns token")
		}
	}
	if got := auditLog(t, e); !slices.Contains(got, "dns_credential.update dns_credential:"+cred.GetId()+" "+e.adminID) {
		t.Errorf("audit = %v", got)
	}
}

// fakeNodeClient is a NodeServiceClient with PutCertificate only.
type fakeNodeClient struct {
	nodev1connect.NodeServiceClient
	puts []*nodev1.PutCertificateRequest
	fail bool
}

func (f *fakeNodeClient) PutCertificate(_ context.Context, req *connect.Request[nodev1.PutCertificateRequest]) (*connect.Response[nodev1.PutCertificateResponse], error) {
	f.puts = append(f.puts, req.Msg)
	if f.fail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("down"))
	}
	sum := sha256.Sum256(req.Msg.GetFullchainPem())
	return connect.NewResponse(&nodev1.PutCertificateResponse{Sha256: hex.EncodeToString(sum[:]), Stored: true}), nil
}

type fakeClients struct{ client *fakeNodeClient }

func (f fakeClients) Client(string) (nodev1connect.NodeServiceClient, error) {
	if f.client == nil {
		return nil, errors.New("not connected")
	}
	return f.client, nil
}

func TestCertSyncPutsEveryImportedCertificate(t *testing.T) {
	e := newEnv(t)
	n := e.addNode("n1", "203.0.113.10")
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	cred := e.createCredential("cf")
	chain, key := testCert(t, "a.example.com")
	e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "A.example.com", Web: &panelv1.WebSettingsInput{CertMode: "imported", CertFullchainPem: chain, CertKeyPem: key}})
	e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "b.example.com", Web: &panelv1.WebSettingsInput{DnsCredentialId: cred.GetId()}})
	e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId()})

	client := &fakeNodeClient{}
	sync := NewCertSync(e.db, e.key, fakeClients{client}, e.log)
	sync.OnConnected(e.ctx, n.ID, client)
	if len(client.puts) != 1 {
		t.Fatalf("PutCertificate calls = %d, want 1 (the imported certificate only)", len(client.puts))
	}
	put := client.puts[0]
	if put.GetDomain() != "a.example.com" || string(put.GetFullchainPem()) != string(chain) || string(put.GetKeyPem()) != string(key) {
		t.Errorf("put = domain %q, chain ok %v, key ok %v", put.GetDomain(), string(put.GetFullchainPem()) == string(chain), string(put.GetKeyPem()) == string(key))
	}
	// A node that is not connected is left for its connection; one that
	// fails is logged without the certificate.
	NewCertSync(e.db, e.key, fakeClients{}, e.log).PushCertificates(n.ID)
	failing := &fakeNodeClient{fail: true}
	NewCertSync(e.db, e.key, fakeClients{failing}, e.log).OnConnected(e.ctx, n.ID, failing)
	if len(failing.puts) != 1 {
		t.Errorf("puts to a failing node = %d", len(failing.puts))
	}
	if logs := e.logs.String(); strings.Contains(logs, "PRIVATE KEY") || strings.Contains(logs, "BEGIN CERTIFICATE") {
		t.Error("the log holds the certificate")
	}
}

func TestCheckCertificateIsThePreflightOne(t *testing.T) {
	// The service judges certificates by preflight.CheckCertificate: the
	// same digest the node computes (SHA-256 of the chain as given).
	chain, key := testCert(t, "web.example.com")
	c, err := preflight.CheckCertificate(chain, key, "web.example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(chain)
	if c.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 = %s", c.SHA256)
	}
}

// blockingResolver answers a lookup only when released.
type blockingResolver struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingResolver) LookupIP(ctx context.Context, _ string) ([]netip.Addr, error) {
	close(b.started)
	select {
	case <-b.release:
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// The DoH lookup of a WEB domain runs outside the lock of the node data: while
// it is slow, the mutations of other nodes and the state builder go on.
func TestWebPreflightDoesNotHoldTheNodeDataLock(t *testing.T) {
	e := newEnv(t)
	resolver := &blockingResolver{started: make(chan struct{}), release: make(chan struct{})}
	e.svc.SetDomainChecker(preflight.New(resolver, nil))
	n1 := e.addNode("n1", "203.0.113.10")
	n2 := e.addNode("n2", "203.0.113.11")
	l1 := e.createListener(&panelv1.CreateListenerRequest{NodeId: n1.ID, Port: 443})
	cred := e.createCredential("cf")

	done := make(chan error, 1)
	go func() {
		_, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{NodeId: n1.ID, ListenerId: l1.GetId(), Type: "web", Domain: "web.example.com",
			Web: &panelv1.WebSettingsInput{DnsCredentialId: cred.GetId()}}))
		done <- err
	}()
	select {
	case <-resolver.started:
	case <-time.After(waitTimeout):
		t.Fatal("the lookup did not start")
	}
	// Another node changes and builds its state while the lookup hangs.
	other := make(chan error, 2)
	go func() {
		_, err := e.listeners.CreateListener(e.ctx, connect.NewRequest(&panelv1.CreateListenerRequest{NodeId: n2.ID, Port: 443}))
		other <- err
	}()
	go func() {
		_, err := e.builder.Build(e.ctx, n2.ID, 1)
		other <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-other:
			if err != nil {
				t.Errorf("while the lookup hangs: %v", err)
			}
		case <-time.After(waitTimeout):
			t.Fatal("a mutation or a build of another node waited for the lookup")
		}
	}
	select {
	case err := <-done:
		t.Fatalf("CreateProxy returned before the lookup: %v", err)
	default:
	}
	close(resolver.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CreateProxy: %v", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("CreateProxy did not finish")
	}
}

// testCertUntil is testCert with the given end of validity.
func testCertUntil(t *testing.T, domain string, notAfter time.Time) (chain, key []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
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

// A WEB proxy is taken with warnings, never refused for them: a node that
// has not reported its public addresses (the preflight could not compare the
// domain with them), and an imported certificate that expires within 21 days
// (Postern does not renew it: the warning names the way to ACME DNS-01).
func TestWebProxyWarnings(t *testing.T) {
	e := newEnv(t)
	domains := &fakeDomains{}
	e.svc.SetDomainChecker(domains)
	n := e.addNode("n1", "203.0.113.10")
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	cred := e.createCredential("cf")
	acme := &panelv1.WebSettingsInput{DnsCredentialId: cred.GetId()}
	has := func(warnings []string, part string) bool {
		return slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, part) })
	}

	created, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "a.example.com", Web: acme,
	}))
	if err != nil {
		t.Fatalf("CreateProxy on a node without public addresses: %v", err)
	}
	if w := created.Msg.GetWarnings(); len(w) != 1 || !has(w, "public IP addresses") {
		t.Errorf("warnings %q, want one about the public addresses", w)
	}
	updated, err := e.proxies.UpdateProxy(e.ctx, connect.NewRequest(&panelv1.UpdateProxyRequest{Id: created.Msg.GetProxy().GetId(), Domain: ptr("b.example.com")}))
	if err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}
	if w := updated.Msg.GetWarnings(); len(w) != 1 || !has(w, "public IP addresses") {
		t.Errorf("update warnings %q, want one about the public addresses", w)
	}

	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error { n.PublicIPs = []string{"203.0.113.10"}; return nil }); err != nil {
		t.Fatal(err)
	}
	soonChain, soonKey := testCertUntil(t, "c.example.com", time.Now().Add(10*24*time.Hour))
	soon, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "c.example.com",
		Web: &panelv1.WebSettingsInput{CertMode: "imported", CertFullchainPem: soonChain, CertKeyPem: soonKey},
	}))
	if err != nil {
		t.Fatalf("CreateProxy with a certificate that expires soon: %v", err)
	}
	if w := soon.Msg.GetWarnings(); len(w) != 1 || !has(w, "expires") || !has(w, "DNS credential") || !has(w, "acme-dns01") {
		t.Errorf("warnings %q, want one that the certificate expires, naming a DNS credential and acme-dns01", w)
	}
	laterChain, laterKey := testCertUntil(t, "d.example.com", time.Now().Add(30*24*time.Hour))
	later, err := e.proxies.CreateProxy(e.ctx, connect.NewRequest(&panelv1.CreateProxyRequest{
		NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "d.example.com",
		Web: &panelv1.WebSettingsInput{CertMode: "imported", CertFullchainPem: laterChain, CertKeyPem: laterKey},
	}))
	if err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}
	if w := later.Msg.GetWarnings(); len(w) != 0 {
		t.Errorf("warnings %q for a node with addresses and a certificate of 30 days, want none", w)
	}
}
