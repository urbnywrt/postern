package proxies

import (
	"strings"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
)

// ReissueCert raises the nonce of an ACME proxy, which the state carries as
// WebSettings.reissue_nonce; it refuses what the node does not issue.
func TestReissueCert(t *testing.T) {
	e := newEnv(t)
	e.svc.SetDomainChecker(&fakeDomains{})
	n := e.addNode("n1", "203.0.113.10")
	l := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Port: 443})
	up := e.createListener(&panelv1.CreateListenerRequest{NodeId: n.ID, Kind: "http-upstream", Port: 8089, TrustedCidrs: []string{"127.0.0.1/32"}})
	cred := e.createCredential("cf")
	acme := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "web.example.com",
		Web: &panelv1.WebSettingsInput{DnsCredentialId: cred.GetId()}})
	chain, key := testCert(t, "imported.example.com")
	imported := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Type: "web", Domain: "imported.example.com",
		Web: &panelv1.WebSettingsInput{CertMode: "imported", CertFullchainPem: chain, CertKeyPem: key}})
	behind := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: up.GetId(), Type: "web", Domain: "site.example.com",
		Web: &panelv1.WebSettingsInput{BasePath: "tg"}})
	fake := e.createProxy(&panelv1.CreateProxyRequest{NodeId: n.ID, ListenerId: l.GetId(), Domain: "cdn.example.com"})

	gen := e.generation(n.ID)
	got, err := e.svc.ReissueCert(e.ctx, acme.GetId())
	if err != nil {
		t.Fatalf("ReissueCert: %v", err)
	}
	if got != gen+1 || e.storedProxy(acme.GetId()).CertReissueNonce != 1 {
		t.Fatalf("generation %d (was %d), nonce %d", got, gen, e.storedProxy(acme.GetId()).CertReissueNonce)
	}
	st := e.build(n.ID)
	for _, p := range st.GetProxies() {
		want := uint64(0)
		if p.GetId() == acme.GetId() {
			want = 1
		}
		if p.GetWeb().GetReissueNonce() != want {
			t.Errorf("proxy %s: reissue_nonce %d, want %d", p.GetDomain(), p.GetWeb().GetReissueNonce(), want)
		}
	}

	for name, c := range map[string]struct{ id, want string }{
		"imported":            {imported.GetId(), "imported"},
		"behind a web server": {behind.GetId(), "web server in front"},
		"fake TLS":            {fake.GetId(), "not a WEB proxy"},
	} {
		gen := e.generation(n.ID)
		_, err := e.svc.ReissueCert(e.ctx, c.id)
		if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want failed_precondition with %q", name, err, c.want)
		}
		if e.generation(n.ID) != gen || e.storedProxy(c.id).CertReissueNonce != 0 {
			t.Errorf("%s: changed the data", name)
		}
	}

	_, err = e.svc.ReissueCert(e.ctx, "01K6Y00000000000000000000Z")
	wantCode(t, err, connect.CodeNotFound)
}
