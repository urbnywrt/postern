package nodes

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/pki"
)

// joiner is a node that joins: its own key and a request for it.
type joiner struct {
	key *ecdsa.PrivateKey
	csr []byte
}

func newJoiner(t *testing.T) joiner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "anything"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return joiner{key: key, csr: csr}
}

func (j joiner) req(token string) *connect.Request[panelv1.JoinRequest] {
	return connect.NewRequest(&panelv1.JoinRequest{Token: token, Csr: j.csr, Arch: "amd64", Version: "1.2.3"})
}

// keyPEM is the key of the joiner as a node keeps it.
func (j joiner) keyPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(j.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// joinPanel is a test panel whose node service sees every call come from an
// address that the test sets, and takes documentation addresses for public
// ones, so that the tests need no real address.
type joinPanel struct {
	*testPanel
	notes *notifyRecorder
	from  netip.Addr // the address of the caller; invalid: unknown
}

func newJoinPanel(t *testing.T) *joinPanel {
	t.Helper()
	p := &joinPanel{testPanel: newTestPanel(t), notes: &notifyRecorder{}, from: netip.MustParseAddr("192.0.2.10")}
	p.svc = NewService(p.db, p.key, p.ca, p.notes, p.log)
	p.svc.callerIP = func(context.Context) (netip.Addr, bool) { return p.from, p.from.IsValid() }
	p.svc.joinHostOK = func(a netip.Addr) bool { return publicUnicastExcept(a, nonPublicPrefixes[:1]) } // CGNAT only
	return p
}

// newNode creates a node with this management host ("" for none).
func (p *joinPanel) newNode(host string) *store.Node {
	p.t.Helper()
	n, err := p.svc.createNode(context.Background(), &panelv1.CreateNodeRequest{Name: "edge", MgmtHost: host, MgmtPort: 61443})
	if err != nil {
		p.t.Fatalf("createNode: %v", err)
	}
	return n
}

func (p *joinPanel) mint(nodeID string) string {
	p.t.Helper()
	token, _, err := p.svc.MintJoinToken(context.Background(), nodeID)
	if err != nil {
		p.t.Fatalf("MintJoinToken: %v", err)
	}
	return token
}

// joinAudit returns the node.join entries of a node, oldest first.
func (p *joinPanel) joinAudit(action string) []*store.AuditEntry {
	p.t.Helper()
	list, err := p.db.ListAudit(context.Background(), store.AuditFilter{ActionPrefix: action, Limit: 100})
	if err != nil {
		p.t.Fatal(err)
	}
	slices.Reverse(list)
	return list
}

func mustCertOf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("no PEM in %q", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestMintJoinToken(t *testing.T) {
	ctx := context.Background()
	p := newJoinPanel(t)
	n := p.newNode("")

	first, expires, err := p.svc.MintJoinToken(ctx, n.ID)
	if err != nil {
		t.Fatalf("MintJoinToken: %v", err)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(first); len(first) != 43 || err != nil || len(raw) != 32 {
		t.Errorf("token %q is not 32 bytes in unpadded base64url", first)
	}
	if d := time.Until(expires) - 24*time.Hour; d > time.Minute || d < -time.Minute {
		t.Errorf("expires in %v, want 24h", time.Until(expires))
	}
	sum := sha256.Sum256([]byte(first))
	stored, err := p.db.JoinTokenOf(ctx, n.ID)
	if err != nil || !bytes.Equal(stored.TokenHash, sum[:]) || stored.Used() {
		t.Fatalf("stored token = %+v, %v; want the hash of the token, unused", stored, err)
	}

	second := p.mint(n.ID)
	if second == first {
		t.Fatal("the same token twice")
	}
	_, err = p.svc.Join(ctx, newJoiner(t).req(first))
	wantCode(t, err, connect.CodeUnauthenticated)
	if got := len(p.joinAudit("node.join_token")); got != 2 {
		t.Errorf("%d node.join_token entries, want 2", got)
	}
	if logs := p.logs.String(); strings.Contains(logs, first) || strings.Contains(logs, second) {
		t.Error("a token is in the log")
	}

	if _, _, err := p.svc.MintJoinToken(ctx, "01NOSUCHNODE0000000000000"); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("token for a missing node = %v, want NotFound", err)
	}
}

func TestJoin(t *testing.T) {
	ctx := context.Background()
	p := newJoinPanel(t)
	n := p.newNode("")
	oldFingerprint := n.CertFingerprint
	token := p.mint(n.ID)
	j := newJoiner(t)

	resp, err := p.svc.Join(ctx, j.req(token))
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	msg := resp.Msg
	if msg.GetNodeId() != n.ID || msg.GetMgmtPort() != 61443 || !bytes.Equal(msg.GetCaPem(), p.ca.CertPEM) {
		t.Errorf("answer = %s %d", msg.GetNodeId(), msg.GetMgmtPort())
	}
	cert := mustCertOf(t, msg.GetCertPem())
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&j.key.PublicKey) {
		t.Error("the certificate is not for the key of the node")
	}
	if cert.Subject.CommonName != nodeCommonName(n.ID) || !slices.Equal(cert.DNSNames, []string{nodeDNSName(n.ID)}) {
		t.Errorf("certificate names %q %v", cert.Subject.CommonName, cert.DNSNames)
	}

	stored := p.node(n.ID)
	fp, _ := pki.Fingerprint(msg.GetCertPem())
	if stored.KeyEnc != nil || stored.CertPEM != string(msg.GetCertPem()) || stored.CertFingerprint != fp || fp == oldFingerprint {
		t.Errorf("stored node: key %v, fingerprint %q (answer %q, old %q)", stored.KeyEnc, stored.CertFingerprint, fp, oldFingerprint)
	}
	if stored.MgmtHost != "192.0.2.10" || stored.LinkHost != "192.0.2.10" {
		t.Errorf("mgmt_host %q link_host %q, want the address of the join", stored.MgmtHost, stored.LinkHost)
	}
	if tok, _ := p.db.JoinTokenOf(ctx, n.ID); !tok.Used() {
		t.Error("the token is not used")
	}
	entries := p.joinAudit("node.join")
	entries = slices.DeleteFunc(entries, func(e *store.AuditEntry) bool { return e.Action != "node.join" })
	if len(entries) != 1 {
		t.Fatalf("%d node.join entries, want 1", len(entries))
	}
	if e := entries[0]; e.Target != "node:"+n.ID || e.Details["source"] != "192.0.2.10" ||
		e.Details["arch"] != "amd64" || e.Details["version"] != "1.2.3" {
		t.Errorf("audit entry = %+v", e)
	}
	if got := p.notes.got(); !slices.Contains(got, n.ID) {
		t.Errorf("notified %v, want the node", got)
	}

	// The node lost the answer and asks again: the same certificate, no new entry.
	again, err := p.svc.Join(ctx, j.req(token))
	if err != nil {
		t.Fatalf("Join again: %v", err)
	}
	if !bytes.Equal(again.Msg.GetCertPem(), msg.GetCertPem()) {
		t.Error("a repeated join got another certificate")
	}
	if got := len(slices.DeleteFunc(p.joinAudit("node.join"), func(e *store.AuditEntry) bool { return e.Action != "node.join" })); got != 1 {
		t.Errorf("%d node.join entries after a repeat, want 1", got)
	}

	// Another key with the used token is refused, and changes nothing.
	_, err = p.svc.Join(ctx, newJoiner(t).req(token))
	wantCode(t, err, connect.CodeUnauthenticated)
	if !strings.Contains(err.Error(), "used already") {
		t.Errorf("error = %v", err)
	}
	if p.node(n.ID).CertFingerprint != fp {
		t.Error("the certificate changed")
	}

	// The bundle cannot be downloaded: the panel has no key.
	if _, err := p.svc.bundle(ctx, n.ID); !errors.Is(err, ErrJoinedNode) || !errors.Is(err, ErrNoBundle) {
		t.Errorf("bundle of a joined node = %v, want ErrJoinedNode", err)
	}

	// Once the node's certificate is replaced (a new kit, say), the retry no
	// longer returns it.
	p.modify(n.ID, func(s *store.Node) { s.CertPEM = n.CertPEM })
	_, err = p.svc.Join(ctx, j.req(token))
	wantCode(t, err, connect.CodeUnauthenticated)

	// Nor does a key that did not use the token, even when the node has a
	// certificate for it.
	other := newJoiner(t)
	otherPEM, err := p.ca.SignServerCSR(other.csr, nodeCommonName(n.ID), []string{nodeDNSName(n.ID)})
	if err != nil {
		t.Fatal(err)
	}
	p.modify(n.ID, func(s *store.Node) { s.CertPEM = string(otherPEM) })
	_, err = p.svc.Join(ctx, other.req(token))
	wantCode(t, err, connect.CodeUnauthenticated)
}

func TestJoinRefuses(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		spoil func(p *joinPanel, nodeID string, r *panelv1.JoinRequest)
		code  connect.Code
		text  string
	}{
		{"unknown token", func(p *joinPanel, _ string, r *panelv1.JoinRequest) {
			r.Token = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		}, connect.CodeUnauthenticated, "not valid"},
		{"malformed token", func(_ *joinPanel, _ string, r *panelv1.JoinRequest) { r.Token = "short" }, connect.CodeUnauthenticated, "not valid"},
		{"expired token", func(p *joinPanel, id string, r *panelv1.JoinRequest) {
			tok, _ := p.db.JoinTokenOf(ctx, id)
			tok.ExpiresAt = time.Now().Add(-time.Second)
			if err := p.db.PutJoinToken(ctx, tok); err != nil {
				p.t.Fatal(err)
			}
		}, connect.CodeUnauthenticated, "has expired: get a new install command"},
		{"deleted node", func(p *joinPanel, id string, _ *panelv1.JoinRequest) {
			if err := p.db.DeleteNode(ctx, id); err != nil {
				p.t.Fatal(err)
			}
		}, connect.CodeUnauthenticated, "not valid"},
		{"garbage csr", func(_ *joinPanel, _ string, r *panelv1.JoinRequest) { r.Csr = []byte("garbage") }, connect.CodeInvalidArgument, "csr"},
		{"oversize csr", func(_ *joinPanel, _ string, r *panelv1.JoinRequest) { r.Csr = make([]byte, 8<<10+1) }, connect.CodeInvalidArgument, "csr"},
		{"bad arch", func(_ *joinPanel, _ string, r *panelv1.JoinRequest) { r.Arch = "386" }, connect.CodeInvalidArgument, "arch"},
		{"empty version", func(_ *joinPanel, _ string, r *panelv1.JoinRequest) { r.Version = "" }, connect.CodeInvalidArgument, "version"},
		{"long version", func(_ *joinPanel, _ string, r *panelv1.JoinRequest) { r.Version = strings.Repeat("1", 65) }, connect.CodeInvalidArgument, "version"},
		{"version with a space", func(_ *joinPanel, _ string, r *panelv1.JoinRequest) { r.Version = "1 2" }, connect.CodeInvalidArgument, "version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newJoinPanel(t)
			n := p.newNode("")
			req := newJoiner(t).req(p.mint(n.ID))
			tt.spoil(p, n.ID, req.Msg)
			_, err := p.svc.Join(ctx, req)
			wantCode(t, err, tt.code)
			if !strings.Contains(err.Error(), tt.text) {
				t.Errorf("error = %v, want it to say %q", err, tt.text)
			}
			if got, err := p.db.NodeByID(ctx, n.ID); err == nil && (got.CertFingerprint != n.CertFingerprint || got.MgmtHost != "") {
				t.Error("a refused join changed the node")
			}
			if tok, err := p.db.JoinTokenOf(ctx, n.ID); err == nil && tok.Used() {
				t.Error("a refused join used the token")
			}
		})
	}
}

// Failed joins lock the address out after five, as failed sign-ins do, and
// nobody else.
func TestJoinLimitsFailuresPerAddress(t *testing.T) {
	ctx := context.Background()
	p := newJoinPanel(t)
	n := p.newNode("")
	token := p.mint(n.ID)
	bad := newJoiner(t).req(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))

	p.from = netip.MustParseAddr("2001:db8:1:1::5")
	for i := range 5 {
		_, err := p.svc.Join(ctx, bad)
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("attempt %d: %v, want Unauthenticated", i+1, err)
		}
	}
	// The address is locked, even with a good token; so is its /64.
	for _, from := range []string{"2001:db8:1:1::5", "2001:db8:1:1::6"} {
		p.from = netip.MustParseAddr(from)
		_, err := p.svc.Join(ctx, newJoiner(t).req(token))
		wantCode(t, err, connect.CodeResourceExhausted)
		var ce *connect.Error
		if !errors.As(err, &ce) || ce.Meta().Get("Retry-After") == "" {
			t.Errorf("%s: no Retry-After in %v", from, err)
		}
	}
	// Another address is not.
	p.from = netip.MustParseAddr("192.0.2.20")
	if _, err := p.svc.Join(ctx, newJoiner(t).req(token)); err != nil {
		t.Errorf("another address: %v", err)
	}
}

// Only a token that is not valid counts against the address: an expired or
// used token, or a bad request with a good one, can only come from a holder of
// the token, and a node that restarts with one must not lock its address out.
func TestJoinCountsOnlyInvalidTokens(t *testing.T) {
	ctx := context.Background()
	p := newJoinPanel(t)
	expired := p.newNode("")
	expiredToken := p.mint(expired.ID)
	tok, _ := p.db.JoinTokenOf(ctx, expired.ID)
	tok.ExpiresAt = time.Now().Add(-time.Second)
	if err := p.db.PutJoinToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	used := p.newNode("")
	usedToken := p.mint(used.ID)
	p.from = netip.MustParseAddr("192.0.2.50")
	if _, err := p.svc.Join(ctx, newJoiner(t).req(usedToken)); err != nil {
		t.Fatalf("first join: %v", err)
	}

	freshToken := p.mint(p.newNode("").ID)

	p.from = netip.MustParseAddr("192.0.2.30")
	for i := range 10 {
		_, err := p.svc.Join(ctx, newJoiner(t).req(expiredToken))
		if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expired attempt %d: %v, want expired", i+1, err)
		}
		_, err = p.svc.Join(ctx, newJoiner(t).req(usedToken))
		if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "used already") {
			t.Fatalf("used attempt %d: %v, want used already", i+1, err)
		}
		badArch := newJoiner(t).req(freshToken)
		badArch.Msg.Arch = "386"
		if _, err := p.svc.Join(ctx, badArch); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("bad arch attempt %d: %v, want InvalidArgument", i+1, err)
		}
		badCSR := newJoiner(t).req(freshToken)
		badCSR.Msg.Csr = []byte("garbage")
		if _, err := p.svc.Join(ctx, badCSR); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("bad csr attempt %d: %v, want InvalidArgument", i+1, err)
		}
	}
	if _, err := p.svc.Join(ctx, newJoiner(t).req(freshToken)); err != nil {
		t.Fatalf("a fresh token after the refusals: %v", err)
	}
}

func TestJoinFillsTheManagementHost(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name, host, from, want string
	}{
		{"public IPv4", "", "192.0.2.10", "192.0.2.10"},
		{"public IPv6", "", "2001:db8::10", "2001:db8::10"},
		{"mapped IPv4", "", "::ffff:192.0.2.10", "192.0.2.10"},
		{"host already set", "edge.example.com", "192.0.2.10", "edge.example.com"},
		{"private", "", "10.0.0.5", ""},
		{"loopback", "", "127.0.0.1", ""},
		{"link-local", "", "fe80::1", ""},
		{"CGNAT", "", "100.64.0.1", ""},
		{"unspecified", "", "0.0.0.0", ""},
		{"unknown address", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newJoinPanel(t)
			p.from = netip.Addr{}
			if tt.from != "" {
				p.from = netip.MustParseAddr(tt.from)
			}
			n := p.newNode(tt.host)
			if _, err := p.svc.Join(ctx, newJoiner(t).req(p.mint(n.ID))); err != nil {
				t.Fatalf("Join: %v", err)
			}
			if got := p.node(n.ID).MgmtHost; got != tt.want {
				t.Errorf("mgmt_host = %q, want %q", got, tt.want)
			}
			wantSource := tt.from
			if wantSource == "" {
				wantSource = "unknown"
			} else {
				wantSource = netip.MustParseAddr(tt.from).Unmap().String()
			}
			for _, e := range p.joinAudit("node.join") {
				if e.Action == "node.join" && e.Details["source"] != wantSource {
					t.Errorf("source = %q, want %q", e.Details["source"], wantSource)
				}
			}
		})
	}
}

// cfRanges are Cloudflare ranges for a test: one documentation network.
type cfRanges []netip.Prefix

func (r cfRanges) Contains(a netip.Addr) bool {
	return slices.ContainsFunc(r, func(p netip.Prefix) bool { return p.Contains(a.Unmap()) })
}

// A join that comes through Cloudflare (the panel behind its proxy) comes from
// an address of Cloudflare, not of the node: it is not taken as the host.
func TestJoinDoesNotTakeACloudflareAddress(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct{ from, want string }{
		{"198.51.100.7", ""},
		{"::ffff:198.51.100.7", ""},
		{"192.0.2.10", "192.0.2.10"},
	} {
		p := newJoinPanel(t)
		WithCloudflareRanges(cfRanges{netip.MustParsePrefix("198.51.100.0/24")})(p.svc)
		p.from = netip.MustParseAddr(tt.from)
		n := p.newNode("")
		if _, err := p.svc.Join(ctx, newJoiner(t).req(p.mint(n.ID))); err != nil {
			t.Fatalf("%s: Join: %v", tt.from, err)
		}
		if got := p.node(n.ID).MgmtHost; got != tt.want {
			t.Errorf("%s: mgmt_host = %q, want %q", tt.from, got, tt.want)
		}
	}
}

// What a join takes as a public address in production: never a documentation
// address, so the tests above replace this rule; here it is checked against
// the same rule without the documentation ranges.
func TestPublicUnicast(t *testing.T) {
	for _, s := range []string{
		"10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "::1", "169.254.1.1", "fe80::1",
		"100.64.0.1", "100.127.255.255", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "fc00::1", "255.255.255.255",
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1", "3fff::1", "::ffff:192.0.2.1", "::ffff:10.0.0.1",
	} {
		if publicUnicast(netip.MustParseAddr(s)) {
			t.Errorf("publicUnicast(%s) = true", s)
		}
	}
	noDocs := nonPublicPrefixes[:1]
	for _, s := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1", "::ffff:203.0.113.1"} {
		if !publicUnicastExcept(netip.MustParseAddr(s), noDocs) {
			t.Errorf("without the documentation ranges, %s is not public", s)
		}
	}
	if publicUnicastExcept(netip.MustParseAddr("100.64.0.1"), noDocs) {
		t.Error("CGNAT is public")
	}
}

// A node made for a join, without a management host, waits in provisioning:
// no error, no event, no dial. Once it has joined and has an address, the
// manager connects with the pin of the joined certificate.
func TestManagerWaitsForTheManagementHostOfAJoin(t *testing.T) {
	ctx := context.Background()
	p := newJoinPanel(t)
	p.from = netip.MustParseAddr("10.0.0.5") // private: the join does not fill the host
	f := newFakeNode(t, nil)
	n := p.newNode("")

	m := p.newManager()
	p.svc.notifier = m
	m.Start(ctx)
	time.Sleep(5 * testTiming.maxBackoff)
	if got := p.node(n.ID).Status; got != store.NodeStatusProvisioning {
		t.Errorf("status = %q, want provisioning", got)
	}
	if kinds := p.eventKinds(n.ID); len(kinds) != 0 {
		t.Errorf("events = %v, want none", kinds)
	}

	j := newJoiner(t)
	resp, err := p.svc.Join(ctx, j.req(p.mint(n.ID)))
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	f.serve(&pki.Bundle{NodeID: n.ID, MgmtPort: int(f.port()), CAPEM: p.ca.CertPEM, CertPEM: resp.Msg.GetCertPem(), KeyPEM: j.keyPEM(t)})
	time.Sleep(3 * testTiming.maxBackoff)
	if d := f.dials.Load(); d != 0 {
		t.Errorf("the manager dialed a node without a host %d times", d)
	}

	p.modify(n.ID, func(s *store.Node) { s.MgmtHost, s.MgmtPort = "127.0.0.1", f.port() })
	m.Notify(n.ID)
	p.waitStatus(n.ID, store.NodeStatusOnline)
	if kinds := p.eventKinds(n.ID); slices.Contains(kinds, "node.error") {
		t.Errorf("events = %v", kinds)
	}
}

// Join is public behind the auth middleware, and the address it records is
// the one the middleware resolved.
func TestJoinThroughTheMiddleware(t *testing.T) {
	ctx := context.Background()
	a := newAPI(t)
	a.svc.joinHostOK = func(netip.Addr) bool { return true }
	created := a.create(&panelv1.CreateNodeRequest{Name: "edge"})
	id := created.GetNode().GetId()
	token, _, err := a.svc.MintJoinToken(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	client := panelv1connect.NewJoinServiceClient(&http.Client{Timeout: waitTimeout}, a.srv.URL)
	if _, err := client.Join(ctx, newJoiner(t).req(token)); err != nil {
		t.Fatalf("Join without a session: %v", err)
	}
	if got := a.node(id).MgmtHost; got != "127.0.0.1" {
		t.Errorf("mgmt_host = %q, want the address of the test client", got)
	}
	list, err := a.db.ListAudit(ctx, store.AuditFilter{ActionPrefix: "node.join", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, e := range list {
		if e.Action == "node.join" {
			sources = append(sources, e.Details["source"])
		}
	}
	if !slices.Equal(sources, []string{"127.0.0.1"}) {
		t.Errorf("sources = %v", sources)
	}

	// The bundle of the joined node is a 409 that says why.
	resp, body := a.get(a.web, BundleURL(id))
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "joined with a key of its own") {
		t.Errorf("bundle: %d %q", resp.StatusCode, body)
	}
}

// MintJoinTokenBy names the admin that it is given in the audit row, with no
// admin in the context: the job of an SSH install mints for its admin.
func TestMintJoinTokenBy(t *testing.T) {
	p := newJoinPanel(t)
	n := p.newNode("")
	const admin = "01ADMINOFTHEJOB00000000000"
	if _, _, err := p.svc.MintJoinTokenBy(context.Background(), n.ID, admin); err != nil {
		t.Fatalf("MintJoinTokenBy: %v", err)
	}
	if got := p.joinAudit("node.join_token"); len(got) != 1 || got[0].AdminID != admin || got[0].Target != "node:"+n.ID {
		t.Errorf("audit = %+v, want one node.join_token row by %s", got, admin)
	}
}
