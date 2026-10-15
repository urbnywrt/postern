package diagnostics

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/links"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/seal"
)

// sealedProxy stores a proxy with a real sealed secret, sealed as
// proxies.Service seals it (its 32 hex digits), and returns the raw secret.
func sealedProxy(t *testing.T, e *env, key seal.Key, l *store.Listener) (*store.Proxy, []byte) {
	t.Helper()
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	p := e.proxy(l, func(p *store.Proxy) {
		enc, err := seal.Seal(key, []byte(hex.EncodeToString(secret)), proxies.SecretAAD(p.ID))
		if err != nil {
			t.Fatal(err)
		}
		p.SecretEnc = enc
	})
	return p, secret
}

func newKey(t *testing.T) seal.Key {
	t.Helper()
	var k seal.Key
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

// secretForms are forms of a proxy secret that text may quote: plain hex,
// the ee (fake-TLS) and dd forms, and base64.
func secretForms(secret []byte, domain string) []string {
	h := hex.EncodeToString(secret)
	return []string{h, links.FakeTLSSecret(h, domain), "dd" + h, base64.RawURLEncoding.EncodeToString(append([]byte{0x70}, secret...))}
}

func TestProblemFeedTakesOutSecrets(t *testing.T) {
	e := newEnv(t)
	key := newKey(t)
	n := e.node(nil)
	l := e.listener(n.ID, 443, "")
	p, secret := sealedProxy(t, e, key, l)
	forms := secretForms(secret, p.Domain)
	got, err := e.db.NodeByID(e.ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	got.LastError = "the engine refused " + forms[0] + " and " + forms[1] + " from 203.0.113.9"
	if err := e.db.UpdateNode(e.ctx, got); err != nil {
		t.Fatal(err)
	}
	feed := NewFeed(FeedConfig{DB: e.db, Key: &key, Now: func() time.Time { return e.now },
		ProxyReport: func(_, _ string) (proxies.ProxyReport, bool) {
			return proxies.ProxyReport{Phase: nodev1.ProxyPhase_PROXY_PHASE_FAILED, Reason: "bad link tg://proxy?secret=" + forms[3] + " or " + forms[2]}, true
		}})
	ps, err := feed.List(e.ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("problems = %v, want last_error and proxy.failed", ps)
	}
	for _, x := range ps {
		for _, f := range append(forms, "203.0.113.9") {
			if strings.Contains(x.Summary, f) {
				t.Errorf("%s: %q holds %q", x.Kind, x.Summary, f)
			}
		}
		if !strings.Contains(x.Summary, "***") {
			t.Errorf("%s: %q, want the secret taken out", x.Kind, x.Summary)
		}
	}
}

// A failed proxy that the panel did not see fail (no proxy.failed event) is
// failed since the feed first saw it; the since stays while its node keeps
// reporting it, and a recovery ends it.
func TestProblemFeedFailedSinceWithoutEvent(t *testing.T) {
	e := newEnv(t)
	now := e.now.Truncate(time.Second)
	e.now = now
	n := e.node(nil)
	p := e.proxy(e.listener(n.ID, 443, ""), nil)
	phase := nodev1.ProxyPhase_PROXY_PHASE_FAILED
	feed := NewFeed(FeedConfig{DB: e.db, Now: func() time.Time { return e.now },
		ProxyReport: func(_, _ string) (proxies.ProxyReport, bool) {
			return proxies.ProxyReport{Phase: phase, Reported: e.now}, true
		}})
	since := func() int64 {
		t.Helper()
		ps, err := feed.List(e.ctx, "", p.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(ps) == 0 {
			return -1
		}
		return ps[0].SinceUnix
	}
	if s := since(); s != now.Unix() {
		t.Fatalf("since = %d, want %d", s, now.Unix())
	}
	e.now = now.Add(5 * time.Minute)
	if s := since(); s != now.Unix() {
		t.Errorf("since after 5 min = %d, want it to stay %d", s, now.Unix())
	}
	phase = nodev1.ProxyPhase_PROXY_PHASE_SERVING
	if s := since(); s != -1 {
		t.Errorf("serving: since = %d, want no problem", s)
	}
	phase = nodev1.ProxyPhase_PROXY_PHASE_FAILED
	if s := since(); s != e.now.Unix() {
		t.Errorf("failed again: since = %d, want %d", s, e.now.Unix())
	}
}

func TestListJournalTakesOutClientIPsAndSecrets(t *testing.T) {
	e := newEnv(t)
	key := newKey(t)
	n := e.node(nil) // public IP 198.51.100.5
	p, secret := sealedProxy(t, e, key, e.listener(n.ID, 443, ""))
	forms := secretForms(secret, p.Domain)
	a := newAPIFor(t, e, NewService(e.db, nil, nil, WithKey(&key)))
	for _, x := range []store.Event{
		{ID: "E1", NodeID: n.ID, ProxyID: p.ID, Kind: "proxy.failed", Severity: "error",
			Message: "client 203.0.113.9 sent " + forms[0] + " to 198.51.100.5"},
		{ID: "E2", NodeID: n.ID, ProxyID: p.ID, Kind: "probe.failed", Severity: "warning",
			Details: map[string]string{"error": "dial [2001:db8::7]:443 with " + forms[1], "vantage": "panel"}},
	} {
		if err := e.db.AppendEvent(e.ctx, &x); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.db.AppendAudit(e.ctx, &store.AuditEntry{ID: "A1", Action: "diagnostics.fix",
		Details: map[string]string{"evidence": "from 192.0.2.44 " + forms[2] + " " + forms[3]}}); err != nil {
		t.Fatal(err)
	}
	ev, err := a.admin.ListJournal(e.ctx, connect.NewRequest(&panelv1.ListJournalRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	au, err := a.admin.ListJournal(e.ctx, connect.NewRequest(&panelv1.ListJournalRequest{Source: "audit"}))
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, x := range ev.Msg.GetEvents() {
		texts = append(texts, x.GetMessage())
		for _, v := range x.GetDetails() {
			texts = append(texts, v)
		}
	}
	for _, x := range au.Msg.GetAudit() {
		for _, v := range x.GetDetails() {
			texts = append(texts, v)
		}
	}
	all := strings.Join(texts, "\n")
	for _, bad := range append(forms, "203.0.113.9", "2001:db8::7", "192.0.2.44") {
		if strings.Contains(all, bad) {
			t.Errorf("the journal shows %q:\n%s", bad, all)
		}
	}
	for _, good := range []string{"198.51.100.5", "<ip>", "***", "panel"} {
		if !strings.Contains(all, good) {
			t.Errorf("the journal lacks %q:\n%s", good, all)
		}
	}
}

// journalText is every message and detail of the events of the journal.
func journalText(t *testing.T, e *env, a *api) string {
	t.Helper()
	ev, err := a.admin.ListJournal(e.ctx, connect.NewRequest(&panelv1.ListJournalRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, x := range ev.Msg.GetEvents() {
		texts = append(texts, x.GetMessage())
		for _, v := range x.GetDetails() {
			texts = append(texts, v)
		}
	}
	return strings.Join(texts, "\n")
}

// The journal also takes out the tokens of DNS credentials and the secrets
// in the parameters of egresses: xray URI credentials, subscription URLs,
// passwords and WARP tokens.
func TestListJournalTakesOutDNSTokensAndEgressSecrets(t *testing.T) {
	e := newEnv(t)
	key := newKey(t)
	n := e.node(nil)
	const token = "cf-token-Zq81LmN0pQ" // gitleaks:allow
	c := &store.DNSCredential{ID: ids.New(), Name: "cf"}
	enc, err := seal.Seal(key, []byte(token), []byte("dnscred:"+c.ID))
	if err != nil {
		t.Fatal(err)
	}
	c.TokenEnc = enc
	if err := e.db.CreateDNSCredential(e.ctx, c); err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{
		store.EgressKindXrayURI:          `{"uri":"vless://5f2c8d6e-uuid-cred@vpn.example.net:443?pbk=PubKeyXyz123#name"}`, // gitleaks:allow
		store.EgressKindXraySubscription: `{"url":"https://sub.example.net/s/SubTok3nAbcdef","select":"all"}`,              // gitleaks:allow
		store.EgressKindHTTP:             `{"addr":"203.0.113.50:8080","user":"alice","password":"Hunter2Password"}`,       // gitleaks:allow
		store.EgressKindWARP:             `{"license":"WarpL1censeKey99"}`,                                                 // gitleaks:allow
	}
	for kind, params := range secrets {
		eg := &store.Egress{ID: ids.New(), Name: kind, Kind: kind}
		if eg.ParamsEnc, err = proxies.SealEgressParams(key, eg.ID, params); err != nil {
			t.Fatal(err)
		}
		if err := e.db.CreateEgress(e.ctx, eg); err != nil {
			t.Fatal(err)
		}
	}
	msg := "acme: " + token + "; xray: 5f2c8d6e-uuid-cred and PubKeyXyz123; fetch https://sub.example.net/s/SubTok3nAbcdef; " + // gitleaks:allow
		"auth Hunter2Password; warp WarpL1censeKey99" // gitleaks:allow
	if err := e.db.AppendEvent(e.ctx, &store.Event{ID: "E1", NodeID: n.ID, Kind: "node.error", Severity: "error", Message: msg}); err != nil {
		t.Fatal(err)
	}
	all := journalText(t, e, newAPIFor(t, e, NewService(e.db, nil, nil, WithKey(&key))))
	for _, bad := range []string{token, "5f2c8d6e-uuid-cred", "PubKeyXyz123", "SubTok3nAbcdef", "Hunter2Password", "WarpL1censeKey99"} { // gitleaks:allow
		if strings.Contains(all, bad) {
			t.Errorf("the journal shows %q:\n%s", bad, all)
		}
	}
}

// A secret that does not open no longer fails the journal: the others are
// still taken out, and so is whatever may be a secret, since the one that
// did not open is unknown.
func TestListJournalCleansBlindWhenASecretDoesNotOpen(t *testing.T) {
	e := newEnv(t)
	key := newKey(t)
	n := e.node(nil)
	l := e.listener(n.ID, 443, "")
	p, secret := sealedProxy(t, e, key, l)
	broken := e.proxy(l, nil) // its secret is not sealed with key
	forms := secretForms(secret, p.Domain)
	unknown := strings.Repeat("ab12", 8) // the secret of broken, say
	if err := e.db.AppendEvent(e.ctx, &store.Event{ID: "E1", NodeID: n.ID, ProxyID: broken.ID, Kind: "proxy.failed",
		Severity: "error", Message: "engine refused " + forms[0] + " and " + unknown + " for proxy p"}); err != nil {
		t.Fatal(err)
	}
	all := journalText(t, e, newAPIFor(t, e, NewService(e.db, nil, nil, WithKey(&key))))
	for _, bad := range []string{forms[0], unknown} {
		if strings.Contains(all, bad) {
			t.Errorf("the journal shows %q:\n%s", bad, all)
		}
	}
	if !strings.Contains(all, "for proxy p") {
		t.Errorf("the journal took out more than secrets:\n%s", all)
	}
}
