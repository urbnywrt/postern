package acme

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A new reissue nonce issues a valid certificate again and records the nonce;
// the same nonce on a manager that starts again (an agent restart) does not.
func TestReissueNonceIssuesAgainOnceAndNotOnRestart(t *testing.T) {
	r := newRig(t)
	const domain = "web.example.com"
	cred := CloudflareToken(testToken)
	if err := r.m.Issue(t.Context(), domain, "", cred); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	first := r.m.Status(domain)
	if !first.Valid || first.Due || first.ReissueNonce != 0 {
		t.Fatalf("first certificate: %+v", first)
	}
	// The same nonce (0, none) asks for nothing.
	r.m.SetReissueNonce(domain, 0)
	if err := r.m.Issue(t.Context(), domain, "", cred); err != nil || r.issuer.callCount() != 1 {
		t.Fatalf("Issue with no reissue: err %v, %d issuances", err, r.issuer.callCount())
	}

	r.m.SetReissueNonce(domain, 1)
	if st := r.m.Status(domain); !st.Due || !st.Valid {
		t.Fatalf("a new nonce does not make the valid certificate due: %+v", st)
	}
	r.clock.add(time.Minute)
	if err := r.m.Issue(t.Context(), domain, "", cred); err != nil {
		t.Fatalf("Issue after the nonce: %v", err)
	}
	if n := r.issuer.callCount(); n != 2 {
		t.Fatalf("issuances after a new nonce = %d, want 2", n)
	}
	second := r.m.Status(domain)
	if second.Due || second.ReissueNonce != 1 || second.FullchainSHA256 == first.FullchainSHA256 {
		t.Fatalf("after the reissue: %+v (first sha %s)", second, first.FullchainSHA256)
	}
	raw, err := os.ReadFile(filepath.Join(r.dir(domain), metaFile))
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil || meta["reissueNonce"] != float64(1) {
		t.Fatalf("meta.json = %s (%v)", raw, err)
	}
	var issued bool
	for _, ev := range r.events.all() {
		if ev.GetKind() == EventCertIssued && strings.Contains(ev.GetDetails()["reason"], "reissue") {
			issued = true
		}
	}
	if !issued {
		t.Errorf("no cert_issued event names the reissue: %v", r.events.kinds())
	}
	// Again with the same nonce: nothing.
	if err := r.m.Issue(t.Context(), domain, "", cred); err != nil || r.issuer.callCount() != 2 {
		t.Fatalf("Issue with the same nonce: err %v, %d issuances", err, r.issuer.callCount())
	}

	// A restart: a new manager on the same files, told the same nonce.
	m2 := &Manager{Paths: r.m.Paths, Now: r.clock.now, LookupIP: r.m.LookupIP, obtain: r.issuer.obtain, retryAfter: r.m.retryAfter}
	m2.SetReissueNonce(domain, 1)
	if err := m2.Issue(t.Context(), domain, "", cred); err != nil {
		t.Fatalf("Issue after a restart: %v", err)
	}
	if n := r.issuer.callCount(); n != 2 {
		t.Fatalf("a restart issued again: %d issuances", n)
	}
	// Renew with the nonce raised again issues once more.
	m2.SetReissueNonce(domain, 2)
	if err := m2.Renew(t.Context()); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if n := r.issuer.callCount(); n != 3 {
		t.Fatalf("Renew after a new nonce: %d issuances, want 3", n)
	}
}

// A new nonce is tried at once, also in the pause of a failure with the old
// one; the same nonce keeps the pause.
func TestReissueNonceIsTriedDespiteThePause(t *testing.T) {
	r := newRig(t)
	const domain = "web.example.com"
	cred := CloudflareToken(testToken)
	if err := r.m.Issue(t.Context(), domain, "", cred); err != nil {
		t.Fatal(err)
	}
	r.issuer.mu.Lock()
	r.issuer.errs = []error{nil, errors.New("CA down"), errors.New("CA down")}
	r.issuer.mu.Unlock()
	r.m.SetReissueNonce(domain, 1)
	if err := r.m.Issue(t.Context(), domain, "", cred); err == nil {
		t.Fatal("the failing reissue succeeded")
	}
	if err := r.m.Issue(t.Context(), domain, "", cred); !errors.Is(err, ErrBackoff) {
		t.Fatalf("the same nonce again: %v, want ErrBackoff", err)
	}
	calls := r.issuer.callCount()
	r.m.SetReissueNonce(domain, 2)
	if err := r.m.Issue(t.Context(), domain, "", cred); err != nil {
		t.Fatalf("a new nonce in the pause: %v", err)
	}
	if r.issuer.callCount() != calls+1 {
		t.Fatalf("a new nonce was not tried at once")
	}
	if st := r.m.Status(domain); st.ReissueNonce != 2 || st.Due {
		t.Fatalf("after the new nonce: %+v", st)
	}
}

// A wanted nonce of 0 asks for nothing: a proxy deleted and made again for
// the same domain (its nonce back at 0) costs no issuance, and a renewal
// keeps the nonce the certificate recorded.
func TestAZeroReissueNonceAsksForNothing(t *testing.T) {
	r := newRig(t)
	const domain = "web.example.com"
	cred := CloudflareToken(testToken)
	r.m.SetReissueNonce(domain, 2)
	if err := r.m.Issue(t.Context(), domain, "", cred); err != nil {
		t.Fatal(err)
	}
	r.m.SetReissueNonce(domain, 0)
	if st := r.m.Status(domain); st.Due || st.ReissueNonce != 2 {
		t.Fatalf("with nonce 0: %+v", st)
	}
	m2 := &Manager{Paths: r.m.Paths, Now: r.clock.now, LookupIP: r.m.LookupIP, obtain: r.issuer.obtain, retryAfter: r.m.retryAfter}
	if err := m2.Issue(t.Context(), domain, "", cred); err != nil || r.issuer.callCount() != 1 {
		t.Fatalf("a new manager without a nonce: err %v, %d issuances", err, r.issuer.callCount())
	}
	// A renewal (61 days on) with no nonce asked keeps the recorded one.
	r.clock.add(61 * 24 * time.Hour)
	if err := m2.Issue(t.Context(), domain, "", cred); err != nil || r.issuer.callCount() != 2 {
		t.Fatalf("renewal: err %v, %d issuances", err, r.issuer.callCount())
	}
	if st := m2.Status(domain); st.ReissueNonce != 2 || st.Due {
		t.Fatalf("after the renewal: %+v", st)
	}
}
