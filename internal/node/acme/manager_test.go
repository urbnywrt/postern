package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/go-acme/lego/v4/acme"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/state"
)

// ---- a CA and an issuer for the tests -------------------------------------------

// testCA issues certificates as a CA would: a leaf for a domain, signed by an
// intermediate of its own, the chain leaf first.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "postern test CA"},
		NotBefore: time.Now().Add(-1000 * 24 * time.Hour), NotAfter: time.Now().Add(1000 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

var serial = struct {
	sync.Mutex
	n int64
}{n: 100}

// issue returns the chain and the key of a certificate for domain, valid from
// notBefore to notAfter, with an ECDSA key as lego makes them (EC PRIVATE KEY).
func (ca *testCA) issue(t *testing.T, domain string, notBefore, notAfter time.Time) *issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der := ca.leaf(t, domain, notBefore, notAfter, &key.PublicKey)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &issued{
		fullchain: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), ca.pem...),
		key:       pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

func (ca *testCA) leaf(t *testing.T, domain string, notBefore, notAfter time.Time, pub any) []byte {
	t.Helper()
	serial.Lock()
	serial.n++
	n := serial.n
	serial.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// obtainCall is a call of the fake issuance.
type obtainCall struct {
	domain, email, token string
	at                   time.Time
}

// fakeIssuer stands in for lego: it issues certificates of its CA, valid for
// life from the clock of the manager, or fails as told.
type fakeIssuer struct {
	t   *testing.T
	ca  *testCA
	now func() time.Time

	mu      sync.Mutex
	calls   []obtainCall
	errs    []error                  // the error of each call in turn; nil, or past the end: success
	life    map[string]time.Duration // by domain; 90 days without
	wrong   string                   // when set, the certificate is for this domain instead
	block   chan struct{}            // when set, a call waits for it to close (or for its context)
	started chan string              // when set, gets the domain of every call
	onDone  func()                   // when set, called as a call that succeeds returns
	onCall  func(domain string)      // when set, called as every call begins
	ahead   time.Duration            // how far ahead of the node's clock the CA's is
}

func newFakeIssuer(t *testing.T, now func() time.Time) *fakeIssuer {
	return &fakeIssuer{t: t, ca: newTestCA(t), now: now, life: map[string]time.Duration{}}
}

func (f *fakeIssuer) obtain(ctx context.Context, domain, email string, cred Credential) (*issued, error) {
	f.mu.Lock()
	n := len(f.calls)
	f.calls = append(f.calls, obtainCall{domain: domain, email: email, token: cred.token(), at: time.Now()})
	var err error
	if n < len(f.errs) {
		err = f.errs[n]
	}
	block, started, onCall := f.block, f.started, f.onCall
	life, ok := f.life[domain]
	if !ok {
		life = 90 * 24 * time.Hour
	}
	certDomain := domain
	if f.wrong != "" {
		certDomain = f.wrong
	}
	f.mu.Unlock()
	if onCall != nil {
		onCall(domain)
	}
	if started != nil {
		started <- domain
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	done, ahead := f.onDone, f.ahead
	f.mu.Unlock()
	now := f.now().Add(ahead)
	is := f.ca.issue(f.t, certDomain, now.Add(-time.Hour), now.Add(life-time.Hour))
	if done != nil {
		done()
	}
	return is, nil
}

func (f *fakeIssuer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeIssuer) callList() []obtainCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// ---- the manager under test -----------------------------------------------------

// eventLog collects events.
type eventLog struct {
	mu   sync.Mutex
	list []*nodev1.NodeEvent
}

func (e *eventLog) add(ev *nodev1.NodeEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.list = append(e.list, ev)
}

func (e *eventLog) all() []*nodev1.NodeEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.list)
}

func (e *eventLog) kinds() []string {
	var out []string
	for _, ev := range e.all() {
		out = append(out, ev.GetKind())
	}
	return out
}

// syncBuffer is a bytes.Buffer for a log that goroutines write to.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// clock is a clock the tests set.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type rig struct {
	m      *Manager
	issuer *fakeIssuer
	events *eventLog
	log    *syncBuffer
	clock  *clock
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{events: &eventLog{}, log: &syncBuffer{}, clock: &clock{t: time.Now().Truncate(time.Second)}}
	r.issuer = newFakeIssuer(t, r.clock.now)
	r.m = &Manager{
		Paths:  state.Paths{Home: t.TempDir()},
		Events: r.events.add,
		Log:    slog.New(slog.NewTextHandler(r.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:    r.clock.now,
		LookupIP: func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("no lookup in the unit tests")
		},
		obtain:     r.issuer.obtain,
		retryAfter: 20 * time.Millisecond,
	}
	return r
}

func (r *rig) dir(domain string) string { return filepath.Join(r.m.Paths.CertsDir(), domain) }

// put writes a certificate for domain into its directory, as another node or
// an earlier issuance left it.
func (r *rig) put(t *testing.T, domain string, is *issued, meta string) {
	t.Helper()
	dir := r.dir(domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{fullchainFile: is.fullchain, privkeyFile: is.key} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if meta != "" {
		if err := os.WriteFile(filepath.Join(dir, metaFile), []byte(meta), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// ---- the tests ------------------------------------------------------------------

var jsTimeRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

func TestIssueWritesTheLayout(t *testing.T) {
	r := newRig(t)
	if err := r.m.Issue(t.Context(), "web.example.com", "admin@example.com", CloudflareToken(testToken)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	calls := r.issuer.callList()
	if len(calls) != 1 || calls[0].domain != "web.example.com" || calls[0].email != "admin@example.com" || calls[0].token != testToken {
		t.Fatalf("issuances = %+v", calls)
	}
	dir := r.dir("web.example.com")
	if got := mode(t, dir); got != 0o700 {
		t.Errorf("the directory has mode %v, want 0700", got)
	}
	for name, want := range map[string]os.FileMode{privkeyFile: 0o600, fullchainFile: 0o644, metaFile: 0o644} {
		if got := mode(t, filepath.Join(dir, name)); got != want {
			t.Errorf("%s has mode %v, want %v", name, got, want)
		}
	}
	chain, err := os.ReadFile(filepath.Join(dir, fullchainFile))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(filepath.Join(dir, privkeyFile))
	leaf, err := certLeaf(chain, key, "web.example.com")
	if err != nil {
		t.Fatalf("the files are not a certificate for the domain and its key: %v", err)
	}
	if n := bytes.Count(chain, []byte("BEGIN CERTIFICATE")); n != 2 {
		t.Errorf("fullchain.pem holds %d certificates, want the chain of 2", n)
	}

	// meta.json: exactly these keys, times as
	// JavaScript's toISOString.
	raw, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("meta.json: %v", err)
	}
	if keys := slices.Sorted(maps.Keys(meta)); !slices.Equal(keys, []string{"expiresAt", "issuedAt", "staging"}) {
		t.Errorf("meta.json has the keys %q", keys)
	}
	for _, k := range []string{"expiresAt", "issuedAt"} {
		if s, _ := meta[k].(string); !jsTimeRE.MatchString(s) {
			t.Errorf("meta.json %s = %q, not as toISOString writes it", k, s)
		}
	}
	if got, want := meta["expiresAt"], leaf.NotAfter.UTC().Format(jsTimeLayout); got != want {
		t.Errorf("expiresAt = %v, want the end of the certificate %v", got, want)
	}
	if got, want := meta["issuedAt"], r.clock.now().UTC().Format(jsTimeLayout); got != want {
		t.Errorf("issuedAt = %v, want %v", got, want)
	}
	if meta["staging"] != false {
		t.Errorf("staging = %v", meta["staging"])
	}

	st := r.m.Status("web.example.com")
	sum := sha256.Sum256(chain)
	if !st.Valid || st.Due || st.Issuing || st.LastError != "" || st.Reason() != "" ||
		!st.NotAfter.Equal(leaf.NotAfter) || !st.IssuedAt.Equal(r.clock.now()) || st.FullchainSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("Status = %+v", st)
	}

	evs := r.events.all()
	if len(evs) != 1 || evs[0].GetKind() != EventCertIssued || evs[0].GetSeverity() != "info" {
		t.Fatalf("events = %v", evs)
	}
	d := evs[0].GetDetails()
	if d["domain"] != "web.example.com" || d["reason"] != "no certificate" || d["staging"] != "false" ||
		d["expires_at"] != leaf.NotAfter.UTC().Format(time.RFC3339) {
		t.Errorf("cert_issued details = %v", d)
	}
}

func TestIssueTakesTheCertificatesAlreadyThere(t *testing.T) {
	// As another issuer may leave them: an RSA key, meta.json of toISOString.
	r := newRig(t)
	now := r.clock.now()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := r.issuer.ca.leaf(t, "web.example.com", now.Add(-10*24*time.Hour), now.Add(80*24*time.Hour), &key.PublicKey)
	there := &issued{
		fullchain: append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), r.issuer.ca.pem...),
		key:       pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	}
	r.put(t, "web.example.com", there, `{"expiresAt":"2026-12-24T10:00:00.000Z","issuedAt":"2026-09-25T10:00:00.123Z","staging":false}`)

	if err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if n := r.issuer.callCount(); n != 0 {
		t.Errorf("a good certificate that was there was issued anew (%d issuances)", n)
	}
	st := r.m.Status("web.example.com")
	if !st.Valid || st.Due || st.Staging || !st.IssuedAt.Equal(time.Date(2026, 9, 25, 10, 0, 0, 123e6, time.UTC)) {
		t.Errorf("Status = %+v", st)
	}
	if len(r.events.all()) != 0 {
		t.Errorf("events = %v", r.events.kinds())
	}
}

func TestIssueDecidesWhetherToIssue(t *testing.T) {
	const domain = "web.example.com"
	day := 24 * time.Hour
	tests := []struct {
		label     string
		staging   bool // of the manager
		write     func(t *testing.T, r *rig)
		wantIssue bool
	}{
		{label: "no certificate", write: func(*testing.T, *rig) {}, wantIssue: true},
		{label: "60 days left", write: put(-30*day, 60*day, `{"staging":false}`), wantIssue: false},
		{label: "31 days left", write: put(-59*day, 31*day, ""), wantIssue: false},
		{label: "29 days left", write: put(-61*day, 29*day, ""), wantIssue: true},
		{label: "expired", write: put(-91*day, -day, ""), wantIssue: true},
		{label: "not valid yet", write: put(day, 90*day, ""), wantIssue: true},
		{label: "from the staging directory", write: put(-day, 89*day, `{"staging":true}`), wantIssue: true},
		{label: "staging, for a staging manager", staging: true, write: put(-day, 89*day, `{"staging":true}`), wantIssue: false},
		{label: "production, for a staging manager", staging: true, write: put(-day, 89*day, `{"staging":false}`), wantIssue: true},
		// Half of its lifetime ahead when that is less than 30 days (Ruling
		// S3-3): a certificate of 6 days is not due as soon as it is issued.
		{label: "6-day certificate, 4 days left", write: put(-2*day, 4*day, ""), wantIssue: false},
		{label: "6-day certificate, 3 days left", write: put(-3*day, 3*day, ""), wantIssue: true},
		{label: "64-day certificate, 31 days left", write: put(-33*day, 31*day, ""), wantIssue: false},
		{label: "64-day certificate, 30 days left", write: put(-34*day, 30*day, ""), wantIssue: true},
		{label: "45-day certificate, 23 days left", write: put(-22*day, 23*day, ""), wantIssue: false},
		{label: "45-day certificate, 22 days left", write: put(-23*day, 22*day, ""), wantIssue: true},
		{label: "for another domain", write: func(t *testing.T, r *rig) {
			now := r.clock.now()
			r.put(t, domain, r.issuer.ca.issue(t, "other.example.com", now.Add(-day), now.Add(80*day)), "")
		}, wantIssue: true},
		{label: "the key of another certificate", write: func(t *testing.T, r *rig) {
			now := r.clock.now()
			a := r.issuer.ca.issue(t, domain, now.Add(-day), now.Add(80*day))
			b := r.issuer.ca.issue(t, domain, now.Add(-day), now.Add(80*day))
			r.put(t, domain, &issued{fullchain: a.fullchain, key: b.key}, "")
		}, wantIssue: true},
		{label: "no key", write: func(t *testing.T, r *rig) {
			put(-day, 80*day, "")(t, r)
			if err := os.Remove(filepath.Join(r.dir(domain), privkeyFile)); err != nil {
				t.Fatal(err)
			}
		}, wantIssue: true},
		{label: "not PEM", write: func(t *testing.T, r *rig) {
			r.put(t, domain, &issued{fullchain: []byte("junk"), key: []byte("junk")}, "")
		}, wantIssue: true},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			r := newRig(t)
			r.m.Staging = tt.staging
			tt.write(t, r)
			before := r.m.Status(domain)
			if before.Due != tt.wantIssue {
				t.Errorf("Status.Due = %v before (%+v), want %v", before.Due, before, tt.wantIssue)
			}
			if err := r.m.Issue(t.Context(), domain, "", CloudflareToken(testToken)); err != nil {
				t.Fatalf("Issue: %v", err)
			}
			if got := r.issuer.callCount() == 1; got != tt.wantIssue {
				t.Errorf("issued = %v, want %v", got, tt.wantIssue)
			}
			if st := r.m.Status(domain); !st.Valid || st.Due {
				t.Errorf("after Issue: Status = %+v", st)
			}
		})
	}
}

func TestRenewalIsDueAtMostThirtyDaysOrHalfTheLifetimeBeforeExpiry(t *testing.T) {
	// Ruling S3-3: due when the validity left is at most min(30 days,
	// lifetime/2). That is 30 days for every lifetime of 60 days or more.
	day := 24 * time.Hour
	tests := []struct {
		life, left time.Duration
		due        bool
	}{
		{90 * day, 30*day + time.Second, false},
		{90 * day, 30 * day, true},
		{90 * day, 29 * day, true},
		{64 * day, 30*day + time.Second, false},
		{64 * day, 30 * day, true},
		{60 * day, 30*day + time.Second, false},
		{60 * day, 30 * day, true},
		{45 * day, 22*day + 12*time.Hour + time.Second, false},
		{45 * day, 22*day + 12*time.Hour, true},
		{6 * day, 3*day + time.Second, false},
		{6 * day, 3 * day, true},
		{6 * day, 6 * day, false}, // just issued
	}
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, tt := range tests {
		leaf := &x509.Certificate{NotBefore: now.Add(tt.left - tt.life), NotAfter: now.Add(tt.left)}
		if due := !now.Before(renewAt(leaf)); due != tt.due {
			t.Errorf("lifetime %v, %v left: due = %v, want %v (renewAt %v)", tt.life, tt.left, due, tt.due, renewAt(leaf))
		}
	}
}

// put returns a writer of a certificate for web.example.com valid from now+from
// to now+to, with meta.json.
func put(from, to time.Duration, meta string) func(t *testing.T, r *rig) {
	return func(t *testing.T, r *rig) {
		now := r.clock.now()
		r.put(t, "web.example.com", r.issuer.ca.issue(t, "web.example.com", now.Add(from), now.Add(to)), meta)
	}
}

func TestIssueTriesOnceMoreAfterRetryAfter(t *testing.T) {
	if RetryAfter != 10*time.Second {
		t.Errorf("RetryAfter = %v, want 10 s", RetryAfter)
	}
	r := newRig(t)
	r.m.retryAfter = 150 * time.Millisecond
	r.issuer.errs = []error{errors.New("the CA is away")}
	if err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	calls := r.issuer.callList()
	if len(calls) != 2 {
		t.Fatalf("%d issuances, want 2", len(calls))
	}
	if gap := calls[1].at.Sub(calls[0].at); gap < 150*time.Millisecond {
		t.Errorf("the retry came %v after the first try, before RetryAfter", gap)
	}
	if got := r.events.kinds(); !slices.Equal(got, []string{EventCertIssued}) {
		t.Errorf("events = %q, want cert_issued only", got)
	}
	if !strings.Contains(r.log.String(), "tried once more") || !strings.Contains(r.log.String(), "the CA is away") {
		t.Errorf("the first failure is not logged:\n%s", r.log)
	}
}

func TestIssueFailsAfterTwoAttempts(t *testing.T) {
	r := newRig(t)
	r.issuer.errs = []error{errors.New("first"), errors.New("error: one or more domains had a problem:\n[web.example.com] second\n")}
	err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken))
	if err == nil || errors.Is(err, ErrBackoff) {
		t.Fatalf("Issue = %v, want the failure", err)
	}
	if n := r.issuer.callCount(); n != 2 {
		t.Errorf("%d issuances, want 2", n)
	}
	evs := r.events.all()
	if len(evs) != 1 || evs[0].GetKind() != EventCertFailed || evs[0].GetSeverity() != "error" {
		t.Fatalf("events = %v", evs)
	}
	d := evs[0].GetDetails()
	if d["domain"] != "web.example.com" || d["reason"] != "second" || d["attempts"] != "2" {
		t.Errorf("cert_failed details = %v", d)
	}
	st := r.m.Status("web.example.com")
	now := r.clock.now()
	if st.Valid || st.LastError != "second" || !st.FailedAt.Equal(now) || !st.RetryAt.Equal(now.Add(10*time.Minute)) ||
		st.Reason() != "no valid certificate: second" {
		t.Errorf("Status = %+v, Reason %q", st, st.Reason())
	}
	if _, err := os.Stat(r.dir("web.example.com")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed issuance left a directory: %v", err)
	}
}

func TestIssuePausesAfterAFailure(t *testing.T) {
	r := newRig(t)
	fail := errors.New("refused")
	r.issuer.errs = []error{fail, fail, fail, fail, fail, fail}
	cred := CloudflareToken(testToken)
	if err := r.m.Issue(t.Context(), "web.example.com", "a@example.com", cred); err == nil {
		t.Fatal("no failure")
	}

	// The same email address and credential within the pause: not tried.
	err := r.m.Issue(t.Context(), "web.example.com", "a@example.com", cred)
	if !errors.Is(err, ErrBackoff) || !strings.Contains(err.Error(), "refused") {
		t.Errorf("Issue in the pause = %v, want ErrBackoff with the last reason", err)
	}
	if n := r.issuer.callCount(); n != 2 {
		t.Errorf("%d issuances, want the 2 of the first Issue", n)
	}
	if len(r.events.all()) != 1 {
		t.Errorf("events = %q, want one", r.events.kinds())
	}

	// Another credential is tried at once; the pause starts over for it.
	if err := r.m.Issue(t.Context(), "web.example.com", "a@example.com", CloudflareToken("another-token")); err == nil || errors.Is(err, ErrBackoff) {
		t.Errorf("Issue with another credential = %v, want a try", err)
	}
	if n := r.issuer.callCount(); n != 4 {
		t.Errorf("%d issuances, want 4", n)
	}
	if st := r.m.Status("web.example.com"); !st.RetryAt.Equal(r.clock.now().Add(10 * time.Minute)) {
		t.Errorf("RetryAt = %v, want 10 minutes on", st.RetryAt)
	}

	// After the pause it is tried again, and the next pause is twice as long.
	r.clock.add(11 * time.Minute)
	if err := r.m.Issue(t.Context(), "web.example.com", "a@example.com", CloudflareToken("another-token")); err == nil || errors.Is(err, ErrBackoff) {
		t.Errorf("Issue after the pause = %v, want a try", err)
	}
	if st := r.m.Status("web.example.com"); !st.RetryAt.Equal(r.clock.now().Add(20 * time.Minute)) {
		t.Errorf("RetryAt = %v, want 20 minutes on", st.RetryAt)
	}

	for n, want := range map[int]time.Duration{1: 10 * time.Minute, 2: 20 * time.Minute, 3: 40 * time.Minute, 6: 320 * time.Minute, 7: 6 * time.Hour, 50: 6 * time.Hour} {
		if got := backoff(n); got != want {
			t.Errorf("backoff(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestIssueWithoutACredentialFails(t *testing.T) {
	r := newRig(t)
	err := r.m.Issue(t.Context(), "web.example.com", "", Credential{})
	if err == nil || !strings.Contains(err.Error(), "no DNS credential") {
		t.Fatalf("Issue = %v", err)
	}
	if n := r.issuer.callCount(); n != 0 {
		t.Errorf("%d issuances without a credential", n)
	}
	if got := r.events.kinds(); !slices.Equal(got, []string{EventCertFailed}) {
		t.Errorf("events = %q", got)
	}
	if err := r.m.Issue(t.Context(), "web.example.com", "", Credential{}); !errors.Is(err, ErrBackoff) {
		t.Errorf("again = %v, want ErrBackoff", err)
	}
	if err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)); err != nil {
		t.Errorf("with a credential = %v", err)
	}
}

func TestIssueKeepsTheCertificateWhenItsRenewalFails(t *testing.T) {
	r := newRig(t)
	put(-70*24*time.Hour, 20*24*time.Hour, "")(t, r)
	before, _ := os.ReadFile(filepath.Join(r.dir("web.example.com"), fullchainFile))
	r.issuer.errs = []error{errors.New("down"), errors.New("down")}
	if err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)); err == nil {
		t.Fatal("no failure")
	}
	after, _ := os.ReadFile(filepath.Join(r.dir("web.example.com"), fullchainFile))
	if !bytes.Equal(before, after) {
		t.Error("the certificate was replaced")
	}
	evs := r.events.all()
	if len(evs) != 1 || evs[0].GetSeverity() != "warning" {
		t.Errorf("events = %v, want one warning: the certificate is still served", evs)
	}
	st := r.m.Status("web.example.com")
	if !st.Valid || st.Reason() != "the renewal of the certificate failed: down" {
		t.Errorf("Status = %+v, Reason %q", st, st.Reason())
	}
}

func TestIssueRefusesACertificateThatCannotBeUsed(t *testing.T) {
	r := newRig(t)
	r.issuer.wrong = "other.example.com"
	err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken))
	if err == nil || !strings.Contains(err.Error(), "cannot be used") {
		t.Fatalf("Issue = %v", err)
	}
	if _, err := os.Stat(r.dir("web.example.com")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a certificate for another domain was written: %v", err)
	}
}

func TestIssueDoesNotTryAgainWhenTheCertificateCannotBeWritten(t *testing.T) {
	r := newRig(t)
	if err := os.MkdirAll(r.m.Paths.CertsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	// A file where the directory of the domain goes.
	if err := os.WriteFile(r.dir("web.example.com"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken))
	if err == nil || !strings.Contains(err.Error(), "writing the certificate") {
		t.Fatalf("Issue = %v", err)
	}
	if n := r.issuer.callCount(); n != 1 {
		t.Errorf("%d issuances, want 1: a new certificate would be lost the same way", n)
	}
	if got := r.events.kinds(); !slices.Equal(got, []string{EventCertFailed}) {
		t.Errorf("events = %q", got)
	}
	// A failure that lasts is not met with an issuance at every call.
	if err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)); !errors.Is(err, ErrBackoff) {
		t.Errorf("Issue again = %v, want ErrBackoff", err)
	}
	if n := r.issuer.callCount(); n != 1 {
		t.Errorf("%d issuances after the pause began, want 1", n)
	}
}

func TestANewCertificateThatIsDueAtOnceIsAFailure(t *testing.T) {
	// The clock of the node is two hours behind the CA's: the certificate it
	// gets is not valid yet, by its own clock. Issued again at every call it
	// would run into the limit of 5 duplicates a week.
	r := newRig(t)
	r.issuer.ahead = 2 * time.Hour
	err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken))
	if err == nil || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("Issue = %v, want a failure that suspects the clock", err)
	}
	st := r.m.Status("web.example.com")
	// The pause starts at its longest: a wrong clock stays wrong, and every
	// try is a duplicate, of which Let's Encrypt allows 5 a week.
	if !strings.Contains(st.LastError, "clock") || !st.RetryAt.Equal(r.clock.now().Add(6*time.Hour)) {
		t.Errorf("Status = %+v, want RetryAt 6 h on", st)
	}
	if got := r.events.kinds(); !slices.Equal(got, []string{EventCertFailed}) {
		t.Errorf("events = %q, want cert_failed only", got)
	}
	if err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)); !errors.Is(err, ErrBackoff) {
		t.Errorf("Issue again = %v, want ErrBackoff", err)
	}
	if n := r.issuer.callCount(); n != 1 {
		t.Errorf("%d issuances, want 1", n)
	}
}

func rateLimited(retryAfter string) error {
	return &acme.RateLimitedError{
		ProblemDetails: &acme.ProblemDetails{
			Type: acme.RateLimitedErr, HTTPStatus: http.StatusTooManyRequests,
			Detail: "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s",
		},
		RetryAfter: retryAfter,
	}
}

func TestTheRetryAfterOfARateLimitIsReadFromTheError(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	week := 7 * day
	tests := []struct {
		label   string
		err     error
		served  time.Time // the end of the certificate that is served; zero for none
		limited bool
		until   time.Time
	}{
		{"seconds", rateLimited("3600"), time.Time{}, true, now.Add(time.Hour)},
		{"an HTTP date", rateLimited("Mon, 05 Oct 2026 14:30:00 GMT"), time.Time{}, true, time.Date(2026, 10, 5, 14, 30, 0, 0, time.UTC)},
		{"wrapped as lego wraps it", fmt.Errorf("error: one or more domains had a problem:\n%w",
			errors.Join(fmt.Errorf("web.example.com: %w", rateLimited("60")))), time.Time{}, true, now.Add(time.Minute)},
		{"without Retry-After", rateLimited(""), time.Time{}, true, time.Time{}},
		{"a Retry-After that is not one", rateLimited("soon"), time.Time{}, true, time.Time{}},
		{"zero seconds", rateLimited("0"), time.Time{}, true, time.Time{}},
		{"a date in the past", rateLimited("Mon, 05 Oct 2026 11:00:00 GMT"), time.Time{}, true, time.Time{}},
		{"another problem", &acme.ProblemDetails{Type: "urn:ietf:params:acme:error:unauthorized", HTTPStatus: 403}, time.Time{}, false, time.Time{}},
		// Only the type tells: the text of a rate limit is not one.
		{"the text of one", errors.New(rateLimited("3600").Error()), time.Time{}, false, time.Time{}},

		// Never more than 7 days, whatever the CA says.
		{"a date far in the future", rateLimited("Fri, 31 Dec 9999 23:59:59 GMT"), time.Time{}, true, now.Add(week)},
		{"huge seconds", rateLimited("99999999999"), time.Time{}, true, now.Add(week)},
		{"seconds of the overflow", rateLimited("9223372036854775807"), time.Time{}, true, now.Add(week)},
		{"7 days in seconds", rateLimited("604800"), time.Time{}, true, now.Add(week)},
		{"7 days and a second", rateLimited("604801"), time.Time{}, true, now.Add(week)},
		{"a date 7 days on", rateLimited("Mon, 12 Oct 2026 12:00:00 GMT"), time.Time{}, true, now.Add(week)},
		{"a date 7 days and a second on", rateLimited("Mon, 12 Oct 2026 12:00:01 GMT"), time.Time{}, true, now.Add(week)},
		// Nor more than half the validity left of the certificate that is
		// served: a 6-day certificate with 3 days left waits 1.5 days at most.
		{"a 6-day certificate with 3 days left", rateLimited("604800"), now.Add(3 * day), true, now.Add(36 * time.Hour)},
		{"a date past half its validity", rateLimited("Wed, 07 Oct 2026 12:00:00 GMT"), now.Add(3 * day), true, now.Add(36 * time.Hour)},
		{"a Retry-After within half its validity", rateLimited("3600"), now.Add(3 * day), true, now.Add(time.Hour)},
		{"a certificate that has expired", rateLimited("3600"), now.Add(-day), true, now.Add(time.Hour)},
	}
	for _, tt := range tests {
		until, limited := rateLimitedUntil(tt.err, now, tt.served)
		if limited != tt.limited || !until.Equal(tt.until) {
			t.Errorf("%s: rateLimitedUntil = %v, %v; want %v, %v", tt.label, until, limited, tt.until, tt.limited)
		}
	}
}

func TestARateLimitNeverOutlivesHalfTheCertificateServed(t *testing.T) {
	// A 6-day certificate with 3 days left is due; the CA says to wait a
	// week. The domain waits a day and a half, and tries again while the
	// certificate it serves is still valid.
	r := newRig(t)
	put(-3*24*time.Hour, 3*24*time.Hour, "")(t, r)
	r.issuer.errs = []error{rateLimited("604800")}
	if err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)); err == nil {
		t.Fatal("Issue went through")
	}
	if st := r.m.Status("web.example.com"); !st.RetryAt.Equal(r.clock.now().Add(36 * time.Hour)) {
		t.Errorf("RetryAt = %v, want a day and a half on", st.RetryAt)
	}
}

func TestARateLimitIsNotTriedAgainBeforeItsRetryAfter(t *testing.T) {
	r := newRig(t)
	r.issuer.errs = []error{rateLimited("7200"), rateLimited("7200")}
	err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken))
	if err == nil || !strings.Contains(err.Error(), "rateLimited") {
		t.Fatalf("Issue = %v", err)
	}
	if n := r.issuer.callCount(); n != 1 {
		t.Errorf("%d issuances, want 1: the retry 10 s later would be refused as well", n)
	}
	if st := r.m.Status("web.example.com"); !st.RetryAt.Equal(r.clock.now().Add(2 * time.Hour)) {
		t.Errorf("RetryAt = %v, want the Retry-After of the CA, 2 h on", st.RetryAt)
	}
	r.clock.add(11 * time.Minute) // past the pause of a first failure
	if err := r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)); !errors.Is(err, ErrBackoff) {
		t.Errorf("Issue 11 minutes on = %v, want ErrBackoff until the Retry-After", err)
	}
	if n := r.issuer.callCount(); n != 1 {
		t.Errorf("%d issuances, want 1", n)
	}
}

// panickingDNS panics once, in RemoveStale, then fails.
type panickingDNS struct {
	recordingDNS
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (p *panickingDNS) RemoveStale(ctx context.Context, domain string) error {
	panicking := false
	p.once.Do(func() { panicking = true })
	if panicking {
		close(p.entered)
		<-p.release
		panic("a provider that panics")
	}
	return errors.New("no zone")
}

func TestAPanicNeverLeavesADomainIssuing(t *testing.T) {
	r := newRig(t)
	r.m.obtain = nil // the issuance of lego, which calls the DNS provider first
	dns := &panickingDNS{entered: make(chan struct{}), release: make(chan struct{})}
	r.m.DNS = func(Credential) (DNSProvider, error) { return dns, nil }
	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		_ = r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken))
	}()
	<-dns.entered
	waiter := make(chan error, 1)
	go func() { waiter <- r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)) }()
	time.Sleep(50 * time.Millisecond) // the waiter waits for the issuance that runs
	close(dns.release)
	if p := <-panicked; p == nil {
		t.Fatal("the provider did not panic")
	}
	select {
	case err := <-waiter:
		if err == nil {
			t.Error("the waiter got no error from an issuance that panicked")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a caller that waited for the issuance is stuck")
	}
	if st := r.m.Status("web.example.com"); st.Issuing {
		t.Error("the domain is left issuing")
	}
}

// alwaysPanickingDNS panics at every call, with a message that could carry
// data.
type alwaysPanickingDNS struct {
	recordingDNS
	calls atomic.Int32
}

func (p *alwaysPanickingDNS) RemoveStale(context.Context, string) error {
	p.calls.Add(1)
	panic("a provider that panics with " + testToken)
}

func TestAPanicIsAFailureWithItsPause(t *testing.T) {
	r := newRig(t)
	r.m.obtain = nil // the issuance of lego, which calls the DNS provider first
	dns := &alwaysPanickingDNS{}
	r.m.DNS = func(Credential) (DNSProvider, error) { return dns, nil }
	issue := func() (p any, err error) {
		defer func() { p = recover() }()
		return nil, r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken))
	}
	if p, _ := issue(); p == nil {
		t.Fatal("the provider did not panic")
	}
	st := r.m.Status("web.example.com")
	if st.LastError != "internal error in the issuance" || !st.RetryAt.Equal(r.clock.now().Add(10*time.Minute)) || st.Issuing {
		t.Errorf("Status = %+v, want the failure and its pause", st)
	}
	evs := r.events.all()
	if len(evs) != 1 || evs[0].GetKind() != EventCertFailed || evs[0].GetDetails()["reason"] != "internal error in the issuance" {
		t.Errorf("events = %v", evs)
	}
	// A panic that comes again at every call is not met again until the
	// pause ends.
	p, err := issue()
	if p != nil {
		t.Fatalf("panicked again: %v", p)
	}
	if !errors.Is(err, ErrBackoff) {
		t.Errorf("Issue again = %v, want ErrBackoff", err)
	}
	if n := dns.calls.Load(); n != 1 {
		t.Errorf("the provider was called %d times, want once", n)
	}
	out := st.LastError + r.log.String() + err.Error()
	for _, ev := range evs {
		out += ev.GetMessage() + fmt.Sprint(ev.GetDetails())
	}
	if strings.Contains(out, "provider that panics") || strings.Contains(out, testToken) {
		t.Errorf("the text of the panic got out: %s", out)
	}
}

func TestAPanickingEventsCallbackNeverLeavesADomainIssuing(t *testing.T) {
	// Events panics at the failure of the issuance, and again when the
	// failure of that panic is reported: the flight ends all the same.
	r := newRig(t)
	r.m.Events = func(*nodev1.NodeEvent) { panic("an Events callback that panics") }
	r.issuer.errs = []error{errors.New("refused"), errors.New("refused")}
	issue := func() (p any, err error) {
		defer func() { p = recover() }()
		return nil, r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken))
	}
	if p, _ := issue(); p == nil {
		t.Fatal("Events did not panic")
	}
	if n := r.issuer.callCount(); n != 2 {
		t.Errorf("%d attempts, want 2", n)
	}
	if st := r.m.Status("web.example.com"); st.Issuing {
		t.Error("the domain is left issuing")
	}
	done := make(chan error, 1)
	go func() {
		_, err := issue()
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrBackoff) {
			t.Errorf("Issue again = %v, want ErrBackoff", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Issue again blocks: the flight was never released")
	}
}

func TestRenewSaysOnceThatItsContextEnded(t *testing.T) {
	r := newRig(t)
	for _, d := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if err := r.m.Issue(t.Context(), d, "", CloudflareToken(testToken)); err != nil {
			t.Fatal(err)
		}
	}
	r.clock.add(80 * 24 * time.Hour) // all three are due
	ctx, cancel := context.WithCancel(t.Context())
	r.issuer.mu.Lock()
	// a.example.com fails twice; the issuance of b.example.com is cut short
	// by the end of the context; c.example.com is not reached.
	n := len(r.issuer.calls)
	r.issuer.errs = make([]error, n+3)
	r.issuer.errs[n], r.issuer.errs[n+1], r.issuer.errs[n+2] = errors.New("refused"), errors.New("refused"), errors.New("cut short")
	r.issuer.onCall = func(domain string) {
		if domain == "b.example.com" {
			cancel()
		}
	}
	r.issuer.mu.Unlock()
	err := r.m.Renew(ctx)
	if err == nil || !strings.Contains(err.Error(), "a.example.com") {
		t.Fatalf("Renew = %v, want the failure of a.example.com", err)
	}
	if got := strings.Count(err.Error(), context.Canceled.Error()); got != 1 {
		t.Errorf("Renew = %q: the end of the context is said %d times, want once", err, got)
	}
	for _, c := range r.issuer.callList()[n:] {
		if c.domain == "c.example.com" {
			t.Error("c.example.com was tried after the context ended")
		}
	}
}

func TestRenewKeepsItsErrorsWhenItsContextEnds(t *testing.T) {
	r := newRig(t)
	for _, d := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if err := r.m.Issue(t.Context(), d, "", CloudflareToken(testToken)); err != nil {
			t.Fatal(err)
		}
	}
	r.clock.add(80 * 24 * time.Hour) // all three are due
	ctx, cancel := context.WithCancel(t.Context())
	r.issuer.mu.Lock()
	// a.example.com fails twice; the context ends as b.example.com gets its
	// certificate, before c.example.com.
	r.issuer.errs = make([]error, len(r.issuer.calls)+2)
	r.issuer.errs[len(r.issuer.calls)], r.issuer.errs[len(r.issuer.calls)+1] = errors.New("refused"), errors.New("refused")
	r.issuer.onDone = cancel
	r.issuer.mu.Unlock()
	err := r.m.Renew(ctx)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "a.example.com") {
		t.Errorf("Renew = %v, want the failure of a.example.com and the end of the context", err)
	}
}

func TestIssueRunsOneIssuancePerDomain(t *testing.T) {
	r := newRig(t)
	r.issuer.block = make(chan struct{})
	r.issuer.started = make(chan string, 10)
	const n = 5
	errs := make(chan error, n)
	for range n {
		go func() { errs <- r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)) }()
	}
	select {
	case <-r.issuer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("no issuance started")
	}
	if st := r.m.Status("web.example.com"); !st.Issuing || st.Reason() != "a certificate is being issued" {
		t.Errorf("Status during the issuance = %+v", st)
	}
	time.Sleep(50 * time.Millisecond) // the other callers have had their chance to start one
	close(r.issuer.block)
	for range n {
		select {
		case err := <-errs:
			if err != nil {
				t.Errorf("Issue: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a caller did not return")
		}
	}
	if got := r.issuer.callCount(); got != 1 {
		t.Errorf("%d issuances for one domain, want 1", got)
	}
	if got := r.events.kinds(); !slices.Equal(got, []string{EventCertIssued}) {
		t.Errorf("events = %q", got)
	}
	if st := r.m.Status("web.example.com"); st.Issuing {
		t.Error("still issuing")
	}
}

func TestIssueRunsDomainsAtTheSameTime(t *testing.T) {
	r := newRig(t)
	r.issuer.block = make(chan struct{})
	r.issuer.started = make(chan string, 2)
	errs := make(chan error, 2)
	for _, d := range []string{"a.example.com", "b.example.com"} {
		go func() { errs <- r.m.Issue(t.Context(), d, "", CloudflareToken(testToken)) }()
	}
	for range 2 {
		select {
		case <-r.issuer.started:
		case <-time.After(5 * time.Second):
			t.Fatal("the issuances of two domains do not run at the same time")
		}
	}
	close(r.issuer.block)
	for range 2 {
		if err := <-errs; err != nil {
			t.Errorf("Issue: %v", err)
		}
	}
}

func TestIssueEndsWithItsContext(t *testing.T) {
	r := newRig(t)
	r.issuer.block = make(chan struct{})
	r.issuer.started = make(chan string, 1)
	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() { errc <- r.m.Issue(ctx, "web.example.com", "", CloudflareToken(testToken)) }()
	<-r.issuer.started
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Issue = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Issue did not end with its context")
	}
	if got := r.events.kinds(); len(got) != 0 {
		t.Errorf("events = %q: an issuance cut short is not a failed one", got)
	}
	if st := r.m.Status("web.example.com"); st.LastError != "" || st.Issuing {
		t.Errorf("Status = %+v", st)
	}

	// Also in the pause before the retry.
	r2 := newRig(t)
	r2.m.retryAfter = time.Hour
	r2.issuer.errs = []error{errors.New("first")}
	ctx2, cancel2 := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel2()
	start := time.Now()
	if err := r2.m.Issue(ctx2, "web.example.com", "", CloudflareToken(testToken)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Issue = %v, want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Issue waited %v for its retry after its context ended", d)
	}
}

func TestIssueKeepsACertificateThatArrivesAsItsContextEnds(t *testing.T) {
	// Another certificate would count against the limits of the CA: the one
	// issued is written although the caller is gone.
	r := newRig(t)
	ctx, cancel := context.WithCancel(t.Context())
	r.issuer.onDone = cancel
	if err := r.m.Issue(ctx, "web.example.com", "", CloudflareToken(testToken)); err != nil {
		t.Fatalf("Issue = %v", err)
	}
	if ctx.Err() == nil {
		t.Fatal("the context did not end")
	}
	if st := r.m.Status("web.example.com"); !st.Valid {
		t.Errorf("the certificate was not written: %+v", st)
	}
	if got := r.events.kinds(); !slices.Equal(got, []string{EventCertIssued}) {
		t.Errorf("events = %q", got)
	}
}

func TestWriteFilesLeavesTheOldFilesWhenOneCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("old "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The second file cannot be staged (its temporary name would leave dir):
	// the first, staged already, is not renamed over the old one.
	err := writeFiles(dir, []newFile{{"a", []byte("new a"), 0o600}, {"sub/b", []byte("new b"), 0o600}})
	if err == nil {
		t.Fatal("writeFiles went through")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{"a", "b"}) {
		t.Errorf("the directory holds %q, want the old files and no temporary one", names)
	}
	for _, name := range []string{"a", "b"} {
		if got, _ := os.ReadFile(filepath.Join(dir, name)); string(got) != "old "+name {
			t.Errorf("%s = %q, want the old content", name, got)
		}
	}

	// All of them can be written: all are replaced, with their modes.
	if err := writeFiles(dir, []newFile{{"a", []byte("new a"), 0o600}, {"b", []byte("new b"), 0o644}}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{"a": 0o600, "b": 0o644} {
		if got, _ := os.ReadFile(filepath.Join(dir, name)); string(got) != "new "+name {
			t.Errorf("%s = %q", name, got)
		}
		if got := mode(t, filepath.Join(dir, name)); got != want {
			t.Errorf("%s has mode %v, want %v", name, got, want)
		}
	}
}

func TestACallerTakesOverAnIssuanceThatWasGivenUp(t *testing.T) {
	r := newRig(t)
	r.issuer.block = make(chan struct{})
	r.issuer.started = make(chan string, 2)
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() { first <- r.m.Issue(ctx, "web.example.com", "", CloudflareToken(testToken)) }()
	<-r.issuer.started
	second := make(chan error, 1)
	go func() { second <- r.m.Issue(t.Context(), "web.example.com", "", CloudflareToken(testToken)) }()
	time.Sleep(50 * time.Millisecond) // the second waits for the first
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Errorf("first = %v", err)
	}
	select {
	case <-r.issuer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the second caller did not run the issuance anew")
	}
	close(r.issuer.block)
	if err := <-second; err != nil {
		t.Errorf("second = %v", err)
	}
	if st := r.m.Status("web.example.com"); !st.Valid {
		t.Errorf("Status = %+v", st)
	}
}

func TestRenewRenewsWhatIsDue(t *testing.T) {
	r := newRig(t)
	r.issuer.life["long.example.com"] = 365 * 24 * time.Hour
	for _, d := range []string{"short.example.com", "long.example.com", "gone.example.com"} {
		if err := r.m.Issue(t.Context(), d, "first@example.com", CloudflareToken("first-token")); err != nil {
			t.Fatal(err)
		}
	}
	// Issue again with what renewals are to use.
	if err := r.m.Issue(t.Context(), "short.example.com", "second@example.com", CloudflareToken("second-token")); err != nil {
		t.Fatal(err)
	}
	r.m.Forget("gone.example.com")
	if n := r.issuer.callCount(); n != 3 {
		t.Fatalf("%d issuances", n)
	}
	if err := r.m.Renew(t.Context()); err != nil {
		t.Fatalf("Renew with nothing due: %v", err)
	}
	if n := r.issuer.callCount(); n != 3 {
		t.Errorf("Renew issued with nothing due (%d issuances)", n)
	}

	r.clock.add(65 * 24 * time.Hour) // 24 days left of the 90-day certificates
	if err := r.m.Renew(t.Context()); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	calls := r.issuer.callList()[3:]
	if len(calls) != 1 || calls[0].domain != "short.example.com" || calls[0].email != "second@example.com" || calls[0].token != "second-token" {
		t.Errorf("renewals = %+v, want short.example.com only, with the last email and credential", calls)
	}
	evs := r.events.all()
	if last := evs[len(evs)-1]; last.GetKind() != EventCertIssued || last.GetDetails()["reason"] != "the certificate was due for renewal" {
		t.Errorf("the last event = %v", last)
	}

	// A renewal that fails is reported by Renew.
	r.clock.add(300 * 24 * time.Hour)
	r.issuer.mu.Lock()
	r.issuer.errs = make([]error, len(r.issuer.calls)+4)
	for i := len(r.issuer.calls); i < len(r.issuer.errs); i++ {
		r.issuer.errs[i] = errors.New("no")
	}
	r.issuer.mu.Unlock()
	if err := r.m.Renew(t.Context()); err == nil || !strings.Contains(err.Error(), "long.example.com") || !strings.Contains(err.Error(), "short.example.com") {
		t.Errorf("Renew = %v, want the failures of both", err)
	}
}

func TestTheCredentialNeverShows(t *testing.T) {
	cred := CloudflareToken(testToken)
	var printed []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		printed = append(printed, fmt.Sprintf(verb, cred), fmt.Sprintf(verb, struct{ C Credential }{cred}),
			fmt.Sprintf(verb, &cred))
	}
	printed = append(printed, cred.String(), fmt.Sprint(cred), fmt.Sprintln(cred))
	js, err := json.Marshal(struct{ C Credential }{cred})
	if err != nil {
		t.Fatal(err)
	}
	printed = append(printed, string(js))
	var logs syncBuffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("text", "cred", cred)
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("json", "cred", cred, "in", struct{ C Credential }{cred})
	printed = append(printed, logs.String())
	for _, s := range printed {
		if strings.Contains(s, testToken) {
			t.Errorf("the credential shows: %s", s)
		}
	}

	// In an unexported field, fmt and slog do not call its methods: the
	// structs of the manager that hold one must not show it either.
	held := map[string]any{
		"tracked":              tracked{email: "admin@example.com", cred: cred},
		"*tracked":             &tracked{email: "admin@example.com", cred: cred},
		"in an exported field": struct{ T tracked }{tracked{cred: cred}},
		"the provider":         newCloudflare(cred, &http.Client{}, "https://192.0.2.1/client/v4"),
	}
	for label, v := range held {
		var out []string
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
			out = append(out, fmt.Sprintf(verb, v))
		}
		var logs syncBuffer
		slog.New(slog.NewTextHandler(&logs, nil)).Info("text", "v", v)
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("json", "v", v)
		out = append(out, logs.String())
		for _, s := range out {
			if strings.Contains(s, testToken) || strings.Contains(s, hex.EncodeToString([]byte(testToken))) {
				t.Errorf("%s: the credential shows: %s", label, s)
			}
		}
	}

	// An issuance whose error holds the credential: it never gets out.
	r := newRig(t)
	leak := fmt.Errorf("the server said: bad token %s", testToken)
	r.issuer.errs = []error{leak, leak}
	err = r.m.Issue(t.Context(), "web.example.com", "", cred)
	st := r.m.Status("web.example.com")
	out := []string{err.Error(), st.LastError, st.Reason(), r.log.String()}
	for _, ev := range r.events.all() {
		out = append(out, ev.GetMessage(), fmt.Sprint(ev.GetDetails()))
	}
	for _, s := range out {
		if strings.Contains(s, testToken) {
			t.Errorf("the credential got out: %s", s)
		}
	}
	if !strings.Contains(st.LastError, "bad token [redacted]") {
		t.Errorf("LastError = %q", st.LastError)
	}
}

func TestIssueRefusesNamesThatAreNotDomains(t *testing.T) {
	r := newRig(t)
	for _, d := range []string{
		"", "example", "web.example.com.", "Web.Example.com", "*.example.com", "../example.com", "web/../../x.example.com",
		"192.0.2.1", "web..example.com", "-web.example.com", "web-.example.com", "web_x.example.com", "web.example.123",
		"wéb.example.com", "web.example.com/x", strings.Repeat("a", 64) + ".example.com", strings.Repeat("a.", 127) + "com",
	} {
		if err := r.m.Issue(t.Context(), d, "", CloudflareToken(testToken)); err == nil {
			t.Errorf("Issue(%q) went through", d)
		}
		if st := r.m.Status(d); st.Valid || st.Problem == "" {
			t.Errorf("Status(%q) = %+v", d, st)
		}
	}
	if n := r.issuer.callCount(); n != 0 {
		t.Errorf("%d issuances", n)
	}
	if _, err := os.Stat(r.m.Paths.CertsDir()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("something was written: %v", err)
	}
	for _, d := range []string{"web.example.com", "a-b.example.com", "xn--80ak6aa92e.example.com", "1.example.com", "example.com", "x.y.z.example.test"} {
		if err := validDomain(d); err != nil {
			t.Errorf("validDomain(%q) = %v", d, err)
		}
	}
}

func TestStatusReason(t *testing.T) {
	tests := []struct {
		st   Status
		want string
	}{
		{Status{Valid: true}, ""},
		{Status{Valid: true, Issuing: true}, ""},
		{Status{Valid: true, LastError: "boom"}, "the renewal of the certificate failed: boom"},
		{Status{Issuing: true, Problem: "no certificate", LastError: "boom"}, "a certificate is being issued"},
		{Status{Problem: "no certificate", LastError: "boom"}, "no valid certificate: boom"},
		{Status{Problem: "no certificate"}, "no valid certificate: no certificate"},
	}
	for _, tt := range tests {
		if got := tt.st.Reason(); got != tt.want {
			t.Errorf("%+v: Reason = %q, want %q", tt.st, got, tt.want)
		}
	}
}

func TestReasonOf(t *testing.T) {
	cred := CloudflareToken(testToken)
	long := strings.Repeat("é", 400)
	tests := []struct {
		err  error
		want string
	}{
		{errors.New("error: one or more domains had a problem:\n[web.example.com] acme: error presenting token: x\n"), "acme: error presenting token: x"},
		{errors.New("error: one or more domains had a problem:\nweb.example.com: acme: error: 429 :: rate limited"), "acme: error: 429 :: rate limited"},
		{errors.New("a\n\tb   c " + testToken), "a b c [redacted]"},
	}
	for _, tt := range tests {
		if got := reasonOf(tt.err, "web.example.com", cred); got != tt.want {
			t.Errorf("reasonOf(%q) = %q, want %q", tt.err, got, tt.want)
		}
	}
	got := reasonOf(errors.New(long), "web.example.com", cred)
	if len(got) > maxReason || !strings.HasSuffix(got, "…") || !utf8.ValidString(got) {
		t.Errorf("a long reason is %d bytes: %q", len(got), got)
	}
}
