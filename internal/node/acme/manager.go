// Package acme issues and renews the certificates of the WEB proxies of a node
// with ACME, by the DNS-01 challenge only (TLS-ALPN-01 is in the backlog),
// through lego.
//
// A certificate lives in data/certs/<domain>/: fullchain.pem (the chain as the
// CA returned it, leaf first), privkey.pem (its key, 0600) and meta.json
// ({expiresAt, issuedAt, staging}), written together, each atomically.
// Certificates already there are taken as they are, and the edge loads them
// from there. The key of the node's ACME account
// is in data/acme/account.json (0600): one account for every domain.
//
// An issuance writes the TXT record _acme-challenge.<domain> through the DNS
// provider (Cloudflare: the zone is the active one of the longest suffix of
// the domain, the TTL is 60 s), after it has removed the TXT records that
// earlier attempts left at that name, and asks the CA to look only once the
// record is visible at Cloudflare and at Google, at both, over
// DNS-over-HTTPS. UDP port 53 is blocked on some nodes: neither lego nor the
// manager ever asks the resolver of the system, for the challenge or for the
// host names of the ACME server and of the Cloudflare API, which are looked up
// over DNS-over-HTTPS as well. The record is deleted afterwards, whatever came
// of the issuance; no other DNS record is ever deleted.
//
// To keep lego off the resolver of the system, the manager empties the list
// of nameservers that lego's DNS client keeps in a package variable: any DNS
// query of lego fails at once, without a packet. That holds for lego's own DNS
// providers too, and most of them look up the zone of a domain with
// dns01.FindZoneByFqdn, which then fails (122 of the 195 providers of lego
// v4.35.2, with the shared code they use). None of those can be plugged in as
// they are: a DNS provider other than the Cloudflare one of this package needs
// a way to find its zone over DNS-over-HTTPS first.
//
// One issuance per domain runs at a time: the callers for a domain wait for
// the one that runs and share its result. An issuance that fails is tried once
// more 10 s later. When that fails as well, cert_failed is reported and the
// domain is not tried again before a pause that grows with every failure in a
// row, from 10 minutes to 6 hours, unless it is asked for with another email
// address or credential. A certificate is renewed once it has at most 30 days
// left, or half its lifetime when that is shorter (Ruling S3-3), and issued
// again, valid or not, when the reissue nonce of its domain (SetReissueNonce,
// WebSettings.reissue_nonce) differs from the one meta.json records: the fix
// reissue_cert of the diagnostics. The nonce asked for is part of what tells
// the tries apart, so a new one is tried at once, whatever the pause.
package acme

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-acme/lego/v4/acme"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/doh"
	"github.com/urbnywrt/postern/internal/node/state"
)

const (
	// RenewBefore is how long before it expires a certificate is renewed;
	// half its lifetime when that is shorter (Ruling S3-3, see renewAt).
	RenewBefore = 30 * 24 * time.Hour
	// RenewEvery is how often the agent is meant to call Renew: every 12
	// hours, the first time a minute after its start.
	RenewEvery = 12 * time.Hour
	// RetryAfter is the pause before the one retry of an issuance that failed.
	RetryAfter = 10 * time.Second
	// HTTPTimeout bounds every request to the ACME server and to the
	// Cloudflare API.
	HTTPTimeout = 30 * time.Second

	// attempts is how many times an issuance is tried before it fails.
	attempts = 2
	// minBackoff and maxBackoff bound the pause after a failed issuance: it is
	// minBackoff after the first failure in a row and doubles with each. A
	// new certificate that is due at once (a wrong clock) waits maxBackoff
	// from the start.
	minBackoff = 10 * time.Minute
	maxBackoff = 6 * time.Hour
	// maxRetryAfter is the longest the domain waits for a rate limit of the
	// CA, whatever its Retry-After says: the longest window of Let's
	// Encrypt's limits. Half the validity left of the certificate served is
	// shorter, when it is (rateLimitedUntil).
	maxRetryAfter = 7 * 24 * time.Hour
	// maxReason bounds the text of a failure, in bytes.
	maxReason = 300
)

// The ACME directories of Let's Encrypt.
const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Event kinds. Their details carry the domain and a short reason, never a
// credential or a key.
const (
	EventCertIssued = "cert_issued"
	EventCertFailed = "cert_failed"

	sevInfo    = "info"
	sevWarning = "warning"
	sevError   = "error"
)

// ErrBackoff is, as errors.Is tells it, the error of an Issue that did not try:
// the last issuance of the domain failed, with the same email address and
// credential, and its pause has not ended. The pause is 10 minutes after the
// first failure in a row and doubles with each, up to 6 hours; 6 hours from
// the start after a new certificate that was due at once (a wrong clock); and
// for a rate limit of the CA, its Retry-After, but never more than 7 days, nor
// than half the validity left of the certificate served. That clamp has the
// normal pause as its floor: a Retry-After shorter than the pause of the
// failure, or clamped below it, waits the pause.
var ErrBackoff = errors.New("acme: the last issuance of the domain failed, and its pause has not ended")

// Credential is the secret with which the DNS provider writes the TXT records
// of a domain: for Cloudflare, an API token with the permission Zone:DNS:Edit
// on the zone of the domain. It never shows: fmt and slog print it as
// [redacted], encoding/json sees no field of it, and the errors of the manager
// never hold it. In a field that is not exported, where fmt and slog print a
// value by reflection without calling its methods, the token does not show
// either: it is held by a closure, and a func is printed as its address,
// whatever the verb and however deep, with nothing of what it holds. (A
// pointer would not do: for a verb such as %s, fmt prints a pointer that it
// cannot format as what it points to.)
type Credential struct {
	get func() string // nil for the zero Credential
}

// CloudflareToken is the credential of a Cloudflare API token.
func CloudflareToken(token string) Credential {
	return Credential{get: func() string { return token }}
}

const redacted = "[redacted]"

// String is [redacted].
func (Credential) String() string { return redacted }

// Format prints [redacted], whatever the verb.
func (Credential) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue is [redacted].
func (Credential) LogValue() slog.Value { return slog.StringValue(redacted) }

// token is the secret itself; "" for the zero Credential.
func (c Credential) token() string {
	if c.get == nil {
		return ""
	}
	return c.get()
}

// scrub takes the secret out of s.
func (c Credential) scrub(s string) string {
	if c.token() == "" {
		return s
	}
	return strings.ReplaceAll(s, c.token(), redacted)
}

// Manager issues and renews certificates. Set the fields, then call its
// methods, from any goroutine; do not change the fields after the first call.
type Manager struct {
	// Paths is the node's layout: the certificates are in Paths.CertsDir(),
	// the ACME account in data/acme/account.json.
	Paths state.Paths
	// Staging takes the certificates from the staging directory of Let's
	// Encrypt, which browsers do not trust: for tests. meta.json says which
	// directory a certificate is from, and a certificate from the other one is
	// due for renewal.
	Staging bool
	// Directory is the URL of the ACME directory; empty means Let's Encrypt,
	// or its staging directory under Staging.
	Directory string
	// RootCAs verify the certificates of the ACME server, of the Cloudflare
	// API and of PropagationEndpoints; nil means the roots of the system.
	RootCAs *x509.CertPool
	// LookupIP resolves the host names of the ACME server and of the
	// Cloudflare API; nil means DNS-over-HTTPS, at doh.DefaultEndpoints.
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
	// PropagationEndpoints are the providers at which the TXT record of a
	// challenge must be visible, at every one of them, before the CA is asked
	// to look: each a group of DNS-over-HTTPS endpoints, asked through a
	// client of its own that fails over among them on errors only. None means
	// Cloudflare (1.1.1.1, 1.0.0.1) and Google (8.8.8.8, 8.8.4.4).
	PropagationEndpoints [][]string
	// DNS returns the DNS provider of an issuance; nil means Cloudflare.
	DNS func(Credential) (DNSProvider, error)
	// Events receives the events cert_issued and cert_failed; nil drops them.
	Events func(*nodev1.NodeEvent)
	// Log receives the log of the manager; nil discards it. Nothing secret is
	// logged.
	Log *slog.Logger
	// Now is the clock of the renewals; nil means time.Now.
	Now func() time.Time

	// Tuning; zero means the default. Tests shorten them.
	propagationTimeout time.Duration
	firstPoll          time.Duration
	pollInterval       time.Duration
	retryAfter         time.Duration
	// obtain stands in for obtainLego in tests.
	obtain func(ctx context.Context, domain, email string, cred Credential) (*issued, error)
	// cloudflareAPI is the base URL of the Cloudflare API; "" is the real one.
	cloudflareAPI string

	once      sync.Once
	transport *http.Transport
	lookupIP  func(ctx context.Context, host string) ([]netip.Addr, error)
	checker   *checker
	accountMu sync.Mutex // account.json

	mu       sync.Mutex
	flights  map[string]*flight   // by domain: the issuance that runs
	tracked  map[string]tracked   // by domain: what Renew renews with
	failures map[string]*failure  // by domain: the last failed issuance
	nonces   map[string]uint64    // by domain: the reissue nonce asked for; none is 0
	touched  map[string]time.Time // by domain: when a certificate was last put or issued for it
}

// Touched returns when a certificate was last put or issued for domain since
// the manager started (zero: never). A caller that removes unused
// certificates counts its grace from it.
func (m *Manager) Touched(domain string) time.Time {
	m.init()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.touched[domain]
}

// touch notes that a certificate is put or issued for domain now.
func (m *Manager) touch(domain string) {
	now := m.now()
	m.mu.Lock()
	m.touched[domain] = now
	m.mu.Unlock()
}

// tracked is what the certificate of a domain is renewed with.
type tracked struct {
	email string
	cred  Credential
}

// flight is an issuance that runs, which the callers for its domain wait for.
type flight struct {
	done chan struct{}
	err  error
	// abandoned: the context of the caller that ran it ended. A caller whose
	// context lives on runs the issuance anew.
	abandoned bool
}

// failure is the last issuance of a domain that failed, and the ones before
// it in a row.
type failure struct {
	key     string // of the email address and the credential it was tried with
	count   int
	at      time.Time
	retryAt time.Time
	reason  string
}

// ProblemNoCertificate is Status.Problem when data/certs/<domain> has no
// certificate at all (as against one that cannot be served).
const ProblemNoCertificate = "no certificate"

// Status is what the manager knows of the certificate of a domain.
type Status struct {
	Domain string
	// Valid reports whether data/certs/<domain> holds a certificate that can
	// be served: it is for the domain, its key matches it, and it is within
	// its validity period.
	Valid bool
	// Problem says why there is no valid certificate ("no certificate", "the
	// certificate expired at ..."); "" when Valid.
	Problem string
	// NotAfter is when the certificate expires, RenewAt when it is due for
	// renewal; both are zero without a certificate.
	NotAfter time.Time
	RenewAt  time.Time
	// IssuedAt and Staging are from meta.json: when the certificate was
	// issued, and whether it is from a staging directory.
	IssuedAt time.Time
	Staging  bool
	// FullchainSHA256 is the SHA-256 digest of fullchain.pem in lowercase hex;
	// a new certificate has a new one.
	FullchainSHA256 string
	// Issuer names the issuer of the certificate (its common name); "" without
	// a certificate that can be read.
	Issuer string
	// ReissueNonce is the reissue nonce meta.json records (0 for none).
	ReissueNonce uint64
	// Due reports whether the next Issue or Renew issues a certificate: there
	// is no valid one, it is due for renewal, it is not from the directory
	// of the manager (staging or not), or it records another reissue nonce
	// than the non-zero one SetReissueNonce asked for.
	Due bool
	// Issuing reports whether an issuance of the domain runs.
	Issuing bool
	// LastError is why the last issuance of the domain failed, on one line and
	// without secrets; "" when it succeeded, or when none has failed since the
	// agent started. FailedAt is when it failed, RetryAt when Issue tries again
	// with the same email address and credential.
	LastError string
	FailedAt  time.Time
	RetryAt   time.Time
}

// Reason is the text for ProxyStatus.reason: what keeps the domain from a
// certificate, or what went wrong with the renewal of the one it has; "" when
// all is well.
func (s Status) Reason() string {
	switch {
	case s.Valid && s.LastError != "":
		return "the renewal of the certificate failed: " + s.LastError
	case s.Valid:
		return ""
	case s.Issuing:
		return "a certificate is being issued"
	case s.LastError != "":
		return "no valid certificate: " + s.LastError
	}
	return "no valid certificate: " + s.Problem
}

// init sets up what the fields leave to the manager, once.
func (m *Manager) init() {
	m.once.Do(func() {
		setupLego()
		legoLogger.Store(m.log())
		m.transport = m.newTransport()
		m.lookupIP = m.LookupIP
		if m.lookupIP == nil {
			m.lookupIP = doh.New(doh.DefaultEndpoints).LookupIP
		}
		endpoints := m.PropagationEndpoints
		if len(endpoints) == 0 { // the check is never left out
			endpoints = defaultPropagationEndpoints()
		}
		m.checker = newChecker(endpoints, m.RootCAs)
		m.flights = map[string]*flight{}
		m.tracked = map[string]tracked{}
		m.failures = map[string]*failure{}
		m.nonces = map[string]uint64{}
		m.touched = map[string]time.Time{}
	})
}

// Issue makes sure that domain has a valid certificate that is not due for
// renewal, and issues one when it has not. It returns at once when it has one,
// and with ErrBackoff when the last issuance of the domain failed with the
// same email address and credential and the pause of that failure (see
// ErrBackoff) has not ended; otherwise it returns when the issuance has
// ended, which takes minutes at the most. An issuance of the domain that runs
// already is waited for, not doubled.
//
// A caller that waits for the issuance of another returns as soon as its ctx
// ends. The caller that runs the issuance returns when the issuance stops,
// which can be tens of seconds after its ctx ended: the pauses of lego between
// its polls of the CA do not see the context, only its requests do. The
// issuance of a caller whose ctx ended is not lost on those who wait for it:
// one of them, whose ctx lives on, takes it over and runs it anew.
//
// The domain is kept for Renew, with email and cred, until Forget. email is
// the contact of the ACME account when it is made; it may be empty.
func (m *Manager) Issue(ctx context.Context, domain, email string, cred Credential) error {
	m.init()
	if err := validDomain(domain); err != nil {
		return fmt.Errorf("acme: %w", err)
	}
	m.mu.Lock()
	m.tracked[domain] = tracked{email: email, cred: cred}
	m.mu.Unlock()
	m.touch(domain)
	return m.ensure(ctx, domain, email, cred)
}

// Renew renews the certificates that are due, of the domains that Issue was
// called for since the agent started and that were not forgotten since, one
// after the other, as Issue does. It returns the errors of those that failed
// or were still in the pause of a failure (ErrBackoff), and the error of ctx,
// once, whenever ctx has ended when it returns.
func (m *Manager) Renew(ctx context.Context) error {
	m.init()
	m.mu.Lock()
	domains := slices.Sorted(maps.Keys(m.tracked))
	m.mu.Unlock()
	var errs []error
	for _, domain := range domains {
		if ctx.Err() != nil {
			break
		}
		m.mu.Lock()
		t, ok := m.tracked[domain]
		m.mu.Unlock()
		if !ok {
			continue
		}
		err := m.ensure(ctx, domain, t.email, t.cred)
		switch {
		case err == nil:
		case ctx.Err() != nil && errors.Is(err, ctx.Err()):
			// Cut short by the end of ctx, which is said once, below.
		default:
			errs = append(errs, err)
		}
	}
	if err := ctx.Err(); err != nil {
		errs = append(errs, err) // with what failed before it
	}
	return errors.Join(errs...)
}

// Forget stops renewing the certificate of domain, and forgets its failures
// and its reissue nonce. The files of the certificate stay.
func (m *Manager) Forget(domain string) {
	m.init()
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tracked, domain)
	delete(m.failures, domain)
	delete(m.nonces, domain)
}

// SetReissueNonce sets the reissue nonce of domain (WebSettings.reissue_nonce):
// while it is not 0 and differs from the one recorded with the certificate on disk, the
// certificate is due (Status.Due), and the next Issue or Renew issues a new
// one, also when the one on disk is valid; 0 asks for nothing. One issuance of a domain runs at a
// time, as always. The nonce is recorded in meta.json with the new
// certificate, so an agent that starts again with the same nonce does not
// issue again. Call it before Status and Issue.
func (m *Manager) SetReissueNonce(domain string, nonce uint64) {
	m.init()
	m.mu.Lock()
	defer m.mu.Unlock()
	if nonce == 0 {
		delete(m.nonces, domain)
		return
	}
	m.nonces[domain] = nonce
}

// reissueNonce is the reissue nonce asked for domain.
func (m *Manager) reissueNonce(domain string) uint64 {
	m.init()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nonces[domain]
}

// Status reports on the certificate of domain: the one on disk (also one that
// the manager did not issue), and the issuances.
func (m *Manager) Status(domain string) Status {
	m.init()
	st := m.inspect(domain, m.now())
	m.mu.Lock()
	defer m.mu.Unlock()
	_, st.Issuing = m.flights[domain]
	if f := m.failures[domain]; f != nil {
		st.LastError, st.FailedAt, st.RetryAt = f.reason, f.at, f.retryAt
	}
	return st
}

// ensure runs the issuance of domain, or waits for the one that runs.
func (m *Manager) ensure(ctx context.Context, domain, email string, cred Credential) error {
	if st := m.inspect(domain, m.now()); !st.Due {
		m.mu.Lock()
		delete(m.failures, domain) // whatever failed before, the certificate is good
		m.mu.Unlock()
		return nil
	}
	for {
		m.mu.Lock()
		if f := m.flights[domain]; f != nil {
			m.mu.Unlock()
			select {
			case <-f.done:
				if f.abandoned && ctx.Err() == nil {
					continue // the one that ran it gave up: run it anew
				}
				return f.err
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		f := &flight{done: make(chan struct{})}
		m.flights[domain] = f
		m.mu.Unlock()
		return m.lead(ctx, f, domain, email, cred)
	}
}

// errIssuancePanicked is what those who wait for an issuance that panicked
// get, should even its failure not be reported.
var errIssuancePanicked = errors.New("acme: internal error in the issuance")

// lead runs the issuance of flight f. The flight ends whatever happens, a
// panic included: the domain is never left issuing, and those who wait for
// it get an error. A panic is a failure as well, with its pause, so that one
// that comes again at every call is not met at every call; its text, which
// could carry data, is not kept. The panic goes on to the caller.
func (m *Manager) lead(ctx context.Context, f *flight, domain, email string, cred Credential) error {
	// The release is deferred first, so that it runs last, whatever the
	// report of a panic below does (Events or the log may panic as well).
	defer func() {
		m.mu.Lock()
		delete(m.flights, domain)
		m.mu.Unlock()
		close(f.done)
	}()
	ended := false
	nonce := m.reissueNonce(domain)
	defer func() {
		if !ended {
			f.err = errIssuancePanicked // set before failed, which may panic itself
			_ = m.failed(domain, attemptKey(email, cred, nonce), m.inspectFor(domain, m.now(), nonce),
				"internal error in the issuance", 0, time.Time{})
		}
	}()
	abandoned, err := m.issue(ctx, domain, email, cred, nonce)
	f.err, f.abandoned, ended = err, abandoned, true
	return err
}

// issue issues the certificate of domain when it is due and the domain is not
// in its pause after a failure: two attempts, RetryAfter apart. nonce is the
// reissue nonce asked for when the issuance began; the new certificate records
// it (a nonce set meanwhile makes it due again, for the next call). abandoned
// reports that it stopped because ctx ended.
func (m *Manager) issue(ctx context.Context, domain, email string, cred Credential, nonce uint64) (abandoned bool, err error) {
	before := m.inspectFor(domain, m.now(), nonce)
	if !before.Due {
		return false, nil // issued by the flight that just ended
	}
	key := attemptKey(email, cred, nonce)
	m.mu.Lock()
	f := m.failures[domain]
	if f != nil && f.key == key && m.now().Before(f.retryAt) {
		m.mu.Unlock()
		return false, fmt.Errorf("%w (%s): the next try is at %s", ErrBackoff, f.reason,
			f.retryAt.UTC().Format(time.RFC3339))
	}
	m.mu.Unlock()
	if cred.token() == "" {
		return false, m.failed(domain, key, before, "no DNS credential", 0, time.Time{})
	}

	obtain := m.obtain
	if obtain == nil {
		obtain = m.obtainLego
	}
	var reason string
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			wait := orDefault(m.retryAfter, RetryAfter)
			m.log().Warn("acme: the issuance failed; it is tried once more", "domain", domain, "in", wait, "err", reason)
			if !sleep(ctx, wait) {
				return true, ctx.Err()
			}
		}
		m.log().Info("acme: issuing a certificate", "domain", domain, "attempt", attempt, "staging", m.Staging)
		is, err := obtain(ctx, domain, email, cred)
		var leaf *x509.Certificate
		switch {
		case err == nil && is == nil:
			err = errors.New("the issuance brought no certificate")
		case err == nil:
			if leaf, err = certLeaf(is.fullchain, is.key, domain); err != nil {
				err = fmt.Errorf("the CA returned a certificate that cannot be used: %w", err)
			}
		}
		if err == nil {
			// Written also when ctx has just ended: the certificate is issued,
			// and another would count against the limits of the CA.
			record := nonce
			if record == 0 {
				record = before.ReissueNonce // a renewal keeps what the certificate recorded
			}
			if err := m.store(domain, is, leaf, m.now(), record); err != nil {
				// Not tried again: a new certificate would not be written either.
				return false, m.failed(domain, key, before, reasonOf(err, domain, cred), attempt, time.Time{})
			}
			after := m.inspectFor(domain, m.now(), nonce)
			if after.Due {
				// Issued again at every call it would be a duplicate, of which
				// the CA allows 5 a week, and a wrong clock stays wrong: it waits
				// the longest pause from the start.
				why := "renewal at " + after.RenewAt.UTC().Format(time.RFC3339)
				if after.Problem != "" {
					why = after.Problem
				}
				return false, m.failed(domain, key, before, "the new certificate is due at once ("+why+
					"): the clock of the node may be wrong", attempt, m.now().Add(maxBackoff))
			}
			m.issued(domain, before, after, nonce)
			return false, nil
		}
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		reason = reasonOf(err, domain, cred)
		var served time.Time // the end of the certificate that is served, if one is
		if before.Valid {
			served = before.NotAfter
		}
		if until, limited := rateLimitedUntil(err, m.now(), served); limited {
			// Not tried again 10 s later: the CA refuses until it says.
			return false, m.failed(domain, key, before, reason, attempt, until)
		}
	}
	return false, m.failed(domain, key, before, reason, attempts, time.Time{})
}

// rateLimitedUntil reports whether err is a rate limit of the CA, lego's
// *acme.RateLimitedError (looked for in the error itself, not in its text),
// and until when the domain waits for it: what its Retry-After says (seconds,
// or an HTTP date), but never longer than maxRetryAfter from now, nor, when a
// certificate is served until served, than half the validity it has left, so
// that it is tried again before it expires. It is zero when the CA said
// nothing that can be used (a time already past, zero, or not a time): the
// pause of a failure applies.
func rateLimitedUntil(err error, now, served time.Time) (time.Time, bool) {
	var rl *acme.RateLimitedError
	if !errors.As(err, &rl) {
		return time.Time{}, false
	}
	var until time.Time
	v := strings.TrimSpace(rl.RetryAfter)
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs > 0 { // bounded before it becomes a Duration, which it could overflow
			until = now.Add(time.Duration(min(secs, int64(maxRetryAfter/time.Second))) * time.Second)
		}
	} else if t, err := http.ParseTime(v); err == nil && t.After(now) {
		until = t
	}
	if until.IsZero() {
		return time.Time{}, true
	}
	limit := now.Add(maxRetryAfter)
	if served.After(now) {
		if half := now.Add(served.Sub(now) / 2); half.Before(limit) {
			limit = half
		}
	}
	if until.After(limit) {
		until = limit
	}
	return until, true
}

// issued reports a new certificate of domain, after on disk.
func (m *Manager) issued(domain string, before, after Status, nonce uint64) {
	m.mu.Lock()
	delete(m.failures, domain)
	m.mu.Unlock()
	why := before.Problem
	switch {
	case before.Valid && before.ReissueNonce != nonce:
		why = "a new certificate was asked for (reissue)"
	case before.Valid && before.Staging != m.Staging:
		why = "the certificate was from the other ACME directory"
	case before.Valid:
		why = "the certificate was due for renewal"
	}
	expires := after.NotAfter.UTC().Format(time.RFC3339)
	m.event(EventCertIssued, sevInfo, fmt.Sprintf("acme: certificate of %s issued, valid until %s", domain, expires),
		map[string]string{
			"domain":     domain,
			"reason":     why,
			"expires_at": expires,
			"staging":    strconv.FormatBool(m.Staging),
		})
}

// failed notes a failed issuance of domain, reports it, and returns its error.
// It is tried again after the pause of its failures in a row, and not before
// notBefore (the Retry-After of a rate limit; zero for none).
func (m *Manager) failed(domain, key string, before Status, reason string, tries int, notBefore time.Time) error {
	now := m.now()
	m.mu.Lock()
	f := m.failures[domain]
	if f == nil || f.key != key {
		f = &failure{key: key}
		m.failures[domain] = f
	}
	f.count++
	f.at, f.reason = now, reason
	f.retryAt = now.Add(backoff(f.count))
	if notBefore.After(f.retryAt) {
		f.retryAt = notBefore
	}
	m.mu.Unlock()
	severity := sevError
	if before.Valid {
		severity = sevWarning // the certificate it has is served until it expires
	}
	m.event(EventCertFailed, severity, fmt.Sprintf("acme: the certificate of %s could not be issued: %s", domain, reason),
		map[string]string{
			"domain":   domain,
			"reason":   reason,
			"attempts": strconv.Itoa(tries),
		})
	return fmt.Errorf("acme: %s: %s", domain, reason)
}

// backoff is the pause after the n-th failed issuance in a row.
func backoff(n int) time.Duration {
	d := minBackoff
	for i := 1; i < n && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}

// attemptKey tells apart the email addresses, credentials and reissue nonces
// a domain is tried with, without keeping a copy of the credential.
func attemptKey(email string, cred Credential, nonce uint64) string {
	sum := sha256.Sum256([]byte(email + "\x00" + cred.token() + "\x00" + strconv.FormatUint(nonce, 10)))
	return hex.EncodeToString(sum[:])
}

// reasonOf is the text of the error of an issuance for a status, an event or
// a log line: on one line, without the credential, without the domain that
// lego puts in front, and maxReason bytes at the most.
func reasonOf(err error, domain string, cred Credential) string {
	s := cred.scrub(err.Error())
	s = strings.TrimPrefix(s, "error: one or more domains had a problem:")
	s = strings.ReplaceAll(s, "["+domain+"] ", "")
	s = strings.Join(strings.Fields(s), " ")
	s = strings.TrimPrefix(s, domain+": ")
	return oneLine(s, maxReason)
}

// oneLine is s on one line, cut to limit bytes (on a character boundary, with
// an ellipsis).
func oneLine(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= limit {
		return s
	}
	cut := limit - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// validDomain checks that a certificate can be issued for domain, and that it
// can name its directory: a host name in lowercase ASCII without a dot at its
// end, of two labels at least and 253 bytes at the most, each label of letters,
// digits and inner hyphens, 63 bytes at the most, the last one not a number.
// That is no IP address, no wildcard, and nothing that leaves data/certs.
func validDomain(domain string) error {
	bad := fmt.Errorf("%q is not a domain name in lowercase ASCII", domain)
	if domain == "" || len(domain) > 253 {
		return bad
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return bad
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return bad
		}
		for i := range len(l) {
			if c := l[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return bad
			}
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return bad
	}
	return nil
}

// sleep waits for d, or until ctx ends: it reports whether it waited.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.New(slog.DiscardHandler)
}

// event logs an event and hands it to Events.
func (m *Manager) event(kind, severity, msg string, details map[string]string) {
	level := slog.LevelInfo
	switch severity {
	case sevWarning:
		level = slog.LevelWarn
	case sevError:
		level = slog.LevelError
	}
	m.log().Log(context.Background(), level, msg, "event", kind, "domain", details["domain"])
	if m.Events != nil {
		m.Events(&nodev1.NodeEvent{Kind: kind, Severity: severity, Message: msg, Details: details})
	}
}
