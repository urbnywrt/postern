package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/doh"
	"github.com/urbnywrt/postern/internal/node/acme"
	"github.com/urbnywrt/postern/internal/webrules"
)

// WEB proxies (slice 3, spec 5.4).
//
// A WEB proxy's engine instance is rendered like a fake-TLS one, with two
// things the reconciler supplies: the public address of its domain
// (webPublicAddr: the A record of the domain, resolved over DNS-over-HTTPS,
// that is one of the node's own public addresses) and, on a tls listener, a
// certificate that the edge serves for the domain. The route of such a proxy
// goes to the edge only while a valid certificate is on disk (webCerts; for
// cert_mode imported, the one whose SHA-256 the panel named, Ruling S3-1): a
// route without one would only answer unrecognized_name. On an http-upstream
// listener the web server in front owns the certificate, and the route is
// served as soon as the instance is.
//
// Certificates of cert_mode acme-dns01 are issued by the ACME manager
// (internal/node/acme), asynchronously: an issuance takes minutes, and a pass
// must not. Every pass asks for the certificate of every such proxy once per
// agent run (so the manager renews it), and again whenever it is due and not
// in the pause of a failure; a proxy that goes, or stops using ACME, is
// forgotten. The reason of a proxy that waits for its certificate is the
// manager's (acme.Status.Reason).

const (
	// webLookupTTL is how long the A records of a WEB domain are kept before
	// they are resolved again; webLookupGrace how long the last answer is used
	// when the lookups fail.
	webLookupTTL   = 5 * time.Minute
	webLookupGrace = time.Hour
	// webLookupTimeout bounds one lookup, webProbeTimeout one readiness
	// request to a new WEB generation.
	webLookupTimeout = 10 * time.Second
	webProbeTimeout  = 5 * time.Second
	// renewEvery is how often the certificates are checked for renewal.
	renewEvery = 12 * time.Hour
)

// webCert is what the pass knows of the certificate of a WEB domain (keyed by
// webrules.CertDomain): whether the edge may serve a route with it, the
// generation the edge reloads it by (from the digest of the chain: new files,
// new generation), and why not, for the proxy's status.
type webCert struct {
	ok     bool
	gen    uint64
	reason string
}

// webLookup is a cached resolution of a WEB domain.
type webLookup struct {
	addrs []netip.Addr
	at    time.Time
	err   error
}

func isWeb(pr *nodev1.Proxy) bool { return pr.GetType() == nodev1.ProxyType_PROXY_TYPE_WEB }

// certManager is the ACME manager of the node: Certs, or one that only
// inspects the certificates on disk when the agent runs without ACME (the
// tests, a node that only imports certificates).
func (r *Reconciler) certManager() *acme.Manager {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Certs == nil {
		r.Certs = &acme.Manager{Paths: r.Store.Paths, Log: r.Log, Now: r.Now}
		r.certsInspectOnly = true
	}
	return r.Certs
}

// lookupIP resolves a name over DNS-over-HTTPS (LookupIP, or a doh client of
// the default endpoints).
func (r *Reconciler) lookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if r.LookupIP != nil {
		return r.LookupIP(ctx, host)
	}
	r.mu.Lock()
	if r.doh == nil {
		r.doh = doh.New(doh.DefaultEndpoints)
	}
	c := r.doh
	r.mu.Unlock()
	return c.LookupIP(ctx, host)
}

// nodePublicIPs are the public IPv4 addresses of the node: the one the agent
// found (NodePublicIPv4), those of its interfaces (InterfaceAddrs), and the
// public addresses its listeners bind (a dedicated IP:443 placement binds the
// address the domain points to, which the host may hold in another way).
func (p *pass) nodePublicIPs() []netip.Addr {
	seen := map[netip.Addr]bool{}
	add := func(a netip.Addr) {
		if isPublicIPv4(a) {
			seen[a.Unmap()] = true
		}
	}
	if ip := p.r.publicIPv4(); ip != "" {
		if a, err := netip.ParseAddr(ip); err == nil {
			add(a)
		}
	}
	addrs := p.r.InterfaceAddrs
	if addrs == nil {
		addrs = net.InterfaceAddrs
	}
	if list, err := addrs(); err == nil {
		for _, a := range list {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					add(ip)
				}
			}
		}
	}
	for _, l := range p.st.GetListeners() {
		if a, err := netip.ParseAddr(l.GetBindIp()); err == nil {
			add(a)
		}
	}
	out := slices.Collect(func(yield func(netip.Addr) bool) {
		for a := range seen {
			if !yield(a) {
				return
			}
		}
	})
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// resolveWeb returns the IPv4 addresses of the A records of domain, from the
// cache when they are fresh (webLookupTTL), else over DNS-over-HTTPS. A failed
// lookup keeps the last answer for webLookupGrace.
func (p *pass) resolveWeb(domain string) ([]netip.Addr, error) {
	now := p.r.now()
	r := p.r
	r.mu.Lock()
	if r.webLookups == nil {
		r.webLookups = map[string]webLookup{}
	}
	cached, ok := r.webLookups[domain]
	r.mu.Unlock()
	if ok && cached.err == nil && now.Sub(cached.at) < webLookupTTL {
		return cached.addrs, nil
	}
	ctx, cancel := context.WithTimeout(p.ctx, webLookupTimeout)
	addrs, err := r.lookupIP(ctx, domain)
	cancel()
	if err != nil {
		if ok && cached.err == nil && now.Sub(cached.at) < webLookupGrace {
			return cached.addrs, nil // the last answer, for a while
		}
		r.mu.Lock()
		r.webLookups[domain] = webLookup{at: now, err: err}
		r.mu.Unlock()
		return nil, err
	}
	var v4 []netip.Addr
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() {
			v4 = append(v4, a)
		}
	}
	slices.SortFunc(v4, netip.Addr.Compare)
	r.mu.Lock()
	r.webLookups[domain] = webLookup{addrs: v4, at: now}
	r.mu.Unlock()
	return v4, nil
}

// webPublicAddr is the public_addr of the vhost of a WEB proxy: an A record of
// its domain that is one of the node's public addresses, as "ip:443" (spec
// 5.4: never a bind address). When the panel names one (WebSettings
// public_addr), it is taken when the A records and the node's addresses
// agree with it. The error says what does not match; it is the proxy's
// reason until it does.
func (p *pass) webPublicAddr(pr *nodev1.Proxy) (string, error) {
	domain, err := webrules.CertDomain(pr.GetDomain())
	if err != nil {
		return "", err
	}
	records, err := p.resolveWeb(domain)
	if err != nil {
		return "", fmt.Errorf("the A record of %s cannot be resolved: %v", domain, err)
	}
	if len(records) == 0 {
		return "", fmt.Errorf("%s has no A record", domain)
	}
	ours := p.nodePublicIPs()
	var match []netip.Addr
	for _, a := range records {
		if slices.Contains(ours, a) {
			match = append(match, a)
		}
	}
	if len(match) == 0 {
		return "", fmt.Errorf("the A record of %s points to %s, none of which is a public address of this node (%s)",
			domain, joinAddrs(records), joinAddrs(ours))
	}
	chosen := match[0]
	if want := pr.GetWeb().GetPublicAddr(); want != "" {
		a, err := webrules.ParsePublicAddr(want)
		if err != nil {
			return "", err
		}
		if !slices.Contains(match, a) {
			return "", fmt.Errorf("public_addr %s is not an A record of %s that this node holds (%s)", a, domain, joinAddrs(match))
		}
		chosen = a
	}
	return webrules.PublicAddr(chosen), nil
}

func joinAddrs(as []netip.Addr) string {
	if len(as) == 0 {
		return "none"
	}
	ss := make([]string, len(as))
	for i, a := range as {
		ss[i] = a.String()
	}
	return strings.Join(ss, ", ")
}

// certRemoveAfter is how long a certificate on disk stays with no WEB proxy for
// its domain before removeUnusedCerts deletes it: long enough for the desired
// state that names the proxy of a certificate just put (PutCertificate comes
// first) to arrive, and for a proxy deleted and made again at once to keep
// it.
const certRemoveAfter = 5 * time.Minute

// evCertRemoved is the event of a certificate removed from the node.
const evCertRemoved = "certificate_removed"

// removeUnusedCerts deletes the certificate of every domain on disk that no
// WEB proxy of the desired state has used for certRemoveAfter (enabled or
// paused, either cert mode): the chain, the private key and what ACME keeps of
// the domain (F4 of the real-server pass). A failure is logged; the pass goes
// on.
func (p *pass) removeUnusedCerts(mgr *acme.Manager, now time.Time) {
	used := map[string]bool{}
	for _, pr := range p.st.GetProxies() {
		if !isWeb(pr) {
			continue
		}
		if d, err := webrules.CertDomain(pr.GetDomain()); err == nil {
			used[d] = true
		}
	}
	domains, err := mgr.Domains()
	if err != nil {
		p.r.log().Warn("cannot list the certificates on disk", "err", err)
		return
	}
	since := map[string]time.Time{}
	for _, d := range domains {
		if used[d] {
			continue
		}
		first, seen := p.r.certUnused[d]
		if !seen {
			first = now
		}
		if t := mgr.Touched(d); t.After(first) {
			first = t // a certificate put or issued since restarts the grace
		}
		if now.Sub(first) < certRemoveAfter {
			since[d] = first
			continue
		}
		removed, err := mgr.Remove(d)
		switch {
		case err != nil:
			p.r.log().Warn("cannot remove the certificate of a domain no proxy uses", "domain", d, "err", err)
			since[d] = first
		case !removed:
			since[d] = first // an issuance or an import runs: later
		default:
			p.r.event(evCertRemoved, sevInfo, "", "the certificate of "+d+" was removed: no WEB proxy uses the domain",
				map[string]string{"domain": d})
		}
	}
	p.r.certUnused = since
}

// certificates is the step of the pass that looks after the certificates of
// the WEB proxies on tls listeners: it asks the ACME manager for the ones of
// cert_mode acme-dns01 (ensureIssue), forgets the domains that no proxy uses
// with ACME any more, and records in p.webCerts whether the edge may serve
// each domain (see webCert).
func (p *pass) certificates() error {
	p.webCerts = map[string]webCert{}
	mgr := p.r.certManager()
	now := p.r.now()
	acmeDomains := map[string]bool{}
	tracked := map[string]string{}
	nonces := p.reissueNonces()
	for domain, n := range nonces {
		mgr.SetReissueNonce(domain, n)
	}
	for _, pr := range p.sortedProxies() {
		if !isWeb(pr) || p.upstreamListener(pr.GetListenerId()) {
			continue
		}
		domain, err := webrules.CertDomain(pr.GetDomain())
		if err != nil {
			continue // the render step reports it
		}
		w := pr.GetWeb()
		if !pr.GetEnabled() {
			// Paused: no route, but the certificate is kept renewed, so that
			// a resume does not cost an issuance.
			if w.GetCertMode() == webrules.CertModeACME && !p.r.certsInspectOnly {
				acmeDomains[domain] = true
				tracked[pr.GetId()] = domain
				p.r.ensureIssue(domain, w.GetAcmeEmail(), w.GetDnsCredential(), nonces[domain], mgr.Status(domain), now)
			}
			continue
		}
		st := mgr.Status(domain)
		c := webCert{gen: certGeneration(st.FullchainSHA256)}
		switch w.GetCertMode() {
		case webrules.CertModeImported:
			want := strings.ToLower(w.GetCertSha256())
			switch {
			case st.Valid && st.FullchainSHA256 == want:
				c.ok = true
			case st.FullchainSHA256 == "" || st.Problem == acme.ProblemNoCertificate:
				c.reason = "waiting for the imported certificate of " + domain
			case st.Valid:
				c.reason = fmt.Sprintf("the certificate stored for %s (sha256 %.12s...) is not the one the panel named (%.12s...)", domain, st.FullchainSHA256, want)
			default:
				c.reason = "no valid certificate: " + st.Problem
			}
		default: // acme-dns01 (the validator admits nothing else)
			acmeDomains[domain] = true
			tracked[pr.GetId()] = domain
			if p.r.certsInspectOnly {
				c.reason = "ACME is not available on this node"
				if st.Valid {
					c.ok = true
				}
				break
			}
			p.r.ensureIssue(domain, w.GetAcmeEmail(), w.GetDnsCredential(), nonces[domain], st, now)
			st = mgr.Status(domain) // Issuing may have changed
			c.ok = st.Valid
			if !c.ok {
				c.reason = st.Reason()
			}
		}
		if prev, dup := p.webCerts[domain]; !dup || (!prev.ok && c.ok) {
			p.webCerts[domain] = c
		}
	}
	// Forget what no proxy renews with ACME any more.
	p.r.mu.Lock()
	old := p.r.certDomains
	p.r.certDomains = tracked
	p.r.mu.Unlock()
	for _, domain := range old {
		if !acmeDomains[domain] {
			mgr.Forget(domain)
		}
	}
	for domain := range acmeDomains {
		if _, ok := nonces[domain]; !ok {
			mgr.SetReissueNonce(domain, 0)
		}
	}
	p.removeUnusedCerts(mgr, now)
	// The plan step reported every WEB proxy whose instance serves as
	// serving; now that the certificates are known, say what each waits for.
	for _, pr := range p.sortedProxies() {
		pl, rec := p.plans[pr.GetId()], p.rt.Instances[pr.GetId()]
		if isWeb(pr) && pr.GetEnabled() && pl != nil && pl.err == nil && rec.Generation > 0 && rec.Hash == pl.hash {
			p.reportServing(pr)
		}
	}
	return nil
}

// reissueNonces are the reissue nonces (WebSettings.reissue_nonce) of the
// domains of the WEB proxies of cert_mode acme-dns01 on tls listeners, paused
// ones included: the highest of the proxies of a domain, so that two proxies
// of one domain never take turns at asking for a new certificate. A domain
// without a nonce is left out.
func (p *pass) reissueNonces() map[string]uint64 {
	out := map[string]uint64{}
	for _, pr := range p.st.GetProxies() {
		w := pr.GetWeb()
		if !isWeb(pr) || p.upstreamListener(pr.GetListenerId()) || w.GetCertMode() != webrules.CertModeACME || w.GetReissueNonce() == 0 {
			continue
		}
		if domain, err := webrules.CertDomain(pr.GetDomain()); err == nil {
			out[domain] = max(out[domain], w.GetReissueNonce())
		}
	}
	return out
}

// upstreamListener reports whether the listener is an http-upstream one.
func (p *pass) upstreamListener(id string) bool {
	for _, l := range p.st.GetListeners() {
		if l.GetId() == id {
			return l.GetKind() == nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM
		}
	}
	return false
}

// certGeneration is the generation of a certificate for the edge (CertRef):
// the first eight bytes of the digest of its chain, so that new files are a
// new generation without any state kept. 0 for no certificate.
func certGeneration(sha string) uint64 {
	b, err := hex.DecodeString(sha)
	if err != nil || len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b[:8])
}

// ensureIssue asks the manager for the certificate of domain in a goroutine
// of its own, once per agent run for each (domain, email, credential, reissue
// nonce), and again when the certificate is due and the manager is not in the
// pause of a failure. One issuance of a domain runs at a time; when it ends, a pass is
// woken so that the route follows at once. The context is the agent's, not
// the pass's: an issuance outlives the pass that asked for it.
func (r *Reconciler) ensureIssue(domain, email, token string, nonce uint64, st acme.Status, now time.Time) {
	sum := sha256.Sum256([]byte(token))
	key := domain + "\x00" + email + "\x00" + hex.EncodeToString(sum[:8]) + "\x00" + strconv.FormatUint(nonce, 10)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.issuing == nil {
		r.issuing = map[string]bool{}
		r.issueAsked = map[string]bool{}
	}
	if r.issuing[domain] {
		return
	}
	if r.issueAsked[key] && (!st.Due || st.Issuing || now.Before(st.RetryAt)) {
		return
	}
	r.issueAsked[key] = true
	r.issuing[domain] = true
	ctx := r.bg
	if ctx == nil {
		ctx = context.Background()
	}
	issue := r.issue
	if issue == nil {
		issue = r.Certs.Issue
	}
	go func() {
		err := issue(ctx, domain, email, acme.CloudflareToken(token))
		if err != nil && !errors.Is(err, acme.ErrBackoff) && ctx.Err() == nil {
			r.log().Warn("certificate issuance failed", "domain", domain, "err", err)
		}
		r.mu.Lock()
		delete(r.issuing, domain)
		r.mu.Unlock()
		r.wakeUp()
	}()
}

// wakeUp asks Run for a pass; nothing happens when Run does not run.
func (r *Reconciler) wakeUp() {
	r.mu.Lock()
	ch := r.wake
	r.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// renewLoop renews the certificates every renewEvery, and wakes a pass after
// each round, until ctx ends.
func (r *Reconciler) renewLoop(ctx context.Context) {
	t := time.NewTicker(renewEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := r.Certs.Renew(ctx); err != nil && ctx.Err() == nil {
			r.log().Warn("certificate renewal", "err", err)
		}
		r.wakeUp()
	}
}

// webReady reports whether the route of an enabled WEB proxy may be served:
// always behind a web server (http-upstream), otherwise when its certificate
// may be (certificates). The reason says what it waits for.
func (p *pass) webReady(pr *nodev1.Proxy) (bool, string) {
	if !isWeb(pr) || p.upstreamListener(pr.GetListenerId()) {
		return true, ""
	}
	domain, err := webrules.CertDomain(pr.GetDomain())
	if err != nil {
		return false, err.Error()
	}
	c, ok := p.webCerts[domain]
	if !ok {
		return false, "no certificate for " + domain
	}
	return c.ok, c.reason
}

// reportServing reports a proxy whose desired generation serves: SERVING, or
// PENDING for a WEB proxy whose route waits for its certificate.
func (p *pass) reportServing(pr *nodev1.Proxy) {
	if ok, reason := p.webReady(pr); !ok {
		p.report(pr.GetId(), nodev1.ProxyPhase_PROXY_PHASE_PENDING, reason)
		return
	}
	p.report(pr.GetId(), nodev1.ProxyPhase_PROXY_PHASE_SERVING, "")
}

// probeWeb is the readiness check of a new WEB generation, in place of the
// fake-TLS probe: a request to its web listener with the vhost as Host, as
// the edge would send it, must get an HTTP answer (the decoy site, or
// whatever telemt says: what matters is that the listener serves HTTP).
func (p *pass) probeWeb(pr *nodev1.Proxy, port uint16) error {
	host, err := webrules.CertDomain(pr.GetDomain())
	if err != nil {
		return err
	}
	probe := p.r.webProbe
	if probe == nil {
		probe = webProbeHTTP
	}
	attempts := orDefault(p.r.probeAttempts, defaultProbeAttempts)
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			if err := sleep(p.ctx, orDefault(p.r.readyPoll, defaultReadyPoll)); err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(p.ctx, webProbeTimeout)
		last = probe(ctx, loopback(port), host)
		cancel()
		if last == nil {
			return nil
		}
		if p.ctx.Err() != nil {
			return p.ctx.Err()
		}
	}
	return fmt.Errorf("the web listener does not answer: %v", last)
}

// webProbeHTTP sends GET / to addr for host and returns nil on any HTTP
// answer.
func webProbeHTTP(ctx context.Context, addr, host string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/", nil)
	if err != nil {
		return err
	}
	req.Host = host
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	client := &http.Client{
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}
