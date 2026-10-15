package diag

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/acme"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/webrules"
)

// Ids of the checks of the WEB proxies.
const (
	IDWebCert  = "web.cert"
	IDWebDNS   = "web.dns"
	IDWebHTTP2 = "web.http2"
	IDWebDecoy = "web.decoy"
)

// FixReissueCert asks for a new ACME certificate of a WEB proxy: the panel
// raises the proxy's cert_reissue_nonce (WebSettings.reissue_nonce).
const FixReissueCert = "reissue_cert"

const (
	// certWarnLeft and certFailLeft are the validity left under which
	// web.cert warns and fails.
	certWarnLeft = 14 * 24 * time.Hour
	certFailLeft = 3 * 24 * time.Hour
	// webUnitTimeout bounds one proxy of web.dns and web.http2; webParallel
	// is how many proxies they check at once.
	webUnitTimeout = 10 * time.Second
	webParallel    = 4
	// ProbeKindWeb is the kind of the probe result web.http2 hands over.
	ProbeKindWeb = "web"
	// maxWebBody bounds what web.http2 reads of the answer.
	maxWebBody = 64 << 10
	// decoyIndex is the index of the decoy site in an instance directory of
	// a WEB proxy (engines/telemt: public/index.html).
	decoyIndex = "public/index.html"
)

// WebChecks are the checks of the WEB proxies (Task 13): the certificate,
// the A record and HTTP/2 through the edge's test listener on a tls listener,
// where the edge terminates TLS; the decoy site of every WEB proxy. On an
// http-upstream listener the web server in front owns the certificate and the
// domain: the panel's web probe covers it.
func WebChecks() []Check {
	return []Check{
		{ID: IDWebCert, Layer: LayerWeb, Light: true, Every: 10 * time.Minute, Targets: webTLSTargets, Run: checkWebCert},
		{ID: IDWebDNS, Layer: LayerWeb, Light: true, Every: 10 * time.Minute, Timeout: unitsTimeout, Targets: webTLSTargets, Run: checkWebDNS},
		{ID: IDWebHTTP2, Layer: LayerWeb, Light: true, Every: 10 * time.Minute, Timeout: unitsTimeout, Targets: webTLSTargets, Run: checkWebHTTP2},
		{ID: IDWebDecoy, Layer: LayerWeb, Run: checkWebDecoy},
	}
}

// webUnit is an enabled WEB proxy the run wants.
type webUnit struct {
	proxy    *nodev1.Proxy
	target   string
	domain   string // webrules.CertDomain; "" when it is not one
	listener *nodev1.Listener
	upstream bool
	rec      state.InstanceRecord
	serving  bool
}

func (u webUnit) tgt() string { return u.target }

func (e *Env) webUnits(tlsOnly bool) []webUnit {
	listeners := map[string]*nodev1.Listener{}
	for _, l := range e.Desired.GetListeners() {
		listeners[l.GetId()] = l
	}
	var out []webUnit
	for _, p := range e.Desired.GetProxies() {
		target := ProxyTarget(p.GetId())
		if p.GetType() != nodev1.ProxyType_PROXY_TYPE_WEB || !p.GetEnabled() || !e.Wants(target) {
			continue
		}
		u := webUnit{proxy: p, target: target, listener: listeners[p.GetListenerId()]}
		u.upstream = u.listener.GetKind() == nodev1.ListenerKind_LISTENER_KIND_HTTP_UPSTREAM
		if tlsOnly && u.upstream {
			continue
		}
		u.domain, _ = webrules.CertDomain(p.GetDomain())
		if e.Runtime != nil {
			u.rec, u.serving = e.Runtime.Instances[p.GetId()]
			u.serving = u.serving && u.rec.Generation > 0
		}
		out = append(out, u)
	}
	return out
}

// webTLSTargets are the enabled WEB proxies on tls listeners.
func webTLSTargets(env *Env) []string {
	var out []string
	for _, u := range (&Env{Desired: env.Desired}).webUnits(true) {
		out = append(out, u.target)
	}
	return out
}

// checkWebCert is web.cert: the certificate on disk that the edge serves for
// the proxy's domain. ok with 14 days left or more, warn under 14, fail
// under 3, expired, missing, not for the domain, or (imported) not the one the
// panel named. The fix reissue_cert is offered for cert_mode acme-dns01 only.
func checkWebCert(_ context.Context, env *Env) []Result {
	var out []Result
	for _, u := range env.webUnits(true) {
		r := env.webCert(u)
		r.Target = u.target
		out = append(out, r)
	}
	return out
}

func (e *Env) webCert(u webUnit) Result {
	if u.domain == "" {
		return Result{Status: Fail, Summary: "the proxy's domain cannot name a certificate"}
	}
	if e.CertStatus == nil {
		return Result{Status: Skip, Summary: "the node's certificates cannot be read"}
	}
	st := e.CertStatus(u.domain)
	acmeMode := u.proxy.GetWeb().GetCertMode() == webrules.CertModeACME
	fix, hint := "", "import a new certificate of "+u.domain+" in the panel"
	if acmeMode {
		fix = FixReissueCert
		hint = "the node renews the certificate 30 days before it expires; see the last ACME error, the DNS credential and the zone of the domain"
	}
	evidence := func() string {
		var b strings.Builder
		if !st.NotAfter.IsZero() {
			fmt.Fprintf(&b, "expires: %s\n", st.NotAfter.UTC().Format(time.RFC3339))
		}
		if st.Issuer != "" {
			fmt.Fprintf(&b, "issuer: %s\n", st.Issuer)
		}
		if st.Problem != "" {
			fmt.Fprintf(&b, "problem: %s\n", st.Problem)
		}
		if acmeMode {
			last := st.LastError
			if last == "" {
				last = "none"
			}
			fmt.Fprintf(&b, "last ACME error: %s\n", last)
			if st.Issuing {
				b.WriteString("an issuance is under way\n")
			}
		}
		return strings.TrimSuffix(b.String(), "\n")
	}
	fail := func(status nodev1.CheckStatus, summary string) Result {
		return Result{Status: status, Summary: summary, Evidence: evidence(), Hint: hint, Fix: fix}
	}
	switch {
	case st.FullchainSHA256 == "" || st.Problem == acme.ProblemNoCertificate:
		return fail(Fail, "no certificate of "+u.domain+" is on the node")
	case !st.Valid:
		return fail(Fail, "the certificate of "+u.domain+" cannot be served: "+st.Problem)
	}
	if !acmeMode {
		if want := strings.ToLower(u.proxy.GetWeb().GetCertSha256()); want != st.FullchainSHA256 {
			r := fail(Fail, "the certificate stored for "+u.domain+" is not the one the panel named")
			r.Evidence += fmt.Sprintf("\nstored sha256: %.12s…, named: %.12s…", st.FullchainSHA256, want)
			return r
		}
	}
	left := st.NotAfter.Sub(e.now())
	days := int(left / (24 * time.Hour))
	switch {
	case left < certFailLeft:
		return fail(Fail, fmt.Sprintf("the certificate of %s expires in %d days", u.domain, days))
	case left < certWarnLeft:
		return e.untrusted(u, fail(Warn, fmt.Sprintf("the certificate of %s expires in %d days", u.domain, days)))
	}
	return e.untrusted(u, Result{Status: OK, Summary: fmt.Sprintf("the certificate of %s is valid until %s (%d days left)",
		u.domain, st.NotAfter.UTC().Format(time.DateOnly), days)})
}

// hintUntrusted is the hint of a chain that is not publicly trusted.
const hintUntrusted = "clients that check the certificate (browsers, the panel's web probe: ingress.external) refuse it; import a certificate of a public CA, or use cert_mode acme-dns01"

// untrusted turns an ok result of web.cert into a warning, and adds to a
// warning, when the stored chain is not publicly trusted (F6 of the
// real-server pass): the edge serves it, but a client that checks it does
// not take it. Roots that cannot be loaded say nothing.
func (e *Env) untrusted(u webUnit, r Result) Result {
	if e.CertTrusted == nil {
		return r
	}
	err := e.CertTrusted(u.domain)
	if err == nil || errors.Is(err, acme.ErrNoRoots) {
		return r
	}
	r.Status = Warn
	r.Summary += "; its chain is not publicly trusted: " + err.Error()
	r.Hint = hintUntrusted
	return r
}

// checkWebDNS is web.dns: the A records of the proxy's domain, resolved over
// DNS-over-HTTPS, are the listener's public address (the proxy's
// public_addr; else a specific public bind address of the listener; else the
// node's public addresses) and none is Cloudflare's proxy.
func checkWebDNS(ctx context.Context, env *Env) []Result {
	units := env.webUnits(true)
	if len(units) == 0 {
		return nil
	}
	var nodeIPs []netip.Addr
	if env.PublicIPs != nil {
		nodeIPs = env.PublicIPs(ctx)
	}
	return eachUnit(ctx, units, webParallel, webUnitTimeout, webUnit.tgt, func(ctx context.Context, u webUnit) Result {
		return env.webDNS(ctx, u, nodeIPs)
	})
}

func (e *Env) webDNS(ctx context.Context, u webUnit, nodeIPs []netip.Addr) Result {
	if u.domain == "" {
		return Result{Status: Fail, Summary: "the proxy's domain is not a host name"}
	}
	if e.LookupIP == nil {
		return Result{Status: Skip, Summary: "no DNS-over-HTTPS resolver"}
	}
	want := webExpectedAddrs(u, nodeIPs)
	if len(want) == 0 {
		return Result{Status: Skip, Summary: "the public address of the listener is not known"}
	}
	addrs, err := e.LookupIP(ctx, u.domain)
	if err != nil {
		return Result{Status: Fail, Summary: "the A record of " + u.domain + " cannot be resolved over DNS-over-HTTPS", Evidence: err.Error()}
	}
	var v4 []netip.Addr
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() && !slices.Contains(v4, a) {
			v4 = append(v4, a)
		}
	}
	slices.SortFunc(v4, netip.Addr.Compare)
	if len(v4) == 0 {
		return Result{Status: Fail, Summary: u.domain + " has no A record", Hint: "add an A record of the domain with the listener's public address"}
	}
	evidence := "A records: " + joinAddrList(v4) + "\nexpected: " + joinAddrList(want)
	for _, a := range v4 {
		if webrules.IsCloudflare(a) {
			return Result{Status: Fail, Summary: "the A record of " + u.domain + " points to Cloudflare's proxy", Evidence: evidence,
				Hint: "switch the record to \"DNS only\" (grey cloud): the edge must terminate TLS itself"}
		}
	}
	for _, a := range v4 {
		if !slices.Contains(want, a) {
			return Result{Status: Fail, Summary: "the A record of " + u.domain + " is not the listener's public address", Evidence: evidence,
				Hint: "point the A record of the domain to the listener's public address"}
		}
	}
	return Result{Status: OK, Summary: "the A record of " + u.domain + " is " + joinAddrList(v4) + ", the listener's public address", keep: v4[0]}
}

// webExpectedAddrs are the addresses the A records of a WEB proxy on a tls
// listener may hold.
func webExpectedAddrs(u webUnit, nodeIPs []netip.Addr) []netip.Addr {
	if pa := u.proxy.GetWeb().GetPublicAddr(); pa != "" {
		if a, err := webrules.ParsePublicAddr(pa); err == nil {
			return []netip.Addr{a}
		}
		return nil
	}
	if a, err := netip.ParseAddr(u.listener.GetBindIp()); err == nil && a.Unmap().Is4() && !a.IsUnspecified() &&
		!a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
		return []netip.Addr{a.Unmap()}
	}
	var out []netip.Addr
	for _, a := range nodeIPs {
		if a = a.Unmap(); a.Is4() {
			out = append(out, a)
		}
	}
	return out
}

func joinAddrList(as []netip.Addr) string {
	ss := make([]string, len(as))
	for i, a := range as {
		ss[i] = a.String()
	}
	return strings.Join(ss, ", ")
}

// checkWebHTTP2 is web.http2: TLS to the edge's test listener of the proxy's
// listener with SNI = the domain and ALPN h2; the chain served is the stored
// fullchain.pem; GET / answers 200 over HTTP/2 (the decoy site, through the
// engine). Each result also goes to the statistics as a probe of kind web.
func checkWebHTTP2(ctx context.Context, env *Env) []Result {
	return eachUnit(ctx, env.webUnits(true), webParallel, webUnitTimeout, webUnit.tgt, func(ctx context.Context, u webUnit) Result {
		var port uint16
		if env.Runtime != nil {
			port = env.Runtime.Ports[state.TestListenerPortKey(u.proxy.GetListenerId())]
		}
		switch {
		case u.domain == "":
			return Result{Status: Fail, Summary: "the proxy's domain is not a host name"}
		case !u.serving:
			return notServing
		case port == 0:
			return Result{Status: Skip, Summary: "the proxy's listener has no test listener yet"}
		}
		stored, err := env.storedChain(u.domain)
		if err != nil {
			return Result{Status: Skip, Summary: "no certificate of " + u.domain + " is stored: see " + IDWebCert}
		}
		start := time.Now()
		summary, err := webGet(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), u.domain, stored)
		took := time.Since(start)
		if err != nil && ctx.Err() != nil {
			return Result{Status: Skip, Summary: notInTime}
		}
		env.handWebProbe(u.proxy.GetId(), took, err)
		if err != nil {
			var we *webError
			if errors.As(err, &we) {
				return Result{Status: Fail, Summary: we.summary, Evidence: we.evidence, Hint: we.hint}
			}
			return Result{Status: Fail, Summary: "TLS to the edge's test listener fails for " + u.domain, Evidence: err.Error(),
				Hint: "see " + IDWebCert + ", ingress.bound and engine.ready"}
		}
		return Result{Status: OK, Summary: fmt.Sprintf("%s in %d ms", summary, took.Milliseconds())}
	})
}

// webError is a failure of web.http2 that is not the TLS connection's.
type webError struct{ summary, evidence, hint string }

func (e *webError) Error() string { return e.summary }

// storedChain is the stored fullchain.pem of domain, as DER.
func (e *Env) storedChain(domain string) ([][]byte, error) {
	if e.Store == nil {
		return nil, fs.ErrNotExist
	}
	data, err := os.ReadFile(filepath.Join(e.Store.Paths.CertsDir(), domain, "fullchain.pem"))
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for {
		var b *pem.Block
		if b, data = pem.Decode(data); b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			out = append(out, b.Bytes)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate in fullchain.pem")
	}
	return out, nil
}

// webGet makes the request of web.http2 to addr and returns the summary of a
// pass.
func webGet(ctx context.Context, addr, domain string, stored [][]byte) (string, error) {
	dialer := &net.Dialer{Timeout: webUnitTimeout}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2: true,
		DisableKeepAlives: true,
		// The chain is compared with the stored one below: what matters is
		// that the edge serves the certificate on disk, whatever its CA.
		TLSClientConfig: &tls.Config{ServerName: domain, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, //nolint:gosec // compared with the stored chain
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxWebBody))
	if resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h2" || resp.ProtoMajor != 2 {
		proto := ""
		if resp.TLS != nil {
			proto = resp.TLS.NegotiatedProtocol
		}
		return "", &webError{summary: "the edge's test listener does not speak HTTP/2 for " + domain,
			evidence: fmt.Sprintf("ALPN %q, protocol %s", proto, resp.Proto), hint: "the edge negotiates h2 on a tls listener: see the edge's version"}
	}
	var served [][]byte
	for _, c := range resp.TLS.PeerCertificates {
		served = append(served, c.Raw)
	}
	if !slices.EqualFunc(served, stored, bytes.Equal) {
		return "", &webError{summary: "the edge serves another certificate for " + domain + " than the one stored",
			evidence: fmt.Sprintf("served %d certificates, stored %d; the leaf differs: %t", len(served), len(stored), len(served) == 0 || !bytes.Equal(served[0], stored[0])),
			hint:     "the edge loads a new certificate on the next pass: wait a minute, then see " + IDWebCert}
	}
	if resp.StatusCode != http.StatusOK {
		return "", &webError{summary: fmt.Sprintf("GET / for %s answers %d over HTTP/2, want 200", domain, resp.StatusCode),
			evidence: "status: " + resp.Status, hint: "the engine's decoy site does not answer: see engine.ready and " + IDWebDecoy}
	}
	return "TLS with the stored certificate, HTTP/2, GET / 200", nil
}

// handWebProbe gives the statistics the result of web.http2 as a probe of
// kind web, its error scrubbed.
func (e *Env) handWebProbe(proxyID string, took time.Duration, err error) {
	if e.AddProbe == nil {
		return
	}
	p := &nodev1.ProbeResult{ProxyId: proxyID, Kind: ProbeKindWeb, Ok: err == nil,
		LatencyMs: uint32(min(max(took.Milliseconds(), 0), 1<<31)), AtUnix: e.now().Unix()}
	if err != nil {
		p.Error = clip(e.Scrub.Clean(err.Error()), maxProbeError, true)
	}
	e.AddProbe(p)
}

// checkWebDecoy is web.decoy (full runs): the index of the decoy site is in
// the instance directory of the proxy's serving generation.
func checkWebDecoy(_ context.Context, env *Env) []Result {
	var out []Result
	for _, u := range env.webUnits(false) {
		r := env.webDecoy(u)
		r.Target = u.target
		out = append(out, r)
	}
	return out
}

func (e *Env) webDecoy(u webUnit) Result {
	if !u.serving {
		return notServing
	}
	if e.Store == nil {
		return Result{Status: Skip, Summary: "the instance directories cannot be read"}
	}
	path := filepath.Join(e.Store.Paths.InstancesDir(), instanceDirName(u.proxy.GetId(), u.rec.Generation), filepath.FromSlash(decoyIndex))
	fi, err := os.Stat(path)
	switch {
	case err != nil:
		return Result{Status: Fail, Summary: "the decoy site of the proxy has no index", Evidence: decoyIndex + ": " + pathError(err),
			Hint: "a new engine generation writes the decoy site again", Fix: FixRecreateInstance}
	case !fi.Mode().IsRegular() || fi.Size() == 0:
		return Result{Status: Fail, Summary: "the index of the proxy's decoy site is empty or not a file", Evidence: decoyIndex,
			Hint: "a new engine generation writes the decoy site again", Fix: FixRecreateInstance}
	}
	return Result{Status: OK, Summary: fmt.Sprintf("the decoy site's index is in place (%d bytes)", fi.Size())}
}

// instanceDirName is the name of the instance directory of a proxy's
// generation, as the reconciler names it (reconcile.instanceDirName).
func instanceDirName(proxyID string, gen uint64) string {
	return "eng-" + strings.ToLower(proxyID) + "-g" + strconv.FormatUint(gen, 10)
}

// pathError is the text of a file system error without its path.
func pathError(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}
