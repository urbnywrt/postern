package publicpage

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
)

// The marker of the public page: every response of [Service.Handler] carries
// it, so that a check of the host can tell this panel's page from another
// site.
const (
	MarkerHeader = "X-Postern-Page"
	markerValue  = "1"
)

// The limits of CheckPublicPage.
const (
	// checkTimeout bounds the HTTPS request, the connection and the TLS
	// handshake included.
	checkTimeout = 10 * time.Second
	// resolveTimeout bounds the lookup of the addresses.
	resolveTimeout = 10 * time.Second
	// maxCheckRedirects is how many redirects on the same host are followed.
	maxCheckRedirects = 3
	// maxCheckBody is how much of the body is read before the connection is
	// dropped.
	maxCheckBody = 64 << 10
	// maxErrorText is the most of an error that the answer carries.
	maxErrorText = 300
)

// dnsNotFound is the dns_error of a name that has no address.
const dnsNotFound = "not found"

// A Resolver looks up the addresses of a name, as doh.Client does.
type Resolver interface {
	LookupIP(ctx context.Context, name string) ([]netip.Addr, error)
}

// WithResolver sets the resolver of CheckPublicPage, the panel's DNS-over-HTTPS
// client. When it fails for another reason than a name that does not exist,
// the system resolver is asked. nil, the default, is the system resolver
// alone.
func WithResolver(r Resolver) Option {
	return func(s *Service) { s.resolver = r }
}

// systemResolver is the resolver of the system, as a Resolver.
type systemResolver struct{}

func (systemResolver) LookupIP(ctx context.Context, name string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
}

// CheckPublicPage reaches the configured host as a visitor does: its addresses,
// and https://<host>/robots.txt.
func (s *Service) CheckPublicPage(ctx context.Context, _ *connect.Request[panelv1.CheckPublicPageRequest]) (*connect.Response[panelv1.CheckPublicPageResponse], error) {
	if _, err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	p, err := s.db.PublicPage(ctx)
	if err != nil {
		return nil, s.fail("could not read the public page", err)
	}
	if p.Host == "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("the public page has no host"))
	}
	out := &panelv1.CheckPublicPageResponse{Host: p.Host}
	addrs, err := s.resolve(ctx, p.Host)
	switch {
	case err != nil && isNameNotFound(err):
		out.DnsError = dnsNotFound
	case err != nil:
		out.DnsError = errorText(err)
	}
	for _, a := range addrs {
		out.Addresses = append(out.Addresses, a.Unmap().String())
	}
	s.checkHTTPS(ctx, p.Host, out)
	s.log.Debug("public page checked", "host", p.Host, "addresses", len(out.Addresses), "https_ok", out.HttpsOk, "served_by_panel", out.ServedByPanel)
	return connect.NewResponse(out), nil
}

// resolve returns the addresses of host: over the resolver of the service, and
// over the system resolver when that one fails for another reason than a name
// that does not exist.
func (s *Service) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	if s.resolver != nil {
		addrs, err := s.resolver.LookupIP(ctx, host)
		if err == nil || isNameNotFound(err) {
			return addrs, err
		}
		s.log.Debug("DNS-over-HTTPS failed, asking the system resolver", "err", err)
	}
	sys := s.sysResolver
	if sys == nil {
		sys = systemResolver{}
	}
	addrs, err := sys.LookupIP(ctx, host)
	if err == nil && len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addrs, err
}

// isNameNotFound reports whether err says that a name has no address.
func isNameNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// errRedirect is the refusal of a redirect to another host, another scheme or
// another port.
var errRedirect = errors.New("redirects to another host")

// checkHTTPS asks https://<host>/robots.txt and fills in what it found.
func (s *Service) checkHTTPS(ctx context.Context, host string, out *panelv1.CheckPublicPageResponse) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	dial := s.checkDial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	tr := &http.Transport{
		DialContext:       dial,
		TLSClientConfig:   &tls.Config{RootCAs: s.checkRoots, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if HostOf(&http.Request{Host: req.URL.Host}) != host || req.URL.Scheme != "https" ||
				(req.URL.Port() != "" && req.URL.Port() != "443") {
				return fmt.Errorf("%w: %s", errRedirect, req.URL.Redacted())
			}
			if len(via) > maxCheckRedirects {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/robots.txt", nil)
	if err != nil {
		out.HttpsError = errorText(err)
		return
	}
	req.Header.Set("User-Agent", "Postern panel check")
	resp, err := client.Do(req)
	if err != nil {
		var ve *tls.CertificateVerificationError
		if errors.As(err, &ve) && len(ve.UnverifiedCertificates) > 0 {
			setCert(out, ve.UnverifiedCertificates[0])
		}
		out.HttpsError = errorText(err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxCheckBody))
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		setCert(out, resp.TLS.PeerCertificates[0])
	}
	out.ServedByPanel = resp.Header.Get(MarkerHeader) == markerValue
	if resp.StatusCode != http.StatusOK {
		out.HttpsError = fmt.Sprintf("the server answered %s", resp.Status)
		return
	}
	out.HttpsOk = true
}

// setCert fills in the issuer and the expiry of the certificate.
func setCert(out *panelv1.CheckPublicPageResponse, c *x509.Certificate) {
	out.CertIssuer = c.Issuer.CommonName
	if out.CertIssuer == "" {
		out.CertIssuer = c.Issuer.String()
	}
	out.CertNotAfterUnix = c.NotAfter.Unix()
}

// errorText is the text of an error for the answer: without the "Get <url>:"
// of the HTTP client, and not too long.
func errorText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "no answer within 10 s"
	}
	text := err.Error()
	if len(text) > maxErrorText {
		text = text[:maxErrorText] + "…"
	}
	return text
}
