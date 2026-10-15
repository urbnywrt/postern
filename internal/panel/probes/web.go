package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/webrules"
)

// The panel's probe of a WEB proxy (Task 13) is at the HTTP/2 and decoy level,
// not the MTProto one (a recorded deviation): GET https://<domain>/ (or
// /<base_path>/) with the system's roots must answer 200 over HTTP/2.
const KindWeb = "web"

// The classes of a failed WEB probe.
const (
	ErrWebCert   = "the certificate is not trusted for the domain"
	ErrWebNoHTTP = "no HTTP/2: the site answered over HTTP/1"
	errWebStatus = "answered %d, want 200"
)

const (
	// maxWebBody bounds what a WEB probe reads of an answer.
	maxWebBody = 64 << 10
)

// webTransport makes the transport of a WEB probe; tests replace it.
type webTransport func() *http.Transport

// systemTransport is the transport of the real WEB probes: the system's
// roots and resolver, HTTP/2 when the site offers it, no proxy.
func systemTransport() *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: probeTimeout}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: probeTimeout,
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   true,
	}
}

// RealWebProbe is the probe of the panel for a WEB proxy, at Target.Addr, its
// URL (webURL). l1OK reports that the site answered over TLS with a trusted
// certificate, whatever it answered.
func RealWebProbe() ProbeFunc { return newWebProbe(systemTransport, time.Now) }

func newWebProbe(tr webTransport, now func() time.Time) ProbeFunc {
	return func(ctx context.Context, t Target) (store.Probe, bool) {
		ctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		start := now()
		resp, err := webGet(ctx, tr, t.Addr)
		p := store.Probe{LatencyMS: latencyMS(now().Sub(start))}
		if err != nil {
			p.Error = webErrorClass(err)
			return p, false
		}
		_ = resp.Body.Close()
		switch {
		case resp.ProtoMajor != 2:
			p.Error = ErrWebNoHTTP
		case resp.StatusCode != http.StatusOK:
			p.Error = fmt.Sprintf(errWebStatus, resp.StatusCode)
		default:
			p.OK = true
		}
		return p, true
	}
}

// webGet is GET url without following a redirect; the body is read (bounded)
// before it is returned.
func webGet(ctx context.Context, tr webTransport, url string) (*http.Response, error) {
	t := tr()
	defer t.CloseIdleConnections()
	client := &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxWebBody))
	return resp, nil
}

// webErrorClass is the class of an error of a WEB probe.
func webErrorClass(err error) string {
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verify *tls.CertificateVerificationError
	if errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &invalid) || errors.As(err, &verify) {
		return ErrWebCert
	}
	return ErrUnreachable
}

// webURL is the URL the panel probes a WEB proxy at, where its decoy site
// answers 200: https://<domain>/ on a tls listener, whose edge leads every
// path of the domain to the engine and its decoy (as the node's web.http2
// asks); https://<domain>/<base_path>/ behind a web server (an http-upstream
// listener), which hands only that subtree to the node.
func webURL(p *store.Proxy, l *store.Listener) (string, error) {
	domain, err := webrules.CertDomain(p.Domain)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNotProbeable, err)
	}
	if base := strings.Trim(p.WebBasePath, "/"); base != "" && l.Kind == store.ListenerKindHTTPUpstream {
		return "https://" + domain + "/" + base + "/", nil
	}
	return "https://" + domain + "/", nil
}

// BasePath is what web.base_path found: the status of GET
// https://<domain>/<base_path> without the slash, and where a redirect points.
type BasePath struct {
	Status   int
	Location string
}

// Redirect reports whether the answer is a redirect.
func (b BasePath) Redirect() bool { return b.Status >= 300 && b.Status < 400 }

// CheckBasePath requests https://<domain>/<base_path> (no slash at the end)
// of a WEB proxy behind a web server (an http-upstream listener) with a base
// path, as a client of the proxy does: the web server in front must not
// answer it with a redirect (the slash it would add breaks the clients). A
// proxy that is not such a one is ErrNotProbeable.
func (s *Scheduler) CheckBasePath(ctx context.Context, proxyID string) (BasePath, error) {
	p, err := s.db.ProxyByID(ctx, proxyID)
	if err != nil {
		return BasePath{}, err
	}
	l, err := s.db.ListenerByID(ctx, p.ListenerID)
	if errors.Is(err, store.ErrNotFound) {
		return BasePath{}, fmt.Errorf("%w: its listener is gone", ErrNotProbeable)
	} else if err != nil {
		return BasePath{}, err
	}
	base := strings.Trim(p.WebBasePath, "/")
	switch {
	case p.Type != store.ProxyTypeWeb:
		return BasePath{}, fmt.Errorf("%w: not a WEB proxy", ErrNotProbeable)
	case l.Kind != store.ListenerKindHTTPUpstream || base == "":
		return BasePath{}, fmt.Errorf("%w: not behind a web server under a base path", ErrNotProbeable)
	}
	domain, err := webrules.CertDomain(p.Domain)
	if err != nil {
		return BasePath{}, fmt.Errorf("%w: %v", ErrNotProbeable, err)
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	resp, err := webGet(ctx, s.webTr, "https://"+domain+"/"+base)
	if err != nil {
		return BasePath{}, fmt.Errorf("the site did not answer: %s", webErrorClass(err))
	}
	_ = resp.Body.Close()
	return BasePath{Status: resp.StatusCode, Location: resp.Header.Get("Location")}, nil
}
