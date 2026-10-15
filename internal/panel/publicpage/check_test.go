package publicpage

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
)

// certHost is a name that the certificate of httptest's TLS servers is valid
// for.
const certHost = "example.com"

// fakeResolver answers every name with addrs, or with err.
type fakeResolver struct {
	addrs []netip.Addr
	err   error
	calls atomic.Int32
}

func (f *fakeResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	f.calls.Add(1)
	return f.addrs, f.err
}

var errNotFound = &net.DNSError{Err: "no such host", Name: certHost, IsNotFound: true}

// tlsSite starts an HTTPS server with h and makes the check of the service
// reach it for every name, trusting its certificate.
func (e *env) tlsSite(h http.Handler) *httptest.Server {
	e.t.Helper()
	srv := httptest.NewTLSServer(h)
	e.t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	e.svc.checkRoots = pool
	e.svc.checkDial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	return srv
}

func (e *env) check() *panelv1.CheckPublicPageResponse {
	e.t.Helper()
	resp, err := e.admin.CheckPublicPage(e.ctx, connect.NewRequest(&panelv1.CheckPublicPageRequest{}))
	if err != nil {
		e.t.Fatalf("CheckPublicPage: %v", err)
	}
	return resp.Msg
}

func TestCheckFindsThePanelsPage(t *testing.T) {
	e := newEnv(t)
	e.svc.resolver = &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::1")}}
	e.svc.sysResolver = &fakeResolver{err: errors.New("the system resolver must not be asked")}
	srv := e.tlsSite(e.svc.Handler())
	e.setPage(&panelv1.PublicPage{Host: certHost, Enabled: true})

	got := e.check()
	if got.GetHost() != certHost || strings.Join(got.GetAddresses(), ",") != "203.0.113.10,2001:db8::1" || got.GetDnsError() != "" {
		t.Errorf("DNS: %v", got)
	}
	if !got.GetHttpsOk() || got.GetHttpsError() != "" || !got.GetServedByPanel() {
		t.Errorf("HTTPS: ok %v, error %q, served by panel %v", got.GetHttpsOk(), got.GetHttpsError(), got.GetServedByPanel())
	}
	cert := srv.Certificate()
	if got.GetCertIssuer() == "" || got.GetCertNotAfterUnix() != cert.NotAfter.Unix() {
		t.Errorf("certificate: issuer %q, not after %d, want %d", got.GetCertIssuer(), got.GetCertNotAfterUnix(), cert.NotAfter.Unix())
	}
}

func TestCheckDNS(t *testing.T) {
	e := newEnv(t)
	e.tlsSite(e.svc.Handler())
	e.setPage(&panelv1.PublicPage{Host: certHost, Enabled: true})

	// A name that does not exist is not asked of the system resolver.
	doh := &fakeResolver{err: errNotFound}
	sys := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	e.svc.resolver, e.svc.sysResolver = doh, sys
	if got := e.check(); got.GetDnsError() != dnsNotFound || len(got.GetAddresses()) != 0 || sys.calls.Load() != 0 {
		t.Errorf("not found over DoH: %v, system asked %d times", got, sys.calls.Load())
	}

	// DoH that fails falls back to the system resolver.
	e.svc.resolver = &fakeResolver{err: errors.New("DoH is unreachable")}
	if got := e.check(); got.GetDnsError() != "" || strings.Join(got.GetAddresses(), ",") != "192.0.2.1" {
		t.Errorf("fallback: %v", got)
	}

	// Both fail: the error of the system resolver; none found: not found.
	e.svc.sysResolver = &fakeResolver{err: errors.New("resolver broken")}
	if got := e.check(); got.GetDnsError() != "resolver broken" {
		t.Errorf("both fail: %q", got.GetDnsError())
	}
	e.svc.resolver, e.svc.sysResolver = nil, &fakeResolver{}
	if got := e.check(); got.GetDnsError() != dnsNotFound {
		t.Errorf("no addresses: %q", got.GetDnsError())
	}
	// The HTTPS check runs whatever DNS says.
	if got := e.check(); !got.GetHttpsOk() {
		t.Errorf("HTTPS with DNS failing: %q", got.GetHttpsError())
	}
}

func TestCheckHTTPSFailures(t *testing.T) {
	e := newEnv(t)
	e.svc.resolver = &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.10")}}

	// Another site answers 200 without the marker.
	e.tlsSite(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	e.setPage(&panelv1.PublicPage{Host: certHost, Enabled: true})
	if got := e.check(); !got.GetHttpsOk() || got.GetServedByPanel() {
		t.Errorf("another site: ok %v, served by panel %v", got.GetHttpsOk(), got.GetServedByPanel())
	}

	// The page while disabled: the panel's, but 404.
	e.tlsSite(e.svc.Handler())
	e.setPage(&panelv1.PublicPage{Host: certHost})
	if got := e.check(); got.GetHttpsOk() || !strings.Contains(got.GetHttpsError(), "404") || !got.GetServedByPanel() {
		t.Errorf("disabled page: ok %v, error %q, served by panel %v", got.GetHttpsOk(), got.GetHttpsError(), got.GetServedByPanel())
	}

	// A certificate that is not for the host: the error, and what it was.
	e.setPage(&panelv1.PublicPage{Host: "proxies.example.net", Enabled: true})
	if got := e.check(); got.GetHttpsOk() || !strings.Contains(got.GetHttpsError(), "certificate") ||
		got.GetCertIssuer() == "" || got.GetCertNotAfterUnix() == 0 {
		t.Errorf("wrong name: %v", got)
	}

	// A certificate that the roots do not trust.
	e.setPage(&panelv1.PublicPage{Host: certHost, Enabled: true})
	e.svc.checkRoots = x509.NewCertPool()
	if got := e.check(); got.GetHttpsOk() || !strings.Contains(got.GetHttpsError(), "certificate") || got.GetCertIssuer() == "" {
		t.Errorf("untrusted: %v", got)
	}

	// Nothing listens.
	e.svc.checkDial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connection refused") }
	if got := e.check(); got.GetHttpsOk() || !strings.Contains(got.GetHttpsError(), "connection refused") || got.GetCertIssuer() != "" {
		t.Errorf("refused: %v", got)
	}
}

func TestCheckRedirects(t *testing.T) {
	e := newEnv(t)
	e.svc.resolver = &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.10")}}
	var elsewhere atomic.Int32
	e.tlsSite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host != certHost:
			elsewhere.Add(1)
		case r.URL.Path == "/robots.txt":
			http.Redirect(w, r, "/robots2.txt", http.StatusFound)
		case r.URL.Path == "/robots2.txt" && r.URL.Query().Get("away") == "":
			http.Redirect(w, r, "https://other.example.com/robots.txt?away=1", http.StatusFound)
		}
	}))
	e.setPage(&panelv1.PublicPage{Host: certHost, Enabled: true})
	got := e.check()
	if got.GetHttpsOk() || !strings.Contains(got.GetHttpsError(), "redirects to another host") || elsewhere.Load() != 0 {
		t.Errorf("redirect away: ok %v, error %q, the other host asked %d times", got.GetHttpsOk(), got.GetHttpsError(), elsewhere.Load())
	}

	// A redirect to another port of the host is not followed.
	var otherPort atomic.Int32
	e.tlsSite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" && r.URL.Query().Get("port") == "" {
			http.Redirect(w, r, "https://"+certHost+":8443/robots.txt?port=1", http.StatusFound)
			return
		}
		otherPort.Add(1)
	}))
	if got := e.check(); got.GetHttpsOk() || !strings.Contains(got.GetHttpsError(), "redirects to another host") || otherPort.Load() != 0 {
		t.Errorf("redirect to another port: ok %v, error %q, the other port asked %d times", got.GetHttpsOk(), got.GetHttpsError(), otherPort.Load())
	}

	// A redirect on the same host is followed.
	e.tlsSite(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			http.Redirect(w, r, "/robots2.txt", http.StatusFound)
			return
		}
		w.Header().Set(MarkerHeader, "1")
	}))
	if got := e.check(); !got.GetHttpsOk() || !got.GetServedByPanel() {
		t.Errorf("redirect on the host: %v", got)
	}
}

func TestCheckNeedsAnAdminAndAHost(t *testing.T) {
	e := newEnv(t)
	_, err := e.anon.CheckPublicPage(e.ctx, connect.NewRequest(&panelv1.CheckPublicPageRequest{}))
	_ = wantCode(t, err, connect.CodeUnauthenticated)
	_, err = e.admin.CheckPublicPage(e.ctx, connect.NewRequest(&panelv1.CheckPublicPageRequest{}))
	_ = wantCode(t, err, connect.CodeFailedPrecondition)
}

func TestEveryAnswerOfThePageCarriesTheMarker(t *testing.T) {
	e := newEnv(t)
	e.setPage(&panelv1.PublicPage{Host: publicHost})
	for _, enabled := range []bool{false, true} {
		e.setPage(&panelv1.PublicPage{Host: publicHost, Enabled: enabled})
		for _, path := range []string{"/", "/robots.txt", "/nope", cssAsset.path} {
			resp, _ := e.get(http.MethodGet, path, publicHost, nil)
			if resp.Header.Get(MarkerHeader) != "1" {
				t.Errorf("enabled %v, GET %s: no marker", enabled, path)
			}
		}
	}
}
