package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// webSite is a TLS site on the loopback standing in for https://example.com:
// tr dials it whatever the URL's host, trusting its certificate when trusted.
func webSite(t *testing.T, http2 bool, h http.HandlerFunc, trusted bool) webTransport {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = http2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	if trusted {
		pool.AddCert(srv.Certificate())
	}
	addr := srv.Listener.Addr().String()
	return func() *http.Transport {
		return &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		}
	}
}

func TestWebProbe(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" || r.URL.Path != "/tg/" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		_, _ = w.Write([]byte("<html>decoy</html>"))
	}
	cases := []struct {
		name    string
		http2   bool
		h       http.HandlerFunc
		trusted bool
		ok, l1  bool
		err     string
	}{
		{"200 over HTTP/2", true, ok, true, true, true, ""},
		{"HTTP/1 only", false, ok, true, false, true, ErrWebNoHTTP},
		{"404", true, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }, true, false, true, "answered 404, want 200"},
		{"untrusted certificate", true, ok, false, false, false, ErrWebCert},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			probe := newWebProbe(webSite(t, c.http2, c.h, c.trusted), time.Now)
			p, l1 := probe(t.Context(), Target{ProxyID: "w", Type: store.ProxyTypeWeb, Addr: "https://example.com/tg/"})
			if p.OK != c.ok || l1 != c.l1 || p.Error != c.err {
				t.Errorf("probe = %+v, l1 %v; want ok %v, l1 %v, error %q", p, l1, c.ok, c.l1, c.err)
			}
		})
	}
	// Nothing listens.
	probe := newWebProbe(func() *http.Transport {
		return &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }}
	}, time.Now)
	if p, l1 := probe(t.Context(), Target{Addr: "https://example.com/"}); p.OK || l1 || p.Error != ErrUnreachable {
		t.Errorf("unreachable: %+v, %v", p, l1)
	}
}

// web.base_path: GET https://<domain>/<base_path> without the slash; a
// redirect is found.
func TestCheckBasePath(t *testing.T) {
	e := newEnv(t)
	n := e.node("proxy.example.com", true)
	up := &store.Listener{NodeID: n.ID, Kind: store.ListenerKindHTTPUpstream, BindIP: "127.0.0.1", Port: 18080}
	if err := e.db.CreateListener(e.ctx, up); err != nil {
		t.Fatal(err)
	}
	tlsL := e.listener(n.ID, 443)
	behind := e.proxy(up, "example.com", secretA, func(p *store.Proxy) {
		p.Type, p.WebBasePath, p.WebSecretMode = store.ProxyTypeWeb, "tg", "plain"
	})
	onTLS := e.proxy(tlsL, "web.example.com", secretB, func(p *store.Proxy) { p.Type, p.WebSecretMode = store.ProxyTypeWeb, "plain" })
	fake := e.proxy(tlsL, "www.example.com", secretB, nil)

	for _, c := range []struct {
		name     string
		h        http.HandlerFunc
		redirect bool
		status   int
	}{
		{"no redirect", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/tg" {
				w.WriteHeader(http.StatusTeapot)
				return
			}
			w.WriteHeader(http.StatusOK)
		}, false, 200},
		{"a redirect to the slash", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
		}, true, 301},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := NewScheduler(e.db, e.key, e.log, withWebTransport(webSite(t, true, c.h, true)))
			got, err := s.CheckBasePath(e.ctx, behind.ID)
			if err != nil || got.Redirect() != c.redirect || got.Status != c.status {
				t.Fatalf("CheckBasePath = %+v, %v", got, err)
			}
			if c.redirect && got.Location != "/tg/" {
				t.Errorf("location = %q", got.Location)
			}
		})
	}
	s := NewScheduler(e.db, e.key, e.log, withWebTransport(webSite(t, true, func(http.ResponseWriter, *http.Request) {}, true)))
	for _, id := range []string{onTLS.ID, fake.ID} {
		if _, err := s.CheckBasePath(e.ctx, id); !errors.Is(err, ErrNotProbeable) {
			t.Errorf("CheckBasePath(%s) = %v, want ErrNotProbeable", id, err)
		}
	}
}
