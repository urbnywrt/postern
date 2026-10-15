package probe

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pageServer is an HTTPS server for example.com (httptest's certificate)
// that answers "/" with status; h2 offers HTTP/2.
func pageServer(t *testing.T, status int, h2 bool) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || r.Host != "example.com" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte("decoy"))
	}))
	srv.EnableHTTP2 = h2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func pageCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestPage(t *testing.T) {
	ok, pool := pageServer(t, http.StatusOK, true)
	bad, _ := pageServer(t, http.StatusBadGateway, true)
	h1, _ := pageServer(t, http.StatusOK, false)
	addr := func(s *httptest.Server) string { return s.Listener.Addr().String() }
	for _, tc := range []struct {
		name string
		addr string
		sni  string
		opt  PageOptions
		want string // "" for success
	}{
		{"200 over h2, chain verified", addr(ok), "example.com", PageOptions{VerifyChain: true, RootCAs: pool, HTTP2: true}, ""},
		{"200, name only", addr(ok), "example.com", PageOptions{}, ""},
		{"200 over HTTP/1.1 when allowed", addr(h1), "example.com", PageOptions{}, ""},
		{"502", addr(bad), "example.com", PageOptions{HTTP2: true}, "502"},
		{"HTTP/1.1 only when HTTP/2 is wanted", addr(h1), "example.com", PageOptions{HTTP2: true}, "application protocol"},
		{"chain not trusted", addr(ok), "example.com", PageOptions{VerifyChain: true}, "certificate"},
		{"certificate for another name", addr(ok), "other.test", PageOptions{}, "not for the domain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Page(pageCtx(t), tc.addr, tc.sni, tc.opt)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("Page: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("Page: %v, want an error with %q", err, tc.want)
			}
		})
	}
}
