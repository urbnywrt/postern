package publicpage

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
)

func TestHostOf(t *testing.T) {
	for host, want := range map[string]string{
		"proxies.example.test":      "proxies.example.test",
		"Proxies.Example.Test":      "proxies.example.test",
		"proxies.example.test:8443": "proxies.example.test",
		"proxies.example.test.":     "proxies.example.test",
		"Proxies.Example.Test.:443": "proxies.example.test",
		"proxies.example.test..":    "proxies.example.test.",
		"[2001:db8::1]:443":         "[2001:db8::1]",
		"[2001:DB8::1]":             "[2001:db8::1]",
		"2001:db8::1":               "2001:db8::1",
		"192.0.2.1:80":              "192.0.2.1",
		"":                          "",
		":443":                      "",
		"İstanbul.example.test:":    "İstanbul.example.test", // not ASCII: left as it is
	} {
		if got := HostOf(&http.Request{Host: host}); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", host, got, want)
		}
	}
}

// Nothing is served until a host is configured; then every spelling of the host
// is served, enabled or not, and no other host is.
func TestServes(t *testing.T) {
	e := newEnv(t)
	req := func(host string) *http.Request { return &http.Request{Host: host} }
	if e.svc.Serves(req(publicHost)) || e.svc.Serves(req("")) {
		t.Error("a page without a host serves something")
	}
	e.setPage(&panelv1.PublicPage{Host: publicHost}) // disabled
	for _, host := range []string{publicHost, "Proxies.Example.Test", publicHost + ":8443", publicHost + ".", "PROXIES.example.TEST.:80"} {
		if !e.svc.Serves(req(host)) {
			t.Errorf("Serves(%q) = false", host)
		}
	}
	for _, host := range []string{"", "example.test", "www." + publicHost, publicHost + ".example", "127.0.0.1:8080", "[::1]:8080"} {
		if e.svc.Serves(req(host)) {
			t.Errorf("Serves(%q) = true", host)
		}
	}
	resp, body := e.get(http.MethodGet, "/", publicHost, nil)
	if resp.StatusCode != http.StatusNotFound || body != "not found\n" {
		t.Errorf("a disabled page: %d %q, want 404 not found", resp.StatusCode, body)
	}
}

// publicHeaders is what every response of the public site carries.
var publicHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
	"X-Content-Type-Options":  "nosniff",
	"X-Frame-Options":         "DENY",
	"Referrer-Policy":         "no-referrer",
}

func checkPublicHeaders(t *testing.T, what string, resp *http.Response, noindex bool) {
	t.Helper()
	for name, want := range publicHeaders {
		if got := resp.Header.Values(name); len(got) != 1 || got[0] != want {
			t.Errorf("%s: %s = %q, want exactly [%q]", what, name, got, want)
		}
	}
	got := resp.Header.Get("X-Robots-Tag")
	switch {
	case noindex && got != robotsHeader:
		t.Errorf("%s: X-Robots-Tag = %q, want %q", what, got, robotsHeader)
	case !noindex && got != "":
		t.Errorf("%s: X-Robots-Tag = %q, want none", what, got)
	}
}

func checkNoStore(t *testing.T, what string, resp *http.Response) {
	t.Helper()
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("%s: Cache-Control = %q, want no-store", what, cc)
	}
	if cc := resp.Header.Get("CDN-Cache-Control"); cc != "no-store" {
		t.Errorf("%s: CDN-Cache-Control = %q, want no-store", what, cc)
	}
}

func TestHeadersOnEveryResponse(t *testing.T) {
	e := newEnv(t)
	e.fixture()

	for _, c := range []struct {
		name, method, path string
		status             int
		contentType        string
	}{
		{"the page", "GET", "/", 200, "text/html; charset=utf-8"},
		{"the page, HEAD", "HEAD", "/", 200, "text/html; charset=utf-8"},
		{"robots.txt", "GET", "/robots.txt", 200, "text/plain; charset=utf-8"},
		{"a path that is nothing", "GET", "/setup", 404, "text/plain; charset=utf-8"},
		{"the API", "POST", "/api/postern.panel.v1.HealthService/Check", 405, "text/plain; charset=utf-8"},
		{"an unknown asset", "GET", "/assets/nope.js", 404, "text/plain; charset=utf-8"},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp, body := e.get(c.method, c.path, publicHost, nil)
			if resp.StatusCode != c.status {
				t.Errorf("status %d, want %d; body %.100q", resp.StatusCode, c.status, body)
			}
			if ct := resp.Header.Get("Content-Type"); ct != c.contentType {
				t.Errorf("Content-Type %q, want %q", ct, c.contentType)
			}
			checkPublicHeaders(t, c.name, resp, true)
			checkNoStore(t, c.name, resp)
			if c.method == "HEAD" {
				if body != "" {
					t.Error("a HEAD response has a body")
				}
				if n, _ := strconv.Atoi(resp.Header.Get("Content-Length")); n <= 0 {
					t.Error("a HEAD response has no Content-Length")
				}
			}
			if c.status == 405 && resp.Header.Get("Allow") != "GET, HEAD" {
				t.Errorf("Allow = %q", resp.Header.Get("Allow"))
			}
		})
	}
	for _, a := range []*asset{cssAsset, jsAsset} {
		t.Run(a.path, func(t *testing.T) {
			resp, body := e.get(http.MethodGet, a.path, publicHost, nil)
			if resp.StatusCode != 200 || body != string(a.data) {
				t.Errorf("status %d, body of %d bytes, want 200 and the asset", resp.StatusCode, len(body))
			}
			if ct := resp.Header.Get("Content-Type"); ct != a.contentType {
				t.Errorf("Content-Type %q, want %q", ct, a.contentType)
			}
			if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
				t.Errorf("Cache-Control = %q", cc)
			}
			if cc := resp.Header.Get("CDN-Cache-Control"); cc != "" {
				t.Errorf("CDN-Cache-Control = %q, want none: an asset may be cached by a CDN", cc)
			}
			checkPublicHeaders(t, a.path, resp, true)
		})
	}
	e.assertNoSecretsLogged()
}

// The robots switch (S6-3): a page saved without allow_indexing, or with it
// false, sends the header and a robots.txt that disallows everything; with it
// true, neither.
func TestRobotsBothWays(t *testing.T) {
	e := newEnv(t)
	f := e.fixture() // saved without the field

	noindexOn := func(how string) {
		t.Helper()
		resp, body := e.get(http.MethodGet, "/robots.txt", publicHost, nil)
		if body != robotsDisallow || resp.Header.Get("X-Robots-Tag") != robotsHeader {
			t.Errorf("%s: robots.txt %q, X-Robots-Tag %q", how, body, resp.Header.Get("X-Robots-Tag"))
		}
		resp, _ = e.get(http.MethodGet, "/nope", publicHost, nil)
		if resp.Header.Get("X-Robots-Tag") != robotsHeader {
			t.Errorf("%s: a 404 without X-Robots-Tag", how)
		}
		if page := e.page(""); !strings.Contains(page, `<meta name="robots" content="noindex, nofollow, noarchive">`) {
			t.Errorf("%s: the page has no robots meta", how)
		}
	}
	noindexOn("allow_indexing left out")
	f.page.AllowIndexing = false
	e.setPage(f.page)
	noindexOn("allow_indexing false")
	if got, _ := e.admin.GetPublicPage(e.ctx, connect.NewRequest(&panelv1.GetPublicPageRequest{})); got.Msg.GetPage().GetAllowIndexing() {
		t.Error("GetPublicPage says indexing is allowed")
	}

	f.page.AllowIndexing = true
	e.setPage(f.page)
	resp, body := e.get(http.MethodGet, "/robots.txt", publicHost, nil)
	if body != robotsAllow || resp.Header.Get("X-Robots-Tag") != "" {
		t.Errorf("noindex off: robots.txt %q, X-Robots-Tag %q", body, resp.Header.Get("X-Robots-Tag"))
	}
	checkPublicHeaders(t, "robots.txt, noindex off", resp, false)
	resp, _ = e.get(http.MethodGet, "/", publicHost, nil)
	checkPublicHeaders(t, "the page, noindex off", resp, false)
	resp, _ = e.get(http.MethodGet, "/nope", publicHost, nil)
	checkPublicHeaders(t, "a 404, noindex off", resp, false)
	if page := e.page(""); strings.Contains(page, `name="robots"`) {
		t.Error("noindex off: the page has a robots meta")
	}
	if got, _ := e.admin.GetPublicPage(e.ctx, connect.NewRequest(&panelv1.GetPublicPageRequest{})); !got.Msg.GetPage().GetAllowIndexing() {
		t.Error("GetPublicPage says indexing is not allowed")
	}
}

// While the page is disabled every request on its host is a 404, whatever the
// method: a 405 would tell that the host is configured.
func TestDisabledHostAnswers404ToEveryMethod(t *testing.T) {
	e := newEnv(t)
	f := e.fixture()
	f.page.Enabled = false
	e.setPage(f.page)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		for _, path := range []string{"/", "/robots.txt", cssAsset.path, "/api/postern.panel.v1.HealthService/Check"} {
			resp, body := e.get(method, path, publicHost, nil)
			if resp.StatusCode != http.StatusNotFound || (method != http.MethodHead && body != "not found\n") || resp.Header.Get("Allow") != "" {
				t.Errorf("%s %s on the disabled host: %d %q, Allow %q; want 404 not found", method, path, resp.StatusCode, body, resp.Header.Get("Allow"))
			}
			checkPublicHeaders(t, method+" "+path, resp, true)
		}
	}
	// Enabled again, the method is looked at.
	f.page.Enabled = true
	e.setPage(f.page)
	if resp, _ := e.get(http.MethodPost, "/", publicHost, nil); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST / on the enabled host: %d, want 405", resp.StatusCode)
	}
}

// Only the two embedded assets are served, by their exact names.
func TestAssetAllowlist(t *testing.T) {
	e := newEnv(t)
	e.fixture()
	cssName := strings.TrimPrefix(cssAsset.path, "/assets/")
	for _, path := range []string{
		"/assets/page.css", "/assets/" + strings.Replace(cssName, "page.", "Page.", 1), "/assets/../" + cssName,
		"/assets%2F" + cssName, "/assets/" + strings.ReplaceAll(cssName, ".", "%2E"), cssAsset.path + "/", cssAsset.path + "x",
		"/assets/..%2F" + cssName, "/assets/", "/assets", "/" + cssName, "/index.html", "/favicon.ico",
	} {
		resp, body := e.get(http.MethodGet, path, publicHost, nil)
		if resp.StatusCode != http.StatusNotFound || body != "not found\n" {
			t.Errorf("GET %s: %d %q, want 404", path, resp.StatusCode, body)
		}
	}
	if len(assets) != 2 || assets[cssAsset.path] == nil || assets[jsAsset.path] == nil {
		t.Errorf("the allowlist is %v", assets)
	}
	if !strings.HasPrefix(cssAsset.path, "/assets/page.") || !strings.HasSuffix(cssAsset.path, ".css") || len(cssAsset.path) != len("/assets/page..css")+16 {
		t.Errorf("the css asset is at %q", cssAsset.path)
	}
}

// The 65th request in flight gets a 503 and is asked back in 5 seconds.
func TestOverTheCap(t *testing.T) {
	e := newEnv(t)
	e.fixture()
	gate := make(chan struct{})
	probed := make(chan string, 4*maxInFlight)
	e.downMu.Lock()
	e.gate, e.probed = gate, probed
	e.downMu.Unlock()

	var wg sync.WaitGroup
	statuses := make(chan int, maxInFlight)
	for range maxInFlight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := e.get(http.MethodGet, "/", publicHost, nil)
			statuses <- resp.StatusCode
		}()
	}
	// Every one of them is inside the render, waiting at the gate.
	for range maxInFlight {
		<-probed
	}
	resp, body := e.get(http.MethodGet, "/", publicHost, nil)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "5" {
		t.Errorf("the request over the cap: %d, Retry-After %q, body %q", resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
	checkPublicHeaders(t, "a 503", resp, true)
	checkNoStore(t, "a 503", resp)
	// An asset over the cap is refused as well: the cap is on the host.
	if resp, _ := e.get(http.MethodGet, cssAsset.path, publicHost, nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("an asset over the cap: %d", resp.StatusCode)
	}

	close(gate)
	wg.Wait()
	close(statuses)
	for st := range statuses {
		if st != http.StatusOK {
			t.Errorf("a request under the cap: %d", st)
		}
	}
	e.downMu.Lock()
	e.gate, e.probed = nil, nil
	e.downMu.Unlock()
	if resp, _ := e.get(http.MethodGet, "/", publicHost, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("after the burst: %d", resp.StatusCode)
	}
}
