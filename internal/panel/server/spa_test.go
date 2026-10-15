package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

const testIndex = `<!doctype html><title>Postern</title><div id="root"></div><script type="module" src="/assets/app-abc123.js"></script>`

func testUI() fstest.MapFS {
	return fstest.MapFS{
		"index.html":            {Data: []byte(testIndex)},
		"favicon.svg":           {Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)},
		"robots.txt":            {Data: []byte("User-agent: *\nDisallow: /\n")},
		"assets/app-abc123.js":  {Data: []byte(`console.log("app")`)},
		"assets/app-abc123.css": {Data: []byte(`body{margin:0}`)},
		"assets/font-1.woff2":   {Data: []byte("wOF2")},
		"assets/data.json":      {Data: []byte(`{"a":1}`)},
		"assets/unknown.xyz123": {Data: []byte("???")},
		"docs/page.html":        {Data: []byte("<!doctype html><title>page</title>")},
		".hidden":               {Data: []byte("secret")},
		"assets/.env":           {Data: []byte("secret")},
		".git/config":           {Data: []byte("secret")},
	}
}

func spaFor(t *testing.T, ui fstest.MapFS) http.Handler {
	t.Helper()
	h, err := newSPA(ui)
	if err != nil {
		t.Fatalf("newSPA: %v", err)
	}
	return h
}

func serveSPA(h http.Handler, method, path string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://panel.example"+path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSPAServesTheFilesOfTheUI(t *testing.T) {
	h := spaFor(t, testUI())
	for _, c := range []struct {
		path, ctype, cache, body string
	}{
		{"/assets/app-abc123.js", "text/javascript; charset=utf-8", "public, max-age=31536000, immutable", `console.log("app")`},
		{"/assets/app-abc123.css", "text/css; charset=utf-8", "public, max-age=31536000, immutable", `body{margin:0}`},
		{"/assets/font-1.woff2", "font/woff2", "public, max-age=31536000, immutable", "wOF2"},
		{"/assets/data.json", "application/json", "public, max-age=31536000, immutable", `{"a":1}`},
		{"/assets/unknown.xyz123", "application/octet-stream", "public, max-age=31536000, immutable", "???"},
		{"/favicon.svg", "image/svg+xml", "no-cache", `<svg xmlns="http://www.w3.org/2000/svg"/>`},
		{"/robots.txt", "text/plain; charset=utf-8", "no-cache", "User-agent: *\nDisallow: /\n"},
		{"/docs/page.html", "text/html; charset=utf-8", "no-cache", "<!doctype html><title>page</title>"},
		{"/index.html", "text/html; charset=utf-8", "no-cache", testIndex},
		{"/", "text/html; charset=utf-8", "no-cache", testIndex},
	} {
		rec := serveSPA(h, http.MethodGet, c.path, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status %d", c.path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != c.ctype {
			t.Errorf("GET %s: Content-Type %q, want %q", c.path, got, c.ctype)
		}
		if got := rec.Header().Get("Cache-Control"); got != c.cache {
			t.Errorf("GET %s: Cache-Control %q, want %q", c.path, got, c.cache)
		}
		if rec.Body.String() != c.body {
			t.Errorf("GET %s: body %q, want %q", c.path, rec.Body.String(), c.body)
		}
	}
}

// What is not a file is the page, so that the router of the page decides.
func TestSPAFallsBackToTheIndex(t *testing.T) {
	h := spaFor(t, testUI())
	for _, path := range []string{
		"/setup", "/login", "/nodes/01ABC", "/a/b/c/d",
		"/assets/", "/assets", "/docs", "/docs/", // a directory is not listed
		"/assets/missing.js",
		"/index.html/", "//index.html",
	} {
		rec := serveSPA(h, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK || rec.Body.String() != testIndex {
			t.Errorf("GET %s: status %d, body %q; want the index", path, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("GET %s: Cache-Control %q, want no-cache: the page of a path that is not a file must not be kept", path, got)
		}
	}
}

// Files that are hidden, and paths that try to leave the UI, are not files.
func TestSPADoesNotServeHiddenFilesOrWhatIsOutside(t *testing.T) {
	h := spaFor(t, testUI())
	for _, path := range []string{
		"/.hidden", "/assets/.env", "/.git/config", "/.git",
		"/../index.html", "/assets/../.hidden", "/assets/../../etc/passwd",
		"/%2e%2e/%2e%2e/etc/passwd", "/assets/%2e%2e/.hidden", "/..%2f..%2fetc/passwd",
	} {
		rec := serveSPA(h, http.MethodGet, path, nil)
		if rec.Body.String() != testIndex {
			t.Errorf("GET %s: body %q, want the index and nothing else", path, rec.Body.String())
		}
	}
}

func TestSPACachesWithEntityTags(t *testing.T) {
	h := spaFor(t, testUI())
	for _, path := range []string{"/assets/app-abc123.js", "/", "/anywhere"} {
		first := serveSPA(h, http.MethodGet, path, nil)
		etag := first.Header().Get("ETag")
		if !strings.HasPrefix(etag, `"`) || len(etag) < 10 {
			t.Fatalf("GET %s: ETag %q is not a strong tag", path, etag)
		}
		again := serveSPA(h, http.MethodGet, path, map[string]string{"If-None-Match": etag})
		if again.Code != http.StatusNotModified || again.Body.Len() != 0 {
			t.Errorf("GET %s with its ETag: status %d with %d bytes, want 304 and none", path, again.Code, again.Body.Len())
		}
		other := serveSPA(h, http.MethodGet, path, map[string]string{"If-None-Match": `"something-else"`})
		if other.Code != http.StatusOK {
			t.Errorf("GET %s with another ETag: status %d, want 200", path, other.Code)
		}
	}
	// Two files that differ do not share a tag.
	a := serveSPA(h, http.MethodGet, "/assets/app-abc123.js", nil).Header().Get("ETag")
	b := serveSPA(h, http.MethodGet, "/assets/app-abc123.css", nil).Header().Get("ETag")
	if a == b {
		t.Errorf("two files have the ETag %s", a)
	}
}

func TestSPAAnswersHEAD(t *testing.T) {
	h := spaFor(t, testUI())
	rec := serveSPA(h, http.MethodHead, "/assets/app-abc123.js", nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: status %d with %d bytes", rec.Code, rec.Body.Len())
	}
	if got := rec.Header().Get("Content-Length"); got != "18" {
		t.Errorf("HEAD: Content-Length %q, want 18", got)
	}
}

func TestSPAHasOnlyReadingMethods(t *testing.T) {
	h := spaFor(t, testUI())
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		rec := serveSPA(h, method, "/", nil)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /: status %d, want 405", method, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s /: Allow %q, want %q", method, got, "GET, HEAD")
		}
	}
}

func TestSPARanges(t *testing.T) {
	h := spaFor(t, testUI())
	rec := serveSPA(h, http.MethodGet, "/assets/app-abc123.js", map[string]string{"Range": "bytes=0-6"})
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "console" {
		t.Errorf("a range: status %d, body %q", rec.Code, rec.Body.String())
	}
}

func TestSPANeedsAnIndex(t *testing.T) {
	ui := testUI()
	delete(ui, "index.html")
	if _, err := newSPA(ui); err == nil {
		t.Error("newSPA accepted a UI without index.html")
	}
	// The panel does not start with it either.
	dir := t.TempDir()
	if srv, err := New(Config{DataDir: dir + "/data", KeysDir: dir + "/keys", UI: ui}); err == nil {
		_ = srv.Close()
		t.Error("New accepted a UI without index.html")
	}
}

// The UI of the configuration is the one that is served, and the API is not
// shadowed by a file of the same name.
func TestConfiguredUIIsServedAndTheAPIIsNotShadowed(t *testing.T) {
	ui := testUI()
	ui["api/postern.panel.v1.HealthService/Check"] = &fstest.MapFile{Data: []byte("not the API")}
	p := newPanel(t, func(c *Config) { c.UI = ui })

	resp, body := p.get("/assets/app-abc123.js")
	if resp.StatusCode != http.StatusOK || body != `console.log("app")` {
		t.Errorf("a file of the configured UI: %d %q", resp.StatusCode, body)
	}
	if resp, body := p.post(healthCheck, `{}`); resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != "{}" {
		t.Errorf("the API under /api: %d %q", resp.StatusCode, body)
	}
	if resp, body := p.get("/api/some/file.js"); resp.StatusCode != http.StatusNotFound || strings.Contains(body, "console") {
		t.Errorf("an unknown API path: %d %q, want the 404 of the API", resp.StatusCode, body)
	}
}
