package publicpage

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
)

// maxInFlight is how many requests the public host answers at a time; the
// rest get a 503 and are asked to come back in retryAfter seconds.
const (
	maxInFlight = 64
	retryAfter  = "5"
)

// contentSecurityPolicy is what the page is allowed to do: load its own style
// sheet and script, show its own images (it has none), and nothing else: no
// connection, no font, no frame, no form, no base URL.
const contentSecurityPolicy = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// robotsHeader is sent with every response while noindex is on.
const robotsHeader = "noindex, nofollow, noarchive"

// The two robots.txt files.
const (
	robotsDisallow = "User-agent: *\nDisallow: /\n"
	robotsAllow    = "User-agent: *\nAllow: /\n"
)

// The assets of the page, embedded: nothing is read from the file system, and
// nothing but these two is served under /assets/.
var (
	//go:embed assets/page.css
	pageCSS []byte
	//go:embed assets/copy.js
	copyJS []byte
)

// An asset is one file of the page, under a name that carries the hash of its
// content, so that it can be cached for good.
type asset struct {
	path        string // "/assets/page.<hash>.css"
	contentType string
	data        []byte
}

// The assets by path: the allowlist of what /assets/ serves.
var (
	cssAsset = newAsset("page", "css", "text/css; charset=utf-8", pageCSS)
	jsAsset  = newAsset("copy", "js", "text/javascript; charset=utf-8", copyJS)
	assets   = map[string]*asset{cssAsset.path: cssAsset, jsAsset.path: jsAsset}
)

func newAsset(name, ext, contentType string, data []byte) *asset {
	sum := sha256.Sum256(data)
	return &asset{
		path:        "/assets/" + name + "." + hex.EncodeToString(sum[:8]) + "." + ext,
		contentType: contentType,
		data:        data,
	}
}

// HostOf returns the Host of a request in the form that hosts are compared in:
// lower case, without the port and without one trailing dot. An IPv6 address
// keeps its brackets; it never equals a configured host, which is a DNS name.
func HostOf(r *http.Request) string {
	h := r.Host
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i >= 0 {
			h = h[:i+1]
		}
	} else if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.IndexByte(h, ':') == i {
		h = h[:i]
	}
	return lowerASCII(strings.TrimSuffix(h, "."))
}

// Serves reports whether the request is for the host of the page: the host
// that is configured, enabled or not. Such a request goes to [Service.Handler]
// and never to the admin UI or API. Without a configured host nothing is
// served.
func (s *Service) Serves(r *http.Request) bool {
	cfg := s.cfg.Load()
	return cfg != nil && cfg.Host != "" && HostOf(r) == cfg.Host
}

// Handler returns the public site, with its own headers:
//
//	GET, HEAD /                          the page
//	GET, HEAD /robots.txt
//	GET, HEAD /assets/page.<hash>.css    the style sheet
//	GET, HEAD /assets/copy.<hash>.js     the script that adds the copy buttons
//	anything else                        404, plain text
//	another method                       405
//
// While the page is disabled everything is a 404, other methods included. At
// most maxInFlight requests are answered at a time; the rest get a 503 with
// Retry-After. Every response
// carries Content-Security-Policy, X-Content-Type-Options, X-Frame-Options,
// Referrer-Policy and X-Postern-Page: 1 (the marker that CheckPublicPage looks
// for), and X-Robots-Tag while noindex is on; the page, which holds
// secrets, and everything but the assets are no-store for browsers and CDNs,
// the assets immutable for a year.
func (s *Service) Handler() http.Handler { return http.HandlerFunc(s.serve) }

func (s *Service) serve(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Load()
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set(MarkerHeader, markerValue)
	if cfg == nil || cfg.NoIndex {
		h.Set("X-Robots-Tag", robotsHeader)
	}

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		h.Set("Retry-After", retryAfter)
		plain(w, r, http.StatusServiceUnavailable, "busy, try again shortly")
		return
	}

	// Disabled comes before the method: while the page is off, every request
	// on its host is a 404, and a 405 would tell that the host is configured.
	if cfg == nil || !cfg.Enabled {
		plain(w, r, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		plain(w, r, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// The path as it was sent, percent-encoding kept, is matched whole: an
	// encoded slash, a "..", a query in the wrong place name nothing.
	switch path := r.URL.EscapedPath(); path {
	case "/":
		s.servePage(w, r, cfg)
	case "/robots.txt":
		body := robotsAllow
		if cfg.NoIndex {
			body = robotsDisallow
		}
		noStore(h)
		h.Set("Content-Type", "text/plain; charset=utf-8")
		write(w, r, http.StatusOK, []byte(body))
	default:
		a := assets[path]
		if a == nil {
			plain(w, r, http.StatusNotFound, "not found")
			return
		}
		h.Set("Content-Type", a.contentType)
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
		write(w, r, http.StatusOK, a.data)
	}
}

// noStore marks a response as one that no browser and no CDN may keep.
func noStore(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("CDN-Cache-Control", "no-store")
}

// plain answers with a line of text that is not kept anywhere.
func plain(w http.ResponseWriter, r *http.Request, status int, text string) {
	h := w.Header()
	noStore(h)
	h.Set("Content-Type", "text/plain; charset=utf-8")
	write(w, r, status, []byte(text+"\n"))
}

// write sends the status and the body, or the headers of the body alone for a
// HEAD request.
func write(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
