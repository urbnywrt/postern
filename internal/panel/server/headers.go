package server

import "net/http"

// contentSecurityPolicy is what the UI is allowed to do: load its own scripts,
// styles, fonts and images, inline styles (the component library sets them),
// and images from data: URLs (the QR codes of the proxy links); talk to its own
// origin, which is the API; and nothing else. frame-ancestors forbids every
// page to put the panel in a frame, whatever X-Frame-Options says in a browser
// that does not know the directive.
//
// base-uri and form-action are directives that default-src does not fall back
// to, so without them nothing would limit what they guard: base-uri keeps an
// injected <base> element from turning the relative links of the page into
// links to another origin; form-action keeps a form, an injected one too, from
// posting what is typed in it (the password of the sign-in) to another origin.
// object-src is one that default-src does stand in for, with 'self': 'none'
// narrows that to no plug-in content (<object>, <embed>) at all, which the UI
// has no use for.
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; " +
	"base-uri 'self'; form-action 'self'; object-src 'none'"

// securityHeaders sets the headers that every response of the panel carries,
// whoever writes it: the UI, the API, a refusal of the authentication, the
// router that does not know a path.
//
//   - Content-Security-Policy, see contentSecurityPolicy;
//   - X-Frame-Options: DENY, the same for old browsers;
//   - X-Content-Type-Options: nosniff, so that a file is what its Content-Type
//     says, and a download of a bundle is never taken for a page;
//   - Referrer-Policy: no-referrer, so that the address of the panel, which has
//     the setup token in it on the first visit, is not sent to anybody.
//
// They are set before the handler runs. The responses that net/http writes
// without a handler (a request that is malformed, a header that is too large) do
// not have them; they carry no content that a browser could be made to run.
//
// These are the headers of the admin. The public page, on its own host, never
// passes here: it sets a stricter policy of its own (publicpage.Handler), with
// no inline style and no data: image.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
