package publicpage

import (
	"net/http"
	"net/netip"
	"strings"
)

// AskRoute is the path of the endpoint that a reverse proxy with on-demand TLS
// asks before it gets a certificate for a name: Caddy's
// on_demand_tls { ask http://127.0.0.1:8080/api/tls/ask }.
const AskRoute = "/api/tls/ask"

// AskHandler answers whether the panel serves a name, so that the reverse
// proxy in front of it gets certificates for the panel's own names and for no
// other:
//
//	GET /api/tls/ask?domain=<name>
//	200  the name is the host of the public page, while the page is enabled,
//	     or one the admin pages were served on (store.DB.AdminHosts)
//	404  any other name, and any peer that is not the reverse proxy
//	400  no name, or one that is not a DNS name
//
// The name is compared in lower case and without a final dot. Only the
// loopback and the peers in trusted (POSTERN_TRUSTED_PROXIES) are answered,
// by the address of the connection, never by X-Forwarded-For. A request that
// carries X-Forwarded-For or Forwarded was relayed by the proxy for somebody
// else, and the proxy's own question never is: it gets a 404 too, so that a
// visitor cannot learn the admin's names through the proxy. There is no auth
// and no body; the answer is never cached. The name is logged at debug only.
//
// The server mounts it ahead of the routing by Host: the proxy may send any
// Host with the question (Caddy sends the one of the ask URL).
func (s *Service) AskHandler(trusted []netip.Prefix) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Length", "0")
		if !askPeer(r, trusted) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		raw := strings.TrimSuffix(r.URL.Query().Get("domain"), ".")
		name, err := checkHost(raw)
		if err != nil || name == "" || name != lowerASCII(raw) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ok, err := s.ownName(r, name)
		if err != nil {
			s.log.Error("could not read the names the admin pages were served on", "err", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		s.log.Debug("on-demand TLS ask", "name", name, "approved", ok)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// ownName reports whether name is one of the panel's: the host of the enabled
// public page or a name the admin pages were served on.
func (s *Service) ownName(r *http.Request, name string) (bool, error) {
	if cfg := s.cfg.Load(); cfg != nil && cfg.Enabled && cfg.Host == name {
		return true, nil
	}
	hosts, err := s.db.AdminHosts(r.Context())
	if err != nil {
		return false, err
	}
	for _, h := range hosts {
		if h.Host == name {
			return true, nil
		}
	}
	return false, nil
}

// askPeer reports whether the request comes straight from the reverse proxy:
// a peer on the loopback or in trusted, with no header that says it relays a
// request of somebody else.
func askPeer(r *http.Request, trusted []netip.Prefix) bool {
	if len(r.Header.Values("X-Forwarded-For")) > 0 || len(r.Header.Values("Forwarded")) > 0 {
		return false
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	addr := ap.Addr().Unmap()
	if addr.IsLoopback() {
		return true
	}
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
