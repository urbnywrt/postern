package publicpage

import (
	"context"
	"net/http"
	"time"

	"github.com/urbnywrt/postern/internal/panel/auth"
)

// adminHostEvery is how often, at most, one name is written to the database
// as a name the admin pages were served on.
const adminHostEvery = time.Hour

// recordTimeout bounds the write of a name, which does not wait for the
// request that brought it.
const recordTimeout = 5 * time.Second

// requestHostKey is the context key of the canonical Host of the request,
// which RecordAdminHosts sets for every request that passes it.
type requestHostKey struct{}

// requestHostOf returns the canonical Host of the request that ctx belongs to,
// or "" when the request did not pass RecordAdminHosts.
func requestHostOf(ctx context.Context) string {
	h, _ := ctx.Value(requestHostKey{}).(string)
	return h
}

// RecordAdminHosts is middleware for the admin chain, inside auth.Middleware:
// it records the canonical Host (HostOf) of every authenticated admin request
// as a name the admin pages are served on, which the page is refused as its
// host, and it gives every request its Host in the context, so that
// UpdatePublicPage can refuse the host of the request that saves it. A name is
// written at most once an hour; the newest 32 are kept (store.MaxAdminHosts).
// A write that fails is logged and holds nothing up.
func (s *Service) RecordAdminHosts(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := HostOf(r)
		ctx := context.WithValue(r.Context(), requestHostKey{}, host)
		if _, ok := auth.AdminFrom(ctx); ok && host != "" {
			s.recordAdminHost(ctx, host)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// recordAdminHost writes host unless it was written within the hour. The time
// is noted whether or not the write goes through, so that a database that
// fails is tried once an hour per name, not once per request.
func (s *Service) recordAdminHost(ctx context.Context, host string) {
	now := s.now()
	s.hostsMu.Lock()
	last, seen := s.hostSeen[host]
	if seen && now.Sub(last) < adminHostEvery {
		s.hostsMu.Unlock()
		return
	}
	s.hostSeen[host] = now
	s.hostsMu.Unlock()

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	if err := s.db.RecordAdminHost(wctx, host, now); err != nil {
		s.log.Warn("could not record a name the admin pages are served on", "host", host, "err", err)
	}
}
