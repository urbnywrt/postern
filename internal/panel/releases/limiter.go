package releases

import (
	"context"
	"sync"
	"time"
)

// How many requests the release APIs get from the panel in an hour, in all:
// GitHub allows 60 an hour per address without a token and 5000 with one (F8);
// the panel stays well under both so that a 304, which counts too, and the
// admin's own requests from the same address do not run it dry.
const (
	limitAnonymous     = 50
	limitAuthenticated = 1000
	limitWindow        = time.Hour
)

// A Limiter paces every API request of the panel to the release feeds: at most
// limitAnonymous an hour without a token and limitAuthenticated with one, and
// none before the time that a 403 or 429 told the panel to wait until.
//
// It also remembers, for every list, the page size that the list could be read
// at within the page limit (see [FetchReleases]): the one thing about a feed
// that every poll of it shares.
type Limiter struct {
	now   func() time.Time
	mu    sync.Mutex
	sent  []time.Time // the times of the requests of the last hour, oldest first
	until time.Time   // no request before this
	sizes map[string]int
}

// NewLimiter returns a limiter that reads the clock now (nil is time.Now).
func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, sizes: map[string]int{}}
}

// pageSize returns the page size remembered for the list key, 0 for none.
func (l *Limiter) pageSize(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sizes[key]
}

// setPageSize remembers the page size of the list key.
func (l *Limiter) setPageSize(key string, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sizes == nil {
		l.sizes = map[string]int{}
	}
	l.sizes[key] = n
}

// Wait blocks until a request may be sent, and counts it: authenticated says
// whether the request carries a token. It returns the error of ctx when that
// ends first; the request is then not counted.
func (l *Limiter) Wait(ctx context.Context, authenticated bool) error {
	for {
		l.mu.Lock()
		d := l.delay(authenticated)
		if d <= 0 {
			l.sent = append(l.sent, l.now())
			l.mu.Unlock()
			return nil
		}
		l.mu.Unlock()
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// delay returns how long the next request has to wait; 0 or less for none.
// The caller holds the lock.
func (l *Limiter) delay(authenticated bool) time.Duration {
	now := l.now()
	cut := now.Add(-limitWindow)
	i := 0
	for i < len(l.sent) && !l.sent[i].After(cut) {
		i++
	}
	l.sent = l.sent[i:]
	d := l.until.Sub(now)
	limit := limitAnonymous
	if authenticated {
		limit = limitAuthenticated
	}
	if len(l.sent) >= limit {
		if w := l.sent[len(l.sent)-limit].Add(limitWindow).Sub(now); w > d {
			d = w
		}
	}
	return d
}

// Defer holds every request back until t, when t is later than what the
// limiter already waits for: the time that a 403 or 429 named.
func (l *Limiter) Defer(t time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t.After(l.until) {
		l.until = t
	}
}

// Until returns the time before which no request is sent, the zero time for
// none.
func (l *Limiter) Until() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.until
}
