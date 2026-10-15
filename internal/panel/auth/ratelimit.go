package auth

import (
	"context"
	"slices"
	"sync"
	"time"
)

// The limits on attempts to sign in. A key is an address, or an address and a
// user name, and each has a count of its own.
const (
	// maxFailures failed attempts within failWindow lock a key.
	maxFailures = 5
	failWindow  = 15 * time.Minute

	// The first lock lasts as long as the window, and every lock after it twice
	// as long as the one before, up to maxLockout. A key that has been left alone
	// for strikeMemory after its last lock starts from the first again; so does a
	// key after a successful sign-in.
	maxLockout   = 24 * time.Hour
	strikeMemory = 24 * time.Hour

	// busyWait is what a caller is told to wait when the attempts that are
	// running now may already use up the limit. fullWait is what it is told when
	// the table of keys is full of locks and has no room for another key.
	busyWait = time.Second
	fullWait = time.Minute

	// sweepEvery is the least time between two sweeps of a full table. A sweep
	// visits every key, and a full table that is not made of idle keys would be
	// swept again by every attempt with a new key, which is what anybody could
	// make the panel do by sending user names.
	sweepEvery = time.Second

	// defaultMaxKeys bounds the memory that the limiter uses: a key is a few
	// dozen bytes, and anybody can make keys by sending user names.
	defaultMaxKeys = 50_000

	// More than maxRecentFailures failed attempts within recentWindow, from all
	// the addresses together, slow every attempt down: it waits slowWait before
	// anything about it is looked up or checked. That locks nobody out.
	maxRecentFailures = 100
	recentWindow      = time.Minute
	slowWait          = time.Second
)

// recentFailures tells whether many attempts have failed of late, wherever they
// came from. It keeps the times of the last maxRecentFailures+1 failures, which
// is what it takes: there have been more than maxRecentFailures within
// recentWindow when the oldest of those is within it.
type recentFailures struct {
	mu    sync.Mutex
	times [maxRecentFailures + 1]time.Time // a ring; once it is full, next is the oldest
	next  int
	full  bool
}

// add notes a failure at now.
func (r *recentFailures) add(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.times[r.next] = now
	if r.next++; r.next == len(r.times) {
		r.next, r.full = 0, true
	}
}

// many reports whether more than maxRecentFailures failures were noted within
// recentWindow before now.
func (r *recentFailures) many(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.full && now.Sub(r.times[r.next]) < recentWindow
}

// sleepCtx waits for d. When ctx is done before that, it stops waiting and
// returns the error of ctx.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// A limiter counts failed attempts to sign in by key and refuses the attempts of
// a key that has failed too often.
//
// It counts an attempt from the moment that it is let in, as one that may fail,
// and not when it has failed. Otherwise a client could send a hundred guesses at
// once, all of which would be let in before the first of them had failed. A key
// with failures and running attempts that together reach the limit lets nobody
// else in until the running ones are over: when they fail, the key is locked,
// and when they succeed or are given up, it is open again.
type limiter struct {
	now     func() time.Time
	maxKeys int // replaced by tests

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time // when a full table was last swept
}

// A bucket is what the limiter knows about one key.
type bucket struct {
	fails       int       // failures in the current window
	windowEnd   time.Time // when that window is over
	running     int       // attempts that were let in and are not over
	lockedUntil time.Time // nobody is let in before this
	strikes     int       // locks so far; the next one is twice as long as the last
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, maxKeys: defaultMaxKeys, buckets: make(map[string]*bucket)}
}

// size is the number of keys that are tracked.
func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// settle brings a bucket up to date: a window that is over has no failures, and
// locks that are long ago are forgotten.
func (b *bucket) settle(now time.Time) {
	if !now.Before(b.windowEnd) {
		b.fails = 0
	}
	if b.strikes > 0 && now.After(b.lockedUntil.Add(strikeMemory)) {
		b.strikes = 0
	}
}

// idle reports whether the bucket holds nothing that is worth keeping. It is
// meant to be called on a settled bucket.
func (b *bucket) idle(now time.Time) bool {
	return b.running == 0 && b.fails == 0 && b.strikes == 0 && !now.Before(b.lockedUntil)
}

// lock starts the next lock of the bucket.
func (b *bucket) lock(now time.Time) {
	b.strikes++
	d := maxLockout
	if shift := b.strikes - 1; shift < 7 { // 15 minutes << 7 is more than the cap
		d = min(failWindow<<shift, maxLockout)
	}
	b.lockedUntil = now.Add(d)
	b.fails = 0
	b.windowEnd = time.Time{}
}

// sweep deletes the buckets that are idle, except those of the keys in keep,
// which the attempt that makes room is about to use. The caller holds l.mu.
func (l *limiter) sweep(now time.Time, keep []string) {
	l.lastSweep = now
	for k, b := range l.buckets {
		if slices.Contains(keep, k) {
			continue
		}
		b.settle(now)
		if b.idle(now) {
			delete(l.buckets, k)
		}
	}
}

// distinct returns the keys without the ones that come twice.
func distinct(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// An attempt is one sign-in that the limiter let in. Its verdict is final: the
// first of fail, succeed and release counts, and the others do nothing, so a
// caller can defer release and call fail or succeed where it knows the outcome.
type attempt struct {
	l    *limiter
	keys []string
	done bool // guarded by l.mu
}

// begin lets an attempt in on all the keys, or, when one of them is locked or
// has no room left, refuses it and says how long to wait. It does not count a
// refused attempt, and it makes no key for one.
func (l *limiter) begin(keys ...string) (*attempt, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	keys = distinct(keys)

	var wait time.Duration
	missing := 0 // keys that the table does not have yet
	for _, k := range keys {
		b := l.buckets[k]
		if b == nil {
			missing++
			continue
		}
		b.settle(now)
		switch {
		case now.Before(b.lockedUntil):
			wait = max(wait, b.lockedUntil.Sub(now))
		case b.fails+b.running >= maxFailures:
			wait = max(wait, busyWait)
		}
	}
	if wait > 0 {
		return nil, wait
	}

	// Is there room for the new keys, all of them? This is settled before any key
	// is made, so that a refusal leaves nothing behind, and so that the sweep that
	// makes room cannot take a bucket from under an attempt that is let in: the
	// keys of this attempt are spared by it.
	if missing > 0 && len(l.buckets)+missing > l.maxKeys {
		if d := now.Sub(l.lastSweep); d >= sweepEvery || d < 0 { // d < 0: the clock went back
			l.sweep(now, keys)
		}
		if len(l.buckets)+missing > l.maxKeys {
			return nil, fullWait
		}
	}

	// From here on nothing fails.
	for _, k := range keys {
		b := l.buckets[k]
		if b == nil {
			b = &bucket{}
			l.buckets[k] = b
		}
		b.running++
	}
	return &attempt{l: l, keys: keys}, 0
}

// finish ends the attempt, once, and applies a verdict to every key.
func (a *attempt) finish(verdict func(k string, b *bucket, now time.Time)) {
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.done {
		return
	}
	a.done = true
	now := l.now()
	for _, k := range a.keys {
		b := l.buckets[k]
		if b == nil {
			continue // cannot happen: a bucket with a running attempt is not swept
		}
		b.settle(now)
		b.running--
		verdict(k, b, now)
		if b.idle(now) {
			delete(l.buckets, k)
		}
	}
}

// fail counts the attempt as a failure on every key. It returns the keys that
// the failure has locked.
func (a *attempt) fail() (locked []string) {
	a.finish(func(k string, b *bucket, now time.Time) {
		if b.fails == 0 {
			b.windowEnd = now.Add(failWindow)
		}
		b.fails++
		if b.fails >= maxFailures {
			b.lock(now)
			locked = append(locked, k)
		}
	})
	return locked
}

// succeed ends the attempt as a success, which clears the history of its keys.
func (a *attempt) succeed() {
	a.finish(func(_ string, b *bucket, _ time.Time) {
		*b = bucket{running: b.running}
	})
}

// release ends the attempt without a verdict: it was not a failure, and it did
// not get in either.
func (a *attempt) release() {
	a.finish(func(string, *bucket, time.Time) {})
}

// Limiter is the limiter of sign-ins for another procedure that anybody can
// call and that must not be open to guessing, such as the join of a node. It
// has the limits of the sign-in (maxFailures failures within failWindow lock a
// key, every lock twice as long as the last), and keys of its own: the caller
// chooses them, with a prefix that no other user of the same Limiter has.
type Limiter struct{ l *limiter }

// NewLimiter returns an empty Limiter on the clock of the system.
func NewLimiter() *Limiter { return &Limiter{l: newLimiter(time.Now)} }

// Attempt is one attempt that a [Limiter] let in. The first of Fail, Succeed
// and Release counts and the others do nothing, so a caller can defer Release.
type Attempt struct{ a *attempt }

// Begin lets an attempt in on all the keys. When one of them is locked or has
// no room left it returns the refusal of the sign-in instead: a Connect
// ResourceExhausted error with the seconds to wait in its Retry-After
// metadata.
func (l *Limiter) Begin(keys ...string) (*Attempt, error) {
	a, wait := l.l.begin(keys...)
	if a == nil {
		return nil, tooManyAttempts(wait)
	}
	return &Attempt{a: a}, nil
}

// Fail counts the attempt as a failure on every key.
func (a *Attempt) Fail() { a.a.fail() }

// Succeed ends the attempt as a success, which clears the history of its keys.
func (a *Attempt) Succeed() { a.a.succeed() }

// Release ends the attempt without a verdict.
func (a *Attempt) Release() { a.a.release() }
