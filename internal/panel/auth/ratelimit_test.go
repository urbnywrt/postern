package auth

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

func newTestLimiter() (*limiter, *fakeClock) {
	clock := newClock()
	return newLimiter(clock.Now), clock
}

// failN lets n attempts in, one after the other, and fails them all.
func failN(t *testing.T, l *limiter, n int, keys ...string) {
	t.Helper()
	for i := range n {
		a, wait := l.begin(keys...)
		if a == nil {
			t.Fatalf("attempt %d of %d was refused for %v", i+1, n, wait)
		}
		a.fail()
	}
}

func TestLimiterLocksAfterFiveFailures(t *testing.T) {
	l, clock := newTestLimiter()
	failN(t, l, maxFailures-1, "user:a")
	if a, _ := l.begin("user:a"); a == nil {
		t.Fatal("refused after four failures")
	} else {
		a.release()
	}

	failN(t, l, 1, "user:a")
	a, wait := l.begin("user:a")
	if a != nil {
		t.Fatal("not refused after five failures")
	}
	if wait != 15*time.Minute {
		t.Errorf("wait = %v, want 15m", wait)
	}

	// Other keys are not affected.
	if a, _ := l.begin("user:b"); a == nil {
		t.Error("another key was refused")
	} else {
		a.release()
	}

	// The wait counts down, and the lock ends when it reaches zero.
	clock.Advance(10 * time.Minute)
	if a, wait := l.begin("user:a"); a != nil || wait != 5*time.Minute {
		t.Errorf("after 10 minutes: attempt %v, wait %v, want a refusal for 5m", a, wait)
	}
	clock.Advance(5 * time.Minute)
	a, wait = l.begin("user:a")
	if a == nil {
		t.Fatalf("still refused at the end of the lock (%v)", wait)
	}
	a.release()
}

func TestLimiterLocksGrowAndAreForgotten(t *testing.T) {
	l, clock := newTestLimiter()
	for _, want := range []time.Duration{
		15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour, 16 * time.Hour,
		24 * time.Hour, 24 * time.Hour, 24 * time.Hour, // capped
	} {
		failN(t, l, maxFailures, "k")
		a, wait := l.begin("k")
		if a != nil || wait != want {
			t.Fatalf("lock of %v expected, got attempt %v and wait %v", want, a, wait)
		}
		clock.Advance(want)
	}

	// A day of peace after the last lock, and the next one is the first again.
	clock.Advance(strikeMemory + time.Second)
	failN(t, l, maxFailures, "k")
	if _, wait := l.begin("k"); wait != 15*time.Minute {
		t.Errorf("lock after a quiet day = %v, want 15m", wait)
	}
}

func TestLimiterCountsFailuresInAWindow(t *testing.T) {
	l, clock := newTestLimiter()
	failN(t, l, maxFailures-1, "k")
	clock.Advance(failWindow) // the window of those failures is over
	failN(t, l, maxFailures-1, "k")
	if a, _ := l.begin("k"); a == nil {
		t.Fatal("failures of two windows were added up")
	} else {
		a.release()
	}

	// Failures within one window are, however they are spread over it.
	l2, clock2 := newTestLimiter()
	failN(t, l2, 2, "k")
	clock2.Advance(failWindow - time.Second)
	failN(t, l2, maxFailures-2, "k")
	if a, wait := l2.begin("k"); a != nil || wait != 15*time.Minute {
		t.Fatalf("five failures in 14m59s: attempt %v, wait %v, want a lock of 15m", a, wait)
	}
}

func TestLimiterSuccessClears(t *testing.T) {
	l, clock := newTestLimiter()
	failN(t, l, maxFailures, "k")
	clock.Advance(15 * time.Minute)
	if l.size() != 1 {
		t.Fatalf("%d keys, want 1", l.size())
	}
	a, _ := l.begin("k")
	if a == nil {
		t.Fatal("refused after the lock")
	}
	a.succeed()
	if l.size() != 0 {
		t.Errorf("%d keys after a success, want none", l.size())
	}
	// The strike of the first lock is forgotten, too.
	failN(t, l, maxFailures, "k")
	if _, wait := l.begin("k"); wait != 15*time.Minute {
		t.Errorf("lock after a success = %v, want 15m", wait)
	}
}

func TestLimiterAttemptsCountOnEveryKey(t *testing.T) {
	l, _ := newTestLimiter()
	// Five failures with five different names from one address.
	for i := range maxFailures {
		failN(t, l, 1, "ip:x", fmt.Sprintf("user:%d", i))
	}
	if a, wait := l.begin("ip:x", "user:new"); a != nil || wait != 15*time.Minute {
		t.Errorf("address not locked: attempt %v, wait %v", a, wait)
	}
	// None of the names is.
	if a, _ := l.begin("ip:y", "user:0"); a == nil {
		t.Error("a name that failed once was refused")
	} else {
		a.release()
	}

	// A refusal on one key lets nothing in and counts nothing on the other.
	l2, _ := newTestLimiter()
	failN(t, l2, maxFailures, "ip:x")
	for range 3 * maxFailures {
		if a, _ := l2.begin("ip:x", "user:z"); a != nil {
			t.Fatal("let in")
		}
	}
	if a, _ := l2.begin("ip:other", "user:z"); a == nil {
		t.Error("refusals were counted against the other key")
	}
}

func TestLimiterReportsTheLongestWait(t *testing.T) {
	l, clock := newTestLimiter()
	failN(t, l, maxFailures, "a")
	clock.Advance(5 * time.Minute)
	failN(t, l, maxFailures, "b")
	if _, wait := l.begin("a", "b"); wait != 15*time.Minute {
		t.Errorf("wait = %v, want the 15m of b", wait)
	}
	if _, wait := l.begin("b", "a"); wait != 15*time.Minute {
		t.Errorf("wait = %v, want the 15m of b", wait)
	}
}

// Attempts that have started count as failures until they are over, so that
// parallel requests cannot make more tries than the limit.
func TestLimiterCountsAttemptsThatAreStillRunning(t *testing.T) {
	l, clock := newTestLimiter()
	var running []*attempt
	for range maxFailures {
		a, wait := l.begin("k")
		if a == nil {
			t.Fatalf("refused with %d running (%v)", len(running), wait)
		}
		running = append(running, a)
	}
	a, wait := l.begin("k")
	if a != nil || wait != busyWait {
		t.Fatalf("sixth running attempt: %v, wait %v, want a refusal for %v", a, wait, busyWait)
	}

	// One that ends without a verdict (a TOTP code is still to come) makes room.
	running[0].release()
	a, _ = l.begin("k")
	if a == nil {
		t.Fatal("refused although one attempt ended")
	}
	running = append(running[1:], a)

	// The others fail: five failures, and now it is a lock, not a wait.
	for _, a := range running {
		a.fail()
	}
	if a, wait := l.begin("k"); a != nil || wait != 15*time.Minute {
		t.Errorf("after the failures: %v, wait %v, want a lock of 15m", a, wait)
	}

	// A verdict is final: failing twice, or failing after a release, counts once.
	clock.Advance(15 * time.Minute)
	a, _ = l.begin("k")
	a.fail()
	a.fail()
	a.release()
	a.succeed()
	failN(t, l, maxFailures-2, "k") // 1 + 3 = 4 failures in this window
	if a, _ := l.begin("k"); a == nil {
		t.Error("a verdict was counted more than once")
	} else {
		a.release()
	}
}

func TestLimiterIsBounded(t *testing.T) {
	l, clock := newTestLimiter()
	l.maxKeys = 10

	// Keys with one failure each are idle again after the window.
	for i := range 10 {
		failN(t, l, 1, fmt.Sprintf("k%d", i))
	}
	if l.size() != 10 {
		t.Fatalf("%d keys, want 10", l.size())
	}
	// Full, and nothing can go: a new key is refused for a while rather than
	// stored.
	if a, wait := l.begin("new"); a != nil || wait != fullWait {
		t.Fatalf("full table: attempt %v, wait %v, want a refusal for %v", a, wait, fullWait)
	}
	if l.size() != 10 {
		t.Errorf("%d keys after a refusal, want 10", l.size())
	}

	// When the old failures are over, room is made.
	clock.Advance(failWindow)
	a, _ := l.begin("new")
	if a == nil {
		t.Fatal("refused although the old keys were idle")
	}
	a.release()
	if l.size() > 10 {
		t.Errorf("%d keys, the limit is 10", l.size())
	}

	// A table of locks is not emptied by the sweep: those keys are in use.
	l2, _ := newTestLimiter()
	l2.maxKeys = 4
	for i := range 4 {
		failN(t, l2, maxFailures, fmt.Sprintf("k%d", i))
	}
	if a, _ := l2.begin("new"); a != nil {
		t.Error("a new key was let in although the table is full of locks")
	}
	if a, wait := l2.begin("k0"); a != nil || wait != 15*time.Minute {
		t.Errorf("a key that is locked lost its lock: %v, %v", a, wait)
	}
}

func TestLimiterCountsNothingForKeysThatAreRefused(t *testing.T) {
	l, _ := newTestLimiter()
	failN(t, l, maxFailures, "locked")
	for i := range 100 {
		if a, _ := l.begin("locked", fmt.Sprintf("other%d", i)); a != nil {
			t.Fatal("let in")
		}
	}
	// The refusals made no keys.
	if l.size() != 1 {
		t.Errorf("%d keys, want 1", l.size())
	}
}

// More than maxRecentFailures failures within recentWindow are many; as many,
// or older ones, are not.
func TestRecentFailures(t *testing.T) {
	var r recentFailures
	if r.many(t0) {
		t.Fatal("no failure is many")
	}
	for i := range maxRecentFailures {
		r.add(t0.Add(time.Duration(i) * 100 * time.Millisecond))
	}
	last := t0.Add(time.Duration(maxRecentFailures-1) * 100 * time.Millisecond)
	if r.many(last) {
		t.Fatalf("%d failures are many", maxRecentFailures)
	}
	r.add(last)
	if !r.many(last) {
		t.Fatalf("%d failures within %v are not many", maxRecentFailures+1, last.Sub(t0))
	}
	// They are as long as the first of them is less than a minute old.
	if !r.many(t0.Add(recentWindow - time.Nanosecond)) {
		t.Error("not many any more before the first failure is a minute old")
	}
	if r.many(t0.Add(recentWindow)) {
		t.Error("still many when the first failure is a minute old")
	}

	// A steady 100 a minute is never many, however long it goes on.
	var steady recentFailures
	at := t0
	for range 10 * maxRecentFailures {
		steady.add(at)
		if steady.many(at) {
			t.Fatalf("100 failures a minute are many at %v", at.Sub(t0))
		}
		at = at.Add(recentWindow / maxRecentFailures)
	}
	// One more within the minute is.
	steady.add(at.Add(-time.Millisecond))
	if !steady.many(at.Add(-time.Millisecond)) {
		t.Error("101 failures within a minute after a long steady stream are not many")
	}
}

// lastSweepAt is when the limiter last swept a full table.
func (l *limiter) lastSweepAt() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastSweep
}

// Two keys that are new, and room for one: the attempt is refused as a whole and
// leaves no key behind, not even the one that would have fitted.
func TestLimiterRefusesNewKeysThatDoNotFitAndMakesNone(t *testing.T) {
	l, _ := newTestLimiter()
	l.maxKeys = 3
	failN(t, l, 1, "a")
	failN(t, l, 1, "b")

	for range 3 { // again and again: nothing is made, nothing is swept away
		a, wait := l.begin("ip:new", "user:new")
		if a != nil || wait != fullWait {
			t.Fatalf("two new keys, room for one: attempt %v, wait %v, want a refusal for %v", a, wait, fullWait)
		}
		if l.size() != 2 {
			t.Fatalf("%d keys after the refusal, want the 2 that were there", l.size())
		}
	}
	// Either of the two alone fits.
	a, wait := l.begin("ip:new")
	if a == nil {
		t.Fatalf("one new key, room for one: refused for %v", wait)
	}
	a.fail()
}

// The table can be filled up to the limit exactly, by one attempt with two new
// keys, and then not a key more.
func TestLimiterLetsNewKeysInUpToTheLimit(t *testing.T) {
	l, _ := newTestLimiter()
	l.maxKeys = 4
	failN(t, l, 1, "a")
	failN(t, l, 1, "b")

	att, wait := l.begin("c", "d")
	if att == nil {
		t.Fatalf("two new keys, room for two: refused for %v", wait)
	}
	if l.size() != 4 {
		t.Fatalf("%d keys, want 4", l.size())
	}
	att.fail()
	if a, wait := l.begin("e"); a != nil || wait != fullWait {
		t.Errorf("a fifth key: attempt %v, wait %v, want a refusal for %v", a, wait, fullWait)
	}
	if l.size() != 4 {
		t.Errorf("%d keys after the refusal, want 4", l.size())
	}
	// Keys that exist need no room, and an attempt with one of them and a new key
	// is refused as a whole.
	if a, wait := l.begin("a", "c"); a == nil {
		t.Errorf("two keys that exist: refused for %v", wait)
	} else {
		a.release()
	}
	if a, wait := l.begin("a", "e"); a != nil || wait != fullWait {
		t.Errorf("a key that exists and a new one: attempt %v, wait %v, want a refusal for %v", a, wait, fullWait)
	}
}

// A key whose window is over is idle, and the sweep that makes room must not
// take it from the attempt that is about to use it, nor the key that the same
// attempt has just made.
func TestLimiterSweepSparesTheKeysOfTheAttempt(t *testing.T) {
	l, clock := newTestLimiter()
	l.maxKeys = 3
	failN(t, l, 1, "old")              // idle once its window is over
	failN(t, l, 1, "stale")            // idle too: this one the sweep may take
	failN(t, l, maxFailures, "locked") // keeps its strike for a day
	clock.Advance(failWindow)          // the windows and the lock are over
	if l.size() != 3 {
		t.Fatalf("%d keys, want a full table of 3", l.size())
	}

	att, wait := l.begin("old", "new")
	if att == nil {
		t.Fatalf("refused for %v, although the sweep makes room", wait)
	}
	if l.size() != 3 {
		t.Errorf("%d keys, want old, new and locked (stale was swept)", l.size())
	}
	for _, key := range []string{"old", "new"} {
		if got := l.runningOn(key); got != 1 {
			t.Errorf("%d attempts running on %q, want 1", got, key)
		}
	}
	att.fail() // finds its keys where it left them
	if got := l.runningOn("old") + l.runningOn("new"); got != 0 {
		t.Errorf("%d attempts still running after the verdict", got)
	}
	if l.size() != 3 {
		t.Errorf("%d keys after the verdict, want 3", l.size())
	}
	// Its failure was written to the bucket that the table holds, not to one that
	// the sweep had taken out: four more are the fifth.
	failN(t, l, maxFailures-1, "old")
	if a, _ := l.begin("old"); a != nil {
		t.Error("the failure of the attempt was lost: old is not locked after five")
	}
}

// When the sweep cannot make room, the keys that exist stay, none is made, and
// the refusal is as for any full table.
func TestLimiterWithNoRoomAfterTheSweepKeepsWhatItHas(t *testing.T) {
	l, clock := newTestLimiter()
	l.maxKeys = 2
	failN(t, l, 1, "old")
	failN(t, l, maxFailures, "locked")
	clock.Advance(failWindow)

	a, wait := l.begin("old", "new")
	if a != nil || wait != fullWait {
		t.Fatalf("attempt %v, wait %v, want a refusal for %v", a, wait, fullWait)
	}
	if l.size() != 2 {
		t.Errorf("%d keys, want 2", l.size())
	}
	// "old" is still a key the table holds, and it is let in on its own.
	a, wait = l.begin("old")
	if a == nil {
		t.Fatalf("old alone: refused for %v", wait)
	}
	a.fail()
}

func TestLimiterSweepsAFullTableAtMostOncePerSecond(t *testing.T) {
	l, clock := newTestLimiter()
	l.maxKeys = 4
	for i := range 4 {
		failN(t, l, maxFailures, fmt.Sprintf("k%d", i)) // locked: nothing to sweep
	}
	for i := range 50 {
		if a, wait := l.begin(fmt.Sprintf("new%d", i)); a != nil || wait != fullWait {
			t.Fatalf("attempt %d: %v, wait %v, want a refusal for %v", i, a, wait, fullWait)
		}
	}
	first := l.lastSweepAt()
	if !first.Equal(clock.Now()) {
		t.Fatalf("last sweep at %v, want the one at %v that the first refusal made", first, clock.Now())
	}

	clock.Advance(500 * time.Millisecond)
	l.begin("x")
	if got := l.lastSweepAt(); !got.Equal(first) {
		t.Errorf("swept again after 500 ms (%v)", got)
	}
	clock.Advance(500 * time.Millisecond)
	l.begin("y")
	if got := l.lastSweepAt(); !got.Equal(first.Add(time.Second)) {
		t.Errorf("not swept after a second: last sweep at %v", got)
	}
}

// A clock that is set back must not keep the limiter from sweeping for as long as
// it was set back: the time since the last sweep is then negative.
func TestLimiterSweepsAgainWhenTheClockWentBack(t *testing.T) {
	l, clock := newTestLimiter()
	l.maxKeys = 2
	failN(t, l, 1, "a")
	failN(t, l, 1, "b")
	l.begin("x") // refused, after a sweep at the time of the clock
	if !l.lastSweepAt().Equal(clock.Now()) {
		t.Fatal("no sweep")
	}

	clock.Advance(-time.Hour)
	l.begin("y")
	if got := l.lastSweepAt(); !got.Equal(clock.Now()) {
		t.Errorf("last sweep at %v after the clock went back to %v, want a new sweep", got, clock.Now())
	}
}

// Whatever mix of attempts, verdicts and time there is, the limiter does not
// panic, stays within its bound, and knows exactly which attempts are running
// on which keys.
func TestLimiterKeepsItsInvariantsUnderRandomUse(t *testing.T) {
	randomLimiterUse(t, 7, 11, 60)
}

// randomLimiterUse runs rounds of random use of a limiter, with the sequence of
// operations that the seed gives, and checks it after every step.
func randomLimiterUse(t *testing.T, seed1, seed2 uint64, rounds int) {
	t.Helper()
	rng := rand.New(rand.NewPCG(seed1, seed2))
	universe := []string{"k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7"}

	for round := range rounds {
		l, clock := newTestLimiter()
		l.maxKeys = 1 + rng.IntN(6)
		var live []*attempt
		for step := range 500 {
			switch op := rng.IntN(10); {
			case op < 5:
				keys := make([]string, 1+rng.IntN(3))
				for i := range keys {
					keys[i] = universe[rng.IntN(len(universe))] // a key may come twice
				}
				a, wait := l.begin(keys...)
				switch {
				case a != nil:
					live = append(live, a)
				case wait <= 0:
					t.Fatalf("round %d step %d: refused with no wait", round, step)
				}
			case op < 8 && len(live) > 0:
				i := rng.IntN(len(live))
				a := live[i]
				live = slices.Delete(live, i, i+1)
				switch rng.IntN(3) {
				case 0:
					a.fail()
				case 1:
					a.succeed()
				default:
					a.release()
				}
			default:
				clock.Advance(time.Duration(rng.IntN(20*60)) * time.Second)
			}
			checkLimiter(t, l, live, fmt.Sprintf("round %d step %d", round, step))
		}
		for _, a := range live {
			a.release()
		}
		checkLimiter(t, l, nil, fmt.Sprintf("round %d at the end", round))
	}
}

// checkLimiter fails the test if the limiter is not what the attempts that are
// running say it is.
func checkLimiter(t *testing.T, l *limiter, live []*attempt, when string) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > l.maxKeys {
		t.Fatalf("%s: %d keys, the limit is %d", when, len(l.buckets), l.maxKeys)
	}
	want := map[string]int{}
	for _, a := range live {
		seen := map[string]bool{}
		for _, k := range a.keys {
			if seen[k] {
				t.Fatalf("%s: an attempt holds the key %q twice", when, k)
			}
			seen[k] = true
			want[k]++
		}
	}
	for k, n := range want {
		b := l.buckets[k]
		if b == nil {
			t.Fatalf("%s: %d attempts are running on %q, which has no bucket", when, n, k)
		}
		if b.running != n {
			t.Fatalf("%s: %q has %d running, want %d", when, k, b.running, n)
		}
	}
	for k, b := range l.buckets {
		if b.running != want[k] {
			t.Fatalf("%s: %q has %d running, want %d", when, k, b.running, want[k])
		}
	}
}
