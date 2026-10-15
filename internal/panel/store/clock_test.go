package store

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// steppingClock is a wall clock that a test sets, as a time sync steps the
// clock of a host.
type steppingClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *steppingClock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *steppingClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// The clock of the store never goes back: when the wall clock is stepped back,
// it gives the last time that it gave until the wall clock has caught up.
func TestStoreClockNeverGoesBack(t *testing.T) {
	wall := &steppingClock{now: testNow.Add(5 * time.Second)}
	clock := monotonic(wall.read)
	for _, step := range []struct {
		wall, want time.Time
	}{
		{testNow.Add(5 * time.Second), testNow.Add(5 * time.Second)},
		{testNow, testNow.Add(5 * time.Second)}, // stepped back
		{testNow.Add(2 * time.Second), testNow.Add(5 * time.Second)},
		{testNow.Add(6 * time.Second), testNow.Add(6 * time.Second)}, // caught up
		{testNow.Add(7 * time.Second), testNow.Add(7 * time.Second)},
	} {
		wall.set(step.wall)
		if got := clock(); !got.Equal(step.want) {
			t.Errorf("clock() with the wall clock at %v = %v, want %v", step.wall, got, step.want)
		}
	}
	// The monotonic reading of time.Now does not hide a step of the wall clock:
	// the clock compares wall times.
	system := monotonic(time.Now)
	if a, b := system(), system(); b.Before(a) {
		t.Errorf("the clock went back: %v after %v", b, a)
	}
}

// The clock gives wall times alone. A time of time.Now that kept its reading of
// the monotonic clock would be compared by that reading (Before, Sub), which
// does not see the wall clock step: the clock would go back with the wall clock.
func TestStoreClockHasNoMonotonicReading(t *testing.T) {
	clock := monotonic(time.Now)
	for range 2 {
		if s := clock().String(); strings.Contains(s, " m=") {
			t.Errorf("clock() = %s: it carries a reading of the monotonic clock", s)
		}
	}
}

// Rows keep the order in which they were made when the wall clock is stepped
// back between them: they are listed by their creation times, which a clock
// that went back would turn around.
func TestRowsKeepTheirOrderWhenTheWallClockStepsBack(t *testing.T) {
	wall := &steppingClock{now: testNow.Add(time.Hour)}
	db, err := open(filepath.Join(t.TempDir(), "panel.db"), embeddedMigrations(), monotonic(wall.read))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	n := mustNode(t, db, "node")
	l := mustListener(t, db, n.ID, 443)
	first := mustProxy(t, db, n.ID, l.ID, "first")
	wall.set(testNow) // an hour back, as a time sync may do
	second := mustProxy(t, db, n.ID, l.ID, "second")
	third := mustProxy(t, db, n.ID, l.ID, "third")

	list, err := db.ListProxies(ctx, ProxyFilter{NodeID: n.ID})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range list {
		got = append(got, p.Name)
	}
	if len(got) != 3 || got[0] != "first" || got[1] != "second" || got[2] != "third" {
		t.Errorf("proxies listed as %v, want first, second, third", got)
	}
	if second.CreatedAt.Before(first.CreatedAt) || third.CreatedAt.Before(second.CreatedAt) {
		t.Errorf("creation times %v, %v, %v go back", first.CreatedAt, second.CreatedAt, third.CreatedAt)
	}
}
