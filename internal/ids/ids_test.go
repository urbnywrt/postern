package ids

import (
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

// ulidPattern matches an id as New writes it: 26 characters of upper-case
// Crockford base32, an alphabet without I, L, O and U.
var ulidPattern = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// timestamp returns the millisecond timestamp that an id carries.
func timestamp(t *testing.T, id string) uint64 {
	t.Helper()
	parsed, err := ulid.ParseStrict(id)
	if err != nil {
		t.Fatalf("ulid.ParseStrict(%q): %v", id, err)
	}
	return parsed.Time()
}

// useClock makes New read the time from clock, forgets the newest timestamp it
// has handed out, and puts both back when the test ends.
func useClock(t *testing.T, clock func() time.Time) {
	t.Helper()
	mu.Lock()
	oldNow, oldLast := now, last
	now, last = clock, 0
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		now, last = oldNow, oldLast
		mu.Unlock()
	})
}

// useEntropy makes New draw its random bits from r, and puts the old source
// back when the test ends.
func useEntropy(t *testing.T, r io.Reader) {
	t.Helper()
	mu.Lock()
	old := source
	source = ulid.Monotonic(r, 0)
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		source = old
		mu.Unlock()
	})
}

func TestNewFormat(t *testing.T) {
	for range 100 {
		id := New()
		if !ulidPattern.MatchString(id) {
			t.Fatalf("New() = %q, want 26 upper-case Crockford base32 characters", id)
		}
		// ParseStrict also rejects a first character above 7, which would
		// overflow the 48-bit timestamp.
		if _, err := ulid.ParseStrict(id); err != nil {
			t.Fatalf("ulid.ParseStrict(%q): %v", id, err)
		}
	}
}

func TestNewCarriesTheCurrentTime(t *testing.T) {
	before := time.Now().UnixMilli()
	id := New()
	after := time.Now().UnixMilli()

	got := int64(timestamp(t, id))
	if got < before || got > after {
		t.Errorf("timestamp of %s is %d ms, want between %d and %d", id, got, before, after)
	}
}

func TestNewSortsByTime(t *testing.T) {
	var got []string
	for range 4 {
		got = append(got, New())
		time.Sleep(2 * time.Millisecond)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("%s was made before %s but does not sort before it", got[i-1], got[i])
		}
		if timestamp(t, got[i-1]) >= timestamp(t, got[i]) {
			t.Errorf("%s and %s carry the same millisecond although 2 ms passed between them", got[i-1], got[i])
		}
	}
}

// TestNewTenThousand covers the monotonic path: ten thousand ids made in a loop
// fit into a few milliseconds, so most of them share a timestamp and only the
// random part can keep them ordered.
func TestNewTenThousand(t *testing.T) {
	const n = 10_000
	seen := make(map[string]struct{}, n)
	prev := ""
	sharedMillisecond := 0
	for i := range n {
		id := New()
		if _, dup := seen[id]; dup {
			t.Fatalf("call %d: %s was handed out before", i, id)
		}
		seen[id] = struct{}{}
		if id <= prev {
			t.Fatalf("call %d: %s does not sort after the previous id %s", i, id, prev)
		}
		if prev != "" && id[:10] == prev[:10] { // the first 10 characters are the timestamp
			sharedMillisecond++
		}
		prev = id
	}
	if sharedMillisecond == 0 {
		t.Error("no two ids shared a millisecond, so the monotonic path was not exercised")
	}
}

func TestNewConcurrent(t *testing.T) {
	const (
		workers = 8
		each    = 2000
	)
	var (
		wg        sync.WaitGroup
		resultsMu sync.Mutex
		seen      = make(map[string]struct{}, workers*each)
		dupes     []string
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			made := make([]string, 0, each)
			for range each {
				made = append(made, New())
			}
			resultsMu.Lock()
			defer resultsMu.Unlock()
			for _, id := range made {
				if _, dup := seen[id]; dup {
					dupes = append(dupes, id)
				}
				seen[id] = struct{}{}
			}
		}()
	}
	wg.Wait()
	if len(dupes) > 0 {
		t.Errorf("%d duplicate ids, first %s", len(dupes), dupes[0])
	}
	if len(seen) != workers*each {
		t.Errorf("got %d distinct ids, want %d", len(seen), workers*each)
	}
}

// The wall clock can step back (a manual change, a VM resuming, an NTP step).
// Ids made afterwards must still sort after the earlier ones, so the timestamp
// stays at the newest value it has had.
func TestNewStaysMonotonicWhenTheClockGoesBack(t *testing.T) {
	base := time.UnixMilli(1_700_000_000_000)
	var clock time.Time
	useClock(t, func() time.Time { return clock })

	steps := []struct {
		at       time.Duration // the clock, relative to base
		wantTime time.Duration // timestamp expected on the id
	}{
		{0, 0},
		{0, 0},                             // same millisecond
		{-time.Millisecond, 0},             // back by 1 ms
		{-time.Hour, 0},                    // back by an hour
		{-time.Hour, 0},                    // still there
		{0, 0},                             // forward again, but not past the newest timestamp
		{2 * time.Second, 2 * time.Second}, // new maximum
		{time.Second, 2 * time.Second},     // back by 1 s
		{2 * time.Second, 2 * time.Second}, // back at the maximum
		{2*time.Second + time.Millisecond, 2*time.Second + time.Millisecond}, // new maximum by 1 ms
	}
	prev := ""
	for i, step := range steps {
		clock = base.Add(step.at)
		id := New()
		if want := uint64(base.Add(step.wantTime).UnixMilli()); timestamp(t, id) != want {
			t.Errorf("step %d: timestamp of %s is %d, want %d", i, id, timestamp(t, id), want)
		}
		if id <= prev {
			t.Errorf("step %d: %s does not sort after the previous id %s", i, id, prev)
		}
		prev = id
	}
}

// almostFull yields ten 0xFF bytes first, which makes the 80 random bits of the
// first id the largest possible value, and 0x01 bytes after that.
type almostFull struct{ started bool }

func (a *almostFull) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0x01
	}
	if !a.started {
		a.started = true
		for i := range min(len(p), 10) {
			p[i] = 0xFF
		}
	}
	return len(p), nil
}

// A second id in the same millisecond as an id with the largest random part has
// nowhere to go. It must move to the next millisecond rather than fail.
func TestNewMovesToTheNextMillisecondWhenTheRandomPartOverflows(t *testing.T) {
	base := time.UnixMilli(1_700_000_000_000)
	useClock(t, func() time.Time { return base })
	useEntropy(t, &almostFull{})

	first := New()
	second := New()
	if want := uint64(base.UnixMilli()); timestamp(t, first) != want {
		t.Errorf("first id %s has timestamp %d, want %d", first, timestamp(t, first), want)
	}
	if want := uint64(base.UnixMilli()) + 1; timestamp(t, second) != want {
		t.Errorf("second id %s has timestamp %d, want %d", second, timestamp(t, second), want)
	}
	if second <= first {
		t.Errorf("%s does not sort after %s", second, first)
	}
}

func TestNewClampsAbsurdClocks(t *testing.T) {
	tests := []struct {
		name string
		at   time.Time
		want uint64
	}{
		{"before 1970", time.UnixMilli(-1), 0},
		{"far past the 48-bit timestamp", time.UnixMilli(1 << 62), ulid.MaxTime()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			useClock(t, func() time.Time { return tc.at })
			id := New()
			if !ulidPattern.MatchString(id) {
				t.Fatalf("New() = %q, want a well-formed id", id)
			}
			if got := timestamp(t, id); got != tc.want {
				t.Errorf("timestamp of %s is %d, want %d", id, got, tc.want)
			}
		})
	}
}

func TestLower(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ulid", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01arz3ndektsv4rrffq69g5fav"},
		{"already lower case", "01arz3ndektsv4rrffq69g5fav", "01arz3ndektsv4rrffq69g5fav"},
		{"mixed", "01ArZ3", "01arz3"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Lower(tc.in); got != tc.want {
				t.Errorf("Lower(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Container names are built from Lower(id), and ToUpper must give the id back.
func TestLowerOfNew(t *testing.T) {
	lowerPattern := regexp.MustCompile(`^[0-9a-hjkmnp-tv-z]{26}$`)
	for range 100 {
		id := New()
		lower := Lower(id)
		if !lowerPattern.MatchString(lower) {
			t.Fatalf("Lower(%q) = %q, want 26 lower-case Crockford base32 characters", id, lower)
		}
		if strings.ToUpper(lower) != id {
			t.Fatalf("ToUpper(Lower(%q)) = %q", id, strings.ToUpper(lower))
		}
	}
}
