// Package ids makes the identifiers of Postern's records: ULIDs.
//
// A ULID is 26 characters of upper-case Crockford base32, a 48-bit timestamp in
// milliseconds followed by 80 random bits. Ids sort by the time they were made,
// which keeps lists in order by id alone. They are identifiers, not secrets:
// within a millisecond each id is the one before it plus a random number.
package ids

import (
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

var (
	mu     sync.Mutex
	source = ulid.Monotonic(rand.Reader, 0) // guarded by mu, it is not safe for concurrent use
	last   uint64                           // the timestamp of the newest id in ms, guarded by mu
	now    = time.Now                       // the clock, replaced by tests
)

// New returns a new id. It is safe for concurrent use.
//
// Every id sorts after all the ids that New returned before it in the same
// process, including those made in the same millisecond, and also when the clock
// goes back: the timestamp then stays at the newest value it has had until the
// clock catches up. Ids made by different processes are ordered by time only
// down to the millisecond.
func New() string {
	mu.Lock()
	defer mu.Unlock()

	// A clock that is wrong enough to fall outside the range of a ULID gives
	// the nearest id that has a place there, rather than a failure.
	ms := uint64(min(max(now().UnixMilli(), 0), int64(ulid.MaxTime())))
	ms = max(ms, last)
	for {
		id, err := ulid.New(ms, source)
		if err == nil {
			last = ms
			return id.String()
		}
		// The random part of the previous id in this millisecond is too close to
		// the largest 80-bit value to be increased. The next millisecond starts a
		// new random part, which still sorts after it.
		if !errors.Is(err, ulid.ErrMonotonicOverflow) {
			// Unreachable: the time is in range except in the last millisecond
			// that a ULID can hold, and crypto/rand cannot fail.
			panic("ids: " + err.Error())
		}
		ms++
	}
}

// Lower returns the lower-case form of id, which is how an id appears in a
// container name (postern-eng-<id>-g<N>). Crockford base32 does not tell the
// cases apart, so it names the same id.
func Lower(id string) string {
	return strings.ToLower(id)
}
