package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

// This file holds the conversions between the Go types of the repositories and
// the SQLite columns that keep them.

// scanner is what *sql.Row and *sql.Rows have in common.
type scanner interface {
	Scan(dest ...any) error
}

// normTime returns t as the store keeps it: in UTC and to the whole second.
// The repositories store this value back into the record that they are given, so
// that the record equals what a later read returns.
func normTime(t time.Time) time.Time {
	return t.Truncate(time.Second).UTC()
}

// normTimePtr is normTime for an optional time.
func normTimePtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	n := normTime(*t)
	return &n
}

// timeFromDB returns the time that a timestamp column holds. The zero time is
// stored as the Unix second that it has, so it comes back as the zero time.
func timeFromDB(sec int64) time.Time {
	return time.Unix(sec, 0).UTC()
}

// unixOrZero is the value to bind for a time in a NOT NULL column whose 0 means
// that there is no time (the published_at of a release, the checked_at of a
// feed): 0 for the zero time.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// timeOrZero is the inverse of unixOrZero: the zero time for 0.
func timeOrZero(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return timeFromDB(sec)
}

// nullTime is the value to bind for an optional time: NULL for nil.
func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Unix()
}

// timePtrFromDB returns the time of a nullable timestamp column, nil for NULL.
func timePtrFromDB(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := timeFromDB(v.Int64)
	return &t
}

// nullBlob is the value to bind for an optional blob: NULL for nil and empty.
// A sealed value is never empty, so the two mean the same.
func nullBlob(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// blobValue is the value to bind for a blob column that is NOT NULL.
func blobValue(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// nullString is the value to bind for a column in which the empty string means
// that there is no value, such as a reference to another row.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// int64Of converts an identity-like counter (a generation, a cursor) for
// storage. SQLite integers are signed, and a value that does not fit is an
// error rather than a quietly different number.
func int64Of(what string, v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("store: %s %d does not fit in a SQLite integer", what, v)
	}
	return int64(v), nil
}

// maxCounter is the most that a statistics counter or size is stored as: 2^50,
// about a petabyte, which for traffic is a petabyte in one minute. No node comes
// near it, and it is small on purpose.
//
// The rollups add the counters of a period up with SUM, and SQLite's SUM stops
// with "integer overflow" when a total leaves int64. Were a counter allowed to be
// as large as an int64, one wrong report (a counter that went backwards and was
// subtracted as an unsigned number is enough) would make the rollup of every
// proxy and node fail, and as PruneStats rolls up what it deletes, every prune
// after it as well, for good. With this limit a day of 1440 minutes adds up to
// less than 2^61, and so do the hours and days made of them.
const maxCounter = 1 << 50

// This does not compile if maxCounter is ever raised so far that the sum of a
// day of minutes, all at the limit, would no longer fit in an int64.
const _ = uint64(math.MaxInt64 - 24*60*maxCounter)

// clampCounter converts a statistics counter or size for storage. A reading is
// only as exact as the node that took it, and one above maxCounter is stored as
// maxCounter.
func clampCounter(v uint64) int64 {
	if v > maxCounter {
		return maxCounter
	}
	return int64(v)
}

// finite returns f, or 0 if f is NaN or infinite. SQLite stores a NaN as NULL,
// which a NOT NULL column refuses, and one bad reading from a node must not make
// the whole minute fail.
func finite(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return f
}

// uint32Of reads a small unsigned value (a port, a limit) from a column. The
// repositories only write values of that range, so anything else means that the
// row was edited by hand; it is clamped rather than wrapped.
func uint32Of(v int64) uint32 {
	switch {
	case v < 0:
		return 0
	case v > math.MaxUint32:
		return math.MaxUint32
	}
	return uint32(v)
}

// uint64Of reads a counter from a column; a negative value reads as 0.
func uint64Of(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// encodeStrings returns the JSON of a list of strings, "[]" for none.
func encodeStrings(s []string) (string, error) {
	if len(s) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(s)
	return string(b), err
}

// decodeStrings is the inverse of encodeStrings. An empty list is nil.
func decodeStrings(s string) ([]string, error) {
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// encodeMap returns the JSON of a map, "{}" for none.
func encodeMap[V any](m map[string]V) (string, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	return string(b), err
}

// decodeMap is the inverse of encodeMap. An empty map is nil.
func decodeMap[V any](s string) (map[string]V, error) {
	var out map[string]V
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// boolInt is how a boolean is stored.
func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// placeholders returns the n question marks of a statement: "?, ?, ?".
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", n), ", ")
}
