package socks5

import "time"

// SetDialTimeout sets the time that Dial allows itself when its context has no
// deadline, and returns the function that puts the old value back. The tests use
// it to see the limit at work without waiting ten seconds for it. It must not be
// called while a Dial is under way.
func SetDialTimeout(d time.Duration) (restore func()) {
	old := dialTimeout
	dialTimeout = d
	return func() { dialTimeout = old }
}
