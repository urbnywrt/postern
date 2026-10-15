//go:build e2e

package e2e

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// What the test prints. Everything goes through scrubbed, by logf, errorf,
// fatalf and skipf: the logs of the panel and of the node's containers, and
// every string that comes from them (a status, a reason, an error), may hold
// a secret of the run or an address of the machine.

// logf logs with the time since the start of the run.
func (e *env) logf(format string, args ...any) {
	e.t.Helper()
	e.t.Logf("%6.1fs  %s", time.Since(e.start).Seconds(), e.scrubbed(fmt.Sprintf(format, args...)))
}

// errorf marks the test as failed, and it goes on.
func (e *env) errorf(format string, args ...any) {
	e.t.Helper()
	e.t.Error(e.scrubbed(fmt.Sprintf(format, args...)))
}

// fatalf marks the test as failed and ends it.
func (e *env) fatalf(format string, args ...any) {
	e.t.Helper()
	e.t.Fatal(e.scrubbed(fmt.Sprintf(format, args...)))
}

// skipf ends the test as skipped, or as failed when the run tries an
// upstream release (overrides.go): a candidate passes only when its tests ran.
func (e *env) skipf(format string, args ...any) {
	e.t.Helper()
	msg := e.scrubbed(fmt.Sprintf(format, args...))
	if o := anyOverride(); o != "" {
		e.t.Fatalf("the test would be skipped (%s), but %s is set: a release passes only when its tests ran", msg, o)
	}
	e.t.Skip(msg)
}

// secret notes values that must never be printed.
func (e *env) secret(values ...string) {
	e.sec.mu.Lock()
	defer e.sec.mu.Unlock()
	for _, v := range values {
		if v != "" {
			e.sec.scrub = append(e.sec.scrub, v, strings.ToUpper(v), strings.ToLower(v))
		}
	}
}

// scrubbed is a text made fit to print: without terminal colours, with every
// secret value replaced, and with every IP address masked that is neither a
// loopback, unspecified nor documentation address. The logs of the node name
// the public address of the machine (the edge reports the exit address of its
// egress), which has no place in the output of a test.
func (e *env) scrubbed(text string) string {
	text = ansiEscape.ReplaceAllString(text, "")
	e.sec.mu.Lock()
	for _, v := range e.sec.scrub {
		text = strings.ReplaceAll(text, v, "<secret>")
	}
	e.sec.mu.Unlock()
	return maskAddresses(text)
}

var (
	ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	ipv4Like   = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	// ipv6Like is a run of hex digits with two colons or more; what is not
	// an address (a time of day, say) does not parse and stays.
	ipv6Like = regexp.MustCompile(`[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:]*`)

	// documentation are the prefixes of RFC 5737 and RFC 3849, which the tests use.
	documentation = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
)

// maskAddresses replaces the IP addresses in text that may belong to the
// machine or to the network around it: those that are not loopback,
// unspecified or documentation addresses.
func maskAddresses(text string) string {
	mask := func(s, masked string) string {
		a, err := netip.ParseAddr(s)
		if err != nil || a.IsLoopback() || a.IsUnspecified() {
			return s
		}
		for _, p := range documentation {
			if p.Contains(a) {
				return s
			}
		}
		return masked
	}
	text = ipv4Like.ReplaceAllStringFunc(text, func(s string) string { return mask(s, "x.x.x.x") })
	return ipv6Like.ReplaceAllStringFunc(text, func(s string) string { return mask(s, "x:x::x") })
}
