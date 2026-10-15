package egressuri

import (
	"bytes"
	"fmt"
	"strings"
)

// maxLineErrors bounds the errors ParseSubscription returns one by one, so that
// a body of junk lines cannot make its caller hold an error for each of them.
const maxLineErrors = 1000

// ParseSubscription reads a subscription: a list of share links, one per line,
// either as it is or as one base64 text (either alphabet, padded or not, line
// breaks allowed). The body is taken as base64 when all of it decodes to text
// that holds "://" somewhere, and as a plain list otherwise. The decoded text
// does not have to be valid UTF-8: a line with a bad byte in a name is still a
// server (the byte becomes U+FFFD), and a line that cannot be read spoils no
// other.
//
// Blank lines and lines that start with "#" are skipped. Every other line is
// read with Parse. A line that fails does not stop the others: the servers that
// could be read are returned in the order of the list, and each failure is
// returned as an error that starts with the number of its line, counted in the
// text that was read (the decoded text of a base64 body). After maxLineErrors
// errors the rest are only counted, in one last error.
//
// Servers are not deduplicated: a link that repeats comes back twice, with the
// same Key.
func ParseSubscription(body []byte) ([]*Server, []error) {
	var (
		servers []*Server
		errs    []error
		dropped int
	)
	lineNo := 0
	for line := range strings.SplitSeq(subscriptionText(body), "\n") {
		lineNo++
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s, err := Parse(line)
		switch {
		case err == nil:
			servers = append(servers, s)
		case len(errs) < maxLineErrors:
			errs = append(errs, fmt.Errorf("line %d: %w", lineNo, err))
		default:
			dropped++
		}
	}
	if dropped > 0 {
		errs = append(errs, fmt.Errorf("%d more lines failed to parse", dropped))
	}
	return servers, errs
}

// subscriptionText returns the text of the list that body holds.
func subscriptionText(body []byte) string {
	body = bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(body), utf8BOM))
	if len(body) == 0 {
		return ""
	}
	// The decoded text need not be UTF-8: a line with a bad byte in it is for
	// Parse to judge, and must not make the whole list read as one base64 line.
	if decoded, ok := decodeBase64(string(body)); ok && bytes.Contains(decoded, []byte("://")) {
		return string(bytes.TrimPrefix(decoded, utf8BOM))
	}
	return string(body)
}
