package release

import (
	"errors"
	"fmt"
	"strings"
)

// SumsFormat is the format of a checksum file.
type SumsFormat int

const (
	// SumsSHA256 is the output of sha256sum, which telemt and mtg publish: a line
	// "<hex>  <name>" (text mode) or "<hex> *<name>" (binary mode) for each file.
	// A file that holds only the hex is read as well (a name is not looked for).
	SumsSHA256 SumsFormat = iota

	// SumsDgst is the .dgst file that Xray (and warp-plus) publish for each asset: a
	// line "<ALGORITHM>= <hex>" for each digest, of which the line SHA2-256 is
	// the one that is read. It names no file.
	SumsDgst
)

// ErrNoSum is returned when the checksum file has no sum for the file that was
// asked for: no line for the name, or no SHA2-256 line. A checksum file that has
// one that cannot be used (two different sums, or one that is not 64 hex
// digits) is another error: it is there, and it is not to be trusted.
var ErrNoSum = errors.New("release: no SHA-256 for the file in the checksum file")

// SumFor returns the SHA-256 that data, the contents of a checksum file of
// format f, gives for the file name, as 64 lower-case hex digits. Upper-case
// digits in the file are folded. The name is compared as a whole, so a name that
// is the start or the end of another one finds nothing (mtg has both
// mtg-2.2.8-linux-amd64.tar.gz and mtg-2.2.8-linux-amd64-v3.tar.gz), and "./" in
// front of a name in the file is left out. The name is ignored for SumsDgst.
//
// It returns [ErrNoSum] if the file has no sum for the name, and another error
// if it has two different sums for it or one that is not 64 hex digits. The
// errors do not quote the file, which comes from the network.
func SumFor(name string, data []byte, f SumsFormat) (sha string, err error) {
	switch f {
	case SumsSHA256:
		return sha256SumFor(name, data)
	case SumsDgst:
		return dgstSumFor(data)
	}
	return "", fmt.Errorf("release: unknown format %d of a checksum file", int(f))
}

func sha256SumFor(name string, data []byte) (string, error) {
	text := strings.TrimSpace(string(data))
	if text != "" && !strings.ContainsAny(text, " \t\r\n") {
		// A file that holds only the sum.
		sum, err := hexSum(text)
		if err != nil {
			return "", fmt.Errorf("release: the checksum file is one word: %w", err)
		}
		return sum, nil
	}

	var found string
	for line := range strings.SplitSeq(text, "\n") {
		hash, file, ok := cutSHA256Line(line)
		if !ok || file != name {
			continue
		}
		sum, err := hexSum(hash)
		if err != nil {
			return "", fmt.Errorf("release: the sum for %q: %w", name, err)
		}
		if found != "" && found != sum {
			return "", fmt.Errorf("release: the checksum file has two different sums for %q", name)
		}
		found = sum
	}
	if found == "" {
		return "", ErrNoSum
	}
	return found, nil
}

// cutSHA256Line splits a line of sha256sum, "<hash>  <file>" or "<hash> *<file>",
// into the hash, as it is written, and the name of the file. ok is false for any
// other line.
func cutSHA256Line(line string) (hash, file string, ok bool) {
	line = strings.TrimSuffix(line, "\r")
	hash, rest, found := strings.Cut(line, " ")
	if !found || hash == "" || rest == "" || (rest[0] != ' ' && rest[0] != '*') {
		return "", "", false
	}
	return hash, strings.TrimPrefix(rest[1:], "./"), true
}

func dgstSumFor(data []byte) (string, error) {
	var found string
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "SHA2-256" {
			continue
		}
		sum, err := hexSum(strings.TrimSpace(value))
		if err != nil {
			return "", fmt.Errorf("release: the SHA2-256 line: %w", err)
		}
		if found != "" && found != sum {
			return "", errors.New("release: the checksum file has two different SHA2-256 lines")
		}
		found = sum
	}
	if found == "" {
		return "", ErrNoSum
	}
	return found, nil
}

// hexSum returns s in lower case if it is 64 hex digits. Its errors do not
// quote s.
func hexSum(s string) (string, error) {
	if len(s) != 64 {
		return "", fmt.Errorf("a SHA-256 is 64 hex digits, this has %d characters", len(s))
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return "", errors.New("a SHA-256 is 64 hex digits, this has other characters")
		}
	}
	return strings.ToLower(s), nil
}
