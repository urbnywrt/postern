package jobs

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	// mask is what a run of secret bytes becomes.
	mask = "***"

	// replacement is what a byte that is not UTF-8 becomes.
	replacement = string(utf8.RuneError)
)

// A scrubber knows the secrets of a job. Secrets shorter than MinSecretLen are
// left alone, since hiding them would hide too much of the output, and a
// secret of several lines, such as a private key, counts line by line: the log
// is cut into lines, so no line holds all of it.
type scrubber struct {
	secrets [][]byte  // the longest first
	first   [256]bool // the bytes that secrets start with
	keep    int       // the length of the longest secret, less one
}

func newScrubber(secrets []string) *scrubber {
	s := &scrubber{}
	seen := map[string]bool{}
	for _, secret := range secrets {
		for part := range strings.SplitSeq(secret, "\n") {
			part = strings.TrimSuffix(part, "\r")
			if len(part) < MinSecretLen || seen[part] {
				continue
			}
			seen[part] = true
			s.secrets = append(s.secrets, []byte(part))
		}
	}
	slices.SortStableFunc(s.secrets, func(a, b []byte) int { return len(b) - len(a) })
	for _, secret := range s.secrets {
		s.first[secret[0]] = true
	}
	if len(s.secrets) > 0 {
		s.keep = len(s.secrets[0]) - 1
	}
	return s
}

// with returns a scrubber that knows the secrets of s and these. s itself does
// not change: a masker that uses it goes on with it until it is given the new
// one.
func (s *scrubber) with(secrets []string) *scrubber {
	all := make([]string, 0, len(s.secrets)+len(secrets))
	for _, secret := range s.secrets {
		all = append(all, string(secret))
	}
	return newScrubber(append(all, secrets...))
}

// longest returns the length of the longest secret that b starts with, 0 if
// none. A secret is only found whole.
func (s *scrubber) longest(b []byte) int {
	if len(b) == 0 || !s.first[b[0]] {
		return 0
	}
	for _, secret := range s.secrets {
		if bytes.HasPrefix(b, secret) {
			return len(secret)
		}
	}
	return 0
}

// replace returns text with the secrets hidden, as a masker hides them.
func (s *scrubber) replace(text string) string {
	m := masker{s: s}
	return string(m.mask(nil, []byte(text), len(text)))
}

// A masker hides the secrets in a stream as it goes. Every byte of every
// occurrence of a secret is hidden, also where secrets overlap each other or
// themselves, and every run of hidden bytes becomes one ***, so that no part of
// a secret is left in sight. A byte is decided once the secrets that start
// there can be seen; the secrets that started before it are known by then.
type masker struct {
	s      *scrubber
	cover  int  // how many of the bytes from the next one on a secret that started before covers
	masked bool // the output so far ends in a mask
}

// mask appends what b[:n] becomes to dst. The secrets that start before n must
// be in b whole if they are there at all: b holds what has come after n too,
// up to keep bytes, or to the end of a line, which no secret holds.
func (m *masker) mask(dst, b []byte, n int) []byte {
	for i := 0; i < n; {
		if l := m.s.longest(b[i:]); i+l > m.cover {
			m.cover = i + l
		}
		if i < m.cover {
			if !m.masked {
				dst = append(dst, mask...)
				m.masked = true
			}
			i++
			continue
		}
		// A run of bytes that starts no secret.
		j := i + 1
		for j < n && !m.s.first[b[j]] {
			j++
		}
		dst = append(dst, b[i:j]...)
		m.masked = false
		i = j
	}
	m.cover = max(m.cover-n, 0)
	return dst
}

// A jobLog is the log of one job: what it wrote, cut into lines, with the
// secrets hidden, and only the newest lines that fit in maxSize together with
// one line at the top that says how much was dropped.
//
// A byte is decided when the secrets that start there can be seen, so a secret
// that arrives in pieces is hidden whole, and the log is the same however the
// output came. A line that grows to maxPartial without its end is added as a
// piece, cut after a whole character.
//
// A jobLog is not safe for concurrent use.
type jobLog struct {
	scrub      *scrubber
	mask       masker
	maxSize    int // the most that String returns
	maxPartial int // how long a line may grow without its end before a piece of it is added

	pending []byte   // what has come but is not decided: the last bytes, which may start a secret
	cur     []byte   // the line that is being written, decided, its end not come yet
	lines   []string // lines with their ends, or pieces of a line, oldest first from head on
	head    int
	size    int   // the length of lines[head:]
	dropped int64 // what was dropped to stay within maxSize
	dirty   bool  // lines have been added since dirty was cleared
}

func newJobLog(s *scrubber, maxSize, maxPartial int) *jobLog {
	return &jobLog{scrub: s, mask: masker{s: s}, maxSize: maxSize, maxPartial: max(maxPartial, 1)}
}

// setScrubber makes the log hide the secrets of s from now on: in what has come
// and is not decided yet, and in everything that comes after it. A masker keeps
// no state of the secrets beyond how far the ones that started already reach,
// which the new secrets do not change.
func (l *jobLog) setScrubber(s *scrubber) {
	l.scrub = s
	l.mask.s = s
}

// write takes output of the job.
func (l *jobLog) write(p []byte) {
	l.pending = append(l.pending, p...)
	// Decided are the bytes of the lines whose end has come, and all but the
	// last keep bytes.
	n := max(bytes.LastIndexByte(l.pending, '\n')+1, len(l.pending)-l.scrub.keep)
	if n <= 0 {
		return
	}
	l.cur = l.mask.mask(l.cur, l.pending, n)
	l.takeLines()
	l.pending = shrink(l.pending, n, 4*(l.maxPartial+l.scrub.keep))
}

// end takes the end of the output: an unfinished last line is added as it is.
func (l *jobLog) end() {
	if len(l.pending) > 0 {
		l.cur = l.mask.mask(l.cur, l.pending, len(l.pending))
		l.pending = nil
	}
	l.takeLines()
	if len(l.cur) > 0 {
		l.add(l.cur)
		l.cur = nil
	}
}

// takeLines adds the whole lines of cur to the log, and a piece of the last
// one when it has grown to maxPartial.
func (l *jobLog) takeLines() {
	start := 0
	for {
		i := bytes.IndexByte(l.cur[start:], '\n')
		if i < 0 {
			break
		}
		l.add(l.cur[start : start+i+1])
		start += i + 1
	}
	if rest := l.cur[start:]; len(rest) >= l.maxPartial {
		start += l.addPiece(rest)
	}
	l.cur = shrink(l.cur, start, 4*l.maxPartial)
}

// addPiece adds a piece of a line that has no end yet, up to its last whole
// character, and returns how long the piece is.
func (l *jobLog) addPiece(b []byte) int {
	n := completeRunes(b)
	if n > 0 {
		l.add(b[:n])
	}
	return n
}

// completeRunes returns the length of b without a character at its end that
// has not come whole. Bytes that are not UTF-8 count as whole.
func completeRunes(b []byte) int {
	for i := len(b) - 1; i >= 0 && i > len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if utf8.FullRune(b[i:]) {
				return len(b)
			}
			return i
		}
	}
	return len(b)
}

// shrink drops the first n bytes of b. A buffer that has grown above limit is
// given back, so that one large write does not keep its memory.
func shrink(b []byte, n, limit int) []byte {
	if cap(b) > limit {
		return bytes.Clone(b[n:])
	}
	return append(b[:0], b[n:]...)
}

// add adds a line and drops the oldest lines until the log fits in maxSize. A
// line that alone does not fit keeps its end.
func (l *jobLog) add(b []byte) {
	line := strings.ToValidUTF8(string(b), replacement)
	if line == "" {
		return
	}
	l.lines = append(l.lines, line)
	l.size += len(line)
	l.dirty = true
	for l.head < len(l.lines)-1 && l.size+len(l.marker()) > l.maxSize {
		l.size -= len(l.lines[l.head])
		l.dropped += int64(len(l.lines[l.head]))
		l.lines[l.head] = ""
		l.head++
	}
	for last := len(l.lines) - 1; l.lines[last] != "" && l.size+len(l.marker()) > l.maxSize; {
		s := l.lines[last]
		cut := min(l.size+len(l.marker())-l.maxSize, len(s))
		for cut < len(s) && !utf8.RuneStart(s[cut]) {
			cut++
		}
		l.lines[last] = s[cut:]
		l.size -= cut
		l.dropped += int64(cut)
	}
	if l.head >= 1024 && 2*l.head >= len(l.lines) {
		l.lines = slices.Clone(l.lines[l.head:])
		l.head = 0
	}
}

// marker is the first line of a log from which lines were dropped.
func (l *jobLog) marker() string {
	if l.dropped == 0 {
		return ""
	}
	return fmt.Sprintf("[%d bytes of earlier output were dropped: the log keeps the last %s]\n", l.dropped, sizeText(l.maxSize))
}

// String returns the log.
func (l *jobLog) String() string {
	var b strings.Builder
	m := l.marker()
	b.Grow(len(m) + l.size)
	b.WriteString(m)
	for _, line := range l.lines[l.head:] {
		b.WriteString(line)
	}
	return b.String()
}

// sizeText writes a size for people: "1 MiB", "64 KiB", "120 bytes".
func sizeText(n int) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d bytes", n)
}
