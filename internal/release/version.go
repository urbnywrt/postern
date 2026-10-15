package release

import (
	"cmp"
	"strings"
)

// ValidVersion reports whether v can name a version in a file name and a path:
// 1 to 64 characters of [0-9A-Za-z._+-], the first of them a letter or a digit
// (the pattern ^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$). The tags of the upstream
// releases (3.5.13, v2.2.8, v26.3.27) and of Postern (v0.5.0) are such strings,
// and nothing in one is taken for something else by a path, a shell or a
// URL.
func ValidVersion(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case '0' <= c && c <= '9', 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
		case i > 0 && (c == '.' || c == '_' || c == '+' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// Compare compares two versions, as semantic versioning 2.0 does after an
// optional leading "v", and returns -1, 0 or 1 for a lower than, equal to or
// higher than b:
//
//   - the core is numbers apart by dots, compared one by one as numbers, of any
//     size, and a number that is missing is zero, so 3.5 and 3.5.0 are the same
//     and 1.2.3.4 is above 1.2.3;
//   - a version with a prerelease (after the first "-") is lower than the same
//     one without, and prereleases are compared by their identifiers apart by
//     dots: numbers by value, a number below any text, text by its leading
//     letters (ASCII) and then a number after them by value (one deviation
//     from semver, which compares rc10 and rc9 as text), and a list that is the
//     start of another below it, so rc.10 is above rc.2, rc10 above rc9, and
//     alpha below alpha.1;
//   - build metadata (after "+") is not looked at;
//   - what does not read as a version at all (dev, an empty string, 1.x) is
//     below every version, and such strings are ordered by the strings.
//
// Compare knows nothing about the prerelease flag that the upstream project has
// set: a caller that must tell prereleases from releases uses that flag, and
// never the text of a tag.
func Compare(a, b string) int {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	switch {
	case !okA && !okB:
		return strings.Compare(a, b)
	case !okA:
		return -1
	case !okB:
		return 1
	}
	if c := compareCore(va.core, vb.core); c != 0 {
		return c
	}
	return comparePrerelease(va.pre, vb.pre)
}

// IsVersion reports whether s reads as a version to [Compare]; what does not
// (dev, an empty string, 1.x) is below every version there.
func IsVersion(s string) bool {
	_, ok := parseVersion(s)
	return ok
}

// Newer reports whether version a is higher than version b ([Compare]).
func Newer(a, b string) bool { return Compare(a, b) > 0 }

// version is a version that has been read.
type version struct {
	core []string // the numbers of the core, as digits without leading zeros
	pre  []string // the identifiers of the prerelease; nil for a release
}

// parseVersion reads s; ok is false if it is not a version.
func parseVersion(s string) (v version, ok bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core, pre, hasPre := strings.Cut(s, "-")
	for number := range strings.SplitSeq(core, ".") {
		if !isDigits(number) {
			return version{}, false
		}
		v.core = append(v.core, strings.TrimLeft(number, "0"))
	}
	if hasPre {
		for id := range strings.SplitSeq(pre, ".") {
			if !isIdentifier(id) {
				return version{}, false
			}
			v.pre = append(v.pre, id)
		}
	}
	return v, true
}

// isDigits reports whether s is one or more ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isIdentifier reports whether s is one or more of [0-9A-Za-z-].
func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case '0' <= c && c <= '9', 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', c == '-':
		default:
			return false
		}
	}
	return true
}

// compareNumbers compares two numbers that are digits without leading zeros
// (zero is the empty string), of any size.
func compareNumbers(x, y string) int {
	if c := cmp.Compare(len(x), len(y)); c != 0 {
		return c
	}
	return strings.Compare(x, y)
}

// compareCore compares the numbers of two cores; the one that is shorter goes on
// with zeros.
func compareCore(a, b []string) int {
	for i := range max(len(a), len(b)) {
		var x, y string
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := compareNumbers(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// comparePrerelease compares two lists of prerelease identifiers; an empty list
// is a release, which is above any prerelease.
func comparePrerelease(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareIdentifier(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a), len(b))
}

// compareIdentifier compares two identifiers of a prerelease: numbers by value,
// a number below any text, and text "naturally" (compareText), so that rc10 is
// above rc9.
func compareIdentifier(x, y string) int {
	xNumber, yNumber := isDigits(x), isDigits(y)
	switch {
	case xNumber && yNumber:
		return compareNumbers(strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0"))
	case xNumber:
		return -1
	case yNumber:
		return 1
	}
	return compareText(x, y)
}

// compareText compares two identifiers that are not numbers by a key: the
// leading letters (by ASCII), then what follows them, which is nothing (the
// lowest), a number (by value: rc9 < rc10, beta2 < beta11) or anything else
// (by ASCII, the highest). Ordering by a key keeps the order total and
// transitive whatever the shapes of the identifiers.
func compareText(x, y string) int {
	xLetters, xRest := splitLetters(x)
	yLetters, yRest := splitLetters(y)
	if c := strings.Compare(xLetters, yLetters); c != 0 {
		return c
	}
	if c := cmp.Compare(restClass(xRest), restClass(yRest)); c != 0 {
		return c
	}
	if isDigits(xRest) {
		return compareNumbers(strings.TrimLeft(xRest, "0"), strings.TrimLeft(yRest, "0"))
	}
	return strings.Compare(xRest, yRest)
}

// splitLetters splits s into its leading ASCII letters and the rest.
func splitLetters(s string) (letters, rest string) {
	i := 0
	for i < len(s) && ('a' <= s[i] && s[i] <= 'z' || 'A' <= s[i] && s[i] <= 'Z') {
		i++
	}
	return s[:i], s[i:]
}

// restClass orders what follows the letters of an identifier: nothing, then a
// number, then anything else.
func restClass(rest string) int {
	switch {
	case rest == "":
		return 0
	case isDigits(rest):
		return 1
	}
	return 2
}
