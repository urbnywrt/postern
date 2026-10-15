package release_test

import (
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/release"
)

func TestValidVersion(t *testing.T) {
	valid := []string{
		// What the components publish.
		"3.5.13", "3.5.12", "v2.2.8", "v26.3.27", "v1.2.6", "v0.5.0", "1780000000",
		// The shapes that the pattern allows.
		"0", "a", "Z", "dev", "latest", "1.0.0-rc.1", "1.2.3+build.5", "v1.2.3-rc.1+b5", "1_2", "a-b", "a.b", "9+", "a_",
		strings.Repeat("a", 64), "v" + strings.Repeat("1", 63),
	}
	for _, v := range valid {
		if !release.ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"", " ", strings.Repeat("a", 65), "v" + strings.Repeat("1", 64),
		// The first character is a letter or a digit.
		".1", "-1", "_1", "+1", "..", ".",
		// Nothing that is not in the set, in particular nothing that could make
		// a path or a command line of a version: the name of a binary has it.
		"a b", " a", "a ", "v 1", "a/b", "/a", "../x", "a/../b", "a\\b", "a:b", "a*", "a?", "a%2f", "a$b", "a;b", "a'b", "a\"b", "a`b", "a|b", "a&b", "a<b", "a=b", "a,b", "a@b", "a#b",
		"a\n", "\na", "a\r", "a\t", "a\x00", "a\x7f", "é", "1é", "日本", "1.0.0 -rc",
	}
	for _, v := range invalid {
		if release.ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = true, want false", v)
		}
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// The cases of the plan.
		{"3.5.13", "3.5.12", 1},
		{"v2.2.8", "2.2.8", 0},
		{"3.5.13", "3.5.13-rc.1", 1},
		{"1.0.0-rc.10", "1.0.0-rc.2", 1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"v26.3.27", "v26.10.1", -1},
		{"3.5", "3.5.0", 0},
		{"dev", "0.0.1", -1},
		{"1.2.3+b5", "1.2.3", 0},

		// Numbers are numbers, not text.
		{"3.5.9", "3.5.10", -1},
		{"10.0.0", "9.99.99", 1},
		{"1.10.0", "1.9.0", 1},
		{"v26.3.27", "v26.3.9", 1},
		{"0.0.1", "0.0.0", 1},
		{"0.10.0", "0.9.0", 1},

		// Segments that are missing are zeros; more than three are allowed.
		{"3", "3.0.0", 0},
		{"v3", "3.0.0", 0},
		{"3.5", "3.5.1", -1},
		{"3.5.0.0", "3.5", 0},
		{"1.2.3.4", "1.2.3", 1},
		{"1.2.3.0", "1.2.3", 0},
		{"1.2.3.4", "1.2.4", -1},
		{"1.2.3.4", "1.2.3.10", -1},
		{"0", "0.0.0.0.0", 0},

		// Leading zeros (a date is written 2026.03.27 as well as 2026.3.27).
		{"2026.03.27", "2026.3.27", 0},
		{"01.2.3", "1.2.3", 0},
		{"1.0.0", "1.00.0", 0},
		{"0", "00", 0},
		{"2026.03.27", "2026.3.28", -1},

		// A number of any size.
		{"99999999999999999999999.0.0", "99999999999999999999998.0.0", 1},
		{"18446744073709551616", "18446744073709551615", 1},
		{"1.0.0", "1.0.99999999999999999999999999999999", -1},
		{"00000000000000000000000000000001", "1", 0},

		// A prerelease is lower than its release, and higher than the release before.
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0-0", "1.0.0", -1},
		{"1.0.1-rc.1", "1.0.0", 1},
		{"1.0.0-rc.1", "0.9.9", 1},
		{"3.5.14-rc.1", "3.5.13", 1},
		{"3.5.13-rc.1", "3.5.14", -1},

		// Identifiers: numbers by value, text by ASCII, numbers below text, a
		// list that is a prefix of another below it.
		{"1.0.0-rc.2", "1.0.0-rc.10", -1},
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0-alpha", "1.0.0-1", 1},
		{"1.0.0-2", "1.0.0-10", -1},
		{"1.0.0-0", "1.0.0-1", -1},
		{"1.0.0-Beta", "1.0.0-alpha", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-a", "1.0.0-a-b", -1},
		{"1.0.0-a-b", "1.0.0-a-c", -1},
		{"1.0.0-rc", "1.0.0-rc.1", -1},
		{"1.0.0-rc.1", "1.0.0-rc.1.1", -1},
		{"1.0.0-rc.1.2", "1.0.0-rc.1.10", -1},
		{"1.0.0-rc.1", "1.0.0-rc.beta", -1},
		{"1.0.0-beta.11", "1.0.0-rc.1", -1},
		{"1.0.0-rc.1-x", "1.0.0-rc.1", 1},
		{"1.0.0-rc.99999999999999999999", "1.0.0-rc.100000000000000000000", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},

		// Letters then digits: the letters, then the number by value (our
		// tags are v1.0.0-rcN).
		{"v1.0.0-rc9", "v1.0.0-rc10", -1},
		{"v1.0.0-rc10", "v1.0.0", -1},
		{"v1.0.0-rc2", "v1.0.0-rc10", -1},
		{"1.0.0-beta2", "1.0.0-beta11", -1},
		{"1.0.0-beta11", "1.0.0-rc1", -1},
		{"1.0.0-rc1", "1.0.0-rc1.1", -1},
		{"1.0.0-rc10", "1.0.0-rc10", 0},
		{"1.0.0-rc", "1.0.0-rc1", -1},
		{"1.0.0-rc9", "1.0.0-rcx", -1},
		// Ordered as a whole even with identifiers of other shapes.
		{"1.0.0-rc9", "1.0.0-rc2x", -1},
		{"1.0.0-rc10", "1.0.0-rc2x", -1},

		// Build metadata is not looked at.
		{"1.2.3+b5", "1.2.3+b6", 0},
		{"1.2.3+b5", "1.2.4", -1},
		{"1.2.3-rc.1+b5", "1.2.3-rc.1", 0},
		{"1.2.3-rc.1+b5", "1.2.3", -1},
		{"1.2.3+", "1.2.3", 0},
		{"1.2.3+a+b", "1.2.3", 0},
		{"1.2.3+rc", "1.2.3-rc", 1},
		{"v1.2.3+b5", "1.2.3", 0},

		// What is not a version is below every version, and among such things
		// the order of the strings.
		{"dev", "0", -1},
		{"dev", "0.0.0", -1},
		{"dev", "0.0.0-0", -1},
		{"", "0", -1},
		{"latest", "99999.0.0", -1},
		{"dev", "dev", 0},
		{"dev", "latest", -1},
		{"", "dev", -1},
		{"a", "b", -1},
		{"vv1.2.3", "0.0.1", -1},
		{"V1.2.3", "0.0.1", -1},
		{"v", "0.0.1", -1},
		{"v", "vv", -1},
		{"1.x", "0.0.1", -1},
		{"1.2.x", "1.2.0", -1},
		{"1..2", "0.0.1", -1},
		{".1.2", "0.0.1", -1},
		{"1.2.", "0.0.1", -1},
		{"1.2.3-", "0.0.1", -1},
		{"1.2.3-.", "0.0.1", -1},
		{"1.2.3-rc.", "0.0.1", -1},
		{"1.2.3-rc..1", "0.0.1", -1},
		{"1.2.3-.rc", "0.0.1", -1},
		{"1.2.3-rc_1", "0.0.1", -1},
		{"1.2.3-rc!", "0.0.1", -1},
		{" 1.2.3", "0.0.1", -1},
		{"1.2.3 ", "0.0.1", -1},
		{"1.2.3\n", "0.0.1", -1},
		{"-1.2.3", "0.0.1", -1},
		{"+1", "0.0.1", -1},
		{"v+x", "0.0.1", -1},
		{"1.2.3.rc", "0.0.1", -1},
		{"٣.٢", "0.0.1", -1}, // digits of another script are not digits
		{"1_2", "0.0.1", -1},
		{"1.2.3-rc.1/x", "0.0.1", -1},
		{"unknown", "unknowm", 1},
	}
	for _, tc := range tests {
		if got := release.Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := release.Compare(tc.b, tc.a); got != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
}

// TestCompareSemverOrder is the example of semver.org, section 11, in order.
func TestCompareSemverOrder(t *testing.T) {
	chain := []string{
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
		"1.0.1", "1.1.0", "2.0.0", "2.1.0", "2.1.1", "10.0.0",
	}
	for i := range chain {
		for j := range chain {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := release.Compare(chain[i], chain[j]); got != want {
				t.Errorf("Compare(%q, %q) = %d, want %d", chain[i], chain[j], got, want)
			}
		}
	}
}

// versionCorpus is a list of strings of every kind, for the properties of the order.
var versionCorpus = []string{
	"", "dev", "latest", "unknown", "v", "vv1.2.3", "V1.2.3", "1.x", "1..2", "1.2.3-", "1.2.3-rc_1", " 1.2.3", "-1", "a", "b", "zzz",
	"0", "0.0.0", "0.0.1", "v0.0.1", "0.1", "0.1.0", "0.10.0", "0.9.0", "1", "1.0", "1.0.0", "v1.0.0", "1.0.0+b1", "1.0.0+b2",
	"1.0.0-0", "1.0.0-1", "1.0.0-2", "1.0.0-10", "1.0.0-a", "1.0.0-a-b", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
	"1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-Beta", "1.0.0-rc", "1.0.0-rc.1", "1.0.0-rc.2", "1.0.0-rc.10", "1.0.0-rc.1.1",
	"1.0.0-rc.99999999999999999999", "1.0.1", "1.1.0", "1.2.3", "1.2.3.4", "1.2.3.0", "2", "2.0.0", "3.5", "3.5.0", "3.5.12", "3.5.13",
	"3.5.13-rc.1", "3.5.13-rc.2", "3.5.14-rc.1", "3.5.14", "10.0.0", "v2.2.8", "2.2.8", "v26.3.27", "v26.10.1", "2026.03.27", "2026.3.27",
	"99999999999999999999999.0.0", "99999999999999999999998.0.0",
}

// TestCompareIsAnOrder checks that Compare is a total preorder over all of
// those: what a sort, a maximum and a "newer than" need.
func TestCompareIsAnOrder(t *testing.T) {
	c := versionCorpus
	cmp := func(a, b string) int {
		got := release.Compare(a, b)
		if got < -1 || got > 1 {
			t.Fatalf("Compare(%q, %q) = %d, want -1, 0 or 1", a, b, got)
		}
		return got
	}
	var counts [3]int // pairs that are less, equal, greater: an order that is all one of them says nothing
	for _, a := range c {
		if cmp(a, a) != 0 {
			t.Errorf("Compare(%q, %q) != 0", a, a)
		}
		for _, b := range c {
			ab, ba := cmp(a, b), cmp(b, a)
			counts[ab+1]++
			if ab != -ba {
				t.Errorf("Compare(%q, %q) = %d but Compare(%q, %q) = %d", a, b, ab, b, a, ba)
			}
			if got, want := release.Newer(a, b), ab > 0; got != want {
				t.Errorf("Newer(%q, %q) = %v, want %v", a, b, got, want)
			}
			for _, d := range c {
				// a <= b and b <= d make a <= d, and a strict step stays strict.
				if ab <= 0 && cmp(b, d) <= 0 {
					if ad := cmp(a, d); ad > 0 {
						t.Errorf("%q <= %q <= %q but %q > %q", a, b, d, a, d)
					} else if (ab < 0 || cmp(b, d) < 0) && ad >= 0 {
						t.Errorf("%q < %q <= %q (or <=, <) but Compare(%q, %q) = %d", a, b, d, a, d, ad)
					}
				}
			}
		}
	}
	// Mostly different, as the corpus is, with some that are the same.
	n := len(c) * len(c)
	if counts[0] < n/3 || counts[2] < n/3 || counts[1] < len(c) || counts[1] > n/10 {
		t.Errorf("of %d pairs, %d are less, %d equal and %d greater: not an order of this corpus", n, counts[0], counts[1], counts[2])
	}
}

func TestNewer(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"3.5.13", "3.5.12", true},
		{"3.5.12", "3.5.13", false},
		{"3.5.13", "3.5.13", false},
		{"v2.2.8", "2.2.8", false},
		{"v0.5.1", "v0.5.0", true},
		{"v0.5.0-rc.1", "v0.5.0", false},
		{"v0.5.0", "v0.5.0-rc.1", true},
		{"v26.10.1", "v26.3.27", true},
		{"dev", "v0.0.1", false},
		{"v0.0.1", "dev", true},
		{"dev", "dev", false},
		{"1.2.3+b5", "1.2.3", false},
	}
	for _, tc := range tests {
		if got := release.Newer(tc.a, tc.b); got != tc.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestIsVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"v0.5.0": true, "3.5": true, "1.2.3-rc.1+b": true,
		"dev": false, "": false, "1.x": false, "v": false, "1.2.3-": false,
	} {
		if got := release.IsVersion(v); got != want {
			t.Errorf("IsVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

// Compare is a total order on prereleases of every shape: antisymmetric and
// transitive.
func TestComparePrereleaseIsAnOrder(t *testing.T) {
	vs := []string{"1.0.0", "1.0.0-rc", "1.0.0-rc1", "1.0.0-rc2", "1.0.0-rc9", "1.0.0-rc10", "1.0.0-rc2x",
		"1.0.0-rc-x", "1.0.0-rcx", "1.0.0-rc.1", "1.0.0-rc.10", "1.0.0-1", "1.0.0-1-x", "1.0.0-Beta2",
		"1.0.0-beta", "1.0.0-beta2", "1.0.0-beta11", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-rc1.1", "1.0.0-a1b2"}
	for _, a := range vs {
		for _, b := range vs {
			if release.Compare(a, b) != -release.Compare(b, a) {
				t.Errorf("release.Compare(%s, %s) = %d, release.Compare(%s, %s) = %d", a, b, release.Compare(a, b), b, a, release.Compare(b, a))
			}
			for _, c := range vs {
				if release.Compare(a, b) < 0 && release.Compare(b, c) < 0 && release.Compare(a, c) >= 0 {
					t.Errorf("%s < %s < %s, but release.Compare(%s, %s) = %d", a, b, c, a, c, release.Compare(a, c))
				}
			}
		}
	}
}
