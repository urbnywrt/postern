package totp

import (
	"encoding/base32"
	"math"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The key of the RFC 6238 test vectors is the 20 ASCII bytes of
// "12345678901234567890". rfcSecret is the same key the way Code, Verify and URI
// take it: base32 without padding.
const (
	rfcKey    = "12345678901234567890"
	rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // gitleaks:allow (the public RFC 6238 test key)
)

// stepN is the step that starts at 1234567890 (an RFC 6238 test time):
// 1234567890 = 41152263 * 30. The codes of the steps around it were computed
// with Python's hmac module, not with this package.
const stepN = 1234567890 / 30

var codesAroundStepN = []struct {
	offset int // steps from stepN
	code   string
}{
	{-3, "798045"},
	{-2, "186057"},
	{-1, "980357"},
	{0, "005924"}, // the RFC 6238 value 89005924, in 6 digits
	{+1, "590587"},
	{+2, "240500"},
	{+3, "992085"},
}

// ---------------------------------------------------------------------------
// The algorithm

// RFC 6238 appendix B, the SHA-1 rows: the same key, 8 digits, 30-second steps.
func TestRFC6238Vectors(t *testing.T) {
	tests := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"}, // a leading zero
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, tc := range tests {
		got := totpAt([]byte(rfcKey), time.Unix(tc.unix, 0), 8)
		if got != tc.want {
			t.Errorf("TOTP at %d = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

// RFC 4226 appendix D: HOTP of the same key for counters 0 to 9, 6 digits.
func TestRFC4226Vectors(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for counter, code := range want {
		if got := hotp([]byte(rfcKey), uint64(counter), 6); got != code {
			t.Errorf("HOTP(%d) = %s, want %s", counter, got, code)
		}
	}
}

// ---------------------------------------------------------------------------
// Code

func TestCode(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		unix   int64
		want   string
	}{
		// The RFC 6238 vectors in 6 digits (the last 6 of the 8).
		{"RFC 6238, 59 s", rfcSecret, 59, "287082"},
		{"RFC 6238, 1111111109 s (leading zero)", rfcSecret, 1111111109, "081804"},
		{"RFC 6238, 1111111111 s (leading zero)", rfcSecret, 1111111111, "050471"},
		{"RFC 6238, 1234567890 s (two leading zeros)", rfcSecret, 1234567890, "005924"},
		{"RFC 6238, 2000000000 s", rfcSecret, 2000000000, "279037"},
		{"RFC 6238, 20000000000 s", rfcSecret, 20000000000, "353130"},

		// The code changes every 30 seconds, on the second.
		{"step 0 starts at 0", rfcSecret, 0, "755224"},
		{"step 0 ends at 29", rfcSecret, 29, "755224"},
		{"step 1 starts at 30", rfcSecret, 30, "287082"},
		{"step 1 ends at 59", rfcSecret, 59, "287082"},
		{"step 2 starts at 60", rfcSecret, 60, "359152"},

		// A key of another length, and the Google Authenticator documentation's secret.
		{"10-byte key, step 0", "JBSWY3DPEHPK3PXP", 0, "282760"},
		{"10-byte key, step 1", "JBSWY3DPEHPK3PXP", 30, "996554"},
		{"10-byte key, 1234567890 s", "JBSWY3DPEHPK3PXP", 1234567890, "742275"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Code(tc.secret, time.Unix(tc.unix, 0))
			if err != nil {
				t.Fatalf("Code: %v", err)
			}
			if got != tc.want {
				t.Errorf("Code(%d) = %s, want %s", tc.unix, got, tc.want)
			}
		})
	}
}

// Only whole seconds count: a step ends with its 29th second, however late.
func TestCodeIgnoresTheFractionOfASecond(t *testing.T) {
	for _, tc := range []struct {
		at   time.Time
		want string
	}{
		{time.Unix(29, 999_999_999), "755224"},
		{time.Unix(30, 0), "287082"},
		{time.Unix(30, 1), "287082"},
		{time.UnixMilli(59_999), "287082"},
		{time.UnixMilli(60_000), "359152"},
	} {
		got, err := Code(rfcSecret, tc.at)
		if err != nil || got != tc.want {
			t.Errorf("Code(%v) = %q, %v, want %q", tc.at.UnixNano(), got, err, tc.want)
		}
	}
}

// The time zone and the clock reading of a time.Time do not matter, only the instant.
func TestCodeDoesNotDependOnTheLocation(t *testing.T) {
	instant := time.Unix(1111111109, 0)
	want := "081804"
	for _, loc := range []*time.Location{time.UTC, time.FixedZone("UTC+14", 14*3600), time.FixedZone("UTC-12", -12*3600)} {
		if got, err := Code(rfcSecret, instant.In(loc)); err != nil || got != want {
			t.Errorf("Code in %s = %q, %v, want %q", loc, got, err, want)
		}
	}
}

// Authenticator apps show a key in groups, in lower case or padded, so a key
// that came from one is read like one that NewSecret made.
func TestCodeReadsLowerCaseAndPaddedSecrets(t *testing.T) {
	// "Hello!" is 6 bytes: 10 base32 characters, which RFC 4648 pads to 16.
	for _, secret := range []string{"JBSWY3DPEE", "JBSWY3DPEE======", "jbswy3dpee", "jbswy3dpee======"} {
		if got, err := Code(secret, time.Unix(59, 0)); err != nil || got != "945916" {
			t.Errorf("Code(%q) = %q, %v, want 945916", secret, got, err)
		}
	}
	if got, err := Code(strings.ToLower(rfcSecret), time.Unix(59, 0)); err != nil || got != "287082" {
		t.Errorf("Code(lower-case RFC secret) = %q, %v, want 287082", got, err)
	}
}

func TestCodeRejectsUnusableSecrets(t *testing.T) {
	at := time.Unix(59, 0)
	for _, secret := range []string{
		"",
		"=",
		"======",
		" ",
		"G",                    // one character cannot be a whole byte
		"GEZ",                  // nor three
		"GEZDGN",               // nor six
		"GEZDGNBV!",            // outside the alphabet
		"GEZDGNBVGY3TQOJ1",     // 1 is not a base32 digit
		"GEZDGNBV GY3TQOJQ",    // spaces
		"GEZDGNBV====GY3TQOJQ", // padding in the middle
		"gezdgnbv-gy3tqojq",    // hyphens
		"JBſWY3DPEHPK3PXP",     // the long s (U+017F) is not an S, although strings.ToUpper would make it one
	} {
		got, err := Code(secret, at)
		if err == nil || got != "" {
			t.Errorf("Code(%q) = %q, %v, want an error and no code", secret, got, err)
			continue
		}
		// A secret does not belong in an error that is logged (short ones would
		// match the words of the message by chance).
		if len(secret) >= 8 && strings.Contains(err.Error(), secret) {
			t.Errorf("the error for %q contains the secret: %v", secret, err)
		}
	}
}

// A time before 1970 has no step. The zero time.Time is one, and is what a
// clock that was never set would give.
func TestCodeRejectsTimesBeforeTheEpoch(t *testing.T) {
	for _, at := range []time.Time{time.Unix(-1, 0), time.Unix(-30, 0), time.Time{}, time.Unix(math.MinInt32, 0)} {
		if got, err := Code(rfcSecret, at); err == nil || got != "" {
			t.Errorf("Code(%v) = %q, %v, want an error and no code", at.Unix(), got, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Verify

// At a time inside stepN, the codes of the steps from -1 to +1 are accepted and
// all others are not.
func TestVerifyAcceptsOneStepEitherWay(t *testing.T) {
	now := time.Unix(stepN*30+10, 0)
	for _, tc := range codesAroundStepN {
		want := tc.offset >= -1 && tc.offset <= 1
		if got := Verify(rfcSecret, tc.code, now); got != want {
			t.Errorf("Verify(code of step %+d) = %v, want %v", tc.offset, got, want)
		}
	}
}

// The code of stepN, checked at every moment around the edges of the steps
// before and after it.
func TestVerifyWindowFollowsTheClock(t *testing.T) {
	const code = "005924"
	for offset := -3; offset <= 3; offset++ {
		want := offset >= -1 && offset <= 1
		for _, at := range []time.Time{
			time.Unix(int64(stepN+offset)*30, 0),              // the first second of the step
			time.Unix(int64(stepN+offset)*30+15, 0),           // its middle
			time.Unix(int64(stepN+offset)*30+29, 999_999_999), // the last instant of the step
		} {
			if got := Verify(rfcSecret, code, at); got != want {
				t.Errorf("Verify(code of step N) at step N%+d, second %d = %v, want %v",
					offset, at.Unix()-int64(stepN+offset)*30, got, want)
			}
		}
	}
}

func TestVerifyRejectsAWrongCode(t *testing.T) {
	now := time.Unix(stepN*30, 0)
	good := "005924"
	if !Verify(rfcSecret, good, now) {
		t.Fatalf("Verify rejects the right code %s", good)
	}
	// Every code that differs from the three accepted ones in one digit.
	accepted := map[string]bool{"980357": true, "005924": true, "590587": true}
	for pos := range good {
		for digit := byte('0'); digit <= '9'; digit++ {
			if digit == good[pos] {
				continue
			}
			code := good[:pos] + string(digit) + good[pos+1:]
			if accepted[code] {
				continue
			}
			if Verify(rfcSecret, code, now) {
				t.Errorf("Verify accepts %s", code)
			}
		}
	}
}

func TestVerifyRejectsCodesOfTheWrongShape(t *testing.T) {
	now := time.Unix(stepN*30+10, 0) // the code is 005924
	if !Verify(rfcSecret, "005924", now) {
		t.Fatal("Verify rejects the right code")
	}
	for _, code := range []string{
		"",
		"5924",     // leading zeros dropped
		"05924",    // five digits
		"0059240",  // seven digits
		"00592400", // eight digits, the RFC value would be 89005924
		"89005924", // the 8-digit code of the same step
		" 005924",  // spaces and line ends are for the caller to trim
		"005924 ",
		"005924\n",
		"005 924",
		"+05924",
		"-05924",
		"0x5924",
		"00592a",
		"٠٠٥٩٢٤", // the same digits in Arabic-Indic numerals
		"００５９２４", // full-width digits
		"005924\x00",
		"\x00005924",
	} {
		if Verify(rfcSecret, code, now) {
			t.Errorf("Verify accepts %q", code)
		}
	}
}

func TestVerifyRejectsUnusableSecrets(t *testing.T) {
	now := time.Unix(59, 0)
	// The code that a key of no bytes gives at that time. A secret that was
	// never set must not turn into a key that anybody can compute.
	emptyKeyCode := hotp(nil, uint64(now.Unix()/30), 6)
	for _, secret := range []string{"", "=", "======", "G", "GEZDGNBV!", "GEZDGNBVGY3TQOJ1", "JBſWY3DPEHPK3PXP"} {
		for _, code := range []string{emptyKeyCode, "287082", "000000"} {
			if Verify(secret, code, now) {
				t.Errorf("Verify(%q, %q) = true", secret, code)
			}
		}
	}
}

func TestVerifyReadsTheSecretLikeCode(t *testing.T) {
	now := time.Unix(59, 0)
	for _, secret := range []string{rfcSecret, strings.ToLower(rfcSecret)} {
		if !Verify(secret, "287082", now) {
			t.Errorf("Verify(%q) = false", secret)
		}
	}
	if !Verify("jbswy3dpee======", "945916", now) {
		t.Error("Verify rejects a lower-case padded secret")
	}
}

// Step -1 of the first step is not a step. Counting it as step 2^64-1 would
// accept the code of that step in the first minute after the epoch.
func TestVerifyDoesNotWrapAroundAtTheEpoch(t *testing.T) {
	wrapped := hotp([]byte(rfcKey), math.MaxUint64, 6)
	if wrapped != "094451" { // from Python, not from this package
		t.Fatalf("HOTP(2^64-1) = %s, want 094451", wrapped)
	}
	for _, at := range []time.Time{time.Unix(0, 0), time.Unix(29, 0)} {
		for _, tc := range []struct {
			what string
			code string
			want bool
		}{
			{"step 0", "755224", true},
			{"step 1", "287082", true},
			{"step 2", "359152", false},
			{"step -1 as 2^64-1", wrapped, false},
		} {
			if got := Verify(rfcSecret, tc.code, at); got != tc.want {
				t.Errorf("Verify(%s) at %d = %v, want %v", tc.what, at.Unix(), got, tc.want)
			}
		}
	}
}

func TestVerifyRejectsTimesBeforeTheEpoch(t *testing.T) {
	// One second before the epoch is 29 seconds from step 0 on the other side,
	// which must not make step 0 acceptable.
	for _, at := range []time.Time{time.Unix(-1, 0), time.Unix(-29, 0), time.Time{}} {
		for _, code := range []string{"755224", "287082"} {
			if Verify(rfcSecret, code, at) {
				t.Errorf("Verify(%s) at %d = true", code, at.Unix())
			}
		}
	}
}

// ---------------------------------------------------------------------------
// NewSecret

func TestNewSecret(t *testing.T) {
	pattern := regexp.MustCompile(`^[A-Z2-7]{32}$`)
	seen := make(map[string]struct{})
	for range 100 {
		secret, err := NewSecret()
		if err != nil {
			t.Fatalf("NewSecret: %v", err)
		}
		if !pattern.MatchString(secret) {
			t.Fatalf("NewSecret() = %q, want 32 base32 characters without padding", secret)
		}
		// 32 characters hold exactly 160 bits, so no padding is ever needed.
		raw, err := base32.StdEncoding.DecodeString(secret)
		if err != nil || len(raw) != 20 {
			t.Fatalf("NewSecret() = %q decodes to %d bytes, %v, want 20 bytes", secret, len(raw), err)
		}
		if _, dup := seen[secret]; dup {
			t.Fatalf("NewSecret() returned %q twice", secret)
		}
		seen[secret] = struct{}{}
	}
}

func TestNewSecretWorksWithCodeAndVerify(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, err := Code(secret, now)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if !regexp.MustCompile(`^[0-9]{6}$`).MatchString(code) {
		t.Fatalf("Code = %q, want 6 digits", code)
	}
	// The code of a step is accepted in that step and in the two next to it.
	for _, at := range []time.Time{now, now.Add(30 * time.Second), now.Add(-30 * time.Second)} {
		if !Verify(secret, code, at) {
			t.Errorf("Verify rejects the code of the current step at %+d s", at.Unix()-now.Unix())
		}
	}
}

// ---------------------------------------------------------------------------
// URI

func TestURI(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP" // the example secret of the Google Authenticator key URI documentation
	const tail = "&algorithm=SHA1&digits=6&period=30"
	tests := []struct {
		name    string
		account string
		issuer  string
		want    string
	}{
		{
			"plain", "admin", "Postern",
			"otpauth://totp/Postern:admin?secret=" + secret + "&issuer=Postern" + tail,
		},
		{
			"an e-mail address keeps its @", "alice@example.com", "Postern",
			"otpauth://totp/Postern:alice@example.com?secret=" + secret + "&issuer=Postern" + tail,
		},
		{
			"spaces are %20, not +", "Alice Admin", "Postern Panel",
			"otpauth://totp/Postern%20Panel:Alice%20Admin?secret=" + secret + "&issuer=Postern%20Panel" + tail,
		},
		{
			"reserved characters are escaped", "a+b&c=d/e?f#g%h", "A&B",
			"otpauth://totp/A%26B:a%2Bb%26c%3Dd%2Fe%3Ff%23g%25h?secret=" + secret + "&issuer=A%26B" + tail,
		},
		{
			"unicode is escaped as UTF-8", "админ", "Постерн",
			"otpauth://totp/%D0%9F%D0%BE%D1%81%D1%82%D0%B5%D1%80%D0%BD:%D0%B0%D0%B4%D0%BC%D0%B8%D0%BD?secret=" + secret +
				"&issuer=%D0%9F%D0%BE%D1%81%D1%82%D0%B5%D1%80%D0%BD" + tail,
		},
		{
			"unreserved punctuation stays", "a-b_c.d~e", "Post-ern_1.0~",
			"otpauth://totp/Post-ern_1.0~:a-b_c.d~e?secret=" + secret + "&issuer=Post-ern_1.0~" + tail,
		},
		{
			// Neither part of a label may contain a colon (it separates them), and
			// there is no way to write one. Dropping it keeps the label readable.
			"colons are dropped", "a:b", "Post:ern: Panel",
			"otpauth://totp/Postern%20Panel:ab?secret=" + secret + "&issuer=Postern%20Panel" + tail,
		},
		{
			"no issuer", "admin", "",
			"otpauth://totp/admin?secret=" + secret + tail,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := URI(secret, tc.account, tc.issuer); got != tc.want {
				t.Errorf("URI(%q, %q) =\n %s\nwant\n %s", tc.account, tc.issuer, got, tc.want)
			}
		})
	}
}

// A standard URL parser must read back what went in (leaving colons aside).
func TestURIParsesBack(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // gitleaks:allow (the public RFC 6238 test key)
	for _, tc := range []struct{ account, issuer string }{
		{"admin", "Postern"},
		{"alice@example.com", "Postern (panel.example.com)"},
		{"Alice Admin", "Postern Panel"},
		{"a+b&c=d/e?f#g%h", "A&B=C"},
		{"админ", "Постерн"},
		{"日本語", "例え"},
		{"emoji 😀", "Postern"},
		{`quote"and'apostrophe`, "<Postern>"},
		{"100% sure", "50%"},
	} {
		uri := URI(secret, tc.account, tc.issuer)
		u, err := url.Parse(uri)
		if err != nil {
			t.Errorf("url.Parse(%q): %v", uri, err)
			continue
		}
		if u.Scheme != "otpauth" || u.Host != "totp" {
			t.Errorf("%q: scheme %q and host %q, want otpauth and totp", uri, u.Scheme, u.Host)
		}
		if want := "/" + tc.issuer + ":" + tc.account; u.Path != want {
			t.Errorf("%q: label %q, want %q", uri, u.Path, want)
		}
		q := u.Query()
		for key, want := range map[string]string{
			"secret": secret, "issuer": tc.issuer, "algorithm": "SHA1", "digits": "6", "period": "30",
		} {
			if got := q.Get(key); got != want {
				t.Errorf("%q: parameter %s = %q, want %q", uri, key, got, want)
			}
		}
		if len(q) != 5 {
			t.Errorf("%q: %d parameters, want 5", uri, len(q))
		}
		if u.Fragment != "" {
			t.Errorf("%q: has a fragment %q", uri, u.Fragment)
		}
	}
}

// What an authenticator app reads from the URI is the secret that NewSecret
// made, unchanged.
func TestURICarriesTheSecret(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(URI(secret, "admin", "Postern"))
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("secret"); got != secret {
		t.Errorf("secret in the URI = %q, want %q", got, secret)
	}
}

// A secret from NewSecret needs no escaping, but one that does not come from
// there must not be able to add or change a parameter of the URI.
func TestURIDoesNotLetTheSecretAddParameters(t *testing.T) {
	const secret = "AAAA&issuer=Evil&digits=8#x"
	u, err := url.Parse(URI(secret, "admin", "Postern"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if len(q) != 5 || q.Get("issuer") != "Postern" || q.Get("digits") != "6" {
		t.Errorf("the secret changed the parameters: %v", q)
	}
	if got := q.Get("secret"); got != secret {
		t.Errorf("secret in the URI = %q, want it read back as %q", got, secret)
	}
	if u.Fragment != "" {
		t.Errorf("the secret started a fragment %q", u.Fragment)
	}
}
