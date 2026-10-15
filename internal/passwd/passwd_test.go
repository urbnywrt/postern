package passwd

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// goodSalt (16 bytes) and goodHash (32 bytes) are well-formed segments for
// hand-made strings. Neither belongs to a real password.
var (
	goodSalt = b64.EncodeToString(bytes.Repeat([]byte{0x11}, 16))
	goodHash = b64.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
)

// withParams returns an encoded hash that is well-formed except, perhaps, for
// the parameter segment. It is meant for strings that are never verified to
// the end.
func withParams(params string) string {
	return "$argon2id$v=19$" + params + "$" + goodSalt + "$" + goodHash
}

// craft returns the encoded form of a real argon2id hash. It does not go
// through Hash, so it can use any cost, and it is what the tests below compare
// Verify against.
func craft(password string, salt []byte, memory, passes uint32, threads uint8, tagLen uint32) string {
	key := argon2.IDKey([]byte(password), salt, passes, memory, threads, tagLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, passes, threads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

// ---------------------------------------------------------------------------
// Hash

var hashPattern = regexp.MustCompile(`^\$argon2id\$v=19\$m=65536,t=3,p=2\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)

func TestHash(t *testing.T) {
	const password = "correct horse battery staple"
	encoded, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	// 16 salt bytes are 22 characters and 32 hash bytes are 43, in the
	// unpadded standard base64 alphabet.
	if !hashPattern.MatchString(encoded) {
		t.Fatalf("Hash() = %q, want $argon2id$v=19$m=65536,t=3,p=2$<22 characters>$<43 characters>", encoded)
	}

	// What the string says is what was done: derive the key again with x/crypto,
	// from the salt and the parameters in the string.
	p, err := decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.memory != 64*1024 || p.passes != 3 || p.threads != 2 {
		t.Errorf("parameters = m=%d,t=%d,p=%d, want m=65536,t=3,p=2", p.memory, p.passes, p.threads)
	}
	if len(p.salt) != 16 || len(p.key) != 32 {
		t.Errorf("salt is %d bytes and key is %d bytes, want 16 and 32", len(p.salt), len(p.key))
	}
	if want := argon2.IDKey([]byte(password), p.salt, 3, 64*1024, 2, 32); !bytes.Equal(p.key, want) {
		t.Error("the hash is not argon2id of the password with the salt and parameters in the string")
	}
}

func TestHashIsSalted(t *testing.T) {
	a, err := Hash("same password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Hash("same password")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical")
	}
	pa, _ := decode(a)
	pb, _ := decode(b)
	if bytes.Equal(pa.salt, pb.salt) {
		t.Error("two hashes of the same password use the same salt")
	}
}

// Hash takes the password as the bytes it is: nothing is trimmed or normalized,
// and no password is too short or too odd. The rules about what a password has
// to be belong to the caller.
func TestHashThenVerify(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"ordinary", "correct horse battery staple"},
		{"empty", ""},
		{"spaces, a tab and a NUL", " padded\t\x00tail "},
		{"unicode", "пароль-密码-é"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := Hash(tc.password)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := Verify(encoded, tc.password); err != nil || !ok {
				t.Errorf("Verify(Hash(pw), pw) = %v, %v, want true, nil", ok, err)
			}
			if tc.name == "ordinary" { // one wrong password is enough here, TestVerify has the others
				if ok, err := Verify(encoded, tc.password+"!"); err != nil || ok {
					t.Errorf("Verify(Hash(pw), other) = %v, %v, want false, nil", ok, err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Verify

func TestVerify(t *testing.T) {
	salt := bytes.Repeat([]byte{0x33}, 16)
	tests := []struct {
		name   string
		stored string
		given  string
		want   bool
	}{
		{"same password", "correct horse battery staple", "correct horse battery staple", true},
		{"last character missing", "correct horse battery staple", "correct horse battery stapl", false},
		{"one character more", "correct horse battery staple", "correct horse battery staplee", false},
		{"upper case", "correct horse battery staple", "Correct horse battery staple", false},
		{"trailing space", "correct horse battery staple", "correct horse battery staple ", false},
		{"leading space", "correct horse battery staple", " correct horse battery staple", false},
		{"trailing newline", "correct horse battery staple", "correct horse battery staple\n", false},
		{"empty given", "correct horse battery staple", "", false},
		{"empty stored", "", "correct horse battery staple", false},
		{"both empty", "", "", true},
		{"NUL appended", "pass", "pass\x00", false},
		{"NUL inside, same", "pass\x00word", "pass\x00word", true},
		{"NUL inside, cut at the NUL", "pass\x00word", "pass", false},
		{"unicode, same", "пароль-密码", "пароль-密码", true},
		{"unicode, composed and decomposed forms differ", "é", "é", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := craft(tc.stored, salt, 64, 1, 1, 32)
			got, err := Verify(encoded, tc.given)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got != tc.want {
				t.Errorf("Verify(hash of %q, %q) = %v, want %v", tc.stored, tc.given, got, tc.want)
			}
		})
	}
}

// The strings below were made with Node.js crypto.argon2Sync (OpenSSL), not
// with x/crypto. The same function reproduces the Argon2id test vector of
// RFC 9106 section 5.3, so these pin the encoding and the derivation against
// an independent implementation.
func TestVerifyKnownAnswers(t *testing.T) {
	tests := []struct {
		name     string
		password string
		encoded  string
	}{
		{
			"the parameters Hash writes, unicode password", "pässwörd-пароль-密码",
			"$argon2id$v=19$m=65536,t=3,p=2$AQIDBAUGBwgJCgsMDQ4PEA$5UdUcr/FDc75hl71vZVnBjckCZA1awyOU3hNIKmHj04",
		},
		{
			"8-byte salt and 24-byte tag", "password",
			"$argon2id$v=19$m=1024,t=2,p=4$c29tZXNhbHQ$MfdjzcytEeXZM5ijm4z8Gut8QmpjPY4o",
		},
		{
			"largest t and p, smallest m for that p", "password",
			"$argon2id$v=19$m=128,t=10,p=16$EBESExQVFhcYGRobHB0eHw$3CWIqOREJfEmCeJcW/8xBZhSmXZMjVPezd9V8gpnRks",
		},
		{
			"64-byte salt and tag", "password",
			"$argon2id$v=19$m=64,t=1,p=1$ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eXw$V9jdmhZ+JVdhONsokuSeSqO1xKFgFeL1ubWKmcgjMq1GPqEFD4cmg19bztD/nphmHe8AiuGnulNojP1EovhPqQ",
		},
		{
			"8-byte salt and 16-byte tag", "password",
			"$argon2id$v=19$m=64,t=1,p=1$MDEyMzQ1Njc$FrsH+C0dkRmgU20SrD2Mjg",
		},
		{
			"empty password", "",
			"$argon2id$v=19$m=64,t=1,p=1$QEFCQ0RFRkdISUpLTE1OTw$JfGVvfB5pnJ/8nODDaVRehibhK8jOBlXr7xUK9gY+es",
		},
		{
			"NUL inside the password", "pass\x00word",
			"$argon2id$v=19$m=64,t=1,p=1$UFFSU1RVVldYWVpbXF1eXw$wMMiOt/yvwaYZGFCowJcvZtWLzby0ZjdtDpuxv6Wr1o",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if ok, err := Verify(tc.encoded, tc.password); err != nil || !ok {
				t.Errorf("Verify(known hash, right password) = %v, %v, want true, nil", ok, err)
			}
			if ok, err := Verify(tc.encoded, tc.password+"x"); err != nil || ok {
				t.Errorf("Verify(known hash, wrong password) = %v, %v, want false, nil", ok, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Strings that are not usable hashes

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	// A parameter segment that is fine, for the cases that spoil another part.
	const params = "m=65536,t=3,p=2"
	// The password that is passed to Verify, which also takes the place of each
	// segment in turn, to see that no error repeats the text it was given.
	const password = "S3cretPassw0rd!"
	nonCanonicalSalt := goodSalt[:len(goodSalt)-1] + "R" // same bytes as goodSalt, with a bit set that base64 leaves unused
	saltWithNewline := goodSalt[:5] + "\n" + goodSalt[5:]
	for _, s := range []string{nonCanonicalSalt, saltWithNewline} {
		// The premise of two of the cases: the standard decoder lets these
		// through and reads the same 16 bytes as from goodSalt.
		if got, err := b64.DecodeString(s); err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0x11}, 16)) {
			t.Fatalf("base64 decoder does not read %q as the bytes of goodSalt: %v", s, err)
		}
	}
	segment := func(n int) string { return b64.EncodeToString(bytes.Repeat([]byte{0x44}, n)) }

	tests := []struct {
		name    string
		encoded string
		want    error
	}{
		// Not an encoded hash at all, or one with the wrong shape.
		{"empty string", "", ErrInvalidHash},
		{"not a hash", "not a hash", ErrInvalidHash},
		{"a single dollar", "$", ErrInvalidHash},
		{"algorithm only", "$argon2id$", ErrInvalidHash},
		{"no salt and no hash", "$argon2id$v=19$" + params, ErrInvalidHash},
		{"no hash", "$argon2id$v=19$" + params + "$" + goodSalt, ErrInvalidHash},
		{"no version", "$argon2id$" + params + "$" + goodSalt + "$" + goodHash, ErrInvalidHash},
		{"one segment too many", withParams(params) + "$extra", ErrInvalidHash},
		{"trailing dollar", withParams(params) + "$", ErrInvalidHash},
		{"leading space", " " + withParams(params), ErrInvalidHash},
		{"trailing newline", withParams(params) + "\n", ErrInvalidHash},
		{"text before the first dollar", "x" + withParams(params), ErrInvalidHash},
		{"bcrypt", "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", ErrInvalidHash},

		// Well-formed, but another algorithm or version.
		{"argon2i", "$argon2i$v=19$" + params + "$" + goodSalt + "$" + goodHash, ErrUnsupportedHash},
		{"argon2d", "$argon2d$v=19$" + params + "$" + goodSalt + "$" + goodHash, ErrUnsupportedHash},
		{"algorithm in capitals", "$ARGON2ID$v=19$" + params + "$" + goodSalt + "$" + goodHash, ErrUnsupportedHash},
		{"empty algorithm", "$$v=19$" + params + "$" + goodSalt + "$" + goodHash, ErrUnsupportedHash},
		{"version 16", "$argon2id$v=16$" + params + "$" + goodSalt + "$" + goodHash, ErrUnsupportedHash},
		{"version 18", "$argon2id$v=18$" + params + "$" + goodSalt + "$" + goodHash, ErrUnsupportedHash},
		{"version 20", "$argon2id$v=20$" + params + "$" + goodSalt + "$" + goodHash, ErrUnsupportedHash},
		{"version with a leading zero", "$argon2id$v=019$" + params + "$" + goodSalt + "$" + goodHash, ErrUnsupportedHash},
		{"version without a number", "$argon2id$v=$" + params + "$" + goodSalt + "$" + goodHash, ErrUnsupportedHash},

		// Parameters that cannot be read.
		{"empty parameters", withParams(""), ErrInvalidHash},
		{"no p", withParams("m=65536,t=3"), ErrInvalidHash},
		{"extra parameter", withParams("m=65536,t=3,p=2,x=1"), ErrInvalidHash},
		{"wrong order", withParams("t=3,m=65536,p=2"), ErrInvalidHash},
		{"wrong name", withParams("m=65536,t=3,q=2"), ErrInvalidHash},
		{"empty value", withParams("m=,t=3,p=2"), ErrInvalidHash},
		{"negative value", withParams("m=65536,t=-3,p=2"), ErrInvalidHash},
		{"plus sign", withParams("m=65536,t=+3,p=2"), ErrInvalidHash},
		{"hexadecimal", withParams("m=65536,t=3,p=0x2"), ErrInvalidHash},
		{"space", withParams("m=65536, t=3,p=2"), ErrInvalidHash},
		{"decimal point", withParams("m=65536,t=3,p=2.0"), ErrInvalidHash},
		{"digit separator", withParams("m=65_536,t=3,p=2"), ErrInvalidHash},
		{"does not fit 32 bits", withParams("m=4294967296,t=3,p=2"), ErrInvalidHash},

		// Parameters outside the bounds (m is in KiB, and at least 8*p).
		{"m is zero", withParams("m=0,t=3,p=2"), ErrUnsupportedHash},
		{"m below 8*p", withParams("m=15,t=3,p=2"), ErrUnsupportedHash},
		{"m below 8", withParams("m=7,t=1,p=1"), ErrUnsupportedHash},
		{"m above 1 GiB", withParams("m=1048577,t=3,p=2"), ErrUnsupportedHash},
		{"m is the largest 32-bit number", withParams("m=4294967295,t=3,p=2"), ErrUnsupportedHash},
		{"t is zero", withParams("m=65536,t=0,p=2"), ErrUnsupportedHash},
		{"t above 10", withParams("m=65536,t=11,p=2"), ErrUnsupportedHash},
		{"t is the largest 32-bit number", withParams("m=65536,t=4294967295,p=2"), ErrUnsupportedHash},
		{"p is zero", withParams("m=65536,t=3,p=0"), ErrUnsupportedHash},
		{"p above 16", withParams("m=65536,t=3,p=17"), ErrUnsupportedHash},
		{"p of 256 (does not fit a byte)", withParams("m=65536,t=3,p=256"), ErrUnsupportedHash},
		{"p is the largest 32-bit number", withParams("m=65536,t=3,p=4294967295"), ErrUnsupportedHash},

		// Salt and hash that cannot be read.
		{"salt with a character outside the alphabet", "$argon2id$v=19$" + params + "$!" + goodSalt[1:] + "$" + goodHash, ErrInvalidHash},
		{"salt with padding", "$argon2id$v=19$" + params + "$" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 16)) + "$" + goodHash, ErrInvalidHash},
		{"salt in the URL alphabet", "$argon2id$v=19$" + params + "$" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb, 0xff}, 8)) + "$" + goodHash, ErrInvalidHash},
		{"salt with unused bits set", "$argon2id$v=19$" + params + "$" + nonCanonicalSalt + "$" + goodHash, ErrInvalidHash},
		{"salt with a newline", "$argon2id$v=19$" + params + "$" + saltWithNewline + "$" + goodHash, ErrInvalidHash},
		{"salt of one character", "$argon2id$v=19$" + params + "$A$" + goodHash, ErrInvalidHash},
		{"hash with a character outside the alphabet", "$argon2id$v=19$" + params + "$" + goodSalt + "$!" + goodHash[1:], ErrInvalidHash},
		{"hash with padding", "$argon2id$v=19$" + params + "$" + goodSalt + "$" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)), ErrInvalidHash},

		// Salt and hash of a size that is not accepted. A hash of no bytes
		// would make x/crypto panic.
		{"empty salt", "$argon2id$v=19$" + params + "$$" + goodHash, ErrUnsupportedHash},
		{"salt of 7 bytes", "$argon2id$v=19$" + params + "$" + segment(7) + "$" + goodHash, ErrUnsupportedHash},
		{"salt of 65 bytes", "$argon2id$v=19$" + params + "$" + segment(65) + "$" + goodHash, ErrUnsupportedHash},
		{"empty hash", "$argon2id$v=19$" + params + "$" + goodSalt + "$", ErrUnsupportedHash},
		{"hash of 4 bytes", "$argon2id$v=19$" + params + "$" + goodSalt + "$" + segment(4), ErrUnsupportedHash},
		{"hash of 15 bytes", "$argon2id$v=19$" + params + "$" + goodSalt + "$" + segment(15), ErrUnsupportedHash},
		{"hash of 65 bytes", "$argon2id$v=19$" + params + "$" + goodSalt + "$" + segment(65), ErrUnsupportedHash},

		// The password, where each segment of a hash would be.
		{"password as the algorithm", "$" + password + "$v=19$" + params + "$" + goodSalt + "$" + goodHash, ErrUnsupportedHash},
		{"password as the version", "$argon2id$" + password + "$" + params + "$" + goodSalt + "$" + goodHash, ErrUnsupportedHash},
		{"password as the parameters", withParams(password), ErrInvalidHash},
		{"password in a parameter", withParams("m=" + password + ",t=3,p=2"), ErrInvalidHash},
		{"password as the salt", "$argon2id$v=19$" + params + "$" + password + "$" + goodHash, ErrInvalidHash},
		{"password as the hash", "$argon2id$v=19$" + params + "$" + goodSalt + "$" + password, ErrInvalidHash},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := Verify(tc.encoded, password)
			if ok {
				t.Error("Verify returned true")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			// A password or a hash does not belong in an error that is logged.
			for _, secret := range []string{password, goodSalt, goodHash} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("the error contains %q: %v", secret, err)
				}
			}
			if len(tc.encoded) >= 10 && strings.Contains(err.Error(), tc.encoded) {
				t.Errorf("the error contains the string that was rejected: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Bounds

func TestDecodeBounds(t *testing.T) {
	tests := []struct {
		params  string
		ok      bool
		memory  uint32
		passes  uint32
		threads uint8
	}{
		{"m=65536,t=3,p=2", true, 65536, 3, 2}, // what Hash writes
		{"m=8,t=1,p=1", true, 8, 1, 1},         // the smallest
		{"m=16,t=1,p=2", true, 16, 1, 2},       // m is 8*p exactly
		{"m=15,t=1,p=2", false, 0, 0, 0},
		{"m=128,t=10,p=16", true, 128, 10, 16}, // the largest t and p
		{"m=127,t=10,p=16", false, 0, 0, 0},
		{"m=1048576,t=1,p=1", true, 1 << 20, 1, 1}, // the largest m: 1 GiB
		{"m=1048577,t=1,p=1", false, 0, 0, 0},
		{"m=65536,t=11,p=2", false, 0, 0, 0},
		{"m=65536,t=3,p=17", false, 0, 0, 0},
		{"m=65536,t=0,p=2", false, 0, 0, 0},
		{"m=65536,t=3,p=0", false, 0, 0, 0},
		{"m=0,t=3,p=2", false, 0, 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.params, func(t *testing.T) {
			p, err := decode(withParams(tc.params))
			if !tc.ok {
				if !errors.Is(err, ErrUnsupportedHash) {
					t.Fatalf("err = %v, want %v", err, ErrUnsupportedHash)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if p.memory != tc.memory || p.passes != tc.passes || p.threads != tc.threads {
				t.Errorf("m=%d,t=%d,p=%d, want m=%d,t=%d,p=%d", p.memory, p.passes, p.threads, tc.memory, tc.passes, tc.threads)
			}
		})
	}
}

func TestDecodeSaltAndHashSizes(t *testing.T) {
	for _, tc := range []struct {
		salt, key int
		ok        bool
	}{
		{16, 32, true},
		{8, 16, true},   // the smallest accepted
		{64, 64, true},  // the largest accepted
		{7, 32, false},  // salt too short
		{65, 32, false}, // salt too long
		{16, 15, false}, // hash too short
		{16, 65, false}, // hash too long
		{0, 32, false},
		{16, 0, false},
	} {
		t.Run(fmt.Sprintf("salt %d, hash %d", tc.salt, tc.key), func(t *testing.T) {
			encoded := "$argon2id$v=19$m=65536,t=3,p=2$" +
				b64.EncodeToString(bytes.Repeat([]byte{0x55}, tc.salt)) + "$" +
				b64.EncodeToString(bytes.Repeat([]byte{0x66}, tc.key))
			p, err := decode(encoded)
			if !tc.ok {
				if !errors.Is(err, ErrUnsupportedHash) {
					t.Fatalf("err = %v, want %v", err, ErrUnsupportedHash)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(p.salt) != tc.salt || len(p.key) != tc.key {
				t.Errorf("salt %d bytes and hash %d bytes, want %d and %d", len(p.salt), len(p.key), tc.salt, tc.key)
			}
		})
	}
}

// Parameters at the edges that Verify accepts must give a correct answer, not
// only get past the check.
func TestVerifyAtTheEdgesOfTheBounds(t *testing.T) {
	salt := bytes.Repeat([]byte{0x77}, 16)
	for _, tc := range []struct {
		name    string
		memory  uint32
		passes  uint32
		threads uint8
	}{
		{"smallest", 8, 1, 1},
		{"m is 8*p", 16, 1, 2},
		{"largest t and p", 128, 10, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := craft("edge password", salt, tc.memory, tc.passes, tc.threads, 32)
			if ok, err := Verify(encoded, "edge password"); err != nil || !ok {
				t.Errorf("right password: %v, %v, want true, nil", ok, err)
			}
			if ok, err := Verify(encoded, "edge passwore"); err != nil || ok {
				t.Errorf("wrong password: %v, %v, want false, nil", ok, err)
			}
		})
	}
}

// A hash that asks for more than the bounds allow is refused before any work
// is done for it: 1 GiB of memory is what a hash with m=1048577 would take.
func TestVerifyRefusesOutOfBoundsParametersBeforeHashing(t *testing.T) {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	ok, err := Verify(withParams("m=1048577,t=10,p=16"), "password")
	runtime.ReadMemStats(&after)

	if ok || !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("Verify = %v, %v, want false, %v", ok, err, ErrUnsupportedHash)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Errorf("Verify allocated %d bytes for a hash it refuses", allocated)
	}
}

// Whatever decode accepts must be safe to hand to argon2.IDKey, which panics
// when the passes or the lanes are zero or the tag has no bytes.
func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		"",
		"$",
		"$argon2id$v=19$m=65536,t=3,p=2$" + goodSalt + "$" + goodHash,
		"$argon2id$v=19$m=8,t=1,p=1$" + goodSalt + "$" + goodHash,
		"$argon2id$v=19$m=1048576,t=10,p=16$" + goodSalt + "$" + goodHash,
		"$argon2id$v=19$m=0,t=0,p=0$$",
		"$argon2id$v=19$m=65536,t=3,p=2$" + goodSalt + "$",
		"$argon2i$v=16$m=1,t=1,p=1$AA$AA",
		"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		"$argon2id$v=19$m=65536,t=3,p=2$" + goodSalt + "$" + goodHash + "\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := decode(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidHash) && !errors.Is(err, ErrUnsupportedHash) {
				t.Fatalf("decode(%q): err = %v, want ErrInvalidHash or ErrUnsupportedHash", s, err)
			}
			return
		}
		if p.passes < 1 || p.passes > 10 {
			t.Errorf("passes = %d, outside 1..10", p.passes)
		}
		if p.threads < 1 || p.threads > 16 {
			t.Errorf("threads = %d, outside 1..16", p.threads)
		}
		if p.memory < 8*uint32(p.threads) || p.memory > 1<<20 {
			t.Errorf("memory = %d KiB with %d threads, outside 8*p..1<<20", p.memory, p.threads)
		}
		if n := len(p.salt); n < 8 || n > 64 {
			t.Errorf("salt of %d bytes, outside 8..64", n)
		}
		if n := len(p.key); n < 16 || n > 64 {
			t.Errorf("hash of %d bytes, outside 16..64", n)
		}
	})
}
