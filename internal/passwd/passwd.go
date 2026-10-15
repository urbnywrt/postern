// Package passwd hashes the passwords of panel admins with argon2id, and checks
// them.
//
// A hash is one string in the PHC format, the one that other argon2 tools write
// and read:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
//
// m is the memory in KiB, t the number of passes over it, p the number of lanes,
// and salt and hash are base64 without padding. The cost is part of the string,
// so it can be raised in a later version while old hashes keep verifying.
package passwd

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// What Hash writes: the second option that RFC 9106 recommends for a machine
// with little memory, with two lanes. A hash takes 64 MiB while it is computed.
const (
	hashMemoryKiB = 64 * 1024
	hashPasses    = 3
	hashThreads   = 2
	saltLen       = 16
	keyLen        = 32
)

// What Verify accepts. A stored hash decides how much memory and time Verify
// spends on it, so an altered or foreign string must not be able to ask for more
// than these. The lower limits are Argon2's own (at least one pass and one lane,
// and m of at least 8*p) and sizes that still mean something. x/crypto panics for
// no passes, no lanes and a hash of no bytes.
const (
	maxMemoryKiB = 1 << 20 // 1 GiB
	maxPasses    = 10
	maxThreads   = 16
	minSaltLen   = 8
	maxSaltLen   = 64
	minKeyLen    = 16
	maxKeyLen    = 64
)

var (
	// ErrInvalidHash is returned by [Verify] for a string that is not an argon2id
	// hash in the form that [Hash] writes: wrong segments, parameters that are not
	// numbers, or a salt or hash that is not unpadded standard base64.
	ErrInvalidHash = errors.New("passwd: invalid password hash")

	// ErrUnsupportedHash is returned by [Verify] for a hash that is well-formed
	// but not acceptable: another algorithm or version, parameters outside the
	// bounds, or a salt or hash of a size that is not accepted.
	ErrUnsupportedHash = errors.New("passwd: unsupported password hash")
)

// b64 is the encoding of the salt and the hash in the string.
var b64 = base64.RawStdEncoding

// Hash returns the argon2id hash of password with a new random salt, in the
// form shown in the package documentation. The password is used as the bytes it
// is, with no normalization, and may be empty: the rules about what a password
// has to be belong to the caller.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("passwd: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, hashPasses, hashMemoryKiB, hashThreads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, hashMemoryKiB, hashPasses, hashThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify reports whether password is the one that encoded was made from. The
// hashes are compared in constant time.
//
// A wrong password gives false and no error. An error, and never true, comes
// back for an encoded string that is not usable: [ErrInvalidHash], or
// [ErrUnsupportedHash] when it names another algorithm or version, or asks for
// more than m = 1<<20 KiB, t = 10 or p = 16 (or for less than Argon2 allows).
// Those are checked before any hashing is done. The errors do not contain the
// password or the string.
func Verify(encoded, password string) (bool, error) {
	h, err := decode(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), h.salt, h.passes, h.memory, h.threads, uint32(len(h.key)))
	return subtle.ConstantTimeCompare(got, h.key) == 1, nil
}

// decoded is an argon2id hash taken apart. Every value in it is within the
// bounds above.
type decoded struct {
	memory  uint32 // KiB
	passes  uint32
	threads uint8
	salt    []byte
	key     []byte
}

func decode(encoded string) (decoded, error) {
	// "$argon2id$v=19$m=..,t=..,p=..$salt$hash" is an empty string and five segments.
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return decoded{}, fmt.Errorf("%w: want five segments after a leading $", ErrInvalidHash)
	}
	if parts[1] != "argon2id" {
		return decoded{}, fmt.Errorf("%w: the algorithm is not argon2id", ErrUnsupportedHash)
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return decoded{}, fmt.Errorf("%w: the version is not %d", ErrUnsupportedHash, argon2.Version)
	}

	cost := strings.Split(parts[3], ",")
	if len(cost) != 3 {
		return decoded{}, fmt.Errorf("%w: want the parameters m, t and p", ErrInvalidHash)
	}
	memory, okM := parameter(cost[0], "m")
	passes, okT := parameter(cost[1], "t")
	threads, okP := parameter(cost[2], "p")
	if !okM || !okT || !okP {
		return decoded{}, fmt.Errorf("%w: want the parameters in the form m=<number>,t=<number>,p=<number>", ErrInvalidHash)
	}
	// p is checked first: it is what makes the limit on m.
	if threads < 1 || threads > maxThreads || passes < 1 || passes > maxPasses ||
		memory < 8*threads || memory > maxMemoryKiB {
		return decoded{}, fmt.Errorf("%w: m=%d, t=%d, p=%d are outside the accepted bounds", ErrUnsupportedHash, memory, passes, threads)
	}

	salt, okSalt := segment(parts[4])
	key, okKey := segment(parts[5])
	if !okSalt || !okKey {
		return decoded{}, fmt.Errorf("%w: the salt and the hash must be unpadded standard base64", ErrInvalidHash)
	}
	if len(salt) < minSaltLen || len(salt) > maxSaltLen || len(key) < minKeyLen || len(key) > maxKeyLen {
		return decoded{}, fmt.Errorf("%w: the salt is %d bytes and the hash %d, want %d to %d and %d to %d",
			ErrUnsupportedHash, len(salt), len(key), minSaltLen, maxSaltLen, minKeyLen, maxKeyLen)
	}

	return decoded{memory: memory, passes: passes, threads: uint8(threads), salt: salt, key: key}, nil
}

// parameter reads a number written as name=digits. The digits are decimal, in
// the range of 32 bits, with no sign.
func parameter(s, name string) (uint32, bool) {
	digits, ok := strings.CutPrefix(s, name+"=")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// segment reads unpadded standard base64, and only text that encoding the bytes
// gives back. The decoder alone also lets line breaks and unused bits through,
// which would make several strings stand for one hash.
func segment(s string) ([]byte, bool) {
	raw, err := b64.DecodeString(s)
	if err != nil || b64.EncodeToString(raw) != s {
		return nil, false
	}
	return raw, true
}
