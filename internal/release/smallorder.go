package release

import (
	"encoding/base64"
	"encoding/hex"
	"slices"

	"aead.dev/minisign"
)

// A public key whose point has a small order (1, 2, 4 or 8: the points of the
// subgroup of order 8 of the curve of Ed25519) is no key. Whoever knows only
// the key can make a signature that verifies under it, for any data, in a few
// tries, and crypto/ed25519 and minisign's library take such a signature. The
// zero value of minisign.PublicKey is one such key, and so is the place holder
// that an unfilled list of keys makes of zeros. libsodium, which minisign
// itself is built on, refuses these keys, and so does this package: when it
// reads the keys that are compiled in, and when it looks for the key of a
// signature among the keys that it is given.

// smallOrderY is the list of the encodings of those points, as libsodium
// keeps it, with the sign bit of x (the top bit of the last byte) left out,
// since both signs are in it: y = 0 (order 4), y = 1 (the identity, order 1),
// y = p-1 (order 2), the two values of y of the points of order 8, and the two
// encodings that are not canonical, p and p+1, of y = 0 and y = 1, which a
// decoder takes as well. There are 8 points and 7 encodings, as the x of the
// identity and of y = p-1 is zero. The tests derive the points from the
// equation of the curve and hold this list against them.
var smallOrderY = [...][32]byte{
	fromHex("0000000000000000000000000000000000000000000000000000000000000000"), // y = 0, order 4
	fromHex("0100000000000000000000000000000000000000000000000000000000000000"), // y = 1, the identity
	fromHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), // order 8
	fromHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), // order 8
	fromHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p-1, order 2
	fromHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p, as 0
	fromHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p+1, as 1
}

// fromHex reads 32 bytes of hex. The constants above are the only use, and the
// tests run it: a typo is a panic that every test of the package finds.
func fromHex(s string) [32]byte {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		panic("release: a constant of the table of small-order keys is not 32 bytes of hex")
	}
	return [32]byte(raw)
}

// smallOrder reports whether key is a key of small order (see above), the zero
// value among them.
func smallOrder(key minisign.PublicKey) bool {
	// String is the base64 of the algorithm (2 bytes), the key id (8) and the 32
	// bytes of the Ed25519 key.
	raw, err := base64.StdEncoding.DecodeString(key.String())
	if err != nil || len(raw) != 2+8+32 {
		return true // cannot happen; and a key that cannot be read is no key
	}
	y := [32]byte(raw[10:])
	y[31] &= 0x7f // the sign of x does not matter
	return slices.Contains(smallOrderY[:], y)
}
