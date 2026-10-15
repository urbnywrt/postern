package release_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	"aead.dev/minisign"
	"golang.org/x/crypto/blake2b"

	"github.com/urbnywrt/postern/internal/release"
)

// A public key whose point has a small order (1, 2, 4 or 8) is no key: a
// signature that verifies under it can be made by anybody, without any secret.
// The zero value of minisign.PublicKey is one, and so is the all-zero text that
// an unfilled place holder makes. The tests find those points from the equation
// of the curve, so that the list that the package keeps is held against the
// mathematics and not against another copy of itself, and then forge
// signatures under such keys, as an attacker would.

// ---------------------------------------------------------------------------
// The curve: -x^2 + y^2 = 1 + d x^2 y^2 over GF(2^255 - 19), in affine
// coordinates. Slow and plain, and enough for this.

var (
	curveP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// curveL is the order of the base point; the whole group has 8*curveL points.
	curveL, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	curveD    = new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), curveP)), curveP)
	// sqrtMinus1 is a square root of -1, which p = 5 (mod 8) makes 2^((p-1)/4).
	sqrtMinus1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(curveP, big.NewInt(1)), 2), curveP)
	bigOne     = big.NewInt(1)
)

func modMul(xs ...*big.Int) *big.Int {
	r := big.NewInt(1)
	for _, x := range xs {
		r.Mul(r, x).Mod(r, curveP)
	}
	return r
}

func modAdd(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), curveP) }
func modSub(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), curveP) }
func modInv(a *big.Int) *big.Int    { return new(big.Int).ModInverse(a, curveP) }

type point struct{ x, y *big.Int }

var identity = point{big.NewInt(0), big.NewInt(1)}

// add is the addition law of the curve, which is complete here (-1 is a square
// and d is not), so no denominator is ever zero.
func (a point) add(b point) point {
	t := modMul(curveD, a.x, b.x, a.y, b.y)
	return point{
		x: modMul(modAdd(modMul(a.x, b.y), modMul(b.x, a.y)), modInv(modAdd(bigOne, t))),
		y: modMul(modAdd(modMul(a.y, b.y), modMul(a.x, b.x)), modInv(modSub(bigOne, t))),
	}
}

func (a point) mul(k *big.Int) point {
	r := identity
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = r.add(r)
		if k.Bit(i) == 1 {
			r = r.add(a)
		}
	}
	return r
}

func (a point) equal(b point) bool { return a.x.Cmp(b.x) == 0 && a.y.Cmp(b.y) == 0 }

// pointWithY returns the point of the curve that has this y and an even x, if
// there is one.
func pointWithY(y *big.Int) (point, bool) {
	yy := modMul(y, y)
	x2 := modMul(modSub(yy, bigOne), modInv(modAdd(modMul(curveD, yy), bigOne)))
	x := new(big.Int).Exp(x2, new(big.Int).Rsh(new(big.Int).Add(curveP, big.NewInt(3)), 3), curveP)
	if modMul(x, x).Cmp(x2) != 0 {
		x = modMul(x, sqrtMinus1)
	}
	if modMul(x, x).Cmp(x2) != 0 {
		return point{}, false
	}
	if x.Bit(0) == 1 {
		x = modSub(big.NewInt(0), x)
	}
	return point{x, y}, true
}

// smallOrderPoints returns the 8 points whose order divides 8. Whatever point q
// is, [L]q is in the group of order 8, and when it is not of a smaller order it
// generates the group.
func smallOrderPoints(t testing.TB) []point {
	t.Helper()
	for y := int64(2); y < 200; y++ {
		q, ok := pointWithY(big.NewInt(y))
		if !ok {
			continue
		}
		g := q.mul(curveL)
		if g.mul(big.NewInt(4)).equal(identity) {
			continue
		}
		points := make([]point, 8)
		p := identity
		for i := range points {
			points[i] = p
			p = p.add(g)
		}
		if !p.equal(identity) {
			t.Fatal("the multiples of a point of order 8 do not come back to the identity")
		}
		return points
	}
	t.Fatal("no point of order 8 found")
	return nil
}

// leInt reads a little-endian integer, and le32 writes one as 32 bytes.
func leInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func le32(x *big.Int) []byte {
	b := x.FillBytes(make([]byte, 32))
	slices.Reverse(b)
	return b
}

// smallOrderEncodings returns every form that a public key of small order has:
// the y of each of the 8 points, and y+p where that is still below 2^255 (a
// form that is not canonical, and that a decoder takes), each with the sign bit
// of x clear and set.
func smallOrderEncodings(t testing.TB) [][]byte {
	t.Helper()
	points := smallOrderPoints(t)

	// What the derivation has to give, or the test is checking nothing: orders
	// 1, 2, 4, 4, 8, 8, 8, 8, and five different y.
	orders := map[int]int{}
	ys := map[string]bool{}
	for _, p := range points {
		for _, o := range []int64{1, 2, 4, 8} {
			if p.mul(big.NewInt(o)).equal(identity) {
				orders[int(o)]++
				break
			}
		}
		ys[p.y.String()] = true
	}
	if orders[1] != 1 || orders[2] != 1 || orders[4] != 2 || orders[8] != 4 || len(ys) != 5 {
		t.Fatalf("the points of small order: %d of order 1, %d of 2, %d of 4, %d of 8, with %d different y; want 1, 1, 2, 4 and 5", orders[1], orders[2], orders[4], orders[8], len(ys))
	}

	limit := new(big.Int).Lsh(big.NewInt(1), 255)
	seen := map[string]bool{}
	var out [][]byte
	for _, p := range points {
		for _, y := range []*big.Int{p.y, new(big.Int).Add(p.y, curveP)} {
			if y.Cmp(limit) >= 0 {
				continue
			}
			for signBit := range 2 {
				enc := le32(y)
				enc[31] |= byte(signBit) << 7
				if !seen[string(enc)] {
					seen[string(enc)] = true
					out = append(out, enc)
				}
			}
		}
	}
	if len(out) != 14 {
		t.Fatalf("%d encodings of the points of small order, want 14 (7 values of y, 2 signs)", len(out))
	}
	return out
}

// keyText returns the text of a public key as minisign.pub has it: the base64 of
// the algorithm, the key id and the 32 bytes of the Ed25519 key.
func keyText(id uint64, key []byte) string {
	raw := make([]byte, 2+8+32)
	binary.LittleEndian.PutUint16(raw, minisign.EdDSA)
	binary.LittleEndian.PutUint64(raw[2:], id)
	copy(raw[10:], key)
	return base64.StdEncoding.EncodeToString(raw)
}

func parseKey(t testing.TB, text string) minisign.PublicKey {
	t.Helper()
	var key minisign.PublicKey
	if err := key.UnmarshalText([]byte(text)); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	return key
}

// ---------------------------------------------------------------------------
// The key lists

func TestSmallOrderKeysAreRefused(t *testing.T) {
	good := newKeyPair(t)
	for i, enc := range smallOrderEncodings(t) {
		name := hex.EncodeToString(enc)
		// The id is anything, and 0 for the first, as the zero value of a key has.
		text := keyText(uint64(i)*0x0101010101010101, enc)
		forms := []struct{ form, list, position string }{
			{"alone", text, "key 1"},
			{"after a key", good.pub.String() + "\n" + text, "key 2"},
			{"in a pub file", "untrusted comment: minisign public key: 0000000000000000\n" + text + "\n", "key 1"},
		}

		t.Run(name, func(t *testing.T) {
			for _, set := range []release.KeySet{release.ReleaseKeys, release.StableKeys} {
				for _, f := range forms {
					if set == release.ReleaseKeys {
						useKeys(t, f.list, "", "")
					} else {
						useKeys(t, "", f.list, "")
					}
					keys, err := release.TrustedKeys(set)
					if err == nil || errors.Is(err, release.ErrNoKeys) {
						t.Fatalf("%s keys, %s: err = %v, want the refusal of a key of small order", set, f.form, err)
					}
					if len(keys) != 0 {
						t.Errorf("%s keys, %s: %d keys came with the error", set, f.form, len(keys))
					}
					msg := err.Error()
					if !strings.Contains(msg, "small order") || !strings.Contains(msg, set.String()) || !strings.Contains(msg, f.position) {
						t.Errorf("%s keys, %s: err = %q, want it to name %q in this set and say that the key has a small order", set, f.form, msg, f.position)
					}
					if strings.Contains(msg, text) || strings.Contains(msg, name) {
						t.Errorf("err = %q quotes the key", msg)
					}
				}
			}

			// As an extra key of a build, which only a set without production keys takes.
			useKeys(t, "", "", text)
			if _, err := release.TrustedKeys(release.ReleaseKeys); err == nil || errors.Is(err, release.ErrNoKeys) || !strings.Contains(err.Error(), "small order") {
				t.Errorf("an extra key: err = %v, want the refusal of a key of small order", err)
			}

			// ProductionKeys lists what TrustedKeys would take: not this one.
			useKeys(t, good.pub.String()+"\n"+text, "", "")
			if got := release.ProductionKeys(release.ReleaseKeys); len(got) != 1 || !got[0].Equal(good.pub) {
				t.Errorf("ProductionKeys = %d keys, want just the good one", len(got))
			}
		})
	}
}

// TestSmallOrderGuardIsNarrow: the keys next to the points of small order, and
// every key that is made, are taken.
func TestSmallOrderGuardIsNarrow(t *testing.T) {
	for _, enc := range smallOrderEncodings(t) {
		// A bit in the middle of y: another number, and no point of small order.
		near := bytes.Clone(enc)
		near[15] ^= 0x10
		useKeys(t, keyText(7, near), "", "")
		keys, err := release.TrustedKeys(release.ReleaseKeys)
		if err != nil || len(keys) != 1 {
			t.Errorf("%x: %d keys, err = %v, want the key next to a point of small order to be taken", near, len(keys), err)
		}
	}
	for range 50 {
		kp := newKeyPair(t)
		useKeys(t, kp.pub.String(), "", "")
		if keys, err := release.TrustedKeys(release.ReleaseKeys); err != nil || len(keys) != 1 {
			t.Fatalf("a key that was made: %d keys, err = %v", len(keys), err)
		}
	}
	// The key of the real minisign program.
	pub := mustRead(t, "testdata/cli.pub")
	useKeys(t, string(pub), "", "")
	if keys, err := release.TrustedKeys(release.ReleaseKeys); err != nil || len(keys) != 1 {
		t.Errorf("the key of testdata/cli.pub: %d keys, err = %v", len(keys), err)
	}
}

// ---------------------------------------------------------------------------
// Forgery

// forgeEd25519 returns an Ed25519 signature of msg that verifies under pub, a
// key of small order, which takes no secret key: for R = [a]B and S = a, [S]B is
// R, and the check [S]B = R + [k]A holds whenever [k]A is the identity, which it
// is for every k that the order of A divides (all of them for the identity
// itself, one in four for an A of order 4). The challenge k depends on R, so a
// new a is tried until it does.
func forgeEd25519(pub ed25519.PublicKey, msg []byte) ([]byte, bool) {
	for range 400 {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, false
		}
		h := sha512.Sum512(seed)
		h[0] &= 248
		h[31] &= 127
		h[31] |= 64
		a := new(big.Int).Mod(leInt(h[:32]), curveL)
		r := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey) // [a]B
		sig := append(bytes.Clone(r), le32(a)...)
		if ed25519.Verify(pub, msg, sig) {
			return sig, true
		}
	}
	return nil, false
}

// forgeMinisign makes a prehashed minisign signature of data, with the trusted
// comment of s and the key id that is given, that verifies under the key of
// small order pub: the signature of the digest, and the signature of the
// signature and the comment.
func forgeMinisign(pub ed25519.PublicKey, id uint64, data []byte, s release.Signed) ([]byte, bool) {
	digest := blake2b.Sum512(data)
	main, ok := forgeEd25519(pub, digest[:])
	if !ok {
		return nil, false
	}
	comment := s.TrustedComment()
	global, ok := forgeEd25519(pub, append(bytes.Clone(main), comment...))
	if !ok {
		return nil, false
	}
	raw := make([]byte, 2+8+64)
	binary.LittleEndian.PutUint16(raw, minisign.HashEdDSA)
	binary.LittleEndian.PutUint64(raw[2:], id)
	copy(raw[10:], main)
	text := "untrusted comment: forged\n" + base64.StdEncoding.EncodeToString(raw) + "\ntrusted comment: " + comment + "\n" + base64.StdEncoding.EncodeToString(global) + "\n"
	return []byte(text), true
}

// withKeyID returns sig with another key id, and nothing else changed.
func withKeyID(t testing.TB, sig []byte, id uint64) []byte {
	t.Helper()
	var s minisign.Signature
	if err := s.UnmarshalText(sig); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	s.KeyID = id
	text, err := s.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	return text
}

// TestVerifyWithRefusesSmallOrderKeys: a key of small order in the list of
// trusted keys, as VerifyWith takes them from its callers, does not make a
// signature that anybody can forge into one that verifies.
func TestVerifyWithRefusesSmallOrderKeys(t *testing.T) {
	data := []byte("an attacker's binary")
	good := newKeyPair(t)
	goodSig := sign(t, data, good, nodeAMD64)

	attack := func(t *testing.T, key minisign.PublicKey, pub ed25519.PublicKey, mustForge bool) {
		t.Helper()
		forged, ok := forgeMinisign(pub, key.ID(), data, nodeAMD64)
		if !ok {
			if mustForge {
				t.Fatal("cannot forge a signature under this key: the premise of the test is gone")
			}
			// crypto/ed25519 does not take this form of the key at all, so there
			// is nothing to forge; the key is still refused whatever the signature.
			t.Log("not forgeable here: only the refusal of the key is checked")
			forged = withKeyID(t, goodSig, key.ID())
		} else if !minisign.Verify(key, data, forged) {
			// The premise: the library takes the forgery, and the guard of this
			// package is all that stands in its way. If the library ever refuses
			// such keys itself, this says so, and the guard is a second one.
			t.Log("minisign.Verify refuses the forged signature itself")
		}

		err := release.VerifyWith(bytes.NewReader(data), forged, nodeAMD64, []minisign.PublicKey{key})
		if err == nil {
			t.Fatal("a signature forged under a key of small order was accepted")
		}
		if !errors.Is(err, release.ErrUntrustedKey) {
			t.Errorf("err = %v, want ErrUntrustedKey: a key of small order is no trusted key", err)
		}
		// And the message says why, for the log of whoever put the key in the list.
		if !strings.Contains(err.Error(), "small order") || !strings.Contains(err.Error(), fmt.Sprintf("%016X", key.ID())) {
			t.Errorf("err = %q, want it to name the key id and to say that the key has a small order", err)
		}

		// Beside a real key it still gets nowhere, and the real key is not harmed.
		keys := []minisign.PublicKey{key, good.pub}
		if err := release.VerifyWith(bytes.NewReader(data), forged, nodeAMD64, keys); err == nil {
			t.Error("a forged signature was accepted beside a real key")
		}
		if err := release.VerifyWith(bytes.NewReader(data), goodSig, nodeAMD64, keys); err != nil {
			t.Errorf("a good signature after a key of small order: %v", err)
		}
		keys = []minisign.PublicKey{good.pub, key}
		if err := release.VerifyWith(bytes.NewReader(data), goodSig, nodeAMD64, keys); err != nil {
			t.Errorf("a good signature before a key of small order: %v", err)
		}

		// Through the compiled-in keys: the list is refused before any signature is looked at.
		useKeys(t, keyText(key.ID(), pubBytes(t, key)), "", "")
		if err := release.Verify(bytes.NewReader(data), forged, nodeAMD64); err == nil {
			t.Error("Verify accepted a forged signature under a compiled-in key of small order")
		}
	}

	t.Run("the zero value of a key", func(t *testing.T) {
		// Key id 0 and 32 zero bytes: a point of order 4.
		attack(t, minisign.PublicKey{}, make(ed25519.PublicKey, 32), true)
	})
	t.Run("the identity", func(t *testing.T) {
		enc := make([]byte, 32)
		enc[0] = 1
		attack(t, parseKey(t, keyText(0x1122334455667788, enc)), enc, true)
	})
	for i, enc := range smallOrderEncodings(t) {
		t.Run(hex.EncodeToString(enc), func(t *testing.T) {
			attack(t, parseKey(t, keyText(uint64(i)+1, enc)), enc, false)
		})
	}
}

// pubBytes returns the 32 bytes of the Ed25519 key of key.
func pubBytes(t testing.TB, key minisign.PublicKey) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(key.String())
	if err != nil || len(raw) != 42 {
		t.Fatalf("a public key is not 42 bytes of base64: %d, %v", len(raw), err)
	}
	return raw[10:]
}
