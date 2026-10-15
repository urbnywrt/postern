package release_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/release"
)

// nodeAMD64 is the artifact that most of the tests sign.
var nodeAMD64 = release.Signed{Component: "postern-node", Version: "v0.5.0", OS: "linux", Arch: "amd64"}

type keyPair struct {
	pub  minisign.PublicKey
	priv minisign.PrivateKey
}

// newKeyPair makes a key pair when the test runs. No key of any kind is
// committed: the keys of these tests live as long as the test does.
func newKeyPair(t testing.TB) keyPair {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return keyPair{pub, priv}
}

func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

func mustRead(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return b
}

// sign signs data with kp for s, as the release workflow does.
func sign(t testing.TB, data []byte, kp keyPair, s release.Signed) []byte {
	t.Helper()
	sig, err := release.Sign(bytes.NewReader(data), kp.priv, s)
	if err != nil {
		t.Fatalf("Sign(%+v): %v", s, err)
	}
	return sig
}

func pubs(kps ...keyPair) []minisign.PublicKey {
	keys := make([]minisign.PublicKey, len(kps))
	for i, kp := range kps {
		keys[i] = kp.pub
	}
	return keys
}

// keyList is a list of public keys in the text form of the key variables of the
// package, the keys apart by sep.
func keyList(sep string, kps ...keyPair) string {
	texts := make([]string, len(kps))
	for i, kp := range kps {
		texts[i] = kp.pub.String()
	}
	return strings.Join(texts, sep)
}

// useKeys sets the three key variables for the rest of the test.
func useKeys(t *testing.T, releaseKeys, stableKeys, extra string) {
	t.Helper()
	t.Cleanup(release.SetProductionKeys(releaseKeys, stableKeys))
	t.Cleanup(release.SetExtraPublicKeys(extra))
}

// withID returns a key that has the bytes of k and the id that is given: a key
// that collides with another one.
func withID(t testing.TB, k minisign.PublicKey, id uint64) minisign.PublicKey {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(k.String())
	if err != nil || len(raw) != 2+8+32 {
		t.Fatalf("a public key is not 42 bytes of base64: %d, %v", len(raw), err)
	}
	binary.LittleEndian.PutUint64(raw[2:10], id)
	var out minisign.PublicKey
	if err := out.UnmarshalText([]byte(base64.StdEncoding.EncodeToString(raw))); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	return out
}

// setChar returns text with the character at position pos of line number line
// replaced by another one that is valid in base64.
func setChar(t testing.TB, text []byte, line, pos int) []byte {
	t.Helper()
	lines := strings.Split(string(text), "\n")
	c := lines[line][pos]
	repl := byte('A')
	if c == 'A' {
		repl = 'B'
	}
	lines[line] = lines[line][:pos] + string(repl) + lines[line][pos+1:]
	return []byte(strings.Join(lines, "\n"))
}

// countingReader counts the bytes that were read from it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// zeroReader is an endless stream of zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// ---------------------------------------------------------------------------
// Signed

func TestTrustedComment(t *testing.T) {
	tests := []struct {
		name string
		s    release.Signed
		want string
	}{
		{"binary", nodeAMD64, "postern postern-node v0.5.0 linux/amd64"},
		{"arm64", release.Signed{Component: "postern-panel", Version: "v1.2.3", OS: "linux", Arch: "arm64"}, "postern postern-panel v1.2.3 linux/arm64"},
		{"no platform", release.Signed{Component: "sha256sums", Version: "v0.5.0"}, "postern sha256sums v0.5.0"},
		{"stable list", release.Signed{Component: "engines-stable", Version: "1780000000"}, "postern engines-stable 1780000000"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.TrustedComment(); got != tc.want {
				t.Errorf("TrustedComment() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSignRejectsBadFields(t *testing.T) {
	// A field with a space or a line break would make the trusted comment
	// ambiguous or break the file, so nothing is signed for it.
	bad := []release.Signed{
		{},
		{Component: "postern-node"},
		{Version: "v0.5.0"},
		{Component: "postern node", Version: "v0.5.0"},
		{Component: "postern-node\n", Version: "v0.5.0"},
		{Component: "postern-node", Version: "v0.5.0 x"},
		{Component: "postern-node", Version: "v0.5.0\nx"},
		{Component: "postern-node", Version: "../x"},
		{Component: "postern-node", Version: "v0.5.0", OS: "linux"},
		{Component: "postern-node", Version: "v0.5.0", Arch: "amd64"},
		{Component: "postern-node", Version: "v0.5.0", OS: "li/nux", Arch: "amd64"},
		{Component: "postern-node", Version: "v0.5.0", OS: "linux", Arch: "amd 64"},
		{Component: "postern-node", Version: "v0.5.0", OS: "linux", Arch: "amd64/x"},
		{Component: "postern-nöde", Version: "v0.5.0"},
	}
	kp := newKeyPair(t)
	for _, s := range bad {
		sig, err := release.Sign(strings.NewReader("data"), kp.priv, s)
		if err == nil {
			t.Errorf("Sign(%+v) succeeded, want an error", s)
		}
		if sig != nil {
			t.Errorf("Sign(%+v) returned a signature along with its error", s)
		}
	}
}

func TestSignReadError(t *testing.T) {
	boom := errors.New("boom")
	kp := newKeyPair(t)
	sig, err := release.Sign(io.MultiReader(strings.NewReader("data"), iotest.ErrReader(boom)), kp.priv, nodeAMD64)
	if !errors.Is(err, boom) {
		t.Errorf("Sign: err = %v, want one that wraps the error of the reader", err)
	}
	if sig != nil {
		t.Error("Sign returned a signature along with its error")
	}
}

// ---------------------------------------------------------------------------
// Verify

func TestVerifyRoundTrip(t *testing.T) {
	kp := newKeyPair(t)
	data := randomBytes(t, 1<<20)
	sig := sign(t, data, kp, nodeAMD64)

	// The shape of the file: the untrusted comment of the release workflow, the
	// prehashed algorithm, the trusted comment that names the artifact.
	var parsed minisign.Signature
	if err := parsed.UnmarshalText(sig); err != nil {
		t.Fatalf("the signature does not parse: %v", err)
	}
	if parsed.Algorithm != minisign.HashEdDSA {
		t.Errorf("algorithm = %#x, want the prehashed %#x", parsed.Algorithm, minisign.HashEdDSA)
	}
	if want := "postern release signature"; parsed.UntrustedComment != want {
		t.Errorf("untrusted comment = %q, want %q", parsed.UntrustedComment, want)
	}
	if want := "postern postern-node v0.5.0 linux/amd64"; parsed.TrustedComment != want {
		t.Errorf("trusted comment = %q, want %q", parsed.TrustedComment, want)
	}
	if parsed.KeyID != kp.pub.ID() {
		t.Errorf("key id = %016X, want %016X", parsed.KeyID, kp.pub.ID())
	}
	// minisign's own Verify, which hashes the message itself for a prehashed
	// signature, agrees.
	if !minisign.Verify(kp.pub, data, sig) {
		t.Error("minisign.Verify refuses the signature")
	}
	// Ed25519 is deterministic and nothing in the file is a clock or a nonce,
	// so a release can be signed again to the byte.
	if again := sign(t, data, kp, nodeAMD64); !bytes.Equal(again, sig) {
		t.Error("signing the same data twice gave two different signatures")
	}

	t.Run("VerifyWith", func(t *testing.T) {
		if err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, pubs(kp)); err != nil {
			t.Fatalf("VerifyWith: %v", err)
		}
	})
	t.Run("Verify", func(t *testing.T) {
		useKeys(t, keyList("\n", kp), "", "")
		if err := release.Verify(bytes.NewReader(data), sig, nodeAMD64); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
}

func TestVerifyPicksKeyByID(t *testing.T) {
	a, b, c := newKeyPair(t), newKeyPair(t), newKeyPair(t)
	data := randomBytes(t, 64<<10)

	for _, order := range [][]keyPair{{a, b}, {b, a}, {a, b, c}, {c, b}, {b}} {
		for _, signer := range []keyPair{a, b, c} {
			sig := sign(t, data, signer, nodeAMD64)
			err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, pubs(order...))
			if slices.ContainsFunc(order, func(k keyPair) bool { return k.pub.Equal(signer.pub) }) {
				if err != nil {
					t.Errorf("signed by %016X, one of %d keys: %v", signer.pub.ID(), len(order), err)
				}
			} else if !errors.Is(err, release.ErrUntrustedKey) {
				t.Errorf("signed by %016X, none of %d keys: err = %v, want ErrUntrustedKey", signer.pub.ID(), len(order), err)
			}
		}
	}
}

func TestVerifyKeyIDCollision(t *testing.T) {
	// A key id is 64 bits that the signature only hints with. A key of the set
	// that has the id but not the key bytes must not hide the one that has both.
	a, b := newKeyPair(t), newKeyPair(t)
	forged := withID(t, a.pub, b.pub.ID())
	data := randomBytes(t, 4096)
	sig := sign(t, data, b, nodeAMD64)

	if err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, []minisign.PublicKey{forged, b.pub}); err != nil {
		t.Errorf("a colliding key in front of the right one: %v", err)
	}
	// With the colliding key alone the key id is known but the signature is not good.
	err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, []minisign.PublicKey{forged})
	if !errors.Is(err, release.ErrBadSignature) {
		t.Errorf("a colliding key alone: err = %v, want ErrBadSignature", err)
	}
}

func TestVerifyUntrustedKey(t *testing.T) {
	a, b, stranger := newKeyPair(t), newKeyPair(t), newKeyPair(t)
	data := randomBytes(t, 4096)
	sig := sign(t, data, stranger, nodeAMD64)

	err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, pubs(a, b))
	if !errors.Is(err, release.ErrUntrustedKey) {
		t.Fatalf("err = %v, want ErrUntrustedKey", err)
	}
	if errors.Is(err, release.ErrBadSignature) || errors.Is(err, release.ErrWrongArtifact) {
		t.Errorf("err = %v: an untrusted key must not be mistaken for a bad signature", err)
	}
	// The error says whose signature it is, so that a rotation that was
	// forgotten shows in a log. The id is what the signature file carries, in
	// the form that minisign prints it, and it is no key material.
	if want := fmt.Sprintf("%016X", stranger.pub.ID()); !strings.Contains(err.Error(), want) {
		t.Errorf("err = %q, want it to name key id %s", err, want)
	}

	t.Run("no keys at all", func(t *testing.T) {
		err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, nil)
		if !errors.Is(err, release.ErrUntrustedKey) {
			t.Errorf("err = %v, want ErrUntrustedKey", err)
		}
		if !errors.Is(err, release.ErrNoKeys) {
			t.Errorf("err = %v, want it to say that there are no keys", err)
		}
	})
}

// TestVerifyRejectsBeforeReading: a signature that cannot be right is refused
// before the data, which can be hundreds of megabytes, is read and hashed.
func TestVerifyRejectsBeforeReading(t *testing.T) {
	a, stranger := newKeyPair(t), newKeyPair(t)
	data := randomBytes(t, 4096)

	tests := []struct {
		name string
		sig  []byte
		want error
	}{
		{"untrusted key", sign(t, data, stranger, nodeAMD64), release.ErrUntrustedKey},
		{"malformed signature", []byte("untrusted comment: x\nnot a signature"), release.ErrBadSignature},
		{"no signature", nil, release.ErrBadSignature},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &countingReader{r: bytes.NewReader(data)}
			err := release.VerifyWith(r, tc.sig, nodeAMD64, pubs(a))
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if r.n != 0 {
				t.Errorf("%d bytes of the data were read before the refusal", r.n)
			}
		})
	}
}

func TestVerifyWrongArtifact(t *testing.T) {
	kp := newKeyPair(t)
	data := randomBytes(t, 4096)
	sig := sign(t, data, kp, nodeAMD64)

	tests := []struct {
		name string
		want release.Signed
	}{
		{"another architecture", release.Signed{Component: "postern-node", Version: "v0.5.0", OS: "linux", Arch: "arm64"}},
		{"another version", release.Signed{Component: "postern-node", Version: "v0.5.1", OS: "linux", Arch: "amd64"}},
		{"a prefix of the version", release.Signed{Component: "postern-node", Version: "v0.5", OS: "linux", Arch: "amd64"}},
		{"a version with a suffix", release.Signed{Component: "postern-node", Version: "v0.5.0-rc.1", OS: "linux", Arch: "amd64"}},
		{"another os", release.Signed{Component: "postern-node", Version: "v0.5.0", OS: "darwin", Arch: "amd64"}},
		{"another component", release.Signed{Component: "postern-panel", Version: "v0.5.0", OS: "linux", Arch: "amd64"}},
		{"no platform", release.Signed{Component: "postern-node", Version: "v0.5.0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := release.VerifyWith(bytes.NewReader(data), sig, tc.want, pubs(kp))
			if !errors.Is(err, release.ErrWrongArtifact) {
				t.Fatalf("err = %v, want ErrWrongArtifact", err)
			}
			// What the signature is for is signed, so it can be told in the message.
			if !strings.Contains(err.Error(), nodeAMD64.TrustedComment()) {
				t.Errorf("err = %q, want it to say what the signature is for (%q)", err, nodeAMD64.TrustedComment())
			}
		})
	}

	// And an artifact that has no platform is signed as such.
	sums := release.Signed{Component: "sha256sums", Version: "v0.5.0"}
	sumsSig := sign(t, data, kp, sums)
	if err := release.VerifyWith(bytes.NewReader(data), sumsSig, sums, pubs(kp)); err != nil {
		t.Errorf("a signature without a platform: %v", err)
	}
	if err := release.VerifyWith(bytes.NewReader(data), sumsSig, nodeAMD64, pubs(kp)); !errors.Is(err, release.ErrWrongArtifact) {
		t.Errorf("the checksums presented as a binary: err = %v, want ErrWrongArtifact", err)
	}
	if err := release.VerifyWith(bytes.NewReader(data), sig, sums, pubs(kp)); !errors.Is(err, release.ErrWrongArtifact) {
		t.Errorf("a binary presented as the checksums: err = %v, want ErrWrongArtifact", err)
	}
}

// TestVerifyWithValidatesWant: what a signature is for is one line of words, so
// a field with a space in it can be made to read as two fields. A want that Sign
// would not sign for is refused as it is, with an error that is none of the four
// about a signature, and no such want matches a signature that is real.
func TestVerifyWithValidatesWant(t *testing.T) {
	kp := newKeyPair(t)
	useKeys(t, keyList("\n", kp), "", "")
	data := randomBytes(t, 4096)
	sig := sign(t, data, kp, nodeAMD64) // "postern postern-node v0.5.0 linux/amd64"
	if err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, pubs(kp)); err != nil {
		t.Fatalf("the control does not verify: %v", err)
	}

	bad := []struct {
		name string
		want release.Signed
		in   string // what the message names
	}{
		// The same comment as the signature's, from fields that are not words.
		{"a version that holds the platform", release.Signed{Component: "postern-node", Version: "v0.5.0 linux/amd64"}, "version"},
		{"a component that holds the version", release.Signed{Component: "postern-node v0.5.0", Version: "linux/amd64"}, "component"},
		// Others that Sign refuses.
		{"nothing", release.Signed{}, "component"},
		{"no version", release.Signed{Component: "postern-node"}, "version"},
		{"no component", release.Signed{Version: "v0.5.0"}, "component"},
		{"a line break in the version", release.Signed{Component: "postern-node", Version: "v0.5.0\nlinux/amd64"}, "version"},
		{"a path for a version", release.Signed{Component: "postern-node", Version: "../v0.5.0"}, "version"},
		{"an os without an architecture", release.Signed{Component: "postern-node", Version: "v0.5.0", OS: "linux"}, "architecture"},
		{"an architecture without an os", release.Signed{Component: "postern-node", Version: "v0.5.0", Arch: "amd64"}, "architecture"},
		{"a slash in the platform", release.Signed{Component: "postern-node", Version: "v0.5.0", OS: "linux/amd64", Arch: "x"}, "platform"},
		{"a space in the architecture", release.Signed{Component: "postern-node", Version: "v0.5.0", OS: "linux", Arch: "amd 64"}, "platform"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			r := &countingReader{r: bytes.NewReader(data)}
			err := release.VerifyWith(r, sig, tc.want, pubs(kp))
			if err == nil {
				t.Fatalf("VerifyWith accepted %+v (the comment %q)", tc.want, tc.want.TrustedComment())
			}
			for _, sentinel := range []error{release.ErrBadSignature, release.ErrWrongArtifact, release.ErrUntrustedKey, release.ErrNoKeys} {
				if errors.Is(err, sentinel) {
					t.Errorf("err = %v: a want that cannot be signed for is not %v", err, sentinel)
				}
			}
			if !strings.Contains(err.Error(), tc.in) {
				t.Errorf("err = %q, want it to name the %s", err, tc.in)
			}
			if r.n != 0 {
				t.Errorf("%d bytes of the data were read before the refusal", r.n)
			}
			// Nor through Verify, with the keys that are compiled in.
			if err := release.Verify(bytes.NewReader(data), sig, tc.want); err == nil {
				t.Errorf("Verify accepted %+v", tc.want)
			}
			// The want is looked at first: beside a signature that is garbage, or by
			// a key that is not trusted, it is still the want that is refused.
			for _, other := range [][]byte{nil, []byte("garbage"), sign(t, data, newKeyPair(t), nodeAMD64)} {
				err := release.VerifyWith(bytes.NewReader(data), other, tc.want, pubs(kp))
				if err == nil || errors.Is(err, release.ErrBadSignature) || errors.Is(err, release.ErrUntrustedKey) {
					t.Errorf("with another signature: err = %v, want the refusal of the want", err)
				}
			}
		})
	}
}

func TestVerifyTampered(t *testing.T) {
	kp := newKeyPair(t)
	data := randomBytes(t, 1<<20)
	sig := sign(t, data, kp, nodeAMD64)
	// The signature is four lines: the untrusted comment, the signature, the
	// trusted comment and the signature of the trusted comment.
	if n := strings.Count(string(sig), "\n"); n != 4 {
		t.Fatalf("a signature has %d lines, the test expects 4", n)
	}

	check := func(t *testing.T, data, sig []byte, want error) {
		t.Helper()
		err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, pubs(kp))
		if want == nil {
			if err != nil {
				t.Errorf("err = %v, want nil", err)
			}
			return
		}
		if !errors.Is(err, want) {
			t.Errorf("err = %v, want %v", err, want)
		}
	}

	t.Run("a data byte", func(t *testing.T) {
		bad := bytes.Clone(data)
		bad[len(bad)/2] ^= 0x01
		check(t, bad, sig, release.ErrBadSignature)
	})
	t.Run("the first and the last data byte", func(t *testing.T) {
		first, last := bytes.Clone(data), bytes.Clone(data)
		first[0] ^= 0x80
		last[len(last)-1] ^= 0x80
		check(t, first, sig, release.ErrBadSignature)
		check(t, last, sig, release.ErrBadSignature)
	})
	t.Run("data appended", func(t *testing.T) {
		check(t, append(bytes.Clone(data), 0), sig, release.ErrBadSignature)
	})
	t.Run("data truncated", func(t *testing.T) {
		check(t, data[:len(data)-1], sig, release.ErrBadSignature)
		check(t, nil, sig, release.ErrBadSignature)
	})
	t.Run("a byte of the trusted comment", func(t *testing.T) {
		// The comment now names v0.5.1 and the caller wants v0.5.0: it is the
		// signature that is bad, since a comment that was changed is not one
		// that anybody signed.
		bad := []byte(strings.Replace(string(sig), "v0.5.0", "v0.5.1", 1))
		if bytes.Equal(bad, sig) {
			t.Fatal("the comment was not changed")
		}
		check(t, data, bad, release.ErrBadSignature)
	})
	t.Run("the trusted comment of another artifact", func(t *testing.T) {
		// The comment of a good signature for arm64 put on the signature of amd64.
		arm := release.Signed{Component: "postern-node", Version: "v0.5.0", OS: "linux", Arch: "arm64"}
		armSig := sign(t, data, kp, arm)
		bad := strings.Split(string(sig), "\n")
		bad[2] = strings.Split(string(armSig), "\n")[2]
		err := release.VerifyWith(bytes.NewReader(data), []byte(strings.Join(bad, "\n")), arm, pubs(kp))
		if !errors.Is(err, release.ErrBadSignature) {
			t.Errorf("err = %v, want ErrBadSignature (the signature of the comment does not carry over)", err)
		}
	})
	t.Run("a byte of the signature", func(t *testing.T) {
		check(t, data, setChar(t, sig, 1, 40), release.ErrBadSignature)
	})
	t.Run("a byte of the signature of the trusted comment", func(t *testing.T) {
		check(t, data, setChar(t, sig, 3, 10), release.ErrBadSignature)
	})
	t.Run("the algorithm downgraded to the legacy one", func(t *testing.T) {
		// "ED" (prehashed) is "RU" at the start of the base64 line, "Ed" is "RW".
		lines := strings.Split(string(sig), "\n")
		if !strings.HasPrefix(lines[1], "RU") {
			t.Fatalf("the signature line starts %q, want a prehashed signature (RU)", lines[1][:4])
		}
		lines[1] = "RW" + lines[1][2:]
		check(t, data, []byte(strings.Join(lines, "\n")), release.ErrBadSignature)
	})
	t.Run("a changed key id is an untrusted key", func(t *testing.T) {
		// The id is in the first ten bytes of the base64 line, after the algorithm.
		check(t, data, setChar(t, sig, 1, 8), release.ErrUntrustedKey)
	})
	t.Run("a truncated file", func(t *testing.T) {
		for _, n := range []int{0, 1, 20, len(sig) / 2, len(sig) - 5} {
			check(t, data, sig[:n], release.ErrBadSignature)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		check(t, data, nil, release.ErrBadSignature)
		check(t, data, []byte("RWQ"), release.ErrBadSignature)
		check(t, data, bytes.Repeat([]byte("untrusted comment: x\n"), 8), release.ErrBadSignature)
		check(t, data, randomBytes(t, 300), release.ErrBadSignature)
	})
	t.Run("the untrusted comment is not covered", func(t *testing.T) {
		// It is shown to people and nothing more: it can be anything.
		other := []byte(strings.Replace(string(sig), "postern release signature", "signed by somebody else", 1))
		if bytes.Equal(other, sig) {
			t.Fatal("the comment was not changed")
		}
		check(t, data, other, nil)
	})
	t.Run("a line break style that Windows makes", func(t *testing.T) {
		crlf := []byte(strings.ReplaceAll(string(sig), "\n", "\r\n"))
		check(t, data, crlf, nil)
	})
}

func TestVerifyWrongSet(t *testing.T) {
	// The release keys sign the binaries and the checksums, the stable keys the
	// list of engines. A signature of one set has no force in the other.
	releaseKey, stableKey := newKeyPair(t), newKeyPair(t)
	useKeys(t, keyList("\n", releaseKey), keyList("\n", stableKey), "")
	data := randomBytes(t, 4096)

	list := release.Signed{Component: "engines-stable", Version: "1780000000"}
	if err := release.Verify(bytes.NewReader(data), sign(t, data, stableKey, list), list); err != nil {
		t.Errorf("an engines list signed by a stable key: %v", err)
	}
	if err := release.Verify(bytes.NewReader(data), sign(t, data, releaseKey, list), list); !errors.Is(err, release.ErrUntrustedKey) {
		t.Errorf("an engines list signed by a release key: err = %v, want ErrUntrustedKey", err)
	}
	for _, component := range []string{"postern-node", "postern-panel", "sha256sums"} {
		s := release.Signed{Component: component, Version: "v0.5.0"}
		if err := release.Verify(bytes.NewReader(data), sign(t, data, releaseKey, s), s); err != nil {
			t.Errorf("%s signed by a release key: %v", component, err)
		}
		if err := release.Verify(bytes.NewReader(data), sign(t, data, stableKey, s), s); !errors.Is(err, release.ErrUntrustedKey) {
			t.Errorf("%s signed by a stable key: err = %v, want ErrUntrustedKey", component, err)
		}
	}
}

func TestVerifyWithoutKeys(t *testing.T) {
	// A build that has neither production nor extra keys verifies nothing.
	useKeys(t, "", "", "")
	kp := newKeyPair(t)
	data := randomBytes(t, 1024)
	sig := sign(t, data, kp, nodeAMD64)

	err := release.Verify(bytes.NewReader(data), sig, nodeAMD64)
	if !errors.Is(err, release.ErrNoKeys) {
		t.Errorf("err = %v, want ErrNoKeys", err)
	}
}

func TestVerifyUnknownComponent(t *testing.T) {
	kp := newKeyPair(t)
	useKeys(t, keyList("\n", kp), keyList("\n", kp), "")
	s := release.Signed{Component: "postern-web", Version: "v0.5.0"}
	data := randomBytes(t, 1024)
	sig := sign(t, data, kp, s) // the format is checked at signing, the set only at verifying

	err := release.Verify(bytes.NewReader(data), sig, s)
	if err == nil {
		t.Fatal("Verify of a component that has no key set succeeded")
	}
	if !strings.Contains(err.Error(), "postern-web") {
		t.Errorf("err = %q, want it to name the component", err)
	}
}

func TestVerifyLegacy(t *testing.T) {
	kp := newKeyPair(t)
	data := randomBytes(t, 1<<20)
	// A legacy signature is over the data itself; minisign.SignWithComments
	// makes one, as the CLI does with -l.
	sig := minisign.SignWithComments(kp.priv, data, nodeAMD64.TrustedComment(), "legacy")
	var parsed minisign.Signature
	if err := parsed.UnmarshalText(sig); err != nil || parsed.Algorithm != minisign.EdDSA {
		t.Fatalf("the test signature is not a legacy one: %v, algorithm %#x", err, parsed.Algorithm)
	}

	t.Run("accepted", func(t *testing.T) {
		if err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, pubs(kp)); err != nil {
			t.Fatalf("VerifyWith: %v", err)
		}
	})
	t.Run("through Verify", func(t *testing.T) {
		useKeys(t, keyList("\n", kp), "", "")
		if err := release.Verify(bytes.NewReader(data), sig, nodeAMD64); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
	t.Run("wrong artifact", func(t *testing.T) {
		other := nodeAMD64
		other.Arch = "arm64"
		if err := release.VerifyWith(bytes.NewReader(data), sig, other, pubs(kp)); !errors.Is(err, release.ErrWrongArtifact) {
			t.Errorf("err = %v, want ErrWrongArtifact", err)
		}
	})
	t.Run("tampered", func(t *testing.T) {
		bad := bytes.Clone(data)
		bad[12345] ^= 1
		if err := release.VerifyWith(bytes.NewReader(bad), sig, nodeAMD64, pubs(kp)); !errors.Is(err, release.ErrBadSignature) {
			t.Errorf("err = %v, want ErrBadSignature", err)
		}
		badComment := []byte(strings.Replace(string(sig), "v0.5.0", "v0.5.1", 1))
		if err := release.VerifyWith(bytes.NewReader(data), badComment, nodeAMD64, pubs(kp)); !errors.Is(err, release.ErrBadSignature) {
			t.Errorf("a changed comment: err = %v, want ErrBadSignature", err)
		}
	})
	t.Run("the algorithm upgraded to the prehashed one", func(t *testing.T) {
		lines := strings.Split(string(sig), "\n")
		if !strings.HasPrefix(lines[1], "RW") {
			t.Fatalf("the signature line starts %q, want a legacy signature (RW)", lines[1][:4])
		}
		lines[1] = "RU" + lines[1][2:]
		if err := release.VerifyWith(bytes.NewReader(data), []byte(strings.Join(lines, "\n")), nodeAMD64, pubs(kp)); !errors.Is(err, release.ErrBadSignature) {
			t.Errorf("err = %v, want ErrBadSignature", err)
		}
	})
}

func TestVerifyLegacyLimit(t *testing.T) {
	if got, want := release.MaxLegacyBytes(), int64(64<<20); got != want {
		t.Fatalf("the limit of legacy signatures is %d bytes, want 64 MiB (%d)", got, want)
	}
	const limit = 1024
	t.Cleanup(release.SetMaxLegacyBytes(limit))

	kp := newKeyPair(t)
	legacy := func(n int) (data, sig []byte) {
		data = randomBytes(t, n)
		return data, minisign.SignWithComments(kp.priv, data, nodeAMD64.TrustedComment(), "legacy")
	}

	t.Run("up to the limit", func(t *testing.T) {
		for _, n := range []int{0, 1, limit - 1, limit} {
			data, sig := legacy(n)
			if err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, pubs(kp)); err != nil {
				t.Errorf("%d bytes: %v", n, err)
			}
		}
	})
	t.Run("past the limit", func(t *testing.T) {
		for _, n := range []int{limit + 1, 2 * limit, 1 << 20} {
			data, sig := legacy(n)
			err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, pubs(kp))
			if !errors.Is(err, release.ErrBadSignature) {
				t.Errorf("%d bytes: err = %v, want ErrBadSignature", n, err)
			}
		}
	})
	t.Run("the data is refused past the limit, not cut at it", func(t *testing.T) {
		// A signature that covers the first limit bytes, and one byte more that
		// it does not cover: cutting the data to what is held would let that
		// byte, and anything after it, go by.
		data := randomBytes(t, limit+1)
		sig := minisign.SignWithComments(kp.priv, data[:limit], nodeAMD64.TrustedComment(), "legacy")
		if err := release.VerifyWith(bytes.NewReader(data[:limit]), sig, nodeAMD64, pubs(kp)); err != nil {
			t.Fatalf("the signature does not cover its %d bytes: %v", limit, err)
		}
		err := release.VerifyWith(bytes.NewReader(data), sig, nodeAMD64, pubs(kp))
		if !errors.Is(err, release.ErrBadSignature) {
			t.Errorf("one byte past the signed ones: err = %v, want ErrBadSignature", err)
		}
	})
	t.Run("a prehashed signature streams, whatever the size", func(t *testing.T) {
		// 8 MiB of zeros that are never held in memory: signed and verified
		// from a reader, well over the limit of the legacy kind.
		const size = 8 << 20
		sig, err := release.Sign(io.LimitReader(zeroReader{}, size), kp.priv, nodeAMD64)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := release.VerifyWith(io.LimitReader(zeroReader{}, size), sig, nodeAMD64, pubs(kp)); err != nil {
			t.Errorf("VerifyWith: %v", err)
		}
		if err := release.VerifyWith(io.LimitReader(zeroReader{}, size-1), sig, nodeAMD64, pubs(kp)); !errors.Is(err, release.ErrBadSignature) {
			t.Errorf("one byte short: err = %v, want ErrBadSignature", err)
		}
	})
}

func TestVerifyReadError(t *testing.T) {
	kp := newKeyPair(t)
	data := randomBytes(t, 4096)
	boom := errors.New("boom")

	sigs := map[string][]byte{
		"prehashed": sign(t, data, kp, nodeAMD64),
		"legacy":    minisign.SignWithComments(kp.priv, data, nodeAMD64.TrustedComment(), "legacy"),
	}
	for name, sig := range sigs {
		t.Run(name, func(t *testing.T) {
			r := io.MultiReader(bytes.NewReader(data[:100]), iotest.ErrReader(boom))
			err := release.VerifyWith(r, sig, nodeAMD64, pubs(kp))
			if !errors.Is(err, boom) {
				t.Errorf("err = %v, want one that wraps the error of the reader", err)
			}
			// A read that failed says nothing about the signature.
			for _, sentinel := range []error{release.ErrBadSignature, release.ErrWrongArtifact, release.ErrUntrustedKey} {
				if errors.Is(err, sentinel) {
					t.Errorf("err = %v: a failed read is not %v", err, sentinel)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// minisign CLI

// TestVerifyMinisignCLIVector checks the signatures that the minisign program
// itself makes, the reference that every other implementation is held to. They
// were made once, with minisign 0.12 from Alpine 3.22 (apk add minisign) in a
// container that was thrown away with its key, as
//
//	minisign -G -W -p cli.pub -s cli.key
//	minisign -S -s cli.key -m cli.msg -t "postern postern-node v0.5.0 linux/amd64"
//	minisign -S -l -s cli.key -m cli.msg -x cli.msg.legacy.minisig -t "postern postern-node v0.5.0 linux/amd64"
//
// and only the public key, the message and the two signatures are committed.
// The test cannot be skipped: it is what ties the package to the real format.
func TestVerifyMinisignCLIVector(t *testing.T) {
	msg := mustRead(t, "testdata/cli.msg")
	if len(msg) != 64 {
		t.Fatalf("testdata/cli.msg is %d bytes, want 64", len(msg))
	}
	pubText := mustRead(t, "testdata/cli.pub")
	var pub minisign.PublicKey
	if err := pub.UnmarshalText(pubText); err != nil {
		t.Fatalf("testdata/cli.pub: %v", err)
	}
	// The second line of the file is the key as it goes into the key variables.
	pubLine := strings.Split(strings.TrimSpace(string(pubText)), "\n")[1]
	if pubLine != pub.String() {
		t.Fatalf("the key line of cli.pub is %q, minisign prints it as %q", pubLine, pub.String())
	}

	vectors := []struct {
		name      string
		file      string
		algorithm uint16
	}{
		{"prehashed", "testdata/cli.msg.minisig", minisign.HashEdDSA},
		{"legacy", "testdata/cli.msg.legacy.minisig", minisign.EdDSA},
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			sig := mustRead(t, v.file)
			var parsed minisign.Signature
			if err := parsed.UnmarshalText(sig); err != nil {
				t.Fatalf("%s does not parse: %v", v.file, err)
			}
			if parsed.Algorithm != v.algorithm {
				t.Fatalf("algorithm = %#x, want %#x", parsed.Algorithm, v.algorithm)
			}
			if parsed.KeyID != pub.ID() {
				t.Fatalf("key id = %016X, want %016X", parsed.KeyID, pub.ID())
			}
			if want := "signature from minisign secret key"; parsed.UntrustedComment != want {
				t.Fatalf("untrusted comment = %q, want %q (the comment of the program)", parsed.UntrustedComment, want)
			}

			if err := release.VerifyWith(bytes.NewReader(msg), sig, nodeAMD64, []minisign.PublicKey{pub}); err != nil {
				t.Fatalf("VerifyWith: %v", err)
			}
			// minisign's own library agrees.
			if !minisign.Verify(pub, msg, sig) {
				t.Error("minisign.Verify refuses the vector")
			}

			other := nodeAMD64
			other.Version = "v0.5.1"
			if err := release.VerifyWith(bytes.NewReader(msg), sig, other, []minisign.PublicKey{pub}); !errors.Is(err, release.ErrWrongArtifact) {
				t.Errorf("another version: err = %v, want ErrWrongArtifact", err)
			}
			bad := bytes.Clone(msg)
			bad[10] ^= 1
			if err := release.VerifyWith(bytes.NewReader(bad), sig, nodeAMD64, []minisign.PublicKey{pub}); !errors.Is(err, release.ErrBadSignature) {
				t.Errorf("a changed message: err = %v, want ErrBadSignature", err)
			}
			stranger := newKeyPair(t)
			if err := release.VerifyWith(bytes.NewReader(msg), sig, nodeAMD64, pubs(stranger)); !errors.Is(err, release.ErrUntrustedKey) {
				t.Errorf("another key: err = %v, want ErrUntrustedKey", err)
			}

			// The same through the key variables: the key line, and the whole
			// .pub file, as an owner may paste either.
			for name, list := range map[string]string{"key line": pubLine, "pub file": string(pubText)} {
				t.Run(name, func(t *testing.T) {
					useKeys(t, list, "", "")
					if err := release.Verify(bytes.NewReader(msg), sig, nodeAMD64); err != nil {
						t.Errorf("Verify: %v", err)
					}
				})
			}
		})
	}
}
