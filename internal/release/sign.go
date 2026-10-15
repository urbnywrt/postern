package release

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"aead.dev/minisign"
)

// untrustedComment is the first line of every signature that Sign makes. It is
// not covered by the signature and is for people to read.
const untrustedComment = "postern release signature"

// maxLegacyBytes is the most data that VerifyWith holds in memory to check a
// legacy signature, which is made over the data itself. A variable so that the
// tests can lower it.
var maxLegacyBytes int64 = 64 << 20

var (
	// ErrUntrustedKey is returned when the key that made the signature (its key
	// id) is not among the keys that are trusted for it.
	ErrUntrustedKey = errors.New("release: the signature is by a key that is not trusted")

	// ErrBadSignature is returned when the signature cannot be read, or does not
	// verify: the data, the trusted comment or the signature was changed, or the
	// signature is not by the key that its key id names.
	ErrBadSignature = errors.New("release: bad signature")

	// ErrWrongArtifact is returned when the signature is good and is for another
	// artifact than the one that was asked for: another component, version, or
	// platform.
	ErrWrongArtifact = errors.New("release: the signature is for another artifact")
)

// Signed names what a signature is for: a component, a version and, for a
// binary, a platform. It is the trusted comment of the signature.
type Signed struct {
	// Component is what is signed: postern-node, postern-panel, sha256sums or
	// engines-stable.
	Component string
	// Version is the version of the release (v0.5.0), or, for the list of
	// engines, the time that the list was made, in Unix seconds.
	Version string
	// OS and Arch are the platform of a binary (linux, amd64). Both are empty
	// for an artifact that has none.
	OS, Arch string
}

// TrustedComment returns the comment that a signature of s carries and that
// the signature covers: "postern <Component> <Version>", and " <OS>/<Arch>" when
// there is an Arch, as in "postern postern-node v0.5.0 linux/amd64".
func (s Signed) TrustedComment() string {
	comment := "postern " + s.Component + " " + s.Version
	if s.Arch != "" {
		comment += " " + s.OS + "/" + s.Arch
	}
	return comment
}

// validate reports whether s names an artifact that can be signed, and so one
// that a signature can be checked for. Every field is one word, so that the
// comment cannot be read as the comment of another artifact (the version
// "v0.5.0 linux/amd64" would make the comment of an amd64 binary), and nothing
// in it breaks the lines of a signature file.
func (s Signed) validate() error {
	switch {
	case !word(s.Component):
		return fmt.Errorf("release: invalid component %q", s.Component)
	case !ValidVersion(s.Version):
		return fmt.Errorf("release: invalid version %q", s.Version)
	case (s.OS == "") != (s.Arch == ""):
		return errors.New("release: an OS without an architecture, or the other way round")
	case s.Arch != "" && (!word(s.OS) || !word(s.Arch) || strings.Contains(s.OS+s.Arch, "/")):
		return fmt.Errorf("release: invalid platform %q/%q", s.OS, s.Arch)
	}
	return nil
}

// word reports whether s is one word of visible ASCII: no space, no control
// character, nothing outside ASCII.
func word(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// Verify checks that sig is a signature of the data of r that is good for want,
// by a key that is trusted for want.Component (see [SetOf] and [TrustedKeys]).
// It returns nil, or one of [ErrNoKeys], [ErrUntrustedKey], [ErrBadSignature]
// and [ErrWrongArtifact], or an error that says that the component has no key
// set or that want is not an artifact that can be signed for (see VerifyWith),
// or that wraps the error of a read of r.
func Verify(r io.Reader, sig []byte, want Signed) error {
	set, err := SetOf(want.Component)
	if err != nil {
		return err
	}
	keys, err := TrustedKeys(set)
	if err != nil {
		return err
	}
	return VerifyWith(r, sig, want, keys)
}

// VerifyWith is [Verify] with the keys that the caller gives, which is how
// every verifier outside this package is tested.
//
// What is wanted has to be an artifact that Sign could have signed for (every
// field one word, the version a [ValidVersion]), or the error is a plain one,
// none of the errors of this package that are values: the comment of the
// signature is compared with want as a line, and a field with a space in it
// could stand for two.
//
// The key that is tried is the one whose id is the key id of the signature; if
// there is none the signature is [ErrUntrustedKey], and the data is not read. A
// key of small order (the zero value of a key is one) is never tried, whatever
// its id: anybody can make a signature for it. A prehashed signature, which is
// what Sign makes, is verified as the data is read, and the data is not held. A
// legacy signature, which is made over the data itself, needs the data in
// memory and is accepted for up to 64 MiB of it.
//
// The signature and its signature of the trusted comment are checked first
// ([ErrBadSignature]), and only then is the comment compared with want
// ([ErrWrongArtifact]): the comment that is compared is one that somebody signed.
func VerifyWith(r io.Reader, sig []byte, want Signed, keys []minisign.PublicKey) error {
	if err := want.validate(); err != nil {
		return err
	}
	var parsed minisign.Signature
	if err := parsed.UnmarshalText(sig); err != nil {
		return fmt.Errorf("%w: %v", ErrBadSignature, err)
	}

	// A key id is a hint (64 bits, chosen when the key is made). Every key of the
	// set that has it is a candidate; there is one, unless two keys collide.
	var candidates []minisign.PublicKey
	degenerate := false
	for _, key := range keys {
		switch {
		case key.ID() != parsed.KeyID:
		case smallOrder(key):
			degenerate = true
		default:
			candidates = append(candidates, key)
		}
	}
	if len(candidates) == 0 {
		switch {
		case len(keys) == 0:
			return fmt.Errorf("%w: %w", ErrUntrustedKey, ErrNoKeys)
		case degenerate:
			return fmt.Errorf("%w: key id %016X is a key of small order, which anybody can make signatures for", ErrUntrustedKey, parsed.KeyID)
		}
		return fmt.Errorf("%w: key id %016X", ErrUntrustedKey, parsed.KeyID)
	}

	good, err := verifyData(r, sig, parsed.Algorithm, candidates)
	if err != nil {
		return err
	}
	if !good {
		return ErrBadSignature
	}
	if got, wanted := parsed.TrustedComment, want.TrustedComment(); got != wanted {
		return fmt.Errorf("%w: it is for %q, and %q is wanted", ErrWrongArtifact, got, wanted)
	}
	return nil
}

// verifyData reads r and reports whether sig, whose algorithm is algorithm, is
// a signature of what it holds by one of keys, and of the trusted comment of sig.
func verifyData(r io.Reader, sig []byte, algorithm uint16, keys []minisign.PublicKey) (bool, error) {
	if algorithm == minisign.HashEdDSA {
		// The signature is over the BLAKE2b-512 digest of the data, which is
		// computed as the data goes by: it is read once and never held.
		digest := minisign.NewReader(r)
		if _, err := io.Copy(io.Discard, digest); err != nil {
			return false, fmt.Errorf("release: reading the signed data: %w", err)
		}
		return slices.ContainsFunc(keys, func(key minisign.PublicKey) bool { return digest.Verify(key, sig) }), nil
	}

	data, err := io.ReadAll(io.LimitReader(r, maxLegacyBytes+1))
	if err != nil {
		return false, fmt.Errorf("release: reading the signed data: %w", err)
	}
	if int64(len(data)) > maxLegacyBytes {
		return false, fmt.Errorf("%w: a legacy signature (not prehashed) is accepted for up to %d bytes of data", ErrBadSignature, maxLegacyBytes)
	}
	return slices.ContainsFunc(keys, func(key minisign.PublicKey) bool { return minisign.Verify(key, data, sig) }), nil
}

// Sign signs the data of r with priv for s and returns the signature, in the
// text form of a .minisig file. The signature is prehashed (the data is read
// once and is not held), its trusted comment is s.TrustedComment() and its
// untrusted comment is "postern release signature". Nothing in it is random or
// a clock: the same data signed again for the same artifact gives the same
// bytes.
//
// It refuses an s that has a field that is empty, that is not one word, or that
// is not a version ([ValidVersion]): such a comment could be read as that of
// another artifact, and VerifyWith would refuse to look for it. The component is
// not looked up, so a signature can be made for a component that has no key set;
// [Verify] will not take it.
func Sign(r io.Reader, priv minisign.PrivateKey, s Signed) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	digest := minisign.NewReader(r)
	if _, err := io.Copy(io.Discard, digest); err != nil {
		return nil, fmt.Errorf("release: reading the data to sign: %w", err)
	}
	return digest.SignWithComments(priv, s.TrustedComment(), untrustedComment), nil
}
