// Package release is what Postern trusts about a release: who may sign it,
// whether a signature holds, whether a binary is one that a node can run, and
// which of two versions is the newer.
//
// Signatures are minisign signatures (https://jedisct1.github.io/minisign/),
// checked with aead.dev/minisign. Two sets of public keys are compiled into a
// binary, and the signature says which key made it (its key id):
//
//   - the release keys sign the binaries of a release, postern-node and
//     postern-panel, and the checksums of the release, sha256sums;
//   - the stable keys sign the list of the engines that are stable,
//     engines-stable.
//
// A signature by a key of the other set is refused, whatever it is a signature
// of, so that a key that is kept in a CI job for one purpose cannot be used for
// the other. What a signature is for is in its trusted comment, which the
// signature covers: "postern <component> <version>", and " <os>/<arch>" after
// it for a binary. A verification names the artifact that it expects, and a
// signature that is good for another one is refused too.
//
// The production keys are the strings productionReleaseKeys and
// productionStableKeys, which the owner commits. A build can add test keys
// with
//
//	-ldflags "-X github.com/urbnywrt/postern/internal/release.extraPublicKeys=<key>[,<key>]"
//
// but only to a set that has no production keys yet: once it has them, the
// extra keys are ignored for it, and [KeyWarnings] says so. A binary that has
// no key for a set verifies nothing of it ([ErrNoKeys]). A key of small order
// (the zero key, the identity and the other points of the subgroup of order 8 of
// the curve), for which anybody can make signatures, is refused when the keys
// are read, and is never tried by [VerifyWith].
//
// The rest of the package is what is checked about a release: [CheckStaticELF]
// (a binary that an engine container can run), [Compare] and [ValidVersion]
// (versions), and [SumFor] (the checksum files that the upstream projects
// publish).
package release

import (
	"errors"
	"fmt"
	"strings"

	"aead.dev/minisign"
)

// The production keys: minisign public keys as the base64 text of a minisign.pub
// file (the second line of it, "RW..."), one to a line, or several on one line
// apart by commas. The whole file may be pasted in as well; its comment lines
// are skipped. The values are set when the keys are made, and are kept as plain
// string variables with constant values so that a build can also set them.
var (
	// productionReleaseKeys may sign postern-node, postern-panel and sha256sums.
	// The keys are public: gitleaks takes their base64 for a secret.
	productionReleaseKeys = "RWTw2e41zd8bd6IycEUpNTRRL2n1eXFfURFwhnmTTYtG0ePp3ojRmOFe" // gitleaks:allow

	// productionStableKeys may sign engines-stable, and nothing else.
	productionStableKeys = "RWQHf4oB/ck3Wtk8EELKVp9cqjmVD91M5LE/P6E7HYB84ul0WP1MDrOf" // gitleaks:allow
)

// extraPublicKeys holds test keys that a build adds (see the package comment),
// in the same form as the production keys. A set uses them only while it has no
// production keys.
var extraPublicKeys string

// KeySet names one of the two sets of trusted public keys.
type KeySet int

const (
	// ReleaseKeys sign postern-node, postern-panel, psiphon-core and sha256sums.
	ReleaseKeys KeySet = iota
	// StableKeys sign engines-stable.
	StableKeys
)

func (s KeySet) String() string {
	switch s {
	case ReleaseKeys:
		return "release"
	case StableKeys:
		return "stable"
	}
	return fmt.Sprintf("KeySet(%d)", int(s))
}

// The components that are signed, as they are named in a trusted comment.
const (
	componentNode  = "postern-node"
	componentPanel = "postern-panel"
	componentSums  = "sha256sums"
	// componentPsiphon is the Psiphon client (psiphon-tunnel-core's
	// ConsoleClient) that a release builds from a pinned upstream commit.
	componentPsiphon = "psiphon-core"
	componentStable  = "engines-stable"
)

// The warnings of [KeyWarnings].
const (
	warnTestKeys        = "test-release-keys"
	warnTestKeysIgnored = "test-release-keys-ignored"
)

// ErrNoKeys is returned when there is no key to verify with: neither a
// production key nor an extra key is compiled in for the set.
var ErrNoKeys = errors.New("release: no trusted public keys are compiled in")

// invalidKeySet is what SetOf returns with its error: neither of the two sets,
// and so one that TrustedKeys refuses. (The zero value of a KeySet is
// ReleaseKeys, and a caller that logs the error and goes on would find the
// release keys trusted for a component that has no key set.)
const invalidKeySet KeySet = -1

// SetOf returns the key set that signs component: ReleaseKeys for postern-node,
// postern-panel, psiphon-core and sha256sums, StableKeys for engines-stable. Another
// component has no key set, and so cannot be verified: the error comes with a
// set that is not one, which [TrustedKeys] refuses.
func SetOf(component string) (KeySet, error) {
	switch component {
	case componentNode, componentPanel, componentSums, componentPsiphon:
		return ReleaseKeys, nil
	case componentStable:
		return StableKeys, nil
	}
	return invalidKeySet, fmt.Errorf("release: no key set signs %q", component)
}

// TrustedKeys returns the keys that are trusted for set: its production keys,
// or, while it has none, the extra keys that the build added. It returns
// [ErrNoKeys] if there are neither.
//
// A key that cannot be read, or that is of small order (the zero key, the
// identity: anybody can sign for it), is an error that names its position in
// the list ("key 2") and never the key. A production list that is malformed is
// not replaced by the extra keys: the production keys exist, and are wrong.
func TrustedKeys(set KeySet) ([]minisign.PublicKey, error) {
	list, err := productionList(set)
	if err != nil {
		return nil, err
	}
	if texts := keyTexts(list); len(texts) > 0 {
		return parseKeys(texts, set.String()+" keys")
	}
	texts := keyTexts(extraPublicKeys)
	if len(texts) == 0 {
		return nil, ErrNoKeys
	}
	return parseKeys(texts, "extra public keys")
}

// ProductionKeys returns the production keys that are compiled in for set, in
// the order of the list, and not the extra keys: the keys that [TrustedKeys]
// would take. A key that cannot be read, or that is of small order, is left out
// here ([TrustedKeys] is the one to say so), and so is any key of a set that
// does not exist.
func ProductionKeys(set KeySet) []minisign.PublicKey {
	list, err := productionList(set)
	if err != nil {
		return nil
	}
	var keys []minisign.PublicKey
	for _, text := range keyTexts(list) {
		var key minisign.PublicKey
		if key.UnmarshalText([]byte(text)) == nil && !smallOrder(key) {
			keys = append(keys, key)
		}
	}
	return keys
}

// KeyWarnings reports what is unusual about the keys of this binary. It returns
// "test-release-keys" when extra keys are in use (a set has no production keys,
// and so takes them), and "test-release-keys-ignored" when extra keys were
// compiled in and a set that has production keys ignores them: the binary was
// built for tests and is, or is meant to be, a production one. It returns
// nothing for a binary that was built without extra keys.
func KeyWarnings() []string {
	if len(keyTexts(extraPublicKeys)) == 0 {
		return nil
	}
	var inUse, ignored bool
	for _, set := range []KeySet{ReleaseKeys, StableKeys} {
		list, _ := productionList(set)
		if len(keyTexts(list)) > 0 {
			ignored = true
		} else {
			inUse = true
		}
	}
	var warnings []string
	if inUse {
		warnings = append(warnings, warnTestKeys)
	}
	if ignored {
		warnings = append(warnings, warnTestKeysIgnored)
	}
	return warnings
}

// productionList returns the list of production keys of set, as it is compiled in.
func productionList(set KeySet) (string, error) {
	switch set {
	case ReleaseKeys:
		return productionReleaseKeys, nil
	case StableKeys:
		return productionStableKeys, nil
	}
	return "", fmt.Errorf("release: unknown key set %d", int(set))
}

// keyTexts splits a list of keys into the text of each one: a key to a line, or
// several on a line apart by commas. Blank entries are left out, and so are the
// comment lines of a minisign.pub file ("untrusted comment: ...").
func keyTexts(list string) []string {
	var texts []string
	for line := range strings.SplitSeq(list, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "untrusted comment:") {
			continue
		}
		for text := range strings.SplitSeq(line, ",") {
			if text = strings.TrimSpace(text); text != "" {
				texts = append(texts, text)
			}
		}
	}
	return texts
}

// parseKeys reads the keys of texts. what says which list it is, for the error
// of a key that is malformed: its position there and what is wrong with it. The
// reasons that the library gives are about the length and the alphabet of the
// key, they do not quote it, and nor does this error: a key is not put in a log.
// A key of small order is refused as well, see smallorder.go.
func parseKeys(texts []string, what string) ([]minisign.PublicKey, error) {
	keys := make([]minisign.PublicKey, len(texts))
	for i, text := range texts {
		if err := keys[i].UnmarshalText([]byte(text)); err != nil {
			return nil, fmt.Errorf("release: %s: key %d is malformed: %v", what, i+1, err)
		}
		if smallOrder(keys[i]) {
			return nil, fmt.Errorf("release: %s: key %d is a key of small order, which anybody can make signatures for", what, i+1)
		}
	}
	return keys, nil
}
