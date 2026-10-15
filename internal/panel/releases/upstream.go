package releases

import (
	"context"
	"fmt"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// What the job of the stable list (scripts/release candidates) checks of an
// upstream release before it runs the end-to-end tests on it: the checksum
// rules and the extraction of the catalog, without a catalog. A candidate has
// no built-in pin and no stable entry yet (rule 1 does not apply to it).

// UpstreamSHA applies the checksum rules 2 to 4 (Global Constraints, Checksum
// rules) to an upstream asset: digest is the SHA-256 that the release API
// states, sums the one of the component's checksum file, each lower-case hex
// or "" for none. The digest is the expected SHA-256 and the checksum file
// must agree with it (ErrChecksumMismatch otherwise); without a digest the
// checksum file is; without either the download is taken as it is
// (store.SHASourceTOFU, sha "").
func UpstreamSHA(digest, sums string) (sha, source string, err error) {
	switch {
	case digest != "" && sums != "" && digest != sums:
		return "", "", fmt.Errorf("%w: the checksum file disagrees with the digest of the release API", ErrChecksumMismatch)
	case digest != "":
		return digest, store.SHASourceDigest, nil
	case sums != "":
		return sums, store.SHASourceSums, nil
	}
	return "", store.SHASourceTOFU, nil
}

// ExtractBinary copies the binary member out of the archive at src, whose
// file name (name) says whether it is a tar.gz or a zip, into dst, by the
// rules with which the catalog extracts every release (ErrNoMember,
// ErrDuplicateMember, ErrBinaryTooLarge, ErrArchive). dst is removed when
// extraction fails.
func ExtractBinary(ctx context.Context, src, name, member, dst string) error {
	return extractMember(ctx, src, name, member, dst)
}
