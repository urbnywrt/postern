package releases

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// The events that the catalog records.
const (
	EventChecksumMismatch = "release_checksum_mismatch" // a source disagrees with the expected SHA-256, or a download does
	EventUnusable         = "release_unusable"          // an asset failed a check, or a node's trial of it
)

// ErrChecksumMismatch is returned by Prepare when a download, or a checksum
// file, has another SHA-256 than the one that is expected.
var ErrChecksumMismatch = errors.New("releases: SHA-256 mismatch")

// An expectation is the SHA-256 that an asset has to have, and where it came
// from (one of the store.SHASource values). An empty sha with source
// store.SHASourceTOFU means that there is nothing to compare with: the first
// download that passes the checks is pinned.
type expectation struct {
	sha    string
	source string
}

func (e expectation) builtin() bool { return e.source == store.SHASourceBuiltin }

// expected applies the checksum rules (Global Constraints, Checksum rules) to
// the asset a of rel for arch, with the component's checksum file fetched when
// the release publishes one:
//
//  1. a pinned SHA-256 is the expectation, a built-in one above all: a
//     checksum file that disagrees with a built-in pin is rejected with the
//     event and changes nothing (R5-4); one that disagrees with any other pin
//     (a digest, the stable list, an earlier download) makes the asset
//     unusable, with the event, and is ErrChecksumMismatch;
//  2. without a pin the checksum file is the expectation (store.SHASourceSums);
//  3. without either, the download is pinned when it passes (TOFU).
//
// A checksum file that cannot be fetched for a reason other than that there is
// none (a 5xx, the network) is an error for an asset without a pin: the rules
// cannot be applied, and a later Prepare tries again. A pinned asset prepares
// on its pin; the file is a cross-check when it can be read.
func (c *Catalog) expected(ctx context.Context, comp Component, rel *store.Release, arch string, a store.ReleaseAsset, src *FeedSource) (expectation, error) {
	sums, err := c.fetchSums(ctx, comp, rel, a, src)
	if err != nil {
		if a.SHA256 != "" {
			// The pin suffices; the checksum file is a cross-check when it can
			// be read. (A 404 is no error: the release has none.)
			c.log.Warn("the checksum file could not be read; the pinned SHA-256 stands",
				"component", comp.Name, "version", rel.Version, "arch", arch, "source", a.SHASource, "err", err)
			return expectation{sha: a.SHA256, source: a.SHASource}, nil
		}
		return expectation{}, err
	}
	if a.SHA256 != "" {
		exp := expectation{sha: a.SHA256, source: a.SHASource}
		if sums != "" && sums != a.SHA256 {
			c.event(ctx, EventChecksumMismatch, "error",
				fmt.Sprintf("%s %s %s: the checksum file disagrees with the %s SHA-256", comp.Name, rel.Version, arch, exp.source),
				map[string]string{"component": comp.Name, "version": rel.Version, "arch": arch,
					"expected": a.SHA256, "got": sums, "source": exp.source, "from": "sums"})
			if exp.builtin() {
				return exp, nil
			}
			c.setUnusable(ctx, comp, rel, arch, fmt.Sprintf("the checksum file disagrees with the %s SHA-256", exp.source))
			return expectation{}, fmt.Errorf("%w: %s %s %s: checksum file against %s", ErrChecksumMismatch, comp.Name, rel.Version, arch, exp.source)
		}
		return exp, nil
	}
	if sums != "" {
		return expectation{sha: sums, source: store.SHASourceSums}, nil
	}
	return expectation{source: store.SHASourceTOFU}, nil
}

// fetchSums returns the SHA-256 that the release's checksum file gives for the
// asset, "" when the release has no checksum file or it does not name the
// asset, and an error when it cannot be read or cannot be trusted.
func (c *Catalog) fetchSums(ctx context.Context, comp Component, rel *store.Release, a store.ReleaseAsset, src *FeedSource) (string, error) {
	if comp.Sums.File == "" || a.URL == "" {
		return "", nil
	}
	i := strings.LastIndex(a.URL, "/")
	if i < 0 {
		return "", nil
	}
	u := a.URL[:i+1] + comp.SumsFile(rel.Version, a.File)
	data, err := c.getSmall(ctx, u, src, maxSumsFile)
	if errors.Is(err, errNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	sum, err := release.SumFor(a.File, data, comp.Sums.Format)
	if errors.Is(err, release.ErrNoSum) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("releases: checksum file of %s %s: %w", comp.Name, rel.Version, err)
	}
	return sum, nil
}

// mismatch handles a download whose SHA-256 is not the expected one: the
// event, and for an asset that is not built in the verdict unusable.
func (c *Catalog) mismatch(ctx context.Context, comp Component, rel *store.Release, arch string, exp expectation, got string) error {
	c.event(ctx, EventChecksumMismatch, "error",
		fmt.Sprintf("%s %s %s: the download has another SHA-256 than the %s one", comp.Name, rel.Version, arch, exp.source),
		map[string]string{"component": comp.Name, "version": rel.Version, "arch": arch,
			"expected": exp.sha, "got": got, "source": exp.source, "from": "download"})
	if !exp.builtin() {
		c.setUnusable(ctx, comp, rel, arch, fmt.Sprintf("the download has another SHA-256 than the %s one", exp.source))
	}
	return fmt.Errorf("%w: %s %s %s: download against %s", ErrChecksumMismatch, comp.Name, rel.Version, arch, exp.source)
}

// setUnusable records the verdict unusable on an asset, with the event.
func (c *Catalog) setUnusable(ctx context.Context, comp Component, rel *store.Release, arch, reason string) {
	if err := c.db.SetAssetState(ctx, comp.Name, rel.Version, arch, store.AssetUnusable, reason, ""); err != nil {
		c.log.Error("could not record that an asset is unusable", "component", comp.Name, "version", rel.Version, "arch", arch, "err", err)
	}
	c.event(ctx, EventUnusable, "warning",
		fmt.Sprintf("%s %s %s is unusable: %s", comp.Name, rel.Version, arch, reason),
		map[string]string{"component": comp.Name, "version": rel.Version, "arch": arch, "reason": reason})
}

// event records an event; a failure is logged and does not fail the caller.
func (c *Catalog) event(ctx context.Context, kind, severity, msg string, details map[string]string) {
	e := &store.Event{Kind: kind, Severity: severity, Message: msg, Details: details}
	if err := c.db.AppendEvent(context.WithoutCancel(ctx), e); err != nil {
		c.log.Error("could not write an event", "kind", kind, "err", err)
	}
	level := slog.LevelWarn
	if severity == "error" {
		level = slog.LevelError
	}
	c.log.Log(ctx, level, msg, "kind", kind)
}

// maxSignature bounds a .minisig.
const maxSignature = 64 << 10

// checkSignature verifies the .minisig of the file at dst of a Postern
// component: by a release key, for "postern <component> <tag> linux/<arch>",
// the tag being the release of Postern that holds it (rel.Tag). A signature
// that does not verify is a verdict (reason != ""), like a binary that is not
// static; one that cannot be fetched, or no key to check it with, is an
// error, and a later Prepare tries again.
//
// A signature kept beside the file (a release bundle brought both: see
// TakeUploaded) is verified instead, with no network: by a release key, for
// the component and the architecture, of any release of Postern.
func (c *Catalog) checkSignature(ctx context.Context, comp Component, rel *store.Release, arch string, a store.ReleaseAsset, src *FeedSource, dst string) (reason string, err error) {
	if kept, err := os.ReadFile(keptSignature(dst)); err == nil {
		keys, err := c.keys(release.ReleaseKeys)
		if err != nil {
			return "", err
		}
		if err := verifyKept(comp, arch, dst, kept, keys); err != nil {
			return "the kept signature does not verify: " + err.Error(), nil
		}
		return "", nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if rel.Tag == "" || a.URL == "" {
		return "", fmt.Errorf("releases: %s %s %s: this panel is no release of Postern, which would hold the file", comp.Name, rel.Version, arch)
	}
	sig, err := c.getSmall(ctx, a.URL+".minisig", src, maxSignature)
	if err != nil {
		return "", fmt.Errorf("releases: the signature of %s %s %s: %w", comp.Name, rel.Version, arch, err)
	}
	keys, err := c.keys(release.ReleaseKeys)
	if err != nil {
		return "", err
	}
	f, err := os.Open(dst)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	want := release.Signed{Component: comp.Name, Version: rel.Tag, OS: "linux", Arch: arch}
	if err := release.VerifyWith(f, sig, want, keys); err != nil {
		return "the signature does not verify: " + err.Error(), nil
	}
	return "", nil
}

// isVerdict reports whether an extraction error is a finding about the archive
// (which makes the asset unusable) rather than a failure of the disk.
func isVerdict(err error) bool {
	return errors.Is(err, ErrNoMember) || errors.Is(err, ErrDuplicateMember) ||
		errors.Is(err, ErrBinaryTooLarge) || errors.Is(err, ErrArchive)
}

// checkBinary extracts the binary of the archive at dst into a fixed temporary
// file next to it and runs the static-ELF check on it. The extracted copy is
// removed either way. A finding about the archive or the binary is returned as
// a verdict (reason != ""); any other error is returned as is. Extraction has
// extractTimeout.
func (c *Catalog) checkBinary(ctx context.Context, dst, file, member, arch string) (reason string, err error) {
	ctx, cancel := context.WithTimeout(ctx, extractTimeout)
	defer cancel()
	bin := filepath.Join(filepath.Dir(dst), "."+arch+"."+filepath.Base(member)+".tmp")
	_ = os.Remove(bin)
	defer func() { _ = os.Remove(bin) }()
	if err := extractMember(ctx, dst, file, member, bin); err != nil {
		if isVerdict(err) {
			return err.Error(), nil
		}
		return "", err
	}
	f, err := os.Open(bin)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	switch err := release.CheckStaticELF(f, arch); {
	case err == nil:
		return "", nil
	case errors.Is(err, release.ErrNotELF), errors.Is(err, release.ErrWrongArch), errors.Is(err, release.ErrDynamic), errors.Is(err, release.ErrPacked):
		return err.Error(), nil
	default:
		return "", err
	}
}
