package releases

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/release"
)

// ErrNotPinned is returned by TakeUploaded for a binary whose SHA-256 no
// release of the component pins for the architecture.
var ErrNotPinned = errors.New("releases: no release of the component pins this binary")

// keptSignature is where the signature of an uploaded file of a Postern
// component is kept: beside the file. Prepare verifies the file with it
// instead of fetching the signature from the release of Postern, which a dev
// or an air-gapped panel does not have.
func keptSignature(dst string) string { return dst + ".minisig" }

// verifyKept verifies sig for the file at path, a binary of the Postern
// component comp for arch: by one of keys (the release keys), its trusted
// comment "postern <component> <tag> linux/<arch>" naming a release of
// Postern (the bundle that brought it; the bytes are tied to the component's
// version by the pin). Every error is a finding about the file or the
// signature.
func verifyKept(comp Component, arch, path string, sig []byte, keys []minisign.PublicKey) error {
	var parsed minisign.Signature
	if err := parsed.UnmarshalText(sig); err != nil {
		return fmt.Errorf("%w: %v", release.ErrBadSignature, err)
	}
	tag, ok := strings.CutPrefix(parsed.TrustedComment, "postern "+comp.Name+" ")
	if ok {
		tag, ok = strings.CutSuffix(tag, " linux/"+arch)
	}
	if !ok || PosternTag(tag) == "" {
		return fmt.Errorf("%w: the signature is for %q, and one for postern %s <release> linux/%s is wanted",
			release.ErrWrongArtifact, parsed.TrustedComment, comp.Name, arch)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return release.VerifyWith(f, sig, release.Signed{Component: comp.Name, Version: tag, OS: "linux", Arch: arch}, keys)
}

// TakeUploaded keeps a binary of a Postern component (psiphon-core) that a
// release bundle brought, with its signature, and returns the version of the
// component it is. The signature has to be by a release key, for the
// component and arch (verifyKept), and the file's SHA-256 has to be the pin of
// a release of the component for arch (else ErrNotPinned): nothing else is
// kept, and the asset is left as it was. A kept file is then prepared as
// Prepare does (the signature, now from beside the file, and the static-ELF
// check), so that it ends ready for the nodes. An asset that is unusable stays
// so (ErrUnusable): only Recheck lifts the verdict.
func (c *Catalog) TakeUploaded(ctx context.Context, component, arch, path string, sig []byte) (string, error) {
	comp, ok := ComponentOf(component)
	if !ok || !comp.Postern {
		return "", fmt.Errorf("%w: %q is not a component that Postern builds", ErrUnknown, component)
	}
	keys, err := c.keys(release.ReleaseKeys)
	if err != nil {
		return "", err
	}
	if err := verifyKept(comp, arch, path, sig, keys); err != nil {
		return "", err
	}
	sha, _, err := fileSHA256(path)
	if err != nil {
		return "", err
	}
	version, err := c.PinnedVersion(ctx, comp.Name, arch, sha)
	if err != nil {
		return "", err
	}
	if err := c.keep(comp, version, comp.AssetName(version, arch), path, sig); err != nil {
		return "", err
	}
	return version, c.prepareArch(ctx, comp.Name, version, arch)
}

// PinnedVersion returns the version of the component whose asset for arch is
// pinned to sha, or ErrNotPinned. A pin of any SHASource is accepted: that is
// safe only because the caller also checks the release-key signature of the
// file; never drop that check, the catalog pin alone proves nothing (a tofu pin
// is the node's own first sight of the bytes).
func (c *Catalog) PinnedVersion(ctx context.Context, component, arch, sha string) (string, error) {
	comp, ok := ComponentOf(component)
	if !ok {
		return "", fmt.Errorf("%w: component %q", ErrUnknown, component)
	}
	rels, err := c.db.ListReleases(ctx, comp.Name)
	if err != nil {
		return "", err
	}
	for _, r := range rels {
		if a, ok := r.Assets[arch]; ok && a.SHA256 == sha && a.File == comp.AssetName(r.Version, arch) && safeFileName(a.File) {
			return r.Version, nil
		}
	}
	return "", fmt.Errorf("%w: %s for %s with SHA-256 %s", ErrNotPinned, comp.Name, arch, sha)
}

// keep copies the file at path and its signature to where Prepare reads them,
// each through a temporary file and a rename.
func (c *Catalog) keep(comp Component, version, file, path string, sig []byte) error {
	dst := c.path(comp, version, file)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { //nolint:gosec // G301: the nodes' engine files are public; the directory is the panel's data
		return err
	}
	unlock := c.lock(dst)
	defer unlock()
	if err := writeFileAtomic(keptSignature(dst), func(w io.Writer) error { _, err := w.Write(sig); return err }); err != nil {
		return err
	}
	return writeFileAtomic(dst, func(w io.Writer) error {
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = src.Close() }()
		_, err = io.Copy(w, src)
		return err
	})
}

// writeFileAtomic writes p through p.up and a rename.
func writeFileAtomic(p string, fill func(io.Writer) error) (err error) {
	tmp := p + ".up"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec // G302,G304: the panel's data; the binaries are public
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err := fill(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
