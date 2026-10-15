package selfupdate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/release"
)

// The components of the binaries and their key set.
const (
	componentNode  = "postern-node"
	componentPanel = "postern-panel"
	binaryOS       = "linux"
)

// archs are the architectures that Postern is released for.
var archs = []string{"amd64", "arm64"}

// The answers of the cache.
var (
	// ErrUnknownAsset is returned for a name that is not one of the release
	// assets (NodeAsset or PanelAsset of a known architecture).
	ErrUnknownAsset = errors.New("selfupdate: not a release asset")
	// ErrBadVersion is returned for a version that release.ValidVersion refuses.
	ErrBadVersion = errors.New("selfupdate: invalid version")
	// ErrNotCached is returned by Open for an asset that is not in the cache.
	ErrNotCached = errors.New("selfupdate: the asset is not cached")
	// ErrConflict is returned by Put for an asset that the cache holds already,
	// verified, with other bytes: cached bytes never change under a version
	// (ruling S5-13); a new build needs a new version string.
	ErrConflict = errors.New("selfupdate: the cache holds the asset with other bytes")
)

// NodeAsset returns the name of the node binary's release asset for arch.
func NodeAsset(arch string) string { return componentNode + "-" + binaryOS + "-" + arch }

// PanelAsset returns the name of the panel binary's release asset for arch.
func PanelAsset(arch string) string { return componentPanel + "-" + binaryOS + "-" + arch }

// ParseAsset returns the component and the architecture of a release asset
// name: NodeAsset or PanelAsset of a known architecture, nothing else (no
// path, no .minisig, not the checksum file).
func ParseAsset(name string) (component, arch string, ok bool) {
	for _, comp := range []string{componentNode, componentPanel} {
		for _, a := range archs {
			if name == comp+"-"+binaryOS+"-"+a {
				return comp, a, true
			}
		}
	}
	return "", "", false
}

// A Cache keeps Postern's binaries under <Dir>/<version>/<asset>, each with
// its <asset>.minisig next to it. An asset is kept only when its signature
// verifies, by a release key, for its component, version, linux and
// architecture (the asset's name says which), and the file is a static ELF
// for that architecture; Open verifies the signature again, so a file that
// was changed under the cache is never handed out.
type Cache struct {
	Dir string
	// Keys gives the trusted public keys of a key set; nil is
	// release.TrustedKeys.
	Keys func(release.KeySet) ([]minisign.PublicKey, error)
}

// signed returns what the signature of the asset has to be for.
func signed(version, asset string) (release.Signed, error) {
	comp, arch, ok := ParseAsset(asset)
	if !ok {
		return release.Signed{}, fmt.Errorf("%w: %q", ErrUnknownAsset, asset)
	}
	if !release.ValidVersion(version) {
		return release.Signed{}, fmt.Errorf("%w: %q", ErrBadVersion, version)
	}
	return release.Signed{Component: comp, Version: version, OS: binaryOS, Arch: arch}, nil
}

func (c *Cache) keys() ([]minisign.PublicKey, error) {
	if c.Keys == nil {
		return release.TrustedKeys(release.ReleaseKeys)
	}
	return c.Keys(release.ReleaseKeys)
}

// verifyFile checks the file at p: its signature sig for want, by a release
// key, and that it is a static ELF for want.Arch. It returns the SHA-256 of
// the file.
func (c *Cache) verifyFile(p string, sig []byte, want release.Signed) (string, error) {
	keys, err := c.keys()
	if err != nil {
		return "", err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if err := release.VerifyWith(io.TeeReader(f, h), sig, want, keys); err != nil {
		return "", err
	}
	if err := release.CheckStaticELF(f, want.Arch); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// path returns where the asset of the version lives. Both were validated.
func (c *Cache) path(version, asset string) string {
	return filepath.Join(c.Dir, version, asset)
}

// Put reads the asset of the version from r (at most 256 MiB) into the cache
// when its signature sig verifies for it; otherwise nothing is kept and the
// error says why (release.ErrUntrustedKey, ErrBadSignature, ErrWrongArtifact,
// ErrNotELF, ErrWrongArch, ErrDynamic, or the cache's own). An asset that is
// cached already, and verifies, is left alone when its bytes are the same and
// is ErrConflict when they differ (S5-13); one that no longer verifies is
// replaced.
func (c *Cache) Put(ctx context.Context, version, asset string, r io.Reader, sig []byte) (err error) {
	want, err := signed(version, asset)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.Dir, 0o755); err != nil { //nolint:gosec // G301: the panel's data; the binaries are public
		return err
	}
	tmp, err := os.CreateTemp(c.Dir, ".put-"+asset+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
			_ = os.Remove(tmpName + ".minisig")
		}
	}()
	n, err := io.Copy(tmp, io.LimitReader(&ctxReader{ctx: ctx, r: r}, maxBinary+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxBinary {
		return fmt.Errorf("%w: %s is over %d bytes", ErrTooLarge, asset, maxBinary)
	}
	sha, err := c.verifyFile(tmpName, sig, want)
	if err != nil {
		return err
	}
	// What the cache holds is looked at and changed under the version's lock,
	// which an upload holds too: a Put never renames over what an upload
	// committed after the look.
	defer c.lockVersion(version)()
	if have, ok := c.cachedSHA(version, asset); ok {
		if have != sha {
			return fmt.Errorf("%w: %s %s", ErrConflict, version, asset)
		}
		_ = os.Remove(tmpName) // the same bytes: nothing to do
		return nil
	}
	if err := os.WriteFile(tmpName+".minisig", sig, 0o644); err != nil { //nolint:gosec // G306: a public signature
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil { //nolint:gosec // G302: a binary
		return err
	}
	if err := os.MkdirAll(filepath.Join(c.Dir, version), 0o755); err != nil { //nolint:gosec // G301: as above
		return err
	}
	return commit(tmpName, c.path(version, asset))
}

// commit moves a verified asset at tmp, and its tmp.minisig, to dst and
// dst.minisig. The signature goes first: a reader that finds the new asset
// finds a signature for it, and Open verifies the pair anyway.
func commit(tmp, dst string) error {
	if err := os.Rename(tmp+".minisig", dst+".minisig"); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// versionLocks holds a lock for each version directory of a cache, by its
// path: Put, the commit of an upload and the install of an update take it
// around what they read of the directory and change in it.
var versionLocks = struct {
	sync.Mutex
	m map[string]*sync.Mutex
}{m: map[string]*sync.Mutex{}}

// lockVersion takes the lock of the version's directory and returns the
// function that gives it back. The version was validated.
func (c *Cache) lockVersion(version string) (unlock func()) {
	key := filepath.Join(c.Dir, version)
	if abs, err := filepath.Abs(key); err == nil {
		key = abs
	}
	versionLocks.Lock()
	mu, ok := versionLocks.m[key]
	if !ok {
		mu = &sync.Mutex{}
		versionLocks.m[key] = mu
	}
	versionLocks.Unlock()
	mu.Lock()
	return mu.Unlock
}

// Open returns the cached asset of the version, after verifying its signature
// (and the ELF) again, and the signature. The caller closes the reader.
func (c *Cache) Open(version, asset string) (io.ReadCloser, []byte, error) {
	want, err := signed(version, asset)
	if err != nil {
		return nil, nil, err
	}
	p := c.path(version, asset)
	sig, err := os.ReadFile(p + ".minisig")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("%w: %s %s", ErrNotCached, version, asset)
	}
	if err != nil {
		return nil, nil, err
	}
	if _, err := c.verifyFile(p, sig, want); errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("%w: %s %s", ErrNotCached, version, asset)
	} else if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}
	return f, sig, nil
}

// Fetch downloads the assets (and their .minisig) of the version from the
// source and puts each into the cache. The first failure is returned; what
// was verified before it stays.
func (c *Cache) Fetch(ctx context.Context, src *Source, version string, assets []string) error {
	for _, a := range assets {
		if _, err := signed(version, a); err != nil {
			return err
		}
	}
	rel, err := src.Release(ctx, version)
	if err != nil {
		return err
	}
	urls := map[string]string{}
	for _, a := range rel.Assets {
		urls[a.Name] = a.URL
	}
	for _, a := range assets {
		u, s := urls[a], urls[a+".minisig"]
		if u == "" || s == "" {
			return fmt.Errorf("%w: %s %s with its .minisig", ErrNoAsset, version, a)
		}
		sig, err := src.download(ctx, s, maxSignature)
		if err != nil {
			return err
		}
		if err := c.fetchOne(ctx, src, version, a, u, sig); err != nil {
			return err
		}
	}
	return nil
}

// fetchOne streams the asset at u into Put.
func (c *Cache) fetchOne(ctx context.Context, src *Source, version, asset, u string, sig []byte) error {
	body, err := src.open(ctx, u)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()
	return c.Put(ctx, version, asset, body, sig)
}

// A ctxReader stops a read when its context is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// tempDir makes a directory under dir for an upload in progress, named so
// that it is never a version (".upload-<hex>").
func tempDir(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: the panel's data
		return "", err
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	p := filepath.Join(dir, ".upload-"+hex.EncodeToString(b[:]))
	if err := os.Mkdir(p, 0o755); err != nil { //nolint:gosec // G301: as above
		return "", err
	}
	return p, nil
}

// cachedSHA returns the SHA-256 of the cached asset of the version when it is
// there and verifies (signature and ELF); a file that is not there, or that
// no longer verifies, is reported as absent.
func (c *Cache) cachedSHA(version, asset string) (string, bool) {
	want, err := signed(version, asset)
	if err != nil {
		return "", false
	}
	p := c.path(version, asset)
	sig, err := os.ReadFile(p + ".minisig")
	if err != nil {
		return "", false
	}
	sha, err := c.verifyFile(p, sig, want)
	if err != nil {
		return "", false
	}
	return sha, true
}

// Sweep removes what an upload or a Put that was cut short left under the
// cache: the temporary ".upload-*" directories and ".put-*" files. The panel
// calls it at start, when no upload is in flight.
func (c *Cache) Sweep() error {
	entries, err := os.ReadDir(c.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".upload-") || strings.HasPrefix(e.Name(), ".put-") {
			if err := os.RemoveAll(filepath.Join(c.Dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// OpenNode opens the signed postern-node binary of the version for arch from
// the cache, after fetching it (and its signature) from the release source
// when the cache does not hold it yet. The caller closes the reader.
func (r *Releases) OpenNode(ctx context.Context, version, arch string) (io.ReadCloser, []byte, error) {
	if r.Cache == nil {
		return nil, nil, errors.New("selfupdate: no cache of releases")
	}
	asset := NodeAsset(arch)
	f, sig, err := r.Cache.Open(version, asset)
	if !errors.Is(err, ErrNotCached) {
		return f, sig, err
	}
	src, err := r.Source(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := r.Cache.Fetch(ctx, src, version, []string{asset}); err != nil {
		return nil, nil, err
	}
	return r.Cache.Open(version, asset)
}
