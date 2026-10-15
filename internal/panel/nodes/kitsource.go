package nodes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/release"
)

// KitSource gives the node binary that a new node is installed with: the
// version of the running panel when it can (see [PanelKit]). version is ""
// when the binary is not known to be of any version.
type KitSource interface {
	NodeBinary(ctx context.Context, arch string) (r io.ReadCloser, sig []byte, version string, err error)
}

// SignedReleases opens a signed postern-node binary of a release from the
// panel's cache of Postern's binaries, which fetches it from the release
// source when it is not cached yet (selfupdate.Releases.OpenNode). The binary
// and its signature were verified by a release key.
type SignedReleases interface {
	OpenNode(ctx context.Context, version, arch string) (io.ReadCloser, []byte, error)
}

// ErrNoBinary is returned by [PanelKit.Signed] when the panel has no signed
// node binary of the version for the architecture: neither the image kit nor
// the cache nor the release source.
var ErrNoBinary = errors.New("nodes: no signed node binary of the version")

// PanelKit is where the panel takes node binaries from: the kit of its image
// (<Dir>/<arch>/postern-node, with postern-node.minisig beside it in a
// release image) and its cache of signed releases.
type PanelKit struct {
	Dir      string         // the kit of the image ([DefaultKitDir]); "" for none
	Version  string         // the version of the running panel
	Releases SignedReleases // nil: the image kit alone
	// Keys gives the trusted public keys; nil is release.TrustedKeys.
	Keys func(release.KeySet) ([]minisign.PublicKey, error)
	Log  *slog.Logger // nil discards
}

var _ KitSource = (*PanelKit)(nil)

func (k *PanelKit) log() *slog.Logger {
	if k.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return k.Log
}

// imageBinary is the path of the node binary of the image kit for arch.
func (k *PanelKit) imageBinary(arch string) string {
	return filepath.Join(k.Dir, arch, kitBinary)
}

// openImage opens the binary of the image kit for arch, as the kit download
// would: a regular executable file.
func (k *PanelKit) openImage(arch string) (*os.File, error) {
	if k.Dir == "" {
		return nil, errors.New("no directory of the node kit is set")
	}
	f, _, err := openKitFile(k.imageBinary(arch), true)
	return f, err
}

// KitSigned opens the binary of the image kit for arch when its signature,
// beside it, verifies by a release key for postern-node of version on
// linux/arch: the image kit is then that version, signed (kit_signed).
func (k *PanelKit) KitSigned(version, arch string) (*os.File, []byte, error) {
	if !release.ValidVersion(version) {
		return nil, nil, fmt.Errorf("invalid version %q", version)
	}
	f, err := k.openImage(arch)
	if err != nil {
		return nil, nil, err
	}
	sig, err := readLimited(k.imageBinary(arch)+".minisig", 64<<10)
	if err == nil {
		err = k.verify(f, sig, version, arch)
	}
	if err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, sig, nil
}

func (k *PanelKit) verify(r io.Reader, sig []byte, version, arch string) error {
	keys := k.Keys
	if keys == nil {
		keys = release.TrustedKeys
	}
	list, err := keys(release.ReleaseKeys)
	if err != nil {
		return err
	}
	return release.VerifyWith(r, sig, release.Signed{Component: kitBinary, Version: version, OS: "linux", Arch: arch}, list)
}

// Known says, without a download, whether [PanelKit.Signed] can have the
// binary of version for arch: nil when the image kit is that version, signed,
// or when there is a cache of releases to fetch it into (whether the release
// has it shows when it is fetched).
func (k *PanelKit) Known(version, arch string) error {
	f, _, err := k.KitSigned(version, arch)
	if err == nil {
		_ = f.Close()
		return nil
	}
	if k.Releases != nil {
		return nil
	}
	return fmt.Errorf("the image kit is not %s, signed (%w), and there is no cache of releases", version, err)
}

// Signed opens the signed node binary of version for arch: the image kit
// when it is that version and its signature verifies, else the cache of
// releases, which fetches it on demand. It is [ErrNoBinary] (wrapped with the
// reason) when neither has it.
func (k *PanelKit) Signed(ctx context.Context, version, arch string) (io.ReadCloser, []byte, error) {
	f, sig, kitErr := k.KitSigned(version, arch)
	if kitErr == nil {
		return f, sig, nil
	}
	if k.Releases == nil {
		return nil, nil, fmt.Errorf("%w: %s for %s: the image kit: %w", ErrNoBinary, version, arch, kitErr)
	}
	r, sig, err := k.Releases.OpenNode(ctx, version, arch)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s for %s: the image kit: %w; the releases: %w", ErrNoBinary, version, arch, kitErr, err)
	}
	return r, sig, nil
}

// NodeBinary is the binary that the kit download and the SSH install send:
// the panel's version, from the image kit when it is that version and
// signed, else from the cache of releases (fetched on demand), else the image
// kit as it is, with a warning in the log that its version may differ from
// the panel's (version is "" then).
func (k *PanelKit) NodeBinary(ctx context.Context, arch string) (io.ReadCloser, []byte, string, error) {
	r, sig, err := k.Signed(ctx, k.Version, arch)
	if err == nil {
		return r, sig, k.Version, nil
	}
	f, ierr := k.openImage(arch)
	if ierr != nil {
		return nil, nil, "", fmt.Errorf("no node binary for %s: %w; the image kit: %w", arch, err, ierr)
	}
	k.log().Warn("the node kit sends the binary of the panel image, whose version may differ from the panel's: "+
		"no signed node binary of the panel's version", "arch", arch, "panel_version", k.Version, "reason", err.Error())
	sig, _ = readLimited(k.imageBinary(arch)+".minisig", 64<<10)
	return f, sig, "", nil
}

// readLimited reads a small file of at most limit bytes.
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a file of the kit directory
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}
