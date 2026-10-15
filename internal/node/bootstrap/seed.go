package bootstrap

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/urbnywrt/postern/internal/node/selfupdate"
	"github.com/urbnywrt/postern/internal/release"
)

const (
	binaryPrefix = "postern-node-"
	maxBinary    = 512 << 20
	maxSignature = 64 << 10
	maxLauncher  = 1 << 20
)

// seed puts the image's binary, signature and launcher into bin/, the way
// install.sh install_binary does, except that an older image never moves
// bin/current back: self-update went ahead of it.
//
//   - bin/postern-node-<v> is installed when it is not there; when it is there
//     with other content it is left alone (a version is never replaced), and
//     bin/current is not switched to it.
//   - bin/current that is missing points at the image's version. One that
//     points at an older version (release.Compare) is switched, and bin/previous
//     points at what it pointed at. An image whose version is not a version
//     (dev) only fills a missing bin/current.
//   - bin/launcher.sh is replaced when bin/current was missing or the image is
//     not older than it.
func (b *boot) seed() error {
	v := b.opt.Version
	if !release.ValidVersion(v) {
		return fmt.Errorf("bootstrap: the image's version %.70q cannot name a binary", v)
	}
	bin := b.path("bin")
	name := binaryPrefix + v
	conflict, err := b.installBinary(bin, name)
	if err != nil {
		return fmt.Errorf("bootstrap: install bin/%s: %w", name, err)
	}

	cur := currentTarget(bin)
	curV, _ := strings.CutPrefix(cur, binaryPrefix)
	switch {
	case cur == "":
		if err := setLink(bin, "current", name); err != nil {
			return fmt.Errorf("bootstrap: %w", err)
		}
		b.log.Info("bootstrap: bin/current is " + name)
	case cur == name || conflict:
	case !release.IsVersion(v):
		b.log.Info("bootstrap: the image's version is not a release; bin/current is kept", "current", cur, "image", v)
	case release.Compare(v, curV) > 0:
		if err := setLink(bin, "previous", cur); err != nil {
			return fmt.Errorf("bootstrap: %w", err)
		}
		if err := setLink(bin, "current", name); err != nil {
			return fmt.Errorf("bootstrap: %w", err)
		}
		b.log.Info("bootstrap: bin/current is "+name+", bin/previous "+cur, "image", v)
	default:
		b.log.Info("bootstrap: bin/current runs a version the image does not go beyond; it is kept", "current", cur, "image", v)
	}

	if !conflict {
		b.installSignature(bin, v)
	}
	if cur == "" || release.Compare(v, curV) >= 0 {
		if err := copyFileAtomic(b.opt.Launcher, filepath.Join(bin, "launcher.sh"), 0o755, maxLauncher); err != nil {
			if _, statErr := os.Stat(filepath.Join(bin, "launcher.sh")); statErr != nil {
				return fmt.Errorf("bootstrap: install bin/launcher.sh: %w", err)
			}
			b.log.Warn("bootstrap: cannot install the image's launcher.sh; the one in bin/ is kept", "err", err)
		}
	}
	return nil
}

// installBinary copies the image's binary to bin/<name>, staged in bin/ (so
// that a noexec /tmp is irrelevant) and renamed. conflict is true when
// bin/<name> is there with other content.
func (b *boot) installBinary(bin, name string) (conflict bool, err error) {
	sum, err := selfupdate.Hash(b.opt.Binary)
	if err != nil {
		return false, err
	}
	target := filepath.Join(bin, name)
	switch have, err := selfupdate.Hash(target); {
	case err == nil && bytes.Equal(have, sum):
		return false, nil
	case err == nil:
		b.log.Warn("bootstrap: bin/" + name + " is there with other content than the image's binary; a version is never replaced, so bin/current is not switched to the image")
		return true, nil
	case !errors.Is(err, os.ErrNotExist):
		return false, err
	}
	if err := copyFileAtomic(b.opt.Binary, target, 0o755, maxBinary); err != nil {
		return false, err
	}
	b.log.Info("bootstrap: installed bin/" + name)
	return false, nil
}

// installSignature keeps the image's signature as bin/.postern-node-<v>.minisig
// (0644), as install.sh and self-update do; the agent checks it before it
// rolls the edge. An image built from source has none.
func (b *boot) installSignature(bin, v string) {
	if b.opt.Signature == "" {
		return
	}
	if _, err := os.Stat(b.opt.Signature); errors.Is(err, os.ErrNotExist) {
		b.log.Info("bootstrap: the image has no signature of its binary; the edge rolls to " + v + " only while the agent runs it")
		return
	}
	dst := filepath.Join(bin, "."+binaryPrefix+v+".minisig")
	if err := copyFileAtomic(b.opt.Signature, dst, 0o644, maxSignature); err != nil {
		b.log.Warn("bootstrap: cannot keep the signature of the binary", "err", err)
	}
}

// currentTarget is the name bin/current points to, "" when it is missing or
// points at nothing.
func currentTarget(bin string) string {
	t, err := os.Readlink(filepath.Join(bin, "current"))
	if err != nil || t == "" {
		return ""
	}
	if _, err := os.Stat(filepath.Join(bin, "current")); err != nil {
		return ""
	}
	return filepath.Base(t)
}

// setLink makes bin/<link> a relative symlink to target in one rename, as
// install.sh set_link does.
func setLink(bin, link, target string) error {
	tmp := filepath.Join(bin, "."+link+".new."+randomHex(4))
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("point bin/%s at %s: %w", link, target, err)
	}
	if err := os.Rename(tmp, filepath.Join(bin, link)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("point bin/%s at %s: %w", link, target, err)
	}
	syncDir(bin)
	return nil
}
