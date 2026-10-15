package selfupdate

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/release"
)

// keepVersions is how many installed versions GC leaves at least.
const keepVersions = 3

// Binaries lists the agent binaries installed in home/bin, oldest first, the
// versions bin/current and bin/previous point to, and the installed versions
// whose signature is kept beside the binary (signaturePath, a regular file),
// which VerifyInstalled needs for any binary but the running agent's own.
func Binaries(home string) *nodev1.NodeBinaries {
	bin := filepath.Join(home, "bin")
	versions := installed(bin)
	var signed []string
	for _, v := range versions {
		if info, err := os.Lstat(signaturePath(bin, v)); err == nil && info.Mode().IsRegular() {
			signed = append(signed, v)
		}
	}
	return &nodev1.NodeBinaries{
		Versions:       versions,
		Current:        versionOf(linkTarget(bin, "current")),
		Previous:       versionOf(linkTarget(bin, "previous")),
		SignedVersions: signed,
	}
}

// GC removes old agent binaries from home/bin while more than three versions
// remain, oldest first. It never removes the binaries bin/current and
// bin/previous point to, nor one that keep keeps (it is given the absolute
// path). It also removes the temporary files an interrupted install left: it
// must not run beside Install. It returns the paths it removed.
func GC(home string, keep func(path string) bool) (removed []string) {
	bin := filepath.Join(home, "bin")
	entries, err := os.ReadDir(bin)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "."+filePrefix) && strings.Contains(e.Name(), ".tmp-") {
			p := filepath.Join(bin, e.Name())
			if os.Remove(p) == nil {
				removed = append(removed, p)
			}
		}
	}
	versions := installed(bin)
	kept := map[string]bool{linkTarget(bin, "current"): true, linkTarget(bin, "previous"): true}
	left := len(versions)
	for _, v := range versions {
		if left <= keepVersions {
			break
		}
		name := filePrefix + v
		p := filepath.Join(bin, name)
		if kept[name] || (keep != nil && keep(p)) {
			continue
		}
		if err := os.Remove(p); err == nil || errors.Is(err, fs.ErrNotExist) {
			_ = os.Remove(signaturePath(bin, v)) // the signature Install kept
			left--
			if err == nil {
				removed = append(removed, p)
			}
		}
	}
	return removed
}

// installed lists the versions of the regular files bin/postern-node-<version>,
// oldest first.
func installed(bin string) []string {
	entries, err := os.ReadDir(bin)
	if err != nil {
		return nil
	}
	var versions []string
	for _, e := range entries {
		v, ok := strings.CutPrefix(e.Name(), filePrefix)
		if !ok || v == "" || !e.Type().IsRegular() {
			continue
		}
		versions = append(versions, v)
	}
	slices.SortFunc(versions, release.Compare)
	return versions
}

// versionOf is the version of an installed binary's name, "" for another name.
func versionOf(name string) string {
	v, _ := strings.CutPrefix(name, filePrefix)
	if v == name {
		return ""
	}
	return v
}
