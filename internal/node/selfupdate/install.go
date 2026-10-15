// Package selfupdate installs a signed postern-node binary as the node agent's
// next version, the way the launcher (deploy/node/launcher.sh) expects it:
// bin/postern-node-<version>, with relative bin/current and bin/previous
// symlinks that are switched by rename. The launcher starts bin/current, and
// goes back to bin/previous by itself when the new binary does not come up
// healthy in three starts.
package selfupdate

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"aead.dev/minisign"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/release"
)

const (
	// MaxSize is the largest binary that Install takes.
	MaxSize = 200 << 20

	// component is the name of the node binary in a trusted comment.
	component = "postern-node"
	// filePrefix names the installed binaries: bin/postern-node-<version>.
	filePrefix = "postern-node-"

	// trialTimeout bounds "<file> version", and maxTrialOutput what of its
	// output is kept.
	trialTimeout   = 10 * time.Second
	maxTrialOutput = 4 << 10
)

// The errors of Install, which the agent turns into gRPC codes.
var (
	// ErrInvalid: the meta is not one of a binary this node can take.
	ErrInvalid = errors.New("selfupdate: invalid binary meta")
	// ErrTooLarge: the binary is over MaxSize.
	ErrTooLarge = errors.New("selfupdate: the binary is too large")
	// ErrChecksum: the data is not what the meta says (size, SHA-256).
	ErrChecksum = errors.New("selfupdate: the binary does not match its meta")
	// ErrSignature: the signature is not good, not by a trusted release key,
	// or for another artifact.
	ErrSignature = errors.New("selfupdate: the signature is refused")
	// ErrDowngrade: an older version without a rollback to bin/previous.
	ErrDowngrade = errors.New("selfupdate: downgrade refused")
	// ErrUnusable: not a static ELF for this node, or its trial failed.
	ErrUnusable = errors.New("selfupdate: the binary cannot run here")
	// ErrExists: the version is installed with other content.
	ErrExists = errors.New("selfupdate: the version is installed with other content")
	// ErrNotInstalled: VerifyInstalled finds no binary of the version.
	ErrNotInstalled = errors.New("selfupdate: the version is not installed")
	// ErrNoKeys: this build trusts no release key, and so installs nothing.
	ErrNoKeys = errors.New("this node build trusts no release key")
)

// Installer installs node binaries into Home/bin.
type Installer struct {
	// Home is POSTERN_HOME.
	Home string
	// Arch is the architecture of the node (runtime.GOARCH when empty).
	Arch string
	// Running is the version of the running agent.
	Running string
	// Keys returns the trusted keys of a set; nil is release.TrustedKeys.
	Keys func(release.KeySet) ([]minisign.PublicKey, error)
	// Exec runs a program and returns its standard output; nil runs it.
	Exec func(ctx context.Context, path string, args ...string) ([]byte, error)
	// SelfExe is the binary that the process runs, which isOwn opens and
	// hashes; "" is /proc/self/exe, which names the running file whatever a
	// path names now. Tests name a file.
	SelfExe string
}

// Install reads the binary that meta describes from r, verifies it and makes
// it bin/current, what bin/current pointed to becoming bin/previous. It
// returns changed=false when bin/current already pointed at that version.
// On an error nothing is changed and nothing is left behind.
func (i *Installer) Install(ctx context.Context, meta *nodev1.NodeBinary, r io.Reader) (changed bool, err error) {
	v, arch, sum, err := i.checkMeta(meta)
	if err != nil {
		return false, err
	}
	keys, err := i.keys()
	if err != nil {
		return false, err
	}
	bin := filepath.Join(i.Home, "bin")
	name := filePrefix + v
	final := filepath.Join(bin, name)
	cur, prev := linkTarget(bin, "current"), linkTarget(bin, "previous")
	if err := i.checkDirection(v, name, prev, meta.GetRollback()); err != nil {
		return false, err
	}
	exists, err := existing(final, sum, v)
	if err != nil {
		return false, err
	}

	tmp, err := receive(bin, name, r, meta.GetSize(), sum)
	if err != nil {
		return false, err
	}
	defer func() {
		if tmp != "" {
			_ = os.Remove(tmp)
		}
	}()
	if err := verify(tmp, meta.GetSignature(), v, arch, keys); err != nil {
		return false, err
	}
	if err := i.try(ctx, tmp, v); err != nil {
		return false, err
	}
	// What goes into bin/ is what was verified: the file is hashed again
	// right before the rename, after the signature check and the trial.
	if err := Rehash(tmp, sum); err != nil {
		return false, err
	}
	// The signature stays beside the binary, so that UpdateEdge verifies the
	// file as this call did (VerifyInstalled).
	if err := writeSignature(bin, v, meta.GetSignature()); err != nil {
		return false, err
	}

	if !exists {
		if err := os.Rename(tmp, final); err != nil {
			return false, fmt.Errorf("selfupdate: installing %s: %w", name, err)
		}
		tmp = ""
	}
	if cur == name {
		return false, nil
	}
	if err := switchLinks(bin, cur, prev, name); err != nil {
		if !exists {
			_ = os.Remove(final)
		}
		return false, err
	}
	syncDir(bin)
	return true, nil
}

// checkMeta checks what the meta says before anything is read.
func (i *Installer) checkMeta(meta *nodev1.NodeBinary) (v, arch string, sum []byte, err error) {
	arch = i.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	if meta == nil {
		return "", "", nil, fmt.Errorf("%w: no meta", ErrInvalid)
	}
	v = meta.GetVersion()
	switch {
	case !release.ValidVersion(v):
		return "", "", nil, fmt.Errorf("%w: invalid version %.64q", ErrInvalid, v)
	case meta.GetArch() != arch:
		return "", "", nil, fmt.Errorf("%w: the binary is for %.32q, and this node is %s", ErrInvalid, meta.GetArch(), arch)
	case meta.GetSize() == 0:
		return "", "", nil, fmt.Errorf("%w: no size", ErrInvalid)
	case meta.GetSize() > MaxSize:
		return "", "", nil, fmt.Errorf("%w: %d bytes, over %d", ErrTooLarge, meta.GetSize(), MaxSize)
	case meta.GetSignature() == "":
		return "", "", nil, fmt.Errorf("%w: no signature", ErrInvalid)
	}
	sum, err = hex.DecodeString(meta.GetSha256())
	if err != nil || len(sum) != sha256.Size {
		return "", "", nil, fmt.Errorf("%w: sha256 is not 64 hex digits", ErrInvalid)
	}
	return v, arch, sum, nil
}

func (i *Installer) keys() ([]minisign.PublicKey, error) {
	get := i.Keys
	if get == nil {
		get = release.TrustedKeys
	}
	keys, err := get(release.ReleaseKeys)
	if errors.Is(err, release.ErrNoKeys) || (err == nil && len(keys) == 0) {
		return nil, ErrNoKeys
	}
	if err != nil {
		return nil, fmt.Errorf("selfupdate: the release keys of this build: %w", err)
	}
	return keys, nil
}

// checkDirection refuses a downgrade: a version older than the running one
// goes in only as a rollback, and a rollback goes only to bin/previous.
// Versions are told apart by their strings; Compare only orders them.
func (i *Installer) checkDirection(v, name, prev string, rollback bool) error {
	if rollback {
		if prev == "" || prev != name {
			return fmt.Errorf("%w: a rollback goes only to bin/previous (%s), not to %s", ErrDowngrade, orNone(prev), v)
		}
		return nil
	}
	if release.Compare(v, i.Running) < 0 {
		return fmt.Errorf("%w: %s is older than the running %s; only a rollback to bin/previous installs an older version", ErrDowngrade, v, i.Running)
	}
	return nil
}

// existing reports whether the version is installed with the content sum, and
// refuses one with other content: bin/current or bin/previous may run it.
func existing(path string, sum []byte, v string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("selfupdate: %w", err)
	}
	other := fmt.Errorf("%w: version %s exists with other content", ErrExists, v)
	if !info.Mode().IsRegular() {
		return false, other
	}
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("selfupdate: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, fmt.Errorf("selfupdate: reading %s: %w", path, err)
	}
	if !bytes.Equal(h.Sum(nil), sum) {
		return false, other
	}
	return true, nil
}

// receive writes the binary to bin/.<name>.tmp-* and checks its size and
// SHA-256. It returns the temporary file, or removes it.
func receive(bin, name string, r io.Reader, size uint64, sum []byte) (path string, err error) {
	if err := os.MkdirAll(bin, 0o755); err != nil { //nolint:gosec // G301: bin/ is install.sh's, 0755: the launcher and the edges run its programs
		return "", fmt.Errorf("selfupdate: %w", err)
	}
	f, err := os.CreateTemp(bin, "."+name+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("selfupdate: %w", err)
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, int64(size)+1))
	if err != nil {
		return "", err
	}
	switch {
	case uint64(n) > size:
		return "", fmt.Errorf("%w: more than the %d bytes of the meta", ErrChecksum, size)
	case uint64(n) < size:
		return "", fmt.Errorf("%w: %d bytes, and the meta says %d", ErrChecksum, n, size)
	case !bytes.Equal(h.Sum(nil), sum):
		return "", fmt.Errorf("%w: SHA-256 %x, and the meta says %x", ErrChecksum, h.Sum(nil), sum)
	}
	if err := f.Chmod(0o755); err != nil {
		return "", fmt.Errorf("selfupdate: %w", err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("selfupdate: %w", err)
	}
	// Closed before it runs: a file open for writing cannot be executed.
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("selfupdate: %w", err)
	}
	return f.Name(), nil
}

// signaturePath is where the signature of bin/postern-node-<v> is kept:
// bin/.postern-node-<v>.minisig (a dot file, which no listing of the installed
// versions takes for one).
func signaturePath(bin, v string) string {
	return filepath.Join(bin, "."+filePrefix+v+".minisig")
}

// writeSignature keeps the signature of version v in bin/, in one rename.
func writeSignature(bin, v, sig string) error {
	path := signaturePath(bin, v)
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(sig), 0o644); err != nil { //nolint:gosec // G306: a signature is public
		_ = os.Remove(tmp)
		return fmt.Errorf("selfupdate: keeping the signature: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("selfupdate: keeping the signature: %w", err)
	}
	return nil
}

// VerifyInstalled checks the installed bin/postern-node-<v> before an edge
// runs it (UpdateEdge), as strictly as Install checks a new one: a regular
// executable file; signed by a release key for postern-node <v> linux/<arch>,
// by the signature Install kept beside it, unless it is the running agent's
// own binary (own, a path; v must be the running version and the contents
// the same); a static ELF for the node; "<file> version" prints "<v> (".
// exec runs it (nil: the Installer's Exec). It returns the file's SHA-256,
// which the caller checks again right before use (Rehash). Errors: ErrInvalid
// (an invalid version), ErrNotInstalled, ErrSignature, ErrUnusable, ErrNoKeys.
func (i *Installer) VerifyInstalled(ctx context.Context, v, own string, exec func(ctx context.Context, path string, args ...string) ([]byte, error)) (path string, sum []byte, err error) {
	if !release.ValidVersion(v) {
		return "", nil, fmt.Errorf("%w: invalid version %.64q", ErrInvalid, v)
	}
	arch := i.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	bin := filepath.Join(i.Home, "bin")
	path = filepath.Join(bin, filePrefix+v)
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", nil, fmt.Errorf("%w: bin/%s%s (UpdateSelf or install.sh installs it)", ErrNotInstalled, filePrefix, v)
	case err != nil:
		return "", nil, fmt.Errorf("selfupdate: %w", err)
	case !info.Mode().IsRegular():
		return "", nil, fmt.Errorf("%w: bin/%s%s is not a regular file", ErrUnusable, filePrefix, v)
	case info.Mode().Perm()&0o111 == 0:
		return "", nil, fmt.Errorf("%w: bin/%s%s is not executable", ErrUnusable, filePrefix, v)
	}
	sum, err = Hash(path)
	if err != nil {
		return "", nil, fmt.Errorf("selfupdate: %w", err)
	}
	if !i.isOwn(v, own, sum) {
		sig, err := os.ReadFile(signaturePath(bin, v))
		if err != nil {
			return "", nil, fmt.Errorf("%w: bin/%s%s has no signature kept by UpdateSelf (%v)", ErrSignature, filePrefix, v, err)
		}
		keys, err := i.keys()
		if err != nil {
			return "", nil, err
		}
		if err := verify(path, string(sig), v, arch, keys); err != nil {
			return "", nil, err
		}
	} else if err := checkELF(path, arch); err != nil {
		return "", nil, err
	}
	if exec == nil {
		exec = i.Exec
	}
	if err := CheckVersion(ctx, exec, path, v); err != nil {
		return "", nil, err
	}
	return path, sum, nil
}

// isOwn reports whether the file of version v, whose SHA-256 is sum, is the
// running agent's own binary: v is the running version, the agent has an own
// binary (own), and sum is the SHA-256 of the binary that the process runs,
// read through the open SelfExe (/proc/self/exe), not through own, a path
// whose file may have been replaced since the agent started (M1).
func (i *Installer) isOwn(v, own string, sum []byte) bool {
	if own == "" || v != i.Running {
		return false
	}
	ownSum, err := Hash(cmp.Or(i.SelfExe, "/proc/self/exe"))
	return err == nil && bytes.Equal(ownSum, sum)
}

// verify checks the signature of the file, by a release key, for
// postern-node <v> linux/<arch>, then that it is a static ELF for arch.
func verify(path, sig, v, arch string, keys []minisign.PublicKey) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("selfupdate: %w", err)
	}
	defer func() { _ = f.Close() }()
	want := release.Signed{Component: component, Version: v, OS: "linux", Arch: arch}
	err = release.VerifyWith(f, []byte(sig), want, keys)
	switch {
	case errors.Is(err, release.ErrUntrustedKey), errors.Is(err, release.ErrBadSignature), errors.Is(err, release.ErrWrongArtifact):
		return fmt.Errorf("%w: %w", ErrSignature, err)
	case err != nil:
		return fmt.Errorf("selfupdate: verifying the signature: %w", err)
	}
	return checkELFOf(f, arch)
}

// checkELF checks that the file is a static ELF for arch (ErrUnusable).
func checkELF(path, arch string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("selfupdate: %w", err)
	}
	defer func() { _ = f.Close() }()
	return checkELFOf(f, arch)
}

func checkELFOf(f *os.File, arch string) error {
	err := release.CheckStaticELF(f, arch)
	switch {
	case errors.Is(err, release.ErrNotELF), errors.Is(err, release.ErrWrongArch), errors.Is(err, release.ErrDynamic):
		return fmt.Errorf("%w: %w", ErrUnusable, err)
	case err != nil:
		return fmt.Errorf("selfupdate: checking the ELF headers: %w", err)
	}
	return nil
}

// Hash returns the SHA-256 of a file.
func Hash(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// Rehash checks that the file still has the SHA-256 sum (ErrChecksum).
func Rehash(path string, sum []byte) error {
	got, err := Hash(path)
	if err != nil {
		return fmt.Errorf("selfupdate: hashing %s again: %w", filepath.Base(path), err)
	}
	if !bytes.Equal(got, sum) {
		return fmt.Errorf("%w: %s changed after it was verified (SHA-256 %x, verified %x)", ErrChecksum, filepath.Base(path), got, sum)
	}
	return nil
}

// try runs "<file> version", which must print "<v> (".
func (i *Installer) try(ctx context.Context, path, v string) error {
	return CheckVersion(ctx, i.Exec, path, v)
}

// CheckVersion runs "<path> version" with exec (nil: the program itself, for
// at most 10 s) and checks that it prints "<v> (" (ErrUnusable).
func CheckVersion(ctx context.Context, exec func(ctx context.Context, path string, args ...string) ([]byte, error), path, v string) error {
	run := exec
	if run == nil {
		run = runProgram
	}
	ctx, cancel := context.WithTimeout(ctx, trialTimeout)
	defer cancel()
	out, err := run(ctx, path, "version")
	if err != nil {
		return fmt.Errorf("%w: running %s version: %v", ErrUnusable, filepath.Base(path), err)
	}
	if !strings.HasPrefix(string(out), v+" (") {
		if len(out) > 80 {
			out = out[:80]
		}
		return fmt.Errorf("%w: it says it is %q, not %s", ErrUnusable, out, v)
	}
	return nil
}

// runProgram runs a program and returns the start of its standard output.
func runProgram(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // G204: the binary that was just verified, by its signature
	var out limitedBuffer
	out.max = maxTrialOutput
	cmd.Stdout = &out
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	return out.Bytes(), err
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// switchLinks points bin/previous at what bin/current pointed to (cur, when
// there was one) and bin/current at name. If bin/current cannot be switched,
// bin/previous is put back.
func switchLinks(bin, cur, prev, name string) error {
	if cur != "" {
		if err := setLink(bin, "previous", cur); err != nil {
			return err
		}
	}
	if err := setLink(bin, "current", name); err != nil {
		if cur != "" {
			if prev != "" {
				_ = setLink(bin, "previous", prev)
			} else {
				_ = os.Remove(filepath.Join(bin, "previous"))
			}
		}
		return err
	}
	return nil
}

// setLink makes bin/<link> a relative symlink to target: a new link beside it,
// renamed over it.
func setLink(bin, link, target string) error {
	tmp := filepath.Join(bin, "."+link+".selfupdate")
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("selfupdate: pointing bin/%s at %s: %w", link, target, err)
	}
	if err := os.Rename(tmp, filepath.Join(bin, link)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("selfupdate: pointing bin/%s at %s: %w", link, target, err)
	}
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// linkTarget is the name that bin/<link> points to, "" when it is no link.
func linkTarget(bin, link string) string {
	t, err := os.Readlink(filepath.Join(bin, link))
	if err != nil || t == "" {
		return ""
	}
	return filepath.Base(t)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
