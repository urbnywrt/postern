// Package artifacts is the node's store of verified engine binaries.
//
// An artifact is one engine release for one CPU architecture, kept at
//
//	<Root>/<engine>/<version>/<arch>/<binary>
//
// next to a marker file, .sha256, holding the SHA-256 of the archive (or raw
// file) it was made from. The panel pins that checksum; the node never trusts
// one it computed itself. Put verifies the upload against the pinned value
// before anything is exposed, and only then moves the finished directory into
// place with a single rename, so a reader sees either the whole artifact or
// nothing, and a Put that fails leaves the store exactly as it was.
//
// The fields of a Ref name directories, and a Ref arrives from outside (the
// panel uploads it), so every one of them is checked to be a plain path element
// before it is used.
package artifacts

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

// Ref identifies one artifact.
type Ref struct {
	// Engine, Version and Arch name the directory of the artifact. Arch is
	// "amd64" or "arm64".
	Engine, Version, Arch string
	// SHA256 is the expected SHA-256 of the uploaded bytes (the archive, or the
	// raw file), as 64 hex digits in either case.
	SHA256 string
	// FileName is the name of the upload on the release page. A name ending in
	// .tar.gz (or .tgz) marks a gzip tar archive to take Binary from, a name
	// ending in .zip a zip archive (in either case of letters); any other name
	// marks the binary itself.
	FileName string
	// Binary is the name of the executable: the member to extract from an
	// archive, and the name it is stored under.
	Binary string
}

var (
	// ErrChecksum is returned (wrapped) by Put when the upload does not match
	// Ref.SHA256.
	ErrChecksum = errors.New("artifacts: checksum mismatch")

	// ErrInvalidRef is returned (wrapped) when a Ref cannot name an artifact: an
	// empty or unsafe path element, or a malformed checksum.
	ErrInvalidRef = errors.New("artifacts: invalid artifact reference")

	// ErrArchive is returned (wrapped) by Put when the upload matches its
	// checksum but is not usable: not an archive of the kind its name says (gzip
	// tar or zip), no regular file named Ref.Binary in it, that file is empty or
	// damaged, or the member named like it has a path that leaves the archive.
	ErrArchive = errors.New("artifacts: unusable archive")

	// ErrTooLarge is returned (wrapped) by Put when the upload, or the binary
	// inside it, exceeds the size limits.
	ErrTooLarge = errors.New("artifacts: too large")
)

// Size limits. They are generous (engine binaries are tens of megabytes; the
// agent accepts uploads of up to 200 MiB) and exist to bound disk use by a
// misbehaving sender and by a decompression bomb. Variables so that tests can
// shrink them.
var (
	maxArchiveBytes int64 = 512 << 20
	maxBinaryBytes  int64 = 1 << 30
)

const (
	// markerName is the file in an artifact directory that records the checksum.
	markerName = ".sha256"
	// stagePrefix starts the names of the scratch directories under Root. The
	// element check below refuses names that start with a dot, so no artifact
	// can ever collide with one.
	stagePrefix = ".stage-"

	maxElementLen = 64
)

// commitMu serialises the short steps that create and remove directories (and
// the final swap), so concurrent Puts cannot undo each other's work. Streaming
// an upload happens outside of it.
var commitMu sync.Mutex

// Store is a directory of artifacts. The zero value is not usable; Root must be
// an absolute path.
type Store struct {
	// Root is the directory of the store, $POSTERN_HOME/data/artifacts.
	Root string
}

// Validate reports whether the reference can name an artifact: the engine,
// version, architecture and binary name must each be a single plain path
// element, and the checksum 64 hex digits. The error matches ErrInvalidRef.
func (r Ref) Validate() error {
	if err := r.validatePath(); err != nil {
		return err
	}
	if err := validElement("binary", r.Binary); err != nil {
		return err
	}
	if !validSHA256(r.SHA256) {
		return fmt.Errorf("%w: checksum must be 64 hex digits", ErrInvalidRef)
	}
	return nil
}

// validatePath checks the parts of the reference that make up its directory.
func (r Ref) validatePath() error {
	for _, f := range [...]struct{ what, value string }{
		{"engine", r.Engine}, {"version", r.Version}, {"arch", r.Arch},
	} {
		if err := validElement(f.what, f.value); err != nil {
			return err
		}
	}
	return nil
}

// validElement accepts 1 to 64 characters of [A-Za-z0-9._+-] that start with a
// letter or a digit. That covers every engine, version (3.5.13, v2.1.7-rc.1+b5)
// and architecture name, and excludes everything that could leave the store or
// collide with its own files: separators, "." and "..", the dot-prefixed
// markers and scratch directories, NUL and other control characters, spaces,
// and ":" (which would corrupt a Docker bind mount spec).
func validElement(what, s string) error {
	if s == "" || len(s) > maxElementLen {
		return fmt.Errorf("%w: %s must be 1 to %d characters, got %d", ErrInvalidRef, what, maxElementLen, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-' || c == '+'):
		default:
			return fmt.Errorf("%w: %s %.64q has a character that is not allowed in a path element", ErrInvalidRef, what, s)
		}
	}
	return nil
}

func validSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// slot returns the directory of the artifact.
func (s *Store) slot(ref Ref) (string, error) {
	if !filepath.IsAbs(s.Root) {
		return "", fmt.Errorf("artifacts: store root %q is not an absolute path", s.Root)
	}
	if err := ref.validatePath(); err != nil {
		return "", err
	}
	return filepath.Join(s.Root, ref.Engine, ref.Version, ref.Arch), nil
}

// Dir returns the directory of the artifact, Root/<engine>/<version>/<arch>. It
// is empty when the reference or the store cannot name one (see Ref.Validate).
func (s *Store) Dir(ref Ref) string {
	dir, err := s.slot(ref)
	if err != nil {
		return ""
	}
	return dir
}

// BinaryPath returns the path of the executable, Dir/<binary>, or "" like Dir.
func (s *Store) BinaryPath(ref Ref) string {
	dir, err := s.slot(ref)
	if err != nil || validElement("binary", ref.Binary) != nil {
		return ""
	}
	return filepath.Join(dir, ref.Binary)
}

// Has reports whether the artifact is stored and was verified against
// ref.SHA256: the binary is there as a regular file, and the marker next to it
// holds the same checksum. It does not read the binary again.
func (s *Store) Has(ref Ref) bool {
	if ref.Validate() != nil {
		return false
	}
	dir, err := s.slot(ref)
	if err != nil {
		return false
	}
	// Lstat: a symlink in place of the binary is not what Put wrote.
	info, err := os.Lstat(filepath.Join(dir, ref.Binary))
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(filepath.Join(dir, markerName))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	marker, err := io.ReadAll(io.LimitReader(f, 256))
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(string(marker)), ref.SHA256)
}

// Put stores an artifact. It streams r to a scratch file inside the store,
// verifies the SHA-256 of the stream against ref.SHA256 (ErrChecksum), takes the
// binary out of the archive (ErrArchive), makes it executable (0755), writes the
// .sha256 marker and moves the finished directory into place with one rename.
// An artifact already stored in the same place is replaced.
//
// A Put that fails, for whatever reason, leaves the store as it found it: no
// scratch files, no half-written artifact, no new directories, and an artifact
// that was there before is untouched.
func (s *Store) Put(ref Ref, r io.Reader) (err error) {
	if err := ref.Validate(); err != nil {
		return err
	}
	final, err := s.slot(ref)
	if err != nil {
		return err
	}
	want := strings.ToLower(ref.SHA256)

	stage, created, err := s.newStage()
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(stage)
		if err != nil {
			commitMu.Lock()
			forget(created)
			commitMu.Unlock()
		}
	}()

	archive := filepath.Join(stage, "upload")
	got, err := receive(archive, r)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%w: %.64q has sha256 %s, expected %s", ErrChecksum, ref.FileName, got, want)
	}

	// Build the finished directory next to the upload, then move it as a whole.
	out := filepath.Join(stage, "artifact")
	if err := os.Mkdir(out, 0o755); err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	binary := filepath.Join(out, ref.Binary)
	switch {
	case isTarGz(ref.FileName):
		err = extractTarGz(archive, ref.Binary, binary)
	case isZip(ref.FileName):
		err = extractZip(archive, ref.Binary, binary)
	default:
		err = installRaw(archive, binary)
	}
	if err != nil {
		return err
	}
	if err := writeFileSync(filepath.Join(out, markerName), []byte(want+"\n"), 0o644); err != nil {
		return fmt.Errorf("artifacts: writing the checksum marker: %w", err)
	}
	syncDir(out)

	return commit(out, final)
}

// newStage creates a scratch directory inside Root, and Root itself if it is
// missing. created lists the directories it had to make, for forget.
func (s *Store) newStage() (stage string, created []string, err error) {
	commitMu.Lock()
	defer commitMu.Unlock()
	if created, err = mkdirAll(s.Root); err != nil {
		return "", nil, err
	}
	if stage, err = os.MkdirTemp(s.Root, stagePrefix+"*"); err != nil {
		forget(created)
		return "", nil, fmt.Errorf("artifacts: %w", err)
	}
	return stage, created, nil
}

// receive copies the upload into a new file at path and returns its SHA-256.
func receive(path string, r io.Reader) (sum string, err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("artifacts: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("artifacts: %w", cerr)
		}
	}()
	h := sha256.New()
	// One byte more than the limit tells "exactly at the limit" from "over it".
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, maxArchiveBytes+1))
	if err != nil {
		return "", fmt.Errorf("artifacts: receiving the upload: %w", err)
	}
	if n > maxArchiveBytes {
		return "", fmt.Errorf("%w: the upload is over %d bytes", ErrTooLarge, maxArchiveBytes)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("artifacts: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isTarGz(name string) bool {
	name = strings.ToLower(name)
	return strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz")
}

func isZip(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".zip")
}

// installRaw makes the upload itself the binary.
func installRaw(upload, dst string) error {
	info, err := os.Stat(upload)
	if err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("%w: the binary is empty", ErrArchive)
	}
	if err := os.Rename(upload, dst); err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	if err := os.Chmod(dst, 0o755); err != nil { // not the umask's business
		return fmt.Errorf("artifacts: %w", err)
	}
	return nil
}

// extractTarGz copies the first regular file of the archive that is called
// binary (at the top, or in a directory) to dst. Nothing else is extracted, and
// no name from the archive is used as a path: dst is fixed by the caller, so a
// hostile member name or link cannot place a file anywhere. A member named like
// the binary whose path leaves the archive (see unsafeMemberName) is refused.
func extractTarGz(archive, binary, dst string) error {
	f, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("%w: not a gzip stream: %w", ErrArchive, err)
	}
	defer func() { _ = zr.Close() }()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: no regular file %q in the archive", ErrArchive, binary)
		}
		if err != nil {
			return fmt.Errorf("%w: reading the archive: %w", ErrArchive, err)
		}
		if !isMember(hdr.Name, binary) {
			continue
		}
		if unsafeMemberName(hdr.Name) {
			return fmt.Errorf("%w: the member named %.64q has an unsafe path", ErrArchive, hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		return writeBinary(dst, tr)
	}
}

// extractZip is extractTarGz for a zip archive: it copies the first regular
// file of the archive that is called binary (at the top, or in a directory) to
// dst, and nothing else. Links and directories are skipped. A member whose
// declared size is over maxBinaryBytes is refused before anything of it is
// read, and the size of what is read is bounded anyway (the reader checks the
// declared size and the CRC of every member as it goes).
func extractZip(archive, binary, dst string) error {
	zr, err := zip.OpenReader(archive)
	if errors.Is(err, zip.ErrInsecurePath) {
		// Only with GODEBUG=zipinsecurepath=0: some member has a path that
		// leaves the archive. The reader is open all the same.
		if zr != nil {
			_ = zr.Close()
		}
		return fmt.Errorf("%w: a member has an unsafe path", ErrArchive)
	}
	if err != nil {
		return fmt.Errorf("%w: not a zip archive: %w", ErrArchive, err)
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if !isMember(f.Name, binary) {
			continue
		}
		if unsafeMemberName(f.Name) {
			return fmt.Errorf("%w: the member named %.64q has an unsafe path", ErrArchive, f.Name)
		}
		if !f.Mode().IsRegular() {
			continue
		}
		if f.UncompressedSize64 > uint64(maxBinaryBytes) {
			return fmt.Errorf("%w: the binary is over %d bytes", ErrTooLarge, maxBinaryBytes)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("%w: reading the archive: %w", ErrArchive, err)
		}
		defer func() { _ = rc.Close() }()
		return writeBinary(dst, rc)
	}
	return fmt.Errorf("%w: no regular file %q in the archive", ErrArchive, binary)
}

// isMember reports whether an archive member name is binary, either exactly
// (also with a leading "./") or as the last element of a path.
func isMember(name, binary string) bool {
	name = path.Clean(name)
	return name == binary || path.Base(name) == binary
}

// unsafeMemberName reports whether an archive member name is a path that leaves
// the archive: absolute, with a ".." element, or with a backslash (a separator
// to some readers) or a NUL in it. No name from an archive is ever used as a
// path here, but a release archive with such a member is not one to trust: the
// readers refuse it when the member is named like the binary.
func unsafeMemberName(name string) bool {
	if strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") {
		return true
	}
	for elem := range strings.SplitSeq(name, "/") {
		if elem == ".." {
			return true
		}
	}
	return false
}

// writeBinary writes src to a new file dst with mode 0755. Reading src fails
// with ErrArchive (it is the archive that is broken), writing dst fails with
// the plain I/O error.
func writeBinary(dst string, src io.Reader) (err error) {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("artifacts: %w", cerr)
		}
	}()
	var total int64
	buf := make([]byte, 64<<10)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxBinaryBytes {
				return fmt.Errorf("%w: the binary is over %d bytes", ErrTooLarge, maxBinaryBytes)
			}
			if _, werr := f.Write(buf[:n]); werr != nil {
				return fmt.Errorf("artifacts: %w", werr)
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return fmt.Errorf("%w: reading the binary: %w", ErrArchive, rerr)
		}
	}
	if total == 0 {
		return fmt.Errorf("%w: the binary is empty", ErrArchive)
	}
	if err := f.Chmod(0o755); err != nil { // not the umask's business
		return fmt.Errorf("artifacts: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("artifacts: %w", err)
	}
	return nil
}

func writeFileSync(path string, data []byte, perm os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		return err
	}
	return f.Sync()
}

// commit moves the finished directory out to its place, replacing what is
// there. The previous artifact is renamed aside first and removed only after the
// new one is in place, and put back if the swap fails.
func commit(out, final string) error {
	commitMu.Lock()
	defer commitMu.Unlock()

	parent := filepath.Dir(final)
	created, err := mkdirAll(parent)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		forget(created)
		return err
	}

	// The artifact directory is 0755 like the directories above it; MkdirTemp
	// made the scratch directory private (and Mkdir obeys the umask).
	if err := os.Chmod(out, 0o755); err != nil {
		return fail(fmt.Errorf("artifacts: %w", err))
	}

	var old string
	switch _, err := os.Lstat(final); {
	case err == nil:
		old = filepath.Join(parent, "."+filepath.Base(final)+".old-"+rand.Text()[:10])
		if err := os.Rename(final, old); err != nil {
			return fail(fmt.Errorf("artifacts: %w", err))
		}
	case !errors.Is(err, fs.ErrNotExist):
		return fail(fmt.Errorf("artifacts: %w", err))
	}

	if err := os.Rename(out, final); err != nil {
		if old != "" {
			_ = os.Rename(old, final)
		}
		return fail(fmt.Errorf("artifacts: installing the artifact: %w", err))
	}
	syncDir(parent)
	if old != "" {
		_ = os.RemoveAll(old)
	}
	return nil
}

// mkdirAll is os.MkdirAll that also returns the directories it created, the
// shallowest first, so that a failed operation can take them away again. A
// directory that someone else creates in the meantime is not reported.
func mkdirAll(dir string) (created []string, err error) {
	var missing []string
	for d := dir; ; {
		info, err := os.Stat(d)
		if err == nil {
			if !info.IsDir() {
				return nil, fmt.Errorf("artifacts: %s is not a directory", d)
			}
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("artifacts: %w", err)
		}
		missing = append(missing, d)
		up := filepath.Dir(d)
		if up == d {
			break
		}
		d = up
	}
	for i := len(missing) - 1; i >= 0; i-- {
		err := os.Mkdir(missing[i], 0o755)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err == nil {
			// Not the umask's business: the layout is the same whoever runs the agent.
			err = os.Chmod(missing[i], 0o755)
		}
		if err != nil {
			_ = os.Remove(missing[i])
			forget(created)
			return nil, fmt.Errorf("artifacts: %w", err)
		}
		created = append(created, missing[i])
	}
	return created, nil
}

// forget removes the directories mkdirAll created, deepest first, as far as they
// are empty. The caller holds commitMu.
func forget(created []string) {
	for i := len(created) - 1; i >= 0; i-- {
		_ = os.Remove(created[i])
	}
}

// syncDir flushes a directory's entries to disk. It is best effort: not every
// file system supports it, and the atomicity of the rename does not depend on it.
func syncDir(dir string) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}
