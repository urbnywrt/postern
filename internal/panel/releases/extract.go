package releases

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

// The bounds of extraction.
const (
	maxBinary      = 256 << 20       // the most that an extracted binary may hold
	extractTimeout = 5 * time.Minute // for the whole of one extraction and check
)

// What an archive may inflate to in all, and how many entries a zip may list:
// a small archive that inflates to gigabytes is not a release of a binary, and
// is not read to its end. Variables so that the tests can lower them.
var (
	maxInflate    int64 = 1 << 30
	maxZipEntries       = 10000
)

// The findings of extraction. Each is a verdict on the archive: it is the
// archive that is wrong, not the network or the disk.
var (
	ErrNoMember        = errors.New("releases: the archive has no regular file at the binary's path")
	ErrDuplicateMember = errors.New("releases: the archive has two members at the binary's path")
	ErrBinaryTooLarge  = errors.New("releases: the binary in the archive is larger than 256 MiB")
	ErrArchive         = errors.New("releases: the archive cannot be read")
)

// isTarGz reports whether name is a gzip-compressed tar.
func isTarGz(name string) bool {
	return strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz")
}

// isZip reports whether name is a zip.
func isZip(name string) bool { return strings.HasSuffix(name, ".zip") }

// memberMatches reports whether an archive member name is member: its cleaned
// path has to be equal. A name that is absolute, that leaves the archive's
// root (".."), or that has a backslash never matches, so no such member is
// read, let alone written. A nested file with the right base name
// ("sub/telemt") does not match "telemt".
func memberMatches(name, member string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	clean := path.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return false
	}
	return clean == member
}

// extractMember copies the one regular file at member in the archive at src
// (a .tar.gz or a .zip, by its name; any other name is the binary itself, as
// the node's artifact store takes it) to dst, a file that it creates with
// O_EXCL. Links, directories and devices are not followed and not written,
// whatever their names; two regular files at the path are ErrDuplicateMember;
// none is ErrNoMember; one of more than maxBinary bytes is ErrBinaryTooLarge;
// an archive that inflates past maxInflate in all, or a zip of more than
// maxZipEntries entries, is ErrArchive. The reads stop with ctx. dst is
// removed when extraction fails.
func extractMember(ctx context.Context, src, name, member, dst string) (err error) {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(dst)
			// A read that ctx stopped is not a finding about the archive.
			if cerr := ctx.Err(); cerr != nil {
				err = cerr
			}
		}
	}()
	switch {
	case isTarGz(name):
		return extractTarGz(&ctxReader{ctx: ctx, r: f}, member, out)
	case isZip(name):
		st, err := f.Stat()
		if err != nil {
			return err
		}
		return extractZip(&ctxReaderAt{ctx: ctx, r: f}, st.Size(), member, out)
	}
	return copyBinary(out, &ctxReader{ctx: ctx, r: f})
}

// A ctxReader fails every read once ctx is done.
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

// A ctxReaderAt is ctxReader for an io.ReaderAt.
type ctxReaderAt struct {
	ctx context.Context
	r   io.ReaderAt
}

func (c *ctxReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.ReadAt(p, off)
}

// extractTarGz is extractMember for a gzip-compressed tar read from r. The
// inflated bytes, the skipped members included, are bounded by maxInflate.
func extractTarGz(r io.Reader, member string, out io.Writer) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrArchive, err)
	}
	inflated := &io.LimitedReader{R: zr, N: maxInflate + 1}
	tr := tar.NewReader(inflated)
	found := false
	for {
		hdr, err := tr.Next()
		if inflated.N <= 0 {
			return fmt.Errorf("%w: the archive inflates past %d bytes", ErrArchive, maxInflate)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrArchive, err)
		}
		if !memberMatches(hdr.Name, member) {
			continue
		}
		// A link, a directory or a device at the path is not the binary. A
		// hard link to it in particular is left unread: its target may be
		// anything.
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if found {
			return ErrDuplicateMember
		}
		found = true
		if err := copyBinary(out, tr); err != nil {
			if inflated.N <= 0 {
				return fmt.Errorf("%w: the archive inflates past %d bytes", ErrArchive, maxInflate)
			}
			return err
		}
	}
	if !found {
		return ErrNoMember
	}
	return nil
}

// extractZip is extractMember for a zip of size bytes read from r. The
// directory is bounded by maxZipEntries entries and maxInflate bytes in all
// (as the entries declare them) before any entry is opened.
func extractZip(r io.ReaderAt, size int64, member string, out io.Writer) error {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrArchive, err)
	}
	if len(zr.File) > maxZipEntries {
		return fmt.Errorf("%w: the zip lists more than %d entries", ErrArchive, maxZipEntries)
	}
	var total uint64
	for _, zf := range zr.File {
		total += zf.UncompressedSize64
		if total > uint64(maxInflate) {
			return fmt.Errorf("%w: the zip inflates past %d bytes", ErrArchive, maxInflate)
		}
	}
	found := false
	for _, zf := range zr.File {
		if !memberMatches(zf.Name, member) {
			continue
		}
		if !zf.Mode().IsRegular() {
			continue
		}
		if found {
			return ErrDuplicateMember
		}
		found = true
		rc, err := zf.Open()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrArchive, err)
		}
		err = copyBinary(out, rc)
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	if !found {
		return ErrNoMember
	}
	return nil
}

// copyBinary writes the member to out, at most maxBinary bytes.
func copyBinary(out io.Writer, in io.Reader) error {
	n, err := io.Copy(out, io.LimitReader(in, maxBinary+1))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrArchive, err)
	}
	if n > maxBinary {
		return ErrBinaryTooLarge
	}
	return nil
}
