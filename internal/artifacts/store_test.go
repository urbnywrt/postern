package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
)

// ---- helpers ------------------------------------------------------------------

type tarEntry struct {
	name     string
	body     string
	typeflag byte // 0 means a regular file
	mode     int64
	linkname string
}

// makeTarGz builds a .tar.gz in memory.
func makeTarGz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644 // deliberately not executable: the store must set 0755 itself
		}
		hdr := &tar.Header{Name: e.name, Typeflag: typeflag, Mode: mode, Linkname: e.linkname}
		if typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func newStore(t *testing.T) *Store {
	t.Helper()
	return &Store{Root: filepath.Join(t.TempDir(), "data", "artifacts")}
}

const (
	tarName = "telemt-x86_64-linux-musl.tar.gz"
	binBody = "\x7fELF pretend this is the telemt binary"
)

// telemtRef is the reference of an archive whose content is data.
func telemtRef(data []byte) Ref {
	return Ref{Engine: "telemt", Version: "3.5.13", Arch: "amd64", SHA256: sum(data), FileName: tarName, Binary: "telemt"}
}

// snapshot describes the tree under root: relative path -> "dir" or the mode and
// content of a file. A missing root gives nil.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		switch {
		case d.IsDir():
			out[rel] = "dir"
		case d.Type()&fs.ModeSymlink != 0:
			target, _ := os.Readlink(path)
			out[rel] = "symlink -> " + target
		default:
			info, err := d.Info()
			if err != nil {
				return err
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[rel] = fmt.Sprintf("%v %q", info.Mode().Perm(), body)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameTree(t *testing.T, got, want map[string]string) {
	t.Helper()
	var diffs []string
	for p, g := range got {
		if w, ok := want[p]; !ok {
			diffs = append(diffs, "unexpected "+p+": "+g)
		} else if g != w {
			diffs = append(diffs, fmt.Sprintf("%s: got %s, want %s", p, g, w))
		}
	}
	for p := range want {
		if _, ok := got[p]; !ok {
			diffs = append(diffs, "missing "+p)
		}
	}
	sort.Strings(diffs)
	if len(diffs) > 0 {
		t.Errorf("the tree differs:\n  %s", strings.Join(diffs, "\n  "))
	}
}

// ---- layout -------------------------------------------------------------------

func TestDirAndBinaryPath(t *testing.T) {
	s := &Store{Root: "/opt/postern/data/artifacts"}
	ref := Ref{Engine: "telemt", Version: "3.5.13", Arch: "arm64", SHA256: strings.Repeat("a", 64), Binary: "telemt"}
	if got, want := s.Dir(ref), "/opt/postern/data/artifacts/telemt/3.5.13/arm64"; got != want {
		t.Errorf("Dir = %q, want %q", got, want)
	}
	if got, want := s.BinaryPath(ref), "/opt/postern/data/artifacts/telemt/3.5.13/arm64/telemt"; got != want {
		t.Errorf("BinaryPath = %q, want %q", got, want)
	}
}

// ---- Put ----------------------------------------------------------------------

func TestPutTarGz(t *testing.T) {
	s := newStore(t)
	archive := makeTarGz(t,
		tarEntry{name: "telemt", body: binBody, mode: 0o644},
		tarEntry{name: "LICENSE", body: "not the binary"},
	)
	ref := telemtRef(archive)
	if s.Has(ref) {
		t.Fatal("Has is true before Put")
	}
	if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
		t.Fatal(err)
	}
	if !s.Has(ref) {
		t.Fatal("Has is false after Put")
	}

	bin := s.BinaryPath(ref)
	info, err := os.Stat(bin)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("binary mode = %v, want 0755 whatever the archive says", info.Mode().Perm())
	}
	// The directory holds the binary and the marker, and nothing else: neither
	// the archive nor the other archive members.
	dir := s.Dir(ref)
	sameTree(t, snapshot(t, dir), map[string]string{
		".":       "dir",
		"telemt":  fmt.Sprintf("-rwxr-xr-x %q", binBody),
		".sha256": fmt.Sprintf("-rw-r--r-- %q", ref.SHA256+"\n"),
	})
}

func TestPutRawFile(t *testing.T) {
	s := newStore(t)
	raw := []byte(binBody)
	ref := Ref{Engine: "mtg", Version: "2.1.7", Arch: "arm64", SHA256: sum(raw), FileName: "mtg-linux-arm64", Binary: "mtg"}
	if err := s.Put(ref, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if !s.Has(ref) {
		t.Fatal("Has is false after Put")
	}
	got, err := os.ReadFile(s.BinaryPath(ref))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("stored binary = %q, want the raw upload", got)
	}
	info, _ := os.Stat(s.BinaryPath(ref))
	if info.Mode().Perm() != 0o755 {
		t.Errorf("binary mode = %v, want 0755", info.Mode().Perm())
	}
	// Nothing but the binary and the marker, in particular no staged upload.
	sameTree(t, snapshot(t, s.Dir(ref)), map[string]string{
		".":       "dir",
		"mtg":     fmt.Sprintf("-rwxr-xr-x %q", binBody),
		".sha256": fmt.Sprintf("-rw-r--r-- %q", ref.SHA256+"\n"),
	})
}

func TestPutTgzSuffixIsAnArchiveToo(t *testing.T) {
	s := newStore(t)
	archive := makeTarGz(t, tarEntry{name: "telemt", body: binBody})
	ref := telemtRef(archive)
	ref.FileName = "telemt.tgz"
	if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(s.BinaryPath(ref)); string(got) != binBody {
		t.Errorf("stored binary = %q, want the archive member", got)
	}
}

func TestPutFindsTheBinaryInAnArchiveMember(t *testing.T) {
	tests := []struct {
		name    string
		entries []tarEntry
		want    string
	}{
		{"top level", []tarEntry{{name: "telemt", body: "top"}}, "top"},
		{"dot slash prefix", []tarEntry{{name: "./telemt", body: "dot"}}, "dot"},
		{"in a directory", []tarEntry{
			{name: "telemt-3.5.13/", typeflag: tar.TypeDir, mode: 0o755},
			{name: "telemt-3.5.13/README", body: "readme"},
			{name: "telemt-3.5.13/telemt", body: "nested"},
		}, "nested"},
		{"first of several", []tarEntry{{name: "telemt", body: "first"}, {name: "other/telemt", body: "second"}}, "first"},
		{"ignores look-alikes", []tarEntry{
			{name: "telemt.sig", body: "signature"},
			{name: "xtelemt", body: "prefix"},
			{name: "telemt-link", typeflag: tar.TypeSymlink, linkname: "/bin/sh"},
			{name: "telemt", body: "the real one"},
		}, "the real one"},
		// A link with the right name is not the binary, and must not hide it.
		{"skips links named like the binary", []tarEntry{
			{name: "telemt", typeflag: tar.TypeSymlink, linkname: "/bin/sh"},
			{name: "bin/telemt", typeflag: tar.TypeLink, linkname: "telemt"},
			{name: "dir/telemt", body: "the real one"},
		}, "the real one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t)
			archive := makeTarGz(t, tt.entries...)
			ref := telemtRef(archive)
			if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(s.BinaryPath(ref)); string(got) != tt.want {
				t.Errorf("stored binary = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPutNeverExtractsLinks makes sure only a regular file can become the binary:
// a symlink or hard link named like the binary is skipped, not followed.
func TestPutNeverExtractsLinks(t *testing.T) {
	for name, typeflag := range map[string]byte{"symlink": tar.TypeSymlink, "hard link": tar.TypeLink} {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			archive := makeTarGz(t, tarEntry{name: "telemt", typeflag: typeflag, linkname: "/etc/passwd"})
			ref := telemtRef(archive)
			err := s.Put(ref, bytes.NewReader(archive))
			if !errors.Is(err, ErrArchive) {
				t.Fatalf("Put = %v, want ErrArchive", err)
			}
			if got := snapshot(t, s.Root); got != nil {
				t.Errorf("a failed Put left %v", got)
			}
		})
	}
}

func TestPutChecksumMismatch(t *testing.T) {
	s := newStore(t)
	archive := makeTarGz(t, tarEntry{name: "telemt", body: binBody})
	ref := telemtRef(archive)
	ref.SHA256 = strings.Repeat("0", 64) // what the panel pinned is not what arrived

	err := s.Put(ref, bytes.NewReader(archive))
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("Put = %v, want ErrChecksum", err)
	}
	if s.Has(ref) {
		t.Error("Has is true after a failed Put")
	}
	// Nothing at all is left: not the archive, not a staging directory, and not
	// the directories that Put would have created for the artifact.
	if got := snapshot(t, s.Root); got != nil {
		t.Errorf("a failed Put left %v", got)
	}
}

func TestPutChecksumMismatchKeepsWhatIsThere(t *testing.T) {
	s := newStore(t)
	good := makeTarGz(t, tarEntry{name: "telemt", body: binBody})
	ref := telemtRef(good)
	if err := s.Put(ref, bytes.NewReader(good)); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, s.Root)

	// Same engine, version and architecture, another archive that does not match
	// its checksum: the artifact in place must survive untouched.
	bad := makeTarGz(t, tarEntry{name: "telemt", body: "something else"})
	badRef := telemtRef(bad)
	badRef.SHA256 = ref.SHA256
	if err := s.Put(badRef, bytes.NewReader(bad)); !errors.Is(err, ErrChecksum) {
		t.Fatalf("Put = %v, want ErrChecksum", err)
	}
	if !s.Has(ref) {
		t.Error("the good artifact is gone after a failed Put")
	}
	sameTree(t, snapshot(t, s.Root), before)
}

func TestPutAcceptsUpperCaseChecksum(t *testing.T) {
	s := newStore(t)
	archive := makeTarGz(t, tarEntry{name: "telemt", body: binBody})
	ref := telemtRef(archive)
	ref.SHA256 = strings.ToUpper(ref.SHA256)
	if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
		t.Fatal(err)
	}
	if !s.Has(ref) {
		t.Error("Has is false for the upper-case spelling of the checksum")
	}
	lower := ref
	lower.SHA256 = strings.ToLower(ref.SHA256)
	if !s.Has(lower) {
		t.Error("Has is false for the lower-case spelling of the checksum")
	}
	if marker, _ := os.ReadFile(filepath.Join(s.Dir(ref), ".sha256")); string(marker) != lower.SHA256+"\n" {
		t.Errorf("marker = %q, want the lower-case checksum", marker)
	}
}

func TestPutBadArchives(t *testing.T) {
	notGzip := []byte("this is not a gzip stream at all")

	var gzOnly bytes.Buffer
	zw := gzip.NewWriter(&gzOnly)
	_, _ = zw.Write([]byte("gzip, but not a tar"))
	_ = zw.Close()

	tests := []struct {
		name string
		data []byte
	}{
		{"not gzip", notGzip},
		{"gzip but not tar", gzOnly.Bytes()},
		{"empty upload", nil},
		{"no such member", makeTarGz(t, tarEntry{name: "README", body: "hello"})},
		{"member is a directory", makeTarGz(t, tarEntry{name: "telemt/", typeflag: tar.TypeDir, mode: 0o755})},
		{"member is empty", makeTarGz(t, tarEntry{name: "telemt", body: ""})},
		{"truncated archive", makeTarGz(t, tarEntry{name: "telemt", body: strings.Repeat("x", 4096)})[:40]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t)
			ref := telemtRef(tt.data) // the checksum matches: only the content is wrong
			err := s.Put(ref, bytes.NewReader(tt.data))
			if !errors.Is(err, ErrArchive) {
				t.Fatalf("Put = %v, want ErrArchive", err)
			}
			if errors.Is(err, ErrChecksum) {
				t.Errorf("Put = %v: a matching checksum must not be reported as a mismatch", err)
			}
			if s.Has(ref) {
				t.Error("Has is true after a failed Put")
			}
			if got := snapshot(t, s.Root); got != nil {
				t.Errorf("a failed Put left %v", got)
			}
		})
	}
}

func TestPutEmptyRawFile(t *testing.T) {
	s := newStore(t)
	ref := Ref{Engine: "mtg", Version: "2.1.7", Arch: "amd64", SHA256: sum(nil), FileName: "mtg", Binary: "mtg"}
	if err := s.Put(ref, bytes.NewReader(nil)); !errors.Is(err, ErrArchive) {
		t.Fatalf("Put = %v, want ErrArchive for an empty binary", err)
	}
	if got := snapshot(t, s.Root); got != nil {
		t.Errorf("a failed Put left %v", got)
	}
}

// TestPutReaderFailure: a download that breaks off half way (a dropped gRPC
// stream) leaves nothing behind and is not mistaken for a checksum problem.
func TestPutReaderFailure(t *testing.T) {
	s := newStore(t)
	archive := makeTarGz(t, tarEntry{name: "telemt", body: strings.Repeat("x", 100_000)})
	ref := telemtRef(archive)
	boom := errors.New("connection reset")
	r := io.MultiReader(bytes.NewReader(archive[:len(archive)/2]), iotest.ErrReader(boom))
	err := s.Put(ref, r)
	if !errors.Is(err, boom) {
		t.Fatalf("Put = %v, want the reader's error", err)
	}
	if errors.Is(err, ErrChecksum) || errors.Is(err, ErrArchive) {
		t.Errorf("Put = %v: a broken stream is neither a checksum nor an archive problem", err)
	}
	if got := snapshot(t, s.Root); got != nil {
		t.Errorf("a failed Put left %v", got)
	}
}

func TestPutReplacesTheArtifactOfTheSameSlot(t *testing.T) {
	s := newStore(t)
	first := makeTarGz(t, tarEntry{name: "telemt", body: "version one"})
	second := makeTarGz(t, tarEntry{name: "telemt", body: "version two"})
	r1, r2 := telemtRef(first), telemtRef(second)

	if err := s.Put(r1, bytes.NewReader(first)); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(r2, bytes.NewReader(second)); err != nil {
		t.Fatal(err)
	}
	if s.Has(r1) {
		t.Error("Has is true for the replaced archive")
	}
	if !s.Has(r2) {
		t.Error("Has is false for the new archive")
	}
	if got, _ := os.ReadFile(s.BinaryPath(r2)); string(got) != "version two" {
		t.Errorf("stored binary = %q, want the new one", got)
	}
	// Putting the very same artifact again is fine too, and leaves no debris.
	if err := s.Put(r2, bytes.NewReader(second)); err != nil {
		t.Fatal(err)
	}
	sameTree(t, snapshot(t, s.Root), map[string]string{
		".":                           "dir",
		"telemt":                      "dir",
		"telemt/3.5.13":               "dir",
		"telemt/3.5.13/amd64":         "dir",
		"telemt/3.5.13/amd64/telemt":  fmt.Sprintf("-rwxr-xr-x %q", "version two"),
		"telemt/3.5.13/amd64/.sha256": fmt.Sprintf("-rw-r--r-- %q", r2.SHA256+"\n"),
	})
}

func TestPutKeepsOtherArtifacts(t *testing.T) {
	s := newStore(t)
	a := makeTarGz(t, tarEntry{name: "telemt", body: "amd64 build"})
	b := makeTarGz(t, tarEntry{name: "telemt", body: "arm64 build"})
	refA, refB := telemtRef(a), telemtRef(b)
	refB.Arch = "arm64"
	if err := s.Put(refA, bytes.NewReader(a)); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(refB, bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	if !s.Has(refA) || !s.Has(refB) {
		t.Errorf("Has(amd64)=%v Has(arm64)=%v, want both", s.Has(refA), s.Has(refB))
	}
	if s.Dir(refA) == s.Dir(refB) {
		t.Errorf("both architectures share %s", s.Dir(refA))
	}
}

func TestPutConcurrent(t *testing.T) {
	s := newStore(t)
	archive := makeTarGz(t, tarEntry{name: "telemt", body: binBody})
	ref := telemtRef(archive)

	const workers = 8
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Put(ref, bytes.NewReader(archive))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("Put #%d: %v", i, err)
		}
	}
	if !s.Has(ref) {
		t.Error("Has is false after concurrent Puts")
	}
	sameTree(t, snapshot(t, s.Root), map[string]string{
		".":                           "dir",
		"telemt":                      "dir",
		"telemt/3.5.13":               "dir",
		"telemt/3.5.13/amd64":         "dir",
		"telemt/3.5.13/amd64/telemt":  fmt.Sprintf("-rwxr-xr-x %q", binBody),
		"telemt/3.5.13/amd64/.sha256": fmt.Sprintf("-rw-r--r-- %q", ref.SHA256+"\n"),
	})
}

func TestPutSizeLimits(t *testing.T) {
	// Not parallel: the limits are package variables.
	t.Run("archive", func(t *testing.T) {
		old := maxArchiveBytes
		maxArchiveBytes = 1024
		t.Cleanup(func() { maxArchiveBytes = old })

		s := newStore(t)
		data := []byte(strings.Repeat("x", 4096))
		ref := Ref{Engine: "mtg", Version: "1", Arch: "amd64", SHA256: sum(data), FileName: "mtg", Binary: "mtg"}
		err := s.Put(ref, bytes.NewReader(data))
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Put = %v, want ErrTooLarge", err)
		}
		if got := snapshot(t, s.Root); got != nil {
			t.Errorf("a failed Put left %v", got)
		}
	})
	t.Run("extracted binary", func(t *testing.T) {
		old := maxBinaryBytes
		maxBinaryBytes = 1024
		t.Cleanup(func() { maxBinaryBytes = old })

		s := newStore(t)
		archive := makeTarGz(t, tarEntry{name: "telemt", body: strings.Repeat("x", 4096)}) // compresses well
		ref := telemtRef(archive)
		if len(archive) >= int(maxArchiveBytes) {
			t.Fatalf("the test archive is %d bytes, too big for this test", len(archive))
		}
		err := s.Put(ref, bytes.NewReader(archive))
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Put = %v, want ErrTooLarge", err)
		}
		if got := snapshot(t, s.Root); got != nil {
			t.Errorf("a failed Put left %v", got)
		}
	})
	t.Run("at the limit", func(t *testing.T) {
		old := maxBinaryBytes
		maxBinaryBytes = 4096
		t.Cleanup(func() { maxBinaryBytes = old })

		s := newStore(t)
		archive := makeTarGz(t, tarEntry{name: "telemt", body: strings.Repeat("x", 4096)})
		ref := telemtRef(archive)
		if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
			t.Fatalf("Put of a binary exactly at the limit: %v", err)
		}
	})
}

// ---- references ---------------------------------------------------------------

func TestInvalidRefs(t *testing.T) {
	good := Ref{Engine: "telemt", Version: "3.5.13", Arch: "amd64", SHA256: strings.Repeat("ab", 32), FileName: tarName, Binary: "telemt"}
	if err := good.Validate(); err != nil {
		t.Fatalf("the reference used as a template is invalid: %v", err)
	}

	// field says which part of the reference is bad: Dir only depends on the
	// engine, version and architecture, BinaryPath on the binary name as well,
	// and the checksum matters to Has and Put only.
	tests := []struct {
		name   string
		field  string
		mutate func(*Ref)
	}{
		{"empty engine", "engine", func(r *Ref) { r.Engine = "" }},
		{"empty version", "version", func(r *Ref) { r.Version = "" }},
		{"empty arch", "arch", func(r *Ref) { r.Arch = "" }},
		{"empty binary", "binary", func(r *Ref) { r.Binary = "" }},
		{"engine dot dot", "engine", func(r *Ref) { r.Engine = ".." }},
		{"engine dot", "engine", func(r *Ref) { r.Engine = "." }},
		{"engine traversal", "engine", func(r *Ref) { r.Engine = "../escape" }},
		{"engine with slash", "engine", func(r *Ref) { r.Engine = "a/b" }},
		{"engine with backslash", "engine", func(r *Ref) { r.Engine = `a\b` }},
		{"engine absolute", "engine", func(r *Ref) { r.Engine = "/etc" }},
		{"version traversal", "version", func(r *Ref) { r.Version = "../../x" }},
		{"version with slash", "version", func(r *Ref) { r.Version = "3.5/13" }},
		{"arch traversal", "arch", func(r *Ref) { r.Arch = "../.." }},
		{"binary traversal", "binary", func(r *Ref) { r.Binary = "../../bin/sh" }},
		{"binary with slash", "binary", func(r *Ref) { r.Binary = "bin/telemt" }},
		{"binary is the marker", "binary", func(r *Ref) { r.Binary = ".sha256" }},
		{"hidden engine", "engine", func(r *Ref) { r.Engine = ".stage-x" }},
		{"nul byte", "version", func(r *Ref) { r.Version = "3.5\x0013" }},
		{"newline", "version", func(r *Ref) { r.Version = "3.5\n13" }},
		{"space", "arch", func(r *Ref) { r.Arch = "am d64" }},
		{"colon", "arch", func(r *Ref) { r.Arch = "amd64:ro" }}, // would corrupt a bind mount spec
		{"unicode", "engine", func(r *Ref) { r.Engine = "telemt\u202e" }},
		{"too long", "version", func(r *Ref) { r.Version = strings.Repeat("1", 65) }},
		{"empty checksum", "sha", func(r *Ref) { r.SHA256 = "" }},
		{"short checksum", "sha", func(r *Ref) { r.SHA256 = strings.Repeat("a", 63) }},
		{"long checksum", "sha", func(r *Ref) { r.SHA256 = strings.Repeat("a", 65) }},
		{"non hex checksum", "sha", func(r *Ref) { r.SHA256 = strings.Repeat("g", 64) }},
		{"checksum with prefix", "sha", func(r *Ref) { r.SHA256 = "sha256:" + strings.Repeat("a", 57) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := good
			tt.mutate(&ref)
			if err := ref.Validate(); !errors.Is(err, ErrInvalidRef) {
				t.Errorf("Validate = %v, want ErrInvalidRef", err)
			}

			base := t.TempDir()
			s := &Store{Root: filepath.Join(base, "artifacts")}
			pathBad := tt.field == "engine" || tt.field == "version" || tt.field == "arch"
			if got := s.Dir(ref); (got == "") != pathBad {
				t.Errorf("Dir = %q, want it empty exactly when engine, version or arch is bad (field %s)", got, tt.field)
			}
			if got := s.BinaryPath(ref); (got == "") != (pathBad || tt.field == "binary") {
				t.Errorf("BinaryPath = %q, want it empty exactly when a path component is bad (field %s)", got, tt.field)
			}
			// A path that is returned never leaves the root.
			for _, p := range []string{s.Dir(ref), s.BinaryPath(ref)} {
				if p != "" && !strings.HasPrefix(p, s.Root+string(filepath.Separator)) {
					t.Errorf("%q is outside the root %q", p, s.Root)
				}
			}

			// A store must refuse such a reference everywhere, and must never
			// touch anything outside its root.
			if s.Has(ref) {
				t.Error("Has is true for an invalid reference")
			}
			data := []byte(binBody)
			if tt.field != "sha" {
				ref.SHA256 = sum(data) // whatever else is wrong, the checksum is right
			}
			if err := s.Put(ref, bytes.NewReader(data)); !errors.Is(err, ErrInvalidRef) {
				t.Errorf("Put = %v, want ErrInvalidRef", err)
			}
			entries, err := os.ReadDir(base)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("an invalid reference made Put create %v next to the store", entries)
			}
		})
	}
}

func TestValidRefs(t *testing.T) {
	sha := strings.Repeat("0123456789abcdef", 4)
	for _, r := range []Ref{
		{Engine: "telemt", Version: "3.5.13", Arch: "amd64", SHA256: sha, Binary: "telemt"},
		{Engine: "warp-plus", Version: "v1.2.3-rc.1+build.5", Arch: "arm64", SHA256: sha, Binary: "warp-plus"},
		{Engine: "xray", Version: "26.1.1", Arch: "amd64", SHA256: strings.ToUpper(sha), Binary: "xray"},
		{Engine: "mtg", Version: "2.1.7", Arch: "amd64", SHA256: sha, Binary: "mtg_linux"},
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
}

func TestRootMustBeAbsolute(t *testing.T) {
	archive := makeTarGz(t, tarEntry{name: "telemt", body: binBody})
	ref := telemtRef(archive)
	for _, root := range []string{"", "artifacts", "./artifacts", "../artifacts"} {
		s := &Store{Root: root}
		if got := s.Dir(ref); got != "" {
			t.Errorf("Root %q: Dir = %q, want empty", root, got)
		}
		if got := s.BinaryPath(ref); got != "" {
			t.Errorf("Root %q: BinaryPath = %q, want empty", root, got)
		}
		if s.Has(ref) {
			t.Errorf("Root %q: Has is true", root)
		}
		if err := s.Put(ref, bytes.NewReader(archive)); err == nil {
			t.Errorf("Root %q: Put succeeded", root)
		}
	}
}

// ---- Has ----------------------------------------------------------------------

func TestHas(t *testing.T) {
	archive := makeTarGz(t, tarEntry{name: "telemt", body: binBody})
	ref := telemtRef(archive)

	put := func(t *testing.T) *Store {
		t.Helper()
		s := newStore(t)
		if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
			t.Fatal(err)
		}
		return s
	}

	t.Run("present", func(t *testing.T) {
		if !put(t).Has(ref) {
			t.Error("Has is false for a stored artifact")
		}
	})
	t.Run("another checksum", func(t *testing.T) {
		other := ref
		other.SHA256 = sum([]byte("something else"))
		if put(t).Has(other) {
			t.Error("Has is true for a different checksum in the same slot")
		}
	})
	t.Run("another version", func(t *testing.T) {
		other := ref
		other.Version = "3.5.14"
		if put(t).Has(other) {
			t.Error("Has is true for a version that was never stored")
		}
	})
	t.Run("another binary name", func(t *testing.T) {
		other := ref
		other.Binary = "other"
		if put(t).Has(other) {
			t.Error("Has is true for a binary name that was never stored")
		}
	})
	t.Run("empty store", func(t *testing.T) {
		if newStore(t).Has(ref) {
			t.Error("Has is true for an empty store")
		}
	})

	damage := map[string]func(t *testing.T, s *Store){
		"marker removed": func(t *testing.T, s *Store) {
			must(t, os.Remove(filepath.Join(s.Dir(ref), ".sha256")))
		},
		"marker holds another checksum": func(t *testing.T, s *Store) {
			must(t, os.WriteFile(filepath.Join(s.Dir(ref), ".sha256"), []byte(sum([]byte("x"))+"\n"), 0o644))
		},
		"marker is empty": func(t *testing.T, s *Store) {
			must(t, os.WriteFile(filepath.Join(s.Dir(ref), ".sha256"), nil, 0o644))
		},
		"binary removed": func(t *testing.T, s *Store) {
			must(t, os.Remove(s.BinaryPath(ref)))
		},
		"binary is a directory": func(t *testing.T, s *Store) {
			must(t, os.Remove(s.BinaryPath(ref)))
			must(t, os.Mkdir(s.BinaryPath(ref), 0o755))
		},
		"binary is a symlink": func(t *testing.T, s *Store) {
			must(t, os.Remove(s.BinaryPath(ref)))
			must(t, os.Symlink("/bin/sh", s.BinaryPath(ref)))
		},
	}
	for name, f := range damage {
		t.Run(name, func(t *testing.T) {
			s := put(t)
			f(t, s)
			if s.Has(ref) {
				t.Error("Has is true for a damaged artifact")
			}
		})
	}

	t.Run("marker spelled with trailing space and capitals", func(t *testing.T) {
		s := put(t)
		must(t, os.WriteFile(filepath.Join(s.Dir(ref), ".sha256"), []byte(strings.ToUpper(ref.SHA256)+"  \r\n"), 0o644))
		if !s.Has(ref) {
			t.Error("Has is false for a marker that differs only in case and white space")
		}
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// TestPutCreatesNothingOutsideItsSlot: a successful Put adds the slot and the
// directories above it, and leaves what was in the root alone.
func TestPutCreatesNothingOutsideItsSlot(t *testing.T) {
	s := newStore(t)
	must(t, os.MkdirAll(filepath.Join(s.Root, "xray", "26.1.1", "amd64"), 0o755))
	must(t, os.WriteFile(filepath.Join(s.Root, "xray", "26.1.1", "amd64", "xray"), []byte("x"), 0o755))
	before := snapshot(t, s.Root)

	archive := makeTarGz(t, tarEntry{name: "telemt", body: binBody})
	ref := telemtRef(archive)
	must(t, s.Put(ref, bytes.NewReader(archive)))

	after := snapshot(t, s.Root)
	for p, v := range before {
		if after[p] != v {
			t.Errorf("%s changed: %q -> %q", p, v, after[p])
		}
	}
	for p := range after {
		if _, ok := before[p]; ok {
			continue
		}
		if p != "telemt" && !strings.HasPrefix(p, "telemt"+string(filepath.Separator)) {
			t.Errorf("Put created %s outside its own slot", p)
		}
	}
}
