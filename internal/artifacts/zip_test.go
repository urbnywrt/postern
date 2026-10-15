package artifacts

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"os"
	"strings"
	"testing"
)

// ---- helpers ------------------------------------------------------------------

type zipEntry struct {
	name   string
	body   string
	mode   fs.FileMode // 0 means a regular file with mode 0644
	store  bool        // store instead of deflate
	header func(*zip.FileHeader)
	// raw, when set, writes the entry with CreateRaw: header as given (see
	// header), body taken as the stored bytes. It lets a test lie about the
	// size or the checksum.
	raw bool
}

// makeZip builds a .zip in memory.
func makeZip(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644 // deliberately not executable: the store must set 0755 itself
		}
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.store || e.raw {
			hdr.Method = zip.Store
		}
		hdr.SetMode(mode)
		if e.raw {
			hdr.CRC32 = crc32.ChecksumIEEE([]byte(e.body))
			hdr.CompressedSize64 = uint64(len(e.body))
			hdr.UncompressedSize64 = uint64(len(e.body))
		}
		if e.header != nil {
			e.header(hdr)
		}
		var err error
		if e.raw {
			w, cerr := zw.CreateRaw(hdr)
			if cerr != nil {
				t.Fatal(cerr)
			}
			_, err = w.Write([]byte(e.body))
		} else {
			w, cerr := zw.CreateHeader(hdr)
			if cerr != nil {
				t.Fatal(cerr)
			}
			_, err = w.Write([]byte(e.body))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const zipName = "Xray-linux-64.zip"

// xrayRef is the reference of a zip archive whose content is data.
func xrayRef(data []byte) Ref {
	return Ref{Engine: "xray", Version: "v26.3.27", Arch: "amd64", SHA256: sum(data), FileName: zipName, Binary: "xray"}
}

// ---- zip ----------------------------------------------------------------------

func TestPutZip(t *testing.T) {
	s := newStore(t)
	archive := makeZip(t,
		zipEntry{name: "LICENSE", body: "not the binary"},
		zipEntry{name: "xray", body: binBody},
		zipEntry{name: "geoip.dat", body: "not the binary either"},
	)
	ref := xrayRef(archive)
	if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
		t.Fatal(err)
	}
	if !s.Has(ref) {
		t.Fatal("Has is false after Put")
	}
	// The directory holds the binary, executable whatever the archive says, and
	// the marker, and nothing else: neither the archive nor its other members.
	sameTree(t, snapshot(t, s.Dir(ref)), map[string]string{
		".":       "dir",
		"xray":    fmt.Sprintf("-rwxr-xr-x %q", binBody),
		".sha256": fmt.Sprintf("-rw-r--r-- %q", ref.SHA256+"\n"),
	})
}

func TestPutZipSuffixIsNotCaseSensitive(t *testing.T) {
	s := newStore(t)
	archive := makeZip(t, zipEntry{name: "warp-plus", body: binBody})
	ref := Ref{Engine: "warp-plus", Version: "v1.2.6", Arch: "arm64", SHA256: sum(archive), FileName: "WARP-PLUS_LINUX-ARM64.ZIP", Binary: "warp-plus"}
	if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(s.BinaryPath(ref)); string(got) != binBody {
		t.Errorf("stored binary = %q, want the archive member", got)
	}
}

func TestPutFindsTheBinaryInAZipMember(t *testing.T) {
	tests := []struct {
		name    string
		entries []zipEntry
		want    string
	}{
		{"top level", []zipEntry{{name: "xray", body: "top"}}, "top"},
		{"stored, not deflated", []zipEntry{{name: "xray", body: "stored", store: true}}, "stored"},
		{"dot slash prefix", []zipEntry{{name: "./xray", body: "dot"}}, "dot"},
		{"in a directory", []zipEntry{
			{name: "Xray-linux-64/", mode: fs.ModeDir | 0o755},
			{name: "Xray-linux-64/README.md", body: "readme"},
			{name: "Xray-linux-64/xray", body: "nested"},
		}, "nested"},
		{"first of several", []zipEntry{{name: "xray", body: "first"}, {name: "other/xray", body: "second"}}, "first"},
		{"ignores look-alikes", []zipEntry{
			{name: "xray.sig", body: "signature"},
			{name: "xxray", body: "prefix"},
			{name: "xray-link", mode: fs.ModeSymlink | 0o777, body: "/bin/sh"},
			{name: "xray", body: "the real one"},
		}, "the real one"},
		// A link or a directory with the right name is not the binary, and must
		// not hide it.
		{"skips links and directories named like the binary", []zipEntry{
			{name: "xray", mode: fs.ModeSymlink | 0o777, body: "/bin/sh"},
			{name: "bin/xray/", mode: fs.ModeDir | 0o755},
			{name: "dir/xray", body: "the real one"},
		}, "the real one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t)
			archive := makeZip(t, tt.entries...)
			ref := xrayRef(archive)
			if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(s.BinaryPath(ref)); string(got) != tt.want {
				t.Errorf("stored binary = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPutZipNeverExtractsLinks(t *testing.T) {
	s := newStore(t)
	archive := makeZip(t, zipEntry{name: "xray", mode: fs.ModeSymlink | 0o777, body: "/etc/passwd"})
	ref := xrayRef(archive)
	if err := s.Put(ref, bytes.NewReader(archive)); !errors.Is(err, ErrArchive) {
		t.Fatalf("Put = %v, want ErrArchive", err)
	}
	if got := snapshot(t, s.Root); got != nil {
		t.Errorf("a failed Put left %v", got)
	}
}

func TestPutBadZipArchives(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"not a zip", []byte("this is not a zip archive at all")},
		{"a tar.gz named .zip", makeTarGz(t, tarEntry{name: "xray", body: binBody})},
		{"empty upload", nil},
		{"no such member", makeZip(t, zipEntry{name: "README.md", body: "hello"})},
		{"member is a directory", makeZip(t, zipEntry{name: "xray/", mode: fs.ModeDir | 0o755})},
		{"member is empty", makeZip(t, zipEntry{name: "xray", body: ""})},
		{"truncated archive", makeZip(t, zipEntry{name: "xray", body: strings.Repeat("x", 4096)})[:100]},
		{"checksum of the member is wrong", makeZip(t, zipEntry{name: "xray", body: binBody, raw: true,
			header: func(h *zip.FileHeader) { h.CRC32 ^= 0xffffffff }})},
		{"member is longer than it says", makeZip(t, zipEntry{name: "xray", body: binBody, raw: true,
			header: func(h *zip.FileHeader) { h.UncompressedSize64 = 3 }})},
		{"unknown compression method", makeZip(t, zipEntry{name: "xray", body: binBody, raw: true,
			header: func(h *zip.FileHeader) { h.Method = 99 }})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t)
			ref := xrayRef(tt.data) // the checksum matches: only the content is wrong
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

// TestPutRefusesUnsafeMemberNames: a member named like the binary whose path
// leaves the archive (an absolute path, a ".." element, a backslash) makes the
// archive unusable. No name from an archive is ever used as a path, but an
// archive built like that is not a release to trust.
func TestPutRefusesUnsafeMemberNames(t *testing.T) {
	for _, name := range []string{
		"../xray",
		"../../../../tmp/xray",
		"/xray",
		"/usr/local/bin/xray",
		"dir/../xray",
		"dir/../../xray",
		"..\\xray/xray",
		"dir\x00/xray",
	} {
		t.Run(fmt.Sprintf("zip %q", name), func(t *testing.T) {
			s := newStore(t)
			// The unsafe member comes first; a safe one after it does not save the archive.
			archive := makeZip(t, zipEntry{name: name, body: "evil"}, zipEntry{name: "xray", body: binBody})
			ref := xrayRef(archive)
			err := s.Put(ref, bytes.NewReader(archive))
			if !errors.Is(err, ErrArchive) {
				t.Fatalf("Put = %v, want ErrArchive", err)
			}
			if got := snapshot(t, s.Root); got != nil {
				t.Errorf("a failed Put left %v", got)
			}
		})
		t.Run(fmt.Sprintf("tar.gz %q", name), func(t *testing.T) {
			if strings.ContainsRune(name, 0) {
				t.Skip("a tar header cannot hold a NUL in a name")
			}
			s := newStore(t)
			tarName := strings.ReplaceAll(name, "xray", "telemt")
			archive := makeTarGz(t, tarEntry{name: tarName, body: "evil"}, tarEntry{name: "telemt", body: binBody})
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

// With GODEBUG=zipinsecurepath=0 the zip reader itself objects to an unsafe
// member, whatever its name: the archive is refused too.
func TestPutZipWithInsecurePathGODEBUG(t *testing.T) {
	t.Setenv("GODEBUG", "zipinsecurepath=0")
	s := newStore(t)
	archive := makeZip(t, zipEntry{name: "../LICENSE", body: "x"}, zipEntry{name: "xray", body: binBody})
	ref := xrayRef(archive)
	if err := s.Put(ref, bytes.NewReader(archive)); !errors.Is(err, ErrArchive) {
		t.Fatalf("Put = %v, want ErrArchive", err)
	}
	if got := snapshot(t, s.Root); got != nil {
		t.Errorf("a failed Put left %v", got)
	}
}

// Safe names that only look odd are fine.
func TestPutAcceptsPlainMemberNames(t *testing.T) {
	for _, name := range []string{"xray", "./xray", "a/b/c/xray", "Xray-linux-64/xray", "x..y/xray"} {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			archive := makeZip(t, zipEntry{name: name, body: binBody})
			ref := xrayRef(archive)
			if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
				t.Fatalf("Put: %v", err)
			}
		})
	}
}

func TestPutZipSizeLimits(t *testing.T) {
	// Not parallel: the limits are package variables.
	t.Run("declared size over the limit", func(t *testing.T) {
		old := maxBinaryBytes
		maxBinaryBytes = 1024
		t.Cleanup(func() { maxBinaryBytes = old })

		s := newStore(t)
		archive := makeZip(t, zipEntry{name: "xray", body: strings.Repeat("x", 4096)}) // compresses well
		if len(archive) >= int(maxBinaryBytes) {
			t.Fatalf("the test archive is %d bytes, too big for this test", len(archive))
		}
		ref := xrayRef(archive)
		if err := s.Put(ref, bytes.NewReader(archive)); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Put = %v, want ErrTooLarge", err)
		}
		if got := snapshot(t, s.Root); got != nil {
			t.Errorf("a failed Put left %v", got)
		}
	})
	t.Run("a bomb that claims a huge size is refused before it is read", func(t *testing.T) {
		s := newStore(t)
		archive := makeZip(t, zipEntry{name: "xray", body: binBody, raw: true,
			header: func(h *zip.FileHeader) { h.UncompressedSize64 = 1 << 40 }})
		ref := xrayRef(archive)
		if err := s.Put(ref, bytes.NewReader(archive)); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Put = %v, want ErrTooLarge", err)
		}
	})
	t.Run("at the limit", func(t *testing.T) {
		old := maxBinaryBytes
		maxBinaryBytes = 4096
		t.Cleanup(func() { maxBinaryBytes = old })

		s := newStore(t)
		archive := makeZip(t, zipEntry{name: "xray", body: strings.Repeat("x", 4096)})
		ref := xrayRef(archive)
		if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
			t.Fatalf("Put of a binary exactly at the limit: %v", err)
		}
	})
	t.Run("archive", func(t *testing.T) {
		old := maxArchiveBytes
		maxArchiveBytes = 1024
		t.Cleanup(func() { maxArchiveBytes = old })

		s := newStore(t)
		archive := makeZip(t, zipEntry{name: "xray", body: strings.Repeat("y", 8192), store: true})
		ref := xrayRef(archive)
		if err := s.Put(ref, bytes.NewReader(archive)); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Put = %v, want ErrTooLarge", err)
		}
	})
}

// A tar.gz under a .zip name and a zip under a .tar.gz name are both refused:
// the name decides how the upload is read.
func TestPutTheNameDecidesTheFormat(t *testing.T) {
	s := newStore(t)
	archive := makeZip(t, zipEntry{name: "telemt", body: binBody})
	ref := telemtRef(archive) // named .tar.gz
	if err := s.Put(ref, bytes.NewReader(archive)); !errors.Is(err, ErrArchive) {
		t.Fatalf("Put = %v, want ErrArchive", err)
	}
}

// unsafeMemberName is what the two readers refuse.
func TestUnsafeMemberName(t *testing.T) {
	for name, want := range map[string]bool{
		"xray": false, "./xray": false, "a/xray": false, "a/b/": false, "x..y": false, "..x/xray": false,
		"../xray": true, "a/../xray": true, "..": true, "/xray": true, "a\\xray": true, "a\x00b": true,
	} {
		if got := unsafeMemberName(name); got != want {
			t.Errorf("unsafeMemberName(%q) = %v, want %v", name, got, want)
		}
	}
}

// The tar.gz reader keeps working for every member type the tests of store_test
// use; a hard link to the binary is still skipped.
func TestPutTarGzStillSkipsLinks(t *testing.T) {
	s := newStore(t)
	archive := makeTarGz(t,
		tarEntry{name: "telemt", typeflag: tar.TypeLink, linkname: "other"},
		tarEntry{name: "dir/telemt", body: "the real one"},
	)
	ref := telemtRef(archive)
	if err := s.Put(ref, bytes.NewReader(archive)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(s.BinaryPath(ref)); string(got) != "the real one" {
		t.Errorf("stored binary = %q", got)
	}
}
