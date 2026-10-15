package releases

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractSafety(t *testing.T) {
	bin := staticELF(t, "amd64", "x")
	decoy := []byte("decoy")
	cases := []struct {
		name    string
		archive string
		data    []byte
		member  string
		want    error  // nil for success
		content []byte // when it succeeds
	}{
		{"plain tar", "a.tar.gz", tarGz(t, member{name: "telemt", data: bin}), "telemt", nil, bin},
		{"dot-slash tar", "a.tar.gz", tarGz(t, member{name: "./telemt", data: bin}), "telemt", nil, bin},
		{"nested member", "a.tar.gz", tarGz(t, member{name: "mtg-2.2.8-linux-amd64/mtg", data: bin}, member{name: "mtg-2.2.8-linux-amd64/README.md", data: decoy}), "mtg-2.2.8-linux-amd64/mtg", nil, bin},
		{"absolute path", "a.tar.gz", tarGz(t, member{name: "/telemt", data: decoy}), "telemt", ErrNoMember, nil},
		{"dot dot", "a.tar.gz", tarGz(t, member{name: "../telemt", data: decoy}), "telemt", ErrNoMember, nil},
		{"dot dot inside", "a.tar.gz", tarGz(t, member{name: "sub/../../telemt", data: decoy}), "telemt", ErrNoMember, nil},
		{"symlink", "a.tar.gz", tarGz(t, member{name: "telemt", typ: tar.TypeSymlink, link: "/etc/passwd"}), "telemt", ErrNoMember, nil},
		{"hardlink named like the member", "a.tar.gz", tarGz(t, member{name: "other", data: decoy}, member{name: "telemt", typ: tar.TypeLink, link: "other"}), "telemt", ErrNoMember, nil},
		{"device", "a.tar.gz", tarGz(t, member{name: "telemt", typ: tar.TypeChar}), "telemt", ErrNoMember, nil},
		{"directory", "a.tar.gz", tarGz(t, member{name: "telemt", typ: tar.TypeDir}), "telemt", ErrNoMember, nil},
		{"duplicate member", "a.tar.gz", tarGz(t, member{name: "telemt", data: bin}, member{name: "./telemt", data: decoy}), "telemt", ErrDuplicateMember, nil},
		{"nested decoy ignored", "a.tar.gz", tarGz(t, member{name: "sub/telemt", data: decoy}, member{name: "telemt", data: bin}), "telemt", nil, bin},
		{"only a nested decoy", "a.tar.gz", tarGz(t, member{name: "sub/telemt", data: decoy}), "telemt", ErrNoMember, nil},
		{"not gzip", "a.tar.gz", []byte("nope"), "telemt", ErrArchive, nil},
		{"zip plain", "a.zip", zipBytes(t, member{name: "xray", data: bin}, member{name: "geoip.dat", data: decoy}), "xray", nil, bin},
		{"zip absolute", "a.zip", zipBytes(t, member{name: "/xray", data: decoy}), "xray", ErrNoMember, nil},
		{"zip dot dot", "a.zip", zipBytes(t, member{name: "../xray", data: decoy}), "xray", ErrNoMember, nil},
		{"zip backslash", "a.zip", zipBytes(t, member{name: `..\xray`, data: decoy}), "xray", ErrNoMember, nil},
		{"zip symlink", "a.zip", zipBytes(t, member{name: "xray", data: []byte("/etc/passwd"), mode: uint32(os.ModeSymlink)}), "xray", ErrNoMember, nil},
		{"zip duplicate", "a.zip", zipBytes(t, member{name: "xray", data: bin}, member{name: "./xray", data: decoy}), "xray", ErrDuplicateMember, nil},
		{"zip decoy ignored", "a.zip", zipBytes(t, member{name: "bin/xray", data: decoy}, member{name: "xray", data: bin}), "xray", nil, bin},
		{"not zip", "a.zip", []byte("nope"), "xray", ErrArchive, nil},
		// Any other name is the binary itself (psiphon-core), as the node's
		// artifact store takes it.
		{"the binary itself", "psiphon-core-linux-amd64", bin, "psiphon-core", nil, bin},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, tc.archive)
			if err := os.WriteFile(src, tc.data, 0o644); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(dir, "out.bin")
			err := extractMember(context.Background(), src, tc.archive, tc.member, dst)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				if _, serr := os.Stat(dst); !errors.Is(serr, os.ErrNotExist) {
					t.Errorf("the output file is left behind")
				}
				// Nothing else was written into the directory.
				entries, _ := os.ReadDir(dir)
				if len(entries) != 1 {
					t.Errorf("directory holds %d entries, want the archive alone", len(entries))
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			got, err := os.ReadFile(dst)
			if err != nil || !bytes.Equal(got, tc.content) {
				t.Errorf("extracted %d bytes, err %v", len(got), err)
			}
		})
	}
}

func TestExtractTooLarge(t *testing.T) {
	// A sparse-looking member that claims more than the limit cannot be
	// fabricated cheaply in a real tar; the copy limit is tested directly.
	var out bytes.Buffer
	in := bytes.NewReader(make([]byte, 1024))
	if err := copyBinary(&out, in); err != nil {
		t.Fatal(err)
	}
	big := &zeroReader{n: maxBinary + 1}
	out.Reset()
	if err := copyBinary(nopWriter{}, big); !errors.Is(err, ErrBinaryTooLarge) {
		t.Errorf("err = %v, want ErrBinaryTooLarge", err)
	}
}

type zeroReader struct{ n int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, errors.New("EOF")
	}
	if int64(len(p)) > z.n {
		p = p[:z.n]
	}
	z.n -= int64(len(p))
	return len(p), nil
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestExtractInflateBound(t *testing.T) {
	old, oldEntries := maxInflate, maxZipEntries
	maxInflate, maxZipEntries = 1<<20, 3
	t.Cleanup(func() { maxInflate, maxZipEntries = old, oldEntries })
	bin := staticELF(t, "amd64", "x")
	dir := t.TempDir()
	// A tiny gzip whose skipped member inflates past the bound: the binary
	// behind it is never reached.
	src := filepath.Join(dir, "a.tar.gz")
	data := tarGz(t, member{name: "zeros", data: make([]byte, 2<<20)}, member{name: "telemt", data: bin})
	if len(data) > 64<<10 {
		t.Fatalf("the test archive is %d bytes; it should be small", len(data))
	}
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	err := extractMember(context.Background(), src, "a.tar.gz", "telemt", filepath.Join(dir, "out"))
	if !errors.Is(err, ErrArchive) || !strings.Contains(err.Error(), "inflates") {
		t.Errorf("tar: err = %v, want ErrArchive (inflates)", err)
	}
	// The member itself inflating past the bound.
	src2 := filepath.Join(dir, "b.tar.gz")
	if err := os.WriteFile(src2, tarGz(t, member{name: "telemt", data: make([]byte, 2<<20)}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extractMember(context.Background(), src2, "b.tar.gz", "telemt", filepath.Join(dir, "out2")); !errors.Is(err, ErrArchive) {
		t.Errorf("tar member: err = %v, want ErrArchive", err)
	}
	// A zip that declares too many entries, or too many bytes.
	zsrc := filepath.Join(dir, "a.zip")
	if err := os.WriteFile(zsrc, zipBytes(t, member{name: "a", data: bin}, member{name: "b", data: bin}, member{name: "c", data: bin}, member{name: "xray", data: bin}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extractMember(context.Background(), zsrc, "a.zip", "xray", filepath.Join(dir, "out3")); !errors.Is(err, ErrArchive) {
		t.Errorf("zip entries: err = %v, want ErrArchive", err)
	}
	zsrc2 := filepath.Join(dir, "b.zip")
	if err := os.WriteFile(zsrc2, zipBytes(t, member{name: "zeros", data: make([]byte, 2<<20)}, member{name: "xray", data: bin}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extractMember(context.Background(), zsrc2, "b.zip", "xray", filepath.Join(dir, "out4")); !errors.Is(err, ErrArchive) {
		t.Errorf("zip bytes: err = %v, want ErrArchive", err)
	}
	// A context that is done stops the reads.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	src3 := filepath.Join(dir, "c.tar.gz")
	if err := os.WriteFile(src3, tarGz(t, member{name: "telemt", data: bin}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extractMember(ctx, src3, "c.tar.gz", "telemt", filepath.Join(dir, "out5")); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: err = %v", err)
	}
}
