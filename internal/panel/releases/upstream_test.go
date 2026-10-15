package releases

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/urbnywrt/postern/internal/panel/store"
)

func TestUpstreamSHA(t *testing.T) {
	const a, b = "aa", "bb"
	for _, c := range []struct {
		digest, sums string
		sha, source  string
		mismatch     bool
	}{
		{digest: a, sums: a, sha: a, source: store.SHASourceDigest},
		{digest: a, sha: a, source: store.SHASourceDigest},
		{sums: b, sha: b, source: store.SHASourceSums},
		{source: store.SHASourceTOFU},
		{digest: a, sums: b, mismatch: true},
	} {
		sha, source, err := UpstreamSHA(c.digest, c.sums)
		switch {
		case c.mismatch && !errors.Is(err, ErrChecksumMismatch):
			t.Errorf("UpstreamSHA(%q, %q): %v, want ErrChecksumMismatch", c.digest, c.sums, err)
		case !c.mismatch && (err != nil || sha != c.sha || source != c.source):
			t.Errorf("UpstreamSHA(%q, %q) = %q, %q, %v; want %q, %q", c.digest, c.sums, sha, source, err, c.sha, c.source)
		}
	}
}

func TestExtractBinary(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range []struct{ name, body string }{{"README", "r"}, {"dir/bin", "the binary"}} {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o755, Size: int64(len(m.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(m.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "x.tar.gz")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "bin")
	if err := ExtractBinary(t.Context(), archive, "x.tar.gz", "dir/bin", dst); err != nil {
		t.Fatalf("ExtractBinary: %v", err)
	}
	if got, err := os.ReadFile(dst); err != nil || string(got) != "the binary" {
		t.Fatalf("the binary is %q (%v)", got, err)
	}
	if err := ExtractBinary(t.Context(), archive, "x.tar.gz", "bin", filepath.Join(dir, "none")); !errors.Is(err, ErrNoMember) {
		t.Fatalf("ExtractBinary of a member that is not there: %v, want ErrNoMember", err)
	}
}
