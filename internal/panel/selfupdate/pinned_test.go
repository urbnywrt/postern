package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// S5-13: a re-upload of a version with other bytes is refused before
// anything is written; the cache and the pin stay as they were.
func TestUploadNeverReplacesPinnedBytes(t *testing.T) {
	f := newUpload(t)
	first := f.good(t, "v0.5.0")
	if rr, _ := f.post(t, f.h, tarOf(t, first...), "application/x-tar"); rr.Code != http.StatusOK {
		t.Fatalf("first: %d %s", rr.Code, rr.Body.String())
	}
	// Another build of the same version: every binary differs.
	var second []member
	for _, comp := range []string{"postern-node", "postern-panel"} {
		for _, arch := range []string{"amd64", "arm64"} {
			bin := elfBin(t, arch, comp+"v0.5.0 rebuilt")
			name := comp + "-linux-" + arch
			second = append(second, member{name, bin}, member{name + ".minisig", f.s.sign(t, bin, comp, "v0.5.0", arch)})
		}
	}
	rr, res := f.post(t, f.h, tarOf(t, second...), "application/x-tar")
	if rr.Code != http.StatusUnprocessableEntity || res.Accepted {
		t.Fatalf("second: %d %s", rr.Code, rr.Body.String())
	}
	for _, a := range res.Assets {
		if a.OK || !strings.Contains(a.Reason, "other bytes") {
			t.Errorf("asset %s: ok=%v reason %q", a.Name, a.OK, a.Reason)
		}
	}
	rc, _, err := f.cache.Open("v0.5.0", NodeAsset("amd64"))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(data, first[0].data) {
		t.Error("the cache was replaced")
	}
	rel, err := f.db.ReleaseOf(context.Background(), ComponentPostern, "v0.5.0")
	if err != nil || rel.Assets["amd64"].SHA256 != sha256Of(first[0].data) {
		t.Errorf("the pin changed: %v %+v", err, rel.Assets["amd64"])
	}
	// The same bytes again are fine (nothing to add), and both were audited.
	if rr, _ := f.post(t, f.h, tarOf(t, first...), "application/x-tar"); rr.Code != http.StatusOK {
		t.Errorf("same bytes again: %d %s", rr.Code, rr.Body.String())
	}
	if got := f.kept(t); len(got) != 8 {
		t.Errorf("kept: %v", got)
	}
	raw, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	var refused, accepted int
	if err := raw.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'releases.upload.refused' AND details LIKE '%other bytes%'`).Scan(&refused); err != nil {
		t.Fatal(err)
	}
	if err := raw.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'releases.upload' AND details LIKE '%sha256:postern-node-linux-amd64%'`).Scan(&accepted); err != nil {
		t.Fatal(err)
	}
	if refused != 1 || accepted != 2 {
		t.Errorf("audit: %d refused, %d accepted", refused, accepted)
	}
}

// An upload of a version that another upload is committing is a 409.
func TestUploadOfAVersionInFlightIsRefused(t *testing.T) {
	f := newUpload(t)
	if !claim("v0.5.0") {
		t.Fatal("claim")
	}
	defer unclaim("v0.5.0")
	rr, _ := f.post(t, f.h, tarOf(t, f.good(t, "v0.5.0")...), "application/x-tar")
	if rr.Code != http.StatusConflict {
		t.Errorf("status %d, want 409", rr.Code)
	}
	if got := f.kept(t); len(got) != 0 {
		t.Errorf("kept: %v", got)
	}
}

// A signature that names a version that is not a Postern release tag is refused.
func TestUploadRefusesNonReleaseVersions(t *testing.T) {
	f := newUpload(t)
	bin := elfBin(t, "amd64", "x")
	ms := []member{{NodeAsset("amd64"), bin}, {NodeAsset("amd64") + ".minisig", f.s.sign(t, bin, "postern-node", "engines-stable", "amd64")}}
	rr, res := f.post(t, f.h, tarOf(t, ms...), "application/x-tar")
	if rr.Code != http.StatusUnprocessableEntity || len(res.Assets) != 1 || !strings.Contains(res.Assets[0].Reason, "not a Postern release version") {
		t.Errorf("status %d: %s", rr.Code, rr.Body.String())
	}
}

func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Put never replaces a cached, verified asset with other bytes (S5-13); the
// same bytes again are a no-op; a tampered file is replaced.
func TestCachePutConflict(t *testing.T) {
	ctx := context.Background()
	s := newSigner(t)
	c := &Cache{Dir: t.TempDir(), Keys: s.keys}
	a, b := elfBin(t, "amd64", "a"), elfBin(t, "amd64", "b")
	sigA, sigB := s.sign(t, a, "postern-node", "v0.5.0", "amd64"), s.sign(t, b, "postern-node", "v0.5.0", "amd64")
	if err := c.Put(ctx, "v0.5.0", NodeAsset("amd64"), bytes.NewReader(a), sigA); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "v0.5.0", NodeAsset("amd64"), bytes.NewReader(b), sigB); !errors.Is(err, ErrConflict) {
		t.Errorf("other bytes: %v, want ErrConflict", err)
	}
	if err := c.Put(ctx, "v0.5.0", NodeAsset("amd64"), bytes.NewReader(a), sigA); err != nil {
		t.Errorf("the same bytes: %v", err)
	}
	rc, _, err := c.Open("v0.5.0", NodeAsset("amd64"))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(data, a) {
		t.Error("the cached bytes changed")
	}
	entries, _ := os.ReadDir(c.Dir)
	if len(entries) != 1 {
		t.Errorf("leftovers under the cache: %v", entries)
	}
	// A file that no longer verifies is replaced.
	if err := os.WriteFile(c.path("v0.5.0", NodeAsset("amd64")), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(ctx, "v0.5.0", NodeAsset("amd64"), bytes.NewReader(b), sigB); err != nil {
		t.Errorf("over a tampered file: %v", err)
	}
}

func TestCacheSweep(t *testing.T) {
	c := &Cache{Dir: t.TempDir()}
	for _, p := range []string{".upload-0123abcd/postern-node-linux-amd64", "v0.5.0/postern-node-linux-amd64"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(c.Dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(c.Dir, p), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(c.Dir, ".put-postern-node-linux-amd64-123"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Sweep(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(c.Dir)
	if len(entries) != 1 || entries[0].Name() != "v0.5.0" {
		t.Errorf("after Sweep: %v", entries)
	}
	if err := (&Cache{Dir: filepath.Join(c.Dir, "none")}).Sweep(); err != nil {
		t.Errorf("Sweep of a missing dir: %v", err)
	}
}
