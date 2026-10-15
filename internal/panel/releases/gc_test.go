package releases

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// The archive GC keeps what is named (the channel versions and newest, the
// built-ins, the versions of the nodes' desired states, the 2 newest of each
// component) and what is recent, and removes the rest after 30 days.
func TestArchiveGC(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	tc := newClockCatalog(t, clk)
	if err := tc.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	old := clk.now().Add(-31 * 24 * time.Hour)
	// archive writes the archive of a version with the given mtime and stores
	// the release, its asset ready.
	archive := func(comp, version, file string, mtime time.Time) string {
		t.Helper()
		if !tc.Known(ctx, comp, version) {
			tc.release(t, comp, version, amd64, file, []byte(version), sum([]byte(version)), store.SHASourceDigest)
		}
		p := filepath.Join(tc.dir, comp, version, file)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(version), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		if err := tc.db.SetAssetState(ctx, comp, version, amd64, store.AssetReady, "", ""); err != nil {
			t.Fatal(err)
		}
		return p
	}
	xrayZip := "Xray-linux-64.zip"
	kept := map[string]string{
		"builtin":          archive("telemt", "3.5.13", tgz, old),
		"channel version":  archive("telemt", "9.0.0", tgz, old),
		"second newest":    archive("telemt", "8.0.0", tgz, old),
		"node provider":    archive("xray", "v1.0.0", xrayZip, old),
		"recent":           archive("telemt", "5.0.0", tgz, clk.now().Add(-time.Hour)),
		"newest in latest": archive("xray", "v30.0.0", xrayZip, old),
	}
	gone := map[string]string{
		"old and unnamed":    archive("telemt", "6.0.0", tgz, old),
		"old xray third":     archive("xray", "v0.9.0", xrayZip, old),
		"old xray fourth":    archive("xray", "v0.8.0", xrayZip, old),
		"not in the catalog": filepath.Join(tc.dir, "telemt", "1.0.0", tgz),
	}
	if err := os.MkdirAll(filepath.Dir(gone["not in the catalog"]), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gone["not in the catalog"], []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(gone["not in the catalog"], old, old); err != nil {
		t.Fatal(err)
	}
	// telemt: 9.0.0 is the latest channel version; its 2 newest are 9.0.0
	// and 8.0.0; 5.0.0 is kept by its recent file alone.
	if err := tc.db.SetChannelVersion(ctx, "telemt", store.ChannelLatest, "9.0.0"); err != nil {
		t.Fatal(err)
	}
	// xray: the 2 newest are v30.0.0 and v26.3.27 (built in); v1.0.0 is a
	// node's provider version; v30.0.0 is the newest of latest as well.
	n := tc.node(t, "n1", amd64)
	if err := tc.db.SetNodeProviderVersion(ctx, n.ID, "xray", "v1.0.0"); err != nil {
		t.Fatal(err)
	}

	if err := tc.gc(ctx); err != nil {
		t.Fatalf("gc: %v", err)
	}
	for why, p := range kept {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: %s was removed", why, p)
		}
	}
	for why, p := range gone {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s: %s is still there", why, p)
		}
	}
	// The asset of a removed archive is unchecked again; a kept one stays ready.
	if a := tc.assetOf(t, "telemt", "6.0.0", amd64); a.State != store.AssetUnchecked || a.SHA256 == "" {
		t.Errorf("6.0.0 after gc = %+v, want unchecked and still pinned", a)
	}
	if a := tc.assetOf(t, "telemt", "8.0.0", amd64); a.State != store.AssetReady {
		t.Errorf("8.0.0 after gc = %+v, want ready", a)
	}
	// Running again removes nothing more.
	if err := tc.gc(ctx); err != nil {
		t.Fatal(err)
	}
	for why, p := range kept {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("second gc, %s: %s was removed", why, p)
		}
	}
}
