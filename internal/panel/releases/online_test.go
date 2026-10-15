//go:build integration

package releases

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// TestOnline reads the real release lists of the four components and prepares
// every built-in pin on both architectures. It needs the network and runs only
// with POSTERN_E2E_ONLINE=1 (and the integration tag); a token in
// POSTERN_GITHUB_TOKEN is used when set. If a built-in pin fails the static
// check the test stops and reports it: the check is never weakened.
func TestOnline(t *testing.T) {
	if os.Getenv("POSTERN_E2E_ONLINE") != "1" {
		t.Skip("POSTERN_E2E_ONLINE is not 1")
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	c := New(Config{DB: db, Dir: t.TempDir(), Log: slog.New(slog.NewTextHandler(testWriter{t}, nil))})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := c.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	token := os.Getenv("POSTERN_GITHUB_TOKEN")
	for _, comp := range Components {
		src := c.Source(ctx, comp)
		src.Token = token
		rels, etag, notModified, _, err := FetchReleases(ctx, c.http, c.lim, src, "", true)
		if err != nil {
			t.Fatalf("%s: FetchReleases: %v", comp.Name, err)
		}
		if notModified || len(rels) == 0 {
			t.Fatalf("%s: no releases (notModified %v)", comp.Name, notModified)
		}
		t.Logf("%s: %d releases, ETag %q, newest %s", comp.Name, len(rels), etag, rels[0].Tag)
	}
	for _, b := range Builtins() {
		comp, _ := ComponentOf(b.Component)
		for _, arch := range Archs {
			start := time.Now()
			if err := c.Prepare(ctx, b.Component, b.Version, []string{arch}); err != nil {
				t.Fatalf("%s %s %s: Prepare: %v", b.Component, b.Version, arch, err)
			}
			if err := c.Ready(ctx, b.Component, b.Version, arch); err != nil {
				t.Fatalf("%s %s %s: Ready: %v", b.Component, b.Version, arch, err)
			}
			t.Logf("%s %s %s (%s): ready in %s", comp.Name, b.Version, arch, comp.MemberPath(b.Version, arch), time.Since(start).Round(time.Second))
		}
	}
}
