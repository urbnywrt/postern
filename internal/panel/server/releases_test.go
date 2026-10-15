package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// releaseAPI stands in for the GitHub API in every test of this package: the
// release tracker polls at start, and no test may reach the real one. It
// answers 404 to everything and counts the paths it was asked.
var releaseAPI struct {
	mu   sync.Mutex
	hits map[string]int
}

func TestMain(m *testing.M) {
	releaseAPI.hits = map[string]int{}
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		releaseAPI.mu.Lock()
		releaseAPI.hits[r.URL.Path]++
		releaseAPI.mu.Unlock()
		http.NotFound(w, r)
	}))
	defaultReleasesAPI = stub.URL
	code := m.Run()
	stub.Close()
	os.Exit(code)
}

func releaseAPIHits(path string) int {
	releaseAPI.mu.Lock()
	defer releaseAPI.mu.Unlock()
	return releaseAPI.hits[path]
}

// The panel seeds the built-in releases when it starts and polls the release
// feeds and the stable list once it serves.
func TestServeRunsTheReleaseTracker(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(Config{DataDir: filepath.Join(dir, "data"), KeysDir: filepath.Join(dir, "keys"), UI: testUI()})
	if err != nil {
		t.Fatal(err)
	}
	before := releaseAPIHits("/repos/telemt/telemt/releases")
	r := serve(t, srv)
	deadline := time.Now().Add(waitFor)
	for releaseAPIHits("/repos/telemt/telemt/releases") == before || releaseAPIHits("/repos/urbnywrt/postern/releases/tags/engines-stable") == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the feeds were not polled at start: hits %v", releaseAPI.hits)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := r.stop(); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	db, err := store.Open(filepath.Join(dir, "data", DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rel, err := db.ReleaseOf(context.Background(), "telemt", "3.5.13")
	if err != nil || rel.Source != store.SourceBuiltin || !rel.Stable {
		t.Errorf("built-in telemt 3.5.13 = %+v, %v; want seeded at start", rel, err)
	}
}
