package releases

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// A clock is a fake time source for the tracker.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newClockCatalog is newTestCatalog on a fake clock, with the feeds of the
// components served by the fake host under /api.
func newClockCatalog(t testing.TB, clk *clock) *testCatalog {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	host := newFakeHost(t)
	dir := t.TempDir()
	c := New(Config{DB: db, Dir: dir, HTTP: host.srv.Client(), APIBase: host.url("/api"), Now: clk.now,
		Log: slog.New(slog.NewTextHandler(testWriter{t}, nil))})
	return &testCatalog{Catalog: c, db: db, host: host, dir: dir}
}

// setStatus makes the fake host answer path with a status and no body.
func (h *fakeHost) setStatus(path string, code int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status[path] = code
}

// feedPath is where the fake host serves the release list of a component.
func feedPath(comp Component) string { return "/api/repos/" + comp.Repo + "/releases" }

// serveFeeds gives every component an empty release list.
func (tc *testCatalog) serveFeeds() {
	for _, comp := range Components {
		tc.host.put(feedPath(comp), []byte("[]"))
	}
}

// node stores a node of this architecture.
func (tc *testCatalog) node(t testing.TB, name, arch string) *store.Node {
	t.Helper()
	n := &store.Node{Name: name, Arch: arch}
	if err := tc.db.CreateNode(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (tc *testCatalog) feedOf(t testing.TB, comp Component) store.Feed {
	t.Helper()
	f, err := tc.db.Feed(context.Background(), tc.Source(context.Background(), comp).ListURL())
	if err != nil {
		t.Fatalf("feed of %s: %v", comp.Name, err)
	}
	return f
}

// The schedule: every feed is polled at start, then every 6 h ± 10 %, each on
// its own; a tick before a feed is due leaves it alone.
func TestTrackerSchedule(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	tc := newClockCatalog(t, clk)
	tc.serveFeeds()
	ctx := context.Background()
	// The stable list fails at start: it is tried again in 15 min, not 6 h.
	stablePath := "/api/repos/urbnywrt/postern/releases/tags/engines-stable"
	tc.host.setStatus(stablePath, 500)

	next := tc.tick(ctx)
	if tc.stableNext != clk.now().Add(stableRetry) {
		t.Errorf("stable list after a failure next at %s, want %s", tc.stableNext, clk.now().Add(stableRetry))
	}
	tc.host.setStatus(stablePath, 0)
	for _, comp := range Components {
		if comp.Pinned {
			// It publishes no releases: no feed is polled for it.
			if got := tc.host.hitCount(feedPath(comp)); got != 0 {
				t.Errorf("%s polled %d times, want none", comp.Name, got)
			}
			continue
		}
		if got := tc.host.hitCount(feedPath(comp)); got != 1 {
			t.Errorf("%s polled %d times at start, want 1", comp.Name, got)
		}
		f := tc.feedOf(t, comp)
		gap := f.NextAt.Sub(clk.now())
		if gap < time.Duration(float64(pollEvery)*0.9) || gap > time.Duration(float64(pollEvery)*1.1) {
			t.Errorf("%s next in %s, want 6 h ± 10 %%", comp.Name, gap)
		}
		if f.LastError != "" || f.CheckedAt != clk.now() || f.Component != comp.Name {
			t.Errorf("%s feed = %+v", comp.Name, f)
		}
	}
	if next.Before(clk.now().Add(time.Minute)) || next.After(clk.now().Add(maxTick)) {
		t.Errorf("next tick at %s, want within [1 min, %s] of now", next, maxTick)
	}

	// Well before any feed is due, nothing is polled; the stable list, due
	// again, finds none (404) and is next due in 6 h.
	clk.advance(5 * time.Hour)
	tc.tick(ctx)
	if tc.stableNext != clk.now().Add(stableEvery) {
		t.Errorf("stable list after a 404 next at %s, want %s", tc.stableNext, clk.now().Add(stableEvery))
	}
	for _, comp := range Components {
		if comp.Pinned {
			// It publishes no releases: no feed is polled for it.
			if got := tc.host.hitCount(feedPath(comp)); got != 0 {
				t.Errorf("%s polled %d times, want none", comp.Name, got)
			}
			continue
		}
		if got := tc.host.hitCount(feedPath(comp)); got != 1 {
			t.Errorf("%s polled %d times after 5 h, want 1", comp.Name, got)
		}
	}
	// Past every possible due time, each is polled once more.
	clk.advance(2 * time.Hour)
	tc.tick(ctx)
	for _, comp := range Components {
		if got := tc.host.hitCount(feedPath(comp)); got != 2 && !comp.Pinned {
			t.Errorf("%s polled %d times after 7 h, want 2", comp.Name, got)
		}
	}

	// A feed that fails records why and is still due again.
	tc.host.setStatus(feedPath(Components[0]), 500)
	clk.advance(7 * time.Hour)
	tc.tick(ctx)
	if f := tc.feedOf(t, Components[0]); f.LastError == "" || !f.NextAt.After(clk.now()) {
		t.Errorf("failed feed = %+v, want an error and a next time", f)
	}

	// Run stops with its context.
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	done := make(chan struct{})
	go func() { tc.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
}

// Refresh polls at once, at most once a minute per component.
func TestRefreshLimit(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	tc := newClockCatalog(t, clk)
	tc.serveFeeds()
	ctx := context.Background()
	telemt, mtg := Components[0], Components[1]

	if err := tc.Refresh(ctx, telemt.Name); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if err := tc.Refresh(ctx, telemt.Name); !errors.Is(err, ErrTooSoon) {
		t.Errorf("second Refresh: %v, want ErrTooSoon", err)
	}
	if err := tc.Refresh(ctx, mtg.Name); err != nil {
		t.Errorf("Refresh of another component: %v", err)
	}
	clk.advance(59 * time.Second)
	if err := tc.Refresh(ctx, telemt.Name); !errors.Is(err, ErrTooSoon) {
		t.Errorf("Refresh at 59 s: %v, want ErrTooSoon", err)
	}
	clk.advance(2 * time.Second)
	if err := tc.Refresh(ctx, telemt.Name); err != nil {
		t.Errorf("Refresh at 61 s: %v", err)
	}
	if got := tc.host.hitCount(feedPath(telemt)); got != 2 {
		t.Errorf("telemt polled %d times, want 2", got)
	}
	if err := tc.Refresh(ctx, "nothing"); !errors.Is(err, ErrUnknown) {
		t.Errorf("Refresh of an unknown component: %v, want ErrUnknown", err)
	}
	// A refused refresh does not count as one.
	if f := tc.feedOf(t, telemt); f.CheckedAt != clk.now() {
		t.Errorf("checked at %s, want %s", f.CheckedAt, clk.now())
	}
}

// A feed that finds a version above a channel version raises release_found
// and prepares it in the background for the architectures of the nodes.
func TestFoundNewerIsPrepared(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	tc := newClockCatalog(t, clk)
	tc.serveFeeds()
	ctx := context.Background()
	if err := tc.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	telemt := Components[0]
	good := tarGz(t, member{name: "telemt", data: staticELF(t, amd64, "9.0.0")})
	tc.host.put("/dl/9.0.0/"+tgz, good)
	asset := fmt.Sprintf(`{"name":%q,"browser_download_url":%q,"digest":"sha256:%s","size":%d,"created_at":"2026-10-01T00:00:00Z"}`,
		tgz, tc.host.url("/dl/9.0.0/"+tgz), sum(good), len(good))
	rel := func(tag string, pre bool, assets string) string {
		return fmt.Sprintf(`{"tag_name":%q,"prerelease":%v,"published_at":"2026-10-02T00:00:00Z","body":"notes","html_url":"https://example.com/r/%s","assets":[%s]}`, tag, pre, tag, assets)
	}
	// 9.0.0 is above the latest version (3.5.13); 9.1.0-rc1 is a prerelease
	// and not followed; 3.0.0 is below.
	tc.host.put(feedPath(telemt), []byte(list(rel("9.1.0-rc1", true, ""), rel("9.0.0", false, asset), rel("3.0.0", false, ""))))

	if err := tc.Refresh(ctx, telemt.Name); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	tc.bg.Wait()

	evs := tc.events(t, EventReleaseFound)
	if len(evs) != 1 || evs[0].Details["version"] != "9.0.0" || evs[0].Details["channels"] != store.ChannelLatest {
		t.Fatalf("release_found events = %+v, want one for 9.0.0 on latest", evs)
	}
	// Without a node there is no architecture to prepare for.
	if a := tc.assetOf(t, telemt.Name, "9.0.0", amd64); a.State != store.AssetUnchecked {
		t.Errorf("9.0.0 amd64 without nodes = %+v, want unchecked", a)
	}
	// The next poll prepares the newest version above the channel that is not
	// ready yet, and does not find it again.
	tc.node(t, "n1", amd64)
	tc.node(t, "n2", amd64)
	clk.advance(2 * time.Minute)
	if err := tc.Refresh(ctx, telemt.Name); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	tc.bg.Wait()
	if evs := tc.events(t, EventReleaseFound); len(evs) != 1 {
		t.Errorf("release_found events after the retry = %d, want 1", len(evs))
	}
	a := tc.assetOf(t, telemt.Name, "9.0.0", amd64)
	if a.State != store.AssetReady || a.SHA256 != sum(good) || a.SHASource != store.SHASourceDigest {
		t.Errorf("9.0.0 amd64 = %+v, want ready, pinned by the digest", a)
	}
	if r, err := tc.db.ReleaseOf(ctx, telemt.Name, "9.0.0"); err != nil || r.Source != store.SourceUpstream || r.Stable || r.Notes != "notes" {
		t.Errorf("9.0.0 = %+v, %v", r, err)
	}
	if r, err := tc.db.ReleaseOf(ctx, telemt.Name, "9.1.0-rc1"); err != nil || !r.Prerelease {
		t.Errorf("9.1.0-rc1 = %+v, %v; want stored as a prerelease", r, err)
	}
	// The built-in release stays built in and stable when the feed repeats it.
	tc.host.put(feedPath(telemt), []byte(list(rel("3.5.13", false, ""), rel("9.0.0", false, asset))))
	clk.advance(2 * time.Minute)
	if err := tc.Refresh(ctx, telemt.Name); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	tc.bg.Wait()
	if r, _ := tc.db.ReleaseOf(ctx, telemt.Name, "3.5.13"); r == nil || r.Source != store.SourceBuiltin || !r.Stable {
		t.Errorf("3.5.13 after the feed = %+v", r)
	}
	// A release that was known is not found again.
	if evs := tc.events(t, EventReleaseFound); len(evs) != 1 {
		t.Errorf("release_found events after a second poll = %d, want 1", len(evs))
	}
	// A digest that disagrees with a pin raises the event and the pin stays.
	bad := fmt.Sprintf(`{"name":%q,"browser_download_url":%q,"digest":"sha256:%s","size":1,"created_at":"2026-10-01T00:00:00Z"}`,
		tgz, tc.host.url("/dl/9.0.0/"+tgz), sum([]byte("other")))
	tc.host.put(feedPath(telemt), []byte(list(rel("9.0.0", false, bad))))
	clk.advance(2 * time.Minute)
	if err := tc.Refresh(ctx, telemt.Name); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	tc.bg.Wait()
	a = tc.assetOf(t, telemt.Name, "9.0.0", amd64)
	if a.SHA256 != sum(good) || a.State != store.AssetUnusable {
		t.Errorf("9.0.0 amd64 after a disagreeing digest = %+v, want the old pin and unusable", a)
	}
	if evs := tc.events(t, EventChecksumMismatch); len(evs) != 1 || evs[0].Details["from"] != "digest" {
		t.Errorf("mismatch events = %+v", evs)
	}
	// An unusable asset stays unusable when it is prepared again (the file
	// still matches the pin); only Recheck takes it out of that state.
	if err := tc.Prepare(ctx, telemt.Name, "9.0.0", []string{amd64}); !errors.Is(err, ErrUnusable) {
		t.Errorf("Prepare of an unusable asset: %v, want ErrUnusable", err)
	}
	if a := tc.assetOf(t, telemt.Name, "9.0.0", amd64); a.State != store.AssetUnusable || a.Reason == "" {
		t.Errorf("after Prepare = %+v, want still unusable with its reason", a)
	}
	if err := tc.Recheck(ctx, telemt.Name, "9.0.0", amd64); err != nil {
		t.Errorf("Recheck: %v", err)
	}
	if a := tc.assetOf(t, telemt.Name, "9.0.0", amd64); a.State != store.AssetReady {
		t.Errorf("after Recheck = %+v, want ready", a)
	}
}

// A version that the stable list created and the feed now sees for the first
// time is found, even though the panel knew it.
func TestFoundWhenOnlyTheStableListKnewIt(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	tc := newClockCatalog(t, clk)
	tc.serveFeeds()
	ctx := context.Background()
	s := newSigner(t)
	tc.keys = s.keys
	if err := tc.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	gen := clk.now().Unix()
	signed := stableListJSON(t, gen, map[string][]entry{"telemt": {telemtEntry("9.0.0", sum([]byte("a")))}})
	if err := tc.ApplyStable(ctx, signed, s.sign(t, signed, s.stablePriv, gen)); err != nil {
		t.Fatal(err)
	}
	telemt := Components[0]
	rel := `{"tag_name":"9.0.0","prerelease":false,"published_at":"2026-10-02T00:00:00Z","body":"notes","html_url":"https://example.com/r/9.0.0","assets":[]}`
	tc.host.put(feedPath(telemt), []byte(list(rel)))
	if err := tc.Refresh(ctx, telemt.Name); err != nil {
		t.Fatal(err)
	}
	evs := tc.events(t, EventReleaseFound)
	if len(evs) != 1 || evs[0].Details["channels"] != store.ChannelStable+","+store.ChannelLatest {
		t.Fatalf("release_found events = %+v, want one for 9.0.0 on both channels", evs)
	}
	if r, _ := tc.db.ReleaseOf(ctx, "telemt", "9.0.0"); r == nil || !r.Stable || r.Source != store.SourceStable || r.Notes != "notes" {
		t.Errorf("9.0.0 = %+v, want stable, source stable, with the feed's notes", r)
	}
	// Seen by the feed once, it is not found again.
	clk.advance(2 * time.Minute)
	if err := tc.Refresh(ctx, telemt.Name); err != nil {
		t.Fatal(err)
	}
	if evs := tc.events(t, EventReleaseFound); len(evs) != 1 {
		t.Errorf("release_found events after a second poll = %d, want 1", len(evs))
	}
}
