package store

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// slice1Migrations are the migrations of slices 0 and 1 as they are embedded:
// what a database of the first release holds.
func slice1Migrations(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, name := range []string{"0001_init.sql", "0002_node_errors.sql"} {
		body, err := fs.ReadFile(embeddedMigrations(), name)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(body)
	}
	return files
}

// seededChannels is what the migration puts into engine_channels: the built-in
// version of every component, on both channels.
var seededChannels = map[string]map[string]string{
	"telemt":       {ChannelStable: "3.5.13", ChannelLatest: "3.5.13"},
	"mtg":          {ChannelStable: "v2.2.8", ChannelLatest: "v2.2.8"},
	"xray":         {ChannelStable: "v26.3.27", ChannelLatest: "v26.3.27"},
	"warp-plus":    {ChannelStable: "v1.2.6", ChannelLatest: "v1.2.6"}, // kept by 0017, read by nothing
	"psiphon-core": {ChannelStable: "20261005-c4a09096ab", ChannelLatest: "20261005-c4a09096ab"},
}

var (
	shaA = strings.Repeat("a", 64)
	shaB = strings.Repeat("b", 64)
	shaC = strings.Repeat("c", 64)
)

// fullRelease is a release with every field set to a value of its own.
func fullRelease() *Release {
	return &Release{
		Engine:      "telemt",
		Version:     "3.5.13",
		Tag:         "3.5.13",
		Source:      SourceUpstream,
		Notes:       "Fixes the thing.",
		URL:         "https://github.com/telemt/telemt/releases/tag/3.5.13",
		Stable:      true,
		Prerelease:  false,
		PublishedAt: testNow.Add(-time.Hour),
		FetchedAt:   testNow,
		Assets: map[string]ReleaseAsset{
			"amd64": {
				File: "telemt-x86_64-linux-musl.tar.gz", URL: "https://github.com/telemt/telemt/releases/download/3.5.13/telemt-x86_64-linux-musl.tar.gz",
				SHA256: shaA, SHASource: SHASourceDigest, State: AssetReady, Size: 1234, CheckedAt: testNow,
			},
			"arm64": {
				File: "telemt-aarch64-linux-musl.tar.gz", URL: "https://github.com/telemt/telemt/releases/download/3.5.13/telemt-aarch64-linux-musl.tar.gz",
				SHA256: shaB, SHASource: SHASourceSums, State: AssetUnusable, Reason: "trial failed: exit status 2", NodeID: "01NODE", Size: 2345, CheckedAt: testNow.Add(time.Minute),
			},
		},
	}
}

func mustRelease(t *testing.T, db *DB, engine, version string) *Release {
	t.Helper()
	r := &Release{Engine: engine, Version: version}
	if err := db.UpsertRelease(context.Background(), r); err != nil {
		t.Fatalf("UpsertRelease(%s %s): %v", engine, version, err)
	}
	return r
}

// A database of slice 1 is backed up and migrated: the channel rows are seeded,
// once, and what the database held reads with the new columns at their
// defaults.
func TestVersionsMigrationOnSlice1Database(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "panel.db")
	clock := fixedClock(time.Unix(1_700_000_000, 0))
	old := mustOpenFS(t, path, slice1Migrations(t), clock)
	// A release and a node of the old shape, in SQL: the repositories of this
	// version name columns that the old database does not have.
	mustExec(t, old, `INSERT INTO engine_releases (engine, version) VALUES ('telemt', '3.5.13')`)
	mustExec(t, old, `INSERT INTO nodes (id, name, created_at, updated_at) VALUES ('N1', 'n1', 0, 0)`)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := open(path, embeddedMigrations(), clock)
	if err != nil {
		t.Fatalf("open the slice-1 database with this version: %v", err)
	}
	defer func() { _ = db.Close() }()
	if got := listBackups(t, path); len(got) != 1 {
		t.Errorf("backups = %v, want one, made before the migration", got)
	}

	channels, err := db.ChannelVersions(ctx)
	if err != nil {
		t.Fatalf("ChannelVersions: %v", err)
	}
	if !reflect.DeepEqual(channels, seededChannels) {
		t.Errorf("channel versions = %v, want the seeded %v", channels, seededChannels)
	}
	if n := count(t, db, `SELECT count(*) FROM engine_channels`); n != 10 {
		t.Errorf("engine_channels has %d rows, want 10", n)
	}

	// The old release row: the old default '[]' for assets reads as none.
	r, err := db.ReleaseOf(ctx, "telemt", "3.5.13")
	if err != nil {
		t.Fatalf("ReleaseOf: %v", err)
	}
	want := &Release{Engine: "telemt", Version: "3.5.13", Source: SourceUpstream, Stable: true, Assets: map[string]ReleaseAsset{}}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("old release = %+v\nwant        %+v", r, want)
	}
	// The old node: no channel of its own, no provider versions.
	n, err := db.NodeByID(ctx, "N1")
	if err != nil {
		t.Fatalf("NodeByID: %v", err)
	}
	if n.EngineChannel != "" || n.ProviderVersions != nil {
		t.Errorf("old node has channel %q and provider versions %v, want none", n.EngineChannel, n.ProviderVersions)
	}

	// A channel that was moved stays moved when the database is opened again:
	// the seed ran once.
	if err := db.SetChannelVersion(ctx, "telemt", ChannelLatest, "3.5.14"); err != nil {
		t.Fatalf("SetChannelVersion: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = open(path, embeddedMigrations(), clock)
	if err != nil {
		t.Fatal(err)
	}
	channels, err = db.ChannelVersions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := channels["telemt"][ChannelLatest]; got != "3.5.14" {
		t.Errorf("telemt latest after reopening = %q, want 3.5.14", got)
	}
	if n := count(t, db, `SELECT count(*) FROM engine_channels`); n != 10 {
		t.Errorf("engine_channels has %d rows after reopening, want 10", n)
	}
	if got := listBackups(t, path); len(got) != 1 {
		t.Errorf("backups after reopening = %v, want still one", got)
	}
}

// The assets column of the first release was a JSON list, '[]' by default; it is
// an object by architecture now, and the old value reads as no assets.
func TestReleaseAssetsOldDefaultReadsAsEmpty(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO engine_releases (engine, version, assets) VALUES ('telemt', '3.5.12', '[]')`)
	r, err := db.ReleaseOf(ctx, "telemt", "3.5.12")
	if err != nil {
		t.Fatalf("ReleaseOf: %v", err)
	}
	if r.Assets == nil || len(r.Assets) != 0 {
		t.Errorf("assets = %v, want an empty map", r.Assets)
	}
	// And an upsert over it writes an object.
	r.Assets = map[string]ReleaseAsset{"amd64": {File: "f", SHA256: shaA, SHASource: SHASourceTOFU}}
	if err := db.UpsertRelease(ctx, r); err != nil {
		t.Fatalf("UpsertRelease: %v", err)
	}
	var raw string
	if err := db.sql.QueryRowContext(ctx, `SELECT assets FROM engine_releases WHERE engine = 'telemt' AND version = '3.5.12'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "{") {
		t.Errorf("assets column = %s, want a JSON object", raw)
	}
}

func TestReleaseRoundTrip(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := fullRelease()
	// Times with a fraction of a second come back whole, and in the record.
	r.PublishedAt = r.PublishedAt.Add(300 * time.Millisecond).In(time.FixedZone("x", 3600))
	if err := db.UpsertRelease(ctx, r); err != nil {
		t.Fatalf("UpsertRelease: %v", err)
	}
	if r.PublishedAt != testNow.Add(-time.Hour) {
		t.Errorf("PublishedAt in the record = %v, want it normalized to %v", r.PublishedAt, testNow.Add(-time.Hour))
	}
	got, err := db.ReleaseOf(ctx, "telemt", "3.5.13")
	if err != nil {
		t.Fatalf("ReleaseOf: %v", err)
	}
	if !reflect.DeepEqual(got, r) {
		t.Errorf("release = %+v\nwant    %+v", got, r)
	}
	list, err := db.ListReleases(ctx, "telemt")
	if err != nil {
		t.Fatalf("ListReleases: %v", err)
	}
	if len(list) != 1 || !reflect.DeepEqual(list[0], r) {
		t.Errorf("ListReleases = %+v, want [%+v]", list, r)
	}
	if _, err := db.ReleaseOf(ctx, "telemt", "3.5.12"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ReleaseOf an unknown version: err = %v, want ErrNotFound", err)
	}
	if _, err := db.ReleaseOf(ctx, "mtg", "3.5.13"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ReleaseOf another engine: err = %v, want ErrNotFound", err)
	}
	if n := count(t, db, `SELECT count(*) FROM engine_releases`); n != 1 {
		t.Errorf("%d rows, want 1", n)
	}
}

func TestReleaseDefaults(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := &Release{Engine: "mtg", Version: "v2.2.8"}
	if err := db.UpsertRelease(ctx, r); err != nil {
		t.Fatalf("UpsertRelease: %v", err)
	}
	want := &Release{Engine: "mtg", Version: "v2.2.8", Source: SourceUpstream, Assets: map[string]ReleaseAsset{}}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("record after the upsert = %+v, want %+v", r, want)
	}
	got, err := db.ReleaseOf(ctx, "mtg", "v2.2.8")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("release = %+v, want %+v", got, want)
	}
	if !got.PublishedAt.IsZero() || !got.FetchedAt.IsZero() {
		t.Errorf("times = %v, %v; want the zero time for 0", got.PublishedAt, got.FetchedAt)
	}
}

// An upsert replaces the release, except that a SHA-256 that is pinned stays
// pinned: another one is refused and changes nothing, none keeps the stored
// one, and the verification of an asset stays unless the upsert sets a state.
func TestReleaseUpsertKeepsPinnedChecksum(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	first := fullRelease()
	if err := db.UpsertRelease(ctx, first); err != nil {
		t.Fatal(err)
	}

	// Another SHA-256 for amd64: refused, the row as it was.
	other := fullRelease()
	other.Notes = "changed"
	a := other.Assets["amd64"]
	a.SHA256 = shaC
	other.Assets["amd64"] = a
	err := db.UpsertRelease(ctx, other)
	if !errors.Is(err, ErrChecksumChanged) {
		t.Fatalf("upsert with another SHA-256: err = %v, want ErrChecksumChanged", err)
	}
	for _, want := range []string{"telemt", "3.5.13", "amd64"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to name %s", err, want)
		}
	}
	if strings.Contains(err.Error(), shaC) || strings.Contains(err.Error(), shaA) {
		t.Errorf("err = %v, want it without the checksums themselves", err)
	}
	got, err := db.ReleaseOf(ctx, "telemt", "3.5.13")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, first) {
		t.Errorf("after the refused upsert: release = %+v\nwant %+v", got, first)
	}

	// The feed says it again, without digests and without a verdict, and with
	// new notes: the notes change, the pins and the verdicts stay.
	again := fullRelease()
	again.Notes = "notes of the second fetch"
	again.FetchedAt = testNow.Add(time.Hour)
	for arch, asset := range again.Assets {
		asset.SHA256, asset.SHASource = "", ""
		asset.State, asset.Reason, asset.NodeID, asset.CheckedAt = "", "", "", time.Time{}
		asset.Size++
		again.Assets[arch] = asset
	}
	if err := db.UpsertRelease(ctx, again); err != nil {
		t.Fatalf("upsert without checksums: %v", err)
	}
	want := fullRelease()
	want.Notes, want.FetchedAt = again.Notes, again.FetchedAt
	for arch, asset := range want.Assets {
		asset.Size++
		want.Assets[arch] = asset
	}
	if !reflect.DeepEqual(again, want) {
		t.Errorf("record after the upsert = %+v\nwant %+v", again, want)
	}
	got, err = db.ReleaseOf(ctx, "telemt", "3.5.13")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("release = %+v\nwant %+v", got, want)
	}

	// The same SHA-256 with a verdict of its own replaces the verdict; an asset
	// of an architecture that was not there is added; one that is not named
	// stays.
	third := &Release{Engine: "telemt", Version: "3.5.13", Source: SourceStable, Stable: true, Assets: map[string]ReleaseAsset{
		"amd64":   {File: "telemt-x86_64-linux-musl.tar.gz", SHA256: shaA, SHASource: SHASourceStable, State: AssetUnchecked, Size: 1},
		"riscv64": {File: "telemt-riscv64-linux-musl.tar.gz", SHA256: shaC, SHASource: SHASourceStable},
	}}
	if err := db.UpsertRelease(ctx, third); err != nil {
		t.Fatalf("third upsert: %v", err)
	}
	got, err = db.ReleaseOf(ctx, "telemt", "3.5.13")
	if err != nil {
		t.Fatal(err)
	}
	if a := got.Assets["amd64"]; a.State != AssetUnchecked || a.SHASource != SHASourceStable || a.Size != 1 || a.URL != "" || !a.CheckedAt.IsZero() {
		t.Errorf("amd64 after a verdict of its own = %+v, want the new verdict and fields", a)
	}
	if a, ok := got.Assets["riscv64"]; !ok || a.SHA256 != shaC {
		t.Errorf("riscv64 = %+v, %v; want it added", a, ok)
	}
	if a := got.Assets["arm64"]; a.SHA256 != shaB || a.State != AssetUnusable || a.Size != 2346 {
		t.Errorf("arm64, not named by the upsert, = %+v; want it as it was", a)
	}
	if got.Source != SourceStable || got.Notes != "" || got.Tag != "" {
		t.Errorf("the row fields were not replaced: source %q notes %q tag %q", got.Source, got.Notes, got.Tag)
	}
	if !reflect.DeepEqual(third, got) {
		t.Errorf("record after the third upsert = %+v\nwant %+v", third, got)
	}
}

func TestListReleasesNewestFirst(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, v := range []string{"3.5.9", "3.5.13", "3.5.10-rc.1", "3.05.13", "dev"} {
		mustRelease(t, db, "telemt", v)
	}
	mustRelease(t, db, "mtg", "v2.2.8")

	list, err := db.ListReleases(ctx, "telemt")
	if err != nil {
		t.Fatalf("ListReleases: %v", err)
	}
	var got []string
	for _, r := range list {
		if r.Engine != "telemt" {
			t.Errorf("a release of %s in the list of telemt", r.Engine)
		}
		got = append(got, r.Version)
	}
	// 3.05.13 and 3.5.13 compare equal, and are two releases: the order among
	// equals is by the string, so that it is the same every time.
	want := []string{"3.5.13", "3.05.13", "3.5.10-rc.1", "3.5.9", "dev"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("versions = %v, want %v", got, want)
	}
	none, err := db.ListReleases(ctx, "xray")
	if err != nil || len(none) != 0 {
		t.Errorf("ListReleases of an engine without releases = %v, %v; want none", none, err)
	}
}

func TestSetAssetState(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow.Add(2 * time.Hour))
	r := fullRelease()
	if err := db.UpsertRelease(ctx, r); err != nil {
		t.Fatal(err)
	}

	if err := db.SetAssetState(ctx, "telemt", "3.5.13", "arm64", AssetReady, "", ""); err != nil {
		t.Fatalf("SetAssetState: %v", err)
	}
	got, err := db.ReleaseOf(ctx, "telemt", "3.5.13")
	if err != nil {
		t.Fatal(err)
	}
	want := r.Assets["arm64"]
	want.State, want.Reason, want.NodeID, want.CheckedAt = AssetReady, "", "", testNow.Add(2*time.Hour)
	if !reflect.DeepEqual(got.Assets["arm64"], want) {
		t.Errorf("arm64 = %+v\nwant  %+v", got.Assets["arm64"], want)
	}
	if !reflect.DeepEqual(got.Assets["amd64"], r.Assets["amd64"]) {
		t.Errorf("amd64 changed: %+v", got.Assets["amd64"])
	}
	if err := db.SetAssetState(ctx, "telemt", "3.5.13", "amd64", AssetUnusable, "exec format error", "01NODE2"); err != nil {
		t.Fatal(err)
	}
	got, _ = db.ReleaseOf(ctx, "telemt", "3.5.13")
	if a := got.Assets["amd64"]; a.State != AssetUnusable || a.Reason != "exec format error" || a.NodeID != "01NODE2" || a.SHA256 != shaA {
		t.Errorf("amd64 = %+v, want unusable with the reason and the node, the pin kept", a)
	}

	if err := db.SetAssetState(ctx, "telemt", "3.5.13", "riscv64", AssetReady, "", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("an arch without an asset: err = %v, want ErrNotFound", err)
	}
	if err := db.SetAssetState(ctx, "telemt", "3.5.12", "amd64", AssetReady, "", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown release: err = %v, want ErrNotFound", err)
	}
}

func TestFeeds(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	const url = "https://api.github.com/repos/telemt/telemt/releases?per_page=100"

	if _, err := db.Feed(ctx, url); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Feed of an unknown url: err = %v, want ErrNotFound", err)
	}
	f := Feed{URL: url, Component: "telemt", ETag: `W/"abc"`, CheckedAt: testNow.Add(500 * time.Millisecond), NextAt: testNow.Add(time.Hour), LastError: ""}
	if err := db.PutFeed(ctx, f); err != nil {
		t.Fatalf("PutFeed: %v", err)
	}
	got, err := db.Feed(ctx, url)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	want := f
	want.CheckedAt = testNow
	if !reflect.DeepEqual(got, want) {
		t.Errorf("feed = %+v\nwant %+v", got, want)
	}

	// The same url again replaces it; another url is another feed.
	f.ETag, f.LastError, f.NextAt = "", "403: rate limited", time.Time{}
	if err := db.PutFeed(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := db.PutFeed(ctx, Feed{URL: "https://git.example.com/api/v1/repos/x/y/releases?limit=50", Component: "postern"}); err != nil {
		t.Fatal(err)
	}
	got, err = db.Feed(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if got.ETag != "" || got.LastError != "403: rate limited" || !got.NextAt.IsZero() || got.CheckedAt != testNow {
		t.Errorf("feed after the second put = %+v", got)
	}
	if n := count(t, db, `SELECT count(*) FROM release_feeds`); n != 2 {
		t.Errorf("%d feeds, want 2", n)
	}
}

// A release and a pin that are built in stay built in: an upstream poll, or the
// stable list, repeating the same digest replaces what it knows better (the
// notes, the page, the file, when it was fetched) and nothing of the provenance.
func TestUpsertReleaseKeepsBuiltin(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seed := &Release{Engine: "telemt", Version: "3.5.13", Source: SourceBuiltin, Stable: true,
		Assets: map[string]ReleaseAsset{"amd64": {File: "f", SHA256: shaA, SHASource: SHASourceBuiltin, State: AssetReady, CheckedAt: testNow}}}
	if err := db.UpsertRelease(ctx, seed); err != nil {
		t.Fatal(err)
	}

	// The poll knows nothing of the pin or of the stable list.
	poll := &Release{Engine: "telemt", Version: "3.5.13", Tag: "3.5.13", Notes: "fetched", URL: "https://github.com/telemt/telemt/releases/tag/3.5.13",
		Stable: false, FetchedAt: testNow.Add(time.Minute),
		Assets: map[string]ReleaseAsset{"amd64": {File: "f", URL: "https://github.com/telemt/telemt/releases/download/3.5.13/f", SHA256: shaA, SHASource: SHASourceDigest, Size: 5}}}
	if err := db.UpsertRelease(ctx, poll); err != nil {
		t.Fatalf("upsert of the poll: %v", err)
	}
	got, err := db.ReleaseOf(ctx, "telemt", "3.5.13")
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != SourceBuiltin || !got.Stable {
		t.Errorf("after the poll: source %q stable %v, want builtin and stable", got.Source, got.Stable)
	}
	if got.Notes != "fetched" || got.Tag != "3.5.13" || got.URL == "" || got.FetchedAt != testNow.Add(time.Minute) {
		t.Errorf("after the poll: notes %q tag %q url %q fetched %v, want what the poll said", got.Notes, got.Tag, got.URL, got.FetchedAt)
	}
	a := got.Assets["amd64"]
	if a.SHASource != SHASourceBuiltin || a.SHA256 != shaA || a.State != AssetReady || a.CheckedAt != testNow {
		t.Errorf("after the poll: asset = %+v, want the built-in pin and its verdict", a)
	}
	if a.URL == "" || a.Size != 5 {
		t.Errorf("after the poll: asset = %+v, want the url and the size of the poll", a)
	}
	if !reflect.DeepEqual(poll, got) {
		t.Errorf("record after the upsert = %+v\nwant %+v", poll, got)
	}

	// The stable list repeating the pin keeps it built in too.
	list := &Release{Engine: "telemt", Version: "3.5.13", Source: SourceStable, Stable: true,
		Assets: map[string]ReleaseAsset{"amd64": {File: "f", SHA256: shaA, SHASource: SHASourceStable}}}
	if err := db.UpsertRelease(ctx, list); err != nil {
		t.Fatal(err)
	}
	got, _ = db.ReleaseOf(ctx, "telemt", "3.5.13")
	if got.Source != SourceBuiltin || got.Assets["amd64"].SHASource != SHASourceBuiltin {
		t.Errorf("after the stable list: source %q, pin source %q; want builtin", got.Source, got.Assets["amd64"].SHASource)
	}

	// Another digest is refused as for any pin.
	bad := &Release{Engine: "telemt", Version: "3.5.13", Assets: map[string]ReleaseAsset{"amd64": {File: "f", SHA256: shaC, SHASource: SHASourceDigest}}}
	if err := db.UpsertRelease(ctx, bad); !errors.Is(err, ErrChecksumChanged) {
		t.Errorf("another digest for a built-in pin: err = %v, want ErrChecksumChanged", err)
	}

	// A release that is not built in takes the source and the stable flag of
	// every upsert.
	if err := db.UpsertRelease(ctx, &Release{Engine: "mtg", Version: "v2.2.8", Source: SourceStable, Stable: true}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertRelease(ctx, &Release{Engine: "mtg", Version: "v2.2.8", Stable: false}); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.ReleaseOf(ctx, "mtg", "v2.2.8"); got.Source != SourceUpstream || got.Stable {
		t.Errorf("a release that is not built in = source %q stable %v, want upstream and not stable", got.Source, got.Stable)
	}
}

// Assets read as a map that is never nil, and an asset stored without a verdict
// is unchecked.
func TestReleaseAssetsReadNeverNil(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	none := &Release{Engine: "telemt", Version: "3.5.14"}
	if err := db.UpsertRelease(ctx, none); err != nil {
		t.Fatal(err)
	}
	if none.Assets == nil || len(none.Assets) != 0 {
		t.Errorf("Assets in the record of a release without assets = %v, want an empty map", none.Assets)
	}
	got, err := db.ReleaseOf(ctx, "telemt", "3.5.14")
	if err != nil {
		t.Fatal(err)
	}
	if got.Assets == nil || len(got.Assets) != 0 {
		t.Fatalf("Assets of a release without assets = %v, want an empty map", got.Assets)
	}
	got.Assets["amd64"] = ReleaseAsset{File: "f"} // must not panic
	if err := db.UpsertRelease(ctx, got); err != nil {
		t.Fatal(err)
	}
	if got.Assets["amd64"].State != AssetUnchecked {
		t.Errorf("state in the record of an asset stored without one = %q, want unchecked", got.Assets["amd64"].State)
	}
	again, _ := db.ReleaseOf(ctx, "telemt", "3.5.14")
	if again.Assets["amd64"].State != AssetUnchecked {
		t.Errorf("state of an asset stored without one = %q, want unchecked", again.Assets["amd64"].State)
	}
	// Seen again without a verdict, it keeps the one it has.
	if err := db.SetAssetState(ctx, "telemt", "3.5.14", "amd64", AssetReady, "", "01NODE"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertRelease(ctx, &Release{Engine: "telemt", Version: "3.5.14", Assets: map[string]ReleaseAsset{"amd64": {File: "f"}}}); err != nil {
		t.Fatal(err)
	}
	if a, _ := db.ReleaseOf(ctx, "telemt", "3.5.14"); a.Assets["amd64"].State != AssetReady {
		t.Errorf("state after an upsert without a verdict = %q, want the ready it had", a.Assets["amd64"].State)
	}
}

func TestPinAsset(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	db.now = fixedClock(testNow.Add(3 * time.Hour))
	r := fullRelease()
	r.Assets["arm64"] = ReleaseAsset{File: "telemt-aarch64-linux-musl.tar.gz", URL: "https://example.com/a", State: AssetUnusable, Reason: "old", NodeID: "01NODE1"}
	if err := db.UpsertRelease(ctx, r); err != nil {
		t.Fatal(err)
	}
	// An unpinned asset is pinned; the reason and the node are cleared.
	if err := db.PinAsset(ctx, "telemt", "3.5.13", "arm64", shaB, SHASourceTOFU, 77, AssetReady); err != nil {
		t.Fatalf("PinAsset: %v", err)
	}
	got, _ := db.ReleaseOf(ctx, "telemt", "3.5.13")
	want := ReleaseAsset{File: "telemt-aarch64-linux-musl.tar.gz", URL: "https://example.com/a", SHA256: shaB, SHASource: SHASourceTOFU,
		State: AssetReady, Size: 77, CheckedAt: testNow.Add(3 * time.Hour)}
	if !reflect.DeepEqual(got.Assets["arm64"], want) {
		t.Errorf("arm64 = %+v\nwant  %+v", got.Assets["arm64"], want)
	}
	// Nothing else of the release changes, and the other asset neither.
	if got.Notes != r.Notes || !got.Stable || !reflect.DeepEqual(got.Assets["amd64"], r.Assets["amd64"]) {
		t.Errorf("release changed: %+v", got)
	}
	// The same pin may be recorded again; another one may not.
	if err := db.PinAsset(ctx, "telemt", "3.5.13", "amd64", shaA, SHASourceSums, 5, AssetReady); err != nil {
		t.Errorf("same pin: %v", err)
	}
	if err := db.PinAsset(ctx, "telemt", "3.5.13", "amd64", shaB, SHASourceSums, 5, AssetReady); !errors.Is(err, ErrChecksumChanged) {
		t.Errorf("another pin: %v, want ErrChecksumChanged", err)
	}
	// A built-in source stays built in.
	r2 := &Release{Engine: "mtg", Version: "v2.2.8", Source: SourceBuiltin, Assets: map[string]ReleaseAsset{"amd64": {File: "f", SHA256: shaA, SHASource: SHASourceBuiltin}}}
	if err := db.UpsertRelease(ctx, r2); err != nil {
		t.Fatal(err)
	}
	if err := db.PinAsset(ctx, "mtg", "v2.2.8", "amd64", shaA, SHASourceSums, 9, AssetReady); err != nil {
		t.Fatal(err)
	}
	got, _ = db.ReleaseOf(ctx, "mtg", "v2.2.8")
	if a := got.Assets["amd64"]; a.SHASource != SHASourceBuiltin || a.State != AssetReady || a.Size != 9 {
		t.Errorf("builtin = %+v", a)
	}
	if err := db.PinAsset(ctx, "mtg", "v2.2.8", "arm64", shaA, SHASourceSums, 9, AssetReady); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing arch: %v", err)
	}
}
