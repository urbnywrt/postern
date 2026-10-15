package releases

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

const (
	tgz   = "telemt-x86_64-linux-musl.tar.gz"
	amd64 = "amd64"
)

func TestSeedIdempotent(t *testing.T) {
	tc := newTestCatalog(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := tc.Seed(ctx); err != nil {
			t.Fatalf("Seed %d: %v", i+1, err)
		}
	}
	for _, b := range Builtins() {
		comp, _ := ComponentOf(b.Component)
		rel, err := tc.db.ReleaseOf(ctx, b.Component, b.Version)
		if err != nil {
			t.Fatalf("%s %s: %v", b.Component, b.Version, err)
		}
		if rel.Source != store.SourceBuiltin || !rel.Stable || rel.Tag != b.Tag || !comp.Postern && b.Tag != b.Version {
			t.Errorf("%s %s: source %q stable %v tag %q", b.Component, b.Version, rel.Source, rel.Stable, rel.Tag)
		}
		for arch, want := range b.Assets {
			a := rel.Assets[arch]
			if a.SHA256 != want.SHA256 || a.SHASource != store.SHASourceBuiltin || a.State != store.AssetUnchecked ||
				a.File != want.File || a.URL != map[bool]string{false: comp.DownloadURL(b.Tag, want.File)}[comp.Postern] {
				t.Errorf("%s %s %s = %+v", b.Component, b.Version, arch, a)
			}
		}
	}
	// A verdict and the notes survive a reseed; the channel rows are not reset.
	if err := tc.db.SetAssetState(ctx, "telemt", "3.5.13", amd64, store.AssetReady, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := tc.db.SetChannelVersion(ctx, "telemt", store.ChannelLatest, "3.5.14"); err != nil {
		t.Fatal(err)
	}
	if err := tc.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	if a := tc.assetOf(t, "telemt", "3.5.13", amd64); a.State != store.AssetReady {
		t.Errorf("state after reseed = %q", a.State)
	}
	chans, _ := tc.db.ChannelVersions(ctx)
	if chans["telemt"][store.ChannelLatest] != "3.5.14" || chans["telemt"][store.ChannelStable] != "3.5.13" {
		t.Errorf("channels = %v", chans["telemt"])
	}
	if len(Builtins()) != 4 {
		t.Errorf("built-in releases = %d, want 4", len(Builtins()))
	}
	if sha, ok := BuiltinSHA("mtg", "v2.2.8", "arm64"); !ok || sha != "562a94dd4cafcb8f179b76cfeafb76da12747c8e230bc76235bf8746cc189644" {
		t.Errorf("BuiltinSHA(mtg) = %q %v", sha, ok)
	}
}

func TestPrepareChecksumOrder(t *testing.T) {
	ctx := context.Background()
	good := tarGz(t, member{name: "telemt", data: staticELF(t, amd64, "good")})
	other := tarGz(t, member{name: "telemt", data: staticELF(t, amd64, "other")})

	t.Run("builtin beats a disagreeing checksum file", func(t *testing.T) {
		tc := newTestCatalog(t)
		tc.release(t, "telemt", "9.0.1", amd64, tgz, good, sum(good), store.SHASourceBuiltin)
		tc.sums("9.0.1", tgz, sum(other))
		if err := tc.Prepare(ctx, "telemt", "9.0.1", []string{amd64}); err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		a := tc.assetOf(t, "telemt", "9.0.1", amd64)
		if a.State != store.AssetReady || a.SHA256 != sum(good) || a.SHASource != store.SHASourceBuiltin || a.Size != int64(len(good)) {
			t.Errorf("asset = %+v", a)
		}
		evs := tc.events(t, EventChecksumMismatch)
		if len(evs) != 1 || evs[0].Severity != "error" || evs[0].Details["source"] != "builtin" {
			t.Errorf("events = %+v", evs)
		}
		if err := tc.Ready(ctx, "telemt", "9.0.1", amd64); err != nil {
			t.Errorf("Ready: %v", err)
		}
	})

	t.Run("builtin: a download that differs is not kept and the state stays", func(t *testing.T) {
		tc := newTestCatalog(t)
		tc.release(t, "telemt", "9.0.2", amd64, tgz, other, sum(good), store.SHASourceBuiltin)
		err := tc.Prepare(ctx, "telemt", "9.0.2", []string{amd64})
		if !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("Prepare: %v", err)
		}
		a := tc.assetOf(t, "telemt", "9.0.2", amd64)
		if a.State != store.AssetUnchecked || a.SHA256 != sum(good) {
			t.Errorf("asset = %+v", a)
		}
		entries, _ := os.ReadDir(filepath.Join(tc.dir, "telemt", "9.0.2"))
		if len(entries) != 0 {
			t.Errorf("files kept: %v", entries)
		}
	})

	t.Run("digest is expected; a disagreeing checksum file makes it unusable", func(t *testing.T) {
		tc := newTestCatalog(t)
		tc.release(t, "telemt", "9.1.0", amd64, tgz, good, sum(good), store.SHASourceDigest)
		tc.sums("9.1.0", tgz, sum(other))
		err := tc.Prepare(ctx, "telemt", "9.1.0", []string{amd64})
		if !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("Prepare: %v", err)
		}
		a := tc.assetOf(t, "telemt", "9.1.0", amd64)
		if a.State != store.AssetUnusable || a.SHA256 != sum(good) || a.Reason == "" {
			t.Errorf("asset = %+v", a)
		}
		if tc.host.hitCount("/dl/9.1.0/"+tgz) != 0 {
			t.Errorf("the archive was downloaded although the sources disagree")
		}
		if len(tc.events(t, EventChecksumMismatch)) != 1 || len(tc.events(t, EventUnusable)) != 1 {
			t.Errorf("events: mismatch %d unusable %d", len(tc.events(t, EventChecksumMismatch)), len(tc.events(t, EventUnusable)))
		}
	})

	t.Run("digest with an agreeing checksum file", func(t *testing.T) {
		tc := newTestCatalog(t)
		tc.release(t, "telemt", "9.1.1", amd64, tgz, good, sum(good), store.SHASourceDigest)
		tc.sums("9.1.1", tgz, sum(good))
		if err := tc.Prepare(ctx, "telemt", "9.1.1", []string{amd64}); err != nil {
			t.Fatal(err)
		}
		if a := tc.assetOf(t, "telemt", "9.1.1", amd64); a.State != store.AssetReady || a.SHASource != store.SHASourceDigest {
			t.Errorf("asset = %+v", a)
		}
	})

	t.Run("digest: a download that differs is unusable and not kept", func(t *testing.T) {
		tc := newTestCatalog(t)
		tc.release(t, "telemt", "9.1.2", amd64, tgz, other, sum(good), store.SHASourceDigest)
		if err := tc.Prepare(ctx, "telemt", "9.1.2", []string{amd64}); !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("Prepare: %v", err)
		}
		if a := tc.assetOf(t, "telemt", "9.1.2", amd64); a.State != store.AssetUnusable || a.SHA256 != sum(good) {
			t.Errorf("asset = %+v", a)
		}
		if _, err := os.Stat(filepath.Join(tc.dir, "telemt", "9.1.2", tgz)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the file was kept: %v", err)
		}
	})

	t.Run("checksum file alone", func(t *testing.T) {
		tc := newTestCatalog(t)
		tc.release(t, "telemt", "9.2.0", amd64, tgz, good, "", "")
		tc.sums("9.2.0", tgz, sum(good))
		if _, err := tc.Ref(ctx, "telemt", "9.2.0", amd64); !errors.Is(err, ErrNoPin) {
			t.Fatalf("Ref before Prepare: %v", err)
		}
		if err := tc.Prepare(ctx, "telemt", "9.2.0", []string{amd64}); err != nil {
			t.Fatal(err)
		}
		a := tc.assetOf(t, "telemt", "9.2.0", amd64)
		if a.State != store.AssetReady || a.SHA256 != sum(good) || a.SHASource != store.SHASourceSums {
			t.Errorf("asset = %+v", a)
		}
		// A checksum file that disagrees with the download: not kept, unusable.
		tc.release(t, "telemt", "9.2.1", amd64, tgz, other, "", "")
		tc.sums("9.2.1", tgz, sum(good))
		if err := tc.Prepare(ctx, "telemt", "9.2.1", []string{amd64}); !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("Prepare: %v", err)
		}
		if a := tc.assetOf(t, "telemt", "9.2.1", amd64); a.State != store.AssetUnusable || a.SHA256 != "" {
			t.Errorf("asset = %+v", a)
		}
	})

	t.Run("TOFU only with neither", func(t *testing.T) {
		tc := newTestCatalog(t)
		tc.release(t, "telemt", "9.3.0", amd64, tgz, good, "", "")
		if err := tc.Prepare(ctx, "telemt", "9.3.0", []string{amd64}); err != nil {
			t.Fatal(err)
		}
		a := tc.assetOf(t, "telemt", "9.3.0", amd64)
		if a.State != store.AssetReady || a.SHA256 != sum(good) || a.SHASource != store.SHASourceTOFU {
			t.Errorf("asset = %+v", a)
		}
		// The pin holds: the upstream file changing is a mismatch next time.
		tc.host.put("/dl/9.3.0/"+tgz, other)
		if err := os.Remove(filepath.Join(tc.dir, "telemt", "9.3.0", tgz)); err != nil {
			t.Fatal(err)
		}
		if err := tc.Prepare(ctx, "telemt", "9.3.0", []string{amd64}); !errors.Is(err, ErrChecksumMismatch) {
			t.Fatalf("Prepare after a change: %v", err)
		}
		if a := tc.assetOf(t, "telemt", "9.3.0", amd64); a.SHA256 != sum(good) || a.State != store.AssetUnusable {
			t.Errorf("asset = %+v", a)
		}
	})

	t.Run("TOFU: a failed download is neither kept nor pinned", func(t *testing.T) {
		tc := newTestCatalog(t)
		bad := tarGz(t, member{name: "telemt", data: dynamicELF(t, amd64, "dyn")})
		tc.release(t, "telemt", "9.3.1", amd64, tgz, bad, "", "")
		if err := tc.Prepare(ctx, "telemt", "9.3.1", []string{amd64}); !errors.Is(err, ErrUnusable) {
			t.Fatalf("Prepare: %v", err)
		}
		a := tc.assetOf(t, "telemt", "9.3.1", amd64)
		if a.State != store.AssetUnusable || a.SHA256 != "" || !strings.HasPrefix(a.Reason, release.ErrDynamic.Error()) {
			t.Errorf("asset = %+v", a)
		}
		entries, _ := os.ReadDir(filepath.Join(tc.dir, "telemt", "9.3.1"))
		if len(entries) != 0 {
			t.Errorf("files kept: %v", entries)
		}
		if _, err := tc.Ref(ctx, "telemt", "9.3.1", amd64); !errors.Is(err, ErrNoPin) {
			t.Errorf("Ref: %v", err)
		}
	})

	t.Run("a checksum file that cannot be read blocks a non-builtin", func(t *testing.T) {
		tc := newTestCatalog(t)
		tc.release(t, "telemt", "9.4.0", amd64, tgz, good, "", "")
		tc.host.put("/dl/9.4.0/"+tgz+".sha256", []byte("zz  "+tgz+"\n"))
		if err := tc.Prepare(ctx, "telemt", "9.4.0", []string{amd64}); err == nil {
			t.Fatal("Prepare passed with a checksum file that cannot be trusted")
		}
		if a := tc.assetOf(t, "telemt", "9.4.0", amd64); a.State != store.AssetUnchecked {
			t.Errorf("asset = %+v", a)
		}
	})
}

func TestDynamicBinary(t *testing.T) {
	tc := newTestCatalog(t)
	ctx := context.Background()
	bad := tarGz(t, member{name: "telemt", data: dynamicELF(t, amd64, "dyn")})
	tc.release(t, "telemt", "9.5.0", amd64, tgz, bad, sum(bad), store.SHASourceDigest)
	if err := tc.Prepare(ctx, "telemt", "9.5.0", []string{amd64}); !errors.Is(err, ErrUnusable) {
		t.Fatalf("Prepare: %v", err)
	}
	a := tc.assetOf(t, "telemt", "9.5.0", amd64)
	if a.State != store.AssetUnusable || !strings.HasPrefix(a.Reason, release.ErrDynamic.Error()) || a.SHA256 != sum(bad) {
		t.Errorf("asset = %+v", a)
	}
	if evs := tc.events(t, EventUnusable); len(evs) != 1 || !strings.HasPrefix(evs[0].Details["reason"], release.ErrDynamic.Error()) {
		t.Errorf("events = %+v", evs)
	}
	// The pin stays, so the version is still named; it is not ready.
	if _, err := tc.Ref(ctx, "telemt", "9.5.0", amd64); err != nil {
		t.Errorf("Ref: %v", err)
	}
	if err := tc.Ready(ctx, "telemt", "9.5.0", amd64); !errors.Is(err, ErrUnusable) {
		t.Errorf("Ready: %v", err)
	}
	// The extracted copy is gone; the archive is kept (it is what was pinned).
	entries, _ := os.ReadDir(filepath.Join(tc.dir, "telemt", "9.5.0"))
	if len(entries) != 1 || entries[0].Name() != tgz {
		t.Errorf("files: %v", entries)
	}
	// Recheck puts it back and tries again: the same verdict.
	if err := tc.Recheck(ctx, "telemt", "9.5.0", amd64); !errors.Is(err, ErrUnusable) {
		t.Errorf("Recheck: %v", err)
	}
}

func TestWrongArch(t *testing.T) {
	tc := newTestCatalog(t)
	ctx := context.Background()
	armBin := tarGz(t, member{name: "telemt", data: staticELF(t, "arm64", "arm")})
	tc.release(t, "telemt", "9.6.0", amd64, tgz, armBin, "", "")
	if err := tc.Prepare(ctx, "telemt", "9.6.0", []string{amd64}); !errors.Is(err, ErrUnusable) {
		t.Fatalf("Prepare: %v", err)
	}
	if a := tc.assetOf(t, "telemt", "9.6.0", amd64); a.State != store.AssetUnusable || !strings.HasPrefix(a.Reason, release.ErrWrongArch.Error()) {
		t.Errorf("asset = %+v", a)
	}
	// A zip provider on arm64.
	xz := zipBytes(t, member{name: "xray", data: staticELF(t, "arm64", "x")}, member{name: "geoip.dat", data: []byte("g")})
	tc.release(t, "xray", "v99.0.0", "arm64", "Xray-linux-arm64-v8a.zip", xz, "", "")
	if err := tc.Prepare(ctx, "xray", "v99.0.0", []string{"arm64"}); err != nil {
		t.Fatalf("Prepare xray: %v", err)
	}
	if a := tc.assetOf(t, "xray", "v99.0.0", "arm64"); a.State != store.AssetReady {
		t.Errorf("asset = %+v", a)
	}
	// Unknown things.
	if err := tc.Prepare(ctx, "nope", "1.0.0", []string{amd64}); !errors.Is(err, ErrUnknown) {
		t.Errorf("unknown component: %v", err)
	}
	if err := tc.Prepare(ctx, "telemt", "0.0.1", []string{amd64}); !errors.Is(err, ErrUnknown) {
		t.Errorf("unknown version: %v", err)
	}
	if err := tc.Prepare(ctx, "telemt", "9.6.0", []string{"arm64"}); !errors.Is(err, ErrUnknown) {
		t.Errorf("missing arch: %v", err)
	}
}

func TestOpenDetectsChange(t *testing.T) {
	tc := newTestCatalog(t)
	ctx := context.Background()
	good := tarGz(t, member{name: "telemt", data: staticELF(t, amd64, "good")})
	tc.release(t, "telemt", "9.7.0", amd64, tgz, good, "", "")
	if err := tc.Prepare(ctx, "telemt", "9.7.0", []string{amd64}); err != nil {
		t.Fatal(err)
	}
	rc, ref, err := tc.Open(ctx, "telemt", "9.7.0", amd64)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil || string(data) != string(good) {
		t.Fatalf("read: %v, %d bytes", err, len(data))
	}
	if ref.Sha256 != sum(good) || ref.Engine != "telemt" || ref.Version != "9.7.0" || ref.Arch != amd64 || ref.FileName != tgz || ref.Binary != "telemt" || ref.Url == "" {
		t.Errorf("ref = %+v", ref)
	}
	// The file changes on disk.
	p := filepath.Join(tc.dir, "telemt", "9.7.0", tgz)
	if err := os.WriteFile(p, append(good, 'x'), 0o644); err != nil {
		t.Fatal(err)
	}
	rc, _, err = tc.Open(ctx, "telemt", "9.7.0", amd64)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(rc)
	_ = rc.Close()
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("read of a changed file: %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the changed file was kept")
	}
	if a := tc.assetOf(t, "telemt", "9.7.0", amd64); a.State != store.AssetUnchecked || a.SHA256 != sum(good) {
		t.Errorf("asset = %+v", a)
	}
	if err := tc.Ready(ctx, "telemt", "9.7.0", amd64); !errors.Is(err, ErrNotReady) {
		t.Errorf("Ready: %v", err)
	}
	if _, _, err := tc.Open(ctx, "telemt", "9.7.0", amd64); !errors.Is(err, ErrNotReady) {
		t.Errorf("Open of a gone file: %v", err)
	}
	// Prepare downloads it again.
	if err := tc.Prepare(ctx, "telemt", "9.7.0", []string{amd64}); err != nil {
		t.Fatal(err)
	}
	if err := tc.Ready(ctx, "telemt", "9.7.0", amd64); err != nil {
		t.Errorf("Ready after Prepare: %v", err)
	}
}

func TestMarkUnusable(t *testing.T) {
	tc := newTestCatalog(t)
	ctx := context.Background()
	good := tarGz(t, member{name: "telemt", data: staticELF(t, amd64, "good")})
	tc.release(t, "telemt", "9.8.0", amd64, tgz, good, "", "")
	tc.release(t, "telemt", "9.8.1", amd64, tgz, good, sum(good), store.SHASourceBuiltin)
	if err := tc.Prepare(ctx, "telemt", "9.8.0", []string{amd64}); err != nil {
		t.Fatal(err)
	}
	if err := tc.Prepare(ctx, "telemt", "9.8.1", []string{amd64}); err != nil {
		t.Fatal(err)
	}
	if err := tc.MarkUnusable(ctx, "telemt", "9.8.0", amd64, "node-1", "exit code 2"); err != nil {
		t.Fatal(err)
	}
	if a := tc.assetOf(t, "telemt", "9.8.0", amd64); a.State != store.AssetUnusable || a.Reason != "exit code 2" || a.NodeID != "node-1" {
		t.Errorf("non-builtin = %+v", a)
	}
	if err := tc.MarkUnusable(ctx, "telemt", "9.8.1", amd64, "node-1", "exit code 2"); err != nil {
		t.Fatal(err)
	}
	if a := tc.assetOf(t, "telemt", "9.8.1", amd64); a.State != store.AssetReady || a.Reason != "exit code 2" || a.NodeID != "node-1" {
		t.Errorf("builtin = %+v", a)
	}
	if err := tc.Ready(ctx, "telemt", "9.8.1", amd64); err != nil {
		t.Errorf("Ready(builtin) = %v", err)
	}
	if evs := tc.events(t, EventUnusable); len(evs) != 2 {
		t.Errorf("events = %d", len(evs))
	}
	if err := tc.MarkUnusable(ctx, "telemt", "9.8.9", amd64, "node-1", "x"); !errors.Is(err, ErrUnknown) {
		t.Errorf("unknown: %v", err)
	}
}

func TestRefNeedsPin(t *testing.T) {
	tc := newTestCatalog(t)
	ctx := context.Background()
	good := tarGz(t, member{name: "telemt", data: staticELF(t, amd64, "good")})
	tc.release(t, "telemt", "9.9.0", amd64, tgz, good, "", "")
	if _, err := tc.Ref(ctx, "telemt", "9.9.0", amd64); !errors.Is(err, ErrNoPin) {
		t.Errorf("Ref without a pin: %v", err)
	}
	if _, _, err := tc.Open(ctx, "telemt", "9.9.0", amd64); !errors.Is(err, ErrNoPin) {
		t.Errorf("Open without a pin: %v", err)
	}
	if err := tc.Ready(ctx, "telemt", "9.9.0", amd64); !errors.Is(err, ErrNotReady) {
		t.Errorf("Ready: %v", err)
	}
	if _, err := tc.Ref(ctx, "telemt", "9.9.0", "arm64"); !errors.Is(err, ErrUnknown) {
		t.Errorf("Ref of a missing arch: %v", err)
	}
	// A digest is a pin: named before Prepare (F10).
	tc.release(t, "telemt", "9.9.1", amd64, tgz, good, sum(good), store.SHASourceDigest)
	ref, err := tc.Ref(ctx, "telemt", "9.9.1", amd64)
	if err != nil || ref.Sha256 != sum(good) {
		t.Errorf("Ref with a digest: %v %v", ref, err)
	}
	if !tc.Known(ctx, "telemt", "9.9.1") || tc.Known(ctx, "telemt", "9.9.2") {
		t.Error("Known")
	}
}

func TestNewest(t *testing.T) {
	tc := newTestCatalog(t)
	ctx := context.Background()
	if err := tc.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	put := func(version string, stable, prerelease bool, archs ...string) {
		rel := &store.Release{Engine: "telemt", Version: version, Tag: version, Stable: stable, Prerelease: prerelease, Assets: map[string]store.ReleaseAsset{}}
		for _, a := range archs {
			rel.Assets[a] = store.ReleaseAsset{File: "f-" + a + ".tar.gz", URL: "https://example.com/" + a}
		}
		if err := tc.db.UpsertRelease(ctx, rel); err != nil {
			t.Fatal(err)
		}
	}
	put("3.6.0", false, false, amd64, "arm64")
	put("3.6.1-rc1", false, true, amd64, "arm64")
	put("3.7.0", false, false, amd64) // no arm64 asset
	put("3.8.0", false, false, amd64, "arm64")
	if err := tc.db.SetAssetState(ctx, "telemt", "3.8.0", "arm64", store.AssetUnusable, "x", ""); err != nil {
		t.Fatal(err)
	}
	both := []string{amd64, "arm64"}
	cases := []struct {
		channel string
		archs   []string
		want    string
	}{
		{store.ChannelStable, both, "3.5.13"},
		{store.ChannelLatest, both, "3.6.0"},
		{store.ChannelLatest, []string{amd64}, "3.8.0"},
		{store.ChannelLatest, nil, "3.8.0"},
	}
	for _, c := range cases {
		got, err := tc.Newest(ctx, "telemt", c.channel, c.archs)
		if err != nil || got != c.want {
			t.Errorf("Newest(%s, %v) = %q, %v; want %q", c.channel, c.archs, got, err, c.want)
		}
	}
	if err := tc.db.PutSetting(ctx, store.SettingIncludePrereleases, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := tc.Newest(ctx, "telemt", store.ChannelLatest, both); got != "3.6.1-rc1" {
		t.Errorf("Newest with prereleases = %q", got)
	}
	for _, c := range []struct {
		channel, version string
		want             bool
	}{
		{store.ChannelStable, "3.5.13", true}, {store.ChannelStable, "3.6.0", false}, {store.ChannelLatest, "3.6.0", true},
		{store.ChannelLatest, "3.6.1-rc1", true}, {store.ChannelLatest, "0.0.0", false}, {store.ChannelLatest, "3.5.13", true},
	} {
		got, err := tc.InChannel(ctx, "telemt", c.channel, c.version)
		if err != nil || got != c.want {
			t.Errorf("InChannel(%s, %s) = %v, %v; want %v", c.channel, c.version, got, err, c.want)
		}
	}
	if _, err := tc.InChannel(ctx, "telemt", "beta", "3.6.0"); err == nil {
		t.Error("InChannel(beta) passed")
	}
	if got, _ := tc.Newest(ctx, "mtg", store.ChannelLatest, both); got != "v2.2.8" {
		t.Errorf("Newest(mtg) = %q", got)
	}
	if got, err := tc.Newest(ctx, "nothing", store.ChannelLatest, both); got != "" || err != nil {
		t.Errorf("Newest(nothing) = %q, %v", got, err)
	}
}

func TestConcurrentPrepare(t *testing.T) {
	tc := newTestCatalog(t)
	ctx := context.Background()
	good := tarGz(t, member{name: "telemt", data: staticELF(t, amd64, "good")})
	tc.release(t, "telemt", "9.10.0", amd64, tgz, good, "", "")
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = tc.Prepare(ctx, "telemt", "9.10.0", []string{amd64})
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("Prepare %d: %v", i, err)
		}
	}
	if n := tc.host.hitCount("/dl/9.10.0/" + tgz); n != 1 {
		t.Errorf("downloads = %d, want 1", n)
	}
	if a := tc.assetOf(t, "telemt", "9.10.0", amd64); a.State != store.AssetReady {
		t.Errorf("asset = %+v", a)
	}
}

func TestComponents(t *testing.T) {
	mtg, _ := ComponentOf("mtg")
	if got := mtg.AssetName("v2.2.8", amd64); got != "mtg-2.2.8-linux-amd64.tar.gz" {
		t.Errorf("AssetName = %q", got)
	}
	if got := mtg.MemberPath("v2.2.8", "arm64"); got != "mtg-2.2.8-linux-arm64/mtg" {
		t.Errorf("MemberPath = %q", got)
	}
	if got := mtg.SumsFile("v2.2.8", "x"); got != "mtg-2.2.8-checksums.txt" {
		t.Errorf("SumsFile = %q", got)
	}
	xray, _ := ComponentOf("xray")
	if got := xray.SumsFile("v26.3.27", "Xray-linux-64.zip"); got != "Xray-linux-64.zip.dgst" {
		t.Errorf("SumsFile(xray) = %q", got)
	}
	telemt, _ := ComponentOf("telemt")
	if got := telemt.DownloadURL("3.5.13", "a"); got != "https://github.com/telemt/telemt/releases/download/3.5.13/a" {
		t.Errorf("DownloadURL = %q", got)
	}
	if _, ok := ComponentOf("postern"); ok {
		t.Error("postern is not a tracked component here")
	}
}

func TestPrepareKeepsConcurrentChanges(t *testing.T) {
	tc := newTestCatalog(t)
	ctx := context.Background()
	good := tarGz(t, member{name: "telemt", data: staticELF(t, amd64, "good")})
	tc.release(t, "telemt", "9.11.0", amd64, tgz, good, "", "")
	// While the download runs the stable list promotes the release and a poll
	// writes notes.
	tc.host.mu.Lock()
	tc.host.before = func(path string) {
		if !strings.HasSuffix(path, tgz) {
			return
		}
		rel, err := tc.db.ReleaseOf(ctx, "telemt", "9.11.0")
		if err != nil {
			t.Error(err)
			return
		}
		rel.Stable, rel.Notes = true, "promoted"
		if err := tc.db.UpsertRelease(ctx, rel); err != nil {
			t.Error(err)
		}
	}
	tc.host.mu.Unlock()
	if err := tc.Prepare(ctx, "telemt", "9.11.0", []string{amd64}); err != nil {
		t.Fatal(err)
	}
	rel, err := tc.db.ReleaseOf(ctx, "telemt", "9.11.0")
	if err != nil {
		t.Fatal(err)
	}
	if !rel.Stable || rel.Notes != "promoted" {
		t.Errorf("Prepare reverted a concurrent change: stable %v notes %q", rel.Stable, rel.Notes)
	}
	if a := rel.Assets[amd64]; a.State != store.AssetReady || a.SHA256 != sum(good) || a.SHASource != store.SHASourceTOFU {
		t.Errorf("asset = %+v", a)
	}
}

func TestPreparePinWithUnreachableSums(t *testing.T) {
	tc := newTestCatalog(t)
	ctx := context.Background()
	good := tarGz(t, member{name: "telemt", data: staticELF(t, amd64, "good")})
	tc.release(t, "telemt", "9.12.0", amd64, tgz, good, sum(good), store.SHASourceDigest)
	tc.host.mu.Lock()
	tc.host.status["/dl/9.12.0/"+tgz+".sha256"] = 503
	tc.host.mu.Unlock()
	if err := tc.Prepare(ctx, "telemt", "9.12.0", []string{amd64}); err != nil {
		t.Fatalf("Prepare with a 503 checksum file: %v", err)
	}
	if a := tc.assetOf(t, "telemt", "9.12.0", amd64); a.State != store.AssetReady {
		t.Errorf("asset = %+v", a)
	}
	// Without a pin the rules cannot be applied: no download, no verdict.
	tc.release(t, "telemt", "9.12.1", amd64, tgz, good, "", "")
	tc.host.mu.Lock()
	tc.host.status["/dl/9.12.1/"+tgz+".sha256"] = 503
	tc.host.mu.Unlock()
	if err := tc.Prepare(ctx, "telemt", "9.12.1", []string{amd64}); err == nil {
		t.Fatal("Prepare passed without a pin and without the checksum file")
	}
	if a := tc.assetOf(t, "telemt", "9.12.1", amd64); a.State != store.AssetUnchecked || tc.host.hitCount("/dl/9.12.1/"+tgz) != 0 {
		t.Errorf("asset = %+v, downloads %d", a, tc.host.hitCount("/dl/9.12.1/"+tgz))
	}
}

func TestSeedContinuesOnForeignPin(t *testing.T) {
	tc := newTestCatalog(t)
	ctx := context.Background()
	// A pin from elsewhere got there first and disagrees with the built-in one.
	rel := &store.Release{Engine: "mtg", Version: "v2.2.8", Assets: map[string]store.ReleaseAsset{
		amd64: {File: "mtg-2.2.8-linux-amd64.tar.gz", URL: "https://example.com/m", SHA256: strings.Repeat("a", 64), SHASource: store.SHASourceTOFU}}}
	if err := tc.db.UpsertRelease(ctx, rel); err != nil {
		t.Fatal(err)
	}
	if err := tc.Seed(ctx); err != nil {
		t.Fatalf("Seed aborted: %v", err)
	}
	if evs := tc.events(t, EventChecksumMismatch); len(evs) != 1 || evs[0].Details["from"] != "seed" {
		t.Errorf("events = %+v", evs)
	}
	// The other built-ins were seeded all the same.
	if _, err := tc.db.ReleaseOf(ctx, "telemt", "3.5.13"); err != nil {
		t.Errorf("telemt not seeded: %v", err)
	}
	if a := tc.assetOf(t, "mtg", "v2.2.8", amd64); a.SHA256 != strings.Repeat("a", 64) {
		t.Errorf("the foreign pin changed: %+v", a)
	}
}
