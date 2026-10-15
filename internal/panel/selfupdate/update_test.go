package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// An updateFixture is a data directory with a database, a cache that holds
// the binaries of v0.5.0, and an Updater of v0.4.0 that the launcher
// started.
type updateFixture struct {
	dir   string
	db    *store.DB
	s     *signer
	cache *Cache
	u     *Updater
	panel []byte // the panel binary of v0.5.0 (amd64)
	// versionOut is what `<binary> version` prints, by the binary's base
	// name prefix (".postern-panel-" for the staged one, "image" for the
	// image).
	versionOut map[string]string
	// onVersion, when set, is called with the path of a binary that is run
	// with `version`.
	onVersion func(path string)
}

func newUpdate(t *testing.T) *updateFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, DatabaseFile))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := newSigner(t)
	f := &updateFixture{dir: dir, db: db, s: s, cache: &Cache{Dir: filepath.Join(dir, "artifacts", "postern"), Keys: s.keys},
		versionOut: map[string]string{".postern-panel-": "v0.5.0 (abc1234, 2026-10-07T00:00:00Z)\n"}}
	f.panel = elfBin(t, "amd64", "panel v0.5.0")
	f.put(t, "v0.5.0", PanelAsset("amd64"), f.panel)
	f.put(t, "v0.5.0", NodeAsset("amd64"), elfBin(t, "amd64", "node v0.5.0"))
	f.put(t, "v0.5.0", NodeAsset("arm64"), elfBin(t, "arm64", "node v0.5.0"))
	f.u = &Updater{DataDir: dir, Releases: &Releases{DB: db, Cache: f.cache, Log: discard()}, DB: db, Version: "v0.4.0",
		HealthyFile: filepath.Join(dir, "run", "launcher", "healthy"), ImageBin: filepath.Join(dir, "image", "postern-panel"),
		Arch: "amd64", Log: discard(), Exec: f.exec}
	return f
}

func (f *updateFixture) put(t *testing.T, v, asset string, data []byte) {
	t.Helper()
	comp, arch, _ := ParseAsset(asset)
	if err := f.cache.Put(context.Background(), v, asset, bytes.NewReader(data), f.s.sign(t, data, comp, v, arch)); err != nil {
		t.Fatalf("Put %s: %v", asset, err)
	}
}

// exec fakes `version`, and runs anything else (the trial script of bin).
func (f *updateFixture) exec(ctx context.Context, path string, args ...string) ([]byte, error) {
	if len(args) == 1 && args[0] == "version" {
		if f.onVersion != nil {
			f.onVersion(path)
		}
		for prefix, out := range f.versionOut {
			if strings.HasPrefix(filepath.Base(path), prefix) {
				return []byte(out), nil
			}
		}
		return nil, errors.New("exec: no such file")
	}
	return runBinary(ctx, path, args...)
}

func (f *updateFixture) bin(name string) string { return filepath.Join(f.dir, "bin", name) }

func (f *updateFixture) link(t *testing.T, name string) string {
	t.Helper()
	target, err := os.Readlink(f.bin(name))
	if err != nil {
		t.Fatalf("bin/%s: %v", name, err)
	}
	return target
}

// binEntries lists bin, without the trial leftovers that must not be there
// either.
func (f *updateFixture) binEntries(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.dir, "bin"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestUpdateInstallsWithTheImageAsPrevious(t *testing.T) {
	f := newUpdate(t)
	ctx := context.Background()
	if err := f.u.Update(ctx, "v0.5.0"); !errors.Is(err, ErrRestart) {
		t.Fatalf("Update: %v, want ErrRestart", err)
	}
	got, err := os.ReadFile(f.bin("postern-panel-v0.5.0"))
	if err != nil || !bytes.Equal(got, f.panel) {
		t.Fatalf("the installed binary: %v (same bytes: %v)", err, bytes.Equal(got, f.panel))
	}
	if fi, _ := os.Stat(f.bin("postern-panel-v0.5.0")); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if c := f.link(t, "current"); c != "postern-panel-v0.5.0" {
		t.Errorf("current -> %q", c)
	}
	if p := f.link(t, "previous"); p != f.u.ImageBin || !filepath.IsAbs(p) {
		t.Errorf("previous -> %q, want the image binary %q", p, f.u.ImageBin)
	}
	if names := f.binEntries(t); len(names) != 3 {
		t.Errorf("bin holds %v, want the binary and two links", names)
	}

	var j journal
	data, err := os.ReadFile(filepath.Join(f.dir, journalFile))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	if err := json.Unmarshal(data, &j); err != nil || j.From != "v0.4.0" || j.To != "v0.5.0" || j.At == 0 || j.Backup == "" {
		t.Fatalf("journal %s: %v", data, err)
	}
	rel, err := f.db.ReleaseOf(ctx, ComponentPostern, "v0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(f.panel)
	if pin := rel.Assets[PanelPinKey("amd64")]; pin.File != PanelAsset("amd64") || pin.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("the panel binary is not pinned: %+v", pin)
	}
	if !strings.Contains(filepath.Base(j.Backup), "pre-v0.5.0") {
		t.Errorf("backup %s is not labelled", j.Backup)
	}
	// The snapshot is a database that opens.
	snap, err := sql.Open("sqlite", "file:"+j.Backup+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = snap.Close() }()
	var n int
	if err := snap.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil || n == 0 {
		t.Errorf("the snapshot: %d migrations, %v", n, err)
	}

	var audited int
	raw := rawDB(t, f.dir)
	if err := raw.QueryRow(`SELECT count(*) FROM audit_log WHERE action = ?`, AuditUpdateStarted).Scan(&audited); err != nil || audited != 1 {
		t.Errorf("audit rows %d, %v", audited, err)
	}
	// The node binaries were not fetched (they were cached), so no row.
	// A second update is refused: the panel restarts.
	if err := f.u.Update(ctx, "v0.5.0"); !errors.Is(err, ErrRefused) {
		t.Errorf("a second Update: %v", err)
	}
}

func rawDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", "file:"+filepath.Join(dir, DatabaseFile)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

func TestUpdateKeepsCurrentAsPrevious(t *testing.T) {
	f := newUpdate(t)
	if err := os.MkdirAll(filepath.Join(f.dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.bin("postern-panel-v0.4.0"), []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("postern-panel-v0.4.0", f.bin("current")); err != nil {
		t.Fatal(err)
	}
	if err := f.u.Update(context.Background(), "v0.5.0"); !errors.Is(err, ErrRestart) {
		t.Fatalf("Update: %v", err)
	}
	if p := f.link(t, "previous"); p != "postern-panel-v0.4.0" {
		t.Errorf("previous -> %q", p)
	}
	if c := f.link(t, "current"); c != "postern-panel-v0.5.0" {
		t.Errorf("current -> %q", c)
	}
}

// assertNothing checks that a refused update left no trace.
func (f *updateFixture) assertNothing(t *testing.T) {
	t.Helper()
	if names := f.binEntries(t); len(names) != 0 {
		t.Errorf("bin holds %v", names)
	}
	if _, err := os.Stat(filepath.Join(f.dir, journalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a journal: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(f.dir, "backups")); len(entries) != 0 {
		t.Errorf("backups: %d", len(entries))
	}
}

func TestUpdateRefusals(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name, version, want string
		setup               func(t *testing.T, f *updateFixture)
	}{
		{name: "a downgrade", version: "v0.3.0", want: "not newer"},
		{name: "the same version", version: "v0.4.0", want: "runs v0.4.0 already"},
		{name: "not under the launcher", version: "v0.5.0", want: "launcher",
			setup: func(_ *testing.T, f *updateFixture) { f.u.HealthyFile = "" }},
		{name: "an old node", version: "v0.5.0", want: "edge-old (v0.3.9)", setup: func(t *testing.T, f *updateFixture) {
			for _, n := range []*store.Node{{Name: "edge-old", AgentVersion: "v0.3.9"}, {Name: "edge-ok", AgentVersion: "v0.4.0"}, {Name: "fresh"}} {
				if err := f.db.CreateNode(ctx, n); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{name: "a failing trial", version: "v0.5.0", want: "does not run here", setup: func(_ *testing.T, f *updateFixture) {
			f.versionOut[".postern-panel-"] = "v0.4.9 (abc, d)\n"
		}},
		{name: "a panel binary that is not the pinned one", version: "v0.5.0", want: "pins", setup: func(t *testing.T, f *updateFixture) {
			rel := &store.Release{Engine: ComponentPostern, Version: "v0.5.0", Source: store.SourceUpload, Assets: map[string]store.ReleaseAsset{
				PanelPinKey("amd64"): {File: PanelAsset("amd64"), SHA256: strings.Repeat("cd", 32), SHASource: store.SHASourceSigned}}}
			if err := f.db.UpsertRelease(ctx, rel); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a binary changed during its trial", version: "v0.5.0", want: "staged", setup: func(t *testing.T, f *updateFixture) {
			f.onVersion = func(p string) {
				if err := os.WriteFile(p, append(append([]byte{}, f.panel...), 'x'), 0o755); err != nil {
					t.Error(err)
				}
			}
		}},
		{name: "a cached file that is not the pinned one", version: "v0.5.0", want: "pins", setup: func(t *testing.T, f *updateFixture) {
			rel := &store.Release{Engine: ComponentPostern, Version: "v0.5.0", Source: store.SourceUpload, Assets: map[string]store.ReleaseAsset{
				"arm64": {File: NodeAsset("arm64"), SHA256: strings.Repeat("ab", 32), SHASource: store.SHASourceSigned}}}
			if err := f.db.UpsertRelease(ctx, rel); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newUpdate(t)
			if c.setup != nil {
				c.setup(t, f)
			}
			err := f.u.Update(ctx, c.version)
			if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Update(%s): %v, want a refusal with %q", c.version, err, c.want)
			}
			f.assertNothing(t)
			// The lock is free again.
			if !f.u.mu.TryLock() {
				t.Fatal("the update lock is held")
			}
			f.u.mu.Unlock()
		})
	}
}

func TestAvailable(t *testing.T) {
	f := newUpdate(t)
	ctx := context.Background()
	if ok, reason := f.u.Available(ctx); !ok {
		t.Fatalf("Available: %s", reason)
	}
	if names := f.binEntries(t); len(names) != 0 {
		t.Errorf("the trial left %v", names)
	}
	// The stock image: no bin/current, the launcher ran the image binary and
	// handed over the marker path (B1). The first update is offered.
	if _, err := os.Lstat(filepath.Join(f.dir, "bin", "current")); !os.IsNotExist(err) {
		t.Fatalf("the fixture has a bin/current: %v", err)
	}
	if ok, reason := f.u.Available(ctx); !ok {
		t.Errorf("from the image binary: %s", reason)
	}
	// Without the marker path the reason says what is missing, and does not
	// claim that the launcher did not start the panel (it may have: an older
	// launcher set no marker for the image binary).
	hf := f.u.HealthyFile
	f.u.HealthyFile = ""
	if ok, reason := f.u.Available(ctx); ok || !strings.Contains(reason, "POSTERN_HEALTHY_FILE is not set") ||
		strings.Contains(reason, "was not started by its launcher") || !strings.Contains(reason, "restart the container") {
		t.Errorf("without the marker path: %v %q", ok, reason)
	}
	f.u.HealthyFile = hf
	f.u.Releases.Cache.Keys = func(release.KeySet) ([]minisign.PublicKey, error) { return nil, nil }
	if ok, reason := f.u.Available(ctx); ok || !strings.Contains(reason, "release key") {
		t.Errorf("without keys: %v %q", ok, reason)
	}
}

func TestMinorFloor(t *testing.T) {
	for v, want := range map[string]string{"v0.5.0": "v0.4.0", "0.5.2": "0.4.0", "v1.0.0": "v0.0.0", "v2.3.0-rc.1": "v2.2.0", "v0.0.1": "", "dev": ""} {
		if got, _ := minorFloor(v); got != want {
			t.Errorf("minorFloor(%s) = %q, want %q", v, got, want)
		}
	}
}

func TestNewerListsRecordedReleases(t *testing.T) {
	f := newUpdate(t)
	ctx := context.Background()
	for _, v := range []string{"v0.3.0", "v0.5.0", "v0.6.0"} {
		if err := f.db.UpsertRelease(ctx, &store.Release{Engine: ComponentPostern, Version: v, Source: store.SourceUpload, Assets: map[string]store.ReleaseAsset{}}); err != nil {
			t.Fatal(err)
		}
	}
	f.u.Releases = nil // no source to list
	got, err := f.u.Newer(ctx)
	if err != nil || len(got) != 2 || got[0].Version != "v0.6.0" || got[1].Version != "v0.5.0" {
		t.Fatalf("Newer: %v %v", got, err)
	}
}

func TestUpdateFetchesWhatIsNotCachedAndRecordsTheRelease(t *testing.T) {
	f := newUpdate(t)
	ctx := context.Background()
	arm := elfBin(t, "arm64", "node v0.5.0 fetched")
	if err := os.Remove(filepath.Join(f.cache.Dir, "v0.5.0", NodeAsset("arm64"))); err != nil {
		t.Fatal(err)
	}
	host := newFakeHost(t)
	name := NodeAsset("arm64")
	host.put("/gh/repos/urbnywrt/postern/releases", []byte(`[{"tag_name":"v0.5.0","prerelease":false,"assets":[`+
		`{"name":"`+name+`","browser_download_url":"`+host.url("/dl/"+name)+`"},`+
		`{"name":"`+name+`.minisig","browser_download_url":"`+host.url("/dl/"+name+".minisig")+`"}]}]`))
	host.put("/dl/"+name, arm)
	host.put("/dl/"+name+".minisig", f.s.sign(t, arm, "postern-node", "v0.5.0", "arm64"))
	f.u.Releases.HTTP, f.u.Releases.APIBase, f.u.Releases.Key = host.srv.Client(), host.url("/gh"), testKey(t)

	if err := f.u.Update(ctx, "v0.5.0"); !errors.Is(err, ErrRestart) {
		t.Fatalf("Update: %v", err)
	}
	if _, ok := f.cache.cachedSHA("v0.5.0", name); !ok {
		t.Error("the node binary was not fetched")
	}
	rel, err := f.db.ReleaseOf(ctx, ComponentPostern, "v0.5.0")
	if err != nil {
		t.Fatalf("the release row: %v", err)
	}
	if a := rel.Assets["arm64"]; a.File != name || a.SHA256 == "" || rel.Source != store.SourceUpstream {
		t.Errorf("row %+v", rel)
	}
}
