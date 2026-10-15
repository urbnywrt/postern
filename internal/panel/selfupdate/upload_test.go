package selfupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// A fakeStable records what ApplyStable was given, and fails when told to.
type fakeStable struct {
	calls [][2][]byte
	err   error
}

func (f *fakeStable) ApplyStable(_ context.Context, list, sig []byte) error {
	f.calls = append(f.calls, [2][]byte{list, sig})
	return f.err
}

type uploadFixture struct {
	s      *signer
	cache  *Cache
	db     *store.DB
	dbPath string
	stable *fakeStable
	h      http.Handler // without the admin check
	admin  http.Handler // with it
}

func newUpload(t testing.TB) *uploadFixture {
	t.Helper()
	s := newSigner(t)
	dbPath := filepath.Join(t.TempDir(), "panel.db")
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := &uploadFixture{s: s, cache: &Cache{Dir: filepath.Join(t.TempDir(), "artifacts", "postern"), Keys: s.keys}, db: db, dbPath: dbPath, stable: &fakeStable{}}
	cfg := UploadConfig{Cache: f.cache, DB: f.db, Stable: f.stable, Log: discard(), MaxBytes: 1 << 20}
	f.h = http.HandlerFunc(cfg.serveUpload)
	f.admin = UploadHandler(cfg)
	return f
}

// good is a complete bundle of version v: the four binaries with their
// signatures.
func (f *uploadFixture) good(t testing.TB, v string) []member {
	t.Helper()
	var ms []member
	for _, comp := range []string{"postern-node", "postern-panel"} {
		for _, arch := range []string{"amd64", "arm64"} {
			bin := elfBin(t, arch, comp+v)
			name := comp + "-linux-" + arch
			ms = append(ms, member{name, bin}, member{name + ".minisig", f.s.sign(t, bin, comp, v, arch)})
		}
	}
	return ms
}

func (f *uploadFixture) post(t testing.TB, h http.Handler, body []byte, ctype string) (*httptest.ResponseRecorder, UploadResult) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, UploadRoute, bytes.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var res UploadResult
	if rr.Header().Get("Content-Type") == "application/json" {
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
			t.Fatalf("the answer is not JSON: %v: %s", err, rr.Body.String())
		}
	}
	return rr, res
}

// kept returns the files under the cache, relative, sorted.
func (f *uploadFixture) kept(t testing.TB) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(f.cache.Dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(f.cache.Dir, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

func TestUploadAcceptsAWholeBundle(t *testing.T) {
	f := newUpload(t)
	ms := f.good(t, "v0.5.0")
	list := []byte(`{"schema":1}`)
	ms = append(ms, member{"engines-stable.json", list}, member{"engines-stable.json.minisig", []byte("untrusted comment: x\n")})
	rr, res := f.post(t, f.h, tarOf(t, ms...), "application/x-tar")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if !res.Accepted || res.Version != "v0.5.0" || len(res.Assets) != 4 {
		t.Fatalf("result: %+v", res)
	}
	for _, a := range res.Assets {
		if !a.OK || a.Reason != "" {
			t.Errorf("asset %s: ok=%v reason=%q", a.Name, a.OK, a.Reason)
		}
	}
	if res.Stable == nil || !res.Stable.Applied || len(f.stable.calls) != 1 || !bytes.Equal(f.stable.calls[0][0], list) {
		t.Errorf("the stable list was not applied: %+v, %d calls", res.Stable, len(f.stable.calls))
	}
	if got := f.kept(t); len(got) != 8 || got[0] != "v0.5.0/postern-node-linux-amd64" {
		t.Errorf("kept: %v", got)
	}
	for _, name := range []string{NodeAsset("amd64"), NodeAsset("arm64"), PanelAsset("amd64"), PanelAsset("arm64")} {
		rc, _, err := f.cache.Open("v0.5.0", name)
		if err != nil {
			t.Errorf("Open %s: %v", name, err)
			continue
		}
		_ = rc.Close()
	}
	rel, err := f.db.ReleaseOf(context.Background(), ComponentPostern, "v0.5.0")
	if err != nil {
		t.Fatalf("the release was not recorded: %v", err)
	}
	if rel.Source != store.SourceUpload || rel.Assets["amd64"].File != NodeAsset("amd64") || rel.Assets["arm64"].State != store.AssetReady || rel.Assets["amd64"].SHA256 == "" {
		t.Errorf("recorded release: %+v", rel)
	}
	// The stable list alone is refused.
	rr, res = f.post(t, f.h, tarOf(t, member{"engines-stable.json", list}), "application/x-tar")
	if rr.Code != http.StatusUnprocessableEntity || res.Accepted {
		t.Errorf("a bundle without binaries: %d %+v", rr.Code, res)
	}
}

func TestUploadKeepsNothingOfABadBundle(t *testing.T) {
	f := newUpload(t)
	other := newSigner(t)
	ms := f.good(t, "v0.5.0")
	// One asset signed by another key; another whose comment names the other arch.
	ms[1].data = other.sign(t, ms[0].data, "postern-node", "v0.5.0", "amd64")
	ms[5].data = f.s.sign(t, ms[4].data, "postern-panel", "v0.5.0", "arm64")
	// A stray signature without its asset, and a member with a path.
	ms = append(ms, member{"../x", []byte("x")}, member{"sub/postern-node-linux-amd64", []byte("x")},
		member{"engines-stable.json", []byte("{}")}, member{"engines-stable.json.minisig", []byte("sig")})
	rr, res := f.post(t, f.h, tarOf(t, ms...), "application/x-tar")
	if rr.Code != http.StatusUnprocessableEntity || res.Accepted {
		t.Fatalf("status %d accepted %v: %s", rr.Code, res.Accepted, rr.Body.String())
	}
	reasons := map[string]string{}
	for _, a := range res.Assets {
		reasons[a.Name] = a.Reason
	}
	if !strings.Contains(reasons["postern-node-linux-amd64"], "not trusted") {
		t.Errorf("the asset by another key: %q", reasons["postern-node-linux-amd64"])
	}
	if !strings.Contains(reasons["postern-panel-linux-amd64"], "another artifact") {
		t.Errorf("the asset with another arch in its comment: %q", reasons["postern-panel-linux-amd64"])
	}
	for _, good := range []string{"postern-node-linux-arm64", "postern-panel-linux-arm64"} {
		if r, ok := reasons[good]; !ok || r != "" {
			t.Errorf("the good asset %s: listed=%v reason %q", good, ok, r)
		}
	}
	if len(res.Ignored) != 2 {
		t.Errorf("ignored members: %v", res.Ignored)
	}
	if len(f.stable.calls) != 0 {
		t.Error("the stable list was applied though the bundle was refused")
	}
	if got := f.kept(t); len(got) != 0 {
		t.Errorf("kept: %v", got)
	}
	if _, err := f.db.ReleaseOf(context.Background(), ComponentPostern, "v0.5.0"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the release was recorded: %v", err)
	}
	entries, _ := os.ReadDir(f.cache.Dir)
	if len(entries) != 0 {
		t.Errorf("a temporary directory stayed: %v", entries)
	}
}

func TestUploadRefusesHalfBundles(t *testing.T) {
	f := newUpload(t)
	ms := f.good(t, "v0.5.0")
	cases := []struct {
		name string
		ms   []member
		want string
	}{
		{"a signature without its asset", append(ms[2:], member{"postern-node-linux-amd64.minisig", ms[1].data}), "no asset"},
		{"an asset without its signature", append([]member{ms[0]}, ms[2:]...), "no .minisig"},
		{"two versions", append(ms[2:], f.good(t, "v0.5.1")[:2]...), "version"},
		{"a member twice", append(ms, ms[0]), "twice"},
		{"a list without its signature", append(ms, member{"engines-stable.json", []byte("{}")}), "no .minisig"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr, res := f.post(t, f.h, tarOf(t, tc.ms...), "application/x-tar")
			if rr.Code != http.StatusUnprocessableEntity || res.Accepted {
				t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
			}
			found := false
			for _, a := range res.Assets {
				found = found || strings.Contains(a.Reason, tc.want)
			}
			if res.Stable != nil && strings.Contains(res.Stable.Reason, tc.want) {
				found = true
			}
			if !found {
				t.Errorf("no reason says %q: %s", tc.want, rr.Body.String())
			}
			if got := f.kept(t); len(got) != 0 {
				t.Errorf("kept: %v", got)
			}
		})
	}
}

func TestUploadRefusesBadRequests(t *testing.T) {
	f := newUpload(t)
	good := tarOf(t, f.good(t, "v0.5.0")...)
	t.Run("truncated tar", func(t *testing.T) {
		rr, _ := f.post(t, f.h, good[:len(good)-2000], "application/x-tar")
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status %d: %s", rr.Code, rr.Body.String())
		}
		if got := f.kept(t); len(got) != 0 {
			t.Errorf("kept: %v", got)
		}
	})
	t.Run("not a tar", func(t *testing.T) {
		rr, _ := f.post(t, f.h, []byte("hello"), "application/x-tar")
		if rr.Code != http.StatusBadRequest {
			t.Errorf("status %d", rr.Code)
		}
	})
	t.Run("wrong content type", func(t *testing.T) {
		rr, _ := f.post(t, f.h, good, "application/octet-stream")
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Errorf("status %d", rr.Code)
		}
	})
	t.Run("too large", func(t *testing.T) {
		big := tarOf(t, member{"postern-node-linux-amd64", bytes.Repeat([]byte{1}, 1<<20)})
		rr, _ := f.post(t, f.h, big, "application/x-tar")
		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status %d", rr.Code)
		}
		if got := f.kept(t); len(got) != 0 {
			t.Errorf("kept: %v", got)
		}
	})
	t.Run("method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, UploadRoute, nil)
		rr := httptest.NewRecorder()
		f.h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("status %d", rr.Code)
		}
	})
	t.Run("no admin", func(t *testing.T) {
		rr, _ := f.post(t, f.admin, good, "application/x-tar")
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("status %d", rr.Code)
		}
		if got := f.kept(t); len(got) != 0 {
			t.Errorf("kept: %v", got)
		}
	})
	if entries, _ := os.ReadDir(f.cache.Dir); len(entries) != 0 {
		t.Errorf("something stayed under the cache: %v", entries)
	}
}

// A bundle that updates a version that is cached already replaces its files.
func TestUploadReplacesACachedVersion(t *testing.T) {
	f := newUpload(t)
	if rr, _ := f.post(t, f.h, tarOf(t, f.good(t, "v0.5.0")[:2]...), "application/x-tar"); rr.Code != http.StatusOK {
		t.Fatalf("first: %d %s", rr.Code, rr.Body.String())
	}
	ms := f.good(t, "v0.5.0")
	if rr, _ := f.post(t, f.h, tarOf(t, ms[2:]...), "application/x-tar"); rr.Code != http.StatusOK {
		t.Fatalf("second: %d %s", rr.Code, rr.Body.String())
	}
	if got := f.kept(t); len(got) != 8 {
		t.Errorf("kept: %v", got)
	}
	rc, _, err := f.cache.Open("v0.5.0", NodeAsset("amd64"))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(data, ms[0].data) {
		t.Error("the first upload's asset is gone")
	}
}

// A fakeProviders is the release catalog for the provider binaries: it pins
// the SHA-256s in pins (by arch) and records what it was given.
type fakeProviders struct {
	pins  map[string]string
	taken map[string][2][]byte // by arch: the file, the signature
}

func (f *fakeProviders) PinnedVersion(_ context.Context, comp, arch, sha string) (string, error) {
	if comp != "psiphon-core" || f.pins[arch] != sha {
		return "", errors.New("no release pins it")
	}
	return "20261005-c4a09096ab", nil
}

func (f *fakeProviders) TakeUploaded(ctx context.Context, comp, arch, path string, sig []byte) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if f.taken == nil {
		f.taken = map[string][2][]byte{}
	}
	f.taken[arch] = [2][]byte{data, sig}
	return f.PinnedVersion(ctx, comp, arch, sha256Of(data))
}

// F2 of the real-server pass: a bundle may bring psiphon-core-linux-<arch>,
// verified as the other binaries are (a release key, its component, version and
// arch, a static ELF) and pinned by the catalog; it goes to the catalog, not to
// the cache of Postern's own binaries.
func TestUploadTakesPsiphonCore(t *testing.T) {
	const v = "v0.5.0"
	psiphon := func(f *uploadFixture, arch string) (bin []byte, ms []member) {
		bin = elfBin(t, arch, "psiphon "+arch)
		name := "psiphon-core-linux-" + arch
		return bin, []member{{name, bin}, {name + ".minisig", f.s.sign(t, bin, "psiphon-core", v, arch)}}
	}
	setup := func(t *testing.T, providers bool) (*uploadFixture, *fakeProviders) {
		f := newUpload(t)
		fp := &fakeProviders{pins: map[string]string{}}
		cfg := UploadConfig{Cache: f.cache, DB: f.db, Stable: f.stable, Log: discard(), MaxBytes: 4 << 20}
		if providers {
			cfg.Providers = fp
		}
		f.h = http.HandlerFunc(cfg.serveUpload)
		return f, fp
	}

	t.Run("with the binaries of Postern", func(t *testing.T) {
		f, fp := setup(t, true)
		ms := f.good(t, v)
		for _, arch := range []string{"amd64", "arm64"} {
			bin, pm := psiphon(f, arch)
			fp.pins[arch] = sha256Of(bin)
			ms = append(ms, pm...)
		}
		rr, res := f.post(t, f.h, tarOf(t, ms...), "application/x-tar")
		if rr.Code != http.StatusOK || !res.Accepted || len(res.Assets) != 6 || len(res.Ignored) != 0 {
			t.Fatalf("status %d: %+v", rr.Code, res)
		}
		if len(fp.taken) != 2 || !bytes.Equal(fp.taken["arm64"][0], elfBin(t, "arm64", "psiphon arm64")) || len(fp.taken["arm64"][1]) == 0 {
			t.Errorf("the catalog got %d binaries", len(fp.taken))
		}
		for _, k := range f.kept(t) {
			if strings.Contains(k, "psiphon") {
				t.Errorf("the cache of Postern's binaries keeps %s", k)
			}
		}
		if got := f.kept(t); len(got) != 8 {
			t.Errorf("kept %v", got)
		}
	})

	t.Run("alone", func(t *testing.T) {
		f, fp := setup(t, true)
		bin, ms := psiphon(f, "amd64")
		fp.pins["amd64"] = sha256Of(bin)
		rr, res := f.post(t, f.h, tarOf(t, ms...), "application/x-tar")
		if rr.Code != http.StatusOK || !res.Accepted || res.Version != v || len(fp.taken) != 1 {
			t.Fatalf("status %d: %+v", rr.Code, res)
		}
		if got := f.kept(t); len(got) != 0 {
			t.Errorf("kept %v", got)
		}
		if _, err := f.db.ReleaseOf(context.Background(), ComponentPostern, v); err == nil {
			t.Error("a release of Postern was recorded for a bundle with no binary of Postern")
		}
	})

	for _, c := range []struct {
		name, want string
		providers  bool
		edit       func(f *uploadFixture, fp *fakeProviders, ms []member) []member
	}{
		{"not the pinned binary", "pins", true, func(_ *uploadFixture, _ *fakeProviders, ms []member) []member { return ms }},
		{"no catalog", "no release catalog", false, func(_ *uploadFixture, fp *fakeProviders, ms []member) []member {
			fp.pins["amd64"] = sha256Of(ms[0].data)
			return ms
		}},
		{"a signature for another component", "signature", true, func(f *uploadFixture, fp *fakeProviders, ms []member) []member {
			fp.pins["amd64"] = sha256Of(ms[0].data)
			ms[1].data = f.s.sign(t, ms[0].data, "postern-node", v, "amd64")
			return ms
		}},
		{"a signature for another arch", "signature", true, func(f *uploadFixture, fp *fakeProviders, ms []member) []member {
			fp.pins["amd64"] = sha256Of(ms[0].data)
			ms[1].data = f.s.sign(t, ms[0].data, "psiphon-core", v, "arm64")
			return ms
		}},
		{"no signature", "no .minisig", true, func(_ *uploadFixture, fp *fakeProviders, ms []member) []member {
			fp.pins["amd64"] = sha256Of(ms[0].data)
			return ms[:1]
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, fp := setup(t, c.providers)
			_, pm := psiphon(f, "amd64")
			pm = c.edit(f, fp, pm)
			ms := append(f.good(t, v), pm...)
			rr, res := f.post(t, f.h, tarOf(t, ms...), "application/x-tar")
			if rr.Code != http.StatusUnprocessableEntity || res.Accepted {
				t.Fatalf("status %d: %+v", rr.Code, res)
			}
			found := false
			for _, a := range res.Assets {
				if a.Name == "psiphon-core-linux-amd64" {
					found = !a.OK && strings.Contains(a.Reason, c.want)
				}
			}
			if !found {
				t.Errorf("assets %+v; want psiphon-core-linux-amd64 refused with %q", res.Assets, c.want)
			}
			if len(fp.taken) != 0 || len(f.kept(t)) != 0 {
				t.Errorf("kept %v, the catalog took %d", f.kept(t), len(fp.taken))
			}
		})
	}
}

// The catalog takes a provider binary only after Postern's own binaries are in:
// when committing those fails, it was given nothing.
func TestUploadTakesProvidersOnlyAfterTheOwnBinaries(t *testing.T) {
	const v = "v0.5.0"
	f := newUpload(t)
	fp := &fakeProviders{pins: map[string]string{}}
	cfg := UploadConfig{Cache: f.cache, DB: f.db, Stable: f.stable, Log: discard(), MaxBytes: 4 << 20, Providers: fp}
	f.h = http.HandlerFunc(cfg.serveUpload)
	bin := elfBin(t, "amd64", "psiphon amd64")
	fp.pins["amd64"] = sha256Of(bin)
	ms := append(f.good(t, v),
		member{"psiphon-core-linux-amd64", bin},
		member{"psiphon-core-linux-amd64.minisig", f.s.sign(t, bin, "psiphon-core", v, "amd64")})
	// A file where the version's directory goes: the commit of the own
	// binaries cannot succeed.
	if err := os.MkdirAll(f.cache.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.cache.Dir, v), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	rr, res := f.post(t, f.h, tarOf(t, ms...), "application/x-tar")
	if res.Accepted {
		t.Fatalf("accepted (status %d) though the own binaries cannot be kept", rr.Code)
	}
	if len(fp.taken) != 0 {
		t.Errorf("the catalog took %d binaries before the own ones were in", len(fp.taken))
	}
}
