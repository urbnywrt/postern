package releases

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"aead.dev/minisign"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// A signer holds a stable key pair and a release key pair, and signs lists.
type signer struct {
	stablePub, releasePub   minisign.PublicKey
	stablePriv, releasePriv minisign.PrivateKey
}

func newSigner(t testing.TB) *signer {
	t.Helper()
	s := &signer{}
	var err error
	if s.stablePub, s.stablePriv, err = minisign.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	if s.releasePub, s.releasePriv, err = minisign.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	return s
}

// keys is the Config.Keys of a catalog that trusts the signer's keys.
func (s *signer) keys(set release.KeySet) ([]minisign.PublicKey, error) {
	if set == release.StableKeys {
		return []minisign.PublicKey{s.stablePub}, nil
	}
	return []minisign.PublicKey{s.releasePub}, nil
}

// entry is one release of a component in a stable list.
type entry struct {
	Version string                  `json:"version"`
	Assets  map[string]BuiltinAsset `json:"assets"`
}

// list encodes a stable list.
func stableListJSON(t testing.TB, generatedAt int64, comps map[string][]entry) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"schema": 1, "generated_at": generatedAt, "components": comps})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sign signs the list with priv for generatedAt.
func (s *signer) sign(t testing.TB, list []byte, priv minisign.PrivateKey, generatedAt int64) []byte {
	t.Helper()
	sig, err := release.Sign(bytes.NewReader(list), priv, release.Signed{Component: "engines-stable", Version: strconv.FormatInt(generatedAt, 10)})
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func telemtEntry(version, sha string) entry {
	return entry{Version: version, Assets: map[string]BuiltinAsset{amd64: {File: tgz, SHA256: sha}}}
}

func TestStableList(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	shaA, shaB := sum([]byte("a")), sum([]byte("b"))
	mtgSHA, _ := BuiltinSHA("mtg", "v2.2.8", amd64)
	mtgEntry := func(sha string) entry {
		comp, _ := ComponentOf("mtg")
		return entry{Version: "v2.2.8", Assets: map[string]BuiltinAsset{amd64: {File: comp.AssetName("v2.2.8", amd64), SHA256: sha}}}
	}

	// setup returns a seeded catalog on the signer's keys at start.
	setup := func(t *testing.T) (*testCatalog, *signer, *clock) {
		t.Helper()
		clk := &clock{t: start}
		tc := newClockCatalog(t, clk)
		s := newSigner(t)
		tc.keys = s.keys
		if err := tc.Seed(ctx); err != nil {
			t.Fatal(err)
		}
		return tc, s, clk
	}
	gen := start.Unix()

	t.Run("good", func(t *testing.T) {
		tc, s, _ := setup(t)
		list := stableListJSON(t, gen, map[string][]entry{"telemt": {telemtEntry("9.0.0", shaA)}, "mtg": {mtgEntry(mtgSHA)}})
		if err := tc.ApplyStable(ctx, list, s.sign(t, list, s.stablePriv, gen)); err != nil {
			t.Fatalf("ApplyStable: %v", err)
		}
		rel, err := tc.db.ReleaseOf(ctx, "telemt", "9.0.0")
		if err != nil {
			t.Fatal(err)
		}
		comp, _ := ComponentOf("telemt")
		a := rel.Assets[amd64]
		if !rel.Stable || rel.Source != store.SourceStable || a.SHA256 != shaA || a.SHASource != store.SHASourceStable ||
			a.State != store.AssetUnchecked || a.File != tgz || a.URL != comp.DownloadURL("9.0.0", tgz) {
			t.Errorf("9.0.0 = %+v", rel)
		}
		var applied int64
		if _, err := tc.db.GetSetting(ctx, store.SettingStableGeneratedAt, &applied); err != nil || applied != gen {
			t.Errorf("stable_generated_at = %d, %v; want %d", applied, err, gen)
		}
		if evs := tc.events(t, EventStableApplied); len(evs) != 1 || evs[0].Severity != "info" {
			t.Errorf("events = %+v", evs)
		}
		if evs := tc.events(t, EventChecksumMismatch); len(evs) != 0 {
			t.Errorf("mismatch events = %+v", evs)
		}
		// The same list again is nothing new.
		if err := tc.ApplyStable(ctx, list, s.sign(t, list, s.stablePriv, gen)); err != nil {
			t.Errorf("ApplyStable again: %v", err)
		}
		if evs := tc.events(t, EventStableApplied); len(evs) != 1 {
			t.Errorf("applied events after a repeat = %d, want 1", len(evs))
		}
	})

	t.Run("refused lists", func(t *testing.T) {
		tc, s, clk := setup(t)
		list := stableListJSON(t, gen, map[string][]entry{"telemt": {telemtEntry("9.0.0", shaA)}})
		good := s.sign(t, list, s.stablePriv, gen)
		tampered := bytes.Replace(list, []byte(shaA), []byte(shaB), 1)
		if err := tc.ApplyStable(ctx, tampered, good); !errors.Is(err, release.ErrBadSignature) {
			t.Errorf("tampered list: %v, want ErrBadSignature", err)
		}
		if err := tc.ApplyStable(ctx, list, s.sign(t, list, s.releasePriv, gen)); !errors.Is(err, release.ErrUntrustedKey) {
			t.Errorf("signed by a release key: %v, want ErrUntrustedKey", err)
		}
		ahead := stableListJSON(t, gen+6*60, nil)
		if err := tc.ApplyStable(ctx, ahead, s.sign(t, ahead, s.stablePriv, gen+6*60)); !errors.Is(err, ErrListAhead) {
			t.Errorf("6 min ahead: %v, want ErrListAhead", err)
		}
		within := stableListJSON(t, gen+4*60, nil)
		if err := tc.ApplyStable(ctx, within, s.sign(t, within, s.stablePriv, gen+4*60)); err != nil {
			t.Errorf("4 min ahead: %v", err)
		}
		clk.advance(10 * time.Minute)
		if err := tc.ApplyStable(ctx, list, good); !errors.Is(err, ErrStaleList) {
			t.Errorf("older list: %v, want ErrStaleList", err)
		}
		// One second older than the applied one is older.
		edge := stableListJSON(t, gen+4*60-1, nil)
		if err := tc.ApplyStable(ctx, edge, s.sign(t, edge, s.stablePriv, gen+4*60-1)); !errors.Is(err, ErrStaleList) {
			t.Errorf("list 1 s older than the applied one: %v, want ErrStaleList", err)
		}
		if tc.Known(ctx, "telemt", "9.0.0") {
			t.Error("a refused list created a release")
		}
		bad := []byte(`{"schema":2,"generated_at":1,"components":{}}`)
		if err := tc.ApplyStable(ctx, bad, s.sign(t, bad, s.stablePriv, 1)); !errors.Is(err, ErrBadList) {
			t.Errorf("schema 2: %v, want ErrBadList", err)
		}
		if err := tc.ApplyStable(ctx, []byte("{"), good); !errors.Is(err, ErrBadList) {
			t.Errorf("not JSON: %v, want ErrBadList", err)
		}
	})

	t.Run("a dropped version loses the flag, a built-in does not", func(t *testing.T) {
		tc, s, clk := setup(t)
		first := stableListJSON(t, gen, map[string][]entry{"telemt": {telemtEntry("9.0.0", shaA)}})
		if err := tc.ApplyStable(ctx, first, s.sign(t, first, s.stablePriv, gen)); err != nil {
			t.Fatal(err)
		}
		clk.advance(time.Hour)
		second := stableListJSON(t, gen+3600, map[string][]entry{"telemt": {telemtEntry("9.0.1", shaB)}})
		if err := tc.ApplyStable(ctx, second, s.sign(t, second, s.stablePriv, gen+3600)); err != nil {
			t.Fatal(err)
		}
		old, err := tc.db.ReleaseOf(ctx, "telemt", "9.0.0")
		if err != nil || old.Stable || old.Assets[amd64].SHA256 != shaA {
			t.Errorf("dropped 9.0.0 = %+v, %v; want kept, not stable, still pinned", old, err)
		}
		if r, _ := tc.db.ReleaseOf(ctx, "telemt", "9.0.1"); r == nil || !r.Stable {
			t.Errorf("9.0.1 = %+v, want stable", r)
		}
		for _, b := range Builtins() {
			if r, _ := tc.db.ReleaseOf(ctx, b.Component, b.Version); r == nil || !r.Stable || r.Source != store.SourceBuiltin {
				t.Errorf("built-in %s %s = %+v, want stable", b.Component, b.Version, r)
			}
		}
	})

	t.Run("disagreeing with a built-in pin is rejected", func(t *testing.T) {
		tc, s, _ := setup(t)
		if err := tc.db.SetAssetState(ctx, "mtg", "v2.2.8", amd64, store.AssetReady, "", ""); err != nil {
			t.Fatal(err)
		}
		list := stableListJSON(t, gen, map[string][]entry{"mtg": {mtgEntry(shaB)}, "telemt": {telemtEntry("9.0.0", shaA)}})
		if err := tc.ApplyStable(ctx, list, s.sign(t, list, s.stablePriv, gen)); err != nil {
			t.Fatalf("ApplyStable: %v", err)
		}
		a := tc.assetOf(t, "mtg", "v2.2.8", amd64)
		if a.SHA256 != mtgSHA || a.SHASource != store.SHASourceBuiltin || a.State != store.AssetReady {
			t.Errorf("built-in mtg asset = %+v, want untouched and ready", a)
		}
		evs := tc.events(t, EventChecksumMismatch)
		if len(evs) != 1 || evs[0].Severity != "error" || evs[0].Details["source"] != store.SHASourceBuiltin || evs[0].Details["from"] != "stable" {
			t.Errorf("mismatch events = %+v", evs)
		}
		// The rest of the list still applies.
		if r, _ := tc.db.ReleaseOf(ctx, "telemt", "9.0.0"); r == nil || !r.Stable {
			t.Errorf("9.0.0 = %+v, want stable", r)
		}
	})

	t.Run("disagreeing with a digest makes the asset unusable", func(t *testing.T) {
		tc, s, _ := setup(t)
		tc.release(t, "telemt", "9.0.0", amd64, tgz, []byte("x"), shaB, store.SHASourceDigest)
		list := stableListJSON(t, gen, map[string][]entry{"telemt": {telemtEntry("9.0.0", shaA)}})
		if err := tc.ApplyStable(ctx, list, s.sign(t, list, s.stablePriv, gen)); err != nil {
			t.Fatalf("ApplyStable: %v", err)
		}
		rel, _ := tc.db.ReleaseOf(ctx, "telemt", "9.0.0")
		a := rel.Assets[amd64]
		if a.SHA256 != shaB || a.SHASource != store.SHASourceDigest || a.State != store.AssetUnusable || a.Reason == "" {
			t.Errorf("asset = %+v, want the digest pin kept and unusable", a)
		}
		if !rel.Stable || rel.Source != store.SourceUpstream {
			t.Errorf("release = %+v, want stable, source upstream", rel)
		}
		if evs := tc.events(t, EventChecksumMismatch); len(evs) != 1 || evs[0].Details["source"] != store.SHASourceDigest {
			t.Errorf("mismatch events = %+v", evs)
		}
	})
}

// The stable list comes from the Postern release source: the release with tag
// engines-stable, through the API. A Gitea release with two attachments of one
// name gives the newest; a 404 means that there is no list yet.
func TestStableListFetch(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	gen := clk.now().Unix()
	tc := newClockCatalog(t, clk)
	s := newSigner(t)
	tc.keys = s.keys
	if err := tc.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	shaA, shaB := sum([]byte("a")), sum([]byte("b"))

	// No list yet: no error, nothing applied.
	if err := tc.refreshStable(ctx); err != nil {
		t.Errorf("refreshStable without a list: %v", err)
	}
	if tc.host.hitCount("/api/repos/urbnywrt/postern/releases/tags/engines-stable") != 1 {
		t.Error("the GitHub tag endpoint of the default source was not asked")
	}

	// Gitea, with the source token, two engines-stable.json attachments.
	if err := tc.db.PutReleaseSource(ctx, store.ReleaseSource{Kind: "gitea", BaseURL: tc.host.url(""), Repo: "o/r"}); err != nil {
		t.Fatal(err)
	}
	older := stableListJSON(t, gen-100, map[string][]entry{"telemt": {telemtEntry("9.0.0", shaA)}})
	newer := stableListJSON(t, gen, map[string][]entry{"telemt": {telemtEntry("9.0.1", shaB)}})
	tc.host.put("/att/1/engines-stable.json", older)
	tc.host.put("/att/2/engines-stable.json", newer)
	tc.host.put("/att/3/engines-stable.json.minisig", s.sign(t, newer, s.stablePriv, gen))
	att := func(id int, name, created string) string {
		return fmt.Sprintf(`{"id":%d,"name":%q,"browser_download_url":%q,"created_at":%q}`, id, name, tc.host.url(fmt.Sprintf("/att/%d/%s", id, name)), created)
	}
	tc.host.put("/api/v1/repos/o/r/releases/tags/engines-stable", []byte(fmt.Sprintf(`{"tag_name":"engines-stable","assets":[%s,%s,%s]}`,
		att(1, "engines-stable.json", "2026-10-01T00:00:00Z"), att(2, "engines-stable.json", "2026-10-03T00:00:00Z"),
		att(3, "engines-stable.json.minisig", "2026-10-03T00:00:00Z"))))
	if err := tc.refreshStable(ctx); err != nil {
		t.Fatalf("refreshStable from Gitea: %v", err)
	}
	if r, _ := tc.db.ReleaseOf(ctx, "telemt", "9.0.1"); r == nil || !r.Stable {
		t.Errorf("9.0.1 = %+v, want stable from the newest attachment", r)
	}
	if tc.Known(ctx, "telemt", "9.0.0") {
		t.Error("the older attachment was applied")
	}
	if tc.host.hitCount("/att/1/engines-stable.json") != 0 {
		t.Error("the older attachment was downloaded")
	}

	// GitHub, through the API base of the panel.
	if err := tc.db.PutReleaseSource(ctx, store.ReleaseSource{Kind: "github", Repo: "o/r"}); err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Hour)
	gen2 := clk.now().Unix()
	third := stableListJSON(t, gen2, map[string][]entry{"telemt": {telemtEntry("9.0.2", shaA)}})
	tc.host.put("/gh/engines-stable.json", third)
	tc.host.put("/gh/engines-stable.json.minisig", s.sign(t, third, s.stablePriv, gen2))
	tc.host.put("/api/repos/o/r/releases/tags/engines-stable", []byte(fmt.Sprintf(`{"tag_name":"engines-stable","assets":[{"name":"engines-stable.json","browser_download_url":%q},{"name":"engines-stable.json.minisig","browser_download_url":%q}]}`,
		tc.host.url("/gh/engines-stable.json"), tc.host.url("/gh/engines-stable.json.minisig"))))
	if err := tc.refreshStable(ctx); err != nil {
		t.Fatalf("refreshStable from GitHub: %v", err)
	}
	if r, _ := tc.db.ReleaseOf(ctx, "telemt", "9.0.2"); r == nil || !r.Stable {
		t.Errorf("9.0.2 = %+v, want stable", r)
	}
	if r, _ := tc.db.ReleaseOf(ctx, "telemt", "9.0.1"); r == nil || r.Stable {
		t.Errorf("9.0.1 after the new list = %+v, want kept and not stable", r)
	}
}
