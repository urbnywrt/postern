package releases

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// The stable list: the asset engines-stable.json (and its .minisig) of the
// release with tag engines-stable in the Postern repository, signed with the
// stable key set.
const (
	stableTag          = "engines-stable"
	stableFile         = "engines-stable.json"
	stableSchema       = 1
	maxStableList      = 1 << 20         // the list
	stableMaxAhead     = 5 * time.Minute // how far ahead of the panel's clock a list may be
	EventStableApplied = "stable_list_applied"
)

// The answers of ApplyStable.
var (
	ErrBadList   = errors.New("releases: the stable list cannot be read")
	ErrStaleList = errors.New("releases: the stable list is older than the one that was applied")
	ErrListAhead = errors.New("releases: the stable list is more than 5 min ahead of the clock")
	// errNoStableList says that the release source has no stable list yet.
	errNoStableList = errors.New("releases: no stable list yet")
)

// A stableList is engines-stable.json.
type stableList struct {
	Schema      int64                    `json:"schema"`
	GeneratedAt int64                    `json:"generated_at"`
	Components  map[string][]stableEntry `json:"components"`
}

// A stableEntry is one release of a component in the list.
type stableEntry struct {
	Version string `json:"version"`
	// Tag is the release of Postern that holds the files of a Postern
	// component (psiphon-core); the other components have none.
	Tag    string                  `json:"tag,omitempty"`
	Assets map[string]BuiltinAsset `json:"assets"`
}

// posternSource returns the feed source of the Postern repository: the
// release source of the settings, with the source token (for GitHub, the
// GitHub token when there is no source token).
func (c *Catalog) posternSource(ctx context.Context) (FeedSource, error) {
	rs, err := c.db.ReleaseSource(ctx)
	if err != nil {
		return FeedSource{}, err
	}
	src := FeedSource{Kind: rs.Kind, APIBase: rs.BaseURL, Repo: rs.Repo, Token: c.sealedToken(ctx, store.SettingSourceToken)}
	if src.Kind == SourceGitHub {
		src.APIBase = c.apiBase
		if src.Token == "" {
			src.Token = c.githubToken(ctx)
		}
	}
	return src, nil
}

// tagURL returns the URL of the release with this tag in the API of src.
func (src FeedSource) tagURL(tag string) string {
	base := strings.TrimRight(src.APIBase, "/")
	if src.Kind == SourceGitea {
		return base + "/api/v1/repos/" + src.Repo + "/releases/tags/" + tag
	}
	return base + "/repos/" + src.Repo + "/releases/tags/" + tag
}

// refreshStable fetches the stable list from the Postern release source and
// applies it. A source without one yet is no error.
func (c *Catalog) refreshStable(ctx context.Context) error {
	src, err := c.posternSource(ctx)
	if err != nil {
		return err
	}
	list, sig, err := c.fetchStable(ctx, src)
	if errors.Is(err, errNoStableList) {
		c.log.Info("the release source has no stable list yet", "err", err)
		return nil
	}
	if err != nil {
		return err
	}
	return c.ApplyStable(ctx, list, sig)
}

// fetchStable reads the release with tag engines-stable through the API of
// src (a 404 is errNoStableList) and downloads its engines-stable.json and
// .minisig, the newest attachment of each name.
func (c *Catalog) fetchStable(ctx context.Context, src FeedSource) (list, sig []byte, err error) {
	if err := checkURLScheme(src.APIBase); err != nil {
		return nil, nil, err
	}
	body, _, _, err := fetchPage(ctx, c.http, c.lim, src, src.tagURL(stableTag), "")
	if errors.Is(err, errNotFound) {
		return nil, nil, fmt.Errorf("%w: %w", errNoStableList, err)
	}
	if err != nil {
		return nil, nil, err
	}
	assets, err := releaseAssets(src.Kind, body)
	if err != nil {
		return nil, nil, fmt.Errorf("releases: the %s release: %w", stableTag, err)
	}
	la, ok := assets[stableFile]
	sa, ok2 := assets[stableFile+".minisig"]
	if !ok || !ok2 {
		return nil, nil, fmt.Errorf("%w: the %s release has no %s with its .minisig", errNoStableList, stableTag, stableFile)
	}
	if list, err = c.getSmall(ctx, la.URL, &src, maxStableList); err != nil {
		return nil, nil, err
	}
	if sig, err = c.getSmall(ctx, sa.URL, &src, maxSumsFile); err != nil {
		return nil, nil, err
	}
	return list, sig, nil
}

// releaseAssets reads the assets of one release as the API of kind returns it,
// by name; of two with one name (Gitea, F9) the newest created_at is kept.
func releaseAssets(kind string, body []byte) (map[string]FeedAsset, error) {
	out := map[string]FeedAsset{}
	keep := func(name, u string, created time.Time) {
		if name == "" || u == "" {
			return
		}
		if o, dup := out[name]; dup && !created.After(o.Created) {
			return
		}
		out[name] = FeedAsset{Name: name, URL: u, Created: created}
	}
	if kind == SourceGitea {
		var r giteaRelease
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("decode: %w", err)
		}
		for _, a := range r.Assets {
			keep(a.Name, a.URL, parseTime(a.CreatedAt))
		}
		return out, nil
	}
	var r githubRelease
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	for _, a := range r.Assets {
		keep(a.Name, a.URL, parseTime(a.CreatedAt))
	}
	return out, nil
}

// ApplyStable applies a signed stable list: list is engines-stable.json and
// sig its .minisig, which has to be by a key of the stable key set for
// Signed{engines-stable, <generated_at>} (R5-6). A list older than the one
// that was applied is ErrStaleList; one more than 5 min ahead of the clock is
// ErrListAhead; one that cannot be read, or has another schema, ErrBadList.
// The same list again changes nothing.
//
// The releases that the list names become stable; one the panel does not know
// is created with source stable and the listed SHA-256 pinned. A release that
// was stable and is not listed loses the flag (its row stays); a built-in one
// stays stable. An entry that disagrees with a built-in pin is rejected and
// the built-in asset keeps its state (R5-4); one that disagrees with any other
// pin makes that asset unusable; both raise release_checksum_mismatch. A good
// list ends with the event stable_list_applied.
//
// ApplyStable reads and writes the setting releases.stable_generated_at, so
// two calls (the tracker's refreshStable, a bundle upload) are serialised by
// the catalog's lock.
func (c *Catalog) ApplyStable(ctx context.Context, list, sig []byte) error {
	c.stableMu.Lock()
	defer c.stableMu.Unlock()
	var sl stableList
	if err := json.Unmarshal(list, &sl); err != nil {
		return fmt.Errorf("%w: %w", ErrBadList, err)
	}
	if sl.Schema != stableSchema || sl.GeneratedAt <= 0 {
		return fmt.Errorf("%w: schema %d, generated_at %d", ErrBadList, sl.Schema, sl.GeneratedAt)
	}
	keys, err := c.keys(release.StableKeys)
	if err != nil {
		return err
	}
	want := release.Signed{Component: stableTag, Version: strconv.FormatInt(sl.GeneratedAt, 10)}
	if err := release.VerifyWith(bytes.NewReader(list), sig, want, keys); err != nil {
		return err
	}
	now := c.now()
	generated := time.Unix(sl.GeneratedAt, 0)
	if generated.After(now.Add(stableMaxAhead)) {
		return fmt.Errorf("%w: generated at %s, now %s", ErrListAhead, generated.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	var applied int64
	if _, err := c.db.GetSetting(ctx, store.SettingStableGeneratedAt, &applied); err != nil {
		return err
	}
	if sl.GeneratedAt < applied {
		return fmt.Errorf("%w: generated at %d, applied %d", ErrStaleList, sl.GeneratedAt, applied)
	}
	if sl.GeneratedAt == applied {
		c.log.Debug("the stable list is the one that was applied", "generated_at", applied)
		return nil
	}

	listed := map[string]map[string]bool{} // component → version → true
	var count, rejected int
	for name, entries := range sl.Components {
		comp, ok := ComponentOf(name)
		if !ok {
			c.log.Warn("the stable list names a component the panel does not know", "component", name)
			continue
		}
		listed[name] = map[string]bool{}
		for _, e := range entries {
			if !release.ValidVersion(e.Version) {
				c.log.Warn("the stable list names a version that is not one", "component", name, "version", e.Version)
				continue
			}
			ok, err := c.applyStableEntry(ctx, comp, e)
			if err != nil {
				return err
			}
			if !ok {
				rejected++
				continue
			}
			listed[name][e.Version] = true
			count++
		}
	}
	// What the previous list named and this one does not loses the flag.
	for _, comp := range Components {
		rels, err := c.db.ListReleases(ctx, comp.Name)
		if err != nil {
			return err
		}
		for _, rel := range rels {
			if !rel.Stable || rel.Source == store.SourceBuiltin || listed[comp.Name][rel.Version] {
				continue
			}
			rel.Stable = false
			if err := c.db.UpsertRelease(ctx, rel); err != nil {
				return err
			}
		}
	}
	if err := c.db.PutSetting(ctx, store.SettingStableGeneratedAt, sl.GeneratedAt); err != nil {
		return err
	}
	c.event(ctx, EventStableApplied, "info",
		fmt.Sprintf("the stable list of %s was applied: %d releases", generated.UTC().Format(time.RFC3339), count),
		map[string]string{"generated_at": strconv.FormatInt(sl.GeneratedAt, 10), "releases": strconv.Itoa(count), "rejected": strconv.Itoa(rejected)})
	return nil
}

// applyStableEntry makes one listed release stable, as ApplyStable documents,
// and reports whether the entry was taken (false: it disagrees with a built-in
// pin, or lists no asset the panel can take).
func (c *Catalog) applyStableEntry(ctx context.Context, comp Component, e stableEntry) (bool, error) {
	tag, relURL := e.Version, comp.ReleaseURL(e.Version)
	download := func(file string) string { return comp.DownloadURL(tag, file) }
	if comp.Postern {
		if PosternTag(e.Tag) == "" {
			c.log.Warn("the stable list names a release of a Postern component without the release of Postern that holds it", "component", comp.Name, "version", e.Version)
			return false, nil
		}
		rs, err := c.db.ReleaseSource(ctx)
		if err != nil {
			return false, err
		}
		tag, relURL = e.Tag, PosternReleaseURL(rs, e.Tag)
		download = func(file string) string { return PosternDownloadURL(rs, tag, file) }
	}
	rel, err := c.db.ReleaseOf(ctx, comp.Name, e.Version)
	switch {
	case errors.Is(err, store.ErrNotFound):
		rel = &store.Release{Engine: comp.Name, Version: e.Version, Tag: tag, Source: store.SourceStable,
			URL: relURL, FetchedAt: c.now(), Assets: map[string]store.ReleaseAsset{}}
	case err != nil:
		return false, err
	}
	assets := map[string]store.ReleaseAsset{}
	unusable := map[string]string{} // arch → the source of the pin that the list disagrees with
	for arch, la := range e.Assets {
		// The list has to name the component's own asset of the version for
		// the architecture, with a SHA-256; anything else is not for this panel.
		if la.File == "" || la.File != comp.AssetName(e.Version, arch) || !hex64.MatchString(la.SHA256) {
			c.log.Warn("the stable list has an asset the panel cannot take", "component", comp.Name, "version", e.Version, "arch", arch, "file", la.File)
			continue
		}
		old, has := rel.Assets[arch]
		if has && old.SHA256 != "" && old.SHA256 != la.SHA256 {
			c.event(ctx, EventChecksumMismatch, "error",
				fmt.Sprintf("%s %s %s: the stable list disagrees with the %s SHA-256", comp.Name, e.Version, arch, old.SHASource),
				map[string]string{"component": comp.Name, "version": e.Version, "arch": arch,
					"expected": old.SHA256, "got": la.SHA256, "source": old.SHASource, "from": "stable"})
			if old.SHASource == store.SHASourceBuiltin {
				// R5-4: the entry is rejected and the built-in asset is left as it is.
				return false, nil
			}
			unusable[arch] = old.SHASource
			continue
		}
		if has && old.SHA256 != "" {
			continue // the same pin: nothing to add
		}
		a := store.ReleaseAsset{File: la.File, URL: download(la.File), SHA256: la.SHA256, SHASource: store.SHASourceStable}
		if has && old.URL != "" {
			a.URL = old.URL // where the feed found the file
		}
		assets[arch] = a
	}
	rel.Stable = true
	rel.Assets = assets
	if err := c.db.UpsertRelease(ctx, rel); err != nil {
		return false, err
	}
	for arch, source := range unusable {
		c.setUnusable(ctx, comp, rel, arch, "the stable list disagrees with the "+source+" SHA-256")
	}
	return true, nil
}
