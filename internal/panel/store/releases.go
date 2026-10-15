package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/release"
)

// The channels that a node follows (Node.EngineChannel, or the panel default,
// the setting SettingDefaultChannel, when that is empty) and that
// engine_channels holds a version for.
const (
	ChannelStable = "stable" // the built-in pins and the signed stable list
	ChannelLatest = "latest" // stable and every upstream release
)

// The values of Release.Source: where the panel learnt of a release.
const (
	SourceBuiltin  = "builtin"  // a pin compiled into the panel
	SourceUpstream = "upstream" // the release list of the upstream project
	SourceStable   = "stable"   // the signed stable list
	SourceUpload   = "upload"   // a bundle that an admin uploaded
)

// The values of ReleaseAsset.SHASource: where the pinned SHA-256 of an asset
// came from.
const (
	SHASourceBuiltin = "builtin" // compiled into the panel
	SHASourceDigest  = "digest"  // the digest of the release API
	SHASourceSums    = "sums"    // the checksum file of the release
	SHASourceTOFU    = "tofu"    // the first download that passed the checks
	SHASourceStable  = "stable"  // the signed stable list
	SHASourceSigned  = "signed"  // the signed checksum file of a Postern release
)

// The values of ReleaseAsset.State.
const (
	AssetUnchecked = "unchecked" // not downloaded and tried yet
	AssetReady     = "ready"     // downloaded, verified and tried
	AssetUnusable  = "unusable"  // failed a check; Reason says which
)

// ErrChecksumChanged is returned by [DB.UpsertRelease] when an asset that has a
// SHA-256 pinned is given another one. A pinned SHA-256 never changes.
var ErrChecksumChanged = errors.New("store: the pinned SHA-256 of an asset would change")

// A ReleaseAsset is the file of a release for one architecture.
type ReleaseAsset struct {
	File string // the name of the file on the release page
	URL  string // where to download it
	// SHA256 is the SHA-256 that the panel pins for the file, lower-case hex,
	// and "" until it is known. SHASource says where it came from, one of the
	// SHASource values. A pin never changes, and one that is built in stays
	// built in.
	SHA256    string
	SHASource string
	// State is one of the Asset values, AssetUnchecked when an asset is stored
	// without one. Reason says why the asset is unusable, NodeID which node's
	// trial run decided the state, and CheckedAt when.
	State     string
	Reason    string
	NodeID    string
	Size      int64
	CheckedAt time.Time
}

// A Release is one version of a component. Engine is the component: telemt,
// mtg, xray, psiphon-core or postern. Version is the upstream tag as published,
// and two versions are the same when their strings are.
type Release struct {
	Engine  string
	Version string
	Tag     string // the tag as published, when it is not the version
	Source  string // one of the Source values, SourceUpstream by default
	Notes   string // the release notes as published, text, at most 64 KiB
	URL     string // the page of the release
	// Stable says whether the version is in the stable channel. Prerelease is
	// the flag of the upstream release, never read from the tag.
	Stable      bool
	Prerelease  bool
	PublishedAt time.Time // the zero time when unknown
	FetchedAt   time.Time
	// Assets are the files of the release by architecture (amd64, arm64). A
	// release that is read, or was stored, always has the map, empty for no
	// assets: unlike the other JSON maps of the store it is never nil.
	Assets map[string]ReleaseAsset
}

// A Feed is a release list that the panel fetches, by its exact URL.
type Feed struct {
	URL       string
	Component string
	ETag      string    // the ETag of the last answer, as it was, "" for none
	CheckedAt time.Time // when it was last fetched; the zero time for never
	NextAt    time.Time // when it is due
	LastError string    // why the last fetch failed; "" when it did not
}

// assetJSON is how an asset is kept in the assets column.
type assetJSON struct {
	File      string `json:"file,omitempty"`
	URL       string `json:"url,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	SHASource string `json:"sha_source,omitempty"`
	State     string `json:"state,omitempty"`
	Reason    string `json:"reason,omitempty"`
	NodeID    string `json:"node_id,omitempty"`
	Size      int64  `json:"size,omitempty"`
	CheckedAt int64  `json:"checked_at,omitempty"` // Unix seconds, 0 for none
}

// encodeAssets returns the JSON of the assets, "{}" for none.
func encodeAssets(assets map[string]ReleaseAsset) (string, error) {
	if len(assets) == 0 {
		return "{}", nil
	}
	out := make(map[string]assetJSON, len(assets))
	for arch, a := range assets {
		out[arch] = assetJSON{
			File: a.File, URL: a.URL, SHA256: a.SHA256, SHASource: a.SHASource,
			State: a.State, Reason: a.Reason, NodeID: a.NodeID, Size: a.Size, CheckedAt: unixOrZero(a.CheckedAt),
		}
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// decodeAssets is the inverse of encodeAssets. No assets is an empty map, and so
// is the list that the column held in the first version ('[]').
func decodeAssets(s string) (map[string]ReleaseAsset, error) {
	if strings.HasPrefix(strings.TrimSpace(s), "[") {
		return map[string]ReleaseAsset{}, nil
	}
	var in map[string]assetJSON
	if err := json.Unmarshal([]byte(s), &in); err != nil {
		return nil, err
	}
	out := make(map[string]ReleaseAsset, len(in))
	for arch, a := range in {
		out[arch] = ReleaseAsset{
			File: a.File, URL: a.URL, SHA256: a.SHA256, SHASource: a.SHASource,
			State: a.State, Reason: a.Reason, NodeID: a.NodeID, Size: a.Size, CheckedAt: timeOrZero(a.CheckedAt),
		}
	}
	return out, nil
}

const releaseColumns = `engine, version, stable, published_at, assets, fetched_at, tag, prerelease, source, notes, url`

func scanRelease(s scanner) (*Release, error) {
	var (
		r                  Release
		stable, prerelease int64
		published, fetched int64
		assets             string
	)
	if err := s.Scan(&r.Engine, &r.Version, &stable, &published, &assets, &fetched,
		&r.Tag, &prerelease, &r.Source, &r.Notes, &r.URL); err != nil {
		return nil, err
	}
	r.Stable, r.Prerelease = stable != 0, prerelease != 0
	r.PublishedAt, r.FetchedAt = timeOrZero(published), timeOrZero(fetched)
	var err error
	if r.Assets, err = decodeAssets(assets); err != nil {
		return nil, fmt.Errorf("decode assets: %w", err)
	}
	return &r, nil
}

// releaseOf reads one release, sql.ErrNoRows when there is none.
func releaseOf(ctx context.Context, q dbtx, engine, version string) (*Release, error) {
	return scanRelease(q.QueryRowContext(ctx,
		`SELECT `+releaseColumns+` FROM engine_releases WHERE engine = ? AND version = ?`, engine, version))
}

// writeAssets stores the assets of a release that exists.
func writeAssets(ctx context.Context, q dbtx, engine, version string, assets map[string]ReleaseAsset) error {
	enc, err := encodeAssets(assets)
	if err != nil {
		return fmt.Errorf("encode assets: %w", err)
	}
	_, err = q.ExecContext(ctx, `UPDATE engine_releases SET assets = ? WHERE engine = ? AND version = ?`, enc, engine, version)
	return err
}

// UpsertRelease stores r, replacing the release of that engine and version if
// there is one. It gives r SourceUpstream for the source if that is empty, and
// puts the values as stored back into r.
//
// What is replaced: the row of the release, that is Stable, Prerelease,
// PublishedAt, FetchedAt, Tag, Source, Notes and URL, by what r says; except
// that a release whose source is built in keeps SourceBuiltin and the stable
// flag it has, whatever r says, so that an upstream poll or the stable list
// repeating a built-in release does not demote it.
//
// What is merged: the assets, by architecture, so that what the panel has found
// out about a file is not lost when the release is seen again. An asset that r
// does not name stays as it is. An asset that r names replaces the stored one
// (its file, its URL, its size), except for:
//
//   - the pin: without a SHA-256 the asset keeps the one that is pinned, with
//     its source; with the same SHA-256 it keeps the stored source unless it
//     names one, and a pin whose source is built in stays built in; a pinned
//     SHA-256 never changes, so an asset that has one and is given another is
//     [ErrChecksumChanged], and nothing is written;
//   - the verdict: without a State the asset keeps the state, the reason, the
//     node and the time that are stored.
//
// An asset that ends up without a state is AssetUnchecked.
func (db *DB) UpsertRelease(ctx context.Context, r *Release) error {
	if r.Engine == "" || r.Version == "" {
		return errors.New("store: upsert release: no engine or version")
	}
	c := *r
	if c.Source == "" {
		c.Source = SourceUpstream
	}
	c.PublishedAt, c.FetchedAt = normTime(c.PublishedAt), normTime(c.FetchedAt)
	assets := make(map[string]ReleaseAsset, len(c.Assets))
	for arch, a := range c.Assets {
		a.CheckedAt = normTime(a.CheckedAt)
		assets[arch] = a
	}

	err := db.withTx(ctx, func(tx *sql.Tx) error {
		old, err := releaseOf(ctx, tx, c.Engine, c.Version)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			old = nil
		case err != nil:
			return err
		}
		if old != nil {
			if old.Source == SourceBuiltin {
				c.Source, c.Stable = SourceBuiltin, old.Stable
			}
			if assets, err = mergeAssets(old, assets); err != nil {
				return err
			}
		}
		for arch, a := range assets {
			if a.State == "" {
				a.State = AssetUnchecked
				assets[arch] = a
			}
		}
		enc, err := encodeAssets(assets)
		if err != nil {
			return fmt.Errorf("encode assets: %w", err)
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO engine_releases (`+releaseColumns+`) VALUES (`+placeholders(11)+`)
			 ON CONFLICT (engine, version) DO UPDATE SET
			   stable = excluded.stable, published_at = excluded.published_at, assets = excluded.assets,
			   fetched_at = excluded.fetched_at, tag = excluded.tag, prerelease = excluded.prerelease,
			   source = excluded.source, notes = excluded.notes, url = excluded.url`,
			c.Engine, c.Version, boolInt(c.Stable), unixOrZero(c.PublishedAt), enc, unixOrZero(c.FetchedAt),
			c.Tag, boolInt(c.Prerelease), c.Source, c.Notes, c.URL)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: upsert release: %w", err)
	}
	c.Assets = assets
	*r = c
	return nil
}

// mergeAssets merges the assets of an upsert into those of the stored release,
// as UpsertRelease documents.
func mergeAssets(old *Release, assets map[string]ReleaseAsset) (map[string]ReleaseAsset, error) {
	out := make(map[string]ReleaseAsset, len(old.Assets)+len(assets))
	for arch, a := range old.Assets {
		out[arch] = a
	}
	for arch, a := range assets {
		if o, ok := old.Assets[arch]; ok {
			switch {
			case a.SHA256 == "":
				a.SHA256, a.SHASource = o.SHA256, o.SHASource
			case o.SHA256 != "" && a.SHA256 != o.SHA256:
				return nil, fmt.Errorf("%w: %s %s %s", ErrChecksumChanged, old.Engine, old.Version, arch)
			case a.SHASource == "" || o.SHASource == SHASourceBuiltin:
				a.SHASource = o.SHASource
			}
			if a.State == "" {
				a.State, a.Reason, a.NodeID, a.CheckedAt = o.State, o.Reason, o.NodeID, o.CheckedAt
			}
		}
		out[arch] = a
	}
	return out, nil
}

// ReleaseOf returns the release of this engine and version, or [ErrNotFound].
func (db *DB) ReleaseOf(ctx context.Context, engine, version string) (*Release, error) {
	r, err := releaseOf(ctx, db.sql, engine, version)
	if err != nil {
		return nil, fmt.Errorf("store: release: %w", queryNotFound(err, "release"))
	}
	return r, nil
}

// ListReleases returns the releases of an engine, newest first by
// [release.Compare]; two versions that compare equal (3.5.13 and 3.05.13) are
// ordered by their strings, descending.
func (db *DB) ListReleases(ctx context.Context, engine string) ([]*Release, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+releaseColumns+` FROM engine_releases WHERE engine = ?`, engine)
	if err != nil {
		return nil, fmt.Errorf("store: list releases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Release
	for rows.Next() {
		r, err := scanRelease(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list releases: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list releases: %w", err)
	}
	slices.SortFunc(out, func(a, b *Release) int {
		if c := release.Compare(b.Version, a.Version); c != 0 {
			return c
		}
		return strings.Compare(b.Version, a.Version)
	})
	return out, nil
}

// SetAssetState records the verdict on an asset: its state, why (for an
// unusable one), and the node whose trial run decided it, at the time of the
// call. The pinned SHA-256 and the rest of the asset stay. A release, or an
// asset of that architecture, that does not exist is [ErrNotFound].
//
// The release catalog decides whether a verdict may be recorded (a built-in pin
// is never made unusable by another source, R5-4) before it calls this.
func (db *DB) SetAssetState(ctx context.Context, engine, version, arch, state, reason, nodeID string) error {
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		r, err := releaseOf(ctx, tx, engine, version)
		if err != nil {
			return queryNotFound(err, "release")
		}
		a, ok := r.Assets[arch]
		if !ok {
			return notFound("release asset")
		}
		a.State, a.Reason, a.NodeID, a.CheckedAt = state, reason, nodeID, normTime(db.now())
		r.Assets[arch] = a
		return writeAssets(ctx, tx, engine, version, r.Assets)
	})
	if err != nil {
		return fmt.Errorf("store: set asset state: %w", err)
	}
	return nil
}

// PinAsset records what Prepare found out about one asset, in one transaction
// that touches nothing else of the release: the SHA-256 (pinned when the asset
// had none; [ErrChecksumChanged] when it had another one; the source of a
// built-in pin stays built in), the size, and the state, with no reason and no
// node, at the time of the call. A release, or an asset of that architecture,
// that does not exist is [ErrNotFound].
func (db *DB) PinAsset(ctx context.Context, engine, version, arch, sha, shaSource string, size int64, state string) error {
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		r, err := releaseOf(ctx, tx, engine, version)
		if err != nil {
			return queryNotFound(err, "release")
		}
		a, ok := r.Assets[arch]
		if !ok {
			return notFound("release asset")
		}
		switch {
		case a.SHA256 == "":
			a.SHA256, a.SHASource = sha, shaSource
		case a.SHA256 != sha:
			return fmt.Errorf("%w: %s %s %s", ErrChecksumChanged, engine, version, arch)
		case a.SHASource != SHASourceBuiltin && shaSource != "":
			a.SHASource = shaSource
		}
		a.Size, a.State, a.Reason, a.NodeID, a.CheckedAt = size, state, "", "", normTime(db.now())
		r.Assets[arch] = a
		return writeAssets(ctx, tx, engine, version, r.Assets)
	})
	if err != nil {
		return fmt.Errorf("store: pin asset: %w", err)
	}
	return nil
}

// Feed returns the feed at this URL, or [ErrNotFound] when the panel has not
// fetched it yet.
func (db *DB) Feed(ctx context.Context, url string) (Feed, error) {
	var (
		f               Feed
		checked, nextAt int64
	)
	err := db.sql.QueryRowContext(ctx,
		`SELECT url, component, etag, checked_at, next_at, last_error FROM release_feeds WHERE url = ?`, url).
		Scan(&f.URL, &f.Component, &f.ETag, &checked, &nextAt, &f.LastError)
	if err != nil {
		return Feed{}, fmt.Errorf("store: feed: %w", queryNotFound(err, "feed"))
	}
	f.CheckedAt, f.NextAt = timeOrZero(checked), timeOrZero(nextAt)
	return f, nil
}

// PutFeed stores f, replacing the feed at its URL.
func (db *DB) PutFeed(ctx context.Context, f Feed) error {
	if f.URL == "" {
		return errors.New("store: put feed: no url")
	}
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO release_feeds (url, component, etag, checked_at, next_at, last_error) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (url) DO UPDATE SET component = excluded.component, etag = excluded.etag,
		   checked_at = excluded.checked_at, next_at = excluded.next_at, last_error = excluded.last_error`,
		f.URL, f.Component, f.ETag, unixOrZero(normTime(f.CheckedAt)), unixOrZero(normTime(f.NextAt)), f.LastError)
	if err != nil {
		return fmt.Errorf("store: put feed: %w", err)
	}
	return nil
}
