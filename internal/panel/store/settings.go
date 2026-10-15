package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// The settings of versions and updates (slice 5), by key. Each is JSON:
//
//   - SettingDefaultChannel: a string, the channel that nodes without a
//     channel of their own follow, ChannelStable when the setting is missing;
//   - SettingReleaseSource: a [ReleaseSource], see [DB.ReleaseSource];
//   - SettingIncludePrereleases: a bool, false when missing, whether the
//     latest channel follows prereleases;
//   - SettingStableGeneratedAt: an integer, the generated_at of the signed
//     stable list that was applied, Unix seconds, 0 when missing;
//   - SettingGitHubToken and SettingSourceToken: sealed, see
//     [DB.SealedSetting]; the token for the GitHub API and the token of the
//     release source of Postern;
//   - SettingPanelLastUpdate: a string, what the last update of the panel
//     did, as the operator reads it.
const (
	SettingDefaultChannel     = "versions.default_channel"
	SettingReleaseSource      = "releases.source"
	SettingIncludePrereleases = "releases.include_prereleases"
	SettingStableGeneratedAt  = "releases.stable_generated_at"
	SettingGitHubToken        = "releases.github_token"
	SettingSourceToken        = "releases.source_token"
	SettingPanelLastUpdate    = "panel.last_update"
)

// ReleaseSource is where the releases of Postern itself come from.
type ReleaseSource struct {
	Kind    string `json:"kind"`     // github or gitea
	BaseURL string `json:"base_url"` // the base URL of a Gitea; "" for GitHub, whose API base is the panel's
	Repo    string `json:"repo"`     // owner/name
}

// DefaultReleaseSource is the release source of a panel that has not set one:
// the repository of Postern on GitHub.
func DefaultReleaseSource() ReleaseSource {
	return ReleaseSource{Kind: "github", Repo: "urbnywrt/postern"}
}

// sealedSetting is the value of a setting that holds sealed bytes:
// {"sealed": "<base64>"}.
type sealedSetting struct {
	Sealed []byte `json:"sealed"`
}

// GetSetting reads the setting with this key into dst, which has to be a pointer
// that encoding/json can decode the value into. It reports whether the setting
// exists; when it does not, dst is left alone.
func (db *DB) GetSetting(ctx context.Context, key string, dst any) (bool, error) {
	return getSetting(ctx, db.sql, key, dst)
}

// PutSetting stores v, as JSON, under this key, replacing what is there.
func (db *DB) PutSetting(ctx context.Context, key string, v any) error {
	return putSetting(ctx, db.sql, key, v)
}

// getSetting is GetSetting in a transaction or out of one.
func getSetting(ctx context.Context, q dbtx, key string, dst any) (bool, error) {
	var raw string
	err := q.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: get setting %q: %w", key, err)
	}
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		return false, fmt.Errorf("store: decode setting %q: %w", key, err)
	}
	return true, nil
}

// putSetting is PutSetting in a transaction or out of one.
func putSetting(ctx context.Context, q dbtx, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("store: encode setting %q: %w", key, err)
	}
	_, err = q.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, string(raw))
	if err != nil {
		return fmt.Errorf("store: put setting %q: %w", key, err)
	}
	return nil
}

// ReleaseSource returns the release source of Postern (the setting
// SettingReleaseSource), or [DefaultReleaseSource] when none is set.
func (db *DB) ReleaseSource(ctx context.Context) (ReleaseSource, error) {
	var s ReleaseSource
	ok, err := db.GetSetting(ctx, SettingReleaseSource, &s)
	if err != nil {
		return ReleaseSource{}, err
	}
	if !ok {
		return DefaultReleaseSource(), nil
	}
	return s, nil
}

// PutReleaseSource stores the release source of Postern.
func (db *DB) PutReleaseSource(ctx context.Context, s ReleaseSource) error {
	return db.PutSetting(ctx, SettingReleaseSource, s)
}

// SealedSetting returns the sealed bytes that the setting with this key holds,
// and whether there is such a setting. The bytes were sealed by internal/seal
// (with the additional data "setting:<key>") before they got here: the store
// keeps them and does not know the key. A setting that is not of that shape is
// an error.
func (db *DB) SealedSetting(ctx context.Context, key string) ([]byte, bool, error) {
	var v sealedSetting
	ok, err := db.GetSetting(ctx, key, &v)
	if err != nil || !ok {
		return nil, false, err
	}
	if len(v.Sealed) == 0 {
		return nil, false, fmt.Errorf("store: setting %q holds no sealed value", key)
	}
	return v.Sealed, true, nil
}

// PutSealedSetting stores sealed bytes under this key, as {"sealed":
// "<base64>"}, replacing what is there. No bytes removes the setting.
func (db *DB) PutSealedSetting(ctx context.Context, key string, sealed []byte) error {
	if len(sealed) == 0 {
		if _, err := db.sql.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, key); err != nil {
			return fmt.Errorf("store: remove setting %q: %w", key, err)
		}
		return nil
	}
	return db.PutSetting(ctx, key, sealedSetting{Sealed: sealed})
}
