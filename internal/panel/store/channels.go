package store

import (
	"context"
	"errors"
	"fmt"
)

// ChannelVersions returns the version of every channel of every component, by
// component and then by channel. The migration seeds the built-in version of
// each engine and provider on both channels.
func (db *DB) ChannelVersions(ctx context.Context) (map[string]map[string]string, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT engine, channel, version FROM engine_channels ORDER BY engine, channel`)
	if err != nil {
		return nil, fmt.Errorf("store: channel versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]map[string]string{}
	for rows.Next() {
		var engine, channel, version string
		if err := rows.Scan(&engine, &channel, &version); err != nil {
			return nil, fmt.Errorf("store: channel versions: %w", err)
		}
		if out[engine] == nil {
			out[engine] = map[string]string{}
		}
		out[engine][channel] = version
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: channel versions: %w", err)
	}
	return out, nil
}

// setChannelVersion is the write of SetChannelVersion, on a connection or in a
// transaction.
func setChannelVersion(ctx context.Context, q dbtx, engine, channel, version string, now int64) error {
	if engine == "" || channel == "" || version == "" {
		return errors.New("no engine, channel or version")
	}
	_, err := q.ExecContext(ctx,
		`INSERT INTO engine_channels (engine, channel, version, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT (engine, channel) DO UPDATE SET version = excluded.version, updated_at = excluded.updated_at`,
		engine, channel, version, now)
	return err
}

// SetChannelVersion moves a channel of a component to a version, at the time of
// the call, adding the row when the component has none. The channel has to be
// [ChannelStable] or [ChannelLatest]: the schema refuses any other. A channel
// moves when a rollout completes: [DB.CompleteRollout] does this in the
// transaction that completes the rollout.
func (db *DB) SetChannelVersion(ctx context.Context, engine, channel, version string) error {
	if err := setChannelVersion(ctx, db.sql, engine, channel, version, normTime(db.now()).Unix()); err != nil {
		return fmt.Errorf("store: set channel version: %w", err)
	}
	return nil
}
