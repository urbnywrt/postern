-- Versions and updates (slice 5, spec section 7): the catalog of the releases
-- of every component, the channels that nodes follow, the feeds that the
-- releases come from, and the rollouts that move a channel, switch engines or
-- update nodes one step at a time.
--
-- engine_releases.engine is the component: telemt, mtg, xray, warp-plus or
-- postern. Its assets column becomes a JSON object by architecture,
-- {"amd64": {...}, "arm64": {...}}; the rows of the first version hold the old
-- default '[]', which reads as no assets.

ALTER TABLE engine_releases ADD COLUMN tag        TEXT    NOT NULL DEFAULT '';
ALTER TABLE engine_releases ADD COLUMN prerelease INTEGER NOT NULL DEFAULT 0 CHECK (prerelease IN (0, 1));
ALTER TABLE engine_releases ADD COLUMN source     TEXT    NOT NULL DEFAULT 'upstream'; -- builtin | upstream | stable | upload
ALTER TABLE engine_releases ADD COLUMN notes      TEXT    NOT NULL DEFAULT '';         -- as published, at most 64 KiB, shown as text
ALTER TABLE engine_releases ADD COLUMN url        TEXT    NOT NULL DEFAULT '';

-- The version of each channel of each component. A channel version moves only
-- when a rollout completes. The rows are seeded with the built-in versions, here
-- and only here: a database that is migrated keeps the versions it has.
CREATE TABLE engine_channels (
  engine     TEXT    NOT NULL,
  channel    TEXT    NOT NULL CHECK (channel IN ('stable', 'latest')),
  version    TEXT    NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (engine, channel)
) STRICT, WITHOUT ROWID;

INSERT INTO engine_channels VALUES
  ('telemt', 'stable', '3.5.13', 0), ('telemt', 'latest', '3.5.13', 0),
  ('mtg', 'stable', 'v2.2.8', 0), ('mtg', 'latest', 'v2.2.8', 0),
  ('xray', 'stable', 'v26.3.27', 0), ('xray', 'latest', 'v26.3.27', 0),
  ('warp-plus', 'stable', 'v1.2.6', 0), ('warp-plus', 'latest', 'v1.2.6', 0);

-- The release lists that the panel fetches, by their exact URL: the ETag of the
-- last answer, when it was fetched, when it is due, and why the last fetch
-- failed.
CREATE TABLE release_feeds (
  url        TEXT PRIMARY KEY,
  component  TEXT    NOT NULL,
  etag       TEXT    NOT NULL DEFAULT '',
  checked_at INTEGER NOT NULL DEFAULT 0,
  next_at    INTEGER NOT NULL DEFAULT 0,
  last_error TEXT    NOT NULL DEFAULT ''
) STRICT;

-- The channel that the proxies of a node follow ('' is the default of the
-- panel), and the version of each egress provider that the node runs while one
-- is set for it, as a JSON object by component.
ALTER TABLE nodes ADD COLUMN engine_channel    TEXT NOT NULL DEFAULT '';   -- '' | stable | latest
ALTER TABLE nodes ADD COLUMN provider_versions TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(provider_versions));

-- A rollout and what it changes: the nodes it holds, its steps, and the proxies
-- (items) that each step changes, with what they held before. The nodes, steps
-- and items go with the rollout.
CREATE TABLE rollouts (
  id            TEXT PRIMARY KEY,
  kind          TEXT    NOT NULL,                 -- version | switch | node
  component     TEXT    NOT NULL,
  channel       TEXT    NOT NULL DEFAULT '',
  from_version  TEXT    NOT NULL DEFAULT '',
  to_version    TEXT    NOT NULL DEFAULT '',
  to_engine     TEXT    NOT NULL DEFAULT '',
  options       TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(options)),
  mode          TEXT    NOT NULL,                 -- manual | auto
  pause_seconds INTEGER NOT NULL DEFAULT 120,
  status        TEXT    NOT NULL,                 -- preparing | running | paused | failed | completed | aborted
  current_step  INTEGER NOT NULL DEFAULT 0,
  resume_at     INTEGER,
  error         TEXT    NOT NULL DEFAULT '',
  created_by    TEXT    NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  finished_at   INTEGER
) STRICT;

-- At most one active version rollout per component and channel (R5-7). A
-- rollout is active while it is preparing, running, paused or failed.
CREATE UNIQUE INDEX rollouts_one_version_per_channel ON rollouts (component, channel)
  WHERE kind = 'version' AND status IN ('preparing', 'running', 'paused', 'failed');

CREATE TABLE rollout_nodes (
  rollout_id TEXT    NOT NULL REFERENCES rollouts (id) ON DELETE CASCADE,
  node_id    TEXT    NOT NULL,
  active     INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  PRIMARY KEY (rollout_id, node_id)
) STRICT, WITHOUT ROWID;

-- At most one active rollout of any kind per node (R5-7). The rows of a rollout
-- are made inactive when it completes or is aborted.
CREATE UNIQUE INDEX rollout_nodes_one_active ON rollout_nodes (node_id) WHERE active = 1;

CREATE TABLE rollout_steps (
  rollout_id  TEXT    NOT NULL REFERENCES rollouts (id) ON DELETE CASCADE,
  idx         INTEGER NOT NULL,
  node_id     TEXT    NOT NULL,
  proxy_id    TEXT    NOT NULL DEFAULT '',         -- the canary proxy of the step, if it is one
  status      TEXT    NOT NULL,                   -- pending | applying | verifying | done | failed | reverted | skipped
  generation  INTEGER NOT NULL DEFAULT 0,         -- the desired generation of the node that the step wrote; 0: not yet
  started_at  INTEGER,
  finished_at INTEGER,
  error       TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (rollout_id, idx)
) STRICT, WITHOUT ROWID;

CREATE TABLE rollout_items (
  rollout_id   TEXT    NOT NULL REFERENCES rollouts (id) ON DELETE CASCADE,
  proxy_id     TEXT    NOT NULL,
  node_id      TEXT    NOT NULL,
  step_idx     INTEGER NOT NULL,
  prev_engine  TEXT    NOT NULL,                  -- what the proxy held when the rollout was made
  prev_policy  TEXT    NOT NULL,
  prev_version TEXT    NOT NULL,
  state        TEXT    NOT NULL DEFAULT 'pending', -- pending | applied | reverted | detached | deferred
  PRIMARY KEY (rollout_id, proxy_id)
) STRICT, WITHOUT ROWID;
