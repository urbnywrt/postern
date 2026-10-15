-- Deployment over SSH (slice 4): how the panel reaches a node over SSH, and the
-- jobs, such as an install, whose logs the UI follows while they run. The
-- conventions are those of 0001_init.sql, except that the two enums here are
-- checked by the schema: their values are fixed, and a value that is not one of
-- them is a bug.

-- How the panel reaches a node over SSH. The host key is the one that an admin
-- confirmed when the panel first met the server. The credentials are kept only
-- when the admin asked for it, and then sealed with the additional data
-- "ssh:<node id>"; they go with the node.
CREATE TABLE ssh_targets (
  node_id       TEXT PRIMARY KEY REFERENCES nodes (id) ON DELETE CASCADE,
  host          TEXT NOT NULL,
  port          INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  user          TEXT NOT NULL,
  host_key      TEXT NOT NULL DEFAULT '',  -- SHA-256 fingerprint as ssh-keygen -l prints it ("SHA256:..."), '' until confirmed
  host_key_type TEXT NOT NULL DEFAULT '',  -- the type of that key, for example ssh-ed25519
  auth_kind     TEXT NOT NULL DEFAULT ''   -- '' when no credentials are kept
                CHECK (auth_kind IN ('', 'password', 'key')),
  secret_enc    BLOB,                      -- the credentials, sealed; NULL when none are kept
  updated_at    INTEGER NOT NULL
) STRICT;

-- A long operation on a node. The log is the output, with the secrets of the
-- job replaced, and at most 1 MiB of it: the newest lines. Jobs are history,
-- like events, so a job keeps naming a node that has been deleted since and has
-- no foreign key.
CREATE TABLE jobs (
  id          TEXT PRIMARY KEY,
  node_id     TEXT NOT NULL,
  kind        TEXT NOT NULL,                    -- install | collect | ...
  status      TEXT NOT NULL DEFAULT 'running'
              CHECK (status IN ('running', 'done', 'failed', 'cancelled')),
  log         TEXT NOT NULL DEFAULT '',
  started_at  INTEGER NOT NULL,
  finished_at INTEGER,                          -- NULL while it runs
  error       TEXT NOT NULL DEFAULT ''
) STRICT;

-- One running job per node.
CREATE UNIQUE INDEX jobs_running_node_idx ON jobs (node_id) WHERE status = 'running';
CREATE INDEX jobs_node_id_started_at_idx ON jobs (node_id, started_at DESC);
