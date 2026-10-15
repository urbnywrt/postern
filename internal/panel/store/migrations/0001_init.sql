-- The panel schema for slices 0 and 1 (spec section 3). Every table that the
-- first slices need is created here, repositories or not, so that later slices
-- do not have to rebuild them.
--
-- Conventions
--   ids        ULIDs as text (internal/ids).
--   times      INTEGER Unix seconds, UTC. A statistics row is keyed by the Unix
--              second at which its minute, hour or day starts.
--   booleans   INTEGER 0 or 1.
--   JSON       TEXT that holds valid JSON.
--   *_enc      BLOB sealed by internal/seal. The store keeps the bytes and does
--              not know the key.
--   enums      TEXT. The values are listed next to the columns, and the
--              services validate them, so that a new value needs no migration.
--
-- Tables are STRICT: SQLite refuses a value of the wrong type instead of
-- quietly storing it.
--
-- Foreign keys (they are switched on for every connection):
--   listeners, proxies and the statistics of a node go with the node;
--   a listener cannot be deleted while a proxy uses it, and a proxy can only
--   use a listener of its own node;
--   an egress chain cannot be deleted while a node or a proxy uses it.
-- The tables nodes and egress_chains refer to each other. Both columns are
-- nullable, so a node is created first and gets its default chain afterwards.

CREATE TABLE admins (
  id              TEXT PRIMARY KEY,
  username        TEXT NOT NULL UNIQUE,
  password_hash   TEXT NOT NULL,
  totp_secret_enc BLOB,
  created_at      INTEGER NOT NULL,
  last_login_at   INTEGER
) STRICT;

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  admin_id   TEXT NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip         TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX sessions_admin_id_idx ON sessions (admin_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL CHECK (json_valid(value))
) STRICT;

CREATE TABLE nodes (
  id                 TEXT PRIMARY KEY,
  name               TEXT NOT NULL,
  mgmt_host          TEXT NOT NULL DEFAULT '',
  mgmt_port          INTEGER NOT NULL DEFAULT 0 CHECK (mgmt_port BETWEEN 0 AND 65535),
  mgmt_mode          TEXT NOT NULL DEFAULT 'port',         -- port | hidden
  mgmt_sni           TEXT NOT NULL DEFAULT '',
  link_host          TEXT NOT NULL DEFAULT '',
  cert_fingerprint   TEXT NOT NULL DEFAULT '',             -- lower-case hex SHA-256 of the node certificate
  cert_pem           TEXT NOT NULL DEFAULT '',             -- the node certificate, to serve its bundle again
  key_enc            BLOB,                                 -- the private key of that certificate, sealed
  default_chain_id   TEXT REFERENCES egress_chains (id) ON DELETE RESTRICT,
  desired_generation INTEGER NOT NULL DEFAULT 0,
  applied_generation INTEGER NOT NULL DEFAULT 0,
  watch_cursor       INTEGER NOT NULL DEFAULT 0,
  agent_version      TEXT NOT NULL DEFAULT '',
  edge_version       TEXT NOT NULL DEFAULT '',
  arch               TEXT NOT NULL DEFAULT '',
  host_info          TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(host_info)),
  public_ips         TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(public_ips)),
  status             TEXT NOT NULL DEFAULT 'provisioning', -- provisioning | online | offline | error
  last_seen_at       INTEGER,
  note               TEXT NOT NULL DEFAULT '',
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL
) STRICT;

CREATE INDEX nodes_default_chain_id_idx ON nodes (default_chain_id) WHERE default_chain_id IS NOT NULL;

CREATE TABLE egresses (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  kind       TEXT NOT NULL,                                -- direct | socks5 | http | xray-uri | xray-subscription | warp | psiphon
  node_id    TEXT REFERENCES nodes (id) ON DELETE CASCADE, -- NULL: not bound to a node
  params_enc BLOB,                                         -- the parameters as JSON, sealed
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

CREATE INDEX egresses_node_id_idx ON egresses (node_id);

CREATE TABLE egress_chains (
  id      TEXT PRIMARY KEY,
  name    TEXT NOT NULL,
  node_id TEXT REFERENCES nodes (id) ON DELETE CASCADE,   -- NULL: usable on every node
  members TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(members)), -- JSON array of egress ids, in order
  "check" TEXT NOT NULL DEFAULT '{}' CHECK (json_valid("check"))  -- JSON health check settings
) STRICT;

CREATE INDEX egress_chains_node_id_idx ON egress_chains (node_id);

CREATE TABLE listeners (
  id                 TEXT PRIMARY KEY,
  node_id            TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  kind               TEXT NOT NULL DEFAULT 'tls',          -- tls | http-upstream
  bind_ip            TEXT NOT NULL DEFAULT '',
  port               INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  link_host_override TEXT NOT NULL DEFAULT '',
  stranger_action    TEXT NOT NULL DEFAULT 'mask',         -- mask | reject | drop
  mask_target        TEXT NOT NULL DEFAULT '',
  non_tls_action     TEXT NOT NULL DEFAULT 'drop',         -- drop | http400
  trusted_cidrs      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(trusted_cidrs)), -- http-upstream only
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL,
  UNIQUE (id, node_id)                                     -- the target of the foreign key of proxies
) STRICT;

CREATE INDEX listeners_node_id_idx ON listeners (node_id);

CREATE TABLE proxies (
  id                    TEXT PRIMARY KEY,
  node_id               TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  listener_id           TEXT NOT NULL,
  type                  TEXT NOT NULL DEFAULT 'faketls',   -- faketls | web
  name                  TEXT NOT NULL DEFAULT '',
  note                  TEXT NOT NULL DEFAULT '',
  tags                  TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags)),
  enabled               INTEGER NOT NULL CHECK (enabled IN (0, 1)), -- no default: a proxy is enabled only when the writer says so
  secret_enc            BLOB NOT NULL,
  domain                TEXT NOT NULL DEFAULT '',
  web_base_path         TEXT NOT NULL DEFAULT '',
  web_secret_mode       TEXT NOT NULL DEFAULT '',          -- plain | dd
  web_carrier           TEXT NOT NULL DEFAULT '',
  cert_mode             TEXT NOT NULL DEFAULT '',          -- acme-tls-alpn | acme-dns01 | imported | external
  dns_credential_id     TEXT NOT NULL DEFAULT '',
  acme_email            TEXT NOT NULL DEFAULT '',
  engine                TEXT NOT NULL DEFAULT 'telemt',    -- telemt | mtg
  engine_version_policy TEXT NOT NULL DEFAULT 'channel',   -- channel | pinned
  engine_version        TEXT NOT NULL DEFAULT '',
  egress_chain_id       TEXT REFERENCES egress_chains (id) ON DELETE RESTRICT, -- NULL: the default chain of the node
  egress_scope_chains   TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(egress_scope_chains)), -- {"me": chain id, "fetch": chain id}
  nat_ip                TEXT NOT NULL DEFAULT '',
  limit_devices         INTEGER NOT NULL DEFAULT 0,        -- 0: no limit
  limit_conns_total     INTEGER NOT NULL DEFAULT 0,
  limit_conns_per_ip    INTEGER NOT NULL DEFAULT 0,
  ad_tag                TEXT NOT NULL DEFAULT '',
  mask_target_override  TEXT NOT NULL DEFAULT '',
  engine_overrides      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(engine_overrides)),
  legacy                TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(legacy)),
  created_at            INTEGER NOT NULL,
  updated_at            INTEGER NOT NULL,
  FOREIGN KEY (listener_id, node_id) REFERENCES listeners (id, node_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX proxies_node_id_idx ON proxies (node_id);
CREATE INDEX proxies_listener_idx ON proxies (listener_id, node_id);
CREATE INDEX proxies_egress_chain_id_idx ON proxies (egress_chain_id) WHERE egress_chain_id IS NOT NULL;

CREATE TABLE domain_pool (
  domain  TEXT NOT NULL,
  node_id TEXT REFERENCES nodes (id) ON DELETE CASCADE,    -- NULL: the global pool
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
) STRICT;

-- SQLite treats NULLs as distinct, so a plain UNIQUE would allow a domain twice
-- in the global pool.
CREATE UNIQUE INDEX domain_pool_scope_idx ON domain_pool (domain, IFNULL(node_id, ''));

CREATE TABLE blacklist (
  cidr    TEXT NOT NULL,
  node_id TEXT REFERENCES nodes (id) ON DELETE CASCADE,    -- NULL: every node
  note    TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE UNIQUE INDEX blacklist_scope_idx ON blacklist (cidr, IFNULL(node_id, ''));

CREATE TABLE engine_releases (
  engine       TEXT NOT NULL,
  version      TEXT NOT NULL,
  stable       INTEGER NOT NULL DEFAULT 1 CHECK (stable IN (0, 1)),
  published_at INTEGER NOT NULL DEFAULT 0,
  assets       TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(assets)),
  fetched_at   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (engine, version)
) STRICT, WITHOUT ROWID;

-- Events and the audit log are history. They keep naming a node, a proxy or an
-- admin after it has been deleted, so they have no foreign keys.
CREATE TABLE events (
  id       TEXT PRIMARY KEY,
  ts       INTEGER NOT NULL,
  node_id  TEXT NOT NULL DEFAULT '',
  proxy_id TEXT NOT NULL DEFAULT '',
  kind     TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  message  TEXT NOT NULL DEFAULT '',
  details  TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details))
) STRICT;

CREATE INDEX events_ts_idx ON events (ts DESC);
CREATE INDEX events_node_id_ts_idx ON events (node_id, ts DESC);

CREATE TABLE audit_log (
  id       TEXT PRIMARY KEY,
  ts       INTEGER NOT NULL,
  admin_id TEXT NOT NULL DEFAULT '',
  action   TEXT NOT NULL,
  target   TEXT NOT NULL DEFAULT '',
  details  TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details))
) STRICT;

CREATE INDEX audit_log_ts_idx ON audit_log (ts DESC);

-- Statistics: one row per proxy or node and bucket. ts is the start of the
-- bucket in Unix seconds. 1m rows are kept for 48 hours and 1h rows for 90
-- days; 1d rows are kept for good. RollupStats fills the coarser tables from the
-- finer ones.
CREATE TABLE stats_proxy_1m (
  proxy_id   TEXT NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
  ts         INTEGER NOT NULL,
  up         INTEGER NOT NULL DEFAULT 0,
  down       INTEGER NOT NULL DEFAULT 0,
  conns_new  INTEGER NOT NULL DEFAULT 0,
  conns_peak INTEGER NOT NULL DEFAULT 0,
  devices    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (proxy_id, ts)
) STRICT, WITHOUT ROWID;

CREATE TABLE stats_proxy_1h (
  proxy_id   TEXT NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
  ts         INTEGER NOT NULL,
  up         INTEGER NOT NULL DEFAULT 0,
  down       INTEGER NOT NULL DEFAULT 0,
  conns_new  INTEGER NOT NULL DEFAULT 0,
  conns_peak INTEGER NOT NULL DEFAULT 0,
  devices    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (proxy_id, ts)
) STRICT, WITHOUT ROWID;

CREATE TABLE stats_proxy_1d (
  proxy_id   TEXT NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
  ts         INTEGER NOT NULL,
  up         INTEGER NOT NULL DEFAULT 0,
  down       INTEGER NOT NULL DEFAULT 0,
  conns_new  INTEGER NOT NULL DEFAULT 0,
  conns_peak INTEGER NOT NULL DEFAULT 0,
  devices    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (proxy_id, ts)
) STRICT, WITHOUT ROWID;

-- Rollups and pruning look at ts alone.
CREATE INDEX stats_proxy_1m_ts_idx ON stats_proxy_1m (ts);
CREATE INDEX stats_proxy_1h_ts_idx ON stats_proxy_1h (ts);

CREATE TABLE stats_node_1m (
  node_id    TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  ts         INTEGER NOT NULL,
  cpu        REAL NOT NULL DEFAULT 0,
  mem_used   INTEGER NOT NULL DEFAULT 0,
  mem_total  INTEGER NOT NULL DEFAULT 0,
  load1      REAL NOT NULL DEFAULT 0,
  disk_used  INTEGER NOT NULL DEFAULT 0,
  disk_total INTEGER NOT NULL DEFAULT 0,
  net_rx     INTEGER NOT NULL DEFAULT 0,
  net_tx     INTEGER NOT NULL DEFAULT 0,
  conns      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (node_id, ts)
) STRICT, WITHOUT ROWID;

CREATE TABLE stats_node_1h (
  node_id    TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  ts         INTEGER NOT NULL,
  cpu        REAL NOT NULL DEFAULT 0,
  mem_used   INTEGER NOT NULL DEFAULT 0,
  mem_total  INTEGER NOT NULL DEFAULT 0,
  load1      REAL NOT NULL DEFAULT 0,
  disk_used  INTEGER NOT NULL DEFAULT 0,
  disk_total INTEGER NOT NULL DEFAULT 0,
  net_rx     INTEGER NOT NULL DEFAULT 0,
  net_tx     INTEGER NOT NULL DEFAULT 0,
  conns      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (node_id, ts)
) STRICT, WITHOUT ROWID;

CREATE TABLE stats_node_1d (
  node_id    TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  ts         INTEGER NOT NULL,
  cpu        REAL NOT NULL DEFAULT 0,
  mem_used   INTEGER NOT NULL DEFAULT 0,
  mem_total  INTEGER NOT NULL DEFAULT 0,
  load1      REAL NOT NULL DEFAULT 0,
  disk_used  INTEGER NOT NULL DEFAULT 0,
  disk_total INTEGER NOT NULL DEFAULT 0,
  net_rx     INTEGER NOT NULL DEFAULT 0,
  net_tx     INTEGER NOT NULL DEFAULT 0,
  conns      INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (node_id, ts)
) STRICT, WITHOUT ROWID;

CREATE INDEX stats_node_1m_ts_idx ON stats_node_1m (ts);
CREATE INDEX stats_node_1h_ts_idx ON stats_node_1h (ts);

-- Where a client address was seen on a proxy. Kept for 7 days.
CREATE TABLE ip_sightings (
  proxy_id   TEXT NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
  ip         TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  bytes      INTEGER NOT NULL DEFAULT 0,
  country    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (proxy_id, ip)
) STRICT, WITHOUT ROWID;

CREATE INDEX ip_sightings_last_seen_idx ON ip_sightings (last_seen);
