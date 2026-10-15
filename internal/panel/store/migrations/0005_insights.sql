-- Statistics, diagnostics and the public page (slice 6; spec section 3).
--
-- Statistics
--   stats_node_*       the connections that the edge refused or evicted, per
--                      period, summed by the rollups.
--   stats_country_*    per proxy, period and country (two letters A-Z, or ''
--                      for an unknown one and for those beyond the 50 that a
--                      minute or an hour keeps): ips, how many addresses the
--                      country had in a minute (over a longer period, the most
--                      of its minutes), and their bytes. Kept: minutes as the
--                      minutes of proxies, hours 30 days, days for good.
--   egress_health_1m   the health of a member of an egress chain of a node in
--                      a minute; status: up | down | unknown.
--   egress_health      its hours: minutes up, down and unknown, the latency of
--                      the minutes that it was up, its last exit address. 30 days.
--   stats_batches      a marker for each minute of a node whose addresses
--                      (ip_sightings, which add up) are stored. 8 days.
--   probes             probes of proxies from outside; vantage: panel | node,
--                      kind: l2 | web. 7 days.
--
-- Fixes are declared in the desired state, as nonces that the panel raises:
-- nodes.edge_roll_nonce (a new edge generation), proxies.restart_nonce (a new
-- engine generation), proxies.cert_reissue_nonce (a new certificate of a WEB
-- proxy). nodes.panel_addrs holds the addresses that a node sees the panel come
-- from, the last IPv4 and the last IPv6 one.
--
-- Diagnostics
--   diagnostic_runs     a run of the checks of a scope of a node.
--                       state: running | done | partial | skipped | failed;
--                       reason: manual | before_change | after_change.
--                       30 days, and at most 100 of a node.
--   diagnostic_results  the results of a run, in order.
--   node_checks         the last result of each light check of a node, and
--                       since when it has had its status.
--
-- The public page has one row (id 1); unavailable: hide | mark. Its items are
-- proxies, in the order of position.

ALTER TABLE stats_node_1m ADD COLUMN refused_prehello INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stats_node_1m ADD COLUMN refused_total INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stats_node_1m ADD COLUMN evicted_prehello INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stats_node_1h ADD COLUMN refused_prehello INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stats_node_1h ADD COLUMN refused_total INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stats_node_1h ADD COLUMN evicted_prehello INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stats_node_1d ADD COLUMN refused_prehello INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stats_node_1d ADD COLUMN refused_total INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stats_node_1d ADD COLUMN evicted_prehello INTEGER NOT NULL DEFAULT 0;

CREATE TABLE stats_country_1m (
  proxy_id TEXT NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
  ts       INTEGER NOT NULL,
  country  TEXT NOT NULL,
  ips      INTEGER NOT NULL DEFAULT 0,
  bytes    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (proxy_id, ts, country)
) STRICT, WITHOUT ROWID;

CREATE TABLE stats_country_1h (
  proxy_id TEXT NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
  ts       INTEGER NOT NULL,
  country  TEXT NOT NULL,
  ips      INTEGER NOT NULL DEFAULT 0,
  bytes    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (proxy_id, ts, country)
) STRICT, WITHOUT ROWID;

CREATE TABLE stats_country_1d (
  proxy_id TEXT NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
  ts       INTEGER NOT NULL,
  country  TEXT NOT NULL,
  ips      INTEGER NOT NULL DEFAULT 0,
  bytes    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (proxy_id, ts, country)
) STRICT, WITHOUT ROWID;

-- Rollups and pruning look at ts alone.
CREATE INDEX stats_country_1m_ts_idx ON stats_country_1m (ts);
CREATE INDEX stats_country_1h_ts_idx ON stats_country_1h (ts);
CREATE INDEX stats_country_1d_ts_idx ON stats_country_1d (ts);

CREATE TABLE egress_health_1m (
  node_id    TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  chain_id   TEXT NOT NULL,
  member_key TEXT NOT NULL,
  ts         INTEGER NOT NULL,
  status     TEXT NOT NULL,                                -- up | down | unknown
  latency_ms INTEGER NOT NULL DEFAULT 0,
  exit_ip    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (node_id, chain_id, member_key, ts)
) STRICT, WITHOUT ROWID;

CREATE INDEX egress_health_1m_ts_idx ON egress_health_1m (ts);

CREATE TABLE egress_health (
  node_id         TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  chain_id        TEXT NOT NULL,
  member_key      TEXT NOT NULL,
  ts              INTEGER NOT NULL,
  minutes_up      INTEGER NOT NULL DEFAULT 0,
  minutes_down    INTEGER NOT NULL DEFAULT 0,
  minutes_unknown INTEGER NOT NULL DEFAULT 0,
  latency_avg_ms  INTEGER NOT NULL DEFAULT 0,
  latency_max_ms  INTEGER NOT NULL DEFAULT 0,
  exit_ip         TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (node_id, chain_id, member_key, ts)
) STRICT, WITHOUT ROWID;

CREATE INDEX egress_health_ts_idx ON egress_health (ts);

CREATE TABLE stats_batches (
  node_id TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  minute  INTEGER NOT NULL,
  PRIMARY KEY (node_id, minute)
) STRICT, WITHOUT ROWID;

CREATE INDEX stats_batches_minute_idx ON stats_batches (minute);

CREATE TABLE probes (
  proxy_id   TEXT NOT NULL REFERENCES proxies (id) ON DELETE CASCADE,
  ts         INTEGER NOT NULL,
  vantage    TEXT NOT NULL,                                -- panel | node
  kind       TEXT NOT NULL,                                -- l2 | web
  ok         INTEGER NOT NULL CHECK (ok IN (0, 1)),
  latency_ms INTEGER NOT NULL DEFAULT 0,
  error      TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (proxy_id, vantage, kind, ts)
) STRICT, WITHOUT ROWID;

CREATE INDEX probes_ts_idx ON probes (ts);

-- Where the addresses of a proxy were seen, those seen last first.
CREATE INDEX ip_sightings_proxy_last_idx ON ip_sightings (proxy_id, last_seen DESC);

ALTER TABLE nodes ADD COLUMN panel_addrs TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(panel_addrs));
ALTER TABLE nodes ADD COLUMN edge_roll_nonce INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxies ADD COLUMN restart_nonce INTEGER NOT NULL DEFAULT 0;
ALTER TABLE proxies ADD COLUMN cert_reissue_nonce INTEGER NOT NULL DEFAULT 0;

CREATE TABLE diagnostic_runs (
  id             TEXT PRIMARY KEY,
  node_id        TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  scope          TEXT NOT NULL,                            -- node | proxy:<id>
  reason         TEXT NOT NULL,                            -- manual | before_change | after_change
  change         TEXT NOT NULL DEFAULT '',
  related_run_id TEXT NOT NULL DEFAULT '',
  admin_id       TEXT NOT NULL DEFAULT '',
  state          TEXT NOT NULL,                            -- running | done | partial | skipped | failed
  error          TEXT NOT NULL DEFAULT '',
  regressed      INTEGER NOT NULL DEFAULT 0 CHECK (regressed IN (0, 1)),
  ok             INTEGER NOT NULL DEFAULT 0,
  warn           INTEGER NOT NULL DEFAULT 0,
  fail           INTEGER NOT NULL DEFAULT 0,
  skip           INTEGER NOT NULL DEFAULT 0,
  started_at     INTEGER NOT NULL,
  finished_at    INTEGER
) STRICT;

CREATE INDEX diagnostic_runs_node_started_idx ON diagnostic_runs (node_id, started_at DESC);

CREATE TABLE diagnostic_results (
  run_id      TEXT NOT NULL REFERENCES diagnostic_runs (id) ON DELETE CASCADE,
  seq         INTEGER NOT NULL,
  check_id    TEXT NOT NULL,
  layer       TEXT NOT NULL,
  target      TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT '',
  summary     TEXT NOT NULL DEFAULT '',
  evidence    TEXT NOT NULL DEFAULT '',
  hint        TEXT NOT NULL DEFAULT '',
  fix         TEXT NOT NULL DEFAULT '',
  vantage     TEXT NOT NULL DEFAULT 'node',
  checked_at  INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (run_id, seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE node_checks (
  node_id    TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  check_id   TEXT NOT NULL,
  target     TEXT NOT NULL DEFAULT '',
  layer      TEXT NOT NULL DEFAULT '',
  status     TEXT NOT NULL DEFAULT '',
  summary    TEXT NOT NULL DEFAULT '',
  evidence   TEXT NOT NULL DEFAULT '',
  hint       TEXT NOT NULL DEFAULT '',
  fix        TEXT NOT NULL DEFAULT '',
  since      INTEGER NOT NULL,
  checked_at INTEGER NOT NULL,
  PRIMARY KEY (node_id, check_id, target)
) STRICT, WITHOUT ROWID;

CREATE TABLE public_page (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  enabled        INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  host           TEXT NOT NULL DEFAULT '',
  title          TEXT NOT NULL DEFAULT '',
  body_md        TEXT NOT NULL DEFAULT '',
  unavailable    TEXT NOT NULL DEFAULT 'mark',             -- hide | mark
  noindex        INTEGER NOT NULL DEFAULT 1 CHECK (noindex IN (0, 1)),
  default_locale TEXT NOT NULL DEFAULT 'ru',
  updated_at     INTEGER NOT NULL DEFAULT 0
) STRICT;

INSERT INTO public_page (id) VALUES (1);

CREATE TABLE public_page_items (
  proxy_id    TEXT PRIMARY KEY REFERENCES proxies (id) ON DELETE CASCADE,
  position    INTEGER NOT NULL,
  public_name TEXT NOT NULL DEFAULT '',
  public_note TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE UNIQUE INDEX public_page_items_position_idx ON public_page_items (position);
