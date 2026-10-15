-- The journal's filters and the problem feed (slice 6): the events of a proxy,
-- and the newest event of a kind of a node (node.error, proxy.failed), are
-- read by index instead of along the time of every event.

CREATE INDEX events_proxy_id_ts_idx ON events (proxy_id, ts DESC);
CREATE INDEX events_node_id_kind_ts_idx ON events (node_id, kind, ts DESC);
