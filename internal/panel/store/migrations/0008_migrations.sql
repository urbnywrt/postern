-- The moves of nodes of the legacy mtproto-node stack into Postern (slice 4,
-- spec section 10), not to be confused with the migrations of this schema. The
-- conventions are those of 0001_init.sql.
--
-- A row is made once there is a snapshot of the legacy node: by a collection
-- over SSH, whose job has the id of the row, or by an upload. The snapshot holds
-- the proxy secrets, the tokens and the private keys of the legacy node, so it
-- is sealed, with the additional data "migration:<id>". The preview and the
-- plan that the later steps make of it hold no secret: they refer to the
-- proxies of the snapshot by their legacy ids, and the secrets stay sealed.
--
-- A migration goes with its node, and the secrets of the legacy node with it.
CREATE TABLE migrations (
  id           TEXT PRIMARY KEY,
  node_id      TEXT NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
  created_at   INTEGER NOT NULL,
  status       TEXT NOT NULL,       -- collected | the steps after it
  snapshot_enc BLOB NOT NULL,       -- the snapshot as JSON, sealed
  preview_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(preview_json)),
  plan_json    TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(plan_json))
) STRICT;

CREATE INDEX migrations_node_id_created_at_idx ON migrations (node_id, created_at DESC);
