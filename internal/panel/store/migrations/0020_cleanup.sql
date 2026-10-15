-- Drops what nothing reads any more: the table migrations with its index, the
-- column nodes.standby and the column proxies.legacy. The conventions are those
-- of 0001_init.sql.

DROP INDEX migrations_node_id_created_at_idx;
DROP TABLE migrations;

ALTER TABLE nodes DROP COLUMN standby;

ALTER TABLE proxies DROP COLUMN legacy;
