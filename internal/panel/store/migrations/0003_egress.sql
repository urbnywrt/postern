-- Egress management (slice 2): what the panel keeps of the egresses, their
-- chains and the egress settings of a node beyond what 0001 made.
--
--   nodes.dns_mode           how the containers of the node resolve names
--                            (NodeSettings.dns_mode): '' (the default of the
--                            node, doh) | doh | system
--   egresses.refresh_nonce   raised when the nodes are to fetch the
--                            subscription of the egress again
--                            (Egress.refresh_nonce)
--   egress_chains.created_at, egress_chains.updated_at
--                            as the other tables have them; 0 for the chains
--                            of a database from before

ALTER TABLE nodes ADD COLUMN dns_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE egresses ADD COLUMN refresh_nonce INTEGER NOT NULL DEFAULT 0;
ALTER TABLE egress_chains ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE egress_chains ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
