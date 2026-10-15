-- Hidden management (slice 4, Ruling S4-7): the public tls listener port that
-- the panel reaches the agent through in mode hidden, with the TLS SNI
-- mgmt_sni. 0 in mode port. nodes.mgmt_port stays the plain management port
-- in both modes: the panel goes back to it when the node leaves mode hidden.

ALTER TABLE nodes ADD COLUMN mgmt_public_port INTEGER NOT NULL DEFAULT 0
  CHECK (mgmt_public_port BETWEEN 0 AND 65535);
