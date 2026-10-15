-- Since when a node has not applied its desired state (slice 6, the check
-- panel.state): the time of the oldest desired generation that the node has
-- not applied. It is set when the desired generation goes up from one that the
-- node had applied, and means nothing while the node is up to date. A node that
-- is behind already when this runs counts from its last update.

ALTER TABLE nodes ADD COLUMN behind_since INTEGER NOT NULL DEFAULT 0;

UPDATE nodes SET behind_since = updated_at WHERE applied_generation < desired_generation;
