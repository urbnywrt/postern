-- The takeover of a legacy mtproto-node stack (slice 4, Task 6; spec section
-- 10). The conventions are those of 0001_init.sql.
--
-- migrations.takeover_json is the last state of the takeover that the node
-- reported (node.v1.TakeoverStatus as JSON: phase, reason, the gap, the steps
-- and the checks, never a secret) with the panel's own probes after it; '{}'
-- before the first takeover. The statuses of a migration that follow applied:
-- switching (the takeover runs), switched (the edge serves the public
-- listeners), rolled_back (the legacy stack serves again), cleaned (the legacy
-- stack is removed; the snapshot stays as the archive).

ALTER TABLE migrations ADD COLUMN takeover_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(takeover_json));
