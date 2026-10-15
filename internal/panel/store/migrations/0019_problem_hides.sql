-- Problem hides: an admin hides a problem of the feed until it changes. key
-- names the problem across refreshes (its source, node, check id or kind, and
-- target); fingerprint is a hash of its severity and summary when it was
-- hidden. The feed deletes a hide when the problem changes or clears, so the
-- table holds only the hides of problems that are there now.

CREATE TABLE problem_hides (
  key         TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  hidden_at   INTEGER NOT NULL,
  admin_id    TEXT NOT NULL DEFAULT ''
) STRICT;
