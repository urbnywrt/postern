-- Join tokens: a node that is installed with one docker run joins the panel
-- with a token instead of a bundle, and brings its own key (a certificate
-- request). A node has at most one live token; a new one replaces it. Only the
-- SHA-256 of a token is kept. used_at is 0 until a join consumes the token;
-- used_key is then the SHA-256 of the PKIX DER public key that joined, so a
-- repeat of the same join (a lost answer) can be told from another key.

CREATE TABLE node_join_tokens (
  node_id    TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  token_hash BLOB NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER NOT NULL DEFAULT 0,
  used_key   BLOB NOT NULL DEFAULT x''
) STRICT;
