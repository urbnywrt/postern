-- WEB proxies (slice 3): the DNS credentials that the nodes issue certificates
-- with, and the imported certificate of a proxy (Ruling S3-1).
--
--   dns_credentials.token_enc   the token, sealed with the master key (AAD
--                               dnscred:<id>); never returned by the API
--   proxies.cert_chain_enc      the imported fullchain.pem, sealed (AAD
--                               cert:<proxy id>); NULL when there is none
--   proxies.cert_key_enc        its private key, sealed the same way
--   proxies.cert_sha256         the lowercase hex SHA-256 of the chain, which
--                               the node serves the route by
--   proxies.cert_not_after      when the certificate expires, Unix seconds

CREATE TABLE dns_credentials (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  provider   TEXT NOT NULL DEFAULT 'cloudflare',
  token_enc  BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
) STRICT;

ALTER TABLE proxies ADD COLUMN cert_chain_enc BLOB;
ALTER TABLE proxies ADD COLUMN cert_key_enc BLOB;
ALTER TABLE proxies ADD COLUMN cert_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE proxies ADD COLUMN cert_not_after INTEGER NOT NULL DEFAULT 0;

CREATE INDEX proxies_dns_credential_idx ON proxies (dns_credential_id) WHERE dns_credential_id <> '';
