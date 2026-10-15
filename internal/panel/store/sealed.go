package store

import (
	"context"
	"fmt"
)

// HasSealedData reports whether the database holds a value that was sealed with
// the master key: the CA of the panel or its client certificate (the settings
// pki.ca and pki.panel_client), a token for a release source (the settings
// releases.github_token and releases.source_token), the TOTP secret of an
// admin, the private key of a node, the secret of a proxy, the parameters of
// an egress, the token of a DNS credential or the SSH credentials of a node.
//
// It is how the panel tells a new installation from one that has lost its key.
// A database that holds no such value has nothing to lose, and the panel makes a
// key for it. One that holds any must not get a new key: the sealed values could
// never be opened again, and the CA that every node trusts would be replaced.
//
// A table or a setting that gets a sealed value in a later migration belongs
// here.
func (db *DB) HasSealedData(ctx context.Context) (bool, error) {
	var found int
	err := db.sql.QueryRowContext(ctx, `SELECT
		EXISTS (SELECT 1 FROM settings WHERE key IN ('pki.ca', 'pki.panel_client', 'releases.github_token', 'releases.source_token'))
		OR EXISTS (SELECT 1 FROM admins WHERE totp_secret_enc IS NOT NULL)
		OR EXISTS (SELECT 1 FROM nodes WHERE key_enc IS NOT NULL)
		OR EXISTS (SELECT 1 FROM proxies)
		OR EXISTS (SELECT 1 FROM egresses WHERE params_enc IS NOT NULL)
		OR EXISTS (SELECT 1 FROM dns_credentials)
		OR EXISTS (SELECT 1 FROM ssh_targets WHERE secret_enc IS NOT NULL)`).Scan(&found)
	if err != nil {
		return false, fmt.Errorf("store: look for sealed data: %w", err)
	}
	return found != 0, nil
}
