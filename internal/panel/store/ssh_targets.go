package store

import (
	"context"
	"fmt"
	"time"
)

// The values of SSHTarget.AuthKind: what the sealed credentials of a target
// are.
const (
	SSHAuthNone     = ""         // no credentials are kept
	SSHAuthPassword = "password" // a password
	SSHAuthKey      = "key"      // a private key, with its passphrase if it has one
)

// An SSHTarget is how the panel reaches a node over SSH. It goes with its node.
//
// HostKey is the fingerprint of the host key that an admin confirmed, as
// ssh-keygen -l prints it ("SHA256:..."), and HostKeyType the type of that key,
// for example "ssh-ed25519"; both are empty until the admin has confirmed one.
// SecretEnc holds the credentials, sealed by the caller with the additional
// data "ssh:<node id>", only when the admin asked the panel to keep them.
type SSHTarget struct {
	NodeID      string
	Host        string
	Port        uint32 // 1 to 65535
	User        string
	HostKey     string
	HostKeyType string
	AuthKind    string // one of the SSHAuth values
	SecretEnc   []byte // nil when no credentials are kept
	UpdatedAt   time.Time
}

const sshTargetColumns = `node_id, host, port, user, host_key, host_key_type, auth_kind, secret_enc, updated_at`

// PutSSHTarget stores t as the target of its node, replacing the one that is
// there, with the time of the clock as the time of the update. A node that does
// not exist is [ErrNotFound].
func (db *DB) PutSSHTarget(ctx context.Context, t *SSHTarget) error {
	updated := normTime(db.now())
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO ssh_targets (`+sshTargetColumns+`) VALUES (`+placeholders(9)+`)
		 ON CONFLICT (node_id) DO UPDATE SET
		   host = excluded.host, port = excluded.port, user = excluded.user,
		   host_key = excluded.host_key, host_key_type = excluded.host_key_type,
		   auth_kind = excluded.auth_kind, secret_enc = excluded.secret_enc,
		   updated_at = excluded.updated_at`,
		t.NodeID, t.Host, int64(t.Port), t.User, t.HostKey, t.HostKeyType, t.AuthKind, nullBlob(t.SecretEnc),
		updated.Unix())
	if err != nil {
		return fmt.Errorf("store: put SSH target: %w", mapErr(err, fkMissing))
	}
	t.UpdatedAt = updated
	return nil
}

// SSHTargetByNode returns the SSH target of a node, or [ErrNotFound].
func (db *DB) SSHTargetByNode(ctx context.Context, nodeID string) (*SSHTarget, error) {
	var (
		t       SSHTarget
		port    int64
		updated int64
	)
	err := db.sql.QueryRowContext(ctx, `SELECT `+sshTargetColumns+` FROM ssh_targets WHERE node_id = ?`, nodeID).
		Scan(&t.NodeID, &t.Host, &port, &t.User, &t.HostKey, &t.HostKeyType, &t.AuthKind, &t.SecretEnc, &updated)
	if err != nil {
		return nil, fmt.Errorf("store: SSH target by node: %w", queryNotFound(err, "SSH target"))
	}
	t.Port = uint32Of(port)
	t.UpdatedAt = timeFromDB(updated)
	return &t, nil
}

// DeleteSSHTarget deletes the SSH target of a node, with the credentials that
// it keeps. It is not an error that there is none.
func (db *DB) DeleteSSHTarget(ctx context.Context, nodeID string) error {
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM ssh_targets WHERE node_id = ?`, nodeID); err != nil {
		return fmt.Errorf("store: delete SSH target: %w", err)
	}
	return nil
}
