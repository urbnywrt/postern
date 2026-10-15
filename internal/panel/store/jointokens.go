package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// A JoinToken lets a node join the panel with a key of its own (see the
// JoinService). Only the SHA-256 of the token is kept; a node has at most one.
type JoinToken struct {
	NodeID    string
	TokenHash []byte // SHA-256 of the token
	CreatedAt time.Time
	ExpiresAt time.Time
	// UsedAt is when a join consumed the token, the zero time while it has not.
	UsedAt time.Time
	// UsedKey is the SHA-256 of the PKIX DER public key that joined with the
	// token; empty while it has not been used.
	UsedKey []byte
}

// Used reports whether a join consumed the token.
func (t *JoinToken) Used() bool { return !t.UsedAt.IsZero() }

const nodeJoinColumns = `node_id, token_hash, created_at, expires_at, used_at, used_key`

// PutJoinToken stores the token of a node, replacing the one it had, used or
// not. The creation time is the clock's if t has none. A node that does not
// exist is [ErrNotFound]; a token hash that another node has, [ErrConflict].
func (db *DB) PutJoinToken(ctx context.Context, t *JoinToken) error {
	created := t.CreatedAt
	if created.IsZero() {
		created = db.now()
	}
	created, expires := normTime(created), normTime(t.ExpiresAt)
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO node_join_tokens (`+nodeJoinColumns+`) VALUES (?, ?, ?, ?, 0, x'')
		 ON CONFLICT (node_id) DO UPDATE SET token_hash = excluded.token_hash,
		   created_at = excluded.created_at, expires_at = excluded.expires_at, used_at = 0, used_key = x''`,
		t.NodeID, t.TokenHash, created.Unix(), expires.Unix())
	if err != nil {
		return fmt.Errorf("store: put join token: %w", mapErr(err, fkMissing))
	}
	t.CreatedAt, t.ExpiresAt, t.UsedAt, t.UsedKey = created, expires, time.Time{}, nil
	return nil
}

// JoinTokenByHash returns the token with this hash, or [ErrNotFound]. It
// returns an expired or used token too: what that means is for the caller.
func (db *DB) JoinTokenByHash(ctx context.Context, hash []byte) (*JoinToken, error) {
	return joinTokenWhere(ctx, db.sql, `token_hash = ?`, hash)
}

// JoinTokenOf returns the token of a node, or [ErrNotFound].
func (db *DB) JoinTokenOf(ctx context.Context, nodeID string) (*JoinToken, error) {
	return joinTokenWhere(ctx, db.sql, `node_id = ?`, nodeID)
}

func joinTokenWhere(ctx context.Context, q dbtx, where string, arg any) (*JoinToken, error) {
	var (
		t                      JoinToken
		created, expires, used int64
	)
	rows, err := q.QueryContext(ctx, `SELECT `+nodeJoinColumns+` FROM node_join_tokens WHERE `+where, arg)
	if err != nil {
		return nil, fmt.Errorf("store: join token: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("store: join token: %w", err)
		}
		return nil, fmt.Errorf("store: join token: %w", notFound("join token"))
	}
	if err := rows.Scan(&t.NodeID, &t.TokenHash, &created, &expires, &used, &t.UsedKey); err != nil {
		return nil, fmt.Errorf("store: join token: %w", err)
	}
	t.CreatedAt, t.ExpiresAt = timeFromDB(created), timeFromDB(expires)
	if used != 0 {
		t.UsedAt = timeFromDB(used)
	}
	if len(t.UsedKey) == 0 {
		t.UsedKey = nil
	}
	return &t, nil
}

// MarkJoinTokenUsed consumes a token: the one of the node with this hash, not
// used yet and not expired at at. usedKey is the SHA-256 of the public key
// that joined. A token that is not there in that state is [ErrConflict]: it
// was replaced, used or has expired in the meantime.
func (db *DB) MarkJoinTokenUsed(ctx context.Context, nodeID string, hash, usedKey []byte, at time.Time) error {
	if err := markJoinTokenUsed(ctx, db.sql, nodeID, hash, usedKey, at); err != nil {
		return fmt.Errorf("store: mark join token used: %w", err)
	}
	return nil
}

func markJoinTokenUsed(ctx context.Context, q dbtx, nodeID string, hash, usedKey []byte, at time.Time) error {
	if len(usedKey) == 0 {
		return errors.New("the key that joined is empty")
	}
	at = normTime(at)
	res, err := q.ExecContext(ctx,
		`UPDATE node_join_tokens SET used_at = ?, used_key = ?
		 WHERE node_id = ? AND token_hash = ? AND used_at = 0 AND expires_at > ?`,
		at.Unix(), usedKey, nodeID, hash, at.Unix())
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return fmt.Errorf("%w: the join token is not there, or was used or has expired", ErrConflict)
	}
	return nil
}

// A NodeJoin is what a join changes: the token it consumes, and the
// certificate of the key the node brought.
type NodeJoin struct {
	NodeID    string
	TokenHash []byte
	UsedKey   []byte // SHA-256 of the PKIX DER public key of the certificate
	At        time.Time

	CertPEM         string
	CertFingerprint string
	// MgmtHost is the address the node joined from, to take as its management
	// address (and link address) when it has none; "" for none.
	MgmtHost string
}

// ApplyJoin consumes the token (as [DB.MarkJoinTokenUsed] does) and gives the
// node the certificate of the join, all in one transaction. The node's sealed
// key is dropped: the panel has no key for this certificate. The management
// address is set only when the node has none, and so is the link address. It
// returns the node as it was written. A token that cannot be consumed is
// [ErrConflict], a node that is gone [ErrNotFound].
func (db *DB) ApplyJoin(ctx context.Context, j NodeJoin) (*Node, error) {
	var out *Node
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		if err := markJoinTokenUsed(ctx, tx, j.NodeID, j.TokenHash, j.UsedKey, j.At); err != nil {
			return err
		}
		n, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, j.NodeID))
		if err != nil {
			return queryNotFound(err, "node")
		}
		n.CertPEM, n.CertFingerprint, n.KeyEnc = j.CertPEM, j.CertFingerprint, nil
		if n.MgmtHost == "" && j.MgmtHost != "" {
			n.MgmtHost = j.MgmtHost
			if n.LinkHost == "" {
				n.LinkHost = j.MgmtHost
			}
		}
		updated := normTime(db.now())
		if err := updateNode(ctx, tx, n, updated); err != nil {
			return err
		}
		n.UpdatedAt = updated
		out = n
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: apply join: %w", err)
	}
	return out, nil
}

// SameKey reports whether the token was used by the key with this hash.
func (t *JoinToken) SameKey(keyHash []byte) bool {
	return t.Used() && len(keyHash) > 0 && bytes.Equal(t.UsedKey, keyHash)
}
