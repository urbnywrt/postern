package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/urbnywrt/postern/internal/ids"
)

// The values of DNSCredential.Provider.
const (
	DNSProviderCloudflare = "cloudflare"
)

// A DNSCredential is a credential of a DNS provider that the nodes issue the
// certificates of WEB proxies with (ACME DNS-01). Its token is sealed; the
// store never sees it open.
type DNSCredential struct {
	ID       string
	Name     string
	Provider string // DNSProviderCloudflare by default
	TokenEnc []byte
	// UsedBy is how many proxies name the credential; read only.
	UsedBy    int
	CreatedAt time.Time
	UpdatedAt time.Time
}

const dnsRowColumns = `c.id, c.name, c.provider, c.token_enc, c.created_at, c.updated_at,
	(SELECT COUNT(*) FROM proxies p WHERE p.dns_credential_id = c.id)`

func scanDNSCredential(s scanner) (*DNSCredential, error) {
	var (
		c                DNSCredential
		created, updated int64
	)
	if err := s.Scan(&c.ID, &c.Name, &c.Provider, &c.TokenEnc, &created, &updated, &c.UsedBy); err != nil {
		return nil, err
	}
	c.CreatedAt, c.UpdatedAt = timeFromDB(created), timeFromDB(updated)
	return &c, nil
}

// CreateDNSCredential stores c. It gives c an ID if it has none, the default
// provider if it has none, and the creation time.
func (db *DB) CreateDNSCredential(ctx context.Context, c *DNSCredential) error {
	return insertDNSCredential(ctx, db.sql, db.now(), c)
}

// insertDNSCredential is [DB.CreateDNSCredential] on q, with now as the time of
// the clock.
func insertDNSCredential(ctx context.Context, q dbtx, now time.Time, c *DNSCredential) error {
	n := *c
	if n.ID == "" {
		n.ID = ids.New()
	}
	if n.Provider == "" {
		n.Provider = DNSProviderCloudflare
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = now
	}
	n.CreatedAt = normTime(n.CreatedAt)
	n.UpdatedAt = n.CreatedAt
	n.UsedBy = 0
	_, err := q.ExecContext(ctx,
		`INSERT INTO dns_credentials (id, name, provider, token_enc, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		n.ID, n.Name, n.Provider, blobValue(n.TokenEnc), n.CreatedAt.Unix(), n.UpdatedAt.Unix())
	if err != nil {
		return fmt.Errorf("store: create dns credential: %w", mapErr(err, fkMissing))
	}
	*c = n
	return nil
}

// DNSCredentialByID returns the credential with this id, or [ErrNotFound].
func (db *DB) DNSCredentialByID(ctx context.Context, id string) (*DNSCredential, error) {
	c, err := scanDNSCredential(db.sql.QueryRowContext(ctx,
		`SELECT `+dnsRowColumns+` FROM dns_credentials c WHERE c.id = ?`, id))
	if err != nil {
		return nil, fmt.Errorf("store: dns credential by id: %w", queryNotFound(err, "dns credential"))
	}
	return c, nil
}

// ListDNSCredentials returns every credential in the order they were created.
func (db *DB) ListDNSCredentials(ctx context.Context) ([]*DNSCredential, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+dnsRowColumns+` FROM dns_credentials c ORDER BY c.created_at, c.id`)
	if err != nil {
		return nil, fmt.Errorf("store: list dns credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*DNSCredential
	for rows.Next() {
		c, err := scanDNSCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list dns credentials: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list dns credentials: %w", err)
	}
	return out, nil
}

// UpdateDNSCredential writes the name, the provider and the token of c, and
// sets the time of the last update. A credential that does not exist is
// [ErrNotFound].
func (db *DB) UpdateDNSCredential(ctx context.Context, c *DNSCredential) error {
	updated := normTime(db.now())
	res, err := db.sql.ExecContext(ctx,
		`UPDATE dns_credentials SET name = ?, provider = ?, token_enc = ?, updated_at = ? WHERE id = ?`,
		c.Name, c.Provider, blobValue(c.TokenEnc), updated.Unix(), c.ID)
	if err != nil {
		return fmt.Errorf("store: update dns credential: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: update dns credential: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: update dns credential: %w", notFound("dns credential"))
	}
	c.UpdatedAt = updated
	return nil
}

// DeleteDNSCredential deletes a credential that no proxy uses. One that a
// proxy names is [ErrConflict]; one that does not exist is [ErrNotFound].
func (db *DB) DeleteDNSCredential(ctx context.Context, id string) error {
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		var used bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM proxies WHERE dns_credential_id = ?)`, id).Scan(&used); err != nil {
			return err
		}
		if used {
			return fmt.Errorf("%w: a proxy uses the dns credential", ErrConflict)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM dns_credentials WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return notFound("dns credential")
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: delete dns credential: %w", err)
	}
	return nil
}
