package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/urbnywrt/postern/internal/ids"
)

// The values of Egress.Kind.
const (
	EgressKindDirect           = "direct"            // out of the node itself, through an interface or not
	EgressKindSOCKS5           = "socks5"            // through a SOCKS5 proxy
	EgressKindHTTP             = "http"              // through an HTTP proxy that takes CONNECT
	EgressKindXrayURI          = "xray-uri"          // through the server of a share link, run by Xray
	EgressKindXraySubscription = "xray-subscription" // through the servers of a subscription, run by Xray
	EgressKindWARP             = "warp"              // through a WARP device of the node, run by Xray
	EgressKindPsiphon          = "psiphon"           // through Psiphon, run by Psiphon's own client
)

// An Egress is a way out to Telegram. The egress chains of the nodes are made
// of them.
type Egress struct {
	ID   string
	Name string
	Kind string // one of the EgressKind values; fixed when the egress is created
	// NodeID is the node that alone can use the egress, "" for one that every
	// node can use. It is fixed when the egress is created.
	NodeID string
	// ParamsEnc is the parameters of the kind as JSON, sealed; nil for none.
	ParamsEnc []byte
	// RefreshNonce is raised when the nodes are to fetch the subscription of
	// the egress again.
	RefreshNonce uint64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

const egressColumns = `id, name, kind, node_id, params_enc, refresh_nonce, created_at, updated_at`

func scanEgress(s scanner) (*Egress, error) {
	var (
		e                Egress
		node             sql.NullString
		nonce            int64
		created, updated int64
	)
	if err := s.Scan(&e.ID, &e.Name, &e.Kind, &node, &e.ParamsEnc, &nonce, &created, &updated); err != nil {
		return nil, err
	}
	e.NodeID = node.String
	e.RefreshNonce = uint64Of(nonce)
	e.CreatedAt, e.UpdatedAt = timeFromDB(created), timeFromDB(updated)
	return &e, nil
}

// CreateEgress stores e. It gives e an ID if it has none, a creation time if
// it has none, and the creation time as the time of the last update if that is
// not set. A node that does not exist is [ErrNotFound], and an id that is taken
// is [ErrConflict].
func (db *DB) CreateEgress(ctx context.Context, e *Egress) error {
	return insertEgress(ctx, db.sql, db.now(), e)
}

// insertEgress is [DB.CreateEgress] on q, with now as the time of the clock.
func insertEgress(ctx context.Context, q dbtx, now time.Time, e *Egress) error {
	c := *e
	if c.ID == "" {
		c.ID = ids.New()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.CreatedAt = normTime(c.CreatedAt)
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = c.CreatedAt
	}
	c.UpdatedAt = normTime(c.UpdatedAt)
	nonce, err := int64Of("refresh nonce", c.RefreshNonce)
	if err != nil {
		return fmt.Errorf("store: create egress: %w", err)
	}
	_, err = q.ExecContext(ctx,
		`INSERT INTO egresses (`+egressColumns+`) VALUES (`+placeholders(8)+`)`,
		c.ID, c.Name, c.Kind, nullString(c.NodeID), nullBlob(c.ParamsEnc), nonce, c.CreatedAt.Unix(), c.UpdatedAt.Unix())
	if err != nil {
		return fmt.Errorf("store: create egress: %w", mapErr(err, fkMissing))
	}
	*e = c
	return nil
}

// EgressByID returns the egress with this id, or [ErrNotFound].
func (db *DB) EgressByID(ctx context.Context, id string) (*Egress, error) {
	e, err := scanEgress(db.sql.QueryRowContext(ctx, `SELECT `+egressColumns+` FROM egresses WHERE id = ?`, id))
	if err != nil {
		return nil, fmt.Errorf("store: egress by id: %w", queryNotFound(err, "egress"))
	}
	return e, nil
}

// ListEgresses returns every egress, in the order they were created.
func (db *DB) ListEgresses(ctx context.Context) ([]*Egress, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+egressColumns+` FROM egresses ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list egresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Egress
	for rows.Next() {
		e, err := scanEgress(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list egresses: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list egresses: %w", err)
	}
	return out, nil
}

// UpdateEgress writes the name, the parameters and the refresh nonce of e, and
// sets the time of the last update. The kind and the node of an egress stay
// what they are. An egress that does not exist is [ErrNotFound].
func (db *DB) UpdateEgress(ctx context.Context, e *Egress) error {
	nonce, err := int64Of("refresh nonce", e.RefreshNonce)
	if err != nil {
		return fmt.Errorf("store: update egress: %w", err)
	}
	updated := normTime(db.now())
	res, err := db.sql.ExecContext(ctx,
		`UPDATE egresses SET name = ?, params_enc = ?, refresh_nonce = ?, updated_at = ? WHERE id = ?`,
		e.Name, nullBlob(e.ParamsEnc), nonce, updated.Unix(), e.ID)
	if err != nil {
		return fmt.Errorf("store: update egress: %w", mapErr(err, fkMissing))
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: update egress: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: update egress: %w", notFound("egress"))
	}
	e.UpdatedAt = updated
	return nil
}

// DeleteEgress deletes an egress. It is refused ([ErrConflict]) while a chain
// has the egress as a member. An egress that does not exist is [ErrNotFound].
func (db *DB) DeleteEgress(ctx context.Context, id string) error {
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM egresses WHERE id = ?`, id)
		if err != nil {
			return mapErr(err, fkInUse)
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return notFound("egress")
		}
		// The members of a chain are a JSON list, which no foreign key covers.
		var used bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM egress_chains, json_each(egress_chains.members) WHERE json_each.value = ?)`,
			id).Scan(&used); err != nil {
			return err
		}
		if used {
			return fmt.Errorf("%w: an egress chain has the egress as a member", ErrConflict)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: delete egress: %w", err)
	}
	return nil
}

// ChainCheck is how the edge checks the members of a chain. A field that is
// zero or empty is the default of the node.
type ChainCheck struct {
	IntervalSeconds  uint32   `json:"interval_seconds,omitempty"`
	TimeoutSeconds   uint32   `json:"timeout_seconds,omitempty"`
	FailThreshold    uint32   `json:"fail_threshold,omitempty"`
	RecoverThreshold uint32   `json:"recover_threshold,omitempty"`
	DCAddrs          []string `json:"dc_addrs,omitempty"`
}

// An EgressChain is an ordered list of egresses, which the edge tries in turn.
type EgressChain struct {
	ID   string
	Name string
	// NodeID is the node that alone can use the chain, "" for one that every
	// node can use. It is fixed when the chain is created.
	NodeID string
	// Members are the ids of the egresses of the chain, in their order. They
	// are not foreign keys: the service keeps them right.
	Members   []string
	Check     ChainCheck
	CreatedAt time.Time
	UpdatedAt time.Time
}

const chainColumns = `id, name, node_id, members, "check", created_at, updated_at`

func scanChain(s scanner) (*EgressChain, error) {
	var (
		c                EgressChain
		node             sql.NullString
		members, check   string
		created, updated int64
	)
	if err := s.Scan(&c.ID, &c.Name, &node, &members, &check, &created, &updated); err != nil {
		return nil, err
	}
	c.NodeID = node.String
	var err error
	if c.Members, err = decodeStrings(members); err != nil {
		return nil, fmt.Errorf("decode members: %w", err)
	}
	if err := json.Unmarshal([]byte(check), &c.Check); err != nil {
		return nil, fmt.Errorf("decode check: %w", err)
	}
	c.CreatedAt, c.UpdatedAt = timeFromDB(created), timeFromDB(updated)
	return &c, nil
}

// chainEncoded is the JSON columns of a chain.
type chainEncoded struct {
	members, check string
}

func encodeChain(c *EgressChain) (chainEncoded, error) {
	var (
		e   chainEncoded
		err error
	)
	if e.members, err = encodeStrings(c.Members); err != nil {
		return e, fmt.Errorf("encode members: %w", err)
	}
	check, err := json.Marshal(c.Check)
	if err != nil {
		return e, fmt.Errorf("encode check: %w", err)
	}
	e.check = string(check)
	return e, nil
}

// CreateChain stores c. It gives c an ID if it has none, a creation time if it
// has none, and the creation time as the time of the last update if that is
// not set. A node that does not exist is [ErrNotFound].
func (db *DB) CreateChain(ctx context.Context, c *EgressChain) error {
	return insertEgressChain(ctx, db.sql, db.now(), c)
}

// insertEgressChain is [DB.CreateChain] on q, with now as the time of the clock.
func insertEgressChain(ctx context.Context, q dbtx, now time.Time, c *EgressChain) error {
	n := *c
	if n.ID == "" {
		n.ID = ids.New()
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = now
	}
	n.CreatedAt = normTime(n.CreatedAt)
	if n.UpdatedAt.IsZero() {
		n.UpdatedAt = n.CreatedAt
	}
	n.UpdatedAt = normTime(n.UpdatedAt)
	enc, err := encodeChain(&n)
	if err != nil {
		return fmt.Errorf("store: create chain: %w", err)
	}
	_, err = q.ExecContext(ctx,
		`INSERT INTO egress_chains (`+chainColumns+`) VALUES (`+placeholders(7)+`)`,
		n.ID, n.Name, nullString(n.NodeID), enc.members, enc.check, n.CreatedAt.Unix(), n.UpdatedAt.Unix())
	if err != nil {
		return fmt.Errorf("store: create chain: %w", mapErr(err, fkMissing))
	}
	*c = n
	return nil
}

// ChainByID returns the chain with this id, or [ErrNotFound].
func (db *DB) ChainByID(ctx context.Context, id string) (*EgressChain, error) {
	c, err := scanChain(db.sql.QueryRowContext(ctx, `SELECT `+chainColumns+` FROM egress_chains WHERE id = ?`, id))
	if err != nil {
		return nil, fmt.Errorf("store: chain by id: %w", queryNotFound(err, "chain"))
	}
	return c, nil
}

// ListChains returns every chain, in the order they were created.
func (db *DB) ListChains(ctx context.Context) ([]*EgressChain, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+chainColumns+` FROM egress_chains ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list chains: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*EgressChain
	for rows.Next() {
		c, err := scanChain(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list chains: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list chains: %w", err)
	}
	return out, nil
}

// UpdateChain writes the name, the members and the check of c, and sets the
// time of the last update. The node of a chain stays what it is. A chain that
// does not exist is [ErrNotFound].
func (db *DB) UpdateChain(ctx context.Context, c *EgressChain) error {
	enc, err := encodeChain(c)
	if err != nil {
		return fmt.Errorf("store: update chain: %w", err)
	}
	updated := normTime(db.now())
	res, err := db.sql.ExecContext(ctx,
		`UPDATE egress_chains SET name = ?, members = ?, "check" = ?, updated_at = ? WHERE id = ?`,
		c.Name, enc.members, enc.check, updated.Unix(), c.ID)
	if err != nil {
		return fmt.Errorf("store: update chain: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: update chain: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: update chain: %w", notFound("chain"))
	}
	c.UpdatedAt = updated
	return nil
}

// DeleteChain deletes a chain. It is refused ([ErrConflict]) while a node has
// it as its default chain, or a proxy uses it, as its chain or for a scope. A
// chain that does not exist is [ErrNotFound].
func (db *DB) DeleteChain(ctx context.Context, id string) error {
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		// The foreign keys of nodes and proxies refuse the delete of a chain that
		// is a default chain or the chain of a proxy.
		res, err := tx.ExecContext(ctx, `DELETE FROM egress_chains WHERE id = ?`, id)
		if err != nil {
			return mapErr(err, fkInUse)
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			return notFound("chain")
		}
		// The scope chains of a proxy are a JSON object, which no foreign key
		// covers.
		var used bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM proxies, json_each(proxies.egress_scope_chains) WHERE json_each.value = ?)`,
			id).Scan(&used); err != nil {
			return err
		}
		if used {
			return fmt.Errorf("%w: a proxy uses the chain for a scope", ErrConflict)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store: delete chain: %w", err)
	}
	return nil
}
