package store

import (
	"context"
	"fmt"
)

// NodeDomainPool returns the enabled domains of the own pool of a node, in the
// order they were added; none when it has no pool of its own.
func (db *DB) NodeDomainPool(ctx context.Context, nodeID string) ([]string, error) {
	return db.strings(ctx, "node domain pool",
		`SELECT domain FROM domain_pool WHERE node_id = ? AND enabled = 1 ORDER BY rowid`, nodeID)
}

// NodeBlacklist returns the blacklist of a node: the entries for every node and
// those of its own, in the order they were added.
func (db *DB) NodeBlacklist(ctx context.Context, nodeID string) ([]string, error) {
	return db.strings(ctx, "node blacklist",
		`SELECT cidr FROM blacklist WHERE node_id IS NULL OR node_id = ? ORDER BY rowid`, nodeID)
}

// strings runs a query of one text column.
func (db *DB) strings(ctx context.Context, what, query string, args ...any) ([]string, error) {
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: %s: %w", what, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("store: %s: %w", what, err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: %s: %w", what, err)
	}
	return out, nil
}
