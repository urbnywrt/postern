package store

import (
	"context"
	"slices"
	"testing"
)

// The own pool of a node is its enabled domains, and its blacklist the entries
// for every node with its own, both in the order they were added.
func TestNodeDomainPoolAndBlacklist(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	other := mustNode(t, db, "n2")
	mustExec(t, db, `INSERT INTO domain_pool (domain, node_id, enabled) VALUES ('b.example.com', ?, 1), ('off.example.com', ?, 0),
		('a.example.com', ?, 1), ('global.example.com', NULL, 1), ('other.example.com', ?, 1)`, n.ID, n.ID, n.ID, other.ID)
	mustExec(t, db, `INSERT INTO blacklist (cidr, node_id) VALUES ('192.0.2.0/24', ?), ('198.51.100.0/24', NULL), ('203.0.113.0/24', ?)`,
		n.ID, other.ID)

	if pool, err := db.NodeDomainPool(ctx, n.ID); err != nil || !slices.Equal(pool, []string{"b.example.com", "a.example.com"}) {
		t.Errorf("NodeDomainPool = %q, %v", pool, err)
	}
	if bl, err := db.NodeBlacklist(ctx, n.ID); err != nil || !slices.Equal(bl, []string{"192.0.2.0/24", "198.51.100.0/24"}) {
		t.Errorf("NodeBlacklist = %q, %v", bl, err)
	}
	if pool, err := db.NodeDomainPool(ctx, "none"); err != nil || pool != nil {
		t.Errorf("NodeDomainPool of no node = %q, %v", pool, err)
	}
}
