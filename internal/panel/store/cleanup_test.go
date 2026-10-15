package store

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// embeddedUpTo returns the embedded migrations numbered up to last.
func embeddedUpTo(t *testing.T, last int) map[string]string {
	t.Helper()
	migs, err := loadMigrations(embeddedMigrations())
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, m := range migs {
		if m.version <= last {
			files[fmt.Sprintf("%04d_%s.sql", m.version, m.name)] = m.sql
		}
	}
	return files
}

// columnsOf returns the names of the columns of a table.
func columnsOf(t *testing.T, db *DB, table string) []string {
	t.Helper()
	return rowsOf(t, db, `SELECT name FROM pragma_table_info(?)`, table)
}

// A database of the schema before 0020, with a row of the table migrations, a
// node marked standby and a proxy with import ids, opens on 0020: the table and
// the columns are gone, and the node and the proxy are read and written as any.
func TestCleanupMigrationOn19(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	old := mustOpenFS(t, path, embeddedUpTo(t, 19), time.Now)
	if got := migrationsApplied(t, old); got[len(got)-1] != 19 {
		t.Fatalf("the old database is at %v, want 19 last", got)
	}
	mustExec(t, old, `INSERT INTO nodes (id, name, standby, created_at, updated_at) VALUES ('N1', 'n', 1, 1, 1)`)
	mustExec(t, old, `INSERT INTO listeners (id, node_id, port, created_at, updated_at) VALUES ('L1', 'N1', 443, 1, 1)`)
	mustExec(t, old, `INSERT INTO proxies (id, node_id, listener_id, enabled, secret_enc, legacy, web_public_addr, created_at, updated_at)
		VALUES ('P1', 'N1', 'L1', 1, x'01', '{"proxy_id":"42"}', '192.0.2.10:443', 1, 1)`)
	mustExec(t, old, `INSERT INTO migrations (id, node_id, created_at, status, snapshot_enc) VALUES ('M1', 'N1', 1, 'cleaned', x'01')`)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	if got := rowsOf(t, db, `SELECT version, name FROM schema_migrations WHERE version = 20`); !slices.Equal(got, []string{"20|cleanup"}) {
		t.Errorf("migration 20 = %v, want cleanup", got)
	}
	if n := count(t, db, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'migrations%'`); n != 0 {
		t.Errorf("%d tables or indexes of migrations are left", n)
	}
	if cols := columnsOf(t, db, "nodes"); slices.Contains(cols, "standby") {
		t.Errorf("nodes still has standby: %v", cols)
	}
	if cols := columnsOf(t, db, "proxies"); slices.Contains(cols, "legacy") || !slices.Contains(cols, "web_public_addr") {
		t.Errorf("proxies columns = %v, want no legacy and web_public_addr kept", cols)
	}

	n, err := db.NodeByID(ctx, "N1")
	if err != nil {
		t.Fatalf("NodeByID: %v", err)
	}
	n.Name = "renamed"
	if err := db.UpdateNode(ctx, n); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	p, err := db.ProxyByID(ctx, "P1")
	if err != nil {
		t.Fatalf("ProxyByID: %v", err)
	}
	if p.WebPublicAddr != "192.0.2.10:443" {
		t.Errorf("web public addr = %q, want it kept", p.WebPublicAddr)
	}
	p.AdTag = "0123456789abcdef0123456789abcdef"
	if err := db.UpdateProxy(ctx, p); err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}
	if err := db.DeleteNode(ctx, "N1"); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
}

// A new database migrates through 20, without the table migrations.
func TestCleanupMigrationOnANewDatabase(t *testing.T) {
	db := newTestDB(t)
	if got := migrationsApplied(t, db); !slices.Contains(got, 20) {
		t.Errorf("applied = %v, want 20 among them", got)
	}
	if n := count(t, db, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'migrations%'`); n != 0 {
		t.Errorf("%d tables or indexes of migrations on a new database", n)
	}
}
