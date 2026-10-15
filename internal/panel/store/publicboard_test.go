package store

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

// migrationsUpTo returns the embedded migrations numbered up to last.
func migrationsUpTo(t *testing.T, last int) map[string]string {
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

// 0021 adds the footer of the page and the code of an item to a database at
// 19, and to one that also has a 20 (the migration of another change), with
// what the page had kept and the new values empty.
func TestPublicBoardMigration(t *testing.T) {
	// The 20 of the other change, once it is merged; until then one of our own.
	fake20 := map[string]string{"0020_other.sql": "CREATE TABLE other_change (x INTEGER) STRICT;"}
	if len(migrationsUpTo(t, 20)) > len(migrationsUpTo(t, 19)) {
		fake20 = nil
	}
	for _, c := range []struct {
		name    string
		oldLast int
		extra   map[string]string
	}{
		{"at 19", 19, nil},
		{"with a 20", 20, fake20},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "panel.db")
			old := mustOpenFS(t, path, with(migrationsUpTo(t, c.oldLast), c.extra), time.Now)
			mustExec(t, old, `INSERT INTO nodes (id, name, created_at, updated_at) VALUES ('N1', 'n', 1, 1)`)
			mustExec(t, old, `INSERT INTO listeners (id, node_id, port, created_at, updated_at) VALUES ('L1', 'N1', 443, 1, 1)`)
			mustExec(t, old, `INSERT INTO proxies (id, node_id, listener_id, enabled, secret_enc, created_at, updated_at) VALUES ('P1', 'N1', 'L1', 1, x'01', 1, 1)`)
			mustExec(t, old, `UPDATE public_page SET title = 'Kept', host = 'proxies.example.com' WHERE id = 1`)
			mustExec(t, old, `INSERT INTO public_page_items (proxy_id, position, public_name, public_note) VALUES ('P1', 0, 'Alpha', 'note')`)
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}

			db := mustOpenFS(t, path, with(migrationsUpTo(t, 21), c.extra), time.Now)
			t.Cleanup(func() { _ = db.Close() })
			if got := migrationsApplied(t, db); !slices.Contains(got, 21) {
				t.Fatalf("applied = %v, want 21 among them", got)
			}
			p, err := db.PublicPage(context.Background())
			if err != nil {
				t.Fatalf("PublicPage: %v", err)
			}
			if p.Title != "Kept" || p.Host != "proxies.example.com" || p.Footer != "" {
				t.Errorf("page after the migration = %+v", p)
			}
			want := []PublicPageItem{{ProxyID: "P1", PublicName: "Alpha", PublicNote: "note"}}
			if !reflect.DeepEqual(p.Items, want) {
				t.Errorf("items after the migration = %+v, want %+v", p.Items, want)
			}
		})
	}
}

// The footer and the codes are stored and read back.
func TestPublicPageFooterAndCodeRoundTrip(t *testing.T) {
	db := newTestDB(t)
	_, ps := pageFixture(t, db)
	ctx := context.Background()
	p := &PublicPage{
		Title: "Pick\nа direction", Footer: "line one\nline two", Unavailable: PublicUnavailableMark, DefaultLocale: "ru",
		Items: []PublicPageItem{
			{ProxyID: ps[0].ID, PublicName: "a", Code: "RU"},
			{ProxyID: ps[1].ID, PublicName: "b"},
		},
	}
	if err := db.UpdatePublicPage(ctx, p); err != nil {
		t.Fatalf("UpdatePublicPage: %v", err)
	}
	got, err := db.PublicPage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, p) {
		t.Errorf("PublicPage() = %+v\nwant %+v", got, p)
	}
}
