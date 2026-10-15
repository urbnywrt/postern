package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

// newTestDB opens a database in a temporary directory with the real migrations.
// RollupStats and PruneStats do not pause between their transactions in it,
// unless a test sets a pause.
func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	db.steps.pause = 0
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// fixedClock returns a clock that always reads t.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// count runs a query that returns one integer.
func count(t *testing.T, db *DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.sql.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// migrationFS builds an fs.FS of migration files.
func migrationFS(files map[string]string) fstest.MapFS {
	m := fstest.MapFS{}
	for name, body := range files {
		m[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return m
}

// with returns a copy of files that also holds the extra ones.
func with(files map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range files {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

const (
	testMigration1 = "CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1);"
	testMigration2 = "CREATE TABLE u (y INTEGER); INSERT INTO t VALUES (2);"
	testMigration3 = "CREATE TABLE w (z INTEGER);"
)

// openFS opens the database at path with the given migrations.
func openFS(t *testing.T, path string, files map[string]string, now func() time.Time) (*DB, error) {
	t.Helper()
	return open(path, migrationFS(files), now)
}

// mustOpenFS is openFS for a call that has to work.
func mustOpenFS(t *testing.T, path string, files map[string]string, now func() time.Time) *DB {
	t.Helper()
	db, err := openFS(t, path, files, now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db
}

// openReadOnly opens a SQLite file that is not the live database, for example a
// backup.
func openReadOnly(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func queryInt(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// embeddedVersions returns the numbers of the migrations that are built in, in
// order: what a database that Open has migrated holds.
func embeddedVersions(t *testing.T) []int {
	t.Helper()
	migs, err := loadMigrations(embeddedMigrations())
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	var out []int
	for _, m := range migs {
		out = append(out, m.version)
	}
	return out
}

func migrationsApplied(t *testing.T, db *DB) []int {
	t.Helper()
	rows, err := db.sql.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func listBackups(t *testing.T, dbPath string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(filepath.Dir(dbPath), "backups"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestOpenCreatesSchema(t *testing.T) {
	db := newTestDB(t)
	rows, err := db.sql.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		got = append(got, name)
	}
	want := []string{
		"admins", "audit_log", "blacklist", "diagnostic_results", "diagnostic_runs", "dns_credentials", "domain_pool",
		"egress_chains", "egress_health", "egress_health_1m", "egresses", "engine_channels",
		"engine_releases", "events", "ip_sightings", "jobs", "listeners", "node_checks", "node_join_tokens",
		"nodes", "probes", "problem_hides", "proxies", "public_page", "public_page_items", "release_feeds", "rollout_items",
		"rollout_nodes", "rollout_steps", "rollouts", "schema_migrations", "sessions", "settings",
		"ssh_targets", "stats_batches", "stats_country_1d", "stats_country_1h", "stats_country_1m",
		"stats_node_1d", "stats_node_1h", "stats_node_1m",
		"stats_proxy_1d", "stats_proxy_1h", "stats_proxy_1m",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tables = %v, want %v", got, want)
	}
}

func TestOpenPragmas(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Hold two connections at once, so that they are two different ones: the
	// pragmas have to be set on every connection, not only on the first.
	var conns []*sql.Conn
	for range 2 {
		c, err := db.sql.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		conns = append(conns, c)
	}
	for i, c := range conns {
		check := func(pragma string, want any) {
			t.Helper()
			var got any
			switch want.(type) {
			case string:
				var s string
				if err := c.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&s); err != nil {
					t.Fatalf("connection %d: PRAGMA %s: %v", i, pragma, err)
				}
				got = s
			default:
				var n int
				if err := c.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&n); err != nil {
					t.Fatalf("connection %d: PRAGMA %s: %v", i, pragma, err)
				}
				got = n
			}
			if got != want {
				t.Errorf("connection %d: PRAGMA %s = %v, want %v", i, pragma, got, want)
			}
		}
		check("journal_mode", "wal")
		check("foreign_keys", 1)
		check("busy_timeout", 5000)
		check("synchronous", 2)   // FULL
		check("secure_delete", 1) // what is deleted is overwritten with zeros
	}
}

func TestOpenFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := filepath.Join(t.TempDir(), "data")
	path := filepath.Join(dir, "panel.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	// The database holds password hashes and sealed secrets.
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("database file mode = %v (err %v), want 0600", fi.Mode().Perm(), err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("data directory mode = %v (err %v), want 0700", fi.Mode().Perm(), err)
	}
}

// The write-ahead log holds the most recent writes, so it needs the same
// protection as the database.
func TestSideFilesAreNotReadableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.PutSetting(context.Background(), "k", "v"); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		fi, err := os.Stat(path + suffix)
		if err != nil {
			t.Fatalf("stat %s: %v (the database is not in WAL mode?)", suffix, err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has mode %v, which others can read or write", suffix, fi.Mode().Perm())
		}
	}
}

func TestOpenKeepsExistingFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := filepath.Join(t.TempDir(), "panel.db")
	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("mode of an existing file = %v (err %v), want it left alone (0640)", fi.Mode().Perm(), err)
	}
}

func TestOpenPathWithSpecialCharacters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("? is not valid in a Windows file name")
	}
	path := filepath.Join(t.TempDir(), "my data #1?x%25", "panel db.sqlite")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%q): %v", path, err)
	}
	if err := db.PutSetting(context.Background(), "k", "v"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the database is not at the path that was given: %v", err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var v string
	if ok, err := db.GetSetting(context.Background(), "k", &v); err != nil || !ok || v != "v" {
		t.Errorf("GetSetting = %q, %v, %v; want the value written before the reopen", v, ok, err)
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if db, err := Open(""); err == nil {
		_ = db.Close()
		t.Fatal("Open(\"\") succeeded")
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	want := embeddedVersions(t)
	for i := range 3 {
		db, err := Open(path)
		if err != nil {
			t.Fatalf("Open #%d: %v", i, err)
		}
		if got := migrationsApplied(t, db); !reflect.DeepEqual(got, want) {
			t.Errorf("open #%d: applied migrations = %v, want %v", i, got, want)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Nothing was applied after the first open, so nothing was backed up.
	if got := listBackups(t, path); len(got) != 0 {
		t.Errorf("backups = %v, want none", got)
	}
}

// Opening a new file from several places at once (two panels started together,
// say) migrates it once: the one that gets the write lock second finds the work
// done. Whether the openers get in each other's way depends on timing, so the
// test does it many times, each time with a file of its own.
func TestConcurrentOpenMigratesOnce(t *testing.T) {
	const rounds, opens = 25, 6
	dir := t.TempDir()
	want := embeddedVersions(t)
	for round := range rounds {
		path := filepath.Join(dir, fmt.Sprintf("panel-%d.db", round))
		dbs := make([]*DB, opens)
		errs := make([]error, opens)
		var wg sync.WaitGroup
		for i := range opens {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dbs[i], errs[i] = Open(path)
			}()
		}
		wg.Wait()
		failed := false
		for i := range opens {
			if errs[i] != nil {
				t.Errorf("round %d, Open #%d: %v", round, i, errs[i])
				failed = true
			}
		}
		if !failed {
			if got := migrationsApplied(t, dbs[0]); !reflect.DeepEqual(got, want) {
				t.Errorf("round %d: applied migrations = %v, want %v", round, got, want)
			}
			if got := listBackups(t, path); len(got) != 0 {
				t.Errorf("round %d: backups = %v, want none", round, got)
			}
		}
		for _, db := range dbs {
			if db != nil {
				_ = db.Close()
			}
		}
		if failed {
			return
		}
	}
}

func TestEmbeddedMigrations(t *testing.T) {
	migs, err := loadMigrations(embeddedMigrations())
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migs) == 0 || migs[0].version != 1 || migs[0].name != "init" {
		t.Fatalf("first embedded migration = %+v, want version 1 named init", migs)
	}
	for i := 1; i < len(migs); i++ {
		if migs[i].version <= migs[i-1].version {
			t.Errorf("migrations are not in order: %d after %d", migs[i].version, migs[i-1].version)
		}
	}
}

func TestLoadMigrations(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		wantVers []int
		wantErr  string
	}{
		{
			name: "ordered by number, not by name",
			files: map[string]string{
				"0010_c.sql": "SELECT 1;", "0002_b.sql": "SELECT 1;", "0001_a.sql": "SELECT 1;",
				"README.md": "not a migration",
			},
			wantVers: []int{1, 2, 10},
		},
		{
			name:    "empty",
			files:   map[string]string{},
			wantErr: "no migrations",
		},
		{
			name:    "duplicate version",
			files:   map[string]string{"0001_a.sql": "SELECT 1;", "0001_b.sql": "SELECT 1;"},
			wantErr: "twice",
		},
		{
			name:    "a sql file without a number",
			files:   map[string]string{"init.sql": "SELECT 1;"},
			wantErr: "init.sql",
		},
		{
			name:    "version zero",
			files:   map[string]string{"0000_x.sql": "SELECT 1;"},
			wantErr: "0000_x.sql",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			migs, err := loadMigrations(migrationFS(tt.files))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []int
			for _, m := range migs {
				got = append(got, m.version)
			}
			if !slices.Equal(got, tt.wantVers) {
				t.Errorf("versions = %v, want %v", got, tt.wantVers)
			}
		})
	}
}

func TestBackupBeforeSecondMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	clock := fixedClock(time.Unix(1_700_000_000, 0))
	v1 := map[string]string{"0001_init.sql": testMigration1}
	v2 := with(v1, map[string]string{"0002_more.sql": testMigration2})

	db := mustOpenFS(t, path, v1, clock)
	if got := listBackups(t, path); len(got) != 0 {
		t.Fatalf("the first migration of an empty database made backups: %v", got)
	}
	_ = db.Close()

	db = mustOpenFS(t, path, v2, clock)
	defer func() { _ = db.Close() }()

	want := "panel.db.1700000000.bak"
	if got := listBackups(t, path); !slices.Equal(got, []string{want}) {
		t.Fatalf("backups = %v, want [%s]", got, want)
	}
	backup := filepath.Join(filepath.Dir(path), "backups", want)
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(backup); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("backup mode = %v (err %v), want 0600", fi.Mode().Perm(), err)
		}
		if fi, err := os.Stat(filepath.Dir(backup)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("backups directory mode = %v (err %v), want 0700", fi.Mode().Perm(), err)
		}
	}

	// The backup is the database as it was before the migration.
	b := openReadOnly(t, backup)
	if got := queryInt(t, b, `SELECT count(*) FROM t`); got != 1 {
		t.Errorf("backup has %d rows in t, want 1", got)
	}
	if got := queryInt(t, b, `SELECT count(*) FROM sqlite_master WHERE name = 'u'`); got != 0 {
		t.Error("backup has the table of the second migration")
	}
	// The live database has it.
	if got := count(t, db, `SELECT count(*) FROM t`); got != 2 {
		t.Errorf("database has %d rows in t, want 2", got)
	}
	if got := migrationsApplied(t, db); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("applied = %v, want [1 2]", got)
	}

	// Opening again applies nothing, so nothing more is backed up.
	_ = db.Close()
	db = mustOpenFS(t, path, v2, clock)
	defer func() { _ = db.Close() }()
	if got := listBackups(t, path); !slices.Equal(got, []string{want}) {
		t.Errorf("backups after reopening = %v, want [%s]", got, want)
	}
}

func TestOneBackupForSeveralMigrations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	clock := fixedClock(time.Unix(1_700_000_000, 0))
	v1 := map[string]string{"0001_init.sql": testMigration1}
	_ = mustOpenFS(t, path, v1, clock).Close()

	v3 := with(v1, map[string]string{"0002_more.sql": testMigration2, "0003_last.sql": testMigration3})
	db := mustOpenFS(t, path, v3, clock)
	defer func() { _ = db.Close() }()
	if got := listBackups(t, path); len(got) != 1 {
		t.Errorf("backups = %v, want exactly one", got)
	}
	if got := migrationsApplied(t, db); !slices.Equal(got, []int{1, 2, 3}) {
		t.Errorf("applied = %v, want [1 2 3]", got)
	}
}

func TestNoBackupForEmptyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	files := map[string]string{"0001_init.sql": testMigration1, "0002_more.sql": testMigration2}
	db := mustOpenFS(t, path, files, fixedClock(time.Unix(1_700_000_000, 0)))
	defer func() { _ = db.Close() }()
	if got := listBackups(t, path); len(got) != 0 {
		t.Errorf("backups = %v, want none for a database that was empty", got)
	}
	if got := migrationsApplied(t, db); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("applied = %v, want [1 2]", got)
	}
}

func TestBackupDoesNotOverwriteAnEarlierOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	clock := fixedClock(time.Unix(1_700_000_000, 0)) // every backup is made in the same second
	v1 := map[string]string{"0001_init.sql": testMigration1}
	v2 := with(v1, map[string]string{"0002_more.sql": testMigration2})
	v3 := with(v2, map[string]string{"0003_last.sql": testMigration3})

	_ = mustOpenFS(t, path, v1, clock).Close()
	_ = mustOpenFS(t, path, v2, clock).Close()
	_ = mustOpenFS(t, path, v3, clock).Close()

	got := listBackups(t, path)
	want := []string{"panel.db.1700000000.bak", "panel.db.1700000001.bak"}
	if !slices.Equal(got, want) {
		t.Fatalf("backups = %v, want %v", got, want)
	}
	// The first one is still the database before the second migration.
	first := openReadOnly(t, filepath.Join(filepath.Dir(path), "backups", want[0]))
	if got := queryInt(t, first, `SELECT count(*) FROM sqlite_master WHERE name IN ('u', 'w')`); got != 0 {
		t.Error("the first backup was overwritten by a later one")
	}
}

func TestFailedMigrationRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	clock := fixedClock(time.Unix(1_700_000_000, 0))
	v1 := map[string]string{"0001_init.sql": testMigration1}
	_ = mustOpenFS(t, path, v1, clock).Close()

	// The second statement fails, and so does the whole migration with it, as
	// does the third migration that comes after.
	bad := with(v1, map[string]string{
		"0002_bad.sql":  "CREATE TABLE ok (x INTEGER); CREATE TABLE ok (y INTEGER);",
		"0003_next.sql": testMigration3,
	})
	if db, err := openFS(t, path, bad, clock); err == nil {
		_ = db.Close()
		t.Fatal("open with a failing migration succeeded")
	} else if !strings.Contains(err.Error(), "0002") {
		t.Errorf("err = %v, want it to name migration 0002", err)
	}

	// A database is left as it was, and it was backed up first.
	if got := listBackups(t, path); len(got) != 1 {
		t.Errorf("backups = %v, want one", got)
	}
	db := mustOpenFS(t, path, v1, clock)
	defer func() { _ = db.Close() }()
	if got := migrationsApplied(t, db); !slices.Equal(got, []int{1}) {
		t.Errorf("applied = %v, want [1]", got)
	}
	if got := count(t, db, `SELECT count(*) FROM sqlite_master WHERE name IN ('ok', 'w')`); got != 0 {
		t.Errorf("%d tables of the failed migrations survived", got)
	}
}

func TestDatabaseNewerThanBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	clock := fixedClock(time.Unix(1_700_000_000, 0))
	v1 := map[string]string{"0001_init.sql": testMigration1}
	v2 := with(v1, map[string]string{"0002_more.sql": testMigration2})
	_ = mustOpenFS(t, path, v2, clock).Close()

	db, err := openFS(t, path, v1, clock)
	if err == nil {
		_ = db.Close()
		t.Fatal("a database from a newer version was opened")
	}
	if !strings.Contains(err.Error(), "newer") {
		t.Errorf("err = %v, want it to say that the database is newer", err)
	}
}

// A migration is its number and its name. A database that holds a number under
// another name than this version gives it was migrated by files that have been
// renumbered or renamed since, and what this version would skip as done is not
// what was done. It is refused before anything is changed, and says why.
func TestDatabaseWithAMigrationOfAnotherName(t *testing.T) {
	v1 := map[string]string{"0001_init.sql": testMigration1}
	tests := []struct {
		name     string
		migrated map[string]string // the files that migrated the database
		now      map[string]string // the files of this version
		want     []string          // what the error says
		applied  []int             // what the database holds, and keeps
	}{
		{
			name:     "the same number under another name",
			migrated: with(v1, map[string]string{"0002_more.sql": testMigration2}),
			now:      with(v1, map[string]string{"0002_other.sql": testMigration3}),
			want:     []string{"migration 2", `"more"`, `"other"`},
			applied:  []int{1, 2},
		},
		{
			// What a renumbering accident looks like: the migration that was 2 is
			// 3 now, and another one has taken the number 2.
			name:     "renumbered, and the number taken by another",
			migrated: with(v1, map[string]string{"0002_more.sql": testMigration2}),
			now:      with(v1, map[string]string{"0002_other.sql": testMigration3, "0003_more.sql": testMigration2}),
			want:     []string{"migration 2", `"more"`, `"other"`},
			applied:  []int{1, 2},
		},
		{
			name:     "the first migration renamed",
			migrated: v1,
			now:      map[string]string{"0001_start.sql": testMigration1, "0002_more.sql": testMigration2},
			want:     []string{"migration 1", `"init"`, `"start"`},
			applied:  []int{1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "panel.db")
			clock := fixedClock(time.Unix(1_700_000_000, 0))
			_ = mustOpenFS(t, path, tt.migrated, clock).Close()

			db, err := openFS(t, path, tt.now, clock)
			if err == nil {
				_ = db.Close()
				t.Fatal("a database with a migration of another name was opened")
			}
			for _, want := range tt.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %v, want it to contain %s", err, want)
				}
			}

			// Refused before anything was done: no copy of a database that is not
			// changed, and the migrations are as they were.
			if got := listBackups(t, path); len(got) != 0 {
				t.Errorf("backups = %v, want none", got)
			}
			db = mustOpenFS(t, path, tt.migrated, clock)
			defer func() { _ = db.Close() }()
			if got := migrationsApplied(t, db); !slices.Equal(got, tt.applied) {
				t.Errorf("applied = %v, want %v", got, tt.applied)
			}
		})
	}
}

// Two versions whose migrations differ, opened on a new file at the same time:
// the one that migrates first wins, and the other has to refuse the database,
// whether it finds out before it takes the write lock or after it has waited for
// it. It must not take the number that the winner applied for the migration of
// its own that has the same number. Whether the loser is already past its first
// look at the database when the winner commits depends on timing, so the test
// does it many times, each time with a file of its own.
func TestConcurrentOpenOfDifferentMigrations(t *testing.T) {
	const rounds = 15
	versions := []map[string]string{
		{"0001_init.sql": testMigration1, "0002_alpha.sql": testMigration2},
		{"0001_init.sql": testMigration1, "0002_beta.sql": testMigration3},
	}
	dir := t.TempDir()
	for round := range rounds {
		path := filepath.Join(dir, fmt.Sprintf("panel-%d.db", round))
		dbs := make([]*DB, len(versions))
		errs := make([]error, len(versions))
		var wg sync.WaitGroup
		for i := range versions {
			wg.Add(1)
			go func() {
				defer wg.Done()
				dbs[i], errs[i] = open(path, migrationFS(versions[i]), time.Now)
			}()
		}
		wg.Wait()
		refused := 0
		for i, err := range errs {
			if err == nil {
				continue
			}
			refused++
			if !strings.Contains(err.Error(), "renumbered or renamed") {
				t.Errorf("round %d, version %d: err = %v, want the refusal of a migration of another name", round, i, err)
			}
		}
		if refused != 1 {
			t.Errorf("round %d: %d of 2 versions were refused (%v), want exactly one", round, refused, errs)
		}
		for _, db := range dbs {
			if db != nil {
				_ = db.Close()
			}
		}
	}
}

// checkApplied is what Open and the transaction of a migration run on the
// migrations that the database holds.
func TestCheckApplied(t *testing.T) {
	migs := []migration{{version: 1, name: "init"}, {version: 2, name: "more"}}
	tests := []struct {
		name    string
		applied map[int]string
		wantErr string // "" for none
	}{
		{name: "nothing applied", applied: map[int]string{}},
		{name: "some", applied: map[int]string{1: "init"}},
		{name: "all", applied: map[int]string{1: "init", 2: "more"}},
		{name: "a number that this version does not know", applied: map[int]string{1: "init", 2: "more", 3: "last"}, wantErr: "newer"},
		{name: "a name that differs", applied: map[int]string{1: "init", 2: "other"}, wantErr: `migration 2 as "other"`},
		{name: "the case of a name counts", applied: map[int]string{1: "Init"}, wantErr: `migration 1 as "Init"`},
		{name: "an empty name differs too", applied: map[int]string{1: ""}, wantErr: "migration 1"},
		{name: "the lowest number that is wrong is reported", applied: map[int]string{1: "start", 2: "other", 3: "last"}, wantErr: "migration 1"},
		{name: "a name that differs before a number that is unknown", applied: map[int]string{2: "other", 3: "last"}, wantErr: "migration 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkApplied(tt.applied, migs)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("err = %v, want none", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestClosedDatabaseReturnsErrors(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CountAdmins(context.Background()); err == nil {
		t.Error("CountAdmins on a closed database returned no error")
	}
}

// TestSchemaCascadeInSQL pins the foreign keys of the schema itself, without the
// help of the repositories: a node takes its listeners, proxies and their
// statistics with it, and a listener in use cannot be deleted.
//
// Deleting a node in plain SQL only works because the table of proxies is
// created after that of listeners: SQLite runs the cascades in the reverse order
// of creation, and the proxies have to go before the listeners that they restrict.
// DeleteNode does not depend on that, but a migration that rebuilds one of the
// two tables has to keep the order, and this test says so if it does not.
func TestSchemaCascadeInSQL(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	exec := func(q string, args ...any) error {
		_, err := db.sql.ExecContext(ctx, q, args...)
		return err
	}
	mustExec := func(q string, args ...any) {
		t.Helper()
		if err := exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec(`INSERT INTO nodes (id, name, created_at, updated_at) VALUES ('N1', 'n', 0, 0)`)
	mustExec(`INSERT INTO listeners (id, node_id, port, created_at, updated_at) VALUES ('L1', 'N1', 443, 0, 0)`)
	mustExec(`INSERT INTO proxies (id, node_id, listener_id, enabled, secret_enc, created_at, updated_at) VALUES ('P1', 'N1', 'L1', 1, x'01', 0, 0)`)
	mustExec(`INSERT INTO stats_proxy_1m (proxy_id, ts) VALUES ('P1', 60)`)
	mustExec(`INSERT INTO stats_node_1m (node_id, ts) VALUES ('N1', 60)`)

	if err := exec(`DELETE FROM listeners WHERE id = 'L1'`); err == nil {
		t.Fatal("a listener that a proxy uses was deleted")
	}
	mustExec(`DELETE FROM nodes WHERE id = 'N1'`)
	for _, table := range []string{"listeners", "proxies", "stats_proxy_1m", "stats_node_1m"} {
		if n := count(t, db, `SELECT count(*) FROM `+table); n != 0 {
			t.Errorf("%s has %d rows left after the node was deleted", table, n)
		}
	}
}

// The schema of the migration of slice 6, on a database that slices 0 and 1
// made: the data stays, the new columns have their defaults, and the public
// page has its one row.
func TestInsightsMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	slice1Database(t, path)
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	if got := rowsOf(t, db, `SELECT version, name FROM schema_migrations WHERE version = 5`); !slices.Equal(got, []string{"5|insights"}) {
		t.Errorf("migration 5 = %v, want insights", got)
	}
	n, err := db.NodeByID(ctx, "N1")
	if err != nil {
		t.Fatalf("NodeByID: %v", err)
	}
	if n.PanelAddrs != nil || n.EdgeRollNonce != 0 {
		t.Errorf("node after the migration: panel addresses %v, edge roll nonce %d; want none and 0", n.PanelAddrs, n.EdgeRollNonce)
	}
	p, err := db.ProxyByID(ctx, "P1")
	if err != nil {
		t.Fatalf("ProxyByID: %v", err)
	}
	if p.RestartNonce != 0 || p.CertReissueNonce != 0 {
		t.Errorf("proxy after the migration: nonces %d and %d, want 0", p.RestartNonce, p.CertReissueNonce)
	}
	if got := rowsOf(t, db, `SELECT conns, refused_prehello, refused_total, evicted_prehello FROM stats_node_1m`); !slices.Equal(got, []string{"3|0|0|0"}) {
		t.Errorf("node minute after the migration = %v, want its connections and no refusals", got)
	}
	if got := rowsOf(t, db, `SELECT ip, bytes FROM ip_sightings`); !slices.Equal(got, []string{string(planted) + "|3"}) {
		t.Errorf("sightings after the migration = %v", got)
	}
	want := []string{"1|0||||mark|1|ru|0"}
	if got := rowsOf(t, db, `SELECT id, enabled, host, title, body_md, unavailable, noindex, default_locale, updated_at FROM public_page`); !slices.Equal(got, want) {
		t.Errorf("public_page = %q, want %q", got, want)
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT INTO public_page (id) VALUES (2)`); err == nil {
		t.Error("a second row of public_page was stored")
	}
}

func TestAMigrationBelowTheAppliedOnesIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	clock := fixedClock(time.Unix(1_700_000_000, 0))
	v1 := map[string]string{"0001_init.sql": testMigration1, "0003_last.sql": testMigration3}
	_ = mustOpenFS(t, path, v1, clock).Close()

	// 0002 came after the database had 0003: it was written for a schema
	// without 0003, and is not run after it.
	late := with(v1, map[string]string{"0002_more.sql": testMigration2})
	db, err := openFS(t, path, late, clock)
	if err == nil {
		_ = db.Close()
		t.Fatal("a database at 0003 ran the new migration 0002")
	}
	for _, want := range []string{"0002", "0003", "renumber"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to say %q", err, want)
		}
	}

	// A migration that holds no statement only reserves its number, and is
	// recorded wherever it is.
	reserved := with(v1, map[string]string{"0002_reserved.sql": "-- reserved, nothing to do\n\n  -- really\n"})
	db = mustOpenFS(t, path, reserved, clock)
	defer func() { _ = db.Close() }()
	if got := migrationsApplied(t, db); !slices.Equal(got, []int{1, 2, 3}) {
		t.Errorf("applied = %v, want [1 2 3]", got)
	}
}

func TestEmbeddedMigrationsHaveNoGap(t *testing.T) {
	migs, err := loadMigrations(embeddedMigrations())
	if err != nil {
		t.Fatal(err)
	}
	want := 1
	for i, m := range migs {
		if m.version != want {
			t.Fatalf("migration %d (%s) is in place %d: the numbers have a gap", m.version, m.name, i+1)
		}
		want++
	}
}
