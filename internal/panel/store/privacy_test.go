package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// planted is the client address that the privacy tests look for on the disk.
var planted = []byte("198.51.100.77")

// fileHolds reports whether the file at path holds b; a file that is not there
// holds nothing.
func fileHolds(t *testing.T, path string, b []byte) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Contains(data, b)
}

// filesHolding returns the names of the files in dir that hold b.
func filesHolding(t *testing.T, dir string, b []byte) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if fileHolds(t, filepath.Join(dir, e.Name()), b) {
			out = append(out, e.Name())
		}
	}
	return out
}

// slice1Database makes a database of slices 0 and 1 at path, with a node N1, a
// listener L1, a proxy P1 and where the planted address was seen on it.
func slice1Database(t *testing.T, path string) {
	t.Helper()
	old := mustOpenFS(t, path, slice1Migrations(t), time.Now)
	mustExec(t, old, `INSERT INTO nodes (id, name, created_at, updated_at) VALUES ('N1', 'n', 1, 1)`)
	mustExec(t, old, `INSERT INTO listeners (id, node_id, port, created_at, updated_at) VALUES ('L1', 'N1', 443, 1, 1)`)
	mustExec(t, old, `INSERT INTO proxies (id, node_id, listener_id, enabled, secret_enc, created_at, updated_at) VALUES ('P1', 'N1', 'L1', 1, x'01', 1, 1)`)
	mustExec(t, old, `INSERT INTO stats_node_1m (node_id, ts, conns) VALUES ('N1', 60, 3)`)
	mustExec(t, old, `INSERT INTO ip_sightings (proxy_id, ip, first_seen, last_seen, bytes) VALUES ('P1', ?, 1, 2, 3)`, string(planted))
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
}

// The copy that is made before a migration keeps everything but where the
// addresses were seen, and leaves no file of its own work beside it.
func TestBackupHoldsNoClientAddresses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	slice1Database(t, path)
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	names := listBackups(t, path)
	if len(names) != 1 || !strings.HasSuffix(names[0], ".bak") {
		t.Fatalf("backups = %v, want one .bak file and nothing beside it", names)
	}
	backup := filepath.Join(filepath.Dir(path), "backups", names[0])
	if fileHolds(t, backup, planted) {
		t.Error("the backup holds the address")
	}
	b := openReadOnly(t, backup)
	if n := queryInt(t, b, `SELECT count(*) FROM ip_sightings`); n != 0 {
		t.Errorf("the backup has %d sightings, want none", n)
	}
	if n := queryInt(t, b, `SELECT count(*) FROM proxies`) + queryInt(t, b, `SELECT count(*) FROM stats_node_1m`); n != 2 {
		t.Errorf("the backup lost data: %d rows of proxies and node minutes, want 2", n)
	}
	// The database itself keeps them until the policy says otherwise.
	if n := count(t, db, `SELECT count(*) FROM ip_sightings`); n != 1 {
		t.Errorf("the database has %d sightings after the migration, want 1", n)
	}
}

// A crash in the middle of a backup leaves its first copy beside it, which
// still holds the client addresses: Open removes it, and what SQLite left
// beside it, and keeps the backups.
func TestOpenRemovesWhatACrashedBackupLeft(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	backups := filepath.Join(filepath.Dir(path), "backups")
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"panel.db.1700000000.bak.tmp", "panel.db.1700000000.bak.tmp-journal"} {
		if err := os.WriteFile(filepath.Join(backups, name), planted, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	kept := []string{"panel.db.1680000000.bak.tmpl", "panel.db.1690000000.bak"} // not copies of a backup
	for _, name := range kept {
		if err := os.WriteFile(filepath.Join(backups, name), []byte("kept"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if names := listBackups(t, path); !slices.Equal(names, kept) {
		t.Errorf("backups after Open = %v, want only %v", names, kept)
	}
}

// The copy that a backup is made of may be taken away while it is made (by
// another Open, for what a crash left): its scrub fails then, instead of
// making a new, empty copy and keeping a backup of nothing.
func TestScrubCopyNeedsItsCopy(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "panel.db.1.bak.tmp"), filepath.Join(dir, "panel.db.1.bak")
	if err := createPrivate(dst); err != nil {
		t.Fatal(err)
	}
	if err := scrubCopy(context.Background(), src, dst); err == nil {
		t.Fatal("scrubCopy of a copy that is not there: no error")
	}
	if _, err := os.Stat(src); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("scrubCopy made the copy that was not there: %v", err)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Size() != 0 {
		t.Errorf("the backup after a failed scrub: %v, %v; want it as it was, empty", fi, err)
	}
}

// A prune that is cancelled in the pause after its last step has emptied the
// write-ahead log of the addresses that it deleted already.
func TestPruneEmptiesTheLogBeforeItsLastPause(t *testing.T) {
	db, _, p, _ := statsFixture(t) // the default policy, countries, keeps no address
	putSighting(t, db, p.ID, string(planted), statsNow)
	ctx, cancel := context.WithCancel(context.Background())
	last := false
	db.steps.inTx = func(what string, _, _ int64) { last = what == "prune the rest" }
	db.steps.onPause = func() {
		if last {
			cancel()
		}
	}
	if err := db.PruneStats(ctx, statsNow, testRetention); !errors.Is(err, context.Canceled) {
		t.Fatalf("PruneStats cancelled in its last pause: err = %v, want context.Canceled", err)
	}
	if n := count(t, db, `SELECT count(*) FROM ip_sightings`); n != 0 {
		t.Fatalf("%d sightings are left, want none", n)
	}
	for _, f := range []string{db.path, db.path + "-wal"} {
		if fileHolds(t, f, planted) {
			t.Errorf("%s still holds the address", filepath.Base(f))
		}
	}
}

// Leaving full deletes the addresses from the disk: from the database file,
// its write-ahead log and the backups, and not only from the table.
func TestLeavingFullLeavesNoAddressOnTheDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	backups := filepath.Join(filepath.Dir(path), "backups")
	slice1Database(t, path)
	db, err := Open(path) // migrates, after a backup
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.now = fixedClock(statsNow)
	ctx := context.Background()
	if names := filesHolding(t, backups, planted); len(names) != 0 {
		t.Errorf("backups that hold the address: %v", names)
	}

	if _, err := db.ApplyStatsSettings(ctx, withPolicy("full")); err != nil {
		t.Fatal(err)
	}
	m := at(10, 12, 0)
	ingest(t, db, MinuteBatch{NodeID: "N1", Minute: m, Sightings: []Sighting{
		{ProxyID: "P1", IP: string(planted), FirstSeen: m, LastSeen: m, Bytes: 10},
	}})
	if !fileHolds(t, path, planted) && !fileHolds(t, path+"-wal", planted) {
		t.Fatal("the address is nowhere on the disk before it is deleted: the test would prove nothing")
	}

	d, err := db.ApplyStatsSettings(ctx, withPolicy("countries"))
	if err != nil {
		t.Fatalf("ApplyStatsSettings: %v", err)
	}
	if d.Sightings != 1 {
		t.Errorf("Deleted = %+v, want the one sighting", d)
	}
	for _, f := range []string{path, path + "-wal"} {
		if fileHolds(t, f, planted) {
			t.Errorf("%s still holds the address", filepath.Base(f))
		}
	}
	if names := filesHolding(t, backups, planted); len(names) != 0 {
		t.Errorf("backups that hold the address: %v", names)
	}
}

// captureLog sends what the store logs to a buffer until the test ends.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

// holdLog has a reader of its own open a snapshot of the database at path,
// which keeps the write-ahead log from being emptied until the function that
// it returns lets it go.
func holdLog(t *testing.T, path string) (release func()) {
	t.Helper()
	ctx := context.Background()
	reader, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := reader.BeginTx(ctx, nil)
	if err != nil {
		_ = reader.Close()
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ip_sightings`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			_ = tx.Rollback()
			_ = reader.Close()
		})
	}
	t.Cleanup(release)
	return release
}

// deleteBehindAHeldLog plants the address under full, and leaves full while a
// reader holds the write-ahead log: the address goes from the table, and stays
// in the log. The store waits for the reader as long as db.walWait. It returns
// what the store logged meanwhile, and the function that lets the reader go.
func deleteBehindAHeldLog(t *testing.T, db *DB, node *Node, p *Proxy) (logs *bytes.Buffer, release func()) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ApplyStatsSettings(ctx, withPolicy(IPPolicyFull)); err != nil {
		t.Fatal(err)
	}
	m := at(10, 12, 0)
	ingest(t, db, MinuteBatch{NodeID: node.ID, Minute: m, Sightings: []Sighting{
		{ProxyID: p.ID, IP: string(planted), FirstSeen: m, LastSeen: m, Bytes: 10},
	}})
	release = holdLog(t, db.path)
	logs = captureLog(t)
	d, err := db.ApplyStatsSettings(ctx, withPolicy(IPPolicyCountries))
	if err != nil || d.Sightings != 1 {
		t.Fatalf("ApplyStatsSettings = %+v, %v; want the sighting deleted and no error", d, err)
	}
	if !fileHolds(t, db.path, planted) && !fileHolds(t, db.path+"-wal", planted) {
		t.Fatal("the address is gone from the disk although a reader kept the log; the test does not hold the log as it means to")
	}
	return logs, release
}

// A reader that holds an old snapshot keeps the write-ahead log from being
// emptied; the settings are applied all the same, the store says so in its
// log, and the next prune empties the log, although it deletes no address of
// its own.
func TestTheLogIsEmptiedLaterWhenAReaderHeldIt(t *testing.T) {
	db, node, p, _ := ingestFixture(t)
	db.walWait = 50 * time.Millisecond // instead of a second
	logs, release := deleteBehindAHeldLog(t, db, node, p)
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "write-ahead log") {
		t.Errorf("the log does not say that the write-ahead log was not emptied:\n%s", logs)
	}
	release()

	if err := db.PruneStats(context.Background(), statsNow, testRetention); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}
	for _, f := range []string{db.path, db.path + "-wal"} {
		if fileHolds(t, f, planted) {
			t.Errorf("%s still holds the address after the prune", filepath.Base(f))
		}
	}
	if fi, err := os.Stat(db.path + "-wal"); err == nil && fi.Size() != 0 {
		t.Errorf("the write-ahead log has %d bytes after the prune, want none", fi.Size())
	}
}

// A crash after the log could not be emptied leaves the deleted address in it,
// and a prune under countries deletes no address that would make it try again:
// Open empties the log.
func TestOpenEmptiesTheLogThatACrashLeft(t *testing.T) {
	db, node, p, _ := ingestFixture(t)
	db.walWait = 50 * time.Millisecond
	_, release := deleteBehindAHeldLog(t, db, node, p)

	// The disk as a crash leaves it: the database and its log, copied while the
	// log still holds the address.
	crashed := filepath.Join(t.TempDir(), "panel.db")
	for _, suffix := range []string{"", "-wal"} {
		data, err := os.ReadFile(db.path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(crashed+suffix, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	release()
	if !fileHolds(t, crashed, planted) && !fileHolds(t, crashed+"-wal", planted) {
		t.Fatal("the copy holds no address: the test would prove nothing")
	}

	again, err := Open(crashed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = again.Close() })
	for _, f := range []string{crashed, crashed + "-wal"} {
		if fileHolds(t, f, planted) {
			t.Errorf("%s still holds the address after Open", filepath.Base(f))
		}
	}
}

// What the IP policy does not keep is not stored, whatever a batch holds: no
// address and no marker unless the policy is full, and no country when it is
// off. None stored is the default, countries; one that cannot be read, or that
// is not known, counts as off. The rest of a batch is stored under every
// policy.
func TestIngestMinuteKeepsWhatThePolicyAllows(t *testing.T) {
	for _, tt := range []struct {
		name      string
		stored    string // the raw JSON of ip_policy, "" for none
		sightings int
		countries int
	}{
		{"none stored", "", 0, 2},
		{"countries", `"countries"`, 0, 2},
		{"off", `"off"`, 0, 0},
		{"full", `"full"`, 1, 2},
		{"unreadable", `42`, 0, 0},
		{"unknown", `"everything"`, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db, node, p, q := statsFixture(t)
			db.now = fixedClock(statsNow)
			if tt.stored != "" {
				mustExec(t, db, `INSERT INTO settings (key, value) VALUES ('ip_policy', ?)`, tt.stored)
			}
			ingest(t, db, fullBatch(node, p, q, at(10, 12, 0)))
			for _, c := range []struct {
				table string
				want  int
			}{
				{"ip_sightings", tt.sightings},
				{"stats_batches", tt.sightings}, // a marker only for addresses that are stored
				{"stats_country_1m", tt.countries},
				{"stats_proxy_1m", 2},
				{"stats_node_1m", 1},
				{"egress_health_1m", 2},
				{"probes", 1},
			} {
				if n := count(t, db, `SELECT count(*) FROM `+c.table); n != c.want {
					t.Errorf("%s: %d rows, want %d", c.table, n, c.want)
				}
			}
		})
	}
}

// The ingestor reads the policy before it writes a batch, and the policy may
// leave full in between: the store reads it again under the write lock, which
// the change of the policy takes as well, so that no address of such a batch
// is left, whichever of the two commits first.
func TestNoAddressSurvivesAPolicyChangeDuringIngest(t *testing.T) {
	db, node, p, q := ingestFixture(t) // full
	ctx := context.Background()
	if s, _, err := db.StatsSettings(ctx); err != nil || s.IPPolicy != IPPolicyFull {
		t.Fatalf("the ingestor reads %q, %v; want full", s.IPPolicy, err)
	}
	batch := fullBatch(node, p, q, at(10, 12, 0)) // made under full
	if _, err := db.ApplyStatsSettings(ctx, withPolicy(IPPolicyCountries)); err != nil {
		t.Fatal(err)
	}
	ingest(t, db, batch)
	if n := count(t, db, `SELECT count(*) FROM ip_sightings`) + count(t, db, `SELECT count(*) FROM stats_batches`); n != 0 {
		t.Fatalf("%d sightings and markers after the policy left full, want none", n)
	}

	for i := range 20 {
		if _, err := db.ApplyStatsSettings(ctx, withPolicy(IPPolicyFull)); err != nil {
			t.Fatal(err)
		}
		var (
			wg                  sync.WaitGroup
			ingestErr, applyErr error
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, ingestErr = db.IngestMinute(ctx, fullBatch(node, p, q, at(10, 11, i)))
		}()
		go func() {
			defer wg.Done()
			_, applyErr = db.ApplyStatsSettings(ctx, withPolicy(IPPolicyCountries))
		}()
		wg.Wait()
		if ingestErr != nil || applyErr != nil {
			t.Fatalf("round %d: IngestMinute: %v; ApplyStatsSettings: %v", i, ingestErr, applyErr)
		}
		if n := count(t, db, `SELECT count(*) FROM ip_sightings`); n != 0 {
			t.Fatalf("round %d: %d sightings are left after the policy left full", i, n)
		}
	}
}

// Under a policy other than full the prune deletes every address there is,
// however recently it was seen: one that came in by another way does not stay
// for ip_days.
func TestPruneStatsDeletesEveryAddressUnlessThePolicyIsFull(t *testing.T) {
	db, _, p, _ := statsFixture(t)
	ctx := context.Background()
	putSighting(t, db, p.ID, "198.51.100.1", statsNow) // seen now: its age would keep it
	if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}
	if n := count(t, db, `SELECT count(*) FROM ip_sightings`); n != 0 {
		t.Errorf("%d sightings are left under the default policy, want none", n)
	}

	if _, err := db.ApplyStatsSettings(ctx, withPolicy(IPPolicyFull)); err != nil {
		t.Fatal(err)
	}
	putSighting(t, db, p.ID, "198.51.100.1", statsNow)
	if err := db.PruneStats(ctx, statsNow, testRetention); err != nil {
		t.Fatalf("PruneStats: %v", err)
	}
	if n := count(t, db, `SELECT count(*) FROM ip_sightings`); n != 1 {
		t.Errorf("%d sightings under full, want the one seen now", n)
	}
}
