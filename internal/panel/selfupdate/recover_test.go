package selfupdate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// recoverAt is a recoverer of version in dir, which does not run from bin
// and whose image binary prints imageOut.
func recoverAt(dir, version, imageOut string) recoverer {
	return recoverer{dataDir: dir, version: version, log: discard(),
		exe: func() (string, error) { return "/usr/local/bin/postern-panel", nil },
		run: func(context.Context, string, ...string) ([]byte, error) {
			if imageOut == "" {
				return nil, errors.New("no image")
			}
			return []byte(imageOut), nil
		},
		imageBin: "/usr/local/bin/postern-panel", now: time.Now}
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func TestRecoverUpdated(t *testing.T) {
	dir := t.TempDir()
	if err := writeJSON(filepath.Join(dir, journalFile), journal{From: "v0.4.0", To: "v0.5.0", Backup: "/data/backups/x.bak", At: 100}); err != nil {
		t.Fatal(err)
	}
	o, err := recoverAt(dir, "v0.5.0", "").recover()
	if err != nil || o.Kind != OutcomeUpdated || o.From != "v0.4.0" || o.To != "v0.5.0" {
		t.Fatalf("recover: %+v %v", o, err)
	}
	if !exists(filepath.Join(dir, journalFile)) {
		t.Fatal("the journal is deleted only once the panel serves")
	}
	db, err := store.Open(filepath.Join(dir, DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	Settle(ctx, db, dir, o, discard())
	if exists(filepath.Join(dir, journalFile)) {
		t.Error("Settle left the journal")
	}
	assertEvent(t, db, EventUpdated)
	if last, err := LastUpdate(ctx, db); err != nil || !strings.Contains(last, "updated from v0.4.0 to v0.5.0") {
		t.Errorf("LastUpdate %q %v", last, err)
	}
}

func assertEvent(t *testing.T, db *store.DB, kind string) *store.Event {
	t.Helper()
	events, err := db.ListEvents(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Kind == kind {
			return e
		}
	}
	t.Fatalf("no event %s among %d", kind, len(events))
	return nil
}

// newerDB makes the database of dir newer than this version, as v0.5.0
// would have migrated it, after a snapshot was taken: a migration this
// version does not know, written through a connection that it leaves open,
// so that -wal and -shm are there. It returns the snapshot.
func newerDB(t *testing.T, dir string) (snapshot string, hold *sql.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(filepath.Join(dir, DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PutSetting(ctx, "test.marker", "before"); err != nil {
		t.Fatal(err)
	}
	snapshot, err = db.Backup(ctx, "pre-v0.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	hold, err = sql.Open("sqlite", "file:"+filepath.Join(dir, DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hold.Close() })
	if _, err := hold.Exec(`PRAGMA wal_autocheckpoint = 0`); err != nil {
		t.Fatal(err)
	}
	if _, err := hold.Exec(`INSERT INTO schema_migrations (version, name, applied_at) VALUES (9999, 'from_the_future', 0)`); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"-wal", "-shm"} {
		if !exists(filepath.Join(dir, DatabaseFile+s)) {
			t.Fatalf("no %s to move", s)
		}
	}
	if newer, err := store.NewerSchema(filepath.Join(dir, DatabaseFile)); err != nil || !newer {
		t.Fatalf("NewerSchema: %v %v", newer, err)
	}
	return snapshot, hold
}

func TestRecoverRestoresTheSnapshotAfterARollback(t *testing.T) {
	dir := t.TempDir()
	snapshot, hold := newerDB(t, dir)
	at := time.Now().Unix() - 100
	if err := writeJSON(filepath.Join(dir, journalFile), journal{From: "v0.4.0", To: "v0.5.0", Backup: snapshot, At: at}); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, rollbackFile), fmt.Sprintf("%d postern-panel-v0.5.0 /usr/local/bin/postern-panel\n", at+60))

	o, err := recoverAt(dir, "v0.4.0", "").recover()
	if err != nil || o.Kind != OutcomeRolledBack || !o.Restored || o.Failed == "" {
		t.Fatalf("recover: %+v %v", o, err)
	}
	_ = hold.Close()
	for _, s := range []string{"", "-wal", "-shm"} {
		if !exists(filepath.Join(o.Failed, DatabaseFile+s)) {
			t.Errorf("%s was not moved to %s", DatabaseFile+s, o.Failed)
		}
	}
	if !strings.HasPrefix(filepath.Base(o.Failed), "failed-v0.5.0-") || filepath.Dir(o.Failed) != filepath.Join(dir, "backups") {
		t.Errorf("failed dir %s", o.Failed)
	}
	fi, err := os.Stat(filepath.Join(dir, DatabaseFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the restored database: %v %v", fi, err)
	}
	if newer, err := store.NewerSchema(filepath.Join(dir, DatabaseFile)); err != nil || newer {
		t.Errorf("the restored database is newer: %v %v", newer, err)
	}
	for _, p := range []string{journalFile, rollbackFile} {
		if exists(filepath.Join(dir, p)) {
			t.Errorf("%s is left", p)
		}
	}
	if !exists(snapshot) {
		t.Error("the snapshot itself is kept")
	}
	db, err := store.Open(filepath.Join(dir, DatabaseFile))
	if err != nil {
		t.Fatalf("the restored database does not open: %v", err)
	}
	defer func() { _ = db.Close() }()
	var marker string
	if ok, err := db.GetSetting(context.Background(), "test.marker", &marker); !ok || err != nil || marker != "before" {
		t.Errorf("the restored data: %q %v %v", marker, ok, err)
	}
	Settle(context.Background(), db, dir, o, discard())
	e := assertEvent(t, db, EventUpdateRolledBack)
	if e.Details["failed_db"] != o.Failed || e.Details["restored_from"] != snapshot {
		t.Errorf("event details %v", e.Details)
	}
}

func TestRecoverRollbackWithoutANewerSchemaKeepsTheDatabase(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	at := time.Now().Unix()
	if err := writeJSON(filepath.Join(dir, journalFile), journal{From: "v0.4.0", To: "v0.5.0", Backup: "/nowhere.bak", At: at}); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, rollbackFile), fmt.Sprintf("%d postern-panel-v0.5.0 postern-panel-v0.4.0", at))
	o, err := recoverAt(dir, "v0.4.0", "").recover()
	if err != nil || o.Kind != OutcomeRolledBack || o.Restored {
		t.Fatalf("recover: %+v %v", o, err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "backups"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "failed-") {
			t.Errorf("the database was moved to %s", e.Name())
		}
	}
	if !exists(filepath.Join(dir, DatabaseFile)) {
		t.Error("the database is gone")
	}
}

func TestRecoverIgnoresAStaleRollbackRecord(t *testing.T) {
	dir := t.TempDir()
	snapshot, hold := newerDB(t, dir)
	at := time.Now().Unix()
	if err := writeJSON(filepath.Join(dir, journalFile), journal{From: "v0.4.0", To: "v0.5.0", Backup: snapshot, At: at}); err != nil {
		t.Fatal(err)
	}
	// A rollback of an earlier attempt, before this journal.
	writeFile(t, filepath.Join(dir, rollbackFile), fmt.Sprintf("%d postern-panel-v0.5.0 postern-panel-v0.4.0", at-1))
	o, err := recoverAt(dir, "v0.4.0", "").recover()
	if err != nil || o.Kind == OutcomeRolledBack || o.Restored {
		t.Fatalf("recover: %+v %v", o, err)
	}
	_ = hold.Close()
	if !exists(filepath.Join(dir, rollbackFile)) {
		t.Error("the stale record was removed")
	}
	if newer, _ := store.NewerSchema(filepath.Join(dir, DatabaseFile)); !newer {
		t.Error("the database was replaced")
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "backups")); len(entries) != 1 {
		t.Errorf("backups: %v", entries) // the snapshot alone
	}
}

// imageFixture is a data directory whose bin/current points at a self-updated
// v1.0.0-rc6, and an image binary: a script whose `version` prints out (exits
// 1 when out is "").
type imageFixture struct {
	dir, bin, image string
	logs            *strings.Builder
}

func newImageFixture(t *testing.T, out, previous string) imageFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake image binary is a shell script")
	}
	dir := t.TempDir()
	f := imageFixture{dir: dir, bin: filepath.Join(dir, "bin"), image: filepath.Join(dir, "image", "postern-panel"), logs: &strings.Builder{}}
	script := "#!/bin/sh\nexit 1\n"
	if out != "" {
		script = "#!/bin/sh\n[ \"$1\" = version ] || exit 2\nprintf '%s\\n' '" + out + "'\n"
	}
	writeFile(t, f.image, script)
	if err := os.Chmod(f.image, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.bin, "postern-panel-v1.0.0-rc6"), "x")
	if previous == "" {
		previous = f.image
	}
	for name, target := range map[string]string{"current": "postern-panel-v1.0.0-rc6", "previous": previous} {
		if err := os.Symlink(target, filepath.Join(f.bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// recoverer is the start of version, running exe.
func (f imageFixture) recoverer(version, exe string) recoverer {
	return recoverer{dataDir: f.dir, version: version, log: slog.New(slog.NewTextHandler(f.logs, nil)),
		exe: func() (string, error) { return exe, nil }, run: runBinary, imageBin: f.image, now: time.Now}
}

func (f imageFixture) selfUpdated() string { return filepath.Join(f.bin, "postern-panel-v1.0.0-rc6") }

// A self-updated binary steps aside for a newer image (prereleases compared
// as versions); an older, equal or unreadable image, or a panel that runs the
// image binary itself, changes nothing.
func TestRecoverANewerImageWins(t *testing.T) {
	for _, tc := range []struct {
		name, out, previous string
		exe                 string // "" is the self-updated binary; "image" the image binary
		restart             bool
		previousLeft        bool
		warn                string
	}{
		{name: "newer prerelease", out: "v1.0.0-rc7 (abc, 2026-10-12)", restart: true,
			warn: "the image carries v1.0.0-rc7, newer than the self-updated v1.0.0-rc6: going back to the image binary"},
		{name: "newer release", out: "v1.0.0 (abc, 2026-10-12)", restart: true},
		{name: "newer, previous is another version", out: "v1.0.0-rc7 (abc, d)", previous: "postern-panel-v1.0.0-rc5",
			restart: true, previousLeft: true},
		{name: "older", out: "v1.0.0-rc5 (abc, d)", previousLeft: true},
		{name: "equal", out: "v1.0.0-rc6 (abc, d)", previousLeft: true},
		{name: "unreadable", out: "", previousLeft: true, warn: "cannot read the version of the image binary"},
		{name: "not a version", out: "garbage", previousLeft: true, warn: "cannot read the version of the image binary"},
		{name: "runs the image itself", out: "v1.0.0-rc7 (abc, d)", exe: "image", previousLeft: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newImageFixture(t, tc.out, tc.previous)
			if err := writeJSON(filepath.Join(f.dir, journalFile), journal{From: "v1.0.0-rc5", To: "v1.0.0-rc6", At: 1}); err != nil {
				t.Fatal(err)
			}
			exe := f.selfUpdated()
			if tc.exe == "image" {
				exe = f.image
			}
			_, err := f.recoverer("v1.0.0-rc6", exe).recover()
			if tc.restart != errors.Is(err, ErrRestart) || (!tc.restart && err != nil) {
				t.Fatalf("recover: %v, want restart %v", err, tc.restart)
			}
			if got := exists(filepath.Join(f.bin, "current")); got == tc.restart {
				t.Errorf("bin/current left: %v", got)
			}
			if got := exists(filepath.Join(f.bin, "previous")); got != tc.previousLeft {
				t.Errorf("bin/previous left: %v, want %v", got, tc.previousLeft)
			}
			if !exists(f.selfUpdated()) {
				t.Error("the version file was removed")
			}
			if got := exists(filepath.Join(f.dir, imageNoteFile)); got != tc.restart {
				t.Errorf("note written: %v", got)
			}
			if tc.warn != "" && !strings.Contains(f.logs.String(), "level=WARN msg=\""+tc.warn) {
				t.Errorf("log %q, want a warning %q", f.logs.String(), tc.warn)
			}
		})
	}
}

// The image binary that runs next finds the note and records that the image
// won; Settle removes the note.
func TestRecoverRecordsThatTheImageWon(t *testing.T) {
	f := newImageFixture(t, "v1.0.0-rc7 (abc, d)", "")
	if _, err := f.recoverer("v1.0.0-rc6", f.selfUpdated()).recover(); !errors.Is(err, ErrRestart) {
		t.Fatalf("recover: %v", err)
	}
	o, err := f.recoverer("v1.0.0-rc7", f.image).recover()
	if err != nil || o.Kind != OutcomeImageNewer || o.From != "v1.0.0-rc6" || o.To != "v1.0.0-rc7" {
		t.Fatalf("recover: %+v %v", o, err)
	}
	db, err := store.Open(filepath.Join(f.dir, DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	Settle(ctx, db, f.dir, o, discard())
	if exists(filepath.Join(f.dir, imageNoteFile)) {
		t.Error("Settle left the note")
	}
	assertEvent(t, db, EventImageNewer)
	if last, err := LastUpdate(ctx, db); err != nil || !strings.Contains(last, "went back to the image v1.0.0-rc7 from the self-updated v1.0.0-rc6") {
		t.Errorf("LastUpdate %q %v", last, err)
	}
	if o, err := f.recoverer("v1.0.0-rc7", f.image).recover(); err != nil || o.Kind != OutcomeNone {
		t.Errorf("the next start: %+v %v", o, err)
	}
}

// A note left by a step-aside that failed names an image that does not run:
// it is dropped, and no event says that the image won.
func TestRecoverDropsANoteOfAnotherImage(t *testing.T) {
	f := newImageFixture(t, "v1.0.0-rc7 (abc, d)", "")
	if err := os.MkdirAll(filepath.Dir(filepath.Join(f.dir, imageNoteFile)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, imageNoteFile), []byte("1 v1.0.0-rc5 v1.0.0-rc7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := f.recoverer("v1.0.0-rc6", f.image).recover()
	if err != nil || o.Kind != OutcomeNone {
		t.Errorf("recover: %+v %v", o, err)
	}
	if exists(filepath.Join(f.dir, imageNoteFile)) {
		t.Error("the note of another image was kept")
	}
}

func TestRecoverDropsAnAbandonedJournal(t *testing.T) {
	dir := t.TempDir()
	if err := writeJSON(filepath.Join(dir, journalFile), journal{From: "v0.4.0", To: "v0.5.0", At: 1}); err != nil {
		t.Fatal(err)
	}
	o, err := recoverAt(dir, "v0.4.0", "").recover()
	if err != nil || o.Kind != OutcomeAbandoned || exists(filepath.Join(dir, journalFile)) {
		t.Fatalf("recover: %+v %v", o, err)
	}
	// One that is installed and not run yet stays.
	if err := writeJSON(filepath.Join(dir, journalFile), journal{From: "v0.4.0", To: "v0.5.0", At: 1}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("postern-panel-v0.5.0", filepath.Join(dir, "bin", "current")); err != nil {
		t.Fatal(err)
	}
	if o, err := recoverAt(dir, "v0.4.0", "").recover(); err != nil || o.Kind != OutcomeNone || !exists(filepath.Join(dir, journalFile)) {
		t.Fatalf("pending: %+v %v", o, err)
	}
}

// A restore cut short after any of its steps never leaves the data directory
// without a database, and the next start finishes it.
func TestRecoverRestoreConvergesAfterACrashAtEachStep(t *testing.T) {
	for _, step := range []string{stepLinked, stepJournaled, stepWALRemoved, stepSwapped} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			snapshot, hold := newerDB(t, dir)
			at := time.Now().Unix() - 100
			if err := writeJSON(filepath.Join(dir, journalFile), journal{From: "v0.4.0", To: "v0.5.0", Backup: snapshot, At: at}); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(dir, rollbackFile), fmt.Sprintf("%d postern-panel-v0.5.0 postern-panel-v0.4.0", at+1))
			crash := errors.New("crash at " + step)
			r := recoverAt(dir, "v0.4.0", "")
			r.fail = func(s string) error {
				if s == step {
					return crash
				}
				return nil
			}
			if _, err := r.recover(); !errors.Is(err, crash) {
				t.Fatalf("recover: %v, want the crash", err)
			}
			if !exists(filepath.Join(dir, DatabaseFile)) {
				t.Fatal("no postern.db after the crash")
			}
			for _, p := range []string{journalFile, rollbackFile} {
				if !exists(filepath.Join(dir, p)) {
					t.Fatalf("%s is gone before the restore was done", p)
				}
			}
			_ = hold.Close()

			r.fail = nil
			o, err := r.recover()
			if err != nil || o.Kind != OutcomeRolledBack || !o.Restored || o.Failed == "" {
				t.Fatalf("the next start: %+v %v", o, err)
			}
			if newer, err := store.NewerSchema(filepath.Join(dir, DatabaseFile)); err != nil || newer {
				t.Errorf("postern.db is not the snapshot: newer %v %v", newer, err)
			}
			if newer, err := store.NewerSchema(filepath.Join(o.Failed, DatabaseFile)); err != nil || !newer {
				t.Errorf("the failed database is not kept whole: newer %v %v", newer, err)
			}
			for _, p := range []string{journalFile, rollbackFile} {
				if exists(filepath.Join(dir, p)) {
					t.Errorf("%s is left", p)
				}
			}
			db, err := store.Open(filepath.Join(dir, DatabaseFile))
			if err != nil {
				t.Fatalf("the restored database does not open: %v", err)
			}
			defer func() { _ = db.Close() }()
			var marker string
			if ok, err := db.GetSetting(context.Background(), "test.marker", &marker); !ok || err != nil || marker != "before" {
				t.Errorf("the restored data: %q %v %v", marker, ok, err)
			}
		})
	}
}
