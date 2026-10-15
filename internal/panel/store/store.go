// Package store is the database of the panel: SQLite, and a thin layer of
// repositories over database/sql.
//
// # Conventions
//
// Ids are ULIDs from internal/ids. A Create method gives a record an id when it
// has none, and a creation time when it has none, so a caller that needs the id
// beforehand, for example to issue a certificate that names it, makes one with
// ids.New and sets it.
//
// Times are kept as Unix seconds. A time that is stored comes back in UTC and
// without the fraction of a second, and the repositories put that value back
// into the record they are given, so after a successful call the record equals
// what a read returns. A record is only changed by a call that succeeds.
//
// Optional values are nil or the empty string. A JSON column is a typed field,
// and an empty list or map reads back as nil.
//
// Values that end in Enc are sealed by internal/seal before they get here. The
// store keeps the bytes and does not know the key.
//
// Errors that callers can tell apart are [ErrNotFound], when a row does not
// exist or a write refers to a row that does not exist, and [ErrConflict], when
// a unique value is taken or a delete is refused because other rows still refer
// to the row. Both wrap the error of SQLite.
//
// # Concurrency
//
// A DB is safe for concurrent use. The database is in WAL mode, so readers do
// not block the writer, and a writer that finds the database locked waits up to
// five seconds. Transactions start with BEGIN IMMEDIATE, which takes the write
// lock at once instead of failing when it is upgraded later.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sqlite "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/urbnywrt/postern/internal/release"
)

var (
	// ErrNotFound is returned when a row that was asked for does not exist, and
	// when a write refers to a row that does not exist: a session of an unknown
	// admin, or a proxy on a listener of another node.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict is returned when a write collides with the data that is
	// there: a unique value, such as a user name, is taken, or a delete is
	// refused because other rows still refer to the row, such as the proxies of
	// a listener.
	ErrConflict = errors.New("store: conflict")
)

// The result codes of SQLite that this package tells apart. The first is a
// primary code, the others are extended ones.
const (
	sqliteBusy                 = 5    // SQLITE_BUSY
	sqliteConstraintForeignKey = 787  // SQLITE_CONSTRAINT_FOREIGNKEY
	sqliteConstraintPrimaryKey = 1555 // SQLITE_CONSTRAINT_PRIMARYKEY
	sqliteConstraintTrigger    = 1811 // what ON DELETE RESTRICT reports
	sqliteConstraintUnique     = 2067 // SQLITE_CONSTRAINT_UNIQUE
)

// fkMeaning is what a foreign-key violation means for the statement that raised
// it. SQLite does not say which of the two it is.
type fkMeaning int

const (
	// fkMissing: an insert or an update refers to a row that does not exist.
	fkMissing fkMeaning = iota
	// fkInUse: a delete would leave rows that still refer to the row.
	fkInUse
)

// mapErr turns the constraint errors of SQLite that callers care about into
// ErrConflict and ErrNotFound. Other errors, including the violation of a CHECK
// or NOT NULL constraint, which is a bug in the caller, pass through.
func mapErr(err error, fk fkMeaning) error {
	var se *sqlite.Error
	if err == nil || !errors.As(err, &se) {
		return err
	}
	switch se.Code() {
	case sqliteConstraintUnique, sqliteConstraintPrimaryKey, sqliteConstraintTrigger:
		return fmt.Errorf("%w: %w", ErrConflict, err)
	case sqliteConstraintForeignKey:
		if fk == fkInUse {
			return fmt.Errorf("%w: %w", ErrConflict, err)
		}
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return err
}

// notFound is the error for a row that is not there.
func notFound(what string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, what)
}

// queryNotFound turns the error of a query for one row into ErrNotFound when
// there was no such row.
func queryNotFound(err error, what string) error {
	if errors.Is(err, sql.ErrNoRows) {
		return notFound(what)
	}
	return err
}

// dbtx is what *sql.DB and *sql.Tx have in common.
type dbtx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// DB is the database of the panel.
type DB struct {
	sql  *sql.DB
	path string
	now  func() time.Time // the clock, replaced by tests

	// wal serializes the checkpoints that empty the write-ahead log after
	// client addresses were deleted (scrubWAL), which run on a connection of
	// their own (conn), and dirty says that the last one could not, so that
	// the log may still hold them.
	wal struct {
		sync.Mutex
		conn  *sql.DB
		dirty bool
	}
	// walWait is how long such a checkpoint waits for the readers of the log,
	// and for a writer. New writers wait for the checkpoint meanwhile, so it
	// is short: a checkpoint that cannot finish is tried again later.
	walWait time.Duration
	// steps is how RollupStats and PruneStats share the write lock, which they
	// take a step at a time (see stepTx).
	steps struct {
		// pause is how long they leave the lock free after each transaction:
		// SQLite does not queue writers, and one that waits for the lock
		// tries again every 100 ms at most, so it only gets the lock in a gap
		// at least that long.
		pause time.Duration
		// slow is how long a transaction may hold the lock before the next
		// step is halved; one of less than half of that doubles it again.
		slow time.Duration
		// Hooks of the tests, nil otherwise: inTx is called in each
		// transaction with what it works on, onPause at each pause.
		inTx    func(what string, from, to int64)
		onPause func()
	}
}

// The defaults of DB.steps.
const (
	defaultStepPause = 150 * time.Millisecond
	defaultSlowStep  = time.Second
)

// defaultWALWait is walWait outside of tests.
const defaultWALWait = time.Second

// maxConns is the size of the connection pool. WAL allows any number of readers
// next to one writer.
const maxConns = 8

//go:embed migrations/*.sql
var embeddedFS embed.FS

// embeddedMigrations is the directory of migrations that is built in.
func embeddedMigrations() fs.FS {
	sub, err := fs.Sub(embeddedFS, "migrations")
	if err != nil {
		panic("store: " + err.Error()) // cannot happen, the directory is embedded above
	}
	return sub
}

// Open opens the database in the file at path, creating the file, and its
// directory, if they do not exist. It sets the connection up (WAL, foreign keys
// on, a busy timeout of 5 seconds) and applies the migrations that the database
// has not seen yet, all in one transaction. Then it empties the write-ahead
// log, which a crash may have left with deleted client addresses in it; and a
// backup that a crash cut short may have left its first copy, which holds them
// too, in backups/, which it removes first.
//
// Before it applies a migration to a database that already holds something, it
// writes a copy of the database to backups/<name>.<unix time>.bak in the
// directory of the database, and it does not touch the database if it cannot.
// It refuses a database that a newer version has migrated further, and one that
// holds a migration under another name than this version gives that number, as
// happens when migration files are renumbered or renamed: nothing is changed.
func Open(path string) (*DB, error) {
	return open(path, embeddedMigrations(), monotonic(time.Now))
}

// monotonic returns a clock that never goes back: the wall time of clock, or
// the last time that it returned while the wall clock is behind it, as when a
// time sync steps the clock of the host back. Rows are kept in the order in
// which they were made by their creation times (and ids.New keeps its ids in
// that order the same way), so a clock that went back would list a row before
// one that was made earlier.
//
// The wall times are compared: a time of time.Now carries a reading of the
// monotonic clock as well, which Before would compare instead, and which does
// not see the wall clock step.
func monotonic(clock func() time.Time) func() time.Time {
	var (
		mu   sync.Mutex
		last time.Time
	)
	return func() time.Time {
		t := clock().Round(0) // the wall time alone
		mu.Lock()
		defer mu.Unlock()
		if t.Before(last) {
			return last
		}
		last = t
		return t
	}
}

// open is Open with the migrations and the clock as parameters, so that tests
// can use their own.
func open(path string, migrations fs.FS, now func() time.Time) (*DB, error) {
	if path == "" {
		return nil, errors.New("store: no database path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("store: create data directory: %w", err)
	}
	// The database holds password hashes and sealed secrets. SQLite would
	// create the file readable by everyone that the umask allows, so create it
	// first. A file that exists keeps the mode it has.
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	sqlDB, err := sql.Open("sqlite", dsn(abs))
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	sqlDB.SetMaxOpenConns(maxConns)
	sqlDB.SetMaxIdleConns(maxConns)

	ctx := context.Background()
	// The first connection puts a new file in WAL mode.
	if err := pingUntilFree(ctx, sqlDB); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("store: open %s: %w", filepath.Base(abs), err)
	}
	db := &DB{sql: sqlDB, path: abs, now: now, walWait: defaultWALWait}
	db.steps.pause, db.steps.slow = defaultStepPause, defaultSlowStep
	removeLeftovers(filepath.Join(filepath.Dir(abs), "backups"))
	if err := db.migrate(ctx, migrations); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	// The connection of the checkpoints of scrubWAL, which set a busy timeout
	// of their own.
	walConn, err := sql.Open("sqlite", fileURI(abs, url.Values{}))
	if err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	walConn.SetMaxOpenConns(1)
	db.wal.conn = walConn
	// A crash after a checkpoint that could not finish leaves deleted client
	// addresses in the log, and nothing else might empty it.
	if err := db.scrubWAL(ctx, true); err != nil {
		slog.Warn("store: the write-ahead log could not be emptied at start; the next prune of the statistics tries again", "err", err)
	}
	return db, nil
}

// openTimeout is the longest that pingUntilFree waits. It is the busy timeout.
const openTimeout = 5 * time.Second

// pingUntilFree connects, and tries again while the database is busy. The busy
// timeout does not help the first connection to a new file: switching it to WAL
// mode needs the file to itself, and SQLite gives up at once when another
// connection, such as that of a second process that was started at the same
// time, is doing the same.
func pingUntilFree(ctx context.Context, db *sql.DB) error {
	deadline := time.Now().Add(openTimeout)
	for delay := 5 * time.Millisecond; ; delay = min(delay*2, 100*time.Millisecond) {
		err := db.PingContext(ctx)
		if err == nil || !isBusy(err) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

// isBusy reports whether err is SQLITE_BUSY, in any of its forms.
func isBusy(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code()&0xff == sqliteBusy
}

// dsn is the connection string for the file at path: a SQLite URI, so that
// characters such as ? and # in the path mean what they say.
//
//   - WAL: readers do not block the writer.
//   - foreign_keys: SQLite ignores foreign keys unless a connection asks.
//   - busy_timeout: a writer that finds the database locked waits.
//   - synchronous=FULL: a commit survives a crash of the operating system. The
//     generation counter of a node must not go back, or the node would hold a
//     newer state than the panel believes it has sent; the writes are few, so
//     the cost does not matter.
//   - txlock=immediate: a transaction takes the write lock when it starts.
//   - secure_delete: what is deleted is overwritten with zeros, instead of
//     staying in the free space of the file. Client addresses are kept for
//     days, and deleted as soon as the IP policy says so (spec §8.6); they must
//     not stay on the disk. It is a setting of the connection, so it is set
//     here, where no connection of the pool can do without it.
func dsn(path string) string {
	q := url.Values{}
	q.Set("_busy_timeout", "5000")
	q.Set("_foreign_keys", "1")
	q.Set("_journal_mode", "WAL")
	q.Set("_synchronous", "FULL")
	q.Set("_txlock", "immediate")
	q.Set("_pragma", "secure_delete(on)")
	return fileURI(path, q)
}

// fileURI is the SQLite URI of the file at path with the parameters q.
func fileURI(path string, q url.Values) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // a drive letter: file:///C:/dir/file
	}
	u := url.URL{Scheme: "file", Path: p, RawQuery: q.Encode()}
	return u.String()
}

// Close closes the database.
func (db *DB) Close() error {
	return errors.Join(db.wal.conn.Close(), db.sql.Close())
}

// withTx runs fn in a transaction and commits it, or rolls it back when fn
// returns an error or panics.
func (db *DB) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// A migration is one file of the migrations directory, <number>_<name>.sql.
type migration struct {
	version int
	name    string
	sql     string
}

var migrationFile = regexp.MustCompile(`^([0-9]+)_(.+)\.sql$`)

// loadMigrations reads the migrations in fsys in the order of their numbers.
// Files that do not end in .sql are ignored; a .sql file that is not named
// <number>_<name>.sql, or a number that is used twice, is an error, so that a
// typo does not make a migration silently disappear.
func loadMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}
	var migs []migration
	names := map[int]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		m := migrationFile.FindStringSubmatch(name)
		if m == nil {
			return nil, fmt.Errorf("store: migration file %q is not named <number>_<name>.sql", name)
		}
		version, err := strconv.Atoi(m[1])
		if err != nil || version < 1 {
			return nil, fmt.Errorf("store: migration file %q: the number must be 1 or more", name)
		}
		if other, dup := names[version]; dup {
			return nil, fmt.Errorf("store: migration number %d is used twice (%s and %s)", version, other, name)
		}
		names[version] = name
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("store: read migration %s: %w", name, err)
		}
		migs = append(migs, migration{version: version, name: m[2], sql: string(body)})
	}
	if len(migs) == 0 {
		return nil, errors.New("store: no migrations found")
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })
	return migs, nil
}

const createMigrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
  version    INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  applied_at INTEGER NOT NULL
) STRICT`

// migrate applies the migrations that the database does not have yet.
func (db *DB) migrate(ctx context.Context, fsys fs.FS) error {
	migs, err := loadMigrations(fsys)
	if err != nil {
		return err
	}
	// Whether there is anything to lose is read before what has been applied. If
	// another process migrates a new file while this one looks, then either the
	// file is still empty here, or it is already migrated by the time that the
	// applied versions are read; in neither case is there a backup to make.
	hasData, err := hasTables(ctx, db.sql)
	if err != nil {
		return err
	}
	applied, err := appliedMigrations(ctx, db.sql)
	if err != nil {
		return err
	}
	if err := checkApplied(applied, migs); err != nil {
		return err
	}
	if err := checkOrder(applied, migs); err != nil {
		return err
	}
	var pending []migration
	for _, m := range migs {
		if _, done := applied[m.version]; !done {
			pending = append(pending, m)
		}
	}
	if len(pending) == 0 {
		return nil
	}

	// A database that holds something is copied before it is changed; one that
	// is empty has nothing to lose.
	if hasData {
		dst, err := db.backup(ctx, "")
		if err != nil {
			return fmt.Errorf("store: back up the database before migrating it: %w", err)
		}
		slog.Info("store: database copied before migrating", "backup", dst)
	}

	return db.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, createMigrationsTable); err != nil {
			return fmt.Errorf("store: create schema_migrations: %w", err)
		}
		// Look again now that this transaction holds the write lock: another
		// process may have applied some while this one was waiting, and it may be
		// a version whose migrations are not these.
		applied, err := appliedMigrations(ctx, tx)
		if err != nil {
			return err
		}
		if err := checkApplied(applied, migs); err != nil {
			return err
		}
		if err := checkOrder(applied, migs); err != nil {
			return err
		}
		for _, m := range pending {
			if _, done := applied[m.version]; done {
				continue
			}
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return fmt.Errorf("store: migration %04d %s: %w", m.version, m.name, err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
				m.version, m.name, db.now().Unix()); err != nil {
				return fmt.Errorf("store: record migration %04d: %w", m.version, err)
			}
			slog.Info("store: applied migration", "version", m.version, "name", m.name)
		}
		return nil
	})
}

// appliedMigrations returns the migrations in schema_migrations, the name of each
// by its number, none if the table does not exist yet.
func appliedMigrations(ctx context.Context, q dbtx) (map[int]string, error) {
	var tables int
	if err := q.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&tables); err != nil {
		return nil, fmt.Errorf("store: look for schema_migrations: %w", err)
	}
	applied := map[int]string{}
	if tables == 0 {
		return applied, nil
	}
	rows, err := q.QueryContext(ctx, `SELECT version, name FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: read schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			v    int
			name string
		)
		if err := rows.Scan(&v, &name); err != nil {
			return nil, fmt.Errorf("store: read schema_migrations: %w", err)
		}
		applied[v] = name
	}
	return applied, rows.Err()
}

// checkApplied refuses a database whose applied migrations are not all the ones
// of this version, by number and by name. A number that this version does not
// know was applied by a newer version, which an older one must not use. A number
// that it knows under another name means that the migration files were
// renumbered or renamed after the database was migrated: the migration that this
// version takes for done is not the one that was run, and would never be. The
// lowest number that is wrong is the one reported.
func checkApplied(applied map[int]string, migs []migration) error {
	ours := make(map[int]string, len(migs))
	for _, m := range migs {
		ours[m.version] = m.name
	}
	versions := make([]int, 0, len(applied))
	for v := range applied {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	for _, v := range versions {
		name, known := ours[v]
		switch {
		case !known:
			return fmt.Errorf("store: the database has migration %d, which this version does not know: "+
				"it was migrated by a newer version, and an older one must not use it", v)
		case name != applied[v]:
			return fmt.Errorf("store: the database has migration %d as %q, but this version has it as %q: "+
				"the migration files were renumbered or renamed after the database was migrated, "+
				"and this version cannot tell what the database holds; start the version that migrated it",
				v, applied[v], name)
		}
	}
	return nil
}

// checkOrder refuses a migration that is not applied while one with a higher
// number is: it was added after the database moved past its number, and was
// written for a schema without the migrations above it, which it would now run
// after. A migration with no statement in it, only comments, merely reserves
// its number, and may be applied anywhere.
func checkOrder(applied map[int]string, migs []migration) error {
	highest := 0
	for v := range applied {
		highest = max(highest, v)
	}
	for _, m := range migs {
		if _, done := applied[m.version]; done || m.version > highest || isEmptySQL(m.sql) {
			continue
		}
		return fmt.Errorf("store: migration %04d %s is not applied, but the database already has migration %04d: "+
			"a new migration must be numbered above every one that is applied; renumber it above %04d",
			m.version, m.name, highest, highest)
	}
	return nil
}

// isEmptySQL reports whether sql holds nothing but blank lines and comments
// that begin with "--".
func isEmptySQL(sql string) bool {
	for line := range strings.Lines(sql) {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "--") {
			return false
		}
	}
	return true
}

// hasTables reports whether the database holds any table of its own.
func hasTables(ctx context.Context, q dbtx) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND substr(name, 1, 7) <> 'sqlite_'`).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: look at the schema: %w", err)
	}
	return n > 0, nil
}

// backup writes a copy of the database to backups/<name>.<unix time>.bak next to
// it and returns the path. The copy is made by SQLite (VACUUM INTO), which gives
// a consistent snapshot also while the write-ahead log holds changes that are
// not in the file yet. A backup of the same second is never overwritten: the
// number counts up to a name that is free.
//
// A backup is kept without client addresses: it stays for as long as the
// operator keeps it, and the addresses only for days, or not at all once the IP
// policy is no longer full (spec §8.6). So the database is copied to
// <backup>.tmp first, the addresses are deleted from that copy, and the backup
// is a copy of it in turn (scrubCopy), which has no deleted row in its free
// pages; the first copy is removed. All of it is written to the volume of the
// database: a VACUUM in place would build its copy in the temporary directory,
// which may be small, or in memory. A backup that cannot be made is removed,
// and is an error.
func (db *DB) backup(ctx context.Context, label string) (string, error) {
	dir := filepath.Join(filepath.Dir(db.path), "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := filepath.Base(db.path)
	if label != "" {
		name += "." + label
	}
	for ts := db.now().Unix(); ; ts++ {
		dst := filepath.Join(dir, fmt.Sprintf("%s.%d.bak", name, ts))
		// The files are made here, with their own mode, and SQLite fills them
		// in; it accepts a target that exists if it is empty.
		err := createPrivate(dst)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		tmp := dst + ".tmp"
		removeBackup(tmp) // nothing of this name is ours to keep
		if err := createPrivate(tmp); err != nil {
			removeBackup(dst)
			return "", err
		}
		err = func() error {
			if _, err := db.sql.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
				return err
			}
			if err := scrubCopy(ctx, tmp, dst); err != nil {
				return fmt.Errorf("delete the client addresses from the copy: %w", err)
			}
			return nil
		}()
		removeBackup(tmp)
		if err != nil {
			removeBackup(dst)
			return "", err
		}
		return dst, nil
	}
}

// Backup writes a copy of the database, as the backup before a migration is
// made (VACUUM INTO, without the client addresses), to
// backups/<name>.<label>.<unix time>.bak next to it and returns the path. The
// label names what the copy is for, such as "pre-v0.5.0" before an update of
// the panel; it is 1 to 64 characters of [0-9A-Za-z._+-] that start with a
// letter or a digit (release.ValidVersion), so that it is part of a file name
// and nothing else.
func (db *DB) Backup(ctx context.Context, label string) (string, error) {
	if !release.ValidVersion(label) {
		return "", fmt.Errorf("store: backup label %q: it must be 1 to 64 of [0-9A-Za-z._+-], the first a letter or a digit", label)
	}
	dst, err := db.backup(ctx, label)
	if err != nil {
		return "", fmt.Errorf("store: back up the database: %w", err)
	}
	return dst, nil
}

// NewerSchema reports whether the database at path holds a migration that
// this version does not know, which a newer version applied: Open refuses
// such a database. It opens the file read-only and changes nothing; a file
// that is not there, or has no migrations yet, is not newer.
func NewerSchema(path string) (bool, error) {
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	migs, err := loadMigrations(embeddedMigrations())
	if err != nil {
		return false, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Set("_busy_timeout", "5000")
	sqlDB, err := sql.Open("sqlite", fileURI(abs, q))
	if err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	defer func() { _ = sqlDB.Close() }()
	sqlDB.SetMaxOpenConns(1)
	applied, err := appliedMigrations(context.Background(), sqlDB)
	if err != nil {
		return false, err
	}
	ours := make(map[int]bool, len(migs))
	for _, m := range migs {
		ours[m.version] = true
	}
	for v := range applied {
		if !ours[v] {
			return true, nil
		}
	}
	return false, nil
}

// createPrivate makes an empty file at path that only its owner can read, and
// fails if the file exists.
func createPrivate(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// scrubCopy deletes where client addresses were seen (the table ip_sightings,
// when it has one) from the database copy at src, and copies what is left to
// dst (VACUUM INTO), which then has no deleted row in its free pages either.
// A copy that is not there is an error, rather than an empty database: another
// Open may have taken it for what a crash left (removeLeftovers).
func scrubCopy(ctx context.Context, src, dst string) (err error) {
	q := url.Values{}
	q.Set("mode", "rw")
	q.Set("_busy_timeout", "5000")
	q.Set("_pragma", "secure_delete(on)")
	b, err := sql.Open("sqlite", fileURI(src, q))
	if err != nil {
		return err
	}
	defer func() {
		// Closing the last connection also removes the files that SQLite made
		// beside the copy.
		if cerr := b.Close(); err == nil {
			err = cerr
		}
	}()
	b.SetMaxOpenConns(1)
	var tables int
	if err := b.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'ip_sightings'`).Scan(&tables); err != nil {
		return err
	}
	if tables > 0 {
		if _, err := b.ExecContext(ctx, `DELETE FROM ip_sightings`); err != nil {
			return err
		}
	}
	_, err = b.ExecContext(ctx, `VACUUM INTO ?`, dst)
	return err
}

// removeBackup removes a copy, and what SQLite may have left beside it.
func removeBackup(path string) {
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
}

// removeLeftovers removes from dir the first copies of backups (<backup>.tmp)
// that a crash left, and what SQLite left beside them: they hold the client
// addresses that a backup is kept without.
func removeLeftovers(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // no backups yet
	}
	for _, e := range entries {
		name := e.Name()
		if !slices.ContainsFunc([]string{"", "-journal", "-wal", "-shm"}, func(side string) bool {
			return strings.HasSuffix(name, ".bak.tmp"+side)
		}) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("store: could not remove what a backup that was cut short left, which may hold client addresses",
				"file", path, "err", err)
		}
	}
}

// scrubWAL empties the write-ahead log into the database file when deleted says
// that rows were just deleted that must not stay on the disk, such as client
// addresses, or when an earlier call could not. secure_delete has overwritten
// the rows in the pages that the log holds; the checkpoint writes those pages
// over the old ones in the file and truncates the log, which still holds the
// rows as they were.
//
// The checkpoint runs on a connection of its own, which waits walWait for the
// readers of the log and for a writer; new writers wait for the checkpoint
// meanwhile. When it cannot finish, the call fails, and the next call tries
// again even if it deleted nothing.
func (db *DB) scrubWAL(ctx context.Context, deleted bool) error {
	db.wal.Lock()
	defer db.wal.Unlock()
	if !deleted && !db.wal.dirty {
		return nil
	}
	err := func() error {
		c, err := db.wal.conn.Conn(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		if _, err := c.ExecContext(ctx, `PRAGMA busy_timeout = `+strconv.FormatInt(db.walWait.Milliseconds(), 10)); err != nil {
			return err
		}
		var busy, frames, done int64
		if err := c.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &done); err != nil {
			return err
		}
		if busy != 0 {
			return errors.New("a reader or a writer is using the write-ahead log, which was not emptied")
		}
		return nil
	}()
	db.wal.dirty = err != nil
	return err
}
