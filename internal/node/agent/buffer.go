// Package agent is the node agent (postern-node agent): the NodeService that
// the panel calls over mTLS, the buffer of records that its Watch stream
// replays, the statistics it takes from the edge, the information GetInfo
// gathers about the host, and Run, which wires them to the reconciler.
package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	sqlite "modernc.org/sqlite"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

// Kinds of buffered records, the kind column of the events table.
const (
	kindState = "state"
	kindStats = "stats"
	kindEvent = "event"
	kindDiag  = "diagnostics"
)

const (
	// bufferRetention is how long records are kept (spec 5.8).
	bufferRetention = 7 * 24 * time.Hour
	// defaultMaxRows bounds the table whatever the age of its rows: a week
	// has some 10 000 minutes of statistics and a few thousand other records.
	defaultMaxRows = 1_000_000
	// scrubPage is how many records ScrubIPs reads at a time.
	scrubPage = 200
	// maxPageBytes bounds the records one page holds in memory: a minute of
	// statistics with many client addresses is some hundreds of kilobytes.
	maxPageBytes = 4 << 20
	// defaultMaxPayload bounds the payload of every record together: over
	// it, the oldest statistics lose their client addresses first, then the
	// oldest records go.
	defaultMaxPayload = 256 << 20
	// metaScrubbed is the meta key of how far ScrubIPsBefore went: the
	// sequence number of the last statistics record it has seen to.
	metaScrubbed = "ips_scrubbed_seq"
)

// SQLite result codes that mean the file is not a usable database.
const (
	sqliteCorrupt = 11 // SQLITE_CORRUPT
	sqliteNotADB  = 26 // SQLITE_NOTADB
)

var errBufferClosed = errors.New("agent: the record buffer is closed")

// bufferSchema is the layout of stats.db. seq is AUTOINCREMENT so that a
// number is never used again, also after the newest records are deleted.
const bufferSchema = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS events (
  seq     INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,
  kind    TEXT NOT NULL,
  payload BLOB NOT NULL
) STRICT;
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
`

// Buffer is the agent's buffer of records for the panel, the SQLite file
// data/stats.db: state reports, minutes of statistics and events, each a
// marshaled WatchResponse under a sequence number that only grows. The Watch
// stream replays it from the panel's cursor; records are kept for 7 days.
//
// The file belongs to one node: its id is kept in the meta table, and a file
// of another node is deleted on open, so that its records never reach the
// panel as records of this one. A new file numbers its records from the time
// it was made, in milliseconds, so that a file made again (lost, damaged,
// another node's) never repeats a number the panel has seen.
type Buffer struct {
	db      *sql.DB
	now     func() time.Time
	log     *slog.Logger
	maxRows int
	// maxPayload bounds SUM(length(payload)) (Maintain).
	maxPayload int64

	mu      sync.Mutex
	changed chan struct{} // closed and replaced by every Append
	closed  bool
}

// openBuffer opens the buffer at path for the node nodeID, creating it when
// it does not exist. A file that is not a database is set aside as
// <path>.corrupt-<unix time> and a new one is made.
func openBuffer(path, nodeID string, now func() time.Time, log *slog.Logger) (*Buffer, error) {
	b, err := openBufferFile(path, nodeID, now, log)
	if err == nil || !isCorrupt(err) {
		return b, err
	}
	aside := fmt.Sprintf("%s.corrupt-%d", path, now().Unix())
	log.Warn("agent: the record buffer is damaged; it is kept aside and a new one is made",
		"file", filepath.Base(aside), "err", err)
	if rerr := os.Rename(path, aside); rerr != nil {
		return nil, fmt.Errorf("agent: setting the damaged record buffer aside: %w", rerr)
	}
	removeSidecars(path)
	return openBufferFile(path, nodeID, now, log)
}

func openBufferFile(path, nodeID string, now func() time.Time, log *slog.Logger) (*Buffer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	// The file holds client addresses: create it private before SQLite does
	// (with the umask's mode), and tighten one that exists.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("agent: opening the record buffer: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}

	db, err := sql.Open("sqlite", bufferDSN(path))
	if err != nil {
		return nil, fmt.Errorf("agent: opening the record buffer: %w", err)
	}
	// One connection: writes are serialized anyway, and the records are
	// small; readers read a page and let go of it.
	db.SetMaxOpenConns(1)
	b := &Buffer{db: db, now: now, log: log, maxRows: defaultMaxRows, maxPayload: defaultMaxPayload, changed: make(chan struct{})}
	owner, err := b.setup(nodeID)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("agent: opening the record buffer: %w", err)
	}
	if owner == nodeID {
		return b, nil
	}
	// Another node's records: delete the file itself, so that nothing of
	// them (client addresses included) stays in its free pages.
	_ = db.Close()
	log.Info("agent: the record buffer belongs to another node; its records are deleted", "node", clipText(owner, 64))
	if err := os.Remove(path); err != nil {
		return nil, fmt.Errorf("agent: deleting the record buffer of another node: %w", err)
	}
	removeSidecars(path)
	return openBufferFile(path, nodeID, now, log)
}

// setup creates the tables and returns the node the file belongs to. A new
// file is made this node's, numbering its records after now in milliseconds.
func (b *Buffer) setup(nodeID string) (owner string, err error) {
	ctx := context.Background()
	if _, err := b.db.ExecContext(ctx, bufferSchema); err != nil {
		return "", err
	}
	err = b.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'node_id'`).Scan(&owner)
	if !errors.Is(err, sql.ErrNoRows) {
		return owner, err
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES ('node_id', ?)`, nodeID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sqlite_sequence (name, seq) SELECT 'events', ? WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'events')`,
		b.now().UnixMilli()); err != nil {
		return "", err
	}
	return nodeID, tx.Commit()
}

// bufferDSN is the connection string for the file at path. WAL lets the
// readers of a page and the writer of a record be; synchronous=NORMAL is
// durable enough for a buffer that the panel reads within minutes;
// secure_delete overwrites what is deleted or replaced (client addresses
// scrubbed from a record) instead of leaving it in the free pages.
func bufferDSN(path string) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	q := url.Values{}
	q.Set("_busy_timeout", "5000")
	q.Set("_journal_mode", "WAL")
	q.Set("_synchronous", "NORMAL")
	q.Set("_pragma", "secure_delete(on)")
	return (&url.URL{Scheme: "file", Path: p, RawQuery: q.Encode()}).String()
}

func removeSidecars(path string) {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		_ = os.Remove(path + suffix)
	}
}

// isCorrupt reports whether err says the file is not a usable database.
func isCorrupt(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case sqliteCorrupt, sqliteNotADB:
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "file is not a database") || strings.Contains(msg, "database disk image is malformed")
}

// recordKind is the kind of a record by its payload.
func recordKind(rec *nodev1.WatchResponse) (string, error) {
	switch rec.GetPayload().(type) {
	case *nodev1.WatchResponse_State:
		return kindState, nil
	case *nodev1.WatchResponse_Stats:
		return kindStats, nil
	case *nodev1.WatchResponse_Event:
		return kindEvent, nil
	case *nodev1.WatchResponse_Diagnostics:
		return kindDiag, nil
	}
	return "", errors.New("agent: a record without payload")
}

// Append buffers a record and returns its sequence number. The record's time
// is now unless it has one; the caller's record is not changed.
func (b *Buffer) Append(rec *nodev1.WatchResponse) (uint64, error) {
	kind, err := recordKind(rec)
	if err != nil {
		return 0, err
	}
	out := proto.Clone(rec).(*nodev1.WatchResponse)
	out.Seq = 0 // the row's key is the number
	if out.TsUnix == 0 {
		out.TsUnix = b.now().Unix()
	}
	payload, err := proto.Marshal(out)
	if err != nil {
		return 0, fmt.Errorf("agent: encoding a record: %w", err)
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, errBufferClosed
	}
	res, err := b.db.Exec(`INSERT INTO events (ts, kind, payload) VALUES (?, ?, ?)`, out.TsUnix, kind, payload)
	if err != nil {
		return 0, fmt.Errorf("agent: buffering a record: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("agent: buffering a record: %w", err)
	}
	close(b.changed)
	b.changed = make(chan struct{})
	return uint64(seq), nil
}

// Changed returns a channel that is closed by the next Append (or Close).
func (b *Buffer) Changed() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.changed
}

// After returns up to limit records with a sequence number above cursor, in
// order.
func (b *Buffer) After(cursor uint64, limit int) ([]*nodev1.WatchResponse, error) {
	recs, _, _, err := b.page(cursor, limit)
	return recs, err
}

// page is After that also returns the last number it read (cursor when it
// read nothing) and whether it stopped before the end: limit records, or
// maxPageBytes of them. A record that cannot be decoded is skipped, but its
// number still moves the cursor on.
func (b *Buffer) page(cursor uint64, limit int) (recs []*nodev1.WatchResponse, last uint64, full bool, err error) {
	last = cursor
	if cursor > math.MaxInt64 {
		return nil, last, false, nil
	}
	rows, err := b.db.Query(`SELECT seq, payload FROM events WHERE seq > ? ORDER BY seq LIMIT ?`, int64(cursor), limit)
	if err != nil {
		return nil, last, false, fmt.Errorf("agent: reading the record buffer: %w", err)
	}
	defer func() { _ = rows.Close() }()
	n, size := 0, 0
	for rows.Next() {
		if size >= maxPageBytes {
			full = true
			break
		}
		var seq int64
		var payload []byte
		if err := rows.Scan(&seq, &payload); err != nil {
			return nil, last, false, fmt.Errorf("agent: reading the record buffer: %w", err)
		}
		n++
		size += len(payload)
		last = uint64(seq)
		rec := &nodev1.WatchResponse{}
		if err := proto.Unmarshal(payload, rec); err != nil {
			b.log.Warn("agent: a buffered record cannot be read; it is skipped", "seq", seq, "err", err)
			continue
		}
		rec.Seq = uint64(seq)
		recs = append(recs, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, cursor, false, fmt.Errorf("agent: reading the record buffer: %w", err)
	}
	return recs, last, full || n == limit, nil
}

// LastSeq is the number of the newest record ever buffered, also when it has
// been pruned since; for a file without records, the number its records start
// after.
func (b *Buffer) LastSeq() (uint64, error) {
	var seq int64
	err := b.db.QueryRow(`SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'events'), 0)`).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("agent: reading the record buffer: %w", err)
	}
	return uint64(seq), nil
}

// Prune deletes the records older than the retention time, then the oldest
// ones over the row limit, and returns how many went.
func (b *Buffer) Prune() (int64, error) {
	res, err := b.db.Exec(`DELETE FROM events WHERE ts < ?`, b.now().Add(-bufferRetention).Unix())
	if err != nil {
		return 0, fmt.Errorf("agent: pruning the record buffer: %w", err)
	}
	old, _ := res.RowsAffected()
	res, err = b.db.Exec(`DELETE FROM events WHERE seq <= (SELECT seq FROM events ORDER BY seq DESC LIMIT 1 OFFSET ?)`, b.maxRows)
	if err != nil {
		return old, fmt.Errorf("agent: pruning the record buffer: %w", err)
	}
	over, _ := res.RowsAffected()
	return old + over, nil
}

// ScrubIPs removes the client addresses from the buffered statistics (the
// IP policy no longer allows them) and returns how many records it changed.
func (b *Buffer) ScrubIPs() (int, error) {
	changed := 0
	var last int64
	for {
		n, next, err := b.scrubPage(last, func(int64, int64) bool { return true })
		changed += n
		if err != nil {
			return changed, fmt.Errorf("agent: scrubbing the record buffer: %w", err)
		}
		if next == last {
			return changed, nil
		}
		last = next
	}
}

// ScrubIPsBefore removes the client addresses from the statistics records
// buffered before t and returns how many records it changed. It goes through
// the records in order and stops at the first one of t or later; the meta
// table remembers how far it went, so that the next call reads only newer
// records.
func (b *Buffer) ScrubIPsBefore(t time.Time) (int, error) {
	limit := t.Unix()
	changed := 0
	for {
		n, more, err := b.scrubOnward(func(ts, _ int64) bool { return ts < limit })
		changed += n
		if err != nil {
			return changed, fmt.Errorf("agent: scrubbing the record buffer: %w", err)
		}
		if !more {
			return changed, nil
		}
	}
}

// scrubOnward scrubs one page of statistics records after the resume point
// while take holds (scrubPage), and moves the resume point on. more says
// whether there may be more to do.
func (b *Buffer) scrubOnward(take func(ts, saved int64) bool) (changed int, more bool, err error) {
	from, err := b.scrubbedTo()
	if err != nil {
		return 0, false, err
	}
	changed, last, err := b.scrubPage(from, take)
	if last > from {
		if serr := b.setScrubbedTo(last); serr != nil && err == nil {
			err = serr
		}
	}
	return changed, last > from && err == nil, err
}

func (b *Buffer) scrubbedTo() (int64, error) {
	var v string
	err := b.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaScrubbed).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	seq, err := strconv.ParseInt(v, 10, 64)
	if err != nil || seq < 0 {
		return 0, nil // read again from the start
	}
	return seq, nil
}

func (b *Buffer) setScrubbedTo(seq int64) error {
	_, err := b.db.Exec(`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
		metaScrubbed, strconv.FormatInt(seq, 10))
	return err
}

// scrubPage goes through up to scrubPage statistics records after the
// number after, in order, while take(ts, saved) holds for the record's time
// and the bytes the page has saved so far, and removes their client
// addresses. It returns how many records it changed and the number of the
// last record it went through (after when none).
func (b *Buffer) scrubPage(after int64, take func(ts, saved int64) bool) (changed int, last int64, err error) {
	last = after
	type update struct {
		seq     int64
		payload []byte
	}
	var updates []update
	var saved int64
	rows, err := b.db.Query(`SELECT seq, ts, payload FROM events WHERE kind = ? AND seq > ? ORDER BY seq LIMIT ?`, kindStats, after, scrubPage)
	if err != nil {
		return 0, last, err
	}
	for rows.Next() {
		var seq, ts int64
		var payload []byte
		if err := rows.Scan(&seq, &ts, &payload); err != nil {
			_ = rows.Close()
			return 0, after, err
		}
		if !take(ts, saved) {
			break
		}
		last = seq
		rec := &nodev1.WatchResponse{}
		if proto.Unmarshal(payload, rec) != nil || len(rec.GetStats().GetIps()) == 0 {
			continue
		}
		rec.GetStats().Ips = nil
		clean, err := proto.Marshal(rec)
		if err != nil {
			continue
		}
		updates = append(updates, update{seq, clean})
		saved += int64(len(payload) - len(clean))
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return 0, after, err
	}
	for _, u := range updates {
		if _, err := b.db.Exec(`UPDATE events SET payload = ? WHERE seq = ?`, u.payload, u.seq); err != nil {
			return changed, after, err
		}
		changed++
	}
	return changed, last, nil
}

// checkpoint empties the write-ahead log into the database file, where
// secure_delete has overwritten what was deleted, so that it is gone from the
// disk as well.
func (b *Buffer) checkpoint() error {
	var busy, frames, done int
	if err := b.db.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &done); err != nil {
		return fmt.Errorf("agent: emptying the write-ahead log of the record buffer: %w", err)
	}
	if busy != 0 {
		return errors.New("agent: the write-ahead log of the record buffer is in use and was not emptied")
	}
	return nil
}

// maintenance is what one Maintain did.
type maintenance struct {
	pruned        int64 // records older than the retention or over the row limit
	scrubbed      int   // records whose client addresses were past the IP retention
	budgetScrubs  int   // records scrubbed to fit the payload budget
	budgetDeletes int64 // records deleted to fit it
}

// Maintain is the hourly care of the buffer: it prunes, removes the client
// addresses buffered more than ipRetention ago, then, while the payload of
// the records is over the budget, removes the client addresses of the oldest
// statistics, then deletes the oldest records; after any of that it empties
// the write-ahead log.
func (b *Buffer) Maintain(ipRetention time.Duration) (maintenance, error) {
	var m maintenance
	var err error
	if m.pruned, err = b.Prune(); err != nil {
		return m, err
	}
	if m.scrubbed, err = b.ScrubIPsBefore(b.now().Add(-ipRetention)); err != nil {
		return m, err
	}
	if m.budgetScrubs, m.budgetDeletes, err = b.fitBudget(); err != nil {
		return m, err
	}
	if m != (maintenance{}) {
		return m, b.checkpoint()
	}
	return m, nil
}

// fitBudget brings the payload of the records down to maxPayload.
func (b *Buffer) fitBudget() (scrubs int, deletes int64, err error) {
	total, err := b.payloadSize()
	if err != nil {
		return 0, 0, err
	}
	// The oldest statistics lose their client addresses first, as many as
	// it takes; the resume point of ScrubIPsBefore moves on with them.
	for total > b.maxPayload {
		over := total
		n, more, err := b.scrubOnward(func(_, saved int64) bool { return over-saved > b.maxPayload })
		scrubs += n
		if err != nil {
			return scrubs, 0, fmt.Errorf("agent: fitting the record buffer: %w", err)
		}
		if total, err = b.payloadSize(); err != nil {
			return scrubs, 0, err
		}
		if !more {
			break
		}
	}
	if total <= b.maxPayload {
		return scrubs, 0, nil
	}
	// Then the oldest records go.
	rows, err := b.db.Query(`SELECT seq, length(payload) FROM events ORDER BY seq`)
	if err != nil {
		return scrubs, 0, fmt.Errorf("agent: fitting the record buffer: %w", err)
	}
	cut := int64(-1)
	for total > b.maxPayload && rows.Next() {
		var seq, size int64
		if err := rows.Scan(&seq, &size); err != nil {
			_ = rows.Close()
			return scrubs, 0, fmt.Errorf("agent: fitting the record buffer: %w", err)
		}
		total -= size
		cut = seq
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return scrubs, 0, fmt.Errorf("agent: fitting the record buffer: %w", err)
	}
	if cut < 0 {
		return scrubs, 0, nil
	}
	res, err := b.db.Exec(`DELETE FROM events WHERE seq <= ?`, cut)
	if err != nil {
		return scrubs, 0, fmt.Errorf("agent: fitting the record buffer: %w", err)
	}
	deletes, _ = res.RowsAffected()
	return scrubs, deletes, nil
}

func (b *Buffer) payloadSize() (int64, error) {
	var total int64
	if err := b.db.QueryRow(`SELECT COALESCE(SUM(length(payload)), 0) FROM events`).Scan(&total); err != nil {
		return 0, fmt.Errorf("agent: reading the record buffer: %w", err)
	}
	return total, nil
}

// Close closes the file and wakes everyone waiting on Changed.
func (b *Buffer) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	close(b.changed)
	b.mu.Unlock()
	return b.db.Close()
}

// ---- journal --------------------------------------------------------------------

// journal publishes the agent's records: it buffers them, which wakes the open
// Watch streams up. A state report that says what the last buffered one said
// (the latency of the egress members aside) is not buffered again: it goes to the open streams only, without a sequence
// number (the panel moves its cursor for numbered records only). A record the
// buffer cannot take goes the same way, so that a full disk does not cut the
// panel off from what happens.
type journal struct {
	buf *Buffer
	log *slog.Logger
	now func() time.Time

	mu        sync.Mutex
	lastState *nodev1.StateReport // the last state report buffered
	lastEmit  time.Time           // when a state report last went out
	watchers  map[*watcher]struct{}
}

// watcher is an open Watch stream's share of the records that are not
// buffered: the latest one only, since each is the whole current state.
type watcher struct {
	live chan *nodev1.WatchResponse
}

func newJournal(buf *Buffer, log *slog.Logger, now func() time.Time) *journal {
	return &journal{buf: buf, log: log, now: now, watchers: map[*watcher]struct{}{}}
}

// event publishes a node event. Its texts are made valid UTF-8 first: a
// message quotes errors, and one invalid byte would make the record one that
// cannot be sent.
func (j *journal) event(ev *nodev1.NodeEvent) {
	ev = proto.Clone(ev).(*nodev1.NodeEvent)
	ev.Kind = strings.ToValidUTF8(ev.Kind, "\uFFFD")
	ev.Severity = strings.ToValidUTF8(ev.Severity, "\uFFFD")
	ev.Message = strings.ToValidUTF8(ev.Message, "\uFFFD")
	ev.ProxyId = strings.ToValidUTF8(ev.ProxyId, "\uFFFD")
	if len(ev.Details) > 0 {
		clean := make(map[string]string, len(ev.Details))
		for k, v := range ev.Details {
			clean[strings.ToValidUTF8(k, "\uFFFD")] = strings.ToValidUTF8(v, "\uFFFD")
		}
		ev.Details = clean
	}
	j.publish(&nodev1.WatchResponse{TsUnix: j.now().Unix(), Payload: &nodev1.WatchResponse_Event{Event: ev}})
}

// stats publishes a minute of statistics.
func (j *journal) stats(b *nodev1.StatsBatch) {
	j.publish(&nodev1.WatchResponse{TsUnix: j.now().Unix(), Payload: &nodev1.WatchResponse_Stats{Stats: b}})
}

func (j *journal) publish(rec *nodev1.WatchResponse) {
	if _, err := j.buf.Append(rec); err != nil {
		j.log.Warn("agent: a record could not be buffered; it goes to the open streams only", "err", err)
		j.mu.Lock()
		j.liveLocked(rec)
		j.mu.Unlock()
	}
}

// state publishes a state report: buffered when it differs from the last one
// buffered, otherwise to the open streams only.
func (j *journal) state(rep *nodev1.StateReport) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.now()
	j.lastEmit = now
	rec := &nodev1.WatchResponse{TsUnix: now.Unix(), Payload: &nodev1.WatchResponse_State{State: rep}}
	if j.lastState != nil && sameReport(j.lastState, rep) {
		j.liveLocked(rec)
		return
	}
	// The report that is about to be buffered is newer than any that waits as a
	// live one, so those go first, before Append: Append wakes the open streams
	// up, and a stream that reads the new record from the buffer and then looks
	// at its live one would send the older report after the newer. (Nothing can
	// put another live report there meanwhile: that takes j.mu.)
	j.dropLiveStatesLocked()
	if _, err := j.buf.Append(rec); err != nil {
		j.log.Warn("agent: a state report could not be buffered; it goes to the open streams only", "err", err)
		j.liveLocked(rec)
		return
	}
	j.lastState = proto.Clone(rep).(*nodev1.StateReport)
}

// sameReport reports whether two state reports say the same, the latency of
// the egress members aside: it changes with every check of the edge, and a
// report that differs only there is not worth a buffered record.
func sameReport(a, b *nodev1.StateReport) bool {
	if len(a.GetEgress()) != len(b.GetEgress()) {
		return false
	}
	return proto.Equal(withoutLatency(a), withoutLatency(b))
}

func withoutLatency(rep *nodev1.StateReport) *nodev1.StateReport {
	out := proto.Clone(rep).(*nodev1.StateReport)
	for _, m := range out.GetEgress() {
		m.LatencyMs = 0
	}
	return out
}

// dropLiveStatesLocked takes the state reports that wait for the watchers
// back: a newer one is about to be buffered, and a watcher that is behind would
// send the older one after it. Other records stay.
func (j *journal) dropLiveStatesLocked() {
	j.dropLiveLocked(func(rec *nodev1.WatchResponse) bool { return rec.GetState() != nil })
}

// diagnostics publishes the light diagnostics (the whole set): buffered when
// it changed, otherwise to the open streams only. A live report that waits
// is taken back before a newer one is buffered, as state reports are.
func (j *journal) diagnostics(rep *nodev1.DiagnosticsReport, buffered bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	rec := &nodev1.WatchResponse{TsUnix: j.now().Unix(), Payload: &nodev1.WatchResponse_Diagnostics{Diagnostics: rep}}
	if !buffered {
		j.liveLocked(rec)
		return
	}
	j.dropLiveLocked(func(rec *nodev1.WatchResponse) bool { return rec.GetDiagnostics() != nil })
	if _, err := j.buf.Append(rec); err != nil {
		j.log.Warn("agent: a diagnostics report could not be buffered; it goes to the open streams only", "err", err)
		j.liveLocked(rec)
	}
}

// dropLiveLocked takes the live records that waiting watchers hold back when
// drop says so; other records stay.
func (j *journal) dropLiveLocked(drop func(*nodev1.WatchResponse) bool) {
	for w := range j.watchers {
		select {
		case rec := <-w.live:
			if !drop(rec) {
				select {
				case w.live <- rec:
				default:
				}
			}
		default:
		}
	}
}

// stateDue reports whether no state report went out for every.
func (j *journal) stateDue(every time.Duration) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.now().Sub(j.lastEmit) >= every
}

func (j *journal) watch() *watcher {
	w := &watcher{live: make(chan *nodev1.WatchResponse, 1)}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.watchers[w] = struct{}{}
	return w
}

func (j *journal) unwatch(w *watcher) {
	j.mu.Lock()
	defer j.mu.Unlock()
	delete(j.watchers, w)
}

// liveLocked hands rec to every watcher, in place of one it has not taken
// yet. j.mu is held, so there is one sender at a time.
func (j *journal) liveLocked(rec *nodev1.WatchResponse) {
	for w := range j.watchers {
		select {
		case w.live <- rec:
			continue
		default:
		}
		select {
		case <-w.live:
		default:
		}
		select {
		case w.live <- rec:
		default:
		}
	}
}

// clipText returns s as valid UTF-8 without control characters, cut to at
// most n bytes on a character boundary: for text that comes from outside the
// agent (files, processes, containers) and goes into a protobuf string.
func clipText(s string, n int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func utf8RuneStart(b byte) bool { return b&0xc0 != 0x80 }
