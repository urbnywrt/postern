package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
	"github.com/urbnywrt/postern/internal/release"
)

// The kinds of an Outcome.
const (
	OutcomeNone       = ""            // no update was in flight
	OutcomeUpdated    = "updated"     // the panel runs the version it updated to
	OutcomeRolledBack = "rolled_back" // the launcher went back to the version before
	OutcomeAbandoned  = "abandoned"   // the journal names an update that never took effect
	OutcomeImageNewer = "image_newer" // a newer image replaced the self-updated binary
)

// An Outcome is what Recover found of the last update of the panel. Settle
// records it once the panel serves.
type Outcome struct {
	Kind     string
	From, To string
	// Backup is the snapshot of the database taken before the update.
	Backup string
	// Restored says that the database was replaced by Backup, since the
	// failed version had migrated it beyond what this version knows; Failed
	// is the directory that its files were moved to.
	Restored bool
	Failed   string
	// Rollback is the launcher's record of the rollback, as it was.
	Rollback string
}

// recoverer is Recover with what it uses as fields, for tests.
type recoverer struct {
	dataDir  string
	version  string
	log      *slog.Logger
	exe      func() (string, error)
	run      func(ctx context.Context, path string, args ...string) ([]byte, error)
	imageBin string
	now      func() time.Time
	// fail, when set, is asked after each step of a restore and stops it
	// with its error: tests crash the restore there.
	fail func(step string) error
}

// The steps of a restore, in order, as recoverer.fail names them.
const (
	stepLinked     = "linked"      // the database files are linked into the failed directory
	stepJournaled  = "journaled"   // the journal says that the restore is under way
	stepWALRemoved = "wal-removed" // -wal and -shm are gone from the data directory
	stepSwapped    = "swapped"     // the snapshot replaced postern.db
)

func (r recoverer) step(name string) error {
	if r.fail == nil {
		return nil
	}
	return r.fail(name)
}

// Recover runs before the store opens and settles what the last update of
// the panel left (spec §7):
//
//   - a panel that runs from <data>/bin while the image binary reports a
//     newer version (a newer image was pulled) removes bin/current (and
//     bin/previous when it points at the image) and returns ErrRestart: the
//     launcher then runs the image, whose start finds the note
//     (OutcomeImageNewer) and Settle records panel_image_newer;
//   - the journal's "to" is the running version: the update worked, and
//     Settle deletes the journal once the panel serves (panel_updated);
//   - the launcher rolled back from bin/postern-panel-<to> (its record not
//     older than the journal) to the journal's "from", which runs: if the
//     database holds a migration that this version does not know, postern.db
//     and its -wal and -shm are kept in backups/failed-<to>-<unix>/ and the
//     journal's snapshot replaces postern.db (0600, by one rename, so that
//     the data directory always has a postern.db); the journal and the
//     record are deleted last, so that a restore cut short at any step is
//     finished by the next start (restore), and Settle records
//     panel_update_rolled_back. A record older than the journal is ignored;
//   - a journal of an update that never took effect (bin/current does not
//     point at the new version, and the running one is not it) is deleted.
func Recover(dataDir, version string, log *slog.Logger) (Outcome, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r := recoverer{dataDir: dataDir, version: version, log: log, exe: os.Executable, run: runBinary,
		imageBin: imageBinary(""), now: time.Now}
	return r.recover()
}

func (r recoverer) path(rel string) string { return filepath.Join(r.dataDir, rel) }

func (r recoverer) recover() (Outcome, error) {
	if newer, err := r.imageIsNewer(); err != nil {
		return Outcome{}, err
	} else if newer {
		return Outcome{}, ErrRestart
	}
	j, ok, err := readJournal(r.path(journalFile))
	if err != nil {
		return Outcome{}, err
	}
	if !ok {
		o, _ := r.imageNote()
		return o, nil
	}
	// A journal written after the note: the update is what matters.
	_ = os.Remove(r.path(imageNoteFile))
	o := Outcome{From: j.From, To: j.To, Backup: j.Backup}
	if j.To == r.version {
		o.Kind = OutcomeUpdated
		return o, nil
	}
	if rec, ok := r.rollback(j); ok {
		o.Kind, o.Rollback = OutcomeRolledBack, rec
		if err := r.restore(&j, &o); err != nil {
			return Outcome{}, err
		}
		for _, p := range []string{r.path(journalFile), r.path(rollbackFile)} {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return Outcome{}, fmt.Errorf("selfupdate: %w", err)
			}
		}
		r.log.Warn("the update of the panel failed and the launcher rolled it back",
			"from", j.From, "to", j.To, "restored", o.Restored, "failed_db", o.Failed, "backup", j.Backup)
		return o, nil
	}
	if cur, _ := os.Readlink(filepath.Join(r.dataDir, binDir, "current")); cur == binPrefix+j.To {
		// Installed, and not run yet: the launcher starts it next.
		return Outcome{}, nil
	}
	if err := os.Remove(r.path(journalFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Outcome{}, fmt.Errorf("selfupdate: %w", err)
	}
	o.Kind = OutcomeAbandoned
	r.log.Warn("the journal named an update of the panel that never took effect; it is dropped",
		"from", j.From, "to", j.To, "running", r.version)
	return o, nil
}

// imageIsNewer reports whether the panel runs from <data>/bin while the image
// binary is newer (release.Newer, prereleases included); then it has written
// the note (run/image-newer: "<unix> <running> <image>"), which the image
// binary turns into an event at its start, and removed bin/current,
// bin/previous when it points at the image binary, and the journal, which the
// newer image makes moot. The version files stay. An image binary whose
// version cannot be read is a warning: the panel runs on.
func (r recoverer) imageIsNewer() (bool, error) {
	exe, err := r.exe()
	if err != nil {
		return false, nil //nolint:nilerr // without its own path the panel cannot tell, and runs on
	}
	if e, err := filepath.EvalSymlinks(exe); err == nil {
		exe = e
	}
	bin := r.path(binDir)
	if b, err := filepath.EvalSymlinks(bin); err == nil {
		bin = b
	}
	if filepath.Dir(exe) != bin {
		return false, nil
	}
	iv := binaryVersion(context.Background(), r.run, r.imageBin)
	if iv == "" {
		r.log.Warn("cannot read the version of the image binary; the self-updated binary runs on", "image_bin", r.imageBin, "running", r.version)
		return false, nil
	}
	if !release.Newer(iv, r.version) {
		return false, nil
	}
	r.log.Warn("the image carries "+iv+", newer than the self-updated "+r.version+": going back to the image binary",
		"image", iv, "running", r.version)
	note := fmt.Sprintf("%d %s %s\n", r.now().Unix(), r.version, iv)
	if err := os.MkdirAll(filepath.Dir(r.path(imageNoteFile)), 0o700); err != nil {
		r.log.Warn("cannot record that the image wins", "err", err)
	} else if err := os.WriteFile(r.path(imageNoteFile), []byte(note), 0o600); err != nil {
		r.log.Warn("cannot record that the image wins", "err", err)
	}
	remove := []string{filepath.Join(r.path(binDir), "current"), r.path(journalFile)}
	if prev := filepath.Join(r.path(binDir), "previous"); r.pointsAtImage(prev) {
		remove = append(remove, prev)
	}
	for _, p := range remove {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("selfupdate: %w", err)
		}
	}
	return true, nil
}

// pointsAtImage reports whether the link link points at the image binary:
// by its path, or at the same file.
func (r recoverer) pointsAtImage(link string) bool {
	target, err := os.Readlink(link)
	if err != nil {
		return false
	}
	if target == r.imageBin {
		return true
	}
	a, errA := os.Stat(link)
	b, errB := os.Stat(r.imageBin)
	return errA == nil && errB == nil && os.SameFile(a, b)
}

// imageNote returns the outcome that the note of imageIsNewer records, and
// whether there is one. A note that cannot be read is dropped, and so is one
// for another image than the binary that runs: a step-aside that failed after
// the note was written left it, and the image did not win.
func (r recoverer) imageNote() (Outcome, bool) {
	data, err := os.ReadFile(r.path(imageNoteFile))
	if err != nil {
		return Outcome{}, false
	}
	f := strings.Fields(string(data))
	if len(f) != 3 || !release.ValidVersion(f[1]) || !release.ValidVersion(f[2]) || f[2] != r.version {
		_ = os.Remove(r.path(imageNoteFile))
		return Outcome{}, false
	}
	return Outcome{Kind: OutcomeImageNewer, From: f[1], To: f[2]}, true
}

// rollback returns the launcher's record when it says that the launcher
// rolled back from the journal's version, not before the journal was written,
// and the version that runs is the journal's "from".
func (r recoverer) rollback(j journal) (string, bool) {
	data, err := os.ReadFile(r.path(rollbackFile))
	if err != nil {
		return "", false
	}
	rec := strings.TrimSpace(string(data))
	f := strings.Fields(rec)
	if len(f) != 3 {
		return "", false
	}
	at, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil || at < j.At || f[1] != binPrefix+j.To || r.version != j.From {
		return "", false
	}
	return rec, true
}

// restore puts the journal's snapshot in place of a database that the failed
// version migrated beyond what this version knows. The snapshot is copied
// first, so that nothing is moved when it cannot be.
//
// The steps never leave the data directory without a postern.db, and each
// can be run again after a crash:
//
//  1. postern.db, -wal and -shm are hard-linked (copied where links do not
//     work) into backups/failed-<to>-<unix>/; the originals stay;
//  2. the journal is rewritten with "restoring" = that directory: from here
//     on the next start does not look at the schema again (which would no
//     longer tell once the -wal is gone) and goes on with step 3;
//  3. -wal and -shm are removed (they belong to the failed database and
//     would be replayed into the snapshot);
//  4. a copy of the snapshot is renamed over postern.db.
//
// The caller deletes the journal and the record only after that.
func (r recoverer) restore(j *journal, o *Outcome) error {
	db := r.path(DatabaseFile)
	if j.Restoring == "" {
		newer, err := store.NewerSchema(db)
		if err != nil {
			return fmt.Errorf("selfupdate: look at the database after the rollback: %w", err)
		}
		if !newer {
			return nil
		}
		if j.Backup == "" {
			return fmt.Errorf("selfupdate: the database was migrated by %s and the journal names no snapshot to restore", j.To)
		}
		if _, err := os.Stat(j.Backup); err != nil {
			return fmt.Errorf("selfupdate: the database was migrated by %s and its snapshot cannot be read: %w", j.To, err)
		}
		failed := r.path(filepath.Join("backups", fmt.Sprintf("failed-%s-%d", j.To, r.now().Unix())))
		if err := os.MkdirAll(failed, 0o700); err != nil {
			return err
		}
		for _, suffix := range []string{"", "-wal", "-shm"} {
			if err := keepFile(db+suffix, filepath.Join(failed, DatabaseFile+suffix)); err != nil {
				return fmt.Errorf("selfupdate: keep the database of %s: %w", j.To, err)
			}
		}
		if err := r.step(stepLinked); err != nil {
			return err
		}
		j.Restoring = failed
		if err := writeJSON(r.path(journalFile), j); err != nil {
			return fmt.Errorf("selfupdate: write the journal: %w", err)
		}
		if err := r.step(stepJournaled); err != nil {
			return err
		}
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(db + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("selfupdate: remove %s: %w", DatabaseFile+suffix, err)
		}
	}
	if err := r.step(stepWALRemoved); err != nil {
		return err
	}
	tmp, err := copyInto(j.Backup, r.dataDir, "."+DatabaseFile+".restore-*")
	if err != nil {
		return fmt.Errorf("selfupdate: copy the snapshot %s: %w", j.Backup, err)
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, db); err != nil {
		return fmt.Errorf("selfupdate: put the snapshot in place: %w", err)
	}
	if err := r.step(stepSwapped); err != nil {
		return err
	}
	o.Restored, o.Failed = true, j.Restoring
	return nil
}

// keepFile makes dst a hard link to src (a copy where a link cannot be
// made), replacing what is at dst; a src that is not there is no error.
func keepFile(src, dst string) error {
	if _, err := os.Stat(src); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := os.Remove(dst); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	tmp, err := copyInto(src, filepath.Dir(dst), "."+filepath.Base(dst)+"-*")
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// readJournal reads the journal; ok is false when there is none. A journal
// that cannot be read is an error (it is not deleted: the operator looks).
func readJournal(path string) (journal, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return journal{}, false, nil
	}
	if err != nil {
		return journal{}, false, fmt.Errorf("selfupdate: %w", err)
	}
	var j journal
	if err := json.Unmarshal(data, &j); err != nil || !release.ValidVersion(j.To) {
		return journal{}, false, fmt.Errorf("selfupdate: the journal %s cannot be read (remove it to go on): %v", path, err)
	}
	return j, true, nil
}

// Settle records the outcome of Recover once the panel serves: an event, the
// setting that GetPanelVersion shows, and for a successful update the removal
// of the journal. Failures are logged.
func Settle(ctx context.Context, db *store.DB, dataDir string, o Outcome, log *slog.Logger) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if o.Kind == OutcomeNone {
		return
	}
	at := time.Now().UTC().Format(time.RFC3339)
	e := &store.Event{Details: map[string]string{"from": o.From, "to": o.To, "backup": o.Backup}}
	var last string
	switch o.Kind {
	case OutcomeUpdated:
		if err := os.Remove(filepath.Join(dataDir, journalFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Error("could not remove the journal of the update", "err", err)
		}
		e.Kind, e.Message = EventUpdated, "the panel was updated from "+o.From+" to "+o.To
		last = "updated from " + o.From + " to " + o.To + " at " + at
	case OutcomeRolledBack:
		e.Kind, e.Severity = EventUpdateRolledBack, "error"
		e.Message = "the panel " + o.To + " did not start and the launcher rolled it back to " + o.From
		e.Details["rollback"] = o.Rollback
		last = o.To + " did not start and was rolled back to " + o.From + " at " + at
		if o.Restored {
			e.Details["restored_from"], e.Details["failed_db"] = o.Backup, o.Failed
			e.Message += "; the database was restored from " + o.Backup + ", and the one of " + o.To + " moved to " + o.Failed
			last += "; the database was restored from " + o.Backup + " (the one of " + o.To + " is in " + o.Failed + ")"
		}
	case OutcomeImageNewer:
		if err := os.Remove(filepath.Join(dataDir, imageNoteFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Error("could not remove the note of the newer image", "err", err)
		}
		e.Kind, e.Message = EventImageNewer, "the image carries "+o.To+", newer than the self-updated "+o.From+": the panel went back to the image binary"
		last = "went back to the image " + o.To + " from the self-updated " + o.From + " at " + at
	case OutcomeAbandoned:
		e.Kind, e.Severity = EventUpdateAbandoned, "warning"
		e.Message = "the update of the panel from " + o.From + " to " + o.To + " never took effect"
		last = "the update from " + o.From + " to " + o.To + " never took effect (" + at + ")"
	default:
		return
	}
	if err := db.AppendEvent(ctx, e); err != nil {
		log.Error("could not record the outcome of the update", "event", e.Kind, "err", err)
	}
	if err := db.PutSetting(ctx, store.SettingPanelLastUpdate, last); err != nil {
		log.Error("could not record the outcome of the update", "err", err)
	}
}

// LastUpdate is what the last update of the panel did, "" for none yet.
func LastUpdate(ctx context.Context, db *store.DB) (string, error) {
	var s string
	_, err := db.GetSetting(ctx, store.SettingPanelLastUpdate, &s)
	return s, err
}
