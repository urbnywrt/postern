package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/urbnywrt/postern/internal/ids"
)

// The states of a diagnostic run.
const (
	RunRunning = "running"
	RunDone    = "done"
	RunPartial = "partial" // the run ended before the node finished its checks
	RunSkipped = "skipped" // the node's checks did not run
	RunFailed  = "failed"
)

// The reasons of a diagnostic run.
const (
	RunManual       = "manual"
	RunBeforeChange = "before_change"
	RunAfterChange  = "after_change"
)

// A DiagnosticRun is a run of the checks of a scope of a node ("node" or
// "proxy:<id>"). The counts are those of its results, set when it finishes.
type DiagnosticRun struct {
	ID           string
	NodeID       string
	Scope        string
	Reason       string
	Change       string
	RelatedRunID string
	AdminID      string
	State        string
	Error        string
	Regressed    bool
	OK, Warn     int
	Fail, Skip   int
	StartedAt    time.Time
	FinishedAt   *time.Time
	// Results are filled by [DB.DiagnosticRun] only, in order.
	Results []DiagnosticResult
}

// A DiagnosticResult is one result of a run, the seq-th.
type DiagnosticResult struct {
	Seq        int
	CheckID    string
	Layer      string
	Target     string
	Status     string // ok, warn, fail, skip
	Summary    string
	Evidence   string
	Hint       string
	Fix        string
	Vantage    string // panel or node
	CheckedAt  time.Time
	DurationMS uint32
}

// A NodeCheck is the last result of a light check of a node, and since when it
// has had its status.
type NodeCheck struct {
	CheckID   string
	Target    string
	Layer     string
	Status    string
	Summary   string
	Evidence  string
	Hint      string
	Fix       string
	Since     time.Time
	CheckedAt time.Time
}

// A CheckChange is a light check whose status changed: From is the status it
// had, "" for a check that the node did not report before.
type CheckChange struct {
	Check NodeCheck
	From  string
}

// CreateDiagnosticRun stores a new run. It gives r an ID if it has none and
// the time of the clock as its start if it has none; the state is running
// unless r names another. A node that does not exist is [ErrNotFound].
func (db *DB) CreateDiagnosticRun(ctx context.Context, r *DiagnosticRun) error {
	if r.ID == "" {
		r.ID = ids.New()
	}
	if r.StartedAt.IsZero() {
		r.StartedAt = db.now()
	}
	r.StartedAt = normTime(r.StartedAt)
	if r.State == "" {
		r.State = RunRunning
	}
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO diagnostic_runs (id, node_id, scope, reason, change, related_run_id, admin_id, state, started_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.NodeID, r.Scope, r.Reason, r.Change, r.RelatedRunID, r.AdminID, r.State, r.StartedAt.Unix())
	if err != nil {
		return fmt.Errorf("store: create diagnostic run: %w", mapErr(err, fkMissing))
	}
	return nil
}

// AddDiagnosticResult stores a result of a run. A run that does not exist is
// [ErrNotFound]; a seq that the run has is [ErrConflict].
func (db *DB) AddDiagnosticResult(ctx context.Context, runID string, r DiagnosticResult) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO diagnostic_results (run_id, seq, check_id, layer, target, status, summary, evidence, hint, fix, vantage, checked_at, duration_ms)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		runID, r.Seq, r.CheckID, r.Layer, r.Target, r.Status, r.Summary, r.Evidence, r.Hint, r.Fix,
		r.Vantage, normTime(r.CheckedAt).Unix(), int64(r.DurationMS))
	if err != nil {
		return fmt.Errorf("store: add diagnostic result: %w", mapErr(err, fkMissing))
	}
	return nil
}

// FinishDiagnosticRun ends a run with its state, error and regression, at the
// time given, and counts its results. A run that does not exist is
// [ErrNotFound].
func (db *DB) FinishDiagnosticRun(ctx context.Context, id, state, errText string, regressed bool, at time.Time) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE diagnostic_runs SET state = ?1, error = ?2, regressed = ?3, finished_at = ?4,
		   ok   = (SELECT COUNT(*) FROM diagnostic_results WHERE run_id = ?5 AND status = 'ok'),
		   warn = (SELECT COUNT(*) FROM diagnostic_results WHERE run_id = ?5 AND status = 'warn'),
		   fail = (SELECT COUNT(*) FROM diagnostic_results WHERE run_id = ?5 AND status = 'fail'),
		   skip = (SELECT COUNT(*) FROM diagnostic_results WHERE run_id = ?5 AND status = 'skip')
		 WHERE id = ?5`,
		state, errText, boolInt(regressed), normTime(at).Unix(), id)
	if err != nil {
		return fmt.Errorf("store: finish diagnostic run: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: finish diagnostic run: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: finish diagnostic run: %w", notFound("diagnostic run"))
	}
	return nil
}

// FailUnfinishedDiagnosticRuns ends every run that is still running, as
// failed with errText: what is left of the runs of a panel that stopped. It
// returns how many there were.
func (db *DB) FailUnfinishedDiagnosticRuns(ctx context.Context, errText string) (int64, error) {
	running, err := db.unfinishedRuns(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: fail unfinished diagnostic runs: %w", err)
	}
	now := db.now()
	for _, id := range running {
		if err := db.FinishDiagnosticRun(ctx, id, RunFailed, errText, false, now); err != nil {
			return 0, err
		}
	}
	return int64(len(running)), nil
}

func (db *DB) unfinishedRuns(ctx context.Context) ([]string, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id FROM diagnostic_runs WHERE state = ?`, RunRunning)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

const runCols = `id, node_id, scope, reason, change, related_run_id, admin_id, state, error, regressed,
	ok, warn, fail, skip, started_at, finished_at`

func scanRun(s scanner) (*DiagnosticRun, error) {
	var (
		r                    DiagnosticRun
		regressed            int64
		ok, warn, fail, skip int64
		started              int64
		finished             sql.NullInt64
	)
	if err := s.Scan(&r.ID, &r.NodeID, &r.Scope, &r.Reason, &r.Change, &r.RelatedRunID, &r.AdminID, &r.State, &r.Error,
		&regressed, &ok, &warn, &fail, &skip, &started, &finished); err != nil {
		return nil, err
	}
	r.Regressed = regressed != 0
	r.OK, r.Warn, r.Fail, r.Skip = int(ok), int(warn), int(fail), int(skip)
	r.StartedAt = timeFromDB(started)
	if finished.Valid {
		t := timeFromDB(finished.Int64)
		r.FinishedAt = &t
	}
	return &r, nil
}

// DiagnosticRun returns a run with its results, in order. A run that does not
// exist is [ErrNotFound].
func (db *DB) DiagnosticRun(ctx context.Context, id string) (*DiagnosticRun, error) {
	r, err := scanRun(db.sql.QueryRowContext(ctx, `SELECT `+runCols+` FROM diagnostic_runs WHERE id = ?`, id))
	if err != nil {
		return nil, fmt.Errorf("store: diagnostic run: %w", queryNotFound(err, "diagnostic run"))
	}
	rows, err := db.sql.QueryContext(ctx,
		`SELECT seq, check_id, layer, target, status, summary, evidence, hint, fix, vantage, checked_at, duration_ms
		 FROM diagnostic_results WHERE run_id = ? ORDER BY seq`, id)
	if err != nil {
		return nil, fmt.Errorf("store: diagnostic run: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			x            DiagnosticResult
			checked, dur int64
		)
		if err := rows.Scan(&x.Seq, &x.CheckID, &x.Layer, &x.Target, &x.Status, &x.Summary, &x.Evidence, &x.Hint, &x.Fix,
			&x.Vantage, &checked, &dur); err != nil {
			return nil, fmt.Errorf("store: diagnostic run: %w", err)
		}
		x.CheckedAt, x.DurationMS = timeFromDB(checked), uint32Of(dur)
		r.Results = append(r.Results, x)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: diagnostic run: %w", err)
	}
	return r, nil
}

// ListDiagnosticRuns returns the runs of a node, newest first, at most limit,
// without their results. With scopes, only the runs of those scopes.
func (db *DB) ListDiagnosticRuns(ctx context.Context, nodeID string, scopes []string, limit int) ([]*DiagnosticRun, error) {
	q := `SELECT ` + runCols + ` FROM diagnostic_runs WHERE node_id = ?`
	args := []any{nodeID}
	if len(scopes) > 0 {
		q += ` AND scope IN (?` + strings.Repeat(`, ?`, len(scopes)-1) + `)`
		for _, s := range scopes {
			args = append(args, s)
		}
	}
	q += ` ORDER BY started_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list diagnostic runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*DiagnosticRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list diagnostic runs: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list diagnostic runs: %w", err)
	}
	return out, nil
}

// NodeChecks returns the light checks of a node, by check id and target.
func (db *DB) NodeChecks(ctx context.Context, nodeID string) ([]NodeCheck, error) {
	out, err := nodeChecks(ctx, db.sql, nodeID)
	if err != nil {
		return nil, fmt.Errorf("store: node checks: %w", err)
	}
	return out, nil
}

func nodeChecks(ctx context.Context, q dbtx, nodeID string) ([]NodeCheck, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT check_id, target, layer, status, summary, evidence, hint, fix, since, checked_at
		 FROM node_checks WHERE node_id = ? ORDER BY check_id, target`, nodeID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []NodeCheck
	for rows.Next() {
		var (
			c              NodeCheck
			since, checked int64
		)
		if err := rows.Scan(&c.CheckID, &c.Target, &c.Layer, &c.Status, &c.Summary, &c.Evidence, &c.Hint, &c.Fix,
			&since, &checked); err != nil {
			return nil, err
		}
		c.Since, c.CheckedAt = timeFromDB(since), timeFromDB(checked)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReplaceNodeChecks replaces the light checks of a node with checks, in one
// transaction. A check that keeps its status keeps its Since; one whose status
// changed, or that is new, gets at. It returns the checks whose status changed
// or that are new, in the order of checks. A node that does not exist is
// [ErrNotFound].
func (db *DB) ReplaceNodeChecks(ctx context.Context, nodeID string, checks []NodeCheck, at time.Time) ([]CheckChange, error) {
	at = normTime(at)
	var changes []CheckChange
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		old, err := nodeChecks(ctx, tx, nodeID)
		if err != nil {
			return err
		}
		type key struct{ id, target string }
		prev := make(map[key]NodeCheck, len(old))
		for _, c := range old {
			prev[key{c.CheckID, c.Target}] = c
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM node_checks WHERE node_id = ?`, nodeID); err != nil {
			return err
		}
		for _, c := range checks {
			p, had := prev[key{c.CheckID, c.Target}]
			if had && p.Status == c.Status {
				c.Since = p.Since
			} else {
				c.Since = at
				changes = append(changes, CheckChange{Check: c, From: p.Status})
			}
			if c.CheckedAt.IsZero() {
				c.CheckedAt = at
			}
			_, err := tx.ExecContext(ctx,
				`INSERT INTO node_checks (node_id, check_id, target, layer, status, summary, evidence, hint, fix, since, checked_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				 ON CONFLICT (node_id, check_id, target) DO UPDATE SET layer = excluded.layer, status = excluded.status,
				   summary = excluded.summary, evidence = excluded.evidence, hint = excluded.hint, fix = excluded.fix,
				   since = excluded.since, checked_at = excluded.checked_at`,
				nodeID, c.CheckID, c.Target, c.Layer, c.Status, c.Summary, c.Evidence, c.Hint, c.Fix,
				normTime(c.Since).Unix(), normTime(c.CheckedAt).Unix())
			if err != nil {
				return mapErr(err, fkMissing)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: replace node checks: %w", err)
	}
	return changes, nil
}

// NodeBehindSince returns since when a node has not applied its desired state:
// the time of the oldest desired generation that it has not applied, and
// whether it is behind at all. A node that does not exist is [ErrNotFound].
func (db *DB) NodeBehindSince(ctx context.Context, nodeID string) (time.Time, bool, error) {
	var desired, applied, since int64
	err := db.sql.QueryRowContext(ctx,
		`SELECT desired_generation, applied_generation, behind_since FROM nodes WHERE id = ?`, nodeID).
		Scan(&desired, &applied, &since)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("store: node behind since: %w", queryNotFound(err, "node"))
	}
	if applied >= desired {
		return time.Time{}, false, nil
	}
	return timeFromDB(since), true, nil
}

// RolloutStepChange is the change of the runs around a step of a rollout,
// "rollout <id> step <n>", n counted from 1.
func RolloutStepChange(rolloutID string, index uint32) string {
	return fmt.Sprintf("rollout %s step %d", rolloutID, uint64(index)+1)
}

// DiagnosticRunsByChange returns the runs whose change begins with prefix,
// oldest first, without their results.
func (db *DB) DiagnosticRunsByChange(ctx context.Context, prefix string) ([]*DiagnosticRun, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+runCols+` FROM diagnostic_runs
		WHERE substr(change, 1, ?) = ? ORDER BY started_at, id`, len(prefix), prefix)
	if err != nil {
		return nil, fmt.Errorf("store: diagnostic runs of a change: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*DiagnosticRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("store: diagnostic runs of a change: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: diagnostic runs of a change: %w", err)
	}
	return out, nil
}
