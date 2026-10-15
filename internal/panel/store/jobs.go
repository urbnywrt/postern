package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/urbnywrt/postern/internal/ids"
)

// The values of Job.Status. A job is created running and ends in one of the
// other three, after which it does not change.
const (
	JobRunning   = "running"
	JobDone      = "done"
	JobFailed    = "failed"
	JobCancelled = "cancelled"
)

// A Job is a long operation on a node, such as an install over SSH, with the
// log that the UI shows while it runs. Jobs are history: a job keeps naming its
// node after the node has been deleted.
//
// A node has at most one running job: [DB.CreateJob] refuses a second one.
type Job struct {
	ID         string
	NodeID     string
	Kind       string // what the job does, for example "install"
	Status     string // one of the Job values
	Log        string // the output, as the job runner keeps it
	Error      string // why the job failed or was cancelled, "" when it is done
	StartedAt  time.Time
	FinishedAt *time.Time // nil while the job runs
}

const jobColumns = `id, node_id, kind, status, log, started_at, finished_at, error`

func scanJob(s scanner) (*Job, error) {
	var (
		j        Job
		started  int64
		finished sql.NullInt64
	)
	if err := s.Scan(&j.ID, &j.NodeID, &j.Kind, &j.Status, &j.Log, &started, &finished, &j.Error); err != nil {
		return nil, err
	}
	j.StartedAt = timeFromDB(started)
	j.FinishedAt = timePtrFromDB(finished)
	return &j, nil
}

// CreateJob stores j as a new running job: whatever j says, its status becomes
// JobRunning and it has no error and no end. It gives j an ID if it has none and
// the time of the clock as its start if it has none. A node that has a running
// job already is [ErrConflict].
func (db *DB) CreateJob(ctx context.Context, j *Job) error {
	c := *j
	if c.ID == "" {
		c.ID = ids.New()
	}
	if c.StartedAt.IsZero() {
		c.StartedAt = db.now()
	}
	c.StartedAt = normTime(c.StartedAt)
	c.Status, c.Error, c.FinishedAt = JobRunning, "", nil

	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO jobs (`+jobColumns+`) VALUES (?, ?, ?, ?, ?, ?, NULL, '')`,
		c.ID, c.NodeID, c.Kind, c.Status, c.Log, c.StartedAt.Unix())
	if err != nil {
		return fmt.Errorf("store: create job: %w", mapErr(err, fkMissing))
	}
	*j = c
	return nil
}

// JobByID returns the job with this id, or [ErrNotFound].
func (db *DB) JobByID(ctx context.Context, id string) (*Job, error) {
	j, err := scanJob(db.sql.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = ?`, id))
	if err != nil {
		return nil, fmt.Errorf("store: job by id: %w", queryNotFound(err, "job"))
	}
	return j, nil
}

// RunningJobByNode returns the job of this kind that a node is running, or
// [ErrNotFound] when it runs none of it. A node runs at most one job (see
// [DB.CreateJob]), whatever its kind, so a node that runs a job of another kind
// has none of this one: the services that share the jobs each ask for their own.
func (db *DB) RunningJobByNode(ctx context.Context, nodeID, kind string) (*Job, error) {
	j, err := scanJob(db.sql.QueryRowContext(ctx,
		`SELECT `+jobColumns+` FROM jobs WHERE node_id = ? AND kind = ? AND status = ?`, nodeID, kind, JobRunning))
	if err != nil {
		return nil, fmt.Errorf("store: running job by node: %w", queryNotFound(err, "running job"))
	}
	return j, nil
}

// UpdateJobLog replaces the log of a running job. A job that does not exist, or
// that has finished, is [ErrNotFound]: a finished job does not change.
func (db *DB) UpdateJobLog(ctx context.Context, id, log string) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE jobs SET log = ? WHERE id = ? AND status = ?`, log, id, JobRunning)
	if err != nil {
		return fmt.Errorf("store: update job log: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: update job log: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: update job log: %w", notFound("running job"))
	}
	return nil
}

// FinishJob ends a running job: it sets the status, which has to be JobDone,
// JobFailed or JobCancelled, the last log, the error ("" for a job that is
// done), and the time of the clock as the end. A job that does not exist, or
// that has finished already, is [ErrNotFound].
func (db *DB) FinishJob(ctx context.Context, id, status, log, errText string) error {
	switch status {
	case JobDone, JobFailed, JobCancelled:
	default:
		return fmt.Errorf("store: finish job: %q is not the status of a finished job", status)
	}
	res, err := db.sql.ExecContext(ctx,
		`UPDATE jobs SET status = ?, log = ?, error = ?, finished_at = ? WHERE id = ? AND status = ?`,
		status, log, errText, normTime(db.now()).Unix(), id, JobRunning)
	if err != nil {
		return fmt.Errorf("store: finish job: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: finish job: %w", err)
	} else if n == 0 {
		return fmt.Errorf("store: finish job: %w", notFound("running job"))
	}
	return nil
}

// FailRunningJobs marks every job that is still running as failed, with errText
// as the error and the time of the clock as the end, and returns how many there
// were. The panel calls it when it starts: the process that ran those jobs is
// gone, and a job that is shown as running would keep its node from running
// another one.
func (db *DB) FailRunningJobs(ctx context.Context, errText string) (int64, error) {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE jobs SET status = ?, error = ?, finished_at = ? WHERE status = ?`,
		JobFailed, errText, normTime(db.now()).Unix(), JobRunning)
	if err != nil {
		return 0, fmt.Errorf("store: fail running jobs: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: fail running jobs: %w", err)
	}
	return n, nil
}
