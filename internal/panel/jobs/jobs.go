// Package jobs runs the long operations of the panel, such as the install of a
// node over SSH, in the background, and keeps their state and their logs in
// the database, where the UI polls them: a job survives a reload of the page.
//
// A node runs one job at a time. The log of a job is what its function writes,
// with the secrets of the job replaced by *** (see [Runner.Start]), and only
// the newest [MaxLog] bytes of it: the oldest lines are dropped, and a line at
// the top says how much. The log is saved while the job runs, at most every
// [FlushInterval], and when it ends.
//
// A job ends done, failed or cancelled. When the panel stops, its running jobs
// are cancelled and recorded as failed; a job that a crash or a kill left
// running in the database is failed when the panel starts again ([New]).
package jobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// The values of Job.Status.
const (
	StatusRunning   = store.JobRunning
	StatusDone      = store.JobDone
	StatusFailed    = store.JobFailed
	StatusCancelled = store.JobCancelled
)

const (
	// MaxLog is the most of its log that a job keeps.
	MaxLog = 1 << 20

	// FlushInterval is the shortest time between two saves of the log of a
	// running job.
	FlushInterval = 500 * time.Millisecond

	// MinSecretLen is the length from which secrets are replaced in the log.
	MinSecretLen = 4
)

// The errors of jobs that did not end by themselves.
const (
	CancelledError = "the job was cancelled"
	StoppedError   = "the panel stopped while the job was running"
	RestartedError = "the panel restarted"
)

const (
	// maxPartial is how long a line may grow without its end before it is
	// cut, so that output without line ends cannot fill the memory.
	maxPartial = 64 << 10

	// maxError is the most of the error of a job that is kept.
	maxError = 4 << 10

	// storeTimeout bounds one write to the database.
	storeTimeout = 10 * time.Second
)

// How far apart the end of a job is tried again when the database refuses it:
// first finishFirstDelay, then twice as long each time, up to finishMaxDelay.
const (
	finishFirstDelay = time.Second
	finishMaxDelay   = 30 * time.Second
)

var (
	// ErrBusy is returned by [Runner.Start] for a node that is running a job.
	ErrBusy = errors.New("jobs: the node is running a job already")

	// ErrNotFound is returned for a job that does not exist, and by
	// [Runner.Cancel] for one that is not running.
	ErrNotFound = errors.New("jobs: no such job")

	// ErrClosed is returned by [Runner.Start] once the runner is closed.
	ErrClosed = errors.New("jobs: the runner is closed")
)

var (
	errCancelled = errors.New(CancelledError)
	errStopped   = errors.New(StoppedError)
	errEnded     = errors.New("jobs: the job has ended, its log takes nothing more")
)

// A Job is a job as the UI sees it.
type Job struct {
	ID         string
	NodeID     string
	Kind       string
	Status     string // one of the Status values
	Log        string // the newest MaxLog bytes of the output, secrets replaced
	Error      string // why the job failed or was cancelled, "" when it is done or running
	StartedAt  time.Time
	FinishedAt *time.Time // nil while the job runs
}

// Store is the part of the database that the runner uses. [*store.DB] is one.
type Store interface {
	CreateJob(ctx context.Context, j *store.Job) error
	JobByID(ctx context.Context, id string) (*store.Job, error)
	UpdateJobLog(ctx context.Context, id, log string) error
	FinishJob(ctx context.Context, id, status, log, errText string) error
	FailRunningJobs(ctx context.Context, errText string) (int64, error)
}

// A Runner runs jobs. It is safe for concurrent use.
type Runner struct {
	store      Store
	flushEvery time.Duration

	mu     sync.Mutex
	closed bool
	jobs   map[string]*job // the running jobs, by id
	nodes  map[string]bool // the nodes that are starting or running a job, or whose job has not been recorded as ended
	wg     sync.WaitGroup

	// giveUp is closed when Close stops waiting: the ends of jobs that the
	// database still refuses are not tried any more.
	giveUp     chan struct{}
	giveUpOnce sync.Once

	logger *slog.Logger // nil: the default logger, as it is when the runner logs; tests set one
}

// job is a running job.
type job struct {
	id, nodeID, kind string
	cancel           context.CancelCauseFunc

	mu    sync.Mutex
	scrub *scrubber // the secrets of the job, which AddSecrets replaces with more
	log   *jobLog
	ended bool // the function has returned, the log takes nothing more

	wake  chan struct{} // there are lines to save; it holds one signal
	done  chan struct{} // closed when the function has returned
	saved chan struct{} // closed when the saver has stopped
}

// New returns a runner over st. The jobs that st has as running are failed
// with [RestartedError] first: no process runs them any more, and a node with
// a running job could not start another one.
func New(ctx context.Context, st Store) (*Runner, error) {
	n, err := st.FailRunningJobs(ctx, RestartedError)
	if err != nil {
		return nil, fmt.Errorf("jobs: fail the jobs that were running: %w", err)
	}
	r := &Runner{store: st, flushEvery: FlushInterval, jobs: map[string]*job{}, nodes: map[string]bool{},
		giveUp: make(chan struct{})}
	if n > 0 {
		r.log().Info("jobs: jobs that were running when the panel stopped are failed", "count", n)
	}
	return r, nil
}

// log is the logger of the runner: the default logger as it is now, unless a
// test has set one.
func (r *Runner) log() *slog.Logger {
	if r.logger != nil {
		return r.logger
	}
	return slog.Default()
}

// Start starts a job of a kind, such as "install", on a node, and returns its
// id. It refuses with [ErrBusy] when the node is running a job.
//
// fn does the work. Its context ends when the job is cancelled ([Runner.Cancel])
// or the runner is closed, and what it writes to log is the log of the job. log
// may be written from several goroutines; once fn has returned, it takes
// nothing more. The job is done when fn returns nil (also when it was cancelled
// and finished anyway), cancelled when fn returns an error after
// [Runner.Cancel], and failed otherwise, with the error that fn returned. A
// panic in fn fails the job. The error of a cancelled job, and of one that
// the closing of the runner stopped, is [CancelledError] or [StoppedError],
// and then "; " and the [Notice] that the error of fn holds, when it holds one.
//
// secrets are what the job knows that must not show, such as a password or a
// private key: the log and the error of the job have them replaced by ***.
// Secrets shorter than [MinSecretLen] are not replaced, and one of several lines
// is replaced line by line. A job that learns more secrets as it runs adds them
// with [AddSecrets].
//
// ctx is that of the caller, typically a request: the job does not end with it,
// but sees its values.
func (r *Runner) Start(ctx context.Context, nodeID, kind string, secrets []string,
	fn func(ctx context.Context, log io.Writer) error) (jobID string, err error) {
	switch {
	case nodeID == "":
		return "", errors.New("jobs: a job needs a node")
	case kind == "":
		return "", errors.New("jobs: a job needs a kind")
	case fn == nil:
		return "", errors.New("jobs: a job needs a function")
	}

	// The node is taken while the job is created, which is not done under the
	// lock, as the database can take its time; Close waits for the start.
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return "", ErrClosed
	}
	if r.nodes[nodeID] {
		r.mu.Unlock()
		return "", fmt.Errorf("%w: node %s", ErrBusy, nodeID)
	}
	r.nodes[nodeID] = true
	r.wg.Add(1)
	r.mu.Unlock()

	rec := &store.Job{NodeID: nodeID, Kind: kind}
	err = r.store.CreateJob(ctx, rec)

	r.mu.Lock()
	if err != nil || r.closed {
		r.mu.Unlock()
		if err == nil {
			// Closed while the job was being created: it does not run.
			r.finish(rec.ID, StatusFailed, "", StoppedError)
			err = ErrClosed
		} else if errors.Is(err, store.ErrConflict) {
			err = fmt.Errorf("%w: node %s", ErrBusy, nodeID)
		} else {
			err = fmt.Errorf("jobs: start a job: %w", err)
		}
		r.mu.Lock()
		delete(r.nodes, nodeID)
		r.mu.Unlock()
		r.wg.Done()
		return "", err
	}
	scrub := newScrubber(secrets)
	jobCtx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
	j := &job{
		id: rec.ID, nodeID: nodeID, kind: kind, scrub: scrub, cancel: cancel,
		log:  newJobLog(scrub, MaxLog, maxPartial),
		wake: make(chan struct{}, 1), done: make(chan struct{}), saved: make(chan struct{}),
	}
	r.jobs[j.id] = j
	r.wg.Add(1) // for the saver; run has the count of the start
	r.mu.Unlock()
	go r.save(j)
	go r.run(jobCtx, j, fn)
	return j.id, nil
}

// Get returns a job, running or not, as the database has it: a running job
// with its log as it was last saved.
func (r *Runner) Get(ctx context.Context, id string) (Job, error) {
	rec, err := r.store.JobByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return Job{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return Job{}, fmt.Errorf("jobs: get a job: %w", err)
	}
	return Job{
		ID: rec.ID, NodeID: rec.NodeID, Kind: rec.Kind, Status: rec.Status, Log: rec.Log, Error: rec.Error,
		StartedAt: rec.StartedAt, FinishedAt: rec.FinishedAt,
	}, nil
}

// Cancel cancels a running job: the context of its function ends. The job
// ends once the function has returned. A job that this runner is not running
// is [ErrNotFound].
func (r *Runner) Cancel(id string) error {
	r.mu.Lock()
	j := r.jobs[id]
	r.mu.Unlock()
	if j == nil {
		return fmt.Errorf("%w: %s is not running", ErrNotFound, id)
	}
	j.cancel(errCancelled)
	return nil
}

// Close stops the runner. No job starts any more, the context of every running
// job ends, and Close waits until their functions have returned and their ends
// are recorded, as failed with [StoppedError] unless they finish their work, or
// until ctx ends. Then the runner stops trying to record the ends that the
// database has refused so far; a job whose end is not recorded is failed when
// the panel starts again. Close may be called more than once.
func (r *Runner) Close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	for _, j := range r.jobs {
		j.cancel(errStopped)
	}
	r.mu.Unlock()

	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		r.giveUpOnce.Do(func() { close(r.giveUp) })
		return fmt.Errorf("jobs: close: %w", ctx.Err())
	}
}

// run runs the function of a job and records its end.
func (r *Runner) run(ctx context.Context, j *job, fn func(context.Context, io.Writer) error) {
	defer r.wg.Done()
	// The outcome is taken at once: a cancel that comes after the function has
	// returned does not change it.
	err := r.call(ctx, j, fn)
	status, errText := outcome(ctx, err, j.scrubber())

	j.mu.Lock()
	j.ended = true
	j.log.end()
	text := j.log.String()
	j.mu.Unlock()
	close(j.done)
	<-j.saved // no save of the log comes after its end

	// The node stays busy until the end is recorded, as the database has it
	// running until then.
	r.finish(j.id, status, text, errText)
	j.cancel(nil)

	r.mu.Lock()
	delete(r.jobs, j.id)
	delete(r.nodes, j.nodeID)
	r.mu.Unlock()
}

// call calls fn and turns a panic into an error.
func (r *Runner) call(ctx context.Context, j *job, fn func(context.Context, io.Writer) error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			msg := j.scrubber().replace(fmt.Sprint(p))
			r.log().Error("jobs: a job panicked", "job", j.id, "kind", j.kind, "panic", msg, "stack", string(debug.Stack()))
			err = fmt.Errorf("the job panicked: %s", msg)
		}
	}()
	return fn(ctx, logWriter{j})
}

// outcome is the status and the error of a job whose function returned err.
func outcome(ctx context.Context, err error, s *scrubber) (status, errText string) {
	if err == nil {
		return StatusDone, ""
	}
	switch cause := context.Cause(ctx); {
	case errors.Is(cause, errCancelled):
		return StatusCancelled, withNotice(CancelledError, err, s)
	case errors.Is(cause, errStopped):
		return StatusFailed, withNotice(StoppedError, err, s)
	}
	return StatusFailed, errorText(err.Error(), s)
}

// errorText is the error of a job as it is kept: secrets replaced, valid
// UTF-8, at most maxError bytes.
func errorText(text string, s *scrubber) string {
	text = strings.ToValidUTF8(s.replace(text), replacement)
	if len(text) > maxError {
		text = strings.ToValidUTF8(text[:maxError], "") + "…"
	}
	return text
}

// withNotice is reason, the fixed error of a job that did not end by itself,
// with the notice that err holds, when it holds one.
func withNotice(reason string, err error, s *scrubber) string {
	var n *notice
	if !errors.As(err, &n) {
		return reason
	}
	return errorText(reason+"; "+n.err.Error(), s)
}

// Notice marks an error of a job as one that the admin has to know however the
// job ends, such as a file with a secret that is left on a server: the error
// of a job that is cancelled, or that the panel stops, says it too, which is
// otherwise only [CancelledError] or [StoppedError]. The error of a job that
// fails holds it anyway. Notice(nil) is nil.
func Notice(err error) error {
	if err == nil {
		return nil
	}
	return &notice{err: err}
}

type notice struct{ err error }

func (n *notice) Error() string { return n.err.Error() }
func (n *notice) Unwrap() error { return n.err }

// finish records the end of a job. When the database refuses, it tries again,
// further and further apart up to finishMaxDelay, until the database takes it,
// or until Close gives up.
func (r *Runner) finish(id, status, text, errText string) {
	delay := finishFirstDelay
	for attempt := 1; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		err := r.store.FinishJob(ctx, id, status, text, errText)
		cancel()
		switch {
		case err == nil:
			if attempt > 1 {
				r.log().Info("jobs: the end of a job is recorded", "job", id, "attempts", attempt)
			}
			return
		case errors.Is(err, store.ErrNotFound):
			// A panel that started on the same database since has failed it.
			r.log().Warn("jobs: the end of a job is not recorded: the database does not have it running", "job", id)
			return
		case attempt == 1 || attempt%10 == 0:
			// Every tenth failure shows, so that a long outage of the database
			// does too.
			r.log().Error("jobs: could not record the end of a job, it is tried again", "job", id, "status", status, "attempt", attempt, "err", err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-r.giveUp:
			timer.Stop()
			r.log().Error("jobs: the end of a job is not recorded; it is failed when the panel starts again", "job", id)
			return
		}
		delay = min(2*delay, finishMaxDelay)
	}
}

// save saves the log of a running job when lines have been added, at most every
// flushEvery, until the function of the job has returned.
func (r *Runner) save(j *job) {
	defer r.wg.Done()
	defer close(j.saved)
	var last time.Time
	for {
		select {
		case <-j.wake:
		case <-j.done:
			return
		}
		if wait := r.flushEvery - time.Since(last); !last.IsZero() && wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-j.done:
				timer.Stop()
				return
			}
		}
		last = time.Now()
		if !r.saveLog(j) {
			return
		}
	}
}

// saveLog saves the log of a job if lines have been added since the last save.
// It reports whether saving should go on: not when the database no longer has
// the job running.
func (r *Runner) saveLog(j *job) bool {
	j.mu.Lock()
	if !j.log.dirty {
		j.mu.Unlock()
		return true
	}
	text := j.log.String()
	j.log.dirty = false
	j.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	err := r.store.UpdateJobLog(ctx, j.id, text)
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNotFound):
		return false
	}
	r.log().Warn("jobs: could not save the log of a job, it is tried again", "job", j.id, "err", err)
	j.mu.Lock()
	j.log.dirty = true
	j.mu.Unlock()
	j.poke()
	return true
}

// scrubber returns the secrets of the job as they are now.
func (j *job) scrubber() *scrubber {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.scrub
}

// poke tells the saver that there are lines to save.
func (j *job) poke() {
	select {
	case j.wake <- struct{}{}:
	default:
	}
}

// A SecretAdder is the log of a running job, as the function of the job gets
// it (see [Runner.Start]). A job that learns secrets as it runs, such as tokens
// that it reads from a server, adds them, and from then on its log and its
// error have them replaced by *** as they have the secrets that the job started
// with. A secret has to be added before it is written: the lines that the log
// has taken are not looked at again.
type SecretAdder interface {
	AddSecrets(secrets ...string)
}

// AddSecrets adds secrets to the job whose log is log, when log is the log of a
// running job ([SecretAdder]). For any other writer, and for the log of a job
// that has ended, it does nothing.
func AddSecrets(log io.Writer, secrets ...string) {
	if s, ok := log.(SecretAdder); ok {
		s.AddSecrets(secrets...)
	}
}

// logWriter is the log that the function of a job writes to.
type logWriter struct{ j *job }

// AddSecrets is [SecretAdder.AddSecrets].
func (w logWriter) AddSecrets(secrets ...string) {
	j := w.j
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.ended || len(secrets) == 0 {
		return
	}
	j.scrub = j.scrub.with(secrets)
	j.log.setScrubber(j.scrub)
}

func (w logWriter) Write(p []byte) (int, error) {
	j := w.j
	j.mu.Lock()
	if j.ended {
		j.mu.Unlock()
		return 0, errEnded
	}
	j.log.write(p)
	dirty := j.log.dirty
	j.mu.Unlock()
	if dirty {
		j.poke()
	}
	return len(p), nil
}
