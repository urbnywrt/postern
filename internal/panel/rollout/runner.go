// Package rollout runs rollouts: a change that goes out one step at a time
// (Global Constraints, Rollouts). The runner drives every active rollout in a
// goroutine of its own, stores each transition before it acts on it, and
// resumes the active rollouts when the panel starts. What a step does is up to
// the executor of the kind of the rollout: engine and provider versions,
// engine switches, node updates.
package rollout

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// Request is what an admin asks for when starting a rollout.
type Request = panelv1.StartRolloutRequest

// Executor does what the steps of one kind of rollout do.
type Executor interface {
	// Plan checks a request and returns the nodes the rollout holds, its
	// steps and its items. It may fill in the fields of r it knows
	// (FromVersion, ToEngine, the canary in Options). A request it refuses is
	// an error that wraps ErrInvalid or ErrRefused.
	Plan(ctx context.Context, r *store.Rollout, req *Request) (nodeIDs []string, steps []store.RolloutStep, items []store.RolloutItem, err error)
	// Apply writes the target of the step into the data of the panel, raises
	// the generation of its node, notifies it, and sets s.Generation.
	Apply(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error
	// Check says whether the step is done; an error means that it failed
	// ([ErrSkipNode]: its node is skipped instead).
	Check(ctx context.Context, r *store.Rollout, s *store.RolloutStep) (done bool, err error)
	// Revert puts what the step changed back.
	Revert(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error
	// Complete completes the rollout once its last step is done.
	Complete(ctx context.Context, r *store.Rollout) error
}

// Preparer is an Executor that has work to do before the first step (fetch
// and check the artifacts): the rollout stays preparing until it is done, and
// fails when it fails.
type Preparer interface {
	Prepare(ctx context.Context, r *store.Rollout) error
}

// Skipper is an Executor that can leave the node of a step on its previous
// version, when its Check returned ErrSkipNode: it reverts what the step
// applied and defers its items.
type Skipper interface {
	Skip(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error
}

// Hooks run around every step (R5-5). A BeforeStep error fails the step
// before it is applied; an AfterStep error after a step that went through
// fails it and reverts it. After a revert AfterStep runs once more, with the
// step reverted, and its error is ignored. The timeout of a step starts once
// BeforeStep returns.
type Hooks struct {
	BeforeStep, AfterStep func(ctx context.Context, r *store.Rollout, s *store.RolloutStep) error
}

// Config is what a Runner works with.
type Config struct {
	DB *store.DB
	// Executors by key: KeyEngineVersion, KeyProviderVersion, KeySwitch,
	// KeyNode. Register adds more.
	Executors map[string]Executor
	Hooks     Hooks
	Log       *slog.Logger     // nil discards
	Now       func() time.Time // nil is time.Now
	// Tick is how often a rollout that waits looks again; 0 is 5 s.
	Tick time.Duration
	// HookTimeout is how long a hook may run; 0 is 30 s. A hook that runs
	// longer fails as if it returned an error (and is left to return).
	HookTimeout time.Duration
}

// The keys of the executors.
const (
	KeyEngineVersion   = "version:engine"
	KeyProviderVersion = "version:provider"
	KeySwitch          = "switch"
	KeyNode            = "node"
)

// DefaultPauseSeconds is the wait after a step of an auto rollout when the
// request names none.
const DefaultPauseSeconds = 120

const defaultTick = 5 * time.Second

const defaultHookTimeout = 30 * time.Second

// The events of rollouts.
const (
	EventStarted   = "rollout_started"
	EventStepDone  = "rollout_step_done"
	EventFailed    = "rollout_failed"
	EventCompleted = "rollout_completed"
	EventAborted   = "rollout_aborted"
	EventItemsKept = "rollout_items_kept"
	EventNodeKept  = "rollout_node_kept"
)

// The errors of the runner and the executors. The API answers ErrInvalid with
// invalid argument, ErrRefused and ErrState with failed precondition, and
// ErrNoExecutor with unimplemented.
var (
	ErrInvalid    = errors.New("rollout: invalid request")
	ErrRefused    = errors.New("rollout: refused")
	ErrState      = errors.New("rollout: not possible now")
	ErrNoExecutor = errors.New("rollout: this kind of rollout is not available")
	// ErrSkipNode is what Check returns when the node of the step is offline
	// and the rollout skips offline nodes.
	ErrSkipNode = errors.New("rollout: the node is offline and skipped")
	// errMoveNow is what Plan returns for a version rollout that has nothing
	// to roll out through (no proxy follows the channel) and whose target it
	// checked: Start completes it at once, with no steps, which moves the
	// channel.
	errMoveNow = errors.New("rollout: the channel moves at once")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// abortingError is the error of a rollout while Abort reverts its steps: a
// rollout found so after a restart is failed, and Abort can be asked again.
const abortingError = "being aborted"

// Runner drives rollouts.
type Runner struct {
	db          *store.DB
	hooks       Hooks
	log         *slog.Logger
	now         func() time.Time
	tick        time.Duration
	hookTimeout time.Duration

	mu        sync.Mutex
	executors map[string]Executor
	locks     map[string]*sync.Mutex        // one per rollout: its transitions and the API calls on it
	wakes     map[string]chan struct{}      // the rollouts that a goroutine drives
	hooksRun  map[string]context.CancelFunc // the hook that runs, by rollout: Abort and Pause end it
	ctx       context.Context               // of Run, nil while Run does not run
	wg        sync.WaitGroup
}

// NewRunner returns a runner; Run drives the rollouts.
func NewRunner(cfg Config) *Runner {
	r := &Runner{
		db: cfg.DB, hooks: cfg.Hooks, log: cfg.Log, now: cfg.Now, tick: cfg.Tick,
		executors: map[string]Executor{}, locks: map[string]*sync.Mutex{}, wakes: map[string]chan struct{}{},
		hooksRun: map[string]context.CancelFunc{},
	}
	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.tick <= 0 {
		r.tick = defaultTick
	}
	r.hookTimeout = cmp.Or(cfg.HookTimeout, defaultHookTimeout)
	for k, e := range cfg.Executors {
		r.executors[k] = e
	}
	return r
}

// Register adds the executor of a kind of rollout.
func (r *Runner) Register(key string, e Executor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.executors[key] = e
}

// isEngine reports whether a component is an engine (its version rollouts
// change proxies) rather than a provider.
func isEngine(component string) bool {
	return component == store.EngineTelemt || component == store.EngineMtg
}

// keyOf is the key of the executor of a rollout.
func keyOf(kind, component string) string {
	switch kind {
	case store.RolloutVersion:
		if isEngine(component) {
			return KeyEngineVersion
		}
		return KeyProviderVersion
	case store.RolloutSwitch:
		return KeySwitch
	case store.RolloutNode:
		return KeyNode
	}
	return ""
}

func (r *Runner) executor(kind, component string) Executor {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.executors[keyOf(kind, component)]
}

func (r *Runner) lock(id string) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.locks[id]
	if m == nil {
		m = &sync.Mutex{}
		r.locks[id] = m
	}
	return m
}

// Run resumes the active rollouts and drives them, and those started later,
// until ctx is done; it returns once their goroutines have stopped.
func (r *Runner) Run(ctx context.Context) {
	r.mu.Lock()
	if r.ctx != nil {
		r.mu.Unlock()
		return
	}
	r.ctx = ctx
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.ctx = nil
		r.mu.Unlock()
		r.wg.Wait()
	}()
	for {
		list, err := r.db.ListRollouts(ctx, true, 0)
		if err == nil {
			for _, ro := range list {
				r.spawn(ro.ID)
			}
			r.finishCompletions(ctx)
			break
		}
		r.log.Error("could not read the active rollouts; trying again", "err", err)
		if !sleep(ctx, r.tick) {
			return
		}
	}
	<-ctx.Done()
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// spawn starts the goroutine of a rollout, unless Run does not run or one
// drives it already (then it is woken).
func (r *Runner) spawn(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx == nil {
		return
	}
	if ch := r.wakes[id]; ch != nil {
		nudge(ch)
		return
	}
	ch := make(chan struct{}, 1)
	r.wakes[id] = ch
	r.wg.Add(1)
	go r.drive(r.ctx, id, ch)
}

func nudge(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// wake has the goroutine of a rollout look at it now, starting one if none
// runs.
func (r *Runner) wake(id string) { r.spawn(id) }

// drive is the goroutine of a rollout: it advances the rollout until it is
// over or ctx is done.
func (r *Runner) drive(ctx context.Context, id string, wake chan struct{}) {
	defer r.wg.Done()
	defer func() {
		r.mu.Lock()
		delete(r.wakes, id)
		r.mu.Unlock()
	}()
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		over, again := r.advance(ctx, id)
		if over || ctx.Err() != nil {
			return
		}
		if again {
			continue
		}
		t.Reset(r.tick)
		select {
		case <-ctx.Done():
			return
		case <-wake:
			if !t.Stop() {
				<-t.C
			}
		case <-t.C:
		}
	}
}

// advance makes one transition of a rollout. over says that the rollout is
// over (its goroutine ends), again that the next transition can be made at
// once.
func (r *Runner) advance(ctx context.Context, id string) (over, again bool) {
	ro, _, _, err := r.db.Rollout(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return true, false
	}
	if err != nil {
		r.log.Error("could not read a rollout", "rollout", id, "err", err)
		return false, false
	}
	switch ro.Status {
	case store.RolloutCompleted:
		// A completion that failed after it was stored is run to its end.
		r.finishCompletion(ctx, ro)
		return !r.unfinished(ctx, ro), false
	case store.RolloutAborted:
		return true, false
	}
	ex := r.executor(ro.Kind, ro.Component)
	if ex == nil {
		r.log.Warn("no executor for a rollout; it waits for a panel that has one", "rollout", id, "kind", ro.Kind, "component", ro.Component)
		return true, false
	}
	if ro.Status == store.RolloutPreparing {
		return false, r.prepare(ctx, ro, ex)
	}
	mu := r.lock(id)
	mu.Lock()
	defer mu.Unlock()
	return r.transition(ctx, id, ex)
}

// prepare runs the preparation of a rollout, without its lock (it may take
// minutes), and then stores the outcome if the rollout is still preparing.
func (r *Runner) prepare(ctx context.Context, ro *store.Rollout, ex Executor) (again bool) {
	var perr error
	if p, ok := ex.(Preparer); ok {
		perr = p.Prepare(ctx, ro)
	}
	if ctx.Err() != nil {
		return false
	}
	mu := r.lock(ro.ID)
	mu.Lock()
	defer mu.Unlock()
	cur, _, _, err := r.db.Rollout(ctx, ro.ID)
	if err != nil {
		r.log.Error("could not read a rollout", "rollout", ro.ID, "err", err)
		return false
	}
	if cur.Status != store.RolloutPreparing {
		return true // aborted meanwhile
	}
	if perr != nil {
		cur.Status, cur.Error = store.RolloutFailed, "preparing: "+perr.Error()
		if err := r.db.UpdateRollout(ctx, cur); err != nil {
			r.log.Error("could not store a rollout", "rollout", cur.ID, "err", err)
			return false
		}
		r.event(ctx, cur, "", EventFailed, "error", "rollout failed: "+cur.Error, nil)
		return false
	}
	cur.Status, cur.CurrentStep, cur.Error = store.RolloutRunning, 0, ""
	if err := r.db.UpdateRollout(ctx, cur); err != nil {
		r.log.Error("could not store a rollout", "rollout", cur.ID, "err", err)
		return false
	}
	return true
}

// transition makes one transition of a rollout that is running, paused or
// failed, under its lock.
func (r *Runner) transition(ctx context.Context, id string, ex Executor) (over, again bool) {
	ro, steps, _, err := r.db.Rollout(ctx, id)
	if err != nil {
		r.log.Error("could not read a rollout", "rollout", id, "err", err)
		return false, false
	}
	switch ro.Status {
	case store.RolloutCompleted, store.RolloutAborted:
		return true, false
	case store.RolloutPreparing:
		return false, true
	case store.RolloutFailed:
		return false, false // until Retry or Abort
	}
	if int(ro.CurrentStep) >= len(steps) {
		return r.complete(ctx, ro, ex)
	}
	st := &steps[ro.CurrentStep]
	switch st.Status {
	case store.StepPending:
		if ro.Status == store.RolloutPaused {
			return false, false
		}
		if ro.ResumeAt != nil && r.now().Before(*ro.ResumeAt) {
			return false, false
		}
		return r.startStep(ctx, ro, st, ex)
	case store.StepApplying:
		return r.apply(ctx, ro, st, ex)
	case store.StepVerifying:
		return r.check(ctx, ro, st, len(steps), ex)
	case store.StepDone, store.StepSkipped:
		return r.next(ctx, ro, len(steps), ex)
	case store.StepFailed:
		if st.StartedAt == nil { // its BeforeStep failed: nothing was applied
			r.failRollout(ctx, ro, st, st.Error)
			return false, false
		}
		return r.revert(ctx, ro, st, ex, st.Error)
	case store.StepReverted:
		r.failRollout(ctx, ro, st, st.Error)
		return false, false
	}
	r.log.Error("a step of a rollout has an unknown status", "rollout", id, "step", st.Index, "status", st.Status)
	return false, false
}

func (r *Runner) storeStep(ctx context.Context, st *store.RolloutStep) bool {
	if err := r.db.UpdateRolloutStep(ctx, st); err != nil {
		r.log.Error("could not store a rollout step", "rollout", st.RolloutID, "step", st.Index, "err", err)
		return false
	}
	return true
}

func (r *Runner) storeRollout(ctx context.Context, ro *store.Rollout) bool {
	if err := r.db.UpdateRollout(ctx, ro); err != nil {
		r.log.Error("could not store a rollout", "rollout", ro.ID, "err", err)
		return false
	}
	return true
}

func (r *Runner) startStep(ctx context.Context, ro *store.Rollout, st *store.RolloutStep, ex Executor) (over, again bool) {
	if ro.ResumeAt != nil {
		ro.ResumeAt = nil
		if !r.storeRollout(ctx, ro) {
			return false, false
		}
	}
	if h := r.hooks.BeforeStep; h != nil {
		if err := r.runHook(ctx, h, ro, st, false); err != nil {
			if ctx.Err() != nil {
				return false, false
			}
			if errors.Is(err, errHookCut) {
				return false, true // the next transition goes on from what is stored
			}
			now := r.now()
			st.Status, st.Error, st.FinishedAt = store.StepFailed, "before-step hook: "+err.Error(), &now
			if r.storeStep(ctx, st) {
				r.failRollout(ctx, ro, st, st.Error)
			}
			return false, false
		}
	}
	now := r.now() // the timeout of the step runs from here
	st.Status, st.StartedAt, st.Generation, st.Error, st.FinishedAt = store.StepApplying, &now, 0, "", nil
	if !r.storeStep(ctx, st) {
		return false, false
	}
	return r.apply(ctx, ro, st, ex)
}

func (r *Runner) apply(ctx context.Context, ro *store.Rollout, st *store.RolloutStep, ex Executor) (over, again bool) {
	if st.Generation == 0 {
		if err := ex.Apply(ctx, ro, st); err != nil {
			if ctx.Err() != nil {
				return false, false
			}
			return r.failStep(ctx, ro, st, ex, "apply: "+err.Error())
		}
	}
	st.Status = store.StepVerifying
	if !r.storeStep(ctx, st) {
		return false, false
	}
	return false, true
}

func (r *Runner) check(ctx context.Context, ro *store.Rollout, st *store.RolloutStep, n int, ex Executor) (over, again bool) {
	done, err := ex.Check(ctx, ro, st)
	if ctx.Err() != nil {
		return false, false
	}
	if errors.Is(err, ErrSkipNode) {
		if canaryStep(ro, st) { // a canary is never skipped
			return r.failStep(ctx, ro, st, ex, "the node of the canary is offline")
		}
		return r.skip(ctx, ro, st, n, ex)
	}
	if err != nil {
		return r.failStep(ctx, ro, st, ex, err.Error())
	}
	if !done {
		return false, false
	}
	if h := r.hooks.AfterStep; h != nil {
		if err := r.runHook(ctx, h, ro, st, true); err != nil {
			if ctx.Err() != nil {
				return false, false
			}
			if errors.Is(err, errHookCut) {
				return false, true
			}
			return r.failStep(ctx, ro, st, ex, "after-step hook: "+err.Error())
		}
	}
	now := r.now()
	st.Status, st.FinishedAt, st.Error = store.StepDone, &now, ""
	if !r.storeStep(ctx, st) {
		return false, false
	}
	r.event(ctx, ro, st.NodeID, EventStepDone, "info", fmt.Sprintf("rollout step %d of %d is done", st.Index+1, n),
		map[string]string{"step": strconv.FormatUint(uint64(st.Index), 10)})
	return r.next(ctx, ro, n, ex)
}

func (r *Runner) skip(ctx context.Context, ro *store.Rollout, st *store.RolloutStep, n int, ex Executor) (over, again bool) {
	sk, ok := ex.(Skipper)
	if !ok {
		return r.failStep(ctx, ro, st, ex, "the node is offline")
	}
	if err := sk.Skip(ctx, ro, st); err != nil {
		r.log.Error("could not skip the node of a rollout step; trying again", "rollout", ro.ID, "step", st.Index, "err", err)
		return false, false
	}
	now := r.now()
	st.Status, st.FinishedAt, st.Error = store.StepSkipped, &now, "the node was offline; its proxies stay on their previous version"
	if !r.storeStep(ctx, st) {
		return false, false
	}
	r.event(ctx, ro, st.NodeID, EventStepDone, "warning", fmt.Sprintf("rollout step %d of %d skipped: its node is offline", st.Index+1, n),
		map[string]string{"step": strconv.FormatUint(uint64(st.Index), 10), "status": store.StepSkipped})
	return r.next(ctx, ro, n, ex)
}

// failStep stores the step failed, then reverts it.
func (r *Runner) failStep(ctx context.Context, ro *store.Rollout, st *store.RolloutStep, ex Executor, cause string) (over, again bool) {
	now := r.now()
	st.Status, st.Error, st.FinishedAt = store.StepFailed, cause, &now
	if !r.storeStep(ctx, st) {
		return false, false
	}
	return r.revert(ctx, ro, st, ex, cause)
}

// revert reverts a failed step, runs AfterStep (its error ignored), and fails
// the rollout. A revert that does not go through is tried again at the next
// tick: the step stays failed and the rollout running.
func (r *Runner) revert(ctx context.Context, ro *store.Rollout, st *store.RolloutStep, ex Executor, cause string) (over, again bool) {
	if err := ex.Revert(ctx, ro, st); err != nil {
		r.log.Error("could not revert a failed rollout step; trying again", "rollout", ro.ID, "step", st.Index, "err", err)
		return false, false
	}
	st.Status = store.StepReverted
	// Stored before the hook, which runs without the lock: an Abort meanwhile
	// sees the step reverted.
	if !r.storeStep(ctx, st) {
		return false, false
	}
	if h := r.hooks.AfterStep; h != nil {
		if err := r.runHook(ctx, h, ro, st, true); err != nil {
			if ctx.Err() != nil || errors.Is(err, errHookCut) {
				return false, true
			}
			r.log.Warn("the after-step hook of a reverted step failed; ignored", "rollout", ro.ID, "step", st.Index, "err", err)
		}
	}
	r.failRollout(ctx, ro, st, cause)
	return false, false
}

func (r *Runner) failRollout(ctx context.Context, ro *store.Rollout, st *store.RolloutStep, cause string) {
	ro.Status, ro.ResumeAt = store.RolloutFailed, nil
	ro.Error = fmt.Sprintf("step %d: %s", st.Index+1, cmp.Or(cause, "failed"))
	if !r.storeRollout(ctx, ro) {
		return
	}
	r.event(ctx, ro, st.NodeID, EventFailed, "error", "rollout failed at "+ro.Error,
		map[string]string{"step": strconv.FormatUint(uint64(st.Index), 10)})
}

// next moves a rollout past a step that is over: to completion after the last
// one, else to the next step, paused (manual) or after the pause (auto).
func (r *Runner) next(ctx context.Context, ro *store.Rollout, n int, ex Executor) (over, again bool) {
	if int(ro.CurrentStep)+1 >= n {
		return r.complete(ctx, ro, ex)
	}
	ro.CurrentStep++
	switch {
	case ro.Status == store.RolloutPaused: // paused while the step ran: it stays so
	case ro.Mode == store.RolloutModeManual:
		ro.Status = store.RolloutPaused
	default:
		at := r.now().Add(time.Duration(ro.PauseSeconds) * time.Second)
		ro.ResumeAt = &at
	}
	if !r.storeRollout(ctx, ro) {
		return false, false
	}
	return false, true
}

func (r *Runner) complete(ctx context.Context, ro *store.Rollout, ex Executor) (over, again bool) {
	if err := ex.Complete(ctx, ro); err != nil {
		r.log.Error("could not complete a rollout; trying again", "rollout", ro.ID, "err", err)
		return false, false
	}
	cur, _, _, err := r.db.Rollout(ctx, ro.ID)
	if err != nil {
		r.log.Error("could not read a rollout", "rollout", ro.ID, "err", err)
		return false, false
	}
	if cur.Status != store.RolloutCompleted {
		cur.Status, cur.ResumeAt = store.RolloutCompleted, nil
		if !r.storeRollout(ctx, cur) {
			return false, false
		}
	}
	r.event(ctx, cur, "", EventCompleted, "info", "rollout completed", nil)
	return true, false
}

// completionWindow is how far back Run looks for completed rollouts whose
// completion did not run to its end: well within the retention of events
// (30 days), whose rollout_completed event is the marker.
const completionWindow = 7 * 24 * time.Hour

// unfinished reports whether a completed rollout lacks its rollout_completed
// event: the panel stopped after the completion was stored and before what
// follows it (telling the nodes, the events) was done.
func (r *Runner) unfinished(ctx context.Context, ro *store.Rollout) bool {
	if ro.Status != store.RolloutCompleted {
		return false
	}
	has, err := r.db.HasEvent(ctx, EventCompleted, "rollout", ro.ID)
	if err != nil {
		r.log.Error("could not look for the completion of a rollout", "rollout", ro.ID, "err", err)
		return false
	}
	return !has
}

// finishCompletion runs the completion of a completed rollout again, when it
// did not run to its end; Complete is idempotent.
func (r *Runner) finishCompletion(ctx context.Context, ro *store.Rollout) {
	if !r.unfinished(ctx, ro) {
		return
	}
	ex := r.executor(ro.Kind, ro.Component)
	if ex == nil {
		return
	}
	mu := r.lock(ro.ID)
	mu.Lock()
	defer mu.Unlock()
	r.log.Info("finishing the completion of a rollout", "rollout", ro.ID)
	r.complete(ctx, ro, ex)
}

// finishCompletions finishes the completions that a stop of the panel cut
// short, for the rollouts completed within the window.
func (r *Runner) finishCompletions(ctx context.Context) {
	list, err := r.db.ListRollouts(ctx, false, 0)
	if err != nil {
		r.log.Error("could not read the rollouts", "err", err)
		return
	}
	cut := r.now().Add(-completionWindow)
	for _, ro := range list {
		if ro.FinishedAt != nil && ro.FinishedAt.After(cut) {
			r.finishCompletion(ctx, ro)
		}
	}
}

// event records an event of a rollout. A failure is logged.
func (r *Runner) event(ctx context.Context, ro *store.Rollout, nodeID, kind, severity, msg string, details map[string]string) {
	d := map[string]string{"rollout": ro.ID, "kind": ro.Kind, "component": ro.Component}
	if ro.Channel != "" {
		d["channel"] = ro.Channel
	}
	if ro.ToVersion != "" {
		d["to_version"] = ro.ToVersion
	}
	for k, v := range details {
		d[k] = v
	}
	e := &store.Event{TS: r.now(), NodeID: nodeID, Kind: kind, Severity: severity, Message: msg, Details: d}
	if err := r.db.AppendEvent(context.WithoutCancel(ctx), e); err != nil {
		r.log.Error("could not record a rollout event", "kind", kind, "rollout", ro.ID, "err", err)
	}
}

// Start plans a rollout, stores it (refused with a *store.RolloutConflict
// when another rollout holds its channel or one of its nodes) and starts
// driving it.
func (r *Runner) Start(ctx context.Context, admin string, req *Request) (*store.Rollout, error) {
	kind := req.GetKind()
	switch kind {
	case store.RolloutVersion, store.RolloutSwitch, store.RolloutNode:
	default:
		return nil, invalid("kind %.32q is not %s, %s or %s", kind, store.RolloutVersion, store.RolloutSwitch, store.RolloutNode)
	}
	mode := cmp.Or(req.GetMode(), store.RolloutModeManual)
	if mode != store.RolloutModeManual && mode != store.RolloutModeAuto {
		return nil, invalid("mode %.32q is not %s or %s", mode, store.RolloutModeManual, store.RolloutModeAuto)
	}
	ex := r.executor(kind, req.GetComponent())
	if ex == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoExecutor, keyOf(kind, req.GetComponent()))
	}
	now := r.now()
	ro := &store.Rollout{
		Kind: kind, Component: req.GetComponent(), Channel: req.GetChannel(), ToVersion: req.GetToVersion(),
		Mode: mode, PauseSeconds: cmp.Or(req.GetPauseSeconds(), DefaultPauseSeconds), Status: store.RolloutPreparing,
		Options: store.RolloutOptions{
			Agent: req.GetAgent(), Edge: req.GetEdge(), SkipOffline: req.GetSkipOffline(),
			CanaryProxyID: req.GetCanaryProxyId(), CanaryNodeID: req.GetCanaryNodeId(),
		},
		CreatedBy: admin, CreatedAt: now, UpdatedAt: now,
	}
	nodeIDs, steps, items, err := ex.Plan(ctx, ro, req)
	moveNow := errors.Is(err, errMoveNow)
	if err != nil && !moveNow {
		return nil, err
	}
	if len(steps) == 0 && !moveNow {
		return nil, refuse("the rollout has nothing to do")
	}
	if moveNow {
		// Nothing to prepare or to step through: the rollout runs only its
		// completion, which moves the channel.
		ro.Status = store.RolloutRunning
	}
	if err := r.db.CreateRollout(ctx, ro, nodeIDs, steps, items); err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("rollout started: %d steps", len(steps))
	if moveNow {
		msg = fmt.Sprintf("the channel moved to %s at once: no proxy follows it", ro.ToVersion)
	}
	r.event(ctx, ro, "", EventStarted, "info", msg, map[string]string{"admin": admin})
	r.log.Info("rollout started", "rollout", ro.ID, "kind", ro.Kind, "component", ro.Component, "channel", ro.Channel, "to", ro.ToVersion, "steps", len(steps))
	if moveNow {
		return r.completeNow(ctx, ro, ex), nil
	}
	r.wake(ro.ID)
	return ro, nil
}

// completeNow completes a stored rollout without steps at once. A completion
// that fails is left to the runner, which tries again; the rollout is
// returned as it is stored then.
func (r *Runner) completeNow(ctx context.Context, ro *store.Rollout, ex Executor) *store.Rollout {
	mu := r.lock(ro.ID)
	mu.Lock()
	over, _ := r.transition(ctx, ro.ID, ex)
	mu.Unlock()
	if !over {
		r.wake(ro.ID)
	}
	if cur, _, _, err := r.db.Rollout(ctx, ro.ID); err == nil {
		return cur
	}
	return ro
}

// load reads a rollout that is not over, for an API call.
func (r *Runner) load(ctx context.Context, id string) (*store.Rollout, []store.RolloutStep, error) {
	ro, steps, _, err := r.db.Rollout(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if ro.Status == store.RolloutCompleted || ro.Status == store.RolloutAborted {
		return nil, nil, fmt.Errorf("%w: rollout %s is %s", ErrState, id, ro.Status)
	}
	return ro, steps, nil
}

// Continue runs the next step of a paused rollout, or the next step of an
// auto rollout at once instead of after its pause.
func (r *Runner) Continue(ctx context.Context, id string) error {
	mu := r.lock(id)
	mu.Lock()
	defer mu.Unlock()
	ro, _, err := r.load(ctx, id)
	if err != nil {
		return err
	}
	switch {
	case ro.Status == store.RolloutPaused:
		ro.Status, ro.ResumeAt = store.RolloutRunning, nil
	case ro.Status == store.RolloutRunning && ro.ResumeAt != nil:
		ro.ResumeAt = nil
	default:
		return fmt.Errorf("%w: rollout %s is %s, not paused", ErrState, id, ro.Status)
	}
	if err := r.db.UpdateRollout(ctx, ro); err != nil {
		return err
	}
	r.wake(id)
	return nil
}

// Pause stops a running rollout after its current step.
func (r *Runner) Pause(ctx context.Context, id string) error {
	mu := r.lock(id)
	mu.Lock()
	defer mu.Unlock()
	ro, _, err := r.load(ctx, id)
	if err != nil {
		return err
	}
	if ro.Status != store.RolloutRunning {
		return fmt.Errorf("%w: rollout %s is %s, not running", ErrState, id, ro.Status)
	}
	ro.Status, ro.ResumeAt = store.RolloutPaused, nil
	if err := r.db.UpdateRollout(ctx, ro); err != nil {
		return err
	}
	// A step's diagnostics do not hold the pause: its hook is cut short, and
	// only now, so that the hook finds the rollout paused and its step goes
	// through (runHook). The lock is free while a hook runs.
	r.cutHook(id)
	r.wake(id)
	return nil
}

// Retry runs the step of a failed rollout that failed again, or its
// preparation when that failed.
func (r *Runner) Retry(ctx context.Context, id string) error {
	mu := r.lock(id)
	mu.Lock()
	defer mu.Unlock()
	ro, steps, err := r.load(ctx, id)
	if err != nil {
		return err
	}
	if ro.Status != store.RolloutFailed {
		return fmt.Errorf("%w: rollout %s is %s, not failed", ErrState, id, ro.Status)
	}
	if ro.Error == abortingError {
		return fmt.Errorf("%w: rollout %s was being aborted; abort it again", ErrState, id)
	}
	ro.Status = store.RolloutRunning
	if int(ro.CurrentStep) < len(steps) {
		st := &steps[ro.CurrentStep]
		switch st.Status {
		case store.StepFailed, store.StepReverted:
			st.Status, st.Generation, st.Error, st.StartedAt, st.FinishedAt = store.StepPending, 0, "", nil, nil
			if err := r.db.UpdateRolloutStep(ctx, st); err != nil {
				return err
			}
		case store.StepPending:
			if ro.CurrentStep == 0 {
				ro.Status = store.RolloutPreparing // the preparation failed
			}
		}
	}
	ro.Error, ro.ResumeAt = "", nil
	if err := r.db.UpdateRollout(ctx, ro); err != nil {
		return err
	}
	r.wake(id)
	return nil
}

// Abort ends a rollout: every step that was applied is reverted, the last
// first, and the rollout is aborted.
func (r *Runner) Abort(ctx context.Context, id string) error {
	r.cutHook(id) // a step's diagnostics do not hold the abort
	mu := r.lock(id)
	mu.Lock()
	defer mu.Unlock()
	ro, steps, err := r.load(ctx, id)
	if err != nil {
		return err
	}
	// A rollout of a kind that this panel has no executor for (one that a
	// later panel started) is aborted without a revert: nothing here can
	// revert it.
	ex := r.executor(ro.Kind, ro.Component)
	if ex == nil {
		r.log.Warn("aborting a rollout that this panel has no executor for; its steps are not reverted",
			"rollout", id, "kind", ro.Kind, "component", ro.Component)
		steps = nil
	}
	// Stored first: a rollout found so after a restart is not driven on.
	ro.Status, ro.Error, ro.ResumeAt = store.RolloutFailed, abortingError, nil
	if err := r.db.UpdateRollout(ctx, ro); err != nil {
		return err
	}
	for i := len(steps) - 1; i >= 0; i-- {
		st := &steps[i]
		switch st.Status {
		case store.StepApplying, store.StepVerifying, store.StepDone, store.StepFailed:
		default:
			continue
		}
		if st.Status == store.StepFailed && st.StartedAt == nil {
			continue // its BeforeStep failed: nothing was applied
		}
		if err := ex.Revert(ctx, ro, st); err != nil {
			return fmt.Errorf("revert step %d: %w", st.Index+1, err)
		}
		if st.Status != store.StepFailed && st.FinishedAt == nil {
			now := r.now()
			st.FinishedAt = &now
		}
		st.Status = store.StepReverted
		if err := r.db.UpdateRolloutStep(ctx, st); err != nil {
			return err
		}
	}
	ro.Status, ro.Error = store.RolloutAborted, ""
	if err := r.db.UpdateRollout(ctx, ro); err != nil {
		return err
	}
	r.event(ctx, ro, "", EventAborted, "warning", "rollout aborted; its applied steps were reverted", nil)
	r.wake(id)
	return nil
}

// errHookCut is a hook after which the rollout or its step is not as it
// was: an Abort or a Pause came while it ran. The transition stops there,
// and the next one goes on from what is stored.
var errHookCut = errors.New("rollout: changed while a hook ran")

// cutHook ends the context of the hook of a rollout that runs, if any.
func (r *Runner) cutHook(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cancel := r.hooksRun[id]; cancel != nil {
		cancel()
	}
}

// runHook runs a hook with a timeout: a hook that does not return in time is
// an error, and is left running to return when it does. The hook gets copies
// of the rollout and the step, so that one left running races with nothing.
//
// The caller holds the rollout's lock; runHook lets it go while the hook
// runs, so that Abort, Pause and Retry never wait for a hook, and Abort and
// Pause end the hook's context. With the lock taken again it reads the
// rollout: when it or the step changed meanwhile the answer is errHookCut,
// except a Pause after the step's work (pauseOK: the step is done, then the
// rollout pauses). Otherwise ro is the stored rollout again.
func (r *Runner) runHook(ctx context.Context, h func(context.Context, *store.Rollout, *store.RolloutStep) error, ro *store.Rollout, st *store.RolloutStep, pauseOK bool) error {
	hctx, cut := context.WithCancel(ctx)
	defer cut()
	r.mu.Lock()
	r.hooksRun[ro.ID] = cut
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.hooksRun, ro.ID)
		r.mu.Unlock()
	}()
	tctx, cancel := context.WithTimeout(hctx, r.hookTimeout)
	defer cancel()
	roc, stc := *ro, *st
	done := make(chan error, 1)
	mu := r.lock(ro.ID)
	mu.Unlock()
	go func() { done <- h(tctx, &roc, &stc) }()
	var err error
	select {
	case err = <-done:
	case <-tctx.Done():
		if hctx.Err() == nil {
			r.log.Warn("a rollout hook did not return in time", "rollout", ro.ID, "step", st.Index, "timeout", r.hookTimeout)
			err = fmt.Errorf("did not return within %s", r.hookTimeout)
		}
	}
	mu.Lock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	cur, steps, _, rerr := r.db.Rollout(ctx, ro.ID)
	if rerr != nil {
		r.log.Error("could not read a rollout after its hook", "rollout", ro.ID, "err", rerr)
		return errHookCut
	}
	// A pause (or a continue) of the rollout while the step's work is over.
	paused := pauseOK && cur.Status != ro.Status && pausable(ro.Status) && pausable(cur.Status)
	if (cur.Status != ro.Status && !paused) || cur.CurrentStep != ro.CurrentStep ||
		int(st.Index) >= len(steps) || steps[st.Index].Status != st.Status {
		return errHookCut
	}
	if hctx.Err() != nil && !paused {
		return errHookCut // cut short, though nothing changed: look again
	}
	*ro = *cur
	if paused {
		return nil // the hooks inform; a pause only cut them short
	}
	return err
}

// pausable is a status between which and the other the work of a step goes
// on: running and paused.
func pausable(status string) bool {
	return status == store.RolloutRunning || status == store.RolloutPaused
}
