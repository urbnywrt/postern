package diag

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
)

const (
	// liveEvery is how often the light set goes out, live-only, when nothing
	// changed.
	liveEvery = 15 * time.Minute
	// lightTick is how often the light loop looks for checks that are due.
	lightTick = time.Second
	// jitter is the share of a cadence a light check's turn moves by, either
	// way.
	jitter = 0.10
	// grace is how long a check whose time is up may take to return what it
	// found before the runner answers for it.
	grace = 500 * time.Millisecond
)

// Runner runs the checks of the catalogue: full runs of a scope, one at a
// time, and the light loop.
type Runner struct {
	env    Env
	checks []Check
	busy   atomic.Bool

	// Test seams.
	slots     int
	overall   time.Duration
	tick      time.Duration
	liveEvery time.Duration
	jitter    func(every time.Duration) time.Duration
}

// NewRunner makes the runner of checks with env.
func NewRunner(env Env, checks []Check) *Runner {
	return &Runner{env: env, checks: checks, slots: Slots, overall: RunTimeout, tick: lightTick, liveEvery: liveEvery, jitter: jittered}
}

// jittered is a random move of a turn of a check of cadence every: within
// ±10 % of it.
func jittered(every time.Duration) time.Duration {
	span := int64(float64(every) * jitter)
	if span <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(2*span+1) - span) //nolint:gosec // scheduling jitter, not a secret
}

// prepare is the environment of a run: the stored desired state and runtime
// record (none when they cannot be read) and the scrubber made of them.
func (r *Runner) prepare() Env {
	env := r.env
	env.Desired, env.Runtime = nil, nil
	if env.Store != nil {
		if st, err := env.Store.LoadDesired(); err == nil {
			env.Desired = st
		}
		if rt, err := env.Store.LoadRuntime(); err == nil {
			env.Runtime = rt
		}
	}
	if env.Scrubber != nil {
		env.Scrub = env.Scrubber(env.Desired, env.Runtime)
	} else {
		env.Scrub = NewScrubber(env.Desired, env.Runtime, nil)
	}
	return env
}

// done is what a check returned.
type done struct {
	check   Check
	results []Result
}

// Run runs every check of scope ("node" or "proxy:<id>"), up to 16 at a
// time, each within its timeout, 3 minutes at most in all, and emits the
// results as they come. It returns ErrBusy while another full run is under
// way and an error wrapping ErrScope for a scope it does not know. emit is
// called from Run's goroutine only.
func (r *Runner) Run(ctx context.Context, scopeName string, emit func(Result)) error {
	if !r.busy.CompareAndSwap(false, true) {
		return ErrBusy
	}
	defer r.busy.Store(false)
	env := r.prepare()
	sc, err := parseScope(scopeName, env.Desired)
	if err != nil {
		return fmt.Errorf("%w %q", ErrScope, scopeName)
	}
	env.scope = sc

	ctx, cancel := context.WithTimeout(ctx, r.overall)
	defer cancel()
	out := make(chan done, len(r.checks))
	sem := make(chan struct{}, max(r.slots, 1))
	budget := MaxRunEvidence
	finish := func(d done) {
		for _, res := range d.results {
			res = finalize(d.check, res, &env, &budget)
			if env.Wants(res.Target) {
				emit(res)
			}
		}
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	pending, started := 0, 0
	for _, c := range r.checks {
		acquired := false
		for !acquired && ctx.Err() == nil {
			select {
			case sem <- struct{}{}:
				acquired = true
			case d := <-out:
				pending--
				finish(d)
			case <-ctx.Done():
			}
		}
		if !acquired {
			break
		}
		pending++
		started++
		wg.Go(func() {
			defer func() { <-sem }()
			out <- done{c, runOne(ctx, c, &env)}
		})
	}
	for ; pending > 0; pending-- {
		finish(<-out)
	}
	for _, c := range r.checks[started:] {
		finish(done{c, []Result{{Status: Skip, Summary: "not run: the run's limit of " + r.overall.String() + " was reached"}}})
	}
	return nil
}

// runOne runs one check within its timeout. A check that does not return in
// time (and grace) is answered for: skip, it did not finish. A check that
// panics fails.
func runOne(ctx context.Context, c Check, env *Env) []Result {
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	ch := make(chan []Result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				ch <- []Result{{Status: Fail, Summary: "the check failed unexpectedly", Evidence: fmt.Sprint(p)}}
			}
		}()
		ch <- c.Run(cctx, env)
	}()
	var rs []Result
	select {
	case rs = <-ch:
	case <-cctx.Done():
		select {
		case rs = <-ch:
		case <-time.After(grace):
			why := "did not finish within " + c.timeout().String()
			if ctx.Err() != nil {
				why = "was cut short by the run's time limit"
			}
			return []Result{{Status: Skip, Summary: "the check " + why, Duration: time.Since(start)}}
		}
	}
	for i := range rs {
		if rs[i].Duration == 0 {
			rs[i].Duration = time.Since(start)
		}
	}
	return rs
}

// finalize fills in what a check left out (its id and layer, the time),
// scrubs and bounds the texts, and keeps evidence for warn and fail only,
// within what is left of budget.
func finalize(c Check, r Result, env *Env, budget *int) Result {
	if r.ID == "" {
		r.ID = c.ID
	}
	if r.Layer == "" {
		r.Layer = c.Layer
	}
	if r.Checked.IsZero() {
		r.Checked = env.now()
	}
	if r.Status == nodev1.CheckStatus_CHECK_STATUS_UNSPECIFIED {
		r.Status = Skip
	}
	scrub := env.Scrub
	if r.keep.IsValid() {
		scrub = scrub.withKeep(r.keep)
	}
	r.Summary = clip(scrub.Clean(r.Summary), MaxSummary, true)
	r.Hint = clip(scrub.Clean(r.Hint), maxHint, true)
	r.Fix = clip(r.Fix, maxFix, true)
	if r.Status != Warn && r.Status != Fail {
		r.Evidence = ""
	} else {
		r.Evidence = clip(scrub.Clean(r.Evidence), min(MaxEvidence, max(*budget, 0)), false)
		*budget -= len(r.Evidence)
	}
	return r
}

// ---- the light loop ---------------------------------------------------------------

// unitKey is a light check, for one target when it has Targets.
type unitKey struct{ id, target string }

type unit struct {
	check   Check
	next    time.Time
	running bool
	ran     bool
}

type unitDone struct {
	key     unitKey
	results []Result
}

// lightLoop is the state of Light, owned by its goroutine.
type lightLoop struct {
	r        *Runner
	ctx      context.Context
	units    map[unitKey]*unit
	set      *lightSet
	doneCh   chan unitDone
	running  int
	wg       sync.WaitGroup
	env      Env
	sent     bool
	lastSent time.Time
	dirty    bool
}

// Light runs the light checks until ctx ends: each check (each target of a
// check with Targets) at its cadence with ±10 % jitter, at most 16 at a time;
// a check whose previous run is still going skips its turn. The results go
// through the confirmation (lightSet): a worse result is reported only when a
// rerun, confirmAfter later or at the check's turn if sooner, finds it worse
// too; report is told the whole light set,
// buffered when a status changed (from the moment every check has run once),
// and live-only every 15 minutes otherwise. report is called from Light's
// goroutine only.
func (r *Runner) Light(ctx context.Context, report func(rep *nodev1.DiagnosticsReport, buffered bool)) {
	l := &lightLoop{r: r, ctx: ctx, units: map[unitKey]*unit{}, set: newLightSet(), doneCh: make(chan unitDone)}
	t := time.NewTicker(r.tick)
	defer t.Stop()
	l.round(r.env.now(), true)
	for {
		select {
		case <-ctx.Done():
			// The running checks end with ctx; what they return is not wanted.
			go func() {
				for range l.doneCh {
				}
			}()
			l.wg.Wait()
			close(l.doneCh)
			return
		case d := <-l.doneCh:
			l.finished(d)
			l.publish(report)
		case <-t.C:
			l.round(r.env.now(), false)
			l.publish(report)
		}
	}
}

// round starts the checks that are due. The state is read, and the scrubber
// made again, only when one is (or at the start).
func (l *lightLoop) round(now time.Time, first bool) {
	due := first
	for _, u := range l.units {
		if !now.Before(u.next) {
			due = true
			break
		}
	}
	if !due {
		return
	}
	l.env = l.r.prepare()
	live := map[unitKey]bool{}
	for _, c := range l.r.checks {
		if !c.Light || c.Every <= 0 {
			continue
		}
		targets := []string{""}
		if c.Targets != nil {
			targets = c.Targets(&l.env)
		}
		for _, tg := range targets {
			k := unitKey{c.ID, tg}
			live[k] = true
			if u := l.units[k]; u != nil {
				u.check = c
				continue
			}
			l.units[k] = &unit{check: c, next: now}
		}
	}
	for k, u := range l.units {
		if !live[k] && !u.running {
			delete(l.units, k)
			if l.set.drop(k) {
				l.dirty = true
			}
		}
	}
	for k, u := range l.units {
		if now.Before(u.next) {
			continue
		}
		if u.running {
			u.next = now.Add(u.check.Every + l.r.jitter(u.check.Every)) // skips its turn
			continue
		}
		if l.running >= max(l.r.slots, 1) {
			continue // waits for a slot
		}
		u.running = true
		l.running++
		u.next = now.Add(u.check.Every + l.r.jitter(u.check.Every))
		env := l.env
		env.Only = k.target
		c := u.check
		l.wg.Go(func() {
			rs := runOne(l.ctx, c, &env)
			select {
			case l.doneCh <- unitDone{k, rs}:
			case <-l.ctx.Done():
			}
		})
	}
}

func (l *lightLoop) finished(d unitDone) {
	l.running--
	u := l.units[d.key]
	if u == nil {
		return
	}
	u.running, u.ran = false, true
	budget := MaxRunEvidence
	var rs []Result
	for _, res := range d.results {
		res = finalize(u.check, res, &l.env, &budget)
		if d.key.target == "" || res.Target == d.key.target {
			rs = append(rs, res)
		}
	}
	changed, confirm := l.set.put(d.key, u.check, rs)
	if changed {
		l.dirty = true
	}
	if confirm {
		// A worsening waits for a rerun: at confirmAfter, or at the unit's
		// turn when that comes sooner.
		if at := l.r.env.now().Add(confirmAfter); at.Before(u.next) {
			u.next = at
		}
	}
}

// publish tells report the light set: buffered when it changed (or was never
// told), live-only when liveEvery went by; nothing before every check ran
// once.
func (l *lightLoop) publish(report func(*nodev1.DiagnosticsReport, bool)) {
	for _, u := range l.units {
		if !u.ran {
			return
		}
	}
	now := l.r.env.now()
	switch {
	case l.dirty || !l.sent:
		report(l.set.report(), true)
	case now.Sub(l.lastSent) >= l.r.liveEvery:
		report(l.set.report(), false)
	default:
		return
	}
	l.sent, l.lastSent, l.dirty = true, now, false
}
