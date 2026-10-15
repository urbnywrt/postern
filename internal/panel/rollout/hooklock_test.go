package rollout

import (
	"context"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// longHook is a hook that waits (its diagnostics) until its context ends; it
// says on entered when it starts, and on left when it returns.
func longHook(entered chan<- string, left chan<- struct{}) func(context.Context, *store.Rollout, *store.RolloutStep) error {
	return func(ctx context.Context, _ *store.Rollout, s *store.RolloutStep) error {
		select {
		case entered <- s.Status:
		default:
		}
		<-ctx.Done()
		select {
		case left <- struct{}{}:
		default:
		}
		return nil
	}
}

// An Abort while a step's BeforeStep waits returns at once, ends the hook,
// and the step is never applied.
func TestAbortDuringBeforeStep(t *testing.T) {
	f := newFixture(t, fiveProxies())
	f.hookTimeout = time.Minute
	entered, left := make(chan string, 1), make(chan struct{}, 1)
	f.hooks.BeforeStep = longHook(entered, left)
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("BeforeStep did not run")
	}
	start := time.Now()
	if err := f.runner.Abort(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Abort took %s during a hook", d)
	}
	select {
	case <-left:
	case <-time.After(time.Second):
		t.Error("the Abort did not end the hook's context")
	}
	f.settle()
	if st := f.status(ro.ID); st != store.RolloutAborted {
		t.Fatalf("status %s", st)
	}
	if s := f.step(ro.ID, 0); s.Status != store.StepPending || s.StartedAt != nil || s.Generation != 0 {
		t.Errorf("step %+v: applied after the abort", s)
	}
	n, _ := f.db.NodeByID(f.ctx, f.nodes["A"].ID)
	if n.DesiredGeneration != 0 {
		t.Errorf("node A at generation %d: the step was applied", n.DesiredGeneration)
	}
	f.holds(store.EnginePolicyChannel, "", "a1")
}

// A Pause is stored before it cuts a step's AfterStep short: the hook that is
// cut finds the rollout paused, so its step goes through. A cut that came
// first could be seen while the rollout was still running, and then the hook
// ran once more, on a paused rollout, until its timeout.
func TestPauseIsStoredBeforeTheHookIsCut(t *testing.T) {
	f := newFixture(t, fiveProxies())
	f.hookTimeout = time.Minute
	entered, seen := make(chan string, 1), make(chan string, 1)
	f.hooks.AfterStep = func(ctx context.Context, ro *store.Rollout, s *store.RolloutStep) error {
		select {
		case entered <- s.Status:
		default:
		}
		<-ctx.Done()
		status := "unreadable"
		if cur, _, _, err := f.db.Rollout(context.Background(), ro.ID); err == nil {
			status = cur.Status
		}
		select {
		case seen <- status:
		default:
		}
		return nil
	}
	ro := f.startRollout(request(store.RolloutModeAuto))
	f.start()
	f.until("AfterStep to run", func() bool {
		select {
		case <-entered:
			return true
		default:
			return false
		}
	})
	if err := f.runner.Pause(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case status := <-seen:
		if status != store.RolloutPaused {
			t.Errorf("the hook was cut while the rollout was %s, want paused", status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the hook was not cut")
	}
	f.waitStatus(ro.ID, store.RolloutPaused, 1)
}

// A Pause while a step's AfterStep waits returns at once and ends the hook;
// the step that went through is done, and the rollout stays paused.
func TestPauseDuringAfterStep(t *testing.T) {
	f := newFixture(t, fiveProxies())
	f.hookTimeout = time.Minute
	entered := make(chan string, 1)
	f.hooks.AfterStep = longHook(entered, nil)
	ro := f.startRollout(request(store.RolloutModeAuto))
	f.start()
	var seen string
	f.until("AfterStep to run", func() bool {
		select {
		case seen = <-entered:
			return true
		default:
			return false
		}
	})
	if seen != store.StepVerifying {
		t.Fatalf("AfterStep saw %s", seen)
	}
	start := time.Now()
	if err := f.runner.Pause(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Pause took %s during a hook", d)
	}
	f.waitStatus(ro.ID, store.RolloutPaused, 1)
	if s := f.step(ro.ID, 0); s.Status != store.StepDone {
		t.Errorf("step 0 %s, want done", s.Status)
	}
	f.settle()
	if s := f.step(ro.ID, 1); s.Status != store.StepPending {
		t.Errorf("step 1 %s while paused", s.Status)
	}
}
