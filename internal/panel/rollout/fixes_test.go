package rollout

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

// The node of the canary is never skipped, at the canary step or at the rest
// of its node: the other nodes get the version only after a canary that went
// through.
func TestCanaryNeverSkipped(t *testing.T) {
	for _, step := range []int{0, 1} {
		t.Run(fmt.Sprint("step=", step), func(t *testing.T) {
			f := newFixture(t, fiveProxies())
			req := request(store.RolloutModeManual)
			req.SkipOffline = true
			ro := f.startRollout(req)
			if step == 0 {
				f.offline("A")
			}
			f.start()
			if step == 1 {
				f.waitStatus(ro.ID, store.RolloutPaused, 1)
				f.offline("A")
				if err := f.runner.Continue(f.ctx, ro.ID); err != nil {
					t.Fatal(err)
				}
			}
			f.until("the step verifying", func() bool { return f.step(ro.ID, step).Status == store.StepVerifying })
			f.clock.Add(6 * time.Minute)
			f.waitStatus(ro.ID, store.RolloutFailed, step)
			if s := f.step(ro.ID, step); s.Status != store.StepReverted || !strings.Contains(s.Error, "offline") {
				t.Errorf("step %s %q", s.Status, s.Error)
			}
			f.holds(store.EnginePolicyChannel, "", "a2", "b1", "c1")
		})
	}
}

// A panel that stopped right after it stored the completion finishes it when
// it starts again: the events and the notice of the channel.
func TestCompletionFinishedOnRestart(t *testing.T) {
	f := newFixture(t, map[string][]string{"A": {"a1"}, "B": {"b1"}})
	p := f.proxy("b1")
	p.Enabled = false
	if err := f.db.UpdateProxy(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	f.waitStatus(ro.ID, store.RolloutPaused, 1)
	if err := f.runner.Continue(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.waitStatus(ro.ID, store.RolloutPaused, 2)
	f.set("B", silent)
	if err := f.runner.Continue(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.until("B applied", func() bool { return f.step(ro.ID, 2).Status == store.StepVerifying })
	f.writer.mu.Lock()
	f.writer.crash = true
	f.writer.mu.Unlock()
	f.set("B", healthy)
	f.waitStatus(ro.ID, store.RolloutCompleted, -1)
	f.settle()
	if f.completed() || len(f.events(EventItemsKept)) != 0 {
		t.Fatal("the completion ran to its end through a crash")
	}

	f.writer.mu.Lock()
	f.writer.crash = false
	f.writer.mu.Unlock()
	f.restart()
	f.until("the completion finished", f.completed)
	if f.channelVersion() != toVersion {
		t.Error("the channel did not move")
	}
	f.holds(store.EnginePolicyPinned, fromVersion, "b1")
	f.writer.mu.Lock()
	if len(f.writer.channels) != 1 {
		t.Errorf("channel notified %v", f.writer.channels)
	}
	f.writer.mu.Unlock()
	if n := len(f.events(EventItemsKept)); n != 1 {
		t.Errorf("%d kept events", n)
	}
	// Once finished, a restart does nothing again.
	f.restart()
	f.settle()
	if n := len(f.events(EventCompleted)); n != 1 {
		t.Errorf("%d completed events", n)
	}
}

func TestHookTimeout(t *testing.T) {
	f := newFixture(t, fiveProxies())
	f.hookTimeout = 50 * time.Millisecond
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.hooks.BeforeStep = func(context.Context, *store.Rollout, *store.RolloutStep) error {
		<-release // a hook that hangs, whatever its context says
		return nil
	}
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	f.waitStatus(ro.ID, store.RolloutFailed, 0)
	if s := f.step(ro.ID, 0); s.Status != store.StepFailed || !strings.Contains(s.Error, "did not return within 50ms") {
		t.Errorf("step %s %q", s.Status, s.Error)
	}
	// The rollout can be aborted: nothing holds its lock.
	if err := f.runner.Abort(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
}

// A rollout of a kind that the panel has no executor for can still be
// aborted; one left half aborted cannot be retried.
func TestAbortEdges(t *testing.T) {
	f := newFixture(t, fiveProxies())
	f.build()
	sw := &store.Rollout{Kind: store.RolloutSwitch, Component: store.EngineMtg, ToEngine: store.EngineMtg, Mode: store.RolloutModeManual, Status: store.RolloutRunning}
	if err := f.db.CreateRollout(f.ctx, sw, nil, []store.RolloutStep{{Index: 0, NodeID: f.nodes["C"].ID}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.runner.Abort(f.ctx, sw.ID); err != nil {
		t.Fatalf("Abort without an executor: %v", err)
	}
	if st := f.status(sw.ID); st != store.RolloutAborted {
		t.Errorf("switch rollout %s", st)
	}

	ro := f.startRollout(request(store.RolloutModeManual))
	ro.Status, ro.Error = store.RolloutFailed, abortingError
	if err := f.db.UpdateRollout(f.ctx, ro); err != nil {
		t.Fatal(err)
	}
	if err := f.runner.Retry(f.ctx, ro.ID); !errors.Is(err, ErrState) {
		t.Errorf("Retry of a half-aborted rollout: %v", err)
	}
	if err := f.runner.Abort(f.ctx, ro.ID); err != nil || f.status(ro.ID) != store.RolloutAborted {
		t.Errorf("Abort again: %v", err)
	}
}
