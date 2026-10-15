package rollout

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/releases"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// stepsOf names the steps of a rollout and their items: "A:a1" for the
// canary, "A:a2" for the rest of its node, and so on.
func stepsOf(f *fixture, id string) []string {
	_, steps, items := f.load(id)
	names := map[string]string{}
	for n, p := range f.proxies {
		names[p.ID] = n
	}
	nodes := map[string]string{}
	for n, node := range f.nodes {
		nodes[node.ID] = n
	}
	out := make([]string, len(steps))
	for i, s := range steps {
		var ps []string
		for _, it := range items {
			if it.StepIndex == s.Index {
				ps = append(ps, names[it.ProxyID])
			}
		}
		out[i] = nodes[s.NodeID] + ":" + strings.Join(ps, ",")
	}
	return out
}

func TestCanaryOrder(t *testing.T) {
	for _, tc := range []struct {
		canary string
		want   string
	}{
		{"", "A:a1 A:a2 B:b1,b2 C:c1"},
		{"b2", "B:b2 B:b1 A:a1,a2 C:c1"},
	} {
		t.Run("canary="+tc.canary, func(t *testing.T) {
			f := newFixture(t, fiveProxies())
			req := request(store.RolloutModeManual)
			if tc.canary != "" {
				req.CanaryProxyId = f.proxies[tc.canary].ID
			}
			ro := f.startRollout(req)
			if got := strings.Join(stepsOf(f, ro.ID), " "); got != tc.want {
				t.Errorf("steps %s, want %s", got, tc.want)
			}
			if ro.FromVersion != fromVersion || ro.Status != store.RolloutPreparing {
				t.Errorf("rollout from %q status %q", ro.FromVersion, ro.Status)
			}
			_, steps, _ := f.load(ro.ID)
			if steps[0].ProxyID == "" || steps[1].ProxyID != "" {
				t.Errorf("the canary step names %q, the rest step %q", steps[0].ProxyID, steps[1].ProxyID)
			}
		})
	}
}

func TestCanarySkipsOfflineNodes(t *testing.T) {
	f := newFixture(t, fiveProxies())
	if _, err := f.db.ModifyNode(f.ctx, f.nodes["A"].ID, func(n *store.Node) error { n.Status = store.NodeStatusOffline; return nil }); err != nil {
		t.Fatal(err)
	}
	ro := f.startRollout(request(store.RolloutModeManual))
	if got := strings.Join(stepsOf(f, ro.ID), " "); got != "B:b1 B:b2 A:a1,a2 C:c1" {
		t.Errorf("steps %s", got)
	}
}

func TestAutoHappyPath(t *testing.T) {
	f := newFixture(t, fiveProxies())
	req := request(store.RolloutModeAuto)
	req.PauseSeconds = 60
	ro := f.startRollout(req)
	f.start()

	f.until("the canary step", func() bool { return f.step(ro.ID, 0).Status == store.StepDone })
	f.holds(store.EnginePolicyRollout, toVersion, "a1")
	f.holds(store.EnginePolicyChannel, "", "a2", "b1", "c1")
	// It pauses until the clock passes the pause.
	f.settle()
	if s := f.step(ro.ID, 1); s.Status != store.StepPending {
		t.Fatalf("step 2 is %s during the pause", s.Status)
	}
	if got, _, _ := f.load(ro.ID); got.ResumeAt == nil || !got.ResumeAt.Equal(f.clock.Now().Add(60*time.Second)) {
		t.Fatalf("resume at %v", got.ResumeAt)
	}
	f.until("completion", func() bool {
		got, _, _ := f.load(ro.ID)
		if got.ResumeAt != nil {
			f.clock.Add(61 * time.Second)
		}
		return got.Status == store.RolloutCompleted && f.completed()
	})
	if v := f.channelVersion(); v != toVersion {
		t.Errorf("channel at %s, want %s", v, toVersion)
	}
	f.holds(store.EnginePolicyChannel, "", "a1", "a2", "b1", "b2", "c1")
	if n := len(f.events(EventStepDone)); n != 4 {
		t.Errorf("%d step events, want 4", n)
	}
	for _, k := range []string{EventStarted, EventCompleted} {
		if len(f.events(k)) != 1 {
			t.Errorf("no single %s event", k)
		}
	}
	f.writer.mu.Lock()
	if len(f.writer.channels) != 1 || f.writer.channels[0] != "telemt/stable" {
		t.Errorf("channel notified %v", f.writer.channels)
	}
	f.writer.mu.Unlock()
	f.catalog.mu.Lock()
	if len(f.catalog.prepared) != 1 || strings.Join(f.catalog.prepared[0], ",") != "amd64" {
		t.Errorf("prepared %v", f.catalog.prepared)
	}
	f.catalog.mu.Unlock()
}

func TestManual(t *testing.T) {
	f := newFixture(t, fiveProxies())
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	f.waitStatus(ro.ID, store.RolloutPaused, 1)
	f.settle()
	if s := f.step(ro.ID, 1); s.Status != store.StepPending {
		t.Fatalf("step 2 is %s while paused", s.Status)
	}
	if err := f.runner.Pause(f.ctx, ro.ID); !errors.Is(err, ErrState) {
		t.Errorf("Pause of a paused rollout: %v", err)
	}
	if err := f.runner.Continue(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.waitStatus(ro.ID, store.RolloutPaused, 2)
	f.holds(store.EnginePolicyRollout, toVersion, "a1", "a2")
	f.holds(store.EnginePolicyChannel, "", "b1")
	if got := f.runManual(ro.ID); got != store.RolloutCompleted {
		t.Fatalf("rollout %s", got)
	}
	if err := f.runner.Continue(f.ctx, ro.ID); !errors.Is(err, ErrState) {
		t.Errorf("Continue of a completed rollout: %v", err)
	}
}

// A paused step finishes, and the rollout stays paused after it.
func TestPauseDuringStep(t *testing.T) {
	f := newFixture(t, fiveProxies())
	f.set("A", silent)
	ro := f.startRollout(request(store.RolloutModeAuto))
	f.start()
	f.until("the canary verifying", func() bool { return f.step(ro.ID, 0).Status == store.StepVerifying })
	if err := f.runner.Pause(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.set("A", healthy)
	f.waitStatus(ro.ID, store.RolloutPaused, 1)
	if s := f.step(ro.ID, 0); s.Status != store.StepDone {
		t.Fatalf("canary %s", s.Status)
	}
	f.settle()
	if s := f.step(ro.ID, 1); s.Status != store.StepPending {
		t.Fatalf("step 2 is %s while paused", s.Status)
	}
}

func TestFailedStepIsReverted(t *testing.T) {
	f := newFixture(t, fiveProxies())
	var mu sync.Mutex
	var after []string
	f.hooks.AfterStep = func(_ context.Context, _ *store.Rollout, s *store.RolloutStep) error {
		mu.Lock()
		defer mu.Unlock()
		after = append(after, fmt.Sprintf("%d:%s", s.Index, s.Status))
		return nil
	}
	f.set("B", failing)
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	if got := f.runManual(ro.ID); got != store.RolloutFailed {
		t.Fatalf("rollout %s", got)
	}
	got, steps, items := f.load(ro.ID)
	if got.CurrentStep != 2 || steps[2].Status != store.StepReverted || steps[3].Status != store.StepPending {
		t.Fatalf("step %d, statuses %s %s", got.CurrentStep, steps[2].Status, steps[3].Status)
	}
	if !strings.Contains(got.Error, "the trial of the binary failed") || !strings.Contains(steps[2].Error, "b1") {
		t.Errorf("errors %q / %q", got.Error, steps[2].Error)
	}
	f.holds(store.EnginePolicyChannel, "", "b1", "b2", "c1")
	f.holds(store.EnginePolicyRollout, toVersion, "a1", "a2")
	for _, it := range items {
		if it.StepIndex == 3 && it.State != store.ItemPending {
			t.Errorf("an item of C is %s", it.State)
		}
	}
	mu.Lock()
	if strings.Join(after, " ") != "0:verifying 1:verifying 2:reverted" {
		t.Errorf("AfterStep saw %v", after)
	}
	mu.Unlock()
	if evs := f.events(EventFailed); len(evs) != 1 || evs[0].Severity != "error" {
		t.Errorf("failed events %v", evs)
	}
	if f.channelVersion() != fromVersion {
		t.Error("the channel moved")
	}

	f.set("B", healthy)
	if err := f.runner.Retry(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.waitStatus(ro.ID, store.RolloutPaused, 3)
	f.holds(store.EnginePolicyRollout, toVersion, "b1", "b2")
	if f.runManual(ro.ID) != store.RolloutCompleted {
		t.Fatal("not completed after the retry")
	}
}

func TestOldReportIgnored(t *testing.T) {
	f := newFixture(t, fiveProxies())
	f.set("B", failing)
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	if f.runManual(ro.ID) != store.RolloutFailed {
		t.Fatal("not failed")
	}
	old := f.step(ro.ID, 2).Generation
	// B goes quiet: its last reports, of the old generation, say that the
	// target failed.
	f.set("B", silent)
	for _, name := range []string{"b1", "b2"} {
		f.reports.set(f.nodes["B"].ID, f.proxies[name].ID, proxies.ProxyReport{
			Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, RunningEngine: nodev1.Engine_ENGINE_TELEMT, RunningVersion: fromVersion,
			FailedEngine: nodev1.Engine_ENGINE_TELEMT, FailedVersion: toVersion, Reason: "old failure", ReportGeneration: old,
		})
	}
	if err := f.runner.Retry(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.until("the retried step verifying", func() bool {
		s := f.step(ro.ID, 2)
		return s.Status == store.StepVerifying && s.Generation > old
	})
	f.settle()
	if st := f.status(ro.ID); st != store.RolloutRunning {
		t.Fatalf("rollout %s: an old report was judged", st)
	}
	f.set("B", healthy)
	f.waitStatus(ro.ID, store.RolloutPaused, 3)
}

func TestStateRejectionFails(t *testing.T) {
	f := newFixture(t, fiveProxies())
	// A rejection of an earlier generation, still shown, does not count.
	f.reject(f.nodes["A"].ID, 0)
	f.set("A", silent)
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	f.until("the canary verifying", func() bool { return f.step(ro.ID, 0).Status == store.StepVerifying })
	f.settle()
	if st := f.status(ro.ID); st != store.RolloutRunning {
		t.Fatalf("rollout %s: an old rejection was judged", st)
	}
	f.set("A", rejecting)
	f.waitStatus(ro.ID, store.RolloutFailed, 0)
	s := f.step(ro.ID, 0)
	if s.Status != store.StepReverted || !strings.Contains(s.Error, "refused its state: bad state") {
		t.Errorf("step %s %q", s.Status, s.Error)
	}
	f.holds(store.EnginePolicyChannel, "", "a1")
}

func TestTimeoutStartsAfterBeforeStep(t *testing.T) {
	f := newFixture(t, fiveProxies())
	f.hooks.BeforeStep = func(context.Context, *store.Rollout, *store.RolloutStep) error {
		f.clock.Add(3 * time.Minute) // a hook that takes three minutes
		return nil
	}
	f.set("A", silent)
	ro := f.startRollout(request(store.RolloutModeManual))
	start := f.clock.Now()
	f.start()
	f.until("the canary verifying", func() bool { return f.step(ro.ID, 0).Status == store.StepVerifying })
	if s := f.step(ro.ID, 0); !s.StartedAt.Equal(start.Add(3 * time.Minute)) {
		t.Errorf("started at %v, want after the hook", s.StartedAt)
	}
	f.clock.Add(2 * time.Minute) // 5 min since the hook began, 2 since the step started
	f.settle()
	if st := f.status(ro.ID); st != store.RolloutRunning {
		t.Fatalf("rollout %s: the hook ate the timeout", st)
	}
	f.clock.Add(2*time.Minute + 30*time.Second) // past 2 min + 2 min for one item
	f.waitStatus(ro.ID, store.RolloutFailed, 0)
	if s := f.step(ro.ID, 0); !strings.Contains(s.Error, "did not finish within 4m0s") {
		t.Errorf("step error %q", s.Error)
	}
}

func TestHooks(t *testing.T) {
	t.Run("before", func(t *testing.T) {
		f := newFixture(t, fiveProxies())
		f.hooks.BeforeStep = func(context.Context, *store.Rollout, *store.RolloutStep) error {
			return errors.New("diagnostics say no")
		}
		ro := f.startRollout(request(store.RolloutModeManual))
		f.start()
		f.waitStatus(ro.ID, store.RolloutFailed, 0)
		s := f.step(ro.ID, 0)
		if s.Status != store.StepFailed || s.StartedAt != nil || s.Generation != 0 || !strings.Contains(s.Error, "diagnostics say no") {
			t.Errorf("step %+v", s)
		}
		n, _ := f.db.NodeByID(f.ctx, f.nodes["A"].ID)
		if n.DesiredGeneration != 0 {
			t.Errorf("node A at generation %d: the step was applied", n.DesiredGeneration)
		}
		f.holds(store.EnginePolicyChannel, "", "a1")
	})
	t.Run("after", func(t *testing.T) {
		f := newFixture(t, fiveProxies())
		var mu sync.Mutex
		var seen []string
		f.hooks.AfterStep = func(_ context.Context, _ *store.Rollout, s *store.RolloutStep) error {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, s.Status)
			return errors.New("the probes fail")
		}
		ro := f.startRollout(request(store.RolloutModeManual))
		f.start()
		f.waitStatus(ro.ID, store.RolloutFailed, 0)
		s := f.step(ro.ID, 0)
		if s.Status != store.StepReverted || !strings.Contains(s.Error, "after-step hook: the probes fail") {
			t.Errorf("step %s %q", s.Status, s.Error)
		}
		f.holds(store.EnginePolicyChannel, "", "a1")
		mu.Lock()
		defer mu.Unlock()
		if strings.Join(seen, " ") != "verifying reverted" {
			t.Errorf("AfterStep saw %v", seen)
		}
	})
}

// offline takes a node offline, last seen now.
func (f *fixture) offline(name string) {
	f.t.Helper()
	seen := f.clock.Now()
	if _, err := f.db.ModifyNode(f.ctx, f.nodes[name].ID, func(n *store.Node) error {
		n.Status, n.LastSeenAt = store.NodeStatusOffline, &seen
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	f.set(name, silent)
}

func TestSkipOfflineDefers(t *testing.T) {
	for _, skip := range []bool{true, false} {
		t.Run(fmt.Sprint("skip=", skip), func(t *testing.T) {
			f := newFixture(t, fiveProxies())
			req := request(store.RolloutModeManual)
			req.SkipOffline = skip
			ro := f.startRollout(req)
			f.start()
			f.waitStatus(ro.ID, store.RolloutPaused, 1)
			f.offline("C")
			if err := f.runner.Continue(f.ctx, ro.ID); err != nil {
				t.Fatal(err)
			}
			f.waitStatus(ro.ID, store.RolloutPaused, 2)
			if err := f.runner.Continue(f.ctx, ro.ID); err != nil {
				t.Fatal(err)
			}
			f.waitStatus(ro.ID, store.RolloutPaused, 3)
			if err := f.runner.Continue(f.ctx, ro.ID); err != nil {
				t.Fatal(err)
			}
			f.until("C applied", func() bool { return f.step(ro.ID, 3).Status == store.StepVerifying })
			f.clock.Add(4 * time.Minute) // within the grace
			f.settle()
			if st := f.status(ro.ID); st != store.RolloutRunning {
				t.Fatalf("rollout %s within the grace", st)
			}
			f.clock.Add(90 * time.Second)
			if !skip {
				f.waitStatus(ro.ID, store.RolloutFailed, 3)
				if s := f.step(ro.ID, 3); !strings.Contains(s.Error, "offline") {
					t.Errorf("step error %q", s.Error)
				}
				f.holds(store.EnginePolicyChannel, "", "c1")
				return
			}
			f.waitStatus(ro.ID, store.RolloutCompleted, -1)
			f.until("the completion", f.completed)
			if s := f.step(ro.ID, 3); s.Status != store.StepSkipped {
				t.Errorf("step %s", s.Status)
			}
			f.holds(store.EnginePolicyPinned, fromVersion, "c1")
			f.holds(store.EnginePolicyChannel, "", "a1", "b1")
			if evs := f.events(EventItemsKept); len(evs) != 1 || !strings.Contains(evs[0].Message, "c1") {
				t.Errorf("kept events %v", evs)
			}
		})
	}
}

func TestDisabledProxyDeferred(t *testing.T) {
	f := newFixture(t, fiveProxies())
	p := f.proxy("b1")
	p.Enabled = false
	if err := f.db.UpdateProxy(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	if f.runManual(ro.ID) != store.RolloutCompleted {
		t.Fatal("not completed")
	}
	f.holds(store.EnginePolicyPinned, fromVersion, "b1")
	f.holds(store.EnginePolicyChannel, "", "b2")
	if evs := f.events(EventItemsKept); len(evs) != 1 || !strings.Contains(evs[0].Message, "b1") {
		t.Errorf("kept events %v", evs)
	}
}

func TestEmptyStep(t *testing.T) {
	f := newFixture(t, map[string][]string{"A": {"a1"}, "B": {"b1"}})
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	f.waitStatus(ro.ID, store.RolloutPaused, 1)
	f.set("A", silent)
	if err := f.runner.Continue(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.until("the empty step verifying", func() bool { return f.step(ro.ID, 1).Status == store.StepVerifying })
	f.settle()
	if s := f.step(ro.ID, 1); s.Status != store.StepVerifying {
		t.Fatalf("the empty step is %s before its generation is applied", s.Status)
	}
	f.set("A", healthy)
	f.waitStatus(ro.ID, store.RolloutPaused, 2)
}

func TestAbort(t *testing.T) {
	f := newFixture(t, fiveProxies())
	f.set("B", failing)
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	if f.runManual(ro.ID) != store.RolloutFailed {
		t.Fatal("not failed")
	}
	if err := f.runner.Abort(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	got, steps, _ := f.load(ro.ID)
	if got.Status != store.RolloutAborted {
		t.Fatalf("rollout %s", got.Status)
	}
	for i, want := range []string{store.StepReverted, store.StepReverted, store.StepReverted, store.StepPending} {
		if steps[i].Status != want {
			t.Errorf("step %d %s, want %s", i, steps[i].Status, want)
		}
	}
	f.holds(store.EnginePolicyChannel, "", "a1", "a2", "b1", "b2", "c1")
	if len(f.events(EventAborted)) != 1 {
		t.Error("no aborted event")
	}
	if err := f.runner.Abort(f.ctx, ro.ID); !errors.Is(err, ErrState) {
		t.Errorf("a second Abort: %v", err)
	}
	// The nodes are free again.
	f.set("B", healthy)
	f.startRollout(request(store.RolloutModeManual))
}

func TestDetachedItem(t *testing.T) {
	f := newFixture(t, fiveProxies())
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	f.waitStatus(ro.ID, store.RolloutPaused, 1)
	p := f.proxy("a2")
	p.EngineVersionPolicy, p.EngineVersion = store.EnginePolicyPinned, "3.5.11"
	if err := f.db.UpdateProxy(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	if f.runManual(ro.ID) != store.RolloutCompleted {
		t.Fatal("not completed")
	}
	f.holds(store.EnginePolicyPinned, "3.5.11", "a2")
	_, _, items := f.load(ro.ID)
	for _, it := range items {
		if it.ProxyID == p.ID && it.State != store.ItemDetached {
			t.Errorf("a2 item %s", it.State)
		}
	}
}

func TestResume(t *testing.T) {
	f := newFixture(t, fiveProxies())
	ro := f.startRollout(request(store.RolloutModeManual))
	// A panel that stopped right after it stored the start of the canary.
	ro.Status = store.RolloutRunning
	if err := f.db.UpdateRollout(f.ctx, ro); err != nil {
		t.Fatal(err)
	}
	t0 := f.clock.Now()
	s := f.step(ro.ID, 0)
	s.Status, s.StartedAt = store.StepApplying, &t0
	if err := f.db.UpdateRolloutStep(f.ctx, &s); err != nil {
		t.Fatal(err)
	}
	f.clock.Add(time.Minute)
	f.set("A", silent)
	f.start()
	f.until("the canary applied again", func() bool {
		s := f.step(ro.ID, 0)
		return s.Status == store.StepVerifying && s.Generation > 0
	})
	if s := f.step(ro.ID, 0); !s.StartedAt.Equal(t0) {
		t.Errorf("started at %v, want %v", s.StartedAt, t0)
	}
	f.holds(store.EnginePolicyRollout, toVersion, "a1")
	// The deadline is the one of the first start.
	f.clock.Add(3*time.Minute + time.Second)
	f.waitStatus(ro.ID, store.RolloutFailed, 0)
}

func TestRefusals(t *testing.T) {
	type setup func(f *fixture, req *Request)
	for _, tc := range []struct {
		name  string
		setup setup
		want  error
		text  string
	}{
		{"conflict", func(f *fixture, _ *Request) { f.startRollout(request(store.RolloutModeManual)) }, store.ErrRolloutConflict, "rollout "},
		{"node conflict", func(f *fixture, req *Request) {
			f.startRollout(request(store.RolloutModeManual))
			req.Channel = store.ChannelLatest
			if _, err := f.db.ModifyNode(f.ctx, f.nodes["A"].ID, func(n *store.Node) error { n.EngineChannel = store.ChannelLatest; return nil }); err != nil {
				f.t.Fatal(err)
			}
			if err := f.db.SetChannelVersion(f.ctx, store.EngineTelemt, store.ChannelLatest, fromVersion); err != nil {
				f.t.Fatal(err)
			}
		}, store.ErrRolloutConflict, "holds node"},
		{"not in the channel", func(f *fixture, _ *Request) { f.catalog.notIn = true }, ErrRefused, "not in the stable channel"},
		{"no pin", func(f *fixture, _ *Request) { f.catalog.noPin["amd64"] = true }, ErrRefused, "no pinned SHA-256 for amd64"},
		{"capability", func(f *fixture, _ *Request) {
			if _, err := f.db.ModifyNode(f.ctx, f.nodes["B"].ID, func(n *store.Node) error { n.HostInfo.Capabilities = nil; return nil }); err != nil {
				f.t.Fatal(err)
			}
		}, ErrRefused, "upgrade node B to use rollouts"},
		{"web minimum", func(f *fixture, req *Request) {
			p := f.proxy("c1")
			p.Type, p.Domain, p.WebBasePath = store.ProxyTypeWeb, "web.example.com", "tg"
			if err := f.db.UpdateProxy(f.ctx, p); err != nil {
				f.t.Fatal(err)
			}
			req.ToVersion = "3.5.7"
		}, ErrRefused, "proxy c1 needs telemt 3.5.8"},
		{"same version", func(_ *fixture, req *Request) { req.ToVersion = fromVersion }, ErrRefused, "already"},
		{"not a component", func(_ *fixture, req *Request) { req.Component = "nginx" }, ErrInvalid, "not a provider"},
		{"bad mode", func(_ *fixture, req *Request) { req.Mode = "fast" }, ErrInvalid, ""},
		{"bad canary", func(_ *fixture, req *Request) { req.CanaryProxyId = "nope" }, ErrInvalid, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, fiveProxies())
			f.build()
			req := request(store.RolloutModeManual)
			tc.setup(f, req)
			_, err := f.runner.Start(f.ctx, "admin1", req)
			if !errors.Is(err, tc.want) || !strings.Contains(fmt.Sprint(err), tc.text) {
				t.Errorf("Start: %v, want %v with %q", err, tc.want, tc.text)
			}
		})
	}

	t.Run("unusable target", func(t *testing.T) {
		f := newFixture(t, fiveProxies())
		f.catalog.prepareErr = fmt.Errorf("%w: telemt 3.5.13 amd64: not static", releases.ErrUnusable)
		ro := f.startRollout(request(store.RolloutModeManual))
		f.start()
		f.waitStatus(ro.ID, store.RolloutFailed, 0)
		got, _, _ := f.load(ro.ID)
		if !strings.HasPrefix(got.Error, "preparing: ") || f.step(ro.ID, 0).Status != store.StepPending {
			t.Errorf("error %q", got.Error)
		}
		f.holds(store.EnginePolicyChannel, "", "a1")
		f.catalog.mu.Lock()
		f.catalog.prepareErr = nil
		f.catalog.mu.Unlock()
		if err := f.runner.Retry(f.ctx, ro.ID); err != nil {
			t.Fatal(err)
		}
		f.waitStatus(ro.ID, store.RolloutPaused, 1)
	})
}
