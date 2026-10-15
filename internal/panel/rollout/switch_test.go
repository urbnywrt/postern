package rollout

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
)

const (
	mtgVersion  = "v2.2.8"
	xrayFrom    = "v26.3.27"
	xrayTo      = "v26.3.28"
	xrayChannel = store.ChannelStable
)

// switchRequest is a switch of proxies to mtg.
func (f *fixture) switchRequest(version string, names ...string) *Request {
	f.t.Helper()
	if err := f.db.SetChannelVersion(f.ctx, store.EngineMtg, store.ChannelStable, mtgVersion); err != nil {
		f.t.Fatal(err)
	}
	req := &Request{Kind: store.RolloutSwitch, Component: store.EngineMtg, ToVersion: version, Mode: store.RolloutModeManual}
	for _, n := range names {
		req.ProxyIds = append(req.ProxyIds, f.proxies[n].ID)
	}
	return req
}

// engines checks the engine, policy and version of proxies.
func (f *fixture) engines(engine, policy, version string, names ...string) {
	f.t.Helper()
	for _, n := range names {
		p := f.proxy(n)
		if p.Engine != engine || p.EngineVersionPolicy != policy || p.EngineVersion != version {
			f.t.Errorf("proxy %s holds %s %s %q, want %s %s %q", n, p.Engine, p.EngineVersionPolicy, p.EngineVersion, engine, policy, version)
		}
	}
}

func TestSwitch(t *testing.T) {
	f := newFixture(t, map[string][]string{"A": {"a1", "a2"}, "B": {"b1"}})
	f.set("B", failing)
	ro := f.startRollout(f.switchRequest("", "a2", "a1", "b1"))
	if got := strings.Join(stepsOf(f, ro.ID), " "); got != "A:a2 A:a1 B:b1" {
		t.Errorf("steps %s: the first proxy given goes first", got)
	}
	if ro.ToEngine != store.EngineMtg || ro.Channel != "" {
		t.Errorf("rollout to %q on channel %q", ro.ToEngine, ro.Channel)
	}
	f.start()
	if f.runManual(ro.ID) != store.RolloutFailed {
		t.Fatal("not failed")
	}
	if s := f.step(ro.ID, 2); s.Status != store.StepReverted || !strings.Contains(s.Error, "b1") {
		t.Errorf("step 3 %s %q", s.Status, s.Error)
	}
	f.engines(store.EngineMtg, store.EnginePolicyRollout, mtgVersion, "a1", "a2")
	f.engines(store.EngineTelemt, store.EnginePolicyChannel, "", "b1")

	f.set("B", healthy)
	if err := f.runner.Retry(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.waitStatus(ro.ID, store.RolloutCompleted, -1)
	f.until("the completion", f.completed)
	f.engines(store.EngineMtg, store.EnginePolicyChannel, "", "a1", "a2", "b1")
	if f.channelVersion() != fromVersion {
		t.Error("a switch moved the telemt channel")
	}
}

func TestSwitchRefusals(t *testing.T) {
	f := newFixture(t, map[string][]string{"A": {"a1", "a2"}, "B": {"b1"}})
	f.build()
	f.checker.refuse[f.proxies["a2"].ID] = "a2: mtg has no ad_tag support"
	_, err := f.runner.Start(f.ctx, "admin1", f.switchRequest("", "a1", "a2"))
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "node A: a2: mtg has no ad_tag support") {
		t.Errorf("a switch of a proxy with an ad tag: %v", err)
	}
	if _, err := f.runner.Start(f.ctx, "admin1", f.switchRequest("")); !errors.Is(err, ErrInvalid) {
		t.Errorf("a switch of no proxy: %v", err)
	}
	p := f.proxy("b1")
	p.Engine = store.EngineMtg
	if err := f.db.UpdateProxy(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := f.runner.Start(f.ctx, "admin1", f.switchRequest("", "b1")); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "already") {
		t.Errorf("a switch of a proxy on mtg: %v", err)
	}
	f.catalog.noPin["amd64"] = true
	if _, err := f.runner.Start(f.ctx, "admin1", f.switchRequest("", "a1")); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no pinned") {
		t.Errorf("a switch without a pin: %v", err)
	}
}

// Two one-proxy switches on two nodes run at once; on one node the second is
// refused.
func TestSwitchesAtOnce(t *testing.T) {
	f := newFixture(t, map[string][]string{"A": {"a1", "a2"}, "B": {"b1"}})
	one := f.startRollout(f.switchRequest("", "a1"))
	two := f.startRollout(f.switchRequest("", "b1"))
	_, err := f.runner.Start(f.ctx, "admin1", f.switchRequest("", "a2"))
	var conflict *store.RolloutConflict
	if !errors.As(err, &conflict) || conflict.Holder != one.ID || conflict.NodeID != f.nodes["A"].ID {
		t.Fatalf("a second switch on node A: %v", err)
	}
	f.start()
	for _, id := range []string{one.ID, two.ID} {
		f.waitStatus(id, store.RolloutPaused, 1)
	}
	f.engines(store.EngineMtg, store.EnginePolicyRollout, mtgVersion, "a1", "b1")
}

func TestSwitchPinned(t *testing.T) {
	f := newFixture(t, map[string][]string{"A": {"a1"}, "B": {"b1"}})
	ro := f.startRollout(f.switchRequest(mtgVersion, "a1", "b1"))
	f.start()
	if f.runManual(ro.ID) != store.RolloutCompleted {
		t.Fatal("not completed")
	}
	f.engines(store.EngineMtg, store.EnginePolicyPinned, mtgVersion, "a1", "b1")
}

// A proxy that was disabled when its step was applied, and so deferred, is
// taken when the step is retried after it was enabled again.
func TestRetryTakesAReenabledProxy(t *testing.T) {
	f := newFixture(t, fiveProxies())
	p := f.proxy("b1")
	p.Enabled = false
	if err := f.db.UpdateProxy(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	f.set("B", failing)
	ro := f.startRollout(request(store.RolloutModeManual))
	f.start()
	if f.runManual(ro.ID) != store.RolloutFailed {
		t.Fatal("not failed")
	}
	p = f.proxy("b1")
	p.Enabled = true
	if err := f.db.UpdateProxy(f.ctx, p); err != nil {
		t.Fatal(err)
	}
	f.set("B", healthy)
	if err := f.runner.Retry(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.waitStatus(ro.ID, store.RolloutPaused, 3)
	f.holds(store.EnginePolicyRollout, toVersion, "b1", "b2")
	if f.runManual(ro.ID) != store.RolloutCompleted {
		t.Fatal("not completed")
	}
	f.holds(store.EnginePolicyChannel, "", "b1")
	if len(f.events(EventItemsKept)) != 0 {
		t.Error("b1 was kept back")
	}
}

// providerRequest is a rollout of xray on the stable channel; every node
// runs xray.
func (f *fixture) providerRequest() *Request {
	f.t.Helper()
	if err := f.db.SetChannelVersion(f.ctx, proxies.EngineXray, xrayChannel, xrayFrom); err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	for _, n := range f.nodes {
		f.provs[n.ID] = []string{proxies.EngineXray}
	}
	f.mu.Unlock()
	return &Request{Kind: store.RolloutVersion, Component: proxies.EngineXray, Channel: xrayChannel, ToVersion: xrayTo,
		Mode: store.RolloutModeManual, SkipOffline: true}
}

func (f *fixture) providerVersion(name string) string {
	f.t.Helper()
	n, err := f.db.NodeByID(f.ctx, f.nodes[name].ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return n.ProviderVersions[proxies.EngineXray]
}

func TestProviderRollout(t *testing.T) {
	f := newFixture(t, map[string][]string{"A": nil, "B": nil, "C": nil, "D": nil})
	req := f.providerRequest()
	// D runs no xray, so it is not in the rollout.
	f.mu.Lock()
	f.provs[f.nodes["D"].ID] = nil
	f.mu.Unlock()
	f.set("B", failing)
	ro := f.startRollout(req)
	if got := strings.Join(stepsOf(f, ro.ID), " "); got != "A: B: C:" {
		t.Errorf("steps %s", got)
	}
	f.start()
	if f.runManual(ro.ID) != store.RolloutFailed {
		t.Fatal("not failed")
	}
	if s := f.step(ro.ID, 1); s.Status != store.StepReverted || !strings.Contains(s.Error, "the trial of the binary failed") {
		t.Errorf("step 2 %s %q", s.Status, s.Error)
	}
	if a, b := f.providerVersion("A"), f.providerVersion("B"); a != xrayTo || b != "" {
		t.Errorf("A at %q, B at %q", a, b)
	}

	f.set("B", healthy)
	if err := f.runner.Retry(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.waitStatus(ro.ID, store.RolloutPaused, 2)
	f.offline("C")
	if err := f.runner.Continue(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.until("C applied", func() bool { return f.step(ro.ID, 2).Status == store.StepVerifying })
	f.clock.Add(6 * time.Minute)
	f.waitStatus(ro.ID, store.RolloutCompleted, -1)
	f.until("the completion", f.completed)
	if s := f.step(ro.ID, 2); s.Status != store.StepSkipped {
		t.Errorf("step 3 %s", s.Status)
	}
	v, err := f.db.ChannelVersions(f.ctx)
	if err != nil || v[proxies.EngineXray][xrayChannel] != xrayTo {
		t.Errorf("the channel is at %v (%v)", v[proxies.EngineXray], err)
	}
	for name, want := range map[string]string{"A": "", "B": "", "C": xrayFrom, "D": ""} {
		if got := f.providerVersion(name); got != want {
			t.Errorf("node %s at %q, want %q", name, got, want)
		}
	}
	f.writer.mu.Lock()
	if len(f.writer.channels) != 1 || f.writer.channels[0] != "xray/stable" {
		t.Errorf("channels notified %v", f.writer.channels)
	}
	f.writer.mu.Unlock()
}

func TestProviderRefusals(t *testing.T) {
	f := newFixture(t, map[string][]string{"A": nil})
	f.build()
	req := f.providerRequest()
	req.ToVersion = xrayFrom
	if _, err := f.runner.Start(f.ctx, "admin1", req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "already") {
		t.Errorf("same version: %v", err)
	}
	req.ToVersion = xrayTo
	f.mu.Lock()
	f.provs[f.nodes["A"].ID] = nil
	f.mu.Unlock()
	if _, err := f.runner.Start(f.ctx, "admin1", req); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no node") {
		t.Errorf("no node runs it: %v", err)
	}
}
