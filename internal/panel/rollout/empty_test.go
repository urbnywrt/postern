package rollout

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// latestRequest is a version rollout of telemt latest to toVersion: no proxy
// of the fixture follows latest.
func latestRequest(f *fixture) *Request {
	f.t.Helper()
	if err := f.db.SetChannelVersion(f.ctx, store.EngineTelemt, store.ChannelLatest, fromVersion); err != nil {
		f.t.Fatal(err)
	}
	req := request(store.RolloutModeManual)
	req.Channel = store.ChannelLatest
	return req
}

func TestNoFollowerMovesTheChannel(t *testing.T) {
	f := newFixture(t, fiveProxies())
	ro := f.startRollout(latestRequest(f))
	if ro.Status != store.RolloutCompleted || ro.FromVersion != fromVersion {
		t.Errorf("rollout %s from %q, want completed from %s", ro.Status, ro.FromVersion, fromVersion)
	}
	got, steps, items := f.load(ro.ID)
	if got.Status != store.RolloutCompleted || got.FinishedAt == nil || len(steps) != 0 || len(items) != 0 {
		t.Errorf("stored %s (finished %v) with %d steps and %d items", got.Status, got.FinishedAt, len(steps), len(items))
	}
	v, err := f.db.ChannelVersions(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v[store.EngineTelemt][store.ChannelLatest] != toVersion || v[store.EngineTelemt][store.ChannelStable] != fromVersion {
		t.Errorf("channels %v", v[store.EngineTelemt])
	}
	active, err := f.db.ListRollouts(f.ctx, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Errorf("%d active rollouts", len(active))
	}
	if started := f.events(EventStarted); len(started) != 1 || !f.completed() ||
		started[0].Message != "the channel moved to "+toVersion+" at once: no proxy follows it" {
		t.Errorf("events: started %v, completed %v", started, f.completed())
	}

	f.holds(store.EnginePolicyChannel, "", "a1", "a2", "b1", "b2", "c1")
	if len(f.writer.notified) != 0 {
		t.Errorf("nodes notified: %v", f.writer.notified)
	}

	// Another move of the same channel goes through: nothing holds it.
	req := latestRequest(f)
	if err := f.db.SetChannelVersion(f.ctx, store.EngineTelemt, store.ChannelLatest, fromVersion); err != nil {
		t.Fatal(err)
	}
	if again := f.startRollout(req); again.Status != store.RolloutCompleted {
		t.Errorf("second move: %s", again.Status)
	}
}

func TestNoFollowerStillValidates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *fixture, req *Request)
		text  string
	}{
		{"not in the channel", func(f *fixture, _ *Request) { f.catalog.notIn = true }, "not in the latest channel"},
		{"same version", func(_ *fixture, req *Request) { req.ToVersion = fromVersion }, "already"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, fiveProxies())
			f.build()
			req := latestRequest(f)
			tc.setup(f, req)
			_, err := f.runner.Start(f.ctx, "admin1", req)
			if !errors.Is(err, ErrRefused) || !strings.Contains(fmt.Sprint(err), tc.text) {
				t.Errorf("Start: %v, want refused with %q", err, tc.text)
			}
			if v, _ := f.db.ChannelVersions(f.ctx); v[store.EngineTelemt][store.ChannelLatest] == toVersion {
				t.Error("the channel moved")
			}
		})
	}
}

func TestFollowerStillRollsOut(t *testing.T) {
	f := newFixture(t, fiveProxies())
	ro := f.startRollout(request(store.RolloutModeManual))
	got, steps, _ := f.load(ro.ID)
	if got.Status != store.RolloutPreparing || len(steps) == 0 {
		t.Errorf("rollout %s with %d steps, want preparing with steps", got.Status, len(steps))
	}
	if f.channelVersion() != fromVersion {
		t.Errorf("the channel moved at once to %s", f.channelVersion())
	}
}

// A node switched to a channel that moved at once runs the new version.
func TestMovedChannelReachesASwitchedNode(t *testing.T) {
	f := newFixture(t, fiveProxies())
	f.startRollout(latestRequest(f))
	n, err := f.db.ModifyNode(f.ctx, f.nodes["A"].ID, func(n *store.Node) error { n.EngineChannel = store.ChannelLatest; return nil })
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.db.ChannelVersions(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := proxies.EffectiveVersion(f.proxy("a1"), n.EngineChannel, store.ChannelStable, v); got.Version != toVersion {
		t.Errorf("a1 on latest runs %s, want %s", got.Version, toVersion)
	}
	if got := proxies.EffectiveVersion(f.proxy("b1"), "", store.ChannelStable, v); got.Version != fromVersion {
		t.Errorf("b1 on stable runs %s, want %s", got.Version, fromVersion)
	}
}
