package rollout

import (
	"testing"

	"github.com/urbnywrt/postern/internal/panel/proxies"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// A node that applied the generation of its step but whose reports the panel
// does not have (it restarted) is not done: the step waits for a report,
// unless the node no longer runs the provider.
func TestProviderStepWaitsForAReport(t *testing.T) {
	f := newFixture(t, map[string][]string{"A": nil, "B": nil})
	ro := f.startRollout(f.providerRequest())
	f.set("A", silent)
	f.start()
	f.until("the canary verifying", func() bool { return f.step(ro.ID, 0).Status == store.StepVerifying })
	// The node has the state; the panel has no report of it.
	if _, err := f.db.ModifyNode(f.ctx, f.nodes["A"].ID, func(n *store.Node) error {
		n.AppliedGeneration = n.DesiredGeneration
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.reports.setEgress(f.nodes["A"].ID, nil)
	f.settle()
	if s := f.step(ro.ID, 0); s.Status != store.StepVerifying {
		t.Fatalf("the canary is %s without a report", s.Status)
	}
	// An egress that dropped the provider leaves nothing to report.
	f.mu.Lock()
	f.provs[f.nodes["A"].ID] = nil
	f.mu.Unlock()
	f.waitStatus(ro.ID, store.RolloutPaused, 1)
}

// A version that an admin gave a node after the rollout was planned is left
// alone: not overwritten by Apply, not cleared by a revert or the completion.
func TestProviderLeavesAnAdminVersion(t *testing.T) {
	f := newFixture(t, map[string][]string{"A": nil, "B": nil, "C": nil})
	ro := f.startRollout(f.providerRequest())
	const own = "v26.3.1"
	if err := f.db.SetNodeProviderVersion(f.ctx, f.nodes["B"].ID, proxies.EngineXray, own); err != nil {
		t.Fatal(err)
	}
	f.start()
	f.waitStatus(ro.ID, store.RolloutPaused, 1)
	if err := f.runner.Continue(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	f.waitStatus(ro.ID, store.RolloutPaused, 2)
	if v := f.providerVersion("B"); v != own {
		t.Errorf("B at %q, want its own %q", v, own)
	}
	if evs := f.events(EventNodeKept); len(evs) != 1 || evs[0].NodeID != f.nodes["B"].ID {
		t.Errorf("node kept events %v", evs)
	}
	// An admin gives A, which went through, a version of its own; the abort
	// does not clear it.
	if err := f.db.SetNodeProviderVersion(f.ctx, f.nodes["A"].ID, proxies.EngineXray, own); err != nil {
		t.Fatal(err)
	}
	if err := f.runner.Abort(f.ctx, ro.ID); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"A": own, "B": own, "C": ""} {
		if v := f.providerVersion(name); v != want {
			t.Errorf("node %s at %q after the abort, want %q", name, v, want)
		}
	}
}
