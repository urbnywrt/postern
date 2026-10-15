package diagnostics

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// A fix from an old run, or for a check that passes now, is stale: no action,
// no audit. A run that is the node's latest of its scope, with the check
// failing in it, still offers its fix when the light checks do not have the
// check.
func TestApplyFixStale(t *testing.T) {
	f := newFixEnv(t)
	n := f.node(func(n *store.Node) {
		n.HostInfo.Capabilities = []string{"diagnostics", "restart-nonce", "edge-roll-nonce", "egress-xray"}
	})
	p := f.proxy(f.listener(n.ID, 443, ""), nil)
	f.agent(n.ID, &fakeNode{})
	sub := f.egress(store.EgressKindXraySubscription, "")
	proxyT, member := "proxy:"+p.ID, "member:C1/"+sub.ID
	old := f.storedRun(n.ID,
		store.DiagnosticResult{CheckID: "engine.ready", Layer: "engine", Target: proxyT, Status: StatusFail, Fix: FixRecreateInstance, Vantage: VantageNode},
		store.DiagnosticResult{CheckID: "panel.versions", Layer: "panel", Status: StatusWarn, Fix: FixRollEdge, Vantage: VantagePanel},
		store.DiagnosticResult{CheckID: "egress.member", Layer: "egress", Target: member, Status: StatusWarn, Fix: FixRefreshSubscription, Vantage: VantageNode})
	reqs := []*panelv1.ApplyFixRequest{
		{NodeId: n.ID, CheckId: "engine.ready", Target: proxyT, Fix: FixRecreateInstance, OfferedRunId: old},
		{NodeId: n.ID, CheckId: "panel.versions", Fix: FixRollEdge, OfferedRunId: old},
		{NodeId: n.ID, CheckId: "egress.member", Target: member, Fix: FixRefreshSubscription, OfferedRunId: old},
	}
	// The light checks pass now.
	f.lights(n.ID, store.NodeCheck{CheckID: "engine.ready", Target: proxyT, Layer: "engine", Status: StatusOK},
		store.NodeCheck{CheckID: "egress.member", Target: member, Layer: "egress", Status: StatusOK})
	// panel.versions has no light check: a newer run of the scope makes the
	// old one stale.
	time.Sleep(1100 * time.Millisecond) // runs are ordered by their start, in seconds
	f.storedRun(n.ID, store.DiagnosticResult{CheckID: "host.docker", Layer: "host", Status: StatusOK, Vantage: VantageNode})
	for _, req := range reqs {
		if _, err := f.apply(req); codeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "stale") {
			t.Errorf("%s from an old run: %v", req.GetFix(), err)
		}
		light := &panelv1.ApplyFixRequest{NodeId: req.GetNodeId(), CheckId: req.GetCheckId(), Target: req.GetTarget(), Fix: req.GetFix()}
		if _, err := f.apply(light); codeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "stale") {
			t.Errorf("%s from the light checks: %v", req.GetFix(), err)
		}
	}
	if got := f.fa.got(); len(got) != 0 {
		t.Errorf("actions %v", got)
	}
	if got := auditCount(t, f.env, "diagnostics.fix"); got != 0 {
		t.Errorf("%d audit entries", got)
	}
	// The latest run, with the check failing, still offers it.
	time.Sleep(1100 * time.Millisecond)
	latest := f.storedRun(n.ID, store.DiagnosticResult{CheckID: "panel.versions", Layer: "panel", Status: StatusWarn, Fix: FixRollEdge, Vantage: VantagePanel})
	if _, err := f.apply(&panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: "panel.versions", Fix: FixRollEdge, OfferedRunId: latest}); err != nil {
		t.Errorf("roll_edge from the latest run: %v", err)
	}
	if got := f.fa.got(); len(got) != 1 {
		t.Errorf("actions %v", got)
	}
}

// Repeated changes of a node and scope wait for one after-run: of the latest
// generation, related to the first before-run.
func TestAfterRunsOncePerScope(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	e.agent(n.ID, &fakeNode{})
	r := e.runner(0)
	c := e.changes(r, nil)
	first := c.Before(e.ctx, n.ID, ScopeNode, "edit 1")
	e.wait(r, first)
	var gens []uint64
	for i := range 3 {
		gen, err := e.db.NextNodeGeneration(e.ctx, n.ID)
		if err != nil {
			t.Fatal(err)
		}
		gens = append(gens, gen)
		before := first
		if i > 0 {
			before = fmt.Sprint("later-", i)
		}
		c.After(n.ID, ScopeNode, "edit", before, gen)
	}
	c.mu.Lock()
	pending := len(c.pending)
	c.mu.Unlock()
	if pending != 1 {
		t.Errorf("%d pending after-runs, want 1", pending)
	}
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error { n.AppliedGeneration = gens[0]; return nil }); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := ofReason(e.runsOf(n.ID), store.RunAfterChange); len(got) != 0 {
		t.Fatalf("an after-run before the latest generation was applied: %+v", got[0])
	}
	if _, err := e.db.ModifyNode(e.ctx, n.ID, func(n *store.Node) error { n.AppliedGeneration = gens[2]; return nil }); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the after-run", func() bool { return len(ofReason(e.runsOf(n.ID), store.RunAfterChange)) == 1 })
	time.Sleep(300 * time.Millisecond)
	after := ofReason(e.runsOf(n.ID), store.RunAfterChange)
	if len(after) != 1 || after[0].RelatedRunID != first || !strings.Contains(after[0].Change, "2 later changes") {
		t.Errorf("after-runs %+v", after)
	}
}
