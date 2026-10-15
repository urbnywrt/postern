package diagnostics

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/ids"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// fakeActions records the actions of the fixes; each raises the node's
// generation, as the services do.
type fakeActions struct {
	db *store.DB

	mu    sync.Mutex
	calls []string
}

func (f *fakeActions) record(ctx context.Context, nodeID, call string) (uint64, error) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
	return f.db.NextNodeGeneration(ctx, nodeID)
}

func (f *fakeActions) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeActions) actions(nodeOfProxy func(string) string) Actions {
	return Actions{
		RestartInstance: func(ctx context.Context, proxyID string) (uint64, error) {
			return f.record(ctx, nodeOfProxy(proxyID), "restart "+proxyID)
		},
		RollEdge: func(ctx context.Context, nodeID string) (uint64, error) { return f.record(ctx, nodeID, "roll "+nodeID) },
		ChangeEgress: func(ctx context.Context, proxyID, chainID string) error {
			_, err := f.record(ctx, nodeOfProxy(proxyID), "egress "+proxyID+" "+chainID)
			return err
		},
		RefreshSubscription: func(ctx context.Context, egressID string) error {
			f.mu.Lock()
			f.calls = append(f.calls, "refresh "+egressID)
			f.mu.Unlock()
			return nil
		},
		SetDNSModeDoH: func(ctx context.Context, nodeID string) error {
			_, err := f.record(ctx, nodeID, "doh "+nodeID)
			return err
		},
		ReissueCert: func(ctx context.Context, proxyID string) (uint64, error) {
			return f.record(ctx, nodeOfProxy(proxyID), "reissue "+proxyID)
		},
	}
}

type fixEnv struct {
	*env
	r   *Runner
	c   *Changes
	fa  *fakeActions
	api *api
}

func newFixEnv(t *testing.T) *fixEnv {
	e := newEnv(t)
	r := e.runner(0)
	c := e.changes(r, nil)
	fa := &fakeActions{db: e.db}
	svc := NewService(e.db, r, nil)
	svc.SetFixes(c, fa.actions(func(id string) string {
		p, err := e.db.ProxyByID(context.Background(), id)
		if err != nil {
			t.Error(err)
			return ""
		}
		return p.NodeID
	}))
	return &fixEnv{env: e, r: r, c: c, fa: fa, api: newAPIFor(t, e, svc)}
}

func (f *fixEnv) apply(req *panelv1.ApplyFixRequest) (*panelv1.ApplyFixResponse, error) {
	resp, err := f.api.admin.ApplyFix(f.ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// applied marks the node's desired generation applied.
func (f *fixEnv) applied(nodeID string) {
	f.t.Helper()
	if _, err := f.db.ModifyNode(f.ctx, nodeID, func(n *store.Node) error { n.AppliedGeneration = n.DesiredGeneration; return nil }); err != nil {
		f.t.Fatal(err)
	}
}

// An offer from the light checks: the light copy is the before-run; the fix
// raises the nonce through its action, is audited and recorded, and its
// after-run, related to the before-run, follows once the node applied it.
func TestApplyFixFromTheLightChecks(t *testing.T) {
	f := newFixEnv(t)
	n := f.node(nil)
	p := f.proxy(f.listener(n.ID, 443, ""), nil)
	f.agent(n.ID, &fakeNode{})
	target := "proxy:" + p.ID
	f.lights(n.ID, store.NodeCheck{CheckID: "engine.ready", Target: target, Layer: "engine", Status: StatusFail, Fix: FixRecreateInstance})

	resp, err := f.apply(&panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: "engine.ready", Target: target, Fix: FixRecreateInstance})
	if err != nil {
		t.Fatalf("ApplyFix: %v", err)
	}
	if got := f.fa.got(); len(got) != 1 || got[0] != "restart "+p.ID {
		t.Errorf("actions %v", got)
	}
	node, _ := f.db.NodeByID(f.ctx, n.ID)
	if resp.GetGeneration() != node.DesiredGeneration || resp.GetGeneration() == 0 {
		t.Errorf("generation %d, the node's %d", resp.GetGeneration(), node.DesiredGeneration)
	}
	before, err := f.db.DiagnosticRun(f.ctx, resp.GetBeforeRunId())
	if err != nil || before.Reason != store.RunBeforeChange || before.Scope != target || len(before.Results) != 1 || before.Results[0].Status != StatusFail {
		t.Fatalf("before-run %+v, %v", before, err)
	}
	if got := auditCount(t, f.env, "diagnostics.fix"); got != 1 {
		t.Errorf("%d audit entries", got)
	}
	ev := events(t, f.db, "diagnostics.fix_applied")
	if len(ev) != 1 || ev[0].ProxyID != p.ID || ev[0].Details["fix"] != FixRecreateInstance || ev[0].Details["before_run_id"] != before.ID {
		t.Errorf("events %+v", ev)
	}
	f.applied(n.ID)
	eventually(t, "the after-run", func() bool { return len(ofReason(f.runsOf(n.ID), store.RunAfterChange)) == 1 })
	after := ofReason(f.runsOf(n.ID), store.RunAfterChange)[0]
	if after.RelatedRunID != before.ID || after.Scope != target || after.Change != "fix recreate_instance" {
		t.Errorf("after-run %+v", after)
	}
}

// storedRun stores a finished run with results.
func (f *fixEnv) storedRun(nodeID string, results ...store.DiagnosticResult) string {
	f.t.Helper()
	run := &store.DiagnosticRun{NodeID: nodeID, Scope: ScopeNode, Reason: store.RunManual, StartedAt: time.Now()}
	if err := f.db.CreateDiagnosticRun(f.ctx, run); err != nil {
		f.t.Fatal(err)
	}
	for i, x := range results {
		x.Seq = i
		if err := f.db.AddDiagnosticResult(f.ctx, run.ID, x); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := f.db.FinishDiagnosticRun(f.ctx, run.ID, store.RunDone, "", false, time.Now()); err != nil {
		f.t.Fatal(err)
	}
	return run.ID
}

// The feed's edge.outdated offers roll_edge for panel.versions with no run:
// ApplyFix takes it while the node's edge and agent versions differ, with a
// light copy as the before-run, and finds it stale once they are the same.
func TestApplyFixRollEdgeFromTheFeed(t *testing.T) {
	f := newFixEnv(t)
	n := f.node(func(n *store.Node) {
		n.EdgeVersion = "1.1.0"
		n.HostInfo.Capabilities = []string{"diagnostics", "edge-roll-nonce"}
	})
	f.agent(n.ID, &fakeNode{})
	feed := NewFeed(FeedConfig{DB: f.db})
	problems, err := feed.List(f.ctx, n.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	var offer *panelv1.Problem
	for _, p := range problems {
		if p.GetKind() == KindEdgeOutdated && p.GetNodeId() == n.ID {
			offer = p
		}
	}
	if offer == nil || offer.GetCheckId() != "panel.versions" || offer.GetFix() != FixRollEdge || !offer.GetFixAvailable() {
		t.Fatalf("the feed's offer %v", offer)
	}

	// A target, or another fix, is not what the panel offers.
	for _, req := range []*panelv1.ApplyFixRequest{
		{NodeId: n.ID, CheckId: "panel.versions", Target: "proxy:x", Fix: FixRollEdge},
		{NodeId: n.ID, CheckId: "panel.versions", Fix: FixSetDNSModeDoH},
	} {
		if _, err := f.apply(req); codeOf(err) != connect.CodeFailedPrecondition {
			t.Errorf("ApplyFix(%v): %v, want failed_precondition", req, err)
		}
	}
	resp, err := f.apply(&panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: offer.GetCheckId(), Target: offer.GetTarget(), Fix: offer.GetFix()})
	if err != nil {
		t.Fatalf("ApplyFix from the feed: %v", err)
	}
	if got := f.fa.got(); len(got) != 1 || got[0] != "roll "+n.ID {
		t.Errorf("actions %v", got)
	}
	if before, err := f.db.DiagnosticRun(f.ctx, resp.GetBeforeRunId()); err != nil || before.Reason != store.RunBeforeChange {
		t.Errorf("before-run %+v, %v", before, err)
	}

	if _, err := f.db.ModifyNode(f.ctx, n.ID, func(n *store.Node) error { n.EdgeVersion = n.AgentVersion; return nil }); err != nil {
		t.Fatal(err)
	}
	_, err = f.apply(&panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: "panel.versions", Fix: FixRollEdge})
	if codeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "stale") {
		t.Errorf("the edge on the agent's version: %v, want stale", err)
	}
	if got := len(f.fa.got()); got != 1 {
		t.Errorf("%d actions, want 1", got)
	}
}

// A fix offered by a run has that run as its before-run.
func TestApplyFixFromARun(t *testing.T) {
	f := newFixEnv(t)
	n := f.node(func(n *store.Node) { n.HostInfo.Capabilities = []string{"diagnostics", "edge-roll-nonce"} })
	f.agent(n.ID, &fakeNode{})
	offered := f.storedRun(n.ID, store.DiagnosticResult{CheckID: "panel.versions", Layer: "panel", Status: StatusWarn, Fix: FixRollEdge, Vantage: VantagePanel})

	resp, err := f.apply(&panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: "panel.versions", Fix: FixRollEdge, OfferedRunId: offered})
	if err != nil {
		t.Fatalf("ApplyFix: %v", err)
	}
	if resp.GetBeforeRunId() != offered {
		t.Errorf("before-run %s, want the offered %s", resp.GetBeforeRunId(), offered)
	}
	if got := f.fa.got(); len(got) != 1 || got[0] != "roll "+n.ID {
		t.Errorf("actions %v", got)
	}
	if b := ofReason(f.runsOf(n.ID), store.RunBeforeChange); len(b) != 0 {
		t.Errorf("a light copy was made: %+v", b[0])
	}
	f.applied(n.ID)
	eventually(t, "the after-run", func() bool { return len(ofReason(f.runsOf(n.ID), store.RunAfterChange)) == 1 })
	if after := ofReason(f.runsOf(n.ID), store.RunAfterChange)[0]; after.RelatedRunID != offered || after.Scope != ScopeNode {
		t.Errorf("after-run %+v", after)
	}

	// The run offered no such fix, or is of another node.
	_, err = f.apply(&panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: "panel.state", Fix: FixRollEdge, OfferedRunId: offered})
	if codeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "did not offer") {
		t.Errorf("a fix the run did not offer: %v", err)
	}
	other := f.node(func(n *store.Node) { n.HostInfo.Capabilities = []string{"edge-roll-nonce"} })
	_, err = f.apply(&panelv1.ApplyFixRequest{NodeId: other.ID, CheckId: "panel.versions", Fix: FixRollEdge, OfferedRunId: offered})
	if codeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("the run of another node: %v", err)
	}
	if got := len(f.fa.got()); got != 1 {
		t.Errorf("%d actions, want 1", got)
	}
}

func TestApplyFixRefusals(t *testing.T) {
	f := newFixEnv(t)
	old := f.node(func(n *store.Node) { n.HostInfo.Capabilities = []string{"diagnostics"} })
	p := f.proxy(f.listener(old.ID, 443, ""), nil)
	target := "proxy:" + p.ID
	f.lights(old.ID, store.NodeCheck{CheckID: "engine.ready", Target: target, Layer: "engine", Status: StatusFail, Fix: FixRecreateInstance},
		store.NodeCheck{CheckID: "host.dns", Layer: "host", Status: StatusFail, Fix: FixSetDNSModeDoH})

	for _, tc := range []struct {
		name string
		req  *panelv1.ApplyFixRequest
		code connect.Code
		text string
	}{
		{"no capability", &panelv1.ApplyFixRequest{NodeId: old.ID, CheckId: "engine.ready", Target: target, Fix: FixRecreateInstance},
			connect.CodeFailedPrecondition, "restart-nonce"},
		{"no forwarder", &panelv1.ApplyFixRequest{NodeId: old.ID, CheckId: "host.dns", Fix: FixSetDNSModeDoH},
			connect.CodeFailedPrecondition, "dns-forwarder"},
		{"unknown fix", &panelv1.ApplyFixRequest{NodeId: old.ID, CheckId: "engine.ready", Target: target, Fix: "reboot"},
			connect.CodeInvalidArgument, "does not know"},
		{"no node", &panelv1.ApplyFixRequest{CheckId: "engine.ready", Fix: FixRecreateInstance}, connect.CodeInvalidArgument, "node_id"},
		{"a fix for the node on a proxy", &panelv1.ApplyFixRequest{NodeId: old.ID, CheckId: "host.dns", Target: target, Fix: FixRollEdge},
			connect.CodeFailedPrecondition, "applies to the node"},
	} {
		_, err := f.apply(tc.req)
		if codeOf(err) != tc.code || !strings.Contains(err.Error(), tc.text) {
			t.Errorf("%s: %v, want %v with %q", tc.name, err, tc.code, tc.text)
		}
	}

	// The light checks no longer offer it.
	n := f.node(nil)
	q := f.proxy(f.listener(n.ID, 443, ""), nil)
	_, err := f.apply(&panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: "engine.ready", Target: "proxy:" + q.ID, Fix: FixRecreateInstance})
	if codeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "stale") {
		t.Errorf("not offered: %v", err)
	}
	// reissue_cert is for a WEB proxy only.
	web := f.node(func(n *store.Node) { n.HostInfo.Capabilities = []string{"web-diagnostics"} })
	w := f.proxy(f.listener(web.ID, 443, ""), nil)
	f.lights(web.ID, store.NodeCheck{CheckID: "web.cert", Target: "proxy:" + w.ID, Layer: "web", Status: StatusFail, Fix: FixReissueCert})
	_, err = f.apply(&panelv1.ApplyFixRequest{NodeId: web.ID, CheckId: "web.cert", Target: "proxy:" + w.ID, Fix: FixReissueCert})
	if codeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "not a WEB proxy") {
		t.Errorf("reissue_cert of a fake-TLS proxy: %v", err)
	}
	if got := f.fa.got(); len(got) != 0 {
		t.Errorf("actions %v", got)
	}
	if got := auditCount(t, f.env, "diagnostics.fix"); got != 0 {
		t.Errorf("%d audit entries of refused fixes", got)
	}
}

func (f *fixEnv) chain(nodeID string, members ...string) *store.EgressChain {
	f.t.Helper()
	c := &store.EgressChain{ID: ids.New(), Name: "c-" + ids.New()[:6], NodeID: nodeID, Members: members}
	if err := f.db.CreateChain(f.ctx, c); err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *fixEnv) egress(kind, nodeID string) *store.Egress {
	f.t.Helper()
	e := &store.Egress{ID: ids.New(), Name: "e-" + ids.New()[:6], Kind: kind, NodeID: nodeID}
	if err := f.db.CreateEgress(f.ctx, e); err != nil {
		f.t.Fatal(err)
	}
	return e
}

// change_egress needs a chain that the node can use, other than the proxy's.
func TestApplyFixChangeEgress(t *testing.T) {
	f := newFixEnv(t)
	n := f.node(nil)
	other := f.node(nil)
	p := f.proxy(f.listener(n.ID, 443, ""), nil)
	f.agent(n.ID, &fakeNode{})
	target := "proxy:" + p.ID
	f.lights(n.ID, store.NodeCheck{CheckID: "e2e.l2", Target: target, Layer: "e2e", Status: StatusFail, Fix: FixChangeEgress})
	direct := f.egress(store.EgressKindDirect, "")
	shared := f.chain("", direct.ID)
	foreign := f.chain(other.ID, direct.ID)
	empty := f.chain("")
	req := func(chain string) *panelv1.ApplyFixRequest {
		return &panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: "e2e.l2", Target: target, Fix: FixChangeEgress, ChainId: chain}
	}
	for _, tc := range []struct {
		chain string
		code  connect.Code
		text  string
	}{
		{"", connect.CodeInvalidArgument, "chain_id"},
		{foreign.ID, connect.CodeFailedPrecondition, "another node"},
		{ids.New(), connect.CodeFailedPrecondition, "no egress chain"},
		{empty.ID, connect.CodeFailedPrecondition, "no members"},
	} {
		if _, err := f.apply(req(tc.chain)); codeOf(err) != tc.code || !strings.Contains(err.Error(), tc.text) {
			t.Errorf("chain %q: %v, want %v with %q", tc.chain, err, tc.code, tc.text)
		}
	}
	if _, err := f.apply(req(shared.ID)); err != nil {
		t.Fatalf("ApplyFix: %v", err)
	}
	if got := f.fa.got(); len(got) != 1 || got[0] != "egress "+p.ID+" "+shared.ID {
		t.Errorf("actions %v", got)
	}
	if ev := events(t, f.db, "diagnostics.fix_applied"); len(ev) != 1 || ev[0].Details["chain_id"] != shared.ID {
		t.Errorf("events %+v", ev)
	}
	// The proxy goes out through it already.
	stored, err := f.db.ProxyByID(f.ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored.EgressChainID = shared.ID
	if err := f.db.UpdateProxy(f.ctx, stored); err != nil {
		t.Fatal(err)
	}
	if _, err := f.apply(req(shared.ID)); codeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "already") {
		t.Errorf("the same chain: %v", err)
	}
}

func TestApplyFixRefreshAndDNS(t *testing.T) {
	f := newFixEnv(t)
	n := f.node(func(n *store.Node) {
		n.HostInfo.Capabilities = []string{"diagnostics", "egress-xray", "dns-forwarder"}
		n.DNSMode = "system"
	})
	f.agent(n.ID, &fakeNode{})
	sub := f.egress(store.EgressKindXraySubscription, "")
	member := "member:C1/" + sub.ID + "/k1"
	f.lights(n.ID, store.NodeCheck{CheckID: "egress.member", Target: member, Layer: "egress", Status: StatusWarn, Fix: FixRefreshSubscription},
		store.NodeCheck{CheckID: "host.dns", Layer: "host", Status: StatusFail, Fix: FixSetDNSModeDoH})

	if _, err := f.apply(&panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: "egress.member", Target: member, Fix: FixRefreshSubscription}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := f.apply(&panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: "host.dns", Fix: FixSetDNSModeDoH}); err != nil {
		t.Fatalf("doh: %v", err)
	}
	if got := f.fa.got(); len(got) != 2 || got[0] != "refresh "+sub.ID || got[1] != "doh "+n.ID {
		t.Errorf("actions %v", got)
	}
	if got := auditCount(t, f.env, "diagnostics.fix"); got != 2 {
		t.Errorf("%d audit entries", got)
	}
}

// reissue_cert of a WEB proxy: offered to a node with web-diagnostics only;
// applied through its action, with its runs.
func TestApplyFixReissueCert(t *testing.T) {
	f := newFixEnv(t)
	for _, caps := range [][]string{{"web-diagnostics"}, {"diagnostics", "restart-nonce"}} {
		n := f.node(func(n *store.Node) { n.HostInfo.Capabilities = caps })
		p := f.proxy(f.listener(n.ID, 443, ""), func(p *store.Proxy) {
			p.Type, p.WebSecretMode, p.CertMode, p.Domain = store.ProxyTypeWeb, "plain", "acme-dns01", "web.example.com"
		})
		f.agent(n.ID, &fakeNode{})
		target := "proxy:" + p.ID
		f.lights(n.ID, store.NodeCheck{CheckID: "web.cert", Target: target, Layer: "web", Status: StatusWarn, Fix: FixReissueCert})
		resp, err := f.apply(&panelv1.ApplyFixRequest{NodeId: n.ID, CheckId: "web.cert", Target: target, Fix: FixReissueCert})
		if caps[0] != "web-diagnostics" {
			if codeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "web-diagnostics") {
				t.Errorf("a node without web-diagnostics: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ApplyFix: %v", err)
		}
		if got := f.fa.got(); len(got) != 1 || got[0] != "reissue "+p.ID {
			t.Errorf("actions %v", got)
		}
		if resp.GetGeneration() == 0 || resp.GetBeforeRunId() == "" {
			t.Errorf("response %v", resp)
		}
		if got := auditCount(t, f.env, "diagnostics.fix"); got != 1 {
			t.Errorf("%d audit entries", got)
		}
	}
	if got := f.fa.got(); len(got) != 1 {
		t.Errorf("actions %v: the node without the capability got one", got)
	}
}
