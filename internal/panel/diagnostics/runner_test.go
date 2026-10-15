package diagnostics

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

const (
	ok   = nodev1.CheckStatus_CHECK_STATUS_OK
	warn = nodev1.CheckStatus_CHECK_STATUS_WARN
	fail = nodev1.CheckStatus_CHECK_STATUS_FAIL
)

func TestRunPanelRowsThenNodeStreamInOrder(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	l := e.listener(n.ID, 443, "")
	p := e.proxy(l, nil)
	e.prober.by[p.ID] = proberAnswer{p: store.Probe{OK: true, LatencyMS: 40}}
	f := &fakeNode{results: []*nodev1.DiagnosticResult{
		nodeResult("host.docker", "", ok, "evidence of an ok result is dropped"),
		nodeResult("ingress.bound", "listener:"+l.ID, fail, "not in Health.bound"),
		nodeResult("host.disk", "", warn, "3% free"),
	}}
	e.agent(n.ID, f)
	r := e.runner(0)

	id, err := r.Run(e.ctx, n.ID, ScopeNode, store.RunManual, "", "")
	if err != nil {
		t.Fatal(err)
	}
	run := e.wait(r, id)
	want := []string{
		"panel.connection  ok panel", "panel.state  ok panel", "panel.versions  ok panel", "panel.link_host  ok panel",
		"panel.geoip  ok panel", "ingress.external proxy:" + p.ID + " ok panel",
		"host.docker  ok node", "ingress.bound listener:" + l.ID + " fail node", "host.disk  warn node",
	}
	if got := summary(run); !slices.Equal(got, want) {
		t.Fatalf("results:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if run.State != store.RunDone || run.OK != 7 || run.Fail != 1 || run.Warn != 1 || run.FinishedAt == nil {
		t.Fatalf("run %+v", run)
	}
	for i, x := range run.Results {
		if x.Seq != i {
			t.Fatalf("seq %d at %d", x.Seq, i)
		}
	}
	if run.Results[6].Evidence != "" || run.Results[7].Evidence != "not in Health.bound" || run.Results[7].DurationMS != 3 ||
		run.Results[7].CheckedAt.Unix() != 1_790_000_000 {
		t.Fatalf("node results kept as %+v / %+v", run.Results[6], run.Results[7])
	}
	if got := f.calls(); !slices.Equal(got, []string{"node"}) {
		t.Fatalf("the node was asked for %v", got)
	}
}

func TestRunProxyScope(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	l := e.listener(n.ID, 443, "")
	p := e.proxy(l, nil)
	other := e.proxy(l, nil)
	e.prober.by[p.ID] = proberAnswer{p: store.Probe{Error: "no datacenter answered through the proxy (L1 ok)"}, l1: true}
	f := &fakeNode{}
	e.agent(n.ID, f)
	r := e.runner(0)
	id, err := r.Run(e.ctx, n.ID, "proxy:"+p.ID, store.RunManual, "", "")
	if err != nil {
		t.Fatal(err)
	}
	run := e.wait(r, id)
	got := summary(run)
	if !slices.Contains(got, "ingress.external proxy:"+p.ID+" warn panel") || slices.ContainsFunc(got, func(s string) bool { return strings.Contains(s, other.ID) }) {
		t.Fatalf("results %v", got)
	}
	if c := f.calls(); !slices.Equal(c, []string{"proxy:" + p.ID}) {
		t.Fatalf("scope sent %v", c)
	}
	for _, bad := range []string{"proxy:", "proxy:nope", "listener:x", "nodes"} {
		if _, err := r.Run(e.ctx, n.ID, bad, store.RunManual, "", ""); !errors.Is(err, ErrScope) {
			t.Fatalf("scope %q: %v, want ErrScope", bad, err)
		}
	}
	n2 := e.node(nil)
	if _, err := r.Run(e.ctx, n2.ID, "proxy:"+p.ID, store.RunManual, "", ""); !errors.Is(err, ErrScope) {
		t.Fatalf("a proxy of another node: %v", err)
	}
	if _, err := r.Run(e.ctx, "nope", ScopeNode, store.RunManual, "", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown node: %v", err)
	}
	if _, err := r.Run(e.ctx, n.ID, ScopeNode, "whenever", "", ""); !errors.Is(err, ErrReason) {
		t.Fatalf("unknown reason: %v", err)
	}
}

func TestRunDeadlineIsPartial(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	f := &fakeNode{results: []*nodev1.DiagnosticResult{nodeResult("host.docker", "", ok, "")}, hold: make(chan struct{})}
	e.agent(n.ID, f)
	// Long enough for the first result to arrive on a loaded runner: before
	// it, the run has nothing and fails instead of being partial.
	r := e.runner(3 * time.Second)
	id, err := r.Run(e.ctx, n.ID, ScopeNode, store.RunManual, "", "")
	if err != nil {
		t.Fatal(err)
	}
	run := e.wait(r, id)
	if run.State != store.RunPartial || run.Error == "" {
		t.Fatalf("state %q error %q, want partial", run.State, run.Error)
	}
	if got := summary(run); got[len(got)-1] != "host.docker  ok node" {
		t.Fatalf("the result that came before the deadline is lost: %v", got)
	}
}

// The node has the run's deadline too, and its "deadline exceeded" can come
// before the panel's own timer fires: the run is partial all the same.
func TestRunDeadlineOfTheNodeIsPartial(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	f := &fakeNode{
		results: []*nodev1.DiagnosticResult{nodeResult("host.docker", "", ok, "")},
		err:     connect.NewError(connect.CodeDeadlineExceeded, errors.New("context deadline exceeded")),
	}
	e.agent(n.ID, f)
	r := e.runner(time.Minute)
	id, err := r.Run(e.ctx, n.ID, ScopeNode, store.RunManual, "", "")
	if err != nil {
		t.Fatal(err)
	}
	run := e.wait(r, id)
	if run.State != store.RunPartial || run.Error == "" {
		t.Fatalf("state %q error %q, want partial", run.State, run.Error)
	}
	if got := summary(run); got[len(got)-1] != "host.docker  ok node" {
		t.Fatalf("the result that came before the deadline is lost: %v", got)
	}
}

func TestRunWithoutTheNodeIsSkipped(t *testing.T) {
	cases := []struct {
		name   string
		change func(*store.Node)
		agent  bool
		status string
		hint   bool
	}{
		{"offline", func(n *store.Node) { n.Status = store.NodeStatusOffline }, true, StatusFail, false},
		{"not connected", nil, false, StatusSkip, false},
		{"no capability", func(n *store.Node) { n.HostInfo.Capabilities = nil }, true, StatusSkip, false},
		{"no capability, rejected", func(n *store.Node) { n.HostInfo.Capabilities = nil; n.StateRejection = "bad state" }, true, StatusWarn, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			n := e.node(c.change)
			f := &fakeNode{results: []*nodev1.DiagnosticResult{nodeResult("host.docker", "", ok, "")}}
			if c.agent {
				e.agent(n.ID, f)
			}
			r := e.runner(0)
			id, err := r.Run(e.ctx, n.ID, ScopeNode, store.RunManual, "", "")
			if err != nil {
				t.Fatal(err)
			}
			run := e.wait(r, id)
			if run.State != store.RunSkipped {
				t.Fatalf("state %q, want skipped", run.State)
			}
			conn := run.Results[0]
			if conn.CheckID != "panel.connection" || conn.Status != c.status || !strings.Contains(conn.Summary+conn.Hint, "did not run") {
				t.Fatalf("panel.connection %+v", conn)
			}
			if c.hint && !strings.Contains(conn.Hint, "diagnostics") {
				t.Fatalf("the reason is not in the hint: %+v", conn)
			}
			for _, x := range run.Results {
				if x.Vantage == VantageNode || x.CheckID == "panel.connection" && x != conn {
					t.Fatalf("one panel.connection and no node result expected: %v", summary(run))
				}
			}
			if len(f.calls()) != 0 {
				t.Fatal("the node was asked")
			}
		})
	}
}

func TestBusyNode(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	f := &fakeNode{hold: make(chan struct{}), started: make(chan struct{}, 1)}
	e.agent(n.ID, f)
	r := e.runner(0)
	audits := 0
	audit := func() error { audits++; return nil }
	first, joined, err := r.StartManual(e.ctx, n.ID, ScopeNode, "a1", audit)
	if err != nil || joined {
		t.Fatal(err, joined)
	}
	<-f.started
	if again, joined, err := r.StartManual(e.ctx, n.ID, ScopeNode, "a1", audit); err != nil || !joined || again != first || audits != 1 {
		t.Fatalf("a second manual run: %q %v %v audits=%d, want the running %q", again, joined, err, audits, first)
	}
	if id, ok := r.Running(n.ID); !ok || id != first {
		t.Fatalf("Running: %q %v", id, ok)
	}
	short, cancel := context.WithTimeout(e.ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := r.Run(short, n.ID, ScopeNode, store.RunAfterChange, "x", ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run on a busy node: %v, want it to wait until its ctx ends", err)
	}
	// Wait with a short ctx returns the run as it is.
	short2, cancel2 := context.WithTimeout(e.ctx, 50*time.Millisecond)
	defer cancel2()
	if run, err := r.Wait(short2, first); !errors.Is(err, context.DeadlineExceeded) || run == nil || run.State != store.RunRunning {
		t.Fatalf("Wait: %+v %v", run, err)
	}
	type res struct {
		id  string
		err error
	}
	done := make(chan res, 1)
	go func() {
		id, err := r.Run(e.ctx, n.ID, ScopeNode, store.RunAfterChange, "x", "")
		done <- res{id, err}
	}()
	select {
	case <-done:
		t.Fatal("Run did not wait for the running run")
	case <-time.After(100 * time.Millisecond):
	}
	close(f.hold)
	got := <-done
	if got.err != nil || got.id == first {
		t.Fatalf("Run after the busy run: %+v", got)
	}
	if run := e.wait(r, first); run.State != store.RunDone || run.AdminID != "a1" {
		t.Fatalf("first run %+v", run)
	}
	e.wait(r, got.id)
}

func TestAuditFailureStartsNothing(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	r := e.runner(0)
	if _, _, err := r.StartManual(e.ctx, n.ID, ScopeNode, "a1", func() error { return errors.New("disk full") }); err == nil {
		t.Fatal("started without an audit")
	}
	if _, ok := r.Running(n.ID); ok {
		t.Fatal("a run is running")
	}
	if runs, _ := e.db.ListDiagnosticRuns(e.ctx, n.ID, nil, 10); len(runs) != 0 {
		t.Fatalf("runs %+v", runs)
	}
}

func TestRegression(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	f := &fakeNode{results: []*nodev1.DiagnosticResult{
		nodeResult("a.ok", "", ok, ""), nodeResult("b.warn", "proxy:p1", warn, "w"), nodeResult("c.fail", "", fail, "f"),
		nodeResult("d.ok", "", ok, ""),
	}}
	e.agent(n.ID, f)
	r := e.runner(0)
	before := e.wait(r, must(r.Run(e.ctx, n.ID, ScopeNode, store.RunBeforeChange, "egress of proxy p1", "")))

	f.mu.Lock()
	f.results = []*nodev1.DiagnosticResult{
		nodeResult("a.ok", "", fail, "x"), nodeResult("b.warn", "proxy:p1", fail, "y"), nodeResult("c.fail", "", fail, "z"),
		nodeResult("d.ok", "", ok, ""), nodeResult("e.new", "", fail, "new"),
	}
	f.mu.Unlock()
	after := e.wait(r, must(r.Run(e.ctx, n.ID, ScopeNode, store.RunAfterChange, "egress of proxy p1", before.ID)))
	if !after.Regressed {
		t.Fatal("not regressed")
	}
	evs := events(t, e.db, "diagnostics.regressed")
	if len(evs) != 1 || evs[0].Severity != "error" || !strings.Contains(evs[0].Message, "egress of proxy p1") ||
		!strings.Contains(evs[0].Message, "a.ok") || !strings.Contains(evs[0].Message, "b.warn (proxy:p1)") ||
		strings.Contains(evs[0].Message, "c.fail") || strings.Contains(evs[0].Message, "e.new") || evs[0].Details["run_id"] != after.ID {
		t.Fatalf("events %+v", evs)
	}
	// A manual run is never compared, nor is an after-run without a related run.
	for _, reason := range []string{store.RunManual, store.RunAfterChange} {
		related := before.ID
		if reason == store.RunAfterChange {
			related = ""
		}
		run := e.wait(r, must(r.Run(e.ctx, n.ID, ScopeNode, reason, "c", related)))
		if run.Regressed {
			t.Fatalf("%s regressed", reason)
		}
	}
	if len(events(t, e.db, "diagnostics.regressed")) != 1 {
		t.Fatal("another regression was recorded")
	}
}

func must(id string, err error) string {
	if err != nil {
		panic(err)
	}
	return id
}

func TestCopyLight(t *testing.T) {
	e := newEnv(t)
	n := e.node(func(n *store.Node) { n.DefaultChainID = "" })
	l := e.listener(n.ID, 443, "")
	p := e.proxy(l, nil)
	at := time.Unix(1_790_000_000, 0)
	_, err := e.db.ReplaceNodeChecks(e.ctx, n.ID, []store.NodeCheck{
		{CheckID: "host.docker", Layer: "host", Status: "ok", Evidence: "dropped"},
		{CheckID: "ingress.bound", Layer: "ingress", Target: "listener:" + l.ID, Status: "fail", Evidence: "kept"},
		{CheckID: "ingress.bound", Layer: "ingress", Target: "listener:other", Status: "fail"},
		{CheckID: "e2e.l1", Layer: "e2e", Target: "proxy:" + p.ID, Status: "ok"},
		{CheckID: "e2e.l1", Layer: "e2e", Target: "proxy:other", Status: "ok"},
	}, at)
	if err != nil {
		t.Fatal(err)
	}
	r := e.runner(0)
	id, err := r.CopyLight(e.ctx, n.ID, "proxy:"+p.ID, "egress of the proxy")
	if err != nil {
		t.Fatal(err)
	}
	run, err := e.db.DiagnosticRun(e.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"e2e.l1 proxy:" + p.ID + " ok node", "host.docker  ok node", "ingress.bound listener:" + l.ID + " fail node"}
	if got := summary(run); !slices.Equal(got, want) {
		t.Fatalf("results %v, want %v", got, want)
	}
	if run.State != store.RunDone || run.Reason != store.RunBeforeChange || run.Change != "egress of the proxy" || run.FinishedAt == nil ||
		run.Results[1].Evidence != "" || run.Results[2].Evidence != "kept" {
		t.Fatalf("run %+v", run)
	}
	if id, err := r.CopyLight(e.ctx, n.ID, ScopeNode, ""); err != nil {
		t.Fatal(err)
	} else if run, _ := e.db.DiagnosticRun(e.ctx, id); len(run.Results) != 5 {
		t.Fatalf("scope node: %v", summary(run))
	}
}

func TestTargetsOfAProxy(t *testing.T) {
	n := &store.Node{DefaultChainID: "D"}
	p := &store.Proxy{ID: "p1", ListenerID: "L1", EgressScopeChains: map[string]string{"me": "M"}}
	in := targetsOf(scopeOf{node: n, proxy: p})
	for target, want := range map[string]bool{
		"": true, "listener:L1": true, "proxy:p1": true, "member:D/a": true, "member:M/x/y": true,
		"listener:L2": false, "proxy:p2": false, "member:E/a": false, "member:": false,
	} {
		if in(target) != want {
			t.Errorf("%q: %v", target, !want)
		}
	}
	p.EgressChainID = "C"
	in = targetsOf(scopeOf{node: n, proxy: p})
	if in("member:D/a") || !in("member:C/a") {
		t.Error("an own chain replaces the node's default")
	}
}

func TestEvidenceLimits(t *testing.T) {
	b := budget{left: maxRunEvidence}
	big := strings.Repeat("é", 2000) // 4000 bytes
	total := 0
	for range 40 {
		ev := b.take(StatusFail, big)
		if len(ev) > maxEvidence || !strings.HasPrefix(big, ev) || len(ev)%2 != 0 {
			t.Fatalf("evidence of %d bytes, or cut inside a character", len(ev))
		}
		total += len(ev)
	}
	if total > maxRunEvidence || total < maxRunEvidence-2 {
		t.Fatalf("evidence of a run: %d bytes", total)
	}
	if b.take(StatusWarn, "more") != "" {
		t.Fatal("evidence past the run's limit")
	}
	b = budget{left: maxRunEvidence}
	if b.take(StatusOK, "x") != "" || b.take(StatusSkip, "x") != "" || b.take(StatusWarn, "x") != "x" {
		t.Fatal("evidence only for warn and fail")
	}
	if clip("aé", 2) != "a" || clip("abc", 5) != "abc" || clip("abc", 0) != "" {
		t.Fatal("clip")
	}
}

func TestRunEvidenceLimitInTheStore(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	var rs []*nodev1.DiagnosticResult
	for range 40 {
		rs = append(rs, nodeResult("x.fail", "", fail, strings.Repeat("e", 3000)))
	}
	rs = append(rs, &nodev1.DiagnosticResult{Id: "long", Status: ok, Summary: strings.Repeat("s", 300)})
	e.agent(n.ID, &fakeNode{results: rs})
	r := e.runner(0)
	run := e.wait(r, must(r.Run(e.ctx, n.ID, ScopeNode, store.RunManual, "", "")))
	total := 0
	for _, x := range run.Results {
		total += len(x.Evidence)
		if len(x.Evidence) > maxEvidence || len(x.Summary) > maxSummary {
			t.Fatalf("result %s: evidence %d, summary %d", x.CheckID, len(x.Evidence), len(x.Summary))
		}
	}
	if total > maxRunEvidence {
		t.Fatalf("evidence of the run: %d", total)
	}
}

func TestStartFailsLeftoverRuns(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	left := &store.DiagnosticRun{NodeID: n.ID, Scope: ScopeNode, Reason: store.RunManual}
	if err := e.db.CreateDiagnosticRun(e.ctx, left); err != nil {
		t.Fatal(err)
	}
	e.runner(0).Start(e.ctx)
	run, _ := e.db.DiagnosticRun(e.ctx, left.ID)
	if run.State != store.RunFailed {
		t.Fatalf("leftover run %+v", run)
	}
}
