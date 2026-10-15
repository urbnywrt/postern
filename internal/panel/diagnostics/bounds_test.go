package diagnostics

import (
	"strings"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// oversized is a result of a misbehaving node: every text field far too
// long. Its id is distinct within its first 128 bytes.
func oversized(i int) *nodev1.DiagnosticResult {
	long := strings.Repeat("x", 5000)
	return &nodev1.DiagnosticResult{Id: string(rune(0x100+i)) + long, Layer: long, Target: "proxy:" + long, Status: fail,
		Summary: long, Evidence: long, Hint: strings.Repeat("h", 20000), Fix: long}
}

func within(t *testing.T, id, layer, target, fix, summary, hint, evidence string) {
	t.Helper()
	if len(id) > maxName || len(layer) > maxName || len(target) > maxName || len(fix) > maxName ||
		len(summary) > maxSummary || len(hint) > maxHint || len(evidence) > maxEvidence {
		t.Fatalf("stored beyond the limits: id %d layer %d target %d fix %d summary %d hint %d evidence %d",
			len(id), len(layer), len(target), len(fix), len(summary), len(hint), len(evidence))
	}
}

func TestANodeCannotOverfillARun(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	var rs []*nodev1.DiagnosticResult
	for i := range maxResults + 100 {
		rs = append(rs, oversized(i))
	}
	e.agent(n.ID, &fakeNode{results: rs})
	r := e.runner(0)
	// 600 oversized results take seconds to store, many more under the load
	// of a full test run: the run is waited for as long as it may last
	// (RunTimeout); its outcome depends on the count, not on time.
	run := e.waitWithin(r, must(r.Run(e.ctx, n.ID, ScopeNode, store.RunManual, "", "")), 5*time.Minute)
	if len(run.Results) != maxResults || run.State != store.RunPartial || !strings.Contains(run.Error, "500") {
		t.Fatalf("%d results, state %q, error %q", len(run.Results), run.State, run.Error)
	}
	total := 0
	for _, x := range run.Results {
		within(t, x.CheckID, x.Layer, x.Target, x.Fix, x.Summary, x.Hint, x.Evidence)
		total += len(x.Evidence)
	}
	if total > maxRunEvidence {
		t.Fatalf("evidence %d", total)
	}
}

func TestANodeCannotOverfillItsLightChecks(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	var rs []*nodev1.DiagnosticResult
	for i := range maxResults + 100 {
		rs = append(rs, oversized(i))
	}
	if err := NewLights(e.db, nil, nil).OnDiagnostics(e.ctx, n.ID, time.Now(), &nodev1.DiagnosticsReport{Results: rs}); err != nil {
		t.Fatal(err)
	}
	checks, err := e.db.NodeChecks(e.ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != maxResults {
		t.Fatalf("%d checks kept", len(checks))
	}
	total := 0
	for _, c := range checks {
		within(t, c.CheckID, c.Layer, c.Target, c.Fix, c.Summary, c.Hint, c.Evidence)
		total += len(c.Evidence)
	}
	if total > maxRunEvidence {
		t.Fatalf("evidence %d", total)
	}
}

func TestPanelEvidenceIsRedacted(t *testing.T) {
	e := newEnv(t)
	n := e.node(func(n *store.Node) {
		n.StateRejection = "client 192.0.2.77 and [2001:db8::77]:443 refused; node 198.51.100.5 fine"
	})
	e.agent(n.ID, &fakeNode{})
	x := panelRun(t, e, n, ScopeNode)["panel.connection "]
	if strings.Contains(x.Evidence, "192.0.2.77") || strings.Contains(x.Evidence, "2001:db8::77") ||
		!strings.Contains(x.Evidence, "<ip>") || !strings.Contains(x.Evidence, "198.51.100.5") {
		t.Fatalf("evidence %q", x.Evidence)
	}
}

// The audit and the row of a new run are written without the runner's lock:
// other nodes are not held up meanwhile, and a second start on the same node
// joins the run once its row is there.
func TestLaunchWritesOutsideTheLock(t *testing.T) {
	e := newEnv(t)
	n := e.node(nil)
	// The run is held until the second start has joined it: else, on a slow
	// machine, the run could end before that start looks, which then starts a
	// run of its own.
	hold := make(chan struct{})
	e.agent(n.ID, &fakeNode{hold: hold})
	r := e.runner(0)
	release := make(chan struct{})
	first := make(chan string, 1)
	go func() {
		id, _, err := r.StartManual(e.ctx, n.ID, ScopeNode, "a1", func() error { <-release; return nil })
		if err != nil {
			t.Error(err)
		}
		first <- id
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, busy := r.Running(n.ID); busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the slot was never taken")
		}
		time.Sleep(5 * time.Millisecond)
	}
	done := make(chan struct{})
	go func() { r.Running("another"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the runner's lock is held while the audit is written")
	}
	joined := make(chan string, 1)
	go func() {
		id, j, err := r.StartManual(e.ctx, n.ID, ScopeNode, "a1", func() error { t.Error("audited twice"); return nil })
		if err != nil || !j {
			t.Errorf("join: %v %v", j, err)
		}
		joined <- id
	}()
	close(release)
	id := <-first
	if got := <-joined; got != id {
		t.Fatalf("joined %q, want %q", got, id)
	}
	close(hold)
	if run := e.wait(r, id); run.State != store.RunDone {
		t.Fatalf("run %+v", run)
	}
}
