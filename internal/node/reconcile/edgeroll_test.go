package reconcile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// edgeBinaryFile writes an agent binary of version v into bin/, as UpdateSelf
// or install.sh leaves it.
func (h *harness) edgeBinaryFile(v string) string {
	h.t.Helper()
	path := filepath.Join(filepath.Dir(h.nodeBinary), "postern-node-"+v)
	if err := os.WriteFile(path, []byte("binary "+v), 0o755); err != nil {
		h.t.Fatal(err)
	}
	return path
}

type rollResult struct {
	gen uint64
	err error
}

// rollEdge asks for an edge roll to binary as UpdateEdge does, runs one pass
// once the request is there, and returns what RollEdge answered.
func (h *harness) rollEdge(binary string) rollResult {
	h.t.Helper()
	got := make(chan rollResult, 1)
	go func() {
		gen, err := h.r.RollEdge(context.Background(), binary, fileSum(h.t, binary), func() {})
		got <- rollResult{gen, err}
	}()
	waitUntil(h.t, "the roll request", func() bool {
		h.r.mu.Lock()
		defer h.r.mu.Unlock()
		return h.r.rollReq != nil
	})
	h.pass()
	select {
	case res := <-got:
		return res
	case <-time.After(10 * time.Second):
		h.t.Fatal("RollEdge did not answer after the pass")
		return rollResult{}
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *harness) edgeBinaryOf(name string) string {
	h.t.Helper()
	spec, ok := h.docker.Spec(name)
	if !ok || len(spec.Binds) == 0 {
		h.t.Fatalf("no spec of %s", name)
	}
	return spec.Binds[0]
}

func mountOf(binary string) string { return binary + ":/opt/postern/bin/postern-node:ro" }

// A roll request puts the binary it names in the new generation's bind, and
// the runtime record keeps it through an agent restart. A generation made after
// a crash takes the binary of the one it replaces; the operator's roll takes
// the agent's own, as before.
func TestRollEdgeToABinary(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	v9 := h.edgeBinaryFile("v9.9.9")

	res := h.rollEdge(v9)
	if res.err != nil || res.gen != 2 {
		t.Fatalf("RollEdge = %d, %v; want generation 2", res.gen, res.err)
	}
	if got := h.edgeBinaryOf("postern-edge-g2"); got != mountOf(v9) {
		t.Errorf("g2 binds %s, want %s", got, mountOf(v9))
	}
	if rt := h.runtime(); rt.EdgeGeneration != 2 || rt.EdgeBinaries[2] != v9 {
		t.Errorf("edge generation %d, binaries %v; want 2 on %s", rt.EdgeGeneration, rt.EdgeBinaries, v9)
	}
	if got := h.fakeEdge(1).drainCalls(); len(got) != 1 {
		t.Errorf("Drain calls on g1 = %v, want one", got)
	}

	// A new agent process reads the record.
	h.r = h.newReconciler()
	h.pass()
	if rt := h.runtime(); rt.EdgeBinaries[2] != v9 {
		t.Errorf("binaries after a restart = %v, want 2 on %s", rt.EdgeBinaries, v9)
	}

	// g2 crashes for good: g3 takes its binary.
	if err := h.docker.Exit("postern-edge-g2", 1); err != nil {
		t.Fatal(err)
	}
	h.pass()
	if got := h.edgeBinaryOf("postern-edge-g3"); got != mountOf(v9) {
		t.Errorf("g3 (after the crash of g2) binds %s, want %s", got, mountOf(v9))
	}
	if rt := h.runtime(); rt.EdgeGeneration != 3 || rt.EdgeBinaries[3] != v9 {
		t.Errorf("edge generation %d, binaries %v; want 3 on %s", rt.EdgeGeneration, rt.EdgeBinaries, v9)
	}

	// The operator's roll takes the agent's own binary.
	h.requestRoll()
	h.pass()
	if got := h.edgeBinaryOf("postern-edge-g4"); got != mountOf(h.nodeBinary) {
		t.Errorf("g4 (the operator's roll) binds %s, want the agent's %s", got, mountOf(h.nodeBinary))
	}
	if rt := h.runtime(); rt.EdgeBinaries[4] != h.nodeBinary {
		t.Errorf("binaries = %v, want 4 on %s", rt.EdgeBinaries, h.nodeBinary)
	}
}

// A generation that replaces one whose binary is gone takes the agent's own.
func TestRollEdgeBinaryGoneFallsBackToTheAgents(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	v9 := h.edgeBinaryFile("v9.9.9")
	if res := h.rollEdge(v9); res.err != nil {
		t.Fatal(res.err)
	}
	if err := os.Remove(v9); err != nil {
		t.Fatal(err)
	}
	if err := h.docker.Exit("postern-edge-g2", 1); err != nil {
		t.Fatal(err)
	}
	h.pass()
	if got := h.edgeBinaryOf("postern-edge-g3"); got != mountOf(h.nodeBinary) {
		t.Errorf("g3 binds %s, want the agent's %s", got, mountOf(h.nodeBinary))
	}
}

// A roll whose generation does not come up answers ErrEdgeRollFailed; the old
// generation serves on its binary, and the failed one leaves no record.
func TestRollEdgeThatFails(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	h.r.edgeStartTimeout = 50 * time.Millisecond
	h.fakeEdge(2).setHealthErr(errors.New("dial unix: no such file or directory"))
	v9 := h.edgeBinaryFile("v9.9.9")

	res := h.rollEdge(v9)
	if !errors.Is(res.err, ErrEdgeRollFailed) {
		t.Fatalf("RollEdge = %d, %v; want ErrEdgeRollFailed", res.gen, res.err)
	}
	rt := h.runtime()
	if rt.EdgeGeneration != 1 {
		t.Errorf("edge generation = %d, want 1", rt.EdgeGeneration)
	}
	if _, ok := rt.EdgeBinaries[2]; ok {
		t.Errorf("binaries = %v: the failed generation is recorded", rt.EdgeBinaries)
	}
	if c := h.container("postern-edge-g1"); c == nil || c.State != "running" || c.RestartPolicy != "unless-stopped" {
		t.Errorf("g1 = %+v, want it serving", c)
	}
	if n := len(h.eventsOf("edge_roll_failed")); n != 1 {
		t.Errorf("edge_roll_failed events = %d, want 1", n)
	}
}

// One roll request at a time; one that gives up is withdrawn.
func TestRollEdgeOneAtATime(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	v9 := h.edgeBinaryFile("v9.9.9")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := h.r.RollEdge(ctx, v9, fileSum(t, v9), func() {})
		done <- err
	}()
	waitUntil(t, "the roll request", func() bool {
		h.r.mu.Lock()
		defer h.r.mu.Unlock()
		return h.r.rollReq != nil
	})
	if _, err := h.r.RollEdge(context.Background(), v9, fileSum(t, v9), func() {}); !errors.Is(err, ErrEdgeRollBusy) {
		t.Errorf("a second RollEdge = %v, want ErrEdgeRollBusy", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("the withdrawn RollEdge = %v, want context.Canceled", err)
	}
	h.pass()
	if n := len(h.creates("edge")); n != 1 {
		t.Errorf("created %d edges, want 1: a withdrawn request rolls nothing", n)
	}
}
