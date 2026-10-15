package reconcile

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/urbnywrt/postern/internal/node/selfupdate"
	"github.com/urbnywrt/postern/internal/node/state"
)

// errKilled stands for a kill of the agent in the middle of a pass.
var errKilled = errors.New("killed")

func fileSum(t *testing.T, path string) []byte {
	t.Helper()
	sum, err := selfupdate.Hash(path)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

// A binary that changed after UpdateEdge verified it is not mounted.
func TestRollEdgeRehashesBeforeTheMount(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	v9 := h.edgeBinaryFile("v9.9.9")
	sum := fileSum(t, v9)
	if err := os.WriteFile(v9, []byte("other"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		_, err := h.r.RollEdge(context.Background(), v9, sum, func() {})
		got <- err
	}()
	waitUntil(t, "the roll request", func() bool {
		h.r.mu.Lock()
		defer h.r.mu.Unlock()
		return h.r.rollReq != nil
	})
	h.pass()
	if err := <-got; err == nil || !strings.Contains(err.Error(), "changed after it was verified") {
		t.Errorf("RollEdge = %v, want a refusal of the changed binary", err)
	}
	if n := len(h.creates("edge")); n != 1 {
		t.Errorf("created %d edges, want 1", n)
	}
}

// killedMidRoll asks for a roll to binary and stops the pass (as a kill of the
// agent would) once generation 2 was made, as it is first asked whether it answers (before the bind check
// ran); then a new reconciler (a new agent process) takes over the node.
func (h *harness) killedMidRoll(binary string) {
	h.t.Helper()
	var saved atomic.Pointer[state.Runtime]
	g2 := h.fakeEdge(2)
	g2.mu.Lock()
	g2.onHealth = func() {
		if rt, err := h.store.LoadRuntime(); err == nil && saved.Load() == nil {
			saved.Store(rt)
		}
		panic(errKilled) // the agent dies here
	}
	g2.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := h.r.RollEdge(context.Background(), binary, fileSum(h.t, binary), func() {})
		done <- err
	}()
	waitUntil(h.t, "the roll request", func() bool {
		h.r.mu.Lock()
		defer h.r.mu.Unlock()
		return h.r.rollReq != nil
	})
	func() {
		defer func() {
			if p := recover(); p != errKilled {
				panic(p)
			}
		}()
		_ = h.r.reconcileOnce(context.Background(), nil)
	}()
	<-done
	g2.mu.Lock()
	g2.onHealth = nil
	g2.mu.Unlock()
	if c := h.container("postern-edge-g2"); c == nil || c.State != "running" {
		h.t.Fatalf("g2 = %+v after the kill, want it running", c)
	}
	// The record was saved as soon as g2 was made, before the kill.
	if rt := saved.Load(); rt == nil || rt.EdgeBinaries[2] != binary || rt.EdgeLastGeneration != 2 || rt.EdgeGeneration != 1 {
		h.t.Fatalf("runtime record as g2 answered = %+v, want g2's binary and number saved, g1 current", rt)
	}
	h.r = h.newReconciler()
}

// Slice 3's bind rule holds across a kill mid-roll: on the next start the new
// generation takes over only when it binds what the old one binds; else it is
// removed and the old one serves on.
func TestKilledRollThatFailsTheBindRuleIsAbandoned(t *testing.T) {
	h := newHarness(t)
	h.apply(h.twoListenerState(1))
	h.pass()
	h.fakeEdge(2).setFailures("L2")
	h.killedMidRoll(h.edgeBinaryFile("v9.9.9"))

	h.pass()
	if c := h.container("postern-edge-g2"); c != nil {
		t.Errorf("g2 = %+v, want it removed", c)
	}
	if g1 := h.container("postern-edge-g1"); g1 == nil || g1.State != "running" || g1.RestartPolicy != "unless-stopped" {
		t.Errorf("g1 = %+v, want it serving", g1)
	}
	if got := h.fakeEdge(1).drainCalls(); len(got) != 0 {
		t.Errorf("g1 was asked to drain: %v", got)
	}
	rt := h.runtime()
	if _, ok := rt.EdgeBinaries[2]; ok || rt.EdgeGeneration != 1 {
		t.Errorf("runtime = generation %d, binaries %v; want 1 and no g2", rt.EdgeGeneration, rt.EdgeBinaries)
	}
	if ev := h.eventsOf("edge_roll_failed"); len(ev) == 0 || !strings.Contains(ev[len(ev)-1].GetMessage(), "L2") {
		t.Errorf("edge_roll_failed events = %v, want one that names L2", ev)
	}
}

// A killed roll whose generation binds everything takes over on the next
// start, on the binary that was recorded before the kill.
func TestKilledRollThatPassesTheBindRuleTakesOver(t *testing.T) {
	h := newHarness(t)
	h.apply(h.twoListenerState(1))
	h.pass()
	v9 := h.edgeBinaryFile("v9.9.9")
	h.killedMidRoll(v9)

	h.pass()
	rt := h.runtime()
	if rt.EdgeGeneration != 2 || rt.EdgeBinaries[2] != v9 || rt.EdgePreviousBinary != h.nodeBinary {
		t.Errorf("runtime = generation %d, binaries %v, previous %q; want 2 on %s after %s",
			rt.EdgeGeneration, rt.EdgeBinaries, rt.EdgePreviousBinary, v9, h.nodeBinary)
	}
	if got := h.fakeEdge(1).drainCalls(); len(got) != 1 {
		t.Errorf("g1 drain calls = %v, want one", got)
	}
}

// UpdateEdge's generation made for other capabilities beside one that serves
// goes by the bind rule too.
func TestRollEdgeWithACapabilityChangeKeepsTheBindRule(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	h.fakeEdge(2).setFailures("L1")
	v9 := h.edgeBinaryFile("v9.9.9")
	h.apply(h.netRawState(2))
	res := h.rollEdge(v9)
	if !errors.Is(res.err, ErrEdgeRollFailed) {
		t.Fatalf("RollEdge = %d, %v; want ErrEdgeRollFailed", res.gen, res.err)
	}
	if c := h.container("postern-edge-g2"); c != nil {
		t.Errorf("g2 = %+v, want it removed", c)
	}
	if g1 := h.container("postern-edge-g1"); g1 == nil || g1.State != "running" || g1.RestartPolicy != "unless-stopped" {
		t.Errorf("g1 = %+v, want it serving", g1)
	}
	if rt := h.runtime(); rt.EdgeGeneration != 1 {
		t.Errorf("edge generation = %d, want 1", rt.EdgeGeneration)
	}
}
