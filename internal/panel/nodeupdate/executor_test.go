package nodeupdate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/rollout"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// wantFailed waits for the rollout to be over and checks that it failed with
// an error that contains want.
func (e *env) wantFailed(ro *store.Rollout, want string) {
	e.t.Helper()
	got := e.waitOver(ro.ID)
	if got.Status != store.RolloutFailed || !strings.Contains(got.Error, want) {
		e.t.Fatalf("rollout %s: %q, want failed with %q", got.Status, got.Error, want)
	}
}

func TestAgentAndEdge(t *testing.T) {
	e := newEnv(t, newBinaries(panelVersion))
	f := newFakeAgent(t, oldVersion, oldVersion)
	n := e.addNode("berlin", f)
	ro, err := e.start(&rollout.Request{Agent: true, Edge: true, NodeIds: []string{n.ID}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if ro.ToVersion != panelVersion {
		t.Errorf("to version %q, want the panel's %s", ro.ToVersion, panelVersion)
	}
	if got := e.waitOver(ro.ID); got.Status != store.RolloutCompleted {
		t.Fatalf("rollout %s: %s", got.Status, got.Error)
	}
	metas, shaOK := f.updates()
	if len(metas) != 1 {
		t.Fatalf("%d UpdateSelf calls, want 1", len(metas))
	}
	m := metas[0]
	if m.GetVersion() != panelVersion || m.GetArch() != "amd64" || m.GetRollback() || !shaOK[0] ||
		m.GetSignature() != "sig of "+panelVersion+" amd64" {
		t.Errorf("UpdateSelf meta %v (sha and size right: %v)", m, shaOK[0])
	}
	edges := f.edges()
	if len(edges) != 1 || edges[0].GetVersion() != panelVersion || edges[0].GetRollback() {
		t.Errorf("UpdateEdge calls %v, want one to %s", edges, panelVersion)
	}
	waitFor(t, "the node record on the target", func() bool {
		got := e.node(n.ID)
		return got.AgentVersion == panelVersion && got.EdgeVersion == panelVersion && got.HostInfo.Healthy
	})
}

func TestDoneOnlyWhenHealthy(t *testing.T) {
	e := newEnv(t, newBinaries(panelVersion))
	f := newFakeAgent(t, oldVersion, oldVersion)
	f.set(func(f *fakeAgent) { f.holdHealthy = true })
	n := e.addNode("berlin", f)
	ro, err := e.start(&rollout.Request{Agent: true, NodeIds: []string{n.ID}})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the restart on the target", func() bool { return e.mgr.AgentSignal(n.ID).Version == panelVersion })
	time.Sleep(1500 * time.Millisecond) // past the hold of the last step: only health holds it
	if s := e.status(ro.ID); s != store.RolloutRunning {
		t.Fatalf("rollout %s while the agent is not healthy, want running", s)
	}
	f.set(func(f *fakeAgent) { f.info.Healthy = true })
	if got := e.waitOver(ro.ID); got.Status != store.RolloutCompleted {
		t.Fatalf("rollout %s: %s", got.Status, got.Error)
	}
}

func TestNotHealthyInTime(t *testing.T) {
	e := newEnv(t, newBinaries(panelVersion))
	f := newFakeAgent(t, oldVersion, oldVersion)
	f.set(func(f *fakeAgent) { f.holdHealthy = true })
	n := e.addNode("berlin", f)
	ro, err := e.start(&rollout.Request{Agent: true, NodeIds: []string{n.ID}})
	if err != nil {
		t.Fatal(err)
	}
	e.wantFailed(ro, "did not answer healthy")
}

func TestUpdateSelfPermissionDenied(t *testing.T) {
	e := newEnv(t, newBinaries(panelVersion))
	f := newFakeAgent(t, oldVersion, oldVersion)
	f.set(func(f *fakeAgent) {
		f.selfErr = connect.NewError(connect.CodePermissionDenied, errors.New("the signature is not by a release key"))
	})
	n := e.addNode("berlin", f)
	ro, err := e.start(&rollout.Request{Agent: true, Edge: true, NodeIds: []string{n.ID}})
	if err != nil {
		t.Fatal(err)
	}
	e.wantFailed(ro, "permission_denied: the signature is not by a release key")
	if len(f.edges()) != 0 {
		t.Error("the edge was rolled after the agent update failed")
	}
}

func TestReconnectOnTheOldVersion(t *testing.T) {
	e := newEnv(t, newBinaries(panelVersion))
	f := newFakeAgent(t, oldVersion, oldVersion)
	// The new agent never comes up: the launcher starts the old one again.
	f.set(func(f *fakeAgent) { f.comeBackAs = oldVersion })
	n := e.addNode("berlin", f)
	ro, err := e.start(&rollout.Request{Agent: true, NodeIds: []string{n.ID}})
	if err != nil {
		t.Fatal(err)
	}
	e.wantFailed(ro, "the node rolled back or restarted: it reconnected with agent "+oldVersion)
}

// A network blip before the upload starts reconnects the panel to the agent
// that still runs the old version: that is no restart, and the update goes on.
func TestReconnectBeforeTheUploadIsNoRestart(t *testing.T) {
	e := newEnv(t, newBinaries(panelVersion))
	f := newFakeAgent(t, oldVersion, oldVersion)
	n := e.addNode("berlin", f)
	f.set(func(f *fakeAgent) { f.blip = true })
	ro, err := e.start(&rollout.Request{Agent: true, NodeIds: []string{n.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.waitOver(ro.ID); got.Status != store.RolloutCompleted {
		t.Fatalf("rollout %s: %s", got.Status, got.Error)
	}
	if metas, _ := f.updates(); len(metas) != 1 || metas[0].GetVersion() != panelVersion {
		t.Errorf("uploads %v, want one of %s", metas, panelVersion)
	}
}

func TestRolledBackEvent(t *testing.T) {
	e := newEnv(t, newBinaries(panelVersion))
	f := newFakeAgent(t, oldVersion, oldVersion)
	f.set(func(f *fakeAgent) { f.holdHealthy = true })
	n := e.addNode("berlin", f)
	ro, err := e.start(&rollout.Request{Agent: true, NodeIds: []string{n.ID}})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the restart", func() bool { return e.mgr.AgentSignal(n.ID).Starts > 0 })
	f.emit("agent_rolled_back")
	e.wantFailed(ro, "the node rolled back or restarted: the launcher rolled the agent back")
}

func TestAgentStartedInThePause(t *testing.T) {
	e := newEnv(t, newBinaries(panelVersion))
	f := newFakeAgent(t, oldVersion, oldVersion)
	n := e.addNode("berlin", f)
	ro, err := e.start(&rollout.Request{Agent: true, NodeIds: []string{n.ID}, PauseSeconds: 3})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the healthy answer on the target", func() bool {
		var healthy int
		f.set(func(f *fakeAgent) { healthy = f.healthyIn })
		return e.mgr.AgentSignal(n.ID).Version == panelVersion && healthy > 1
	})
	time.Sleep(100 * time.Millisecond)
	f.emit("agent_started") // a second start: the agent restarted after it was healthy
	e.wantFailed(ro, "the node rolled back or restarted: the agent started again")
}

func TestRestartInThePauseFailsTheNextStep(t *testing.T) {
	e := newEnv(t, newBinaries(panelVersion))
	f1, f2 := newFakeAgent(t, oldVersion, oldVersion), newFakeAgent(t, oldVersion, oldVersion)
	n1 := e.addNode("a-first", f1)
	e.addNode("b-second", f2)
	ro, err := e.start(&rollout.Request{Agent: true, CanaryNodeId: n1.ID, PauseSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first step done", func() bool {
		_, steps, _, err := e.db.Rollout(e.ctx, ro.ID)
		return err == nil && steps[0].Status == store.StepDone
	})
	f1.emit("agent_started")
	e.wantFailed(ro, "node a-first of the step before, after its update: the node rolled back or restarted")
	if metas, _ := f2.updates(); len(metas) != 0 {
		t.Error("the second node was updated after the first restarted")
	}
}

func TestEdgeAborted(t *testing.T) {
	e := newEnv(t, newBinaries())
	f := newFakeAgent(t, panelVersion, oldVersion)
	f.set(func(f *fakeAgent) {
		f.edgeErr = connect.NewError(connect.CodeAborted, errors.New("the new edge did not bind :443"))
	})
	n := e.addNode("berlin", f)
	ro, err := e.start(&rollout.Request{Edge: true, NodeIds: []string{n.ID}})
	if err != nil {
		t.Fatal(err)
	}
	e.wantFailed(ro, "the edge did not roll to "+panelVersion+": the new edge did not bind :443")
}

func TestEdgeOnlyFromTheNodesBinaries(t *testing.T) {
	e := newEnv(t, newBinaries()) // nothing in the cache
	f := newFakeAgent(t, "v0.4.5", "v0.4.5")
	f.set(func(f *fakeAgent) {
		f.info.Binaries.Versions = []string{oldVersion, "v0.4.5", "v0.4.7"}
		f.info.Binaries.SignedVersions = []string{oldVersion} // v0.4.7 has no kept signature; v0.4.5 is the agent's own
	})
	n := e.addNode("berlin", f)
	// A binary without a kept signature is refused, by name of the reason.
	if _, err := e.start(&rollout.Request{Edge: true, ToVersion: "v0.4.7", NodeIds: []string{n.ID}}); !errors.Is(err, rollout.ErrRefused) ||
		!strings.Contains(err.Error(), "has no signature kept for its agent binary v0.4.7") {
		t.Errorf("edge-only to an installed version without a kept signature: %v", err)
	}
	ro, err := e.start(&rollout.Request{Edge: true, ToVersion: oldVersion, NodeIds: []string{n.ID}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := e.waitOver(ro.ID); got.Status != store.RolloutCompleted {
		t.Fatalf("rollout %s: %s", got.Status, got.Error)
	}
	if got := e.bins.opens(); len(got) != 0 {
		t.Errorf("binaries opened %v, want none", got)
	}
	if edges := f.edges(); len(edges) != 1 || edges[0].GetVersion() != oldVersion {
		t.Errorf("UpdateEdge calls %v", edges)
	}
	// A version that the node does not hold is refused.
	if _, err := e.start(&rollout.Request{Edge: true, ToVersion: "v0.4.9", NodeIds: []string{n.ID}}); !errors.Is(err, rollout.ErrRefused) ||
		!strings.Contains(err.Error(), "has no agent binary v0.4.9") {
		t.Errorf("edge-only to a version the node lacks: %v", err)
	}
}

// The running agent's own binary needs no kept signature for its edge.
func TestEdgeOnlyToTheAgentsOwnUnsigned(t *testing.T) {
	e := newEnv(t, newBinaries())
	f := newFakeAgent(t, "v0.4.5", oldVersion)
	f.set(func(f *fakeAgent) {
		f.info.Binaries.Versions = []string{oldVersion, "v0.4.5"}
		f.info.Binaries.SignedVersions = nil
	})
	n := e.addNode("berlin", f)
	ro, err := e.start(&rollout.Request{Edge: true, ToVersion: "v0.4.5", NodeIds: []string{n.ID}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := e.waitOver(ro.ID); got.Status != store.RolloutCompleted {
		t.Fatalf("rollout %s: %s", got.Status, got.Error)
	}
	if edges := f.edges(); len(edges) != 1 || edges[0].GetVersion() != "v0.4.5" {
		t.Errorf("UpdateEdge calls %v", edges)
	}
}

func TestRollbackOnlyToThePrevious(t *testing.T) {
	e := newEnv(t, newBinaries(oldVersion, "v0.4.1"))
	f := newFakeAgent(t, panelVersion, panelVersion)
	f.set(func(f *fakeAgent) {
		f.info.Binaries = nodesBinaries(oldVersion, panelVersion)
	})
	n := e.addNode("berlin", f)
	if _, err := e.start(&rollout.Request{Agent: true, ToVersion: "v0.4.1", NodeIds: []string{n.ID}}); !errors.Is(err, rollout.ErrRefused) ||
		!strings.Contains(err.Error(), "goes back only to its previous version ("+oldVersion+")") {
		t.Fatalf("an older version that is not the previous: %v", err)
	}
	ro, err := e.start(&rollout.Request{Agent: true, ToVersion: oldVersion, NodeIds: []string{n.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.waitOver(ro.ID); got.Status != store.RolloutCompleted {
		t.Fatalf("rollout %s: %s", got.Status, got.Error)
	}
	if metas, _ := f.updates(); len(metas) != 1 || !metas[0].GetRollback() || metas[0].GetVersion() != oldVersion {
		t.Errorf("UpdateSelf %v, want one with rollback to %s", metas, oldVersion)
	}
}

func TestRefusals(t *testing.T) {
	e := newEnv(t, newBinaries(panelVersion, "v0.6.0", "v0.3.9"))
	old := newFakeAgent(t, oldVersion, oldVersion)
	old.set(func(f *fakeAgent) { f.info.Capabilities = []string{"rollout-status", CapUpdateEdge} })
	n := e.addNode("old", old)
	for _, c := range []struct {
		name string
		req  *rollout.Request
		want string
	}{
		{"capability", &rollout.Request{Agent: true, NodeIds: []string{n.ID}}, "node old cannot update itself: update them once with install.sh and the node kit"},
		{"above the panel", &rollout.Request{Edge: true, ToVersion: "v0.6.0"}, "above the version of the panel"},
		{"below the previous minor", &rollout.Request{Edge: true, ToVersion: "v0.3.9"}, "below v0.4.0, the previous minor"},
		{"nothing", &rollout.Request{}, "updates the agent, the edge or both"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.start(c.req)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestUnsignedImageKitRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "amd64"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "amd64", "postern-node"), []byte("unsigned"), 0o755); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, &nodes.PanelKit{Dir: dir, Version: panelVersion})
	f := newFakeAgent(t, oldVersion, oldVersion)
	n := e.addNode("berlin", f)
	_, err := e.start(&rollout.Request{Agent: true, NodeIds: []string{n.ID}})
	if !errors.Is(err, rollout.ErrRefused) || !strings.Contains(err.Error(), "no signed node binary "+panelVersion+" for amd64") {
		t.Errorf("err = %v, want refused for the unsigned kit", err)
	}
}

func TestTwoNodesAtOnce(t *testing.T) {
	e := newEnv(t, newBinaries(panelVersion))
	f1, f2 := newFakeAgent(t, oldVersion, oldVersion), newFakeAgent(t, oldVersion, oldVersion)
	f1.set(func(f *fakeAgent) { f.restartDelay = 300 * time.Millisecond })
	f2.set(func(f *fakeAgent) { f.restartDelay = 300 * time.Millisecond })
	n1, n2 := e.addNode("one", f1), e.addNode("two", f2)
	var wg sync.WaitGroup
	ids := make([]string, 2)
	for i, id := range []string{n1.ID, n2.ID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ro, err := e.start(&rollout.Request{Agent: true, NodeIds: []string{id}})
			if err != nil {
				t.Errorf("Start %s: %v", id, err)
				return
			}
			ids[i] = ro.ID
		}()
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	// Both run at once: the second node updates while the first one does.
	waitFor(t, "both nodes updating", func() bool {
		m1, _ := f1.updates()
		m2, _ := f2.updates()
		return len(m1) == 1 && len(m2) == 1
	})
	for _, id := range ids {
		if got := e.waitOver(id); got.Status != store.RolloutCompleted {
			t.Errorf("rollout %s: %s", got.Status, got.Error)
		}
	}
}

func nodesBinaries(previous, current string) *nodev1.NodeBinaries {
	return &nodev1.NodeBinaries{Versions: []string{previous, current}, Current: current, Previous: previous}
}
