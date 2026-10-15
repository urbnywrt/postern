package versions

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/internal/panel/rollout"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// stubExecutor plans one step on one node and does nothing.
type stubExecutor struct{ node string }

func (e stubExecutor) Plan(_ context.Context, r *store.Rollout, _ *rollout.Request) ([]string, []store.RolloutStep, []store.RolloutItem, error) {
	r.FromVersion = "3.5.12"
	return []string{e.node}, []store.RolloutStep{{Index: 0, NodeID: e.node}}, nil, nil
}
func (stubExecutor) Apply(context.Context, *store.Rollout, *store.RolloutStep) error { return nil }
func (stubExecutor) Check(context.Context, *store.Rollout, *store.RolloutStep) (bool, error) {
	return false, nil
}
func (stubExecutor) Revert(context.Context, *store.Rollout, *store.RolloutStep) error { return nil }
func (stubExecutor) Complete(context.Context, *store.Rollout) error                   { return nil }

func TestRolloutProcedures(t *testing.T) {
	a := newAPI(t, true)
	ctx := context.Background()
	c := a.client()
	start := &panelv1.StartRolloutRequest{Kind: store.RolloutVersion, Component: store.EngineTelemt, Channel: store.ChannelStable, ToVersion: "3.5.13"}

	if _, err := c.StartRollout(ctx, connect.NewRequest(start)); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("without a runner: %v", err)
	}
	n := a.addNode("alpha", "")
	a.svc.SetRollouts(rollout.NewRunner(rollout.Config{DB: a.db, Executors: map[string]rollout.Executor{rollout.KeyEngineVersion: stubExecutor{node: n.ID}}}))

	resp, err := c.StartRollout(ctx, connect.NewRequest(start))
	if err != nil {
		t.Fatalf("StartRollout: %v", err)
	}
	ro := resp.Msg.GetRollout()
	if ro.GetStatus() != store.RolloutPreparing || ro.GetMode() != store.RolloutModeManual || ro.GetPauseSeconds() != 120 ||
		len(ro.GetSteps()) != 1 || ro.GetSteps()[0].GetNodeName() != "alpha" || ro.GetFromVersion() != "3.5.12" {
		t.Errorf("rollout %v", ro)
	}

	_, err = c.StartRollout(ctx, connect.NewRequest(start))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "rollout "+ro.GetId()) {
		t.Errorf("a second rollout of the channel: %v", err)
	}
	if _, err := c.PauseRollout(ctx, connect.NewRequest(&panelv1.PauseRolloutRequest{Id: ro.GetId()})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("Pause of a preparing rollout: %v", err)
	}
	bad := &panelv1.StartRolloutRequest{Kind: "everything"}
	if _, err := c.StartRollout(ctx, connect.NewRequest(bad)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a bad kind: %v", err)
	}
	if _, err := c.GetRollout(ctx, connect.NewRequest(&panelv1.GetRolloutRequest{Id: "nope"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("Get of no rollout: %v", err)
	}

	ab, err := c.AbortRollout(ctx, connect.NewRequest(&panelv1.AbortRolloutRequest{Id: ro.GetId()}))
	if err != nil || ab.Msg.GetRollout().GetStatus() != store.RolloutAborted || ab.Msg.GetRollout().GetFinishedUnix() == 0 {
		t.Fatalf("Abort: %v %v", ab, err)
	}
	list, err := c.ListRollouts(ctx, connect.NewRequest(&panelv1.ListRolloutsRequest{}))
	if err != nil || len(list.Msg.GetRollouts()) != 1 {
		t.Fatalf("List: %v %v", list, err)
	}
	active, err := c.ListRollouts(ctx, connect.NewRequest(&panelv1.ListRolloutsRequest{ActiveOnly: true}))
	if err != nil || len(active.Msg.GetRollouts()) != 0 {
		t.Fatalf("List active: %v %v", active, err)
	}

	// Refusals are audited too, with the answer.
	var actions []string
	for _, line := range a.auditLog() {
		if !strings.Contains(line, "versions.rollout.") {
			continue
		}
		entry := strings.Fields(line)[1]
		if strings.Contains(line, `"result":"failed"`) {
			entry += "!"
			if !strings.Contains(line, `"code":"`) || !strings.Contains(line, `"error":"`) {
				t.Errorf("a failed entry without its answer: %s", line)
			}
		}
		actions = append(actions, entry)
	}
	want := "versions.rollout.start versions.rollout.start! versions.rollout.pause! versions.rollout.start! versions.rollout.abort"
	if strings.Join(actions, " ") != want {
		t.Errorf("audit %v, want %s", actions, want)
	}
}

// A step shows the latest runs before and after it of its node, with the
// regression of the after-run.
func TestRolloutStepRuns(t *testing.T) {
	a := newAPI(t, true)
	ctx := context.Background()
	n, other := a.addNode("alpha", ""), a.addNode("beta", "")
	a.svc.SetRollouts(rollout.NewRunner(rollout.Config{DB: a.db, Executors: map[string]rollout.Executor{rollout.KeyEngineVersion: stubExecutor{node: n.ID}}}))
	resp, err := a.client().StartRollout(ctx, connect.NewRequest(&panelv1.StartRolloutRequest{Kind: store.RolloutVersion,
		Component: store.EngineTelemt, Channel: store.ChannelStable, ToVersion: "3.5.13"}))
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Msg.GetRollout().GetId()
	change := store.RolloutStepChange(id, 0)
	run := func(nodeID, reason, change, state string, regressed bool) string {
		t.Helper()
		r := &store.DiagnosticRun{NodeID: nodeID, Scope: "node", Reason: reason, Change: change}
		if err := a.db.CreateDiagnosticRun(ctx, r); err != nil {
			t.Fatal(err)
		}
		if state != store.RunRunning {
			if err := a.db.FinishDiagnosticRun(ctx, r.ID, state, "", regressed, r.StartedAt); err != nil {
				t.Fatal(err)
			}
		}
		return r.ID
	}
	get := func() *panelv1.RolloutStep {
		t.Helper()
		got, err := a.client().GetRollout(ctx, connect.NewRequest(&panelv1.GetRolloutRequest{Id: id}))
		if err != nil {
			t.Fatal(err)
		}
		return got.Msg.GetRollout().GetSteps()[0]
	}
	if st := get(); st.GetBeforeRunId() != "" || st.GetAfterRunId() != "" {
		t.Fatalf("runs before any: %v", st)
	}
	run(other.ID, store.RunBeforeChange, change, store.RunDone, false) // another node's
	run(n.ID, store.RunBeforeChange, change+"0", store.RunDone, false) // step 10's
	before := run(n.ID, store.RunBeforeChange, change, store.RunPartial, false)
	st := get()
	if st.GetBeforeRunId() != before || st.GetBeforeRunState() != store.RunPartial || st.GetAfterRunId() != "" {
		t.Fatalf("step %v, want the before-run %s", st, before)
	}
	after := run(n.ID, store.RunAfterChange, change, store.RunDone, true)
	st = get()
	if st.GetAfterRunId() != after || st.GetAfterRunState() != store.RunDone || !st.GetAfterRegressed() || st.GetBeforeRunId() != before {
		t.Fatalf("step %v, want the after-run %s, regressed", st, after)
	}
}
