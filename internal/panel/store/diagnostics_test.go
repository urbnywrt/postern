package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDiagnosticRunLifecycle(t *testing.T) {
	db := newTestDB(t)
	db.now = fixedClock(testNow)
	ctx := context.Background()
	n := mustNode(t, db, "n1")

	r := &DiagnosticRun{NodeID: n.ID, Scope: "node", Reason: RunManual, AdminID: "a1"}
	if err := db.CreateDiagnosticRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	if r.ID == "" || r.State != RunRunning || !r.StartedAt.Equal(testNow.Truncate(time.Second)) {
		t.Fatalf("created %+v", r)
	}
	for i, st := range []string{"ok", "fail", "warn", "ok", "skip"} {
		res := DiagnosticResult{Seq: i, CheckID: "c", Layer: "host", Target: "", Status: st, Vantage: "node", CheckedAt: testNow, DurationMS: 7}
		if err := db.AddDiagnosticResult(ctx, r.ID, res); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AddDiagnosticResult(ctx, r.ID, DiagnosticResult{Seq: 0, CheckID: "x"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("a seq twice: %v, want ErrConflict", err)
	}
	if err := db.AddDiagnosticResult(ctx, "nope", DiagnosticResult{Seq: 0, CheckID: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a run that does not exist: %v, want ErrNotFound", err)
	}
	if err := db.FinishDiagnosticRun(ctx, r.ID, RunDone, "", true, testNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := db.DiagnosticRun(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != RunDone || !got.Regressed || got.OK != 2 || got.Warn != 1 || got.Fail != 1 || got.Skip != 1 ||
		got.FinishedAt == nil || len(got.Results) != 5 || got.Results[1].Status != "fail" || got.Results[4].Seq != 4 ||
		got.Results[0].DurationMS != 7 || got.AdminID != "a1" {
		t.Fatalf("got %+v", got)
	}
	if err := db.FinishDiagnosticRun(ctx, "nope", RunDone, "", false, testNow); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finish a run that does not exist: %v", err)
	}
	if _, err := db.DiagnosticRun(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read a run that does not exist: %v", err)
	}
}

func TestListDiagnosticRunsAndUnfinished(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	for i, scope := range []string{"node", "proxy:p1", "proxy:p2", "node"} {
		db.now = fixedClock(testNow.Add(time.Duration(i) * time.Minute))
		r := &DiagnosticRun{ID: scope + string(rune('a'+i)), NodeID: n.ID, Scope: scope, Reason: RunManual}
		if err := db.CreateDiagnosticRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	all, err := db.ListDiagnosticRuns(ctx, n.ID, nil, 10)
	if err != nil || len(all) != 4 || all[0].ID != "noded" {
		t.Fatalf("all: %v %+v", err, all)
	}
	p1, err := db.ListDiagnosticRuns(ctx, n.ID, []string{"node", "proxy:p1"}, 2)
	if err != nil || len(p1) != 2 || p1[0].ID != "noded" || p1[1].ID != "proxy:p1b" {
		t.Fatalf("p1: %v %+v", err, p1)
	}
	if err := db.FinishDiagnosticRun(ctx, "noded", RunDone, "", false, testNow); err != nil {
		t.Fatal(err)
	}
	k, err := db.FailUnfinishedDiagnosticRuns(ctx, "the panel restarted")
	if err != nil || k != 3 {
		t.Fatalf("FailUnfinished: %d %v", k, err)
	}
	r, _ := db.DiagnosticRun(ctx, "nodea")
	if r.State != RunFailed || r.Error != "the panel restarted" || r.FinishedAt == nil {
		t.Fatalf("unfinished: %+v", r)
	}
	if r, _ := db.DiagnosticRun(ctx, "noded"); r.State != RunDone {
		t.Fatalf("a finished run was touched: %+v", r)
	}
}

func TestReplaceNodeChecksKeepsSince(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	t0 := testNow.Truncate(time.Second)
	ch, err := db.ReplaceNodeChecks(ctx, n.ID, []NodeCheck{
		{CheckID: "host.docker", Status: "ok"},
		{CheckID: "ingress.bound", Target: "listener:L1", Status: "fail", Evidence: "e"},
	}, t0)
	if err != nil || len(ch) != 2 || ch[0].From != "" || ch[1].Check.Status != "fail" {
		t.Fatalf("first: %v %+v", err, ch)
	}
	t1 := t0.Add(time.Minute)
	ch, err = db.ReplaceNodeChecks(ctx, n.ID, []NodeCheck{
		{CheckID: "host.docker", Status: "ok", Summary: "again"},
		{CheckID: "ingress.bound", Target: "listener:L1", Status: "ok"},
		{CheckID: "host.disk", Status: "warn"},
	}, t1)
	if err != nil || len(ch) != 2 || ch[0].Check.CheckID != "ingress.bound" || ch[0].From != "fail" || ch[1].Check.CheckID != "host.disk" {
		t.Fatalf("second: %v %+v", err, ch)
	}
	got, err := db.NodeChecks(ctx, n.ID)
	if err != nil || len(got) != 3 {
		t.Fatalf("NodeChecks: %v %+v", err, got)
	}
	by := map[string]NodeCheck{}
	for _, c := range got {
		by[c.CheckID] = c
	}
	if !by["host.docker"].Since.Equal(t0) || by["host.docker"].Summary != "again" || !by["host.docker"].CheckedAt.Equal(t1) {
		t.Fatalf("unchanged status lost its since: %+v", by["host.docker"])
	}
	if !by["ingress.bound"].Since.Equal(t1) || !by["host.disk"].Since.Equal(t1) {
		t.Fatalf("changed: %+v", got)
	}
	// A check that the node no longer reports is dropped.
	if _, err := db.ReplaceNodeChecks(ctx, n.ID, []NodeCheck{{CheckID: "host.disk", Status: "warn"}}, t1.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.NodeChecks(ctx, n.ID); len(got) != 1 || !got[0].Since.Equal(t1) {
		t.Fatalf("after drop: %+v", got)
	}
	if _, err := db.ReplaceNodeChecks(ctx, "nope", []NodeCheck{{CheckID: "x"}}, t1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown node: %v", err)
	}
}

func TestNodeBehindSince(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	if _, behind, err := db.NodeBehindSince(ctx, n.ID); err != nil || behind {
		t.Fatalf("new node: %v %v", behind, err)
	}
	db.now = fixedClock(testNow)
	if _, err := db.NextNodeGeneration(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	db.now = fixedClock(testNow.Add(10 * time.Minute))
	if _, err := db.NextNodeGeneration(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	since, behind, err := db.NodeBehindSince(ctx, n.ID)
	if err != nil || !behind || !since.Equal(testNow.Truncate(time.Second)) {
		t.Fatalf("behind: %v %v %v, want since the first unapplied generation", since, behind, err)
	}
	mustExec(t, db, `UPDATE nodes SET applied_generation = desired_generation WHERE id = ?`, n.ID)
	if _, behind, _ := db.NodeBehindSince(ctx, n.ID); behind {
		t.Fatal("caught up, still behind")
	}
	db.now = fixedClock(testNow.Add(time.Hour))
	if _, err := db.NextNodeGeneration(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	if since, _, _ := db.NodeBehindSince(ctx, n.ID); !since.Equal(testNow.Add(time.Hour).Truncate(time.Second)) {
		t.Fatalf("since after catching up: %v", since)
	}
	if _, _, err := db.NodeBehindSince(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown node: %v", err)
	}
}

func TestDiagnosticRunsByChange(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	n := mustNode(t, db, "n1")
	if got := RolloutStepChange("r1", 0); got != "rollout r1 step 1" {
		t.Fatalf("change %q", got)
	}
	for i, change := range []string{RolloutStepChange("r1", 0), "rollout r10 step 1", RolloutStepChange("r1", 9), "other"} {
		db.now = fixedClock(testNow.Add(time.Duration(i) * time.Minute))
		if err := db.CreateDiagnosticRun(ctx, &DiagnosticRun{NodeID: n.ID, Scope: "node", Reason: RunBeforeChange, Change: change}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.DiagnosticRunsByChange(ctx, "rollout r1 step ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Change != "rollout r1 step 1" || got[1].Change != "rollout r1 step 10" {
		t.Fatalf("runs %+v", got)
	}
}
