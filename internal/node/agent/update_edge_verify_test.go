package agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/reconcile"
	"github.com/urbnywrt/postern/internal/node/selfupdate/selfupdatetest"
)

// The binary of an edge is verified as UpdateSelf verifies one: the signature
// kept beside it, a static ELF. The running agent's own file needs no kept
// signature.
func TestUpdateEdgeVerifiesTheBinary(t *testing.T) {
	r := newRig(t)
	r.runningEdge(1, "v9.9.8")
	asked := r.setRoll(func(context.Context, string) (uint64, error) {
		r.setEdgeVersion(2, "v9.9.9", nil)
		return 2, nil
	})

	r.edgeBinary("v9.9.9", "v9.9.9", 0o755, unsigned)
	_, err := updateEdge(r.client, "v9.9.9")
	wantCode(t, err, connect.CodePermissionDenied)

	r.edgeBinary("v9.9.9", "v9.9.9", 0o755, dynamic)
	_, err = updateEdge(r.client, "v9.9.9")
	wantCode(t, err, connect.CodeFailedPrecondition)

	// Signed, but by a key this build does not trust.
	path := r.edgeBinary("v9.9.9", "v9.9.9", 0o755, unsigned)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	other := selfupdatetest.NewSigner(t).Meta(t, data, "v9.9.9", runtime.GOARCH).GetSignature()
	if err := os.WriteFile(filepath.Join(r.home, "bin", ".postern-node-v9.9.9.minisig"), []byte(other), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = updateEdge(r.client, "v9.9.9")
	wantCode(t, err, connect.CodePermissionDenied)
	if got := r.asked(asked); len(got) != 0 {
		t.Errorf("rolls asked for %v, want none", got)
	}

	// The running agent's own binary (its version, its contents) goes in
	// without a kept signature.
	own := r.edgeBinary("v0.5.0", "v0.5.0", 0o755, unsigned)
	r.svc.ownBinary = own
	r.svc.installer.SelfExe = own // what /proc/self/exe opens
	r.setEdgeVersion(1, "v0.4.0", nil)
	r.setRoll(func(context.Context, string) (uint64, error) {
		r.setEdgeVersion(2, "v0.5.0", nil)
		return 2, nil
	})
	if _, err := updateEdge(r.client, "v0.5.0"); err != nil {
		t.Errorf("UpdateEdge(the agent's own version) = %v", err)
	}
}

// An older version than the running edge's goes in only as a rollback, and a
// rollback only to the version the edge ran before its last roll.
func TestUpdateEdgeRefusesAnOlderVersion(t *testing.T) {
	r := newRig(t)
	r.runningEdge(2, "v9.9.9", "v9.9.7")
	r.edgeBinary("v9.9.8", "v9.9.8", 0o755)
	r.edgeBinary("v9.9.7", "v9.9.7", 0o755)
	asked := r.setRoll(func(context.Context, string) (uint64, error) {
		r.setEdgeVersion(3, "v9.9.7", nil)
		return 3, nil
	})
	_, err := updateEdge(r.client, "v9.9.8")
	wantCode(t, err, connect.CodePermissionDenied)

	rollback := func(v string) error {
		_, err := r.client.UpdateEdge(context.Background(), connect.NewRequest(&nodev1.UpdateEdgeRequest{Version: v, Rollback: true}))
		return err
	}
	wantCode(t, rollback("v9.9.8"), connect.CodePermissionDenied) // not the previous one
	if err := rollback("v9.9.7"); err != nil {
		t.Errorf("rollback to the previous version = %v", err)
	}
	if got := r.asked(asked); len(got) != 1 {
		t.Errorf("rolls asked for %v, want the rollback only", got)
	}
}

// A roll that an earlier call gave up on still runs: Unavailable, and no
// edge_roll_failed.
func TestUpdateEdgeWhileAnAbandonedRollRuns(t *testing.T) {
	r := newRig(t)
	r.runningEdge(1, "v9.9.8")
	r.edgeBinary("v9.9.9", "v9.9.9", 0o755)
	r.setRoll(func(context.Context, string) (uint64, error) { return 0, reconcile.ErrEdgeRollBusy })
	_, err := updateEdge(r.client, "v9.9.9")
	wantCode(t, err, connect.CodeUnavailable)
	if n := countKind(r.bufferKinds(), "event:edge_roll_failed"); n != 0 {
		t.Errorf("edge_roll_failed events = %d, want 0", n)
	}
}
