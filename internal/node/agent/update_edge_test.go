package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/reconcile"
	"github.com/urbnywrt/postern/internal/node/selfupdate/selfupdatetest"
	"github.com/urbnywrt/postern/internal/node/state"
)

// saysMarker ends a test binary: what follows it is what its "version"
// prints (fileVersionExec).
const saysMarker = "\nsays:"

// fileVersionExec stands in for running "<file> version": it prints what the
// file says it is (after saysMarker), then " (test)".
func fileVersionExec(_ context.Context, path string, args ...string) ([]byte, error) {
	if len(args) != 1 || args[0] != "version" {
		return nil, errors.New("unexpected arguments")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	i := bytes.LastIndex(data, []byte(saysMarker))
	if i < 0 {
		return nil, errors.New("exec format error")
	}
	return []byte(string(data[i+len(saysMarker):]) + " (test)\n"), nil
}

// binaryKind is how edgeBinary makes a binary.
type binaryKind int

const (
	signed   binaryKind = iota // a static ELF, signed by the rig's release key
	unsigned                   // a static ELF without a kept signature
	dynamic                    // a signed ELF with an interpreter
)

// edgeBinary writes bin/postern-node-<v>, whose "version" prints says, and the
// signature UpdateSelf keeps beside it (unless unsigned).
func (r *rig) edgeBinary(v, says string, mode os.FileMode, kind ...binaryKind) string {
	r.t.Helper()
	bin := filepath.Join(r.home, "bin")
	path := filepath.Join(bin, "postern-node-"+v)
	if err := os.MkdirAll(bin, 0o755); err != nil {
		r.t.Fatal(err)
	}
	k := signed
	if len(kind) > 0 {
		k = kind[0]
	}
	data := selfupdatetest.Binary(r.t, runtime.GOARCH, v)
	if k == dynamic {
		data = selfupdatetest.DynamicBinary(r.t, runtime.GOARCH, v)
	}
	data = append(data, saysMarker+says...)
	if err := os.WriteFile(path, data, mode); err != nil {
		r.t.Fatal(err)
	}
	if k != unsigned {
		sig := r.signer.Meta(r.t, data, v, runtime.GOARCH).GetSignature()
		if err := os.WriteFile(filepath.Join(bin, ".postern-node-"+v+".minisig"), []byte(sig), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	return path
}

// runningEdge records edge generation gen as the one that serves, answering
// Health with version.
func (r *rig) runningEdge(gen uint64, version string, previous ...string) {
	r.t.Helper()
	rt := state.NewRuntime()
	rt.EdgeGeneration = gen
	if len(previous) > 0 {
		rt.EdgePreviousBinary = filepath.Join(r.home, "bin", "postern-node-"+previous[0])
	}
	if err := r.store.SaveRuntime(rt); err != nil {
		r.t.Fatal(err)
	}
	r.setEdgeVersion(gen, version, nil)
}

// setRoll sets what the reconciler's RollEdge does, and records the binaries
// it was asked for.
func (r *rig) setRoll(f func(ctx context.Context, binary string) (uint64, error)) *[]string {
	asked := &[]string{}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roll = func(ctx context.Context, binary string) (uint64, error) {
		r.mu.Lock()
		*asked = append(*asked, binary)
		r.mu.Unlock()
		return f(ctx, binary)
	}
	return asked
}

func (r *rig) asked(a *[]string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(*a)
}

func updateEdge(c interface {
	UpdateEdge(context.Context, *connect.Request[nodev1.UpdateEdgeRequest]) (*connect.Response[nodev1.UpdateEdgeResponse], error)
}, v string,
) (*nodev1.UpdateEdgeResponse, error) {
	resp, err := c.UpdateEdge(context.Background(), connect.NewRequest(&nodev1.UpdateEdgeRequest{Version: v}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// The edge rolls to an installed binary: the reconciler is asked for a roll to
// bin/postern-node-<v>, and the answer is the new generation once it answers
// Health with v.
func TestUpdateEdge(t *testing.T) {
	r := newRig(t)
	r.runningEdge(1, "v9.9.8")
	bin := r.edgeBinary("v9.9.9", "v9.9.9", 0o755)
	asked := r.setRoll(func(_ context.Context, _ string) (uint64, error) {
		r.setEdgeVersion(2, "v9.9.9", nil)
		return 2, nil
	})
	resp, err := updateEdge(r.client, "v9.9.9")
	if err != nil {
		t.Fatalf("UpdateEdge: %v", err)
	}
	if resp.GetGeneration() != 2 || resp.GetVersion() != "v9.9.9" {
		t.Errorf("UpdateEdge = %v, want generation 2 on v9.9.9", resp)
	}
	if got := r.asked(asked); !slices.Equal(got, []string{bin}) {
		t.Errorf("rolls asked for %v, want [%s]", got, bin)
	}
}

// The edge that runs v already, and answers, is not rolled.
func TestUpdateEdgeSameVersion(t *testing.T) {
	r := newRig(t)
	r.runningEdge(3, "v9.9.9")
	r.edgeBinary("v9.9.9", "v9.9.9", 0o755)
	asked := r.setRoll(func(context.Context, string) (uint64, error) { return 4, nil })
	resp, err := updateEdge(r.client, "v9.9.9")
	if err != nil || resp.GetGeneration() != 3 || resp.GetVersion() != "v9.9.9" {
		t.Fatalf("UpdateEdge = %v, %v; want generation 3 without a roll", resp, err)
	}
	if got := r.asked(asked); len(got) != 0 {
		t.Errorf("rolls asked for %v, want none", got)
	}
}

// A roll that fails is Aborted with the reason. The reconciler records
// edge_roll_failed for a generation that did not come up; the agent records it
// for what else ends a roll (the 120 s, a generation on another version).
func TestUpdateEdgeAborted(t *testing.T) {
	r := newRig(t)
	r.runningEdge(1, "v9.9.8")
	r.edgeBinary("v9.9.9", "v9.9.9", 0o755)

	r.setRoll(func(context.Context, string) (uint64, error) {
		return 0, fmt.Errorf("%w: edge g2 does not answer", reconcile.ErrEdgeRollFailed)
	})
	_, err := updateEdge(r.client, "v9.9.9")
	wantCode(t, err, connect.CodeAborted)
	if !strings.Contains(err.Error(), "edge g2 does not answer") {
		t.Errorf("err = %v, want the reason", err)
	}
	if n := countKind(r.bufferKinds(), "event:edge_roll_failed"); n != 0 {
		t.Errorf("edge_roll_failed events from the agent = %d, want 0 (the reconciler's)", n)
	}

	r.setRoll(func(ctx context.Context, _ string) (uint64, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	})
	r.svc.edgeRollTimeout = 50 * time.Millisecond
	_, err = updateEdge(r.client, "v9.9.9")
	wantCode(t, err, connect.CodeAborted)
	if n := countKind(r.bufferKinds(), "event:edge_roll_failed"); n != 1 {
		t.Errorf("edge_roll_failed events = %d, want 1", n)
	}

	r.setRoll(func(context.Context, string) (uint64, error) {
		r.setEdgeVersion(5, "v9.9.7", nil)
		return 5, nil
	})
	_, err = updateEdge(r.client, "v9.9.9")
	wantCode(t, err, connect.CodeAborted)
	if !strings.Contains(err.Error(), "v9.9.7") {
		t.Errorf("err = %v, want the version the new generation answers", err)
	}
	if n := countKind(r.bufferKinds(), "event:edge_roll_failed"); n != 2 {
		t.Errorf("edge_roll_failed events = %d, want 2", n)
	}
}

// What is not a binary of the version is refused before any roll.
func TestUpdateEdgeRefusesTheBinary(t *testing.T) {
	r := newRig(t)
	r.runningEdge(1, "v9.9.8")
	asked := r.setRoll(func(context.Context, string) (uint64, error) { return 2, nil })

	_, err := updateEdge(r.client, "../v9")
	wantCode(t, err, connect.CodeInvalidArgument)

	_, err = updateEdge(r.client, "v9.9.9") // not installed
	wantCode(t, err, connect.CodeFailedPrecondition)

	r.edgeBinary("v9.9.9", "v9.9.6", 0o755) // prints another version
	_, err = updateEdge(r.client, "v9.9.9")
	wantCode(t, err, connect.CodeFailedPrecondition)
	if !strings.Contains(err.Error(), "v9.9.6") {
		t.Errorf("err = %v, want what it says it is", err)
	}

	r.edgeBinary("v9.9.15", "v9.9.15", 0o644) // not executable
	_, err = updateEdge(r.client, "v9.9.15")
	wantCode(t, err, connect.CodeFailedPrecondition)

	target := r.edgeBinary("v9.9.14", "v9.9.14", 0o755) // a symlink to it
	if err := os.Symlink(target, filepath.Join(r.home, "bin", "postern-node-v9.9.13")); err != nil {
		t.Fatal(err)
	}
	_, err = updateEdge(r.client, "v9.9.13")
	wantCode(t, err, connect.CodeFailedPrecondition)

	if got := r.asked(asked); len(got) != 0 {
		t.Errorf("rolls asked for %v, want none", got)
	}
}

// A second call while a roll runs is Unavailable.
func TestUpdateEdgeOneAtATime(t *testing.T) {
	r := newRig(t)
	r.runningEdge(1, "v9.9.8")
	r.edgeBinary("v9.9.9", "v9.9.9", 0o755)
	release := make(chan struct{})
	r.setRoll(func(context.Context, string) (uint64, error) {
		<-release
		r.setEdgeVersion(2, "v9.9.9", nil)
		return 2, nil
	})
	first := make(chan error, 1)
	go func() {
		_, err := updateEdge(r.client, "v9.9.9")
		first <- err
	}()
	waitFor(t, "the first roll", func() bool {
		r.svc.mu.Lock()
		defer r.svc.mu.Unlock()
		return r.svc.edgeRolling
	})
	_, err := updateEdge(r.client, "v9.9.9")
	wantCode(t, err, connect.CodeUnavailable)
	close(release)
	if err := <-first; err != nil {
		t.Errorf("the first call: %v", err)
	}
}

func countKind(kinds []string, kind string) int {
	n := 0
	for _, k := range kinds {
		if k == kind {
			n++
		}
	}
	return n
}

// procSysWith makes a /proc/sys under home whose net.ipv4.tcp_migrate_req is
// value ("" leaves the key out, as Linux before 5.14).
func procSysWith(home, value string) string {
	dir := filepath.Join(home, "procsys-"+value)
	if value != "" {
		_ = os.MkdirAll(filepath.Join(dir, "net", "ipv4"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, "net", "ipv4", "tcp_migrate_req"), []byte(value+"\n"), 0o644)
	}
	return dir
}

// Without net.ipv4.tcp_migrate_req = 1 (finding F2) GetInfo warns
// edge-handoff-unsafe, and the event edge_handoff_unsafe is recorded once at
// the start.
func TestRunWarnsOfAnUnsafeHandoff(t *testing.T) {
	for _, value := range []string{"0", ""} {
		t.Run("value "+value, func(t *testing.T) {
			p := newTestPKI(t)
			home := installHome(t, p, testNodeID)
			a := startAgent(t, home, p, func(o *Options) { o.procSys = procSysWith(home, value) })
			c := a.client()
			info, err := c.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(info.Msg.GetWarnings(), "edge-handoff-unsafe") {
				t.Errorf("warnings = %v, want edge-handoff-unsafe", info.Msg.GetWarnings())
			}
			if n := strings.Count(a.stderr.String(), "event=edge_handoff_unsafe"); n != 1 {
				t.Errorf("edge_handoff_unsafe in the log %d times, want once:\n%s", n, a.stderr.String())
			}
		})
	}
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	a := startAgent(t, home, p, nil) // tcp_migrate_req = 1
	info, err := a.client().GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(info.Msg.GetWarnings(), "edge-handoff-unsafe") || strings.Contains(a.stderr.String(), "edge_handoff_unsafe") {
		t.Errorf("warnings = %v with tcp_migrate_req = 1", info.Msg.GetWarnings())
	}
}

// Docker that does not answer at the marker deadline is not the binary's
// fault: the agent does not exit (the launcher would count the start and roll
// a good binary back), and the deadline starts over.
func TestRunMarkerDeadlineWhileDockerIsDown(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	saveStateWithoutProxies(t, home)
	due := make(chan time.Time, 1)
	var asked atomic.Int32
	a := startAgent(t, home, p, func(o *Options) {
		f := o.docker.(*dockerapi.Fake)
		f.SetError("List", errors.New("docker is down"))
		f.SetError("Ping", errors.New("docker is down"))
		o.after = func(time.Duration) <-chan time.Time { asked.Add(1); return due }
	})
	c := a.client()
	waitFor(t, "the deadline", func() bool { return asked.Load() == 1 })
	due <- time.Now()
	waitFor(t, "the deadline again", func() bool { return asked.Load() == 2 })
	if _, err := c.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{})); err != nil {
		t.Fatalf("the agent stopped while Docker was down: %v", err)
	}
	if !strings.Contains(a.stderr.String(), "Docker does not answer") {
		t.Errorf("no word of Docker in the log:\n%s", a.stderr.String())
	}
}

// The restart after UpdateSelf belongs to that call: the flag is the call's
// own (its context), so another call that ends meanwhile asks for nothing.
func TestRestartIsScopedToTheCall(t *testing.T) {
	r := newRig(t)
	due := new(atomic.Bool)
	r.svc.askRestart(context.WithValue(context.Background(), restartKey{}, due))
	if !due.Load() || r.restarts.Load() != 0 {
		t.Errorf("due %v, restarts %d; want the call's flag set and no restart yet", due.Load(), r.restarts.Load())
	}
	// Another call through the handler ends: no restart.
	if _, err := r.client.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{})); err != nil {
		t.Fatal(err)
	}
	if r.restarts.Load() != 0 {
		t.Errorf("restarts = %d after another call, want 0", r.restarts.Load())
	}
}
