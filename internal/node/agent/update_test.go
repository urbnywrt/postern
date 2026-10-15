package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/selfupdate"
	"github.com/urbnywrt/postern/internal/node/selfupdate/selfupdatetest"
)

// updateSelf sends meta, then data in chunks of 1 KiB.
func updateSelf(c nodev1connect.NodeServiceClient, meta *nodev1.NodeBinary, data []byte) (*nodev1.UpdateSelfResponse, error) {
	stream := c.UpdateSelf(context.Background())
	if meta != nil {
		if err := stream.Send(&nodev1.UpdateSelfRequest{Part: &nodev1.UpdateSelfRequest_Meta{Meta: meta}}); err != nil {
			_, err = stream.CloseAndReceive()
			return nil, err
		}
	}
	for len(data) > 0 {
		n := min(len(data), 1024)
		if err := stream.Send(&nodev1.UpdateSelfRequest{Part: &nodev1.UpdateSelfRequest_Chunk{Chunk: data[:n]}}); err != nil {
			break // the answer says why
		}
		data = data[n:]
	}
	resp, err := stream.CloseAndReceive()
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func wantCode(t *testing.T, err error, code connect.Code) {
	t.Helper()
	if connect.CodeOf(err) != code {
		t.Fatalf("err = %v, want %v", err, code)
	}
}

// A good binary is installed, the answer says restarting, and then Run stops
// with ErrRestart, the launcher's bin/current pointing at the new binary.
func TestUpdateSelfRestartsTheAgent(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	if err := os.Symlink("postern-node-test", filepath.Join(home, "bin", "current")); err != nil {
		t.Fatal(err)
	}
	signer := selfupdatetest.NewSigner(t)
	a := startAgent(t, home, p, func(o *Options) {
		o.releaseKeys = signer.Keys
		o.exec = selfupdatetest.Exec("v0.6.0")
	})
	c := a.client()
	data := selfupdatetest.Binary(t, runtime.GOARCH, "v0.6.0")
	resp, err := updateSelf(c, signer.Meta(t, data, "v0.6.0", runtime.GOARCH), data)
	if err != nil {
		t.Fatalf("UpdateSelf: %v", err)
	}
	if resp.GetVersion() != "v0.6.0" || !resp.GetRestarting() {
		t.Errorf("UpdateSelf = %v, want v0.6.0 restarting", resp)
	}
	select {
	case err := <-a.done:
		a.done <- err
		if !errors.Is(err, ErrRestart) {
			t.Fatalf("Run = %v, want ErrRestart\n%s", err, a.stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the agent did not stop for the restart")
	}
	bin := selfupdate.Binaries(home)
	if bin.GetCurrent() != "v0.6.0" || bin.GetPrevious() != "test" {
		t.Errorf("binaries = %v, want current v0.6.0 and previous test", bin)
	}
	if log := a.stderr.String(); !strings.Contains(log, "event=agent_updating") || !strings.Contains(log, "from dev to v0.6.0") {
		t.Errorf("no agent_updating in the log:\n%s", log)
	}
}

func TestUpdateSelfRefuses(t *testing.T) {
	r := newRig(t)
	data := selfupdatetest.Binary(t, runtime.GOARCH, "v0.6.0")
	meta := r.signer.Meta(t, data, "v0.6.0", runtime.GOARCH)

	_, err := updateSelf(r.client, nil, data)
	wantCode(t, err, connect.CodeInvalidArgument)

	big := r.signer.Meta(t, data, "v0.6.0", runtime.GOARCH)
	big.Size = selfupdate.MaxSize + 1
	_, err = updateSelf(r.client, big, data)
	wantCode(t, err, connect.CodeResourceExhausted)

	// More chunks than an update may have.
	r.svc.updateMu.Lock()
	r.svc.maxUpload = 100
	r.svc.updateMu.Unlock()
	_, err = updateSelf(r.client, meta, data)
	wantCode(t, err, connect.CodeResourceExhausted)
	r.svc.updateMu.Lock()
	r.svc.maxUpload = defaultMaxUpload
	r.svc.updateMu.Unlock()

	other := selfupdatetest.NewSigner(t).Meta(t, data, "v0.6.0", runtime.GOARCH)
	_, err = updateSelf(r.client, other, data)
	wantCode(t, err, connect.CodePermissionDenied)

	old := selfupdatetest.Binary(t, runtime.GOARCH, "v0.4.0")
	_, err = updateSelf(r.client, r.signer.Meta(t, old, "v0.4.0", runtime.GOARCH), old)
	wantCode(t, err, connect.CodePermissionDenied)

	dyn := selfupdatetest.DynamicBinary(t, runtime.GOARCH, "v0.6.0")
	_, err = updateSelf(r.client, r.signer.Meta(t, dyn, "v0.6.0", runtime.GOARCH), dyn)
	wantCode(t, err, connect.CodeFailedPrecondition)

	if r.restarts.Load() != 0 || exists(filepath.Join(r.home, "bin", "postern-node-v0.6.0")) {
		t.Error("a refused update installed something or restarted")
	}

	// A good one: the restart is asked for once its answer went out.
	resp, err := updateSelf(r.client, meta, data)
	if err != nil || !resp.GetRestarting() {
		t.Fatalf("UpdateSelf = %v, %v", resp, err)
	}
	waitFor(t, "the restart", func() bool { return r.restarts.Load() == 1 })
	if !strings.Contains(strings.Join(r.bufferKinds(), " "), "event:agent_updating") {
		t.Errorf("no agent_updating event: %v", r.bufferKinds())
	}
	// The same version again: nothing changes, no restart.
	resp, err = updateSelf(r.client, meta, data)
	if err != nil || resp.GetRestarting() {
		t.Fatalf("UpdateSelf again = %v, %v", resp, err)
	}
	time.Sleep(50 * time.Millisecond)
	if r.restarts.Load() != 1 {
		t.Errorf("restarts = %d, want 1", r.restarts.Load())
	}
}

// One UpdateSelf at a time: a second call while one runs is Unavailable.
func TestUpdateSelfOneAtATime(t *testing.T) {
	r := newRig(t)
	data := selfupdatetest.Binary(t, runtime.GOARCH, "v0.6.0")
	// The second call is made only once the first holds the lock: polling
	// with calls of its own would race the first for it.
	locked := make(chan struct{}, 1)
	r.svc.updateLocked = func() { locked <- struct{}{} }
	first := r.client.UpdateSelf(context.Background())
	if err := first.Send(&nodev1.UpdateSelfRequest{Part: &nodev1.UpdateSelfRequest_Meta{Meta: r.signer.Meta(t, data, "v0.6.0", runtime.GOARCH)}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-locked:
	case <-time.After(20 * time.Second):
		t.Fatal("the first call never took the lock")
	}
	_, err := updateSelf(r.client, nil, []byte("x"))
	wantCode(t, err, connect.CodeUnavailable)
	if err := first.Send(&nodev1.UpdateSelfRequest{Part: &nodev1.UpdateSelfRequest_Chunk{Chunk: data}}); err != nil {
		t.Fatal(err)
	}
	if resp, err := first.CloseAndReceive(); err != nil || !resp.Msg.GetRestarting() {
		t.Fatalf("the first call = %v, %v", resp, err)
	}
}

// Binaries that a managed container mounts are kept by the GC after an
// UpdateSelf; the others go while more than three versions remain.
func TestUpdateSelfCollectsOldBinaries(t *testing.T) {
	r := newRig(t)
	bin := filepath.Join(r.home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"v0.1.0", "v0.2.0", "v0.3.0", "v0.4.0"} {
		if err := os.WriteFile(filepath.Join(bin, "postern-node-"+v), []byte(v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("postern-node-v0.4.0", filepath.Join(bin, "current")); err != nil {
		t.Fatal(err)
	}
	mounted := filepath.Join(bin, "postern-node-v0.1.0")
	r.docker.AddImage(RunnerImage)
	if _, err := r.docker.Create(context.Background(), dockerapi.ContainerSpec{
		Name: "postern-edge-g1", Image: RunnerImage, Labels: map[string]string{"postern.managed": "true"},
		Binds: []string{mounted + ":/opt/postern/bin/postern-node:ro"},
	}); err != nil {
		t.Fatal(err)
	}
	data := selfupdatetest.Binary(t, runtime.GOARCH, "v0.6.0")
	if _, err := updateSelf(r.client, r.signer.Meta(t, data, "v0.6.0", runtime.GOARCH), data); err != nil {
		t.Fatal(err)
	}
	got := selfupdate.Binaries(r.home)
	want := []string{"v0.1.0", "v0.4.0", "v0.6.0"} // mounted, previous, current
	if strings.Join(got.GetVersions(), " ") != strings.Join(want, " ") {
		t.Errorf("versions = %v, want %v", got.GetVersions(), want)
	}
}

// GetInfo.healthy is false until the agent's first good pass wrote its marker.
func TestRunReportsHealthy(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	saveStateWithoutProxies(t, home) // a pass that lists the containers
	var docker *dockerapi.Fake
	passes := make(chan error, 16)
	a := startAgent(t, home, p, func(o *Options) {
		docker = o.docker.(*dockerapi.Fake)
		docker.SetError("List", errors.New("docker is down"))
		o.passed = func(err error) { passes <- err }
	})
	c := a.client()
	healthy := func() bool {
		t.Helper()
		info, err := c.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return info.Msg.GetHealthy()
	}
	if healthy() {
		t.Error("healthy before any pass")
	}
	select {
	case <-passes:
	case <-time.After(20 * time.Second):
		t.Fatal("no pass")
	}
	if healthy() {
		t.Error("healthy after a failed pass")
	}
	docker.SetError("List", nil)
	if _, err := c.ApplyState(context.Background(), connect.NewRequest(&nodev1.ApplyStateRequest{State: validState(2)})); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "healthy", healthy)
}

// An agent without its marker 10 minutes after the start stops with an error
// that says why (the launcher counts the start); one with it goes on.
func TestRunMarkerDeadline(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	saveStateWithoutProxies(t, home) // a pass that lists the containers
	due := make(chan time.Time, 1)
	var asked atomic.Int64
	passes := make(chan error, 16)
	a := startAgent(t, home, p, func(o *Options) {
		o.docker.(*dockerapi.Fake).SetError("List", errors.New("docker is down"))
		o.after = func(d time.Duration) <-chan time.Time { asked.Store(int64(d)); return due }
		o.passed = func(err error) { passes <- err }
	})
	a.client()
	select {
	case <-passes:
	case <-time.After(20 * time.Second):
		t.Fatal("no pass")
	}
	waitFor(t, "the deadline", func() bool { return asked.Load() != 0 })
	if time.Duration(asked.Load()) != 10*time.Minute {
		t.Errorf("deadline = %v, want 10m", time.Duration(asked.Load()))
	}
	due <- time.Now()
	select {
	case err := <-a.done:
		a.done <- err
		if err == nil || !strings.Contains(err.Error(), "not healthy 10m0s after the start") || !strings.Contains(err.Error(), "docker is down") {
			t.Errorf("Run = %v, want the deadline and why", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the agent did not stop at the deadline")
	}
}

func TestRunMarkerDeadlineWhenHealthy(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	due := make(chan time.Time, 1)
	a := startAgent(t, home, p, func(o *Options) {
		o.after = func(time.Duration) <-chan time.Time { return due }
	})
	c := a.client()
	waitFor(t, "the healthy marker", func() bool { return exists(a.marker()) })
	due <- time.Now()
	time.Sleep(100 * time.Millisecond)
	if _, err := c.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{})); err != nil {
		t.Fatalf("the healthy agent stopped at the deadline: %v", err)
	}
	if err := a.stop(); err != nil {
		t.Errorf("Run = %v", err)
	}
}

// saveStateWithoutProxies stores a desired state, so that a pass asks Docker.
func saveStateWithoutProxies(t *testing.T, home string) {
	t.Helper()
	st := validState(1)
	st.Proxies = nil
	if err := (&storeFor{home}).save(st); err != nil {
		t.Fatal(err)
	}
}
