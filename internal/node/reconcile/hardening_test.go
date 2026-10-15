package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
)

// A serving container that cannot be started again is removed once, as the
// proxy's own instance: it is not reported a second time as an orphan.
func TestNoSpuriousOrphanWhenRestartFails(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	if err := h.docker.Stop(context.Background(), engName1, 0); err != nil {
		t.Fatal(err)
	}
	h.docker.SetError("Start", errors.New("cannot start: boom"))
	h.pass()
	if n := len(h.eventsOf("orphan_removed")); n != 0 {
		t.Errorf("orphan_removed events = %d, want none", n)
	}
	if c := h.container(engName1); c != nil {
		t.Errorf("g1 = %+v, want removed", c)
	}
	// The attempt at g2 failed to start as well (and used its number).
	h.docker.SetError("Start", nil)
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 3 {
		t.Errorf("instance = g%d, want g3", rec.Generation)
	}
	if c := h.container("postern-eng-01j9zzproxy0000000000000p1-g3"); c == nil || c.State != "running" {
		t.Errorf("g3 = %+v, want running", c)
	}
}

// A Drain that fails is asked again on the next pass; once it went through it
// is not repeated.
func TestFailedEdgeDrainIsRetried(t *testing.T) {
	h := newHarness(t)
	h.addContainer("postern-edge-g1", "edge", "edge", 1, true)
	h.addContainer("postern-edge-g2", "edge", "edge", 2, true)
	h.apply(h.baseState(1))
	old := h.fakeEdge(1)
	old.setDrainErr(errors.New("edge Drain: unavailable"))
	h.pass()
	if n := len(old.drainCalls()); n != 1 {
		t.Fatalf("Drain calls = %d, want 1", n)
	}
	old.setDrainErr(nil)
	h.pass()
	if n := len(old.drainCalls()); n != 2 {
		t.Errorf("Drain calls = %d, want 2 (retried)", n)
	}
	h.pass()
	if n := len(old.drainCalls()); n != 2 {
		t.Errorf("Drain calls = %d, want still 2", n)
	}
	if n := len(h.eventsOf("edge_draining")); n != 1 {
		t.Errorf("edge_draining events = %d, want 1", n)
	}
}

// The force-stop deadline of an old edge runs from the first attempt, also
// when Drain never goes through.
func TestEdgeDrainDeadlineWhenDrainFails(t *testing.T) {
	h := newHarness(t)
	h.addContainer("postern-edge-g1", "edge", "edge", 1, true)
	h.addContainer("postern-edge-g2", "edge", "edge", 2, true)
	h.apply(h.baseState(1))
	h.fakeEdge(1).setDrainErr(errors.New("edge Drain: unavailable"))
	h.pass()
	h.clock.Advance(time.Hour)
	h.pass()
	if h.container("postern-edge-g1") == nil {
		t.Fatal("removed before the drain limit")
	}
	h.clock.Advance(10 * time.Minute)
	h.pass()
	if c := h.container("postern-edge-g1"); c != nil {
		t.Errorf("g1 = %+v, want removed", c)
	}
}

// An old edge that outlives its drain time is stopped with time to drain: on
// SIGTERM the edge waits up to 30 s for its connections, so a shorter stop
// timeout would have Docker kill it in the middle of that.
func TestOldEdgeIsStoppedWithTimeToDrain(t *testing.T) {
	h := newHarness(t)
	h.addContainer("postern-edge-g1", "edge", "edge", 1, true)
	h.addContainer("postern-edge-g2", "edge", "edge", 2, true)
	h.apply(h.baseState(1))
	h.pass()
	h.clock.Advance(time.Hour + 10*time.Minute)
	h.docker.ResetCalls()
	h.pass()
	var stops []time.Duration
	for _, c := range h.docker.Calls() {
		if c.Method == "Stop" && c.Target == "postern-edge-g1" {
			stops = append(stops, c.Timeout)
		}
	}
	if len(stops) != 1 {
		t.Fatalf("Stop calls for g1 = %v, want one", stops)
	}
	if stops[0] < 35*time.Second {
		t.Errorf("g1 was stopped with a timeout of %v, want at least 35s (the edge drains for up to 30s)", stops[0])
	}
	if c := h.container("postern-edge-g1"); c != nil {
		t.Errorf("g1 = %+v, want removed", c)
	}
}

// The edge container carries a stop timeout of its own, so that a stop which
// names none (the Docker daemon shutting down) leaves it the time to drain that
// the reconciler's own stop does: on SIGTERM the edge waits up to 30 s for its
// connections. The engines keep Docker's default.
func TestEdgeContainerHasTimeToDrain(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()

	edges := h.creates("edge")
	if len(edges) != 1 {
		t.Fatalf("created %d edges, want 1", len(edges))
	}
	switch st := edges[0].StopTimeout; {
	case st == nil:
		t.Error("the edge has no stop timeout of its own, want 35 s")
	case *st != 35:
		t.Errorf("the edge's stop timeout = %d s, want 35 s", *st)
	}
	engines := h.creates("engine")
	if len(engines) != 1 {
		t.Fatalf("created %d engines, want 1", len(engines))
	}
	if st := engines[0].StopTimeout; st != nil {
		t.Errorf("the engine's stop timeout = %d s, want none (Docker's default)", *st)
	}
}

// The edge container has a limit of open files of its own: the caps of the
// edge on connections are derived from it, and a relayed connection holds two
// descriptors. Docker's default limit depends on the host. The engines keep it.
func TestEdgeContainerHasOpenFileLimit(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()

	edges := h.creates("edge")
	if len(edges) != 1 {
		t.Fatalf("created %d edges, want 1", len(edges))
	}
	want := []dockerapi.Ulimit{{Name: "nofile", Soft: 1048576, Hard: 1048576}}
	if got := edges[0].Ulimits; !slices.Equal(got, want) {
		t.Errorf("the edge's ulimits = %+v, want %+v", got, want)
	}
	engines := h.creates("engine")
	if len(engines) != 1 {
		t.Fatalf("created %d engines, want 1", len(engines))
	}
	if got := engines[0].Ulimits; got != nil {
		t.Errorf("the engine's ulimits = %+v, want none (Docker's default)", got)
	}
}

// The limit of open files of the edge is min(1048576, fs.nr_open of the host):
// no process may have more than fs.nr_open, and a container whose limit is
// over it cannot be started. A value that cannot be read leaves 1048576.
func TestEdgeOpenFileLimit(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content string // of /proc/sys/fs/nr_open; "" for a file that cannot be read
		limit   int64
		nrOpen  int64
		fails   bool
	}{
		{"the default of Linux", "1048576\n", 1048576, 1048576, false},
		{"a host that allows more", "1073741816\n", 1048576, 1073741816, false},
		{"a host that allows less", "524288\n", 524288, 524288, false},
		{"spaces around", " 65536 \n", 65536, 65536, false},
		{"no such file", "", 1048576, 0, true},
		{"not a number", "lots\n", 1048576, 0, true},
		{"zero", "0\n", 1048576, 0, true},
		{"negative", "-1\n", 1048576, 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			read := func(name string) ([]byte, error) {
				if name != "/proc/sys/fs/nr_open" {
					t.Errorf("read %s, want /proc/sys/fs/nr_open", name)
				}
				if tt.content == "" {
					return nil, fs.ErrNotExist
				}
				return []byte(tt.content), nil
			}
			limit, nrOpen, err := edgeOpenFileLimit(read)
			if limit != tt.limit || nrOpen != tt.nrOpen || (err != nil) != tt.fails {
				t.Errorf("edgeOpenFileLimit = %d (fs.nr_open %d, error %v), want %d (fs.nr_open %d, an error: %v)",
					limit, nrOpen, err, tt.limit, tt.nrOpen, tt.fails)
			}
		})
	}
}

// The edge's limit of open files follows fs.nr_open of the host, which is read
// whenever the spec of an edge is built; the value is logged once.
func TestEdgeOpenFileLimitFollowsTheHost(t *testing.T) {
	h := newHarness(t)
	h.nrOpen = "524288\n"
	logs := &lockedBuffer{}
	h.r.Log = slog.New(slog.NewTextHandler(logs, nil))
	h.apply(h.baseState(1))
	h.pass()

	edges := h.creates("edge")
	if len(edges) != 1 {
		t.Fatalf("created %d edges, want 1", len(edges))
	}
	want := []dockerapi.Ulimit{{Name: "nofile", Soft: 524288, Hard: 524288}}
	if got := edges[0].Ulimits; !slices.Equal(got, want) {
		t.Errorf("the edge's ulimits on a host with fs.nr_open 524288 = %+v, want %+v", got, want)
	}

	// The next edge reads it again; it is logged once all the same.
	h.mu.Lock()
	h.nrOpen = ""
	h.mu.Unlock()
	want = []dockerapi.Ulimit{{Name: "nofile", Soft: 1048576, Hard: 1048576}}
	if got := h.r.edgeSpec(2, false, h.nodeBinary).Ulimits; !slices.Equal(got, want) {
		t.Errorf("the edge's ulimits when fs.nr_open cannot be read = %+v, want %+v", got, want)
	}
	out := logs.String()
	if n := strings.Count(out, "limit of open files"); n != 1 {
		t.Errorf("the limit of open files of the edge is logged %d times, want once:\n%s", n, out)
	}
	if !strings.Contains(out, "nofile=524288") || !strings.Contains(out, "fs_nr_open=524288") {
		t.Errorf("the log does not tell the limit and where it comes from:\n%s", out)
	}
}

// lockedBuffer collects log output; it is safe for concurrent use.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// A stopped serving engine whose bind sources are gone is not started (Docker
// would create the missing binary as an empty directory): it is replaced.
func TestStoppedEngineWithMissingBinaryIsNotStarted(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	if err := h.docker.Stop(context.Background(), engName1, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(h.paths.ArtifactsDir(), "telemt")); err != nil {
		t.Fatal(err)
	}
	h.docker.ResetCalls()
	h.pass()
	for _, c := range h.docker.Calls() {
		if c.Method == "Start" && c.Target == engName1 {
			t.Error("started an engine whose binary is gone")
		}
	}
	if c := h.container(engName1); c != nil {
		t.Errorf("g1 = %+v, want removed", c)
	}
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || !strings.Contains(ps.GetReason(), "artifact missing") {
		t.Errorf("status = %v, want failed: artifact missing", ps)
	}
}

// An edge container left created is not started when its bind sources are
// not right.
func TestCreatedEdgeNotStartedWithoutNodeBinary(t *testing.T) {
	h := newHarness(t)
	h.addContainer("postern-edge-g4", "edge", "edge", 4, false)
	h.apply(h.baseState(1))
	if err := os.Remove(h.nodeBinary); err != nil {
		t.Fatal(err)
	}
	h.docker.ResetCalls()
	err := h.r.reconcileOnce(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "node binary") {
		t.Fatalf("pass = %v, want a node binary error", err)
	}
	for _, c := range h.docker.Calls() {
		if c.Method == "Start" {
			t.Errorf("started %s", c.Target)
		}
	}
}

// A new runner image rolls the engines.
func TestRunnerImageChangeIsBlueGreen(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	const newImage = "alpine:3.22"
	h.r.RunnerImage = newImage
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 2 {
		t.Fatalf("instance = g%d, want g2", rec.Generation)
	}
	creates := h.creates("engine")
	if last := creates[len(creates)-1]; last.Image != newImage {
		t.Errorf("g2 image = %q, want %q", last.Image, newImage)
	}
}

// A new binary for the same version (another checksum) rolls the engine.
func TestArtifactChecksumChangeIsBlueGreen(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	binary := []byte("#!/bin/sh\n# rebuilt\nexit 0\n")
	sum := sha256.Sum256(binary)
	newSum := hex.EncodeToString(sum[:])
	if err := h.arts.Put(artifacts.Ref{
		Engine: "telemt", Version: "3.5.13", Arch: "amd64", SHA256: newSum, FileName: "telemt", Binary: "telemt",
	}, bytes.NewReader(binary)); err != nil {
		t.Fatal(err)
	}
	st := h.baseState(2)
	st.Artifacts[0].Sha256 = newSum
	h.apply(st)
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 2 {
		t.Errorf("instance = g%d, want g2", rec.Generation)
	}
	// The same checksum in another case is the same binary.
	st = h.baseState(3)
	st.Artifacts[0].Sha256 = strings.ToUpper(newSum)
	h.apply(st)
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 2 {
		t.Errorf("instance = g%d after a case change of the checksum, want g2", rec.Generation)
	}
}

// The serving record keeps the binary its container mounts.
func TestServingRecordKeepsBinaryPath(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	rec := h.runtime().Instances[proxyID]
	want := filepath.Join(h.paths.ArtifactsDir(), "telemt", "3.5.13", "amd64", "telemt")
	if rec.BinaryPath != want {
		t.Errorf("binary path = %q, want %q", rec.BinaryPath, want)
	}
	if !slices.Contains(h.creates("engine")[0].Binds, want+":/opt/engine/telemt:ro") {
		t.Errorf("engine binds = %v", h.creates("engine")[0].Binds)
	}
}
