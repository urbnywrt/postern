package reconcile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/trial"
)

// refOf is the store reference of an artifact of the desired state.
func refOf(a *nodev1.ArtifactRef) artifacts.Ref {
	return artifacts.Ref{Engine: a.Engine, Version: a.Version, Arch: a.Arch, SHA256: a.Sha256, FileName: a.FileName, Binary: a.Binary}
}

// storeArtifact stores one more stand-in binary, as newHarness does.
func (h *harness) storeArtifact(engine, version, name string) *nodev1.ArtifactRef {
	h.t.Helper()
	binary := []byte("#!/bin/sh\nexit 0\n")
	sum := sha256.Sum256(binary)
	ref := &nodev1.ArtifactRef{Engine: engine, Version: version, Arch: "amd64", Sha256: hex.EncodeToString(sum[:]), FileName: name, Binary: name}
	if err := h.arts.Put(refOf(ref), bytes.NewReader(binary)); err != nil {
		h.t.Fatal(err)
	}
	return ref
}

// An artifact stored before this slice has no trial record: it is tried in
// the pass that needs it, once, and then used; later passes trust the record.
func TestArtifactTriedOnceThenUsed(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	h.pass()
	want := []string{h.arts.BinaryPath(refOf(h.artifact))}
	if got := h.trials.tried(); !slices.Equal(got, want) {
		t.Errorf("tried %q, want %q", got, want)
	}
	rec, ok := h.arts.Trial(refOf(h.artifact))
	if !ok || !rec.OK || rec.Image != runnerImage || !rec.At.Equal(h.clock.Now()) {
		t.Errorf("record = %+v, %v", rec, ok)
	}
	if c := h.container(engName1); c == nil || c.State != "running" {
		t.Errorf("g1 = %+v, want running", c)
	}
	if ps := h.proxyStatus(proxyID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING {
		t.Errorf("status = %v", ps)
	}
}

// A trial that did not run (Docker was not reachable) leaves the artifact
// untried: the start fails for this pass, nothing is recorded, and the next
// pass tries again.
func TestArtifactTrialNotRunIsTriedNextPass(t *testing.T) {
	h := newHarness(t)
	h.trials.set(trial.Result{Reason: "asking Docker about the runner image: connection refused"})
	h.apply(h.baseState(1))
	h.pass()

	if n := len(h.creates("engine")); n != 0 {
		t.Errorf("created %d engines, want none", n)
	}
	ps := h.proxyStatus(proxyID)
	const want = "artifact not tried yet: telemt 3.5.13 for amd64: asking Docker about the runner image: connection refused"
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || ps.GetReason() != want {
		t.Errorf("status = %v, want failed: %s", ps, want)
	}
	if _, ok := h.arts.Trial(refOf(h.artifact)); ok {
		t.Error("a trial that did not run was recorded")
	}
	if ev := h.eventsOf("artifact_untried"); len(ev) != 1 || ev[0].GetProxyId() != proxyID || ev[0].GetSeverity() != "warning" {
		t.Errorf("artifact_untried events = %v", ev)
	}

	h.trials.set(trial.Result{Ran: true, OK: true})
	h.pass()
	if n := len(h.trials.tried()); n != 2 {
		t.Errorf("tried %d times, want 2", n)
	}
	if ps := h.proxyStatus(proxyID); ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING || ps.GetReason() != "" {
		t.Errorf("status = %v, want serving", ps)
	}
	if n := len(h.eventsOf("artifact_untried")); n != 1 {
		t.Errorf("artifact_untried events = %d, want 1", n)
	}
}

// An artifact whose trial failed is unusable: the proxy fails with the
// reason, the verdict is recorded (no second trial) and reported once.
func TestArtifactUnusableFailsTheProxy(t *testing.T) {
	h := newHarness(t)
	h.trials.set(trial.Result{Ran: true, Reason: "exited with 0, want 1: usage"})
	h.apply(h.baseState(1))
	h.pass()
	h.pass()

	if n := len(h.creates("engine")); n != 0 {
		t.Errorf("created %d engines, want none", n)
	}
	ps := h.proxyStatus(proxyID)
	const want = "artifact unusable: telemt 3.5.13 for amd64: exited with 0, want 1: usage"
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_FAILED || ps.GetReason() != want {
		t.Errorf("status = %v, want failed: %s", ps, want)
	}
	if n := len(h.trials.tried()); n != 1 {
		t.Errorf("tried %d times, want 1 (the record holds the verdict)", n)
	}
	if rec, ok := h.arts.Trial(refOf(h.artifact)); !ok || rec.OK || rec.Reason != "exited with 0, want 1: usage" {
		t.Errorf("record = %+v, %v", rec, ok)
	}
	ev := h.eventsOf("artifact_unusable")
	if len(ev) != 1 || ev[0].GetProxyId() != proxyID || ev[0].GetSeverity() != "error" || ev[0].GetDetails()["version"] != "3.5.13" {
		t.Errorf("artifact_unusable events = %v", ev)
	}
}

// An unusable new version aborts the upgrade and leaves the serving generation
// alone.
func TestArtifactUnusableKeepsTheServingGeneration(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()

	next := h.storeArtifact("telemt", "3.5.14", "telemt")
	st := h.baseState(2)
	st.Proxies[0].EngineVersion = "3.5.14"
	st.Artifacts = append(st.Artifacts, next)
	h.apply(st)
	h.trials.set(trial.Result{Ran: true, Reason: "the binary cannot be started: exec format error"})
	h.pass()

	if c := h.container(engName1); c == nil || c.State != "running" {
		t.Errorf("g1 = %+v, want running", c)
	}
	if h.container(engName2) != nil {
		t.Error("a g2 was created with an unusable binary")
	}
	ps := h.proxyStatus(proxyID)
	if ps.GetPhase() != nodev1.ProxyPhase_PROXY_PHASE_SERVING || !strings.Contains(ps.GetReason(), "artifact unusable: telemt 3.5.14 for amd64: the binary cannot be started") {
		t.Errorf("status = %v", ps)
	}
	if ev := h.eventsOf("artifact_unusable"); len(ev) != 1 {
		t.Errorf("artifact_unusable events = %v", ev)
	}
	if rt := h.runtime(); rt.Instances[proxyID].Generation != 1 || rt.AppliedGeneration != 2 {
		t.Errorf("runtime = %+v", rt.Instances[proxyID])
	}
}

// A provider binary that is unusable fails the egress start the same way.
func TestEgressArtifactUnusable(t *testing.T) {
	h := newHarness(t)
	h.apply(h.providerState(1, uriEgress("nl", vless("vpn.example.com", 443, "a"))))
	// telemt was tried already; the verdict below is xray's.
	if err := h.arts.RecordTrial(refOf(h.artifact), artifacts.TrialRecord{OK: true, At: h.clock.Now(), Image: runnerImage}); err != nil {
		t.Fatal(err)
	}
	h.trials.set(trial.Result{Ran: true, Reason: "exited with 1, want 0"})
	h.pass()

	if h.container("postern-egr-nl-g1") != nil {
		t.Error("an egress instance was started with an unusable binary")
	}
	ev := h.eventsOf("artifact_unusable")
	if len(ev) != 1 || !strings.Contains(ev[0].GetMessage(), "artifact unusable: xray v26.3.27 for amd64: exited with 1, want 0") {
		t.Errorf("artifact_unusable events = %v", ev)
	}
	// The verdict holds: no second trial.
	h.pass()
	if n := len(h.eventsOf("artifact_unusable")); n != 1 {
		t.Errorf("artifact_unusable events = %d, want 1", n)
	}
}

// GC keeps what the desired state names, what a managed container mounts, what
// the runtime record points at and the two most recently used versions of
// every engine and architecture; it removes the rest and stale stage
// directories, at most once an hour.
func TestArtifactGC(t *testing.T) {
	h := newHarness(t)
	now := h.clock.Now()
	h.r.lastGC = now // not in the first pass: the fixtures below are built around it
	// Older telemt versions, used at different times.
	older := map[string]*nodev1.ArtifactRef{}
	for v, age := range map[string]time.Duration{"3.5.12": time.Hour, "3.5.11": 2 * time.Hour, "3.5.10": 3 * time.Hour, "3.5.8": 5 * time.Hour} {
		older[v] = h.storeArtifact("telemt", v, "telemt")
		if err := h.arts.RecordTrial(refOf(older[v]), artifacts.TrialRecord{OK: true, At: now.Add(-age), Image: runnerImage}); err != nil {
			t.Fatal(err)
		}
	}
	// One without a record: its upload time is the binary's.
	older["3.5.9"] = h.storeArtifact("telemt", "3.5.9", "telemt")
	if err := os.Chtimes(h.arts.BinaryPath(refOf(older["3.5.9"])), now.Add(-4*time.Hour), now.Add(-4*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// 3.5.10 is mounted by a managed container that is not an instance.
	if _, err := h.docker.Fake.Create(context.Background(), dockerapi.ContainerSpec{
		Name: "postern-agent", Image: runnerImage, Labels: map[string]string{"postern.managed": "true", "postern.role": "agent"},
		Binds: []string{h.arts.BinaryPath(refOf(older["3.5.10"])) + ":/opt/engine/telemt:ro"},
	}); err != nil {
		t.Fatal(err)
	}
	// Stage directories: a stale one and a fresh one (ages at the time GC
	// runs, an hour from now).
	for name, age := range map[string]time.Duration{".stage-old": 2 * time.Hour, ".stage-new": time.Minute - time.Hour} {
		dir := filepath.Join(h.paths.ArtifactsDir(), name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(dir, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}

	h.apply(h.baseState(1))
	h.pass()
	// 3.5.8 is what the runtime record points at (and nothing mounts it).
	rt := h.runtime()
	rec := rt.Instances[proxyID]
	rec.BinaryPath = h.arts.BinaryPath(refOf(older["3.5.8"]))
	rt.Instances[proxyID] = rec
	if err := h.store.SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	if n := len(h.eventsOf("artifact_removed")); n != 0 {
		t.Fatalf("GC ran within the hour: %d removals", n)
	}

	h.clock.Advance(time.Hour)
	h.pass()

	has := func(v string) bool { return h.arts.Has(refOf(older[v])) }
	for v, want := range map[string]bool{"3.5.12": true, "3.5.11": false, "3.5.10": true, "3.5.9": false, "3.5.8": true} {
		if has(v) != want {
			t.Errorf("telemt %s kept = %v, want %v", v, has(v), want)
		}
	}
	for _, a := range []*nodev1.ArtifactRef{h.artifact, h.xrayArtifact, h.psiphonArtifact} {
		if !h.arts.Has(refOf(a)) {
			t.Errorf("desired artifact %s %s removed", a.Engine, a.Version)
		}
	}
	if _, err := os.Stat(filepath.Join(h.paths.ArtifactsDir(), ".stage-old")); !os.IsNotExist(err) {
		t.Errorf("stale stage dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.paths.ArtifactsDir(), ".stage-new")); err != nil {
		t.Errorf("fresh stage dir: %v", err)
	}
	ev := h.eventsOf("artifact_removed")
	var removed []string
	for _, e := range ev {
		removed = append(removed, e.GetDetails()["engine"]+" "+e.GetDetails()["version"]+" "+e.GetDetails()["arch"])
	}
	slices.Sort(removed)
	if want := []string{"telemt 3.5.11 amd64", "telemt 3.5.9 amd64"}; !slices.Equal(removed, want) {
		t.Errorf("removed %q, want %q", removed, want)
	}

	// Not again within the hour.
	old := h.storeArtifact("telemt", "3.5.1", "telemt")
	if err := os.Chtimes(h.arts.BinaryPath(refOf(old)), now.Add(-9*time.Hour), now.Add(-9*time.Hour)); err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(30 * time.Minute)
	h.pass()
	if !h.arts.Has(refOf(old)) {
		t.Error("GC ran again within the hour")
	}
}

// GC never touches the artifact of the serving engine, which its container
// mounts (the inspect answer's Binds), even when the desired state no longer
// names it and newer versions were used since.
func TestArtifactGCKeepsWhatContainersMount(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	d := h.container(engName1)
	bin := h.arts.BinaryPath(refOf(h.artifact))
	if d == nil || !slices.ContainsFunc(d.Binds, func(b string) bool { return strings.HasPrefix(b, bin+":") }) {
		t.Fatalf("g1 binds = %v, want the binary %s", d.Binds, bin)
	}
	// A state that names only newer versions, which the proxy cannot move to.
	st := h.baseState(2)
	st.Proxies[0].EngineVersion = "3.5.15"
	st.Artifacts = []*nodev1.ArtifactRef{h.storeArtifact("telemt", "3.5.15", "telemt"), h.storeArtifact("telemt", "3.5.16", "telemt"), proto.Clone(h.xrayArtifact).(*nodev1.ArtifactRef), proto.Clone(h.psiphonArtifact).(*nodev1.ArtifactRef)}
	h.apply(st)
	h.trials.set(trial.Result{Reason: "docker is away"})
	h.clock.Advance(2 * time.Hour)
	h.pass()
	if !h.arts.Has(refOf(h.artifact)) {
		t.Error("the mounted artifact of the serving generation was removed")
	}
	if c := h.container(engName1); c == nil || c.State != "running" {
		t.Errorf("g1 = %+v, want running", c)
	}
}

// Trial containers that no running trial owns and that are older than twice
// the trial timeout are orphans: removed by every pass. One in flight, and one
// that is young, survive.
func TestOrphanTrialContainers(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	mk := func(name string) {
		t.Helper()
		if _, err := h.docker.Fake.Create(ctx, dockerapi.ContainerSpec{Name: name, Image: runnerImage, Labels: trial.Labels}); err != nil {
			t.Fatal(err)
		}
		if err := h.docker.Fake.Start(ctx, name); err != nil {
			t.Fatal(err)
		}
	}
	mk("postern-trial-telemt-0a0a0a0a") // in flight
	mk("postern-trial-telemt-0b0b0b0b") // orphan
	h.clock.Advance(2*trial.DefaultTimeout + time.Second)
	mk("postern-trial-xray-0c0c0c0c") // young
	h.trials.inFlight = map[string]bool{"postern-trial-telemt-0a0a0a0a": true}

	h.apply(h.baseState(1))
	h.pass()
	for name, want := range map[string]bool{"postern-trial-telemt-0a0a0a0a": true, "postern-trial-telemt-0b0b0b0b": false, "postern-trial-xray-0c0c0c0c": true} {
		if got := h.container(name) != nil; got != want {
			t.Errorf("%s exists = %v, want %v", name, got, want)
		}
	}
	ev := h.eventsOf("orphan_removed")
	if len(ev) != 1 || ev[0].GetDetails()["container"] != "postern-trial-telemt-0b0b0b0b" {
		t.Errorf("orphan_removed events = %v", ev)
	}
	// The young one ages into an orphan by the next pass.
	h.clock.Advance(2*trial.DefaultTimeout + time.Second)
	h.pass()
	if h.container("postern-trial-xray-0c0c0c0c") != nil {
		t.Error("the aged trial container was not removed")
	}
	if h.container("postern-trial-telemt-0a0a0a0a") == nil {
		t.Error("the in-flight trial container was removed")
	}
}

// recordTrial writes the trial record of a stored artifact.
func (h *harness) recordTrial(a *nodev1.ArtifactRef, ok bool, at time.Time) {
	h.t.Helper()
	if err := h.arts.RecordTrial(refOf(a), artifacts.TrialRecord{OK: ok, At: at, Image: runnerImage}); err != nil {
		h.t.Fatal(err)
	}
}

// A version whose trial failed takes no "newest" slot: a bad upload and a
// good one within the hour do not evict the last known-good older version.
func TestArtifactGCSkipsFailedTrials(t *testing.T) {
	h := newHarness(t)
	now := h.clock.Now()
	h.r.lastGC = now
	h.recordTrial(h.artifact, true, now.Add(-3*time.Hour)) // the serving 3.5.13, desired
	good := h.storeArtifact("telemt", "3.5.14", "telemt")
	h.recordTrial(good, true, now)
	bad := h.storeArtifact("telemt", "3.5.15", "telemt")
	h.recordTrial(bad, false, now)
	older := h.storeArtifact("telemt", "3.5.12", "telemt")
	h.recordTrial(older, true, now.Add(-time.Hour))
	oldest := h.storeArtifact("telemt", "3.5.11", "telemt")
	h.recordTrial(oldest, true, now.Add(-2*time.Hour))

	h.apply(h.baseState(1))
	h.pass()
	h.clock.Advance(time.Hour)
	h.pass()

	for _, c := range []struct {
		a    *nodev1.ArtifactRef
		want bool
	}{{good, true}, {bad, false}, {older, true}, {oldest, false}, {h.artifact, true}} {
		if got := h.arts.Has(refOf(c.a)); got != c.want {
			t.Errorf("telemt %s kept = %v, want %v", c.a.Version, got, c.want)
		}
	}
}

// The binary a proxy ran before its current one is its rollback target: the
// record keeps it, and GC keeps the artifact even when nothing mounts it, the
// desired state no longer names it and two newer versions were used since.
func TestArtifactGCKeepsThePreviousBinary(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	first := h.arts.BinaryPath(refOf(h.artifact))

	next := h.storeArtifact("telemt", "3.5.14", "telemt")
	h.recordTrial(next, true, h.clock.Now())
	st := h.baseState(2)
	st.Proxies[0].EngineVersion = "3.5.14"
	st.Artifacts = append(st.Artifacts, next)
	h.apply(st)
	h.pass()
	h.pass() // g1 has no connections: gone
	rec := h.runtime().Instances[proxyID]
	if rec.Generation != 2 || rec.BinaryPath != h.arts.BinaryPath(refOf(next)) || rec.PreviousBinaryPath != first {
		t.Fatalf("record = %+v, want g2 on 3.5.14 with 3.5.13 as the previous binary", rec)
	}
	if h.container(engName1) != nil {
		t.Fatal("g1 still exists")
	}

	// Another generation on the same binary keeps the previous one.
	st = h.baseState(3)
	st.Proxies[0].EngineVersion = "3.5.14"
	st.Proxies[0].Secret = secret2
	st.Artifacts = append(st.Artifacts, next)
	h.apply(st)
	h.pass()
	if rec := h.runtime().Instances[proxyID]; rec.Generation != 3 || rec.PreviousBinaryPath != first {
		t.Fatalf("record = %+v, want g3 with 3.5.13 still the previous binary", rec)
	}

	// 3.5.13 is no longer desired, older than two newer versions, and nothing
	// mounts it.
	now := h.clock.Now()
	h.recordTrial(h.artifact, true, now.Add(-5*time.Hour))
	st = h.baseState(4)
	st.Proxies[0].EngineVersion = "3.5.14"
	st.Proxies[0].Secret = secret2
	st.Artifacts = []*nodev1.ArtifactRef{next, proto.Clone(h.xrayArtifact).(*nodev1.ArtifactRef), proto.Clone(h.psiphonArtifact).(*nodev1.ArtifactRef)}
	for _, v := range []string{"3.5.15", "3.5.16"} {
		h.recordTrial(h.storeArtifact("telemt", v, "telemt"), true, now)
	}
	h.apply(st)
	h.clock.Advance(2 * time.Hour)
	h.pass()
	if !h.arts.Has(refOf(h.artifact)) {
		t.Error("the previous binary of the serving proxy was removed")
	}
	if h.container(engName1) != nil || h.container(engName2) != nil {
		t.Error("an old generation still exists")
	}
}

// previousBinary names the rollback target: the old binary when the new one
// differs, else what it was.
func TestPreviousBinary(t *testing.T) {
	for _, c := range []struct{ previous, old, next, want string }{
		{"", "", "/a", ""},
		{"", "/a", "/b", "/a"},
		{"/a", "/b", "/b", "/a"},
		{"/a", "/b", "/c", "/b"},
		{"/a", "/b", "", "/b"},
		{"/a", "", "/b", "/a"},
	} {
		if got := previousBinary(c.previous, c.old, c.next); got != c.want {
			t.Errorf("previousBinary(%q, %q, %q) = %q, want %q", c.previous, c.old, c.next, got, c.want)
		}
	}
}

// A collection that Docker fails is tried again by the next pass, not an
// hour later.
func TestArtifactGCRetriesAfterDockerFailure(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()                                         // the first pass collects (nothing to remove yet)
	for _, v := range []string{"3.5.14", "3.5.15"} { // the two newest
		h.recordTrial(h.storeArtifact("telemt", v, "telemt"), true, h.clock.Now())
	}
	old := h.storeArtifact("telemt", "3.5.1", "telemt")
	if err := os.Chtimes(h.arts.BinaryPath(refOf(old)), h.clock.Now().Add(-9*time.Hour), h.clock.Now().Add(-9*time.Hour)); err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(time.Hour)
	h.docker.SetError("Inspect", errors.New("docker hiccup"))
	h.pass()
	h.docker.SetError("Inspect", nil)
	if !h.arts.Has(refOf(old)) {
		t.Fatal("an artifact was removed although the mounts were not known")
	}
	h.pass()
	if h.arts.Has(refOf(old)) {
		t.Error("the next pass did not collect after the failed one")
	}
}
