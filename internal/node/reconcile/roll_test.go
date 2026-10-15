package reconcile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
)

// requestRoll asks for an edge roll as install.sh --roll-edge does.
func (h *harness) requestRoll() {
	h.t.Helper()
	path := h.paths.EdgeRollPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("1790000000\n"), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// indexOf is the position of the first entry of trace that is what, or -1.
func indexOf(trace []string, what string) int {
	return slices.Index(trace, what)
}

// The operator's roll (Ruling 44, spec 7): the next pass writes the config of
// generation N+1, creates and starts it beside N, waits until N+1 answers, and
// only then lets N go the way of an old generation: restart policy "no", Drain,
// removal once it has exited. N is never stopped or drained before N+1 answers,
// so the listeners are never without an edge. The request is taken once.
func TestOperatorRollStartsANewEdgeBesideTheRunningOne(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	if c := h.container("postern-edge-g1"); c == nil || c.State != "running" {
		t.Fatalf("g1 = %+v, want running", c)
	}
	sets1 := h.fakeEdge(1).setCount()

	// The config of g2 is on disk, and routes the proxy, before g2 exists.
	h.docker.mu.Lock()
	h.docker.onCreate = func(spec dockerapi.ContainerSpec) {
		if spec.Name != "postern-edge-g2" {
			return
		}
		data, err := os.ReadFile(h.paths.EdgeConfigPath(2))
		if err != nil {
			t.Errorf("config-g2.json is not there when g2 is created: %v", err)
			return
		}
		if rec := h.runtime().Instances[proxyID]; !bytes.Contains(data, []byte(addr(rec.ListenPort))) {
			t.Errorf("config-g2.json does not route the proxy:\n%s", data)
		}
	}
	h.docker.mu.Unlock()

	h.requestRoll()
	h.takeTrace()
	h.pass()
	trace := h.takeTrace()

	if c := h.container("postern-edge-g2"); c == nil || c.State != "running" {
		t.Fatalf("g2 = %+v, want running", c)
	}
	if spec, ok := h.docker.Spec("postern-edge-g2"); !ok || spec.Binds[0] != h.nodeBinary+":/opt/postern/bin/postern-node:ro" {
		t.Errorf("g2 runs %v, want the agent's binary %s", spec.Binds, h.nodeBinary)
	}
	if rt := h.runtime(); rt.EdgeGeneration != 2 {
		t.Errorf("edge generation = %d, want 2", rt.EdgeGeneration)
	}
	if _, err := os.Stat(h.paths.EdgeRollPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the roll request is still there: %v", err)
	}
	g1 := h.container("postern-edge-g1")
	if g1 == nil || g1.State != "running" || g1.RestartPolicy != "no" {
		t.Errorf("g1 = %+v, want it running out its drain with restart policy no", g1)
	}
	if got := h.fakeEdge(1).drainCalls(); !slices.Equal(got, []uint32{3600}) {
		t.Errorf("Drain calls on g1 = %v, want [3600]", got)
	}
	if h.fakeEdge(2).setCount() == 0 {
		t.Error("g2 got no config")
	}
	if got := h.fakeEdge(1).setCount(); got != sets1 {
		t.Errorf("g1 got %d configs after the roll began, want none", got-sets1)
	}

	// The order: g2 made, started and answering, then g1 let go of; nothing
	// stops or removes g1 while it drains.
	order := []string{"create postern-edge-g2", "start postern-edge-g2", "health g2", "restart policy postern-edge-g1 no", "drain g1"}
	last := -1
	for _, step := range order {
		i := indexOf(trace, step)
		if i < 0 || i < last {
			t.Fatalf("trace = %q, want %q in this order", trace, order)
		}
		last = i
	}
	for _, step := range trace {
		if step == "stop postern-edge-g1" || step == "remove postern-edge-g1" {
			t.Errorf("trace = %q: g1 is stopped or removed while it drains", trace)
		}
	}
	if kinds := h.eventKinds(); !slices.Contains(kinds, "edge_roll") {
		t.Errorf("events = %v, want an edge_roll", kinds)
	}

	// The request was taken: the next pass rolls nothing.
	h.pass()
	if n := len(h.creates("edge")); n != 2 {
		t.Errorf("created %d edges, want 2: a request rolls once", n)
	}
	// g1 exits at the end of its drain, and goes.
	if err := h.docker.Exit("postern-edge-g1", 0); err != nil {
		t.Fatal(err)
	}
	h.pass()
	if c := h.container("postern-edge-g1"); c != nil {
		t.Errorf("g1 = %+v, want removed", c)
	}
	if _, err := os.Stat(h.paths.EdgeConfigPath(1)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config-g1.json still there: %v", err)
	}
	if c := h.container("postern-edge-g2"); c == nil || c.State != "running" {
		t.Errorf("g2 = %+v, want running", c)
	}
}

// A roll whose new generation does not come up leaves the edge that runs as it
// was, and the node goes on with it: the half-made generation is removed, the
// old one keeps serving and taking its configuration, and the failure is an
// event. Its number is not used again.
func TestFailedRollKeepsTheRunningEdge(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	h.r.edgeStartTimeout = 50 * time.Millisecond
	h.fakeEdge(2).setHealthErr(errors.New("dial unix: no such file or directory"))
	sets1 := h.fakeEdge(1).setCount()

	h.requestRoll()
	h.apply(h.baseState(2))
	h.pass() // the pass goes on with g1

	if c := h.container("postern-edge-g2"); c != nil {
		t.Errorf("g2 = %+v, want it removed", c)
	}
	for _, f := range []string{h.paths.EdgeConfigPath(2), h.paths.EdgeSocketPath(2)} {
		if _, err := os.Stat(f); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s of the failed generation is still there: %v", filepath.Base(f), err)
		}
	}
	g1 := h.container("postern-edge-g1")
	if g1 == nil || g1.State != "running" || g1.RestartPolicy != "unless-stopped" {
		t.Errorf("g1 = %+v, want it running as before", g1)
	}
	if got := h.fakeEdge(1).drainCalls(); len(got) != 0 {
		t.Errorf("g1 was asked to drain: %v", got)
	}
	if h.fakeEdge(1).setCount() == sets1 {
		t.Error("g1 got no config in the pass of the failed roll")
	}
	rt := h.runtime()
	if rt.EdgeGeneration != 1 || rt.AppliedGeneration != 2 {
		t.Errorf("edge generation %d, applied %d; want 1 and 2", rt.EdgeGeneration, rt.AppliedGeneration)
	}
	ev := h.eventsOf("edge_roll_failed")
	if len(ev) != 1 || ev[0].GetSeverity() != "error" || !strings.Contains(ev[0].GetMessage(), "does not answer") {
		t.Errorf("edge_roll_failed events = %v, want one error that says why", ev)
	}
	if _, err := os.Stat(h.paths.EdgeRollPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the roll request is still there: %v", err)
	}

	// Another roll makes generation 3: 2 was used.
	h.requestRoll()
	h.pass()
	if c := h.container("postern-edge-g3"); c == nil || c.State != "running" {
		t.Errorf("g3 = %+v, want running", c)
	}
	if rt := h.runtime(); rt.EdgeGeneration != 3 {
		t.Errorf("edge generation = %d, want 3", rt.EdgeGeneration)
	}
}

// A request that cannot be taken (deleted) is not acted on: a roll on every
// pass would be worse than none. The problem is logged, and the pass goes on.
func TestRollRequestThatCannotBeTakenIsLeftAlone(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()
	// A directory with something in it cannot be removed as a file.
	if err := os.MkdirAll(filepath.Join(h.paths.EdgeRollPath(), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	h.pass()
	h.pass()
	if n := len(h.creates("edge")); n != 1 {
		t.Errorf("created %d edges, want 1", n)
	}
}

// After an update of the agent the edge runs the old binary until it is rolled.
// The agent says so, once per generation, and rolls nothing by itself (Ruling
// 38): the data plane changes when the operator says.
func TestOutdatedEdgeIsReportedNotRolled(t *testing.T) {
	h := newHarness(t)
	h.r.Version = "v0.1.1"
	h.fakeEdge(1).setVersion("v0.1.0")
	h.apply(h.baseState(1))
	h.pass()
	h.pass()

	ev := h.eventsOf("edge_outdated")
	if len(ev) != 1 {
		t.Fatalf("edge_outdated events = %v, want one", ev)
	}
	if ev[0].GetSeverity() != "warning" || !strings.Contains(ev[0].GetMessage(), "v0.1.0") || !strings.Contains(ev[0].GetMessage(), "v0.1.1") ||
		!strings.Contains(ev[0].GetMessage(), "--roll-edge") {
		t.Errorf("event = %v, want a warning that names both versions and the roll", ev[0])
	}
	if d := ev[0].GetDetails(); d["edge_version"] != "v0.1.0" || d["agent_version"] != "v0.1.1" || d["generation"] != "1" {
		t.Errorf("details = %v", d)
	}
	if n := len(h.creates("edge")); n != 1 {
		t.Errorf("created %d edges, want 1: no roll without the operator", n)
	}

	// Rolled to the agent's binary: nothing more to say.
	h.fakeEdge(2).setVersion("v0.1.1")
	h.requestRoll()
	h.pass()
	h.pass()
	if n := len(h.eventsOf("edge_outdated")); n != 1 {
		t.Errorf("edge_outdated events = %d after the roll, want still 1", n)
	}

	// An edge from before the version field says nothing, and is older.
	h2 := newHarness(t)
	h2.r.Version = "v0.1.1"
	h2.apply(h2.baseState(1))
	h2.pass()
	ev = h2.eventsOf("edge_outdated")
	if len(ev) != 1 || !strings.Contains(ev[0].GetMessage(), "does not report") {
		t.Errorf("edge_outdated events = %v, want one for an edge that does not say its version", ev)
	}
}

// netRawState is a desired state whose default chain goes out through wg0, so
// that the edge needs CAP_NET_RAW.
func (h *harness) netRawState(gen uint64) *nodev1.NodeState {
	st := h.baseState(gen)
	st.Egresses[0].ParamsJson = `{"interface":"wg0"}`
	return st
}

// A roll makes the generation that the desired state needs, as any new one: it
// holds CAP_NET_RAW while a member is tied to an interface, and the limit of
// open files. The next pass finds it as it should be and makes no other.
func TestRolledEdgeHasTheCapabilitiesAndTheLimitOfOpenFiles(t *testing.T) {
	h := newHarness(t)
	h.apply(h.netRawState(1))
	h.pass()

	h.requestRoll()
	h.pass()
	edges := h.creates("edge")
	if len(edges) != 2 || edges[1].Name != "postern-edge-g2" {
		t.Fatalf("edges created: %+v, want g1 and the rolled g2", edges)
	}
	if !slices.Equal(edges[1].CapAdd, []string{"NET_BIND_SERVICE", "NET_RAW"}) {
		t.Errorf("g2 adds the capabilities %v, want NET_BIND_SERVICE and NET_RAW", edges[1].CapAdd)
	}
	if want := []dockerapi.Ulimit{{Name: "nofile", Soft: 1048576, Hard: 1048576}}; !slices.Equal(edges[1].Ulimits, want) {
		t.Errorf("g2 has the ulimits %+v, want %+v", edges[1].Ulimits, want)
	}
	if rt := h.runtime(); rt.EdgeGeneration != 2 || rt.EdgeNetRaw != 2 {
		t.Errorf("edge generation %d, the one with NET_RAW %d; want 2 and 2", rt.EdgeGeneration, rt.EdgeNetRaw)
	}

	h.pass()
	if n := len(h.creates("edge")); n != 2 {
		t.Errorf("created %d edges, want still 2", n)
	}
}

// A roll that fails while the edge that runs holds CAP_NET_RAW leaves that edge
// the one with the capability: the passes after it make no generation for it.
func TestFailedRollKeepsTheCapabilitiesOfTheRunningEdge(t *testing.T) {
	h := newHarness(t)
	h.apply(h.netRawState(1))
	h.pass()
	h.r.edgeStartTimeout = 50 * time.Millisecond
	h.fakeEdge(2).setHealthErr(errors.New("dial unix: no such file or directory"))

	h.requestRoll()
	h.pass() // g2 does not come up and is removed; g1 goes on
	if c := h.container("postern-edge-g2"); c != nil {
		t.Fatalf("g2 = %+v, want it removed", c)
	}
	if rt := h.runtime(); rt.EdgeGeneration != 1 || rt.EdgeNetRaw != 1 {
		t.Errorf("edge generation %d, the one with NET_RAW %d; want 1 and 1", rt.EdgeGeneration, rt.EdgeNetRaw)
	}

	h.pass()
	if n := len(h.creates("edge")); n != 2 {
		t.Errorf("created %d edges, want 2 (g1 and the failed g2): g1 has the capability", n)
	}
	if g1 := h.container("postern-edge-g1"); g1 == nil || g1.State != "running" || g1.RestartPolicy != "unless-stopped" {
		t.Errorf("g1 = %+v, want it running as before", g1)
	}
}

// A roll asked for in the pass in which the edge comes to need other
// capabilities is the one new generation that those make.
func TestRollWithACapabilityChangeMakesOneGeneration(t *testing.T) {
	h := newHarness(t)
	h.apply(h.baseState(1))
	h.pass()

	h.apply(h.netRawState(2))
	h.requestRoll()
	h.pass()
	h.pass()
	edges := h.creates("edge")
	if len(edges) != 2 || edges[1].Name != "postern-edge-g2" || !slices.Contains(edges[1].CapAdd, "NET_RAW") {
		t.Fatalf("edges created: %+v, want one new generation, g2, with NET_RAW", edges)
	}
	if _, err := os.Stat(h.paths.EdgeRollPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the roll request is still there: %v", err)
	}
}

// A rolled generation starts with the DNS forwarder in the config file it comes
// up from, and the engines, which follow the forwarder, are left alone.
func TestRollKeepsTheForwarderOfTheEngines(t *testing.T) {
	h := newHarness(t)
	h.fakeEdge(1).setDNS(true)
	h.fakeEdge(2).setDNS(true)
	h.apply(h.baseState(1))
	h.pass()
	if g := h.generation(); g != 1 || !h.mounted() {
		t.Fatalf("g%d (mount %v), want g1 with the mount", g, h.mounted())
	}

	h.requestRoll()
	h.pass()
	h.passAfter(time.Minute)
	if c := h.container("postern-edge-g2"); c == nil || c.State != "running" {
		t.Fatalf("g2 = %+v, want running", c)
	}
	data, err := os.ReadFile(h.paths.EdgeConfigPath(2))
	if err != nil {
		t.Fatal(err)
	}
	var file edgev1.EdgeConfig
	if err := protojson.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if !file.GetDns().GetEnabled() {
		t.Errorf("config-g2.json has dns %v, want the forwarder enabled", file.GetDns())
	}
	if g := h.generation(); g != 1 || !h.mounted() {
		t.Errorf("after the roll: g%d (mount %v), want g1 with the mount", g, h.mounted())
	}
}
