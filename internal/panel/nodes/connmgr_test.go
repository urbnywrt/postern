package nodes

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
)

func TestManagerPushesStateWhenTheNodeIsBehind(t *testing.T) {
	p := newTestPanel(t)
	tr := &trace{}
	f := newFakeNode(t, tr)
	n := p.addNode("edge-1", f)
	p.bump(n.ID, 2)

	b := &fakeBuilder{}
	e := &fakeEnsurer{trace: tr}
	m := p.newManager()
	m.SetStateBuilder(b)
	m.SetArtifactEnsurer(e)
	m.Start(context.Background())

	waitFor(t, "the node to accept generation 2", func() bool { return f.acceptedGeneration() == 2 })
	if got := f.applyCalls(); !slices.Equal(got, []uint64{2}) {
		t.Errorf("ApplyState generations = %v, want [2]", got)
	}
	if got := b.generations(); !slices.Equal(got, []uint64{2}) {
		t.Errorf("Build generations = %v, want [2]", got)
	}
	if got := tr.get(); !slices.Equal(got, []string{"ensure:2", "apply:2"}) {
		t.Errorf("steps = %v, want the artifacts ensured before the state is applied", got)
	}
	if got := e.agentVersions(); !slices.Equal(got, []string{"1.2.3"}) {
		t.Errorf("the ensurer saw agent versions %v, want the node's info", got)
	}

	p.waitStatus(n.ID, store.NodeStatusOnline)
	got := p.node(n.ID)
	if got.AgentVersion != "1.2.3" || got.EdgeVersion != "1.2.3" || got.Arch != "amd64" ||
		got.HostInfo.OS != "Debian GNU/Linux 13 (trixie)" ||
		!slices.Equal(got.PublicIPs, []string{"203.0.113.10", "2001:db8::10"}) || got.LastSeenAt == nil {
		t.Errorf("node after GetInfo = %+v", got)
	}
	if got.DesiredGeneration != 2 {
		t.Errorf("desired generation = %d, want it untouched at 2", got.DesiredGeneration)
	}
	if kinds := p.eventKinds(n.ID); !slices.Contains(kinds, "node.online") {
		t.Errorf("events = %v, want node.online", kinds)
	}

	logs := p.logs.String()
	for _, secret := range []string{testProxySecret, "PRIVATE KEY"} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log holds a secret: %q", secret)
		}
	}
}

// An engine that cannot be provided does not hold the state back: the node takes
// it, reports the proxies whose engine it lacks as failed, and serves the rest.
func TestManagerPushesTheStateWhenItsArtifactsCannotBeProvided(t *testing.T) {
	p := newTestPanel(t)
	tr := &trace{}
	f := newFakeNode(t, tr)
	n := p.addNode("edge-1", f)
	p.bump(n.ID, 1)

	e := &fakeEnsurer{trace: tr, err: errors.New("proxies: download telemt-x86_64-linux-musl.tar.gz: 502 Bad Gateway")}
	m := p.newManager()
	m.SetStateBuilder(&fakeBuilder{})
	m.SetArtifactEnsurer(e)
	m.Start(context.Background())

	waitFor(t, "the node to accept generation 1", func() bool { return f.acceptedGeneration() == 1 })
	if got := tr.get(); len(got) < 2 || got[0] != "ensure:1" || got[1] != "apply:1" {
		t.Errorf("steps = %v, want the artifacts tried and then the state applied", got)
	}
	if logs := p.logs.String(); !strings.Contains(logs, "502 Bad Gateway") {
		t.Error("the log does not say why the artifacts could not be provided")
	}
}

// The artifacts of the state are tried again at every resync, also when the
// node has the state, with what the node says it has then: an engine that
// could not be provided gets there in the end.
func TestManagerProvidesTheArtifactsAgainAtEveryResync(t *testing.T) {
	p := newTestPanel(t)
	tr := &trace{}
	f := newFakeNode(t, tr)
	n := p.addNode("edge-1", f)
	p.bump(n.ID, 1)

	e := &fakeEnsurer{trace: tr, err: errors.New("proxies: download telemt-x86_64-linux-musl.tar.gz: 502 Bad Gateway")}
	m := p.newManager()
	m.cfg.resyncEvery = 20 * time.Millisecond
	m.SetStateBuilder(&fakeBuilder{})
	m.SetArtifactEnsurer(e)
	m.Start(context.Background())
	waitFor(t, "the node to accept generation 1", func() bool { return f.acceptedGeneration() == 1 })

	f.setInfo(&nodev1.GetInfoResponse{AgentVersion: "1.2.4", Arch: "amd64"})
	e.setErr(nil)
	waitFor(t, "the artifacts to be tried again with what the node says now", func() bool {
		return slices.Contains(e.agentVersions(), "1.2.4")
	})
	if got := countOf(tr.get(), "ensure:1"); got < 2 {
		t.Errorf("the artifacts of generation 1 were tried %d times, want them tried again", got)
	}
	if got := f.applyCalls(); !slices.Equal(got, []uint64{1}) {
		t.Errorf("ApplyState generations = %v, want [1]: a state that the node has is not sent again", got)
	}
}

// What the node has already accepted is not sent again: the agent would turn
// it down as stale.
func TestManagerDoesNotPushWhatTheNodeHas(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	p.bump(n.ID, 2)
	f.setGenerations(2, 1) // accepted 2, still applying it

	b := &fakeBuilder{}
	m := p.newManager()
	m.SetStateBuilder(b)
	m.Start(context.Background())

	// A record is handled after the first look at the generations, so once it
	// is through, the manager has decided.
	seq := f.emit(eventRecord("probe"))
	waitFor(t, "the record to be handled", func() bool { return p.node(n.ID).WatchCursor == seq })
	if got := f.applyCalls(); len(got) != 0 {
		t.Errorf("ApplyState generations = %v, want none", got)
	}
	if got := b.generations(); len(got) != 0 {
		t.Errorf("Build generations = %v, want none", got)
	}
}

func TestManagerRetriesARejectedState(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	p.bump(n.ID, 1)
	f.setRejectNext(2)

	b := &fakeBuilder{}
	m := p.newManager()
	m.SetStateBuilder(b)
	m.Start(context.Background())

	waitFor(t, "the node to accept generation 1", func() bool { return f.acceptedGeneration() == 1 })
	if got := f.applyCalls(); !slices.Equal(got, []uint64{1, 1, 1}) {
		t.Errorf("ApplyState generations = %v, want two rejections and an acceptance", got)
	}
	if got := b.generations(); !slices.Equal(got, []uint64{1, 1, 1}) {
		t.Errorf("Build generations = %v, want a fresh state for every attempt", got)
	}
	kinds := p.eventKinds(n.ID)
	if c := countOf(kinds, "node.state_rejected"); c != 1 {
		t.Errorf("events = %v, want one node.state_rejected for the same generation and reason", kinds)
	}
	if logs := p.logs.String(); !strings.Contains(logs, "port 70000 is out of range") {
		t.Error("the log does not say why the state was rejected")
	}
	if got := p.node(n.ID).Status; got != store.NodeStatusOnline {
		t.Errorf("status = %q, want online: a rejected state is not a broken connection", got)
	}
}

func TestManagerRetriesWhenTheStateCannotBeBuilt(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	p.bump(n.ID, 1)

	b := &fakeBuilder{err: errors.New("the database is locked")}
	m := p.newManager()
	m.SetStateBuilder(b)
	m.Start(context.Background())

	waitFor(t, "Build to be tried again", func() bool { return len(b.generations()) >= 3 })
	b.setErr(nil)
	waitFor(t, "the node to accept generation 1", func() bool { return f.acceptedGeneration() == 1 })
	if got := f.applyCalls(); !slices.Equal(got, []uint64{1}) {
		t.Errorf("ApplyState generations = %v, want [1]", got)
	}
}

// Why the node refused the state of the panel is kept with the node until the
// node has the desired generation: the panel shows it.
func TestManagerKeepsWhyTheNodeRefusedItsState(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	p.bump(n.ID, 1)
	f.setRejectNext(1 << 30)

	m := p.newManager()
	m.SetStateBuilder(&fakeBuilder{})
	m.Start(context.Background())
	waitFor(t, "the reason of the rejection to be kept", func() bool {
		return p.node(n.ID).StateRejection == "listener l1: port 70000 is out of range"
	})

	f.setRejectNext(0)
	waitFor(t, "the node to accept generation 1", func() bool { return f.acceptedGeneration() == 1 })
	waitFor(t, "the reason to go", func() bool { return p.node(n.ID).StateRejection == "" })
}

// A reason that is kept from before (the panel restarted, or the answer of the
// node to the push that it took was lost) goes as soon as the node is seen with
// the desired generation.
func TestManagerForgetsARejectionOnceTheNodeHasItsState(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	p.bump(n.ID, 2)
	f.setGenerations(2, 2)
	p.modify(n.ID, func(s *store.Node) { s.StateRejection = "listener l1: port 70000 is out of range" })

	m := p.newManager()
	m.SetStateBuilder(&fakeBuilder{})
	m.Start(context.Background())
	waitFor(t, "the old reason to go", func() bool { return p.node(n.ID).StateRejection == "" })
	if got := f.applyCalls(); len(got) != 0 {
		t.Errorf("ApplyState generations = %v, want none", got)
	}
}

// What the node says about its last pass is kept with the node, within bounds,
// and goes with the report of a pass that went through.
func TestManagerKeepsWhyTheLastPassFailed(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	m := p.newManager()
	m.Start(context.Background())
	p.waitStatus(n.ID, store.NodeStatusOnline)

	report := func(applied uint64, lastError string) uint64 {
		t.Helper()
		seq := f.emit(&nodev1.WatchResponse{Payload: &nodev1.WatchResponse_State{State: &nodev1.StateReport{
			AppliedGeneration: applied, LastError: lastError,
		}}})
		waitFor(t, "the report to be handled", func() bool { return p.node(n.ID).WatchCursor == seq })
		return seq
	}

	const why = "edge g1 does not answer: dial unix /opt/postern/data/run/edge-g1.sock: connect: no such file or directory"
	report(1, why)
	if got := p.node(n.ID).LastError; got != why {
		t.Errorf("last error = %q, want %q", got, why)
	}

	report(1, strings.Repeat(string(rune(0x044f)), 700)) // 1400 bytes
	if got := p.node(n.ID).LastError; len(got) > maxReasonLen || !utf8.ValidString(got) || got == "" {
		t.Errorf("last error of %d bytes, valid UTF-8 %v; want at most %d bytes, valid", len(got), utf8.ValidString(got), maxReasonLen)
	}

	report(2, "")
	if got := p.node(n.ID); got.LastError != "" || got.AppliedGeneration != 2 {
		t.Errorf("after a pass that went through: last error %q, applied %d; want none and 2", got.LastError, got.AppliedGeneration)
	}
}

func TestManagerPushesOnNotify(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)

	m := p.newManager()
	m.SetStateBuilder(&fakeBuilder{})
	m.Start(context.Background())
	p.waitStatus(n.ID, store.NodeStatusOnline)

	p.bump(n.ID, 1)
	m.Notify(n.ID)
	waitFor(t, "generation 1", func() bool { return f.acceptedGeneration() == 1 })

	p.bump(n.ID, 1)
	m.Notify(n.ID)
	waitFor(t, "generation 2", func() bool { return f.acceptedGeneration() == 2 })

	if got := f.applyCalls(); !slices.Equal(got, []uint64{1, 2}) {
		t.Errorf("ApplyState generations = %v, want [1 2]", got)
	}
}

// A node that holds a newer generation than the panel (its state came from a
// restored backup of the panel, or from an earlier install) would refuse
// every state as stale. The panel moves its own counter past the node's.
func TestManagerMovesItsGenerationPastTheNodes(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	p.bump(n.ID, 2)
	f.setGenerations(7, 7)

	b := &fakeBuilder{}
	m := p.newManager()
	m.SetStateBuilder(b)
	m.Start(context.Background())

	waitFor(t, "the node to accept generation 8", func() bool { return f.acceptedGeneration() == 8 })
	if got := p.node(n.ID).DesiredGeneration; got != 8 {
		t.Errorf("desired generation = %d, want 8", got)
	}
	if got := b.generations(); !slices.Equal(got, []uint64{8}) {
		t.Errorf("Build generations = %v, want [8]", got)
	}
}

// A node far ahead of the panel is wrong, or hostile: the panel does not race
// its counter after it.
func TestManagerDoesNotChaseAGenerationFarAhead(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	p.bump(n.ID, 1)
	f.setGenerations(1<<40, 0)

	b := &fakeBuilder{}
	m := p.newManager()
	m.SetStateBuilder(b)
	m.Start(context.Background())

	p.waitStatus(n.ID, store.NodeStatusError)
	if got := p.node(n.ID).DesiredGeneration; got != 1 {
		t.Errorf("desired generation = %d, want it left at 1", got)
	}
	if got := f.applyCalls(); len(got) != 0 {
		t.Errorf("ApplyState generations = %v, want none", got)
	}
	if got := b.generations(); len(got) != 0 {
		t.Errorf("Build generations = %v, want none", got)
	}
	waitFor(t, "the error event", func() bool { return slices.Contains(p.eventKinds(n.ID), "node.error") })
}

// What a node says about itself is stored within bounds: it is shown in the
// panel, and a node is not trusted to be sensible.
func TestManagerStoresWhatTheNodeSaysWithinBounds(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	caps := []string{"faketls", strings.Repeat("c", 1000)}
	for i := range 100 {
		caps = append(caps, fmt.Sprintf("extra-%d", i))
	}
	owners := []*nodev1.PortOwner{
		{Bind: "0.0.0.0", Port: 80, Owner: "nginx (pid 812)"},
		{Bind: "not an address", Port: 81, Owner: "x"},
		{Bind: "::", Port: 0, Owner: "a port that is none"},
		{Bind: "::", Port: 70000, Owner: "a port out of range"},
		{Bind: "2001:db8::1", Port: 8443, Owner: strings.Repeat("o", 1000)},
	}
	for port := range uint32(1000) {
		owners = append(owners, &nodev1.PortOwner{Bind: "127.0.0.1", Port: 10000 + port, Owner: "busy (pid 1)"})
	}
	f.setInfo(&nodev1.GetInfoResponse{
		AgentVersion: strings.Repeat("v", 1000),
		EdgeVersion:  "1.2.3",
		Arch:         "arm64",
		Os:           strings.Repeat(string(rune(0x044f)), 300), // a Cyrillic letter: two bytes each
		PublicIps:    []string{"203.0.113.10", "not an address", "fe80::1%eth0", " 2001:db8::1 ", "198.51.100.300"},
		Capabilities: caps,
		PortOwners:   owners,
	})

	m := p.newManager()
	m.Start(context.Background())
	p.waitStatus(n.ID, store.NodeStatusOnline)

	got := p.node(n.ID)
	if len(got.AgentVersion) != 256 {
		t.Errorf("agent version of %d bytes stored, want it cut to 256", len(got.AgentVersion))
	}
	if len(got.HostInfo.OS) != 256 || !utf8.ValidString(got.HostInfo.OS) {
		t.Errorf("OS of %d bytes stored, valid UTF-8 %v; want 256 bytes, valid", len(got.HostInfo.OS), utf8.ValidString(got.HostInfo.OS))
	}
	if want := []string{"203.0.113.10", "2001:db8::1"}; !slices.Equal(got.PublicIPs, want) {
		t.Errorf("public IPs = %q, want %q", got.PublicIPs, want)
	}
	c := got.HostInfo.Capabilities
	if len(c) != maxCapabilities || c[0] != "faketls" || len(c[1]) != maxCapabilityLen {
		t.Errorf("capabilities stored = %d of them, %.80q; want %d, the long one cut to %d bytes", len(c), c, maxCapabilities, maxCapabilityLen)
	}
	po := got.HostInfo.PortOwners
	if len(po) != maxPortOwners {
		t.Fatalf("%d port owners stored, want %d", len(po), maxPortOwners)
	}
	if po[0] != (store.PortOwner{Bind: "0.0.0.0", Port: 80, Owner: "nginx (pid 812)"}) ||
		po[1].Bind != "2001:db8::1" || po[1].Port != 8443 || len(po[1].Owner) != maxOwnerLen {
		t.Errorf("port owners stored = %+v ..., want the ones with an address and a port, the long owner cut to %d bytes", po[:2], maxOwnerLen)
	}
}

// What a node says about itself is stored at every GetInfo, not only when the
// panel connects: the version of the edge changes when the operator rolls the
// edge (Ruling 38), and the capabilities when the node is updated (Ruling 43).
func TestManagerRefreshesWhatTheNodeSaysAtEveryResync(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	f.setInfo(&nodev1.GetInfoResponse{AgentVersion: "1.2.3", Arch: "amd64", Os: "Debian GNU/Linux 13 (trixie)", Capabilities: []string{"faketls"}})

	m := p.newManager()
	m.cfg.resyncEvery = 20 * time.Millisecond
	m.Start(context.Background())
	p.waitStatus(n.ID, store.NodeStatusOnline)
	if got := p.node(n.ID); got.EdgeVersion != "" || !slices.Equal(got.HostInfo.Capabilities, []string{"faketls"}) {
		t.Fatalf("after connecting: edge version %q, capabilities %q", got.EdgeVersion, got.HostInfo.Capabilities)
	}

	// The node is updated, and its edge rolled.
	caps := []string{"edge-roll", "edge-version", "faketls", "last-error"}
	f.setInfo(&nodev1.GetInfoResponse{
		AgentVersion: "1.2.4", EdgeVersion: "1.2.4", Arch: "amd64", Os: "Debian GNU/Linux 13 (trixie)",
		PublicIps: []string{"203.0.113.10"}, Capabilities: caps,
		PortOwners: []*nodev1.PortOwner{{Bind: "0.0.0.0", Port: 443, Owner: "postern-edge-g2"}},
	})
	waitFor(t, "the new facts of the node", func() bool {
		got := p.node(n.ID)
		return got.AgentVersion == "1.2.4" && got.EdgeVersion == "1.2.4" && slices.Equal(got.HostInfo.Capabilities, caps) &&
			slices.Equal(got.PublicIPs, []string{"203.0.113.10"}) &&
			slices.Equal(got.HostInfo.PortOwners, []store.PortOwner{{Bind: "0.0.0.0", Port: 443, Owner: "postern-edge-g2"}})
	})
	if got := f.watchCursors(); len(got) != 1 {
		t.Errorf("Watch was opened %d times, want once: the facts came without a new connection", len(got))
	}
}

func TestClip(t *testing.T) {
	ya := string(rune(0x044f)) // two bytes
	bad := string(utf8.RuneError)
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 10, "abc"},
		{"abcdef", 3, "abc"},
		{"", 3, ""},
		{ya + ya + ya, 5, ya + ya}, // not in the middle of a character
		{ya + ya + ya, 4, ya + ya},
		{"a\xffb", 10, "a" + bad + "b"},
		{"a\xff\xfeb", 10, "a" + bad + "b"}, // a run of bad bytes is one replacement
	}
	for _, tt := range tests {
		got := clip(tt.in, tt.n)
		if got != tt.want {
			t.Errorf("clip(%q, %d) = %q, want %q", tt.in, tt.n, got, tt.want)
		}
		if !utf8.ValidString(got) || len(got) > tt.n {
			t.Errorf("clip(%q, %d) = %q: not valid UTF-8 within %d bytes", tt.in, tt.n, got, tt.n)
		}
	}
}

func TestManagerHandlesWatchRecords(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)

	ing := &recordingIngestor{}
	m := p.newManager()
	m.SetIngestor(ing)
	m.Start(context.Background())
	p.waitStatus(n.ID, store.NodeStatusOnline)

	f.emit(stateRecord(3))
	f.emit(statsRecord())
	last := f.emit(eventRecord("engine.started"))
	waitFor(t, "the cursor to reach the last record", func() bool { return p.node(n.ID).WatchCursor == last })

	got := p.node(n.ID)
	if got.AppliedGeneration != 3 {
		t.Errorf("applied generation = %d, want 3 from the state report", got.AppliedGeneration)
	}
	if got.Status != store.NodeStatusOnline {
		t.Errorf("status = %q, want online", got.Status)
	}
	want := []ingested{
		{nodeID: n.ID, seq: 1, kind: "state"},
		{nodeID: n.ID, seq: 2, kind: "stats"},
		{nodeID: n.ID, seq: 3, kind: "event"},
	}
	if recs := ing.records(); !slices.Equal(recs, want) {
		t.Errorf("ingested %+v, want %+v", recs, want)
	}
}

func TestManagerResumesWatchFromTheStoredCursor(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)
	for range 7 {
		f.emit(eventRecord("old"))
	}
	p.modify(n.ID, func(n *store.Node) { n.WatchCursor = 5 })

	ing := &recordingIngestor{}
	m := p.newManager()
	m.SetIngestor(ing)
	m.Start(context.Background())

	waitFor(t, "records 6 and 7", func() bool { return p.node(n.ID).WatchCursor == 7 })
	if got := ing.seqs(); !slices.Equal(got, []uint64{6, 7}) {
		t.Errorf("ingested %v, want [6 7]: what was before the stored cursor is not replayed", got)
	}
	if got := f.watchCursors(); !slices.Equal(got, []uint64{5}) {
		t.Errorf("Watch cursors = %v, want [5]", got)
	}

	// The stream breaks; the next one starts after the last record handled.
	f.dropWatch()
	waitFor(t, "a second Watch", func() bool { return len(f.watchCursors()) == 2 })
	if got := f.watchCursors()[1]; got != 7 {
		t.Errorf("Watch cursor after reconnecting = %d, want 7", got)
	}
	seq := f.emit(eventRecord("new"))
	waitFor(t, "the new record", func() bool { return p.node(n.ID).WatchCursor == seq })

	// A panel that restarts resumes from the database as well.
	m.Close()
	m2 := p.newManager()
	m2.SetIngestor(ing)
	m2.Start(context.Background())
	waitFor(t, "the Watch of the new manager", func() bool { return len(f.watchCursors()) == 3 })
	if got := f.watchCursors()[2]; got != seq {
		t.Errorf("Watch cursor after a restart = %d, want %d", got, seq)
	}
	last := f.emit(eventRecord("after restart"))
	waitFor(t, "the record after the restart", func() bool { return p.node(n.ID).WatchCursor == last })
	if got := ing.seqs(); !slices.Equal(got, []uint64{6, 7, 8, 9}) {
		t.Errorf("ingested %v, want every record once", got)
	}
}

func TestManagerRetriesAndThenSkipsARecordItCannotStore(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)

	ing := &recordingIngestor{fail: func(ev *nodev1.WatchResponse, attempt int) error {
		switch ev.GetSeq() {
		case 1:
			if attempt < 3 {
				return errors.New("database is locked")
			}
		case 2:
			return errors.New("a record that can never be stored")
		}
		return nil
	}}
	m := p.newManager()
	m.SetIngestor(ing)
	m.Start(context.Background())

	f.emit(eventRecord("one"))
	f.emit(eventRecord("two"))
	last := f.emit(eventRecord("three"))
	waitFor(t, "the cursor to pass every record", func() bool { return p.node(n.ID).WatchCursor == last })
	for seq, want := range map[uint64]int{1: 3, 2: 3, 3: 1} {
		if got := ing.attempts(seq); got != want {
			t.Errorf("record %d given %d times, want %d", seq, got, want)
		}
	}
	if logs := p.logs.String(); !strings.Contains(logs, "skipped") {
		t.Error("the log does not say that a record was skipped")
	}
}

func TestManagerMarksANodeOffline(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)

	m := p.newManager()
	m.Start(context.Background())
	p.waitStatus(n.ID, store.NodeStatusOnline)

	down := time.Now()
	f.down()
	p.waitStatus(n.ID, store.NodeStatusOffline)
	if elapsed := time.Since(down); elapsed < testTiming.offlineAfter {
		t.Errorf("offline after %v, want no sooner than %v", elapsed, testTiming.offlineAfter)
	}
	if p.node(n.ID).LastSeenAt == nil {
		t.Error("an offline node has no last-seen time")
	}

	f.back()
	p.waitStatus(n.ID, store.NodeStatusOnline)
	// The event follows the status.
	waitFor(t, "three events", func() bool { return len(p.eventKinds(n.ID)) == 3 })
	if kinds := p.eventKinds(n.ID); !slices.Equal(kinds, []string{"node.online", "node.offline", "node.online"}) {
		t.Errorf("events = %v", kinds)
	}
}

// A node that has never answered is still being installed, not offline.
func TestManagerKeepsAnUnreachableNewNodeProvisioning(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil) // never serves: connections are closed at once
	n := p.createNode("edge-1", f.port())

	m := p.newManager()
	m.Start(context.Background())
	waitFor(t, "several attempts", func() bool { return f.dials.Load() >= 3 })
	time.Sleep(2 * testTiming.offlineAfter)
	if got := p.node(n.ID).Status; got != store.NodeStatusProvisioning {
		t.Errorf("status = %q, want provisioning", got)
	}
	if kinds := p.eventKinds(n.ID); len(kinds) != 0 {
		t.Errorf("events = %v, want none", kinds)
	}
}

func TestManagerRefusesNodesItCannotPin(t *testing.T) {
	tests := []struct {
		name  string
		spoil func(n *store.Node)
		log   string
	}{
		{"no fingerprint", func(n *store.Node) { n.CertFingerprint = "" }, "fingerprint"},
		{"malformed fingerprint", func(n *store.Node) { n.CertFingerprint = "not-hex" }, "fingerprint"},
		{"short fingerprint", func(n *store.Node) { n.CertFingerprint = "abcd" }, "fingerprint"},
		{"no management port", func(n *store.Node) { n.MgmtPort = 0 }, "management address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestPanel(t)
			f := newFakeNode(t, nil)
			n := p.addNode("edge-1", f)
			p.modify(n.ID, tt.spoil)

			m := p.newManager()
			m.Start(context.Background())
			p.waitStatus(n.ID, store.NodeStatusError)
			time.Sleep(5 * testTiming.maxBackoff)
			if d := f.dials.Load(); d != 0 {
				t.Errorf("the manager connected %d times", d)
			}
			if logs := p.logs.String(); !strings.Contains(logs, tt.log) {
				t.Errorf("the log does not mention %q:\n%s", tt.log, logs)
			}
			if kinds := p.eventKinds(n.ID); !slices.Equal(kinds, []string{"node.error"}) {
				t.Errorf("events = %v, want one node.error", kinds)
			}

			// Mending the node lets the manager connect.
			p.modify(n.ID, func(s *store.Node) {
				s.CertFingerprint, s.MgmtHost, s.MgmtPort = n.CertFingerprint, n.MgmtHost, n.MgmtPort
			})
			m.Notify(n.ID)
			p.waitStatus(n.ID, store.NodeStatusOnline)
		})
	}
}

// A node that presents a certificate of the CA, but not its own, is not
// talked to: the pin is what keeps one node from posing as another.
func TestManagerRefusesANodeThatPresentsAnotherCertificate(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.createNode("edge-1", f.port())
	elsewhere := newFakeNode(t, nil) // never serves
	other := p.createNode("edge-2", elsewhere.port())
	f.serve(p.bundle(other.ID)) // edge-1's address answers with edge-2's credentials

	m := p.newManager()
	m.Start(context.Background())
	p.waitStatus(n.ID, store.NodeStatusError)
	if got := f.getInfoCalls(); got != 0 {
		t.Errorf("GetInfo reached the impostor %d times", got)
	}
	if logs := p.logs.String(); !strings.Contains(logs, "pinned") {
		t.Errorf("the log does not say that the pin did not match:\n%s", logs)
	}
	if got := p.node(other.ID).Status; got != store.NodeStatusProvisioning {
		t.Errorf("the other node is %q, want provisioning", got)
	}
}

func TestManagerClient(t *testing.T) {
	p := newTestPanel(t)
	f := newFakeNode(t, nil)
	n := p.addNode("edge-1", f)

	m := p.newManager()
	if _, err := m.Client(n.ID); !errors.Is(err, ErrUnknownNode) {
		t.Errorf("Client before Start: %v, want ErrUnknownNode", err)
	}
	m.Start(context.Background())
	p.waitStatus(n.ID, store.NodeStatusOnline)

	waitFor(t, "a client", func() bool {
		_, err := m.Client(n.ID)
		return err == nil
	})
	c, err := m.Client(n.ID)
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		t.Fatalf("GetInfo through Client: %v", err)
	}
	if info.Msg.GetAgentVersion() != "1.2.3" {
		t.Errorf("agent version = %q", info.Msg.GetAgentVersion())
	}
	if _, err := m.Client("01JABCDEFGHJKMNPQRSTVWXYZ0"); !errors.Is(err, ErrUnknownNode) {
		t.Errorf("Client of an unknown node: %v, want ErrUnknownNode", err)
	}

	f.down()
	p.waitStatus(n.ID, store.NodeStatusOffline)
	if _, err := m.Client(n.ID); !errors.Is(err, ErrNotConnected) {
		t.Errorf("Client of an offline node: %v, want ErrNotConnected", err)
	}
}

func TestManagerStartsAndStopsWithTheNodes(t *testing.T) {
	p := newTestPanel(t)
	m := p.newManager()
	ing := &recordingIngestor{}
	m.SetIngestor(ing)
	m.Start(context.Background())

	// A node created after Start is connected once the manager is told.
	f := newFakeNode(t, nil)
	n := p.createNode("edge-1", f.port())
	f.serve(p.bundle(n.ID))
	m.Notify(n.ID)
	p.waitStatus(n.ID, store.NodeStatusOnline)
	waitFor(t, "an open connection", func() bool { return f.openConns() > 0 })

	// A deleted node is let go, and its connection with it.
	if err := p.db.DeleteNode(context.Background(), n.ID); err != nil {
		t.Fatal(err)
	}
	m.Notify(n.ID)
	waitFor(t, "the runner of the deleted node to stop", func() bool { return !hasRunner(m, n.ID) })
	waitFor(t, "the connection to close", func() bool { return f.openConns() == 0 })
	// What the ingestor keeps of the node in memory goes with it.
	waitFor(t, "the ingestor to forget the node", func() bool { return ing.forgot(n.ID) })
}

func TestManagerCloseLeavesNothingRunning(t *testing.T) {
	p := newTestPanel(t)
	up := newFakeNode(t, nil)
	n1 := p.addNode("edge-1", up)
	unreachable := newFakeNode(t, nil)
	p.createNode("edge-2", unreachable.port())

	m := p.newManager()
	m.SetIngestor(&recordingIngestor{})
	m.Start(context.Background())
	p.waitStatus(n1.ID, store.NodeStatusOnline)
	waitFor(t, "a try at the unreachable node", func() bool { return unreachable.dials.Load() > 0 })

	done := make(chan struct{})
	go func() {
		m.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(waitTimeout):
		t.Fatal("Close did not return")
	}
	if left := managerGoroutines(); len(left) != 0 {
		t.Errorf("goroutines left after Close:\n%s", strings.Join(left, "\n\n"))
	}
	waitFor(t, "the connection to close", func() bool { return up.openConns() == 0 })

	// Notify after Close starts nothing, and Close may be called again.
	m.Notify(n1.ID)
	if hasRunner(m, n1.ID) {
		t.Error("Notify after Close started a runner")
	}
	m.Close()
}

// hasRunner reports whether the manager runs a goroutine for the node.
func hasRunner(m *Manager, nodeID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.runners[nodeID]
	return ok
}

// managerGoroutines returns the stacks of the goroutines that run code of the
// connection manager.
func managerGoroutines() []string {
	buf := make([]byte, 4<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var out []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "panel/nodes.(*runner)") || strings.Contains(g, "panel/nodes.(*session)") ||
			strings.Contains(g, "panel/nodes.(*Manager)") {
			out = append(out, g)
		}
	}
	return out
}

func countOf(list []string, s string) int {
	n := 0
	for _, x := range list {
		if x == s {
			n++
		}
	}
	return n
}

// hookRecorder is a ConnectHook that notes the nodes it was told of, in the
// trace of the test, so that its place among the steps is seen.
type hookRecorder struct {
	trace *trace
	mu    sync.Mutex
	ids   []string
}

func (h *hookRecorder) OnConnected(_ context.Context, nodeID string, client nodev1connect.NodeServiceClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ids = append(h.ids, nodeID)
	if client != nil {
		h.trace.add("hook")
	}
}

func (h *hookRecorder) got() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.ids...)
}

// The connect hook runs with the client of a node that connected, before its
// state is built and applied: what the hook puts on the node (imported
// certificates) is there when the state names it.
func TestManagerTellsTheConnectHookBeforeTheState(t *testing.T) {
	p := newTestPanel(t)
	tr := &trace{}
	f := newFakeNode(t, tr)
	n := p.addNode("edge-1", f)
	p.bump(n.ID, 2)

	h := &hookRecorder{trace: tr}
	m := p.newManager()
	m.SetStateBuilder(&fakeBuilder{})
	m.SetArtifactEnsurer(&fakeEnsurer{trace: tr})
	m.SetConnectHook(h)
	m.Start(context.Background())

	waitFor(t, "the node to accept generation 2", func() bool { return f.acceptedGeneration() == 2 })
	if got := h.got(); !slices.Equal(got, []string{n.ID}) {
		t.Errorf("hook saw %v, want the node once", got)
	}
	if got := tr.get(); !slices.Equal(got, []string{"hook", "ensure:2", "apply:2"}) {
		t.Errorf("steps = %v, want the hook before the state", got)
	}
}
