package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"unicode/utf8"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/node/diag"
	"github.com/urbnywrt/postern/internal/node/reconcile"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/version"
)

// installHome makes a POSTERN_HOME the way install.sh leaves it: the bundle
// unpacked into pki/ and data/state/node-id.
func installHome(t *testing.T, p *testPKI, nodeID string) string {
	t.Helper()
	home := t.TempDir()
	write := func(rel string, data []byte) {
		t.Helper()
		path := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("pki/bundle.json", fmt.Appendf(nil, `{"version":1,"node_id":%q,"mgmt_port":61234}`, nodeID))
	write("pki/ca.pem", p.ca.CertPEM)
	write("pki/node.pem", p.nodeCert)
	write("pki/node-key.pem", p.nodeKey)
	write("data/state/node-id", []byte(nodeID+"\n"))
	write("bin/postern-node-test", []byte("#!/bin/sh\nexit 0\n"))
	if err := os.Chmod(filepath.Join(home, "bin/postern-node-test"), 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

// fakeEdgeClient is an edge that answers every call.
type fakeEdgeClient struct{ gen uint64 }

func (e fakeEdgeClient) SetConfig(context.Context, *edgev1.EdgeConfig) ([]*edgev1.ListenerFailure, error) {
	return nil, nil
}
func (e fakeEdgeClient) Snapshot(context.Context) (*edgev1.SnapshotResponse, error) {
	return &edgev1.SnapshotResponse{Generation: e.gen}, nil
}
func (e fakeEdgeClient) Health(context.Context) (*edgev1.HealthResponse, error) {
	return &edgev1.HealthResponse{Generation: e.gen, Listening: true}, nil
}
func (e fakeEdgeClient) Drain(context.Context, uint32) error { return nil }

// agentRun is an agent started by a test.
type agentRun struct {
	t      *testing.T
	home   string
	stderr *syncBuffer
	docker *dockerapi.Fake
	cancel context.CancelFunc
	done   chan error
	addr   chan net.Addr
	pki    *testPKI
}

func testOptions(home string, stderr *syncBuffer, docker dockerapi.Client, addr chan net.Addr) Options {
	return Options{
		Home:       home,
		MgmtListen: "127.0.0.1:0",
		Stderr:     stderr,
		docker:     docker,
		proc:       fstest.MapFS{},
		osRelease:  []string{filepath.Join(home, "no-os-release")},
		addrs:      func() ([]net.Addr, error) { return []net.Addr{ipNet("203.0.113.10/24")}, nil },
		echoURLs:   []string{},
		nodeBinary: filepath.Join(home, "bin/postern-node-test"),
		edge:       func(gen uint64) reconcile.EdgeClient { return fakeEdgeClient{gen: gen} },
		listening:  func(a net.Addr) { addr <- a },
		// No list of the middle proxies is fetched from Telegram.
		meConfigURLs: []string{},
		// A host whose edge handoff is safe (net.ipv4.tcp_migrate_req = 1).
		procSys: procSysWith(home, "1"),
		// No check reaches the internet.
		diagChecks: []diag.Check{},
	}
}

func startAgent(t *testing.T, home string, p *testPKI, tweak func(*Options)) *agentRun {
	t.Helper()
	a := &agentRun{t: t, home: home, stderr: &syncBuffer{}, docker: dockerapi.NewFake(), done: make(chan error, 1), addr: make(chan net.Addr, 1), pki: p}
	opt := testOptions(home, a.stderr, a.docker, a.addr)
	if tweak != nil {
		tweak(&opt)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	go func() { a.done <- Run(ctx, opt) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-a.done:
		case <-time.After(20 * time.Second):
			t.Error("the agent did not stop")
		}
	})
	return a
}

// listening waits for the management listener and returns a panel client.
func (a *agentRun) client() nodev1connect.NodeServiceClient {
	a.t.Helper()
	select {
	case addr := <-a.addr:
		return a.pki.client(a.t, addr.String(), a.pki.clientCert, a.pki.clientKey)
	case err := <-a.done:
		a.t.Fatalf("the agent stopped: %v\n%s", err, a.stderr.String())
	case <-time.After(20 * time.Second):
		a.t.Fatalf("the agent did not listen\n%s", a.stderr.String())
	}
	return nil
}

func (a *agentRun) stop() error {
	a.t.Helper()
	a.cancel()
	select {
	case err := <-a.done:
		a.done <- err // for the cleanup
		return err
	case <-time.After(20 * time.Second):
		a.t.Fatal("the agent did not stop")
	}
	return nil
}

func (a *agentRun) marker() string {
	return filepath.Join(a.home, "data", "run", "launcher", "healthy")
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// watchKinds collects the kinds of the records of a Watch stream from cursor 0
// until want is among them.
func watchUntil(t *testing.T, c nodev1connect.NodeServiceClient, want string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := c.Watch(ctx, connect.NewRequest(&nodev1.WatchRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	var kinds []string
	for stream.Receive() {
		kinds = append(kinds, kindsOf([]*nodev1.WatchResponse{stream.Msg()})...)
		if kinds[len(kinds)-1] == want {
			return kinds
		}
	}
	t.Fatalf("no %s in %v: %v", want, kinds, stream.Err())
	return nil
}

func TestRunServesAndWritesTheHealthyMarker(t *testing.T) {
	checkGoroutines(t)
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	a := startAgent(t, home, p, nil)
	c := a.client()

	waitFor(t, "the healthy marker", func() bool { return exists(a.marker()) })
	data, err := os.ReadFile(a.marker())
	if err != nil || strings.TrimSpace(string(data)) != version.String() {
		t.Errorf("marker = %q, %v", data, err)
	}
	info, err := c.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.Msg.GetAgentVersion() != version.Version || len(info.Msg.GetPublicIps()) != 1 {
		t.Errorf("GetInfo = %v", info.Msg)
	}
	kinds := watchUntil(t, c, "event:agent_started")
	if kinds[0] != "state" {
		t.Errorf("first record = %s, want the state report", kinds[0])
	}
	if err := a.stop(); err != nil {
		t.Errorf("Run = %v, want nil after a stop", err)
	}
	if !strings.Contains(a.stderr.String(), "agent") {
		t.Errorf("log = %s", a.stderr.String())
	}
}

// The marker waits for a reconcile pass that went through: a process that is
// up but cannot reconcile is what the launcher's rollback is for.
func TestRunWritesTheMarkerOnlyAfterAGoodPass(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	st := validState(1)
	st.Proxies = nil
	if err := (&storeFor{home}).save(st); err != nil {
		t.Fatal(err)
	}
	var docker *dockerapi.Fake
	passes := make(chan error, 16)
	a := startAgent(t, home, p, func(o *Options) {
		docker = o.docker.(*dockerapi.Fake)
		docker.SetError("List", errors.New("docker is down"))
		o.passed = func(err error) { passes <- err }
	})
	c := a.client()
	nextPass := func() error {
		t.Helper()
		select {
		case err := <-passes:
			return err
		case <-time.After(20 * time.Second):
			t.Fatal("no reconcile pass")
		}
		return nil
	}
	if err := nextPass(); err == nil {
		t.Fatal("the first pass went through although Docker is down")
	}
	if exists(a.marker()) {
		t.Fatal("marker written after a failed pass")
	}
	docker.SetError("List", nil)
	next := validState(2)
	next.Proxies = nil
	resp, err := c.ApplyState(context.Background(), connect.NewRequest(&nodev1.ApplyStateRequest{State: next}))
	if err != nil || !resp.Msg.GetAccepted() {
		t.Fatalf("ApplyState = %v, %v", resp, err)
	}
	for nextPass() != nil {
	}
	if !exists(a.marker()) {
		t.Error("no marker after a pass that went through")
	}
	watchUntil(t, c, "event:reconcile_failed")
}

// A state report says why the last pass failed, so that the panel can show
// it, and says nothing once a pass went through.
func TestRunReportsWhyThePassFailed(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	st := validState(1)
	st.Proxies = nil
	if err := (&storeFor{home}).save(st); err != nil {
		t.Fatal(err)
	}
	var docker *dockerapi.Fake
	a := startAgent(t, home, p, func(o *Options) {
		docker = o.docker.(*dockerapi.Fake)
		docker.SetError("List", errors.New("docker is down"))
	})
	c := a.client()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := c.Watch(ctx, connect.NewRequest(&nodev1.WatchRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	until := func(what string, ok func(*nodev1.StateReport) bool) {
		t.Helper()
		for stream.Receive() {
			if rep := stream.Msg().GetState(); rep != nil && ok(rep) {
				return
			}
		}
		t.Fatalf("no state report with %s: %v", what, stream.Err())
	}
	until("the error of the pass", func(rep *nodev1.StateReport) bool {
		return strings.Contains(rep.GetLastError(), "docker is down")
	})

	docker.SetError("List", nil)
	next := validState(2)
	next.Proxies = nil
	if resp, err := c.ApplyState(context.Background(), connect.NewRequest(&nodev1.ApplyStateRequest{State: next})); err != nil || !resp.Msg.GetAccepted() {
		t.Fatalf("ApplyState = %v, %v", resp, err)
	}
	until("no error after a pass that went through", func(rep *nodev1.StateReport) bool {
		return rep.GetAppliedGeneration() == 2 && rep.GetLastError() == ""
	})
}

// The first report of an agent that just started, the opening one of Watch, has
// the proxies of the runtime record, before any pass has run through (M1):
// here no pass can, Docker being down.
func TestRunOpensWatchWithTheRecordedProxies(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	if err := (&storeFor{home}).save(validState(4)); err != nil {
		t.Fatal(err)
	}
	rt := state.NewRuntime()
	rt.AppliedGeneration = 4
	rt.EdgeGeneration = 1
	rt.Instances["p1"] = state.InstanceRecord{Generation: 2, Engine: "telemt", Version: "3.5.13", ListenPort: 20000}
	if err := (&state.Store{Paths: state.Paths{Home: home}}).SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	a := startAgent(t, home, p, func(o *Options) {
		o.docker.(*dockerapi.Fake).SetError("List", errors.New("docker is down"))
	})
	c := a.client()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := c.Watch(ctx, connect.NewRequest(&nodev1.WatchRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	if !stream.Receive() {
		t.Fatalf("no opening report: %v", stream.Err())
	}
	rep := stream.Msg().GetState()
	want := []*nodev1.ProxyStatus{{
		ProxyId: "p1", Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING, Engine: nodev1.Engine_ENGINE_TELEMT,
		RunningVersion: "3.5.13", InstanceGeneration: 2,
	}}
	if rep.GetAppliedGeneration() != 4 || len(rep.GetProxies()) != 1 || !proto.Equal(rep.GetProxies()[0], want[0]) {
		t.Errorf("opening report = %v, want generation 4 and %v", rep, want)
	}
}

// The error of a pass goes out as text of 512 bytes at most, valid UTF-8, on
// one line: it is the text of an error, which may be long or quote anything.
func TestFitReportBoundsTheLastError(t *testing.T) {
	long := strings.Repeat("é", 400) + "\nnext line\x00"
	rep := fitReport(&nodev1.StateReport{AppliedGeneration: 3, LastError: long})
	got := rep.GetLastError()
	if len(got) > 512 || len(got) < 500 || !utf8.ValidString(got) || strings.ContainsAny(got, "\n\x00") {
		t.Errorf("last error = %d bytes %q, want at most 512 bytes of valid text on one line", len(got), got)
	}
	if !strings.HasPrefix(long, got) {
		t.Errorf("last error = %q, want the start of the text", got)
	}
	if rep.GetAppliedGeneration() != 3 {
		t.Errorf("applied generation = %d, want it kept", rep.GetAppliedGeneration())
	}
	if got := fitReport(&nodev1.StateReport{LastError: "edge g1: \xff refused"}).GetLastError(); !utf8.ValidString(got) {
		t.Errorf("last error = %q, want valid UTF-8", got)
	}
}

// The marker waits for all three: the state loaded, the server serving, a
// pass that went through; it is written once.
func TestHealthMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "launcher", "healthy")
	m := &healthMarker{path: path, log: discardLog()}
	m.passed(nil)
	m.setLoaded()
	m.passed(nil)
	if exists(path) {
		t.Fatal("written before the server serves")
	}
	m.setServing()
	m.passed(errors.New("docker is down"))
	if exists(path) {
		t.Fatal("written after a failed pass")
	}
	m.passed(nil)
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) != version.String() {
		t.Fatalf("marker = %q, %v", data, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("marker mode = %v, %v", info.Mode().Perm(), err)
	}
	// Once only: the launcher deletes it at the next start, not the agent.
	if err := os.WriteFile(path, []byte("seen\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.passed(nil)
	if data, _ := os.ReadFile(path); string(data) != "seen\n" {
		t.Errorf("written again: %q", data)
	}

	// A marker that is not loaded but serving waits too.
	other := &healthMarker{path: filepath.Join(t.TempDir(), "healthy"), log: discardLog()}
	other.setServing()
	other.passed(nil)
	if exists(other.path) {
		t.Error("written before the state was loaded")
	}

	// A pass whose state was refused is the state's fault, not the agent's
	// (spec 7): the marker is written. Docker that is down and an edge that
	// does not answer are the agent's.
	refused := &healthMarker{path: filepath.Join(t.TempDir(), "healthy"), log: discardLog()}
	refused.setLoaded()
	refused.setServing()
	refused.passed(errors.New("edge g1 does not answer after 30s: dial unix: no such file or directory"))
	if exists(refused.path) {
		t.Fatal("written after a pass whose edge did not answer")
	}
	refused.passed(fmt.Errorf("edge g1: the edge did not apply the config: bind: address already in use: %w", reconcile.ErrRefused))
	if !exists(refused.path) {
		t.Error("not written after a pass whose state the edge refused")
	}
}

// A desired state that is refused does not keep the agent from its marker: a
// good binary is not rolled back for a state that the panel has to mend (I1,
// spec 7).
func TestRunWritesTheMarkerWhenTheStateIsRefused(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	// A state that does not validate, put there by hand: ApplyState would
	// refuse it.
	st := validState(1)
	st.Proxies[0].Secret = "short"
	if err := (&storeFor{home}).save(st); err != nil {
		t.Fatal(err)
	}
	passes := make(chan error, 16)
	a := startAgent(t, home, p, func(o *Options) {
		o.passed = func(err error) { passes <- err }
	})
	a.client()
	select {
	case err := <-passes:
		if !errors.Is(err, reconcile.ErrRefused) {
			t.Fatalf("pass = %v, want a refusal of the state", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no reconcile pass")
	}
	if !exists(a.marker()) {
		t.Error("no marker after a pass whose state was refused")
	}
}

func TestRunRefusesTheStateOfAnotherNode(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	if err := os.WriteFile(filepath.Join(home, "data/state/node-id"), []byte(otherNodeID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr := &syncBuffer{}
	err := Run(context.Background(), testOptions(home, stderr, dockerapi.NewFake(), make(chan net.Addr, 1)))
	if err == nil || !strings.Contains(err.Error(), otherNodeID) || !strings.Contains(err.Error(), testNodeID) || !strings.Contains(err.Error(), "install.sh") {
		t.Errorf("Run = %v, want a refusal naming both nodes and install.sh", err)
	}
}

func TestRunRecordsTheNodeIDWhenItIsMissing(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	if err := os.Remove(filepath.Join(home, "data/state/node-id")); err != nil {
		t.Fatal(err)
	}
	a := startAgent(t, home, p, nil)
	a.client()
	data, err := os.ReadFile(filepath.Join(home, "data/state/node-id"))
	if err != nil || strings.TrimSpace(string(data)) != testNodeID {
		t.Errorf("node-id = %q, %v", data, err)
	}
}

func TestRunRejectsABadBundle(t *testing.T) {
	p := newTestPKI(t)
	for _, tc := range []struct {
		name, file, data, want string
	}{
		{"node id not of the panel", "pki/bundle.json", `{"version":1,"node_id":"node-1","mgmt_port":61234}`, "node id"},
		{"lower case node id", "pki/bundle.json", `{"version":1,"node_id":"` + strings.ToLower(testNodeID) + `","mgmt_port":61234}`, "node id"},
		{"no key", "pki/node-key.pem", "", "node-key.pem"},
		{"another format", "pki/bundle.json", `{"version":2,"node_id":"` + testNodeID + `","mgmt_port":61234}`, "version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := installHome(t, p, testNodeID)
			path := filepath.Join(home, tc.file)
			var err error
			if tc.data == "" {
				err = os.Remove(path)
			} else {
				err = os.WriteFile(path, []byte(tc.data), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = Run(context.Background(), testOptions(home, &syncBuffer{}, dockerapi.NewFake(), make(chan net.Addr, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Run = %v, want an error about %s", err, tc.want)
			}
		})
	}
}

// Records buffered for another node never reach the panel as this node's.
func TestRunWipesTheBufferOfAnotherNode(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	old, err := openBuffer(filepath.Join(home, "data", "stats.db"), otherNodeID, time.Now, discardLog())
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, old, eventRecord("of_the_other_node"))
	_ = old.Close()

	a := startAgent(t, home, p, nil)
	kinds := watchUntil(t, a.client(), "event:agent_started")
	if strings.Contains(strings.Join(kinds, ","), "of_the_other_node") {
		t.Errorf("records = %v", kinds)
	}
}

func TestRunReportsAndClearsTheRollbackRecord(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	record := filepath.Join(home, "data", "run", "launcher", "rollback")
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte("1790000000 postern-node-v2 postern-node-v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := startAgent(t, home, p, nil)
	c := a.client()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := c.Watch(ctx, connect.NewRequest(&nodev1.WatchRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	var ev *nodev1.NodeEvent
	for ev == nil && stream.Receive() {
		if e := stream.Msg().GetEvent(); e.GetKind() == "agent_rolled_back" {
			ev = e
		}
	}
	if ev == nil {
		t.Fatalf("no rollback event: %v", stream.Err())
	}
	if ev.GetSeverity() != "warning" || ev.GetDetails()["from"] != "postern-node-v2" || ev.GetDetails()["to"] != "postern-node-v1" {
		t.Errorf("event = %v", ev)
	}
	if exists(record) {
		t.Error("the rollback record is still there")
	}
	if !strings.Contains(a.stderr.String(), "level=WARN") {
		t.Errorf("no warning in the log:\n%s", a.stderr.String())
	}
}

// The reconciler's probe speaks to the engine as the edge does: a PROXY v2
// header with the source the reconciler gives, then the fake-TLS hello.
func TestFakeTLSProbeSendsTheProxyHeader(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 28) // signature, version, family, length, IPv4 source and destination
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := io.ReadFull(c, buf)
		got <- buf[:n]
	}()
	src := netip.MustParseAddrPort("127.0.0.1:1")
	err = fakeTLSProbe(context.Background(), ln.Addr().String(), "a.example.com", make([]byte, 16), src)
	if err == nil {
		t.Fatal("the probe succeeded against a server that never answered")
	}
	header := <-got
	sig := []byte("\r\n\r\n\x00\r\nQUIT\n")
	if len(header) < 28 || !bytes.Equal(header[:12], sig) {
		t.Fatalf("the probe did not start with a PROXY v2 header: %x", header)
	}
	if source := netip.AddrPortFrom(netip.AddrFrom4([4]byte(header[16:20])), uint16(header[24])<<8|uint16(header[25])); source != src {
		t.Errorf("PROXY source = %v, want %v", source, src)
	}
}

// With mgmt_hidden_only the agent serves only the hidden listener. When no
// authenticated request arrives through it for the fallback timeout, the agent
// reopens the plain listener (event mgmt.fallback); an authenticated request
// through the hidden listener then closes the plain one again (spec 5.3).
func TestRunMgmtHiddenOnlyFallback(t *testing.T) {
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	st := validState(1)
	st.Settings.MgmtSni = "cdn.example.com"
	st.Settings.MgmtHiddenOnly = true
	if err := (&storeFor{home}).save(st); err != nil {
		t.Fatal(err)
	}
	plainOpens := make(chan net.Addr, 4)
	hiddenOpens := make(chan net.Addr, 1)
	a := startAgent(t, home, p, func(o *Options) {
		o.listening = func(addr net.Addr) { plainOpens <- addr }
		o.hiddenLn = func(addr net.Addr) { hiddenOpens <- addr }
		o.mgmtFallbackAfter = 300 * time.Millisecond
		o.mgmtCheckEvery = 15 * time.Millisecond
	})

	var hiddenAddr net.Addr
	select {
	case hiddenAddr = <-hiddenOpens:
	case <-time.After(20 * time.Second):
		t.Fatalf("the hidden listener did not open\n%s", a.stderr.String())
	}
	// The plain listener is off at startup; the fallback reopens it.
	var plainAddr net.Addr
	select {
	case plainAddr = <-plainOpens:
	case <-time.After(20 * time.Second):
		t.Fatalf("the fallback did not reopen the plain listener\n%s", a.stderr.String())
	}
	if c, err := net.DialTimeout("tcp", plainAddr.String(), 2*time.Second); err == nil {
		_ = c.Close()
	} else {
		t.Fatalf("the reopened plain listener does not accept connections: %v", err)
	}

	// An authenticated request through the hidden listener closes the plain one.
	hidden := p.proxyClient(t, hiddenAddr.String(), v4Source)
	if _, err := hidden.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{})); err != nil {
		t.Fatalf("GetInfo through the hidden listener: %v", err)
	}
	waitFor(t, "the plain listener closed again", func() bool {
		c, err := net.DialTimeout("tcp", plainAddr.String(), 200*time.Millisecond)
		if err != nil {
			return true
		}
		_ = c.Close()
		return false
	})
	// The reopen was recorded as a mgmt.fallback event.
	watchUntil(t, hidden, "event:mgmt.fallback")
}

func TestMgmtListenDefault(t *testing.T) {
	if got := mgmtListen("", 61234); got != "0.0.0.0:61234" {
		t.Errorf("default = %q", got)
	}
	if got := mgmtListen("127.0.0.1:5000", 61234); got != "127.0.0.1:5000" {
		t.Errorf("explicit = %q", got)
	}
}

// storeFor saves a desired state into a home before the agent starts.
type storeFor struct{ home string }

func (s *storeFor) save(st *nodev1.NodeState) error {
	return (&state.Store{Paths: state.Paths{Home: s.home}}).SaveDesired(st)
}

// The agent that Run starts stores imported certificates: PutCertificate
// goes to the ACME manager of the run (Ruling S3-1), which the service must
// be given.
func TestRunStoresAnImportedCertificate(t *testing.T) {
	checkGoroutines(t)
	p := newTestPKI(t)
	home := installHome(t, p, testNodeID)
	a := startAgent(t, home, p, nil)
	c := a.client()

	now := time.Now()
	chain, key := selfSigned(t, "web.example.com", now.Add(-time.Hour), now.Add(60*24*time.Hour))
	resp, err := c.PutCertificate(context.Background(), connect.NewRequest(&nodev1.PutCertificateRequest{
		Domain: "web.example.com", FullchainPem: chain, KeyPem: key,
	}))
	if err != nil {
		t.Fatalf("PutCertificate: %v", err)
	}
	if !resp.Msg.GetStored() || resp.Msg.GetSha256() == "" {
		t.Errorf("PutCertificate = %v, want the certificate stored", resp.Msg)
	}
	if err := a.stop(); err != nil {
		t.Errorf("Run = %v, want nil after a stop", err)
	}
}
