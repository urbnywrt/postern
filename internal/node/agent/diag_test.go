package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/diag"
	"github.com/urbnywrt/postern/internal/node/state"
)

// Every socket is listed on its own: two SO_REUSEPORT sockets of one port,
// the edge's and a stranger's, are two owners, and host.ports fails the
// listener; a socket whose process cannot be seen is unknown (never the
// expected container), which is a warning; the agent's own socket is ours.
func TestSocketOwnersForHostPorts(t *testing.T) {
	_, docker := portsWorld(t)
	edgeID := containerID(t, docker, "postern-edge-g2")
	tcp := procNetHeader +
		procNetLine(0, "00000000:01BB", "0A", 1) + // 0.0.0.0:443, the edge
		procNetLine(1, "00000000:01BB", "0A", 2) + // 0.0.0.0:443 again (SO_REUSEPORT), a stranger
		procNetLine(2, "00000000:20FB", "0A", 3) + // 0.0.0.0:8443, nobody can tell
		procNetLine(3, "00000000:1F90", "0A", 4) // 0.0.0.0:8080, the agent itself
	proc := deniedFS{MapFS: fstest.MapFS{
		"net/tcp":    {Data: []byte(tcp)},
		"200/comm":   {Data: []byte("postern-node\n")},
		"200/cgroup": {Data: []byte("0::/system.slice/docker-" + edgeID + ".scope\n")},
		"200/fd/3":   symlink("socket:[1]"),
		"600/comm":   {Data: []byte("haproxy\n")},
		"600/cgroup": {Data: []byte("0::/system.slice/haproxy.service\n")},
		"600/fd/3":   symlink("socket:[2]"),
		"700/comm":   {Data: []byte("postern-node\n")},
		"700/fd/3":   symlink("socket:[4]"),
		"800/comm":   {Data: []byte("hidden\n")},
		"800/fd/3":   symlink("socket:[3]"),
	}, deny: map[string]bool{"800/fd": true}}

	owners := socketOwners(context.Background(), proc, docker, 700)
	if len(owners) != 4 {
		t.Fatalf("owners = %+v, want one for each socket", owners)
	}
	byInode := map[int]diag.SocketOwner{}
	for i, o := range owners {
		byInode[i+1] = o
	}
	if o := byInode[1]; o.Owner != "postern-edge-g2" || !o.Known || o.PID != 200 {
		t.Errorf("edge socket = %+v", o)
	}
	if o := byInode[2]; o.Owner != "haproxy (pid 600)" || !o.Known {
		t.Errorf("stranger socket = %+v", o)
	}
	if o := byInode[3]; o.Known || o.Owner != "" {
		t.Errorf("hidden socket = %+v, want unknown", o)
	}
	if o := byInode[4]; o.Owner != diag.OwnerAgent {
		t.Errorf("own socket = %+v", o)
	}

	st := &nodev1.NodeState{Listeners: []*nodev1.Listener{
		{Id: "a", BindIp: "203.0.113.10", Port: 443}, {Id: "b", BindIp: "0.0.0.0", Port: 8443}, {Id: "c", BindIp: "0.0.0.0", Port: 8080},
	}}
	store := testStore(t, st)
	r := diag.NewRunner(diag.Env{Store: store, PortOwners: func(ctx context.Context) []diag.SocketOwner {
		return socketOwners(ctx, proc, docker, 700)
	}}, catalogueOnly(diag.IDPorts))
	got := map[string]diag.Result{}
	if err := r.Run(context.Background(), diag.ScopeNode, func(res diag.Result) { got[res.Target] = res }); err != nil {
		t.Fatal(err)
	}
	if res := got["listener:a"]; res.Status != diag.Fail || !strings.Contains(res.Evidence, "haproxy (pid 600)") {
		t.Errorf("a = %+v", res)
	}
	if res := got["listener:b"]; res.Status != diag.Warn {
		t.Errorf("b = %+v, want warn: owner unknown", res)
	}
	if res := got["listener:c"]; res.Status != diag.OK {
		t.Errorf("c = %+v, want ok: the agent's own", res)
	}
}

func catalogueOnly(ids ...string) []diag.Check {
	var out []diag.Check
	for _, c := range diag.Catalogue() {
		for _, id := range ids {
			if c.ID == id {
				out = append(out, c)
			}
		}
	}
	return out
}

func testStore(t *testing.T, st *nodev1.NodeState) *state.Store {
	t.Helper()
	s := &state.Store{Paths: state.Paths{Home: t.TempDir()}}
	if st != nil {
		st.Generation = 1
		if err := s.SaveDesired(st); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// RunDiagnostics over the panel's mTLS: results stream as they come, an
// unknown scope is InvalidArgument, a second run ResourceExhausted, and the
// end of a run is the event diagnostics_run with the counts.
func TestRunDiagnosticsOverMTLS(t *testing.T) {
	r := newRig(t)
	if err := r.store.SaveDesired(&nodev1.NodeState{Generation: 1, Proxies: []*nodev1.Proxy{{Id: "p1", ListenerId: "L1"}}}); err != nil {
		t.Fatal(err)
	}
	checks := []diag.Check{
		{ID: "host.fake", Layer: diag.LayerHost, Run: func(context.Context, *diag.Env) []diag.Result {
			return []diag.Result{{Status: diag.OK, Summary: "fine"}, {Target: "proxy:p2", Status: diag.Fail, Summary: "other proxy"}}
		}},
		{ID: "engine.fake", Layer: diag.LayerEngine, Run: func(context.Context, *diag.Env) []diag.Result {
			return []diag.Result{{Target: "proxy:p1", Status: diag.Fail, Summary: "client 198.51.100.7 failed", Evidence: "detail"}}
		}},
	}
	svc := r.newService()
	svc.diag = diag.NewRunner(diag.Env{Store: r.store, Now: r.clock.Now}, checks)
	addr := serveTLS(t, svc.handler(), r.pki.serverTLS(t))
	client := r.pki.client(t, addr, r.pki.clientCert, r.pki.clientKey)

	stream, err := client.RunDiagnostics(context.Background(), connect.NewRequest(&nodev1.RunDiagnosticsRequest{Scope: "proxy:p1"}))
	if err != nil {
		t.Fatal(err)
	}
	var got []*nodev1.DiagnosticResult
	for stream.Receive() {
		got = append(got, stream.Msg())
	}
	if err := stream.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("results = %v, want the node's and p1's", got)
	}
	for _, res := range got {
		if res.GetTarget() == "proxy:p1" && (res.GetSummary() != "client <ip> failed" || res.GetEvidence() != "detail" || res.GetLayer() != "engine") {
			t.Errorf("p1 result = %v", res)
		}
	}
	waitFor(t, "the diagnostics_run event", func() bool {
		recs, _ := r.buf.After(0, 100)
		for _, rec := range recs {
			if ev := rec.GetEvent(); ev.GetKind() == "diagnostics_run" {
				d := ev.GetDetails()
				return d["scope"] == "proxy:p1" && d["ok"] == "1" && d["fail"] == "1" && d["warn"] == "0" && d["skip"] == "0"
			}
		}
		return false
	})

	// An unknown scope.
	stream, _ = client.RunDiagnostics(context.Background(), connect.NewRequest(&nodev1.RunDiagnosticsRequest{Scope: "proxy:nope"}))
	for stream.Receive() {
	}
	if code := connect.CodeOf(stream.Err()); code != connect.CodeInvalidArgument {
		t.Errorf("unknown scope: %v, want InvalidArgument", stream.Err())
	}

	// A second run while one runs.
	release2 := make(chan struct{})
	svc2 := r.newService()
	started := make(chan struct{})
	svc2.diag = diag.NewRunner(diag.Env{}, []diag.Check{{ID: "host.slow", Run: func(context.Context, *diag.Env) []diag.Result {
		close(started)
		<-release2
		return []diag.Result{{Status: diag.OK}}
	}}})
	addr2 := serveTLS(t, svc2.handler(), r.pki.serverTLS(t))
	client2 := r.pki.client(t, addr2, r.pki.clientCert, r.pki.clientKey)
	first := make(chan error, 1)
	go func() {
		s, err := client2.RunDiagnostics(context.Background(), connect.NewRequest(&nodev1.RunDiagnosticsRequest{Scope: "node"}))
		if err != nil {
			first <- err
			return
		}
		for s.Receive() {
		}
		first <- s.Err()
	}()
	<-started
	s2, _ := client2.RunDiagnostics(context.Background(), connect.NewRequest(&nodev1.RunDiagnosticsRequest{Scope: "node"}))
	for s2.Receive() {
	}
	if code := connect.CodeOf(s2.Err()); code != connect.CodeResourceExhausted {
		t.Errorf("second run: %v, want ResourceExhausted", s2.Err())
	}
	close(release2)
	select {
	case err := <-first:
		if err != nil {
			t.Errorf("first run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the first run did not end")
	}
}

func TestRecordKindDiagnostics(t *testing.T) {
	kind, err := recordKind(&nodev1.WatchResponse{Payload: &nodev1.WatchResponse_Diagnostics{Diagnostics: &nodev1.DiagnosticsReport{}}})
	if err != nil || kind != kindDiag {
		t.Errorf("recordKind = %q, %v", kind, err)
	}
}

// A live diagnostics report waits for the watchers in place of none; one that
// is buffered takes a waiting live one back first, and leaves other live
// records alone.
func TestJournalDiagnostics(t *testing.T) {
	clock := newTestClock()
	buf := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	j := newJournal(buf, discardLog(), clock.Now)
	w := j.watch()
	defer j.unwatch(w)
	rep := func(status nodev1.CheckStatus) *nodev1.DiagnosticsReport {
		return &nodev1.DiagnosticsReport{Results: []*nodev1.DiagnosticResult{{Id: "host.x", Status: status}}}
	}

	j.diagnostics(rep(diag.OK), false)
	if recs, _ := buf.After(0, 10); len(recs) != 0 {
		t.Errorf("a live report was buffered: %v", recs)
	}
	j.diagnostics(rep(diag.Fail), true)
	select {
	case rec := <-w.live:
		t.Errorf("the older live report still waits: %v", rec)
	default:
	}
	recs, _ := buf.After(0, 10)
	if len(recs) != 1 || recs[0].GetDiagnostics().GetResults()[0].GetStatus() != diag.Fail {
		t.Errorf("buffered = %v", recs)
	}

	// A waiting live state report is not a diagnostics report: it stays.
	j.mu.Lock()
	j.liveLocked(&nodev1.WatchResponse{Payload: &nodev1.WatchResponse_State{State: &nodev1.StateReport{AppliedGeneration: 7}}})
	j.mu.Unlock()
	j.diagnostics(rep(diag.OK), true)
	select {
	case rec := <-w.live:
		if rec.GetState().GetAppliedGeneration() != 7 {
			t.Errorf("live = %v", rec)
		}
	default:
		t.Error("the live state report was taken back")
	}
}

// The scrubber of a run takes the WARP account's token and key out.
func TestDiagScrubberWARP(t *testing.T) {
	store := testStore(t, nil)
	st := &nodev1.NodeState{Egresses: []*nodev1.Egress{{Id: "W1", Kind: nodev1.EgressKind_EGRESS_KIND_WARP}}}
	dir := store.Paths.EgressStateDir("W1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	acct := `{"private_key":"cHJpdmF0ZS1rZXktb2YtdGhlLWRldmljZQ==","token":"warp-token-1234567890"}` // gitleaks:allow (made-up test value)
	if err := os.WriteFile(filepath.Join(dir, warpAccountFile), []byte(acct), 0o600); err != nil {
		t.Fatal(err)
	}
	s := diagScrubber(store, st, nil, nil)
	got := s.Clean("token warp-token-1234567890 key cHJpdmF0ZS1rZXktb2YtdGhlLWRldmljZQ==")
	if got != "token *** key ***" {
		t.Errorf("Clean = %q", got)
	}
}

// The addresses over the bound of a minute's countries are counted, and the
// count goes with the minute.
func TestMinuteAddrOverflow(t *testing.T) {
	m := newMinute(60)
	for i := range maxMinuteAddrs {
		m.addrs[ipKey{"p", strconv.Itoa(i)}] = 1
	}
	m.addr(ipKey{"p", "0"}, 5) // known: counted
	m.addr(ipKey{"p", "new"}, 5)
	m.addr(ipKey{"p", "new2"}, 5)
	if m.overflow != 2 || m.addrs[ipKey{"p", "0"}] != 6 {
		t.Errorf("overflow = %d, known address = %d", m.overflow, m.addrs[ipKey{"p", "0"}])
	}
}

// The diagnostics' environment hands the L2 probes of e2e.l2 to the
// statistics, and has the gate's checks of the way out; the runner has the
// egress and end-to-end checks.
func TestDiagEnvEgressAndProbes(t *testing.T) {
	clock := newTestClock()
	buf := openTestBuffer(t, filepath.Join(t.TempDir(), "stats.db"), testNodeID, clock)
	c := &statsCollector{source: &fakeSnapshots{}, agg: newAggregator(), journal: newJournal(buf, discardLog(), clock.Now),
		proc: fstest.MapFS{}, mode: func() ipMode { return modeOff }, log: discardLog()}
	env := diagDeps{info: &hostInfo{}, stats: c}.env()
	if env.PingDC == nil || env.ProxySecret == nil || env.ProxyDCs == nil || env.AddProbe == nil {
		t.Fatal("the egress checks or the probe hand-off are not wired")
	}
	env.AddProbe(&nodev1.ProbeResult{ProxyId: "P1", Kind: diag.ProbeKindL2, Ok: true})
	c.tick(context.Background(), minuteAt(0, 5))
	c.tick(context.Background(), minuteAt(1, 5))
	recs, err := buf.After(0, 10)
	if err != nil || len(recs) != 1 {
		t.Fatalf("records = %v, %v", recs, err)
	}
	if ps := recs[0].GetStats().GetProbes(); len(ps) != 1 || ps[0].GetProxyId() != "P1" || ps[0].GetKind() != "l2" {
		t.Errorf("probes = %v", ps)
	}
	ids := map[string]bool{}
	for _, ch := range slices.Concat(diag.EgressChecks(), diag.E2EChecks()) {
		ids[ch.ID] = true
	}
	for _, id := range []string{"egress.member", "egress.dc", "egress.me", "e2e.l1", "e2e.l2"} {
		if !ids[id] {
			t.Errorf("check %s missing", id)
		}
	}
}
