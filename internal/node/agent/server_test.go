package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/artifacts"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/telemt"
	"github.com/urbnywrt/postern/internal/node/acme"
	"github.com/urbnywrt/postern/internal/node/reconcile"
	"github.com/urbnywrt/postern/internal/node/selfupdate"
	"github.com/urbnywrt/postern/internal/node/selfupdate/selfupdatetest"
	"github.com/urbnywrt/postern/internal/node/state"
	"github.com/urbnywrt/postern/internal/node/trial"
	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/xray"
	"github.com/urbnywrt/postern/internal/release"
	"github.com/urbnywrt/postern/internal/version"
)

// testSecret is a made-up proxy secret, built at run time.
var testSecret = strings.Repeat("a1", 16)

func validState(gen uint64) *nodev1.NodeState {
	return &nodev1.NodeState{
		Generation: gen,
		Settings:   &nodev1.NodeSettings{DefaultChainId: "default", DomainPool: []string{"pool.example.com"}},
		Listeners: []*nodev1.Listener{{
			Id: "L1", Kind: nodev1.ListenerKind_LISTENER_KIND_TLS, BindIp: "0.0.0.0", Port: 443,
			StrangerAction: nodev1.StrangerAction_STRANGER_ACTION_MASK,
		}},
		Proxies: []*nodev1.Proxy{{
			Id: "p1", ListenerId: "L1", Type: nodev1.ProxyType_PROXY_TYPE_FAKETLS, Enabled: true,
			Secret: testSecret, Domain: "a.example.com",
			Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13",
		}},
		Egresses: []*nodev1.Egress{{Id: "direct", Kind: nodev1.EgressKind_EGRESS_KIND_DIRECT}},
		Chains:   []*nodev1.EgressChain{{Id: "default", MemberEgressIds: []string{"direct"}}},
	}
}

func withPolicy(st *nodev1.NodeState, p nodev1.IpPolicy) *nodev1.NodeState {
	st.Settings.IpPolicy = p
	return st
}

// rig is a Service over a temporary POSTERN_HOME, served over mTLS like the
// agent serves it, with a client like the panel's.
type rig struct {
	t      *testing.T
	home   string
	paths  state.Paths
	store  *state.Store
	clock  *testClock
	buf    *Buffer
	j      *journal
	docker *dockerapi.Fake
	arts   *artifacts.Store
	ring   *logRing
	info   *hostInfo
	pki    *testPKI
	svc    *Service
	addr   string
	client nodev1connect.NodeServiceClient

	mu     sync.Mutex
	report *nodev1.StateReport
	edges  map[uint64]versionEdge                                   // what the edge of each generation answers to Health
	roll   func(ctx context.Context, binary string) (uint64, error) // the reconciler's RollEdge (setRoll)
	kicks  atomic.Int32
	trials *fakeTrials

	signer   *selfupdatetest.Signer
	restarts atomic.Int32
	healthy  atomic.Bool
}

// fakeTrials is a trial runner that answers what the test says and records
// what it was asked.
type fakeTrials struct {
	mu     sync.Mutex
	result trial.Result
	runs   []fakeTrialRun
}

type fakeTrialRun struct {
	path, binary string
	trial        engines.Trial
}

func (f *fakeTrials) Run(_ context.Context, binaryPath, binaryName string, t engines.Trial) trial.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, fakeTrialRun{binaryPath, binaryName, t})
	return f.result
}

func (f *fakeTrials) set(res trial.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.result = res
}

func (f *fakeTrials) last() (fakeTrialRun, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.runs) == 0 {
		return fakeTrialRun{}, 0
	}
	return f.runs[len(f.runs)-1], len(f.runs)
}

// versionEdge is the control client of an edge that answers Health only: with
// its generation and its version, or with err.
type versionEdge struct {
	reconcile.EdgeClient // nil: no other call is made
	gen                  uint64
	version              string
	err                  error
}

func (e versionEdge) Health(context.Context) (*edgev1.HealthResponse, error) {
	if e.err != nil {
		return nil, e.err
	}
	return &edgev1.HealthResponse{Generation: e.gen, Listening: true, Version: e.version}, nil
}

// setEdgeVersion makes the edge of generation gen answer Health with version,
// or with err.
func (r *rig) setEdgeVersion(gen uint64, version string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.edges[gen] = versionEdge{gen: gen, version: version, err: err}
}

// edge is the control client of edge generation gen: an edge without a socket
// when the test set none.
func (r *rig) edge(gen uint64) reconcile.EdgeClient {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.edges[gen]; ok {
		return e
	}
	return versionEdge{gen: gen, err: errors.New("dial unix: no such file or directory")}
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{
		t: t, home: t.TempDir(), clock: newTestClock(), docker: dockerapi.NewFake(), pki: newTestPKI(t), edges: map[uint64]versionEdge{},
		trials: &fakeTrials{result: trial.Result{Ran: true, OK: true}},
		signer: selfupdatetest.NewSigner(t),
	}
	r.paths = state.Paths{Home: r.home}
	r.store = &state.Store{Paths: r.paths}
	r.buf = openTestBuffer(t, filepath.Join(r.home, "data", "stats.db"), testNodeID, r.clock)
	r.j = newJournal(r.buf, discardLog(), r.clock.Now)
	r.arts = &artifacts.Store{Root: r.paths.ArtifactsDir()}
	r.ring = newLogRing(100, r.clock.Now)
	r.report = &nodev1.StateReport{}
	osRelease := filepath.Join(r.home, "os-release")
	if err := os.WriteFile(osRelease, []byte("NAME=Test\nPRETTY_NAME=\"Test Linux 1.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.info = &hostInfo{
		osRelease: []string{osRelease},
		addrs:     func() ([]net.Addr, error) { return []net.Addr{ipNet("203.0.113.10/24"), ipNet("10.0.0.1/8")}, nil },
		now:       r.clock.Now,
		log:       discardLog(),
		proc: fstest.MapFS{
			"net/tcp":    {Data: []byte(procNetHeader + procNetLine(0, "00000000:01BB", "0A", 77))},
			"900/comm":   {Data: []byte("caddy\n")},
			"900/cgroup": {Data: []byte("0::/system.slice/caddy.service\n")},
			"900/fd/9":   symlink("socket:[77]"),
		},
		docker: r.docker,
	}
	r.svc = r.newService()
	r.addr = serveTLS(t, r.svc.handler(), r.pki.serverTLS(t))
	r.client = r.pki.client(t, r.addr, r.pki.clientCert, r.pki.clientKey)
	return r
}

func (r *rig) newService() *Service {
	return newService(serviceConfig{
		store:     r.store,
		buffer:    r.buf,
		journal:   r.j,
		status:    r.status,
		trigger:   func() { r.kicks.Add(1) },
		artifacts: r.arts,
		drivers:   map[nodev1.Engine]engines.Driver{nodev1.Engine_ENGINE_TELEMT: telemt.New()},
		providers: map[nodev1.EgressKind]providers.Driver{nodev1.EgressKind_EGRESS_KIND_XRAY_URI: xray.New()},
		trials:    r.trials,
		docker:    r.docker,
		info:      r.info,
		ring:      r.ring,
		edge:      r.edge,
		certs:     &acme.Manager{Paths: r.paths, Now: r.clock.Now},
		log:       discardLog(),
		now:       r.clock.Now,
		installer: &selfupdate.Installer{
			Home: r.home, Arch: runtime.GOARCH, Running: "v0.5.0", Keys: r.signer.Keys, Exec: selfupdatetest.Exec("v0.6.0"),
		},
		home:     r.home,
		healthy:  r.healthy.Load,
		restart:  func() { r.restarts.Add(1) },
		rollEdge: r.rollEdge,
		edgeExec: fileVersionExec,
	})
}

// rollEdge is the reconciler's RollEdge as the test set it (setRoll).
func (r *rig) rollEdge(ctx context.Context, binary string, _ []byte) (uint64, error) {
	r.mu.Lock()
	f := r.roll
	r.mu.Unlock()
	if f == nil {
		return 0, errors.New("no edge roll in this test")
	}
	return f(ctx, binary)
}

func (r *rig) status() *nodev1.StateReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return proto.Clone(r.report).(*nodev1.StateReport)
}

func (r *rig) setReport(rep *nodev1.StateReport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.report = rep
}

func (r *rig) apply(st *nodev1.NodeState) *nodev1.ApplyStateResponse {
	r.t.Helper()
	resp, err := r.client.ApplyState(context.Background(), connect.NewRequest(&nodev1.ApplyStateRequest{State: st}))
	if err != nil {
		r.t.Fatalf("ApplyState: %v", err)
	}
	return resp.Msg
}

func (r *rig) bufferKinds() []string {
	r.t.Helper()
	recs, err := r.buf.After(0, 1000)
	if err != nil {
		r.t.Fatal(err)
	}
	return kindsOf(recs)
}

func TestApplyState(t *testing.T) {
	r := newRig(t)

	got := r.apply(validState(5))
	if !got.GetAccepted() || got.GetGeneration() != 5 || got.GetReason() != "" {
		t.Fatalf("first state: %v", got)
	}
	if st, err := r.store.LoadDesired(); err != nil || st.GetGeneration() != 5 {
		t.Fatalf("stored desired state = %v, %v", st.GetGeneration(), err)
	}
	if n := r.kicks.Load(); n != 1 {
		t.Errorf("reconcile triggered %d times, want 1", n)
	}

	for _, gen := range []uint64{5, 4, 0} {
		got = r.apply(validState(gen))
		if got.GetAccepted() || got.GetReason() != "stale generation" || got.GetGeneration() != 5 {
			t.Errorf("generation %d: %v, want rejected as stale with the node's generation 5", gen, got)
		}
	}

	bad := validState(6)
	bad.Proxies[0].Secret = "zz" + testSecret[2:]
	got = r.apply(bad)
	if got.GetAccepted() || !strings.HasPrefix(got.GetReason(), "invalid node state: ") || got.GetGeneration() != 5 {
		t.Errorf("invalid state: %v", got)
	}
	if strings.Contains(got.GetReason(), testSecret[2:]) {
		t.Error("the reason quotes the secret")
	}
	if got = r.apply(nil); got.GetAccepted() {
		t.Errorf("no state: %v", got)
	}
	if st, _ := r.store.LoadDesired(); st.GetGeneration() != 5 {
		t.Errorf("a rejected state was stored: generation %d", st.GetGeneration())
	}
	if n := r.kicks.Load(); n != 1 {
		t.Errorf("reconcile triggered %d times after rejections, want 1", n)
	}

	if got = r.apply(validState(9)); !got.GetAccepted() || got.GetGeneration() != 9 {
		t.Errorf("newer state: %v", got)
	}
	info, err := r.client.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if info.Msg.GetDesiredGeneration() != 9 {
		t.Errorf("desired generation = %d, want 9", info.Msg.GetDesiredGeneration())
	}

	kinds := strings.Join(r.bufferKinds(), ",")
	if strings.Count(kinds, "event:state_accepted") != 2 || strings.Count(kinds, "event:state_rejected") != 2 {
		t.Errorf("journal = %s, want 2 accepted and 2 rejected (stale ones are not news)", kinds)
	}

	// A new agent process knows the generation it accepted.
	again := r.newService()
	resp, err := again.ApplyState(context.Background(), connect.NewRequest(&nodev1.ApplyStateRequest{State: validState(9)}))
	if err != nil || resp.Msg.GetReason() != "stale generation" {
		t.Errorf("after a restart: %v, %v", resp, err)
	}
}

func receive(t *testing.T, stream *connect.ServerStreamForClient[nodev1.WatchResponse]) *nodev1.WatchResponse {
	t.Helper()
	if !stream.Receive() {
		t.Fatalf("stream ended: %v", stream.Err())
	}
	return stream.Msg()
}

func openWatch(t *testing.T, r *rig, cursor uint64) *connect.ServerStreamForClient[nodev1.WatchResponse] {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	stream, err := r.client.Watch(ctx, connect.NewRequest(&nodev1.WatchRequest{Cursor: cursor}))
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	return stream
}

func TestWatchReplaysFromTheCursorThenStreamsLive(t *testing.T) {
	r := newRig(t)
	r.setReport(&nodev1.StateReport{AppliedGeneration: 3})
	seqs := appendAll(t, r.buf, eventRecord("one"), eventRecord("two"), eventRecord("three"))

	stream := openWatch(t, r, seqs[0])
	first := receive(t, stream)
	if first.GetState().GetAppliedGeneration() != 3 || first.GetSeq() != 0 {
		t.Fatalf("first record = %v, want the current state report, not buffered", first)
	}
	for i, want := range []string{"two", "three"} {
		rec := receive(t, stream)
		if rec.GetEvent().GetKind() != want || rec.GetSeq() != seqs[i+1] {
			t.Fatalf("replayed %v, want %s with seq %d", rec, want, seqs[i+1])
		}
	}
	r.j.event(&nodev1.NodeEvent{Kind: "live", Severity: "info", Message: "now"})
	rec := receive(t, stream)
	if rec.GetEvent().GetKind() != "live" || rec.GetSeq() <= seqs[2] {
		t.Errorf("live record = %v", rec)
	}
}

// The panel waits for the response headers of Watch, which connect sends with
// the first record: a node with nothing buffered still answers at once.
func TestWatchAnswersAtOnce(t *testing.T) {
	r := newRig(t)
	r.setReport(&nodev1.StateReport{AppliedGeneration: 7, Proxies: []*nodev1.ProxyStatus{{ProxyId: "p1", Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING}}})
	start := time.Now()
	stream := openWatch(t, r, 0)
	rec := receive(t, stream)
	if rec.GetState().GetAppliedGeneration() != 7 || len(rec.GetState().GetProxies()) != 1 {
		t.Errorf("first record = %v", rec)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the first record took %v", d)
	}
}

// State reports are buffered when they change; one that says nothing new
// goes to the open streams only, without a sequence number.
func TestWatchStateReportsAreBufferedWhenTheyChange(t *testing.T) {
	r := newRig(t)
	last, _ := r.buf.LastSeq()
	stream := openWatch(t, r, last)
	receive(t, stream) // the opening report

	rep := &nodev1.StateReport{AppliedGeneration: 1, Proxies: []*nodev1.ProxyStatus{{ProxyId: "p1", Phase: nodev1.ProxyPhase_PROXY_PHASE_SERVING}}}
	r.j.state(rep)
	if rec := receive(t, stream); rec.GetSeq() == 0 || !proto.Equal(rec.GetState(), rep) {
		t.Fatalf("first report = %v, want it buffered", rec)
	}
	r.j.state(proto.Clone(rep).(*nodev1.StateReport))
	if rec := receive(t, stream); rec.GetSeq() != 0 || !proto.Equal(rec.GetState(), rep) {
		t.Fatalf("unchanged report = %v, want it live only", rec)
	}
	changed := proto.Clone(rep).(*nodev1.StateReport)
	changed.Proxies[0].Phase = nodev1.ProxyPhase_PROXY_PHASE_FAILED
	r.j.state(changed)
	if rec := receive(t, stream); rec.GetSeq() == 0 || !proto.Equal(rec.GetState(), changed) {
		t.Fatalf("changed report = %v, want it buffered", rec)
	}
	if got := strings.Count(strings.Join(r.bufferKinds(), ","), "state"); got != 2 {
		t.Errorf("buffered state reports = %d, want 2", got)
	}
}

func TestWatchShowsClientAddressesOnlyUnderTheFullPolicy(t *testing.T) {
	r := newRig(t)
	appendAll(t, r.buf, statsRecord(60, "203.0.113.7"))
	stream := openWatch(t, r, 0)
	receive(t, stream)
	if rec := receive(t, stream); rec.GetStats() == nil || len(rec.GetStats().GetIps()) != 0 {
		t.Errorf("without a policy: %v", rec)
	}

	if resp := r.apply(withPolicy(validState(1), nodev1.IpPolicy_IP_POLICY_FULL)); !resp.GetAccepted() {
		t.Fatal(resp)
	}
	receive(t, stream) // state_accepted
	r.j.stats(statsRecord(120, "203.0.113.8").GetStats())
	if rec := receive(t, stream); len(rec.GetStats().GetIps()) != 1 {
		t.Errorf("with the full policy: %v", rec)
	}

	// Turning the policy down also clears what the buffer holds.
	if resp := r.apply(withPolicy(validState(2), nodev1.IpPolicy_IP_POLICY_COUNTRIES)); !resp.GetAccepted() {
		t.Fatal(resp)
	}
	recs, err := r.buf.After(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs {
		if len(rec.GetStats().GetIps()) != 0 {
			t.Errorf("buffered after the policy went down: %v", rec)
		}
	}
}

// A cursor beyond what the buffer holds (a file made again) does not keep the
// new records from the panel.
func TestWatchCursorAheadOfTheBuffer(t *testing.T) {
	r := newRig(t)
	last, _ := r.buf.LastSeq()
	stream := openWatch(t, r, last+100000)
	receive(t, stream)
	r.j.event(&nodev1.NodeEvent{Kind: "after", Severity: "info"})
	if rec := receive(t, stream); rec.GetEvent().GetKind() != "after" {
		t.Errorf("record = %v", rec)
	}
}

func uploadMeta(ref *nodev1.ArtifactRef) *nodev1.UploadArtifactRequest {
	return &nodev1.UploadArtifactRequest{Part: &nodev1.UploadArtifactRequest_Meta{Meta: ref}}
}

func uploadChunks(data []byte, size int) []*nodev1.UploadArtifactRequest {
	var out []*nodev1.UploadArtifactRequest
	for len(data) > 0 {
		n := min(size, len(data))
		out = append(out, &nodev1.UploadArtifactRequest{Part: &nodev1.UploadArtifactRequest_Chunk{Chunk: data[:n]}})
		data = data[n:]
	}
	return out
}

func (r *rig) upload(msgs ...*nodev1.UploadArtifactRequest) (*nodev1.UploadArtifactResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream := r.client.UploadArtifact(ctx)
	for _, m := range msgs {
		if err := stream.Send(m); err != nil {
			break // the server has answered already; CloseAndReceive says why
		}
	}
	resp, err := stream.CloseAndReceive()
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func TestUploadArtifact(t *testing.T) {
	r := newRig(t)
	body := bytes.Repeat([]byte("telemt binary "), 2000)
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	ref := func(version, sha string) *nodev1.ArtifactRef {
		return &nodev1.ArtifactRef{Engine: "telemt", Version: version, Arch: "amd64", Sha256: sha, FileName: "telemt", Binary: "telemt"}
	}
	stored := func(version, sha string) bool {
		return r.arts.Has(artifacts.Ref{Engine: "telemt", Version: version, Arch: "amd64", SHA256: sha, FileName: "telemt", Binary: "telemt"})
	}

	resp, err := r.upload(append([]*nodev1.UploadArtifactRequest{uploadMeta(ref("3.5.13", strings.ToUpper(sha)))}, uploadChunks(body, 4096)...)...)
	if err != nil || !resp.GetStored() || resp.GetSha256() != sha || !resp.GetTried() || !resp.GetUsable() || resp.GetReason() != "" {
		t.Fatalf("upload = %v, %v", resp, err)
	}
	if !stored("3.5.13", sha) {
		t.Error("the artifact is not in the store")
	}
	if run, n := r.trials.last(); n != 1 || run.path != r.arts.BinaryPath(artifacts.Ref{Engine: "telemt", Version: "3.5.13", Arch: "amd64", Binary: "telemt"}) ||
		run.binary != "telemt" || run.trial.ExitCode != 1 || len(run.trial.Args) != 4 {
		t.Errorf("trial runs = %d, last %+v; want one of telemt's trial", n, run)
	}
	if rec, ok := r.arts.Trial(artifacts.Ref{Engine: "telemt", Version: "3.5.13", Arch: "amd64", SHA256: sha, Binary: "telemt"}); !ok || !rec.OK || rec.Image != RunnerImage || !rec.At.Equal(r.clock.Now()) {
		t.Errorf("trial record = %+v, %v", rec, ok)
	}
	if n := r.kicks.Load(); n != 1 {
		t.Errorf("reconcile triggered %d times, want 1 (a missing artifact may have arrived)", n)
	}

	other := sha256.Sum256([]byte("something else"))
	for _, tc := range []struct {
		name    string
		msgs    []*nodev1.UploadArtifactRequest
		code    connect.Code
		message string
		version string
	}{
		{"checksum mismatch", append([]*nodev1.UploadArtifactRequest{uploadMeta(ref("3.5.14", hex.EncodeToString(other[:])))}, uploadChunks(body, 4096)...), connect.CodeInvalidArgument, "checksum", "3.5.14"},
		{"chunk before meta", uploadChunks(body, 4096), connect.CodeInvalidArgument, "meta", "3.5.15"},
		{"nothing at all", nil, connect.CodeInvalidArgument, "meta", "3.5.16"},
		{"meta twice", []*nodev1.UploadArtifactRequest{uploadMeta(ref("3.5.17", sha)), uploadMeta(ref("3.5.17", sha))}, connect.CodeInvalidArgument, "meta", "3.5.17"},
		{"bad reference", []*nodev1.UploadArtifactRequest{uploadMeta(&nodev1.ArtifactRef{Engine: "../x", Version: "1", Arch: "amd64", Sha256: sha})}, connect.CodeInvalidArgument, "invalid", "3.5.18"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := r.upload(tc.msgs...)
			if connect.CodeOf(err) != tc.code || !strings.Contains(err.Error(), tc.message) {
				t.Errorf("upload = %v, %v; want code %v with %q", resp, err, tc.code, tc.message)
			}
			if stored(tc.version, sha) || stored(tc.version, hex.EncodeToString(other[:])) {
				t.Error("stored anyway")
			}
		})
	}

	r.svc.maxUpload = 10000
	_, err = r.upload(append([]*nodev1.UploadArtifactRequest{uploadMeta(ref("3.5.19", sha))}, uploadChunks(body, 4096)...)...)
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Errorf("too large: %v, want resource exhausted", err)
	}
	if stored("3.5.19", sha) {
		t.Error("an upload over the limit was stored")
	}
	r.svc.maxUpload = defaultMaxUpload

	// The binary name defaults to the engine's.
	noBinary := ref("3.5.20", sha)
	noBinary.Binary = ""
	if resp, err := r.upload(append([]*nodev1.UploadArtifactRequest{uploadMeta(noBinary)}, uploadChunks(body, 65536)...)...); err != nil || !resp.GetStored() {
		t.Errorf("upload without a binary name = %v, %v", resp, err)
	}
	if !stored("3.5.20", sha) {
		t.Error("stored under another name")
	}
	if entries, _ := os.ReadDir(r.arts.Root); slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return strings.HasPrefix(e.Name(), ".stage-") }) {
		t.Errorf("scratch left in the store: %v", entries)
	}
}

func TestGetInfo(t *testing.T) {
	r := newRig(t)
	r.setReport(&nodev1.StateReport{AppliedGeneration: 4})
	if resp := r.apply(validState(5)); !resp.GetAccepted() {
		t.Fatal(resp)
	}
	sha := putArtifact(t, r.arts, "telemt", "3.5.13", "amd64", []byte("a binary"))

	resp, err := r.client.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	want := &nodev1.GetInfoResponse{
		AgentVersion:      version.Version,
		EdgeVersion:       "", // no edge yet
		Arch:              runtime.GOARCH,
		Os:                "Test Linux 1.0",
		PublicIps:         []string{"203.0.113.10"},
		AppliedGeneration: 4,
		DesiredGeneration: 5,
		Artifacts:         []*nodev1.ArtifactRef{{Engine: "telemt", Version: "3.5.13", Arch: "amd64", Sha256: sha, Binary: "telemt", State: "untried"}},
		PortOwners:        []*nodev1.PortOwner{{Bind: "0.0.0.0", Port: 443, Owner: "caddy (pid 900)"}},
		// The list of this build, as node.proto documents it (Ruling 43),
		// sorted.
		Capabilities: []string{
			"artifact-direct", "artifact-trial", "diagnostics", "dns-forwarder", "edge-roll", "edge-roll-nonce", "edge-version", "egress-interface",
			"egress-psiphon-core", "egress-warp", "egress-xray", "engine-mtg", "faketls", "last-error", "me-routing",
			"restart-nonce", "rollout-status", "stats-v2", "update-edge", "update-self", "web-diagnostics",
		},
		Binaries: &nodev1.NodeBinaries{}, // nothing installed in bin/
		Healthy:  false,
		Warnings: release.KeyWarnings(),
		// The plain management listener: the TCP source, IP only (R6-1).
		PeerAddr: "127.0.0.1",
	}
	if !slices.IsSorted(want.Capabilities) {
		t.Errorf("the expected capabilities are not sorted: %v", want.Capabilities)
	}
	if !proto.Equal(resp.Msg, want) {
		t.Errorf("GetInfo = %v\nwant %v", resp.Msg, want)
	}

	// healthy is the marker of this process; binaries what bin/ holds.
	r.healthy.Store(true)
	bin := filepath.Join(r.home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// v0.9.0 has its signature kept beside it (UpdateSelf or install.sh);
	// a signature without its binary is not a signed version.
	for _, name := range []string{"postern-node-v0.10.0", "postern-node-v0.9.0", ".postern-node-v0.9.0.minisig", ".postern-node-v0.8.0.minisig"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("postern-node-v0.10.0", filepath.Join(bin, "current")); err != nil {
		t.Fatal(err)
	}
	resp, err = r.client.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	wantBin := &nodev1.NodeBinaries{Versions: []string{"v0.9.0", "v0.10.0"}, Current: "v0.10.0", SignedVersions: []string{"v0.9.0"}}
	if !resp.Msg.GetHealthy() || !proto.Equal(resp.Msg.GetBinaries(), wantBin) {
		t.Errorf("GetInfo: healthy %v, binaries %v; want true, %v", resp.Msg.GetHealthy(), resp.Msg.GetBinaries(), wantBin)
	}
}

// The version of the edge in GetInfo is the one the edge that carries the
// traffic reports, not the agent's: an edge keeps the binary it was started
// with when the agent is updated (Ruling 38). It is empty when nobody can say.
func TestGetInfoReportsTheVersionOfTheRunningEdge(t *testing.T) {
	r := newRig(t)
	edgeVersion := func() string {
		t.Helper()
		resp, err := r.client.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg.GetEdgeVersion()
	}
	r.setEdgeVersion(2, "v0.1.0", nil)
	r.setEdgeVersion(3, "v0.1.1", nil)
	if got := edgeVersion(); got != "" {
		t.Errorf("edge version without an edge = %q, want empty", got)
	}

	rt := state.NewRuntime()
	rt.EdgeGeneration = 2
	if err := r.store.SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	if got := edgeVersion(); got != "v0.1.0" {
		t.Errorf("edge version = %q, want v0.1.0, what edge g2 reports", got)
	}
	// The edge of the runtime record is the one that is asked.
	rt.EdgeGeneration = 3
	if err := r.store.SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	if got := edgeVersion(); got != "v0.1.1" {
		t.Errorf("edge version = %q, want v0.1.1, what edge g3 reports", got)
	}
	// An edge that does not answer, and one older than the field.
	r.setEdgeVersion(3, "", errors.New("dial unix: connection refused"))
	if got := edgeVersion(); got != "" {
		t.Errorf("edge version of an edge that does not answer = %q, want empty", got)
	}
	r.setEdgeVersion(3, "", nil)
	if got := edgeVersion(); got != "" {
		t.Errorf("edge version of an edge that does not say = %q, want empty", got)
	}
}

// The capability probe-sources says that the edge exempts the panel's probes:
// it is the edge that does, so it is reported only while the running edge is
// of the agent's version (Ruling 38), and kept in the sorted order.
func TestGetInfoProbeSourcesFollowsTheEdgeVersion(t *testing.T) {
	r := newRig(t)
	caps := func() []string {
		t.Helper()
		resp, err := r.client.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.IsSorted(resp.Msg.GetCapabilities()) {
			t.Errorf("capabilities %v, want them sorted", resp.Msg.GetCapabilities())
		}
		return resp.Msg.GetCapabilities()
	}
	if slices.Contains(caps(), capProbeSources) {
		t.Error("probe-sources without an edge")
	}
	rt := state.NewRuntime()
	rt.EdgeGeneration = 2
	if err := r.store.SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	r.setEdgeVersion(2, version.Version+"-older", nil)
	if slices.Contains(caps(), capProbeSources) {
		t.Error("probe-sources with an edge of another version")
	}
	r.setEdgeVersion(2, version.Version, nil)
	if !slices.Contains(caps(), capProbeSources) {
		t.Error("no probe-sources with an edge of the agent's version")
	}
	r.setEdgeVersion(2, "", errors.New("dial unix: connection refused"))
	if slices.Contains(caps(), capProbeSources) {
		t.Error("probe-sources with an edge that does not answer")
	}
}

// The edge's listeners and the engines' ports are attributed to the agent's
// containers when the process behind them cannot be seen.
func TestGetInfoAttributesPortsOfItsContainers(t *testing.T) {
	r := newRig(t)
	if resp := r.apply(validState(5)); !resp.GetAccepted() {
		t.Fatal(resp)
	}
	rt := state.NewRuntime()
	rt.EdgeGeneration = 2
	rt.Ports[state.EnginePortKey("p1", 3, state.PortListen)] = 20000
	rt.Ports[state.EnginePortKey("p1", 3, state.PortSocks)] = 30000
	rt.Instances["p1"] = state.InstanceRecord{Generation: 3, ListenPort: 20000, SocksPort: 30000}
	if err := r.store.SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	addTestContainer(t, r.docker, "postern-edge-g2", managedLabels("edge", "edge", 2), true)
	addTestContainer(t, r.docker, "postern-eng-p1-g3", managedLabels("engine", "p1", 3), true)
	r.info.proc = fstest.MapFS{"net/tcp": {Data: []byte(procNetHeader +
		procNetLine(0, "00000000:01BB", "0A", 1) + procNetLine(1, "0100007F:4E20", "0A", 2) + procNetLine(2, "0100007F:7530", "0A", 3))}}

	resp, err := r.client.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	got := ownersMap(resp.Msg.GetPortOwners())
	want := map[string]string{"0.0.0.0:443": "postern-edge-g2", "127.0.0.1:20000": "postern-eng-p1-g3", "127.0.0.1:30000": "postern-edge-g2"}
	if !mapsEqual(got, want) {
		t.Errorf("owners = %v, want %v", got, want)
	}
}

func (r *rig) logLines(target string, tail uint32) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := r.client.StreamLogs(ctx, connect.NewRequest(&nodev1.StreamLogsRequest{Target: target, Tail: tail}))
	if err != nil {
		return nil, err
	}
	var lines []string
	for stream.Receive() {
		lines = append(lines, stream.Msg().GetStream()+":"+stream.Msg().GetLine())
		if stream.Msg().GetTsUnixNano() == 0 {
			r.t.Errorf("a line without a time: %v", stream.Msg())
		}
	}
	return lines, stream.Err()
}

func TestStreamLogs(t *testing.T) {
	r := newRig(t)
	_, _ = r.ring.Write([]byte("line one\nline two\nline three\n"))
	rt := state.NewRuntime()
	rt.EdgeGeneration = 2
	rt.Instances["P1"] = state.InstanceRecord{Generation: 3}
	if err := r.store.SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	addTestContainer(t, r.docker, "postern-edge-g2", managedLabels("edge", "edge", 2), true)
	addTestContainer(t, r.docker, "postern-eng-p1-g3", managedLabels("engine", "P1", 3), true)
	if err := r.docker.AppendLogs("postern-edge-g2", "edge: ready\nedge: drained\n"); err != nil {
		t.Fatal(err)
	}
	if err := r.docker.AppendLogs("postern-eng-p1-g3", "telemt up\n"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		target string
		tail   uint32
		want   []string
	}{
		{"agent", 2, []string{"stderr:line two", "stderr:line three"}},
		{"agent", 0, []string{"stderr:line one", "stderr:line two", "stderr:line three"}},
		{"edge", 0, []string{"combined:edge: ready", "combined:edge: drained"}},
		{"edge", 1, []string{"combined:edge: drained"}},
		{"proxy:P1", 0, []string{"combined:telemt up"}},
	} {
		got, err := r.logLines(tc.target, tc.tail)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("%s tail %d = %q, %v; want %q", tc.target, tc.tail, got, err, tc.want)
		}
	}
	for _, tc := range []struct {
		target string
		code   connect.Code
	}{
		{"proxy:p2", connect.CodeNotFound},
		{"proxy:", connect.CodeInvalidArgument},
		{"nonsense", connect.CodeInvalidArgument},
		{"", connect.CodeInvalidArgument},
	} {
		if _, err := r.logLines(tc.target, 0); connect.CodeOf(err) != tc.code {
			t.Errorf("%q: %v, want %v", tc.target, err, tc.code)
		}
	}

	// No edge yet.
	if err := r.store.SaveRuntime(state.NewRuntime()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.logLines("edge", 0); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("edge without one: %v", err)
	}
}

func TestStreamLogsFollowsTheAgent(t *testing.T) {
	r := newRig(t)
	_, _ = r.ring.Write([]byte("before\n"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := r.client.StreamLogs(ctx, connect.NewRequest(&nodev1.StreamLogsRequest{Target: "agent", Tail: 1, Follow: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	if !stream.Receive() || stream.Msg().GetLine() != "before" {
		t.Fatalf("first line: %v %v", stream.Msg(), stream.Err())
	}
	_, _ = r.ring.Write([]byte("after\n"))
	if !stream.Receive() || stream.Msg().GetLine() != "after" {
		t.Fatalf("followed line: %v %v", stream.Msg(), stream.Err())
	}
}

// Only the panel's client certificate opens the node. In TLS 1.3 the client's
// handshake can complete before the server has checked the client
// certificate, so every case makes a real call.
func TestOnlyThePanelCertificateIsAccepted(t *testing.T) {
	r := newRig(t)
	if _, err := r.client.GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{})); err != nil {
		t.Fatalf("the panel's client: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(r.pki.ca.Cert)
	noCert := clientWithTLS(t, r.addr, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: strings.ToLower(testNodeID) + ".internal"})
	other := newTestPKI(t)
	for _, tc := range []struct {
		name   string
		client nodev1connect.NodeServiceClient
	}{
		{"no client certificate", noCert},
		{"a client certificate of another CA", r.pki.client(t, r.addr, other.clientCert, other.clientKey)},
		{"the node's own certificate", r.pki.client(t, r.addr, r.pki.nodeCert, r.pki.nodeKey)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := tc.client.GetInfo(ctx, connect.NewRequest(&nodev1.GetInfoRequest{}))
			if err == nil {
				t.Fatal("GetInfo succeeded")
			}
			_, err = tc.client.ApplyState(ctx, connect.NewRequest(&nodev1.ApplyStateRequest{State: validState(99)}))
			if err == nil {
				t.Fatal("ApplyState succeeded")
			}
		})
	}
	if st, _ := r.store.LoadDesired(); st != nil {
		t.Errorf("a refused client changed the state: %v", st.GetGeneration())
	}
}

// The capabilities are reported sorted, as node.proto documents them.
func TestCapabilitiesAreSorted(t *testing.T) {
	if !slices.IsSorted(capabilities) {
		t.Errorf("capabilities = %v, want them sorted", capabilities)
	}
	for _, c := range []string{"engine-mtg", "rollout-status"} {
		if !slices.Contains(capabilities, c) {
			t.Errorf("capabilities lack %s", c)
		}
	}
}
