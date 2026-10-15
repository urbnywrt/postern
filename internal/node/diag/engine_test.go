package diag

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/dockerapi"
	"github.com/urbnywrt/postern/internal/engines"
	"github.com/urbnywrt/postern/internal/engines/telemt"
	"github.com/urbnywrt/postern/internal/node/state"
)

const (
	engToken = "api-token-for-the-engine-0123" // gitleaks:allow (made-up test value)
	engName  = "postern-eng-p1-g2"
)

// testClockAt is a clock that moves only when told to.
type testClockAt struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClockAt) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClockAt) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeAPI is telemt's API: ready or not, and /v1/stats/dcs from a testdata
// file.
type fakeAPI struct {
	mu    sync.Mutex
	ready bool
	dcs   string // testdata file name
}

func (a *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.Header.Get("Authorization") != engToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/v1/health/ready":
		if a.ready {
			_, _ = w.Write([]byte(`{"ok":true,"data":{"ready":true,"status":"ready"}}`))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"ok":true,"data":{"ready":false,"status":"starting","reason":"admission closed"}}`))
	case "/v1/stats/dcs":
		body, err := os.ReadFile(filepath.Join("testdata", a.dcs))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// engineWorld is a node with one proxy p1 on telemt, generation 2 serving,
// its container in a fake Docker, its API an httptest server.
type engineWorld struct {
	t      *testing.T
	clock  *testClockAt
	docker *dockerapi.Fake
	api    *fakeAPI
	store  *state.Store
	proxy  *nodev1.Proxy
	runner *Runner
}

func newEngineWorld(t *testing.T, checks ...string) *engineWorld {
	t.Helper()
	w := &engineWorld{t: t, clock: &testClockAt{now: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}, docker: dockerapi.NewFake(), api: &fakeAPI{ready: true, dcs: "dcs_full.json"}}
	w.docker.Now = w.clock.Now
	srv := httptest.NewServer(w.api)
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	apiPort, _ := strconv.Atoi(port)

	w.store = &state.Store{Paths: state.Paths{Home: t.TempDir()}}
	w.proxy = &nodev1.Proxy{Id: "P1", ListenerId: "L1", Enabled: true, Secret: testSecret, Domain: "example.com",
		Engine: nodev1.Engine_ENGINE_TELEMT, EngineVersion: "3.5.13", UseMiddleProxy: true}
	w.saveDesired()
	rt := state.NewRuntime()
	rt.Instances["P1"] = state.InstanceRecord{Generation: 2, Engine: "telemt", Version: "3.5.13", ListenPort: 20001, APIPort: uint16(apiPort), APIToken: engToken}
	if err := w.store.SaveRuntime(rt); err != nil {
		t.Fatal(err)
	}
	spec := telemt.New().Container(engines.Instance{Proxy: w.proxy, Generation: 2, RunnerImage: "alpine:3.22"})
	if spec.Name != engName {
		t.Fatalf("container name %q", spec.Name)
	}
	if _, err := w.docker.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	if err := w.docker.Start(context.Background(), engName); err != nil {
		t.Fatal(err)
	}
	var cs []Check
	for _, c := range EngineChecks() {
		for _, id := range checks {
			if c.ID == id {
				cs = append(cs, c)
			}
		}
	}
	w.runner = NewRunner(Env{Store: w.store, Docker: w.docker, Now: w.clock.Now,
		Drivers: map[nodev1.Engine]engines.Driver{nodev1.Engine_ENGINE_TELEMT: telemt.New()}}, cs)
	return w
}

func (w *engineWorld) saveDesired() {
	w.t.Helper()
	st, _ := w.store.LoadDesired()
	gen := st.GetGeneration() + 1
	if err := w.store.SaveDesired(&nodev1.NodeState{Generation: gen, Proxies: []*nodev1.Proxy{w.proxy}}); err != nil {
		w.t.Fatal(err)
	}
}

// run is a full run of the node; the one result of the check.
func (w *engineWorld) run() Result {
	w.t.Helper()
	var got []Result
	if err := w.runner.Run(context.Background(), ScopeNode, func(r Result) { got = append(got, r) }); err != nil {
		w.t.Fatal(err)
	}
	if len(got) != 1 || got[0].Target != "proxy:P1" {
		w.t.Fatalf("results = %+v, want one for proxy:P1", got)
	}
	return got[0]
}

func TestEngineContainer(t *testing.T) {
	w := newEngineWorld(t, IDEngineContainer)
	if r := w.run(); r.Status != OK {
		t.Errorf("running: %+v", r)
	}
	w.clock.Advance(time.Minute)
	_ = w.docker.Restarted(engName, 1)
	if r := w.run(); r.Status != Warn || r.Fix != "" {
		t.Errorf("one restart: %+v", r)
	}
	// Three more within the window: a crash loop, with the log, scrubbed.
	_ = w.docker.AppendLogs(engName, "panic: secret "+testSecret+" peer 198.51.100.7:4431\n")
	w.clock.Advance(time.Minute)
	_ = w.docker.Restarted(engName, 3)
	r := w.run()
	if r.Status != Fail || r.Fix != FixRecreateInstance || !strings.Contains(r.Summary, "crash loop") {
		t.Errorf("crash loop: %+v", r)
	}
	if !strings.Contains(r.Evidence, "panic: secret *** peer <ip>:4431") || strings.Contains(r.Evidence, testSecret) || strings.Contains(r.Evidence, "198.51.100.7") {
		t.Errorf("evidence = %q", r.Evidence)
	}
	// Ten quiet minutes later it is fine again.
	w.clock.Advance(11 * time.Minute)
	w.run()
	w.clock.Advance(time.Minute)
	if r := w.run(); r.Status != OK {
		t.Errorf("after the window: %+v", r)
	}

	for _, st := range []string{"paused", "restarting", "dead"} {
		_ = w.docker.SetState(engName, st)
		if r := w.run(); r.Status != Fail || r.Fix != FixRecreateInstance || !strings.Contains(r.Summary, map[string]string{"paused": "paused", "restarting": "loop", "dead": "dead"}[st]) {
			t.Errorf("%s: %+v", st, r)
		}
	}
	_ = w.docker.Remove(context.Background(), engName, true)
	if r := w.run(); r.Status != Fail || !strings.Contains(r.Summary, "missing") {
		t.Errorf("missing: %+v", r)
	}
	if err := w.store.SaveRuntime(state.NewRuntime()); err != nil {
		t.Fatal(err)
	}
	if r := w.run(); r.Status != Fail || !strings.Contains(r.Summary, "no engine serves") {
		t.Errorf("not serving: %+v", r)
	}
}

func TestEngineContainerExited(t *testing.T) {
	w := newEngineWorld(t, IDEngineContainer)
	for i := range 30 {
		_ = w.docker.AppendLogs(engName, fmt.Sprintf("line %d\n", i))
	}
	_ = w.docker.Exit(engName, 2)
	r := w.run()
	if r.Status != Fail || !strings.Contains(r.Summary, "exited (exit code 2)") {
		t.Errorf("exited: %+v", r)
	}
	if !strings.Contains(r.Evidence, "line 29") || strings.Contains(r.Evidence, "line 9\n") {
		t.Errorf("evidence is not the last 20 lines: %q", r.Evidence)
	}
	// A first look at a container that restarted lately warns.
	w2 := newEngineWorld(t, IDEngineContainer)
	_ = w2.docker.Restarted(engName, 2)
	w2.clock.Advance(time.Minute)
	if r := w2.run(); r.Status != Warn {
		t.Errorf("recently restarted: %+v", r)
	}
}

func TestEngineReadyAndDCs(t *testing.T) {
	w := newEngineWorld(t, IDEngineReady)
	if r := w.run(); r.Status != OK {
		t.Errorf("ready: %+v", r)
	}
	w.api.mu.Lock()
	w.api.ready = false
	w.api.mu.Unlock()
	if r := w.run(); r.Status != Fail || r.Fix != FixRecreateInstance || !strings.Contains(r.Evidence, "admission closed") {
		t.Errorf("not ready: %+v", r)
	}

	w = newEngineWorld(t, IDEngineDCs)
	cases := map[string]nodev1.CheckStatus{
		"dcs_full.json": OK, "dcs_idle_endpoints.json": OK, "dcs_partial.json": Warn, "dcs_zero.json": Fail,
		"dcs_source_unavailable.json": Skip, "dcs_feature_disabled.json": Skip, "missing.json": Skip,
	}
	for file, want := range cases {
		w.api.mu.Lock()
		w.api.dcs = file
		w.api.mu.Unlock()
		if r := w.run(); r.Status != want {
			t.Errorf("%s: %v %q, want %v", file, r.Status, r.Summary, want)
		} else if want == Warn && !strings.Contains(r.Evidence, "DC 2: 0 endpoints in use (0 %), writers 0 % covered (fresh 0 %)") {
			t.Errorf("%s evidence: %q", file, r.Evidence)
		}
	}
	// A proxy without the middle proxies is not asked.
	w.proxy.UseMiddleProxy = false
	w.saveDesired()
	if r := w.run(); r.Status != Skip || !strings.Contains(r.Summary, "does not use") {
		t.Errorf("ME off: %+v", r)
	}
}

func TestEngineVersion(t *testing.T) {
	w := newEngineWorld(t, IDEngineVersion)
	w.clock.now = time.Now()
	if r := w.run(); r.Status != OK {
		t.Errorf("as desired: %+v", r)
	}
	w.proxy.EngineVersion = "3.5.14"
	w.saveDesired()
	if r := w.run(); r.Status != OK || !strings.Contains(r.Summary, "under way") {
		t.Errorf("a fresh roll: %+v", r)
	}
	old := time.Now().Add(-11 * time.Minute)
	if err := os.Chtimes(filepath.Join(w.store.Paths.StateDir(), "desired.json"), old, old); err != nil {
		t.Fatal(err)
	}
	if r := w.run(); r.Status != Warn || !strings.Contains(r.Summary, "3.5.14 is desired") {
		t.Errorf("a roll stuck: %+v", r)
	}
}

// telemtLine is a line as telemt writes it, colours and all.
func telemtLine(level, target, msg string) string {
	return "2026-10-07T12:00:00.000001Z \x1b[33m " + level + "\x1b[0m \x1b[2m" + target + "\x1b[0m: " + msg + "\n"
}

func TestEngineLog(t *testing.T) {
	w := newEngineWorld(t, IDEngineLog)
	r := w.run()
	if r.Status != OK {
		t.Errorf("an empty log: %+v", r)
	}
	w.clock.Advance(time.Minute)
	_ = w.docker.AppendLogs(engName,
		telemtLine("INFO", "telemt::maestro", "=== Middle Proxy Mode ===")+
			telemtLine("ERROR", "telemt::maestro::me_startup", "ME startup failed: proxy-secret is unavailable and no saved secret found; secret "+testSecret+" from 198.51.100.7")+
			telemtLine("WARN", "telemt::transport::upstream::connect", "Upstream marked unhealthy fails=9")+
			telemtLine("WARN", "telemt::other", "something nobody knows about 198.51.100.8 "+testSecret))
	r = w.run()
	if r.Status != Fail || r.Fix != FixChangeEgress || !strings.Contains(r.Summary, "getProxySecret fails") {
		t.Errorf("known lines: %+v", r)
	}
	for _, leak := range []string{testSecret, "198.51.100.7", "198.51.100.8", "nobody knows"} {
		if strings.Contains(r.Summary+r.Evidence+r.Hint, leak) {
			t.Errorf("the result quotes %q: %+v", leak, r)
		}
	}
	if !strings.Contains(r.Evidence, "1× the route through the edge's SOCKS port fails") || !strings.Contains(r.Evidence, "1 other warning or error lines") {
		t.Errorf("evidence = %q", r.Evidence)
	}
	// Nothing new: the lines are not read again, the finding holds a while.
	w.clock.Advance(time.Minute)
	r = w.run()
	if r.Status != Fail || !strings.Contains(r.Evidence, "1× getProxySecret") {
		t.Errorf("a run without new lines: %+v", r)
	}
	w.clock.Advance(logWindow)
	if r := w.run(); r.Status != OK {
		t.Errorf("after the window: %+v", r)
	}

	// At most 64 KiB a run: a known line after 100 KiB of others is found by
	// the next run.
	w.clock.Advance(time.Minute)
	filler := strings.Repeat(telemtLine("INFO", "telemt::x", strings.Repeat("x", 200)), 100<<10/230)
	_ = w.docker.AppendLogs(engName, filler+telemtLine("WARN", "telemt::maestro::tls_bootstrap", "TLS-front fetch not ready within timeout; using cache"))
	if r := w.run(); r.Status != OK {
		t.Errorf("the first 64 KiB: %+v", r)
	}
	if r := w.run(); r.Status != Warn {
		t.Errorf("the rest: %+v", r)
	}
}

func TestEngineLogSilentGeneration(t *testing.T) {
	w := newEngineWorld(t, IDEngineLog)
	// A generation made before the log level: its container has no RUST_LOG.
	_ = w.docker.Remove(context.Background(), engName, true)
	spec := telemt.New().Container(engines.Instance{Proxy: w.proxy, Generation: 2, RunnerImage: "alpine:3.22"})
	spec.Env = nil
	if _, err := w.docker.Create(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	_ = w.docker.Start(context.Background(), engName)
	if r := w.run(); r.Status != Skip || !strings.Contains(r.Summary, "silent") {
		t.Errorf("silent generation: %+v", r)
	}
}

// DCsResult judges by the coverage of the writers only, never by the share
// of endpoints that hold a writer nor by the fresh coverage.
func TestDCsResultCoverage(t *testing.T) {
	dc := func(n int, avail, cov float64) engines.DCHealth {
		return engines.DCHealth{DC: n, AvailableEndpoints: 1, AvailablePct: avail, CoveragePct: cov, FreshCoveragePct: cov, HasFreshCoverage: true}
	}
	on := func(dcs ...engines.DCHealth) engines.EngineHealth {
		return engines.EngineHealth{MiddleProxy: true, DCs: dcs}
	}
	stale := dc(3, 100, 100)
	stale.FreshCoveragePct = 60
	old := engines.DCHealth{DC: 5, AvailablePct: 0, CoveragePct: 100} // no fresh coverage in the answer
	cases := []struct {
		name    string
		h       engines.EngineHealth
		status  nodev1.CheckStatus
		summary string
	}{
		{"idle endpoints, full coverage", on(dc(1, 50, 100), dc(2, 70, 100)), OK, "the middle proxies of all 2 datacenters are covered"},
		{"an answer without fresh coverage", on(old), OK, "the middle proxies of all 1 datacenters are covered"},
		{"partial coverage in one DC", on(dc(1, 100, 100), dc(2, 100, 50)), Warn, "some datacenters are not fully covered"},
		{"covered, partly fresh", on(dc(1, 100, 100), stale), OK, "the middle proxies of all 2 datacenters are covered"},
		{"partly fresh and partial coverage", on(stale, dc(2, 100, 50)), Warn, "some datacenters are not fully covered"},
		{"all endpoints in use, no coverage", on(dc(1, 100, 0), dc(2, 100, 0)), Fail, "no middle proxy of any datacenter is available"},
		{"off", engines.EngineHealth{Reason: "feature_disabled", DCs: []engines.DCHealth{dc(1, 0, 0)}}, Skip, "the engine's runtime statistics are off"},
		{"no snapshot", engines.EngineHealth{Reason: "source_unavailable"}, Skip, "the middle proxies have not started yet (no snapshot)"},
	}
	for _, c := range cases {
		r := DCsResult(c.h)
		if r.Status != c.status || r.Summary != c.summary {
			t.Errorf("%s: %v %q, want %v %q", c.name, r.Status, r.Summary, c.status, c.summary)
		}
		if (c.status == Warn || c.status == Fail) && (r.Hint != hintEgressME || !strings.Contains(r.Evidence, "endpoints in use")) {
			t.Errorf("%s: hint %q evidence %q", c.name, r.Hint, r.Evidence)
		}
	}
	if r := DCsResult(on(dc(1, 100, 100), stale)); !strings.Contains(r.Evidence, "DC 3: 1 endpoints in use (100 %), writers 100 % covered (fresh 60 %)") {
		t.Errorf("evidence = %q", r.Evidence)
	}
	if r := DCsResult(on(old)); r.Evidence != "DC 5: 0 endpoints in use (0 %), writers 100 % covered" {
		t.Errorf("evidence without fresh coverage = %q", r.Evidence)
	}
}

func FuzzDCs(f *testing.F) {
	for _, file := range []string{"dcs_full.json", "dcs_idle_endpoints.json", "dcs_partial.json", "dcs_zero.json", "dcs_source_unavailable.json", "dcs_feature_disabled.json"} {
		body, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(body)
	}
	f.Add([]byte(`{"ok":true,"data":{"middle_proxy_enabled":false,"dcs":[{"dc":1,"available_pct":0,"coverage_pct":0}]}}`))
	f.Add([]byte(`{"ok":true,"data":{"middle_proxy_enabled":true,"dcs":[{"dc":1,"available_pct":-5,"coverage_pct":1e309}]}}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		h, err := telemt.ParseDCs(body)
		if err != nil {
			return
		}
		r := DCsResult(h)
		if !h.MiddleProxy && r.Status != Skip {
			t.Fatalf("middle proxies off, status %v", r.Status)
		}
		if r.Status == nodev1.CheckStatus_CHECK_STATUS_UNSPECIFIED {
			t.Fatal("no status")
		}
	})
}
