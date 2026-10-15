package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/probe"
	"github.com/urbnywrt/postern/internal/socks5"
)

var defaultDCs = []string{"149.154.175.50:443", "149.154.167.51:443", "149.154.175.100:443", "149.154.167.91:443", "91.108.56.130:443"}

// ---------------------------------------------------------------------------
// The parameters of the checks
// ---------------------------------------------------------------------------

func TestHealthCheckDefaults(t *testing.T) {
	want := checkConfig{
		interval:         30 * time.Second,
		timeout:          4 * time.Second,
		failThreshold:    3,
		recoverThreshold: 2,
		dcAddrs:          defaultDCs,
		echoURLs:         []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"},
	}
	for name, hc := range map[string]*edgev1.HealthCheck{
		"nil":      nil,
		"empty":    {},
		"explicit": DefaultHealthCheck(),
	} {
		got, err := newCheckConfig(hc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.interval != want.interval || got.timeout != want.timeout ||
			got.failThreshold != want.failThreshold || got.recoverThreshold != want.recoverThreshold ||
			strings.Join(got.dcAddrs, ",") != strings.Join(want.dcAddrs, ",") ||
			strings.Join(got.echoURLs, ",") != strings.Join(want.echoURLs, ",") {
			t.Errorf("%s: got %+v, want %+v", name, got, want)
		}
	}
}

func TestDefaultHealthCheckIsAFreshMessage(t *testing.T) {
	a := DefaultHealthCheck()
	if a.GetIntervalSeconds() != 30 || a.GetTimeoutSeconds() != 4 || a.GetFailThreshold() != 3 || a.GetRecoverThreshold() != 2 {
		t.Errorf("defaults %v", a)
	}
	a.DcAddrs[0] = "192.0.2.1:1"
	a.EchoUrls[0] = "http://changed.example"
	b := DefaultHealthCheck()
	if b.DcAddrs[0] != defaultDCs[0] || b.EchoUrls[0] != "https://api.ipify.org" {
		t.Errorf("a change of one default message reached the next one: %v", b)
	}
}

func TestHealthCheckOverrides(t *testing.T) {
	got, err := newCheckConfig(&edgev1.HealthCheck{
		IntervalSeconds: 5, TimeoutSeconds: 2, FailThreshold: 7, RecoverThreshold: 4,
		DcAddrs:  []string{"192.0.2.1:443", "dc.example:8443", "[2001:db8::1]:443"},
		EchoUrls: []string{"http://echo.example/ip", "https://echo.example:8443/plain"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.interval != 5*time.Second || got.timeout != 2*time.Second || got.failThreshold != 7 || got.recoverThreshold != 4 {
		t.Errorf("got %+v", got)
	}
	if strings.Join(got.dcAddrs, ",") != "192.0.2.1:443,dc.example:8443,[2001:db8::1]:443" {
		t.Errorf("dc addresses %v", got.dcAddrs)
	}
	if strings.Join(got.echoURLs, ",") != "http://echo.example/ip,https://echo.example:8443/plain" {
		t.Errorf("echo urls %v", got.echoURLs)
	}
}

// ---------------------------------------------------------------------------
// Hysteresis
// ---------------------------------------------------------------------------

func TestHysteresis(t *testing.T) {
	type step struct {
		probe probeResult
		want  string // the status after the probe
	}
	ok, fail := okProbe, failProbe
	cases := []struct {
		name  string
		hc    *edgev1.HealthCheck
		steps []step
	}{
		{"three failures in a row bring a member down", nil, []step{
			{fail, "unknown"}, {fail, "unknown"}, {fail, "down"},
		}},
		{"the first success of a member that is not known is enough", nil, []step{
			{ok, "up"},
		}},
		{"two failures do not bring an up member down", nil, []step{
			{ok, "up"}, {fail, "up"}, {fail, "up"},
		}},
		{"three failures bring an up member down", nil, []step{
			{ok, "up"}, {fail, "up"}, {fail, "up"}, {fail, "down"},
		}},
		{"a success resets the count of failures", nil, []step{
			{ok, "up"}, {fail, "up"}, {fail, "up"}, {ok, "up"}, {fail, "up"}, {fail, "up"}, {ok, "up"},
		}},
		{"a success resets the count of failures of a member that is not known", nil, []step{
			{fail, "unknown"}, {fail, "unknown"}, {ok, "up"}, {fail, "up"}, {fail, "up"},
		}},
		{"a member that is down needs two successes in a row", nil, []step{
			{fail, "unknown"}, {fail, "unknown"}, {fail, "down"},
			{ok, "down"}, {ok, "up"},
		}},
		{"a failure resets the count of successes", nil, []step{
			{fail, "unknown"}, {fail, "unknown"}, {fail, "down"},
			{ok, "down"}, {fail, "down"}, {ok, "down"}, {ok, "up"},
		}},
		{"a member that is down stays down while it fails", nil, []step{
			{fail, "unknown"}, {fail, "unknown"}, {fail, "down"}, {fail, "down"}, {fail, "down"}, {fail, "down"},
			{ok, "down"}, {ok, "up"},
		}},
		{"it goes down again after it was back", nil, []step{
			{fail, "unknown"}, {fail, "unknown"}, {fail, "down"}, {ok, "down"}, {ok, "up"},
			{fail, "up"}, {fail, "up"}, {fail, "down"},
		}},
		{"thresholds of one", &edgev1.HealthCheck{FailThreshold: 1, RecoverThreshold: 1}, []step{
			{ok, "up"}, {fail, "down"}, {ok, "up"}, {fail, "down"}, {fail, "down"}, {ok, "up"},
		}},
		{"thresholds of five and three", &edgev1.HealthCheck{FailThreshold: 5, RecoverThreshold: 3}, []step{
			{fail, "unknown"}, {fail, "unknown"}, {fail, "unknown"}, {fail, "unknown"}, {fail, "down"},
			{ok, "down"}, {ok, "down"}, {ok, "up"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ds := newDialers("a")
			sp := newScriptedProbe()
			r := newTestRouter(t, ds, sp, []*edgev1.Chain{chainOf("c", mem("a", "direct"))}, tc.hc)
			for i, st := range tc.steps {
				sp.set("a", st.probe)
				r.probeRound(context.Background(), false)
				if got := r.Health()[0].GetStatus(); got != st.want {
					t.Fatalf("step %d: status %q, want %q", i+1, got, st.want)
				}
			}
		})
	}
}

func TestNewThresholdsApplyToTheNextProbe(t *testing.T) {
	ds := newDialers("a")
	sp := newScriptedProbe()
	chains := []*edgev1.Chain{chainOf("c", mem("a", "direct"))}
	r := newTestRouter(t, ds, sp, chains, &edgev1.HealthCheck{FailThreshold: 5})
	sp.set("a", okProbe)
	r.probeRound(context.Background(), false)
	sp.set("a", failProbe)
	for range 3 {
		r.probeRound(context.Background(), false)
	}
	if got := r.Health()[0].GetStatus(); got != "up" {
		t.Fatalf("status %q after three failures with a threshold of 5, want up", got)
	}
	if err := r.Apply(chains, &edgev1.HealthCheck{FailThreshold: 3}); err != nil {
		t.Fatal(err)
	}
	r.probeRound(context.Background(), false) // the fourth failure in a row
	if got := r.Health()[0].GetStatus(); got != "down" {
		t.Errorf("status %q after the threshold was lowered to 3, want down", got)
	}
}

func TestProbeDataIsReported(t *testing.T) {
	clk := newFakeClock()
	ds := newDialers("a")
	sp := newScriptedProbe()
	r := newRouter(quiet, deps{newDialer: ds.factory(), probe: sp.probe, exit: sp.exit, clock: clk})
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("a", "direct"))}, nil); err != nil {
		t.Fatal(err)
	}
	probe := func(res probeResult) *edgev1.MemberHealth {
		sp.set("a", res)
		r.probeRound(context.Background(), false)
		return r.Health()[0]
	}

	clk.Advance(time.Minute)
	sp.setExit("a", exitResult{ip: "203.0.113.7"})
	h := probe(probeResult{ok: true, latency: 37*time.Millisecond + 400*time.Microsecond})
	if h.GetStatus() != "up" || h.GetLatencyMs() != 37 || h.GetExitIp() != "203.0.113.7" || h.GetCheckedUnix() != clk.Now().Unix() {
		t.Errorf("after a success: %v (now %d)", h, clk.Now().Unix())
	}

	// The latency is rounded to the nearest millisecond, and a connection that is
	// quicker than that is not reported as no latency at all.
	for _, tc := range []struct {
		d    time.Duration
		want uint32
	}{{37*time.Millisecond + 600*time.Microsecond, 38}, {400 * time.Microsecond, 1}, {2 * time.Second, 2000}} {
		clk.Advance(time.Second)
		if h := probe(probeResult{ok: true, latency: tc.d}); h.GetLatencyMs() != tc.want {
			t.Errorf("a latency of %v is reported as %d ms, want %d", tc.d, h.GetLatencyMs(), tc.want)
		}
	}

	// A probe that brings no exit ip keeps the one that was known; a failing
	// probe moves the time of the last check, and drops the latency only when the
	// member goes down.
	clk.Advance(time.Second)
	h = probe(failProbe)
	if h.GetStatus() != "up" || h.GetExitIp() != "203.0.113.7" || h.GetCheckedUnix() != clk.Now().Unix() || h.GetLatencyMs() != 2000 {
		t.Errorf("after one failure: %v", h)
	}
	probe(failProbe)
	h = probe(failProbe)
	if h.GetStatus() != "down" || h.GetLatencyMs() != 0 || h.GetExitIp() != "203.0.113.7" {
		t.Errorf("after the member went down: %v", h)
	}
}

func TestTransitionsAreLogged(t *testing.T) {
	var lb logBuf
	clk := newFakeClock()
	ds := newDialers("a")
	sp := newScriptedProbe()
	r := newRouter(lb.logger(), deps{newDialer: ds.factory(), probe: sp.probe, exit: sp.exit, clock: clk})
	member := &edgev1.ChainMember{Key: "a", Kind: "socks5", Addr: "127.0.0.1:1", Username: "alice-user", Password: "hunter2-secret"}
	if err := r.Apply([]*edgev1.Chain{chainOf("c1", member), chainOf("c2", member)}, nil); err != nil {
		t.Fatal(err)
	}
	round := func(res probeResult) {
		sp.set("a", res)
		r.probeRound(context.Background(), false)
	}

	// unknown -> down
	failure := probeResult{err: fmt.Errorf("dial %s: %w", "127.0.0.1:1", opErr(syscall.ECONNREFUSED))}
	round(failure)
	round(failure)
	if got := find(lb.records(t), "WARN", "down"); len(got) != 0 {
		t.Fatalf("a warning before the threshold: %v", got)
	}
	round(failure)
	recs := lb.records(t)
	downs := find(recs, "WARN", "is down")
	if len(downs) != 1 {
		t.Fatalf("%d warnings for the member going down, want 1: %s", len(downs), lb.String())
	}
	d := downs[0]
	if d["member"] != "a" || d["from"] != "unknown" || d["to"] != "down" {
		t.Errorf("the warning is %v", d)
	}
	if chains, _ := d["chains"].([]any); len(chains) != 2 || chains[0] != "c1" || chains[1] != "c2" {
		t.Errorf("the warning names the chains %v, want c1 and c2", d["chains"])
	}
	if reason, _ := d["reason"].(string); !strings.Contains(reason, "refused") {
		t.Errorf("the warning gives the reason %q, want the error of the probe", reason)
	}

	// still down: nothing more to say above debug
	round(failure)
	round(failure)
	// down -> up needs two
	round(okProbe)
	if got := find(lb.records(t), "INFO", "is up"); len(got) != 0 {
		t.Fatalf("a message at info before the member is back: %v", got)
	}
	round(okProbe)
	ups := find(lb.records(t), "INFO", "is up")
	if len(ups) != 1 || ups[0]["from"] != "down" || ups[0]["to"] != "up" || ups[0]["member"] != "a" {
		t.Fatalf("the member coming back: %v", ups)
	}

	// up -> down again
	round(failure)
	round(failure)
	round(failure)
	if got := find(lb.records(t), "WARN", "is down"); len(got) != 2 || got[1]["from"] != "up" {
		t.Errorf("the second descent: %v", got)
	}

	// Nothing is said above debug between transitions, and nothing secret is said.
	var loud []string
	for _, rec := range lb.records(t) {
		if rec["level"] != "DEBUG" {
			loud = append(loud, rec["msg"].(string))
		}
	}
	if len(loud) != 3 {
		t.Errorf("messages above debug: %v, want 3 (two descents, one return)", loud)
	}
	for _, secret := range []string{"hunter2-secret", "alice-user"} {
		if strings.Contains(lb.String(), secret) {
			t.Errorf("the log carries %q", secret)
		}
	}

	// A member that is up from the start says so once.
	lb2 := logBuf{}
	r2 := newRouter(lb2.logger(), deps{newDialer: ds.factory(), probe: sp.probe, exit: sp.exit, clock: clk})
	if err := r2.Apply([]*edgev1.Chain{chainOf("c", mem("a", "direct"))}, nil); err != nil {
		t.Fatal(err)
	}
	sp.set("a", probeResult{ok: true, latency: 25 * time.Millisecond})
	sp.setExit("a", exitResult{ip: "203.0.113.7"})
	r2.probeRound(context.Background(), false)
	r2.probeRound(context.Background(), false)
	if ups := find(lb2.records(t), "INFO", "is up"); len(ups) != 1 || ups[0]["from"] != "unknown" {
		t.Errorf("the first success: %v", ups)
	}
	if known := find(lb2.records(t), "INFO", "exit ip is known"); len(known) != 1 || known[0]["exit_ip"] != "203.0.113.7" {
		t.Errorf("the first exit ip: %v", known)
	}
	if got := find(lb2.records(t), "INFO", "exit ip changed"); len(got) != 0 {
		t.Errorf("the first exit ip was reported as a change: %v", got)
	}
}

// ---------------------------------------------------------------------------
// A round of probes
// ---------------------------------------------------------------------------

func TestProbeRoundProbesEveryMemberOnce(t *testing.T) {
	ds := newDialers()
	sp := newScriptedProbe()
	var members []*edgev1.ChainMember
	for i := range 10 {
		members = append(members, mem(fmt.Sprintf("m%02d", i), "direct"))
	}
	r := newTestRouter(t, ds, sp, []*edgev1.Chain{chainOf("c", members...)}, nil)
	r.probeRound(context.Background(), false)
	for _, m := range members {
		if got := sp.count(m.GetKey()); got != 1 {
			t.Errorf("%s was probed %d times, want 1", m.GetKey(), got)
		}
	}
	// A round for the members that were never probed finds none.
	r.probeRound(context.Background(), true)
	if got := sp.total(); got != 10 {
		t.Errorf("%d probes in all, want 10", got)
	}
}

func TestProbeRoundBoundsItsConcurrency(t *testing.T) {
	ds := newDialers()
	sp := newScriptedProbe()
	gate := make(chan struct{})
	sp.hook = func(string) { <-gate }
	var members []*edgev1.ChainMember
	for i := range 100 {
		members = append(members, mem(fmt.Sprintf("m%03d", i), "direct"))
	}
	r := newTestRouter(t, ds, sp, []*edgev1.Chain{chainOf("c", members...)}, nil)

	done := make(chan struct{})
	go func() {
		r.probeRound(context.Background(), false)
		close(done)
	}()
	active := func() int {
		sp.mu.Lock()
		defer sp.mu.Unlock()
		return sp.active
	}
	waitFor(t, func() bool { return active() == maxConcurrentProbes }, "%d probes to run at once", maxConcurrentProbes)
	time.Sleep(20 * time.Millisecond)
	if got := active(); got != maxConcurrentProbes {
		t.Errorf("%d probes run at once, want exactly %d while all of them wait", got, maxConcurrentProbes)
	}
	close(gate)
	select {
	case <-done:
	case <-time.After(ioTimeout):
		t.Fatal("the round did not finish")
	}
	if got := sp.total(); got != 100 {
		t.Errorf("%d members probed, want 100", got)
	}
	if sp.maxActive != maxConcurrentProbes {
		t.Errorf("at most %d probes ran at once, want %d", sp.maxActive, maxConcurrentProbes)
	}
}

func TestProbeRoundSurvivesAPanickingProbe(t *testing.T) {
	var lb logBuf
	ds := newDialers()
	sp := newScriptedProbe()
	sp.hook = func(key string) {
		if key == "boom" {
			panic("a bug in a probe")
		}
	}
	r := newRouter(lb.logger(), deps{newDialer: ds.factory(), probe: sp.probe, exit: sp.exit, clock: newFakeClock()})
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("boom", "direct"), mem("z", "direct"))}, nil); err != nil {
		t.Fatal(err)
	}
	r.probeRound(context.Background(), false)

	got := statuses(r.Health())
	if got["c/a"] != "up" || got["c/z"] != "up" {
		t.Errorf("the members next to the one that panicked: %v", got)
	}
	if got["c/boom"] != "unknown" {
		t.Errorf("the member that panicked is %q, want unknown: a bug is not evidence", got["c/boom"])
	}
	errs := find(lb.records(t), "ERROR", "panic")
	if len(errs) != 1 || errs[0]["member"] != "boom" || !strings.Contains(fmt.Sprint(errs[0]["stack"]), "goroutine") {
		t.Errorf("the log of the panic: %v", errs)
	}
}

func TestAbortedProbesAreNotRecorded(t *testing.T) {
	ds := newDialers("a")
	sp := newScriptedProbe()
	r := newTestRouter(t, ds, sp, []*edgev1.Chain{chainOf("c", mem("a", "direct"))}, nil)

	// The probe itself says it was cut short.
	sp.set("a", probeResult{aborted: true})
	for range 5 {
		r.probeRound(context.Background(), false)
	}
	// A context that ends while the probe runs.
	ctx, cancel := context.WithCancel(context.Background())
	sp.hook = func(string) { cancel() }
	sp.set("a", failProbe)
	for range 5 {
		r.probeRound(ctx, false)
	}
	h := r.Health()[0]
	if h.GetStatus() != "unknown" || h.GetCheckedUnix() != 0 {
		t.Errorf("a probe that was cut short was recorded: %v", h)
	}
}

// The status of a member is recorded before its exit address is asked for, so
// a question of the exit address that is cut short loses the address and keeps
// the status. A member that fails the datacenters is not asked at all.
func TestTheExitAddressIsAskedForAfterTheStatusIsRecorded(t *testing.T) {
	ds := newDialers("a", "b")
	sp := newScriptedProbe()
	r := newTestRouter(t, ds, sp, []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}, nil)
	sp.set("a", okProbe)
	sp.setExit("a", exitResult{aborted: true})
	sp.set("b", failProbe)
	sp.setExit("b", exitResult{ip: "203.0.113.9"})
	r.probeRound(context.Background(), false)
	got := r.Health()
	if got[0].GetStatus() != "up" || got[0].GetExitIp() != "" || got[0].GetCheckedUnix() == 0 {
		t.Errorf("a: %v, want up without an exit address", got[0])
	}
	if got[1].GetExitIp() != "" || sp.exitCount("b") != 0 {
		t.Errorf("b, which reaches no datacenter, was asked for its exit address: %v", got[1])
	}
	if sp.exitCount("a") != 1 {
		t.Errorf("a was asked for its exit address %d times, want once", sp.exitCount("a"))
	}

	// A context that ends while the exit address is asked for: the status is
	// kept, the address is not taken.
	ctx, cancel := context.WithCancel(context.Background())
	sp.setExit("a", exitResult{ip: "203.0.113.7"})
	r3 := newRouter(quiet, deps{newDialer: ds.factory(), probe: sp.probe, clock: newFakeClock(),
		exit: func(ctx context.Context, m *member, c checkConfig) exitResult {
			cancel()
			return sp.exit(ctx, m, c)
		}})
	if err := r3.Apply([]*edgev1.Chain{chainOf("c", mem("a", "direct"))}, nil); err != nil {
		t.Fatal(err)
	}
	r3.probeRound(ctx, false)
	if h := r3.Health()[0]; h.GetStatus() != "up" || h.GetExitIp() != "" {
		t.Errorf("after the context ended in the question of the exit address: %v, want up without an exit address", h)
	}
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

// runHealth runs the loop of r until the test ends, or until the returned
// function is called, which waits for it to return.
func runHealth(t *testing.T, r *Router) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		if err := r.RunHealth(ctx); err != nil {
			t.Errorf("RunHealth: %v", err)
		}
		close(done)
	}()
	stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(ioTimeout):
			t.Error("RunHealth did not return after its context was cancelled")
		}
	}
	t.Cleanup(stop)
	return stop
}

func newLoopRouter(t *testing.T, keys ...string) (*Router, *scriptedProbe, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	sp := newScriptedProbe()
	ds := newDialers(keys...)
	var members []*edgev1.ChainMember
	for _, k := range keys {
		members = append(members, mem(k, "direct"))
	}
	r := newRouter(quiet, deps{clock: clk, newDialer: ds.factory(), probe: sp.probe, exit: sp.exit})
	if err := r.Apply([]*edgev1.Chain{chainOf("c", members...)}, &edgev1.HealthCheck{IntervalSeconds: 30}); err != nil {
		t.Fatal(err)
	}
	return r, sp, clk
}

// A router runs one loop of checks: a second call of RunHealth while the first
// runs is refused at once, and one after the first has returned runs.
func TestRunHealthRefusesASecondLoop(t *testing.T) {
	r, sp, clk := newLoopRouter(t, "a")
	stop := runHealth(t, r)
	waitFor(t, func() bool { return sp.total() == 1 }, "the first round")
	clk.waitTimers(t, 1)

	errc := make(chan error, 1)
	go func() { errc <- r.RunHealth(context.Background()) }()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrHealthRunning) {
			t.Errorf("the second RunHealth: %v, want ErrHealthRunning", err)
		}
	case <-time.After(ioTimeout):
		t.Fatal("the second RunHealth runs next to the first")
	}
	if got := sp.total(); got != 1 {
		t.Errorf("%d probes, want only the first round of the first loop", got)
	}

	stop()
	runHealth(t, r) // the loop may run again once the first has returned
	waitFor(t, func() bool { return sp.total() == 2 }, "the first round of the next loop")
}

func TestRunHealthProbesAtOnceAndEveryInterval(t *testing.T) {
	r, sp, clk := newLoopRouter(t, "a", "b")
	runHealth(t, r)

	waitFor(t, func() bool { return sp.total() == 2 }, "the first round")
	clk.waitTimers(t, 1)

	clk.Advance(29 * time.Second)
	time.Sleep(20 * time.Millisecond)
	if got := sp.total(); got != 2 {
		t.Fatalf("%d probes 29s after the start, want the 2 of the first round", got)
	}
	clk.Advance(time.Second)
	waitFor(t, func() bool { return sp.total() == 4 }, "the second round")
	clk.waitTimers(t, 1)
}

func TestRunHealthCountsTheIntervalFromTheStartOfARound(t *testing.T) {
	r, sp, clk := newLoopRouter(t, "a")
	sp.hook = func(string) { clk.Advance(12 * time.Second) } // a round that takes 12 seconds
	runHealth(t, r)
	waitFor(t, func() bool { return sp.total() == 1 }, "the first round")
	clk.waitTimers(t, 1)

	// 18 seconds are left of the 30 that the round began with.
	clk.Advance(17 * time.Second)
	time.Sleep(20 * time.Millisecond)
	if got := sp.total(); got != 1 {
		t.Fatalf("%d probes 29s after the start, want 1", got)
	}
	clk.Advance(time.Second)
	waitFor(t, func() bool { return sp.total() == 2 }, "the second round, 30s after the first began")
}

func TestRunHealthStartsTheNextRoundAtOnceAfterOneThatTookTooLong(t *testing.T) {
	r, sp, clk := newLoopRouter(t, "a")
	var once sync.Once
	sp.hook = func(string) { once.Do(func() { clk.Advance(45 * time.Second) }) } // the first round is longer than the interval
	runHealth(t, r)
	waitFor(t, func() bool { return sp.total() == 2 }, "the second round to follow the first at once")
	clk.waitTimers(t, 1) // and the third waits for its time
}

func TestRunHealthStopsWithItsContext(t *testing.T) {
	r, sp, clk := newLoopRouter(t, "a")
	stop := runHealth(t, r)
	waitFor(t, func() bool { return sp.total() == 1 }, "the first round")
	clk.waitTimers(t, 1)
	stop()
	if got := clk.timerCount(); got != 0 {
		t.Errorf("%d timers left behind", got)
	}
}

func TestRunHealthDoesNothingWithAContextThatIsDone(t *testing.T) {
	r, sp, _ := newLoopRouter(t, "a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		if err := r.RunHealth(ctx); err != nil {
			t.Errorf("RunHealth: %v", err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(ioTimeout):
		t.Fatal("RunHealth did not return")
	}
	if got := sp.total(); got != 0 {
		t.Errorf("%d probes ran for a context that was done", got)
	}
}

func TestRunHealthStopsInTheMiddleOfARound(t *testing.T) {
	r, sp, _ := newLoopRouter(t, "a")
	entered := make(chan struct{})
	release := make(chan struct{})
	sp.hook = func(string) {
		close(entered)
		<-release
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		if err := r.RunHealth(ctx); err != nil {
			t.Errorf("RunHealth: %v", err)
		}
		close(done)
	}()
	<-entered
	cancel()
	close(release) // the probe ends after the context did
	select {
	case <-done:
	case <-time.After(ioTimeout):
		t.Fatal("RunHealth did not return after its context was cancelled in the middle of a round")
	}
	if h := r.Health()[0]; h.GetStatus() != "unknown" || h.GetCheckedUnix() != 0 {
		t.Errorf("a probe that ended with the context was recorded: %v", h)
	}
}

func TestRunHealthProbesNewMembersAtOnce(t *testing.T) {
	r, sp, clk := newLoopRouter(t, "a")
	runHealth(t, r)
	waitFor(t, func() bool { return sp.total() == 1 }, "the first round")
	clk.waitTimers(t, 1)

	// A member that is added is probed without waiting for the next round, and
	// the ones that are known are left alone until then.
	chains := []*edgev1.Chain{chainOf("c", mem("a", "direct"), mem("b", "direct"))}
	if err := r.Apply(chains, &edgev1.HealthCheck{IntervalSeconds: 30}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return sp.count("b") == 1 }, "the probe of the new member")
	clk.waitTimers(t, 1)
	if got := sp.count("a"); got != 1 {
		t.Errorf("a was probed %d times, want 1", got)
	}
	if got := r.Health()[1].GetStatus(); got != "up" {
		t.Errorf("the new member is %q, want up", got)
	}

	// An Apply that adds nothing does not wake the loop.
	if err := r.Apply(chains, &edgev1.HealthCheck{IntervalSeconds: 30}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if got := sp.total(); got != 2 {
		t.Errorf("%d probes after an Apply that changed nothing, want 2", got)
	}

	// The next full round still waits for its time, from the start of the first.
	clk.Advance(30 * time.Second)
	waitFor(t, func() bool { return sp.total() == 4 }, "the second round")
}

func TestRunHealthFollowsTheCurrentInterval(t *testing.T) {
	r, sp, clk := newLoopRouter(t, "a")
	runHealth(t, r)
	waitFor(t, func() bool { return sp.total() == 1 }, "the first round")
	clk.waitTimers(t, 1)

	chains := []*edgev1.Chain{chainOf("c", mem("a", "direct"))}
	clk.Advance(4 * time.Second)
	if err := r.Apply(chains, &edgev1.HealthCheck{IntervalSeconds: 10}); err != nil {
		t.Fatal(err)
	}
	// The wait that is under way follows the new interval at once, counted from
	// the start of the last round: an edge that ran with the default of 30s
	// before its first chain came does not keep it for that chain's checks.
	clk.waitTimers(t, 1)
	clk.Advance(5 * time.Second)
	time.Sleep(20 * time.Millisecond)
	if got := sp.total(); got != 1 {
		t.Fatalf("%d probes 9s after the first round, want 1", got)
	}
	clk.Advance(time.Second)
	waitFor(t, func() bool { return sp.total() == 2 }, "the second round, 10s after the first began")
	clk.waitTimers(t, 1)
	clk.Advance(10 * time.Second)
	waitFor(t, func() bool { return sp.total() == 3 }, "the third round, 10s after the second")

	// A longer interval lengthens the wait under way the same way.
	if err := r.Apply(chains, &edgev1.HealthCheck{IntervalSeconds: 30}); err != nil {
		t.Fatal(err)
	}
	clk.waitTimers(t, 1)
	clk.Advance(29 * time.Second)
	time.Sleep(20 * time.Millisecond)
	if got := sp.total(); got != 3 {
		t.Fatalf("%d probes 29s after the third round, want 3", got)
	}
	clk.Advance(time.Second)
	waitFor(t, func() bool { return sp.total() == 4 }, "the fourth round, 30s after the third began")
}

// An Apply that changes nothing but the interval does not probe anything by
// itself: it only moves the next round.
func TestRunHealthANewIntervalProbesNothingAtOnce(t *testing.T) {
	r, sp, clk := newLoopRouter(t, "a")
	runHealth(t, r)
	waitFor(t, func() bool { return sp.total() == 1 }, "the first round")
	clk.waitTimers(t, 1)
	clk.Advance(20 * time.Second)
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("a", "direct"))}, &edgev1.HealthCheck{IntervalSeconds: 5}); err != nil {
		t.Fatal(err)
	}
	// 20s have gone since the first round began, more than the new 5: the next
	// round is due at once, and then 5s after it.
	waitFor(t, func() bool { return sp.total() == 2 }, "the round that the new interval made due")
	clk.waitTimers(t, 1)
	time.Sleep(20 * time.Millisecond)
	if got := sp.total(); got != 2 {
		t.Errorf("%d probes, want 2", got)
	}
}

func TestRunHealthWithNothingToProbe(t *testing.T) {
	clk := newFakeClock()
	sp := newScriptedProbe()
	r := newRouter(quiet, deps{clock: clk, probe: sp.probe, exit: sp.exit})
	runHealth(t, r)
	clk.waitTimers(t, 1)
	clk.Advance(30 * time.Second)
	clk.waitTimers(t, 1)
	if got := sp.total(); got != 0 {
		t.Errorf("%d probes of nothing", got)
	}
}

// ---------------------------------------------------------------------------
// The probe: the datacenters
// ---------------------------------------------------------------------------

func newProbeRouter(clk clock) *Router {
	return newRouter(quiet, deps{clock: clk})
}

func TestProbeTriesDatacentersInOrderAndStopsAtTheFirstThatAnswers(t *testing.T) {
	clk := newFakeClock()
	dcs := []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:443", "192.0.2.4:443"}
	d := &fakeDialer{}
	d.fn = func(_ context.Context, addr string) (net.Conn, error) {
		switch addr {
		case dcs[0]:
			return nil, opErr(syscall.ECONNREFUSED)
		case dcs[1]:
			return dcPipe(dcHangsUp), nil // connects, and hangs up: a direct member goes on
		}
		clk.Advance(120 * time.Millisecond) // the time the dial takes
		return dcPipe(dcAnswers), nil
	}
	r := newProbeRouter(clk)
	res := r.probeMember(context.Background(), &member{key: "m", spec: memberSpec{kind: KindDirect}, dialer: d}, checkConfig{timeout: time.Second, dcAddrs: dcs})
	if !res.ok || res.aborted || res.err != nil {
		t.Fatalf("result %+v, want a success", res)
	}
	if res.latency != 120*time.Millisecond {
		t.Errorf("latency %v, want 120ms: the time of the check that passed", res.latency)
	}
	if got := d.calls(); strings.Join(got, ",") != strings.Join(dcs[:3], ",") {
		t.Errorf("dialed %v, want the first three in order", got)
	}
}

func TestProbeClosesTheConnectionOfTheDatacenter(t *testing.T) {
	for _, mode := range []dcMode{dcAnswers, dcWrongNonce} {
		var conn *trackedConn
		d := &fakeDialer{fn: func(context.Context, string) (net.Conn, error) {
			conn = &trackedConn{Conn: dcPipe(mode)}
			return conn, nil
		}}
		r := newProbeRouter(newFakeClock())
		res := r.probeMember(context.Background(), &member{key: "m", dialer: d}, checkConfig{timeout: time.Second, dcAddrs: []string{"192.0.2.1:443"}})
		if res.ok != (mode == dcAnswers) || conn == nil || !conn.closed.Load() {
			t.Errorf("mode %d: result %+v, connection closed: %v", mode, res, conn != nil && conn.closed.Load())
		}
	}
}

func TestProbeWhenNoDatacenterAnswers(t *testing.T) {
	dcs := []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:443"}
	errs := map[string]error{dcs[0]: opErr(syscall.ECONNREFUSED), dcs[1]: context.DeadlineExceeded, dcs[2]: errLastDC}
	d := &fakeDialer{fn: func(_ context.Context, addr string) (net.Conn, error) { return nil, errs[addr] }}
	r := newProbeRouter(newFakeClock())
	res := r.probeMember(context.Background(), &member{key: "m", dialer: d}, checkConfig{
		timeout: time.Second, dcAddrs: dcs, echoURLs: []string{"http://echo.example/ip"},
	})
	if res.ok || res.aborted {
		t.Fatalf("result %+v, want a failure", res)
	}
	if !errors.Is(res.err, errLastDC) || !strings.Contains(res.err.Error(), dcs[2]) {
		t.Errorf("error %v, want the last one, with its datacenter", res.err)
	}
	if got := d.calls(); len(got) != 3 {
		t.Errorf("dialed %v, want every datacenter", got)
	}
}

func TestProbeStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := &fakeDialer{fn: func(ctx context.Context, _ string) (net.Conn, error) {
		cancel()
		return nil, ctx.Err()
	}}
	r := newProbeRouter(newFakeClock())
	res := r.probeMember(ctx, &member{key: "m", dialer: d}, checkConfig{timeout: time.Second, dcAddrs: defaultDCs})
	if !res.aborted || res.ok {
		t.Errorf("result %+v, want one that was cut short", res)
	}
	if got := d.calls(); len(got) != 1 {
		t.Errorf("dialed %v after the context was done", got)
	}
}

// Each datacenter has the timeout of the check, and the check of a member has
// twice that in all: a member that never answers costs a round 8 s and not 20,
// however many datacenters there are, which counts on a node with a hundred
// members.
func TestProbeOfAMemberHasTwiceTheTimeoutInAll(t *testing.T) {
	for name, dial := range map[string]func(context.Context, string) (net.Conn, error){
		"dials that hang":       hang,
		"datacenters that hold": func(context.Context, string) (net.Conn, error) { return dcPipe(dcSilent), nil },
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := &fakeDialer{fn: dial}
				r := newProbeRouter(realClock{})
				start := time.Now()
				res := r.probeMember(context.Background(), &member{key: "m", dialer: d}, checkConfig{timeout: 4 * time.Second, dcAddrs: defaultDCs})
				if res.ok || res.aborted || !errors.Is(res.err, context.DeadlineExceeded) {
					t.Errorf("result %+v, want a failure for want of time", res)
				}
				if got := time.Since(start); got != 8*time.Second {
					t.Errorf("the check took %v, want 2 x 4s", got)
				}
				if got := len(d.calls()); got != 2 {
					t.Errorf("%d datacenters were dialed, want 2", got)
				}
			})
		})
	}
}

// startEarlyAckProxy serves a proxy of one kind on 127.0.0.1 that acknowledges
// every CONNECT at once, before it has connected anywhere, as the SOCKS inbound
// of Xray does, and then hangs up after the first bytes of the client ("hang
// up", its way out failed) or takes them and says nothing ("silent"). It
// returns its address and the number of CONNECTs it took.
func startEarlyAckProxy(t *testing.T, kind, then string) (string, func() int) {
	t.Helper()
	var connects atomic.Int32
	after := func(c net.Conn) {
		if then == "hang up" {
			_, _ = io.ReadFull(c, make([]byte, 64)) // the header of the client...
			_ = c.Close()                           // ...and then the way out fails
			return
		}
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}
	if kind == KindSOCKS5 {
		addr := startSOCKS5(t, func(context.Context, socks5.Request) (net.Conn, error) {
			connects.Add(1)
			near, far := net.Pipe()
			go after(far)
			return near, nil
		})
		return addr, func() int { return int(connects.Load()) }
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.SetDeadline(time.Now().Add(ioTimeout))
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					_ = c.Close()
					return
				}
				connects.Add(1)
				if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					_ = c.Close()
					return
				}
				after(c)
			}()
		}
	}()
	return ln.Addr().String(), func() int { return int(connects.Load()) }
}

// A proxy that acknowledged a CONNECT and then hung up has a broken way out:
// the check of the member stops there for the round, and the other datacenters
// are not dialed through it. A round of such a member costs one dial.
func TestProbeOfAProxyThatHangsUpAfterTheConnectStopsThere(t *testing.T) {
	for _, kind := range []string{KindSOCKS5, KindHTTP} {
		t.Run(kind, func(t *testing.T) {
			addr, connects := startEarlyAckProxy(t, kind, "hang up")
			d, err := NewMemberDialer(&edgev1.ChainMember{Key: "p", Kind: kind, Addr: addr}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			r := newProbeRouter(newFakeClock())
			res := r.probeMember(context.Background(), &member{key: "p", spec: memberSpec{kind: kind}, dialer: d}, checkConfig{timeout: time.Second, dcAddrs: defaultDCs})
			// The end of the stream, or a reset when the proxy closes with the
			// rest of the request unread, as the HTTP one here does.
			closed := errors.Is(res.err, io.EOF) || errors.Is(res.err, syscall.ECONNRESET)
			if res.ok || res.aborted || !closed {
				t.Errorf("result %+v (%v), want a failure: the proxy hung up", res, res.err)
			}
			if n := connects(); n != 1 {
				t.Errorf("%d datacenters were asked for through the proxy, want 1", n)
			}
		})
	}
}

// One round through a proxy that acknowledges every CONNECT and never brings
// an answer costs the member twice the timeout at most, however many
// datacenters there are.
func TestOneRoundThroughASilentEarlyAckProxyCostsTwiceTheTimeoutAtMost(t *testing.T) {
	const timeout = 200 * time.Millisecond
	addr, connects := startEarlyAckProxy(t, KindSOCKS5, "silent")
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "p", Kind: KindSOCKS5, Addr: addr}, timeout)
	if err != nil {
		t.Fatal(err)
	}
	r := newProbeRouter(newFakeClock())
	start := time.Now()
	res := r.probeMember(context.Background(), &member{key: "p", spec: memberSpec{kind: KindSOCKS5}, dialer: d}, checkConfig{timeout: timeout, dcAddrs: defaultDCs})
	elapsed := time.Since(start)
	if res.ok || res.aborted {
		t.Errorf("result %+v, want a failure", res)
	}
	if elapsed < 2*timeout || elapsed > 4*timeout {
		t.Errorf("the round of the member took %v, want 2 x %v", elapsed, timeout)
	}
	if n := connects(); n != 2 {
		t.Errorf("%d datacenters were asked for through the proxy, want 2", n)
	}
}

// The timeout of the check of a datacenter covers the exchange as well: a
// member that connects at once to a datacenter that never answers holds the
// probe for the timeout and no longer.
func TestProbeBoundsTheExchangeByTheTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{fn: func(context.Context, string) (net.Conn, error) { return dcPipe(dcSilent), nil }}
		r := newProbeRouter(realClock{})
		start := time.Now()
		res := r.probeMember(context.Background(), &member{key: "m", dialer: d}, checkConfig{timeout: 4 * time.Second, dcAddrs: defaultDCs[:2]})
		if res.ok || res.aborted || !errors.Is(res.err, context.DeadlineExceeded) {
			t.Errorf("result %+v, want a failure for want of time", res)
		}
		if got := time.Since(start); got != 8*time.Second {
			t.Errorf("two datacenters took %v, want 2 x 4s", got)
		}
	})
}

// errLastDC is an error that a test looks for in the result of a probe.
var errLastDC = errors.New("the last datacenter failed")

// A datacenter passes the check only when it answers req_pq_multi with its
// resPQ: a connection that the member made is not enough (F1).
func TestProbeWantsTheResPQOfTheDatacenter(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode dcMode
		want func(error) bool
	}{
		{"the connection closes after the request", dcHangsUp, func(err error) bool { return errors.Is(err, io.EOF) }},
		{"a resPQ for another nonce", dcWrongNonce, func(err error) bool { return errors.Is(err, probe.ErrBadResPQ) }},
		{"no answer", dcSilent, func(err error) bool { return errors.Is(err, context.DeadlineExceeded) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDialer{fn: func(context.Context, string) (net.Conn, error) { return dcPipe(tc.mode), nil }}
			r := newProbeRouter(newFakeClock())
			res := r.probeMember(context.Background(), &member{key: "m", dialer: d}, checkConfig{
				timeout: 200 * time.Millisecond, dcAddrs: []string{"192.0.2.1:443"},
			})
			if res.ok || res.aborted {
				t.Fatalf("result %+v, want a failure", res)
			}
			if !tc.want(res.err) {
				t.Errorf("error %v", res.err)
			}
			if !strings.Contains(res.err.Error(), "192.0.2.1:443") {
				t.Errorf("error %q does not name the datacenter", res.err)
			}
		})
	}
}

// A probe that gets its answer from a datacenter after others failed is a
// success with nothing of their errors left in it.
func TestProbeThatSucceedsCarriesNoErrorOfTheDatacentersBefore(t *testing.T) {
	dcs := []string{"192.0.2.1:443", "192.0.2.2:443", "192.0.2.3:443"}
	d := &fakeDialer{fn: func(_ context.Context, addr string) (net.Conn, error) {
		switch addr {
		case dcs[0]:
			return nil, opErr(syscall.ECONNREFUSED)
		case dcs[1]:
			return dcPipe(dcWrongNonce), nil
		}
		return dcPipe(dcAnswers), nil
	}}
	r := newProbeRouter(newFakeClock())
	res := r.probeMember(context.Background(), &member{key: "m", dialer: d}, checkConfig{timeout: time.Second, dcAddrs: dcs})
	if !res.ok || res.err != nil {
		t.Errorf("result %+v, want a success without an error", res)
	}
}

// TestMemberThatAcknowledgesTheConnectEarlyGoesDown is the failure of Xray
// that a check of the connection alone does not see: its SOCKS inbound says yes
// to a CONNECT before its outbound has connected, and when the outbound cannot,
// it takes what the client sends and closes. No datacenter is ever reached, and
// the member goes down.
func TestMemberThatAcknowledgesTheConnectEarlyGoesDown(t *testing.T) {
	dc := startFakeDC(t, dcAnswers, nil)
	var asked atomic.Int32
	proxy := startSOCKS5(t, func(context.Context, socks5.Request) (net.Conn, error) {
		asked.Add(1)
		near, far := net.Pipe()
		go func() {
			_, _ = io.ReadFull(far, make([]byte, 64)) // the header of the client...
			_ = far.Close()                           // ...and then the outbound fails
		}()
		return near, nil
	})
	r := newRouter(quiet, deps{clock: newFakeClock()})
	hc := &edgev1.HealthCheck{TimeoutSeconds: 2, DcAddrs: []string{dc.Addr()}, EchoUrls: []string{closedHTTPURL(t)}}
	if err := r.Apply([]*edgev1.Chain{chainOf("c", &edgev1.ChainMember{Key: "xray", Kind: KindSOCKS5, Addr: proxy})}, hc); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		r.probeRound(context.Background(), false)
	}
	if h := r.Health()[0]; h.GetStatus() != "down" {
		t.Errorf("member %v, want down: no datacenter answered through it", h)
	}
	if n := asked.Load(); n != 3 {
		t.Errorf("the proxy was asked %d times, want once a round", n)
	}
	if n := dc.Accepted(); n != 0 {
		t.Errorf("the datacenter took %d connections through a proxy whose outbound fails", n)
	}
}

// A member through which a datacenter answers is up, and its latency is the
// time from the start of the dial to the resPQ.
func TestMemberThatReachesADatacenterIsUpWithTheTimeOfTheResPQ(t *testing.T) {
	clk := newFakeClock()
	dc := startFakeDC(t, dcAnswers, func() { clk.Advance(37 * time.Millisecond) }) // the datacenter takes 37 ms to answer
	const dcAddr = "149.154.167.51:443"
	proxy := startSOCKS5(t, func(ctx context.Context, req socks5.Request) (net.Conn, error) {
		if net.JoinHostPort(req.Host, fmt.Sprint(req.Port)) != dcAddr {
			return nil, opErr(syscall.ECONNREFUSED)
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dc.Addr())
	})
	r := newRouter(quiet, deps{clock: clk})
	hc := &edgev1.HealthCheck{TimeoutSeconds: 2, DcAddrs: []string{dcAddr}, EchoUrls: []string{closedHTTPURL(t)}}
	if err := r.Apply([]*edgev1.Chain{chainOf("c", &edgev1.ChainMember{Key: "s", Kind: KindSOCKS5, Addr: proxy})}, hc); err != nil {
		t.Fatal(err)
	}
	r.probeRound(context.Background(), false)
	if h := r.Health()[0]; h.GetStatus() != "up" || h.GetLatencyMs() != 37 {
		t.Errorf("member %v, want up with a latency of 37 ms", h)
	}
	if n := dc.Accepted(); n != 1 {
		t.Errorf("the datacenter took %d connections, want 1", n)
	}
}

// The status of a member is recorded as soon as the datacenters have spoken:
// the echo services, which can take long, do not hold it back.
func TestStatusIsRecordedBeforeTheExitAddressIsAskedFor(t *testing.T) {
	dc := startFakeDC(t, dcAnswers, nil)
	release := make(chan struct{})
	exit := startEchoHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte("203.0.113.7"))
	})
	clk := newFakeClock()
	r := newRouter(quiet, deps{clock: clk})
	hc := &edgev1.HealthCheck{TimeoutSeconds: 2, DcAddrs: []string{dc.Addr()}, EchoUrls: []string{exit.url()}}
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("m", KindDirect))}, hc); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.probeRound(context.Background(), false)
	}()
	waitFor(t, func() bool { return exit.hits.Load() == 1 }, "the echo service to be asked")
	if h := r.Health()[0]; h.GetStatus() != "up" || h.GetCheckedUnix() != clk.Now().Unix() || h.GetExitIp() != "" {
		t.Errorf("while the exit address is asked for: %v, want the member up already", h)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(ioTimeout):
		t.Fatal("the round did not finish")
	}
	if h := r.Health()[0]; h.GetStatus() != "up" || h.GetExitIp() != "203.0.113.7" {
		t.Errorf("after the round: %v", h)
	}
}

// ---------------------------------------------------------------------------
// The probe: the exit address
// ---------------------------------------------------------------------------

// echoSrv is an HTTP echo service of the exit address.
type echoSrv struct {
	*httptest.Server
	hits atomic.Int32
	mu   sync.Mutex
	last *http.Request
}

func startEchoHTTP(t *testing.T, h http.HandlerFunc) *echoSrv {
	t.Helper()
	e := &echoSrv{}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		e.mu.Lock()
		e.last = r.Clone(context.Background())
		e.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(e.Close)
	return e
}

func (e *echoSrv) url() string { return e.URL + "/ip" }

func answer(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func newDirect(t *testing.T) Dialer {
	t.Helper()
	d, err := NewMemberDialer(mem("d", "direct"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestFetchExitIPAnswers(t *testing.T) {
	long := strings.Repeat("1", 300)
	cases := []struct {
		name    string
		status  int
		body    string
		want    string // the address, "" when the answer must be refused
		wantErr string
	}{
		{"plain address", 200, "203.0.113.7", "203.0.113.7", ""},
		{"with a line feed", 200, "203.0.113.7\n", "203.0.113.7", ""},
		{"with spaces and a carriage return", 200, "  203.0.113.7 \r\n", "203.0.113.7", ""},
		{"ipv6", 200, "2001:db8::5\n", "2001:db8::5", ""},
		{"ipv4 in an ipv6 form", 200, "::ffff:203.0.113.7", "203.0.113.7", ""},
		{"empty", 200, "", "", "address"},
		{"a page", 200, "<html><body>203.0.113.7</body></html>", "", "address"},
		{"more than the address", 200, "203.0.113.7 and more", "", "address"},
		{"two addresses", 200, "203.0.113.7\n198.51.100.1\n", "", "address"},
		{"too long", 200, long, "", "long"},
		{"private", 200, "10.1.2.3", "", "public"},
		{"loopback", 200, "127.0.0.1", "", "public"},
		{"link local", 200, "169.254.1.1", "", "public"},
		{"unspecified", 200, "0.0.0.0", "", "public"},
		{"loopback of ipv6", 200, "::1", "", "public"},
		{"unique local", 200, "fd00::1", "", "public"},
		{"server error", 500, "203.0.113.7", "", "500"},
		{"not found", 404, "203.0.113.7", "", "404"},
		{"no content", 204, "", "", "204"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := startEchoHTTP(t, answer(tc.status, tc.body))
			got, err := fetchExitIP(context.Background(), newDirect(t), e.url(), 2*time.Second, nil)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("got %q, want an error about %q", got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q does not mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("got %q (%v), want %q", got, err, tc.want)
			}
		})
	}
}

func TestFetchExitIPDoesNotFollowRedirects(t *testing.T) {
	target := startEchoHTTP(t, answer(200, "203.0.113.7"))
	redirect := startEchoHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.url(), http.StatusFound)
	})
	if got, err := fetchExitIP(context.Background(), newDirect(t), redirect.url(), 2*time.Second, nil); err == nil {
		t.Errorf("got %q through a redirect, want an error", got)
	}
	if target.hits.Load() != 0 {
		t.Error("the redirect was followed")
	}
}

func TestFetchExitIPIsBoundedByTheTimeout(t *testing.T) {
	slow := startEchoHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	})
	start := time.Now()
	_, err := fetchExitIP(context.Background(), newDirect(t), slow.url(), 150*time.Millisecond, nil)
	if err == nil {
		t.Fatal("got an answer from a server that does not answer")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("the request took %v with a timeout of 150ms", el)
	}
}

func TestFetchExitIPRequest(t *testing.T) {
	// The proxy of the environment is not used: the request goes through the
	// member and nothing else.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	e := startEchoHTTP(t, answer(200, "203.0.113.7"))
	if _, err := fetchExitIP(context.Background(), newDirect(t), e.url(), 2*time.Second, nil); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r := e.last
	if r.Method != http.MethodGet || r.URL.Path != "/ip" {
		t.Errorf("request %s %s, want GET /ip", r.Method, r.URL.Path)
	}
	if r.Header.Get("User-Agent") == "" {
		t.Error("the request has no User-Agent")
	}
	if !r.Close {
		t.Error("the request does not ask for the connection to be closed")
	}
}

func TestFetchExitIPPassesTheNameToTheMember(t *testing.T) {
	// A name is for the member to resolve: a proxy resolves it where it is.
	e := startEchoHTTP(t, answer(200, "203.0.113.7"))
	var asked []string
	d := &fakeDialer{fn: func(ctx context.Context, addr string) (net.Conn, error) {
		asked = append(asked, addr)
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", e.Listener.Addr().String())
	}}
	for _, tc := range []struct{ url, want string }{
		{"http://echo.example/ip", "echo.example:80"},
		{"http://echo.example:8080/ip", "echo.example:8080"},
	} {
		got, err := fetchExitIP(context.Background(), d, tc.url, 2*time.Second, nil)
		if err != nil || got != "203.0.113.7" {
			t.Errorf("%s: got %q (%v)", tc.url, got, err)
		}
		if last := asked[len(asked)-1]; last != tc.want {
			t.Errorf("%s: the member was asked for %q, want %q", tc.url, last, tc.want)
		}
	}
	// https: the port is 443.
	_, _ = fetchExitIP(context.Background(), d, "https://echo.example/ip", time.Second, nil)
	if last := asked[len(asked)-1]; last != "echo.example:443" {
		t.Errorf("https: the member was asked for %q, want echo.example:443", last)
	}
}

func TestFetchExitIPOverTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(answer(200, "203.0.113.7"))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the server logs the handshake that the client refuses
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	url := srv.URL + "/ip"

	got, err := fetchExitIP(context.Background(), newDirect(t), url, 2*time.Second, &tls.Config{RootCAs: pool})
	if err != nil || got != "203.0.113.7" {
		t.Errorf("with the certificate of the server trusted: %q, %v", got, err)
	}
	// With the roots of the system, a certificate of nobody's is refused: the
	// check of the certificate is on.
	if got, err := fetchExitIP(context.Background(), newDirect(t), url, 2*time.Second, nil); err == nil {
		t.Errorf("got %q from a server with an untrusted certificate", got)
	} else if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Errorf("error %q is not about the certificate", err)
	}
}

func TestProbeAsksTheEchoServicesInOrder(t *testing.T) {
	bad := startEchoHTTP(t, answer(500, "oops"))
	junk := startEchoHTTP(t, answer(200, "<html>"))
	good := startEchoHTTP(t, answer(200, "203.0.113.7\n"))
	never := startEchoHTTP(t, answer(200, "198.51.100.1"))
	r := newProbeRouter(newFakeClock())
	cfg := checkConfig{
		timeout:  2 * time.Second,
		echoURLs: []string{bad.url(), junk.url(), good.url(), never.url()},
	}
	res := r.probeExit(context.Background(), &member{key: "m", dialer: newDirect(t)}, cfg)
	if res.aborted || res.ip != "203.0.113.7" || res.err != nil {
		t.Fatalf("result %+v", res)
	}
	for name, e := range map[string]*echoSrv{"bad": bad, "junk": junk, "good": good} {
		if got := e.hits.Load(); got != 1 {
			t.Errorf("%s was asked %d times, want 1", name, got)
		}
	}
	if got := never.hits.Load(); got != 0 {
		t.Errorf("a service after the first that answered was asked %d times", got)
	}
}

func TestProbeWhenNoEchoServiceAnswers(t *testing.T) {
	bad := startEchoHTTP(t, answer(500, "oops"))
	r := newProbeRouter(newFakeClock())
	res := r.probeExit(context.Background(), &member{key: "m", dialer: newDirect(t)}, checkConfig{
		timeout: 2 * time.Second, echoURLs: []string{bad.url(), closedHTTPURL(t)},
	})
	if res.aborted || res.ip != "" || res.err == nil {
		t.Errorf("result %+v, want no exit ip and an error", res)
	}
}

func TestProbeExitStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	asked := 0
	d := &fakeDialer{fn: func(ctx context.Context, _ string) (net.Conn, error) {
		asked++
		cancel()
		return nil, ctx.Err()
	}}
	r := newProbeRouter(newFakeClock())
	res := r.probeExit(ctx, &member{key: "m", dialer: d}, checkConfig{timeout: time.Second, echoURLs: []string{"http://echo.example/ip", "http://echo2.example/ip"}})
	if !res.aborted || asked != 1 {
		t.Errorf("result %+v after %d questions, want one that was cut short after one", res, asked)
	}
}

func closedHTTPURL(t *testing.T) string {
	t.Helper()
	return "http://" + closedAddr(t) + "/ip"
}

func TestExitIPFailureNeverMarksAMemberDown(t *testing.T) {
	var lb logBuf
	dc := startFakeDC(t, dcAnswers, nil).Addr()
	var mode atomic.Value
	mode.Store("fail")
	e := startEchoHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case "fail":
			http.Error(w, "oops", http.StatusInternalServerError)
		default:
			_, _ = w.Write([]byte(mode.Load().(string)))
		}
	})
	r := newRouter(lb.logger(), deps{clock: newFakeClock()})
	hc := &edgev1.HealthCheck{TimeoutSeconds: 2, DcAddrs: []string{dc}, EchoUrls: []string{e.url()}}
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("m", "direct"))}, hc); err != nil {
		t.Fatal(err)
	}
	round := func() *edgev1.MemberHealth {
		r.probeRound(context.Background(), false)
		return r.Health()[0]
	}

	// The echo service fails, round after round: the member is up, with no exit
	// ip, and the warning is given once.
	for i := range 6 {
		if h := round(); h.GetStatus() != "up" || h.GetExitIp() != "" {
			t.Fatalf("round %d: %v, want up without an exit ip", i+1, h)
		}
	}
	if got := find(lb.records(t), "WARN", "exit ip is not known"); len(got) != 1 {
		t.Errorf("%d warnings about the exit ip after 6 rounds, want 1: %s", len(got), lb.String())
	}

	// It answers: the exit ip is known, and that is said once.
	mode.Store("203.0.113.7")
	if h := round(); h.GetExitIp() != "203.0.113.7" || h.GetStatus() != "up" {
		t.Fatalf("after the echo service answered: %v", h)
	}
	round()
	if got := find(lb.records(t), "INFO", "exit ip is known again"); len(got) != 1 {
		t.Errorf("%d messages that the exit ip is known again, want 1", len(got))
	}

	// It answers another address: that is the exit ip now, and it is said.
	mode.Store("198.51.100.4")
	if h := round(); h.GetExitIp() != "198.51.100.4" {
		t.Fatalf("after the exit ip changed: %v", h)
	}
	changed := find(lb.records(t), "INFO", "exit ip changed")
	if len(changed) != 1 || changed[0]["from"] != "203.0.113.7" || changed[0]["to"] != "198.51.100.4" {
		t.Errorf("the change of the exit ip: %v", changed)
	}

	// It fails again: the exit ip that was known is kept, and the warning is
	// given again, once.
	mode.Store("fail")
	for range 5 {
		if h := round(); h.GetExitIp() != "198.51.100.4" || h.GetStatus() != "up" {
			t.Fatalf("with the echo service failing again: %v", h)
		}
	}
	if got := find(lb.records(t), "WARN", "exit ip is not known"); len(got) != 2 {
		t.Errorf("%d warnings about the exit ip in all, want 2", len(got))
	}
}

func TestMemberGoesDownByTheDatacentersOnly(t *testing.T) {
	// The echo service works and no datacenter answers: the member is down.
	e := startEchoHTTP(t, answer(200, "203.0.113.7"))
	dcAddr := closedAddr(t)
	r := newRouter(quiet, deps{clock: newFakeClock()})
	hc := &edgev1.HealthCheck{TimeoutSeconds: 1, DcAddrs: []string{dcAddr}, EchoUrls: []string{e.url()}}
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("m", "direct"))}, hc); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		r.probeRound(context.Background(), false)
	}
	if h := r.Health()[0]; h.GetStatus() != "down" {
		t.Errorf("member %v, want down: no datacenter answers", h)
	}
	if got := e.hits.Load(); got != 0 {
		t.Errorf("the echo service was asked %d times through a member that reaches no datacenter", got)
	}
}

func TestEchoRequestsGoThroughTheMemberAlone(t *testing.T) {
	// The proxies of the environment have no say in how the exit address is found
	// out. (A test cannot look at them through a request: ProxyFromEnvironment
	// reads the environment once, and never proxies a loopback address.)
	cfg := &tls.Config{ServerName: "echo.example"}
	tr := newEchoTransport(newDirect(t), 3*time.Second, cfg)
	if tr.Proxy != nil {
		t.Error("the transport has a proxy")
	}
	if !tr.DisableKeepAlives {
		t.Error("the transport keeps connections alive: each would be left open after its request")
	}
	if tr.TLSClientConfig != cfg {
		t.Error("the transport does not use the TLS configuration it was given")
	}
	if tr.TLSHandshakeTimeout != 3*time.Second || tr.ResponseHeaderTimeout != 3*time.Second {
		t.Errorf("timeouts of the transport: handshake %v, headers %v, want 3s", tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout)
	}
}

// countingDialer counts the bytes that are read from the connections it makes.
type countingDialer struct {
	Dialer
	read atomic.Int64
}

func (d *countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := d.Dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: c, n: &d.read}, nil
}

type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func TestFetchExitIPReadsLittleOfALongAnswer(t *testing.T) {
	// A service that answers with megabytes is not read to its end: an address is at
	// most 45 bytes, and an answer of more than 128 is not one. (The transport reads
	// on after the body is closed, up to 256 KiB, to be able to reuse the connection,
	// which is why the bound is not tighter.)
	e := startEchoHTTP(t, answer(200, strings.Repeat("1", 4<<20)))
	d := &countingDialer{Dialer: newDirect(t)}
	_, err := fetchExitIP(context.Background(), d, e.url(), 2*time.Second, nil)
	if err == nil || !strings.Contains(err.Error(), "long") {
		t.Fatalf("error %v, want one about the length of the answer", err)
	}
	time.Sleep(50 * time.Millisecond) // for the transport to finish what it reads after the close
	if got := d.read.Load(); got > 512<<10 {
		t.Errorf("%d bytes were read of an answer of 4 MiB that is refused after 128", got)
	}
}

// TestHealthLoopEndToEnd runs the loop with the real probe and the real members,
// against a datacenter that goes away and comes back, and an echo service.
func TestHealthLoopEndToEnd(t *testing.T) {
	dc := startFakeDC(t, dcAnswers, nil)
	dcAddr := dc.Addr()
	exit := startEchoHTTP(t, answer(200, "203.0.113.7"))
	clk := newFakeClock()
	r := newRouter(quiet, deps{clock: clk})
	hc := &edgev1.HealthCheck{IntervalSeconds: 30, TimeoutSeconds: 1, DcAddrs: []string{dcAddr}, EchoUrls: []string{exit.url()}}
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("m", "direct"))}, hc); err != nil {
		t.Fatal(err)
	}
	runHealth(t, r)

	member := func() *edgev1.MemberHealth { return r.Health()[0] }
	round := func() { // one more round, and wait for it to be recorded
		t.Helper()
		before := member().GetCheckedUnix()
		clk.waitTimers(t, 1)
		clk.Advance(30 * time.Second)
		waitFor(t, func() bool { return member().GetCheckedUnix() > before }, "the round to be recorded")
	}

	// The first round is at once: the member is up, and then its exit address is
	// known.
	waitFor(t, func() bool { return member().GetStatus() == "up" }, "the member to be up")
	waitFor(t, func() bool { return member().GetExitIp() == "203.0.113.7" }, "the exit address")
	if h := member(); h.GetCheckedUnix() != clk.Now().Unix() { // the clock is a fake one, which a real dial does not move: no latency to see
		t.Errorf("after the first round: %v", h)
	}
	echoAddr := exit.Listener.Addr().String()
	conn, key, err := r.Dial(context.Background(), "c", echoAddr)
	if err != nil || key != "m" {
		t.Fatalf("Dial through an up member: key %q, error %v", key, err)
	}
	_ = conn.Close()

	// The datacenter goes away: two failed rounds are not enough, the third is.
	if err := dc.Close(); err != nil {
		t.Fatal(err)
	}
	round()
	round()
	if got := member().GetStatus(); got != "up" {
		t.Fatalf("after two failed rounds: %q, want up", got)
	}
	round()
	if h := member(); h.GetStatus() != "down" || h.GetLatencyMs() != 0 {
		t.Fatalf("after three failed rounds: %v, want down", h)
	}
	if _, _, err := r.Dial(context.Background(), "c", echoAddr); !errors.Is(err, ErrNoUsableMember) {
		t.Errorf("Dial through a member that is down: %v, want ErrNoUsableMember", err)
	}

	// It comes back: one success is not enough, two are.
	if err := dc.Reopen(); err != nil {
		t.Fatal(err)
	}
	round()
	if got := member().GetStatus(); got != "down" {
		t.Fatalf("after one successful round: %q, want down", got)
	}
	round()
	if got := member().GetStatus(); got != "up" {
		t.Fatalf("after two successful rounds: %q, want up", got)
	}
	conn, key, err = r.Dial(context.Background(), "c", echoAddr)
	if err != nil || key != "m" {
		t.Fatalf("Dial through the member that is back: key %q, error %v", key, err)
	}
	_ = conn.Close()
}
