package diag

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/internal/node/state"
)

const testSecret = "0123456789abcdef0123456789abcdef" // gitleaks:allow (made-up test value)

// testStore is a store with two proxies: p1 on listener L1 with chain C1 (and
// the scope chain C3), p2 on L2 with the default chain C2.
func testStore(t *testing.T) *state.Store {
	t.Helper()
	st := &state.Store{Paths: state.Paths{Home: t.TempDir()}}
	desired := &nodev1.NodeState{
		Generation: 3,
		Settings:   &nodev1.NodeSettings{DefaultChainId: "C2"},
		Listeners: []*nodev1.Listener{
			{Id: "L1", BindIp: "0.0.0.0", Port: 443},
			{Id: "L2", BindIp: "203.0.113.10", Port: 8443},
		},
		Proxies: []*nodev1.Proxy{
			{Id: "p1", ListenerId: "L1", Secret: testSecret, Domain: "example.com", EgressChainId: "C1", EgressScopeChains: map[string]string{"me": "C3"}},
			{Id: "p2", ListenerId: "L2", Secret: "fedcba9876543210fedcba9876543210", Domain: "example.org"}, // gitleaks:allow (made-up test value)
		},
	}
	if err := st.SaveDesired(desired); err != nil {
		t.Fatal(err)
	}
	return st
}

func targetsCheck(id string, targets ...string) Check {
	return Check{ID: id, Layer: LayerHost, Run: func(_ context.Context, env *Env) []Result {
		var out []Result
		for _, tg := range targets {
			if env.Wants(tg) {
				out = append(out, Result{Target: tg, Status: OK, Summary: "fine"})
			}
		}
		return out
	}}
}

func collect(t *testing.T, r *Runner, scope string) ([]Result, error) {
	t.Helper()
	var out []Result
	err := r.Run(context.Background(), scope, func(res Result) { out = append(out, res) })
	return out, err
}

func TestRunScopes(t *testing.T) {
	all := []string{"", "listener:L1", "listener:L2", "proxy:p1", "proxy:p2", "member:C1/a", "member:C2/b", "member:C3/c"}
	// A check that ignores the scope is filtered by the runner all the same.
	careless := Check{ID: "careless", Layer: LayerHost, Run: func(context.Context, *Env) []Result {
		return []Result{{Target: "proxy:p2", Status: OK}, {Target: "proxy:p1", Status: OK}}
	}}
	r := NewRunner(Env{Store: testStore(t)}, []Check{targetsCheck("t", all...), careless})

	got, err := collect(t, r, "proxy:p1")
	if err != nil {
		t.Fatal(err)
	}
	var targets []string
	for _, res := range got {
		targets = append(targets, res.ID+"@"+res.Target)
	}
	slices.Sort(targets)
	want := []string{"careless@proxy:p1", "t@", "t@listener:L1", "t@member:C1/a", "t@member:C3/c", "t@proxy:p1"}
	if !slices.Equal(targets, want) {
		t.Errorf("proxy:p1 targets = %v, want %v", targets, want)
	}
	// p2 has no chain of its own: the node's default.
	got, _ = collect(t, r, "proxy:p2")
	if n := len(got); n != 5 { // "", L2, p2, C2/b, careless p2
		t.Errorf("proxy:p2 gave %d results: %v", n, got)
	}
	got, _ = collect(t, r, "node")
	if len(got) != len(all)+2 {
		t.Errorf("node gave %d results, want %d", len(got), len(all)+2)
	}
	for _, s := range []string{"proxy:nope", "proxy:", "bogus", ""} {
		if _, err := collect(t, r, s); !errors.Is(err, ErrScope) {
			t.Errorf("scope %q: err = %v, want ErrScope", s, err)
		}
	}
}

func TestRunBusy(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	block := Check{ID: "block", Run: func(ctx context.Context, _ *Env) []Result {
		close(started)
		<-release
		return []Result{{Status: OK}}
	}}
	r := NewRunner(Env{}, []Check{block})
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background(), ScopeNode, func(Result) {}) }()
	<-started
	if err := r.Run(context.Background(), ScopeNode, func(Result) {}); !errors.Is(err, ErrBusy) {
		t.Errorf("second run: err = %v, want ErrBusy", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Once it is over, a run goes again.
	r.checks = []Check{targetsCheck("t", "")}
	if _, err := collect(t, r, ScopeNode); err != nil {
		t.Errorf("a run after the first: %v", err)
	}
}

func TestRunOverallDeadline(t *testing.T) {
	waits := func(id string) Check {
		return Check{ID: id, Run: func(ctx context.Context, _ *Env) []Result {
			<-ctx.Done()
			return []Result{{Status: Warn, Summary: "stopped"}}
		}}
	}
	r := NewRunner(Env{}, []Check{waits("a"), waits("b"), waits("c")})
	r.slots, r.overall = 1, 200*time.Millisecond
	start := time.Now()
	got, err := collect(t, r, ScopeNode)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the run took %s past its limit of 200ms", d)
	}
	if len(got) != 3 {
		t.Fatalf("results = %v, want one for each check", got)
	}
	byID := map[string]Result{}
	for _, res := range got {
		byID[res.ID] = res
	}
	if byID["a"].Status != Warn {
		t.Errorf("a = %+v, want what it returned when its time was up", byID["a"])
	}
	for _, id := range []string{"b", "c"} {
		if byID[id].Status != Skip {
			t.Errorf("%s = %+v, want skip: never started", id, byID[id])
		}
	}
}

func TestRunCheckTimeoutAndPanic(t *testing.T) {
	hang := Check{ID: "hang", Timeout: 50 * time.Millisecond, Run: func(context.Context, *Env) []Result {
		time.Sleep(2 * time.Second) // ignores its context
		return nil
	}}
	boom := Check{ID: "boom", Run: func(context.Context, *Env) []Result { panic("boom") }}
	r := NewRunner(Env{}, []Check{hang, boom})
	got, err := collect(t, r, ScopeNode)
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range got {
		switch res.ID {
		case "hang":
			if res.Status != Skip {
				t.Errorf("hang = %+v, want skip", res)
			}
		case "boom":
			if res.Status != Fail {
				t.Errorf("boom = %+v, want fail", res)
			}
		}
	}
}

func TestRunStreamsAsTheyFinish(t *testing.T) {
	slow := Check{ID: "slow", Run: func(context.Context, *Env) []Result {
		time.Sleep(300 * time.Millisecond)
		return []Result{{Status: OK}}
	}}
	fast := Check{ID: "fast", Run: func(context.Context, *Env) []Result { return []Result{{Status: OK}} }}
	r := NewRunner(Env{}, []Check{slow, fast})
	var order []string
	var at []time.Duration
	start := time.Now()
	if err := r.Run(context.Background(), ScopeNode, func(res Result) {
		order = append(order, res.ID)
		at = append(at, time.Since(start))
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(order, []string{"fast", "slow"}) {
		t.Errorf("order = %v, want the fast one first", order)
	}
	if at[0] > 200*time.Millisecond {
		t.Errorf("the fast result came after %s: not streamed", at[0])
	}
}

func TestRunSixteenAtATime(t *testing.T) {
	var cur, peak atomic.Int32
	c := func(id string) Check {
		return Check{ID: id, Run: func(context.Context, *Env) []Result {
			n := cur.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(40 * time.Millisecond)
			cur.Add(-1)
			return []Result{{Status: OK}}
		}}
	}
	var checks []Check
	for i := range 40 {
		checks = append(checks, c(string(rune('a'+i%26))+string(rune('0'+i/26))))
	}
	got, err := collect(t, NewRunner(Env{}, checks), ScopeNode)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 40 {
		t.Errorf("%d results, want 40", len(got))
	}
	if p := peak.Load(); p != Slots {
		t.Errorf("at most %d checks ran at a time, want %d", p, Slots)
	}
}

func TestFinalizeScrubsAndBounds(t *testing.T) {
	r := NewRunner(Env{Store: testStore(t)}, []Check{{ID: "x", Layer: LayerHost, Run: func(context.Context, *Env) []Result {
		long := make([]byte, 3000)
		for i := range long {
			long[i] = 'a'
		}
		return []Result{
			{Status: OK, Summary: "secret " + testSecret + " from 198.51.100.7", Evidence: "dropped for ok"},
			{Target: "proxy:p1", Status: Fail, Summary: string(long), Evidence: string(long)},
		}
	}}})
	got, err := collect(t, r, ScopeNode)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Summary != "secret *** from <ip>" || got[0].Evidence != "" {
		t.Errorf("ok result = %+v", got[0])
	}
	if len(got[1].Summary) != MaxSummary || len(got[1].Evidence) != MaxEvidence {
		t.Errorf("summary %d, evidence %d bytes, want %d and %d", len(got[1].Summary), len(got[1].Evidence), MaxSummary, MaxEvidence)
	}
	if got[0].Layer != LayerHost || got[0].ID != "x" || got[0].Checked.IsZero() {
		t.Errorf("defaults not filled in: %+v", got[0])
	}
}

// ---- light ------------------------------------------------------------------------

func TestLightSlowCheckSkipsItsTurn(t *testing.T) {
	var runs, cur, peak atomic.Int32
	slow := Check{ID: "slow", Light: true, Every: 20 * time.Millisecond, Run: func(ctx context.Context, _ *Env) []Result {
		runs.Add(1)
		if n := cur.Add(1); n > peak.Load() {
			peak.Store(n)
		}
		defer cur.Add(-1)
		select {
		case <-time.After(150 * time.Millisecond):
		case <-ctx.Done():
		}
		return []Result{{Status: OK}}
	}}
	r := NewRunner(Env{}, []Check{slow})
	r.tick = 2 * time.Millisecond
	r.jitter = func(time.Duration) time.Duration { return 0 }
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	r.Light(ctx, func(*nodev1.DiagnosticsReport, bool) {})
	if p := peak.Load(); p != 1 {
		t.Errorf("%d runs of the check at once, want 1", p)
	}
	if n := runs.Load(); n > 4 || n < 2 {
		t.Errorf("%d runs in 400ms of a 150ms check due every 20ms; want 2 to 4", n)
	}
}

func TestLightSlots(t *testing.T) {
	var cur, peak atomic.Int32
	var checks []Check
	for i := range 30 {
		checks = append(checks, Check{ID: string(rune('A' + i)), Light: true, Every: time.Hour, Run: func(context.Context, *Env) []Result {
			n := cur.Add(1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			time.Sleep(30 * time.Millisecond)
			cur.Add(-1)
			return []Result{{Status: OK}}
		}})
	}
	r := NewRunner(Env{}, checks)
	r.tick = 2 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	var reports atomic.Int32
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()
	r.Light(ctx, func(rep *nodev1.DiagnosticsReport, _ bool) {
		if len(rep.GetResults()) == 30 {
			reports.Add(1)
		}
	})
	if p := peak.Load(); p > Slots || p < 2 {
		t.Errorf("peak %d light checks at once, want at most %d", p, Slots)
	}
	if reports.Load() == 0 {
		t.Error("no report with every check")
	}
}

func TestLightPerTarget(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	c := Check{ID: "per", Light: true, Every: time.Hour,
		Targets: func(*Env) []string { return []string{"proxy:a", "proxy:b"} },
		Run: func(_ context.Context, env *Env) []Result {
			mu.Lock()
			seen[env.Only]++
			mu.Unlock()
			// A check that returns more than its target is cut to it.
			return []Result{{Target: "proxy:a", Status: OK}, {Target: "proxy:b", Status: OK}}
		}}
	r := NewRunner(Env{}, []Check{c})
	r.tick = 2 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	var last *nodev1.DiagnosticsReport
	r.Light(ctx, func(rep *nodev1.DiagnosticsReport, _ bool) {
		last = rep
		cancel()
	})
	if seen["proxy:a"] != 1 || seen["proxy:b"] != 1 {
		t.Errorf("runs by target = %v", seen)
	}
	if len(last.GetResults()) != 2 {
		t.Errorf("report = %v, want one result per target", last)
	}
}

func TestLightHysteresis(t *testing.T) {
	s := newLightSet()
	minute := Check{ID: "m", Every: time.Minute}
	k := unitKey{"m", ""}
	put := func(st nodev1.CheckStatus) nodev1.CheckStatus {
		s.put(k, minute, []Result{{ID: "m", Status: st, Summary: "x"}})
		return s.byUnit[k][0].Status
	}
	// Folded into the confirmation: after ok, one failing run is not reported
	// at all (it was warn); a first failure after a start is still warn.
	steps := []struct{ in, want nodev1.CheckStatus }{
		{Fail, Warn}, {Fail, Fail}, {Fail, Fail}, {OK, OK}, {Fail, OK}, {Warn, Warn}, {Fail, Warn}, {Fail, Fail},
	}
	for i, st := range steps {
		if got := put(st.in); got != st.want {
			t.Errorf("step %d: %v -> %v, want %v", i, st.in, got, st.want)
		}
	}
	// A slower check fails at once.
	slow := Check{ID: "s", Every: 10 * time.Minute}
	s.put(unitKey{"s", ""}, slow, []Result{{ID: "s", Status: Fail}})
	if got := s.byUnit[unitKey{"s", ""}][0].Status; got != Fail {
		t.Errorf("a 10-min check failing once = %v, want fail", got)
	}
}

func TestLightConfirmsAWorsening(t *testing.T) {
	s := newLightSet()
	slow := Check{ID: "s", Every: 10 * time.Minute}
	k := unitKey{"s", ""}
	put := func(st nodev1.CheckStatus, summary string) (Result, bool, bool) {
		changed, confirm := s.put(k, slow, []Result{{ID: "s", Status: st, Summary: summary}})
		return s.byUnit[k][0], changed, confirm
	}
	// A fresh start reports what it finds, bad or not.
	if r, changed, confirm := put(Fail, "first"); r.Status != Fail || !changed || confirm {
		t.Fatalf("first run fail: %v changed %t confirm %t", r.Status, changed, confirm)
	}
	if r, _, confirm := put(OK, "fine"); r.Status != OK || confirm {
		t.Fatalf("recovery: %v confirm %t, want ok at once", r.Status, confirm)
	}
	// A single bad run, then a good one: nothing worse is reported.
	if r, changed, confirm := put(Fail, "bad"); r.Status != OK || r.Summary != "fine" || changed || !confirm {
		t.Errorf("one bad run: %v %q changed %t confirm %t, want ok kept and a rerun", r.Status, r.Summary, changed, confirm)
	}
	if r, changed, confirm := put(OK, "fine again"); r.Status != OK || changed || confirm {
		t.Errorf("good rerun: %v changed %t confirm %t", r.Status, changed, confirm)
	}
	// The streak was reset: the next bad run waits again.
	if r, _, confirm := put(Warn, "slow"); r.Status != OK || !confirm {
		t.Errorf("bad run after reset: %v confirm %t, want ok kept and a rerun", r.Status, confirm)
	}
	// Two bad runs report the better of the two, in the newer's words.
	if r, changed, confirm := put(Fail, "down"); r.Status != Warn || r.Summary != "down" || !changed || confirm {
		t.Errorf("confirmed: %v %q changed %t confirm %t, want warn %q", r.Status, r.Summary, changed, confirm, "down")
	}
	// Worse again: warn kept until a rerun fails too.
	if r, _, confirm := put(Fail, "down"); r.Status != Warn || !confirm {
		t.Errorf("fail after warn: %v confirm %t", r.Status, confirm)
	}
	if r, _, _ := put(Fail, "down 2"); r.Status != Fail || r.Summary != "down 2" {
		t.Errorf("fail confirmed: %v %q", r.Status, r.Summary)
	}
	// Recovery at once.
	if r, changed, confirm := put(OK, "back"); r.Status != OK || !changed || confirm {
		t.Errorf("recovery: %v changed %t confirm %t", r.Status, changed, confirm)
	}
}

func TestLightSchedulesTheConfirmingRun(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	slow := Check{ID: "s", Light: true, Every: 10 * time.Minute}
	minute := Check{ID: "m", Light: true, Every: time.Minute}
	r := NewRunner(Env{Now: func() time.Time { return now }}, []Check{slow, minute})
	l := &lightLoop{r: r, units: map[unitKey]*unit{}, set: newLightSet()}
	l.env = r.prepare()
	run := func(c Check, next time.Time, st nodev1.CheckStatus) *unit {
		k := unitKey{c.ID, ""}
		u := l.units[k]
		if u == nil {
			u = &unit{check: c}
			l.units[k] = u
		}
		u.running, u.next = true, next
		l.running++
		l.finished(unitDone{k, []Result{{Status: st}}})
		return u
	}
	turn := now.Add(10 * time.Minute)
	if u := run(slow, turn, OK); !u.next.Equal(turn) {
		t.Errorf("an ok run moved the next turn to %v", u.next)
	}
	if u := run(slow, turn, Fail); !u.next.Equal(now.Add(confirmAfter)) || confirmAfter != time.Minute {
		t.Errorf("a bad run of a 10-min check: next turn %v, want %v (60 s)", u.next, now.Add(confirmAfter))
	}
	// The normal turn stays when it comes sooner.
	soon := now.Add(55 * time.Second)
	run(minute, soon, OK)
	if u := run(minute, soon, Fail); !u.next.Equal(soon) {
		t.Errorf("a bad run of a 1-min check: next turn %v, want its own %v", u.next, soon)
	}
}

// The light loop is driven by hand with an injected clock: round, the run's
// result from doneCh, finished, publish; no real time passes.
func TestLightReportsOnChangeOnly(t *testing.T) {
	var status atomic.Int32
	status.Store(int32(OK))
	c := Check{ID: "c", Light: true, Every: 5 * time.Minute, Run: func(context.Context, *Env) []Result {
		return []Result{{Status: nodev1.CheckStatus(status.Load()), Summary: "run"}}
	}}
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	r := NewRunner(Env{Now: func() time.Time { return now }}, []Check{c})
	r.liveEvery = 12 * time.Minute
	r.jitter = func(time.Duration) time.Duration { return 0 }
	type rep struct {
		buffered bool
		status   nodev1.CheckStatus
	}
	var reps []rep
	report := func(d *nodev1.DiagnosticsReport, buffered bool) {
		reps = append(reps, rep{buffered, d.GetResults()[0].GetStatus()})
	}
	l := &lightLoop{r: r, ctx: t.Context(), units: map[unitKey]*unit{}, set: newLightSet(), doneCh: make(chan unitDone)}
	step := func(at time.Duration, first bool) {
		now = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC).Add(at)
		l.round(now, first)
		if l.running > 0 {
			select {
			case d := <-l.doneCh:
				l.finished(d)
			case <-time.After(10 * time.Second):
				t.Fatalf("at %v: the check did not return", at)
			}
		}
		l.publish(report)
	}
	step(0, true)               // ok: the first report, buffered
	step(5*time.Minute, false)  // ok: nothing changed
	step(10*time.Minute, false) // ok
	step(12*time.Minute, false) // no run; liveEvery went by: live-only
	status.Store(int32(Warn))
	step(15*time.Minute, false) // warn once: held, a rerun at 16 min
	step(16*time.Minute, false) // warn confirmed: buffered
	step(21*time.Minute, false) // warn again: nothing changed
	l.wg.Wait()

	want := []rep{{true, OK}, {false, OK}, {true, Warn}}
	if !slices.Equal(reps, want) {
		t.Errorf("reports = %v, want %v", reps, want)
	}
}
