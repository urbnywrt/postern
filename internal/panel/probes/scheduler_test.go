package probes

import (
	"context"
	"errors"
	"fmt"
	randv2 "math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/store"
)

func TestOffsetIsStableAndSpread(t *testing.T) {
	const interval = 5 * time.Minute
	seen := map[time.Duration]bool{}
	for i := range 200 {
		id := fmt.Sprintf("proxy-%d", i)
		off := offset(id, interval)
		if off < 0 || off >= interval || off%time.Second != 0 {
			t.Fatalf("offset(%s) = %v, want whole seconds in [0, %v)", id, off, interval)
		}
		if again := offset(id, interval); again != off {
			t.Fatalf("offset(%s) = %v, then %v", id, off, again)
		}
		seen[off] = true
	}
	if len(seen) < 120 { // 200 random picks of 300 seconds give about 146
		t.Errorf("200 proxies got %d distinct offsets, want them spread", len(seen))
	}
	// FNV-32a of "a" is 0xe40c292c = 3826002220; mod 300 is 220.
	if got := offset("a", interval); got != 220*time.Second {
		t.Errorf("offset(a) = %v, want 220s (FNV-32a mod the interval)", got)
	}
}

func TestJitterBoundsAndSpread(t *testing.T) {
	const interval = 5 * time.Minute
	s := NewScheduler(nil, [32]byte{}, nil, WithRand(randv2.New(randv2.NewPCG(7, 9))))
	off := offset("p", interval)
	lo, hi := time.Duration(0), time.Duration(0)
	var prev time.Time
	for k := int64(1000); k < 3000; k++ {
		due := s.dueOf("p", k, interval)
		j := due.Sub(slotStart(k, off, interval))
		if j < -interval/5 || j > interval/5 {
			t.Fatalf("slot %d: jitter %v outside ±%v", k, j, interval/5)
		}
		lo, hi = min(lo, j), max(hi, j)
		if !prev.IsZero() {
			if gap := due.Sub(prev); gap < interval*3/5 || gap > interval*7/5 {
				t.Fatalf("slot %d: %v after the one before, want 0.6 to 1.4 intervals", k, gap)
			}
		}
		prev = due
	}
	if lo > -interval/6 || hi < interval/6 {
		t.Errorf("jitter only spans [%v, %v]; want close to ±%v", lo, hi, interval/5)
	}
}

func TestScheduleProbesEveryInterval(t *testing.T) {
	e := newEnv(t)
	n := e.node("proxy.example.com", true)
	p := e.proxy(e.listener(n.ID, 443), "www.example.com", secretA, nil)
	rec := newRecorder(e.clock, true)
	s := e.scheduler(rec.probe)

	runFor(s, e.clock, 60*time.Minute, 5*time.Second)
	if got := rec.count(p.ID); got < 11 || got > 13 {
		t.Fatalf("%d probes in an hour at 5 minutes, want 12 ± 1", got)
	}
	for i := 1; i < len(rec.times); i++ {
		if gap := rec.times[i].Sub(rec.times[i-1]); gap < 3*time.Minute-5*time.Second || gap > 7*time.Minute+5*time.Second {
			t.Errorf("probe %d came %v after the one before", i, gap)
		}
	}
	tg := rec.calls[0]
	if tg.Addr != "proxy.example.com:443" || tg.SNI != "www.example.com" || rec.secret[p.ID] != secretA || tg.Type != store.ProxyTypeFakeTLS {
		t.Errorf("target %+v (secret %s), want the link host, the port, the domain and the secret", tg, rec.secret[p.ID])
	}
	ps, err := e.db.Probes(e.ctx, p.ID, "", e.clock.Now().Add(-2*time.Hour), e.clock.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != rec.count(p.ID) || ps[0].Vantage != VantagePanel || ps[0].Kind != KindL2 || !ps[0].OK || ps[0].LatencyMS != 42 {
		t.Errorf("stored %+v, want every probe as panel/l2", ps)
	}
	if strings.Contains(e.logs.String(), secretA) {
		t.Error("the log has the secret")
	}
}

func TestIntervalZeroIsOff(t *testing.T) {
	e := newEnv(t)
	n := e.node("proxy.example.com", true)
	p := e.proxy(e.listener(n.ID, 443), "www.example.com", secretA, nil)
	e.setInterval(0)
	rec := newRecorder(e.clock, false)
	s := e.scheduler(rec.probe)
	runFor(s, e.clock, 2*time.Hour, 30*time.Second)
	if got := rec.count(p.ID); got != 0 {
		t.Fatalf("%d probes with the interval 0, want none", got)
	}
}

func TestIntervalChangeAppliesAtTheNextRound(t *testing.T) {
	e := newEnv(t)
	n := e.node("proxy.example.com", true)
	p := e.proxy(e.listener(n.ID, 443), "www.example.com", secretA, nil)
	rec := newRecorder(e.clock, true)
	s := e.scheduler(rec.probe)

	runFor(s, e.clock, 30*time.Minute, 5*time.Second)
	before := rec.count(p.ID)
	e.setInterval(60)
	runFor(s, e.clock, 3*time.Hour, 5*time.Second)
	if got := rec.count(p.ID) - before; got < 2 || got > 4 {
		t.Fatalf("%d probes in 3 hours after the interval became 60 minutes, want 3 ± 1", got)
	}
	e.setInterval(1)
	before = rec.count(p.ID)
	runFor(s, e.clock, 10*time.Minute, 5*time.Second)
	if got := rec.count(p.ID) - before; got < 9 || got > 11 {
		t.Fatalf("%d probes in 10 minutes after the interval became 1 minute, want 10 ± 1", got)
	}
}

func TestSchedulerSkipsWhatItDoesNotProbe(t *testing.T) {
	e := newEnv(t)
	on := e.node("proxy.example.com", true)
	off := e.node("off.example.com", true)
	noHost := e.node("", true)
	lOn, lOff, lNoHost := e.listener(on.ID, 443), e.listener(off.ID, 443), e.listener(noHost.ID, 443)
	good := e.proxy(lOn, "www.example.com", secretA, nil)
	lOverride := &store.Listener{NodeID: noHost.ID, BindIP: "0.0.0.0", Port: 8443, LinkHostOverride: "203.0.113.7"}
	if err := e.db.CreateListener(e.ctx, lOverride); err != nil {
		t.Fatalf("CreateListener: %v", err)
	}
	override := e.proxy(lOverride, "www.example.com", secretA, nil)
	skipped := map[string]string{
		e.proxy(lOn, "paused.example.com", secretB, func(p *store.Proxy) { p.Enabled = false }).ID: "paused",
		e.proxy(lOff, "www.example.com", secretB, nil).ID:                                          "offline node",
		e.proxy(lNoHost, "www.example.com", secretB, nil).ID:                                       "no link host",
	}
	if _, err := e.db.ModifyNode(e.ctx, off.ID, func(n *store.Node) error { n.Status = store.NodeStatusOffline; return nil }); err != nil {
		t.Fatal(err)
	}
	rec := newRecorder(e.clock, true)
	s := e.scheduler(rec.probe)
	runFor(s, e.clock, 15*time.Minute, 5*time.Second)
	if rec.count(good.ID) == 0 {
		t.Error("the enabled proxy of an online node was not probed")
	}
	if rec.count(override.ID) == 0 {
		t.Error("the proxy whose listener has a link host of its own was not probed")
	}
	for _, c := range rec.calls {
		if c.ProxyID == override.ID && c.Addr != "203.0.113.7:8443" {
			t.Errorf("probed at %s, want the listener's link host", c.Addr)
		}
	}
	for id, why := range skipped {
		if got := rec.count(id); got != 0 {
			t.Errorf("%s: probed %d times, want never", why, got)
		}
	}
}

func TestAddrOfRefusesTheManagementName(t *testing.T) {
	n := &store.Node{LinkHost: "proxy.example.com", MgmtSNI: "mgmt.example.com"}
	l := &store.Listener{Port: 443}
	for name, p := range map[string]*store.Proxy{
		"web on mgmt": {Type: store.ProxyTypeWeb, Domain: "mgmt.example.com"},
		"mgmt sni":    {Type: store.ProxyTypeFakeTLS, Domain: "MGMT.example.com."},
		"no listener": {Type: store.ProxyTypeFakeTLS, Domain: "www.example.com"},
	} {
		ll := l
		if name == "no listener" {
			ll = nil
		}
		if _, err := addrOf(p, n, ll); !errors.Is(err, ErrNotProbeable) {
			t.Errorf("%s: %v, want ErrNotProbeable", name, err)
		}
	}
	if addr, err := addrOf(&store.Proxy{Type: store.ProxyTypeFakeTLS, Domain: "www.example.com"}, n, l); err != nil || addr != "proxy.example.com:443" {
		t.Errorf("addrOf = %q, %v", addr, err)
	}
	// The decoy: the root on a tls listener, also under a base path; the
	// base path behind a web server, which hands only it to the node.
	up := &store.Listener{Port: 18080, Kind: store.ListenerKindHTTPUpstream}
	for _, c := range []struct {
		base string
		l    *store.Listener
		want string
	}{
		{"", l, "https://web.example.com/"},
		{"tg/one", l, "https://web.example.com/"},
		{"tg/one", up, "https://web.example.com/tg/one/"},
	} {
		if addr, err := addrOf(&store.Proxy{Type: store.ProxyTypeWeb, Domain: "Web.Example.com.", WebBasePath: c.base}, &store.Node{}, c.l); err != nil || addr != c.want {
			t.Errorf("addrOf(WEB, %q, %q) = %q, %v; want %q", c.base, c.l.Kind, addr, err, c.want)
		}
	}
}

func TestConcurrencyCap(t *testing.T) {
	e := newEnv(t)
	e.setInterval(1)
	n := e.node("proxy.example.com", true)
	l := e.listener(n.ID, 443)
	for range 20 {
		e.proxy(l, "www.example.com", secretA, nil)
	}
	var running, most, total atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, 20)
	s := e.scheduler(func(_ context.Context, _ Target) (store.Probe, bool) {
		now := running.Add(1)
		for m := most.Load(); now > m && !most.CompareAndSwap(m, now); m = most.Load() {
		}
		started <- struct{}{}
		<-release
		running.Add(-1)
		total.Add(1)
		return store.Probe{OK: true}, true
	})
	// Every proxy is due within the first two minutes.
	for range 2 * 60 / 5 {
		s.round(e.ctx)
		e.clock.Add(5 * time.Second)
	}
	for range maxConcurrent {
		<-started
	}
	time.Sleep(100 * time.Millisecond)
	if got := running.Load(); got != maxConcurrent {
		t.Errorf("%d probes run at once, want %d", got, maxConcurrent)
	}
	close(release)
	s.wg.Wait()
	if most.Load() != maxConcurrent || total.Load() != 20 {
		t.Errorf("at most %d at once, %d in all; want %d and 20", most.Load(), total.Load(), maxConcurrent)
	}
}

// scripted is a probe function that answers with the results it is given, in
// order.
type scripted struct {
	mu      sync.Mutex
	results []bool
}

func (sc *scripted) probe(context.Context, Target) (store.Probe, bool) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	ok := sc.results[0]
	sc.results = sc.results[1:]
	if ok {
		return store.Probe{OK: true}, true
	}
	return store.Probe{Error: ErrRefusedSecret}, false
}

func kinds(t *testing.T, e *env, proxyID string) []string {
	t.Helper()
	evs, err := e.db.ListEvents(e.ctx, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(evs) - 1; i >= 0; i-- { // ListEvents is newest first
		if evs[i].ProxyID == proxyID && strings.HasPrefix(evs[i].Kind, "probe.") {
			out = append(out, evs[i].Kind+"/"+evs[i].Severity)
		}
	}
	return out
}

func TestStreakEventsOnce(t *testing.T) {
	e := newEnv(t)
	n := e.node("proxy.example.com", true)
	p := e.proxy(e.listener(n.ID, 443), "www.example.com", secretA, nil)
	sc := &scripted{results: []bool{false, false, false, false, true, true, false, true, false, false, true}}
	s := e.scheduler(sc.probe)
	var got []store.Probe
	s.OnResult(func(r store.Probe) { got = append(got, r) })
	for range 11 {
		if _, _, err := s.Probe(e.ctx, p.ID); err != nil {
			t.Fatal(err)
		}
		e.clock.Add(time.Minute)
	}
	want := []string{"probe.failed/warn", "probe.recovered/info", "probe.failed/warn", "probe.recovered/info"}
	if k := kinds(t, e, p.ID); fmt.Sprint(k) != fmt.Sprint(want) {
		t.Errorf("events %v, want %v", k, want)
	}
	if len(got) != 11 || got[0].ProxyID != p.ID || got[0].Error != ErrRefusedSecret {
		t.Errorf("OnResult saw %+v", got)
	}
}

func TestDownAtItsBounds(t *testing.T) {
	e := newEnv(t)
	n := e.node("proxy.example.com", true)
	p := e.proxy(e.listener(n.ID, 443), "www.example.com", secretA, nil)
	sc := &scripted{results: []bool{false, true, false, false}}
	s := e.scheduler(sc.probe)
	s.load(e.ctx) // the interval: 5 minutes

	probe := func() {
		t.Helper()
		if _, _, err := s.Probe(e.ctx, p.ID); err != nil {
			t.Fatal(err)
		}
	}
	probe()
	if s.Down(p.ID) {
		t.Error("down after one failure")
	}
	e.clock.Add(time.Minute)
	probe()
	e.clock.Add(time.Minute)
	probe()
	if s.Down(p.ID) {
		t.Error("down after a failure that follows a success")
	}
	e.clock.Add(time.Minute)
	probe()
	if !s.Down(p.ID) {
		t.Error("not down after two failures")
	}
	e.clock.Add(15 * time.Minute) // 3 intervals
	if !s.Down(p.ID) {
		t.Error("not down at 3 intervals")
	}
	e.clock.Add(time.Second)
	if s.Down(p.ID) {
		t.Error("down after more than 3 intervals")
	}
	e.clock.Add(-time.Second)
	e.setInterval(0)
	s.round(e.ctx)
	if s.Down(p.ID) {
		t.Error("down while the probes are off")
	}
	if s.Down("another") {
		t.Error("a proxy without probes is down")
	}
}

func TestStartLoadsTheLastProbes(t *testing.T) {
	e := newEnv(t)
	n := e.node("proxy.example.com", true)
	p := e.proxy(e.listener(n.ID, 443), "www.example.com", secretA, nil)
	now := e.clock.Now()
	for i, ok := range []bool{true, false, false} {
		if err := e.db.InsertProbe(e.ctx, store.Probe{ProxyID: p.ID, TS: now.Add(time.Duration(i-3) * time.Minute), Vantage: VantagePanel, Kind: KindL2, OK: ok}); err != nil {
			t.Fatal(err)
		}
	}
	e.setInterval(0) // nothing runs by itself
	sc := &scripted{results: []bool{false, true}}
	s := e.scheduler(sc.probe)
	s.load(e.ctx)
	s.interval = 5 * time.Minute
	if !s.Down(p.ID) {
		t.Fatal("not down with two failures stored")
	}
	for range 2 {
		if _, _, err := s.Probe(e.ctx, p.ID); err != nil {
			t.Fatal(err)
		}
		e.clock.Add(time.Minute)
	}
	if k := kinds(t, e, p.ID); fmt.Sprint(k) != "[probe.recovered/info]" {
		t.Errorf("events %v, want only the recovery: the streak was reported before", k)
	}
}

func TestSchedulerStopsWithItsContext(t *testing.T) {
	e := newEnv(t)
	e.setInterval(1)
	n := e.node("proxy.example.com", true)
	p := e.proxy(e.listener(n.ID, 443), "www.example.com", secretA, nil)
	e.clock.Add(10 * time.Minute)
	inProbe := make(chan struct{}, 1)
	s := NewScheduler(e.db, e.key, e.log, WithNow(e.clock.Now), WithProbe(func(ctx context.Context, _ Target) (store.Probe, bool) {
		inProbe <- struct{}{}
		<-ctx.Done()
		return store.Probe{Error: ErrUnreachable}, false
	}))
	s.tick = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(e.ctx)
	s.Start(ctx)
	go func() {
		for ctx.Err() == nil { // the clock moves until a probe is due
			e.clock.Add(5 * time.Second)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	select {
	case <-inProbe:
	case <-time.After(10 * time.Second):
		t.Fatal("no probe started")
	}
	cancel()
	done := make(chan struct{})
	go func() { s.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the scheduler did not stop with its context")
	}
	ps, err := e.db.Probes(e.ctx, p.ID, "", time.Unix(0, 0), e.clock.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 0 {
		t.Errorf("a probe that the stop cut off was stored: %+v", ps)
	}
}
