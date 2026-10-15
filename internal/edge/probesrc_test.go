package edge

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// The panel's probes (EdgeConfig.probe_sources, Ruling R6-1): a connection of
// a public listener from one of the addresses is exempt from the limits of its
// proxy, up to maxExemptPerProxy at a time, and closed exemptLifetime after
// its accept.

const probeSrc = "127.0.0.9"

// probeSourceConfig is limitedRoute with devices = 1 and probeSrc as the
// panel's address.
func probeSourceConfig(gen uint64, port uint32, be *backend) *edgev1.EdgeConfig {
	cfg := limitedRoute(gen, port, be, &edgev1.EdgeLimits{Devices: 1})
	cfg.ProbeSources = []string{probeSrc}
	return cfg
}

// fakeTimers stands in for time.AfterFunc: it records every timer that the
// edge starts and fires it only when the test says so.
type fakeTimers struct {
	mu     sync.Mutex
	timers []*fakeTimer
}

type fakeTimer struct {
	d       time.Duration
	f       func()
	stopped bool
}

func installFakeTimers(e *Edge) *fakeTimers {
	ft := &fakeTimers{}
	e.afterFunc = func(d time.Duration, f func()) func() bool {
		ft.mu.Lock()
		defer ft.mu.Unlock()
		tm := &fakeTimer{d: d, f: f}
		ft.timers = append(ft.timers, tm)
		return func() bool {
			ft.mu.Lock()
			defer ft.mu.Unlock()
			was := !tm.stopped
			tm.stopped = true
			return was
		}
	}
	return ft
}

func (ft *fakeTimers) count() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return len(ft.timers)
}

func (ft *fakeTimers) get(t *testing.T, i int) *fakeTimer {
	t.Helper()
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if i >= len(ft.timers) {
		t.Fatalf("timer %d: only %d were started", i, len(ft.timers))
	}
	return ft.timers[i]
}

// exemptOpen is the number of exempt connections of a proxy open now.
func exemptOpen(e *Edge, proxyID string) int {
	p := e.stats.proxy(proxyID)
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exempt
}

func TestProbeSourceTakesNoDeviceSlot(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	installFakeTimers(e)
	mustApply(t, e, probeSourceConfig(1, port, be))

	user := openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	before := proxyCounters(e.Snapshot(false), "p1")
	probe := openRelay(t, probeSrc, loopback(port), "proxy.example.com", be)
	expectRefused(t, "127.0.0.3", port) // the one device slot is the user's

	roundTrip(t, probe, "the probe's bytes")
	snap := e.Snapshot(true)
	p := proxyCounters(snap, "p1")
	if p.GetDevicesActive() != 1 || p.GetConnsActive() != 1 {
		t.Errorf("counters %v: want the user as the one device and the one active client connection", p)
	}
	if p.GetConnsTotal() != before.GetConnsTotal()+1 {
		t.Errorf("conns_total %d, want %d: the probe counts in the totals", p.GetConnsTotal(), before.GetConnsTotal()+1)
	}
	if up := p.GetBytesUp() - before.GetBytesUp(); up < uint64(len("ping")+len("the probe's bytes")) {
		t.Errorf("bytes up grew by %d: the probe's bytes are not counted", up)
	}
	if p.GetBytesDown() <= before.GetBytesDown() {
		t.Error("bytes down did not grow: the probe's bytes are not counted")
	}
	if ip := ipCounters(snap, "p1", probeSrc); ip != nil {
		t.Errorf("the probe source has IP counters: %v", ip)
	}
	if exemptOpen(e, "p1") != 1 {
		t.Errorf("exempt connections %d, want 1", exemptOpen(e, "p1"))
	}
	roundTrip(t, user, "the user is still served")
	_ = probe.Close()
	waitFor(t, "the probe to end", func() bool { return exemptOpen(e, "p1") == 0 })
	if ip := ipCounters(e.Snapshot(true), "p1", probeSrc); ip != nil {
		t.Errorf("the probe source has IP counters after its end: %v", ip)
	}
}

func TestProbeSourceIsBounded(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	ft := installFakeTimers(e)
	mustApply(t, e, probeSourceConfig(1, port, be))

	openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	var probes []interface{ Close() error }
	for range maxExemptPerProxy {
		probes = append(probes, openRelay(t, probeSrc, loopback(port), "proxy.example.com", be))
	}
	// The fifth is an ordinary client: over the device limit.
	expectRefused(t, probeSrc, port)
	if ft.count() != maxExemptPerProxy {
		t.Errorf("%d timers, want one per exempt connection, %d", ft.count(), maxExemptPerProxy)
	}
	_ = probes[0].Close()
	waitFor(t, "a probe to end", func() bool { return exemptOpen(e, "p1") == maxExemptPerProxy-1 })
	openRelay(t, probeSrc, loopback(port), "proxy.example.com", be)

	// Without a device limit a fifth one is let in as a client, and counted
	// as one.
	cfg := limitedRoute(2, port, be, nil)
	cfg.ProbeSources = []string{probeSrc}
	mustApply(t, e, cfg)
	openRelay(t, probeSrc, loopback(port), "proxy.example.com", be)
	if ip := ipCounters(e.Snapshot(true), "p1", probeSrc); ip == nil || ip.GetConnsActive() != 1 {
		t.Errorf("IP counters of the fifth probe %v, want one active connection", ip)
	}
}

func TestProbeSourceClosedAfterItsLifetime(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	ft := installFakeTimers(e)
	mustApply(t, e, probeSourceConfig(1, port, be))

	user := openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	if ft.count() != 0 {
		t.Fatalf("a client connection started %d timers", ft.count())
	}
	probe := openRelay(t, probeSrc, loopback(port), "proxy.example.com", be)
	tm := ft.get(t, 0)
	if tm.d > exemptLifetime || tm.d < exemptLifetime-5*time.Second {
		t.Fatalf("the probe is closed after %v, want %v from its accept", tm.d, exemptLifetime)
	}
	roundTrip(t, probe, "before its time")
	tm.f()
	readToEOF(t, probe, 5*time.Second)
	waitFor(t, "the probe to end", func() bool { return exemptOpen(e, "p1") == 0 })
	roundTrip(t, user, "the user is not closed")

	// A probe that ends before its time stops its timer.
	p2 := openRelay(t, probeSrc, loopback(port), "proxy.example.com", be)
	_ = p2.Close()
	waitFor(t, "the second probe to end", func() bool { return exemptOpen(e, "p1") == 0 })
	ft.mu.Lock()
	stopped := ft.timers[1].stopped
	ft.mu.Unlock()
	if !stopped {
		t.Error("the timer of a probe that ended is not stopped")
	}
}

func TestProbeSourceOnAWebRoute(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	ft := installFakeTimers(e)
	cfg := webConfig(1, port, "web.example.com", be.addr)
	cfg.Routes[0].Limits = &edgev1.EdgeLimits{Devices: 1}
	cfg.ProbeSources = []string{probeSrc}
	mustApply(t, e, cfg)

	get := func(client *http.Client, i int) (*http.Response, error) {
		return client.Do(newRequest(t, http.MethodGet, fmt.Sprintf("https://web.example.com/%d", i), ""))
	}
	user, _ := webClient(t, ca, "127.0.0.2", loopback(port))
	decodeEcho(t, mustDo(t, user, newRequest(t, http.MethodGet, "https://web.example.com/u", "")))
	before := proxyCounters(e.Snapshot(false), "pw")

	probe, probeTr := webClient(t, ca, probeSrc, loopback(port))
	if got := decodeEcho(t, mustDo(t, probe, newRequest(t, http.MethodGet, "https://web.example.com/p", ""))); got.URI != "/p" {
		t.Fatalf("the probe's request: the backend saw %q", got.URI)
	}
	other, _ := webClient(t, ca, "127.0.0.3", loopback(port))
	if resp, err := get(other, 1); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a second device is let in")
	}
	snap := e.Snapshot(true)
	p := proxyCounters(snap, "pw")
	if p.GetDevicesActive() != 1 || p.GetConnsTotal() != before.GetConnsTotal()+1 || p.GetBytesDown() <= before.GetBytesDown() {
		t.Errorf("counters %v (before %v): want one device, the probe in conns_total and its bytes counted", p, before)
	}
	if ip := ipCounters(snap, "pw", probeSrc); ip != nil {
		t.Errorf("the probe source has IP counters: %v", ip)
	}
	if ft.count() != 1 {
		t.Fatalf("%d timers, want 1 for the probe", ft.count())
	}
	ft.get(t, 0).f()
	waitFor(t, "the web probe to be closed", func() bool { return exemptOpen(e, "pw") == 0 })
	probeTr.CloseIdleConnections()
}

func TestProbeSourceOnATestListenerChangesNothing(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port, testPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{})
	ft := installFakeTimers(e)
	cfg := probeSourceConfig(1, port, be)
	cfg.TestListeners = []*edgev1.TestListener{{Port: testPort, ListenerId: "l1"}}
	mustApply(t, e, cfg)

	openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	for range maxExemptPerProxy + 1 {
		openRelay(t, probeSrc, loopback(testPort), "proxy.example.com", be)
	}
	if ft.count() != 0 || exemptOpen(e, "p1") != 0 {
		t.Fatalf("the test listener's connections took %d exempt places and %d timers", exemptOpen(e, "p1"), ft.count())
	}
	// The public listener still has every exempt place.
	for range maxExemptPerProxy {
		openRelay(t, probeSrc, loopback(port), "proxy.example.com", be)
	}
	if p := proxyCounters(e.Snapshot(false), "p1"); p.GetConnsTotal() != 1+maxExemptPerProxy {
		t.Errorf("conns_total %d, want %d: the test listener's are not counted", p.GetConnsTotal(), 1+maxExemptPerProxy)
	}
}

func TestBlacklistedProbeSourceIsDropped(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{})
	cfg := probeSourceConfig(1, port, be)
	cfg.BlacklistCidrs = []string{probeSrc + "/32"}
	mustApply(t, e, cfg)

	c := dialEdge(t, probeSrc, loopback(port))
	expectClosed(t, c, 5*time.Second)
	be.expectNone(t, 50*time.Millisecond)
}

func TestProbeSourcesFollowTheTable(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	log, buf := captureLogger(slog.LevelInfo)
	e := newTestEdgeLog(t, log, Options{})
	installFakeTimers(e)
	cfg := probeSourceConfig(1, port, be)
	// An IPv4-mapped address is its IPv4 address; a prefix, a zone and a
	// name are no single address, and are ignored.
	cfg.ProbeSources = []string{"::ffff:" + probeSrc, "127.0.0.0/8", "fe80::1%eth0", "panel.example.com"}
	if err := CheckConfig(cfg); err != nil {
		t.Fatalf("CheckConfig: %v; an entry that is not an address is ignored, not an error", err)
	}
	mustApply(t, e, cfg)
	openRelay(t, "127.0.0.2", loopback(port), "proxy.example.com", be)
	openRelay(t, probeSrc, loopback(port), "proxy.example.com", be)
	expectRefused(t, "127.0.0.10", port) // the prefix exempts nobody

	cfg.Generation = 2
	mustApply(t, e, cfg) // the same entries again: logged once
	if n := strings.Count(buf.String(), "127.0.0.0/8"); n != 1 {
		t.Errorf("the ignored prefix is logged %d times, want once:\n%s", n, buf.String())
	}
	for _, s := range []string{"fe80::1%eth0", "panel.example.com"} {
		if !strings.Contains(buf.String(), s) {
			t.Errorf("the ignored entry %q is not logged:\n%s", s, buf.String())
		}
	}

	// A new table, a new set.
	cfg.Generation = 3
	cfg.ProbeSources = []string{"127.0.0.10"}
	mustApply(t, e, cfg)
	expectRefused(t, probeSrc, port)
	openRelay(t, "127.0.0.10", loopback(port), "proxy.example.com", be)
}
