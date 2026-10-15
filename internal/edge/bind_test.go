package edge

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// foreignAddr is a private address that is not expected on the host; a test
// that binds it to fail skips when the host does have it.
const foreignAddr = "10.255.255.1"

func skipIfLocal(t *testing.T) {
	t.Helper()
	if ln, err := net.Listen("tcp4", foreignAddr+":0"); err == nil {
		_ = ln.Close()
		t.Skipf("%s is an address of this host", foreignAddr)
	}
}

// failureIDs returns the ids of the failed listeners of e, sorted.
func failureIDs(e *Edge) []string {
	var ids []string
	for _, f := range e.Failures() {
		ids = append(ids, f.GetListenerId())
	}
	return ids
}

// A listener whose port is held by a foreign socket fails on its own: the
// configuration applies, the other listeners serve, the failure is reported
// with its address, and the listener is tried again until it binds. Once the
// port is free it serves within the retry time, and leaves the failure list.
func TestApplyBindsEachListenerOnItsOwn(t *testing.T) {
	checkGoroutines(t)
	beA := newBackend(t, true, echoHandler)
	beB := newBackend(t, true, echoHandler)
	ports := []uint32{freePort(t), freePort(t)}
	slices.Sort(ports)
	// The second port is taken by a socket without SO_REUSEPORT.
	blocker, err := net.Listen("tcp4", loopback(ports[1]).String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Close() }()

	e := newTestEdge(t, Options{})
	e.retryMin, e.retryMax = 20*time.Millisecond, 50*time.Millisecond
	cfg := &edgev1.EdgeConfig{
		Generation: 1,
		Listeners:  []*edgev1.EdgeListener{tlsListener("good", ports[0], "reject"), tlsListener("held", ports[1], "reject")},
		Routes: []*edgev1.Route{
			engineRoute("good", "a.example.com", "p1", beA.addr),
			engineRoute("held", "b.example.com", "p2", beB.addr),
		},
	}
	mustApply(t, e, cfg)

	if g := e.Generation(); g != 1 {
		t.Fatalf("generation %d, want 1: the configuration did not apply", g)
	}
	if got, want := e.Bound(), []string{loopback(ports[0]).String()}; !slices.Equal(got, want) {
		t.Fatalf("bound %v, want %v", got, want)
	}
	failures := e.Failures()
	if len(failures) != 1 || failures[0].GetListenerId() != "held" {
		t.Fatalf("failures = %v, want the listener held alone", failures)
	}
	if reason := failures[0].GetReason(); !strings.Contains(reason, loopback(ports[1]).String()) {
		t.Errorf("the reason %q does not name the address %s", reason, loopback(ports[1]))
	}
	openRelay(t, "", loopback(ports[0]), "a.example.com", beA) // the good one serves

	// The same configuration again: the failure stays, the good one is untouched.
	mustApply(t, e, cfg)
	if got := failureIDs(e); !slices.Equal(got, []string{"held"}) {
		t.Fatalf("failures after the second Apply = %v, want [held]", got)
	}

	// Free the port: the listener binds on a retry and serves.
	_ = blocker.Close()
	waitFor(t, "the held listener to bind", func() bool { return len(e.Failures()) == 0 })
	if got, want := e.Bound(), []string{loopback(ports[0]).String(), loopback(ports[1]).String()}; !slices.Equal(got, want) {
		t.Fatalf("bound %v, want %v", got, want)
	}
	openRelay(t, "", loopback(ports[1]), "b.example.com", beB)

	// A configuration without the listener drops it, and no failure is left.
	cfg2 := oneRoute(1, ports[0], "reject", "a.example.com", beA.addr)
	mustApply(t, e, cfg2)
	if got := e.Failures(); len(got) != 0 {
		t.Errorf("failures = %v, want none", got)
	}
}

// A listener on an address that is not on the host fails alone, whatever its
// kind: an http-upstream listener that cannot bind leaves the tls listener
// serving. (An http-upstream listener must bind a private or loopback
// address; the one here is private and not on the host.)
func TestHTTPUpstreamListenerOnAForeignAddressFailsAlone(t *testing.T) {
	skipIfLocal(t)
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	web := newWebBackend(t, nil)
	port, upPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{})
	e.retryMin, e.retryMax = time.Hour, time.Hour // no retry during the test
	cfg := oneRoute(1, port, "reject", "a.example.com", be.addr)
	cfg.Listeners = append(cfg.Listeners, &edgev1.EdgeListener{
		Id: "up", BindIp: foreignAddr, Port: upPort, Kind: "http-upstream",
		StrangerAction: "reject", NonTlsAction: "drop", TrustedCidrs: []string{"127.0.0.0/8"},
	})
	cfg.Routes = append(cfg.Routes, webRoute("up", "web.example.com", "pu", web.addr))
	mustApply(t, e, cfg)

	if got, want := e.Bound(), []string{loopback(port).String()}; !slices.Equal(got, want) {
		t.Fatalf("bound %v, want %v", got, want)
	}
	if got := failureIDs(e); !slices.Equal(got, []string{"up"}) {
		t.Fatalf("failures = %v, want [up]", e.Failures())
	}
	if reason := e.Failures()[0].GetReason(); !strings.Contains(reason, fmt.Sprintf("%s:%d", foreignAddr, upPort)) {
		t.Errorf("the reason %q does not name the address", reason)
	}
	openRelay(t, "", loopback(port), "a.example.com", be)

	// A retry that fails again keeps the failure.
	e.retryBinds()
	if got := failureIDs(e); !slices.Equal(got, []string{"up"}) {
		t.Fatalf("failures after a retry = %v, want [up]", e.Failures())
	}
	// A configuration without the listener, while it still fails, drops it.
	mustApply(t, e, oneRoute(1, port, "reject", "a.example.com", be.addr))
	if got := e.Failures(); len(got) != 0 {
		t.Errorf("failures = %v after the listener went, want none", got)
	}
}

// The retry wait starts at retryMin and doubles up to retryMax; a failure that
// is new starts over.
func TestBindRetryBackoff(t *testing.T) {
	skipIfLocal(t)
	checkGoroutines(t)
	e := newTestEdge(t, Options{})
	e.retryMin, e.retryMax = 30*time.Second, 5*time.Minute
	cfg := &edgev1.EdgeConfig{Generation: 1, Listeners: []*edgev1.EdgeListener{{
		Id: "up", BindIp: foreignAddr, Port: freePort(t), Kind: "tls", StrangerAction: "reject", NonTlsAction: "drop",
	}}}
	mustApply(t, e, cfg)
	wait := func() time.Duration {
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, f := range e.failed {
			return f.wait
		}
		return 0
	}
	if got := wait(); got != 30*time.Second {
		t.Fatalf("first wait %v, want 30s", got)
	}
	var waits []time.Duration
	for i := range 5 {
		e.retryDue(time.Now().Add(time.Duration(i+1) * time.Hour)) // the failure is due
		waits = append(waits, wait())
	}
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	if !slices.Equal(waits, want) {
		t.Errorf("waits = %v, want %v", waits, want)
	}
}
