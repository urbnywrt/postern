package egress

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// pairs makes the connections of a fake member out of real TCP pairs: the near
// end goes to the router, and the far end, the proxy, to the test.
type pairs struct {
	ln   net.Listener
	fars chan *net.TCPConn
}

func newPairs(t *testing.T) *pairs {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return &pairs{ln: ln, fars: make(chan *net.TCPConn, 16)}
}

func (p *pairs) dial(context.Context, string) (net.Conn, error) {
	c, err := net.Dial("tcp", p.ln.Addr().String())
	if err != nil {
		return nil, err
	}
	a, err := p.ln.Accept()
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	p.fars <- a.(*net.TCPConn)
	return c, nil
}

// newPassiveRouter is a router with one chain of one SOCKS5 member "a", whose
// connections are TCP pairs, a scripted probe and a fake clock. One failure takes
// the member down, so that the result of one round shows.
func newPassiveRouter(t *testing.T) (*Router, *scriptedProbe, *fakeClock, *pairs) {
	t.Helper()
	clk := newFakeClock()
	sp := newScriptedProbe()
	ds := newDialers("a")
	p := newPairs(t)
	ds.get("a").fn = p.dial
	r := newRouter(quiet, deps{clock: clk, newDialer: ds.factory(), probe: sp.probe, exit: sp.exit})
	hc := &edgev1.HealthCheck{IntervalSeconds: 30, FailThreshold: 1}
	if err := r.Apply([]*edgev1.Chain{chainOf("c", mem("a", "socks5"))}, hc); err != nil {
		t.Fatal(err)
	}
	return r, sp, clk, p
}

// connect dials through the chain and returns the connection and the far end.
func connect(t *testing.T, r *Router, p *pairs) (net.Conn, *net.TCPConn) {
	t.Helper()
	c, _, err := r.Dial(context.Background(), "c", "149.154.167.51:443")
	if err != nil {
		t.Fatal(err)
	}
	far := <-p.fars
	_ = c.SetDeadline(time.Now().Add(ioTimeout))
	return c, far
}

// earlyEnd is a connection that the member acknowledged and then ended without
// a byte: the far end closes, or resets when reset is set, and the near end reads
// to the end.
func earlyEnd(t *testing.T, r *Router, p *pairs, reset bool) {
	t.Helper()
	c, far := connect(t, r, p)
	if reset {
		_ = far.SetLinger(0)
	}
	_ = far.Close()
	_, _ = io.Copy(io.Discard, c) // the way of the relay: WriteTo
	_ = c.Close()
}

// goodConn is a connection through which the upstream answered.
func goodConn(t *testing.T, r *Router, p *pairs) {
	t.Helper()
	c, far := connect(t, r, p)
	if _, err := far.Write([]byte("resPQ")); err != nil {
		t.Fatal(err)
	}
	_ = far.Close()
	if _, err := io.ReadAll(c); err != nil { // the way of a plain reader: Read
		t.Fatal(err)
	}
	_ = c.Close()
}

// startPassive runs the loop and waits for its first round.
func startPassive(t *testing.T, r *Router, sp *scriptedProbe, clk *fakeClock) {
	t.Helper()
	runHealth(t, r)
	waitFor(t, func() bool { return sp.count("a") == 1 }, "the first round")
	clk.waitTimers(t, 1)
}

// noMoreRounds checks that the member was probed want times, and stays so.
func noMoreRounds(t *testing.T, sp *scriptedProbe, want int) {
	t.Helper()
	time.Sleep(50 * time.Millisecond)
	if got := sp.count("a"); got != want {
		t.Fatalf("%d probes of the member, want %d", got, want)
	}
}

func statusOf(r *Router) string { return statuses(r.Health())["c/a"] }

func TestPassiveEarlyEndsTriggerARoundThatTakesTheMemberDown(t *testing.T) {
	r, sp, clk, p := newPassiveRouter(t)
	sp.set("a", okProbe, failProbe)
	startPassive(t, r, sp, clk)

	earlyEnd(t, r, p, false)
	earlyEnd(t, r, p, true)
	noMoreRounds(t, sp, 1)
	if got := statusOf(r); got != "up" {
		t.Fatalf("after 2 early ends the member is %s, want up: the passive signal alone decides nothing", got)
	}
	earlyEnd(t, r, p, false)
	waitFor(t, func() bool { return sp.count("a") == 2 }, "the round of the third early end")
	waitFor(t, func() bool { return statusOf(r) == "down" }, "the member down by its failed round")
}

func TestPassiveRoundThatPassesKeepsTheMemberUp(t *testing.T) {
	r, sp, clk, p := newPassiveRouter(t)
	startPassive(t, r, sp, clk) // every probe passes
	for range 3 {
		earlyEnd(t, r, p, false)
	}
	waitFor(t, func() bool { return sp.count("a") == 2 }, "the round of the third early end")
	noMoreRounds(t, sp, 2)
	if got := statusOf(r); got != "up" {
		t.Fatalf("the member is %s after its round passed, want up", got)
	}
}

func TestPassiveClientsThatHangUpCountForNothing(t *testing.T) {
	r, sp, clk, p := newPassiveRouter(t)
	sp.set("a", okProbe, failProbe)
	startPassive(t, r, sp, clk)
	for range 5 {
		c, far := connect(t, r, p)
		_ = c.Close() // the client hangs up first
		_ = far.Close()
	}
	for range 5 { // the client ends its stream first, and the upstream follows
		c, far := connect(t, r, p)
		_ = c.(interface{ CloseWrite() error }).CloseWrite()
		_ = far.Close()
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}
	noMoreRounds(t, sp, 1)
	if got := statusOf(r); got != "up" {
		t.Fatalf("the member is %s, want up", got)
	}
}

func TestPassiveLateEndsDoNotCount(t *testing.T) {
	r, sp, clk, p := newPassiveRouter(t)
	startPassive(t, r, sp, clk)
	var conns []net.Conn
	var fars []*net.TCPConn
	for range 3 {
		c, far := connect(t, r, p)
		conns, fars = append(conns, c), append(fars, far)
	}
	clk.Advance(passiveWindow)
	for i, c := range conns {
		_ = fars[i].Close()
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}
	noMoreRounds(t, sp, 1)
}

func TestPassiveRoundsAreRateLimited(t *testing.T) {
	r, sp, clk, p := newPassiveRouter(t)
	startPassive(t, r, sp, clk)
	for range 3 {
		earlyEnd(t, r, p, false)
	}
	waitFor(t, func() bool { return sp.count("a") == 2 }, "the first passive round")
	for range 6 {
		earlyEnd(t, r, p, false)
	}
	clk.Advance(passiveInterval - time.Second)
	earlyEnd(t, r, p, false)
	noMoreRounds(t, sp, 2)

	clk.Advance(time.Second)
	earlyEnd(t, r, p, false) // still in a row: the next round is due
	waitFor(t, func() bool { return sp.count("a") == 3 }, "the passive round 5 s after the first")
	noMoreRounds(t, sp, 3)
}

func TestPassiveGoodConnectionResetsTheCount(t *testing.T) {
	r, sp, clk, p := newPassiveRouter(t)
	startPassive(t, r, sp, clk)
	earlyEnd(t, r, p, false)
	earlyEnd(t, r, p, false)
	goodConn(t, r, p)
	earlyEnd(t, r, p, false)
	earlyEnd(t, r, p, false)
	noMoreRounds(t, sp, 1)
	earlyEnd(t, r, p, false)
	waitFor(t, func() bool { return sp.count("a") == 2 }, "the round of the third early end in a row")
}

func TestPassiveWatchKeepsTheRelayWorking(t *testing.T) {
	// The connection of a proxy member is watched, and a relay still has its
	// half-close and its bytes.
	r, _, _, p := newPassiveRouter(t)
	c, far := connect(t, r, p)
	if _, ok := c.(interface{ CloseWrite() error }); !ok {
		t.Fatalf("the connection is a %T without CloseWrite", c)
	}
	go func() {
		b, _ := io.ReadAll(far)
		_, _ = far.Write(append([]byte("echo:"), b...))
		_ = far.Close()
	}()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = c.(interface{ CloseWrite() error }).CloseWrite()
	var got []byte
	buf := new(bytesWriter)
	if _, err := io.Copy(buf, c); err != nil {
		t.Fatal(err)
	}
	got = buf.b
	if string(got) != "echo:ping" {
		t.Fatalf("got %q", got)
	}
}

type bytesWriter struct{ b []byte }

func (w *bytesWriter) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
