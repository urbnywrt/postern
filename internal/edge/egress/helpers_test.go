package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// No test in this package calls t.Parallel. TestNoGoroutineLeak counts the
// goroutines of the whole process, and that only means something while nothing
// else runs next to it.

// ioTimeout bounds every read and write of a test that talks to a real socket,
// so that a component that stops answering fails the test and does not hang it.
const ioTimeout = 5 * time.Second

// quiet is the logger of tests that do not look at the log.
var quiet = slog.New(slog.DiscardHandler)

// ---------------------------------------------------------------------------
// Log capture.
// ---------------------------------------------------------------------------

// logBuf collects log output. A log handler writes from many goroutines, and the
// test reads while they may still write.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// logger returns a JSON logger that writes everything, debug included, to l.
func (l *logBuf) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// records parses the lines that have been written so far.
func (l *logBuf) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(l.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q is not JSON: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// find returns the records of the given level whose message contains msg.
func find(recs []map[string]any, level, msg string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["level"] == level && strings.Contains(r["msg"].(string), msg) {
			out = append(out, r)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Configuration helpers.
// ---------------------------------------------------------------------------

func mem(key, kind string) *edgev1.ChainMember {
	return &edgev1.ChainMember{Key: key, Kind: kind}
}

func chainOf(id string, members ...*edgev1.ChainMember) *edgev1.Chain {
	return &edgev1.Chain{Id: id, Members: members}
}

// statuses maps "chain/member" to the status of the member in the output of
// Router.Health.
func statuses(hs []*edgev1.MemberHealth) map[string]string {
	out := make(map[string]string)
	for _, h := range hs {
		out[h.GetChainId()+"/"+h.GetMemberKey()] = h.GetStatus()
	}
	return out
}

// ---------------------------------------------------------------------------
// Fake dialers.
// ---------------------------------------------------------------------------

// opErr is a dial error as the net package reports it for errno.
func opErr(errno syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
}

// fakeDialer is a Dialer that notes the address of every dial and leaves the
// answer to fn. Without fn it connects to a sink.
type fakeDialer struct {
	mu    sync.Mutex
	addrs []string
	fn    func(ctx context.Context, addr string) (net.Conn, error)
}

func (f *fakeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.addrs = append(f.addrs, addr)
	f.mu.Unlock()
	if f.fn == nil {
		return sinkConn(), nil
	}
	return f.fn(ctx, addr)
}

func (f *fakeDialer) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.addrs...)
}

// sinkConn is a connection to a peer that reads and ignores what it is sent, and
// that goes away when the connection is closed.
func sinkConn() net.Conn {
	near, far := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, far)
		_ = far.Close()
	}()
	return near
}

// echoConn is a connection to a peer that sends back what it is sent, after it
// has sent banner.
func echoConn(banner string) net.Conn {
	near, far := net.Pipe()
	go func() {
		if banner != "" {
			if _, err := far.Write([]byte(banner)); err != nil {
				_ = far.Close()
				return
			}
		}
		_, _ = io.Copy(far, far)
		_ = far.Close()
	}()
	return near
}

func failing(err error) func(context.Context, string) (net.Conn, error) {
	return func(context.Context, string) (net.Conn, error) { return nil, err }
}

// dialers is a set of fake dialers by member key. Its factory stands in for
// NewMemberDialer in a router under test, and notes the timeout the router asks
// the dialer of each member to apply.
type dialers struct {
	mu       sync.Mutex
	by       map[string]*fakeDialer
	timeouts map[string]time.Duration
	built    map[string]int // how many times the dialer of a member was built
}

func newDialers(keys ...string) *dialers {
	d := &dialers{by: make(map[string]*fakeDialer), timeouts: make(map[string]time.Duration), built: make(map[string]int)}
	for _, k := range keys {
		d.by[k] = &fakeDialer{}
	}
	return d
}

func (d *dialers) get(key string) *fakeDialer { return d.by[key] }

func (d *dialers) factory() func(*edgev1.ChainMember, time.Duration) (Dialer, error) {
	return func(m *edgev1.ChainMember, timeout time.Duration) (Dialer, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		f, ok := d.by[m.GetKey()]
		if !ok {
			f = &fakeDialer{}
			d.by[m.GetKey()] = f
		}
		d.timeouts[m.GetKey()] = timeout
		d.built[m.GetKey()]++
		return f, nil
	}
}

// ---------------------------------------------------------------------------
// Scripted probes and a fake clock.
// ---------------------------------------------------------------------------

var (
	okProbe   = probeResult{ok: true, latency: 25 * time.Millisecond}
	failProbe = probeResult{err: errors.New("no datacenter answered")}
)

// scriptedProbe stands in for the probe of a router: it answers each check of
// the datacenters from the script of the member, in order, and repeats the last
// answer when the script is used up; and each question of the exit address
// from the exit script of the member in the same way. A member without an exit
// script has nothing to say about its exit address (its answer is aborted, and
// not recorded).
type scriptedProbe struct {
	mu        sync.Mutex
	script    map[string][]probeResult
	next      map[string]int
	calls     map[string]int
	exits     map[string][]exitResult
	nextExit  map[string]int
	exitCalls map[string]int
	active    int
	maxActive int
	hook      func(key string) // called at the start of every probe, before it answers
}

func newScriptedProbe() *scriptedProbe {
	return &scriptedProbe{
		script: make(map[string][]probeResult), next: make(map[string]int), calls: make(map[string]int),
		exits: make(map[string][]exitResult), nextExit: make(map[string]int), exitCalls: make(map[string]int),
	}
}

// set replaces the script of a member; the next probe starts it again.
func (p *scriptedProbe) set(key string, results ...probeResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.script[key] = results
	p.next[key] = 0
}

// setExit replaces the exit script of a member; the next question starts it
// again.
func (p *scriptedProbe) setExit(key string, results ...exitResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exits[key] = results
	p.nextExit[key] = 0
}

func (p *scriptedProbe) exit(_ context.Context, m *member, _ checkConfig) exitResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exitCalls[m.key]++
	script := p.exits[m.key]
	if len(script) == 0 {
		return exitResult{aborted: true}
	}
	i := p.nextExit[m.key]
	if i >= len(script) {
		i = len(script) - 1
	} else {
		p.nextExit[m.key]++
	}
	return script[i]
}

func (p *scriptedProbe) exitCount(key string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exitCalls[key]
}

func (p *scriptedProbe) probe(_ context.Context, m *member, _ checkConfig) probeResult {
	p.mu.Lock()
	p.active++
	p.maxActive = max(p.maxActive, p.active)
	hook := p.hook
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
	}()
	if hook != nil {
		hook(m.key)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[m.key]++
	script := p.script[m.key]
	if len(script) == 0 {
		return okProbe
	}
	i := p.next[m.key]
	if i >= len(script) {
		i = len(script) - 1
	} else {
		p.next[m.key]++
	}
	return script[i]
}

func (p *scriptedProbe) count(key string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[key]
}

func (p *scriptedProbe) total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.calls {
		n += c
	}
	return n
}

// fakeClock is a clock that moves only when a test says so.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers map[*fakeTimer]struct{}
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_700_000_000, 0), timers: make(map[*fakeTimer]struct{})}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, at: c.now.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		t.ch <- c.now
		return t
	}
	c.timers[t] = struct{}{}
	return t
}

// Advance moves the clock forward and fires the timers that are due, the
// earliest first.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	var due []*fakeTimer
	for t := range c.timers {
		if !t.at.After(now) {
			due = append(due, t)
			delete(c.timers, t)
		}
	}
	c.mu.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].at.Before(due[j].at) })
	for _, t := range due {
		t.ch <- now
	}
}

func (c *fakeClock) timerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

// waitTimers waits until n timers are waiting to fire: that is how a test knows
// that the loop under test has finished its work and is asleep.
func (c *fakeClock) waitTimers(t *testing.T, n int) {
	t.Helper()
	waitFor(t, func() bool { return c.timerCount() == n }, "the clock to have %d pending timers", n)
}

type fakeTimer struct {
	c  *fakeClock
	at time.Time
	ch chan time.Time
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	_, active := t.c.timers[t]
	delete(t.c.timers, t)
	return active
}

// waitFor polls cond until it holds. It is how a test waits for another
// goroutine to get somewhere, without a sleep of a fixed length.
func waitFor(t *testing.T, cond func() bool, format string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(ioTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for "+format, args...)
		}
		time.Sleep(time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Real sockets.
// ---------------------------------------------------------------------------

// givenPorts are the ports that freePort has returned in this test binary.
var givenPorts sync.Map

// freePort returns a loopback port that nothing listens on, and never the same
// one twice: the listener that found it is closed at once, so the kernel may
// hand the port out again, and a test that asks for two would get one twice.
func freePort(t *testing.T) uint32 {
	t.Helper()
	for {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		if _, given := givenPorts.LoadOrStore(port, true); !given {
			return uint32(port)
		}
	}
}

// closedAddr returns the address of a loopback port that refuses connections.
func closedAddr(t *testing.T) string {
	t.Helper()
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(freePort(t))))
}

// startEcho serves a TCP echo on a loopback port until the test ends and returns
// its address.
func startEcho(t *testing.T) string {
	t.Helper()
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
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// roundTrip writes msg to c and reads the same number of bytes back.
func roundTrip(t *testing.T, c net.Conn, msg string) string {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(got)
}

// roundTripAsIs is roundTrip that leaves the deadlines of c alone. A test that
// looks for a deadline that a dial left on the connection must not set one of its
// own first, which would replace it. The exchange runs in a goroutine so that a
// connection that hangs fails the test and does not hang it.
func roundTripAsIs(t *testing.T, c net.Conn, msg string) string {
	t.Helper()
	type result struct {
		got string
		err error
	}
	done := make(chan result, 1)
	go func() {
		if _, err := c.Write([]byte(msg)); err != nil {
			done <- result{err: err}
			return
		}
		got := make([]byte, len(msg))
		_, err := io.ReadFull(c, got)
		done <- result{string(got), err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("round trip: %v", r.err)
		}
		return r.got
	case <-time.After(ioTimeout):
		t.Fatal("the round trip did not finish")
		return ""
	}
}
