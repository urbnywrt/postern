package edge

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// needLoopbackSources skips a test whose clients connect from several addresses
// of 127.0.0.0/8: Linux takes them all as local without any setup, other
// systems do not.
func needLoopbackSources(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("clients from several loopback addresses need Linux")
	}
}

// ingressState is what the counts of the caps are at a moment.
type ingressState struct {
	preHello int // connections before the end of their hello, the evicted ones until they give their place back
	sources  int // the sources they come from
	conns    int // every connection, the evicted ones until they end
	pending  int // the connections before their hello that may be evicted
	leaving  int // evicted connections that have not ended yet
}

func (g *ingress) state() ingressState {
	g.mu.Lock()
	defer g.mu.Unlock()
	return ingressState{preHello: g.preHello, sources: len(g.sources), conns: g.conns, pending: g.pending, leaving: g.leaving}
}

// waitPreHello waits until n connections are before the end of their hello,
// and no evicted one is still on its way out.
func waitPreHello(t *testing.T, e *Edge, n int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d connections before their hello", n), func() bool {
		s := e.ingress.state()
		return s.preHello == n && s.pending == n && s.leaving == 0
	})
}

// waitIngressIdle waits until the connections have given every place back.
func waitIngressIdle(t *testing.T, e *Edge) {
	t.Helper()
	waitFor(t, "every place in the caps to be given back", func() bool {
		return e.ingress.state() == ingressState{}
	})
}

// closedWithin reports whether the edge closes c within d without sending
// anything: a read that ends with the end of the stream or a reset, not with
// the deadline.
func closedWithin(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	n, err := c.Read(make([]byte, 1))
	var ne net.Error
	return n == 0 && err != nil && (!errors.As(err, &ne) || !ne.Timeout())
}

// expectClosedAtAccept connects from the address from, sends a whole hello for
// the route and checks that the edge closes the connection at once, without an
// answer.
func expectClosedAtAccept(t *testing.T, from string, to netip.AddrPort) {
	t.Helper()
	start := time.Now()
	c := dialEdge(t, from, to)
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = c.Write(helloRecord("proxy.example.com")) // fails if the edge has closed it already
	expectClosed(t, c, time.Second)
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("closed after %v; a connection over a cap is to be closed at once", d)
	}
}

// expectOpen checks that the edge keeps c open, and sends nothing, for d.
func expectOpen(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	n, err := c.Read(make([]byte, 1))
	var ne net.Error
	if n > 0 || !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("the connection did not stay open for %v: read %d bytes, %v", d, n, err)
	}
}

// countingCloser stands in for the connection of a ticket: it counts the
// times it is closed.
type countingCloser struct{ closed atomic.Int32 }

func (c *countingCloser) Close() error {
	c.closed.Add(1)
	return nil
}

// closes returns how often the connection of the ticket tk was closed.
func closes(tk *ticket) int32 { return tk.conn.(*countingCloser).closed.Load() }

// remoteConn is a connection that claims to come from another address.
type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }

// ---------------------------------------------------------------------------
// The caps and their counts
// ---------------------------------------------------------------------------

func TestSourceKey(t *testing.T) {
	for _, tt := range []struct{ addr, want string }{
		{"192.0.2.7", "192.0.2.7"},
		{"::ffff:192.0.2.7", "192.0.2.7"}, // an IPv4-mapped address is the IPv4 address
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::"},
		{"2001:db8:1:2::1", "2001:db8:1:2::"},
		{"2001:db8:1:2::1%eth0", "2001:db8:1:2::"}, // a zone does not matter
		{"2001:db8:1:3::1", "2001:db8:1:3::"},
		{"::1", "::"},
	} {
		if got, want := sourceKey(netip.MustParseAddr(tt.addr)), netip.MustParseAddr(tt.want); got != want {
			t.Errorf("sourceKey(%s) = %v, want %v", tt.addr, got, want)
		}
	}

	for _, tt := range []struct {
		a, b string
		same bool
	}{
		{"2001:db8:a:b::1", "2001:db8:a:b:ffff:ffff:ffff:ffff", true}, // one /64
		{"2001:db8:a:b::1", "2001:db8:a:c::1", false},                 // two /64s
		{"2001:db8:a:b::1", "2001:db8:b:b::1", false},
		{"192.0.2.1", "192.0.2.2", false}, // IPv4 goes by the address
		{"192.0.2.1", "::ffff:192.0.2.1", true},
		{"192.0.2.1", "2001:db8::c000:201", false}, // an IPv6 address that ends like it is another source
	} {
		if same := sourceKey(netip.MustParseAddr(tt.a)) == sourceKey(netip.MustParseAddr(tt.b)); same != tt.same {
			t.Errorf("%s and %s one source: %v, want %v", tt.a, tt.b, same, tt.same)
		}
	}

	if sourceKey(netip.Addr{}).IsValid() {
		t.Error("the source of the invalid address is valid")
	}
}

func TestMemoryLimit(t *testing.T) {
	const (
		cgroup   = "/sys/fs/cgroup/memory.max"
		meminfo  = "/proc/meminfo"
		machine  = "MemTotal:        8030784 kB\nMemFree:         1048576 kB\nMemAvailable:    4194304 kB\n"
		machineB = 8030784 << 10
	)
	for _, tt := range []struct {
		name  string
		files map[string]string
		want  uint64
		from  string
	}{
		{"cgroup limit", map[string]string{cgroup: "536870912\n", meminfo: machine}, 512 << 20, "cgroup"},
		{"cgroup without a limit", map[string]string{cgroup: "max\n", meminfo: machine}, machineB, "meminfo"},
		{"no cgroup v2", map[string]string{meminfo: machine}, machineB, "meminfo"},
		{"cgroup unreadable", map[string]string{cgroup: "lots\n", meminfo: machine}, machineB, "meminfo"},
		{"cgroup of nothing", map[string]string{cgroup: "0\n", meminfo: machine}, machineB, "meminfo"},
		{"MemTotal in bytes", map[string]string{meminfo: "MemTotal: 1048576\n"}, 1 << 20, "meminfo"},
		{"no MemTotal", map[string]string{meminfo: "MemFree: 1024 kB\n"}, 0, "unknown"},
		{"MemTotal unreadable", map[string]string{meminfo: "MemTotal: many kB\n"}, 0, "unknown"},
		{"MemTotal empty", map[string]string{meminfo: "MemTotal:\n"}, 0, "unknown"},
		{"no files", nil, 0, "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			read := func(name string) ([]byte, error) {
				if s, ok := tt.files[name]; ok {
					return []byte(s), nil
				}
				return nil, fs.ErrNotExist
			}
			if got, from := memoryLimit(read); got != tt.want || from != tt.from {
				t.Errorf("memoryLimit = %d from %s, want %d from %s", got, from, tt.want, tt.from)
			}
		})
	}
}

func TestDeriveCaps(t *testing.T) {
	for _, tt := range []struct {
		nofile, memory uint64
		want           caps
	}{
		// Limits that are not known: 4096 open files, and the floor of the
		// memory bound.
		{0, 0, caps{preHello: 512, conns: 1024, byFiles: 1024, byMemory: 1024}},
		// The edge container: 1048576 open files, and the memory bounds.
		{1 << 20, 8 << 30, caps{preHello: 4096, conns: 41943, byFiles: 209715, byMemory: 41943}},
		{1 << 20, 1 << 30, caps{preHello: 2621, conns: 5242, byFiles: 209715, byMemory: 5242}},
		{1 << 20, 512 << 20, caps{preHello: 1310, conns: 2621, byFiles: 209715, byMemory: 2621}},
		{1 << 20, 64 << 20, caps{preHello: 512, conns: 1024, byFiles: 209715, byMemory: 1024}}, // 327 by memory: the floor
		{1 << 20, 0, caps{preHello: 512, conns: 1024, byFiles: 209715, byMemory: 1024}},
		// Fewer open files.
		{4096, 8 << 30, caps{preHello: 512, conns: 1024, byFiles: 1024, byMemory: 41943}}, // 819 by files: the floor
		{16384, 8 << 30, caps{preHello: 1638, conns: 3276, byFiles: 3276, byMemory: 41943}},
		{65536, 8 << 30, caps{preHello: 4096, conns: 13107, byFiles: 13107, byMemory: 41943}},
		// No limit at all (RLIM_INFINITY, a huge cgroup): nothing overflows.
		{math.MaxUint64, math.MaxUint64, caps{preHello: 4096, conns: 429496729, byFiles: 429496729, byMemory: math.MaxInt32}},
		// Never a cap of nothing.
		{3, 1 << 30, caps{preHello: 1, conns: 1024, byFiles: 1024, byMemory: 5242}},
	} {
		got := deriveCaps(tt.nofile, tt.memory)
		if got != tt.want {
			t.Errorf("deriveCaps(%d, %d) = %+v, want %+v", tt.nofile, tt.memory, got, tt.want)
		}
		if got.preHello > got.conns/2 && got.preHello > 1 {
			t.Errorf("deriveCaps(%d, %d): the pre-hello cap %d is over half the total %d", tt.nofile, tt.memory, got.preHello, got.conns)
		}
	}
}

func TestCapsAreLoggedAtStart(t *testing.T) {
	log, buf := captureLogger(slog.LevelInfo)
	New(log, Options{MaxConns: 2000})
	nofile := openFileLimit()
	memory, from := systemMemory()
	c := deriveCaps(nofile, memory)
	openFiles := "unknown"
	if nofile != 0 {
		openFiles = fmt.Sprint(nofile)
	}
	out := buf.String()
	for _, want := range []string{
		"edge: connection caps", "open_files=" + openFiles + " ", fmt.Sprintf("memory=%d ", memory), "memory_from=" + from + " ",
		fmt.Sprintf("max_conns_by_open_files=%d ", c.byFiles), fmt.Sprintf("max_conns_by_memory=%d ", c.byMemory),
		"max_conns=2000 ", fmt.Sprintf("max_prehello=%d ", c.preHello), "max_prehello_per_source=16",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the log of a new edge lacks %q:\n%s", want, out)
		}
	}
}

func TestIngressAdmit(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	v4 := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}) }
	newIngressOf := func(maxPreHello, maxConns int, hello time.Duration) *ingress {
		return newIngress(Options{MaxPreHello: maxPreHello, MaxConns: maxConns, ClientHelloTimeout: hello})
	}
	// admit lets a connection from a in, and says whether it took the place
	// of the oldest one before its hello.
	admit := func(t *testing.T, g *ingress, a netip.Addr) (*ticket, bool) {
		t.Helper()
		tk, over, evicted := g.admit(&countingCloser{}, a, false, now)
		if tk == nil {
			t.Fatalf("a connection from %v was refused, over the %s cap", a, over)
		}
		return tk, evicted
	}
	let := func(t *testing.T, g *ingress, a netip.Addr) *ticket {
		t.Helper()
		tk, evicted := admit(t, g, a)
		if evicted {
			t.Fatalf("a connection from %v took the place of another, want a free place", a)
		}
		return tk
	}
	refuse := func(t *testing.T, g *ingress, a netip.Addr, want string) {
		t.Helper()
		if tk, over, evicted := g.admit(&countingCloser{}, a, false, now); tk != nil || over != want || evicted {
			t.Fatalf("a connection from %v: ticket %v, over %q, evicted %v; want it refused over the %s cap", a, tk, over, evicted, want)
		}
	}
	expectState := func(t *testing.T, g *ingress, want ingressState) {
		t.Helper()
		if got := g.state(); got != want {
			t.Fatalf("counts %+v, want %+v", got, want)
		}
	}
	expectCounted := func(t *testing.T, g *ingress, refusedPreHello, refusedTotal, evicted uint64) {
		t.Helper()
		p, c, v := g.refusedPreHello.Load(), g.refusedTotal.Load(), g.evictedPreHello.Load()
		if p != refusedPreHello || c != refusedTotal || v != evicted {
			t.Errorf("refused %d before the hello and %d over the total, evicted %d; want %d, %d and %d",
				p, c, v, refusedPreHello, refusedTotal, evicted)
		}
	}
	// gone plays the goroutine of an evicted connection: its read fails, and it
	// ends.
	gone := func(tk *ticket) {
		tk.helloRead()
		tk.release()
	}

	t.Run("the oldest makes way when the edge is full", func(t *testing.T) {
		g := newIngressOf(4, 100, 10*time.Second)
		var tks []*ticket
		for i := range 4 {
			tks = append(tks, let(t, g, v4(i)))
		}
		tk, evicted := admit(t, g, v4(10))
		if !evicted {
			t.Fatal("a connection to a full edge was let in without taking the place of the oldest")
		}
		if closes(tks[0]) != 1 || closes(tks[1]) != 0 || closes(tk) != 0 {
			t.Fatalf("closed: the oldest %d times, the next %d, the newcomer %d; want only the oldest, once",
				closes(tks[0]), closes(tks[1]), closes(tk))
		}
		// The evicted connection gives its places back itself, when its
		// goroutine sees the connection closed; until then it is counted, but
		// not as one that may be evicted.
		expectState(t, g, ingressState{preHello: 5, sources: 5, conns: 5, pending: 4, leaving: 1})
		gone(tks[0])
		gone(tks[0])
		expectState(t, g, ingressState{preHello: 4, sources: 4, conns: 4, pending: 4, leaving: 0})
		if closes(tks[0]) != 1 {
			t.Errorf("the evicted connection was closed %d times, want once", closes(tks[0]))
		}

		// A connection past its hello is not evicted: the oldest of the others goes.
		tks[1].helloRead()
		let(t, g, v4(11))
		if _, evicted := admit(t, g, v4(12)); !evicted || closes(tks[2]) != 1 || closes(tks[1]) != 0 {
			t.Errorf("evicted %v; closed: the one past its hello %d times, the oldest before it %d; want the latter, once",
				evicted, closes(tks[1]), closes(tks[2]))
		}
		expectCounted(t, g, 0, 0, 2)
	})

	t.Run("evictions on their way out are bounded", func(t *testing.T) {
		g := newIngressOf(2, 100, 10*time.Second)
		a, b := let(t, g, v4(1)), let(t, g, v4(2))
		c, _ := admit(t, g, v4(3)) // evicts a
		admit(t, g, v4(4))         // evicts b
		// a and b have not ended yet: as many are on their way out as there may
		// be before their hello, and the next one is refused instead.
		refuse(t, g, v4(5), capPreHello)
		gone(a)
		if _, evicted := admit(t, g, v4(6)); !evicted || closes(c) != 1 {
			t.Errorf("evicted %v, the oldest closed %d times; want it evicted once a place is free", evicted, closes(c))
		}
		gone(b)
		expectCounted(t, g, 1, 0, 3)
	})

	t.Run("the pre-hello cap of a source", func(t *testing.T) {
		g := newIngressOf(100, 1000, 10*time.Second)
		v6 := func(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("2001:db8:7:7::%x", i)) }
		var first *ticket
		for i := range perSourcePreHello {
			tk := let(t, g, v4(1))
			if i == 0 {
				first = tk
			}
			let(t, g, v6(i+1)) // another address of the /64 every time
		}
		expectState(t, g, ingressState{preHello: 32, sources: 2, conns: 32, pending: 32})
		refuse(t, g, v4(1), capPreHello)
		refuse(t, g, netip.MustParseAddr("::ffff:198.51.100.1"), capPreHello)
		refuse(t, g, netip.MustParseAddr("2001:db8:7:7:ffff::1"), capPreHello)
		let(t, g, v4(2))                                  // the next address
		let(t, g, netip.MustParseAddr("2001:db8:7:8::1")) // the next /64

		first.helloRead()
		let(t, g, v4(1))
		expectCounted(t, g, 3, 0, 0)

		// With the edge full as well, the source is refused and nobody is evicted.
		g = newIngressOf(perSourcePreHello, 1000, 10*time.Second)
		var tks []*ticket
		for range perSourcePreHello {
			tks = append(tks, let(t, g, v4(1)))
		}
		refuse(t, g, v4(1), capPreHello)
		if closes(tks[0]) != 0 {
			t.Error("a connection refused over the cap of its source evicted another")
		}
		if _, evicted := admit(t, g, v4(2)); !evicted || closes(tks[0]) != 1 {
			t.Error("a connection from another source did not take the place of the oldest")
		}
	})

	t.Run("the total cap", func(t *testing.T) {
		g := newIngressOf(4, 6, 10*time.Second)
		var tks []*ticket
		for i := range 6 {
			tk := let(t, g, v4(i))
			tk.helloRead() // relayed or masked: held, but no longer before its hello
			tks = append(tks, tk)
		}
		expectState(t, g, ingressState{conns: 6})
		refuse(t, g, v4(10), capTotal) // room before the hello, none in all
		tks[0].release()
		expectState(t, g, ingressState{conns: 5})
		let(t, g, v4(10))
		refuse(t, g, v4(11), capTotal)
		expectCounted(t, g, 0, 2, 0)

		// Full with connections before their hello, the oldest of them makes way
		// for the newcomer: it leaves the total as well.
		g = newIngressOf(2, 2, 10*time.Second)
		a := let(t, g, v4(1))
		let(t, g, v4(2))
		if _, evicted := admit(t, g, v4(3)); !evicted || closes(a) != 1 {
			t.Fatal("a newcomer to an edge full of connections before their hello did not take the place of the oldest")
		}
		expectState(t, g, ingressState{preHello: 3, sources: 3, conns: 3, pending: 2, leaving: 1})
		gone(a)
		expectState(t, g, ingressState{preHello: 2, sources: 2, conns: 2, pending: 2})
		expectCounted(t, g, 0, 0, 1)
	})

	t.Run("the hello deadline follows the load", func(t *testing.T) {
		g := newIngressOf(6, 100, 10*time.Second) // half the cap is 3
		deadline := func(tk *ticket) time.Duration { return tk.helloBy.Sub(now) }
		var tks []*ticket
		for i := range 6 {
			tk := let(t, g, v4(i))
			want := 10 * time.Second
			if i > 3 { // more than half the cap taken by others
				want = 3 * time.Second
			}
			if got := deadline(tk); got != want {
				t.Errorf("connection %d, with %d others before their hello: %v for the hello, want %v", i+1, i, got, want)
			}
			tks = append(tks, tk)
		}
		// A newcomer to a full edge, in the place of the oldest, is under load.
		tk, _ := admit(t, g, v4(6))
		if got := deadline(tk); got != 3*time.Second {
			t.Errorf("a connection in the place of the oldest: %v for the hello, want 3s", got)
		}
		gone(tks[0])
		tk.release()
		// Back to half the cap, the full time again; the others keep theirs.
		tks[1].release()
		tks[2].helloRead()
		if got := deadline(let(t, g, v4(10))); got != 10*time.Second {
			t.Errorf("with 3 others before their hello: %v for the hello, want 10s", got)
		}
		if got := deadline(let(t, g, v4(11))); got != 3*time.Second {
			t.Errorf("with 4 others before their hello: %v for the hello, want 3s", got)
		}
		if got := deadline(tks[3]); got != 10*time.Second {
			t.Errorf("a connection admitted before the load came has %v for the hello now, want its 10s", got)
		}

		// A ClientHelloTimeout shorter than 3 s is not made longer.
		g = newIngressOf(4, 100, time.Second)
		for range 3 {
			let(t, g, v4(1))
		}
		if got := deadline(let(t, g, v4(1))); got != time.Second {
			t.Errorf("under load with a ClientHelloTimeout of 1s: %v for the hello, want 1s", got)
		}
	})

	t.Run("places are given back once", func(t *testing.T) {
		g := newIngressOf(4, 4, 10*time.Second)
		a, b := let(t, g, v4(1)), let(t, g, v4(1))
		a.helloRead()
		a.helloRead()
		expectState(t, g, ingressState{preHello: 1, sources: 1, conns: 2, pending: 1})
		a.release()
		a.release()
		b.release() // before its hello: both places
		b.release()
		expectState(t, g, ingressState{})
	})

	t.Run("a probe holds no place", func(t *testing.T) {
		g := newIngressOf(1, 1, 10*time.Second)
		first := let(t, g, v4(1))
		for range 3 {
			p, over, evicted := g.admit(&countingCloser{}, v4(1), true, now)
			if p == nil || !p.probe || over != "" || evicted {
				t.Fatalf("a probe at the caps: ticket %v, over %q, evicted %v; want it let in", p, over, evicted)
			}
			if got := p.helloBy.Sub(now); got != 10*time.Second {
				t.Errorf("a probe has %v for its hello, want the ClientHelloTimeout", got)
			}
			p.helloRead()
			p.release()
		}
		if closes(first) != 0 {
			t.Error("a probe evicted a connection")
		}
		expectState(t, g, ingressState{preHello: 1, sources: 1, conns: 1, pending: 1})
		expectCounted(t, g, 0, 0, 0)
	})
}

// ---------------------------------------------------------------------------
// The caps on real connections
// ---------------------------------------------------------------------------

func TestPreHelloCapHoldsAgainstAFlood(t *testing.T) {
	needLoopbackSources(t)
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	const maxPreHello, flood, sources = 32, 200, 20
	e := newTestEdge(t, Options{MaxPreHello: maxPreHello, ClientHelloTimeout: 10 * time.Second})
	// Above half the cap a new connection has 3 s for its hello, which a slow
	// run of the test could see run out; the test is about the cap.
	e.ingress.fastHello = 10 * time.Second
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))
	hello := helloRecord("proxy.example.com")

	// The flood: clients from 20 addresses, 10 from each (fewer than a source
	// may have), that send the first byte of a hello and nothing more. Each
	// one past the cap takes the place of the oldest.
	type client struct {
		c      net.Conn
		closed bool
	}
	clients := make([]client, flood)
	var wg sync.WaitGroup
	for i := range flood {
		wg.Go(func() {
			from := fmt.Sprintf("127.0.1.%d", 1+i%sources)
			d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(from)}}
			c, err := d.Dial("tcp4", loopback(port).String())
			if err != nil {
				t.Errorf("client %d from %s: %v", i, from, err)
				return
			}
			_ = c.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = c.Write(hello[:1]) // fails if the edge has closed it already
			clients[i] = client{c: c, closed: closedWithin(c, 2*time.Second)}
		})
	}
	wg.Wait()
	var open []net.Conn
	closed := 0
	for _, cl := range clients {
		if cl.c == nil {
			continue
		}
		t.Cleanup(func() { _ = cl.c.Close() })
		// One evicted after its own read gave up is closed by now as well.
		if cl.closed || closedWithin(cl.c, 10*time.Millisecond) {
			closed++
		} else {
			open = append(open, cl.c)
		}
	}
	if len(open) != maxPreHello || closed != flood-maxPreHello {
		t.Fatalf("%d clients held and %d closed, want %d and %d: the cap does not hold", len(open), closed, maxPreHello, flood-maxPreHello)
	}
	waitPreHello(t, e, maxPreHello)
	// The cap of the edge is full; one evicted at a time, as long as the
	// evicted ones end as fast as they are replaced, and refused otherwise.
	snap := e.Snapshot(true)
	if p, v := snap.GetRefusedPrehello(), snap.GetEvictedPrehello(); p+v != flood-maxPreHello || v == 0 || snap.GetRefusedTotal() != 0 {
		t.Errorf("Snapshot counts %d evicted, %d refused before the hello and %d over the total; want %d evicted or refused, and 0",
			v, p, snap.GetRefusedTotal(), flood-maxPreHello)
	}

	// A well-formed hello from a fresh address is routed, and an old silent
	// client makes way for it.
	relayed := openRelay(t, "127.0.2.2", loopback(port), "proxy.example.com", be)
	gone := 0
	for _, c := range open {
		if closedWithin(c, 10*time.Millisecond) {
			gone++
		}
	}
	if gone != 1 {
		t.Errorf("%d silent clients closed for the new one, want 1", gone)
	}

	// After the flood every place comes back, and every goroutine ends (see
	// checkGoroutines).
	for _, c := range append(open, relayed) {
		_ = c.Close()
	}
	waitIngressIdle(t, e)
}

func TestEvictionMakesRoomForANewHello(t *testing.T) {
	checkGoroutines(t)
	log, buf := captureLogger(slog.LevelInfo)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdgeLog(t, log, Options{MaxPreHello: 4, ClientHelloTimeout: 10 * time.Second})
	e.ingress.fastHello = 10 * time.Second // no deadline runs out in the test
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))

	// The cap is full of silent connections, opened one after the other.
	var silent []net.Conn
	for i := range 4 {
		silent = append(silent, dialEdge(t, "", loopback(port)))
		waitPreHello(t, e, i+1)
	}

	// A new one with a well-formed hello is routed, and the oldest silent one
	// is closed to make room; the others stay.
	c := openRelay(t, "", loopback(port), "proxy.example.com", be)
	expectClosed(t, silent[0], time.Second)
	for _, s := range silent[1:] {
		expectOpen(t, s, 10*time.Millisecond)
	}
	// The relay is past its hello. Once the cap is full again, the next
	// newcomer makes the next oldest go.
	silent = append(silent, dialEdge(t, "", loopback(port)))
	waitPreHello(t, e, 4)
	openRelay(t, "", loopback(port), "proxy.example.com", be)
	expectClosed(t, silent[1], time.Second)
	for _, s := range silent[2:] {
		expectOpen(t, s, 10*time.Millisecond)
	}

	snap := e.Snapshot(true)
	if snap.GetEvictedPrehello() != 2 || snap.GetRefusedPrehello() != 0 || snap.GetRefusedTotal() != 0 {
		t.Errorf("Snapshot counts %d evicted, %d refused before the hello and %d over the total; want 2, 0 and 0",
			snap.GetEvictedPrehello(), snap.GetRefusedPrehello(), snap.GetRefusedTotal())
	}
	waitFor(t, "the warning", func() bool { return strings.Contains(buf.String(), "evicted_prehello=1 ") })
	if strings.Contains(buf.String(), "evicted_prehello=2 ") {
		t.Errorf("two warnings within a minute:\n%s", buf)
	}

	// The relays are past their hello: three silent ones are left before it.
	waitPreHello(t, e, 3)
	_ = c.Close()
	for _, s := range silent {
		_ = s.Close()
	}
}

func TestPreHelloCapPerSource(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port := freePort(t)
	e := newTestEdge(t, Options{ClientHelloTimeout: 10 * time.Second})
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", be.addr))
	hello := helloRecord("proxy.example.com")

	var pending []net.Conn
	for range 16 {
		c := dialEdge(t, "", loopback(port))
		send(t, c, hello[:5]) // the header of the record, and nothing of the hello yet
		pending = append(pending, c)
	}
	waitPreHello(t, e, 16)

	// The 17th from the address is closed at once while the 16 are pending.
	expectClosedAtAccept(t, "", loopback(port))
	be.expectNone(t, 100*time.Millisecond)
	if got := e.Snapshot(true).GetRefusedPrehello(); got != 1 {
		t.Errorf("Snapshot counts %d refused before the hello, want 1", got)
	}
	for _, c := range pending {
		expectOpen(t, c, 10*time.Millisecond)
	}

	t.Run("another source has its own", func(t *testing.T) {
		needLoopbackSources(t)
		openRelay(t, "127.0.0.3", loopback(port), "proxy.example.com", be)
	})

	// One of the 16 done, the address may open another, and that one is routed.
	_ = pending[0].Close()
	waitPreHello(t, e, 15)
	openRelay(t, "", loopback(port), "proxy.example.com", be)
	if got := e.Snapshot(true).GetRefusedPrehello(); got != 1 {
		t.Errorf("Snapshot counts %d refused before the hello, want still 1", got)
	}
}

func TestHelloDeadlineShortensUnderLoad(t *testing.T) {
	checkGoroutines(t)
	port := freePort(t)
	const fast = 300 * time.Millisecond
	e := newTestEdge(t, Options{MaxPreHello: 4, ClientHelloTimeout: 10 * time.Second})
	e.ingress.fastHello = fast // the 3 s of the edge, shortened for the test
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", loopback(freePort(t))))

	// open connects a silent client and waits until the edge counts it.
	n := 0
	open := func() net.Conn {
		c := dialEdge(t, "", loopback(port))
		n++
		waitPreHello(t, e, n)
		return c
	}

	// Up to half the cap (2 of 4) taken by others, a connection has the whole
	// ClientHelloTimeout.
	c1, c2, c3 := open(), open(), open()

	// With 3 others it has the short deadline.
	start := time.Now()
	c4 := open()
	expectClosed(t, c4, 3*time.Second)
	n--
	if d := time.Since(start); d < fast-50*time.Millisecond || d > 2*time.Second {
		t.Errorf("a connection under load was closed after %v, want it closed at its short deadline of %v", d, fast)
	}
	// The connections that came before keep their deadline.
	for _, c := range []net.Conn{c1, c2, c3} {
		expectOpen(t, c, 10*time.Millisecond)
	}

	// Back under half the cap, a new connection has the whole time again.
	_ = c1.Close()
	_ = c2.Close()
	n -= 2
	waitPreHello(t, e, n)
	c5 := open()
	expectOpen(t, c5, fast+300*time.Millisecond)
	expectOpen(t, c3, 10*time.Millisecond)
}

func TestConnsCapAtAccept(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	site := newBackend(t, false, echoHandler)
	md := newMaskDialer(site.addr)
	port := freePort(t)
	e := newTestEdge(t, Options{MaxConns: 3, DialMask: md.dial, ClientHelloTimeout: 10 * time.Second,
		Resolver: resolverOf("pool.example.com", "203.0.113.10")})
	cfg := oneRoute(1, port, "mask", "proxy.example.com", be.addr)
	cfg.MaskDomains = []string{"pool.example.com"}
	mustApply(t, e, cfg)
	conns := func() int { return e.ingress.state().conns }

	// Relayed, masked and before its hello: three connections held.
	relayed := openRelay(t, "", loopback(port), "proxy.example.com", be)
	masked := dialEdge(t, "", loopback(port))
	send(t, masked, helloRecord("pool.example.com"))
	md.target(t)
	site.next(t)
	roundTrip(t, masked, "masked")
	silent := dialEdge(t, "", loopback(port))
	waitFor(t, "three connections held", func() bool { return conns() == 3 })
	if s := e.ingress.state(); s != (ingressState{preHello: 1, sources: 1, conns: 3, pending: 1}) {
		t.Fatalf("counts %+v; want the silent one before its hello, of 3", s)
	}

	// The fourth is closed at accept.
	expectClosedAtAccept(t, "", loopback(port))
	be.expectNone(t, 100*time.Millisecond)
	snap := e.Snapshot(true)
	if snap.GetRefusedTotal() != 1 || snap.GetRefusedPrehello() != 0 || snap.GetEvictedPrehello() != 0 {
		t.Errorf("Snapshot counts %d refused over the total, %d before the hello, %d evicted; want 1, 0 and 0",
			snap.GetRefusedTotal(), snap.GetRefusedPrehello(), snap.GetEvictedPrehello())
	}

	// Each of them holds its place until it ends; then a new one takes it.
	for _, held := range []net.Conn{relayed, masked, silent} {
		_ = held.Close()
		waitFor(t, "the place to be given back", func() bool { return conns() == 2 })
		openRelay(t, "", loopback(port), "proxy.example.com", be)
		expectClosedAtAccept(t, "", loopback(port))
	}
	if got := e.Snapshot(true).GetRefusedTotal(); got != 4 {
		t.Errorf("Snapshot counts %d refused over the total, want 4", got)
	}
}

func TestCapsSpareProbes(t *testing.T) {
	checkGoroutines(t)
	be := newBackend(t, true, echoHandler)
	port, testPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{MaxPreHello: 2, MaxConns: 1, ClientHelloTimeout: 10 * time.Second})
	cfg := oneRoute(1, port, "reject", "proxy.example.com", be.addr)
	cfg.TestListeners = []*edgev1.TestListener{{Port: testPort, ListenerId: "l1"}}
	mustApply(t, e, cfg)

	dialEdge(t, "", loopback(port)) // silent: the public listener is full
	waitPreHello(t, e, 1)
	expectClosedAtAccept(t, "", loopback(port))

	// The node's own probes, on the test listener, go through and take no place.
	probe := dialEdge(t, "", loopback(testPort))
	for range 3 {
		openRelay(t, "", loopback(testPort), "proxy.example.com", be)
	}
	expectOpen(t, probe, 10*time.Millisecond)
	if s := e.ingress.state(); s != (ingressState{preHello: 1, sources: 1, conns: 1, pending: 1}) {
		t.Errorf("counts %+v: the probes are counted", s)
	}

	// A probe comes from the loopback interface: a connection to the test
	// listener from any other address is held to the caps like any other.
	srv, cli := tcpPair(t)
	from := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}
	e.accept(loopback(testPort), remoteConn{Conn: srv, remote: from})
	expectClosed(t, cli, time.Second)
	if s := e.Snapshot(true); s.GetRefusedTotal() != 2 || s.GetRefusedPrehello() != 0 {
		t.Errorf("Snapshot counts %d refused over the total and %d before the hello, want 2 and 0",
			s.GetRefusedTotal(), s.GetRefusedPrehello())
	}
}

// Every way a connection can go gives its places back: the counts come back to
// zero.
func TestCapPlacesAreGivenBack(t *testing.T) {
	checkGoroutines(t)
	log, _ := captureLogger(slog.LevelInfo) // the panic below is logged
	be := newBackend(t, true, echoHandler)
	site := newBackend(t, false, echoHandler)
	md := newMaskDialer(site.addr)
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		if addr == "203.0.113.66:443" { // boom.example.com
			panic("the mask dialer exploded")
		}
		return md.dial(ctx, addr)
	}
	port, port2, dead := freePort(t), freePort(t), freePort(t)
	e := newTestEdgeLog(t, log, Options{DialMask: dial, ClientHelloTimeout: 300 * time.Millisecond,
		Resolver: resolverOf("pool.example.com", "203.0.113.10", "boom.example.com", "203.0.113.66")})
	e.dropDelay = func() time.Duration { return 50 * time.Millisecond }
	l2 := tlsListener("l2", port2, "drop")
	l2.NonTlsAction = "http400"
	mustApply(t, e, &edgev1.EdgeConfig{
		Generation:  1,
		Listeners:   []*edgev1.EdgeListener{tlsListener("l1", port, "mask"), l2},
		Routes:      []*edgev1.Route{engineRoute("l1", "proxy.example.com", "p1", be.addr), engineRoute("l1", "dead.example.com", "p2", loopback(dead))},
		MaskDomains: []string{"pool.example.com", "boom.example.com"},
	})
	hello := helloRecord("proxy.example.com")

	_ = openRelay(t, "", loopback(port), "proxy.example.com", be).Close() // relayed

	c := dialEdge(t, "", loopback(port)) // masked
	send(t, c, helloRecord("pool.example.com"))
	md.target(t)
	site.next(t)
	roundTrip(t, c, "masked")
	_ = c.Close()

	c = dialEdge(t, "", loopback(port)) // a stranger that is rejected
	send(t, c, helloRecord("other.example.com"))
	expectAlert(t, c)
	_ = c.Close() // the edge waits for the end of the client's side after an answer

	c = dialEdge(t, "", loopback(port)) // the backend is down
	send(t, c, helloRecord("dead.example.com"))
	expectClosed(t, c, 3*time.Second)

	c = dialEdge(t, "", loopback(port)) // silent until the hello deadline
	expectClosed(t, c, 3*time.Second)

	c = dialEdge(t, "", loopback(port)) // cut off in the middle of the hello
	send(t, c, hello[:20])
	_ = c.Close()

	c = dialEdge(t, "", loopback(port)) // a panic while it is served
	send(t, c, helloRecord("boom.example.com"))
	expectClosed(t, c, 3*time.Second)

	c = dialEdge(t, "", loopback(port2)) // a stranger that is dropped
	send(t, c, helloRecord("other.example.com"))
	expectClosed(t, c, 3*time.Second)

	c = dialEdge(t, "", loopback(port2)) // not TLS
	send(t, c, []byte("GET / HTTP/1.1\r\n\r\n"))
	if got := readToEOF(t, c, 3*time.Second); !strings.HasPrefix(string(got), "HTTP/1.1 400") {
		t.Errorf("not TLS: got %q, want the 400 answer", got)
	}
	_ = c.Close()

	waitIngressIdle(t, e)
	if s := e.Snapshot(true); s.GetRefusedPrehello() != 0 || s.GetRefusedTotal() != 0 || s.GetEvictedPrehello() != 0 {
		t.Errorf("refusals counted where there was none: %v", s)
	}

	// A connection accepted as a drain begins is closed, and takes no place.
	e.conns.drain()
	srv, cli := tcpPair(t)
	e.accept(loopback(port), srv)
	expectClosed(t, cli, time.Second)
	if s := e.ingress.state(); s != (ingressState{}) {
		t.Errorf("counts %+v after a connection the drain closed", s)
	}
}

func TestRefusalsAreLogged(t *testing.T) {
	needLoopbackSources(t)
	checkGoroutines(t)
	const client = "127.0.0.9"
	clk := newFakeClock()
	log, buf := captureLogger(slog.LevelInfo)
	port := freePort(t)
	e := newTestEdgeLog(t, log, Options{MaxPreHello: 2, MaxConns: 1, Now: clk.Now, ClientHelloTimeout: 10 * time.Second})
	mustApply(t, e, oneRoute(1, port, "reject", "proxy.example.com", loopback(freePort(t))))
	dialEdge(t, client, loopback(port))
	waitPreHello(t, e, 1)

	warnings := func() []string {
		var out []string
		for line := range strings.Lines(buf.String()) {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, "refused_total=") {
				out = append(out, line)
			}
		}
		return out
	}
	for range 3 {
		expectClosedAtAccept(t, client, loopback(port))
	}
	waitFor(t, "the warning", func() bool { return len(warnings()) > 0 })
	w := warnings()
	if len(w) != 1 {
		t.Fatalf("%d warnings for three refusals within a minute, want one:\n%s", len(w), buf)
	}
	for _, want := range []string{"refused_prehello=0 ", "refused_total=1 ", "evicted_prehello=0 "} {
		if !strings.Contains(w[0], want) {
			t.Errorf("the warning lacks %q: %s", want, w[0])
		}
	}
	if strings.Contains(buf.String(), client) {
		t.Errorf("a client address is in the log at info level:\n%s", buf)
	}

	// At most once a minute, by the clock of the edge.
	e.warnCaps()
	clk.Advance(59 * time.Second)
	e.warnCaps()
	if n := len(warnings()); n != 1 {
		t.Errorf("%d warnings within a minute, want one:\n%s", n, buf)
	}
	clk.Advance(time.Second)
	e.warnCaps()
	e.warnCaps()
	// The edge closes a refused connection before it warns, so the warning of
	// the third refusal may still be on its way: if it comes now, it is the
	// second, and the calls above find the minute taken. Either way there are
	// two, and the second counts every refusal.
	waitFor(t, "the second warning", func() bool { return len(warnings()) >= 2 })
	if n := len(warnings()); n != 2 {
		t.Errorf("%d warnings a minute after the first, want two:\n%s", n, buf)
	}
	if w := warnings(); !strings.Contains(w[len(w)-1], "refused_total=3 ") {
		t.Errorf("the second warning does not count every refusal since the start: %s", w[len(w)-1])
	}
}
