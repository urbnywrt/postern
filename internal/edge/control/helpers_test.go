package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/gen/go/postern/edge/v1/edgev1connect"
	"github.com/urbnywrt/postern/internal/edge"
	"github.com/urbnywrt/postern/internal/edge/egress"
)

// The tests here run a real edge, router and SOCKS ports behind the control
// service, with real TCP connections on the loopback interface and a unix
// socket for the control calls. They run one after the other: several count the
// goroutines of the process.

var quiet = slog.New(slog.DiscardHandler)

// logBuffer collects log output; it is safe for concurrent use.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// checkGoroutines makes the test fail if the number of goroutines of the
// process has not come back to what it is now within 2 s of the end of the
// test. Call it first, so that its cleanup runs after all the others.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := runtime.NumGoroutine()
	t.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			n := runtime.NumGoroutine()
			if n <= before {
				return
			}
			if time.Now().After(deadline) {
				buf := make([]byte, 1<<20)
				buf = buf[:runtime.Stack(buf, true)]
				t.Errorf("%d goroutines before the test, %d two seconds after it:\n%s", before, n, buf)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// waitFor polls cond until it holds, for at most 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// shortDir returns a new temporary directory with a short path: the path of a
// unix socket may not be longer than 107 bytes, and t.TempDir includes the name
// of the test.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ec")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// freePorts returns n different TCP ports of 127.0.0.1 that were free a moment
// ago.
func freePorts(t *testing.T, n int) []uint32 {
	t.Helper()
	var lns []net.Listener
	var ports []uint32
	for range n {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("finding a free port: %v", err)
		}
		lns = append(lns, ln) // held, so that the next one is another port
		ports = append(ports, uint32(ln.Addr().(*net.TCPAddr).Port))
	}
	for _, ln := range lns {
		_ = ln.Close()
	}
	return ports
}

func addr(port uint32) string { return fmt.Sprintf("127.0.0.1:%d", port) }

// portOpen reports whether something accepts connections at 127.0.0.1:port.
func portOpen(port uint32) bool {
	c, err := net.DialTimeout("tcp4", addr(port), time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// echoBackend starts a TCP server on 127.0.0.1 that sends back what it gets,
// and returns its address. It stands in for an engine: the edge replays the
// ClientHello to it, so the first thing it echoes is the hello.
func echoBackend(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = io.Copy(c, c)
				_ = c.Close() // the client is done: end the stream, or the relay never ends
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

// helloRecord builds a small, well-formed ClientHello in one TLS record for the
// server name sni.
func helloRecord(sni string) []byte {
	u16 := func(n int) []byte { return []byte{byte(n >> 8), byte(n)} }
	entry := append([]byte{0}, u16(len(sni))...) // host_name
	entry = append(entry, sni...)
	list := append(u16(len(entry)), entry...)
	exts := append(u16(0), u16(len(list))...) // server_name
	exts = append(exts, list...)

	body := []byte{3, 3}                                // legacy_version
	body = append(body, bytes.Repeat([]byte{7}, 32)...) // random
	body = append(body, 0)                              // empty session id
	body = append(body, 0, 2, 0x13, 0x01)               // one cipher suite
	body = append(body, 1, 0)                           // null compression
	body = append(body, u16(len(exts))...)
	body = append(body, exts...)
	msg := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append(append([]byte{0x16, 3, 1}, u16(len(msg))...), msg...)
}

// relay connects to the edge at port, sends a ClientHello for sni and checks
// that the echo backend behind the route is reached: the hello comes back, and
// then a message of the test. The connection is closed at the end of the test.
func relay(t *testing.T, port uint32, sni string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr(port), 3*time.Second)
	if err != nil {
		t.Fatalf("connecting to the edge at %s: %v", addr(port), err)
	}
	t.Cleanup(func() { _ = c.Close() })
	hello := helloRecord(sni)
	write(t, c, hello)
	if got := readN(t, c, len(hello)); !bytes.Equal(got, hello) {
		t.Fatalf("the backend did not get the ClientHello byte for byte")
	}
	roundTrip(t, c, "ping")
	return c
}

func write(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(b); err != nil {
		t.Fatalf("writing: %v", err)
	}
}

func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("reading %d bytes: %v", n, err)
	}
	return buf
}

func roundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	write(t, c, []byte(msg))
	if got := readN(t, c, len(msg)); string(got) != msg {
		t.Fatalf("echo: got %q, want %q", got, msg)
	}
}

// closedSoon reports whether the peer of c closes the connection within d: a
// read that ends with EOF or with a reset, not with the deadline.
func closedSoon(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := io.ReadAll(c)
	var ne net.Error
	return !errors.As(err, &ne) || !ne.Timeout()
}

// aliveFor checks that the connection c carries on for d: it still echoes at
// the end of the time.
func aliveFor(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	time.Sleep(d)
	roundTrip(t, c, "still there")
}

// ---------------------------------------------------------------------------
// The configurations of the tests
// ---------------------------------------------------------------------------

// routeConfig is a configuration of one TLS listener on port that routes the
// server name proxy.example.com to backend for the proxy p1.
func routeConfig(gen uint64, port uint32, backend netip.AddrPort) *edgev1.EdgeConfig {
	return &edgev1.EdgeConfig{
		Generation: gen,
		Listeners: []*edgev1.EdgeListener{{
			Id: "l1", BindIp: "127.0.0.1", Port: port, Kind: "tls",
			StrangerAction: "reject", NonTlsAction: "drop",
		}},
		Routes: []*edgev1.Route{{
			ListenerId: "l1", Sni: "proxy.example.com", ProxyId: "p1", Kind: "engine",
			Backend: backend.String(),
		}},
	}
}

// withEgress adds a chain c with one direct member m and a SOCKS port that
// leads into it.
func withEgress(cfg *edgev1.EdgeConfig, chain, member string, socksPort uint32) *edgev1.EdgeConfig {
	cfg.Chains = append(cfg.Chains, &edgev1.Chain{
		Id:      chain,
		Members: []*edgev1.ChainMember{{Key: member, Kind: "direct"}},
	})
	cfg.Socks = append(cfg.Socks, &edgev1.SocksPort{Port: socksPort, ProxyId: "p1", DefaultChainId: chain})
	return cfg
}

// duplicateListener makes cfg invalid for the edge, and for the edge alone: a
// second listener takes the address of the first.
func duplicateListener(cfg *edgev1.EdgeConfig) *edgev1.EdgeConfig {
	dup := cfg.GetListeners()[0]
	cfg.Listeners = append(cfg.Listeners, &edgev1.EdgeListener{
		Id: "l2", BindIp: dup.GetBindIp(), Port: dup.GetPort(), Kind: "tls",
		StrangerAction: "reject", NonTlsAction: "drop",
	})
	return cfg
}

func proxyCounters(s *edgev1.SnapshotResponse, id string) *edgev1.ProxyCounters {
	for _, p := range s.GetProxies() {
		if p.GetProxyId() == id {
			return p
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------

// rig is a control service on a unix socket in front of a real edge, router
// and SOCKS ports, with a client of it.
type rig struct {
	t       *testing.T
	logs    *logBuffer
	edge    *edge.Edge
	router  *egress.Router
	socks   *egress.SocksPorts
	srv     *Server
	cfgPath string
	sock    string
	hs      *http.Server
	client  edgev1connect.EdgeControlServiceClient
}

// newRig starts the service. It is stopped at the end of the test: a drain with
// no time to wait, and the shutdown of the HTTP server.
func newRig(t *testing.T) *rig {
	t.Helper()
	return newRigLevel(t, slog.LevelDebug)
}

// newRigLevel is newRig with a log that has the lines of level and above.
func newRigLevel(t *testing.T, level slog.Level) *rig {
	t.Helper()
	return newRigWith(t, level, edge.Options{ClientHelloTimeout: 3 * time.Second})
}

// newRigWith is newRigLevel with an edge of the given options.
func newRigWith(t *testing.T, level slog.Level, opts edge.Options) *rig {
	t.Helper()
	checkGoroutines(t)
	logs := &logBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: level}))
	dir := shortDir(t)
	r := &rig{
		t:       t,
		logs:    logs,
		cfgPath: filepath.Join(dir, "config.json"),
		sock:    filepath.Join(dir, "s.sock"),
	}
	r.edge = edge.New(log, opts)
	r.router = egress.NewRouter(log)
	r.socks = egress.NewSocksPorts(log, r.router)
	r.srv = NewServer(r.edge, r.router, r.socks, r.cfgPath, log)

	ln, err := ListenUnix(r.sock)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	r.hs = &http.Server{Handler: r.srv.Handler()}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = r.hs.Serve(ln)
	}()
	r.client = NewClient(r.sock)
	t.Cleanup(func() {
		r.srv.BeginDrain(0)
		select {
		case <-r.srv.Drained():
		case <-time.After(5 * time.Second):
			t.Error("the drain at the end of the test did not finish")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.hs.Shutdown(ctx); err != nil {
			t.Errorf("shutting the HTTP server down: %v", err)
		}
		<-served
	})
	return r
}

func callCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// set sends a configuration and returns the answer. A transport error fails
// the test: rejection is applied=false, not an error.
func (r *rig) set(cfg *edgev1.EdgeConfig) *edgev1.SetConfigResponse {
	r.t.Helper()
	ctx, cancel := callCtx()
	defer cancel()
	resp, err := r.client.SetConfig(ctx, connect.NewRequest(&edgev1.SetConfigRequest{Config: cfg}))
	if err != nil {
		r.t.Fatalf("SetConfig: %v", err)
	}
	return resp.Msg
}

func (r *rig) mustSet(cfg *edgev1.EdgeConfig) {
	r.t.Helper()
	if resp := r.set(cfg); !resp.GetApplied() {
		r.t.Fatalf("SetConfig refused a configuration that is good: %s", resp.GetError())
	}
}

// mustRefuse sends a configuration that is not to be applied, and returns the
// reason.
func (r *rig) mustRefuse(cfg *edgev1.EdgeConfig) string {
	r.t.Helper()
	resp := r.set(cfg)
	if resp.GetApplied() {
		r.t.Fatal("SetConfig applied a configuration that is bad")
	}
	if resp.GetError() == "" {
		r.t.Fatal("SetConfig refused a configuration without saying why")
	}
	return resp.GetError()
}

func (r *rig) snapshot() *edgev1.SnapshotResponse {
	r.t.Helper()
	ctx, cancel := callCtx()
	defer cancel()
	resp, err := r.client.Snapshot(ctx, connect.NewRequest(&edgev1.SnapshotRequest{}))
	if err != nil {
		r.t.Fatalf("Snapshot: %v", err)
	}
	return resp.Msg
}

func (r *rig) health() *edgev1.HealthResponse {
	r.t.Helper()
	ctx, cancel := callCtx()
	defer cancel()
	resp, err := r.client.Health(ctx, connect.NewRequest(&edgev1.HealthRequest{}))
	if err != nil {
		r.t.Fatalf("Health: %v", err)
	}
	return resp.Msg
}

func (r *rig) drain(maxSeconds uint32) {
	r.t.Helper()
	ctx, cancel := callCtx()
	defer cancel()
	if _, err := r.client.Drain(ctx, connect.NewRequest(&edgev1.DrainRequest{MaxSeconds: maxSeconds})); err != nil {
		r.t.Fatalf("Drain: %v", err)
	}
}

// savedConfig returns the configuration in the file of the rig.
func (r *rig) savedConfig() *edgev1.EdgeConfig {
	r.t.Helper()
	cfg, err := LoadConfig(r.cfgPath)
	if err != nil {
		r.t.Fatalf("the saved configuration: %v", err)
	}
	return cfg
}

// savedBytes returns the content of the file of the rig, nil if there is none.
func (r *rig) savedBytes() []byte {
	r.t.Helper()
	b, err := os.ReadFile(r.cfgPath)
	if err != nil && !os.IsNotExist(err) {
		r.t.Fatal(err)
	}
	return b
}

// drained reports whether the drain is over.
func (r *rig) drained() bool {
	select {
	case <-r.srv.Drained():
		return true
	default:
		return false
	}
}

// waitDrained waits for the end of the drain, for at most d.
func (r *rig) waitDrained(d time.Duration) bool {
	select {
	case <-r.srv.Drained():
		return true
	case <-time.After(d):
		return false
	}
}
