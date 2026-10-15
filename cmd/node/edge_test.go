package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/gen/go/postern/edge/v1/edgev1connect"
	"github.com/urbnywrt/postern/internal/edge/control"
	"github.com/urbnywrt/postern/internal/probe/probetest"
)

// TestMain lets the tests run this test binary as postern-node: a process of the
// edge that gets real signals and has a real exit status.
func TestMain(m *testing.M) {
	if os.Getenv(asMainEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

const asMainEnv = "POSTERN_NODE_TEST_AS_MAIN"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// checkGoroutines makes the test fail if the goroutines of the process have not
// come back to their number at the start within 2 s of the end of the test.
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

// shortDir returns a temporary directory with a path short enough for a unix
// socket.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "en")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func freePorts(t *testing.T, n int) []uint32 {
	t.Helper()
	var lns []net.Listener
	var ports []uint32
	for range n {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("finding a free port: %v", err)
		}
		lns = append(lns, ln)
		ports = append(ports, uint32(ln.Addr().(*net.TCPAddr).Port))
	}
	for _, ln := range lns {
		_ = ln.Close()
	}
	return ports
}

func addr(port uint32) string { return fmt.Sprintf("127.0.0.1:%d", port) }

func portOpen(port uint32) bool {
	c, err := net.DialTimeout("tcp4", addr(port), time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// echoBackend starts a TCP server on 127.0.0.1 that sends back what it gets:
// first of all the ClientHello that the edge replays to it.
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
				_ = c.Close()
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

// helloRecord builds a small, well-formed ClientHello for the server name sni.
func helloRecord(sni string) []byte {
	u16 := func(n int) []byte { return []byte{byte(n >> 8), byte(n)} }
	entry := append([]byte{0}, u16(len(sni))...)
	entry = append(entry, sni...)
	list := append(u16(len(entry)), entry...)
	exts := append(u16(0), u16(len(list))...)
	exts = append(exts, list...)
	body := []byte{3, 3}
	body = append(body, bytes.Repeat([]byte{7}, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0)
	body = append(body, u16(len(exts))...)
	body = append(body, exts...)
	msg := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append(append([]byte{0x16, 3, 1}, u16(len(msg))...), msg...)
}

// relay connects to the edge at port, and checks that a ClientHello for sni
// gets through to the echo backend and that the connection then carries data.
func relay(t *testing.T, port uint32, sni string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr(port), 3*time.Second)
	if err != nil {
		t.Fatalf("connecting to the edge at %s: %v", addr(port), err)
	}
	t.Cleanup(func() { _ = c.Close() })
	hello := helloRecord(sni)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(hello); err != nil {
		t.Fatalf("writing the hello: %v", err)
	}
	if _, err := io.ReadFull(c, make([]byte, len(hello))); err != nil {
		t.Fatalf("reading the echo of the hello: %v", err)
	}
	echo(t, c, "ping")
	return c
}

func echo(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("writing: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != msg {
		t.Fatalf("echo: got %q, %v; want %q", got, err, msg)
	}
}

// closedSoon reports whether the peer of c closes the connection within d.
func closedSoon(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := io.ReadAll(c)
	var ne net.Error
	return !errors.As(err, &ne) || !ne.Timeout()
}

// routeConfig is a configuration of one TLS listener on port that routes
// proxy.example.com to backend, for the generation gen.
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

// paths returns the options of an edge process in a new directory, with the
// configuration cfg already in its file.
func paths(t *testing.T, cfg *edgev1.EdgeConfig) edgeOptions {
	t.Helper()
	dir := shortDir(t)
	opts := edgeOptions{configPath: filepath.Join(dir, "config.json"), socketPath: filepath.Join(dir, "s.sock")}
	if cfg != nil {
		if err := control.SaveConfig(opts.configPath, cfg); err != nil {
			t.Fatal(err)
		}
	}
	return opts
}

func health(t *testing.T, c edgev1connect.EdgeControlServiceClient) (*edgev1.HealthResponse, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Health(ctx, connect.NewRequest(&edgev1.HealthRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// ---------------------------------------------------------------------------
// An edge process inside the test process
// ---------------------------------------------------------------------------

// edgeRun is serveEdge running in a goroutine of the test, with signals that
// the test sends.
type edgeRun struct {
	t      *testing.T
	opts   edgeOptions
	sigs   chan os.Signal
	logs   *syncBuffer
	exited chan struct{}
	code   int // the exit code, once exited is closed
	client edgev1connect.EdgeControlServiceClient
}

// startEdge runs the edge process on opts and waits until it answers on its
// socket. sigtermWait is the cap of the drain that SIGTERM begins.
func startEdge(t *testing.T, opts edgeOptions, sigtermWait time.Duration) *edgeRun {
	t.Helper()
	checkGoroutines(t)
	r := &edgeRun{
		t:      t,
		opts:   opts,
		sigs:   make(chan os.Signal, 4),
		logs:   &syncBuffer{},
		exited: make(chan struct{}),
		client: control.NewClient(opts.socketPath),
	}
	go func() {
		r.code = serveEdge(opts, r.logs, r.sigs, sigtermWait)
		close(r.exited)
	}()
	t.Cleanup(func() {
		select {
		case <-r.exited:
		default:
			r.sigs <- os.Interrupt
			select {
			case <-r.exited:
			case <-time.After(5 * time.Second):
				t.Error("the edge did not stop at the end of the test")
			}
		}
	})
	waitFor(t, "the control socket to answer\n"+r.logs.String(), func() bool {
		select {
		case <-r.exited:
			t.Fatalf("the edge exited with %d before it answered:\n%s", r.code, r.logs.String())
		default:
		}
		_, err := health(t, r.client)
		return err == nil
	})
	return r
}

// wait returns the exit code, waiting for at most d for the process to exit.
func (r *edgeRun) wait(d time.Duration) (code int, exited bool) {
	select {
	case <-r.exited:
		return r.code, true
	case <-time.After(d):
		return 0, false
	}
}

func (r *edgeRun) running() bool {
	select {
	case <-r.exited:
		return false
	default:
		return true
	}
}

func (r *edgeRun) mustExit(d time.Duration) {
	r.t.Helper()
	code, ok := r.wait(d)
	if !ok {
		r.t.Fatalf("the edge did not exit within %v:\n%s", d, r.logs.String())
	}
	if code != 0 {
		r.t.Fatalf("the edge exited with %d, want 0:\n%s", code, r.logs.String())
	}
}

func (r *edgeRun) setConfig(cfg *edgev1.EdgeConfig) *edgev1.SetConfigResponse {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := r.client.SetConfig(ctx, connect.NewRequest(&edgev1.SetConfigRequest{Config: cfg}))
	if err != nil {
		r.t.Fatalf("SetConfig: %v", err)
	}
	return resp.Msg
}

func (r *edgeRun) drain(maxSeconds uint32) {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.client.Drain(ctx, connect.NewRequest(&edgev1.DrainRequest{MaxSeconds: maxSeconds})); err != nil {
		r.t.Fatalf("Drain: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

func TestEdgeFlags(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "no flags", args: []string{"edge"}, wantCode: 2, wantStderr: "--config is required"},
		{name: "only config", args: []string{"edge", "--config", "c.json"}, wantCode: 2, wantStderr: "--socket is required"},
		{name: "only socket", args: []string{"edge", "--socket", "s.sock"}, wantCode: 2, wantStderr: "--config is required"},
		{name: "empty values", args: []string{"edge", "--config", "", "--socket", ""}, wantCode: 2, wantStderr: "is required"},
		{name: "unknown flag", args: []string{"edge", "--bogus"}, wantCode: 2, wantStderr: "bogus"},
		{name: "a flag without its value", args: []string{"edge", "--config"}, wantCode: 2, wantStderr: "config"},
		{name: "extra argument", args: []string{"edge", "--config", "c.json", "--socket", "s.sock", "extra"}, wantCode: 2, wantStderr: `unexpected argument "extra"`},
		{name: "help", args: []string{"edge", "-h"}, wantCode: 0, wantStdout: "Usage: postern-node edge"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("run(%q) = %d, want %d (stderr %q)", tt.args, code, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
			if tt.wantCode == 2 {
				if stdout.Len() != 0 {
					t.Errorf("stdout = %q, want it empty on a usage error", stdout.String())
				}
				if !strings.Contains(stderr.String(), "Usage: postern-node edge") {
					t.Errorf("stderr = %q, want the usage", stderr.String())
				}
			}
		})
	}
}

// The usage that the program prints lists the command.
func TestUsageListsEdge(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(nil, io.Discard, &stderr); code != 2 || !strings.Contains(stderr.String(), "edge") {
		t.Errorf("run(nil) = %d, usage %q: want 2 and a line for the edge command", code, stderr.String())
	}
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

func TestEdgeStartupFailures(t *testing.T) {
	be := echoBackend(t)

	t.Run("no configuration file", func(t *testing.T) {
		opts := paths(t, nil)
		var stdout, stderr syncBuffer
		code := run([]string{"edge", "--config", opts.configPath, "--socket", opts.socketPath}, &stdout, &stderr)
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), opts.configPath) {
			t.Errorf("stderr %q does not name the file", stderr.String())
		}
		if _, err := os.Lstat(opts.socketPath); err == nil {
			t.Error("a socket was opened without a configuration")
		}
	})

	t.Run("malformed configuration file", func(t *testing.T) {
		opts := paths(t, nil)
		if err := os.WriteFile(opts.configPath, []byte(`{"generation": `), 0o600); err != nil {
			t.Fatal(err)
		}
		var stderr syncBuffer
		if code := run([]string{"edge", "--config", opts.configPath, "--socket", opts.socketPath}, io.Discard, &stderr); code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		if _, err := os.Lstat(opts.socketPath); err == nil {
			t.Error("a socket was opened with a configuration that could not be read")
		}
	})

	t.Run("a configuration that cannot be applied", func(t *testing.T) {
		port := freePorts(t, 1)[0]
		cfg := routeConfig(1, port, be)
		cfg.Routes[0].ListenerId = "nope" // a route of a listener that is not there
		opts := paths(t, cfg)
		var stderr syncBuffer
		if code := run([]string{"edge", "--config", opts.configPath, "--socket", opts.socketPath}, io.Discard, &stderr); code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "nope") {
			t.Errorf("stderr %q does not say what is wrong", stderr.String())
		}
		if _, err := os.Lstat(opts.socketPath); err == nil {
			t.Error("a socket was opened for an edge that is not configured")
		}
	})

	t.Run("a listener that cannot be bound", func(t *testing.T) {
		// A plain listener holds the port, and does not share it as the edge
		// does. That fails the listener, not the edge: it comes up, reports
		// the failure, and tries the bind again (internal/edge).
		port := freePorts(t, 1)[0]
		occupied, err := net.Listen("tcp4", addr(port))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = occupied.Close() }()
		r := startEdge(t, paths(t, routeConfig(1, port, be)), 30*time.Second)
		h, err := health(t, r.client)
		if err != nil {
			t.Fatal(err)
		}
		f := h.GetListenerFailures()
		if h.GetGeneration() != 1 || len(h.GetBound()) != 0 || len(f) != 1 || f[0].GetListenerId() != "l1" || !strings.Contains(f[0].GetReason(), addr(port)) {
			t.Errorf("Health = %v, want generation 1, nothing bound and the failure of l1 at %s", h, addr(port))
		}
		if !strings.Contains(r.logs.String(), "l1") {
			t.Errorf("the log %q does not say which listener failed", r.logs.String())
		}
		r.sigs <- os.Interrupt
		r.mustExit(5 * time.Second)
	})

	t.Run("a socket that cannot be opened", func(t *testing.T) {
		ports := freePorts(t, 2)
		cfg := routeConfig(1, ports[0], be)
		cfg.Socks = []*edgev1.SocksPort{{Port: ports[1], ProxyId: "p1"}}
		opts := paths(t, cfg)
		opts.socketPath = filepath.Join(filepath.Dir(opts.socketPath), "missing", "s.sock")
		var stderr syncBuffer
		if code := run([]string{"edge", "--config", opts.configPath, "--socket", opts.socketPath}, io.Discard, &stderr); code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		// What was bound is let go: the process is not left holding the ports.
		waitFor(t, "the ports to be free again", func() bool { return !portOpen(ports[0]) && !portOpen(ports[1]) })
	})

	t.Run("a socket that is in use", func(t *testing.T) {
		port := freePorts(t, 1)[0]
		opts := paths(t, routeConfig(1, port, be))
		other, err := control.ListenUnix(opts.socketPath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		var stderr syncBuffer
		if code := run([]string{"edge", "--config", opts.configPath, "--socket", opts.socketPath}, io.Discard, &stderr); code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "in use") {
			t.Errorf("stderr %q does not say that the socket is in use", stderr.String())
		}
		waitFor(t, "the port to be free again", func() bool { return !portOpen(port) })
	})
}

// The edge comes up from its file, and is configured when it first answers: the
// socket is opened after the configuration is applied, not before.
func TestEdgeComesUpFromTheFile(t *testing.T) {
	be := echoBackend(t)
	ports := freePorts(t, 2)
	cfg := routeConfig(6, ports[0], be)
	cfg.Chains = []*edgev1.Chain{{Id: "c1", Members: []*edgev1.ChainMember{{Key: "m1", Kind: "direct"}}}}
	cfg.Socks = []*edgev1.SocksPort{{Port: ports[1], ProxyId: "p1", DefaultChainId: "c1"}}
	opts := paths(t, cfg)

	r := startEdge(t, opts, 30*time.Second)

	// The very first answer already shows the configuration.
	h, err := health(t, r.client)
	if err != nil {
		t.Fatal(err)
	}
	if h.GetGeneration() != 6 || !slices.Equal(h.GetBound(), []string{addr(ports[0])}) || !h.GetListening() {
		t.Errorf("Health = %v, want generation 6 and %s", h, addr(ports[0]))
	}
	if !portOpen(ports[1]) {
		t.Error("the SOCKS port is not open")
	}
	relay(t, ports[0], "proxy.example.com")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snap, err := r.client.Snapshot(ctx, connect.NewRequest(&edgev1.SnapshotRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if snap.Msg.GetGeneration() != 6 || len(snap.Msg.GetHealth()) != 1 {
		t.Errorf("Snapshot = %v, want generation 6 and the member of chain c1", snap.Msg)
	}

	fi, err := os.Lstat(opts.socketPath)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Mode().Type() != os.ModeSocket {
		t.Errorf("control socket: %v, %v; want a socket, mode 600", fi, err)
	}

	// The log says that it is so: the three parts are applied, and then the socket
	// is opened.
	logs := r.logs.String()
	applied := strings.Index(logs, "control: configuration applied")
	opened := strings.Index(logs, "edge: control socket open")
	if applied < 0 || opened < 0 || applied > opened {
		t.Errorf("the configuration was applied at %d and the socket opened at %d in the log, want the first before the second:\n%s", applied, opened, logs)
	}
}

// SetConfig changes what the process does and what it will do after a restart,
// and the generation that it keeps is the one from the file.
func TestEdgeSetConfigIsKeptForTheNextStart(t *testing.T) {
	be := echoBackend(t)
	ports := freePorts(t, 2)
	opts := paths(t, routeConfig(4, ports[0], be))

	r := startEdge(t, opts, 30*time.Second)
	next := routeConfig(4, ports[1], be) // another listener, the same generation
	next.MaskDomains = []string{"mask.example.com"}
	if resp := r.setConfig(next); !resp.GetApplied() {
		t.Fatalf("SetConfig: %s", resp.GetError())
	}
	if resp := r.setConfig(routeConfig(5, ports[1], be)); resp.GetApplied() {
		t.Error("SetConfig took another generation than the one of the file")
	}
	saved, err := control.LoadConfig(opts.configPath)
	if err != nil || !proto.Equal(saved, next) {
		t.Fatalf("the file holds %v, %v; want the configuration that was set", saved, err)
	}
	_ = relay(t, ports[1], "proxy.example.com").Close()

	r.sigs <- syscall.SIGTERM
	r.mustExit(5 * time.Second)

	// The next start, without anybody to configure it, is the configuration that
	// was set last.
	r2 := startEdge(t, opts, 30*time.Second)
	h, err := health(t, r2.client)
	if err != nil {
		t.Fatal(err)
	}
	if h.GetGeneration() != 4 || !slices.Equal(h.GetBound(), []string{addr(ports[1])}) {
		t.Errorf("Health after the restart = %v, want generation 4 on %s", h, addr(ports[1]))
	}
	relay(t, ports[1], "proxy.example.com")
}

// ---------------------------------------------------------------------------
// Stopping
// ---------------------------------------------------------------------------

func TestEdgeSIGTERMDrains(t *testing.T) {
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	opts := paths(t, routeConfig(1, port, be))
	r := startEdge(t, opts, 30*time.Second)
	c := relay(t, port, "proxy.example.com")

	r.sigs <- syscall.SIGTERM

	waitFor(t, "the listener to close", func() bool { return !portOpen(port) })
	time.Sleep(300 * time.Millisecond)
	if !r.running() {
		t.Fatalf("the edge exited with a connection open:\n%s", r.logs.String())
	}
	echo(t, c, "still there")
	h, err := health(t, r.client)
	if err != nil || h.GetListening() {
		t.Errorf("Health while draining = %v, %v; want it answered, not listening", h, err)
	}

	_ = c.Close()
	r.mustExit(5 * time.Second)
	if _, err := os.Lstat(opts.socketPath); err == nil {
		t.Error("the socket is left behind")
	}
}

func TestEdgeSIGTERMGivesUpAfterTheCap(t *testing.T) {
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	r := startEdge(t, paths(t, routeConfig(1, port, be)), 400*time.Millisecond)
	c := relay(t, port, "proxy.example.com")

	start := time.Now()
	r.sigs <- syscall.SIGTERM
	if _, exited := r.wait(150 * time.Millisecond); exited {
		t.Fatal("the edge exited before the cap, with a connection open")
	}
	r.mustExit(5 * time.Second)
	if d := time.Since(start); d < 350*time.Millisecond {
		t.Errorf("the edge exited after %v, want it to wait for the cap of 400 ms", d)
	}
	if !closedSoon(c, 2*time.Second) {
		t.Error("the connection that was left was not closed")
	}
}

func TestEdgeSIGTERMWhenIdleExitsAtOnce(t *testing.T) {
	r := startEdge(t, paths(t, routeConfig(1, freePorts(t, 1)[0], echoBackend(t))), 30*time.Second)
	r.sigs <- syscall.SIGTERM
	r.mustExit(3 * time.Second)
}

func TestEdgeSIGINTStopsAtOnce(t *testing.T) {
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	r := startEdge(t, paths(t, routeConfig(1, port, be)), 30*time.Second)
	c := relay(t, port, "proxy.example.com")

	r.sigs <- os.Interrupt

	r.mustExit(3 * time.Second)
	if !closedSoon(c, 2*time.Second) {
		t.Error("the connection was not closed by the interrupt")
	}
}

// An interrupt after a SIGTERM does not wait for the cap either.
func TestEdgeSIGINTAfterSIGTERM(t *testing.T) {
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	r := startEdge(t, paths(t, routeConfig(1, port, be)), 30*time.Second)
	c := relay(t, port, "proxy.example.com")

	r.sigs <- syscall.SIGTERM
	waitFor(t, "the listener to close", func() bool { return !portOpen(port) })
	if !r.running() {
		t.Fatal("the edge exited with a connection open")
	}
	r.sigs <- os.Interrupt
	r.mustExit(3 * time.Second)
	if !closedSoon(c, 2*time.Second) {
		t.Error("the connection was not closed by the interrupt")
	}
}

// Drain over the socket is the other way to stop: the process exits by itself
// when it has drained.
func TestEdgeDrainRPCStopsTheProcess(t *testing.T) {
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	opts := paths(t, routeConfig(1, port, be))
	r := startEdge(t, opts, 30*time.Second)
	c := relay(t, port, "proxy.example.com")

	r.drain(30)
	if portOpen(port) {
		t.Error("the listener is open after Drain has answered")
	}
	time.Sleep(300 * time.Millisecond)
	if !r.running() {
		t.Fatalf("the edge exited with a connection open:\n%s", r.logs.String())
	}
	echo(t, c, "still there")

	_ = c.Close()
	r.mustExit(5 * time.Second)
	if _, err := os.Lstat(opts.socketPath); err == nil {
		t.Error("the socket is left behind")
	}
}

// An edge with nothing open exits as soon as it has answered Drain, and the
// answer gets through.
func TestEdgeDrainRPCWhenIdle(t *testing.T) {
	r := startEdge(t, paths(t, routeConfig(1, freePorts(t, 1)[0], echoBackend(t))), 30*time.Second)
	r.drain(30) // fails the test if the answer does not arrive
	r.mustExit(3 * time.Second)
}

// ---------------------------------------------------------------------------
// The health loop
// ---------------------------------------------------------------------------

// The process runs the health checks of the egress, and runs them once: a
// second loop would probe next to the first.
func TestEdgeRunsOneHealthLoop(t *testing.T) {
	const (
		interval = time.Second // the interval of the health check
		want     = 4           // the probes to wait for: three gaps
	)
	be := echoBackend(t)
	port := freePorts(t, 1)[0]

	// A datacenter that answers the checks (a member is up only on a resPQ), and
	// says when each probe got its answer.
	probes := make(chan time.Time, 32)
	dc, err := probetest.NewServer(probetest.Answers, func() {
		select {
		case probes <- time.Now():
		default: // the test has what it needs
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dc.Close() })
	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.5\n")
	}))
	t.Cleanup(echoSrv.Close)

	cfg := routeConfig(1, port, be)
	cfg.Chains = []*edgev1.Chain{{Id: "c1", Members: []*edgev1.ChainMember{{Key: "m1", Kind: "direct"}}}}
	cfg.Health = &edgev1.HealthCheck{
		IntervalSeconds: uint32(interval / time.Second), TimeoutSeconds: 2,
		DcAddrs:  []string{dc.Addr()},
		EchoUrls: []string{echoSrv.URL},
	}
	r := startEdge(t, paths(t, cfg), 30*time.Second)

	status := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		snap, err := r.client.Snapshot(ctx, connect.NewRequest(&edgev1.SnapshotRequest{}))
		if err != nil || len(snap.Msg.GetHealth()) != 1 {
			return "?"
		}
		return snap.Msg.GetHealth()[0].GetStatus()
	}
	waitFor(t, "the member to be up", func() bool { return status() == "up" })

	// A round begins an interval after the one before it began, so one loop
	// probes the datacenter once an interval, however slow the machine is, and a
	// second loop would probe it next to the first. The test does not count the
	// probes of a stretch of the clock, which a slow machine stretches: it waits
	// for four of them (the first is the round that made the member up) and
	// checks that no two came less than half an interval after one another.
	var at []time.Time
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for len(at) < want {
		select {
		case when := <-probes:
			at = append(at, when)
		case <-deadline.C:
			t.Fatalf("%d probes of the datacenter in 30 s with an interval of %v, want %d", len(at), interval, want)
		}
	}
	for i := 1; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap < interval/2 {
			t.Errorf("probes %d and %d of the datacenter came %v apart, with an interval of %v: want at least %v (one loop)",
				i, i+1, gap, interval, interval/2)
		}
	}

	r.sigs <- syscall.SIGTERM
	r.mustExit(5 * time.Second) // the goroutine check at the end of the test sees to the loop ending
}

// ---------------------------------------------------------------------------
// A real process
// ---------------------------------------------------------------------------

// edgeProc is the edge as a process of its own: this test binary run as
// postern-node.
type edgeProc struct {
	t      *testing.T
	cmd    *exec.Cmd
	logs   *syncBuffer
	waited chan struct{}
	err    error // the result of Wait, once waited is closed
	client edgev1connect.EdgeControlServiceClient
}

func startProc(t *testing.T, opts edgeOptions) *edgeProc {
	t.Helper()
	p := &edgeProc{t: t, logs: &syncBuffer{}, waited: make(chan struct{}), client: control.NewClient(opts.socketPath)}
	p.cmd = exec.Command(os.Args[0], "edge", "--config", opts.configPath, "--socket", opts.socketPath)
	p.cmd.Env = append(os.Environ(), asMainEnv+"=1")
	p.cmd.Stderr = p.logs
	p.cmd.Stdout = p.logs
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.waited)
	}()
	t.Cleanup(func() {
		select {
		case <-p.waited:
		default:
			_ = p.cmd.Process.Kill()
			<-p.waited
		}
	})
	waitFor(t, "the process to answer\n"+p.logs.String(), func() bool {
		select {
		case <-p.waited:
			t.Fatalf("the process exited before it answered: %v\n%s", p.err, p.logs.String())
		default:
		}
		_, err := health(t, p.client)
		return err == nil
	})
	return p
}

func (p *edgeProc) signal(s syscall.Signal) {
	p.t.Helper()
	if err := p.cmd.Process.Signal(s); err != nil {
		p.t.Fatalf("signal %v: %v", s, err)
	}
}

func (p *edgeProc) running() bool {
	select {
	case <-p.waited:
		return false
	default:
		return true
	}
}

// exitCode waits for the process and returns its exit code, -1 when it was
// killed by a signal.
func (p *edgeProc) exitCode(d time.Duration) int {
	p.t.Helper()
	select {
	case <-p.waited:
	case <-time.After(d):
		p.t.Fatalf("the process did not exit within %v:\n%s", d, p.logs.String())
	}
	if p.err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(p.err, &ee) {
		return ee.ExitCode()
	}
	p.t.Fatalf("waiting for the process: %v", p.err)
	return 0
}

func TestEdgeProcessSIGTERM(t *testing.T) {
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	opts := paths(t, routeConfig(1, port, be))
	p := startProc(t, opts)
	c := relay(t, port, "proxy.example.com")

	p.signal(syscall.SIGTERM)

	waitFor(t, "the listener to close", func() bool { return !portOpen(port) })
	time.Sleep(300 * time.Millisecond)
	if !p.running() {
		t.Fatalf("the process exited with a connection open: %d\n%s", p.exitCode(time.Second), p.logs.String())
	}
	echo(t, c, "still there")

	_ = c.Close()
	if code := p.exitCode(5 * time.Second); code != 0 {
		t.Errorf("exit code = %d, want 0\n%s", code, p.logs.String())
	}
	if _, err := os.Lstat(opts.socketPath); err == nil {
		t.Error("the socket is left behind")
	}
}

func TestEdgeProcessSIGINT(t *testing.T) {
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	p := startProc(t, paths(t, routeConfig(1, port, be)))
	c := relay(t, port, "proxy.example.com")

	p.signal(syscall.SIGINT)

	if code := p.exitCode(5 * time.Second); code != 0 {
		t.Errorf("exit code = %d, want 0\n%s", code, p.logs.String())
	}
	if !closedSoon(c, 2*time.Second) {
		t.Error("the connection was not closed")
	}
}

func TestEdgeProcessDrainRPC(t *testing.T) {
	be := echoBackend(t)
	port := freePorts(t, 1)[0]
	p := startProc(t, paths(t, routeConfig(1, port, be)))
	c := relay(t, port, "proxy.example.com")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := p.client.Drain(ctx, connect.NewRequest(&edgev1.DrainRequest{MaxSeconds: 30})); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if !p.running() {
		t.Fatalf("the process exited with a connection open:\n%s", p.logs.String())
	}
	echo(t, c, "still there")
	_ = c.Close()
	if code := p.exitCode(5 * time.Second); code != 0 {
		t.Errorf("exit code = %d, want 0\n%s", code, p.logs.String())
	}
}

// A process that is killed leaves its socket; the next one starts from what the
// first was last given, without the agent.
func TestEdgeProcessRestartAfterKill(t *testing.T) {
	be := echoBackend(t)
	ports := freePorts(t, 2)
	opts := paths(t, routeConfig(3, ports[0], be))

	first := startProc(t, opts)
	next := routeConfig(3, ports[1], be)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := first.client.SetConfig(ctx, connect.NewRequest(&edgev1.SetConfigRequest{Config: next}))
	if err != nil || !resp.Msg.GetApplied() {
		t.Fatalf("SetConfig: %v, %v", resp, err)
	}
	if err := first.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if code := first.exitCode(5 * time.Second); code != -1 {
		t.Fatalf("exit code after the kill = %d, want -1", code)
	}
	if fi, err := os.Lstat(opts.socketPath); err != nil || fi.Mode().Type() != os.ModeSocket {
		t.Fatalf("the killed process left %v, %v; this test is about a stale socket", fi, err)
	}

	second := startProc(t, opts)
	h, err := health(t, second.client)
	if err != nil {
		t.Fatal(err)
	}
	if h.GetGeneration() != 3 || !slices.Equal(h.GetBound(), []string{addr(ports[1])}) {
		t.Errorf("Health after the restart = %v, want generation 3 on %s", h, addr(ports[1]))
	}
	relay(t, ports[1], "proxy.example.com")
}
