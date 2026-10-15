package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/proxyproto"
	"github.com/urbnywrt/postern/internal/tlsx"
)

// The helpers of the tests of this package. The tests run real TCP connections
// on the loopback interface, sequentially: several of them count the goroutines
// of the process.

// alertBytes is the TLS alert record the reject action sends, written out here
// independently of the package.
var alertBytes = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70}

// ---------------------------------------------------------------------------
// Clock and goroutines
// ---------------------------------------------------------------------------

// fakeClock is a clock that only moves when it is told to.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// checkGoroutines makes the test fail if the number of goroutines of the
// process has not come back to what it is now within 2 s of the end of the
// test. Call it first, so that its cleanup runs after all the others, which
// close the edges, backends and clients of the test.
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

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

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

func captureLogger(level slog.Level) (*slog.Logger, *logBuffer) {
	buf := &logBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})), buf
}

// ---------------------------------------------------------------------------
// Edges and configurations
// ---------------------------------------------------------------------------

// newTestEdge returns an edge that is drained at the end of the test. A
// ClientHelloTimeout left at zero becomes 3 s, so that a test that goes wrong
// does not wait for the default 10 s, a Resolver left nil is one that knows
// no name, so that no test asks the real DNS, and a CertsDir left empty is an
// empty directory of the test, so that no test reads the node's certificates.
func newTestEdge(t *testing.T, opts Options) *Edge {
	t.Helper()
	return newTestEdgeLog(t, discardLogger(), opts)
}

func newTestEdgeLog(t *testing.T, log *slog.Logger, opts Options) *Edge {
	t.Helper()
	if opts.ClientHelloTimeout == 0 {
		opts.ClientHelloTimeout = 3 * time.Second
	}
	if opts.Resolver == nil {
		opts.Resolver = fakeResolver{}
	}
	if opts.CertsDir == "" {
		opts.CertsDir = t.TempDir()
	}
	e := New(log, opts)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = e.Drain(ctx)
	})
	return e
}

func mustApply(t *testing.T, e *Edge, cfg *edgev1.EdgeConfig) {
	t.Helper()
	if err := e.Apply(cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// givenPorts are the ports that freePort has returned in this test binary.
var givenPorts sync.Map

// freePort returns a TCP port of 127.0.0.1 that was free a moment ago, and
// never the same one twice: the listener that found it is closed at once, so
// the kernel may hand the port out again, and a test that asks for two would
// get one twice.
func freePort(t *testing.T) uint32 {
	t.Helper()
	for {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("finding a free port: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		if err := ln.Close(); err != nil {
			t.Fatalf("finding a free port: %v", err)
		}
		if _, given := givenPorts.LoadOrStore(port, true); !given {
			return uint32(port)
		}
	}
}

// freeDualPort returns a TCP port that was free a moment ago on every address,
// IPv4 and IPv6.
func freeDualPort(t *testing.T) uint32 {
	t.Helper()
	ln, err := net.Listen("tcp", ":0") // a dual-stack socket
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	return uint32(port)
}

func loopback(port uint32) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))
}

// tlsListener is a TLS listener on 127.0.0.1 that drops non-TLS traffic.
func tlsListener(id string, port uint32, stranger string) *edgev1.EdgeListener {
	return &edgev1.EdgeListener{
		Id:             id,
		BindIp:         "127.0.0.1",
		Port:           port,
		Kind:           "tls",
		StrangerAction: stranger,
		NonTlsAction:   "drop",
	}
}

// engineRoute routes sni of a listener to backend, with a PROXY v2 header.
func engineRoute(listenerID, sni, proxyID string, backend netip.AddrPort) *edgev1.Route {
	return &edgev1.Route{
		ListenerId:    listenerID,
		Sni:           sni,
		ProxyId:       proxyID,
		Kind:          "engine",
		Backend:       backend.String(),
		ProxyProtocol: true,
	}
}

// oneRoute is a configuration of one listener on port that routes sni to
// backend for proxy "p1".
func oneRoute(gen uint64, port uint32, stranger, sni string, backend netip.AddrPort) *edgev1.EdgeConfig {
	return &edgev1.EdgeConfig{
		Generation: gen,
		Listeners:  []*edgev1.EdgeListener{tlsListener("l1", port, stranger)},
		Routes:     []*edgev1.Route{engineRoute("l1", sni, "p1", backend)},
	}
}

// proxyCounters returns the counters of a proxy from a snapshot, or nil.
func proxyCounters(s *edgev1.SnapshotResponse, id string) *edgev1.ProxyCounters {
	for _, p := range s.GetProxies() {
		if p.GetProxyId() == id {
			return p
		}
	}
	return nil
}

// ipCounters returns the counters of an IP of a proxy from a snapshot, or nil.
func ipCounters(s *edgev1.SnapshotResponse, proxyID, ip string) *edgev1.IpCounters {
	for _, c := range s.GetIps() {
		if c.GetProxyId() == proxyID && c.GetIp() == ip {
			return c
		}
	}
	return nil
}

// activeConns is the number of active connections of a proxy.
func activeConns(e *Edge, proxyID string) uint32 {
	return proxyCounters(e.Snapshot(true), proxyID).GetConnsActive()
}

// ---------------------------------------------------------------------------
// ClientHellos
// ---------------------------------------------------------------------------

func u16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

// helloRecord builds a small, well-formed ClientHello in one TLS record. Its
// server_name extension carries sni byte for byte, whatever it holds; with an
// empty sni the hello has no extensions at all.
func helloRecord(sni string) []byte {
	msg := helloMsg(sni, 0)
	return records(msg, len(msg))
}

// helloMsg builds the handshake message of a well-formed ClientHello with the
// server name sni (none if empty) and, when pad > 0, a padding extension of
// pad zero bytes.
func helloMsg(sni string, pad int) []byte {
	var exts []byte
	if sni != "" {
		entry := append([]byte{0}, u16(len(sni))...) // host_name
		entry = append(entry, sni...)
		list := append(u16(len(entry)), entry...)
		exts = append(u16(0), u16(len(list))...) // server_name
		exts = append(exts, list...)
	}
	if pad > 0 {
		exts = append(exts, u16(21)...) // padding
		exts = append(exts, u16(pad)...)
		exts = append(exts, make([]byte, pad)...)
	}
	body := []byte{3, 3}                                // legacy_version
	body = append(body, bytes.Repeat([]byte{7}, 32)...) // random
	body = append(body, 0)                              // empty session id
	body = append(body, 0, 2, 0x13, 0x01)               // one cipher suite
	body = append(body, 1, 0)                           // null compression
	if exts != nil {
		body = append(body, u16(len(exts))...)
		body = append(body, exts...)
	}
	return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// records frames a handshake message into TLS handshake records that carry at
// most size bytes of it each.
func records(msg []byte, size int) []byte {
	var out []byte
	for len(msg) > 0 {
		n := min(size, len(msg))
		out = append(out, 0x16, 3, 1)
		out = append(out, u16(n)...)
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

// tinyRecordHello is the costliest hello a client can send within budget
// bytes: a ClientHello for sni cut into records of one byte each, six bytes on
// the wire for every byte of the message.
func tinyRecordHello(sni string, budget int) []byte {
	base := len(helloMsg(sni, 0))
	pad := budget/6 - base - 4 // the padding extension has a 4-byte header
	return records(helloMsg(sni, pad), 1)
}

// realHello returns the first flight of a crypto/tls client for serverName:
// its ClientHello, taken off a pipe.
func realHello(t *testing.T, serverName string) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		cfg := &tls.Config{ServerName: serverName, NextProtos: []string{"h2", "http/1.1"}}
		_ = tls.Client(cli, cfg).Handshake() // fails once srv is closed below
	}()
	_ = srv.SetDeadline(time.Now().Add(5 * time.Second))
	h, err := tlsx.ReadClientHello(srv, 65536)
	_ = srv.Close()
	_ = cli.Close()
	<-done
	if err != nil {
		t.Fatalf("capturing a ClientHello of crypto/tls: %v", err)
	}
	return h.Raw
}

// ---------------------------------------------------------------------------
// Backends and mask targets
// ---------------------------------------------------------------------------

// backendConn is a connection a backend accepted, after the PROXY header and
// the ClientHello at its start were read.
type backendConn struct {
	header *proxyproto.Header // nil when the backend expects none
	hello  []byte             // the ClientHello record(s), as received
	err    error              // set when the header or the hello could not be read
	conn   net.Conn
	r      *bufio.Reader // the rest of the stream; read through it, not through conn
}

// backend is a TCP server on 127.0.0.1 that stands in for an engine.
type backend struct {
	addr     netip.AddrPort
	ln       net.Listener
	proxy    bool // read a PROXY v2 header first
	raw      bool // read nothing at all
	handler  func(bc *backendConn)
	accepted chan *backendConn
	done     chan struct{} // closed when the backend closes

	wg    sync.WaitGroup
	mu    sync.Mutex
	conns []net.Conn
}

// newBackend starts a backend. It reads a PROXY v2 header first if proxy is
// set, then the ClientHello, and passes what it read to the test (see next).
// Then it runs handler, if there is one, and closes the connection; without a
// handler the test serves the connection itself. Everything is closed at the
// end of the test.
func newBackend(t *testing.T, proxy bool, handler func(bc *backendConn)) *backend {
	t.Helper()
	return startBackend(t, proxy, false, handler)
}

// newRawServer starts a backend that reads nothing itself: the test gets every
// connection as it was accepted, and reads from bc.r.
func newRawServer(t *testing.T) *backend {
	t.Helper()
	return startBackend(t, false, true, nil)
}

func startBackend(t *testing.T, proxy, raw bool, handler func(bc *backendConn)) *backend {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting a backend: %v", err)
	}
	b := &backend{
		addr:     ln.Addr().(*net.TCPAddr).AddrPort(),
		ln:       ln,
		proxy:    proxy,
		raw:      raw,
		handler:  handler,
		accepted: make(chan *backendConn, 64),
		done:     make(chan struct{}),
	}
	b.wg.Add(1)
	go b.serve()
	t.Cleanup(b.close)
	return b
}

func (b *backend) serve() {
	defer b.wg.Done()
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		b.mu.Lock()
		b.conns = append(b.conns, c)
		b.mu.Unlock()
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			bc := b.read(c)
			select {
			case b.accepted <- bc:
			case <-b.done:
				return
			}
			if bc.err == nil && b.handler != nil {
				b.handler(bc)
				_ = c.Close()
			}
		}()
	}
}

func (b *backend) read(c net.Conn) *backendConn {
	bc := &backendConn{conn: c, r: bufio.NewReader(c)}
	if b.raw {
		return bc
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	if b.proxy {
		bc.header, bc.err = proxyproto.ReadV2(bc.r)
		if bc.err != nil {
			return bc
		}
	}
	h, err := tlsx.ReadClientHello(bc.r, 1<<20)
	bc.hello, bc.err = h.Raw, err
	return bc
}

func (b *backend) close() {
	close(b.done)
	_ = b.ln.Close()
	b.mu.Lock()
	for _, c := range b.conns {
		_ = c.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
}

// next returns the next connection the backend accepted.
func (b *backend) next(t *testing.T) *backendConn {
	t.Helper()
	select {
	case bc := <-b.accepted:
		if bc.err != nil {
			t.Fatalf("backend: reading the start of a connection: %v", bc.err)
		}
		return bc
	case <-time.After(5 * time.Second):
		t.Fatal("backend: no connection came")
		return nil
	}
}

// expectNone fails the test if the backend accepts a connection within d.
func (b *backend) expectNone(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-b.accepted:
		t.Fatal("backend: a connection came that should not have")
	case <-time.After(d):
	}
}

// echoHandler sends back whatever the client sends after its hello and
// half-closes when the client does.
func echoHandler(bc *backendConn) {
	_, _ = io.Copy(bc.conn, bc.r)
	if tc, ok := bc.conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, bc.r)
}

// maskDialer is a DialMask that records the targets asked for and connects to
// a backend of the test instead, whatever the target.
type maskDialer struct {
	to      netip.AddrPort
	targets chan string
	fail    atomic.Bool // refuse every dial
}

func newMaskDialer(to netip.AddrPort) *maskDialer {
	return &maskDialer{to: to, targets: make(chan string, 64)}
}

func (m *maskDialer) dial(ctx context.Context, addr string) (net.Conn, error) {
	m.targets <- addr
	if m.fail.Load() {
		return nil, syscall.ECONNREFUSED
	}
	// From 127.0.0.2: Linux may give a connection to the mask target the
	// port that a client of the edge on 127.0.0.1 has too, and the edge would
	// take that client for a mask loop (isMaskLoop) and close it.
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
	return d.DialContext(ctx, "tcp4", m.to.String())
}

// target returns the next target the dialer was asked for.
func (m *maskDialer) target(t *testing.T) string {
	t.Helper()
	select {
	case a := <-m.targets:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("DialMask was not called")
		return ""
	}
}

// expectNoDial fails the test if DialMask has been called.
func (m *maskDialer) expectNoDial(t *testing.T) {
	t.Helper()
	select {
	case a := <-m.targets:
		t.Fatalf("DialMask was called for %q", a)
	default:
	}
}

// fakeResolver stands in for the DNS: it knows the addresses of the names it
// has, in the order given, and no other name.
type fakeResolver map[string][]netip.Addr

// resolverOf returns a fakeResolver of pairs of a name and its addresses, the
// addresses separated by commas: resolverOf("a.example.com", "203.0.113.1").
func resolverOf(pairs ...string) fakeResolver {
	r := fakeResolver{}
	for i := 0; i+1 < len(pairs); i += 2 {
		for a := range strings.SplitSeq(pairs[i+1], ",") {
			r[pairs[i]] = append(r[pairs[i]], netip.MustParseAddr(a))
		}
	}
	return r
}

func (r fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" {
		return nil, fmt.Errorf("fakeResolver: network %q, want ip", network)
	}
	// The edge asks for absolute names (netpolicy.AbsoluteName), which a
	// resolver takes as the same name without the final dot.
	if addrs, ok := r[strings.TrimSuffix(host, ".")]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// countingConn counts the Read calls made on a connection.
type countingConn struct {
	net.Conn
	reads atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(p)
}

// tcpPair returns the two ends of a TCP connection over the loopback interface:
// the accepted one and the dialed one. Both are closed at the end of the test.
func tcpPair(t *testing.T) (accepted, dialed *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	d, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	a, err := ln.Accept()
	if err != nil {
		_ = d.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = a.Close()
		_ = d.Close()
	})
	return a.(*net.TCPConn), d.(*net.TCPConn)
}

// forwarder relays every connection it accepts to a fixed address, with
// half-close, as a NAT hairpin does: the far end sees the forwarder's address,
// not the one of the connection that came in.
type forwarder struct {
	addr netip.AddrPort
	ln   net.Listener
	wg   sync.WaitGroup
	mu   sync.Mutex
	open []net.Conn
}

func newForwarder(t *testing.T, to netip.AddrPort) *forwarder {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &forwarder{addr: ln.Addr().(*net.TCPAddr).AddrPort(), ln: ln}
	f.wg.Add(1)
	go f.serve(to)
	t.Cleanup(f.close)
	return f
}

func (f *forwarder) serve(to netip.AddrPort) {
	defer f.wg.Done()
	for {
		in, err := f.ln.Accept()
		if err != nil {
			return
		}
		out, err := net.Dial("tcp4", to.String())
		if err != nil {
			_ = in.Close()
			continue
		}
		f.mu.Lock()
		f.open = append(f.open, in, out)
		f.mu.Unlock()
		copyHalf := func(dst, src net.Conn) {
			defer f.wg.Done()
			_, _ = io.Copy(dst, src)
			_ = dst.(*net.TCPConn).CloseWrite()
		}
		f.wg.Add(2)
		go copyHalf(out, in)
		go copyHalf(in, out)
	}
}

func (f *forwarder) close() {
	_ = f.ln.Close()
	f.mu.Lock()
	for _, c := range f.open {
		_ = c.Close()
	}
	f.mu.Unlock()
	f.wg.Wait()
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

// dialEdge connects to the edge at to from the address from ("" for any
// address). Linux takes every address of 127.0.0.0/8 as a local address, which
// is how the tests have clients with different IPs. The connection is closed at
// the end of the test.
func dialEdge(t *testing.T, from string, to netip.AddrPort) *net.TCPConn {
	t.Helper()
	d := net.Dialer{Timeout: 3 * time.Second}
	if from != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(from)}
	}
	c, err := d.Dial("tcp4", to.String())
	if err != nil {
		t.Fatalf("connecting to the edge at %s: %v", to, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*net.TCPConn)
}

func send(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(b); err != nil {
		t.Fatalf("writing to the edge: %v", err)
	}
}

// readN reads exactly n bytes within 5 s.
func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("reading %d bytes: %v", n, err)
	}
	return buf
}

// readToEOF reads until the peer ends its stream, for at most d.
func readToEOF(t *testing.T, c net.Conn, d time.Duration) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("reading to the end of the stream: got %q, then %v", b, err)
	}
	return b
}

// expectClosed checks that the peer closes the connection within d without
// sending anything: the read ends with EOF or with a reset.
func expectClosed(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	b, err := io.ReadAll(c)
	if len(b) > 0 {
		t.Fatalf("expected the connection to be closed without data, got %q", b)
	}
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("expected the connection to be closed, got %v", err)
	}
}

// expectAlert checks that the edge answers with the unrecognized_name alert and
// then ends the stream.
func expectAlert(t *testing.T, c net.Conn) {
	t.Helper()
	if got := readToEOF(t, c, 5*time.Second); !bytes.Equal(got, alertBytes) {
		t.Fatalf("expected the alert % x, got % x", alertBytes, got)
	}
}

// roundTrip sends msg through an echo backend and checks that it comes back.
func roundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	send(t, c, []byte(msg))
	if got := readN(t, c, len(msg)); string(got) != msg {
		t.Fatalf("echo: got %q, want %q", got, msg)
	}
}

// openRelay connects from the address from, sends a ClientHello for sni and
// checks that the echo backend be gets it and echoes. It returns the client
// connection.
func openRelay(t *testing.T, from string, to netip.AddrPort, sni string, be *backend) *net.TCPConn {
	t.Helper()
	c := dialEdge(t, from, to)
	send(t, c, helloRecord(sni))
	be.next(t)
	roundTrip(t, c, "ping")
	return c
}
