package socks5_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/urbnywrt/postern/internal/socks5"
)

// No test in this package calls t.Parallel. TestNoGoroutineLeak counts the
// goroutines of the whole process, and that only means something while nothing
// else runs next to it.

// ---------------------------------------------------------------------------
// Wire-format helpers. Everything the tests expect on the wire is spelled out by
// hand after RFC 1928 (SOCKS5) and RFC 1929 (user name and password), so that
// the tests share no code with the server and the client they check.
// ---------------------------------------------------------------------------

const (
	socksVer = 0x05 // version of the protocol
	authVer  = 0x01 // version of the user name and password sub-negotiation

	methNoAuth   = 0x00
	methGSSAPI   = 0x01
	methUserPass = 0x02
	methNone     = 0xff // in the server's answer: no method is acceptable

	cmdConnect = 0x01
	cmdBind    = 0x02
	cmdUDP     = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repOK          = 0x00
	repGeneral     = 0x01
	repNotAllowed  = 0x02
	repNetUnreach  = 0x03
	repHostUnreach = 0x04
	repRefused     = 0x05
	repTTL         = 0x06
	repCmd         = 0x07
	repAtyp        = 0x08
)

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// hello is the greeting of a client: version, number of methods, the methods.
func hello(methods ...byte) []byte {
	return cat([]byte{socksVer, byte(len(methods))}, methods)
}

// creds is the request of the user name and password sub-negotiation.
func creds(user, pass string) []byte {
	return cat([]byte{authVer, byte(len(user))}, []byte(user), []byte{byte(len(pass))}, []byte(pass))
}

// v4, v6 and dom are the address field of a request or a reply: the type byte
// and the address itself. dom takes names of at most 255 bytes.
func v4(s string) []byte {
	a := netip.MustParseAddr(s).As4()
	return cat([]byte{atypIPv4}, a[:])
}

func v6(s string) []byte {
	a := netip.MustParseAddr(s).As16()
	return cat([]byte{atypIPv6}, a[:])
}

func dom(s string) []byte { return cat([]byte{atypDomain, byte(len(s))}, []byte(s)) }

func portBytes(p int) []byte { return []byte{byte(p >> 8), byte(p)} }

// request is a request with the given command; it carries the reserved byte 0.
func request(cmd byte, addr []byte, port int) []byte {
	return cat([]byte{socksVer, cmd, 0}, addr, portBytes(port))
}

func connectReq(addr []byte, port int) []byte { return request(cmdConnect, addr, port) }

// failReply is the reply to a request that failed: the code and the
// unspecified IPv4 address with port 0.
func failReply(code byte) []byte {
	return []byte{socksVer, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0}
}

// okReply is the reply to a request that succeeded, with the bound address bnd
// (type byte and address) and port.
func okReply(bnd []byte, port int) []byte {
	return cat([]byte{socksVer, repOK, 0}, bnd, portBytes(port))
}

// unbound is the bound address of a reply when the server has none to report.
var unbound = okReply(v4("0.0.0.0"), 0)

// payload returns n bytes that do not repeat over short distances, so that data
// which arrives out of place or cut short does not go unnoticed.
func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

// ---------------------------------------------------------------------------
// Test doubles and harness.
// ---------------------------------------------------------------------------

const ioTimeout = 5 * time.Second

// quiet is the logger of tests that do not look at the log.
var quiet = slog.New(slog.DiscardHandler)

// opErr is a dial error as the net package reports it for errno.
func opErr(errno syscall.Errno) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
}

// fakeNetErr is a net.Error that is not one of the net package's own.
type fakeNetErr struct{ timeout bool }

func (e fakeNetErr) Error() string   { return "fake network error" }
func (e fakeNetErr) Timeout() bool   { return e.timeout }
func (e fakeNetErr) Temporary() bool { return false }

// recorder is a DialFunc that notes every request it gets and then leaves the
// answer to fn.
type recorder struct {
	mu   sync.Mutex
	reqs []socks5.Request
	fn   socks5.DialFunc
}

func (r *recorder) dial(ctx context.Context, req socks5.Request) (net.Conn, error) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req)
	r.mu.Unlock()
	return r.fn(ctx, req)
}

func (r *recorder) requests() []socks5.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]socks5.Request(nil), r.reqs...)
}

// echo is the DialFunc of a target that sends back whatever it is sent. The
// target is the far end of a net.Pipe and goes away when the near end is closed.
func echo(context.Context, socks5.Request) (net.Conn, error) {
	up, far := net.Pipe()
	go func() {
		_, _ = io.Copy(far, far)
		_ = far.Close()
	}()
	return up, nil
}

// sink is the DialFunc of a target that reads and ignores whatever it is sent.
func sink(context.Context, socks5.Request) (net.Conn, error) {
	up, far := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, far)
		_ = far.Close()
	}()
	return up, nil
}

func failWith(err error) socks5.DialFunc {
	return func(context.Context, socks5.Request) (net.Conn, error) { return nil, err }
}

// refuse is the DialFunc of a target that refuses every connection.
var refuse = failWith(opErr(syscall.ECONNREFUSED))

// trackedConn notes that it was closed.
type trackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// addrConn is a connection whose local address is the one it is given.
type addrConn struct {
	net.Conn
	local net.Addr
}

func (c addrConn) LocalAddr() net.Addr { return c.local }

// namedAddr is a net.Addr that is not an IP address.
type namedAddr struct{ network, addr string }

func (a namedAddr) Network() string { return a.network }
func (a namedAddr) String() string  { return a.addr }

// logBuf collects log output. A log handler writes from many goroutines, and
// the test reads while they may still write.
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

func (l *logBuf) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// startServer serves srv on a loopback listener until the test ends and returns
// the address of the listener.
func startServer(t *testing.T, srv *socks5.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve returned %v after its listener was closed, want nil", err)
			}
		case <-time.After(ioTimeout):
			t.Error("Serve did not return after its listener was closed")
		}
	})
	return ln.Addr().String()
}

// connect starts a server whose DialFunc is fn and returns a raw client
// connection to it, with the recorder of the requests that reach fn.
func connect(t *testing.T, fn socks5.DialFunc) (*net.TCPConn, *recorder) {
	t.Helper()
	rec := &recorder{fn: fn}
	addr := startServer(t, &socks5.Server{Dial: rec.dial, Logger: quiet})
	return dialRaw(t, addr), rec
}

// dialRaw opens a TCP connection to addr. Its reads and writes give up after
// ioTimeout, so that a server that does not answer fails a test and does not
// hang it.
func dialRaw(t *testing.T, addr string) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, ioTimeout)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		t.Fatal(err)
	}
	return c.(*net.TCPConn)
}

// serve runs srv.ServeConn on one end of a fresh net.Pipe. It returns the other
// end and a channel that is closed when ServeConn has returned.
//
// A net.Pipe has no buffer: a write waits until the other side has read all of
// it. Tests that drive a pipe therefore exchange exactly what the other side
// reads and writes, in lock step.
func serve(ctx context.Context, srv *socks5.Server) (client net.Conn, done <-chan struct{}) {
	client, server := net.Pipe()
	d := make(chan struct{})
	go func() {
		defer close(d)
		srv.ServeConn(ctx, server)
	}()
	return client, d
}

// serveT is serve for tests that run in real time. The client end gives up after
// ioTimeout, so that a server that stops answering fails the test and does not
// hang it, and it is closed when the test ends. Tests in a synctest bubble use
// serve: a deadline there would be one of the fake clock.
func serveT(t *testing.T, srv *socks5.Server) (client net.Conn, done <-chan struct{}) {
	t.Helper()
	client, done = serve(context.Background(), srv)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		t.Fatal(err)
	}
	return client, done
}

// serveB is serve for tests in a synctest bubble. The client end gives up after a
// day of fake time. A server that waits for ever then fails its test; without
// the deadline the bubble would end in a deadlock panic, which takes the other
// tests of the package down with it.
func serveB(ctx context.Context, srv *socks5.Server) (client net.Conn, done <-chan struct{}) {
	client, done = serve(ctx, srv)
	_ = client.SetDeadline(time.Now().Add(24 * time.Hour))
	return client, done
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(ioTimeout):
		t.Fatal("ServeConn did not return")
	}
}

func send(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatalf("write % x: %v", b, err)
	}
}

func expect(t *testing.T, c net.Conn, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	n, err := io.ReadFull(c, got)
	if err != nil {
		t.Fatalf("read: got % x and then %v, want % x", got[:n], err, want)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("read % x, want % x", got, want)
	}
}

// expectClosed checks that the peer has closed the connection cleanly and sends
// nothing more: the next read ends in EOF. A peer that closes a TCP connection
// with bytes of ours still unread makes it end in a reset instead, and that is
// not clean: where the peer has been sent a whole message, it is expected to have
// read all of it.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	var b [64]byte
	n, err := c.Read(b[:])
	if n > 0 {
		t.Fatalf("read % x, want the connection closed", b[:n])
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read failed with %v, want EOF: the peer should have closed the connection after reading everything", err)
	}
}

// expectDropped is expectClosed for a peer that was sent more than it cares to
// read, such as an HTTP request on a SOCKS5 port: it may have closed with some of
// it unread, and the connection may end in a reset.
func expectDropped(t *testing.T, c net.Conn) {
	t.Helper()
	var b [64]byte
	n, err := c.Read(b[:])
	if n > 0 {
		t.Fatalf("read % x, want the connection closed", b[:n])
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("read failed with %v, want the connection closed", err)
	}
}

// greetNoAuth performs the greeting of a client that offers no authentication.
func greetNoAuth(t *testing.T, c net.Conn) {
	t.Helper()
	send(t, c, hello(methNoAuth))
	expect(t, c, []byte{socksVer, methNoAuth})
}

// ping sends four bytes through a tunnel to an echo target and expects them back.
func ping(t *testing.T, c net.Conn) {
	t.Helper()
	send(t, c, []byte("ping"))
	expect(t, c, []byte("ping"))
}

// connectOnce runs a whole exchange on a fresh connection to addr: the greeting
// without authentication and a CONNECT to 192.0.2.1:443. It returns the reply.
func connectOnce(t *testing.T, addr string) (*net.TCPConn, []byte) {
	t.Helper()
	c := dialRaw(t, addr)
	greetNoAuth(t, c)
	send(t, c, connectReq(v4("192.0.2.1"), 443))
	reply := make([]byte, len(unbound))
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return c, reply
}

// ---------------------------------------------------------------------------
// Server: negotiation.
// ---------------------------------------------------------------------------

func TestMethodSelection(t *testing.T) {
	tests := []struct {
		name    string
		offered []byte
		want    byte
	}{
		{"no authentication", []byte{methNoAuth}, methNoAuth},
		{"user and password", []byte{methUserPass}, methUserPass},
		{"user and password preferred, offered second", []byte{methNoAuth, methUserPass}, methUserPass},
		{"user and password preferred, offered first", []byte{methUserPass, methNoAuth}, methUserPass},
		{"user and password among others", []byte{methGSSAPI, methUserPass, 0x80}, methUserPass},
		{"user and password offered twice", []byte{methUserPass, methUserPass}, methUserPass},
		{"no authentication among others", []byte{methGSSAPI, 0x03, methNoAuth}, methNoAuth},
		{"nothing acceptable", []byte{methGSSAPI, 0x03, 0x80, 0xfe}, methNone},
		{"no methods at all", nil, methNone},
		{"only the marker for no acceptable method", []byte{methNone}, methNone},
		{"the most methods a client can list, the last one the right one", append(bytes.Repeat([]byte{0x80}, 254), methUserPass), methUserPass},
		{"the most methods a client can list, none of them acceptable", bytes.Repeat([]byte{0x80}, 255), methNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := connect(t, refuse)
			send(t, c, hello(tc.offered...))
			expect(t, c, []byte{socksVer, tc.want})
			if tc.want == methNone {
				expectClosed(t, c)
			}
			if got := rec.requests(); len(got) != 0 {
				t.Errorf("the DialFunc was called %d times, want never", len(got))
			}
		})
	}
}

func TestUsernameReachesDialFunc(t *testing.T) {
	tests := []struct {
		name   string
		user   string
		pass   string
		noAuth bool // the client offers no authentication at all
	}{
		{"scope me", "me", "pw", false},
		{"scope fetch", "fetch", "pw", false},
		{"empty scope sent as credentials", "", "", false},
		{"empty user name and a password", "", "pw", false},
		{"longest user name and password", strings.Repeat("u", 255), strings.Repeat("p", 255), false},
		{"user name with control and high bytes", "\x00\xff\r\n me", "pw", false},
		{"no authentication", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := connect(t, echo)
			if tc.noAuth {
				greetNoAuth(t, c)
			} else {
				send(t, c, hello(methNoAuth, methUserPass))
				expect(t, c, []byte{socksVer, methUserPass})
				send(t, c, creds(tc.user, tc.pass))
				expect(t, c, []byte{authVer, 0x00})
			}
			send(t, c, connectReq(v4("192.0.2.1"), 443))
			expect(t, c, unbound)
			ping(t, c)

			want := []socks5.Request{{Username: tc.user, Host: "192.0.2.1", Port: 443}}
			if got := rec.requests(); !reflect.DeepEqual(got, want) {
				t.Errorf("the DialFunc got %+v, want %+v", got, want)
			}
		})
	}
}

func TestBadCredentialsVersion(t *testing.T) {
	c, rec := connect(t, refuse)
	send(t, c, hello(methUserPass))
	expect(t, c, []byte{socksVer, methUserPass})
	// A sub-negotiation of version 5. The server needs no more than the first
	// two bytes to know, and answers with a failure status.
	send(t, c, []byte{socksVer, 0x00})
	expect(t, c, []byte{authVer, 0x01})
	expectClosed(t, c)
	if got := rec.requests(); len(got) != 0 {
		t.Errorf("the DialFunc was called %d times, want never", len(got))
	}
}

// ---------------------------------------------------------------------------
// Server: requests.
// ---------------------------------------------------------------------------

func TestRequestAddressForms(t *testing.T) {
	long := strings.Repeat("a", 255)
	tests := []struct {
		name string
		addr []byte
		port int
		want socks5.Request
	}{
		{"IPv4", v4("149.154.167.51"), 443, socks5.Request{Host: "149.154.167.51", Port: 443}},
		{"IPv6", v6("2001:db8::1"), 8443, socks5.Request{Host: "2001:db8::1", Port: 8443}},
		{"IPv6 written out in full", v6("2001:db8:0:0:0:0:0:1"), 1, socks5.Request{Host: "2001:db8::1", Port: 1}},
		{"IPv6 with an IPv4-mapped address", v6("::ffff:192.0.2.1"), 80, socks5.Request{Host: "::ffff:192.0.2.1", Port: 80}},
		{"domain", dom("example.com"), 443, socks5.Request{Host: "example.com", Port: 443}},
		{"domain with an underscore", dom("my_host.example"), 443, socks5.Request{Host: "my_host.example", Port: 443}},
		{"domain of 255 bytes", dom(long), 443, socks5.Request{Host: long, Port: 443}},
		{"domain in UTF-8", dom("пример.example"), 443, socks5.Request{Host: "пример.example", Port: 443}},
		{"domain that is an IP literal", dom("192.0.2.1"), 443, socks5.Request{Host: "192.0.2.1", Port: 443}},
		{"highest port", v4("192.0.2.1"), 65535, socks5.Request{Host: "192.0.2.1", Port: 65535}},
		{"port 0 is passed on", v4("192.0.2.1"), 0, socks5.Request{Host: "192.0.2.1", Port: 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := connect(t, sink)
			greetNoAuth(t, c)
			send(t, c, connectReq(tc.addr, tc.port))
			expect(t, c, unbound)
			if got := rec.requests(); !reflect.DeepEqual(got, []socks5.Request{tc.want}) {
				t.Errorf("the DialFunc got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestUnsupportedCommand(t *testing.T) {
	cmds := []struct {
		name string
		cmd  byte
	}{
		{"BIND", cmdBind},
		{"UDP ASSOCIATE", cmdUDP},
		{"command 0", 0x00},
		{"command 4", 0x04},
		{"command 255", 0xff},
	}
	addrs := []struct {
		name string
		addr []byte
	}{
		{"IPv4", v4("192.0.2.1")},
		{"domain", dom("example.com")},
		{"IPv6", v6("2001:db8::1")},
	}
	for _, cmd := range cmds {
		for _, addr := range addrs {
			t.Run(cmd.name+" with "+addr.name, func(t *testing.T) {
				c, rec := connect(t, sink)
				greetNoAuth(t, c)
				send(t, c, request(cmd.cmd, addr.addr, 443))
				expect(t, c, failReply(repCmd))
				expectClosed(t, c)
				if got := rec.requests(); len(got) != 0 {
					t.Errorf("the DialFunc was called %d times, want never", len(got))
				}
			})
		}
	}
}

func TestUnsupportedAddressType(t *testing.T) {
	for _, atyp := range []byte{0x00, 0x02, 0x05, 0x80, 0xff} {
		t.Run(fmt.Sprintf("type %#02x", atyp), func(t *testing.T) {
			c, rec := connect(t, sink)
			greetNoAuth(t, c)
			// The header alone is enough to know: the address behind an unknown
			// type has no length, so the server must not wait for it.
			send(t, c, []byte{socksVer, cmdConnect, 0, atyp})
			expect(t, c, failReply(repAtyp))
			expectClosed(t, c)
			if got := rec.requests(); len(got) != 0 {
				t.Errorf("the DialFunc was called %d times, want never", len(got))
			}
		})
	}
}

func TestMalformedRequestGetsFailureReply(t *testing.T) {
	bad := func(name string) []byte { return connectReq(dom(name), 443) }
	tests := []struct {
		name string
		req  []byte
	}{
		{"reserved byte set", []byte{socksVer, cmdConnect, 1, atypIPv4, 192, 0, 2, 1, 0x01, 0xbb}},
		{"empty domain", bad("")},
		{"domain with a space", bad("exa mple.com")},
		{"domain with a tab", bad("example.com\t")},
		{"domain with a line break", bad("example.com\r\nProxy-Authorization: x")},
		{"domain with a NUL byte", bad("example.com\x00.evil.example")},
		{"domain with a DEL byte", bad("example\x7f.com")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := connect(t, sink)
			greetNoAuth(t, c)
			send(t, c, tc.req)
			expect(t, c, failReply(repGeneral))
			expectClosed(t, c)
			if got := rec.requests(); len(got) != 0 {
				t.Errorf("the DialFunc was called %d times, want never: %+v", len(got), got)
			}
		})
	}
}

// step is one exchange with a scripted peer. The tests of the server use it on
// the client side: send first, then expect recv. The tests of the client use it
// on the server side: expect read first, wait for pause, then send write;
// wantClosed makes the peer wait for the other side to hang up.
type step struct {
	send, recv []byte
	read       []byte
	pause      time.Duration
	write      []byte
	wantClosed bool
}

func TestMalformedHandshakeClosesConnection(t *testing.T) {
	tests := []struct {
		name  string
		steps []step
	}{
		{"hangs up at once", nil},
		{"SOCKS4 request", []step{{send: []byte{4, 1, 0, 80, 192, 0, 2, 1, 0}}}},
		{"HTTP request", []step{{send: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")}}},
		{"TLS record", []step{{send: []byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5}}}},
		{"greeting of version 0", []step{{send: []byte{0, 1, 0}}}},
		{"version byte only", []step{{send: []byte{socksVer}}}},
		{"cut inside the method list", []step{{send: []byte{socksVer, 3, methNoAuth}}}},
		{"cut inside the credentials", []step{
			{send: hello(methUserPass), recv: []byte{socksVer, methUserPass}},
			{send: []byte{authVer, 4, 'a', 'b'}},
		}},
		{"cut after the request header", []step{
			{send: hello(methNoAuth), recv: []byte{socksVer, methNoAuth}},
			{send: []byte{socksVer, cmdConnect, 0, atypIPv4, 192, 0}},
		}},
		{"cut inside a domain name", []step{
			{send: hello(methNoAuth), recv: []byte{socksVer, methNoAuth}},
			{send: []byte{socksVer, cmdConnect, 0, atypDomain, 11, 'e', 'x'}},
		}},
		{"cut before the port", []step{
			{send: hello(methNoAuth), recv: []byte{socksVer, methNoAuth}},
			{send: cat([]byte{socksVer, cmdConnect, 0}, dom("example.com"), []byte{0x01})},
		}},
		{"request of another version", []step{
			{send: hello(methNoAuth), recv: []byte{socksVer, methNoAuth}},
			{send: []byte{4, cmdConnect, 0, atypIPv4}},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := connect(t, sink)
			for _, s := range tc.steps {
				send(t, c, s.send)
				if s.recv != nil {
					expect(t, c, s.recv)
				}
			}
			// The peer says no more. A server that is still waiting for bytes
			// closes the connection on the end of the stream. One that has
			// turned the peer away may have left some of what it sent unread.
			_ = c.CloseWrite()
			expectDropped(t, c)
			if got := rec.requests(); len(got) != 0 {
				t.Errorf("the DialFunc was called %d times, want never", len(got))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Server: what the DialFunc does.
// ---------------------------------------------------------------------------

func TestDialErrorReplies(t *testing.T) {
	refused := opErr(syscall.ECONNREFUSED)
	tests := []struct {
		name string
		err  error
		want byte
	}{
		{"connection refused", refused, repRefused},
		{"bare ECONNREFUSED", syscall.ECONNREFUSED, repRefused},
		{"refused, wrapped", fmt.Errorf("chain member 1: %w", refused), repRefused},
		{"refused among several errors", errors.Join(errors.New("member 1: boom"), refused), repRefused},
		{"network unreachable", opErr(syscall.ENETUNREACH), repHostUnreach},
		{"host unreachable", opErr(syscall.EHOSTUNREACH), repHostUnreach},
		{"connection timed out", opErr(syscall.ETIMEDOUT), repHostUnreach},
		{"context deadline", fmt.Errorf("dial: %w", context.DeadlineExceeded), repHostUnreach},
		{"i/o deadline", os.ErrDeadlineExceeded, repHostUnreach},
		{"network error that is a timeout", fakeNetErr{timeout: true}, repHostUnreach},
		{"name not found", &net.DNSError{Err: "no such host", Name: "nowhere.example", IsNotFound: true}, repHostUnreach},
		// The reply of an upstream proxy goes on to the client as it came.
		{"upstream said connection refused", &socks5.ReplyError{Code: repRefused}, repRefused},
		{"upstream said host unreachable", &socks5.ReplyError{Code: repHostUnreach}, repHostUnreach},
		{"upstream said network unreachable", &socks5.ReplyError{Code: repNetUnreach}, repNetUnreach},
		{"upstream said TTL expired", &socks5.ReplyError{Code: repTTL}, repTTL},
		{"upstream said general failure", &socks5.ReplyError{Code: repGeneral}, repGeneral},
		{"upstream said not allowed", &socks5.ReplyError{Code: repNotAllowed}, repNotAllowed},
		{"upstream said command not supported", &socks5.ReplyError{Code: repCmd}, repCmd},
		{"upstream said address type not supported", &socks5.ReplyError{Code: repAtyp}, repAtyp},
		{"upstream said not allowed, wrapped", fmt.Errorf("member 1: %w", &socks5.ReplyError{Code: repNotAllowed}), repNotAllowed},
		{"upstream said not allowed, next to a refusal", errors.Join(&socks5.ReplyError{Code: repNotAllowed}, refused), repNotAllowed},
		{"upstream sent a code that is not assigned", &socks5.ReplyError{Code: 0x09}, repGeneral},
		{"upstream sent the code of success", &socks5.ReplyError{Code: repOK}, repGeneral},
		{"other error", errors.New("boom"), repGeneral},
		{"connection reset", opErr(syscall.ECONNRESET), repGeneral},
		{"permission denied", opErr(syscall.EACCES), repGeneral},
		{"canceled", context.Canceled, repGeneral},
		{"end of file", io.EOF, repGeneral},
		{"network error that is not a timeout", fakeNetErr{}, repGeneral},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, reply := connectOnce(t, startServer(t, &socks5.Server{Dial: failWith(tc.err), Logger: quiet}))
			if want := failReply(tc.want); !bytes.Equal(reply, want) {
				t.Errorf("reply % x, want % x", reply, want)
			}
			expectClosed(t, c)
		})
	}
}

func TestRealRefusedConnection(t *testing.T) {
	// A port nobody listens on: the error is the one the net package makes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := ln.Addr().String()
	_ = ln.Close()

	dial := func(ctx context.Context, req socks5.Request) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target)
	}
	c, reply := connectOnce(t, startServer(t, &socks5.Server{Dial: dial, Logger: quiet}))
	if want := failReply(repRefused); !bytes.Equal(reply, want) {
		t.Errorf("reply % x, want % x", reply, want)
	}
	expectClosed(t, c)
}

func TestDialFuncReturnsNoConnection(t *testing.T) {
	nothing := func(context.Context, socks5.Request) (net.Conn, error) { return nil, nil }
	c, reply := connectOnce(t, startServer(t, &socks5.Server{Dial: nothing, Logger: quiet}))
	if want := failReply(repGeneral); !bytes.Equal(reply, want) {
		t.Errorf("reply % x, want % x", reply, want)
	}
	expectClosed(t, c)
}

func TestDialFuncReturnsConnectionAndError(t *testing.T) {
	// A DialFunc that fails but still hands back a connection does not make the
	// server hold on to it.
	up, far := net.Pipe()
	defer func() { _ = far.Close() }()
	tracked := &trackedConn{Conn: up}
	dial := func(context.Context, socks5.Request) (net.Conn, error) { return tracked, errors.New("boom") }

	c, reply := connectOnce(t, startServer(t, &socks5.Server{Dial: dial, Logger: quiet}))
	if want := failReply(repGeneral); !bytes.Equal(reply, want) {
		t.Errorf("reply % x, want % x", reply, want)
	}
	expectClosed(t, c)
	if !tracked.closed.Load() {
		t.Error("the connection that came with the error was left open")
	}
}

func TestDialPanicBecomesFailureReply(t *testing.T) {
	logs := &logBuf{}
	var calls atomic.Int32
	dial := func(ctx context.Context, req socks5.Request) (net.Conn, error) {
		if calls.Add(1) == 1 {
			panic("dial exploded")
		}
		return echo(ctx, req)
	}
	addr := startServer(t, &socks5.Server{Dial: dial, Logger: logs.logger()})

	c, reply := connectOnce(t, addr)
	if want := failReply(repGeneral); !bytes.Equal(reply, want) {
		t.Errorf("reply % x, want % x", reply, want)
	}
	expectClosed(t, c)
	if out := logs.String(); !strings.Contains(out, "dial exploded") {
		t.Errorf("the panic is not in the log:\n%s", out)
	}

	// The server is still there for the next connection.
	c2, reply := connectOnce(t, addr)
	if !bytes.Equal(reply, unbound) {
		t.Fatalf("reply % x, want % x", reply, unbound)
	}
	ping(t, c2)
}

func TestSuccessReplyCarriesLocalAddress(t *testing.T) {
	tcp := func(ip string, port int, zone string) net.Addr {
		return &net.TCPAddr{IP: net.ParseIP(ip), Port: port, Zone: zone}
	}
	tests := []struct {
		name  string
		local net.Addr // the local address of the connection to the target
		keep  bool     // leave the connection as it is, with the address of a net.Pipe
		want  []byte   // the whole reply
	}{
		{"IPv4", tcp("192.0.2.7", 40001, ""), false, okReply(v4("192.0.2.7"), 40001)},
		{"IPv4 held in 4 bytes", &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7).To4(), Port: 2}, false, okReply(v4("192.0.2.7"), 2)},
		{"IPv6", tcp("2001:db8::5", 443, ""), false, okReply(v6("2001:db8::5"), 443)},
		{"IPv6 with a zone", tcp("2001:db8::6", 1, "eth0"), false, okReply(v6("2001:db8::6"), 1)},
		{"UDP address", &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: 53}, false, okReply(v4("192.0.2.9"), 53)},
		{"address that is not an IP", namedAddr{"unix", "/run/example.sock"}, false, unbound},
		{"address of a net.Pipe", nil, true, unbound},
		{"no address", nil, false, unbound},
		{"empty TCP address", &net.TCPAddr{}, false, unbound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dial := func(ctx context.Context, req socks5.Request) (net.Conn, error) {
				up, err := sink(ctx, req)
				if tc.keep {
					return up, err
				}
				return addrConn{Conn: up, local: tc.local}, err
			}
			client, done := serveT(t, &socks5.Server{Dial: dial, Logger: quiet})
			greetNoAuth(t, client)
			send(t, client, connectReq(v4("192.0.2.1"), 443))
			expect(t, client, tc.want)
			_ = client.Close()
			waitDone(t, done)
		})
	}
}

func TestServerWithoutDialFunc(t *testing.T) {
	srv := &socks5.Server{Logger: quiet}
	t.Run("Serve refuses to start", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }() // also frees a Serve that did not notice
		served := make(chan error, 1)
		go func() { served <- srv.Serve(ln) }()
		select {
		case err := <-served:
			if err == nil {
				t.Fatal("Serve returned nil for a Server without a Dial function")
			}
		case <-time.After(ioTimeout):
			t.Fatal("Serve took no notice that the Server has no Dial function")
		}
	})
	t.Run("ServeConn fails the request", func(t *testing.T) {
		client, done := serveT(t, srv)
		greetNoAuth(t, client)
		send(t, client, connectReq(v4("192.0.2.1"), 443))
		expect(t, client, failReply(repGeneral))
		waitDone(t, done)
	})
}

func TestDefaults(t *testing.T) {
	t.Run("a nil Logger is slog.Default", func(t *testing.T) {
		logs := &logBuf{}
		old := slog.Default()
		slog.SetDefault(logs.logger())
		defer slog.SetDefault(old)

		client, done := serveT(t, &socks5.Server{Dial: refuse})
		greetNoAuth(t, client)
		send(t, client, connectReq(v4("192.0.2.1"), 443))
		expect(t, client, failReply(repRefused))
		waitDone(t, done)
		if out := logs.String(); !strings.Contains(out, "cannot connect") {
			t.Errorf("the failed connection did not reach the default logger:\n%s", out)
		}
	})

	t.Run("a nil context is the background context", func(t *testing.T) {
		var ctx context.Context // nil
		client, done := serve(ctx, &socks5.Server{Dial: echo, Logger: quiet})
		defer func() { _ = client.Close() }()
		_ = client.SetDeadline(time.Now().Add(ioTimeout))
		greetNoAuth(t, client)
		send(t, client, connectReq(v4("192.0.2.1"), 443))
		expect(t, client, unbound)
		ping(t, client)
		_ = client.Close()
		waitDone(t, done)
	})
}

// TestPipelinedBytesAreNotLost sends everything in one write: the greeting, the
// request, and the first bytes for the target. A client is not supposed to do so
// before it has seen the reply, but nothing in the server may swallow what it
// has not asked for.
func TestPipelinedBytesAreNotLost(t *testing.T) {
	for _, withAuth := range []bool{false, true} {
		t.Run("with authentication "+strconv.FormatBool(withAuth), func(t *testing.T) {
			far := make(chan net.Conn, 1)
			dial := func(context.Context, socks5.Request) (net.Conn, error) {
				up, f := net.Pipe()
				far <- f
				return up, nil
			}
			c, _ := connect(t, dial)

			out := hello(methNoAuth)
			if withAuth {
				out = cat(hello(methUserPass), creds("me", "pw"))
			}
			send(t, c, cat(out, connectReq(dom("example.com"), 443), []byte("early bytes")))

			if withAuth {
				expect(t, c, []byte{socksVer, methUserPass, authVer, 0x00})
			} else {
				expect(t, c, []byte{socksVer, methNoAuth})
			}
			expect(t, c, unbound)

			var f net.Conn
			select {
			case f = <-far:
			case <-time.After(ioTimeout):
				t.Fatal("the target was never dialed")
			}
			defer func() { _ = f.Close() }()
			_ = f.SetDeadline(time.Now().Add(ioTimeout))
			got := make([]byte, len("early bytes"))
			if _, err := io.ReadFull(f, got); err != nil || string(got) != "early bytes" {
				t.Fatalf("the target received %q (%v), want %q", got, err, "early bytes")
			}
			if _, err := f.Write([]byte("late bytes")); err != nil {
				t.Fatal(err)
			}
			expect(t, c, []byte("late bytes"))
		})
	}
}

func TestNothingSecretIsLogged(t *testing.T) {
	const pass = "hunter2-hunter2"
	logs := &logBuf{}

	flows := []struct {
		name string
		dial socks5.DialFunc
		run  func(t *testing.T, c net.Conn)
	}{
		{"a tunnel", echo, func(t *testing.T, c net.Conn) {
			send(t, c, hello(methNoAuth, methUserPass))
			expect(t, c, []byte{socksVer, methUserPass})
			send(t, c, creds("me", pass))
			expect(t, c, []byte{authVer, 0x00})
			send(t, c, connectReq(v4("192.0.2.1"), 443))
			expect(t, c, unbound)
			ping(t, c)
		}},
		{"a refused connection", refuse, func(t *testing.T, c net.Conn) {
			send(t, c, hello(methUserPass))
			expect(t, c, []byte{socksVer, methUserPass})
			send(t, c, creds("me", pass))
			expect(t, c, []byte{authVer, 0x00})
			send(t, c, connectReq(v4("192.0.2.1"), 443))
			expect(t, c, failReply(repRefused))
		}},
		{"credentials cut short", refuse, func(t *testing.T, c net.Conn) {
			send(t, c, hello(methUserPass))
			expect(t, c, []byte{socksVer, methUserPass})
			whole := creds("me", pass)
			send(t, c, whole[:len(whole)-3])
		}},
	}
	for _, f := range flows {
		client, done := serveT(t, &socks5.Server{Dial: f.dial, Logger: logs.logger()})
		f.run(t, client)
		_ = client.Close()
		waitDone(t, done)
	}

	out := logs.String()
	if out == "" {
		t.Fatal("nothing was logged at debug level: the check below proves nothing")
	}
	if strings.Contains(out, pass) || strings.Contains(out, pass[:6]) {
		t.Errorf("the password is in the log:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Server: Serve.
// ---------------------------------------------------------------------------

func TestServeReturnsWhenListenerIsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &socks5.Server{Dial: echo, Logger: quiet}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()

	c, reply := connectOnce(t, ln.Addr().String())
	if !bytes.Equal(reply, unbound) {
		t.Fatalf("reply % x, want % x", reply, unbound)
	}

	_ = ln.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v for a closed listener, want nil", err)
		}
	case <-time.After(ioTimeout):
		t.Fatal("Serve did not return after its listener was closed")
	}

	// What was accepted goes on, whatever happens to the listener.
	ping(t, c)
	if conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		_ = conn.Close()
		t.Error("the closed listener still takes connections")
	}
}

// scriptListener is a net.Listener that hands out a fixed sequence of results
// from Accept and then reports itself closed.
type scriptListener struct {
	mu    sync.Mutex
	steps []acceptResult
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func (l *scriptListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.steps) == 0 {
		return nil, net.ErrClosed
	}
	s := l.steps[0]
	l.steps = l.steps[1:]
	return s.conn, s.err
}

func (l *scriptListener) left() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.steps)
}

func (l *scriptListener) Close() error   { return nil }
func (l *scriptListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

func TestServeAcceptErrors(t *testing.T) {
	acceptErr := func(errno syscall.Errno) error {
		return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept4", errno)}
	}

	t.Run("transient errors do not stop the server", func(t *testing.T) {
		// Running out of file descriptors is what a busy edge sees now and
		// then. The server waits and tries again, it does not give up.
		client, server := net.Pipe()
		defer func() { _ = client.Close() }()
		_ = client.SetDeadline(time.Now().Add(ioTimeout))
		ln := &scriptListener{steps: []acceptResult{
			{err: acceptErr(syscall.EMFILE)},
			{err: acceptErr(syscall.ENFILE)},
			{err: acceptErr(syscall.ECONNRESET)},
			{err: fakeNetErr{timeout: true}},
			{conn: server},
		}}
		srv := &socks5.Server{Dial: echo, Logger: quiet}
		if err := srv.Serve(ln); err != nil {
			t.Fatalf("Serve returned %v, want nil once the listener reports itself closed", err)
		}
		if n := ln.left(); n != 0 {
			t.Fatalf("%d results of Accept left unused", n)
		}
		// Serve has returned; the connection it took is served all the same.
		greetNoAuth(t, client)
		send(t, client, connectReq(v4("192.0.2.1"), 443))
		expect(t, client, unbound)
		ping(t, client)
		_ = client.Close()
	})

	t.Run("other errors end the server", func(t *testing.T) {
		boom := errors.New("accept: the listener is broken")
		_, server := net.Pipe()
		defer func() { _ = server.Close() }()
		ln := &scriptListener{steps: []acceptResult{{err: boom}, {conn: server}}}
		srv := &socks5.Server{Dial: echo, Logger: quiet}
		if err := srv.Serve(ln); !errors.Is(err, boom) {
			t.Fatalf("Serve returned %v, want %v", err, boom)
		}
		if n := ln.left(); n != 1 {
			t.Errorf("%d results of Accept left, want 1: Serve went on after the error", n)
		}
	})
}

// ---------------------------------------------------------------------------
// Server: time. These tests run in a synctest bubble. The clock is fake and
// moves only when every goroutine in the bubble waits, so a limit of ten
// seconds costs nothing and is met to the nanosecond. The bubble also fails a
// test whose goroutines are still waiting when it ends, which is the check for
// leaks.
// ---------------------------------------------------------------------------

// mustEndAt checks that ServeConn is still at work one nanosecond before
// start+after and has returned at that moment.
func mustEndAt(t *testing.T, done <-chan struct{}, start time.Time, after time.Duration) {
	t.Helper()
	time.Sleep(time.Until(start.Add(after)) - time.Nanosecond)
	synctest.Wait()
	select {
	case <-done:
		t.Fatalf("ServeConn returned before %v had passed", after)
	default:
	}
	time.Sleep(time.Nanosecond)
	synctest.Wait()
	select {
	case <-done:
	default:
		t.Fatalf("ServeConn still running %v after the start", after)
	}
}

// mustBeDone checks that ServeConn has returned by the time every goroutine of
// the bubble is waiting.
func mustBeDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	synctest.Wait()
	select {
	case <-done:
	default:
		t.Fatal("ServeConn is still running")
	}
}

func TestHandshakeTimeout(t *testing.T) {
	limits := []struct {
		name      string
		set       time.Duration // Server.HandshakeTimeout
		effective time.Duration
	}{
		{"default", 0, 10 * time.Second},
		{"negative means the default", -time.Second, 10 * time.Second},
		{"configured", 3 * time.Second, 3 * time.Second},
	}
	stalls := []struct {
		name  string
		drive func(t *testing.T, c net.Conn, limit time.Duration)
	}{
		{"silent peer", func(*testing.T, net.Conn, time.Duration) {}},
		{"stall after the greeting", func(t *testing.T, c net.Conn, _ time.Duration) {
			greetNoAuth(t, c)
		}},
		{"stall after the credentials", func(t *testing.T, c net.Conn, _ time.Duration) {
			send(t, c, hello(methUserPass))
			expect(t, c, []byte{socksVer, methUserPass})
			send(t, c, creds("me", "pw"))
			expect(t, c, []byte{authVer, 0x00})
		}},
		{"trickle that does not buy time", func(t *testing.T, c net.Conn, limit time.Duration) {
			send(t, c, []byte{socksVer})
			time.Sleep(limit / 2)
			send(t, c, []byte{1})
			time.Sleep(limit / 4)
		}},
		{"peer that does not read the answer", func(t *testing.T, c net.Conn, _ time.Duration) {
			// The greeting is sent and the answer is never read: the server
			// blocks in writing it, and the limit must cover that as well.
			send(t, c, hello(methNoAuth))
		}},
		{"one limit for all phases", func(t *testing.T, c net.Conn, limit time.Duration) {
			// A greeting that takes three quarters of the time, and then no
			// request. The limit was set at the start. It is not set anew when
			// the greeting is done, which would give the request all of it again.
			send(t, c, []byte{socksVer, 1})
			time.Sleep(limit * 3 / 4)
			send(t, c, []byte{methNoAuth})
			expect(t, c, []byte{socksVer, methNoAuth})
		}},
	}
	for _, l := range limits {
		for _, s := range stalls {
			t.Run(l.name+"/"+s.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					srv := &socks5.Server{Dial: refuse, HandshakeTimeout: l.set, Logger: quiet}
					client, done := serveB(context.Background(), srv)
					defer func() { _ = client.Close() }()
					start := time.Now()
					s.drive(t, client, l.effective)
					mustEndAt(t, done, start, l.effective)
					if _, err := client.Write([]byte{0}); !errors.Is(err, io.ErrClosedPipe) {
						t.Errorf("write after the cut-off failed with %v, want io.ErrClosedPipe", err)
					}
				})
			})
		}
	}
}

func TestHandshakeDeadlineEndsWithTheHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := &socks5.Server{Dial: echo, HandshakeTimeout: 3 * time.Second, Logger: quiet}
		client, done := serveB(context.Background(), srv)
		greetNoAuth(t, client)
		send(t, client, connectReq(v4("192.0.2.1"), 443))
		expect(t, client, unbound)

		// A tunnel may sit idle for ever so long. The limit on the handshake is
		// not a limit on the relay.
		time.Sleep(time.Hour)
		ping(t, client)

		_ = client.Close()
		mustBeDone(t, done)
	})
}

func TestSlowDialIsNotCutOffByHandshakeTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		slow := func(ctx context.Context, req socks5.Request) (net.Conn, error) {
			time.Sleep(30 * time.Second) // ten times the handshake timeout
			return echo(ctx, req)
		}
		srv := &socks5.Server{Dial: slow, HandshakeTimeout: 3 * time.Second, Logger: quiet}
		client, done := serveB(context.Background(), srv)
		greetNoAuth(t, client)
		send(t, client, connectReq(v4("192.0.2.1"), 443))
		expect(t, client, unbound)
		ping(t, client)

		_ = client.Close()
		mustBeDone(t, done)
	})
}

func TestReplyWriteIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		up, far := net.Pipe()
		defer func() { _ = far.Close() }()
		tracked := &trackedConn{Conn: up}
		dial := func(context.Context, socks5.Request) (net.Conn, error) { return tracked, nil }
		srv := &socks5.Server{Dial: dial, HandshakeTimeout: 3 * time.Second, Logger: quiet}
		client, done := serveB(context.Background(), srv)
		defer func() { _ = client.Close() }()

		greetNoAuth(t, client)
		send(t, client, connectReq(v4("192.0.2.1"), 443))
		start := time.Now()
		// The client never reads the reply. The server must not wait for it for
		// ever, and must let go of the target.
		mustEndAt(t, done, start, 3*time.Second)
		if !tracked.closed.Load() {
			t.Error("the target connection was left open")
		}
	})
}

func TestClientGoneWhileDialing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		up, far := net.Pipe()
		defer func() { _ = far.Close() }()
		tracked := &trackedConn{Conn: up}
		dialing := make(chan struct{})
		dial := func(context.Context, socks5.Request) (net.Conn, error) {
			close(dialing)
			time.Sleep(5 * time.Second)
			return tracked, nil
		}
		client, done := serveB(context.Background(), &socks5.Server{Dial: dial, Logger: quiet})
		greetNoAuth(t, client)
		send(t, client, connectReq(v4("192.0.2.1"), 443))
		<-dialing
		_ = client.Close() // hangs up while the dial is under way

		time.Sleep(10 * time.Second) // the dial ends, and the server finds nobody to answer
		mustBeDone(t, done)
		if !tracked.closed.Load() {
			t.Error("the target connection was left open")
		}
	})
}

func TestContextCancelEndsTheConnection(t *testing.T) {
	t.Run("during the handshake", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			client, done := serveB(ctx, &socks5.Server{Dial: refuse, Logger: quiet})
			defer func() { _ = client.Close() }()
			greetNoAuth(t, client)
			cancel()
			mustBeDone(t, done)
		})
	})

	t.Run("during the dial", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			dialing := make(chan struct{})
			dial := func(ctx context.Context, _ socks5.Request) (net.Conn, error) {
				close(dialing)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			client, done := serveB(ctx, &socks5.Server{Dial: dial, Logger: quiet})
			defer func() { _ = client.Close() }()
			greetNoAuth(t, client)
			send(t, client, connectReq(v4("192.0.2.1"), 443))
			<-dialing
			cancel()
			mustBeDone(t, done)
		})
	})

	t.Run("during the relay", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			var up *trackedConn
			dial := func(ctx context.Context, req socks5.Request) (net.Conn, error) {
				c, err := echo(ctx, req)
				up = &trackedConn{Conn: c}
				return up, err
			}
			client, done := serveB(ctx, &socks5.Server{Dial: dial, Logger: quiet})
			defer func() { _ = client.Close() }()
			greetNoAuth(t, client)
			send(t, client, connectReq(v4("192.0.2.1"), 443))
			expect(t, client, unbound)
			ping(t, client)
			cancel()
			mustBeDone(t, done)
			if !up.closed.Load() {
				t.Error("the target connection was left open")
			}
		})
	})

	t.Run("before ServeConn starts", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			client, done := serveB(ctx, &socks5.Server{Dial: refuse, Logger: quiet})
			defer func() { _ = client.Close() }()
			mustBeDone(t, done)
		})
	})
}

// TestNoGoroutineLeak runs connections of every kind through a server and checks
// that the process is back to the goroutines it started with once they are over.
func TestNoGoroutineLeak(t *testing.T) {
	dial := func(ctx context.Context, req socks5.Request) (net.Conn, error) {
		switch req.Port {
		case 444:
			return nil, opErr(syscall.ECONNREFUSED)
		case 445:
			return nil, errors.New("boom")
		}
		return echo(ctx, req)
	}
	srv := &socks5.Server{Dial: dial, HandshakeTimeout: 300 * time.Millisecond, Logger: quiet}

	count := func() int {
		runtime.GC()
		return runtime.NumGoroutine()
	}

	run := func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		served := make(chan error, 1)
		go func() { served <- srv.Serve(ln) }()
		addr := ln.Addr().String()

		var wg sync.WaitGroup
		client := func(f func(c *net.TCPConn)) {
			wg.Go(func() {
				conn, err := net.DialTimeout("tcp", addr, ioTimeout)
				if err != nil {
					t.Errorf("dial: %v", err)
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(ioTimeout))
				f(conn.(*net.TCPConn))
			})
		}
		handshake := func(c *net.TCPConn, port int) {
			_, _ = c.Write(hello(methNoAuth))
			var m [2]byte
			_, _ = io.ReadFull(c, m[:])
			_, _ = c.Write(connectReq(v4("192.0.2.1"), port))
			var reply [10]byte
			_, _ = io.ReadFull(c, reply[:])
		}

		for range 4 { // tunnels, closed by the client
			client(func(c *net.TCPConn) {
				handshake(c, 443)
				_, _ = c.Write([]byte("ping"))
				var b [4]byte
				_, _ = io.ReadFull(c, b[:])
			})
		}
		for range 2 { // tunnels that the client half-closes first
			client(func(c *net.TCPConn) {
				handshake(c, 443)
				_, _ = c.Write([]byte("ping"))
				_ = c.CloseWrite()
				_, _ = io.Copy(io.Discard, c)
			})
		}
		for _, port := range []int{444, 445, 444} { // dials that fail
			client(func(c *net.TCPConn) {
				handshake(c, port)
				_, _ = io.Copy(io.Discard, c)
			})
		}
		for range 3 { // garbage
			client(func(c *net.TCPConn) {
				_, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
				_, _ = io.Copy(io.Discard, c)
			})
		}
		for range 3 { // peers that say nothing and wait for the timeout
			client(func(c *net.TCPConn) {
				_, _ = io.Copy(io.Discard, c)
			})
		}
		for range 3 { // peers that vanish in the middle of the handshake
			client(func(c *net.TCPConn) {
				_, _ = c.Write([]byte{socksVer, 2})
			})
		}
		for range 3 { // peers that vanish in the middle of the tunnel
			client(func(c *net.TCPConn) {
				handshake(c, 443)
			})
		}
		wg.Wait()

		_ = ln.Close()
		if err := <-served; err != nil {
			t.Errorf("Serve returned %v, want nil", err)
		}
	}

	run() // warm up: the runtime starts a few goroutines of its own on first use
	base := count()
	run()

	deadline := time.Now().Add(3 * time.Second)
	for {
		n := count()
		if n <= base {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			buf = buf[:runtime.Stack(buf, true)]
			t.Fatalf("%d goroutines left, started with %d:\n%s", n, base, buf)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConcurrentConnections(t *testing.T) {
	addr := startServer(t, &socks5.Server{Dial: echo, Logger: quiet})
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Go(func() {
			user := []string{"me", "fetch", ""}[i%3]
			ctx, cancel := context.WithTimeout(context.Background(), ioTimeout)
			defer cancel()
			conn, err := socks5.Dial(ctx, addr, user, "x", "192.0.2.1:443")
			if err != nil {
				t.Errorf("client %d: %v", i, err)
				return
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(ioTimeout))
			msg := payload(8192 + i)
			go func() { _, _ = conn.Write(msg) }()
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, msg) {
				t.Errorf("client %d: echo failed (%v)", i, err)
			}
		})
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Relay.
// ---------------------------------------------------------------------------

// failingWriter is a connection on which every write fails, as it does on a
// socket whose peer has reset it.
type failingWriter struct{ net.Conn }

func (failingWriter) Write([]byte) (int, error) { return 0, syscall.EPIPE }

// failingReader is a connection on which every read fails.
type failingReader struct{ net.Conn }

func (failingReader) Read([]byte) (int, error) { return 0, syscall.ECONNRESET }

// halfCloser is a connection that can half-close, as a TCP connection can. It
// only says that it did: a half-close that ends nothing is what a test of the
// failure paths needs, to see that they do not mistake one for a way out.
type halfCloser struct{ net.Conn }

func (halfCloser) CloseWrite() error { return nil }

// The same failing connections, with a CloseWrite.
type (
	failingWriterHC struct{ halfCloser }
	failingReaderHC struct{ halfCloser }
)

func (failingWriterHC) Write([]byte) (int, error) { return 0, syscall.EPIPE }
func (failingReaderHC) Read([]byte) (int, error)  { return 0, syscall.ECONNRESET }

func TestRelayCopiesBothWays(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a1, a2 := net.Pipe()
		b1, b2 := net.Pipe()
		res := make(chan [2]int64, 1)
		go func() {
			x, y := socks5.Relay(a2, b1)
			res <- [2]int64{x, y}
		}()

		// More than one 32 KiB buffer each way, and different amounts, so that
		// neither the data nor the counts can be mixed up.
		up, down := payload(100_000), payload(70_001)
		gotUp, gotDown := make([]byte, len(up)), make([]byte, len(down))
		var wg sync.WaitGroup
		wg.Go(func() {
			if _, err := a1.Write(up); err != nil {
				t.Errorf("write a: %v", err)
			}
		})
		wg.Go(func() {
			if _, err := b2.Write(down); err != nil {
				t.Errorf("write b: %v", err)
			}
		})
		wg.Go(func() {
			if _, err := io.ReadFull(b2, gotUp); err != nil {
				t.Errorf("read b: %v", err)
			}
		})
		wg.Go(func() {
			if _, err := io.ReadFull(a1, gotDown); err != nil {
				t.Errorf("read a: %v", err)
			}
		})
		wg.Wait()
		if !bytes.Equal(gotUp, up) {
			t.Error("the bytes from a to b arrived changed")
		}
		if !bytes.Equal(gotDown, down) {
			t.Error("the bytes from b to a arrived changed")
		}

		_ = a1.Close()
		r := <-res
		if r != [2]int64{int64(len(up)), int64(len(down))} {
			t.Errorf("Relay counted %v bytes, want %v", r, [2]int64{int64(len(up)), int64(len(down))})
		}
	})
}

func TestRelayEndsWhenEitherSideCloses(t *testing.T) {
	// a1 and b2 are the far ends, a2 and b1 are the ends that Relay holds. A
	// net.Pipe cannot half-close, so the end of one direction ends the other too.
	closers := []struct {
		name  string
		close func(a1, a2, b1, b2 net.Conn)
	}{
		{"far end of a", func(a1, _, _, _ net.Conn) { _ = a1.Close() }},
		{"far end of b", func(_, _, _, b2 net.Conn) { _ = b2.Close() }},
		{"relayed end of a", func(_, a2, _, _ net.Conn) { _ = a2.Close() }},
		{"relayed end of b", func(_, _, b1, _ net.Conn) { _ = b1.Close() }},
	}
	for _, tc := range closers {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a1, a2 := net.Pipe()
				b1, b2 := net.Pipe()
				res := make(chan [2]int64, 1)
				go func() {
					x, y := socks5.Relay(a2, b1)
					res <- [2]int64{x, y}
				}()
				synctest.Wait() // Relay is at work and everything is idle

				tc.close(a1, a2, b1, b2)
				if r := <-res; r != [2]int64{0, 0} {
					t.Errorf("Relay counted %v bytes, want none", r)
				}

				// Relay closed what it held, so that nothing is left open.
				for name, c := range map[string]net.Conn{"a": a1, "b": b2} {
					if _, err := c.Write([]byte{0}); err == nil {
						t.Errorf("side %s is still open after Relay returned", name)
					}
				}
			})
		})
	}
}

func TestRelayStopsOnErrors(t *testing.T) {
	writeSome := func(a1, _ net.Conn) { go func() { _, _ = a1.Write([]byte("data")) }() }
	nothing := func(_, _ net.Conn) {}
	tests := []struct {
		name  string
		wrap  func(a2, b1 net.Conn) (net.Conn, net.Conn) // what Relay gets in place of the pipe ends it would hold
		drive func(a1, b2 net.Conn)
	}{
		{"write to b fails", func(a2, b1 net.Conn) (net.Conn, net.Conn) { return a2, failingWriter{b1} }, writeSome},
		{"read from b fails", func(a2, b1 net.Conn) (net.Conn, net.Conn) { return a2, failingReader{b1} }, nothing},
		// A failure is the end of the exchange also for connections that could
		// half-close. A half-close is for the end of a stream, and a peer that is
		// gone will not end the other one.
		{"write to b fails, b can half-close", func(a2, b1 net.Conn) (net.Conn, net.Conn) {
			return halfCloser{a2}, failingWriterHC{halfCloser{b1}}
		}, writeSome},
		{"read from b fails, a can half-close", func(a2, b1 net.Conn) (net.Conn, net.Conn) {
			return halfCloser{a2}, failingReaderHC{halfCloser{b1}}
		}, nothing},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a1, a2 := net.Pipe()
				b1, b2 := net.Pipe()
				done := make(chan struct{})
				go func() {
					a, b := tc.wrap(a2, b1)
					socks5.Relay(a, b)
					close(done)
				}()
				tc.drive(a1, b2)
				<-done // Relay returns although neither far end has closed

				for name, c := range map[string]net.Conn{"a": a1, "b": b2} {
					if _, err := c.Write([]byte{0}); err == nil {
						t.Errorf("side %s is still open after Relay returned", name)
					}
				}
			})
		})
	}
}

// tcpPair returns the two ends of a TCP connection over loopback.
func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			c = nil
		}
		accepted <- c
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sc := <-accepted
	if sc == nil {
		t.Fatal("accept failed")
	}
	for _, c := range []net.Conn{cc, sc} {
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(ioTimeout))
	}
	return cc.(*net.TCPConn), sc.(*net.TCPConn)
}

func TestRelayHalfClose(t *testing.T) {
	// One side sends its request, says that it is done and waits for the
	// answer. The other side answers only once it has seen the end of the
	// request. A relay that closed everything at the first end of stream would
	// cut the answer off.
	for _, aAsks := range []bool{true, false} {
		name := "b asks"
		if aAsks {
			name = "a asks"
		}
		t.Run(name, func(t *testing.T) {
			aFar, aNear := tcpPair(t)
			bNear, bFar := tcpPair(t)
			res := make(chan [2]int64, 1)
			go func() {
				x, y := socks5.Relay(aNear, bNear)
				res <- [2]int64{x, y}
			}()

			asker, answerer := aFar, bFar
			if !aAsks {
				asker, answerer = bFar, aFar
			}
			question, answer := payload(1000), payload(1<<20) // the answer is large, to be sure it is not cut

			send(t, asker, question)
			_ = asker.CloseWrite()
			got, err := io.ReadAll(answerer)
			if err != nil || !bytes.Equal(got, question) {
				t.Fatalf("the answering side read %d bytes (%v), want the %d of the question and then the end of the stream", len(got), err, len(question))
			}
			go func() {
				_, _ = answerer.Write(answer)
				_ = answerer.CloseWrite()
			}()
			got, err = io.ReadAll(asker)
			if err != nil || !bytes.Equal(got, answer) {
				t.Fatalf("the asking side read %d bytes (%v), want the whole answer of %d", len(got), err, len(answer))
			}

			var r [2]int64
			select {
			case r = <-res:
			case <-time.After(ioTimeout):
				t.Fatal("Relay did not return after both directions had ended")
			}
			want := [2]int64{int64(len(question)), int64(len(answer))} // a to b, b to a
			if !aAsks {
				want = [2]int64{int64(len(answer)), int64(len(question))}
			}
			if r != want {
				t.Errorf("Relay counted %v bytes, want %v", r, want)
			}
		})
	}
}

// TestRelayWaitsForTheOtherDirection pins down what half-close means for the end
// of a relay. When one far end is gone, the other is told that the stream has
// ended, and may still answer: Relay is over when it has ended its side too, not
// before. A connection that cannot half-close has no such state (see
// TestRelayEndsWhenEitherSideCloses).
func TestRelayWaitsForTheOtherDirection(t *testing.T) {
	aFar, aNear := tcpPair(t)
	bNear, bFar := tcpPair(t)
	done := make(chan struct{})
	go func() {
		socks5.Relay(aNear, bNear)
		close(done)
	}()

	_ = aFar.Close()
	// The other far end is told: its stream ends. Nothing else has happened to it.
	if n, err := bFar.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read on the far end of b: %d bytes and %v, want the end of the stream", n, err)
	}
	select {
	case <-done:
		t.Fatal("Relay returned while b could still send")
	case <-time.After(200 * time.Millisecond):
	}

	_ = bFar.Close() // b ends its direction too
	select {
	case <-done:
	case <-time.After(ioTimeout):
		t.Fatal("Relay did not return after both directions had ended")
	}
}

func TestRelayClosesBothConnectionsAtTheEnd(t *testing.T) {
	aFar, aNear := tcpPair(t)
	bNear, bFar := tcpPair(t)
	done := make(chan struct{})
	go func() {
		socks5.Relay(aNear, bNear)
		close(done)
	}()

	// Both far ends are done: each half-closes, and nobody closes outright.
	_ = aFar.CloseWrite()
	_ = bFar.CloseWrite()
	select {
	case <-done:
	case <-time.After(ioTimeout):
		t.Fatal("Relay did not return after both directions had ended")
	}
	// A write would fail on a connection that has only been half-closed, so ask
	// the connection itself: a read says "closed" only if Close was called, and
	// says EOF if it was not, since the far end has sent its end of stream.
	for name, c := range map[string]*net.TCPConn{"a": aNear, "b": bNear} {
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("a read on the relayed connection of side %s fails with %v, want it closed (net.ErrClosed)", name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Client.
// ---------------------------------------------------------------------------

// fakeProxy listens on loopback and plays steps with the first connection that
// arrives. A step that does not go as expected fails the test.
func fakeProxy(t *testing.T, steps []step) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(ioTimeout))
		if err := play(c, steps); err != nil {
			t.Errorf("fake proxy: %v", err)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String()
}

func play(c net.Conn, steps []step) error {
	for i, s := range steps {
		if s.read != nil {
			got := make([]byte, len(s.read))
			if n, err := io.ReadFull(c, got); err != nil {
				return fmt.Errorf("step %d: the client sent % x and then %v, want % x", i, got[:n], err, s.read)
			}
			if !bytes.Equal(got, s.read) {
				return fmt.Errorf("step %d: the client sent % x, want % x", i, got, s.read)
			}
		}
		time.Sleep(s.pause)
		if s.write != nil {
			if _, err := c.Write(s.write); err != nil {
				return fmt.Errorf("step %d: write: %w", i, err)
			}
		}
		if s.wantClosed {
			var b [16]byte
			n, err := c.Read(b[:])
			if n > 0 || (!errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET)) {
				return fmt.Errorf("step %d: wanted the client to hang up, read % x and then %v", i, b[:n], err)
			}
		}
	}
	return nil
}

func dialVia(addr, user, pass, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ioTimeout)
	defer cancel()
	return socks5.Dial(ctx, addr, user, pass, target)
}

func TestDialWireFormat(t *testing.T) {
	long := strings.Repeat("a", 255)
	noAuthReply := []byte{socksVer, methNoAuth}
	userPassReply := []byte{socksVer, methUserPass}
	authOK := []byte{authVer, 0x00}
	granted := okReply(v4("192.0.2.9"), 40000)

	tests := []struct {
		name       string
		user, pass string
		target     string
		steps      []step
	}{
		{"IPv4 without credentials", "", "", "149.154.167.51:443", []step{
			{read: hello(methNoAuth), write: noAuthReply},
			{read: connectReq(v4("149.154.167.51"), 443), write: granted},
		}},
		{"domain with credentials", "me", "pw", "example.com:443", []step{
			{read: hello(methNoAuth, methUserPass), write: userPassReply},
			{read: creds("me", "pw"), write: authOK},
			{read: connectReq(dom("example.com"), 443), write: granted},
		}},
		{"credentials, but the server asks for none", "me", "pw", "[2001:db8::1]:8443", []step{
			{read: hello(methNoAuth, methUserPass), write: noAuthReply},
			{read: connectReq(v6("2001:db8::1"), 8443), write: granted},
		}},
		{"password only", "", "pw", "192.0.2.1:80", []step{
			{read: hello(methNoAuth, methUserPass), write: userPassReply},
			{read: creds("", "pw"), write: authOK},
			{read: connectReq(v4("192.0.2.1"), 80), write: granted},
		}},
		{"user name only", "me", "", "192.0.2.1:80", []step{
			{read: hello(methNoAuth, methUserPass), write: userPassReply},
			{read: creds("me", ""), write: authOK},
			{read: connectReq(v4("192.0.2.1"), 80), write: granted},
		}},
		{"IPv4-mapped IPv6 address stays IPv6", "", "", "[::ffff:192.0.2.1]:80", []step{
			{read: hello(methNoAuth), write: noAuthReply},
			{read: connectReq(v6("::ffff:192.0.2.1"), 80), write: granted},
		}},
		{"longest credentials and domain", strings.Repeat("u", 255), strings.Repeat("p", 255), long + ":65535", []step{
			{read: hello(methNoAuth, methUserPass), write: userPassReply},
			{read: creds(strings.Repeat("u", 255), strings.Repeat("p", 255)), write: authOK},
			{read: connectReq(dom(long), 65535), write: granted},
		}},
		{"domain in UTF-8", "", "", "пример.example:443", []step{
			{read: hello(methNoAuth), write: noAuthReply},
			{read: connectReq(dom("пример.example"), 443), write: granted},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := fakeProxy(t, tc.steps)
			conn, err := dialVia(addr, tc.user, tc.pass, tc.target)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			_ = conn.Close()
		})
	}
}

func TestDialReplyForms(t *testing.T) {
	forms := []struct {
		name  string
		reply []byte
	}{
		{"IPv4", okReply(v4("192.0.2.9"), 40000)},
		{"IPv6", okReply(v6("2001:db8::9"), 40000)},
		{"domain", okReply(dom("proxy.example"), 40000)},
		{"empty domain", okReply([]byte{atypDomain, 0}, 40000)},
		{"longest domain", okReply(dom(strings.Repeat("a", 255)), 40000)},
		{"reserved byte set", []byte{socksVer, repOK, 0x7f, atypIPv4, 192, 0, 2, 9, 0x9c, 0x40}},
	}
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			// The reply and the first bytes of the target's answer arrive in the
			// same segment. Dial must take the reply and not a byte more.
			addr := fakeProxy(t, []step{
				{read: hello(methNoAuth), write: []byte{socksVer, methNoAuth}},
				{read: connectReq(v4("192.0.2.1"), 443), write: cat(f.reply, []byte("hello"))},
			})
			conn, err := dialVia(addr, "", "", "192.0.2.1:443")
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(ioTimeout))
			got := make([]byte, 5)
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
				t.Fatalf("first bytes on the connection: %q (%v), want %q", got, err, "hello")
			}
		})
	}
}

func TestDialRefusals(t *testing.T) {
	const pass = "hunter2-hunter2"

	hangUp := []step{{wantClosed: true}}
	with := func(steps ...[]step) []step {
		var all []step
		for _, s := range steps {
			all = append(all, s...)
		}
		return all
	}
	greet := []step{{read: hello(methNoAuth), write: []byte{socksVer, methNoAuth}}}
	greetAuth := []step{{read: hello(methNoAuth, methUserPass), write: []byte{socksVer, methUserPass}}}

	tests := []struct {
		name       string
		user, pass string
		steps      []step
		check      func(t *testing.T, err error)
	}{
		{"no acceptable method", "", "", with([]step{{read: hello(methNoAuth), write: []byte{socksVer, methNone}}}, hangUp),
			func(t *testing.T, err error) {
				if !strings.Contains(err.Error(), "no acceptable") {
					t.Errorf("the error does not say that no method was acceptable: %v", err)
				}
			}},
		{"method that was not offered", "", "", with([]step{{read: hello(methNoAuth), write: []byte{socksVer, methGSSAPI}}}, hangUp), nil},
		{"server demands credentials the client has none of", "", "", with([]step{{read: hello(methNoAuth), write: []byte{socksVer, methUserPass}}}, hangUp), nil},
		{"answer of another version", "", "", with([]step{{read: hello(methNoAuth), write: []byte{4, methNoAuth}}}, hangUp), nil},
		{"credentials rejected", "me", pass, with(greetAuth, []step{{read: creds("me", pass), write: []byte{authVer, 0x01}}}, hangUp),
			func(t *testing.T, err error) {
				if strings.Contains(err.Error(), pass) {
					t.Errorf("the error contains the password: %v", err)
				}
			}},
		{"credentials answered in another version", "me", pass, with(greetAuth, []step{{read: creds("me", pass), write: []byte{socksVer, 0x00}}}, hangUp), nil},
		{"reply of another version", "", "", with(greet, []step{{read: connectReq(v4("192.0.2.1"), 443), write: []byte{4, repOK, 0, atypIPv4, 0, 0, 0, 0, 0, 0}}}, hangUp), nil},
		{"reply with an unknown address type", "", "", with(greet, []step{{read: connectReq(v4("192.0.2.1"), 443), write: []byte{socksVer, repOK, 0, 0x02, 1, 2, 3, 4, 0, 0}}}, hangUp), nil},
		{"hangs up after the greeting", "", "", []step{{read: hello(methNoAuth)}}, func(t *testing.T, err error) {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("error %v, want io.ErrUnexpectedEOF", err)
			}
		}},
		{"hangs up after the method", "", "", []step{{read: hello(methNoAuth), write: []byte{socksVer}}}, func(t *testing.T, err error) {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("error %v, want io.ErrUnexpectedEOF", err)
			}
		}},
		{"hangs up after the request", "", "", with(greet, []step{{read: connectReq(v4("192.0.2.1"), 443)}}), func(t *testing.T, err error) {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("error %v, want io.ErrUnexpectedEOF", err)
			}
		}},
		{"reply cut inside the address", "", "", with(greet, []step{{read: connectReq(v4("192.0.2.1"), 443), write: []byte{socksVer, repOK, 0, atypIPv6, 0x20, 0x01, 0x0d}}}), func(t *testing.T, err error) {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("error %v, want io.ErrUnexpectedEOF", err)
			}
		}},
		{"reply cut inside the domain", "", "", with(greet, []step{{read: connectReq(v4("192.0.2.1"), 443), write: []byte{socksVer, repOK, 0, atypDomain, 9, 'a', 'b'}}}), func(t *testing.T, err error) {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("error %v, want io.ErrUnexpectedEOF", err)
			}
		}},
		{"reply cut before the port", "", "", with(greet, []step{{read: connectReq(v4("192.0.2.1"), 443), write: []byte{socksVer, repOK, 0, atypIPv4, 192, 0, 2, 9, 0x9c}}}), func(t *testing.T, err error) {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("error %v, want io.ErrUnexpectedEOF", err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := fakeProxy(t, tc.steps)
			conn, err := dialVia(addr, tc.user, tc.pass, "192.0.2.1:443")
			if err == nil {
				_ = conn.Close()
				t.Fatal("Dial succeeded")
			}
			if conn != nil {
				t.Errorf("Dial returned a connection along with the error %v", err)
			}
			if tc.check != nil {
				tc.check(t, err)
			}
		})
	}
}

func TestDialFailureReplies(t *testing.T) {
	for _, code := range []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xab, 0xff} {
		t.Run(fmt.Sprintf("code %#02x", code), func(t *testing.T) {
			addr := fakeProxy(t, []step{
				{read: hello(methNoAuth), write: []byte{socksVer, methNoAuth}},
				{read: connectReq(v4("192.0.2.1"), 443), write: failReply(code)},
				{wantClosed: true},
			})
			conn, err := dialVia(addr, "", "", "192.0.2.1:443")
			if err == nil {
				_ = conn.Close()
				t.Fatal("Dial succeeded")
			}
			var re *socks5.ReplyError
			if !errors.As(err, &re) {
				t.Fatalf("error %v is not a *socks5.ReplyError", err)
			}
			if re.Code != code {
				t.Errorf("ReplyError.Code = %#02x, want %#02x", re.Code, code)
			}
		})
	}

	t.Run("a short failure reply is enough", func(t *testing.T) {
		// Some servers send the two bytes of the verdict and nothing else.
		addr := fakeProxy(t, []step{
			{read: hello(methNoAuth), write: []byte{socksVer, methNoAuth}},
			{read: connectReq(v4("192.0.2.1"), 443), write: []byte{socksVer, repRefused}},
			{wantClosed: true},
		})
		_, err := dialVia(addr, "", "", "192.0.2.1:443")
		var re *socks5.ReplyError
		if !errors.As(err, &re) || re.Code != repRefused {
			t.Fatalf("error %v, want a ReplyError with code %#02x", err, repRefused)
		}
	})
}

func TestReplyError(t *testing.T) {
	tests := []struct {
		code byte
		is   error  // what the error answers to in errors.Is, if anything
		text string // part of the message
	}{
		{repGeneral, nil, "0x01"},
		{repNotAllowed, nil, "0x02"},
		{repNetUnreach, syscall.ENETUNREACH, "0x03"},
		{repHostUnreach, syscall.EHOSTUNREACH, "0x04"},
		{repRefused, syscall.ECONNREFUSED, "refused"},
		{repTTL, syscall.ETIMEDOUT, "0x06"},
		{repCmd, nil, "0x07"},
		{repAtyp, nil, "0x08"},
		{0xab, nil, "0xab"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("code %#02x", tc.code), func(t *testing.T) {
			var err error = &socks5.ReplyError{Code: tc.code}
			if msg := err.Error(); !strings.Contains(msg, tc.text) || !strings.HasPrefix(msg, "socks5:") {
				t.Errorf("message %q, want it to start with %q and contain %q", msg, "socks5:", tc.text)
			}
			for _, errno := range []error{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ECONNREFUSED, syscall.ETIMEDOUT} {
				if got, want := errors.Is(err, errno), errno == tc.is; got != want {
					t.Errorf("errors.Is(err, %v) = %v, want %v", errno, got, want)
				}
			}
		})
	}
}

func TestDialRejectsBadArguments(t *testing.T) {
	tests := []struct {
		name       string
		user, pass string
		target     string
	}{
		{"user name over 255 bytes", strings.Repeat("u", 256), "pw", "192.0.2.1:443"},
		{"password over 255 bytes", "me", strings.Repeat("p", 256), "192.0.2.1:443"},
		{"empty target", "", "", ""},
		{"no port", "", "", "example.com"},
		{"empty port", "", "", "example.com:"},
		{"port 0", "", "", "example.com:0"},
		{"port too high", "", "", "example.com:65536"},
		{"negative port", "", "", "example.com:-1"},
		{"port that is a service name", "", "", "example.com:https"},
		{"empty host", "", "", ":443"},
		{"IPv6 without brackets", "", "", "2001:db8::1:443"},
		{"IPv6 without a port", "", "", "[2001:db8::1]"},
		{"IPv6 with a zone", "", "", "[2001:db8::1%eth0]:443"},
		{"domain over 255 bytes", "", "", strings.Repeat("a", 256) + ":443"},
		{"domain with a space", "", "", "exa mple.com:443"},
		{"domain with a line break", "", "", "example.com\r\nX: y:443"},
		{"domain with a NUL byte", "", "", "example.com\x00:443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The proxy is there, and must not be bothered with a request that
			// cannot be sent.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			contacted := make(chan struct{}, 1)
			go func() {
				if c, err := ln.Accept(); err == nil {
					contacted <- struct{}{}
					_ = c.Close()
				}
			}()

			conn, err := dialVia(ln.Addr().String(), tc.user, tc.pass, tc.target)
			if err == nil {
				_ = conn.Close()
				t.Fatal("Dial succeeded")
			}
			if conn != nil {
				t.Errorf("Dial returned a connection along with the error %v", err)
			}
			_ = ln.Close()
			select {
			case <-contacted:
				t.Error("the proxy was contacted")
			case <-time.After(50 * time.Millisecond):
			}
		})
	}

	t.Run("bad proxy addresses", func(t *testing.T) {
		for _, addr := range []string{"", "127.0.0.1", "127.0.0.1:", "[::1", "no such host.example:1080"} {
			if conn, err := dialVia(addr, "", "", "192.0.2.1:443"); err == nil {
				_ = conn.Close()
				t.Errorf("Dial through %q succeeded", addr)
			}
		}
	})
}

func TestDialProxyUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	_, err = dialVia(addr, "", "", "192.0.2.1:443")
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("error %v, want one that answers to ECONNREFUSED", err)
	}
}

func TestDialContext(t *testing.T) {
	// A proxy that takes the greeting and then says nothing.
	stalled := func(t *testing.T) string {
		return fakeProxy(t, []step{{read: hello(methNoAuth)}, {wantClosed: true}})
	}

	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		start := time.Now()
		conn, err := socks5.Dial(ctx, stalled(t), "", "", "192.0.2.1:443")
		if err == nil {
			_ = conn.Close()
			t.Fatal("Dial succeeded")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error %v, want one that answers to context.DeadlineExceeded", err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("Dial took %v to give up on a deadline of 100ms", d)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		start := time.Now()
		conn, err := socks5.Dial(ctx, stalled(t), "", "", "192.0.2.1:443")
		if err == nil {
			_ = conn.Close()
			t.Fatal("Dial succeeded")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error %v, want one that answers to context.Canceled", err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("Dial took %v to give up after the cancellation", d)
		}
	})

	t.Run("already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		conn, err := socks5.Dial(ctx, "127.0.0.1:1", "", "", "192.0.2.1:443")
		if err == nil {
			_ = conn.Close()
			t.Fatal("Dial succeeded")
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error %v, want one that answers to context.Canceled", err)
		}
	})
}

func TestDialDefaultTimeout(t *testing.T) {
	// The limit is ten seconds. A test cannot wait for that, so it is made short.
	defer socks5.SetDialTimeout(150 * time.Millisecond)()

	t.Run("a context without a deadline gets it", func(t *testing.T) {
		// A proxy that takes the greeting and then says nothing.
		addr := fakeProxy(t, []step{{read: hello(methNoAuth)}, {wantClosed: true}})
		start := time.Now()
		conn, err := socks5.Dial(context.Background(), addr, "", "", "192.0.2.1:443")
		if err == nil {
			_ = conn.Close()
			t.Fatal("Dial succeeded")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("error %v, want one that answers to context.DeadlineExceeded", err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("Dial took %v to give up, the limit was 150ms", d)
		}
	})

	t.Run("a context with a deadline keeps its own", func(t *testing.T) {
		// The proxy takes more than twice the default to answer, and well within
		// the deadline of the context.
		addr := fakeProxy(t, []step{
			{read: hello(methNoAuth), pause: 350 * time.Millisecond, write: []byte{socksVer, methNoAuth}},
			{read: connectReq(v4("192.0.2.1"), 443), write: unbound},
		})
		conn, err := dialVia(addr, "", "", "192.0.2.1:443")
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		_ = conn.Close()
	})
}

// TestDialedConnectionOutlivesItsContext checks what a caller relies on: once
// Dial has returned, the context and its deadline have nothing more to do with
// the connection.
func TestDialedConnectionOutlivesItsContext(t *testing.T) {
	addr := startServer(t, &socks5.Server{Dial: echo, Logger: quiet})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	conn, err := socks5.Dial(ctx, addr, "me", "pw", "192.0.2.1:443")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	cancel()
	time.Sleep(700 * time.Millisecond) // past the deadline as well

	// The connection is used as Dial left it. Setting a deadline here would hide
	// the one that Dial may have left behind, so a watchdog keeps the test from
	// hanging instead.
	watchdog := time.AfterFunc(ioTimeout, func() { _ = conn.Close() })
	defer watchdog.Stop()
	ping(t, conn)
}

// ---------------------------------------------------------------------------
// Client and server together.
// ---------------------------------------------------------------------------

func TestEndToEnd(t *testing.T) {
	users := []struct{ user, pass string }{{"me", "x"}, {"fetch", "x"}, {"", ""}}
	targets := []struct {
		name   string
		target string
		host   string
		port   uint16
	}{
		{"IPv4", "149.154.167.51:443", "149.154.167.51", 443},
		{"domain", "example.com:443", "example.com", 443},
		{"IPv6", "[2001:db8::1]:8443", "2001:db8::1", 8443},
	}
	for _, u := range users {
		for _, tg := range targets {
			t.Run(fmt.Sprintf("user %q to %s", u.user, tg.name), func(t *testing.T) {
				rec := &recorder{fn: echo}
				addr := startServer(t, &socks5.Server{Dial: rec.dial, Logger: quiet})
				conn, err := dialVia(addr, u.user, u.pass, tg.target)
				if err != nil {
					t.Fatalf("Dial: %v", err)
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(ioTimeout))

				msg := payload(4096)
				go func() { _, _ = conn.Write(msg) }()
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, msg) {
					t.Fatalf("the echo came back wrong (%v)", err)
				}

				want := []socks5.Request{{Username: u.user, Host: tg.host, Port: tg.port}}
				if got := rec.requests(); !reflect.DeepEqual(got, want) {
					t.Errorf("the DialFunc got %+v, want %+v", got, want)
				}
			})
		}
	}
}

// Handshake does on a connection that the caller made what Dial does after it
// has connected: the request goes out, the reply is read, and the connection
// is left to the caller without a deadline.
func TestHandshakeOnAConnectionOfTheCaller(t *testing.T) {
	rec := &recorder{fn: echo}
	addr := startServer(t, &socks5.Server{Dial: rec.dial, Logger: quiet})
	conn, err := net.DialTimeout("tcp", addr, ioTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// Time enough for the handshake on a machine that is busy; the test waits
	// it out below, to look at the connection after it.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := socks5.Handshake(ctx, conn, "me", "pw", "192.0.2.1:443"); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	<-ctx.Done()
	time.Sleep(50 * time.Millisecond) // past the deadline of ctx
	done := make(chan error, 1)
	go func() {
		if _, err := conn.Write([]byte("ping")); err != nil {
			done <- err
			return
		}
		got := make([]byte, 4)
		_, err := io.ReadFull(conn, got)
		if err == nil && string(got) != "ping" {
			err = fmt.Errorf("the echo is %q", got)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the connection after the handshake: %v", err)
		}
	case <-time.After(ioTimeout):
		t.Fatal("the connection after the handshake hangs")
	}
	want := []socks5.Request{{Username: "me", Host: "192.0.2.1", Port: 443}}
	if got := rec.requests(); !reflect.DeepEqual(got, want) {
		t.Errorf("the server got %+v, want %+v", got, want)
	}

	// A refusal is the error of Dial, and the connection is the caller's to close.
	addr = startServer(t, &socks5.Server{Dial: failWith(&socks5.ReplyError{Code: repNotAllowed}), Logger: quiet})
	refused, err := net.DialTimeout("tcp", addr, ioTimeout)
	if err != nil {
		t.Fatal(err)
	}
	err = socks5.Handshake(context.Background(), refused, "", "", "192.0.2.1:443")
	var re *socks5.ReplyError
	if !errors.As(err, &re) || re.Code != repNotAllowed {
		t.Errorf("error %v, want a ReplyError with code 0x02", err)
	}
	if err := refused.Close(); err != nil {
		t.Errorf("Handshake closed the connection: %v", err)
	}

	// Arguments that Dial refuses are refused before anything goes out.
	for _, tc := range []struct{ user, target string }{
		{strings.Repeat("u", 256), "192.0.2.1:443"},
		{"", "no-port"},
	} {
		c, s := net.Pipe()
		if err := socks5.Handshake(context.Background(), c, tc.user, "", tc.target); err == nil {
			t.Errorf("user of %d bytes, target %q: no error", len(tc.user), tc.target)
		}
		_ = c.Close()
		_ = s.Close()
	}
}

func TestEndToEndFailureCodes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want byte // code the client sees
	}{
		{"refused", opErr(syscall.ECONNREFUSED), repRefused},
		{"unreachable", opErr(syscall.EHOSTUNREACH), repHostUnreach},
		{"timeout", context.DeadlineExceeded, repHostUnreach},
		{"anything else", errors.New("boom"), repGeneral},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := startServer(t, &socks5.Server{Dial: failWith(tc.err), Logger: quiet})
			conn, err := dialVia(addr, "me", "x", "192.0.2.1:443")
			if err == nil {
				_ = conn.Close()
				t.Fatal("Dial succeeded")
			}
			var re *socks5.ReplyError
			if !errors.As(err, &re) || re.Code != tc.want {
				t.Fatalf("error %v, want a ReplyError with code %#02x", err, tc.want)
			}
		})
	}
}

// TestChainedServers puts a server behind a server: the DialFunc of the first
// is the client of the second, as the edge will have it when an egress member
// is a SOCKS5 proxy. What the far server says reaches the near client, with the
// same meaning.
func TestChainedServers(t *testing.T) {
	tests := []struct {
		name string
		far  socks5.DialFunc
		want byte // 0: a tunnel
	}{
		{"tunnel", echo, 0},
		{"refused", refuse, repRefused},
		{"unreachable", failWith(opErr(syscall.ENETUNREACH)), repHostUnreach},
		{"general failure", failWith(errors.New("boom")), repGeneral},
		{"not allowed by the ruleset of the far server", failWith(&socks5.ReplyError{Code: repNotAllowed}), repNotAllowed},
		{"ttl expired behind the far server", failWith(&socks5.ReplyError{Code: repTTL}), repTTL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			farRec := &recorder{fn: tc.far}
			farAddr := startServer(t, &socks5.Server{Dial: farRec.dial, Logger: quiet})
			near := func(ctx context.Context, req socks5.Request) (net.Conn, error) {
				return socks5.Dial(ctx, farAddr, req.Username, "x", net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port))))
			}
			nearAddr := startServer(t, &socks5.Server{Dial: near, Logger: quiet})

			conn, err := dialVia(nearAddr, "me", "x", "[2001:db8::1]:8443")
			if tc.want == 0 {
				if err != nil {
					t.Fatalf("Dial: %v", err)
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(ioTimeout))
				ping(t, conn)
				want := []socks5.Request{{Username: "me", Host: "2001:db8::1", Port: 8443}}
				if got := farRec.requests(); !reflect.DeepEqual(got, want) {
					t.Errorf("the far server's DialFunc got %+v, want %+v", got, want)
				}
				return
			}
			if err == nil {
				_ = conn.Close()
				t.Fatal("Dial succeeded")
			}
			var re *socks5.ReplyError
			if !errors.As(err, &re) || re.Code != tc.want {
				t.Fatalf("error %v, want a ReplyError with code %#02x", err, tc.want)
			}
		})
	}
}

// TestBulkTransferThroughTheServer moves eight megabytes each way at once, over
// real TCP connections on both sides of the server, where the relay copies by
// the means of the operating system. The data comes back whole and in order, and
// nothing deadlocks while both directions are full.
func TestBulkTransferThroughTheServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(2 * ioTimeout))
				_, _ = io.Copy(c, c) // echo, until the client has ended its stream
			})
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	backend := ln.Addr().String()
	dial := func(ctx context.Context, _ socks5.Request) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", backend)
	}
	addr := startServer(t, &socks5.Server{Dial: dial, Logger: quiet})

	conn, err := dialVia(addr, "me", "x", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * ioTimeout))

	msg := payload(8 << 20)
	go func() {
		_, _ = conn.Write(msg)
		_ = conn.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading the echo: %v (after %d of %d bytes)", err, len(got), len(msg))
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("the echo is %d bytes and differs from the %d bytes sent", len(got), len(msg))
	}
}

// TestHalfCloseThroughTheServer sends a request, says that it is done, and waits
// for the answer of a target that answers only once it has seen the end of the
// request, over real TCP connections on both sides of the server.
func TestHalfCloseThroughTheServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(ioTimeout))
				data, _ := io.ReadAll(c) // until the end of the request
				_, _ = c.Write(bytes.ToUpper(data))
			})
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	backend := ln.Addr().String()
	dial := func(ctx context.Context, _ socks5.Request) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", backend)
	}
	addr := startServer(t, &socks5.Server{Dial: dial, Logger: quiet})

	conn, err := dialVia(addr, "me", "x", "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))

	send(t, conn, []byte("half-close works"))
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "HALF-CLOSE WORKS" {
		t.Fatalf("answer %q (%v), want %q", got, err, "HALF-CLOSE WORKS")
	}
}

// ---------------------------------------------------------------------------
// Fuzzing: whatever the peer sends, nothing panics, nothing hangs.
// ---------------------------------------------------------------------------

// eofConn is a target that is already finished: it has nothing to say and takes
// what it is sent.
type eofConn struct{}

func (eofConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (eofConn) Write(b []byte) (int, error)      { return len(b), nil }
func (eofConn) Close() error                     { return nil }
func (eofConn) LocalAddr() net.Addr              { return nil }
func (eofConn) RemoteAddr() net.Addr             { return nil }
func (eofConn) SetDeadline(time.Time) error      { return nil }
func (eofConn) SetReadDeadline(time.Time) error  { return nil }
func (eofConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzServeConn(f *testing.F) {
	seeds := [][]byte{
		cat(hello(methNoAuth), connectReq(v4("192.0.2.1"), 443)),
		cat(hello(methNoAuth), connectReq(v4("192.0.2.1"), 444), []byte("payload")),
		cat(hello(methNoAuth, methUserPass), creds("me", "pw"), connectReq(dom("example.com"), 443)),
		cat(hello(methUserPass), creds("", ""), connectReq(v6("2001:db8::1"), 8443)),
		cat(hello(methNoAuth), request(cmdBind, v4("192.0.2.1"), 443)),
		cat(hello(methNoAuth), request(cmdUDP, dom("example.com"), 53)),
		cat(hello(methNoAuth), []byte{socksVer, cmdConnect, 0, 0x09}),
		cat(hello(methNoAuth), connectReq(dom(""), 443)),
		cat(hello(methNoAuth), connectReq(dom("a b"), 443)),
		cat(hello(methGSSAPI)),
		hello(),
		{socksVer},
		{4, 1, 0, 80, 192, 0, 2, 1, 0},
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		{},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	srv := &socks5.Server{
		Dial: func(_ context.Context, req socks5.Request) (net.Conn, error) {
			switch req.Port % 3 {
			case 0:
				return nil, opErr(syscall.ECONNREFUSED)
			case 1:
				return nil, errors.New("fuzz: dial failed")
			}
			return eofConn{}, nil
		},
		HandshakeTimeout: 2 * time.Second, // only a backstop: the peer below always ends the stream
		Logger:           quiet,
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		client, server := net.Pipe()
		served := make(chan struct{})
		go func() {
			defer close(served)
			srv.ServeConn(context.Background(), server)
		}()
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			_, _ = io.Copy(io.Discard, client)
		}()

		_ = client.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = client.Write(data)
		_ = client.Close()
		<-served
		<-drained
	})
}

func FuzzDialReply(f *testing.F) {
	seeds := [][]byte{
		cat([]byte{socksVer, methNoAuth}, okReply(v4("192.0.2.9"), 40000)),
		cat([]byte{socksVer, methNoAuth}, okReply(v6("2001:db8::9"), 40000)),
		cat([]byte{socksVer, methNoAuth}, okReply(dom("proxy.example"), 40000)),
		cat([]byte{socksVer, methNoAuth}, failReply(repRefused)),
		cat([]byte{socksVer, methNoAuth}, []byte{socksVer, repRefused}),
		cat([]byte{socksVer, methNoAuth}, []byte{socksVer, repOK, 0, atypDomain, 200, 'a'}),
		cat([]byte{socksVer, methNoAuth}, []byte{socksVer, repOK, 0, 0x09}),
		{socksVer, methNone},
		{socksVer, methUserPass},
		{socksVer},
		{4, 0},
		{},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		defer func() { _ = ln.Close() }()
		served := make(chan struct{})
		go func() {
			defer close(served)
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var greeting [3]byte
			if _, err := io.ReadFull(c, greeting[:]); err != nil {
				return
			}
			_, _ = c.Write(data)
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.CloseWrite() // the client sees the end of the reply and does not wait for more
			}
			_, _ = io.Copy(io.Discard, c) // until the client hangs up
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := socks5.Dial(ctx, ln.Addr().String(), "", "", "192.0.2.1:443")
		if (conn == nil) == (err == nil) {
			t.Fatalf("Dial returned the connection %v and the error %v: exactly one of them must be nil", conn, err)
		}
		if conn != nil {
			_ = conn.Close()
		}
		_ = ln.Close() // frees the fake server if the client never came
		<-served
	})
}
