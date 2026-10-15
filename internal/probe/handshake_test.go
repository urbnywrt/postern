package probe

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// dial opens a TCP connection to addr that the test closes when it ends.
func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// recordingConn is a connection that counts the calls of Close and records the
// deadlines that are set on it, in their order.
type recordingConn struct {
	net.Conn
	closes    int
	deadlines []deadlineCall
}

// deadlineCall is a call of SetDeadline, SetReadDeadline or SetWriteDeadline.
type deadlineCall struct {
	method string
	at     time.Time
}

func (d deadlineCall) String() string { return d.method + "(" + d.at.String() + ")" }

func (c *recordingConn) Close() error {
	c.closes++
	return c.Conn.Close()
}

func (c *recordingConn) SetDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, deadlineCall{"SetDeadline", t})
	return c.Conn.SetDeadline(t)
}

func (c *recordingConn) SetReadDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, deadlineCall{"SetReadDeadline", t})
	return c.Conn.SetReadDeadline(t)
}

func (c *recordingConn) SetWriteDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, deadlineCall{"SetWriteDeadline", t})
	return c.Conn.SetWriteDeadline(t)
}

// spyConn is a connection that records what is done with it. It has nothing to
// read, and every method it does not have panics (the embedded Conn is nil).
type spyConn struct {
	net.Conn
	writes, deadlines, closes int
}

func (c *spyConn) Write(b []byte) (int, error)      { c.writes++; return len(b), nil }
func (c *spyConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *spyConn) SetDeadline(time.Time) error      { c.deadlines++; return nil }
func (c *spyConn) Close() error                     { c.closes++; return nil }
func (c *spyConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443} }
func (c *spyConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000} }
func (c *spyConn) SetReadDeadline(time.Time) error  { c.deadlines++; return nil }
func (c *spyConn) SetWriteDeadline(time.Time) error { c.deadlines++; return nil }

func TestHandshakeLeavesTheConnectionToCarryOn(t *testing.T) {
	secret := randomBytes(16)
	// What a fake-TLS server sends after its answer is its first data: the
	// connection is positioned right before it.
	firstData := tlsRecord(0x17, 0x0303, []byte("the first data of the server"))
	srv := startFakeServer(t, fakeServer{secret: secret, answer: func(c *conversation) []byte {
		answer := signed(secret, c.hello.random, serverHello(c.hello.sessionID), changeCipherSpec, appData(3000))
		return append(answer, firstData...)
	}})
	conn := &recordingConn{Conn: dial(t, srv.addr)}

	const timeout = 5 * time.Second
	start := time.Now()
	if err := Handshake(conn, testSNI, secret, Options{Timeout: timeout}); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	end := time.Now()
	if c := srv.next(t); c.err != nil || !c.digestOK || c.hello.sni != testSNI {
		t.Fatalf("the server saw err %v, digest ok %v, server name %q", c.err, c.digestOK, c.hello.sni)
	}

	// The handshake ran under a deadline of its own, and took it off when it
	// was done: the last deadline that is set on the connection is the zero
	// time, so the connection carries on without one.
	if len(conn.deadlines) < 2 {
		t.Fatalf("deadlines set on the connection: %v, want the handshake's and then the zero time", conn.deadlines)
	}
	if d := conn.deadlines[0]; d.method != "SetDeadline" || d.at.Before(start.Add(timeout)) || d.at.After(end.Add(timeout)) {
		t.Errorf("the first deadline is %s(%v), want SetDeadline of the timeout from the start of the handshake, %v to %v",
			d.method, d.at, start.Add(timeout), end.Add(timeout))
	}
	if d := conn.deadlines[len(conn.deadlines)-1]; d.method != "SetDeadline" || !d.at.IsZero() {
		t.Errorf("the last deadline is %s(%v), want SetDeadline of the zero time: the deadline of the handshake must not outlive it",
			d.method, d.at)
	}

	got := make([]byte, len(firstData))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("reading after the handshake: %v", err)
	}
	if !bytes.Equal(got, firstData) {
		t.Errorf("after the handshake the connection reads % x, want the server's first data % x: Handshake must read the three records of the answer and nothing more", got, firstData)
	}
	if conn.closes != 0 {
		t.Error("Handshake closed the connection")
	}
}

func TestHandshakeAnswers(t *testing.T) {
	secret := randomBytes(16)
	tests := []struct {
		name    string
		server  fakeServer
		wantErr error  // matched with errors.Is
		wantMsg string // part of the error text
	}{
		{
			name:    "a server with another secret",
			server:  fakeServer{secret: randomBytes(16), answerAnyway: true},
			wantErr: ErrBadServerDigest,
		},
		{
			name: "a TLS alert",
			server: fakeServer{secret: secret, answer: func(*conversation) []byte {
				return tlsRecord(0x15, 0x0303, []byte{2, 112})
			}},
			wantMsg: "alert 112",
		},
		{
			name:    "the connection closed without an answer",
			server:  fakeServer{secret: secret, answer: func(*conversation) []byte { return nil }},
			wantErr: io.EOF,
		},
		{
			name: "the connection closed inside the answer",
			server: fakeServer{secret: secret, hangUp: true, answer: func(c *conversation) []byte {
				return serverHello(c.hello.sessionID)
			}},
			wantErr: io.ErrUnexpectedEOF,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startFakeServer(t, tt.server)
			conn := &recordingConn{Conn: dial(t, srv.addr)}
			start := time.Now()
			err := Handshake(conn, testSNI, secret, Options{Timeout: 5 * time.Second})
			switch {
			case err == nil:
				t.Fatal("Handshake succeeded, want an error")
			case tt.wantErr == ErrBadServerDigest && err != ErrBadServerDigest:
				// Exactly the error, as FakeTLS returns it, not one that wraps it.
				t.Fatalf("Handshake: %v, want ErrBadServerDigest itself", err)
			case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
				t.Fatalf("Handshake: %v, want %v", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Handshake: %q, want it to mention %q", err, tt.wantMsg)
			}
			if !strings.HasPrefix(err.Error(), "probe: ") || strings.Count(err.Error(), "probe:") != 1 {
				t.Errorf("Handshake: %q, want the prefix %q, once", err, "probe: ")
			}
			if strings.Contains(err.Error(), hex.EncodeToString(secret)) {
				t.Errorf("the error gives the secret away: %v", err)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("Handshake took %v: it waited for more than the server sent", elapsed)
			}
			if conn.closes != 0 {
				t.Error("Handshake closed the connection; that is the caller's to do")
			}
			if c := srv.next(t); c.err != nil {
				t.Fatalf("the server could not read the ClientHello: %v", c.err)
			}
		})
	}
}

func TestHandshakeTimeout(t *testing.T) {
	secret := randomBytes(16)
	srv := startFakeServer(t, fakeServer{secret: secret, hold: true})
	conn := dial(t, srv.addr)

	const timeout = 300 * time.Millisecond
	start := time.Now()
	err := Handshake(conn, testSNI, secret, Options{Timeout: timeout})
	elapsed := time.Since(start)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Handshake: %v, want os.ErrDeadlineExceeded", err)
	}
	if !strings.HasPrefix(err.Error(), "probe: ") || strings.Count(err.Error(), "probe:") != 1 {
		t.Errorf("Handshake: %q, want the prefix %q, once", err, "probe: ")
	}
	if elapsed < timeout || elapsed > timeout+2*time.Second {
		t.Errorf("Handshake returned after %v, want about %v", elapsed, timeout)
	}
	if c := srv.next(t); c.err != nil {
		t.Errorf("server: %v", c.err)
	}
}

func TestHandshakeProxyHeader(t *testing.T) {
	secret := randomBytes(16)
	srv := startFakeServer(t, fakeServer{secret: secret, proxyHeader: true})
	conn := dial(t, srv.addr)

	src := netip.MustParseAddrPort("192.0.2.10:4321")
	if err := Handshake(conn, testSNI, secret, Options{ProxyHeader: &src, Timeout: 5 * time.Second}); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	c := srv.next(t)
	if c.err != nil {
		t.Fatalf("server: %v", c.err)
	}
	if c.proxySrc != src {
		t.Errorf("PROXY source %s, want %s", c.proxySrc, src)
	}
	if want := netip.MustParseAddrPort(conn.RemoteAddr().String()); c.proxyDst != want {
		t.Errorf("PROXY destination %s, want %s, the address the connection goes to", c.proxyDst, want)
	}
	if !c.digestOK {
		t.Error("the client digest does not verify")
	}
}

func TestHandshakeDatesTheHello(t *testing.T) {
	secret := randomBytes(16)
	srv := startFakeServer(t, fakeServer{secret: secret})
	conn := dial(t, srv.addr)

	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	if err := Handshake(conn, testSNI, secret, Options{Timeout: 5 * time.Second, Now: func() time.Time { return at }}); err != nil {
		t.Fatalf("Handshake: %v", err)
	}
	if c := srv.next(t); c.err != nil || c.timestamp != uint32(at.Unix()) {
		t.Errorf("the server saw err %v and timestamp %d, want %d from Options.Now", c.err, c.timestamp, at.Unix())
	}
}

func TestHandshakeArguments(t *testing.T) {
	zero := netip.AddrPort{}
	tests := []struct {
		name   string
		secret []byte
		sni    string
		opt    Options
		want   string
	}{
		{name: "no secret", secret: nil, sni: testSNI, want: "16 bytes"},
		{name: "short secret", secret: randomBytes(15), sni: testSNI, want: "16 bytes"},
		{name: "long secret", secret: randomBytes(17), sni: testSNI, want: "16 bytes"},
		{name: "no server name", secret: randomBytes(16), sni: "", want: "server name"},
		{name: "server name too long", secret: randomBytes(16), sni: strings.Repeat("a", 254), want: "server name"},
		{name: "invalid PROXY source", secret: randomBytes(16), sni: testSNI, opt: Options{ProxyHeader: &zero}, want: "PROXY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &spyConn{}
			err := Handshake(conn, tt.sni, tt.secret, tt.opt)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Handshake: %v, want an error about the %s", err, tt.want)
			}
			if conn.writes != 0 || conn.deadlines != 0 || conn.closes != 0 {
				t.Errorf("Handshake touched the connection (%d writes, %d deadlines, %d closes) before it checked its arguments",
					conn.writes, conn.deadlines, conn.closes)
			}
			if len(tt.secret) > 0 && strings.Contains(err.Error(), hex.EncodeToString(tt.secret)) {
				t.Errorf("the error gives the secret away: %v", err)
			}
		})
	}

	t.Run("no connection", func(t *testing.T) {
		if err := Handshake(nil, testSNI, randomBytes(16), Options{}); err == nil || !strings.HasPrefix(err.Error(), "probe: ") {
			t.Fatalf("Handshake(nil): %v, want an error", err)
		}
	})
}

func TestHandshakeOnAConnectionThatFails(t *testing.T) {
	conn := &spyConn{} // reads EOF at once
	err := Handshake(conn, testSNI, randomBytes(16), Options{Timeout: time.Second})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Handshake: %v, want io.EOF", err)
	}
	if conn.writes != 1 {
		t.Errorf("%d writes, want the ClientHello in one", conn.writes)
	}
	if conn.deadlines == 0 {
		t.Error("Handshake set no deadline: a silent server would hold it forever")
	}
	if conn.closes != 0 {
		t.Error("Handshake closed the connection; that is the caller's to do")
	}
}
