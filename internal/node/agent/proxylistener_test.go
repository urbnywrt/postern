package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/urbnywrt/postern/gen/go/postern/node/v1"
	"github.com/urbnywrt/postern/gen/go/postern/node/v1/nodev1connect"
	"github.com/urbnywrt/postern/internal/pki"
	"github.com/urbnywrt/postern/internal/proxyproto"
)

// listenProxyV2 is a PROXY v2 listener on a free loopback port.
func listenProxyV2(t *testing.T, timeout time.Duration) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pl := newProxyV2Listener(ln, timeout)
	t.Cleanup(func() { _ = pl.Close() })
	return pl
}

// dialWith opens a connection to addr and writes prefix on it first.
func dialWith(t *testing.T, addr string, prefix []byte) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if len(prefix) > 0 {
		if _, err := c.Write(prefix); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// accepted takes the next connection of ln, or fails after a while.
func accepted(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		t.Cleanup(func() { _ = r.c.Close() })
		return r.c
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return")
		return nil
	}
}

var (
	v4Source = netip.MustParseAddrPort("203.0.113.10:40001")
	v6Source = netip.MustParseAddrPort("[2001:db8::10]:40002")
	v2Dest   = netip.MustParseAddrPort("198.51.100.1:443")
)

// The wrapper takes the source of the PROXY v2 header as the connection's
// remote address, and what follows the header is read through it.
func TestProxyV2ListenerReportsTheHeaderSource(t *testing.T) {
	ln := listenProxyV2(t, time.Second)
	for _, src := range []netip.AddrPort{v4Source, v6Source} {
		c := dialWith(t, ln.Addr().String(), append(proxyproto.HeaderV2(src, v2Dest), "hello"...))
		s := accepted(t, ln)
		if got := s.RemoteAddr().String(); got != src.String() {
			t.Errorf("RemoteAddr = %s, want %s", got, src)
		}
		if _, ok := s.RemoteAddr().(*net.TCPAddr); !ok {
			t.Errorf("RemoteAddr is a %T, want *net.TCPAddr", s.RemoteAddr())
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "hello" {
			t.Errorf("read after the header = %q, %v; want hello", buf, err)
		}
		// Bytes written later, past the header, come through as well, and the
		// deadline of the header is gone.
		if _, err := c.Write([]byte(" world")); err != nil {
			t.Fatal(err)
		}
		buf = make([]byte, 6)
		if _, err := io.ReadFull(s, buf); err != nil || string(buf) != " world" {
			t.Errorf("second read = %q, %v; want ' world'", buf, err)
		}
	}
}

// A LOCAL header names no client: the connection keeps its own address.
func TestProxyV2ListenerKeepsTheTCPAddressForALocalHeader(t *testing.T) {
	ln := listenProxyV2(t, time.Second)
	local := []byte("\r\n\r\n\x00\r\nQUIT\n\x20\x00\x00\x00")
	c := dialWith(t, ln.Addr().String(), append(local, 'x'))
	s := accepted(t, ln)
	if got := s.RemoteAddr().String(); got != c.LocalAddr().String() {
		t.Errorf("RemoteAddr = %s, want the TCP peer %s", got, c.LocalAddr())
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(s, buf); err != nil || buf[0] != 'x' {
		t.Errorf("read after the header = %q, %v", buf, err)
	}
}

// A connection without a header is closed and never handed out: garbage at
// once, or nothing within the timeout. A later connection with a header still
// comes through.
func TestProxyV2ListenerClosesConnectionsWithoutAHeader(t *testing.T) {
	ln := listenProxyV2(t, 200*time.Millisecond)
	garbage := dialWith(t, ln.Addr().String(), []byte("GET / HTTP/1.1\r\n"))
	silent := dialWith(t, ln.Addr().String(), nil)
	for _, c := range []net.Conn{garbage, silent} {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Errorf("a connection without a header: Read = %v, want EOF (closed)", err)
		}
	}
	dialWith(t, ln.Addr().String(), proxyproto.HeaderV2(v4Source, v2Dest))
	if got := accepted(t, ln).RemoteAddr().String(); got != v4Source.String() {
		t.Errorf("RemoteAddr = %s, want %s", got, v4Source)
	}
}

// tempAcceptErr is a temporary Accept error: run waits and accepts again
// rather than ending its loop.
type tempAcceptErr struct{}

func (tempAcceptErr) Error() string   { return "temporary accept error" }
func (tempAcceptErr) Timeout() bool   { return false }
func (tempAcceptErr) Temporary() bool { return true }

// flakyListener returns a number of temporary errors from its first Accept
// calls, then the connections of the real listener underneath.
type flakyListener struct {
	net.Listener
	mu    sync.Mutex
	fails int
}

func (f *flakyListener) Accept() (net.Conn, error) {
	f.mu.Lock()
	if f.fails > 0 {
		f.fails--
		f.mu.Unlock()
		return nil, tempAcceptErr{}
	}
	f.mu.Unlock()
	return f.Listener.Accept()
}

// A temporary Accept error does not end the loop: the listener still hands out
// a connection that arrives after it.
func TestProxyV2ListenerRetriesTemporaryAcceptErrors(t *testing.T) {
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	flaky := &flakyListener{Listener: raw, fails: 3}
	ln := newProxyV2Listener(flaky, time.Second)
	t.Cleanup(func() { _ = ln.Close() })
	dialWith(t, ln.Addr().String(), append(proxyproto.HeaderV2(v4Source, v2Dest), "hi"...))
	if got := accepted(t, ln).RemoteAddr().String(); got != v4Source.String() {
		t.Errorf("RemoteAddr = %s, want %s after temporary Accept errors", got, v4Source)
	}
}

// Close wins over a connection whose header is already in: a closed listener
// never hands it out.
func TestProxyV2ListenerCloseWinsOverAReadyConnection(t *testing.T) {
	ln := listenProxyV2(t, time.Second)
	// The header is read in prepare, which then waits to hand the connection
	// out; nobody calls Accept yet.
	dialWith(t, ln.Addr().String(), proxyproto.HeaderV2(v4Source, v2Dest))
	time.Sleep(100 * time.Millisecond)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept after Close with a ready connection = %v, want net.ErrClosed", err)
	}
}

// Close ends Accept with net.ErrClosed.
func TestProxyV2ListenerClose(t *testing.T) {
	ln := listenProxyV2(t, time.Second)
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept on a closed listener = %v, want net.ErrClosed", err)
	}
}

// proxyClient is a NodeService client that writes a PROXY v2 header with src
// before the TLS handshake, as the edge does on the hidden management
// listener (spec 5.3); with the zero src it writes none.
func (p *testPKI) proxyClient(t *testing.T, addr string, src netip.AddrPort) nodev1connect.NodeServiceClient {
	t.Helper()
	fp, err := pki.Fingerprint(p.nodeCert)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := pki.ClientTLSConfig(p.ca.CertPEM, p.clientCert, p.clientKey, strings.ToLower(testNodeID)+".internal", fp)
	if err != nil {
		t.Fatal(err)
	}
	conf.NextProtos = []string{"h2"}
	dst := netip.MustParseAddrPort(addr)
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	tr := &http.Transport{
		Protocols: &protocols, ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if src.IsValid() {
				if err := proxyproto.WriteV2(raw, src, dst); err != nil {
					_ = raw.Close()
					return nil, err
				}
			}
			tc := tls.Client(raw, conf)
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tc, nil
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return nodev1connect.NewNodeServiceClient(&http.Client{Transport: tr, Timeout: 10 * time.Second}, "https://"+addr, connect.WithGRPC())
}

// On the hidden management listener (spec 5.3) peer_addr is the source of
// the PROXY v2 header, IPv4 or IPv6, and a connection without a header is
// closed before any TLS.
func TestGetInfoPeerAddrBehindProxyV2(t *testing.T) {
	r := newRig(t)
	ln := listenProxyV2(t, time.Second)
	addr := serveTLSOn(t, ln, r.svc.handler(), r.pki.serverTLS(t))

	for _, tc := range []struct {
		src  netip.AddrPort
		want string
	}{
		{v4Source, "203.0.113.10"},
		{v6Source, "2001:db8::10"},
		{netip.MustParseAddrPort("[::ffff:203.0.113.11]:5"), "203.0.113.11"},
	} {
		resp, err := r.pki.proxyClient(t, addr, tc.src).GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{}))
		if err != nil {
			t.Fatalf("GetInfo with source %s: %v", tc.src, err)
		}
		if got := resp.Msg.GetPeerAddr(); got != tc.want {
			t.Errorf("peer_addr with source %s = %q, want %q", tc.src, got, tc.want)
		}
	}

	// No header: closed.
	if _, err := r.pki.proxyClient(t, addr, netip.AddrPort{}).GetInfo(context.Background(), connect.NewRequest(&nodev1.GetInfoRequest{})); err == nil {
		t.Error("GetInfo without a PROXY header succeeded, want the connection closed")
	}
}

// peerIP is the IP of a peer address as peer_addr reports it: unmapped,
// without port, "" when it is not a unicast address.
func TestPeerIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"127.0.0.1:5000", "127.0.0.1"},
		{"203.0.113.10:40001", "203.0.113.10"},
		{"[2001:db8::10]:40002", "2001:db8::10"},
		{"[::ffff:203.0.113.10]:1", "203.0.113.10"},
		{"[::1]:1", "::1"},
		{"224.0.0.1:1", ""},
		{"[ff02::1]:1", ""},
		{"0.0.0.0:1", ""},
		{"[::]:1", ""},
		{"[fe80::1%eth0]:1", ""},
		{"203.0.113.10", ""},
		{"", ""},
		{"pipe", ""},
	}
	for _, tc := range cases {
		if got := peerIP(tc.in); got != tc.want {
			t.Errorf("peerIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The wrapper's Read is the buffered reader's: a header followed by bytes in
// one write loses nothing.
func TestProxyConnReadsThroughTheBuffer(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(proxyproto.HeaderV2(v4Source, v2Dest))
	buf.WriteString("payload")
	br := bufio.NewReader(&buf)
	h, err := proxyproto.ReadV2(br)
	if err != nil {
		t.Fatal(err)
	}
	c := &proxyConn{Conn: nil, r: br, remote: tcpAddr(h.Src)}
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "payload" {
		t.Errorf("ReadAll = %q, %v; want payload", got, err)
	}
	if c.RemoteAddr().String() != v4Source.String() {
		t.Errorf("RemoteAddr = %s, want %s", c.RemoteAddr(), v4Source)
	}
}
