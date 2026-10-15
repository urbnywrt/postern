package egress

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/socks5"
)

// ---------------------------------------------------------------------------
// NewMemberDialer: what it accepts and what it refuses.
// ---------------------------------------------------------------------------

func TestNewMemberDialerValidation(t *testing.T) {
	long := strings.Repeat("a", 256)
	cases := []struct {
		name    string
		m       *edgev1.ChainMember
		wantErr string // a part of the error, "" for none
	}{
		{"nil member", nil, "nil"},
		{"empty kind", mem("k", ""), "kind"},
		{"unknown kind", mem("k", "wireguard"), "kind"},

		{"direct", mem("k", "direct"), ""},
		{"direct ignores addr", &edgev1.ChainMember{Key: "k", Kind: "direct", Addr: "whatever"}, ""},
		{"direct with bind ip", &edgev1.ChainMember{Key: "k", Kind: "direct", BindIp: "127.0.0.2"}, ""},
		{"direct with bind ip v6", &edgev1.ChainMember{Key: "k", Kind: "direct", BindIp: "2001:db8::1"}, ""},
		{"direct with bad bind ip", &edgev1.ChainMember{Key: "k", Kind: "direct", BindIp: "not-an-ip"}, "bind_ip"},
		{"direct with zone in bind ip", &edgev1.ChainMember{Key: "k", Kind: "direct", BindIp: "fe80::1%eth0"}, "bind_ip"},
		{"direct with long device", &edgev1.ChainMember{Key: "k", Kind: "direct", BindDevice: "abcdefghijklmnop"}, "bind_device"},
		{"direct with slash in device", &edgev1.ChainMember{Key: "k", Kind: "direct", BindDevice: "a/b"}, "bind_device"},

		{"socks5", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "127.0.0.1:1080"}, ""},
		{"socks5 with credentials", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "proxy.example:1080", Username: "u", Password: "p"}, ""},
		{"socks5 ipv6 proxy", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "[2001:db8::1]:1080"}, ""},
		{"socks5 without addr", mem("k", "socks5"), "addr"},
		{"socks5 addr without port", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "127.0.0.1"}, "addr"},
		{"socks5 port 0", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "127.0.0.1:0"}, "addr"},
		{"socks5 port too big", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "127.0.0.1:70000"}, "addr"},
		{"socks5 port not a number", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "127.0.0.1:http"}, "addr"},
		{"socks5 long username", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "127.0.0.1:1080", Username: long}, "username"},
		{"socks5 long password", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "127.0.0.1:1080", Password: long}, "password"},
		{"socks5 with bind ip", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "127.0.0.1:1080", BindIp: "127.0.0.2"}, ""},
		{"socks5 with bad bind ip", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "127.0.0.1:1080", BindIp: "not-an-ip"}, "bind_ip"},
		{"socks5 with zone in bind ip", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "127.0.0.1:1080", BindIp: "fe80::1%eth0"}, "bind_ip"},
		{"socks5 with long device", &edgev1.ChainMember{Key: "k", Kind: "socks5", Addr: "127.0.0.1:1080", BindDevice: "abcdefghijklmnop"}, "bind_device"},

		{"http", &edgev1.ChainMember{Key: "k", Kind: "http", Addr: "127.0.0.1:3128"}, ""},
		{"http with credentials", &edgev1.ChainMember{Key: "k", Kind: "http", Addr: "127.0.0.1:3128", Username: "u", Password: "p:q"}, ""},
		{"http without addr", mem("k", "http"), "addr"},
		{"http addr without port", &edgev1.ChainMember{Key: "k", Kind: "http", Addr: "proxy.example"}, "addr"},
		{"http colon in username", &edgev1.ChainMember{Key: "k", Kind: "http", Addr: "127.0.0.1:3128", Username: "a:b", Password: "p"}, "username"},
		{"http credentials of 1 KiB each", &edgev1.ChainMember{Key: "k", Kind: "http", Addr: "127.0.0.1:3128", Username: strings.Repeat("u", 1024), Password: strings.Repeat("p", 1024)}, ""},
		{"http username of more than 1 KiB", &edgev1.ChainMember{Key: "k", Kind: "http", Addr: "127.0.0.1:3128", Username: strings.Repeat("u", 1025), Password: "p"}, "username"},
		{"http password of more than 1 KiB", &edgev1.ChainMember{Key: "k", Kind: "http", Addr: "127.0.0.1:3128", Username: "u", Password: strings.Repeat("p", 1025)}, "password"},
		{"http with bind ip v6", &edgev1.ChainMember{Key: "k", Kind: "http", Addr: "127.0.0.1:3128", BindIp: "2001:db8::1"}, ""},
		{"http with bad bind ip", &edgev1.ChainMember{Key: "k", Kind: "http", Addr: "127.0.0.1:3128", BindIp: "192.0.2.300"}, "bind_ip"},
		{"http with slash in device", &edgev1.ChainMember{Key: "k", Kind: "http", Addr: "127.0.0.1:3128", BindDevice: "a/b"}, "bind_device"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewMemberDialer(tc.m, time.Second)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewMemberDialer: %v", err)
				}
				if d == nil {
					t.Fatal("NewMemberDialer returned no dialer and no error")
				}
				return
			}
			if err == nil {
				t.Fatalf("NewMemberDialer succeeded, want an error about %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewMemberDialerErrorsDoNotCarryCredentials(t *testing.T) {
	for _, kind := range []string{"socks5", "http"} {
		_, err := NewMemberDialer(&edgev1.ChainMember{Key: "k", Kind: kind, Addr: "no-port", Username: "alice", Password: "hunter2"}, time.Second)
		if err == nil {
			t.Fatalf("%s: no error for an address without a port", kind)
		}
		if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "alice") {
			t.Errorf("%s: error %q carries the credentials", kind, err)
		}
	}
}

func TestNewMemberDialerDefaultTimeout(t *testing.T) {
	for _, kind := range []string{"socks5", "http"} {
		d, err := NewMemberDialer(&edgev1.ChainMember{Key: "k", Kind: kind, Addr: "127.0.0.1:1"}, 0)
		if err != nil {
			t.Fatal(err)
		}
		var got time.Duration
		switch d := d.(type) {
		case *socks5Dialer:
			got = d.timeout
		case *httpDialer:
			got = d.timeout
		default:
			t.Fatalf("%s: unexpected dialer type %T", kind, d)
		}
		if got != DefaultDialTimeout || DefaultDialTimeout != 4*time.Second {
			t.Errorf("%s: timeout %v, default %v, want both 4s", kind, got, DefaultDialTimeout)
		}
	}
	d, err := NewMemberDialer(mem("k", "direct"), -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.(*directDialer).sock.nd.Timeout; got != DefaultDialTimeout {
		t.Errorf("direct: timeout %v, want the default %v", got, DefaultDialTimeout)
	}
}

// ---------------------------------------------------------------------------
// The error classes of a dial through a member.
// ---------------------------------------------------------------------------

func TestAnswered(t *testing.T) {
	refusedByTarget := &socks5.ReplyError{Code: 0x05}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"socks5 refused reply", refusedByTarget, true},
		{"socks5 host unreachable reply", &socks5.ReplyError{Code: 0x04}, true},
		{"socks5 reply, wrapped", fmt.Errorf("member: %w", refusedByTarget), true},
		{"http 502", &ConnectError{Status: 502}, true},
		{"http 403", &ConnectError{Status: 403}, true},
		{"http 407 is the member's own credentials", &ConnectError{Status: 407}, false},
		{"connection to the member refused", opErr(syscall.ECONNREFUSED), false},
		{"timeout", context.DeadlineExceeded, false},
		{"proxy closed in the handshake", io.ErrUnexpectedEOF, false},
		{"credentials rejected", errors.New("socks5: the proxy rejected the credentials"), false},
		{"joined, one answered", errors.Join(opErr(syscall.ECONNREFUSED), refusedByTarget), true},
	}
	for _, tc := range cases {
		if got := answered(tc.err); got != tc.want {
			t.Errorf("%s: answered = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// direct
// ---------------------------------------------------------------------------

func TestDirectMemberConnects(t *testing.T) {
	addr := startEcho(t)
	d, err := NewMemberDialer(mem("d", "direct"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if got := roundTrip(t, conn, "hello"); got != "hello" {
		t.Errorf("echo returned %q", got)
	}
	// The connection the engine's bytes pass through is the bare TCP connection,
	// so that CloseWrite (half-close) and the splice of the relay keep working.
	if _, ok := conn.(*net.TCPConn); !ok {
		t.Errorf("the connection is a %T, want *net.TCPConn", conn)
	}
}

func TestDirectMemberRefused(t *testing.T) {
	d, err := NewMemberDialer(mem("d", "direct"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.DialContext(context.Background(), "tcp", closedAddr(t))
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("error %v, want a refused connection", err)
	}
	var re *socks5.ReplyError
	if errors.As(err, &re) || answered(err) {
		t.Errorf("a refused connection of a direct member was taken for the answer of a proxy")
	}
}

func TestDirectMemberUnsupportedNetwork(t *testing.T) {
	d, err := NewMemberDialer(mem("d", "direct"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp", "unix", ""} {
		if conn, err := d.DialContext(context.Background(), network, "127.0.0.1:1"); err == nil {
			_ = conn.Close()
			t.Errorf("network %q: dial succeeded", network)
		}
	}
}

func TestDirectMemberHonoursItsTimeout(t *testing.T) {
	// A listener whose backlog is full leaves the next SYN unanswered on Linux,
	// which a unit test cannot rely on. A context that is already late makes the
	// same point: the dial gives up with the error of the context.
	d, err := NewMemberDialer(mem("d", "direct"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.DialContext(ctx, "tcp", startEcho(t)); !errors.Is(err, context.Canceled) {
		t.Errorf("error %v, want context.Canceled", err)
	}
}

// needSecondLoopback skips the test unless this machine connects from 127.0.0.2
// to 127.0.0.1, as Linux does, where every address of 127.0.0.0/8 is local: a
// source address other than the usual 127.0.0.1 is what shows that bind_ip was
// used. It finds that out with a plain dial to a listener of its own, so that
// in the test itself a failure of the member is a failure of the test.
func needSecondLoopback(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: ioTimeout}
	c, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("cannot connect from 127.0.0.2 here: %v", err)
	}
	_ = c.Close()
}

func TestDirectMemberBindIP(t *testing.T) {
	needSecondLoopback(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	seen := make(chan net.Addr, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		seen <- c.RemoteAddr()
		_ = c.Close()
	}()

	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "d", Kind: "direct", BindIp: "127.0.0.2"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial from 127.0.0.2: %v", err)
	}
	defer func() { _ = conn.Close() }()
	select {
	case a := <-seen:
		if ip := a.(*net.TCPAddr).IP; !ip.Equal(net.ParseIP("127.0.0.2")) {
			t.Errorf("the target saw %v, want 127.0.0.2", ip)
		}
	case <-time.After(ioTimeout):
		t.Fatal("the target saw no connection")
	}
}

// sourceNoter accepts TCP connections on 127.0.0.1, notes the address that
// each comes from, and hands it to serve.
type sourceNoter struct {
	addr    string
	mu      sync.Mutex
	sources []netip.Addr
}

func startSourceNoter(t *testing.T, serve func(net.Conn)) *sourceNoter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &sourceNoter{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.sources = append(s.sources, c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap())
			s.mu.Unlock()
			go serve(c)
		}
	}()
	return s
}

func (s *sourceNoter) seen() []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]netip.Addr(nil), s.sources...)
}

// A proxy member makes its connection to the proxy from bind_ip, as a direct
// member makes the one to its target.
func TestProxyMembersBindIP(t *testing.T) {
	needSecondLoopback(t)
	echo := startEcho(t)
	serve := map[string]func(net.Conn){
		KindSOCKS5: func(c net.Conn) {
			srv := &socks5.Server{Dial: (&requestLog{target: echo}).dial, Logger: quiet}
			srv.ServeConn(context.Background(), c)
		},
		KindHTTP: func(c net.Conn) { serveConnect(c, echo, func(string) bool { return true }) },
	}
	for _, kind := range []string{KindSOCKS5, KindHTTP} {
		t.Run(kind, func(t *testing.T) {
			proxy := startSourceNoter(t, serve[kind])
			d, err := NewMemberDialer(&edgev1.ChainMember{Key: "p", Kind: kind, Addr: proxy.addr, BindIp: "127.0.0.2"}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.DialContext(context.Background(), "tcp", "192.0.2.10:443")
			if err != nil {
				t.Fatalf("dial from 127.0.0.2: %v", err)
			}
			defer func() { _ = conn.Close() }()
			if got := roundTrip(t, conn, "ping"); got != "ping" {
				t.Errorf("echo returned %q", got)
			}
			if got := proxy.seen(); len(got) != 1 || got[0] != netip.MustParseAddr("127.0.0.2") {
				t.Errorf("the proxy saw connections from %v, want one from 127.0.0.2", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The race of the addresses of a name (RFC 8305)
// ---------------------------------------------------------------------------

func addrs(list ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range list {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestInterleaveFamilies(t *testing.T) {
	for _, tc := range []struct{ in, want []netip.Addr }{
		{nil, nil},
		{addrs("192.0.2.1"), addrs("192.0.2.1")},
		{addrs("2001:db8::1", "2001:db8::2", "192.0.2.1", "192.0.2.2", "2001:db8::3"), addrs("2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2", "2001:db8::3")},
		{addrs("192.0.2.1", "2001:db8::1", "2001:db8::2"), addrs("192.0.2.1", "2001:db8::1", "2001:db8::2")},
	} {
		if got := interleaveFamilies(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("interleaveFamilies(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// raceAttempt is a dial of raceDial in a test: when it began, and how it ended.
type raceAttempt struct {
	addr  netip.Addr
	start time.Duration
}

// raceDialer stands in for the dial of raceDial: each address does what its
// behaviour says, after the time it says, and every dial is noted.
type raceDialer struct {
	t0       time.Time
	mu       sync.Mutex
	attempts []raceAttempt
	conns    []*trackedConn
	act      map[netip.Addr]func(ctx context.Context) (net.Conn, error)
}

func (r *raceDialer) dial(ctx context.Context, a netip.Addr) (net.Conn, error) {
	r.mu.Lock()
	r.attempts = append(r.attempts, raceAttempt{addr: a, start: time.Since(r.t0)})
	act := r.act[a]
	r.mu.Unlock()
	conn, err := act(ctx)
	if tc, ok := conn.(*trackedConn); ok {
		r.mu.Lock()
		r.conns = append(r.conns, tc)
		r.mu.Unlock()
	}
	return conn, err
}

func after(d time.Duration, conn net.Conn, err error) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		select {
		case <-time.After(d):
			if conn == nil && err == nil {
				conn = &trackedConn{Conn: sinkConn()}
			}
			return conn, err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// The addresses are raced as RFC 8305 says: the next attempt starts when the
// one before has had 300 ms to itself, or at once when it fails; the first
// connection wins, and an attempt that connects after it is closed.
func TestRaceDial(t *testing.T) {
	refused := opErr(syscall.ECONNREFUSED)
	t.Run("an address that never answers holds the next one up for 300 ms", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rd := &raceDialer{t0: time.Now(), act: map[netip.Addr]func(context.Context) (net.Conn, error){
				netip.MustParseAddr("2001:db8::1"): noAnswer,
				netip.MustParseAddr("192.0.2.1"):   after(50*time.Millisecond, nil, nil),
				netip.MustParseAddr("2001:db8::2"): after(0, nil, nil),
			}}
			conn, err := raceDial(context.Background(), addrs("2001:db8::1", "192.0.2.1", "2001:db8::2"), rd.dial)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			if got := time.Since(rd.t0); got != 350*time.Millisecond {
				t.Errorf("the race took %v, want 350ms", got)
			}
			want := []raceAttempt{{netip.MustParseAddr("2001:db8::1"), 0}, {netip.MustParseAddr("192.0.2.1"), 300 * time.Millisecond}}
			if !slices.Equal(rd.attempts, want) {
				t.Errorf("attempts %v, want %v", rd.attempts, want)
			}
		})
	})
	t.Run("a failure starts the next attempt at once", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rd := &raceDialer{t0: time.Now(), act: map[netip.Addr]func(context.Context) (net.Conn, error){
				netip.MustParseAddr("2001:db8::1"): after(100*time.Millisecond, nil, refused),
				netip.MustParseAddr("192.0.2.1"):   after(0, nil, nil),
			}}
			conn, err := raceDial(context.Background(), addrs("2001:db8::1", "192.0.2.1"), rd.dial)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			if len(rd.attempts) != 2 || rd.attempts[1].start != 100*time.Millisecond {
				t.Errorf("attempts %v, want the second at 100ms", rd.attempts)
			}
		})
	})
	t.Run("the first failure is the error when every attempt fails", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			unreachable := opErr(syscall.EHOSTUNREACH)
			rd := &raceDialer{t0: time.Now(), act: map[netip.Addr]func(context.Context) (net.Conn, error){
				netip.MustParseAddr("2001:db8::1"): after(500*time.Millisecond, nil, unreachable),
				netip.MustParseAddr("192.0.2.1"):   after(10*time.Millisecond, nil, refused), // starts at 300 ms, fails first
			}}
			_, err := raceDial(context.Background(), addrs("2001:db8::1", "192.0.2.1"), rd.dial)
			if !errors.Is(err, syscall.ECONNREFUSED) {
				t.Errorf("error %v, want the refusal, which came first", err)
			}
		})
	})
	t.Run("a connection that loses the race is closed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rd := &raceDialer{t0: time.Now(), act: map[netip.Addr]func(context.Context) (net.Conn, error){
				netip.MustParseAddr("2001:db8::1"): func(context.Context) (net.Conn, error) {
					time.Sleep(400 * time.Millisecond) // deaf to the cancellation, as a dialer may be
					return &trackedConn{Conn: sinkConn()}, nil
				},
				netip.MustParseAddr("192.0.2.1"): after(10*time.Millisecond, nil, nil),
			}}
			conn, err := raceDial(context.Background(), addrs("2001:db8::1", "192.0.2.1"), rd.dial)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			synctest.Wait()
			time.Sleep(time.Second)
			synctest.Wait()
			rd.mu.Lock()
			defer rd.mu.Unlock()
			if len(rd.conns) != 2 || conn != net.Conn(rd.conns[0]) || rd.conns[0].closed.Load() || !rd.conns[1].closed.Load() {
				t.Errorf("the winner must stay open and the late connection be closed")
			}
		})
	})
	t.Run("a single address is dialed as it is", func(t *testing.T) {
		rd := &raceDialer{t0: time.Now(), act: map[netip.Addr]func(context.Context) (net.Conn, error){
			netip.MustParseAddr("192.0.2.1"): func(context.Context) (net.Conn, error) { return nil, refused },
		}}
		if _, err := raceDial(context.Background(), addrs("192.0.2.1"), rd.dial); !errors.Is(err, syscall.ECONNREFUSED) {
			t.Errorf("error %v", err)
		}
	})
}

// noAnswer is the dial of an address that never answers.
func noAnswer(ctx context.Context) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// countingListener counts the connections it accepts.
type countingListener struct {
	net.Listener
	mu sync.Mutex
	n  int
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.n++
		l.mu.Unlock()
	}
	return c, err
}

func (l *countingListener) accepted() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n
}

func startCounting(t *testing.T) (*countingListener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := &countingListener{Listener: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := cl.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return cl, ln.Addr().String()
}

func TestDirectMemberAppliesTheDestinationPolicyToWhatNamesResolveTo(t *testing.T) {
	if _, err := net.LookupHost("localhost"); err != nil {
		t.Skipf("localhost does not resolve here: %v", err)
	}
	cl, addr := startCounting(t)
	_, port, _ := net.SplitHostPort(addr)
	d, err := NewMemberDialer(mem("d", "direct"), time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// A name is not an address, and the SOCKS port lets names through. A direct
	// member resolves the name itself, so it is the one to look at the address
	// it is about to connect to.
	deny := withDestinationPolicy(context.Background(), destinationAllowed)
	for _, target := range []string{"localhost:" + port, addr} {
		conn, err := d.DialContext(deny, "tcp", target)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("%s: dial through the policy succeeded", target)
		}
		if !errors.Is(err, ErrDestinationNotAllowed) {
			t.Errorf("%s: error %v, want ErrDestinationNotAllowed", target, err)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if n := cl.accepted(); n != 0 {
		t.Errorf("the target accepted %d connections, want none", n)
	}

	// Without the policy in the context, as in the health probes, the same
	// dial goes through; and a permissive policy lets it through as well.
	for name, ctx := range map[string]context.Context{
		"no policy":         context.Background(),
		"permissive policy": withDestinationPolicy(context.Background(), func(netip.Addr) bool { return true }),
	} {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		_ = conn.Close()
	}
}

// ---------------------------------------------------------------------------
// socks5
// ---------------------------------------------------------------------------

// startSOCKS5 serves a SOCKS5 proxy with the given DialFunc on a loopback port
// until the test ends and returns its address.
func startSOCKS5(t *testing.T, dial socks5.DialFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &socks5.Server{Dial: dial, Logger: quiet}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// requestLog notes the requests that reach a DialFunc and answers each by
// connecting to target, a real echo server, whatever the request asked for.
type requestLog struct {
	mu     sync.Mutex
	reqs   []socks5.Request
	target string
	err    error // when set, every request fails with it
}

func (l *requestLog) dial(ctx context.Context, req socks5.Request) (net.Conn, error) {
	l.mu.Lock()
	l.reqs = append(l.reqs, req)
	l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", l.target)
}

func (l *requestLog) requests() []socks5.Request {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]socks5.Request(nil), l.reqs...)
}

func TestSOCKS5MemberAgainstServer(t *testing.T) {
	log := &requestLog{target: startEcho(t)}
	proxy := startSOCKS5(t, log.dial)
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "s", Kind: "socks5", Addr: proxy, Username: "alice", Password: "pw"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	targets := []struct {
		dial string
		want socks5.Request
	}{
		{"192.0.2.10:443", socks5.Request{Username: "alice", Host: "192.0.2.10", Port: 443}},
		{"example.com:8443", socks5.Request{Username: "alice", Host: "example.com", Port: 8443}},
		{"[2001:db8::1]:443", socks5.Request{Username: "alice", Host: "2001:db8::1", Port: 443}},
	}
	for _, tc := range targets {
		conn, err := d.DialContext(context.Background(), "tcp", tc.dial)
		if err != nil {
			t.Fatalf("%s: %v", tc.dial, err)
		}
		if got := roundTrip(t, conn, "ping"); got != "ping" {
			t.Errorf("%s: echo returned %q", tc.dial, got)
		}
		if _, ok := conn.(*net.TCPConn); !ok {
			t.Errorf("%s: the connection is a %T, want *net.TCPConn", tc.dial, conn)
		}
		_ = conn.Close()
	}
	got := log.requests()
	if len(got) != len(targets) {
		t.Fatalf("the proxy saw %d requests, want %d", len(got), len(targets))
	}
	for i, tc := range targets {
		if got[i] != tc.want {
			t.Errorf("request %d: the proxy saw %+v, want %+v", i, got[i], tc.want)
		}
	}
}

func TestSOCKS5MemberWithoutCredentials(t *testing.T) {
	log := &requestLog{target: startEcho(t)}
	proxy := startSOCKS5(t, log.dial)
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "s", Kind: "socks5", Addr: proxy}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", "192.0.2.10:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if got := log.requests(); len(got) != 1 || got[0].Username != "" {
		t.Errorf("the proxy saw %+v, want one request without a user name", got)
	}
}

func TestSOCKS5MemberTargetRefusedIsAReplyError(t *testing.T) {
	proxy := startSOCKS5(t, (&requestLog{err: opErr(syscall.ECONNREFUSED)}).dial)
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "s", Kind: "socks5", Addr: proxy}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.DialContext(context.Background(), "tcp", "192.0.2.10:443")
	var re *socks5.ReplyError
	if !errors.As(err, &re) || re.Code != 0x05 {
		t.Fatalf("error %v, want a ReplyError with code 0x05", err)
	}
	if !answered(err) {
		t.Error("the answer of a proxy that works was not recognised as one")
	}
}

func TestSOCKS5MemberDownIsNotAReplyError(t *testing.T) {
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "s", Kind: "socks5", Addr: closedAddr(t)}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.DialContext(context.Background(), "tcp", "192.0.2.10:443")
	if err == nil {
		t.Fatal("dial through a proxy that is not there succeeded")
	}
	// This error is a refused connection as well, and errors.Is cannot tell it
	// from the refusal of a target that a working proxy reports. The type can.
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("error %v, want a refused connection", err)
	}
	var re *socks5.ReplyError
	if errors.As(err, &re) || answered(err) {
		t.Errorf("a proxy that is down was taken for one that answered: %v", err)
	}
}

func TestSOCKS5MemberKeepsNoDeadlineOnTheConnection(t *testing.T) {
	log := &requestLog{target: startEcho(t)}
	proxy := startSOCKS5(t, log.dial)
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "s", Kind: "socks5", Addr: proxy}, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", "192.0.2.10:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	time.Sleep(300 * time.Millisecond) // longer than the timeout of the member
	if got := roundTripAsIs(t, conn, "late"); got != "late" {
		t.Errorf("echo returned %q", got)
	}
}

func TestSOCKS5MemberTimesOutInTheHandshake(t *testing.T) {
	proxy := startMute(t)
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "s", Kind: "socks5", Addr: proxy}, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = d.DialContext(context.Background(), "tcp", "192.0.2.10:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error %v, want a deadline", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("the dial took %v with a timeout of 100ms", el)
	}
}

// startMute serves a TCP listener that accepts connections and says nothing.
func startMute(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	return ln.Addr().String()
}

// ---------------------------------------------------------------------------
// http
// ---------------------------------------------------------------------------

// proxyLog notes what the CONNECT requests that reach an httptest proxy carried.
type proxyLog struct {
	mu   sync.Mutex
	reqs []proxyReq
}

type proxyReq struct{ method, target, auth string }

func (l *proxyLog) add(r proxyReq) {
	l.mu.Lock()
	l.reqs = append(l.reqs, r)
	l.mu.Unlock()
}

func (l *proxyLog) all() []proxyReq {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]proxyReq(nil), l.reqs...)
}

// startHTTPProxy serves an HTTP proxy that takes CONNECT, with httptest. It asks
// for basic authentication when user is not empty, and connects through to the
// target of the request.
func startHTTPProxy(t *testing.T, user, pass string) (addr string, log *proxyLog) {
	t.Helper()
	log = &proxyLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(proxyReq{method: r.Method, target: r.Host, auth: r.Header.Get("Proxy-Authorization")})
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		if user != "" {
			u, p, ok := parseBasic(r.Header.Get("Proxy-Authorization"))
			if !ok || u != user || p != pass {
				w.Header().Set("Proxy-Authenticate", `Basic realm="egress"`)
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
		}
		up, err := net.DialTimeout("tcp", r.Host, ioTimeout)
		if err != nil {
			http.Error(w, "cannot connect", http.StatusBadGateway)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() {
			_, _ = io.Copy(up, conn)
			_ = up.Close()
		}()
		_, _ = io.Copy(conn, up)
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), log
}

func parseBasic(h string) (user, pass string, ok bool) {
	req := &http.Request{Header: http.Header{"Authorization": {h}}}
	return req.BasicAuth()
}

func TestHTTPMemberConnectsThroughAnHTTPProxy(t *testing.T) {
	target := startEcho(t)
	proxy, log := startHTTPProxy(t, "", "")
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "h", Kind: "http", Addr: proxy}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if got := roundTrip(t, conn, "through the tunnel"); got != "through the tunnel" {
		t.Errorf("echo returned %q", got)
	}
	if _, ok := conn.(*net.TCPConn); !ok {
		t.Errorf("the connection is a %T, want *net.TCPConn", conn)
	}
	reqs := log.all()
	if len(reqs) != 1 || reqs[0].method != http.MethodConnect || reqs[0].target != target || reqs[0].auth != "" {
		t.Errorf("the proxy saw %+v, want one CONNECT to %s without credentials", reqs, target)
	}
}

func TestHTTPMemberBasicAuth(t *testing.T) {
	target := startEcho(t)
	proxy, log := startHTTPProxy(t, "alice", "p:w") // a colon in the password is fine
	good, err := NewMemberDialer(&edgev1.ChainMember{Key: "h", Kind: "http", Addr: proxy, Username: "alice", Password: "p:w"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := good.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	if got := roundTrip(t, conn, "x"); got != "x" {
		t.Errorf("echo returned %q", got)
	}
	_ = conn.Close()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:p:w"))
	if reqs := log.all(); len(reqs) != 1 || reqs[0].auth != want {
		t.Errorf("the proxy saw %+v, want the credentials %q", reqs, want)
	}

	for name, m := range map[string]*edgev1.ChainMember{
		"wrong password": {Key: "h", Kind: "http", Addr: proxy, Username: "alice", Password: "hunter2"},
		"no credentials": {Key: "h", Kind: "http", Addr: proxy},
	} {
		d, err := NewMemberDialer(m, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, err = d.DialContext(context.Background(), "tcp", target)
		var ce *ConnectError
		if !errors.As(err, &ce) || ce.Status != http.StatusProxyAuthRequired {
			t.Errorf("%s: error %v, want a ConnectError with status 407", name, err)
			continue
		}
		if answered(err) {
			t.Errorf("%s: a rejection of the credentials of the member was taken for an answer about the target", name)
		}
		for _, secret := range []string{"hunter2", "alice", base64.StdEncoding.EncodeToString([]byte("alice:hunter2"))} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: error %q carries %q", name, err, secret)
			}
		}
	}
}

func TestHTTPMemberTargetUnreachableIsAConnectError(t *testing.T) {
	proxy, _ := startHTTPProxy(t, "", "")
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "h", Kind: "http", Addr: proxy}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.DialContext(context.Background(), "tcp", closedAddr(t))
	var ce *ConnectError
	if !errors.As(err, &ce) || ce.Status != http.StatusBadGateway {
		t.Fatalf("error %v, want a ConnectError with status 502", err)
	}
	if !answered(err) {
		t.Error("a 502 of a proxy that works was not recognised as an answer")
	}
}

func TestHTTPMemberProxyDownIsNotAnAnswer(t *testing.T) {
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "h", Kind: "http", Addr: closedAddr(t)}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.DialContext(context.Background(), "tcp", "192.0.2.10:443")
	if err == nil || answered(err) || !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("error %v, want a refused connection to the proxy and not an answer", err)
	}
}

// rawProxy is a TCP server that reads the head of a request, notes it, and then
// leaves the answer to reply. It shows what an HTTP member puts on the wire and
// how it reads what comes back, byte by byte, which httptest does not.
type rawProxy struct {
	addr  string
	mu    sync.Mutex
	heads []string
	got   chan struct{} // receives one value for every request head read
}

func startRawProxy(t *testing.T, reply func(c net.Conn)) *rawProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &rawProxy{addr: ln.Addr().String(), got: make(chan struct{}, 16)}
	var cmu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		cmu.Lock()
		defer cmu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			cmu.Lock()
			conns = append(conns, c)
			cmu.Unlock()
			go func() {
				_ = c.SetReadDeadline(time.Now().Add(ioTimeout))
				var head strings.Builder
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					head.WriteString(line)
					if err != nil || line == "\r\n" || line == "\n" {
						break
					}
				}
				_ = c.SetReadDeadline(time.Time{})
				p.mu.Lock()
				p.heads = append(p.heads, head.String())
				p.mu.Unlock()
				p.got <- struct{}{}
				reply(c)
			}()
		}
	}()
	return p
}

func (p *rawProxy) requests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.heads...)
}

func writeAll(c net.Conn, s string) { _, _ = c.Write([]byte(s)) }

func TestHTTPMemberRequestOnTheWire(t *testing.T) {
	cases := []struct {
		name               string
		username, password string
		target             string
		want               string
	}{
		{
			name:   "ipv4 without credentials",
			target: "192.0.2.10:443",
			want:   "CONNECT 192.0.2.10:443 HTTP/1.1\r\nHost: 192.0.2.10:443\r\n\r\n",
		},
		{
			name:     "domain with credentials",
			username: "alice", password: "pw",
			target: "example.com:8443",
			want: "CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\nProxy-Authorization: Basic " +
				base64.StdEncoding.EncodeToString([]byte("alice:pw")) + "\r\n\r\n",
		},
		{
			name:   "ipv6 keeps its brackets",
			target: "[2001:db8::1]:443",
			want:   "CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n",
		},
		{
			name:     "empty user name with a password is sent as it is",
			password: "pw",
			target:   "192.0.2.10:443",
			want: "CONNECT 192.0.2.10:443 HTTP/1.1\r\nHost: 192.0.2.10:443\r\nProxy-Authorization: Basic " +
				base64.StdEncoding.EncodeToString([]byte(":pw")) + "\r\n\r\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := startRawProxy(t, func(c net.Conn) { writeAll(c, "HTTP/1.1 200 Connection established\r\n\r\n") })
			m := &edgev1.ChainMember{Key: "h", Kind: "http", Addr: p.addr, Username: tc.username, Password: tc.password}
			d, err := NewMemberDialer(m, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.DialContext(context.Background(), "tcp", tc.target)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			if got := p.requests(); len(got) != 1 || got[0] != tc.want {
				t.Errorf("the proxy read %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHTTPMemberReadsExactlyTheHeadOfTheAnswer(t *testing.T) {
	cases := []struct {
		name  string
		reply string
	}{
		{"canonical", "HTTP/1.1 200 Connection established\r\nProxy-Agent: x\r\n\r\nhello"},
		{"http 1.0", "HTTP/1.0 200 OK\r\n\r\nhello"},
		{"bare line feeds", "HTTP/1.1 200 OK\nX: y\n\nhello"},
		{"any 2xx", "HTTP/1.1 204 No Content\r\n\r\nhello"},
		{"without a reason phrase", "HTTP/1.1 200\r\n\r\nhello"},
		{"interim answer first", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\nhello"},
		{"a content length is ignored", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nhello"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The answer and the first bytes of the tunnel go out in one write, so
			// that they arrive together. A reader that buffers takes the first
			// bytes of the tunnel along with the head and loses them.
			p := startRawProxy(t, func(c net.Conn) { writeAll(c, tc.reply) })
			d, err := NewMemberDialer(&edgev1.ChainMember{Key: "h", Kind: "http", Addr: p.addr}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.DialContext(context.Background(), "tcp", "192.0.2.10:443")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetReadDeadline(time.Now().Add(ioTimeout))
			got := make([]byte, 5)
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "hello" {
				t.Errorf("the tunnel starts with %q (%v), want %q", got, err, "hello")
			}
		})
	}
}

func TestHTTPMemberRefusesBadAnswers(t *testing.T) {
	cases := []struct {
		name    string
		wantErr string // a part of the error, "" for any
		reply   func(c net.Conn)
	}{
		{"not http", "", func(c net.Conn) { writeAll(c, "SSH-2.0-OpenSSH\r\n\r\n") }},
		{"another major version", "", func(c net.Conn) { writeAll(c, "HTTP/2.0 200 OK\r\n\r\n") }},
		{"status of two digits", "", func(c net.Conn) { writeAll(c, "HTTP/1.1 20 OK\r\n\r\n") }},
		{"status that is not a number", "", func(c net.Conn) { writeAll(c, "HTTP/1.1 2xx OK\r\n\r\n") }},
		{"closed at once", "", func(c net.Conn) { _ = c.Close() }},
		{"closed in the middle of the head", "", func(c net.Conn) { writeAll(c, "HTTP/1.1 200 OK\r\nX: y"); _ = c.Close() }},
		{"head of more than 16 KiB", "16 KiB", func(c net.Conn) {
			writeAll(c, "HTTP/1.1 200 OK\r\n")
			filler := strings.Repeat("X-Filler: "+strings.Repeat("a", 100)+"\r\n", 200)
			writeAll(c, filler)
		}},
		{"endless 1xx answers", "16 KiB", func(c net.Conn) {
			for range 2000 {
				if _, err := c.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n")); err != nil {
					return
				}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := startRawProxy(t, tc.reply)
			d, err := NewMemberDialer(&edgev1.ChainMember{Key: "h", Kind: "http", Addr: p.addr}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.DialContext(context.Background(), "tcp", "192.0.2.10:443")
			if err == nil {
				_ = conn.Close()
				t.Fatal("dial succeeded")
			}
			if answered(err) {
				t.Errorf("a broken answer was taken for the reply of a working proxy: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestHTTPMemberRefusesBadTargets(t *testing.T) {
	p := startRawProxy(t, func(c net.Conn) { writeAll(c, "HTTP/1.1 200 OK\r\n\r\n") })
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "h", Kind: "http", Addr: p.addr}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"",
		"example.com",            // no port
		"example.com:0",          // port 0
		"example.com:99999",      // port out of range
		":443",                   // no host
		"bad host.example:443",   // a space ends the authority
		"a.example\r\nX: 1:443",  // a line break would start another header
		"a.example\x00:443",      // control character
		"user@example.com:443",   // userinfo
		"example.com/path:443",   // not an authority
		"[not-an-ip]:443",        // brackets are for IPv6 literals
		"fe80::1%eth0:443",       // zone
		"a:b:443",                // colon in a name
		"example.com:443/../etc", // junk after the port
	} {
		conn, err := d.DialContext(context.Background(), "tcp", target)
		if err == nil {
			_ = conn.Close()
			t.Errorf("target %q: dial succeeded", target)
		}
	}
	if got := p.requests(); len(got) != 0 {
		t.Errorf("the proxy was sent %q for targets that are not valid", got)
	}
}

func TestHTTPMemberUnsupportedNetwork(t *testing.T) {
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "h", Kind: "http", Addr: closedAddr(t)}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp", "tcp4", ""} {
		if conn, err := d.DialContext(context.Background(), network, "192.0.2.10:443"); err == nil {
			_ = conn.Close()
			t.Errorf("network %q: dial succeeded", network)
		} else if errors.Is(err, syscall.ECONNREFUSED) {
			t.Errorf("network %q: the proxy was dialed", network)
		}
	}
}

func TestHTTPMemberTimesOutAndStopsWithItsContext(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		p := startRawProxy(t, func(net.Conn) {}) // reads the request and never answers
		d, err := NewMemberDialer(&edgev1.ChainMember{Key: "h", Kind: "http", Addr: p.addr}, 100*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_, err = d.DialContext(context.Background(), "tcp", "192.0.2.10:443")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error %v, want a deadline", err)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Errorf("the dial took %v with a timeout of 100ms", el)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		p := startRawProxy(t, func(net.Conn) {})
		d, err := NewMemberDialer(&edgev1.ChainMember{Key: "h", Kind: "http", Addr: p.addr}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		errc := make(chan error, 1)
		go func() {
			_, err := d.DialContext(ctx, "tcp", "192.0.2.10:443")
			errc <- err
		}()
		select {
		case <-p.got:
		case <-time.After(ioTimeout):
			t.Fatal("the proxy did not get the request")
		}
		cancel()
		select {
		case err := <-errc:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("error %v, want context.Canceled", err)
			}
		case <-time.After(ioTimeout):
			t.Fatal("the dial did not stop when its context was cancelled")
		}
	})
}

func TestHTTPMemberKeepsNoDeadlineOnTheConnection(t *testing.T) {
	target := startEcho(t)
	proxy, _ := startHTTPProxy(t, "", "")
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "h", Kind: "http", Addr: proxy}, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	time.Sleep(300 * time.Millisecond) // longer than both the timeout and the context
	if got := roundTripAsIs(t, conn, "late"); got != "late" {
		t.Errorf("echo returned %q", got)
	}
}

func TestDirectMemberAcceptsTheTCPFamilies(t *testing.T) {
	addr := startEcho(t)
	d, err := NewMemberDialer(mem("d", "direct"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp4", addr)
	if err != nil {
		t.Fatalf("tcp4: %v", err)
	}
	if got := roundTrip(t, conn, "four"); got != "four" {
		t.Errorf("echo returned %q", got)
	}
	_ = conn.Close()
	// tcp6 to an IPv4 address finds no address to connect to, and that is the
	// error of the dial, not a network that the dialer refuses.
	if conn, err := d.DialContext(context.Background(), "tcp6", addr); err == nil {
		_ = conn.Close()
		t.Error("tcp6 to an IPv4 address connected")
	} else if errors.Is(err, errUnsupportedNetwork) {
		t.Errorf("tcp6: %v, want the error of the dial", err)
	}
}

func TestSOCKS5MemberUnsupportedNetwork(t *testing.T) {
	d, err := NewMemberDialer(&edgev1.ChainMember{Key: "s", Kind: "socks5", Addr: closedAddr(t)}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp", "tcp4", ""} {
		conn, err := d.DialContext(context.Background(), network, "192.0.2.10:443")
		if err == nil {
			_ = conn.Close()
			t.Errorf("network %q: dial succeeded", network)
			continue
		}
		if !errors.Is(err, errUnsupportedNetwork) {
			t.Errorf("network %q: error %v, want the network to be refused before the proxy is dialed", network, err)
		}
	}
}
