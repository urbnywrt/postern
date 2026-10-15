//go:build integration

package providers_test

// The probe of the integration tests is the test binary itself: TestMain runs
// probeMain instead of the tests when POSTERN_PROVIDERS_PROBE=1. The tests copy
// the binary into their scratch directory and run it in a container on the host
// network, where the members are: with Docker Desktop the daemon's host network
// is a VM, out of reach of the test process, and on a Linux server it is the
// network the agent runs in. So the binary needs nothing beside it, not even a
// Go toolchain, and the readiness code it exercises is the code that ships
// (xray.Driver.Ready). It must be static (CGO_ENABLED=0): the runner image is
// Alpine.
//
// The probe waits up to -wait for Ready on every port of -ports, then runs the
// checks it is asked for through the first port, prints a line per check
// ("ok <check>: ..." or "FAIL <check>: ..."), runs them all, and exits 1 when
// one failed:
//
//	-loopback-only     the ports answer on no address but the loopback
//	-echo              CONNECT to an echo server of its own on 127.0.0.1 and
//	                   get 64 KiB back
//	-dc addr           CONNECT to a Telegram datacenter and exchange
//	                   req_pq_multi / resPQ (unencrypted MTProto over the
//	                   intermediate transport)
//	-tls host:port     CONNECT and complete a TLS handshake, the certificate
//	                   checked for host
//	-poke host:port    CONNECT, send a few bytes, and report what came back;
//	                   never a failure (it is there to make the member dial)

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/providers"
	"github.com/urbnywrt/postern/internal/providers/xray"
	"github.com/urbnywrt/postern/internal/socks5"
)

// probeEnv makes the test binary the probe.
const probeEnv = "POSTERN_PROVIDERS_PROBE"

func TestMain(m *testing.M) {
	if os.Getenv(probeEnv) == "1" {
		os.Exit(probeMain(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func probeMain(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	ports := fs.String("ports", "", "member ports, comma-separated")
	wait := fs.Duration("wait", 60*time.Second, "how long to wait for Ready")
	echo := fs.Bool("echo", false, "echo check")
	dc := fs.String("dc", "", "datacenter address for the MTProto check")
	tlsTarget := fs.String("tls", "", "host:port for the TLS check")
	loopbackOnly := fs.Bool("loopback-only", false, "check that the ports are on the loopback only")
	poke := fs.String("poke", "", "host:port to make the member dial")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var in providers.Instance
	for i, p := range strings.Split(*ports, ",") {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			fmt.Printf("FAIL ports: bad port %q\n", p)
			return 2
		}
		in.Members = append(in.Members, providers.Member{Key: "m" + strconv.Itoa(i), Port: uint16(n)})
	}
	proxy := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(in.Members[0].Port)))

	ctx, cancel := context.WithTimeout(context.Background(), *wait)
	defer cancel()
	start := time.Now()
	for {
		err := xray.Driver{}.Ready(ctx, in)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			fmt.Printf("FAIL ready: not ready after %v: %v\n", time.Since(start).Round(time.Millisecond), err)
			return 1
		}
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Printf("ok ready: every member port answers the SOCKS5 greeting (after %v)\n", time.Since(start).Round(time.Millisecond))

	failed := false
	run := func(name string, check func() (string, error)) {
		msg, err := check()
		if err != nil {
			failed = true
			fmt.Printf("FAIL %s: %v\n", name, err)
			return
		}
		fmt.Printf("ok %s: %s\n", name, msg)
	}
	if *loopbackOnly {
		run("loopback-only", func() (string, error) { return probeLoopbackOnly(in) })
	}
	if *echo {
		run("echo", func() (string, error) { return probeEcho(proxy) })
	}
	if *dc != "" {
		run("dc", func() (string, error) { return probeDC(proxy, *dc) })
	}
	if *poke != "" {
		run("poke", func() (string, error) { return probePoke(proxy, *poke), nil })
	}
	if *tlsTarget != "" {
		run("tls", func() (string, error) { return probeTLS(proxy, *tlsTarget) })
	}
	if failed {
		return 1
	}
	return 0
}

// probeLoopbackOnly dials every port on every address of the namespace that is
// not a loopback address: none may answer.
func probeLoopbackOnly(in providers.Instance) (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("interface addresses: %w", err)
	}
	tried := 0
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		for _, m := range in.Members {
			tried++
			c, err := net.DialTimeout("tcp", net.JoinHostPort(ipn.IP.String(), strconv.Itoa(int(m.Port))), 2*time.Second)
			if err == nil {
				_ = c.Close()
				return "", fmt.Errorf("port %d answers on a non-loopback address", m.Port)
			}
		}
	}
	return fmt.Sprintf("%d non-loopback address/port pairs refused", tried), nil
}

// dialThrough connects to target through the SOCKS5 port; the connection has 30
// s for the whole check.
func dialThrough(proxy, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := socks5.Dial(ctx, proxy, "", "", target)
	if err != nil {
		return nil, fmt.Errorf("CONNECT to %s: %w", target, err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	return conn, nil
}

func probeEcho(proxy string) (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("echo listener: %w", err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	conn, err := dialThrough(proxy, l.Addr().String())
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	payload := make([]byte, 64<<10)
	_, _ = rand.Read(payload)
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return "", fmt.Errorf("reading the echo: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return "", errors.New("the echo differs from what was sent")
	}
	return fmt.Sprintf("%d bytes back through the member", len(payload)), nil
}

// probePoke makes the member dial target, and says what happened: a CONNECT, a
// few bytes, and whatever comes back within a few seconds.
func probePoke(proxy, target string) string {
	conn, err := dialThrough(proxy, target)
	if err != nil {
		return err.Error()
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("poke\r\n")); err != nil {
		return "CONNECT acknowledged, then writing failed: " + err.Error()
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(make([]byte, 64))
	return fmt.Sprintf("CONNECT acknowledged, %d bytes back, then %v", n, err)
}

// MTProto constants (Global Constraints).
const (
	reqPQMulti   = 0xbe7e8ef1
	resPQ        = 0x05162463
	intermediate = 0xeeeeeeee
)

// probeDC connects to a datacenter, sends an unencrypted req_pq_multi over the
// intermediate transport, and wants a resPQ with the same nonce. A CONNECT alone
// proves nothing: Xray acknowledges it before its outbound has connected (F1).
func probeDC(proxy, dc string) (string, error) {
	start := time.Now()
	conn, err := dialThrough(proxy, dc)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	fail := func(format string, args ...any) (string, error) {
		return "", fmt.Errorf("CONNECT to %s acknowledged, but %s", dc, fmt.Sprintf(format, args...))
	}

	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	msg := make([]byte, 0, 40)
	msg = binary.LittleEndian.AppendUint64(msg, 0)                             // auth_key_id
	msg = binary.LittleEndian.AppendUint64(msg, uint64(time.Now().Unix())<<32) // message_id
	msg = binary.LittleEndian.AppendUint32(msg, 20)                            // message_data_length
	msg = binary.LittleEndian.AppendUint32(msg, reqPQMulti)
	msg = append(msg, nonce[:]...)
	frame := binary.LittleEndian.AppendUint32(nil, intermediate)
	frame = binary.LittleEndian.AppendUint32(frame, uint32(len(msg)))
	frame = append(frame, msg...)
	if _, err := conn.Write(frame); err != nil {
		return fail("sending req_pq_multi failed: %v", err)
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return fail("no answer came back: %v", err)
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n < 4 || n > 64<<10 {
		return fail("a frame of %d bytes came back", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return fail("reading the answer failed: %v", err)
	}
	switch {
	case n == 4:
		return fail("the datacenter answered with error code %d", int32(binary.LittleEndian.Uint32(body)))
	case len(body) < 20+4+16:
		return fail("an answer of %d bytes is too short for resPQ", len(body))
	case binary.LittleEndian.Uint64(body[0:8]) != 0:
		return fail("the answer is encrypted")
	case binary.LittleEndian.Uint32(body[20:24]) != resPQ:
		return fail("the answer is not resPQ (constructor %#08x)", binary.LittleEndian.Uint32(body[20:24]))
	case !bytes.Equal(body[24:40], nonce[:]):
		return fail("resPQ carries another nonce")
	}
	return fmt.Sprintf("CONNECT to %s, req_pq_multi answered with resPQ in %v", dc, time.Since(start).Round(time.Millisecond)), nil
}

// ---- the probe's own tests ------------------------------------------------------

// socksShim is a SOCKS5 server on the loopback that connects to every target
// directly: the probe's checks run against it as they run against a member.
func socksShim(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	srv := &socks5.Server{
		Dial: func(ctx context.Context, r socks5.Request) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port))))
		},
		Logger: slog.New(slog.DiscardHandler),
	}
	go func() { _ = srv.Serve(l) }()
	return l.Addr().String()
}

// fakeDC answers one req_pq_multi with what answer makes of its nonce (a whole
// frame, length included; nil closes the connection), after checking that the
// request is what a datacenter wants. A bad request is reported on bad.
func fakeDC(t *testing.T, answer func(nonce []byte) []byte) (addr string, bad <-chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	problems := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		head := make([]byte, 8)
		if _, err := io.ReadFull(c, head); err != nil {
			problems <- "no header: " + err.Error()
			return
		}
		tag, n := binary.LittleEndian.Uint32(head[0:4]), binary.LittleEndian.Uint32(head[4:8])
		msg := make([]byte, n)
		if _, err := io.ReadFull(c, msg); err != nil {
			problems <- "no message: " + err.Error()
			return
		}
		msgID := binary.LittleEndian.Uint64(msg[8:16])
		switch now := uint64(time.Now().Unix()) << 32; {
		case tag != intermediate:
			problems <- fmt.Sprintf("transport tag %#x", tag)
		case n != 40:
			problems <- fmt.Sprintf("a message of %d bytes", n)
		case binary.LittleEndian.Uint64(msg[0:8]) != 0:
			problems <- "auth_key_id is not 0"
		case msgID%4 != 0 || msgID > now+(30<<32) || msgID+(300<<32) < now:
			problems <- "message_id is not a current one, divisible by 4"
		case binary.LittleEndian.Uint32(msg[16:20]) != 20:
			problems <- "message_data_length is not 20"
		case binary.LittleEndian.Uint32(msg[20:24]) != reqPQMulti:
			problems <- "not req_pq_multi"
		}
		if a := answer(msg[24:40]); a != nil {
			_, _ = c.Write(a)
		}
	}()
	return l.Addr().String(), problems
}

// resPQFrame is a datacenter's answer: auth_key_id 0, message_id, length, then
// resPQ (constructor, nonce, server_nonce, pq, the vector of fingerprints).
func resPQFrame(authKeyID uint64, constructor uint32, nonce []byte) []byte {
	body := binary.LittleEndian.AppendUint64(nil, authKeyID)
	body = binary.LittleEndian.AppendUint64(body, uint64(time.Now().Unix())<<32|1)
	inner := binary.LittleEndian.AppendUint32(nil, constructor)
	inner = append(inner, nonce...)
	inner = append(inner, bytes.Repeat([]byte{0x5e}, 16)...)                          // server_nonce
	inner = append(inner, 8, 0x17, 0xed, 0x48, 0x94, 0x1a, 0x08, 0xf9, 0x81, 0, 0, 0) // pq, a TL string
	inner = binary.LittleEndian.AppendUint32(inner, 0x1cb5c415)                       // vector
	inner = binary.LittleEndian.AppendUint32(inner, 1)
	inner = binary.LittleEndian.AppendUint64(inner, 0xc3b42b026ce86b21)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(inner)))
	body = append(body, inner...)
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(body))), body...)
}

func TestProbeDC(t *testing.T) {
	shim := socksShim(t)
	tests := []struct {
		name   string
		answer func(nonce []byte) []byte
		want   string // "" for success, else part of the error
	}{
		{"resPQ", func(n []byte) []byte { return resPQFrame(0, resPQ, n) }, ""},
		{"another nonce", func(n []byte) []byte { return resPQFrame(0, resPQ, make([]byte, 16)) }, "another nonce"},
		{"not resPQ", func(n []byte) []byte { return resPQFrame(0, 0x12345678, n) }, "not resPQ"},
		{"encrypted", func(n []byte) []byte { return resPQFrame(7, resPQ, n) }, "encrypted"},
		{"an error code", func(n []byte) []byte {
			return append(binary.LittleEndian.AppendUint32(nil, 4), binary.LittleEndian.AppendUint32(nil, uint32(0xfffffe6c))...) // -404
		}, "error code -404"},
		{"too short", func(n []byte) []byte { return append(binary.LittleEndian.AppendUint32(nil, 8), make([]byte, 8)...) }, "too short"},
		{"closed", func(n []byte) []byte { return nil }, "no answer came back"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc, bad := fakeDC(t, tt.answer)
			msg, err := probeDC(shim, dc)
			select {
			case p := <-bad:
				t.Fatalf("the fake datacenter did not like the request: %s", p)
			default:
			}
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("probeDC = %v", err)
			case tt.want == "" && !strings.Contains(msg, "resPQ"):
				t.Errorf("probeDC = %q", msg)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("probeDC = %q, %v; want an error that says %q", msg, err, tt.want)
			}
		})
	}
}

// TestProbeDCDirectOnline is the probe's DC check against a real datacenter,
// directly (no provider): it shows that the check's MTProto is what a datacenter
// answers. Only with POSTERN_E2E_ONLINE=1.
func TestProbeDCDirectOnline(t *testing.T) {
	if os.Getenv("POSTERN_E2E_ONLINE") != "1" {
		t.Skip("set POSTERN_E2E_ONLINE=1 to talk to a Telegram datacenter")
	}
	msg, err := probeDC(socksShim(t), dc2)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(msg)
}

func probeTLS(proxy, target string) (string, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("bad -tls %q", target)
	}
	conn, err := dialThrough(proxy, target)
	if err != nil {
		return "", err
	}
	tc := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	defer func() { _ = tc.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		var unknown x509.UnknownAuthorityError
		if errors.As(err, &unknown) {
			return "", fmt.Errorf("TLS handshake with %s: %w (no CA bundle in the container?)", target, err)
		}
		return "", fmt.Errorf("TLS handshake with %s: %w", target, err)
	}
	st := tc.ConnectionState()
	return fmt.Sprintf("TLS handshake with %s: %s, %s, certificate verified", target, tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite)), nil
}
