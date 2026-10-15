//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/probe"
)

// The tests of the helpers of the end-to-end test. They need no Docker.

// madeUpPublicIPv4 is a random IPv4 address that may be anybody's: neither
// private, nor loopback, nor documentation. It is made up here so that none is
// written down.
func madeUpPublicIPv4() string {
	for {
		a := netip.AddrFrom4([4]byte(randomBytes(4)))
		if a.IsGlobalUnicast() && !a.IsPrivate() && !slices.ContainsFunc(documentation, func(p netip.Prefix) bool { return p.Contains(a) }) {
			return a.String()
		}
	}
}

// TestMaskAddresses checks what the test does to the logs that it prints: the
// addresses of the machine are masked, those of the test are kept.
func TestMaskAddresses(t *testing.T) {
	public6 := func() string {
		b := [16]byte(randomBytes(16))
		b[0], b[1] = 0x2a, 0x0b // in 2000::/3, outside 2001:db8::/32
		return netip.AddrFrom16(b).String()
	}
	v4, v6, mapped := madeUpPublicIPv4(), public6(), madeUpPublicIPv4()
	tests := []struct{ in, want string }{
		{"\x1b[3mexit_ip\x1b[0m\x1b[2m=\x1b[0m" + v4 + " up", "exit_ip=x.x.x.x up"},
		{"dial " + v4 + ":443 failed", "dial x.x.x.x:443 failed"},
		{"a Telegram DC 149.154.175.50:443", "a Telegram DC x.x.x.x:443"},
		{"listen=[" + v6 + "]:443", "listen=[x:x::x]:443"},
		{"from ::ffff:" + mapped, "from ::ffff:x.x.x.x"},
		{"listen=127.0.0.1:443 [::1]:80 [::]:61343 0.0.0.0:1", "listen=127.0.0.1:443 [::1]:80 [::]:61343 0.0.0.0:1"},
		{"link 203.0.113.10:443, 192.0.2.1 and 2001:db8::7", "link 203.0.113.10:443, 192.0.2.1 and 2001:db8::7"},
		{"time=2026-10-04T16:28:42.150Z version 3.5.13", "time=2026-10-04T16:28:42.150Z version 3.5.13"},
	}
	e := &env{sec: &secrets{}}
	value := hex.EncodeToString(randomBytes(16))
	e.secret(value)
	for _, tt := range tests {
		if got := e.scrubbed(tt.in); got != tt.want {
			t.Errorf("scrubbed(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	for _, v := range []string{value, strings.ToUpper(value)} {
		if got := e.scrubbed("the value " + v + " is noted"); got != "the value <secret> is noted" {
			t.Errorf("a value noted as secret is printed: %q", got)
		}
	}
}

// What the test prints of the panel and the node, a status or an error that
// waitFor gets from them for one, goes through the scrubber. The printing is
// done by a helper test in a process of its own (TestHelperPrintsScrubbed),
// whose output this test reads.
func TestPrintedOutputIsScrubbed(t *testing.T) {
	secret, addr := hex.EncodeToString(randomBytes(16)), madeUpPublicIPv4()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperPrintsScrubbed$", "-test.v", "-test.count=1", "-test.timeout=1m")
	cmd.Env = append(os.Environ(), "POSTERN_E2E_HELPER=print", "POSTERN_E2E_HELPER_SECRET="+secret, "POSTERN_E2E_HELPER_ADDR="+addr)
	out, err := cmd.CombinedOutput()
	// The helper fails on purpose: waitFor ends with the error of its check.
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("the helper test did not run and fail: %v", err)
	}
	text := string(out)
	for _, want := range []string{
		"a log line: the node says <secret> and x.x.x.x",
		"an error: the node says <secret> and x.x.x.x",
		"the thing: a status: the node says <secret> and x.x.x.x",
		"waiting for the thing: a check that failed: the node says <secret> and x.x.x.x",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the helper did not print %q", want)
		}
	}
	// What leaked is said, not shown.
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(strings.ToLower(line), secret) {
			t.Errorf("a line of the output has the secret in it: %d bytes", len(line))
		}
		if strings.Contains(line, addr) {
			t.Errorf("a line of the output has the address of the machine in it: %d bytes", len(line))
		}
	}
}

// TestHelperPrintsScrubbed prints, as the end-to-end test does, a value noted
// as secret and an address that may be the machine's. It runs only in the
// process that TestPrintedOutputIsScrubbed starts.
func TestHelperPrintsScrubbed(t *testing.T) {
	if os.Getenv("POSTERN_E2E_HELPER") != "print" {
		t.Skip("a helper of TestPrintedOutputIsScrubbed")
	}
	secret, addr := os.Getenv("POSTERN_E2E_HELPER_SECRET"), os.Getenv("POSTERN_E2E_HELPER_ADDR")
	e := &env{t: t, ctx: context.Background(), start: time.Now(), sec: &secrets{}}
	e.secret(secret)
	said := "the node says " + strings.ToUpper(secret) + " and " + addr
	e.logf("a log line: %s", said)
	e.errorf("an error: %s", said)
	calls := 0
	e.waitFor("the thing", time.Minute, time.Millisecond, func(context.Context) (bool, string, error) {
		calls++
		if calls == 1 {
			return false, "a status: " + said, nil
		}
		return false, "", errors.New("a check that failed: " + said)
	})
}

// The check of the logs finds every value that is noted, in any letter case,
// says in which log and how often, and never shows the value. A log that was
// cut is reported too: what was cut was not checked.
func TestFindLeaks(t *testing.T) {
	secret, token := hex.EncodeToString(randomBytes(16)), rand.Text()
	leaks := []leak{{"the secret of the proxy", secret}, {"the setup token", token}}
	logs := []logText{
		{name: "clean", text: "level=INFO msg=serving", whole: true},
		{name: "upper", text: "secret=" + strings.ToUpper(secret), whole: true},
		{name: "twice", text: token + " " + strings.ToLower(token), whole: true},
		{name: "cut", text: "level=INFO", whole: false},
	}
	got := findLeaks(logs, leaks)
	want := []string{
		"upper holds the secret of the proxy",
		"twice holds the setup token, 2 times",
		"cut was cut at its size limit, so it was not checked in full",
	}
	if !slices.Equal(got, want) {
		t.Errorf("findLeaks = %q, want %q", got, want)
	}
	for _, f := range got {
		if strings.Contains(strings.ToLower(f), secret) || strings.Contains(strings.ToLower(f), strings.ToLower(token)) {
			t.Errorf("a finding shows the value: %d bytes", len(f))
		}
	}
}

// The setup URL that the panel prints once on stdout is the one place where
// the token may be: printed a second time, or the token anywhere else, is a
// leak.
func TestTheSetupURLMayHoldTheToken(t *testing.T) {
	token := rand.Text()
	url := "http://127.0.0.1:8080/setup?token=" + token
	once := "postern-panel: the panel has no admin yet. Open this URL:\n\n  " + url + "\n\n"
	tests := []struct {
		name, stdout string
		leaks        int
	}{
		{"the URL once", once, 0},
		{"the URL twice", once + url + "\n", 1},
		{"the token on its own", once + "token " + token + "\n", 1},
		{"nothing", "", 0},
	}
	for _, tt := range tests {
		got := findLeaks([]logText{{name: "stdout", text: withoutSetupURL(tt.stdout, url), whole: true}},
			[]leak{{"the setup token", token}})
		if len(got) != tt.leaks {
			t.Errorf("%s: %d findings, want %d: %q", tt.name, len(got), tt.leaks, got)
		}
	}
}

// A log holds the private key of the node when it holds a line of the body of
// its PEM block, the body without its line breaks, or the key in hex; the
// markers alone, or a few characters of the body, are no leak.
func TestKeyLeaks(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	// The marker is put together here, so that no scanner takes this file for
	// one that holds a key.
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE " + "KEY", Bytes: der})
	values, err := keyLeaks(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	var leaks []leak
	for _, v := range values {
		leaks = append(leaks, leak{"the key", v})
	}
	lines := strings.Split(strings.TrimSpace(string(keyPEM)), "\n")
	body := strings.Join(lines[1:len(lines)-1], "")
	tests := []struct {
		name, log string
		leak      bool
	}{
		{"the PEM block", string(keyPEM), true},
		{"the PEM block quoted, as in JSON", strconv.Quote(string(keyPEM)), true},
		{"the body without its line breaks", "key=" + body, true},
		{"the second line of the body", "x " + lines[2] + " y", true},
		{"the last line of the body", lines[len(lines)-2], true},
		{"the key in hex", "der=" + hex.EncodeToString(der), true},
		{"the markers", lines[0] + " " + lines[len(lines)-1], false},
		{"a few characters of the body", body[:12], false},
	}
	for _, tt := range tests {
		got := findLeaks([]logText{{name: "log", text: tt.log, whole: true}}, leaks)
		if (len(got) > 0) != tt.leak {
			t.Errorf("%s: %d findings, want a leak: %v", tt.name, len(got), tt.leak)
		}
	}
	if _, err := keyLeaks([]byte("not a PEM block")); err == nil {
		t.Error("keyLeaks takes what is not a PEM block")
	}
}

// The context of a run ends on SIGINT and on SIGTERM, which is how a CI job
// that is cancelled stops the test: the waiting ends and the cleanup runs.
func TestRunContextEndsOnASignal(t *testing.T) {
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			// Without a handler of the run the signal would end this process:
			// one of the test's own keeps it alive, so that the test can fail.
			guard := make(chan os.Signal, 1)
			signal.Notify(guard, sig)
			defer signal.Stop(guard)

			ctx := runContext(t)
			if ctx.Err() != nil {
				t.Fatalf("the context of the run has ended before the signal: %v", ctx.Err())
			}
			self, err := os.FindProcess(os.Getpid())
			if err != nil {
				t.Fatal(err)
			}
			if err := self.Signal(sig); err != nil {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
				t.Fatalf("the context of the run did not end on %v", sig)
			}
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Errorf("the context of the run ended with %v, want it canceled", ctx.Err())
			}
		})
	}
}

// helloServer accepts one connection on the loopback, reads the ClientHello of
// a probe from it, and then does answer with it. It returns its address.
func helloServer(t *testing.T, answer func(c *net.TCPConn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		var hdr [5]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(hdr[3:]))); err != nil {
			return
		}
		answer(c.(*net.TCPConn))
	}()
	return ln.Addr().String()
}

// A probe with a wrong secret has to be refused by a server: what is not a
// refusal (nothing listens, an answer that is no answer of a fake-TLS server,
// a probe that was canceled) must not pass for one. The errors are those of
// the real probe.FakeTLS.
func TestRefusalOfAWrongSecret(t *testing.T) {
	record := func(typ byte, body []byte) []byte {
		return append([]byte{typ, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
	}
	tests := []struct {
		name    string
		answer  func(c *net.TCPConn) // nil: nothing listens
		timeout time.Duration
		want    string // how it was refused; "" for no refusal
	}{
		{
			name: "an answer that does not prove the secret",
			answer: func(c *net.TCPConn) {
				answer := slices.Concat(record(0x16, make([]byte, 64)), record(0x14, []byte{1}), record(0x17, make([]byte, 16)))
				_, _ = c.Write(answer)
			},
			want: "the server's answer does not prove the secret",
		},
		{
			name:   "a TLS alert",
			answer: func(c *net.TCPConn) { _, _ = c.Write(record(0x15, []byte{2, 112})) },
			want:   "the server answered with a TLS alert",
		},
		{
			name:   "the connection closed after the ClientHello",
			answer: func(*net.TCPConn) {},
			want:   "the server closed the connection after the ClientHello",
		},
		{
			name:   "the connection reset after the ClientHello",
			answer: func(c *net.TCPConn) { _ = c.SetLinger(0) },
			want:   "the server reset the connection after the ClientHello",
		},
		{
			name:    "no answer until the probe gives up",
			answer:  func(c *net.TCPConn) { _, _ = io.Copy(io.Discard, c) },
			timeout: 300 * time.Millisecond,
			want:    "the server did not answer before the probe gave up",
		},
		{
			name:   "an answer of another kind of server",
			answer: func(c *net.TCPConn) { _, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n") },
		},
		{
			name: "nothing listens",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var addr string
			if tt.answer != nil {
				addr = helloServer(t, tt.answer)
			} else {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr = ln.Addr().String()
				_ = ln.Close()
			}
			timeout := tt.timeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}
			err := probe.FakeTLS(context.Background(), addr, proxyDomain, randomBytes(16), probe.Options{Timeout: timeout})
			how, ok := refusal(err)
			if ok != (tt.want != "") || how != tt.want {
				t.Errorf("refusal(%v) = %q, %v; want %q, %v", err, how, ok, tt.want, tt.want != "")
			}
		})
	}

	// A probe that is canceled while it waits for the answer (the run got a
	// signal) ends as one that ran out of time does, but it is not a refusal.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := helloServer(t, func(c *net.TCPConn) { _, _ = io.Copy(io.Discard, c) })
	time.AfterFunc(100*time.Millisecond, cancel)
	err := probe.FakeTLS(ctx, addr, proxyDomain, randomBytes(16), probe.Options{Timeout: 5 * time.Second})
	if how, ok := refusal(err); ok || !errors.Is(err, context.Canceled) {
		t.Errorf("a probe canceled while it waits (%v): refusal %v, %q; want no refusal", err, ok, how)
	}

	// A connection that is not made in time is not one that the server
	// refused: the error of probe.FakeTLS then, which no listener of a test
	// can bring about on every network.
	dialTimeout := fmt.Errorf("probe: connecting: %w (%w)",
		&net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}, context.DeadlineExceeded)
	if how, ok := refusal(dialTimeout); ok {
		t.Errorf("a connection that was not made in time (%v) passes for a refusal: %s", dialTimeout, how)
	}
	if _, ok := refusal(nil); ok {
		t.Error("no error passes for a refusal")
	}
}

func TestPortsCover(t *testing.T) {
	for _, c := range []struct {
		list string
		want bool
	}{
		{"20000-40999\n", true},
		{"8080,20000-40999,50000", true},
		{"19000-30000,30001-41000", true},
		{"20000-30000,30000-40999", true},
		{"20000-30000,30002-40999", false},
		{"20001-40999", false},
		{"20000-40998", false},
		{"", false},
		{"\n", false},
		{"20000-x", false},
	} {
		if got := portsCover(c.list, 20000, 40999); got != c.want {
			t.Errorf("portsCover(%q, 20000, 40999) = %v, want %v", c.list, got, c.want)
		}
	}
}
