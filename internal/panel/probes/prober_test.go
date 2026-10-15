package probes

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/probe"
)

func TestProbeClassifies(t *testing.T) {
	errL2 := errors.New("probe: EOF")
	for _, tc := range []struct {
		name      string
		l2, l1    error
		ok, l1OK  bool
		wantError string
	}{
		{name: "L2 ok", ok: true, l1OK: true},
		{name: "L2 failed, L1 ok", l2: errL2, l1OK: true, wantError: ErrNoDatacenterL1},
		{name: "both failed, wrong digest", l2: errL2, l1: fmt.Errorf("x: %w", probe.ErrBadServerDigest), wantError: ErrRefusedSecret},
		{name: "both failed, no answer", l2: errL2, l1: io.EOF, wantError: ErrUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &clock{t: time.Unix(1000, 0)}
			l1Called := false
			f := newProbe(
				func(_ context.Context, addr, sni string, secret []byte, dc int16, opt probe.Options) error {
					if addr != "proxy.example.com:443" || sni != "www.example.com" || len(secret) != 16 || dc != probeDC || opt.Timeout != probeTimeout {
						t.Errorf("L2(%s, %s, %d bytes, dc %d, %v)", addr, sni, len(secret), dc, opt.Timeout)
					}
					c.Add(1234 * time.Millisecond)
					return tc.l2
				},
				func(_ context.Context, addr, sni string, _ []byte, _ probe.Options) error {
					l1Called = true
					return tc.l1
				}, c.Now)
			p, l1 := f(t.Context(), Target{Addr: "proxy.example.com:443", SNI: "www.example.com", Secret: make([]byte, 16)})
			if p.OK != tc.ok || l1 != tc.l1OK || p.Error != tc.wantError || p.LatencyMS != 1234 {
				t.Errorf("= %+v, l1 %v; want ok %v, l1 %v, error %q, 1234 ms", p, l1, tc.ok, tc.l1OK, tc.wantError)
			}
			if l1Called != (tc.l2 != nil) {
				t.Errorf("L1 called: %v, want only after a failed L2", l1Called)
			}
		})
	}
}

// fakeTLSServer is a fake-TLS server that knows secret as far as the
// handshake goes: it answers a ClientHello with the ServerHello,
// ChangeCipherSpec and application data records whose digest proves the
// secret, then closes the connection, so that no datacenter ever answers
// through it.
func fakeTLSServer(t *testing.T, secret []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var hdr [5]byte
				if _, err := io.ReadFull(c, hdr[:]); err != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
				if _, err := io.ReadFull(c, body); err != nil || len(body) < 38 {
					return
				}
				clientRandom := body[6:38]
				hello := append([]byte{0x02, 0, 0, 38}, 3, 3)
				hello = append(hello, make([]byte, 32)...)
				hello = append(hello, 0, 0x13, 0x01, 0)
				answer := append([]byte{0x16, 3, 3, 0, byte(len(hello))}, hello...)
				answer = append(answer, 0x14, 3, 3, 0, 1, 1)
				answer = append(answer, 0x17, 3, 3, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8)
				mac := hmac.New(sha256.New, secret)
				mac.Write(clientRandom)
				mac.Write(answer)
				copy(answer[11:43], mac.Sum(nil))
				_, _ = c.Write(answer)
				_, _ = c.Read(make([]byte, 1024)) // what L2 sends, then hang up
			}()
		}
	}()
	return ln.Addr().String()
}

func TestRealProbeAgainstFakes(t *testing.T) {
	secret, _ := hex.DecodeString(secretA)
	other, _ := hex.DecodeString(secretB)
	addr := fakeTLSServer(t, secret)

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	_ = closed.Close()

	for _, tc := range []struct {
		name   string
		addr   string
		secret []byte
		want   string
		l1     bool
	}{
		{"the proxy knows the secret, no datacenter", addr, secret, ErrNoDatacenterL1, true},
		{"the proxy does not know the secret", addr, other, ErrRefusedSecret, false},
		{"nothing listens", closedAddr, secret, ErrUnreachable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, l1 := RealProbe()(t.Context(), Target{Addr: tc.addr, SNI: "www.example.com", Secret: tc.secret})
			if p.OK || p.Error != tc.want || l1 != tc.l1 {
				t.Errorf("= %+v, l1 %v; want error %q, l1 %v", p, l1, tc.want, tc.l1)
			}
		})
	}
}
