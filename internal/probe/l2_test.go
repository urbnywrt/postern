package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/iotest"
	"time"
)

// checkRequest checks what the server made of the client's request: the header
// and the req_pq_multi message, sent between before and after.
func checkRequest(t *testing.T, s *dcSession, tag uint32, dc int16, before, after time.Time) {
	t.Helper()
	if s.err != nil {
		t.Fatalf("the server could not read the request: %v", s.err)
	}
	if s.tag != tag {
		t.Errorf("transport tag %#x, want %#x", s.tag, tag)
	}
	if s.dc != dc {
		t.Errorf("datacenter %d in the header, want %d", s.dc, dc)
	}
	switch pad := s.frameLen - 40; {
	case tag == tagIntermediate && pad != 0:
		t.Errorf("a frame of %d bytes, want 40: the intermediate transport has no padding", s.frameLen)
	case pad < 0 || pad > 15:
		t.Errorf("a frame of %d bytes, want 40 and 0 to 15 bytes of padding", s.frameLen)
	}
	if s.authKeyID != 0 {
		t.Errorf("auth_key_id %#x, want 0: the message is not encrypted", s.authKeyID)
	}
	if s.dataLen != 20 {
		t.Errorf("message_data_length %d, want 20", s.dataLen)
	}
	if s.crc != testReqPQMulti {
		t.Errorf("constructor %#x, want req_pq_multi (%#x)", s.crc, testReqPQMulti)
	}
	if s.msgID%4 != 0 {
		t.Errorf("message_id %#x is not a multiple of 4", s.msgID)
	}
	if sec := int64(s.msgID >> 32); sec < before.Unix() || sec > after.Unix() {
		t.Errorf("message_id %#x says %d, want the time of the request (%d to %d)", s.msgID, sec, before.Unix(), after.Unix())
	}
	if s.nonce == [16]byte{} {
		t.Error("the nonce is all zero")
	}
}

// checkError checks an error of DCPing or L2 against what a test wants: wantErr
// matched with errors.Is, wantMsg a part of its text; both empty mean success.
// It never gives away the secret or the nonce.
func checkError(t *testing.T, err, wantErr error, wantMsg string, secret []byte, nonce [16]byte) {
	t.Helper()
	success := wantErr == nil && wantMsg == ""
	switch {
	case success && err != nil:
		t.Fatalf("%v, want success", err)
	case success:
		return
	case err == nil:
		t.Fatal("success, want an error")
	case wantErr != nil && !errors.Is(err, wantErr):
		t.Errorf("%v, want %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), wantMsg) {
		t.Errorf("%q, want it to mention %q", err, wantMsg)
	}
	if !strings.HasPrefix(err.Error(), "probe: ") || strings.Count(err.Error(), "probe:") != 1 {
		t.Errorf("%q, want the prefix %q, once", err, "probe: ")
	}
	for _, s := range []string{hex.EncodeToString(nonce[:]), string(nonce[:])} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("the error gives the nonce away: %q", err)
		}
	}
	if secret != nil && strings.Contains(err.Error(), hex.EncodeToString(secret)) {
		t.Errorf("the error gives the secret away: %q", err)
	}
}

// answerCase is an answer of a datacenter and what DCPing and L2 make of it.
type answerCase struct {
	name    string
	server  dcServer
	wantErr error  // matched with errors.Is
	wantMsg string // part of the error text; both empty mean success
}

// answerCases are the answers that DCPing and L2 judge alike; the answers are
// framed for the transport the client asked for.
func answerCases() []answerCase {
	answer := func(f func(s *dcSession) []byte) dcServer { return dcServer{answer: f} }
	return []answerCase{
		{name: "a resPQ", server: dcServer{}},
		{
			name: "a resPQ with three fingerprints",
			server: answer(func(s *dcSession) []byte {
				return dcFrame(s.tag, plainMessage(0, serverMsgID(), resPQBody(s.nonce, 1, 2, 3)))
			}),
		},
		{
			name:   "a resPQ with 15 bytes after it",
			server: answer(func(s *dcSession) []byte { return paddedFrame(resPQMessage(s.nonce), 15) }),
		},
		{
			name: "a resPQ for another nonce",
			server: answer(func(s *dcSession) []byte {
				return dcFrame(s.tag, resPQMessage([16]byte(randomBytes(16))))
			}),
			wantErr: ErrBadResPQ, wantMsg: "nonce",
		},
		{
			name: "another message",
			server: answer(func(s *dcSession) []byte {
				body := resPQBody(s.nonce, testFingerprint)
				return dcFrame(s.tag, plainMessage(0, serverMsgID(), append(le32(0xa7eff811), body[4:]...)))
			}),
			wantErr: ErrBadResPQ, wantMsg: "0xa7eff811",
		},
		{
			name: "an encrypted message",
			server: answer(func(s *dcSession) []byte {
				return dcFrame(s.tag, plainMessage(0x1122334455667788, serverMsgID(), resPQBody(s.nonce, testFingerprint)))
			}),
			wantErr: ErrBadResPQ, wantMsg: "auth_key_id",
		},
		{
			name:    "a transport error",
			server:  answer(func(s *dcSession) []byte { return dcFrame(s.tag, le32(0xfffffe6c)) }),
			wantErr: ErrBadResPQ, wantMsg: "-404",
		},
		{
			name:    "a short frame",
			server:  answer(func(*dcSession) []byte { return paddedFrame(make([]byte, 12), 0) }),
			wantErr: ErrBadResPQ, wantMsg: "too short",
		},
		{
			// Refused on its length: the probe does not wait for a megabyte.
			name:    "an oversized frame",
			server:  answer(func(*dcSession) []byte { return le32(1 << 20) }),
			wantErr: ErrBadResPQ, wantMsg: "1048576",
		},
		{
			name:    "the connection closed without an answer",
			server:  answer(func(*dcSession) []byte { return nil }),
			wantErr: io.EOF, wantMsg: "without answering",
		},
		{
			name: "the connection closed inside the frame",
			server: dcServer{hangUp: true, answer: func(s *dcSession) []byte {
				return dcFrame(s.tag, resPQMessage(s.nonce))[:30]
			}},
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "the connection closed inside the length",
			server:  dcServer{hangUp: true, answer: func(*dcSession) []byte { return []byte{84, 0} }},
			wantErr: io.ErrUnexpectedEOF,
		},
	}
}

// ---- DCPing -------------------------------------------------------------------

func TestDCPing(t *testing.T) {
	srv := startFakeDC(t, dcServer{})
	conn := &recordingConn{Conn: dial(t, srv.addr)}
	before := time.Now()
	if err := DCPing(t.Context(), conn); err != nil {
		t.Fatalf("DCPing: %v", err)
	}
	after := time.Now()
	checkRequest(t, srv.next(t), tagIntermediate, 0, before, after)
	if conn.closes != 0 {
		t.Error("DCPing closed the connection; that is the caller's to do")
	}
}

func TestDCPingIsFreshEveryTime(t *testing.T) {
	srv := startFakeDC(t, dcServer{})
	var sessions []*dcSession
	for range 2 {
		if err := DCPing(t.Context(), dial(t, srv.addr)); err != nil {
			t.Fatalf("DCPing: %v", err)
		}
		sessions = append(sessions, srv.next(t))
	}
	if sessions[0].nonce == sessions[1].nonce {
		t.Error("two pings sent the same nonce")
	}
	if sessions[0].header == sessions[1].header {
		t.Error("two pings sent the same header")
	}
}

func TestDCPingAnswers(t *testing.T) {
	const timeout = 5 * time.Second
	for _, tt := range answerCases() {
		t.Run(tt.name, func(t *testing.T) {
			srv := startFakeDC(t, tt.server)
			conn := &recordingConn{Conn: dial(t, srv.addr)}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()

			start := time.Now()
			err := DCPing(ctx, conn)
			elapsed := time.Since(start)
			s := srv.next(t)
			if s.err != nil {
				t.Fatalf("the server could not read the request: %v", s.err)
			}
			checkError(t, err, tt.wantErr, tt.wantMsg, nil, s.nonce)
			// Every answer here is complete: the verdict comes from what the
			// server sent, not from running out of time.
			if errors.Is(err, context.DeadlineExceeded) || elapsed > timeout/2 {
				t.Errorf("DCPing took %v and returned %v: it waited for more than the server sent", elapsed, err)
			}
			if conn.closes != 0 {
				t.Error("DCPing closed the connection; that is the caller's to do")
			}
		})
	}
}

// deadlineRecorder records the deadlines set on a connection.
type deadlineRecorder struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *deadlineRecorder) record(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines = append(c.deadlines, t)
}

func (c *deadlineRecorder) SetDeadline(t time.Time) error {
	c.record(t)
	return c.Conn.SetDeadline(t)
}

func (c *deadlineRecorder) SetReadDeadline(t time.Time) error {
	c.record(t)
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	c.record(t)
	return c.Conn.SetWriteDeadline(t)
}

func (c *deadlineRecorder) recorded() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadlines
}

func TestDCPingDeadlines(t *testing.T) {
	t.Run("the deadline of the context, cleared afterwards", func(t *testing.T) {
		// What follows the resPQ stays on the connection, after the deadline
		// of the ping has passed.
		extra := randomBytes(16)
		srv := startFakeDC(t, dcServer{hangUp: true, answer: func(s *dcSession) []byte {
			return append(dcFrame(s.tag, resPQMessage(s.nonce)), extra...)
		}})
		conn := &deadlineRecorder{Conn: dial(t, srv.addr)}
		deadline := time.Now().Add(300 * time.Millisecond)
		ctx, cancel := context.WithDeadline(t.Context(), deadline)
		defer cancel()

		if err := DCPing(ctx, conn); err != nil {
			t.Fatalf("DCPing: %v", err)
		}
		d := conn.recorded()
		if len(d) < 2 || !d[0].Equal(deadline) || !d[len(d)-1].IsZero() {
			t.Fatalf("deadlines %v, want the context's first and none at the end", d)
		}
		time.Sleep(time.Until(deadline) + 200*time.Millisecond)
		rest, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("reading after the ping: %v (its deadline must not outlive it)", err)
		}
		if len(rest) != len(extra) {
			t.Errorf("%d bytes after the ping, want the %d the server sent after the resPQ: DCPing must read the resPQ and nothing more", len(rest), len(extra))
		}
	})

	t.Run("ten seconds when the context has no deadline", func(t *testing.T) {
		srv := startFakeDC(t, dcServer{})
		conn := &deadlineRecorder{Conn: dial(t, srv.addr)}
		before := time.Now()
		if err := DCPing(context.Background(), conn); err != nil {
			t.Fatalf("DCPing: %v", err)
		}
		after := time.Now()
		d := conn.recorded()
		if len(d) < 2 || d[0].Before(before.Add(10*time.Second)) || d[0].After(after.Add(10*time.Second)) || !d[len(d)-1].IsZero() {
			t.Fatalf("deadlines %v, want 10 s from the call first and none at the end", d)
		}
	})

	t.Run("cleared after a wrong answer", func(t *testing.T) {
		srv := startFakeDC(t, dcServer{answer: func(s *dcSession) []byte { return dcFrame(s.tag, le32(0xfffffe6c)) }})
		conn := &deadlineRecorder{Conn: dial(t, srv.addr)}
		if err := DCPing(t.Context(), conn); !errors.Is(err, ErrBadResPQ) {
			t.Fatalf("DCPing: %v, want ErrBadResPQ", err)
		}
		if d := conn.recorded(); len(d) < 2 || !d[len(d)-1].IsZero() {
			t.Fatalf("deadlines %v, want none at the end", d)
		}
	})
}

func TestDCPingTimeout(t *testing.T) {
	srv := startFakeDC(t, dcServer{hold: true})
	conn := dial(t, srv.addr)
	const timeout = 300 * time.Millisecond
	// The clock starts before the context's: the time DCPing takes is at
	// least the timeout.
	start := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	err := DCPing(ctx, conn)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("DCPing: %v, want context.DeadlineExceeded and os.ErrDeadlineExceeded", err)
	}
	if errors.Is(err, ErrBadResPQ) {
		t.Errorf("DCPing: %v, a timeout is no verdict on an answer", err)
	}
	if err != nil && (!strings.HasPrefix(err.Error(), "probe: ") || strings.Count(err.Error(), "probe:") != 1) {
		t.Errorf("DCPing: %q, want the prefix %q, once", err, "probe: ")
	}
	if elapsed < timeout || elapsed > timeout+2*time.Second {
		t.Errorf("DCPing returned after %v, want about %v", elapsed, timeout)
	}
	if s := srv.next(t); s.err != nil {
		t.Errorf("server: %v", s.err)
	}
}

func TestDCPingCanceled(t *testing.T) {
	srv := startFakeDC(t, dcServer{hold: true})
	conn := &deadlineRecorder{Conn: dial(t, srv.addr)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	time.AfterFunc(200*time.Millisecond, cancel)

	start := time.Now()
	err := DCPing(ctx, conn)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("DCPing: %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("DCPing returned %v after the cancellation", elapsed)
	}
	if d := conn.recorded(); len(d) == 0 || !d[len(d)-1].IsZero() {
		t.Errorf("deadlines %v, want none at the end", d)
	}
}

func TestDCPingNoConnection(t *testing.T) {
	if err := DCPing(t.Context(), nil); err == nil || !strings.HasPrefix(err.Error(), "probe: ") {
		t.Fatalf("DCPing(nil): %v, want an error", err)
	}
}

// ---- L2 -----------------------------------------------------------------------

func TestL2(t *testing.T) {
	secret := randomBytes(16)
	for _, dc := range []int16{2, 4, -2} {
		t.Run(fmt.Sprintf("datacenter %d", dc), func(t *testing.T) {
			px := startFakeProxy(t, fakeServer{secret: secret}, dcServer{})
			before := time.Now()
			if err := L2(t.Context(), px.addr, testSNI, secret, dc, Options{Timeout: 5 * time.Second}); err != nil {
				t.Fatalf("L2: %v", err)
			}
			after := time.Now()

			if c := px.next(t); c.err != nil || !c.digestOK || c.hello.sni != testSNI {
				t.Fatalf("the proxy saw err %v, digest ok %v, server name %q", c.err, c.digestOK, c.hello.sni)
			}
			s := px.session(t)
			checkRequest(t, s, tagPaddedIntermediate, dc, before, after)
			if !s.ccs {
				t.Error("no ChangeCipherSpec record before the data")
			}
			// The header and the frame go out in one application data record.
			if len(s.records) != 1 || s.records[0] != 64+4+s.frameLen {
				t.Errorf("application data records of %v bytes, want one of %d", s.records, 64+4+s.frameLen)
			}
		})
	}

	t.Run("the clock of Options", func(t *testing.T) {
		px := startFakeProxy(t, fakeServer{secret: secret}, dcServer{})
		at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
		if err := L2(t.Context(), px.addr, testSNI, secret, 2, Options{Timeout: 5 * time.Second, Now: func() time.Time { return at }}); err != nil {
			t.Fatalf("L2: %v", err)
		}
		if c := px.next(t); c.timestamp != uint32(at.Unix()) {
			t.Errorf("ClientHello dated %d, want %d", c.timestamp, at.Unix())
		}
		checkRequest(t, px.session(t), tagPaddedIntermediate, 2, at, at)
	})

	t.Run("a PROXY header", func(t *testing.T) {
		px := startFakeProxy(t, fakeServer{secret: secret, proxyHeader: true}, dcServer{})
		src := netip.MustParseAddrPort("127.0.0.1:1")
		if err := L2(t.Context(), px.addr, testSNI, secret, 2, Options{ProxyHeader: &src, Timeout: 5 * time.Second}); err != nil {
			t.Fatalf("L2: %v", err)
		}
		c := px.next(t)
		if c.err != nil || c.proxySrc != src {
			t.Errorf("the proxy saw err %v and PROXY source %s, want %s", c.err, c.proxySrc, src)
		}
		if s := px.session(t); s.err != nil {
			t.Errorf("the datacenter half: %v", s.err)
		}
	})
}

func TestL2Answers(t *testing.T) {
	secret := randomBytes(16)
	alert := func(desc byte) func(*dcSession) []byte {
		return func(*dcSession) []byte { return tlsRecord(0x15, 0x0303, []byte{2, desc}) }
	}
	tests := append(answerCases(), []answerCase{
		{
			name:   "the answer in records of 3 bytes after an empty one",
			server: dcServer{recordSize: 3},
		},
		{
			name:    "a TLS alert",
			server:  dcServer{raw: alert(80)},
			wantErr: ErrBadResPQ, wantMsg: "alert 80 (internal_error)",
		},
		{
			name:    "a handshake record",
			server:  dcServer{raw: func(*dcSession) []byte { return tlsRecord(0x16, 0x0303, randomBytes(40)) }},
			wantErr: ErrBadResPQ, wantMsg: "0x16",
		},
		{
			name:    "a ChangeCipherSpec record",
			server:  dcServer{raw: func(*dcSession) []byte { return changeCipherSpec }},
			wantErr: ErrBadResPQ, wantMsg: "0x14",
		},
		{
			name:    "an application data record of TLS 1.0",
			server:  dcServer{raw: func(*dcSession) []byte { return tlsRecord(0x17, 0x0301, randomBytes(40)) }},
			wantErr: ErrBadResPQ, wantMsg: "version",
		},
		{
			// Two bytes of the record, inside the length of the frame.
			name:    "the connection closed inside a record",
			server:  dcServer{hangUp: true, raw: func(*dcSession) []byte { return tlsRecord(0x17, 0x0303, randomBytes(40))[:7] }},
			wantErr: io.ErrUnexpectedEOF,
		},
	}...)

	const timeout = 5 * time.Second
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			px := startFakeProxy(t, fakeServer{secret: secret}, tt.server)
			start := time.Now()
			err := L2(t.Context(), px.addr, testSNI, secret, 2, Options{Timeout: timeout})
			elapsed := time.Since(start)
			s := px.session(t)
			if s.err != nil {
				t.Fatalf("the datacenter half could not read the request: %v", s.err)
			}
			checkError(t, err, tt.wantErr, tt.wantMsg, secret, s.nonce)
			if errors.Is(err, context.DeadlineExceeded) || elapsed > timeout/2 {
				t.Errorf("L2 took %v and returned %v: it waited for more than the server sent", elapsed, err)
			}
		})
	}
}

func TestL2Handshake(t *testing.T) {
	secret := randomBytes(16)

	t.Run("a proxy with another secret", func(t *testing.T) {
		px := startFakeProxy(t, fakeServer{secret: randomBytes(16), answerAnyway: true}, dcServer{})
		err := L2(t.Context(), px.addr, testSNI, secret, 2, Options{Timeout: 5 * time.Second})
		if err != ErrBadServerDigest {
			t.Fatalf("L2: %v, want ErrBadServerDigest itself, as FakeTLS returns it", err)
		}
		if s := px.session(t); s.err == nil {
			t.Errorf("the request went out after a failed handshake: the datacenter half saw datacenter %d", s.dc)
		}
	})

	t.Run("a TLS alert instead of a ServerHello", func(t *testing.T) {
		px := startFakeProxy(t, fakeServer{secret: secret, answer: func(*conversation) []byte {
			return tlsRecord(0x15, 0x0303, []byte{2, 112})
		}}, dcServer{})
		err := L2(t.Context(), px.addr, testSNI, secret, 2, Options{Timeout: 5 * time.Second})
		if err == nil || !strings.Contains(err.Error(), "alert 112") || errors.Is(err, ErrBadResPQ) {
			t.Fatalf("L2: %v, want the error of the handshake", err)
		}
	})
}

// TestL2AlertError checks the two faces of a TLS alert in place of the answer:
// a verdict on the answer like any other record that is not data
// (ErrBadResPQ), and an *AlertError that tells which alert came.
func TestL2AlertError(t *testing.T) {
	secret := randomBytes(16)
	tests := []struct {
		name string
		raw  []byte
		want *AlertError // nil: no alert
	}{
		{name: "a fatal alert", raw: tlsRecord(0x15, 0x0303, []byte{2, 80}), want: &AlertError{Level: 2, Description: 80}},
		{name: "a warning", raw: tlsRecord(0x15, 0x0303, []byte{1, 0}), want: &AlertError{Level: 1, Description: 0}},
		{name: "a handshake record", raw: tlsRecord(0x16, 0x0303, randomBytes(40))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			px := startFakeProxy(t, fakeServer{secret: secret}, dcServer{raw: func(*dcSession) []byte { return tt.raw }})
			err := L2(t.Context(), px.addr, testSNI, secret, 2, Options{Timeout: 5 * time.Second})
			if !errors.Is(err, ErrBadResPQ) {
				t.Errorf("L2: %v, want ErrBadResPQ", err)
			}
			var alert *AlertError
			switch {
			case tt.want == nil && errors.As(err, &alert):
				t.Errorf("L2: %v is an *AlertError; a record of another type is not an alert", err)
			case tt.want != nil && !errors.As(err, &alert):
				t.Errorf("L2: %v, want an *AlertError", err)
			case tt.want != nil && *alert != *tt.want:
				t.Errorf("L2: the alert %+v, want %+v", *alert, *tt.want)
			}
			if err != nil && (!strings.HasPrefix(err.Error(), "probe: ") || strings.Count(err.Error(), "probe:") != 1) {
				t.Errorf("L2: %q, want the prefix %q, once", err, "probe: ")
			}
			if s := px.session(t); s.err != nil {
				t.Errorf("the datacenter half: %v", s.err)
			}
		})
	}
}

func TestL2Timeout(t *testing.T) {
	secret := randomBytes(16)
	tests := []struct {
		name    string
		timeout time.Duration
		ctx     func(t *testing.T) context.Context
		want    time.Duration
	}{
		{
			name: "Options.Timeout", timeout: 300 * time.Millisecond, want: 300 * time.Millisecond,
			ctx: func(t *testing.T) context.Context { return t.Context() },
		},
		{
			name: "the deadline of the context", timeout: 0, want: 300 * time.Millisecond,
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The handshake succeeds; the datacenter never answers.
			px := startFakeProxy(t, fakeServer{secret: secret}, dcServer{hold: true})
			start := time.Now()
			err := L2(tt.ctx(t), px.addr, testSNI, secret, 2, Options{Timeout: tt.timeout})
			elapsed := time.Since(start)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("L2: %v, want context.DeadlineExceeded", err)
			}
			if errors.Is(err, ErrBadResPQ) {
				t.Errorf("L2: %v, a timeout is no verdict on an answer", err)
			}
			if elapsed < tt.want || elapsed > tt.want+2*time.Second {
				t.Errorf("L2 returned after %v, want about %v", elapsed, tt.want)
			}
			if s := px.session(t); s.err != nil {
				t.Errorf("the datacenter half: %v", s.err)
			}
		})
	}

	t.Run("canceled", func(t *testing.T) {
		px := startFakeProxy(t, fakeServer{secret: secret}, dcServer{hold: true})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		time.AfterFunc(200*time.Millisecond, cancel)
		start := time.Now()
		err := L2(ctx, px.addr, testSNI, secret, 2, Options{Timeout: 10 * time.Second})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("L2: %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("L2 returned %v after the cancellation", elapsed)
		}
	})
}

func TestL2ConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	err = L2(t.Context(), addr, testSNI, randomBytes(16), 2, Options{Timeout: 5 * time.Second})
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("L2: %v, want the connection refused", err)
	}
	if !strings.HasPrefix(err.Error(), "probe: ") {
		t.Errorf("L2: %q, want the prefix %q", err, "probe: ")
	}
}

func TestL2Arguments(t *testing.T) {
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
		{name: "no server name", secret: randomBytes(16), sni: "", want: "server name"},
		{name: "invalid PROXY source", secret: randomBytes(16), sni: testSNI, opt: Options{ProxyHeader: &zero}, want: "PROXY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Port 1 refuses: an argument that slipped through would fail with
			// a connection error instead.
			err := L2(t.Context(), "127.0.0.1:1", tt.sni, tt.secret, 2, tt.opt)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("L2: %v, want an error about the %s", err, tt.want)
			}
			if len(tt.secret) > 0 && strings.Contains(err.Error(), hex.EncodeToString(tt.secret)) {
				t.Errorf("the error gives the secret away: %v", err)
			}
		})
	}
}

// ---- TLS records ----------------------------------------------------------------

func TestRecordWriter(t *testing.T) {
	var out bytes.Buffer
	w := &recordWriter{w: &out}
	data := randomBytes(40000)
	if n, err := w.Write(data); err != nil || n != len(data) {
		t.Fatalf("Write: %d, %v", n, err)
	}
	more := randomBytes(10)
	if n, err := w.Write(more); err != nil || n != len(more) {
		t.Fatalf("Write: %d, %v", n, err)
	}

	// A ChangeCipherSpec first, once; then records of at most 16384 bytes.
	want := bytes.Clone(changeCipherSpec)
	want = append(want, tlsRecord(0x17, 0x0303, data[:16384])...)
	want = append(want, tlsRecord(0x17, 0x0303, data[16384:32768])...)
	want = append(want, tlsRecord(0x17, 0x0303, data[32768:])...)
	want = append(want, tlsRecord(0x17, 0x0303, more)...)
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("the records are not a ChangeCipherSpec followed by application data records of at most 16384 bytes")
	}
}

func TestRecordReader(t *testing.T) {
	appData := func(payload string) []byte { return tlsRecord(0x17, 0x0303, []byte(payload)) }
	empty := func(n int) []byte { return bytes.Repeat(appData(""), n) }
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	tests := []struct {
		name      string
		stream    []byte
		want      string      // what reads out before the error
		wantErr   error       // matched with errors.Is; io.EOF is the clean end
		wantBad   string      // part of the text of a bad answer
		wantAlert *AlertError // the alert, for a TLS alert
	}{
		{name: "records", stream: join(appData("abc"), appData(""), appData("defgh")), want: "abcdefgh", wantErr: io.EOF},
		{name: "nothing", stream: nil, wantErr: io.EOF},
		{
			name:   "16 empty records in a row, twice",
			stream: join(empty(16), appData("a"), empty(16), appData("b")),
			want:   "ab", wantErr: io.EOF,
		},
		{
			// Refused on the 17th: the data after it is not waited for.
			name:   "17 empty records in a row",
			stream: join(appData("a"), empty(17), appData("b")),
			want:   "a", wantBad: "more than 16 empty",
		},
		{
			name:   "a TLS alert",
			stream: join(appData("ab"), tlsRecord(0x15, 0x0303, []byte{2, 80})),
			want:   "ab", wantBad: "alert 80 (internal_error)", wantAlert: &AlertError{Level: 2, Description: 80},
		},
		{
			name:    "a warning of TLS 1.0",
			stream:  tlsRecord(0x15, 0x0301, []byte{1, 112}),
			wantBad: "alert 112 (unrecognized_name)", wantAlert: &AlertError{Level: 1, Description: 112},
		},
		{name: "an alert record of another size", stream: tlsRecord(0x15, 0x0303, []byte{2, 80, 0}), wantBad: "alert"},
		{name: "a handshake record", stream: tlsRecord(0x16, 0x0303, []byte("x")), wantBad: "0x16"},
		{name: "another version", stream: tlsRecord(0x17, 0x0302, []byte("x")), wantBad: "version"},
		{name: "half a header", stream: appData("abc")[:3], wantErr: io.ErrUnexpectedEOF},
		{name: "half a record", stream: join(appData("ab"), appData("cdef")[:7]), want: "abcd", wantErr: io.ErrUnexpectedEOF},
		{name: "half an alert", stream: tlsRecord(0x15, 0x0303, []byte{2, 80})[:6], wantErr: io.ErrUnexpectedEOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// One byte at a time: the reader must not count on whole records.
			r := &recordReader{r: iotest.OneByteReader(bytes.NewReader(tt.stream))}
			var got []byte
			buf := make([]byte, 3)
			var err error
			for err == nil {
				var n int
				n, err = r.Read(buf)
				got = append(got, buf[:n]...)
			}
			if string(got) != tt.want {
				t.Errorf("read %q, want %q", got, tt.want)
			}
			// The verdict on the answer: a TLS alert is an *AlertError, any
			// other bad record a badAnswer; pingError makes both ErrBadResPQ.
			var (
				bad   badAnswer
				alert *AlertError
			)
			switch {
			case tt.wantAlert != nil:
				if !errors.As(err, &alert) || *alert != *tt.wantAlert {
					t.Errorf("Read: %v, want the alert %+v", err, *tt.wantAlert)
				}
			case tt.wantBad != "":
				if !errors.As(err, &bad) || errors.As(err, &alert) {
					t.Errorf("Read: %v, want a bad answer, not an alert", err)
				}
			case !errors.Is(err, tt.wantErr) || errors.As(err, &bad) || errors.As(err, &alert):
				t.Errorf("Read: %v, want %v", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tt.wantBad) {
				t.Errorf("Read: %q, want it to mention %q", err, tt.wantBad)
			}
		})
	}
}

// ---- the request ----------------------------------------------------------------

// TestPingWritesOnce checks that the request goes out in a single write: on
// a fake-TLS connection that is a single record.
func TestPingWritesOnce(t *testing.T) {
	var w countingWriter
	_ = ping(&w, bytes.NewReader(nil), tagPaddedIntermediate, 2, randomBytes(16), time.Now())
	if w.writes != 1 {
		t.Errorf("%d writes, want the header and the frame in one", w.writes)
	}
	if n := len(w.data); n < 64+4+40 || n > 64+4+40+15 {
		t.Fatalf("%d bytes written, want the header, the frame of req_pq_multi and 0 to 15 bytes of padding", n)
	}
	if got := binary.LittleEndian.Uint32(w.data); got == tagPaddedIntermediate || got == tagIntermediate {
		t.Errorf("the header starts with the tag %#x", got)
	}
}

type countingWriter struct {
	writes int
	data   []byte
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	w.data = append(w.data, p...)
	return len(p), nil
}
