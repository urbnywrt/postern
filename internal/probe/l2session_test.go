package probe

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestL2Session(t *testing.T) {
	secret := randomBytes(16)
	px := startFakeProxy(t, fakeServer{secret: secret}, dcServer{repeat: true})
	s, err := OpenL2(t.Context(), px.addr, testSNI, secret, 2, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("OpenL2: %v", err)
	}
	defer func() { _ = s.Close() }()
	if c := px.next(t); c.err != nil || !c.digestOK {
		t.Fatalf("the proxy saw err %v, digest ok %v", c.err, c.digestOK)
	}
	sess := px.session(t)
	if sess.tag != tagPaddedIntermediate || sess.dc != 2 {
		t.Errorf("the session opened with tag %#x for datacenter %d, want %#x for 2", sess.tag, sess.dc, tagPaddedIntermediate)
	}
	// The answers carry the nonces of the requests: each Ping checks its own.
	for i := range 3 {
		if err := s.Ping(t.Context()); err != nil {
			t.Fatalf("Ping %d on the session: %v", i+1, err)
		}
	}
}

func TestL2SessionNoAnswer(t *testing.T) {
	secret := randomBytes(16)
	// The server answers the first request only.
	px := startFakeProxy(t, fakeServer{secret: secret}, dcServer{})
	s, err := OpenL2(t.Context(), px.addr, testSNI, secret, 2, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("OpenL2: %v", err)
	}
	defer func() { _ = s.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if err := s.Ping(ctx); err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ping without an answer: %v, want a deadline", err)
	}
}

func TestL2SessionWrongSecret(t *testing.T) {
	// The fake server hangs up on a client without its secret.
	px := startFakeProxy(t, fakeServer{secret: randomBytes(16)}, dcServer{repeat: true})
	if s, err := OpenL2(t.Context(), px.addr, testSNI, randomBytes(16), 2, Options{Timeout: 5 * time.Second}); err == nil {
		_ = s.Close()
		t.Fatal("OpenL2 with another secret than the proxy's opened a session")
	}
}
