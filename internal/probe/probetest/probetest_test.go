package probetest_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/probe"
	"github.com/urbnywrt/postern/internal/probe/probetest"
)

// The datacenter answers probe.DCPing as a datacenter does, and fails it in the
// ways that a check of a way to the datacenters must tell apart.
func TestModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode probetest.Mode
		want func(error) bool
	}{
		{"answers", probetest.Answers, func(err error) bool { return err == nil }},
		{"hangs up", probetest.HangsUp, func(err error) bool { return errors.Is(err, io.EOF) }},
		{"another nonce", probetest.WrongNonce, func(err error) bool { return errors.Is(err, probe.ErrBadResPQ) }},
		{"silent", probetest.Silent, func(err error) bool { return errors.Is(err, context.DeadlineExceeded) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := probetest.Pipe(tc.mode)
			defer func() { _ = conn.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if err := probe.DCPing(ctx, conn); !tc.want(err) {
				t.Errorf("DCPing: %v", err)
			}
		})
	}
}

// A client that does not speak the request of DCPing is hung up on.
func TestServeHangsUpOnAnythingElse(t *testing.T) {
	near, far := net.Pipe()
	done := make(chan struct{})
	go func() {
		probetest.Serve(far, probetest.Answers, func() { t.Error("an answer to something else") })
		close(done)
	}()
	_ = near.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := near.Write(make([]byte, 64)); err != nil { // the tag of no transport
		t.Fatal(err)
	}
	if n, err := near.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Errorf("read %d bytes, %v; want the end of the stream", n, err)
	}
	<-done
}

// A Server answers on its port, calls answering before every answer, counts its
// connections, and can be closed and opened again at the same address.
func TestServer(t *testing.T) {
	answered := 0
	s, err := probetest.NewServer(probetest.Answers, func() { answered++ })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ping := func() error {
		conn, err := net.DialTimeout("tcp", s.Addr(), 5*time.Second)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return probe.DCPing(ctx, conn)
	}
	if err := ping(); err != nil {
		t.Fatalf("DCPing: %v", err)
	}
	if s.Accepted() != 1 || answered != 1 {
		t.Errorf("accepted %d, answered %d; want 1 and 1", s.Accepted(), answered)
	}

	addr := s.Addr()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ping(); err == nil {
		t.Error("DCPing succeeded with the server closed")
	}
	if err := s.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
	if err := s.Reopen(); err != nil {
		t.Fatal(err)
	}
	if s.Addr() != addr {
		t.Errorf("reopened at %s, want %s", s.Addr(), addr)
	}
	if err := ping(); err != nil {
		t.Errorf("DCPing after Reopen: %v", err)
	}
}
