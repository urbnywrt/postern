package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// deadlineSpy is a ResponseWriter that notes the write deadlines that are set on
// it, as the connection of the HTTP server takes them.
type deadlineSpy struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (s *deadlineSpy) SetWriteDeadline(t time.Time) error {
	s.deadlines = append(s.deadlines, t)
	return nil
}

func serveSpied(h http.Handler, method, path string, header map[string]string) *deadlineSpy {
	req := httptest.NewRequest(method, "http://panel.example"+path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	spy := &deadlineSpy{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(spy, req)
	return spy
}

// checkAMinuteAhead fails the test unless deadline is the write deadline that a
// static response sets: a minute after the request, which came between before
// and after.
func checkAMinuteAhead(t *testing.T, what string, deadline, before, after time.Time) {
	t.Helper()
	if deadline.Before(before.Add(time.Minute)) || deadline.After(after.Add(time.Minute)) {
		t.Errorf("%s: the write deadline is %v, want a minute after the request, between %v and %v",
			what, deadline, before.Add(time.Minute), after.Add(time.Minute))
	}
}

// Every response that carries a file of the UI is bounded, whatever it says: a
// file, the page for a path that is not one, HEAD, a 304 and a range.
func TestSPABoundsEveryStaticResponseWithAWriteDeadline(t *testing.T) {
	h := spaFor(t, testUI())
	etag := serveSPA(h, http.MethodGet, "/assets/app-abc123.js", nil).Header().Get("ETag")
	for _, c := range []struct {
		name, method, path string
		header             map[string]string
		status             int
	}{
		{"a file", http.MethodGet, "/assets/app-abc123.js", nil, http.StatusOK},
		{"the page for a path that is not a file", http.MethodGet, "/nodes/01ABC", nil, http.StatusOK},
		{"HEAD", http.MethodHead, "/", nil, http.StatusOK},
		{"a file that has not changed", http.MethodGet, "/assets/app-abc123.js", map[string]string{"If-None-Match": etag}, http.StatusNotModified},
		{"a range", http.MethodGet, "/assets/app-abc123.js", map[string]string{"Range": "bytes=0-6"}, http.StatusPartialContent},
	} {
		before := time.Now()
		spy := serveSpied(h, c.method, c.path, c.header)
		after := time.Now()
		if spy.Code != c.status {
			t.Errorf("%s: status %d, want %d", c.name, spy.Code, c.status)
		}
		if len(spy.deadlines) != 1 {
			t.Errorf("%s: %d write deadlines were set, want 1: %v", c.name, len(spy.deadlines), spy.deadlines)
			continue
		}
		checkAMinuteAhead(t, c.name, spy.deadlines[0], before, after)
	}

	// A refusal has no file to write.
	if spy := serveSpied(h, http.MethodPost, "/", nil); spy.Code != http.StatusMethodNotAllowed || len(spy.deadlines) != 0 {
		t.Errorf("POST /: status %d with %d write deadlines, want 405 and none", spy.Code, len(spy.deadlines))
	}
}

// A write deadline is the response's own: the HTTP server has no write timeout,
// and a call of the API sets none, since a response of it may be a stream. The
// responses that are bounded set one themselves: a file of the UI, here, and the
// download of the node kit (TestNodeKitHasAWriteDeadlineThroughTheServer).
func TestOnlyBoundedResponsesHaveAWriteDeadline(t *testing.T) {
	p := newPanel(t, func(c *Config) { c.UI = testUI() })
	if got := p.srv.http.WriteTimeout; got != 0 {
		t.Errorf("the HTTP server has a write timeout of %v: a response of the API may be a stream", got)
	}
	h := p.srv.Handler()

	before := time.Now()
	spy := serveSpied(h, http.MethodGet, "/assets/app-abc123.js", nil)
	after := time.Now()
	if spy.Code != http.StatusOK || len(spy.deadlines) != 1 {
		t.Fatalf("a file of the UI: status %d with %d write deadlines, want 200 and 1", spy.Code, len(spy.deadlines))
	}
	checkAMinuteAhead(t, "a file of the UI", spy.deadlines[0], before, after)

	for _, c := range []struct {
		name, method, path string
		status             int
	}{
		{"a call of the API", http.MethodPost, healthCheck, http.StatusOK},
		{"an unknown API path", http.MethodGet, "/api/nope", http.StatusNotFound},
		{"a download without a session", http.MethodGet, "/api/nodes/nope/bundle.tar", http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(c.method, "http://panel.example"+c.path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		spy := &deadlineSpy{ResponseRecorder: httptest.NewRecorder()}
		h.ServeHTTP(spy, req)
		if spy.Code != c.status {
			t.Errorf("%s: status %d, want %d", c.name, spy.Code, c.status)
		}
		if len(spy.deadlines) != 0 {
			t.Errorf("%s: %d write deadlines were set on it, want none: %v", c.name, len(spy.deadlines), spy.deadlines)
		}
	}
}

// stalledConn is the server side of a connection to a client that reads
// nothing. A write to it waits until the write deadline that was set on it has
// passed, as a write does when the buffers are full; with no deadline it waits
// until release is closed.
type stalledConn struct {
	net.Conn
	release <-chan struct{}

	mu       sync.Mutex
	deadline time.Time
}

func (c *stalledConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}

func (c *stalledConn) Write([]byte) (int, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	var expired <-chan time.Time // nil, which is never ready, without a deadline
	if !deadline.IsZero() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case <-expired:
		return 0, os.ErrDeadlineExceeded
	case <-c.release:
		return 0, net.ErrClosed
	}
}

type stalledListener struct {
	net.Listener
	release <-chan struct{}
}

func (l stalledListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &stalledConn{Conn: c, release: l.release}, nil
}

// A client that does not read is let go when the deadline of its response has
// passed: the connection is closed, and nothing waits for the client for ever.
func TestSPAGivesUpOnAClientThatDoesNotRead(t *testing.T) {
	h, err := newSPA(testUI())
	if err != nil {
		t.Fatal(err)
	}
	const timeout = 200 * time.Millisecond
	h.writeTimeout = timeout

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	srv := &http.Server{Handler: h}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(stalledListener{Listener: ln, release: release})
	}()
	t.Cleanup(func() {
		close(release) // lets a write that has no deadline go, if the test failed
		_ = srv.Close()
		<-served
	})

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	start := time.Now()
	if _, err := io.WriteString(conn, "GET /assets/app-abc123.js HTTP/1.1\r\nHost: panel.example\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	// The client reads until the server closes the connection.
	if err := conn.SetReadDeadline(start.Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, conn)
	elapsed := time.Since(start)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the server still held the connection to a client that does not read after %v, with a write deadline of %v", elapsed, timeout)
	}
	if elapsed < timeout*3/4 {
		t.Errorf("the connection was closed after %v, before the write deadline of %v", elapsed, timeout)
	}
}

// The deadline of a file does not stay on the connection for the next request,
// which is a call of the API on a connection that the browser keeps: it is set
// for one response, and net/http takes it off. (The call is a POST because a
// client sends a GET again on a new connection when the first fails, and the
// failure would not show.)
func TestSPADeadlineDoesNotOutliveItsResponse(t *testing.T) {
	h, err := newSPA(testUI())
	if err != nil {
		t.Fatal(err)
	}
	h.writeTimeout = 100 * time.Millisecond
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ping", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "pong") })
	mux.Handle("/", h)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr}

	do := func(method, path string) (body string, reused bool) {
		t.Helper()
		trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), method, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s %s: reading the body: %v", method, path, err)
		}
		return string(b), reused
	}

	if body, _ := do(http.MethodGet, "/assets/app-abc123.js"); body != `console.log("app")` {
		t.Fatalf("the file: %q", body)
	}
	time.Sleep(3 * h.writeTimeout) // the deadline of the file has passed
	body, reused := do(http.MethodPost, "/api/ping")
	if !reused {
		t.Fatal("the call of the API did not use the connection of the file, so this test shows nothing")
	}
	if body != "pong" {
		t.Errorf("the call of the API on the connection that was kept: %q, want pong", body)
	}
}
