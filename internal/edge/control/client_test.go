package control

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
	"github.com/urbnywrt/postern/internal/edge"
	"github.com/urbnywrt/postern/internal/edge/egress"
)

// ---------------------------------------------------------------------------
// ListenUnix
// ---------------------------------------------------------------------------

func TestListenUnixSocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "s.sock")
	ln, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Type() != fs.ModeSocket {
		t.Errorf("%s is %v, want a socket", path, fi.Mode())
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("mode of the socket = %o, want 600: only root talks to the edge", got)
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("connecting to the socket: %v", err)
	}
	_ = c.Close()

	// Closing the listener takes the socket away: nothing is left for the next
	// start to find.
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the socket is still there after Close: %v", err)
	}
}

// A process that was killed leaves its socket behind; the next one of the same
// generation must be able to take its place.
func TestListenUnixReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "s.sock")
	old, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false) // as if the process had been killed
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("the stale socket was not left behind: %v", err)
	}

	ln, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix over a stale socket: %v", err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
			close(accepted)
		}
	}()
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("connecting to the new socket: %v", err)
	}
	_ = c.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Error("the new listener did not get the connection")
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket after the replacement: %v, %v; want mode 600", fi, err)
	}
}

// A socket that something listens on is not stale, and is not taken away.
func TestListenUnixRefusesLiveSocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "s.sock")
	first, err := ListenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	second, err := ListenUnix(path)
	if err == nil {
		_ = second.Close()
		t.Fatal("ListenUnix took over a socket that is in use")
	}
	if !strings.Contains(err.Error(), "in use") {
		t.Errorf("error = %v, want it to say that the socket is in use", err)
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("the first listener lost its socket: %v", err)
	}
	_ = c.Close()
}

// The path comes from the command line: whatever is there that is not a socket
// is somebody's file, and stays.
func TestListenUnixLeavesOtherFilesAlone(t *testing.T) {
	dir := shortDir(t)

	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := ListenUnix(file); err == nil {
		_ = ln.Close()
		t.Error("ListenUnix replaced a regular file")
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "precious" {
		t.Errorf("the file is %q, %v after the attempt, want it untouched", b, err)
	}

	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if ln, err := ListenUnix(sub); err == nil {
		_ = ln.Close()
		t.Error("ListenUnix replaced a directory")
	}
	if fi, err := os.Stat(sub); err != nil || !fi.IsDir() {
		t.Errorf("the directory is %v, %v after the attempt, want it untouched", fi, err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if ln, err := ListenUnix(link); err == nil {
		_ = ln.Close()
		t.Error("ListenUnix replaced a symbolic link")
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "precious" {
		t.Errorf("the file behind the link is %q, %v, want it untouched", b, err)
	}
}

func TestListenUnixErrors(t *testing.T) {
	dir := shortDir(t)
	t.Run("no directory", func(t *testing.T) {
		if ln, err := ListenUnix(filepath.Join(dir, "missing", "s.sock")); err == nil {
			_ = ln.Close()
			t.Error("ListenUnix in a directory that does not exist succeeded")
		}
	})
	// A socket address has 108 bytes, the last for the NUL: 107 are the longest path.
	pathOf := func(n int) string {
		prefix := filepath.Join(dir, "p")
		return prefix + strings.Repeat("x", n-len(prefix))
	}
	t.Run("the longest path", func(t *testing.T) {
		ln, err := ListenUnix(pathOf(107))
		if err != nil {
			t.Fatalf("ListenUnix with a path of 107 bytes: %v", err)
		}
		_ = ln.Close()
	})
	t.Run("path too long", func(t *testing.T) {
		for _, n := range []int{108, 140} {
			ln, err := ListenUnix(pathOf(n))
			if err == nil {
				_ = ln.Close()
				t.Fatalf("ListenUnix accepted a path of %d bytes, longer than a socket address can be", n)
			}
			if !strings.Contains(err.Error(), "too long") {
				t.Errorf("error for %d bytes = %v, want it to say that the path is too long", n, err)
			}
		}
	})
	t.Run("empty path", func(t *testing.T) {
		ln, err := ListenUnix("")
		if err == nil {
			_ = ln.Close()
			t.Fatal("ListenUnix accepted an empty path")
		}
		if !strings.Contains(err.Error(), "no socket path") {
			t.Errorf("error = %v, want it to say that there is no socket path", err)
		}
	})
}

// ---------------------------------------------------------------------------
// NewClient
// ---------------------------------------------------------------------------

// serve runs handler on a new unix socket until the end of the test.
func serve(t *testing.T, handler http.Handler) string {
	t.Helper()
	sock := filepath.Join(shortDir(t), "s.sock")
	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = hs.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
		<-done
	})
	return sock
}

func bareServer(t *testing.T) *Server {
	t.Helper()
	r := egress.NewRouter(quiet)
	return NewServer(edge.New(quiet, edge.Options{}), r, egress.NewSocksPorts(quiet, r), filepath.Join(shortDir(t), "c.json"), quiet)
}

func TestClientSpeaksConnectOverHTTP1(t *testing.T) {
	checkGoroutines(t)
	type seen struct{ method, proto, path, ctype, version string }
	var (
		mu    sync.Mutex
		calls []seen
	)
	inner := bareServer(t).Handler()
	sock := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, seen{r.Method, r.Proto, r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Connect-Protocol-Version")})
		mu.Unlock()
		inner.ServeHTTP(w, r)
	}))

	client := NewClient(sock)
	ctx, cancel := callCtx()
	defer cancel()
	if _, err := client.Health(ctx, connect.NewRequest(&edgev1.HealthRequest{})); err != nil {
		t.Fatalf("Health: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("the server saw %d calls, want 1", len(calls))
	}
	want := seen{"POST", "HTTP/1.1", "/postern.edge.v1.EdgeControlService/Health", "application/proto", "1"}
	if calls[0] != want {
		t.Errorf("the call was %+v, want %+v", calls[0], want)
	}
}

// The agent keeps a client for as long as an edge generation lives, and an edge
// restarts without its socket staying: the client must work with the new one,
// not trip over a connection that belonged to the old process.
func TestClientSurvivesServerRestart(t *testing.T) {
	checkGoroutines(t)
	dir := shortDir(t)
	sock := filepath.Join(dir, "s.sock")
	start := func() (stop func()) {
		ln, err := ListenUnix(sock)
		if err != nil {
			t.Fatal(err)
		}
		hs := &http.Server{Handler: bareServer(t).Handler()}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = hs.Serve(ln)
		}()
		return func() {
			_ = hs.Close() // not Shutdown: a process that dies does not close anything politely
			<-done
		}
	}

	client := NewClient(sock)
	for round := range 3 {
		stop := start()
		for call := range 2 {
			ctx, cancel := callCtx()
			_, err := client.Health(ctx, connect.NewRequest(&edgev1.HealthRequest{}))
			cancel()
			if err != nil {
				stop()
				t.Fatalf("round %d, call %d: %v", round, call, err)
			}
		}
		stop()
	}
}

func TestClientDeadSocket(t *testing.T) {
	checkGoroutines(t)
	client := NewClient(filepath.Join(shortDir(t), "none.sock"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := client.Health(ctx, connect.NewRequest(&edgev1.HealthRequest{}))
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != connect.CodeUnavailable {
		t.Errorf("error = %v, want CodeUnavailable", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the call took %v to fail", d)
	}
}

// The calls of the agent have their own deadlines; the client must obey them
// and not add its own.
func TestClientObeysTheDeadlineOfTheCall(t *testing.T) {
	checkGoroutines(t)
	release := make(chan struct{})
	sock := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release) }) // runs before the shutdown of the server
	client := NewClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := client.Health(ctx, connect.NewRequest(&edgev1.HealthRequest{}))
	if err == nil {
		t.Fatal("a call to a server that never answers succeeded")
	}
	if d := time.Since(start); d < 250*time.Millisecond || d > 3*time.Second {
		t.Errorf("the call ended after %v, want about 300 ms", d)
	}
}

// countingListener counts the connections that are accepted.
type countingListener struct {
	net.Listener
	accepted atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

// Every call is a connection of its own: the calls are few, and no connection
// is left idle for an edge that exits to leave dead.
func TestClientOpensAConnectionPerCall(t *testing.T) {
	checkGoroutines(t)
	sock := filepath.Join(shortDir(t), "s.sock")
	ln, err := ListenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingListener{Listener: ln}
	hs := &http.Server{Handler: bareServer(t).Handler()}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = hs.Serve(counting)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
		<-done
	})

	client := NewClient(sock)
	for range 3 {
		ctx, cancel := callCtx()
		_, err := client.Health(ctx, connect.NewRequest(&edgev1.HealthRequest{}))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := counting.accepted.Load(); n != 3 {
		t.Errorf("the server accepted %d connections for 3 calls, want 3", n)
	}
}
