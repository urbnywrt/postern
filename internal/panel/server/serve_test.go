package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	panelv1 "github.com/urbnywrt/postern/gen/go/postern/panel/v1"
	"github.com/urbnywrt/postern/gen/go/postern/panel/v1/panelv1connect"
	"github.com/urbnywrt/postern/internal/panel/store"
)

// A run is a server that is being served on a free loopback port.
type run struct {
	t      *testing.T
	addr   string
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
	err    error
}

func serve(t *testing.T, srv *Server) *run {
	t.Helper()
	ln := listener(t)
	ctx, cancel := context.WithCancel(context.Background())
	r := &run{t: t, addr: ln.Addr().String(), cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() { _ = r.stop() })
	return r
}

// stop asks Serve to stop, as a signal does, and returns what it returned.
func (r *run) stop() error {
	r.once.Do(func() {
		r.cancel()
		select {
		case r.err = <-r.done:
		case <-time.After(waitFor):
			r.t.Error("Serve did not return after it was asked to stop")
		}
	})
	return r.err
}

func (r *run) url(path string) string { return "http://" + r.addr + path }

// ready waits until the server answers.
func (r *run) ready() {
	r.t.Helper()
	eventually(r.t, "the server to answer", func() bool {
		resp, err := http.Post(r.url(healthCheck), "application/json", strings.NewReader("{}"))
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

func TestServeAnswersAndStopsWhenAskedTo(t *testing.T) {
	p := newPanel(t)
	r := serve(t, p.srv)
	r.ready()

	resp, err := http.Get(r.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /: status %d", resp.StatusCode)
	}

	if err := r.stop(); err != nil {
		t.Errorf("Serve returned %v after a clean stop, want nil", err)
	}
	// Nobody is accepting any more.
	if conn, err := net.DialTimeout("tcp", r.addr, time.Second); err == nil {
		_ = conn.Close()
		t.Error("the port still accepts connections after Serve returned")
	}
	// And the store is closed.
	if _, err := p.srv.db.CountAdmins(context.Background()); err == nil {
		t.Error("the database is still open after Serve returned")
	}
}

var setupURLPattern = regexp.MustCompile(`http://\S+/setup\?token=[A-Za-z0-9_-]+`)

// A panel with no admin prints the URL of its setup, once, and never logs it.
func TestSetupURLIsPrintedOnce(t *testing.T) {
	p := newPanel(t)
	token, ok := p.srv.auth.SetupToken()
	if !ok {
		t.Fatal("no setup token")
	}
	r := serve(t, p.srv)
	r.ready()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}

	out := p.out.String()
	if n := strings.Count(out, "/setup?token="); n != 1 {
		t.Fatalf("the setup URL is in the output %d times, want once:\n%s", n, out)
	}
	want := "http://" + r.addr + "/setup?token=" + token
	if got := setupURLPattern.FindString(out); got != want {
		t.Errorf("setup URL %q, want %q", got, want)
	}
	if logs := p.logs.String(); strings.Contains(logs, token) {
		t.Error("the setup token is in the log")
	}
}

// The URL that was printed works: the page is there, and its token sets the
// panel up.
func TestThePrintedSetupURLWorks(t *testing.T) {
	p := newPanel(t)
	r := serve(t, p.srv)
	r.ready()

	printed := setupURLPattern.FindString(p.out.String())
	if printed == "" {
		t.Fatalf("no setup URL in the output: %q", p.out.String())
	}
	u, err := url.Parse(printed)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(printed)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s: status %d", u.Path, resp.StatusCode)
	}

	client := panelv1connect.NewAuthServiceClient(http.DefaultClient, "http://"+u.Host+"/api")
	status, err := client.GetSetupStatus(context.Background(), connect.NewRequest(&panelv1.GetSetupStatusRequest{}))
	if err != nil || !status.Msg.GetNeedsSetup() {
		t.Fatalf("GetSetupStatus = %v, %v; want that setup is needed", status, err)
	}
	if _, err := client.Setup(context.Background(), connect.NewRequest(&panelv1.SetupRequest{
		SetupToken: u.Query().Get("token"), Username: adminName, Password: adminPassword,
	})); err != nil {
		t.Fatalf("Setup with the printed token: %v", err)
	}
}

// Once there is an admin, a start has nothing to print.
func TestNoSetupURLWhenThereIsAnAdmin(t *testing.T) {
	p := newPanel(t)
	p.signIn()
	if err := p.srv.Close(); err != nil {
		t.Fatal(err)
	}
	p.ts.Close()

	p.start()
	r := serve(t, p.srv)
	r.ready()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if out := p.out.String(); strings.Contains(out, "setup") || strings.Contains(out, "token") {
		t.Errorf("a panel that is set up printed %q", out)
	}
}

func TestSetupURL(t *testing.T) {
	for _, c := range []struct{ listen, want string }{
		{"127.0.0.1:8080", "http://127.0.0.1:8080/setup?token=T0k-en_1"},
		{"192.0.2.10:8080", "http://192.0.2.10:8080/setup?token=T0k-en_1"},
		{"[2001:db8::1]:8080", "http://[2001:db8::1]:8080/setup?token=T0k-en_1"},
		{"[::1]:9090", "http://[::1]:9090/setup?token=T0k-en_1"},
		// Where the server listens on every interface, the address that was
		// asked for cannot be opened: it is this machine.
		{":8080", "http://localhost:8080/setup?token=T0k-en_1"},
		{"0.0.0.0:8080", "http://localhost:8080/setup?token=T0k-en_1"},
		{"[::]:8080", "http://localhost:8080/setup?token=T0k-en_1"},
		{"[::]:80", "http://localhost:80/setup?token=T0k-en_1"},
	} {
		if got := setupURL(c.listen, "T0k-en_1"); got != c.want {
			t.Errorf("setupURL(%q) = %q, want %q", c.listen, got, c.want)
		}
	}
	// The token is escaped, whatever it is made of.
	if got := setupURL("127.0.0.1:1", "a b&c"); got != "http://127.0.0.1:1/setup?token=a+b%26c" {
		t.Errorf("setupURL with an odd token = %q", got)
	}
}

// Stopping lets the requests that are being answered finish, and refuses new
// ones meanwhile.
func TestShutdownIsGraceful(t *testing.T) {
	p := newPanel(t)
	inner := p.srv.http.Handler
	entered := make(chan struct{})
	release := make(chan struct{})
	p.srv.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(entered)
			<-release
			_, _ = io.WriteString(w, "finished")
			return
		}
		inner.ServeHTTP(w, r)
	})
	r := serve(t, p.srv)
	r.ready()

	type result struct {
		status int
		body   string
		err    error
	}
	answer := make(chan result, 1)
	go func() {
		resp, err := http.Get(r.url("/slow"))
		if err != nil {
			answer <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		answer <- result{status: resp.StatusCode, body: string(body), err: err}
	}()
	<-entered

	r.cancel() // the signal
	eventually(t, "the listener to close", func() bool {
		conn, err := net.DialTimeout("tcp", r.addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
		}
		return err != nil
	})
	select {
	case err := <-r.done:
		t.Fatalf("Serve returned (%v) while a request was still being answered", err)
	case <-time.After(100 * time.Millisecond):
	}
	// The store is not closed under a request.
	if _, err := p.srv.db.CountAdmins(context.Background()); err != nil {
		t.Errorf("the database was closed while a request was running: %v", err)
	}

	close(release)
	select {
	case res := <-answer:
		if res.err != nil || res.status != http.StatusOK || res.body != "finished" {
			t.Errorf("the request that was running got %d %q, %v; want 200 finished", res.status, res.body, res.err)
		}
	case <-time.After(waitFor):
		t.Fatal("the request that was running did not finish")
	}
	if err := r.stop(); err != nil {
		t.Errorf("Serve returned %v, want nil", err)
	}
}

// A connection that has not sent a request, which is what a browser opens ahead
// of time, does not keep the panel from stopping: Shutdown alone waits five
// seconds for it.
func TestShutdownDoesNotWaitForConnectionsThatSentNothing(t *testing.T) {
	p := newPanel(t)
	r := serve(t, p.srv)
	r.ready()
	var idle []net.Conn
	for range 3 {
		conn, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		idle = append(idle, conn)
	}
	// Let the server accept them.
	eventually(t, "the server to have accepted the connections", func() bool {
		p.srv.fresh.mu.Lock()
		defer p.srv.fresh.mu.Unlock()
		return len(p.srv.fresh.conns) >= len(idle)
	})

	start := time.Now()
	if err := r.stop(); err != nil {
		t.Errorf("Serve returned %v, want nil", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("stopping took %v with connections that had sent nothing, want well below the 5 seconds that net/http waits", d)
	}
}

// A request that does not finish does not keep the panel from stopping.
func TestShutdownGivesUpOnRequestsThatDoNotFinish(t *testing.T) {
	p := newPanel(t)
	p.srv.shutdownTimeout = 100 * time.Millisecond
	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	p.srv.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stuck" {
			close(entered)
			<-release
			return
		}
		_, _ = io.WriteString(w, "{}")
	})
	r := serve(t, p.srv)
	r.ready()
	go func() {
		resp, err := http.Get(r.url("/stuck"))
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-entered

	start := time.Now()
	if err := r.stop(); err != nil {
		t.Errorf("Serve returned %v, want nil", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("stopping took %v", d)
	}
}

// goroutineIn reports whether a goroutine is running code whose name contains s.
func goroutineIn(s string) bool {
	buf := make([]byte, 1<<20)
	return bytes.Contains(buf[:runtime.Stack(buf, true)], []byte(s))
}

// The node manager is started with the server, and stopped before the store is
// closed.
func TestServeRunsTheNodeManagerAndStopsIt(t *testing.T) {
	p := newPanel(t)
	// A node that was created earlier, without a certificate: the manager has a
	// goroutine for it, which cannot connect and waits.
	if err := p.srv.db.CreateNode(context.Background(), &store.Node{Name: "n1", MgmtHost: "192.0.2.10", MgmtPort: 61443}); err != nil {
		t.Fatal(err)
	}
	r := serve(t, p.srv)
	r.ready()
	eventually(t, "the manager to start a goroutine for the node", func() bool {
		return goroutineIn("internal/panel/nodes.(*runner).run")
	})
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if goroutineIn("internal/panel/nodes.(*runner).run") {
		eventually(t, "the goroutines of the manager to end", func() bool { return !goroutineIn("internal/panel/nodes.(*runner).run") })
		t.Error("a goroutine of the node manager was still running when Serve returned")
	}
}

// A server that cannot listen gives its resources back.
func TestListenAndServeReportsAPortThatIsTaken(t *testing.T) {
	taken := listener(t)
	defer func() { _ = taken.Close() }()
	p := newPanel(t, func(c *Config) { c.Listen = taken.Addr().String() })

	err := p.srv.ListenAndServe(context.Background())
	if err == nil {
		t.Fatal("ListenAndServe succeeded on a port that is taken")
	}
	if !strings.Contains(err.Error(), taken.Addr().String()) {
		t.Errorf("the error does not name the address: %v", err)
	}
	if _, err := p.srv.db.CountAdmins(context.Background()); err == nil {
		t.Error("the database was left open")
	}
}

func TestListenAndServeUsesTheConfiguredAddress(t *testing.T) {
	free := listener(t)
	addr := free.Addr().String()
	_ = free.Close()
	p := newPanel(t, func(c *Config) { c.Listen = addr })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.srv.ListenAndServe(ctx) }()
	r := &run{t: t, addr: addr}
	r.ready()
	if !strings.Contains(p.out.String(), "http://"+addr+"/setup?token=") {
		t.Errorf("the setup URL does not use the address of the listener: %q", p.out.String())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ListenAndServe returned %v, want nil", err)
		}
	case <-time.After(waitFor):
		t.Fatal("ListenAndServe did not return")
	}
}

// A listener that fails stops the server, and the error is the answer.
func TestServeReturnsTheErrorOfAListenerThatFails(t *testing.T) {
	p := newPanel(t)
	ln := listener(t)
	_ = ln.Close()
	done := make(chan error, 1)
	go func() { done <- p.srv.Serve(context.Background(), ln) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Serve returned nil for a listener that is closed")
		}
	case <-time.After(waitFor):
		t.Fatal("Serve did not return")
	}
	if _, err := p.srv.db.CountAdmins(context.Background()); err == nil {
		t.Error("the database was left open")
	}
}

func TestServeAfterCloseIsAnError(t *testing.T) {
	p := newPanel(t)
	if err := p.srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.srv.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
	ln := listener(t)
	defer func() { _ = ln.Close() }()
	if err := p.srv.Serve(context.Background(), ln); err == nil {
		t.Error("Serve of a closed server returned nil")
	}
}

// The marker that tells the launcher that the start was good is written when the
// panel is serving, and only when it was asked to.
func TestHealthyMarker(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "healthy")
	p := newPanel(t, func(c *Config) { c.HealthyFile = marker })
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the marker was written before the panel was serving")
	}
	r := serve(t, p.srv)
	r.ready()
	eventually(t, "the marker", func() bool { _, err := os.Stat(marker); return err == nil })
	if data, err := os.ReadFile(marker); err != nil || strings.TrimSpace(string(data)) == "" {
		t.Errorf("the marker holds %q, %v; want the version", data, err)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
}

func TestNoHealthyMarkerUnlessAsked(t *testing.T) {
	p := newPanel(t)
	r := serve(t, p.srv)
	r.ready()
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{p.dataDir, p.keysDir} {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err == nil && d.Name() == "healthy" {
				t.Errorf("the panel wrote %s without being asked to", path)
			}
			return nil
		})
	}
}

// If the marker cannot be written the panel serves all the same, and says so.
func TestHealthyMarkerThatCannotBeWrittenIsAWarning(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "no", "such", "dir", "healthy")
	p := newPanel(t, func(c *Config) { c.HealthyFile = marker })
	r := serve(t, p.srv)
	r.ready()
	eventually(t, "the warning", func() bool {
		return strings.Contains(p.logs.String(), "level=WARN") && strings.Contains(p.logs.String(), "healthy")
	})
	if err := r.stop(); err != nil {
		t.Errorf("Serve returned %v", err)
	}
}

// The proxies that the operator names are the ones whose X-Forwarded-For counts,
// all the way to the limits on sign-in.
func TestTrustedProxiesOfTheConfigReachTheLimiter(t *testing.T) {
	failures := func(t *testing.T, p *panel, xffs []string) (last *http.Response, lastBody string) {
		t.Helper()
		for i, xff := range xffs {
			// Another user name each time, so that the lock is the one of the address.
			body := `{"username":"nobody` + string(rune('a'+i)) + `","password":"wrong password here"}`
			last, lastBody = p.do(http.MethodPost, loginPath, strings.NewReader(body), map[string]string{
				"Content-Type":    "application/json",
				"X-Forwarded-For": xff,
			})
		}
		return last, lastBody
	}
	sixAddresses := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"}

	t.Run("by default the loopback is a proxy", func(t *testing.T) {
		p := newPanel(t)
		resp, body := failures(t, p, sixAddresses)
		// Six clients, one failure each: nobody is locked.
		if code, _ := errorBody(t, body); code != "unauthenticated" {
			t.Errorf("the sixth address got %d %q, want unauthenticated", resp.StatusCode, code)
		}
	})
	t.Run("a proxy that is not the loopback leaves the loopback as it is", func(t *testing.T) {
		p := newPanel(t, func(c *Config) { c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")} })
		resp, body := failures(t, p, sixAddresses)
		// The header is ignored: six failures of one address.
		if code, _ := errorBody(t, body); code != "resource_exhausted" {
			t.Errorf("the sixth address got %d %q, want resource_exhausted", resp.StatusCode, code)
		}
	})
}
