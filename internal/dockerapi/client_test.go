package dockerapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// runnerImage is the image every node container runs (Global Constraints).
const runnerImage = "alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

var (
	testID     = strings.Repeat("ab12", 16) // a 64 hex digit container ID
	testDigest = "sha256:" + strings.Repeat("ab", 32)
)

// ---- a stand-in for dockerd ---------------------------------------------------

// request is what the test daemon saw on the wire.
type request struct {
	Method string
	Path   string // request target without the query, still escaped
	Query  url.Values
	Header http.Header
	Body   []byte
}

// testDaemon is an httptest server on a unix socket that plays dockerd. It
// strips the /v<version> prefix before routing, so routes are registered as
// "POST /containers/{id}/start", and records every request. GET /version and
// GET /_ping are answered unless a test registers its own route for them.
type testDaemon struct {
	t      *testing.T
	socket string
	mux    *http.ServeMux // routes registered by the test
	std    *http.ServeMux // fallbacks

	mu   sync.Mutex
	reqs []request
}

var versionPrefix = regexp.MustCompile(`^/v[0-9]+\.[0-9]+`)

func newTestDaemon(t *testing.T, apiVersion string) *testDaemon {
	t.Helper()
	// Unix socket paths are limited to about 100 bytes, and neither t.TempDir()
	// (it embeds the test name) nor macOS's default temp dir is short enough, so
	// use a short directory of our own.
	base := ""
	if st, err := os.Stat("/tmp"); err == nil && st.IsDir() {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "dkr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	d := &testDaemon{
		t:      t,
		socket: filepath.Join(dir, "docker.sock"),
		mux:    http.NewServeMux(),
		std:    http.NewServeMux(),
	}
	d.std.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ApiVersion": apiVersion, "MinAPIVersion": "1.24", "Version": "test"})
	})
	d.std.HandleFunc("GET /_ping", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "OK")
	})
	d.std.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeMessage(w, http.StatusNotImplemented, "test daemon: no route for "+r.Method+" "+r.URL.Path)
	})

	ln, err := net.Listen("unix", d.socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(d.serve))
	_ = srv.Listener.Close() // the TCP listener httptest made; we serve on the socket
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return d
}

func (d *testDaemon) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	target, _, _ := strings.Cut(r.RequestURI, "?")
	d.mu.Lock()
	d.reqs = append(d.reqs, request{Method: r.Method, Path: target, Query: r.URL.Query(), Header: r.Header.Clone(), Body: body})
	d.mu.Unlock()

	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(body))
	if p := versionPrefix.FindString(r2.URL.Path); p != "" {
		r2.URL.Path = strings.TrimPrefix(r2.URL.Path, p)
		r2.URL.RawPath = strings.TrimPrefix(r2.URL.RawPath, p)
	}
	if _, pattern := d.mux.Handler(r2); pattern != "" {
		d.mux.ServeHTTP(w, r2)
		return
	}
	d.std.ServeHTTP(w, r2)
}

func (d *testDaemon) handle(pattern string, h http.HandlerFunc) { d.mux.HandleFunc(pattern, h) }

func (d *testDaemon) client() Client { return New(d.socket) }

func (d *testDaemon) requests() []request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]request(nil), d.reqs...)
}

// last is the most recent request. The client negotiates the API version
// before its first real request, so after a call the operation itself is last.
func (d *testDaemon) last() request {
	d.t.Helper()
	reqs := d.requests()
	if len(reqs) == 0 {
		d.t.Fatal("no request reached the daemon")
	}
	return reqs[len(reqs)-1]
}

func (d *testDaemon) count(method, path string) int {
	n := 0
	for _, r := range d.requests() {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeMessage(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"message": message})
}

// frame builds one frame of Docker's multiplexed log stream.
func frame(stream byte, payload string) []byte {
	b := make([]byte, 8, 8+len(payload))
	b[0] = stream
	binary.BigEndian.PutUint32(b[4:], uint32(len(payload)))
	return append(b, payload...)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// ---- assertions ---------------------------------------------------------------

func wantRequest(t *testing.T, got request, method, path string) {
	t.Helper()
	if got.Method != method || got.Path != path {
		t.Fatalf("request = %s %s, want %s %s", got.Method, got.Path, method, path)
	}
}

func wantQuery(t *testing.T, got, want url.Values) {
	t.Helper()
	if got.Encode() != want.Encode() {
		t.Errorf("query = %q, want %q", got.Encode(), want.Encode())
	}
}

func wantJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("body %q is not JSON: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("bad expectation %q: %v", want, err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("body = %s\nwant   %s", got, want)
	}
}

// assertGolden compares a JSON request body with testdata/<name>. The
// comparison is semantic (field order and layout do not matter); -update
// rewrites the file with the indented body.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, got, "", "  "); err != nil {
		t.Fatalf("request body is not JSON: %v\n%s", err, got)
	}
	pretty.WriteByte('\n')
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, pretty.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("%s is not JSON: %v", path, err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("request body differs from %s (run with -update to accept)\n got:\n%s\nwant:\n%s", path, pretty.Bytes(), want)
	}
}

// asAPIError returns err as an *APIError and fails the test when it is not one.
func asAPIError(t *testing.T, err error) *APIError {
	t.Helper()
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v (%T), want *APIError", err, err)
	}
	return apiErr
}

func wantAPIError(t *testing.T, err error, status int, messagePart string) {
	t.Helper()
	apiErr := asAPIError(t, err)
	if apiErr.StatusCode != status {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, status)
	}
	if !strings.Contains(apiErr.Message, messagePart) || !strings.Contains(err.Error(), messagePart) {
		t.Errorf("error %q does not surface Docker's message %q", err, messagePart)
	}
}

func wantDetails(t *testing.T, got *ContainerDetails, want ContainerDetails) {
	t.Helper()
	if got == nil {
		t.Fatal("details = nil")
	}
	g, w := *got, want
	for _, p := range []struct {
		name string
		g, w *time.Time
	}{
		{"Created", &g.Created, &w.Created},
		{"StartedAt", &g.StartedAt, &w.StartedAt},
		{"FinishedAt", &g.FinishedAt, &w.FinishedAt},
	} {
		if !p.g.Equal(*p.w) {
			t.Errorf("%s = %v, want %v", p.name, *p.g, *p.w)
		}
		*p.g, *p.w = time.Time{}, time.Time{}
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("details = %+v\nwant     %+v", g, w)
	}
}

// engineSpec is the spec behind testdata/create_engine.json: an engine container
// as the node agent will create it, plus the fields only other roles use.
func engineSpec() ContainerSpec {
	return ContainerSpec{
		Name:          "postern-eng-abc123-g2",
		Image:         runnerImage,
		User:          "65534:65534",
		NetworkMode:   "host",
		RestartPolicy: "unless-stopped",
		PidMode:       "host",
		Entrypoint:    []string{"/opt/engine/telemt", "/etc/telemt/config.toml"},
		Cmd:           []string{"--verbose"},
		Env:           []string{"TZ=UTC", "RUST_LOG=info"},
		Binds: []string{
			"/opt/postern/data/artifacts/telemt/3.5.13/x86_64/telemt:/opt/engine/telemt:ro",
			"/opt/postern/data/instances/abc123-g2:/etc/telemt",
		},
		CapAdd:      []string{"NET_BIND_SERVICE"},
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Labels: map[string]string{
			"postern.managed":    "true",
			"postern.role":       "engine",
			"postern.id":         "abc123",
			"postern.generation": "2",
		},
		Tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,size=16m"},
		ReadOnly:    true,
		MemoryBytes: 256 << 20,
		PidsLimit:   256,
		Ulimits:     []Ulimit{{Name: "nofile", Soft: 1048576, Hard: 1048576}},
		LogMaxSize:  "5m",
		LogMaxFile:  2,
		StopTimeout: new(35),
	}
}

// ---- construction and API version negotiation ---------------------------------

func TestNewSocketPath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", DefaultSocket},
		{"/run/docker.sock", "/run/docker.sock"},
		{"unix:///run/user/1000/docker.sock", "/run/user/1000/docker.sock"},
	} {
		if got := New(tc.in).(*client).socket; got != tc.want {
			t.Errorf("New(%q) uses socket %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAPIVersionNegotiation(t *testing.T) {
	for _, tc := range []struct{ name, server, want string }{
		{"daemon older than the client", "1.43", "1.43"},
		{"daemon equal to the client", "1.47", "1.47"},
		{"daemon newer is capped", "1.56", "1.47"},
		{"compared as numbers, not as text", "1.9", "1.9"},
		{"a newer major version is capped", "2.0", "1.47"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDaemon(t, tc.server)
			d.handle("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, []any{}) })
			if _, err := d.client().List(testCtx(t), nil, false); err != nil {
				t.Fatal(err)
			}
			wantRequest(t, d.last(), "GET", "/v"+tc.want+"/containers/json")
			if got := d.requests()[0]; got.Method != "GET" || got.Path != "/version" {
				t.Errorf("first request = %s %s, want the unversioned GET /version", got.Method, got.Path)
			}
		})
	}
}

func TestAPIVersionNegotiatedOnce(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, []any{}) })
	c := d.client()
	for range 3 {
		if _, err := c.List(testCtx(t), nil, false); err != nil {
			t.Fatal(err)
		}
	}
	if n := d.count("GET", "/version"); n != 1 {
		t.Errorf("GET /version sent %d times, want once", n)
	}
}

func TestAPIVersionFailureIsNotCached(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	var mu sync.Mutex
	calls := 0
	d.handle("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			writeMessage(w, http.StatusInternalServerError, "daemon is warming up")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ApiVersion": "1.47"})
	})
	d.handle("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, []any{}) })
	c := d.client()

	_, err := c.List(testCtx(t), nil, false)
	wantAPIError(t, err, http.StatusInternalServerError, "daemon is warming up")
	if _, err := c.List(testCtx(t), nil, false); err != nil {
		t.Fatalf("second call: %v", err)
	}
	wantRequest(t, d.last(), "GET", "/v1.47/containers/json")
}

func TestAPIVersionGarbageIsRejected(t *testing.T) {
	for _, body := range []string{`{"ApiVersion":"banana"}`, `{}`, `{"ApiVersion":"1"}`, `not json`} {
		d := newTestDaemon(t, "1.47")
		d.handle("GET /version", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
		if _, err := d.client().List(testCtx(t), nil, false); err == nil {
			t.Errorf("version answer %q: List succeeded, want an error", body)
		}
		if n := len(d.requests()); n != 1 {
			t.Errorf("version answer %q: %d requests reached the daemon, want only the version probe", body, n)
		}
	}
}

func TestPing(t *testing.T) {
	d := newTestDaemon(t, "1.43")
	d.handle("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, []any{}) })
	c := d.client()

	got, err := c.Ping(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if got != "1.43" {
		t.Errorf("Ping = %q, want the negotiated 1.43", got)
	}
	paths := []string{}
	for _, r := range d.requests() {
		paths = append(paths, r.Method+" "+r.Path)
	}
	if want := []string{"GET /_ping", "GET /version"}; !reflect.DeepEqual(paths, want) {
		t.Errorf("Ping requests = %v, want %v", paths, want)
	}

	if _, err := c.List(testCtx(t), nil, false); err != nil {
		t.Fatal(err)
	}
	wantRequest(t, d.last(), "GET", "/v1.43/containers/json")

	// The daemon is upgraded. Ordinary calls keep the version they have...
	d.handle("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"ApiVersion": "1.45"})
	})
	if _, err := c.List(testCtx(t), nil, false); err != nil {
		t.Fatal(err)
	}
	wantRequest(t, d.last(), "GET", "/v1.43/containers/json")

	// ...and Ping renegotiates: the new version is returned and used from then on.
	if got, err = c.Ping(testCtx(t)); err != nil || got != "1.45" {
		t.Fatalf("second Ping = %q, %v; want 1.45", got, err)
	}
	if _, err := c.List(testCtx(t), nil, false); err != nil {
		t.Fatal(err)
	}
	wantRequest(t, d.last(), "GET", "/v1.45/containers/json")
}

func TestPingDaemonError(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /_ping", func(w http.ResponseWriter, _ *http.Request) {
		writeMessage(w, http.StatusInternalServerError, "daemon is shutting down")
	})
	_, err := d.client().Ping(testCtx(t))
	wantAPIError(t, err, http.StatusInternalServerError, "daemon is shutting down")
}

func TestSocketMissing(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")
	_, err := New(sock).Ping(testCtx(t))
	if err == nil || !strings.Contains(err.Error(), "absent.sock") {
		t.Fatalf("Ping on a missing socket: err = %v, want an error naming the socket", err)
	}
}

func TestContextDeadlineEndsAHungRequest(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/json", func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := d.client().List(ctx, nil, false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("List returned after %v, the deadline was not honoured", took)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1.47/containers/json", http.StatusMovedPermanently)
	})
	d.handle("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, []any{}) })
	_, err := d.client().Inspect(testCtx(t), "web")
	wantAPIError(t, err, http.StatusMovedPermanently, "")
	if n := d.count("GET", "/v1.47/containers/json"); n != 0 {
		t.Errorf("the redirect was followed (%d requests to the target)", n)
	}
}

func TestConcurrentCalls(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, []any{}) })
	c := d.client()
	ctx := testCtx(t)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.List(ctx, nil, true)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	for _, r := range d.requests() {
		if r.Path != "/version" && r.Path != "/v1.47/containers/json" {
			t.Errorf("unexpected request %s %s", r.Method, r.Path)
		}
	}
}

// ---- errors -------------------------------------------------------------------

func TestAPIErrorMessage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		respond func(w http.ResponseWriter)
		status  int
		message string
	}{
		{"docker's JSON message", func(w http.ResponseWriter) { writeMessage(w, 500, "  something broke \n") }, 500, "something broke"},
		{"plain text body", func(w http.ResponseWriter) { w.WriteHeader(502); _, _ = io.WriteString(w, "bad gateway from proxy\n") }, 502, "bad gateway from proxy"},
		{"JSON without a message", func(w http.ResponseWriter) { writeJSON(w, 500, map[string]string{"error": "x"}) }, 500, `{"error":"x"}`},
		{"empty body", func(w http.ResponseWriter) { w.WriteHeader(503) }, 503, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDaemon(t, "1.47")
			d.handle("GET /containers/{id}/json", func(w http.ResponseWriter, _ *http.Request) { tc.respond(w) })
			_, err := d.client().Inspect(testCtx(t), "web")
			wantAPIError(t, err, tc.status, tc.message)
			if apiErr := asAPIError(t, err); apiErr.Message != tc.message {
				t.Errorf("Message = %q, want exactly %q", apiErr.Message, tc.message)
			}
			if want := fmt.Sprintf("%d %s", tc.status, http.StatusText(tc.status)); !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name the status %q", err, want)
			}
			if !strings.Contains(err.Error(), `inspect container "web"`) {
				t.Errorf("error %q does not say what was attempted", err)
			}
		})
	}
}

func TestAPIErrorIsNotFound(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   bool
	}{{404, true}, {409, false}, {500, false}} {
		err := error(newAPIError("op", tc.status, "m"))
		if got := errors.Is(err, ErrNotFound); got != tc.want {
			t.Errorf("errors.Is(%d, ErrNotFound) = %v, want %v", tc.status, got, tc.want)
		}
		if errors.Is(err, errEmptyID) {
			t.Errorf("a %d error matches errEmptyID", tc.status)
		}
	}
}

func TestContainerAddressingRejectsEmptyID(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	c := d.client()
	ctx := testCtx(t)
	calls := map[string]func() error{
		"Inspect":          func() error { _, err := c.Inspect(ctx, ""); return err },
		"Start":            func() error { return c.Start(ctx, "") },
		"Stop":             func() error { return c.Stop(ctx, "", time.Second) },
		"Remove":           func() error { return c.Remove(ctx, "", true) },
		"SetRestartPolicy": func() error { return c.SetRestartPolicy(ctx, "", "no") },
		"Logs":             func() error { _, err := c.Logs(ctx, "", 10, false); return err },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, errEmptyID) {
			t.Errorf("%s with an empty ID: err = %v, want errEmptyID", name, err)
		}
	}
	if n := len(d.requests()); n != 0 {
		t.Errorf("%d requests reached the daemon, want none", n)
	}
}

func TestContainerIDIsEscapedInThePath(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	_, _ = d.client().Inspect(testCtx(t), "a/b?x=1#frag")
	wantRequest(t, d.last(), "GET", "/v1.47/containers/a%2Fb%3Fx=1%23frag/json")
	if len(d.last().Query) != 0 {
		t.Errorf("an ID leaked into the query string: %v", d.last().Query)
	}
}

// ---- create -------------------------------------------------------------------

func TestCreateSendsTheGoldenPayload(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("POST /containers/create", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{"Id": testID, "Warnings": []string{}})
	})
	id, err := d.client().Create(testCtx(t), engineSpec())
	if err != nil {
		t.Fatal(err)
	}
	if id != testID {
		t.Errorf("Create returned %q, want %q", id, testID)
	}
	got := d.last()
	wantRequest(t, got, "POST", "/v1.47/containers/create")
	wantQuery(t, got.Query, url.Values{"name": {"postern-eng-abc123-g2"}})
	if ct := got.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	assertGolden(t, "create_engine.json", got.Body)
}

func TestCreateOmitsUnsetFields(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("POST /containers/create", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{"Id": testID})
	})
	if _, err := d.client().Create(testCtx(t), ContainerSpec{Image: "alpine:3.22"}); err != nil {
		t.Fatal(err)
	}
	got := d.last()
	wantJSON(t, got.Body, `{"Image":"alpine:3.22","HostConfig":{}}`)
	if got.Query.Has("name") {
		t.Errorf("a nameless spec sent name=%q", got.Query.Get("name"))
	}
}

func TestCreateMemorySwap(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("POST /containers/create", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{"Id": testID})
	})
	if _, err := d.client().Create(testCtx(t), ContainerSpec{Image: "alpine:3.22", MemoryBytes: 64 << 20, MemorySwap: 64 << 20}); err != nil {
		t.Fatal(err)
	}
	wantJSON(t, d.last().Body, `{"Image":"alpine:3.22","HostConfig":{"Memory":67108864,"MemorySwap":67108864}}`)
}

func TestCreateLogConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		size string
		file int
		want string
	}{
		{"untouched", "", 0, `{}`},
		{"size only", "5m", 0, `{"LogConfig":{"Type":"json-file","Config":{"max-size":"5m"}}}`},
		{"file count only", "", 3, `{"LogConfig":{"Type":"json-file","Config":{"max-file":"3"}}}`},
		{"both", "10m", 2, `{"LogConfig":{"Type":"json-file","Config":{"max-size":"10m","max-file":"2"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDaemon(t, "1.47")
			d.handle("POST /containers/create", func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusCreated, map[string]any{"Id": testID})
			})
			spec := ContainerSpec{Image: "alpine:3.22", LogMaxSize: tc.size, LogMaxFile: tc.file}
			if _, err := d.client().Create(testCtx(t), spec); err != nil {
				t.Fatal(err)
			}
			wantJSON(t, d.last().Body, `{"Image":"alpine:3.22","HostConfig":`+tc.want+`}`)
		})
	}
}

// StopTimeout is a field of the container config, at the top level of the
// create body and not in HostConfig. Unset it is left out, but an explicit 0 is
// sent: the pointer tells them apart.
func TestCreateStopTimeout(t *testing.T) {
	for _, tc := range []struct {
		name    string
		timeout *int
		want    string
	}{
		{"unset", nil, `{"Image":"alpine:3.22","HostConfig":{}}`},
		{"zero", new(0), `{"Image":"alpine:3.22","StopTimeout":0,"HostConfig":{}}`},
		{"seconds", new(35), `{"Image":"alpine:3.22","StopTimeout":35,"HostConfig":{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDaemon(t, "1.47")
			d.handle("POST /containers/create", func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusCreated, map[string]any{"Id": testID})
			})
			spec := ContainerSpec{Image: "alpine:3.22", StopTimeout: tc.timeout}
			if _, err := d.client().Create(testCtx(t), spec); err != nil {
				t.Fatal(err)
			}
			wantJSON(t, d.last().Body, tc.want)
		})
	}
}

// Ulimits go into HostConfig, each with its name and both limits; none leaves
// the field out.
func TestCreateUlimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		ulimits []Ulimit
		want    string
	}{
		{"none", nil, `{}`},
		{"open files", []Ulimit{{Name: "nofile", Soft: 1048576, Hard: 1048576}},
			`{"Ulimits":[{"Name":"nofile","Soft":1048576,"Hard":1048576}]}`},
		{"two, soft under hard", []Ulimit{{Name: "nofile", Soft: 1024, Hard: 4096}, {Name: "nproc", Soft: 64, Hard: 64}},
			`{"Ulimits":[{"Name":"nofile","Soft":1024,"Hard":4096},{"Name":"nproc","Soft":64,"Hard":64}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDaemon(t, "1.47")
			d.handle("POST /containers/create", func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusCreated, map[string]any{"Id": testID})
			})
			spec := ContainerSpec{Image: "alpine:3.22", Ulimits: tc.ulimits}
			if _, err := d.client().Create(testCtx(t), spec); err != nil {
				t.Fatal(err)
			}
			wantJSON(t, d.last().Body, `{"Image":"alpine:3.22","HostConfig":`+tc.want+`}`)
		})
	}
}

func TestCreateRejectsBadSpecsLocally(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	c := d.client()
	for name, spec := range map[string]ContainerSpec{
		"no image":               {Name: "x"},
		"unknown restart policy": {Image: "alpine:3.22", RestartPolicy: "sometimes"},
		"ulimit without a name":  {Image: "alpine:3.22", Ulimits: []Ulimit{{Soft: 1, Hard: 1}}},
		"ulimit soft over hard":  {Image: "alpine:3.22", Ulimits: []Ulimit{{Name: "nofile", Soft: 2048, Hard: 1024}}},
	} {
		if _, err := c.Create(testCtx(t), spec); err == nil {
			t.Errorf("%s: Create succeeded, want an error", name)
		}
	}
	if n := len(d.requests()); n != 0 {
		t.Errorf("%d requests reached the daemon, want none", n)
	}
}

func TestCreateErrors(t *testing.T) {
	t.Run("missing image is not found", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handle("POST /containers/create", func(w http.ResponseWriter, _ *http.Request) {
			writeMessage(w, http.StatusNotFound, "No such image: alpine:9")
		})
		_, err := d.client().Create(testCtx(t), ContainerSpec{Name: "x", Image: "alpine:9"})
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
		wantAPIError(t, err, http.StatusNotFound, "No such image: alpine:9")
	})
	t.Run("name conflict", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handle("POST /containers/create", func(w http.ResponseWriter, _ *http.Request) {
			writeMessage(w, http.StatusConflict, `Conflict. The container name "/dup" is already in use`)
		})
		_, err := d.client().Create(testCtx(t), ContainerSpec{Name: "dup", Image: "alpine:3.22"})
		wantAPIError(t, err, http.StatusConflict, "already in use")
		if errors.Is(err, ErrNotFound) {
			t.Error("a 409 matches ErrNotFound")
		}
		if !strings.Contains(err.Error(), `create container "dup"`) {
			t.Errorf("error %q does not say what was attempted", err)
		}
	})
	t.Run("daemon error", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handle("POST /containers/create", func(w http.ResponseWriter, _ *http.Request) {
			writeMessage(w, http.StatusBadRequest, "invalid reference format")
		})
		_, err := d.client().Create(testCtx(t), ContainerSpec{Image: "x"})
		wantAPIError(t, err, http.StatusBadRequest, "invalid reference format")
	})
	t.Run("answer without an ID", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handle("POST /containers/create", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusCreated, map[string]any{"Warnings": []string{"w"}})
		})
		if id, err := d.client().Create(testCtx(t), ContainerSpec{Image: "x"}); err == nil {
			t.Errorf("Create returned id %q without an error", id)
		}
	})
}

// ---- start, stop, remove, restart policy --------------------------------------

func TestContainerOperations(t *testing.T) {
	const path = "/containers/postern-edge-g1"
	cases := []struct {
		name   string
		call   func(ctx context.Context, c Client) error
		method string
		path   string
		query  url.Values
		body   string // expected request body, "" for none
		ok     []int  // statuses that mean success
	}{
		{"start", func(ctx context.Context, c Client) error { return c.Start(ctx, "postern-edge-g1") },
			"POST", path + "/start", nil, "", []int{204, 304}},
		{"stop with timeout", func(ctx context.Context, c Client) error { return c.Stop(ctx, "postern-edge-g1", 10*time.Second) },
			"POST", path + "/stop", url.Values{"t": {"10"}}, "", []int{204, 304}},
		{"stop rounds the timeout up", func(ctx context.Context, c Client) error {
			return c.Stop(ctx, "postern-edge-g1", 1500*time.Millisecond)
		},
			"POST", path + "/stop", url.Values{"t": {"2"}}, "", []int{204}},
		{"stop with zero timeout kills at once", func(ctx context.Context, c Client) error { return c.Stop(ctx, "postern-edge-g1", 0) },
			"POST", path + "/stop", url.Values{"t": {"0"}}, "", []int{204}},
		{"stop with a negative timeout uses the daemon default", func(ctx context.Context, c Client) error { return c.Stop(ctx, "postern-edge-g1", -1) },
			"POST", path + "/stop", nil, "", []int{204}},
		{"remove", func(ctx context.Context, c Client) error { return c.Remove(ctx, "postern-edge-g1", false) },
			"DELETE", path, url.Values{"v": {"1"}}, "", []int{204}},
		{"remove forced", func(ctx context.Context, c Client) error { return c.Remove(ctx, "postern-edge-g1", true) },
			"DELETE", path, url.Values{"v": {"1"}, "force": {"1"}}, "", []int{204}},
		{"set restart policy", func(ctx context.Context, c Client) error {
			return c.SetRestartPolicy(ctx, "postern-edge-g1", "unless-stopped")
		}, "POST", path + "/update", nil, `{"RestartPolicy":{"Name":"unless-stopped"}}`, []int{200}},
		{"empty restart policy means no", func(ctx context.Context, c Client) error {
			return c.SetRestartPolicy(ctx, "postern-edge-g1", "")
		}, "POST", path + "/update", nil, `{"RestartPolicy":{"Name":"no"}}`, []int{200}},
	}
	for _, tc := range cases {
		route := func(d *testDaemon, status int, message string) {
			d.handle(tc.method+" "+tc.path, func(w http.ResponseWriter, _ *http.Request) {
				switch {
				case message != "":
					writeMessage(w, status, message)
				case status == 200:
					writeJSON(w, status, map[string]any{"Warnings": []string{}})
				default:
					w.WriteHeader(status)
				}
			})
		}
		for _, status := range tc.ok {
			t.Run(fmt.Sprintf("%s/%d", tc.name, status), func(t *testing.T) {
				d := newTestDaemon(t, "1.47")
				route(d, status, "")
				if err := tc.call(testCtx(t), d.client()); err != nil {
					t.Fatal(err)
				}
				got := d.last()
				wantRequest(t, got, tc.method, "/v1.47"+tc.path)
				wantQuery(t, got.Query, tc.query)
				if tc.body == "" {
					if len(got.Body) != 0 {
						t.Errorf("unexpected request body %q", got.Body)
					}
				} else {
					wantJSON(t, got.Body, tc.body)
				}
			})
		}
		t.Run(tc.name+"/404", func(t *testing.T) {
			d := newTestDaemon(t, "1.47")
			route(d, 404, "No such container: postern-edge-g1")
			err := tc.call(testCtx(t), d.client())
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound", err)
			}
			wantAPIError(t, err, 404, "No such container: postern-edge-g1")
		})
		t.Run(tc.name+"/500", func(t *testing.T) {
			d := newTestDaemon(t, "1.47")
			route(d, 500, "cannot kill container: boom")
			err := tc.call(testCtx(t), d.client())
			wantAPIError(t, err, 500, "cannot kill container: boom")
			if errors.Is(err, ErrNotFound) {
				t.Error("a 500 matches ErrNotFound")
			}
		})
	}
}

func TestRemoveRunningContainerConflict(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("DELETE /containers/web", func(w http.ResponseWriter, _ *http.Request) {
		writeMessage(w, http.StatusConflict, `cannot remove container "/web": container is running`)
	})
	err := d.client().Remove(testCtx(t), "web", false)
	wantAPIError(t, err, http.StatusConflict, "container is running")
}

func TestSetRestartPolicyRejectsUnknownPolicyLocally(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	if err := d.client().SetRestartPolicy(testCtx(t), "web", "sometimes"); err == nil {
		t.Fatal("SetRestartPolicy accepted an unknown policy")
	}
	if n := len(d.requests()); n != 0 {
		t.Errorf("%d requests reached the daemon, want none", n)
	}
}

// ---- list and inspect ---------------------------------------------------------

func TestListQuery(t *testing.T) {
	for _, tc := range []struct {
		name   string
		labels map[string]string
		all    bool
		want   url.Values
	}{
		{"everything running", nil, false, nil},
		{"all containers", nil, true, url.Values{"all": {"1"}}},
		{"label filters are sorted", map[string]string{"postern.role": "edge", "postern.managed": "true"}, true,
			url.Values{"all": {"1"}, "filters": {`{"label":["postern.managed=true","postern.role=edge"]}`}}},
		{"empty value means any value", map[string]string{"postern.id": ""}, false,
			url.Values{"filters": {`{"label":["postern.id"]}`}}},
		{"values are not interpreted", map[string]string{"k": "a=b,c d"}, false,
			url.Values{"filters": {`{"label":["k=a=b,c d"]}`}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDaemon(t, "1.47")
			d.handle("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, []any{}) })
			got, err := d.client().List(testCtx(t), tc.labels, tc.all)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 0 {
				t.Errorf("List = %v, want nothing", got)
			}
			wantRequest(t, d.last(), "GET", "/v1.47/containers/json")
			wantQuery(t, d.last().Query, tc.want)
		})
	}
}

func TestListParsesContainers(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[
 {"Id":"`+testID+`","Names":["/postern-eng-abc123-g2"],"Image":"`+runnerImage+`","ImageID":"sha256:5291449c3df7",
  "Command":"/opt/engine/telemt /etc/telemt/config.toml","Created":1759555200,"Ports":[],
  "Labels":{"postern.managed":"true","postern.role":"engine","postern.id":"abc123","postern.generation":"2"},
  "State":"running","Status":"Up 3 minutes","HostConfig":{"NetworkMode":"host"},"Mounts":[]},
 {"Id":"cd34","Names":["/web/db","/db"],"Image":"alpine:3.22","Created":1759550000,"Labels":null,
  "State":"exited","Status":"Exited (0) 2 hours ago"},
 {"Id":"ef56","Names":[],"Image":"sha256:ff","Created":0,"State":"created","Status":"Created"}
]`)
	})
	got, err := d.client().List(testCtx(t), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []Container{
		{ID: testID, Name: "postern-eng-abc123-g2", Image: runnerImage, State: "running", Status: "Up 3 minutes",
			Labels:  map[string]string{"postern.managed": "true", "postern.role": "engine", "postern.id": "abc123", "postern.generation": "2"},
			Created: time.Date(2025, 10, 4, 5, 20, 0, 0, time.UTC)},
		// A container reachable through legacy links has several names; the
		// primary one has no second slash.
		{ID: "cd34", Name: "db", Image: "alpine:3.22", State: "exited", Status: "Exited (0) 2 hours ago",
			Created: time.Date(2025, 10, 4, 3, 53, 20, 0, time.UTC)},
		{ID: "ef56", Image: "sha256:ff", State: "created", Status: "Created", Created: time.Unix(0, 0)},
	}
	if len(got) != len(want) {
		t.Fatalf("List returned %d containers, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !got[i].Created.Equal(want[i].Created) {
			t.Errorf("[%d] Created = %v, want %v", i, got[i].Created, want[i].Created)
		}
		g, w := got[i], want[i]
		g.Created, w.Created = time.Time{}, time.Time{}
		if len(g.Labels) == 0 && len(w.Labels) == 0 {
			g.Labels, w.Labels = nil, nil
		}
		if !reflect.DeepEqual(g, w) {
			t.Errorf("[%d] = %+v\nwant %+v", i, g, w)
		}
	}
}

func TestListError(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/json", func(w http.ResponseWriter, _ *http.Request) {
		writeMessage(w, http.StatusInternalServerError, "database is locked")
	})
	_, err := d.client().List(testCtx(t), nil, true)
	wantAPIError(t, err, http.StatusInternalServerError, "database is locked")
}

const inspectExited = `{
 "Id":"%s","Created":"2025-10-04T05:20:00.123456789Z","Path":"/opt/postern/bin/postern-node","Args":["edge"],
 "State":{"Status":"exited","Running":false,"Paused":false,"Restarting":false,"OOMKilled":false,"Dead":false,
  "Pid":0,"ExitCode":137,"Error":"","StartedAt":"2025-10-04T05:20:01.5Z","FinishedAt":"2025-10-04T06:00:00.25Z"},
 "Image":"sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8","Name":"/postern-edge-g1",
 "HostConfig":{"NetworkMode":"host","RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0},
  "Binds":["/opt/postern/bin/postern-node:/opt/postern/bin/postern-node:ro","/opt/postern/data/edge:/data"],
  "PortBindings":{"8088/tcp":[{"HostIp":"127.0.0.1","HostPort":"8088"}],"443/tcp":[{"HostIp":"","HostPort":"443"},{"HostIp":"::","HostPort":"443"}]}},
 "Config":{"Image":"%s","Labels":{"postern.managed":"true","postern.role":"edge"},"Tty":false}}`

func TestInspectParsesDetails(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/postern-edge-g1/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, inspectExited, testID, runnerImage)
	})
	got, err := d.client().Inspect(testCtx(t), "postern-edge-g1")
	if err != nil {
		t.Fatal(err)
	}
	wantRequest(t, d.last(), "GET", "/v1.47/containers/postern-edge-g1/json")
	wantDetails(t, got, ContainerDetails{
		Container: Container{
			ID: testID, Name: "postern-edge-g1", Image: runnerImage, State: "exited", Status: "exited",
			Labels:  map[string]string{"postern.managed": "true", "postern.role": "edge"},
			Created: time.Date(2025, 10, 4, 5, 20, 0, 123456789, time.UTC),
		},
		RestartPolicy: "unless-stopped",
		Binds:         []string{"/opt/postern/bin/postern-node:/opt/postern/bin/postern-node:ro", "/opt/postern/data/edge:/data"},
		ExitCode:      137,
		StartedAt:     time.Date(2025, 10, 4, 5, 20, 1, 500000000, time.UTC),
		FinishedAt:    time.Date(2025, 10, 4, 6, 0, 0, 250000000, time.UTC),
		NetworkMode:   "host",
		PortBindings: []PortBinding{
			{ContainerPort: "443/tcp", HostIP: "", HostPort: "443"},
			{ContainerPort: "443/tcp", HostIP: "::", HostPort: "443"},
			{ContainerPort: "8088/tcp", HostIP: "127.0.0.1", HostPort: "8088"},
		},
	})
}

func TestInspectNeverStartedContainer(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/{id}/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Id":"`+testID+`","Created":"2025-10-04T05:20:00Z","Name":"/fresh",
 "State":{"Status":"created","Running":false,"ExitCode":0,"StartedAt":"0001-01-01T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"},
 "HostConfig":{"RestartPolicy":{"Name":"","MaximumRetryCount":0}},"Config":{"Image":"alpine:3.22","Labels":null}}`)
	})
	got, err := d.client().Inspect(testCtx(t), "fresh")
	if err != nil {
		t.Fatal(err)
	}
	wantDetails(t, got, ContainerDetails{
		Container:     Container{ID: testID, Name: "fresh", Image: "alpine:3.22", State: "created", Status: "created", Created: time.Date(2025, 10, 4, 5, 20, 0, 0, time.UTC)},
		RestartPolicy: "no", // an unset policy is reported as the default, "no"
	})
	if !got.StartedAt.IsZero() || !got.FinishedAt.IsZero() {
		t.Errorf("StartedAt/FinishedAt = %v/%v, want zero times", got.StartedAt, got.FinishedAt)
	}
}

func TestInspectRunning(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/{id}/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Id":"`+testID+`","Created":"2025-10-04T05:20:00Z","Name":"/up",
 "State":{"Status":"running","Running":true,"ExitCode":0,"StartedAt":"2025-10-04T05:20:01Z","FinishedAt":"0001-01-01T00:00:00Z"},
 "HostConfig":{"RestartPolicy":{"Name":"no"}},"Config":{"Image":"alpine:3.22"}}`)
	})
	got, err := d.client().Inspect(testCtx(t), "up")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Running || got.State != "running" || got.ExitCode != 0 || !got.FinishedAt.IsZero() {
		t.Errorf("details = %+v", got)
	}
}

func TestInspectNotFound(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		writeMessage(w, http.StatusNotFound, "No such container: "+r.PathValue("id"))
	})
	got, err := d.client().Inspect(testCtx(t), "ghost")
	if got != nil {
		t.Errorf("details = %+v, want nil", got)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	wantAPIError(t, err, http.StatusNotFound, "No such container: ghost")
}

func TestInspectBadTimestamp(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/{id}/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Id":"x","Created":"yesterday","Name":"/x","State":{},"Config":{}}`)
	})
	if _, err := d.client().Inspect(testCtx(t), "x"); err == nil {
		t.Fatal("Inspect accepted an unparsable timestamp")
	}
}

// ---- logs ---------------------------------------------------------------------

func (d *testDaemon) handleInspectForLogs(tty bool) {
	d.handle("GET /containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"Id": testID, "Name": "/" + r.PathValue("id"), "Created": "2025-10-04T05:20:00Z",
			"State":  map[string]any{"Status": "running", "Running": true},
			"Config": map[string]any{"Image": "alpine:3.22", "Tty": tty},
		})
	})
}

func TestLogsDemultiplexes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tail      int
		follow    bool
		wantQuery url.Values
	}{
		{"tail 100", 100, false, url.Values{"stdout": {"1"}, "stderr": {"1"}, "tail": {"100"}}},
		{"all lines, following", -1, true, url.Values{"stdout": {"1"}, "stderr": {"1"}, "tail": {"all"}, "follow": {"1"}}},
		{"no history, following", 0, true, url.Values{"stdout": {"1"}, "stderr": {"1"}, "tail": {"0"}, "follow": {"1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDaemon(t, "1.47")
			d.handleInspectForLogs(false)
			d.handle("GET /containers/{id}/logs", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/vnd.docker.multiplexed-stream")
				_, _ = w.Write(frame(1, "hello\n"))
				_, _ = w.Write(frame(2, "oops\n"))
				_, _ = w.Write(frame(1, "bye\n"))
			})
			rc, err := d.client().Logs(testCtx(t), "web", tc.tail, tc.follow)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = rc.Close() }()
			got, err := io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "hello\noops\nbye\n" {
				t.Errorf("logs = %q, want the three lines without frame headers", got)
			}
			wantRequest(t, d.last(), "GET", "/v1.47/containers/web/logs")
			wantQuery(t, d.last().Query, tc.wantQuery)
		})
	}
}

func TestLogsOfATTYContainerAreRaw(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handleInspectForLogs(true)
	raw := "plain tty output\r\n\x01\x00\x00\x00 looks like a header but is not\r\n"
	d.handle("GET /containers/{id}/logs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
		_, _ = io.WriteString(w, raw)
	})
	rc, err := d.client().Logs(testCtx(t), "web", -1, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != raw {
		t.Errorf("logs = %q, want the raw stream %q", got, raw)
	}
}

func TestLogsOfAMissingContainer(t *testing.T) {
	t.Run("unknown before the logs call", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handle("GET /containers/{id}/json", func(w http.ResponseWriter, r *http.Request) {
			writeMessage(w, http.StatusNotFound, "No such container: "+r.PathValue("id"))
		})
		rc, err := d.client().Logs(testCtx(t), "ghost", 10, false)
		if rc != nil {
			t.Error("Logs returned a reader")
		}
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
		if n := d.count("GET", "/v1.47/containers/ghost/logs"); n != 0 {
			t.Errorf("the logs endpoint was called %d times for a container that does not exist", n)
		}
	})
	t.Run("removed in between", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handleInspectForLogs(false)
		d.handle("GET /containers/{id}/logs", func(w http.ResponseWriter, _ *http.Request) {
			writeMessage(w, http.StatusNotFound, "No such container: web")
		})
		_, err := d.client().Logs(testCtx(t), "web", 10, false)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
		wantAPIError(t, err, http.StatusNotFound, "No such container: web")
	})
	t.Run("logging driver cannot be read", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handleInspectForLogs(false)
		d.handle("GET /containers/{id}/logs", func(w http.ResponseWriter, _ *http.Request) {
			writeMessage(w, http.StatusNotImplemented, "configured logging driver does not support reading")
		})
		_, err := d.client().Logs(testCtx(t), "web", 10, false)
		wantAPIError(t, err, http.StatusNotImplemented, "does not support reading")
	})
}

func TestLogsFollowStopsWhenTheReaderIsClosed(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handleInspectForLogs(false)
	released := make(chan struct{})
	d.handle("GET /containers/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(frame(1, "line1\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(released)
	})
	rc, err := d.client().Logs(testCtx(t), "web", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("line1\n"))
	if _, err := io.ReadFull(rc, buf); err != nil || string(buf) != "line1\n" {
		t.Fatalf("first line = %q, %v", buf, err)
	}
	if err := rc.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("closing the reader did not end the request on the daemon side")
	}
}

func TestLogsFollowStopsWhenTheContextIsCancelled(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handleInspectForLogs(false)
	d.handle("GET /containers/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(frame(1, "line1\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	rc, err := d.client().Logs(ctx, "web", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	buf := make([]byte, len("line1\n"))
	if _, err := io.ReadFull(rc, buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	rest, err := io.ReadAll(rc)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("read after cancel: %q, %v; want context.Canceled", rest, err)
	}
}

func TestDemuxReader(t *testing.T) {
	big := strings.Repeat("0123456789abcdef", 8192) // 128 KiB, more than any read buffer
	manyFrames := make([][]byte, 0, 500)
	var manyWant strings.Builder
	for i := range 500 {
		line := fmt.Sprintf("line %d\n", i)
		manyFrames = append(manyFrames, frame(byte(1+i%2), line))
		manyWant.WriteString(line)
	}

	cases := []struct {
		name    string
		in      []byte
		want    string // what must have been read before the end or the error
		wantErr string // "" for a clean EOF; "EOF" for io.ErrUnexpectedEOF; otherwise a message part
	}{
		{"empty stream", nil, "", ""},
		{"two frames", cat(frame(1, "hello\n"), frame(2, "oops\n")), "hello\noops\n", ""},
		{"stdin frames are output", frame(0, "x"), "x", ""},
		{"zero-length frames are skipped", cat(frame(1, ""), frame(1, "a"), frame(2, ""), frame(2, "b"), frame(1, "")), "ab", ""},
		{"frame bigger than any read", frame(1, big), big, ""},
		{"many frames", cat(manyFrames...), manyWant.String(), ""},
		{"a line split over frames", cat(frame(1, "he"), frame(1, "llo\n")), "hello\n", ""},
		{"truncated header", cat(frame(1, "ok"), []byte{1, 0, 0}), "ok", "EOF"},
		{"truncated payload", frame(1, "hello")[:8+2], "he", "EOF"},
		{"header without payload", cat(frame(1, "ok"), frame(2, "gone")[:8]), "ok", "EOF"},
		{"unknown stream type", cat(frame(1, "a"), frame(9, "x")), "a", "stream type 9"},
		{"not a multiplexed stream", []byte("2025-10-04T05:20:00Z hello\n"), "", "not a multiplexed"},
		{"reserved bytes set", cat(frame(1, "a"), []byte{1, 0, 7, 0, 0, 0, 0, 1, 'x'}), "a", "not a multiplexed"},
		{"error frame from the daemon", cat(frame(1, "a"), frame(3, "log driver failed")), "a", "log driver failed"},
	}
	sources := map[string]func(io.Reader) io.Reader{
		"whole":        func(r io.Reader) io.Reader { return r },
		"byte by byte": iotest.OneByteReader,
		"halves":       iotest.HalfReader,
		"data+EOF":     iotest.DataErrReader,
	}
	sinks := map[string]func(io.Reader) io.Reader{
		"read all":    func(r io.Reader) io.Reader { return r },
		"read 1 byte": iotest.OneByteReader,
	}
	for _, tc := range cases {
		for srcName, wrapSrc := range sources {
			for sinkName, wrapSink := range sinks {
				t.Run(tc.name+"/"+srcName+"/"+sinkName, func(t *testing.T) {
					d := &demuxReader{r: io.NopCloser(wrapSrc(bytes.NewReader(tc.in)))}
					got, err := io.ReadAll(wrapSink(d))
					if string(got) != tc.want {
						t.Errorf("read %d bytes %.40q..., want %d bytes %.40q...", len(got), got, len(tc.want), tc.want)
					}
					switch tc.wantErr {
					case "":
						if err != nil {
							t.Errorf("err = %v, want a clean EOF", err)
						}
					case "EOF":
						if !errors.Is(err, io.ErrUnexpectedEOF) {
							t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
						}
					default:
						if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
							t.Errorf("err = %v, want one mentioning %q", err, tc.wantErr)
						}
					}
					// The end, like an error, is sticky.
					wantAgain := err
					if wantAgain == nil {
						wantAgain = io.EOF
					}
					if n, again := d.Read(make([]byte, 8)); n != 0 || !errors.Is(again, wantAgain) {
						t.Errorf("read after the end returned %d, %v; want 0, %v", n, again, wantAgain)
					}
				})
			}
		}
	}
}

func TestDemuxReaderClosesTheBody(t *testing.T) {
	closed := false
	body := struct {
		io.Reader
		io.Closer
	}{strings.NewReader(""), closerFunc(func() error { closed = true; return nil })}
	if err := (&demuxReader{r: body}).Close(); err != nil || !closed {
		t.Errorf("Close = %v, body closed = %v", err, closed)
	}
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// ---- images -------------------------------------------------------------------

func TestImageExists(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ref    string
		status int
		want   bool
		path   string
	}{
		{"present", "alpine:3.22", 200, true, "/v1.47/images/alpine:3.22/json"},
		{"present by tag and digest", runnerImage, 200, true, "/v1.47/images/" + runnerImage + "/json"},
		{"absent", "alpine:9", 404, false, "/v1.47/images/alpine:9/json"},
		{"registry path keeps its slashes", "registry.example.com/team/app:1.2", 404, false,
			"/v1.47/images/registry.example.com/team/app:1.2/json"},
		{"registry with a port", "localhost:5000/app", 200, true, "/v1.47/images/localhost:5000/app/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDaemon(t, "1.47")
			d.handle("GET /images/", func(w http.ResponseWriter, _ *http.Request) {
				if tc.status == 404 {
					writeMessage(w, 404, "No such image: "+tc.ref)
					return
				}
				writeJSON(w, tc.status, map[string]any{"Id": "sha256:" + strings.Repeat("ab", 32)})
			})
			got, err := d.client().ImageExists(testCtx(t), tc.ref)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("ImageExists(%q) = %v, want %v", tc.ref, got, tc.want)
			}
			wantRequest(t, d.last(), "GET", tc.path)
		})
	}
}

func TestImageExistsErrors(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /images/", func(w http.ResponseWriter, _ *http.Request) {
		writeMessage(w, http.StatusInternalServerError, "image store is busy")
	})
	got, err := d.client().ImageExists(testCtx(t), "alpine:3.22")
	if got {
		t.Error("ImageExists = true on an error")
	}
	wantAPIError(t, err, http.StatusInternalServerError, "image store is busy")

	d2 := newTestDaemon(t, "1.47")
	if _, err := d2.client().ImageExists(testCtx(t), ""); err == nil {
		t.Error("ImageExists accepted an empty reference")
	}
	if n := len(d2.requests()); n != 0 {
		t.Errorf("%d requests reached the daemon for an empty reference", n)
	}
}

const pullStreamOK = `{"status":"Pulling from library/alpine","id":"3.22"}
{"status":"Pulling fs layer","progressDetail":{},"id":"abc"}
{"status":"Downloading","progressDetail":{"current":10,"total":100},"progress":"[=>    ]","id":"abc"}
{"status":"Pull complete","progressDetail":{},"id":"abc"}
{"status":"Digest: sha256:abcd"}
{"status":"Status: Downloaded newer image for alpine:3.22"}
`

func TestPullSplitsTheReference(t *testing.T) {
	for _, tc := range []struct{ ref, from, tag string }{
		{"alpine", "alpine", "latest"},
		{"alpine:3.22", "alpine", "3.22"},
		{runnerImage, "alpine", testDigestOf(runnerImage)},
		{"alpine@" + testDigest, "alpine", testDigest},
		{"localhost:5000/team/app", "localhost:5000/team/app", "latest"},
		{"localhost:5000/team/app:1.2", "localhost:5000/team/app", "1.2"},
		{"registry.example.com/team/app", "registry.example.com/team/app", "latest"},
		{"registry.example.com/team/app:1.2@" + testDigest, "registry.example.com/team/app", testDigest},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			d := newTestDaemon(t, "1.47")
			d.handle("POST /images/create", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, pullStreamOK) })
			if err := d.client().Pull(testCtx(t), tc.ref); err != nil {
				t.Fatal(err)
			}
			wantRequest(t, d.last(), "POST", "/v1.47/images/create")
			wantQuery(t, d.last().Query, url.Values{"fromImage": {tc.from}, "tag": {tc.tag}})
		})
	}
}

// testDigestOf returns the digest part of name[:tag]@digest.
func testDigestOf(ref string) string {
	_, digest, _ := strings.Cut(ref, "@")
	return digest
}

func TestPullFailures(t *testing.T) {
	t.Run("error in the middle of the stream", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handle("POST /images/create", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"status":"Pulling from team/app","id":"1.2"}`+"\n"+
				`{"status":"Downloading","progressDetail":{"current":1,"total":2},"id":"abc"}`+"\n"+
				`{"errorDetail":{"message":"unauthorized: authentication required"},"error":"unauthorized: authentication required"}`+"\n")
		})
		err := d.client().Pull(testCtx(t), "registry.example.com/team/app:1.2")
		if err == nil || !strings.Contains(err.Error(), "unauthorized: authentication required") {
			t.Fatalf("err = %v, want the registry's message", err)
		}
		if !strings.Contains(err.Error(), "registry.example.com/team/app:1.2") {
			t.Errorf("err = %v, want it to name the image", err)
		}
	})
	t.Run("error field only", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handle("POST /images/create", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"error":"toomanyrequests: rate limit"}`+"\n")
		})
		err := d.client().Pull(testCtx(t), "alpine:3.22")
		if err == nil || !strings.Contains(err.Error(), "toomanyrequests: rate limit") {
			t.Fatalf("err = %v, want the registry's message", err)
		}
	})
	t.Run("stream cut short", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handle("POST /images/create", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"status":"Pulling from team/app","id":"1.2"}`+"\n"+`{"status":"Downl`)
		})
		if err := d.client().Pull(testCtx(t), "alpine:3.22"); err == nil {
			t.Fatal("a pull stream that ends in the middle of a message succeeded")
		}
	})
	t.Run("image does not exist", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handle("POST /images/create", func(w http.ResponseWriter, _ *http.Request) {
			writeMessage(w, http.StatusNotFound, "pull access denied for nope, repository does not exist")
		})
		err := d.client().Pull(testCtx(t), "nope")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
		wantAPIError(t, err, http.StatusNotFound, "pull access denied for nope")
	})
	t.Run("daemon error", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		d.handle("POST /images/create", func(w http.ResponseWriter, _ *http.Request) {
			writeMessage(w, http.StatusInternalServerError, "Get registry: no such host")
		})
		wantAPIError(t, d.client().Pull(testCtx(t), "alpine:3.22"), http.StatusInternalServerError, "no such host")
	})
	t.Run("empty reference", func(t *testing.T) {
		d := newTestDaemon(t, "1.47")
		if err := d.client().Pull(testCtx(t), ""); err == nil {
			t.Error("Pull accepted an empty reference")
		}
		if n := len(d.requests()); n != 0 {
			t.Errorf("%d requests reached the daemon", n)
		}
	})
}

// Inspect reads the restart count and the environment.
func TestInspectRestartCountAndEnv(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/{id}/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"Id":"`+testID+`","Created":"2025-10-04T05:20:00Z","Name":"/up","RestartCount":4,
 "State":{"Status":"paused","Running":true,"StartedAt":"2025-10-04T05:20:01Z"},
 "HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}},"Config":{"Image":"alpine:3.22","Env":["A=1","RUST_LOG=info"]}}`)
	})
	got, err := d.client().Inspect(testCtx(t), "up")
	if err != nil {
		t.Fatal(err)
	}
	if got.RestartCount != 4 || !slices.Equal(got.Env, []string{"A=1", "RUST_LOG=info"}) || got.State != "paused" || !got.Running {
		t.Errorf("details = %+v", got)
	}
}

// LogsSince asks for timestamps and for the lines since a time, to the
// nanosecond.
func TestLogsSince(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handleInspectForLogs(false)
	d.handle("GET /containers/{id}/logs", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(frame(1, "2026-10-07T12:00:00.000000001Z hello\n"))
	})
	since := time.Date(2026, 10, 7, 12, 0, 0, 5, time.UTC)
	rc, err := d.client().LogsSince(testCtx(t), "web", since)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(got) != "2026-10-07T12:00:00.000000001Z hello\n" {
		t.Errorf("logs = %q", got)
	}
	wantQuery(t, d.last().Query, url.Values{"stdout": {"1"}, "stderr": {"1"}, "tail": {"all"}, "timestamps": {"1"},
		"since": {strconv.FormatInt(since.Unix(), 10) + ".000000005"}})
	// Zero: all of it.
	rc, err = d.client().LogsSince(testCtx(t), "web", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()
	if d.last().Query.Has("since") {
		t.Errorf("since without a time: %v", d.last().Query)
	}
}

func TestFakeLogsSinceAndStates(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	f := NewFake()
	f.Now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := f.Create(ctx, ContainerSpec{Name: "c", Image: "x", Env: []string{"K=v"}}); err != nil {
		t.Fatal(err)
	}
	_ = f.Start(ctx, "c")
	_ = f.AppendLogs("c", "one\ntwo\n")
	now = now.Add(time.Minute)
	_ = f.AppendLogs("c", "three\n")
	rc, _ := f.LogsSince(ctx, "c", now)
	got, _ := io.ReadAll(rc)
	if string(got) != now.Format(time.RFC3339Nano)+" three\n" {
		t.Errorf("since = %q", got)
	}
	_ = f.Restarted("c", 2)
	_ = f.SetState("c", "paused")
	d, _ := f.Inspect(ctx, "c")
	if d.RestartCount != 2 || d.State != "paused" || !d.Running || !slices.Equal(d.Env, []string{"K=v"}) {
		t.Errorf("details = %+v", d)
	}
}

func TestInfo(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /info", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ID": "x", "SecurityOptions": []string{"name=seccomp,profile=builtin", "name=userns"},
		})
	})
	got, err := d.client().Info(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	wantRequest(t, d.last(), "GET", "/v1.47/info")
	if want := []string{"name=seccomp,profile=builtin", "name=userns"}; !slices.Equal(got.SecurityOptions, want) {
		t.Errorf("SecurityOptions = %q, want %q", got.SecurityOptions, want)
	}
}

func TestInfoError(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /info", func(w http.ResponseWriter, _ *http.Request) {
		writeMessage(w, http.StatusInternalServerError, "boom")
	})
	if _, err := d.client().Info(testCtx(t)); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Info err = %v, want the daemon's message", err)
	}
}

func TestCreatePrivileged(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("POST /containers/create", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{"Id": testID})
	})
	if _, err := d.client().Create(testCtx(t), ContainerSpec{Image: "alpine:3.22", Privileged: true}); err != nil {
		t.Fatal(err)
	}
	wantJSON(t, d.last().Body, `{"Image":"alpine:3.22","HostConfig":{"Privileged":true}}`)
}

func TestInspectMounts(t *testing.T) {
	d := newTestDaemon(t, "1.47")
	d.handle("GET /containers/postern-agent/json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"Id": testID, "Name": "/postern-agent", "Created": "2025-10-04T05:20:00Z",
			"State":  map[string]any{"Status": "running", "Running": true},
			"Config": map[string]any{"Image": runnerImage},
			"Mounts": []map[string]any{
				{"Type": "bind", "Source": "/opt/postern", "Destination": "/opt/postern", "Mode": "", "RW": true},
				{"Type": "bind", "Source": "/etc/os-release", "Destination": "/host/etc/os-release", "Mode": "ro", "RW": false},
			},
		})
	})
	got, err := d.client().Inspect(testCtx(t), "postern-agent")
	if err != nil {
		t.Fatal(err)
	}
	want := []MountPoint{
		{Type: "bind", Source: "/opt/postern", Destination: "/opt/postern", RW: true},
		{Type: "bind", Source: "/etc/os-release", Destination: "/host/etc/os-release"},
	}
	if !reflect.DeepEqual(got.Mounts, want) {
		t.Errorf("Mounts = %+v, want %+v", got.Mounts, want)
	}
}
