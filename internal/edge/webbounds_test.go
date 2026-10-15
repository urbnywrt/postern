package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	edgev1 "github.com/urbnywrt/postern/gen/go/postern/edge/v1"
)

// The bounds of the WEB path that a client cannot get around: what one stream,
// one source and the node's own probes may hold of the requests in flight, and
// what a request must be to be passed on at all.

// ---------------------------------------------------------------------------
// HTTP/2 frame by frame
// ---------------------------------------------------------------------------

// h2Raw is an HTTP/2 connection to the edge that the test drives frame by
// frame. A goroutine of its own reads the frames and turns those of the
// streams into events: the :status of a response, or the reset of a stream.
type h2Raw struct {
	c      *tls.Conn
	fr     *http2.Framer
	wmu    sync.Mutex // the framer writes one frame at a time
	events chan h2Event
	// pending holds the events read for other streams than the one waited
	// for; of the test's goroutine alone.
	pending map[uint32][]string
}

type h2Event struct {
	stream uint32
	what   string // the :status, or "RST_STREAM <code>", or "GOAWAY <code>" (stream 0)
}

// dialH2 makes an HTTP/2 connection to the edge at to for name, with the
// settings given. It is closed at the end of the test.
func dialH2(t *testing.T, ca *testCA, to netip.AddrPort, name string, settings ...http2.Setting) *h2Raw {
	t.Helper()
	c := dialWeb(t, ca, to, name, "h2")
	if p := c.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("ALPN %q, want h2", p)
	}
	_ = c.SetDeadline(time.Time{})
	if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	h := &h2Raw{c: c, fr: http2.NewFramer(c, c), events: make(chan h2Event, 256), pending: make(map[uint32][]string)}
	h.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := h.fr.WriteSettings(settings...); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(h.events)
		for {
			f, err := h.fr.ReadFrame()
			if err != nil {
				return
			}
			var ev h2Event
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					h.wmu.Lock()
					err = h.fr.WriteSettingsAck()
					h.wmu.Unlock()
					if err != nil {
						return
					}
				}
				continue
			case *http2.MetaHeadersFrame:
				ev = h2Event{f.StreamID, f.PseudoValue("status")}
			case *http2.RSTStreamFrame:
				ev = h2Event{f.StreamID, "RST_STREAM " + f.ErrCode.String()}
			case *http2.GoAwayFrame:
				ev = h2Event{0, "GOAWAY " + f.ErrCode.String()}
			default:
				continue
			}
			h.events <- ev
		}
	}()
	return h
}

// request opens stream id with the pseudo-headers and headers in fields, in
// pairs, ending it when end is set.
func (h *h2Raw) request(t *testing.T, id uint32, end bool, fields ...string) {
	t.Helper()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for i := 0; i+1 < len(fields); i += 2 {
		_ = enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
	}
	h.wmu.Lock()
	defer h.wmu.Unlock()
	if err := h.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndStream: end, EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
}

func (h *h2Raw) data(t *testing.T, id uint32, end bool, p string) {
	t.Helper()
	h.wmu.Lock()
	defer h.wmu.Unlock()
	if err := h.fr.WriteData(id, end, []byte(p)); err != nil {
		t.Fatal(err)
	}
}

func (h *h2Raw) ping() error {
	h.wmu.Lock()
	defer h.wmu.Unlock()
	return h.fr.WritePing(false, [8]byte{'p', 'i', 'n', 'g'})
}

// status returns the next event of stream id: the :status of its response, or
// "RST_STREAM <code>". It pings meanwhile, as a client that keeps its
// connection alive does, and fails the test after wait.
func (h *h2Raw) status(t *testing.T, id uint32, wait time.Duration) string {
	t.Helper()
	deadline := time.After(wait)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if evs := h.pending[id]; len(evs) > 0 {
			h.pending[id] = evs[1:]
			return evs[0]
		}
		select {
		case ev, ok := <-h.events:
			switch {
			case !ok:
				t.Fatalf("stream %d: the connection ended", id)
			case ev.stream == 0:
				t.Fatalf("stream %d: %s", id, ev.what)
			}
			h.pending[ev.stream] = append(h.pending[ev.stream], ev.what)
		case <-tick.C:
			if err := h.ping(); err != nil {
				t.Fatalf("stream %d: ping: %v", id, err)
			}
		case <-deadline:
			t.Fatalf("stream %d: nothing came of it in %v", id, wait)
		}
	}
}

// get is the header block of a GET of path from web.example.com.
func get(path string) []string {
	return []string{":method", "GET", ":scheme", "https", ":path", path, ":authority", "web.example.com"}
}

// ---------------------------------------------------------------------------
// What a stream, a source and a probe hold
// ---------------------------------------------------------------------------

// shortProgress is the progress timeout of the tests, which shortens
// webProgressTimeout.
const shortProgress = 300 * time.Millisecond

// A client that lets no byte of its responses through (an HTTP/2 window of 0)
// while it keeps its connection alive loses its streams once their writes
// make no progress for the progress timeout, and with them their places among
// the requests in flight: another client is served.
func TestWebStreamThatTakesNothingLosesItsSlot(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir, MaxConns: 4})
	e.web.progress = shortProgress
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	h := dialH2(t, ca, loopback(port), "web.example.com", http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})
	for id := uint32(1); id <= 7; id += 2 {
		h.request(t, id, true, get(fmt.Sprintf("/%d", id))...)
	}
	for id := uint32(1); id <= 7; id += 2 {
		// The headers go out, the body cannot.
		if st := h.status(t, id, 5*time.Second); st != "200" {
			t.Fatalf("stream %d: %s, want the headers of the response", id, st)
		}
	}
	for id := uint32(1); id <= 7; id += 2 {
		if st := h.status(t, id, 5*time.Second); !strings.HasPrefix(st, "RST_STREAM") {
			t.Fatalf("stream %d: %s, want it reset for want of progress", id, st)
		}
	}
	waitFor(t, "the slots of the stalled streams back", func() bool { return e.web.inflight.Load() == 0 })
	if err := h.ping(); err != nil {
		t.Errorf("the connection of the stalled client: %v; only its streams were to end", err)
	}
	client, _ := webClient(t, ca, "", loopback(port))
	decodeEcho(t, mustDo(t, client, newRequest(t, http.MethodGet, "https://web.example.com/other", "")))
}

// The progress timeout times only a write or a read that is under way: a long
// poll whose backend is quiet for longer, a response with a longer pause
// between two writes, and an upload that is slow but keeps coming all go
// through, over HTTP/2 and over HTTP/1.1.
func TestWebProgressTimeoutSparesWhatMakesProgress(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	quiet := 3 * shortProgress
	be := newWebBackend(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/poll": // quiet, then the whole answer
			time.Sleep(quiet)
			_, _ = io.WriteString(w, "answer")
		case "/pause": // a part, a pause, the rest
			_, _ = io.WriteString(w, "first,")
			_ = http.NewResponseController(w).Flush()
			time.Sleep(quiet)
			_, _ = io.WriteString(w, "second")
		default: // the body as it came
			b, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write(b)
		}
	})
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	e.web.progress = shortProgress
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	client, _ := webClient(t, ca, "", loopback(port))
	for path, want := range map[string]string{"/poll": "answer", "/pause": "first,second"} {
		t.Run("HTTP/2 "+path, func(t *testing.T) {
			resp := mustDo(t, client, newRequest(t, http.MethodGet, "https://web.example.com"+path, ""))
			b, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK || string(b) != want || resp.Proto != "HTTP/2.0" {
				t.Errorf("%s %d %q, %v; want HTTP/2 200 %q", resp.Proto, resp.StatusCode, b, err, want)
			}
		})
		t.Run("HTTP/1.1 "+path, func(t *testing.T) {
			c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
			resp := rawExchange(t, c, bufio.NewReader(c), "GET "+path+" HTTP/1.1\r\nHost: web.example.com\r\n\r\n")
			b, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != http.StatusOK || string(b) != want {
				t.Errorf("%d %q, %v; want 200 %q", resp.StatusCode, b, err, want)
			}
		})
	}

	const parts = 5
	gap := shortProgress / 2
	t.Run("HTTP/2 slow upload", func(t *testing.T) {
		h := dialH2(t, ca, loopback(port), "web.example.com")
		h.request(t, 1, false, ":method", "POST", ":scheme", "https", ":path", "/up", ":authority", "web.example.com")
		for i := range parts {
			time.Sleep(gap)
			h.data(t, 1, i == parts-1, "part")
		}
		if st := h.status(t, 1, 5*time.Second); st != "200" {
			t.Errorf("a slow upload that keeps coming: %s, want 200", st)
		}
	})
	t.Run("HTTP/1.1 slow upload", func(t *testing.T) {
		c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
		send(t, c, []byte("POST /up HTTP/1.1\r\nHost: web.example.com\r\nTransfer-Encoding: chunked\r\n\r\n"))
		for range parts {
			time.Sleep(gap)
			send(t, c, []byte("4\r\npart\r\n"))
		}
		resp := rawExchange(t, c, bufio.NewReader(c), "0\r\n\r\n")
		b, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK || string(b) != strings.Repeat("part", parts) {
			t.Errorf("a slow upload that keeps coming: %d %q, %v", resp.StatusCode, b, err)
		}
	})
	// The client has read the last answer before the handler gives its slot back.
	waitFor(t, "every slot back", func() bool { return e.web.inflight.Load() == 0 })
}

// An upload that stalls loses its stream once no byte of its body comes for
// the progress timeout: it is the client's fault, answered 400 and not logged
// as a backend that cannot be reached, and its place is free.
func TestWebStalledUploadFreesItsSlot(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	log, logs := captureLogger(slog.LevelInfo)
	e := newTestEdgeLog(t, log, Options{CertsDir: dir})
	e.web.progress = shortProgress
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	h := dialH2(t, ca, loopback(port), "web.example.com")
	h.request(t, 1, false, ":method", "POST", ":scheme", "https", ":path", "/up", ":authority", "web.example.com")
	h.data(t, 1, false, "first")
	if st := h.status(t, 1, 5*time.Second); st != "400" {
		t.Errorf("the stalled upload: %s, want 400", st)
	}
	waitFor(t, "the slot of the stalled upload back", func() bool { return e.web.inflight.Load() == 0 })
	if out := logs.String(); strings.Contains(out, "cannot reach the backend") {
		t.Errorf("a stalled upload is logged as a backend that cannot be reached:\n%s", out)
	}
}

// One source holds max(32, MaxConns/16) of the requests in flight at most; a
// request over its share is answered 503 without going anywhere, and another
// source is served. The source of a web route is the address of the client,
// that of an http-upstream listener the client that X-Forwarded-For names.
func TestWebSourceShareOfTheRequestsInFlight(t *testing.T) {
	checkGoroutines(t)
	if got := newTestEdge(t, Options{MaxConns: 1024}).web.maxPerSource; got != 64 {
		t.Errorf("the share of a source with MaxConns 1024: %d, want 64", got)
	}
	if got := newTestEdge(t, Options{MaxConns: 100}).web.maxPerSource; got != 32 {
		t.Errorf("the share of a source with MaxConns 100: %d, want 32", got)
	}

	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	held, release := make(chan struct{}, 16), make(chan struct{})
	be := newWebBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/base/hold" || r.URL.Path == "/hold" {
			held <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		echoWeb(w, r)
	})
	port, upstreamPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	e.web.maxPerSource = 2
	cfg := webConfig(1, port, "web.example.com", be.addr)
	up := upstreamConfig(upstreamPort, "web.example.com", be.addr, "127.0.0.1")
	cfg.Listeners = append(cfg.Listeners, up.Listeners...)
	cfg.Routes = append(cfg.Routes, up.Routes...)
	mustApply(t, e, cfg)

	// hold starts a request that the backend holds, and waits until it is there.
	var wg sync.WaitGroup
	defer func() {
		close(release)
		wg.Wait()
	}()
	hold := func(t *testing.T, do func() (*http.Response, error)) {
		t.Helper()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp, err := do(); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
		select {
		case <-held:
		case <-time.After(5 * time.Second):
			t.Fatal("a held request did not reach the backend")
		}
	}
	expect503 := func(t *testing.T, resp *http.Response) {
		t.Helper()
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" {
			t.Errorf("over the share: status %d, Retry-After %q; want 503 and 1", resp.StatusCode, resp.Header.Get("Retry-After"))
		}
	}

	t.Run("web route", func(t *testing.T) {
		a, _ := webClient(t, ca, "127.0.0.2", loopback(port))
		for range 2 {
			hold(t, func() (*http.Response, error) { return a.Get("https://web.example.com/hold") })
		}
		for len(be.requests) > 0 {
			<-be.requests
		}
		expect503(t, mustDo(t, a, newRequest(t, http.MethodGet, "https://web.example.com/third", "")))
		be.expectNone(t)
		b, _ := webClient(t, ca, "127.0.0.3", loopback(port))
		decodeEcho(t, mustDo(t, b, newRequest(t, http.MethodGet, "https://web.example.com/other", "")))
	})
	t.Run("http-upstream", func(t *testing.T) {
		var conns []net.Conn
		var connsMu sync.Mutex
		t.Cleanup(func() {
			connsMu.Lock()
			defer connsMu.Unlock()
			for _, c := range conns {
				_ = c.Close()
			}
		})
		upGet := func(client, path string) (*http.Response, error) {
			c, err := net.Dial("tcp4", loopback(upstreamPort).String())
			if err != nil {
				return nil, err
			}
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			req := "GET " + path + " HTTP/1.1\r\nHost: web.example.com\r\nX-Forwarded-For: " + client + "\r\n\r\n"
			if _, err := io.WriteString(c, req); err != nil {
				return nil, err
			}
			return http.ReadResponse(bufio.NewReader(c), nil)
		}
		for range 2 {
			hold(t, func() (*http.Response, error) { return upGet("198.51.100.1", "/base/hold") })
		}
		for len(be.requests) > 0 {
			<-be.requests
		}
		resp, err := upGet("198.51.100.1", "/base/third")
		if err != nil {
			t.Fatal(err)
		}
		expect503(t, resp)
		be.expectNone(t)
		resp, err = upGet("198.51.100.2", "/base/other")
		if err != nil {
			t.Fatal(err)
		}
		decodeEcho(t, resp)
	})
}

// The node's own probes, which come to a test listener from the loopback
// interface, take no place among the requests in flight: they are served
// when the requests of the clients are at their cap.
func TestWebProbeTakesNoSlot(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	held, release := make(chan struct{}, 4), make(chan struct{})
	be := newWebBackend(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			held <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		echoWeb(w, r)
	})
	port, testPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir, MaxConns: 1})
	cfg := webConfig(1, port, "web.example.com", be.addr)
	cfg.TestListeners = []*edgev1.TestListener{{Port: testPort, ListenerId: "l1"}}
	mustApply(t, e, cfg)

	client, _ := webClient(t, ca, "", loopback(port))
	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, err := client.Get("https://web.example.com/hold"); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	defer func() {
		close(release)
		<-done
	}()
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("the held request did not reach the backend")
	}
	if n := e.web.inflight.Load(); n != 1 {
		t.Fatalf("%d requests in flight, want the 1 that the cap allows", n)
	}
	probe, _ := webClient(t, ca, "127.0.0.1", loopback(testPort))
	decodeEcho(t, mustDo(t, probe, newRequest(t, http.MethodGet, "https://web.example.com/probe", "")))
	// The probe has its answer before its handler gives the slot back.
	waitFor(t, "the slot of the probe back, the held request in flight", func() bool { return e.web.inflight.Load() == 1 })
}

// ---------------------------------------------------------------------------
// What a request must be to be passed on
// ---------------------------------------------------------------------------

// An HTTP/2 request whose method is no token, or whose path has a byte that
// no HTTP/1.1 request line may carry, cannot go to the backend as it came: it
// is the client's fault, answered 400 and not logged as a backend that cannot
// be reached, and nothing is dialed.
func TestWebRequestThatHTTP1CannotCarry(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	log, logs := captureLogger(slog.LevelInfo)
	e := newTestEdgeLog(t, log, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	h := dialH2(t, ca, loopback(port), "web.example.com")
	for i, fields := range [][]string{
		{":method", "G@T", ":scheme", "https", ":path", "/x", ":authority", "web.example.com"},
		{":method", "GET", ":scheme", "https", ":path", "/base/a b HTTP/1.0", ":authority", "web.example.com"},
		{":method", "GET", ":scheme", "https", ":path", "/base/caf\xc3\xa9", ":authority", "web.example.com"},
	} {
		id := uint32(2*i + 1)
		h.request(t, id, true, fields...)
		if st := h.status(t, id, 5*time.Second); st != "400" {
			t.Errorf("%q: %s, want 400", fields, st)
		}
	}
	be.expectNone(t)
	if n := be.dialed.Load(); n != 0 {
		t.Errorf("%d connections to the backend, want none", n)
	}
	if out := logs.String(); strings.Contains(out, "cannot reach the backend") {
		t.Errorf("a request that HTTP/1.1 cannot carry is logged as a backend that cannot be reached:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// Fix round 3
// ---------------------------------------------------------------------------

// dialH2Deaf makes an HTTP/2 connection to the edge that never reads what the
// edge sends: it gives the edge every window that it may, so that only the
// buffers of the sockets hold the edge back once they are full.
func dialH2Deaf(t *testing.T, ca *testCA, to netip.AddrPort, name string) *http2.Framer {
	t.Helper()
	c := dialWeb(t, ca, to, name, "h2")
	_ = c.SetDeadline(time.Time{})
	if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(c, nil) // it writes, and reads nothing
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1<<31 - 1}); err != nil {
		t.Fatal(err)
	}
	if err := fr.WriteWindowUpdate(0, 1<<31-1-65535); err != nil {
		t.Fatal(err)
	}
	return fr
}

// A client that keeps its connection busy (it pings) but reads nothing fills
// the buffers of the sockets, and the writes of the connection itself stall:
// a reset of a stream could not get through either. The connection is closed
// once its writes make no progress for the progress timeout, and its slots are
// free.
func TestWebConnectionWhoseWritesStallIsClosed(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	const big = 64 << 20 // more than the buffers of two sockets of the loopback hold
	be := newWebBackend(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(big))
		_, _ = io.CopyN(w, zeros{}, big)
	})
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	e.web.progress = shortProgress
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	fr := dialH2Deaf(t, ca, loopback(port), "web.example.com")
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	fields := get("/big")
	for i := 0; i+1 < len(fields); i += 2 {
		_ = enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndStream: true, EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() { // the client keeps its connection busy
		defer close(stopped)
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if fr.WritePing(false, [8]byte{'b', 'u', 's', 'y'}) != nil {
					return
				}
			}
		}
	}()
	defer func() {
		close(stop)
		<-stopped
	}()
	waitFor(t, "the request in flight", func() bool { return e.web.inflight.Load() == 1 })
	waitFor(t, "the connection whose writes stall to be closed, and its slot back", func() bool {
		return e.web.inflight.Load() == 0 && activeConns(e, "pw") == 0
	})
}

// An HTTP/1.1 upload with a declared length that stalls frees its slot within
// the progress timeout as well: the read that timed out leaves the deadline
// expired, so that what Go then reads of the rest of the body to keep the
// connection fails at once instead of waiting.
func TestWebStalledUploadWithALengthFreesItsSlot(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	log, logs := captureLogger(slog.LevelInfo)
	e := newTestEdgeLog(t, log, Options{CertsDir: dir})
	e.web.progress = shortProgress
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
	send(t, c, []byte("POST /up HTTP/1.1\r\nHost: web.example.com\r\nContent-Length: 1000\r\n\r\n0123456789"))
	waitFor(t, "the request in flight", func() bool { return e.web.inflight.Load() == 1 })
	start := time.Now()
	waitFor(t, "the slot of the stalled upload back", func() bool { return e.web.inflight.Load() == 0 })
	if d := time.Since(start); d > 10*shortProgress {
		t.Errorf("the slot came back after %v, with a progress timeout of %v", d, shortProgress)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Errorf("the stalled upload: %v, %v; want 400", resp, err)
	}
	if out := logs.String(); strings.Contains(out, "cannot reach the backend") {
		t.Errorf("a stalled upload is logged as a backend that cannot be reached:\n%s", out)
	}
}

// closingBackend accepts connections, reads what comes first and closes each
// one without an answer: a backend that fails after the dial.
func closingBackend(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = c.Read(make([]byte, 4096))
			_ = c.Close()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// A backend that fails after the dial is the backend's fault for a request
// without a body too, over HTTP/2 (whose request has a body of no bytes) and
// over HTTP/1.1: 502, and the warning.
func TestWebBackendThatFailsAfterTheDialIsTheBackends(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	backend := closingBackend(t)
	for _, proto := range []string{"HTTP/2", "HTTP/1.1"} {
		t.Run(proto, func(t *testing.T) {
			port := freePort(t)
			log, logs := captureLogger(slog.LevelInfo)
			e := newTestEdgeLog(t, log, Options{CertsDir: dir})
			mustApply(t, e, webConfig(1, port, "web.example.com", backend))
			var status int
			if proto == "HTTP/2" {
				client, _ := webClient(t, ca, "", loopback(port))
				resp := mustDo(t, client, newRequest(t, http.MethodGet, "https://web.example.com/x", ""))
				_ = resp.Body.Close()
				status = resp.StatusCode
			} else {
				c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
				resp := rawExchange(t, c, bufio.NewReader(c), "GET /x HTTP/1.1\r\nHost: web.example.com\r\n\r\n")
				_, _ = io.Copy(io.Discard, resp.Body)
				status = resp.StatusCode
			}
			if status != http.StatusBadGateway {
				t.Errorf("GET: %d, want 502", status)
			}
			if out := logs.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "cannot reach the backend") {
				t.Errorf("GET: no warning about the backend:\n%s", out)
			}
		})
	}
}

// What the transport refuses before it connects, other than a dial, is a fault
// of the request, and so of its client: 400, and no warning about the backend.
// HTTP/2 lets a declared trailer through that is no header name.
func TestWebRequestThatTheTransportRefusesIsTheClients(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	log, logs := captureLogger(slog.LevelInfo)
	e := newTestEdgeLog(t, log, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	h := dialH2(t, ca, loopback(port), "web.example.com")
	h.request(t, 1, true, append(get("/x"), "trailer", "b@d")...)
	if st := h.status(t, 1, 5*time.Second); st != "400" {
		t.Errorf("a declared trailer that is no name: %s, want 400", st)
	}
	if n := be.dialed.Load(); n != 0 {
		t.Errorf("%d connections to the backend, want none", n)
	}
	if out := logs.String(); strings.Contains(out, "cannot reach the backend") {
		t.Errorf("a request that the transport refuses is logged as a backend that cannot be reached:\n%s", out)
	}
}

// A Host with a port that is no port is refused with 400, before its name is
// looked at.
func TestWebHostWithAPortThatIsNoPort(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newWebBackend(t, nil)
	port := freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	mustApply(t, e, webConfig(1, port, "web.example.com", be.addr))

	h := dialH2(t, ca, loopback(port), "web.example.com")
	for i, authority := range []string{"web.example.com:junk", "web.example.com:", "web.example.com:65536", "web.example.com:443:443"} {
		id := uint32(2*i + 1)
		h.request(t, id, true, ":method", "GET", ":scheme", "https", ":path", "/x", ":authority", authority)
		if st := h.status(t, id, 5*time.Second); st != "400" {
			t.Errorf("HTTP/2 :authority %q: %s, want 400", authority, st)
		}
	}
	for _, host := range []string{"web.example.com:junk", "web.example.com:443:443"} {
		c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
		resp := rawExchange(t, c, bufio.NewReader(c), "GET /x HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusBadRequest || !resp.Close {
			t.Errorf("HTTP/1.1 Host %q: %d, close %v; want 400 and the connection closed", host, resp.StatusCode, resp.Close)
		}
	}
	be.expectNone(t)
	// A port that is one is no fault.
	c := dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
	if got := decodeEcho(t, rawExchange(t, c, bufio.NewReader(c), "GET /y HTTP/1.1\r\nHost: web.example.com:443\r\n\r\n")); got.URI != "/y" {
		t.Errorf("Host with port 443: the backend saw %q", got.URI)
	}
}

// A hijack that fails, as it does under HTTP/2, is no hijack: the client gets
// a 502 for the upgrade that the backend answered, and not an empty response.
// (Go 1.27 refuses Upgrade in an HTTP/2 request, so this is reached with a
// ResponseWriter that cannot hijack, here.)
func TestWebFailedHijackIsNoHijack(t *testing.T) {
	e := newTestEdge(t, Options{})
	rec := httptest.NewRecorder()
	w := newWebResponse(rec, time.Second)
	if _, _, err := w.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Hijack: %v, want ErrNotSupported", err)
	}
	if isHijacked(w) {
		t.Error("a hijack that failed is taken for one")
	}
	req := httptest.NewRequest(http.MethodGet, "https://web.example.com/ws", nil)
	tg := &webTarget{route: &route{sni: "web.example.com", proxyID: "pw", backendKey: "127.0.0.1:1"}, roundTrip: true}
	req = req.WithContext(context.WithValue(req.Context(), webTargetKey{}, tg))
	e.webProxyError(w, req, errors.New("can't switch protocols using non-Hijacker ResponseWriter"))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status %d, want 502", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Fix round 4
// ---------------------------------------------------------------------------

// earlyBackend stands in for an engine that answers a POST as soon as it has
// its head, before it has read the body (telemt does, with 503, when its
// budget for bodies is spent), and reads the body afterwards; anything else
// it answers "hi". Its connections are kept alive. It tells on answered that
// it has answered a POST, and on bodies how many bytes of the body of that
// POST it got before the body ended or the edge closed the connection.
type earlyBackend struct {
	addr     netip.AddrPort
	answered chan struct{}
	bodies   chan int64
}

func newEarlyBackend(t *testing.T) *earlyBackend {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &earlyBackend{
		addr:     netip.MustParseAddrPort(ln.Addr().String()),
		answered: make(chan struct{}, 16),
		bodies:   make(chan int64, 16),
	}
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		conns  []net.Conn
		closed bool
	)
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		closed = true
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = c.Close()
				return
			}
			conns = append(conns, c)
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				b.serve(c)
			}()
		}
	}()
	return b
}

// serve serves the requests of the connection c.
func (b *earlyBackend) serve(c net.Conn) {
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Method != http.MethodPost {
			_, _ = io.Copy(io.Discard, req.Body)
			if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"); err != nil {
				return
			}
			continue
		}
		if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
			return
		}
		select {
		case b.answered <- struct{}{}:
		default:
		}
		n, err := io.Copy(io.Discard, req.Body)
		select {
		case b.bodies <- n:
		default:
		}
		if err != nil {
			return
		}
	}
}

// slowToEnd makes every request of the web server of e take d more to end once
// its handler has returned. Go reads an HTTP/1.1 connection between requests
// from the end of the body of one, and stops that read as the request ends: a
// read deadline that the request left expired ends the read first, and spoils
// the connection, only most of the time; with d, every time. Call it before
// the first Apply, which starts the goroutines that read the handler.
func slowToEnd(e *Edge, d time.Duration) {
	h := e.web.handler
	e.web.handler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		h.ServeHTTP(rw, req)
		time.Sleep(d)
	})
}

// A backend may answer a request before it has had its body: telemt does,
// with 503, when its budget for bodies is spent. Over HTTP/1.1, Go then reads
// what is left of the body itself (256 KiB at most) as the answer goes out, and
// keeps the connection for the next request, which must be served: an early
// answer is no failure of the request, and leaves the read deadline of the
// connection alone. So it is over a web route, and over an http-upstream
// listener, whose connections carry the requests of every user of the web
// server in front of it.
func TestWebEarlyAnswerKeepsTheConnection(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	be := newEarlyBackend(t)
	port, upstreamPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	slowToEnd(e, 20*time.Millisecond)
	cfg := webConfig(1, port, "web.example.com", be.addr)
	up := upstreamConfig(upstreamPort, "web.example.com", be.addr, "127.0.0.1")
	cfg.Listeners = append(cfg.Listeners, up.Listeners...)
	cfg.Routes = append(cfg.Routes, up.Routes...)
	mustApply(t, e, cfg)

	// The rest of the body comes in pieces, a little apart, as over a slow
	// link: so it is Go, as it writes the head of the answer, that reads the
	// end of the body, and not the transport that passes the body on.
	const half, piece = 64 << 10, 4 << 10
	body := strings.Repeat("a", 2*half)
	for _, tc := range []struct {
		name    string
		dial    func(t *testing.T) net.Conn
		headers string // the headers of a request but Host
	}{
		{"web route over HTTP/1.1", func(t *testing.T) net.Conn {
			return dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
		}, ""},
		{"http-upstream", func(t *testing.T) net.Conn {
			return dialEdge(t, "", loopback(upstreamPort))
		}, "X-Forwarded-For: 198.51.100.1\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.dial(t)
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			br := bufio.NewReader(c)
			send(t, c, fmt.Appendf(nil, "POST /base/up HTTP/1.1\r\nHost: web.example.com\r\n%sContent-Length: %d\r\n\r\n%s",
				tc.headers, len(body), body[:half]))
			select {
			case <-be.answered:
			case <-time.After(5 * time.Second):
				t.Fatal("the backend did not answer the POST")
			}
			time.Sleep(20 * time.Millisecond) // a pause in the upload, as a real link has
			for off := half; off < len(body); off += piece {
				send(t, c, []byte(body[off:off+piece]))
				time.Sleep(2 * time.Millisecond)
			}
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("the POST: %v", err)
			}
			b, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != http.StatusOK || string(b) != "ok" || resp.Close {
				t.Fatalf("the POST: %d %q, %v, close %v; want 200 \"ok\" on a connection kept alive", resp.StatusCode, b, err, resp.Close)
			}
			// The answer went out before the body had gone through, which is
			// what this test is about.
			select {
			case n := <-be.bodies:
				if n == int64(len(body)) {
					t.Fatal("the backend had the whole body: the answer did not come early, and the test proves nothing")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the backend did not tell how much of the body it had")
			}
			send(t, c, []byte("GET /base/next HTTP/1.1\r\nHost: web.example.com\r\n"+tc.headers+"\r\n"))
			resp, err = http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("the next request on the connection kept alive got no answer: %v", err)
			}
			b, err = io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != http.StatusOK || string(b) != "hi" {
				t.Errorf("the next request on the connection kept alive: %d %q, %v; want 200 \"hi\"", resp.StatusCode, b, err)
			}
		})
	}
}

// A request with a body whose backend cannot be dialed is answered 502 when
// the body came whole with the head (a body still on its way may make the
// request fail as the client's, see webProxyError). Then Go has the rest of
// the body at hand, reads it as the transport closes the body, and keeps the
// connection: the next request on it is answered too, and not dropped. ReverseProxy closes the body once more,
// when Go waits for that next request already: the deadline that the first
// close left expired is not set again.
func TestWebBackendDownKeepsTheConnection(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	// Nothing listens on port 1, and no test binds it: a free port of
	// freePort could be taken by the listeners of the edge themselves.
	down := netip.MustParseAddrPort("127.0.0.1:1")
	port, upstreamPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	slowToEnd(e, 20*time.Millisecond)
	cfg := webConfig(1, port, "web.example.com", down)
	up := upstreamConfig(upstreamPort, "web.example.com", down, "127.0.0.1")
	cfg.Listeners = append(cfg.Listeners, up.Listeners...)
	cfg.Routes = append(cfg.Routes, up.Routes...)
	mustApply(t, e, cfg)

	for _, tc := range []struct {
		name    string
		dial    func(t *testing.T) net.Conn
		headers string // the headers of a request but Host
	}{
		{"web route over HTTP/1.1", func(t *testing.T) net.Conn {
			return dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
		}, ""},
		{"http-upstream", func(t *testing.T) net.Conn {
			return dialEdge(t, "", loopback(upstreamPort))
		}, "X-Forwarded-For: 198.51.100.1\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.dial(t)
			br := bufio.NewReader(c)
			resp := rawExchange(t, c, br, "POST /base/up HTTP/1.1\r\nHost: web.example.com\r\n"+tc.headers+"Content-Length: 5\r\n\r\nhello")
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusBadGateway || resp.Close {
				t.Fatalf("the POST: %d, close %v; want 502 on a connection kept alive", resp.StatusCode, resp.Close)
			}
			send(t, c, []byte("GET /base/next HTTP/1.1\r\nHost: web.example.com\r\n"+tc.headers+"\r\n"))
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("the next request on the connection kept alive got no answer: %v", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusBadGateway {
				t.Errorf("the next request on the connection kept alive: %d, want 502", resp.StatusCode)
			}
		})
	}
}

// A request whose backend cannot be dialed is answered 502 also when its body
// follows its head: the dial fails before the body is there, and the request
// is the backend's, not one that its client abandoned. The connection may be
// closed after the answer, since the rest of the body is not read.
func TestWebBackendDownAnswersABodyThatFollowsItsHead(t *testing.T) {
	checkGoroutines(t)
	ca := newTestCA(t)
	dir := t.TempDir()
	ca.install(t, dir, "web.example.com")
	down := netip.MustParseAddrPort("127.0.0.1:1") // see TestWebBackendDownKeepsTheConnection
	port, upstreamPort := freePort(t), freePort(t)
	e := newTestEdge(t, Options{CertsDir: dir})
	cfg := webConfig(1, port, "web.example.com", down)
	up := upstreamConfig(upstreamPort, "web.example.com", down, "127.0.0.1")
	cfg.Listeners = append(cfg.Listeners, up.Listeners...)
	cfg.Routes = append(cfg.Routes, up.Routes...)
	mustApply(t, e, cfg)

	for _, tc := range []struct {
		name    string
		dial    func(t *testing.T) net.Conn
		headers string // the headers of a request but Host
	}{
		{"web route over HTTP/1.1", func(t *testing.T) net.Conn {
			return dialWeb(t, ca, loopback(port), "web.example.com", "http/1.1")
		}, ""},
		{"http-upstream", func(t *testing.T) net.Conn {
			return dialEdge(t, "", loopback(upstreamPort))
		}, "X-Forwarded-For: 198.51.100.1\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.dial(t)
			br := bufio.NewReader(c)
			send(t, c, []byte("POST /base/up HTTP/1.1\r\nHost: web.example.com\r\n"+tc.headers+"Content-Length: 5\r\n\r\n"))
			time.Sleep(100 * time.Millisecond) // the dial fails meanwhile
			_, _ = c.Write([]byte("hello"))    // may fail: the edge may have closed the connection
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("the POST got no answer: %v; want 502", err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("the POST: %d, want 502", resp.StatusCode)
			}
		})
	}
}

// readDeadlines is a ResponseWriter that records the read deadlines set
// through it, as the ResponseWriter of an HTTP/1.1 server sets them on its
// connection.
type readDeadlines struct {
	http.ResponseWriter
	mu  sync.Mutex
	set []time.Time
}

func (d *readDeadlines) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.set = append(d.set, t)
	return nil
}

// state returns how many read deadlines were set, and the last one.
func (d *readDeadlines) state() (int, time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.set) == 0 {
		return 0, time.Time{}
	}
	return len(d.set), d.set[len(d.set)-1]
}

// stepBody is the body of a request as the server hands it over: each Read
// returns what the test sends on reads, once it is sent.
type stepBody struct{ reads chan stepRead }

type stepRead struct {
	n   int
	err error
}

func (b stepBody) Read([]byte) (int, error) {
	r := <-b.reads
	return r.n, r.err
}

func (stepBody) Close() error { return nil }

// The read deadline of the connection is left expired only where the request
// fails: by a read of the body that fails, the timeout of a stalled upload
// among them, and by a close of the body before its end while the backend has
// not answered (a 400, a 413, a backend that cannot be had), once the handler
// has answered the request and returns. From then on it is
// not touched: a read under way does not clear it, and a second close does not
// set it again, since Go may have read the rest of the body meanwhile and wait
// for the next request. Once the backend has answered, Go reads what is left
// of the body itself and keeps the connection: a read of the body that Go has
// closed, and a close of the body, leave the deadline alone.
func TestWebBodyLeavesTheDeadlineExpiredOnlyWhenTheRequestFails(t *testing.T) {
	p := make([]byte, 16)
	newBody := func() (*webBody, *readDeadlines, chan stepRead) {
		reads := make(chan stepRead, 1)
		rw := &readDeadlines{ResponseWriter: httptest.NewRecorder()}
		return newWebBody(stepBody{reads}, rw, time.Minute), rw, reads
	}
	isExpired := func(d time.Time) bool { return !d.IsZero() && d.Before(time.Now()) }

	t.Run("a read that fails", func(t *testing.T) {
		b, rw, reads := newBody()
		reads <- stepRead{0, os.ErrDeadlineExceeded}
		_, _ = b.Read(p)
		n, last := rw.state()
		if !isExpired(last) || !b.failed.Load() {
			t.Fatalf("after a read that fails: deadline %v, failed %v; want it expired, and the body failed", last, b.failed.Load())
		}
		reads <- stepRead{4, nil}
		_, _ = b.Read(p)
		_ = b.Close()
		if m, _ := rw.state(); m != n {
			t.Errorf("%d read deadlines set after the expiry; it is to stay as it is", m-n)
		}
	})
	t.Run("a body closed before its end", func(t *testing.T) {
		b, rw, _ := newBody()
		_ = b.Close()
		// Put off until the request is answered: Go's close of the body would
		// read the rest of it, fail on the expired deadline, and end the
		// context of the request before it is judged.
		if n, last := rw.state(); n != 0 {
			t.Fatalf("a close before the end set the read deadline to %v before the handler returned", last)
		}
		_ = b.Close() // ReverseProxy closes the body after the transport
		b.handlerDone()
		if n, last := rw.state(); n != 1 || !isExpired(last) {
			t.Fatalf("after a close before the end and the handler: %d read deadlines, the last %v; want it expired", n, last)
		}
		_ = b.Close()
		if n, _ := rw.state(); n != 1 {
			t.Errorf("a second close set the read deadline again: Go may have read the rest of the body since, and wait for the next request")
		}
	})
	t.Run("a read under way when the body is closed", func(t *testing.T) {
		b, rw, reads := newBody()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = b.Read(p)
		}()
		waitFor(t, "the read to arm its deadline", func() bool { n, _ := rw.state(); return n == 1 })
		_ = b.Close()
		b.handlerDone()           // the request was answered
		reads <- stepRead{4, nil} // the read comes back with bytes
		<-done
		if n, last := rw.state(); n != 2 || !isExpired(last) {
			t.Errorf("after a read that came back once the body was closed: %d read deadlines, the last %v; want the expiry last", n, last)
		}
	})
	t.Run("a read of a body that Go has closed", func(t *testing.T) {
		b, rw, reads := newBody()
		reads <- stepRead{0, http.ErrBodyReadAfterClose}
		_, _ = b.Read(p)
		if _, last := rw.state(); !last.IsZero() || b.failed.Load() {
			t.Errorf("after a read of a body that Go has closed: deadline %v, failed %v; want it cleared, and no fault", last, b.failed.Load())
		}
	})
	t.Run("a body closed after the backend answered", func(t *testing.T) {
		b, rw, _ := newBody()
		b.answered.Store(true) // as webRoundTripper does
		_ = b.Close()
		if n, last := rw.state(); n != 0 {
			t.Errorf("the close of a body whose backend has answered set the read deadline to %v", last)
		}
	})
	t.Run("a body read to its end", func(t *testing.T) {
		b, rw, reads := newBody()
		reads <- stepRead{4, io.EOF}
		_, _ = b.Read(p)
		_ = b.Close()
		if n, last := rw.state(); n != 2 || !last.IsZero() {
			t.Errorf("a body read to its end: %d read deadlines, the last %v; want the one of the read, cleared", n, last)
		}
	})
	t.Run("a body after its handler has returned", func(t *testing.T) {
		b, rw, reads := newBody()
		b.handlerDone()
		reads <- stepRead{0, os.ErrDeadlineExceeded}
		_, _ = b.Read(p)
		_ = b.Close()
		if n, _ := rw.state(); n != 0 {
			t.Errorf("%d read deadlines set once the handler had returned, want none", n)
		}
	})
}
