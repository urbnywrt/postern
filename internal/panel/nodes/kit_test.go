package nodes

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urbnywrt/postern/internal/panel/auth"
)

// kitOrder is what the tar of a kit holds: these members, in this order, with
// these modes.
var kitOrder = []struct {
	name string
	mode int64
}{
	{"postern-node", 0o755},
	{"install.sh", 0o755},
	{"launcher.sh", 0o755},
	{"compose.yaml", 0o644},
}

// testKit is a node kit in a directory of a test, laid out as in the panel
// image: the scripts at the top, and the binary of each architecture in a
// directory of its own.
type testKit struct {
	t   *testing.T
	dir string
}

// newTestKit writes a kit with the binaries of arches. The sizes of the files
// try the padding of the tar: install.sh fills its blocks exactly, and the
// others do not.
func newTestKit(t *testing.T, arches ...string) *testKit {
	t.Helper()
	k := &testKit{t: t, dir: t.TempDir()}
	k.write("install.sh", 0o755, padded("#!/usr/bin/env bash\n# the installer of a test kit\n", 2*512))
	k.write("launcher.sh", 0o755, []byte("#!/bin/sh\n# the launcher of a test kit\nexec \"$@\"\n"))
	k.write("compose.yaml", 0o644, padded("# the compose file of a test kit\nservices: {}\n", 511))
	for _, arch := range arches {
		k.addBinary(arch)
	}
	return k
}

// addBinary writes the binary of arch into the kit.
func (k *testKit) addBinary(arch string) {
	k.t.Helper()
	k.write(arch+"/postern-node", 0o755, fakeBinary(arch))
}

// path is where the file name (slash-separated, relative to the kit) is.
func (k *testKit) path(name string) string {
	return filepath.Join(k.dir, filepath.FromSlash(name))
}

func (k *testKit) write(name string, mode os.FileMode, data []byte) {
	k.t.Helper()
	path := k.path(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		k.t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		k.t.Fatal(err)
	}
	// WriteFile applies the umask to a new file.
	if err := os.Chmod(path, mode); err != nil {
		k.t.Fatal(err)
	}
}

func (k *testKit) read(name string) []byte {
	k.t.Helper()
	data, err := os.ReadFile(k.path(name))
	if err != nil {
		k.t.Fatal(err)
	}
	return data
}

// want is the content of the members of the tar of arch, in their order.
func (k *testKit) want(arch string) [][]byte {
	k.t.Helper()
	return [][]byte{k.read(arch + "/postern-node"), k.read("install.sh"), k.read("launcher.sh"), k.read("compose.yaml")}
}

// remove deletes a file of the kit.
func (k *testKit) remove(name string) {
	k.t.Helper()
	if err := os.Remove(k.path(name)); err != nil {
		k.t.Fatal(err)
	}
}

// replaceWithDir puts an empty directory where a file of the kit was.
func (k *testKit) replaceWithDir(name string) {
	k.t.Helper()
	k.remove(name)
	if err := os.Mkdir(k.path(name), 0o755); err != nil {
		k.t.Fatal(err)
	}
}

func (k *testKit) chmod(name string, mode os.FileMode) {
	k.t.Helper()
	if err := os.Chmod(k.path(name), mode); err != nil {
		k.t.Fatal(err)
	}
}

// fakeBinary is the binary of arch in a test kit: the ELF magic, the name of
// the architecture and random bytes, some 70 KB, of a size of its own.
func fakeBinary(arch string) []byte {
	size := 70_001
	if arch == "arm64" {
		size += 777
	}
	var seed [32]byte
	copy(seed[:], arch)
	b := make([]byte, size)
	_, _ = rand.NewChaCha8(seed).Read(b)
	copy(b, "\x7fELF "+arch)
	return b
}

// padded is text of n bytes: prefix, then comment characters, then a newline.
func padded(prefix string, n int) []byte {
	b := bytes.Repeat([]byte("#"), n)
	copy(b, prefix)
	b[n-1] = '\n'
	return b
}

// request sends a request with client and returns the response with its body.
func request(t *testing.T, client *http.Client, method, url string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: reading the body: %v", method, url, err)
	}
	return resp, body
}

// checkKitTar checks that data is the tar of a kit, and returns the content of
// its members in their order: the four members of kitOrder and nothing else,
// regular files of uid and gid 0 without user or group names, with the Unix
// epoch as their time. Each is one USTAR header block right after the content
// of the one before (so there is no extended header), and two blocks of zeros
// end the archive.
func checkKitTar(t *testing.T, data []byte) [][]byte {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	contents := make([][]byte, 0, len(kitOrder))
	offset := 0
	for i, want := range kitOrder {
		hdr, err := tr.Next()
		if err != nil {
			t.Fatalf("member %d of the tar: %v", i, err)
		}
		if hdr.Name != want.name || hdr.Typeflag != tar.TypeReg || hdr.Mode != want.mode {
			t.Errorf("member %d is %q of type %q and mode %o, want %q, a regular file of mode %o",
				i, hdr.Name, hdr.Typeflag, hdr.Mode, want.name, want.mode)
		}
		if hdr.Uid != 0 || hdr.Gid != 0 || hdr.Uname != "" || hdr.Gname != "" {
			t.Errorf("%s belongs to %d:%d (%q:%q), want 0:0 without names", hdr.Name, hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname)
		}
		if !hdr.ModTime.Equal(time.Unix(0, 0)) {
			t.Errorf("%s has the time %v, want the Unix epoch", hdr.Name, hdr.ModTime)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("%s: %v", hdr.Name, err)
		}
		if int64(len(content)) != hdr.Size {
			t.Fatalf("%s: %d bytes, the header says %d", hdr.Name, len(content), hdr.Size)
		}
		if offset+512 > len(data) {
			t.Fatalf("the header of %s is not at offset %d", hdr.Name, offset)
		}
		block := data[offset : offset+512]
		if string(block[257:265]) != "ustar\x0000" || block[156] != tar.TypeReg ||
			string(bytes.TrimRight(block[:100], "\x00")) != want.name {
			t.Errorf("the block at offset %d is not the USTAR header of %s: magic %q, type %q, name %q",
				offset, want.name, block[257:265], block[156], bytes.TrimRight(block[:100], "\x00"))
		}
		offset += 512 + (len(content)+511)/512*512
		contents = append(contents, content)
	}
	if hdr, err := tr.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("the tar has more than the four members of a kit: %v, %v", hdr, err)
	}
	if len(data) != offset+1024 || !bytes.Equal(data[offset:], make([]byte, 1024)) {
		t.Errorf("the tar is %d bytes, want the members and two blocks of zeros, %d", len(data), offset+1024)
	}
	return contents
}

func TestKitDownload(t *testing.T) {
	kit := newTestKit(t, "amd64", "arm64")
	a := newAPI(t, WithKitDir(kit.dir))

	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			resp, body := request(t, a.web, http.MethodGet, a.srv.URL+"/api/node-kit/"+arch)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, body %.200q", resp.StatusCode, body)
			}
			if got := resp.Header.Get("Content-Type"); got != "application/x-tar" {
				t.Errorf("Content-Type = %q, want application/x-tar", got)
			}
			disposition, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
			if want := "postern-node-kit-linux-" + arch + ".tar"; err != nil || disposition != "attachment" || params["filename"] != want {
				t.Errorf("Content-Disposition = %q, want an attachment named %s", resp.Header.Get("Content-Disposition"), want)
			}
			if got := resp.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
				t.Errorf("Content-Length = %q, the body has %d bytes", got, len(body))
			}

			got := checkKitTar(t, body)
			for i, want := range kit.want(arch) {
				if !bytes.Equal(got[i], want) {
					t.Errorf("%s in the tar (%d bytes) is not the file of the kit (%d bytes)", kitOrder[i].name, len(got[i]), len(want))
				}
			}
		})
	}
	if logs := a.logs.String(); !strings.Contains(logs, "node kit downloaded") {
		t.Errorf("the download is not in the log:\n%s", logs)
	}
}

// HEAD has the headers of a GET, the length included, and no body.
func TestKitDownloadHead(t *testing.T) {
	kit := newTestKit(t, "amd64")
	a := newAPI(t, WithKitDir(kit.dir))
	url := a.srv.URL + "/api/node-kit/amd64"

	get, full := request(t, a.web, http.MethodGet, url)
	head, body := request(t, a.web, http.MethodHead, url)
	if head.StatusCode != http.StatusOK || len(body) != 0 {
		t.Fatalf("HEAD: status %d with %d bytes of body, want 200 and none", head.StatusCode, len(body))
	}
	for _, name := range []string{"Content-Type", "Content-Disposition", "Cache-Control", "Content-Length"} {
		if head.Header.Get(name) != get.Header.Get(name) || head.Header.Get(name) == "" {
			t.Errorf("HEAD: %s = %q, GET has %q", name, head.Header.Get(name), get.Header.Get(name))
		}
	}
	if got := head.Header.Get("Content-Length"); got != strconv.Itoa(len(full)) {
		t.Errorf("HEAD: Content-Length = %q, the GET had %d bytes", got, len(full))
	}
}

func TestKitDownloadNeedsAnAdmin(t *testing.T) {
	kit := newTestKit(t, "amd64")
	a := newAPI(t, WithKitDir(kit.dir))
	url := a.srv.URL + "/api/node-kit/amd64"
	binary := kit.read("amd64/postern-node")[:64]

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		resp, body := request(t, &http.Client{Timeout: waitTimeout}, method, url)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without a session: status = %d, want 401", method, resp.StatusCode)
		}
		if bytes.Contains(body, binary) {
			t.Errorf("%s without a session got the binary", method)
		}
	}

	// A session cookie that is not a session is no better.
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: strings.Repeat("A", 43)})
	resp, err := (&http.Client{Timeout: waitTimeout}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status with a forged cookie = %d, want 401", resp.StatusCode)
	}

	// The handler asks for an admin itself, whatever it is mounted behind.
	mux := http.NewServeMux()
	mux.Handle(KitRoute, a.svc.KitHandler())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/node-kit/amd64", nil))
	if rec.Code != http.StatusUnauthorized || bytes.Contains(rec.Body.Bytes(), binary) {
		t.Errorf("status without the middleware = %d, want 401 and no binary", rec.Code)
	}
}

func TestKitDownloadRefusesOtherMethods(t *testing.T) {
	kit := newTestKit(t, "amd64")
	a := newAPI(t, WithKitDir(kit.dir))
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		resp, _ := request(t, a.web, method, a.srv.URL+"/api/node-kit/amd64")
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, resp.StatusCode)
		}
		if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s: Allow = %q, want \"GET, HEAD\"", method, got)
		}
	}
	if _, err := os.Stat(kit.path("amd64/postern-node")); err != nil {
		t.Errorf("the kit is not as it was: %v", err)
	}
}

// The architecture is amd64 or arm64, exactly; anything else is no path into
// the kit directory, or anywhere else.
func TestKitDownloadOfUnknownArchitectures(t *testing.T) {
	kit := newTestKit(t, "amd64", "arm64")
	// A directory that a sloppy check of the architecture would serve.
	kit.write("x86/postern-node", 0o755, fakeBinary("x86"))
	a := newAPI(t, WithKitDir(kit.dir))
	binary := kit.read("amd64/postern-node")[:64]

	for _, path := range []string{
		"/api/node-kit/x86",
		"/api/node-kit/AMD64",
		"/api/node-kit/x86_64",
		"/api/node-kit/aarch64",
		"/api/node-kit/amd64.tar",
		"/api/node-kit/..%2Famd64", // the architecture "../amd64"
		"/api/node-kit/amd64%2F",
		"/api/node-kit/%2e%2e",
		"/api/node-kit/",
	} {
		resp, body := request(t, a.web, http.MethodGet, a.srv.URL+path)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: status = %d, want 404", path, resp.StatusCode)
		}
		if bytes.Contains(body, binary) || bytes.Contains(body, []byte("\x7fELF x86")) {
			t.Errorf("GET %s got a binary", path)
		}
	}

	// The handler itself, given what a router might give it.
	for _, arch := range []string{"", "../amd64", "amd64/../arm64", "x86"} {
		req := httptest.NewRequest(http.MethodGet, "/api/node-kit/x", nil)
		req.SetPathValue("arch", arch)
		rec := httptest.NewRecorder()
		a.svc.serveKit(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("arch %q: status = %d, want 404", arch, rec.Code)
		}
	}
}

func TestKitDownloadWithoutTheKit(t *testing.T) {
	kit := newTestKit(t, "amd64") // and not arm64
	a := newAPI(t, WithKitDir(kit.dir))

	resp, body := request(t, a.web, http.MethodGet, a.srv.URL+"/api/node-kit/arm64")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("a kit that is not there: status = %d, want 404", resp.StatusCode)
	}
	if !strings.Contains(string(body), "no node kit for arm64") {
		t.Errorf("the 404 does not say that there is no kit: %q", body)
	}
	if resp, _ := request(t, a.web, http.MethodGet, a.srv.URL+"/api/node-kit/amd64"); resp.StatusCode != http.StatusOK {
		t.Errorf("the kit that is there: status = %d, want 200", resp.StatusCode)
	}

	// A panel that was not told where a kit is has none.
	bare := newAPI(t)
	for _, arch := range []string{"amd64", "arm64"} {
		if resp, _ := request(t, bare.web, http.MethodGet, bare.srv.URL+"/api/node-kit/"+arch); resp.StatusCode != http.StatusNotFound {
			t.Errorf("a panel without a kit directory: status = %d, want 404", resp.StatusCode)
		}
	}
}

// A kit is there for an architecture when its binary is a regular file that
// can be executed, and the three scripts are regular files.
func TestKitAvailability(t *testing.T) {
	for _, c := range []struct {
		name  string
		spoil func(k *testKit)
		want  bool
	}{
		{"a whole kit", func(*testKit) {}, true},
		{"scripts that are not executable", func(k *testKit) {
			k.chmod("install.sh", 0o644)
			k.chmod("launcher.sh", 0o644)
		}, true},
		{"a binary that is a link to a file", func(k *testKit) {
			k.write("elsewhere/postern-node", 0o755, fakeBinary("amd64"))
			k.remove("amd64/postern-node")
			if err := os.Symlink(k.path("elsewhere/postern-node"), k.path("amd64/postern-node")); err != nil {
				k.t.Fatal(err)
			}
		}, true},
		{"a binary that is not executable", func(k *testKit) { k.chmod("amd64/postern-node", 0o644) }, false},
		{"no binary", func(k *testKit) { k.remove("amd64/postern-node") }, false},
		{"a binary that is a directory", func(k *testKit) { k.replaceWithDir("amd64/postern-node") }, false},
		{"no install.sh", func(k *testKit) { k.remove("install.sh") }, false},
		{"no launcher.sh", func(k *testKit) { k.remove("launcher.sh") }, false},
		{"no compose.yaml", func(k *testKit) { k.remove("compose.yaml") }, false},
		{"an install.sh that is a directory", func(k *testKit) { k.replaceWithDir("install.sh") }, false},
		{"a compose.yaml that is a directory", func(k *testKit) { k.replaceWithDir("compose.yaml") }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			kit := newTestKit(t, "amd64")
			c.spoil(kit)
			s := &Service{kitDir: kit.dir}
			if got := s.kitAvailable("amd64"); got != c.want {
				t.Errorf("available = %v, want %v", got, c.want)
			}
		})
	}

	kit := newTestKit(t, "amd64")
	kit.write("x86/postern-node", 0o755, fakeBinary("x86"))
	s := &Service{kitDir: kit.dir}
	for arch, want := range map[string]bool{"amd64": true, "arm64": false, "x86": false, "../" + filepath.Base(kit.dir) + "/amd64": false, "": false} {
		if got := s.kitAvailable(arch); got != want {
			t.Errorf("available(%q) = %v, want %v", arch, got, want)
		}
	}
	if (&Service{}).kitAvailable("amd64") {
		t.Error("a panel without a kit directory has a kit")
	}
	if (&Service{kitDir: filepath.Join(kit.dir, "not-there")}).kitAvailable("amd64") {
		t.Error("a kit directory that does not exist has a kit")
	}
}

// stalledDownload is a download of a kit from the handler of a service, held
// at the first write of the response: by then the handler has opened the files
// of the kit, and has read none of them.
type stalledDownload struct {
	stalled chan struct{} // closed when the handler has come to its first write
	release func()        // lets the handler go on
	done    chan stalledResult
}

type stalledResult struct {
	resp *http.Response
	body []byte
	err  error // of the request, or of reading the body
}

// stallingWriter holds the first write until release is closed.
type stallingWriter struct {
	http.ResponseWriter
	once    sync.Once
	stalled chan struct{}
	release chan struct{}
}

func (w *stallingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.stalled)
		<-w.release
	})
	return w.ResponseWriter.Write(p)
}

func startStalledDownload(t *testing.T, s *Service, arch string) *stalledDownload {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	d := &stalledDownload{
		stalled: make(chan struct{}),
		release: func() { once.Do(func() { close(release) }) },
		done:    make(chan stalledResult, 1),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("arch", arch)
		s.serveKit(&stallingWriter{ResponseWriter: w, stalled: d.stalled, release: release}, r)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(d.release) // before the server closes, which waits for the handler
	go func() {
		resp, err := (&http.Client{Timeout: waitTimeout}).Get(srv.URL + "/api/node-kit/" + arch)
		if err != nil {
			d.done <- stalledResult{err: err}
			return
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		d.done <- stalledResult{resp: resp, body: body, err: err}
	}()
	select {
	case <-d.stalled:
	case r := <-d.done:
		t.Fatalf("the download ended before the handler wrote anything: status %v, err %v", r.resp, r.err)
	case <-time.After(waitTimeout):
		t.Fatal("the handler did not start to write")
	}
	return d
}

// finish lets the handler go on, and returns what the client got.
func (d *stalledDownload) finish(t *testing.T) stalledResult {
	t.Helper()
	d.release()
	select {
	case r := <-d.done:
		return r
	case <-time.After(waitTimeout):
		t.Fatal("the download did not end")
		return stalledResult{}
	}
}

// A file that grows after the handler opened it is sent as large as it was
// then: the header of its member, which is written first, holds.
func TestKitCopyIsBounded(t *testing.T) {
	kit := newTestKit(t, "amd64")
	want := kit.want("amd64")
	s := &Service{kitDir: kit.dir, log: slog.New(slog.DiscardHandler)}

	d := startStalledDownload(t, s, "amd64")
	for _, name := range []string{"amd64/postern-node", "install.sh", "launcher.sh", "compose.yaml"} {
		f, err := os.OpenFile(kit.path(name), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(bytes.Repeat([]byte("+"), 1500)); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	r := d.finish(t)
	if r.err != nil {
		t.Fatalf("the download failed: %v", r.err)
	}
	if got := r.resp.Header.Get("Content-Length"); got != strconv.Itoa(len(r.body)) {
		t.Errorf("Content-Length = %q, the body has %d bytes", got, len(r.body))
	}
	got := checkKitTar(t, r.body)
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("%s: %d bytes in the tar, want the %d that the file had when it was opened", kitOrder[i].name, len(got[i]), len(want[i]))
		}
	}
}

// A file that shrinks after the handler opened it cannot be sent whole: the
// handler logs it and cuts the connection, so that the client does not take
// what it got for the whole tar.
func TestKitDownloadOfAFileThatShrinks(t *testing.T) {
	kit := newTestKit(t, "amd64")
	logs := &lockedBuffer{}
	s := &Service{kitDir: kit.dir, log: slog.New(slog.NewTextHandler(logs, nil))}

	d := startStalledDownload(t, s, "amd64")
	if err := os.Truncate(kit.path("amd64/postern-node"), 100); err != nil {
		t.Fatal(err)
	}
	r := d.finish(t)
	if r.err == nil {
		t.Fatalf("the client read %d bytes and no error, want the download cut off", len(r.body))
	}
	if r.resp != nil && r.resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (the response had begun)", r.resp.StatusCode)
	}
	if got := logs.String(); !strings.Contains(got, "level=ERROR") || !strings.Contains(got, "got shorter") {
		t.Errorf("the log does not say what went wrong:\n%s", got)
	}
}

// The handler cuts the connection by a panic with http.ErrAbortHandler, which
// net/http takes for that and does not log.
func TestKitDownloadAbortsWithErrAbortHandler(t *testing.T) {
	kit := newTestKit(t, "amd64")
	s := &Service{kitDir: kit.dir, log: slog.New(slog.DiscardHandler)}
	req := httptest.NewRequest(http.MethodGet, "/api/node-kit/amd64", nil)
	req.SetPathValue("arch", "amd64")
	w := &failingWriter{ResponseRecorder: httptest.NewRecorder(), after: 600}

	defer func() {
		if p := recover(); p != http.ErrAbortHandler {
			t.Errorf("panic = %v, want http.ErrAbortHandler", p)
		}
	}()
	s.serveKit(w, req)
	t.Error("the handler returned after a failed write")
}

// failingWriter is a ResponseWriter whose connection fails after some bytes.
type failingWriter struct {
	*httptest.ResponseRecorder
	after   int
	written int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.after {
		return 0, errors.New("the connection is gone")
	}
	w.written += len(p)
	return w.ResponseRecorder.Write(p)
}

// deadlineSpy is a ResponseWriter that notes the write deadlines that are set
// on it, as the connection of the HTTP server takes them, and whether the
// response had started by then.
type deadlineSpy struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
	started   bool // the header or a byte of the body went out
	late      bool // a deadline was set after the response had started
}

func (s *deadlineSpy) SetWriteDeadline(t time.Time) error {
	s.deadlines = append(s.deadlines, t)
	s.late = s.late || s.started
	return nil
}

func (s *deadlineSpy) WriteHeader(code int) {
	s.started = true
	s.ResponseRecorder.WriteHeader(code)
}

func (s *deadlineSpy) Write(p []byte) (int, error) {
	s.started = true
	return s.ResponseRecorder.Write(p)
}

// The download of a kit is bounded by a write deadline of a quarter of an
// hour, which is set before the response starts. A refusal has nothing to
// bound.
func TestKitDownloadHasAWriteDeadline(t *testing.T) {
	kit := newTestKit(t, "amd64")
	s := &Service{kitDir: kit.dir, log: slog.New(slog.DiscardHandler)}
	for _, c := range []struct {
		method, arch string
		status       int
		deadline     bool
	}{
		{http.MethodGet, "amd64", http.StatusOK, true},
		{http.MethodHead, "amd64", http.StatusOK, true},
		{http.MethodGet, "arm64", http.StatusNotFound, false},
		{http.MethodPost, "amd64", http.StatusMethodNotAllowed, false},
	} {
		req := httptest.NewRequest(c.method, "/api/node-kit/"+c.arch, nil)
		req.SetPathValue("arch", c.arch)
		spy := &deadlineSpy{ResponseRecorder: httptest.NewRecorder()}
		before := time.Now()
		s.serveKit(spy, req)
		after := time.Now()
		what := c.method + " " + c.arch
		if spy.Code != c.status {
			t.Errorf("%s: status %d, want %d", what, spy.Code, c.status)
		}
		switch {
		case !c.deadline:
			if len(spy.deadlines) != 0 {
				t.Errorf("%s: %d write deadlines, want none", what, len(spy.deadlines))
			}
		case len(spy.deadlines) != 1:
			t.Errorf("%s: %d write deadlines, want 1: %v", what, len(spy.deadlines), spy.deadlines)
		case spy.late:
			t.Errorf("%s: the write deadline was set after the response had started", what)
		case spy.deadlines[0].Before(before.Add(15*time.Minute)) || spy.deadlines[0].After(after.Add(15*time.Minute)):
			t.Errorf("%s: the write deadline is %v, want 15 minutes after the request, between %v and %v",
				what, spy.deadlines[0], before.Add(15*time.Minute), after.Add(15*time.Minute))
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

// A client that does not read is let go when the deadline of the download has
// passed: the connection is closed, and the handler, which holds the files of
// the kit open, does not wait for the client for ever.
func TestKitDownloadGivesUpOnAClientThatDoesNotRead(t *testing.T) {
	kit := newTestKit(t, "amd64")
	logs := &lockedBuffer{}
	const timeout = 200 * time.Millisecond
	s := &Service{kitDir: kit.dir, log: slog.New(slog.NewTextHandler(logs, nil)), kitTimeoutOverride: timeout}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("arch", "amd64")
		s.serveKit(w, r)
	})}
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
	if _, err := io.WriteString(conn, "GET /api/node-kit/amd64 HTTP/1.1\r\nHost: panel.example\r\n\r\n"); err != nil {
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
	waitFor(t, "the log of the download that was cut off", func() bool {
		return strings.Contains(logs.String(), "the download of a node kit was cut off")
	})
}

// jsonRecords decodes the JSON lines of a log.
func jsonRecords(t *testing.T, logs *lockedBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("a line of the log is not JSON: %v: %q", err, line)
		}
		out = append(out, rec)
	}
	return out
}

// A kit that the panel has and cannot serve is a fault: the 404 is logged as a
// warning, with the architecture and the reason and nothing else. A panel
// without a kit logs nothing for each request: its start says that it has none.
func TestKitThatCannotBeServedIsLogged(t *testing.T) {
	for _, c := range []struct {
		name   string
		dir    func(t *testing.T) string
		arch   string
		status int
		reason string // a part of the err of the warning; "" for no warning
	}{
		{"a kit without the architecture", func(t *testing.T) string { return newTestKit(t, "amd64").dir },
			"arm64", http.StatusNotFound, filepath.Join("arm64", "postern-node")},
		{"a binary that cannot be executed", func(t *testing.T) string {
			k := newTestKit(t, "amd64")
			k.chmod("amd64/postern-node", 0o644)
			return k.dir
		}, "amd64", http.StatusNotFound, "is not executable"},
		{"a kit that is served", func(t *testing.T) string { return newTestKit(t, "amd64").dir },
			"amd64", http.StatusOK, ""},
		{"no directory of a kit", func(t *testing.T) string { return filepath.Join(t.TempDir(), "node-kit") },
			"amd64", http.StatusNotFound, ""},
		{"no kit at all", func(*testing.T) string { return "" }, "amd64", http.StatusNotFound, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			logs := &lockedBuffer{}
			s := &Service{kitDir: c.dir(t), log: slog.New(slog.NewJSONHandler(logs, nil))}
			req := httptest.NewRequest(http.MethodGet, "/api/node-kit/"+c.arch, nil)
			req.SetPathValue("arch", c.arch)
			rec := httptest.NewRecorder()
			s.serveKit(rec, req)
			if rec.Code != c.status {
				t.Fatalf("status %d, want %d", rec.Code, c.status)
			}
			var warnings []map[string]any
			for _, r := range jsonRecords(t, logs) {
				if r["level"] == "WARN" || r["level"] == "ERROR" {
					warnings = append(warnings, r)
				}
			}
			if c.reason == "" {
				if len(warnings) != 0 {
					t.Errorf("warnings: %v, want none", warnings)
				}
				return
			}
			if len(warnings) != 1 {
				t.Fatalf("warnings: %v, want one", warnings)
			}
			w := warnings[0]
			if w["level"] != "WARN" || w["arch"] != c.arch || !strings.Contains(fmt.Sprint(w["err"]), c.reason) {
				t.Errorf("the warning is %v, want level WARN, arch %s and an err that says %q", w, c.arch, c.reason)
			}
			for key := range w {
				if !slices.Contains([]string{"time", "level", "msg", "arch", "err"}, key) {
					t.Errorf("the warning has %q: want the architecture and the error, nothing else (%v)", key, w)
				}
			}
		})
	}
}
